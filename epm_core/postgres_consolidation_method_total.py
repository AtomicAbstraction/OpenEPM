"""Durable calculated parent total over explicit mixed-method contributions."""
from decimal import Decimal,localcontext,ROUND_HALF_EVEN
import json
import re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_method_total import (FUNCTION,PUBLIC_FUNCTION,COMPILER,
 COMPILER_V2,COMPILER_V3,PLAN_DIGEST,PLAN_DIGEST_V2,PLAN_DIGEST_V3,
 compile_total,decode_total)
from .persistence_contract import ApplicationScope,Coordinate,NumericCell
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_consolidation_method_coverage import PostgresConsolidationMethodCoverage
from .postgres_consolidation_full import enforce_consolidation_target_policy
from .postgres_job_final_fence import finish_published_job
from .postgres_jobs import PostgresJobQueue,_canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_calculation_status import published_input_status
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates

_JOB=re.compile(r'[0-9a-f]{32}\Z')

def _require_lineage_bound(lineage):
 # PostgreSQL jsonb::text emits separator spaces.  ensure_ascii expands every
 # non-ASCII code point, so this is conservative relative to UTF-8 jsonb text.
 encoded=json.dumps(lineage,sort_keys=True,ensure_ascii=True).encode('ascii')
 if len(encoded)>65536:raise ValueError('METHOD_TOTAL_LINEAGE_LIMIT')
 return len(encoded)

def _compiler_identity(plan):
 return ({2:(COMPILER_V2,PLAN_DIGEST_V2),
          3:(COMPILER_V3,PLAN_DIGEST_V3),
          4:(COMPILER,PLAN_DIGEST)}[plan.document['version']])

def _validate_v2_grain(coverage,sources,target,entity_dim):
 common=None
 for source in sources:
  members=source['members']
  if members.get(entity_dim)!=coverage['parentEntityId']:
   raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')
  fixed={key:value for key,value in members.items() if key!=entity_dim}
  if common is None:common=fixed
  if (fixed!=common or target.get(entity_dim)!=coverage['parentEntityId']
   or {key:value for key,value in target.items() if key!=entity_dim}!=fixed):
   raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')

def _validate_v3_legacy_grain(coverage,sources,target,roles,active_members):
 if set(roles)!={'Account','Entity','Currency'}:
  raise ValueError('METHOD_TOTAL_ROLE_REQUIRED')
 entity_dim=roles['Entity'];account_dim=roles['Account']
 if (target.get(entity_dim)!=coverage['parentEntityId']
  or not target.get(account_dim)):
  raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')
 target_common={key:value for key,value in target.items()
                if key not in (entity_dim,account_dim)}
 coordinates=[target,*[source['members'] for source in sources]]
 if any((dimension,member) not in active_members
        for members in coordinates for dimension,member in members.items()):
  raise ValueError('METHOD_TOTAL_MEMBER_UNAVAILABLE')
 transforms=[]
 for source in sources:
  members=source['members'];source_account=members.get(account_dim)
  if (members.get(entity_dim)!=coverage['parentEntityId'] or not source_account
   or {key:value for key,value in members.items()
       if key not in (entity_dim,account_dim)}!=target_common):
   raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')
  transforms.append([{'dimensionId':account_dim,
   'sourceMemberId':source_account,'targetMemberId':target[account_dim]}])
 return transforms

def _validate_v4_grain(coverage,placements,sources,target,roles,
                       active_dimensions,active_members):
 if set(roles)!={'Account','Entity','Currency','Scenario','Year','Period'}:
  raise ValueError('METHOD_TOTAL_ROLE_REQUIRED')
 entity_dim=roles['Entity'];account_dim=roles['Account']
 currency_dim=roles['Currency'];axes=set(active_dimensions)-{currency_dim}
 if (target.get(entity_dim)!=coverage['parentEntityId']
  or not target.get(account_dim) or set(target)!=axes):
  raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')
 target_common={key:value for key,value in target.items()
                if key not in (entity_dim,account_dim)}
 coordinates=[target,*[source['members'] for source in sources]]
 if any(set(members)!=axes for members in coordinates):
  raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')
 if any((dimension,member) not in active_members
        for members in coordinates for dimension,member in members.items()):
  raise ValueError('METHOD_TOTAL_MEMBER_UNAVAILABLE')
 period_roles=(('Scenario','scenarioId'),('Year','yearId'),('Period','periodId'))
 for role,coverage_key in period_roles:
  dimension=roles.get(role)
  if dimension is not None and any(
   members[dimension]!=coverage[coverage_key] for members in coordinates):
   raise ValueError('METHOD_TOTAL_COVERAGE_GRAIN_MISMATCH')
 transforms=[]
 for placement,source in zip(placements,sources,strict=True):
  members=source['members'];source_account=members.get(account_dim)
  if (members.get(entity_dim)!=coverage['parentEntityId'] or not source_account
   or {key:value for key,value in members.items()
       if key not in (entity_dim,account_dim)}!=target_common):
   raise ValueError('METHOD_TOTAL_GRAIN_MISMATCH')
  child=placement.get('childEntityId')
  if (not child or (entity_dim,child) not in active_members):
   raise ValueError('METHOD_TOTAL_MEMBER_UNAVAILABLE')
  transforms.append([
   {'dimensionId':entity_dim,'placementChildMemberId':child,
    'sourceMemberId':members[entity_dim],
    'targetMemberId':target[entity_dim]},
   {'dimensionId':account_dim,'sourceMemberId':source_account,
    'targetMemberId':target[account_dim]}])
 return transforms

def _validate_v3_unit(placement,members,currency_dim,currency):
 if placement['outputUnit']!={'dimensionId':currency_dim,'memberId':currency}:
  raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')
 if currency_dim in members:raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')

def _load_v4_layout(db,scope):
 dimensions=db.execute('''SELECT model_role,dimension_id FROM epm.dimension
  WHERE workspace_id=%s AND application_id=%s AND status='Active'
  ORDER BY dimension_id''',(scope.workspace_id,scope.application_id)).fetchall()
 active_rows=db.execute('''SELECT m.dimension_id,m.member_id FROM epm.member m
  JOIN epm.dimension d ON d.workspace_id=m.workspace_id
   AND d.application_id=m.application_id AND d.dimension_id=m.dimension_id
   AND d.status='Active'
  WHERE m.workspace_id=%s AND m.application_id=%s AND m.status='Active' ''',
  (scope.workspace_id,scope.application_id)).fetchall()
 return dimensions,active_rows

def _candidate_result(coverage,target,amount,lineage,currency_dim,currency,plan):
 result={'parentEntityId':coverage['parentEntityId'],
  'scenarioId':coverage['scenarioId'],'yearId':coverage['yearId'],
  'periodId':coverage['periodId'],'targetMembers':target,'amount':amount,
  'placementCount':len(lineage),'coverageDigest':coverage['coverageDigest'],
  'outputUnit':{'dimensionId':currency_dim,'memberId':currency},
  'sourceLookupLineage':lineage,'accountingPolicyStatus':'Unreviewed',
  'wholeStatementCertified':False,'effects':'None'}
 if plan.document['version']>=3:
  result['transformedAxes']=plan.document['transformedAxes']
 return result

def enforce_method_total_dimensional_security(db,identity,scope,candidate):
 """Authorize every published contribution source and the parent total."""
 if not isinstance(candidate,dict):
  raise ValueError('METHOD_TOTAL_SECURITY_COORDINATES_INVALID')
 lineage=candidate.get('sourceLookupLineage')
 target=candidate.get('targetMembers')
 if (not isinstance(lineage,list) or not 1<=len(lineage)<=64
  or not isinstance(target,dict) or not target):
  raise ValueError('METHOD_TOTAL_SECURITY_COORDINATES_INVALID')
 reads={}
 try:
  for item in lineage:
   if (not isinstance(item,dict) or item.get('kind')!='MethodContribution'
    or not isinstance(item.get('source'),dict)
    or not isinstance(item['source'].get('members'),dict)):
    raise ValueError('METHOD_TOTAL_SECURITY_COORDINATES_INVALID')
   coordinate=Coordinate.from_mapping(item['source']['members'])
   reads[coordinate.series_key]=coordinate
  output=Coordinate.from_mapping(target)
 except (KeyError,TypeError,ValueError) as error:
  if (isinstance(error,ValueError)
   and str(error)=='METHOD_TOTAL_SECURITY_COORDINATES_INVALID'):
   raise
  raise ValueError('METHOD_TOTAL_SECURITY_COORDINATES_INVALID') from error
 authorize_coordinates(db,identity,scope,reads.values(),kind=AccessKind.READ)
 authorize_coordinates(db,identity,scope,(output,),kind=AccessKind.WRITE)

class PostgresConsolidationMethodTotal:
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
  self.dsn,self.identity=dsn,identity
 def _candidate(self,scope,plan):
  coverage=PostgresConsolidationMethodCoverage(self.dsn,identity=self.identity).inspect(
   scope,plan.document['coverageProgram'])
  if (coverage['coverageDigest']!=plan.document['expectedCoverageDigest']
   or not coverage['complete'] or coverage['effects']!='None'
   or coverage['accountingPolicyStatus']!='Unreviewed'):
   raise ValueError('STALE_METHOD_TOTAL_COVERAGE')
  sources=coverage['statementPackSources'];placements=coverage['placements']
  if not 1<=len(sources)==len(placements)<=64:raise ValueError('METHOD_TOTAL_SCOPE_INVALID')
  if len({p['relationshipId'] for p in placements})!=len(placements):raise ValueError('METHOD_TOTAL_SCOPE_INVALID')
  target=plan.document['targetMembers'];currency_dim=plan.document['currencyDimensionId'];currency=plan.document['currencyMemberId']
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope)
   if plan.document['version']==2:
    dimensions=db.execute("""SELECT model_role,dimension_id FROM epm.dimension
     WHERE workspace_id=%s AND application_id=%s AND status='Active'
     AND model_role=ANY(%s) ORDER BY model_role,dimension_id""",
     (scope.workspace_id,scope.application_id,['Entity','Currency'])).fetchall()
    active_rows=[]
   elif plan.document['version']==3:
    dimensions=db.execute("""SELECT model_role,dimension_id FROM epm.dimension
     WHERE workspace_id=%s AND application_id=%s AND status='Active'
     AND model_role=ANY(%s) ORDER BY model_role,dimension_id""",
     (scope.workspace_id,scope.application_id,
      ['Account','Entity','Currency'])).fetchall()
    active_rows=db.execute('''SELECT dimension_id,member_id FROM epm.member
     WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
     (scope.workspace_id,scope.application_id)).fetchall()
   else:
    dimensions,active_rows=_load_v4_layout(db,scope)
  by_role={}
  relevant={'Account','Entity','Currency','Scenario','Year','Period'}
  for row in dimensions:
   role=row['model_role']
   if role not in relevant:continue
   if role in by_role:raise ValueError('METHOD_TOTAL_ROLE_AMBIGUOUS')
   by_role[role]=row['dimension_id']
  if ('Entity' not in by_role or by_role.get('Currency')!=currency_dim
   or (plan.document['version']>=3 and 'Account' not in by_role)):
   raise ValueError('METHOD_TOTAL_ROLE_REQUIRED')
  entity_dim=by_role['Entity']
  if currency_dim in target:raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')
  active_members={(row['dimension_id'],row['member_id']) for row in active_rows}
  if (plan.document['version']>=3
   and (currency_dim,currency) not in active_members):
   raise ValueError('METHOD_TOTAL_MEMBER_UNAVAILABLE')
  transformations=(None if plan.document['version']==2 else
   _validate_v3_legacy_grain(coverage,sources,target,by_role,active_members)
   if plan.document['version']==3 else
   _validate_v4_grain(coverage,placements,sources,target,by_role,
    {row['dimension_id'] for row in dimensions},active_members))
  if plan.document['version']==2:
   _validate_v2_grain(coverage,sources,target,entity_dim)
  lineage=[];total=Decimal(0)
  for ordinal,(placement,source) in enumerate(zip(placements,sources,strict=True)):
   members=source['members'];unit=placement['outputUnit']
   if plan.document['version']>=3:
    _validate_v3_unit(placement,members,currency_dim,currency)
   elif unit!={'dimensionId':currency_dim,'memberId':currency}:
    raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')
   elif currency_dim in members:raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')
   # Each method publisher has already transformed its child placement to the
   # parent output coordinate.  The child remains lineage, never output grain.
   amount=NumericCell.from_wire(present=True,amount=placement['amount']).amount;total+=amount
   lineage.append({'kind':'MethodContribution','relationshipId':placement['relationshipId'],
    'method':placement['method'],'amount':format(amount,'.8f'),'outputUnit':unit,
    'source':source,'sourceStatus':placement['sourceStatus'],
    'contextStatus':placement['contextStatus']})
   if transformations is not None:
    lineage[-1]['transformedAxes']=transformations[ordinal]
  with localcontext() as context:
   context.prec=80;rounded=total.quantize(Decimal('0.00000001'),rounding=ROUND_HALF_EVEN)
  amount=NumericCell.from_wire(present=True,amount=format(rounded,'f')).amount
  _require_lineage_bound(lineage)
  return _candidate_result(coverage,target,format(amount,'.8f'),lineage,
                           currency_dim,currency,plan)

 def inspect(self,scope,program):
  plan=compile_total(program);candidate=self._candidate(scope,plan)
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
   enforce_method_total_dimensional_security(
    db,self.identity,scope,candidate)
   state=db.execute('SELECT metadata_revision,data_revision,policy_revision,commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s',(scope.workspace_id,scope.application_id)).fetchone()
   pointer=db.execute('SELECT published_revision FROM epm.calculation_publication WHERE workspace_id=%s AND application_id=%s AND result_key=%s',(scope.workspace_id,scope.application_id,plan.document['resultKey'])).fetchone()
   if (pointer['published_revision'] if pointer else 0)!=plan.document['expectedPublicationRevision']:raise ValueError('STALE_METHOD_TOTAL_POINTER')
  return plan,candidate,state
 def admit(self,scope,program,*,idempotency_key):
  plan,_,state=self.inspect(scope,program)
  compiler,digest=_compiler_identity(plan)
  return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,idempotency_key=idempotency_key,function_name=FUNCTION,normalized_program=plan.document,compiler_version=compiler,plan_digest=digest,expected_metadata_revision=state['metadata_revision'],expected_data_revision=state['data_revision'],expected_policy_revision=state['policy_revision'],resource_class='short',authorization_function=PUBLIC_FUNCTION)
 def publish(self,claim):
  if not isinstance(claim,dict) or not _JOB.fullmatch(claim.get('job_id','')):raise ValueError('INVALID_WORKER_CLAIM')
  scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
  with connect_postgres(self.dsn,row_factory=dict_row) as before,before.transaction():
   PostgresNumericFactStore._set_scope(before,scope)
   initial_job=before.execute('''SELECT * FROM epm.job
    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
    (scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
   if not initial_job:
    raise ValueError('METHOD_TOTAL_JOB_UNAVAILABLE')
   plan=decode_total(initial_job['normalized_program'])
   compiler,digest=_compiler_identity(plan)
   if (initial_job['function_name']!=FUNCTION
    or initial_job['compiler_version']!=compiler
    or initial_job['plan_digest']!=digest
    or initial_job['program_digest']!=_canonical_digest(
     initial_job['normalized_program'])):
    raise ValueError('UNSUPPORTED_METHOD_TOTAL_JOB')
   if (initial_job['issuer']!=self.identity.issuer
    or initial_job['subject_id']!=self.identity.subject_id):
    raise ValueError('METHOD_TOTAL_JOB_UNAVAILABLE')
   initial_live=before.execute(
    'SELECT %s::timestamptz>clock_timestamp() valid',
    (initial_job['lease_until'],)).fetchone()['valid']
   if (initial_job['status']!='running'
    or initial_job['claim_generation']!=claim.get('claim_generation')
    or initial_job['claimant']!=claim.get('claimant') or not initial_live):
    raise ValueError('STALE_WORKER_FENCE')
  candidate=self._candidate(scope,plan)
  with connect_postgres(self.dsn,row_factory=dict_row) as authorization,authorization.transaction():
   PostgresNumericFactStore._set_scope(authorization,scope)
   PostgresAccessChecker.check_in_transaction(
    authorization,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
   enforce_method_total_dimensional_security(
    authorization,self.identity,scope,candidate)
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
   state=db.execute('''SELECT s.*,a.status application_status
    FROM epm.application_state s JOIN epm.application a
    USING(workspace_id,application_id)
    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
    (scope.workspace_id,scope.application_id)).fetchone()
   job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
    AND application_id=%s AND job_id=%s FOR UPDATE''',
    (scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
   if job is None:raise ValueError('METHOD_TOTAL_JOB_UNAVAILABLE')
   receipt=db.execute('''SELECT command_digest,actor_id,result
    FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
    AND operation_id=%s''',(scope.workspace_id,scope.application_id,
    claim['job_id'])).fetchone()
   if receipt:
    if receipt['command_digest']!=job['program_digest'] or receipt['actor_id']!=job['subject_id']:raise ValueError('METHOD_TOTAL_RECEIPT_CONFLICT')
    return receipt['result']
   immutable=('issuer','subject_id','function_name','normalized_program',
    'program_digest','compiler_version','plan_digest',
    'expected_metadata_revision','expected_data_revision',
    'expected_policy_revision')
   if any(job[key]!=initial_job[key] for key in immutable):
    raise ValueError('STALE_WORKER_FENCE')
   valid=db.execute('SELECT %s::timestamptz>clock_timestamp() valid',(job['lease_until'],)).fetchone()['valid']
   if job['status']!='running' or job['claim_generation']!=claim.get('claim_generation') or job['claimant']!=claim.get('claimant') or not valid:raise ValueError('STALE_WORKER_FENCE')
   if job['function_name']!=FUNCTION or job['compiler_version']!=compiler or job['plan_digest']!=digest or job['program_digest']!=_canonical_digest(job['normalized_program']):raise ValueError('UNSUPPORTED_METHOD_TOTAL_JOB')
   access=PostgresAccessChecker.check_in_transaction(
    db,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
   if state['application_status']!='Active' or state['processing_mode']!='Active' or any(state[k]!=job['expected_'+k] for k in ('metadata_revision','data_revision','policy_revision')):raise ValueError('STALE_JOB_INPUT_REVISION')
   pointer=db.execute('SELECT published_revision FROM epm.calculation_publication WHERE workspace_id=%s AND application_id=%s AND result_key=%s',(scope.workspace_id,scope.application_id,plan.document['resultKey'])).fetchone()
   if (pointer['published_revision'] if pointer else 0)!=plan.document['expectedPublicationRevision']:raise ValueError('STALE_METHOD_TOTAL_POINTER')
   current_sources=source_status(db,scope,candidate)
   if not current_sources['matchesAtRead']:
    raise ValueError('STALE_METHOD_TOTAL_SOURCE')
   enforce_method_total_dimensional_security(
    db,self.identity,scope,candidate)
   target=Coordinate.from_mapping(candidate['targetMembers']);policy=enforce_consolidation_target_policy(db,scope,target,access.role)
   db.execute('INSERT INTO epm.coordinate(workspace_id,application_id,series_key,members) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING',(scope.workspace_id,scope.application_id,target.series_key,Jsonb(dict(target.members))))
   target_row=db.execute('SELECT coordinate_id,members FROM epm.coordinate WHERE workspace_id=%s AND application_id=%s AND series_key=%s',(scope.workspace_id,scope.application_id,target.series_key)).fetchone()
   if target_row['members']!=dict(target.members):raise ValueError('COORDINATE_HASH_COLLISION')
   revision=state['commit_revision']+1;amount=NumericCell.from_wire(present=True,amount=candidate['amount']).amount;unit=candidate['outputUnit']
   db.execute('''INSERT INTO epm.calculation_generation(workspace_id,application_id,generation_id,job_id,result_key,source_commit_revision,source_metadata_revision,source_policy_revision,function_name,factor,row_count,published_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',(scope.workspace_id,scope.application_id,claim['job_id'],claim['job_id'],plan.document['resultKey'],state['commit_revision'],state['metadata_revision'],state['policy_revision'],FUNCTION,revision))
   evidence_digest=_canonical_digest(candidate['sourceLookupLineage'])
   db.execute('''INSERT INTO epm.calculation_unit_result(workspace_id,application_id,generation_id,coordinate_id,output_unit_currency_dimension_id,output_unit_currency_member_id,source_amount,source_change_id,source_evidence_digest,amount,rate_strategy,rate_numerator,rate_denominator,rate_sources,source_lookup_lineage) VALUES(%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,'identity-same-currency',1,1,%s,%s)''',(scope.workspace_id,scope.application_id,claim['job_id'],target_row['coordinate_id'],unit['dimensionId'],unit['memberId'],amount,evidence_digest,amount,Jsonb([{'kind':'Identity','currency':unit}]),Jsonb(candidate['sourceLookupLineage'])))
   result={**candidate,'generationId':claim['job_id'],'resultKey':plan.document['resultKey'],'publishedRevision':revision,'committedRevision':revision,'publicationSupported':True,'effects':'CalculatedGenerationOnly','planningPolicy':policy}
   db.execute('''INSERT INTO epm.calculation_publication(workspace_id,application_id,result_key,generation_id,published_revision) VALUES(%s,%s,%s,%s,%s) ON CONFLICT(workspace_id,application_id,result_key) DO UPDATE SET generation_id=EXCLUDED.generation_id,published_revision=EXCLUDED.published_revision,updated_at=transaction_timestamp()''',(scope.workspace_id,scope.application_id,plan.document['resultKey'],claim['job_id'],revision));db.execute('UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s',(revision,scope.workspace_id,scope.application_id));db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,claim['job_id'],job['program_digest'],job['subject_id'],revision,Jsonb(result)));finish_published_job(db,scope,claim,revision=revision,result=result);return result

def source_status(db,scope,result):
 try:
  lineage=result['sourceLookupLineage']
  pins=[{'resultKey':row['source']['resultKey'],
         'generationId':row['source']['generationId'],
         'publishedRevision':row['source']['publishedRevision']}
        for row in lineage]
 except (KeyError,TypeError):
  return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
 if not 1<=len(pins)<=64:
  return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
 status=published_input_status(db,scope,{'publishedInputs':pins})
 if status is None:return {'matchesAtRead':False,'truncated':False,'dependencies':[]}
 recursive=[]
 for item in lineage:
  source=item['source'];method=item.get('method')
  row=db.execute('''SELECT g.function_name,j.normalized_program,
   j.compiler_version,j.plan_digest,j.program_digest,
   o.result AS receipt_result FROM epm.calculation_generation g
   JOIN epm.job j ON j.workspace_id=g.workspace_id
    AND j.application_id=g.application_id AND j.job_id=g.job_id
   JOIN epm.operation_receipt o ON o.workspace_id=g.workspace_id
    AND o.application_id=g.application_id AND o.operation_id=g.job_id
   WHERE g.workspace_id=%s AND g.application_id=%s
    AND g.generation_id=%s AND g.result_key=%s''',
   (scope.workspace_id,scope.application_id,source['generationId'],
    source['resultKey'])).fetchone()
  valid=bool(row);source_detail=context_detail={'matchesAtRead':False}
  if valid and method=='Equity':
   from .postgres_equity_method_publication import context_status,source_status as child_status
   source_detail=child_status(db,scope,row['receipt_result'])
   context_detail=context_status(db,scope,row['normalized_program'],row['receipt_result'])
  elif valid and method=='Proportional':
   from .postgres_proportional_publication import context_status,source_status as child_status
   source_detail=child_status(db,scope,row['receipt_result'])
   context_detail=context_status(db,scope,row['normalized_program'],row['receipt_result'])
  elif valid and method=='Full':
   function=row['function_name']
   receipt=row['receipt_result']
   if (function=='consolidation.full.typed.contribute'
       and isinstance(receipt,dict)):
    from .postgres_consolidation_full import (
     decode_typed_full_contribution,typed_full_context_status)
    try:plan=decode_typed_full_contribution(row['normalized_program'])
    except (TypeError,KeyError,ValueError):plan=None
    if (plan is not None and row['compiler_version']==plan.compiler_version
        and row['plan_digest']==plan.plan_digest
        and row['program_digest']==_canonical_digest(row['normalized_program'])):
     context_detail=typed_full_context_status(
      db,scope,row['normalized_program'],receipt)
     if receipt.get('sourceLayer')=='raw_plus_ic_elimination':
      source_detail=(context_detail.get('sourceStatus') or
                     {'matchesAtRead':False})
     else:
      source_detail=PostgresConsolidationMethodCoverage._full_source_status(
       db,scope,receipt)
   elif function=='consolidation.full.contribute' and isinstance(receipt,dict):
    source_detail=PostgresConsolidationMethodCoverage._full_source_status(
     db,scope,receipt);context_detail={'matchesAtRead':True}
  valid=valid and source_detail['matchesAtRead'] and context_detail['matchesAtRead']
  recursive.append({'relationshipId':item.get('relationshipId'),'method':method,
   'matchesAtRead':valid,'sourceStatus':source_detail,
   'contextStatus':context_detail})
 status['methodContributions']=recursive
 status['matchesAtRead'] &= all(item['matchesAtRead'] for item in recursive)
 return status
