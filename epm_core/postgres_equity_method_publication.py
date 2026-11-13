"""Durable calculated-only publication of an explicit Equity-method candidate."""
import re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_equity_method_publication import (FUNCTION,PUBLIC_FUNCTION,
 COMPILER,PLAN_DIGEST,compile_publication,decode_publication)
from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope,Coordinate,NumericCell
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_equity_method_contribution import PostgresEquityMethodContributionPreview
from .postgres_jobs import PostgresJobQueue,_canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_consolidation_full import enforce_consolidation_target_policy
from .postgres_job_final_fence import finish_published_job
from .postgres_dimensional_security_enforcement import authorize_coordinates

_JOB=re.compile(r'[0-9a-f]{32}\Z')


def enforce_equity_publication_dimensional_security(
        db,identity,scope,candidate):
 sources=(candidate.get('lineage') or {}).get('sources') or {}
 if set(sources)!= {'openingCarryingValue','postAcquisitionResult',
                    'postAcquisitionOci'}:
  raise ValueError('EQUITY_SOURCE_LINEAGE_INVALID')
 authorize_coordinates(db,identity,scope,tuple(
  Coordinate.from_mapping(sources[name]['members']) for name in sorted(sources)),
  kind=AccessKind.READ)
 authorize_coordinates(db,identity,scope,(
  Coordinate.from_mapping(candidate['targetMembers']),),kind=AccessKind.WRITE)


def source_status(db,scope,receipt):
 lineage=receipt.get('sourceLookupLineage') if isinstance(receipt,dict) else None
 raw=[item for item in lineage or [] if isinstance(item,dict) and item.get('kind')=='RawCoordinate']
 if len(raw)!=3:return {'matchesAtRead':False,'sources':[]}
 status=[]
 for item in raw:
  row=db.execute('''SELECT n.present,n.amount,n.change_id,c.members FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s AND c.application_id=%s AND c.coordinate_id=%s''',(scope.workspace_id,scope.application_id,item.get('coordinateId'))).fetchone()
  matches=bool(row and row['present'] and row['members']==item.get('members') and format(row['amount'],'.8f')==item.get('amount') and row['change_id']==item.get('changeId'))
  status.append({'name':item.get('name'),'coordinateId':item.get('coordinateId'),'matchesAtRead':matches})
 return {'matchesAtRead':all(item['matchesAtRead'] for item in status),'sources':status}


def context_status(db,scope,normalized,receipt):
 reasons=[]
 try:
  args=normalized['previewProgram']['arguments'];method=args['methodPreviewProgram']['arguments']
  decision=next(item for item in method['decisions'] if item['relationshipId']==args['relationshipId'])
  if decision['method']!='Equity':reasons.append('METHOD_NOT_EQUITY')
  relationship=db.execute('''SELECT r.parent_member_id,r.child_member_id,r.status FROM epm.relationship r JOIN epm.dimension d ON d.workspace_id=r.workspace_id AND d.application_id=r.application_id AND d.dimension_id=r.dimension_id AND d.model_role='Entity' AND d.status='Active' WHERE r.workspace_id=%s AND r.application_id=%s AND r.relationship_id=%s AND EXISTS(SELECT 1 FROM epm.hierarchy_definition hierarchy
          WHERE hierarchy.workspace_id=r.workspace_id AND hierarchy.application_id=r.application_id
            AND hierarchy.dimension_id=r.dimension_id AND hierarchy.hierarchy_id=r.hierarchy_id
            AND hierarchy.status='Active') ''',(scope.workspace_id,scope.application_id,args['relationshipId'])).fetchone()
  if (not relationship or relationship['status']!='Active'
      or relationship['parent_member_id']!=receipt.get('parentEntityId')
      or relationship['child_member_id']!=receipt.get('childEntityId')):reasons.append('RELATIONSHIP_CHANGED')
  rows=db.execute('''SELECT account_name,amount,change_id FROM epm.ownership_value_current WHERE workspace_id=%s AND application_id=%s AND relationship_id=%s AND scenario_member_id=%s AND year_member_id=%s AND period_member_id=%s AND present AND account_name IN ('POWN','PCON','PCTRL','Active','Method')''',(scope.workspace_id,scope.application_id,args['relationshipId'],method['scenarioId'],method['yearId'],method['periodId'])).fetchall()
  current={row['account_name']:row for row in rows};expected=(receipt.get('lineage') or {}).get('ownership',{})
  for account in ('Active','Method','PCON','PCTRL','POWN'):
   row=current.get(account);pin=expected.get(account)
   if (not row or not pin or row['change_id']!=pin.get('changeId')
       or format(row['amount'],'.8f')!=pin.get('amount')):reasons.append('OWNERSHIP_CHANGED:'+account)
  if current.get('Method') and format(current['Method']['amount'],'.8f')!='2.00000000':reasons.append('METHOD_CODE_CHANGED')
  if current.get('POWN') and format(current['POWN']['amount'],'.8f')!=receipt.get('ownershipShare'):reasons.append('POWN_CHANGED')
  policy=db.execute('''SELECT state_token,definition_digest,family,effective_from,effective_before,required_elections,source_refs FROM epm.policy_pack_draft WHERE workspace_id=%s AND application_id=%s AND policy_id=%s AND state_token=%s AND effective_from<=%s AND effective_before>%s''',(scope.workspace_id,scope.application_id,method['policyId'],method['policyStateToken'],method['effectiveOn'],method['effectiveOn'])).fetchone()
  digest=(policy['definition_digest'] if policy else None)
  if not policy or digest!=method['policyDigest']:reasons.append('POLICY_CHANGED')
 except (KeyError,StopIteration,TypeError,ValueError):reasons.append('CONTEXT_LINEAGE_INVALID')
 return {'matchesAtRead':not reasons,'reasons':sorted(set(reasons))}

class PostgresEquityMethodPublication:
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
  self.dsn,self.identity=dsn,identity
 def _candidate(self,scope,plan):
  result=PostgresEquityMethodContributionPreview(self.dsn,identity=self.identity).preview(scope,plan.document['previewProgram'])
  if (result['previewDigest']!=plan.document['expectedPreviewDigest'] or result['method']!='Equity'
      or result['accountingPolicyStatus']!='Unreviewed' or result['publicationSupported'] is not False
      or result['effects']!='None'):raise ValueError('STALE_EQUITY_PUBLICATION_PREVIEW')
  return result
 def inspect(self,scope,program):
  plan=compile_publication(program);result=self._candidate(scope,plan)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
    state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
    pointer=db.execute('''SELECT committed_revision AS published_revision FROM epm.calculation_result_state WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',(scope.workspace_id,scope.application_id,plan.document['resultKey'])).fetchone()
    if (pointer['published_revision'] if pointer else 0)!=plan.document['expectedPublicationRevision']:raise ValueError('STALE_EQUITY_PUBLICATION_POINTER')
  return plan,result,state
 def admit(self,scope,program,*,idempotency_key):
  plan,_,state=self.inspect(scope,program)
  return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,idempotency_key=idempotency_key,
   function_name=FUNCTION,normalized_program=plan.document,compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
   expected_metadata_revision=state['metadata_revision'],expected_data_revision=state['data_revision'],
   expected_policy_revision=state['policy_revision'],resource_class='short',authorization_function=PUBLIC_FUNCTION)
 def publish(self,claim):
  if not isinstance(claim,dict) or not _JOB.fullmatch(claim.get('job_id','')):raise ValueError('INVALID_WORKER_CLAIM')
  scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
  with connect_postgres(self.dsn,row_factory=dict_row) as before:
   with before.transaction():
    PostgresNumericFactStore._set_scope(before,scope)
    PostgresAccessChecker.check_in_transaction(before,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
    job=before.execute('''SELECT *,lease_until>clock_timestamp() AS unexpired
     FROM epm.job WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
     (scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
    receipt=before.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
    if receipt:
     if not job or receipt['command_digest']!=job['program_digest'] or receipt['actor_id']!=job['subject_id']:raise ValueError('EQUITY_PUBLICATION_RECEIPT_CONFLICT')
     return receipt['result']
    if (not job or job['issuer']!=self.identity.issuer
        or job['subject_id']!=self.identity.subject_id):
     raise ValueError('EQUITY_PUBLICATION_JOB_UNAVAILABLE')
    plan=decode_publication(job['normalized_program'])
    if (job['status']!='running'
        or job['claim_generation']!=claim.get('claim_generation')
        or job['claimant']!=claim.get('claimant') or not job['unexpired']):
     raise ValueError('STALE_WORKER_FENCE')
    if (job['function_name']!=FUNCTION or job['compiler_version']!=COMPILER
        or job['plan_digest']!=PLAN_DIGEST
        or job['program_digest']!=_canonical_digest(job['normalized_program'])):
     raise ValueError('UNSUPPORTED_EQUITY_PUBLICATION_JOB')
  initial_job=job;candidate=self._candidate(scope,plan)
  opening=plan.document['previewProgram']['arguments']['openingCarryingValue']
  source_lineage=[{'kind':'RawCoordinate','name':name,
      'coordinateId':source['coordinateId'],'members':source['members'],
      'amount':source['amount'],'changeId':source['changeId']}
      for name,source in sorted(candidate['lineage']['sources'].items())]
  source_lineage.append({'kind':'EquityMethodContext',
      'relationshipId':candidate['relationshipId'],'method':'Equity',
      'ownershipShare':candidate['ownershipShare'],
      'methodPreviewDigest':candidate['lineage']['methodPreviewDigest'],
      'ownership':candidate['lineage']['ownership'],
      'policy':candidate['lineage']['policy']})
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    state=db.execute('''SELECT s.metadata_revision,s.data_revision,s.policy_revision,s.commit_revision,s.processing_mode,a.status AS application_status FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',(scope.workspace_id,scope.application_id)).fetchone()
    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
    job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s AND application_id=%s AND job_id=%s FOR UPDATE''',(scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
    receipt=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
    if receipt:
     if receipt['command_digest']!=job['program_digest'] or receipt['actor_id']!=job['subject_id']:raise ValueError('EQUITY_PUBLICATION_RECEIPT_CONFLICT')
     return receipt['result']
    immutable=('issuer','subject_id','function_name','normalized_program',
      'program_digest','compiler_version','plan_digest',
      'expected_metadata_revision','expected_data_revision',
      'expected_policy_revision')
    if any(job[key]!=initial_job[key] for key in immutable):
     raise ValueError('STALE_WORKER_FENCE')
    unexpired=db.execute('SELECT %s::timestamptz>clock_timestamp() ok',(job['lease_until'],)).fetchone()['ok']
    if (job['status']!='running' or job['claim_generation']!=claim.get('claim_generation') or job['claimant']!=claim.get('claimant') or not unexpired):raise ValueError('STALE_WORKER_FENCE')
    if (job['function_name']!=FUNCTION or job['compiler_version']!=COMPILER or job['plan_digest']!=PLAN_DIGEST or job['program_digest']!=_canonical_digest(job['normalized_program'])):raise ValueError('UNSUPPORTED_EQUITY_PUBLICATION_JOB')
    if (not state or state['application_status']!='Active' or state['processing_mode']!='Active' or any(state[k]!=job['expected_'+k] for k in ('metadata_revision','data_revision','policy_revision'))):raise ValueError('STALE_JOB_INPUT_REVISION')
    pointer=db.execute('''SELECT committed_revision AS published_revision FROM epm.calculation_result_state WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',(scope.workspace_id,scope.application_id,plan.document['resultKey'])).fetchone()
    if (pointer['published_revision'] if pointer else 0)!=plan.document['expectedPublicationRevision']:raise ValueError('STALE_EQUITY_PUBLICATION_POINTER')
    source_current=source_status(db,scope,{'sourceLookupLineage':source_lineage})
    if not source_current['matchesAtRead']:
     raise ValueError('STALE_EQUITY_PUBLICATION_SOURCE')
    context_current=context_status(db,scope,plan.document,{
      'parentEntityId':candidate['parentEntityId'],
      'childEntityId':candidate['childEntityId'],
      'ownershipShare':candidate['ownershipShare'],
      'lineage':candidate['lineage']})
    if not context_current['matchesAtRead']:
     raise ValueError('STALE_EQUITY_PUBLICATION_CONTEXT')
    enforce_equity_publication_dimensional_security(
     db,self.identity,scope,candidate)
    access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=PUBLIC_FUNCTION)
    target=Coordinate.from_mapping(candidate['targetMembers']);policy=enforce_consolidation_target_policy(db,scope,target,access.role)
    db.execute('''INSERT INTO epm.coordinate(workspace_id,application_id,series_key,members) VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING''',(scope.workspace_id,scope.application_id,target.series_key,Jsonb(dict(target.members))))
    target_row=db.execute('''SELECT coordinate_id,members FROM epm.coordinate WHERE workspace_id=%s AND application_id=%s AND series_key=%s''',(scope.workspace_id,scope.application_id,target.series_key)).fetchone()
    if target_row['members']!=dict(target.members):raise ValueError('COORDINATE_HASH_COLLISION')
    amount=NumericCell.from_wire(present=True,amount=candidate['closingCarryingValueCandidate']).amount;revision=state['commit_revision']+1
    db.execute('''INSERT INTO epm.calculation_operation_staging(workspace_id,application_id,generation_id,job_id,result_key,source_commit_revision,source_metadata_revision,source_policy_revision,function_name,factor,row_count,published_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',(scope.workspace_id,scope.application_id,claim['job_id'],claim['job_id'],plan.document['resultKey'],state['commit_revision'],state['metadata_revision'],state['policy_revision'],FUNCTION,revision))
    db.execute('''INSERT INTO epm.calculation_unit_result_staging(workspace_id,application_id,generation_id,coordinate_id,output_unit_currency_dimension_id,output_unit_currency_member_id,source_amount,source_change_id,amount,rate_strategy,rate_numerator,rate_denominator,rate_sources,source_lookup_lineage) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'identity-same-currency',1,1,%s,%s)''',(scope.workspace_id,scope.application_id,claim['job_id'],target_row['coordinate_id'],candidate['lineage']['currency']['dimensionId'],candidate['lineage']['currency']['memberId'],opening['amount'],opening['changeId'],amount,Jsonb([{'kind':'Identity','currency':candidate['lineage']['currency']}]),Jsonb(source_lineage)))
    result={**candidate,'generationId':claim['job_id'],'resultKey':plan.document['resultKey'],'publishedRevision':revision,'committedRevision':revision,'sourceCommitRevision':state['commit_revision'],'publicationSupported':True,'effects':'CalculatedGenerationOnly','planningPolicy':policy,'sourceLookupLineage':source_lineage}
    from .postgres_calculation_impact import calculation_publication_impact,record_calculation_impact
    impact=calculation_publication_impact(operation_id=claim['job_id'],causal_revision=revision,result_key=plan.document['resultKey'],existed=pointer is not None);result['impactDigest']=impact.digest
    from .postgres_current_result_publication import advance_result_head_during_conversion
    advance_result_head_during_conversion(db,scope,result_key=plan.document['resultKey'],operation_id=claim['job_id'],committed_revision=revision)
    db.execute('''UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(revision,scope.workspace_id,scope.application_id))
    db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,claim['job_id'],job['program_digest'],job['subject_id'],revision,Jsonb(result)))
    record_calculation_impact(db,scope,operation_id=claim['job_id'],impact=impact)
    finish_published_job(db,scope,claim,revision=revision,result=result)
    return result
