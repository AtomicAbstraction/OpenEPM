"""Private fixed-core boundary for atomic populated-layout activation."""
from hashlib import sha256
import json,re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_access import (PostgresAccessChecker,VerifiedIdentity,
                              durable_authority_fields,
                              durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout

_HEX32=re.compile(r'^[0-9a-f]{32}$');_HEX64=re.compile(r'^[0-9a-f]{64}$');_KEY=re.compile(r'^[A-Za-z0-9._-]{8,128}$')
REQUEST='metadata.layout.populated.activate.request'
READ='metadata.layout.populated.activate.read'
CANCEL='metadata.layout.populated.activate.cancel'
PUBLIC_FUNCTIONS=frozenset((REQUEST,READ,CANCEL))
_PIN_KEYS=('metadataRevision','dataRevision','policyRevision','schemaEpoch','sourceCommitRevision')
def _digest(v):return sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()

def _pins(value):
 if (not isinstance(value,dict) or set(value)!=set(_PIN_KEYS)
  or any(type(value[key]) is not int or value[key]<0 for key in _PIN_KEYS)):
  raise ValueError('LAYOUT_ACTIVATION_PINS_INVALID')
 return value

class PostgresPopulatedLayoutActivation:
 def __init__(self,dsn,*,identity):
  if not dsn or not isinstance(identity,VerifiedIdentity):raise ValueError('Activation DSN and verified identity required')
  self.dsn,self.identity=dsn,identity
 def execute(self,scope,program):
  if (not isinstance(program,dict) or set(program)!= {'languageVersion','function','arguments'}
   or type(program.get('languageVersion')) is not int or program['languageVersion']!=2
   or program.get('function') not in PUBLIC_FUNCTIONS or not isinstance(program.get('arguments'),dict)):
   raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
  function,args=program['function'],program['arguments']
  if function==REQUEST:
   if set(args)!= {'requestId','targetGenerationId','validationDigest','expectedPins','dependencyDecisions','idempotencyKey'}:
    raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
   return self.request(scope,request_id=args['requestId'],target_generation_id=args['targetGenerationId'],
    validation_digest=args['validationDigest'],expected_pins=args['expectedPins'],
    dependency_decisions=args['dependencyDecisions'],idempotency_key=args['idempotencyKey'])
  if function==READ:
   if set(args)!= {'activationId'}:raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
   return self.read(scope,args['activationId'])
  if set(args)!= {'activationId','expectedStatus','expectedStateVersion'}:
   raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
  return self.cancel(scope,args['activationId'],expected_status=args['expectedStatus'],
   expected_state_version=args['expectedStateVersion'])
 def request(self,scope,*,request_id,target_generation_id,validation_digest,expected_pins,dependency_decisions,idempotency_key):
  if (not isinstance(scope,ApplicationScope) or not _HEX32.fullmatch(request_id or '')
   or not _HEX32.fullmatch(target_generation_id or '')
   or not _HEX64.fullmatch(validation_digest or '') or not _KEY.fullmatch(idempotency_key or '')
   or not isinstance(dependency_decisions,list) or len(dependency_decisions)>10000):raise ValueError('LAYOUT_ACTIVATION_REQUEST_INVALID')
  pins=_pins(expected_pins)
  seen=set()
  for d in dependency_decisions:
   if (not isinstance(d,dict) or set(d)!= {'kind','id','decision'} or d['kind'] not in ('rule','publication')
    or d['decision'] not in ('Compatible','Invalidate','Rebuild') or not isinstance(d['id'],str)
    or not 1<=len(d['id'])<=256
    or (d['kind'],d['id']) in seen):raise ValueError('LAYOUT_ACTIVATION_DECISION_INVALID')
   seen.add((d['kind'],d['id']))
  decisions=sorted(dependency_decisions,key=lambda d:(d['kind'],d['id']))
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    authorization_scope_digest=resolve_effective_dimensional_scope(
     db,self.identity,scope,access=access,
     function=REQUEST).scope_digest
    descriptor={'scope':[scope.workspace_id,scope.application_id],
     'identity':[self.identity.issuer,self.identity.subject_id],
     'verifiedGroups':list(self.identity.groups),
     'authorizationScopeDigest':authorization_scope_digest,
     'requestId':request_id,'targetGenerationId':target_generation_id,
     'validationDigest':validation_digest,'expectedPins':pins,
     'dependencyDecisions':decisions,'idempotencyKey':idempotency_key}
    rdigest=_digest(descriptor);aid=sha256((rdigest+':activation').encode()).hexdigest()[:32]
    prior=db.execute('''SELECT activation_id,status,request_digest,
     verified_groups,authorization_scope_digest FROM epm.layout_replacement_activation
     WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
     (scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,idempotency_key)).fetchone()
    if prior:
     if (prior['request_digest']!=rdigest
      or tuple(prior['verified_groups'])!=self.identity.groups
      or prior['authorization_scope_digest'] is None
      or prior['authorization_scope_digest']!=authorization_scope_digest):
      raise ValueError('LAYOUT_ACTIVATION_IDEMPOTENCY_CONFLICT')
     return {'activationId':prior['activation_id'],'status':prior['status'],'duplicate':True}
    certificate=db.execute('''SELECT c.generation_id,c.validation_digest,c.activation_eligible,
     c.metadata_revision,c.data_revision,c.policy_revision,c.schema_epoch,c.source_commit_revision,r.status
     FROM epm.layout_replacement_validation_certificate c JOIN epm.layout_replacement_request r
      USING(workspace_id,application_id,request_id)
     WHERE c.workspace_id=%s AND c.application_id=%s AND c.request_id=%s''',
     (scope.workspace_id,scope.application_id,request_id)).fetchone()
    actual_pins=(None if not certificate else {'metadataRevision':certificate['metadata_revision'],
     'dataRevision':certificate['data_revision'],'policyRevision':certificate['policy_revision'],
     'schemaEpoch':certificate['schema_epoch'],'sourceCommitRevision':certificate['source_commit_revision']})
    if (not certificate or certificate['status']!='Validated' or not certificate['activation_eligible']
     or certificate['generation_id']!=target_generation_id or certificate['validation_digest']!=validation_digest
     or actual_pins!=pins):raise ValueError('LAYOUT_ACTIVATION_VALIDATION_STALE')
    token_issued_at,authority_kind=durable_authority_fields(self.identity)
    result=db.execute('SELECT epm.layout_replacement_activation_authority_request(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS result',
     (scope.workspace_id,scope.application_id,aid,request_id,idempotency_key,rdigest,self.identity.issuer,
      self.identity.subject_id,validation_digest,Jsonb(decisions),list(self.identity.groups),
      authorization_scope_digest,token_issued_at,
      authority_kind)).fetchone()['result']
    return result
 def read(self,scope,activation_id):
  if not _HEX32.fullmatch(activation_id or ''):raise ValueError('LAYOUT_ACTIVATION_ID_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope)
    access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    authorization_scope_digest=resolve_effective_dimensional_scope(
     db,self.identity,scope,access=access,function=READ).scope_digest
    r=db.execute('''SELECT x.activation_id,x.request_id,x.status,x.validation_digest,x.dependency_decisions,
     c.generation_id,c.activation_eligible,
     x.source_schema_epoch,x.target_schema_epoch,
     x.source_projection_generation,x.target_projection_generation,x.source_metadata_revision,x.source_data_revision,
     x.source_policy_revision,x.source_commit_revision,x.claim_generation,x.error_code,x.result,
     x.verified_groups,x.authorization_scope_digest
     FROM epm.layout_replacement_activation x JOIN epm.layout_replacement_validation_certificate c
      USING(workspace_id,application_id,request_id)
     WHERE x.workspace_id=%s AND x.application_id=%s AND x.activation_id=%s''',
     (scope.workspace_id,scope.application_id,activation_id)).fetchone()
    if not r:raise ValueError('LAYOUT_ACTIVATION_NOT_FOUND')
    if (tuple(r['verified_groups'])!=self.identity.groups
     or r['authorization_scope_digest'] is None
     or r['authorization_scope_digest']!=authorization_scope_digest):
     raise ValueError('LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CHANGED')
    pins={'metadataRevision':r['source_metadata_revision'],'dataRevision':r['source_data_revision'],
      'policyRevision':r['source_policy_revision'],'schemaEpoch':r['source_schema_epoch'],
      'sourceCommitRevision':r['source_commit_revision']}
    return {'activationId':r['activation_id'],'requestId':r['request_id'],'targetGenerationId':r['generation_id'],
     'status':r['status'],'dependencyDecisions':r['dependency_decisions'],
     'certificate':{'validationDigest':r['validation_digest'],'activationEligible':r['activation_eligible'],'pins':pins},
     'targetSchemaEpoch':r['target_schema_epoch'],'sourceProjectionGeneration':r['source_projection_generation'],
     'targetProjectionGeneration':r['target_projection_generation'],'stateVersion':r['claim_generation'],
     'errorCode':r['error_code'],'receipt':r['result']}
 def cancel(self,scope,activation_id,*,expected_status,expected_state_version):
  if (not _HEX32.fullmatch(activation_id or '') or expected_status!='Requested'
   or type(expected_state_version) is not int or expected_state_version<0):
   raise ValueError('LAYOUT_ACTIVATION_CANCEL_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    changed=db.execute('SELECT epm.layout_replacement_activation_cancel(%s,%s,%s,%s,%s) AS changed',
     (scope.workspace_id,scope.application_id,activation_id,expected_status,expected_state_version)).fetchone()['changed']
    if not changed:raise ValueError('LAYOUT_ACTIVATION_STATE_STALE')
    return {'activationId':activation_id,'status':'Cancelled','stateVersion':expected_state_version+1}
 def request_cancel_as_task_controller(self,scope,activation_id):
  """Cancel an unclaimed activation through its native fence as current admin."""
  if (not isinstance(scope,ApplicationScope)
   or not isinstance(activation_id,str) or not _HEX32.fullmatch(activation_id)):
   raise ValueError('LAYOUT_ACTIVATION_ID_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope)
    PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    row=db.execute('''SELECT status,claim_generation
     FROM epm.layout_replacement_activation WHERE workspace_id=%s
     AND application_id=%s AND activation_id=%s''',
     (scope.workspace_id,scope.application_id,activation_id)).fetchone()
    if not row:raise ValueError('LAYOUT_ACTIVATION_NOT_FOUND')
    if row['status']=='Cancelled':
     return {'activationId':activation_id,'status':'Cancelled',
      'stateVersion':row['claim_generation']}
    if row['status']!='Requested':raise ValueError('LAYOUT_ACTIVATION_STATE_STALE')
    changed=db.execute('SELECT epm.layout_replacement_activation_cancel(%s,%s,%s) AS changed',
     (scope.workspace_id,scope.application_id,activation_id)).fetchone()['changed']
    if not changed:raise ValueError('LAYOUT_ACTIVATION_STATE_STALE')
    return {'activationId':activation_id,'status':'Cancelled',
     'stateVersion':row['claim_generation']+1}

class PostgresPopulatedLayoutActivator:
 def __init__(self,worker_dsn,runtime_dsn):
  if not worker_dsn or not runtime_dsn:raise ValueError('Worker and runtime DSNs are required')
  self.dsn,self.runtime_dsn=worker_dsn,runtime_dsn
 def claim(self,scope,activation_id,*,claimant,lease_seconds=120):
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   r=db.execute('''SELECT * FROM epm.layout_replacement_activation_authority_claim(
    %s,%s,%s,%s,%s::integer)''',
    (scope.workspace_id,scope.application_id,activation_id,claimant,lease_seconds)).fetchone()
  return dict(r) if r else None
 def publish(self,scope,activation_id,*,claimant,claim_generation):
  with connect_postgres(self.runtime_dsn,row_factory=dict_row) as authority:
   with authority.transaction():
    PostgresNumericFactStore._set_scope(authority,scope)
    row=authority.execute('''SELECT issuer,subject_id,verified_groups,
     authorization_scope_digest,token_issued_at,authority_kind,
     status,claimant,claim_generation
     FROM epm.layout_replacement_activation WHERE workspace_id=%s
       AND application_id=%s AND activation_id=%s''',
     (scope.workspace_id,scope.application_id,activation_id)).fetchone()
    if row is None:raise ValueError('LAYOUT_ACTIVATION_NOT_FOUND')
    identity=durable_execution_identity(row)
    access=PostgresAccessChecker.check_in_transaction(
     authority,identity,scope,'admin')
    current_scope=resolve_effective_dimensional_scope(
     authority,identity,scope,access=access,function=REQUEST).scope_digest
    if (row['authorization_scope_digest'] is None
     or row['authorization_scope_digest']!=current_scope):
     raise ValueError('LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CHANGED')
    with connect_postgres(self.dsn,row_factory=dict_row) as worker:
     with worker.transaction():
      PostgresNumericFactStore._set_scope(worker,scope)
      return worker.execute('SELECT epm.layout_replacement_activation_publish(%s,%s,%s,%s,%s) AS result',
       (scope.workspace_id,scope.application_id,activation_id,claimant,claim_generation)).fetchone()['result']
