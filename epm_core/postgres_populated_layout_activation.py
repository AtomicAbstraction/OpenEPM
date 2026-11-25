"""Private fixed-core boundary for atomic populated-layout activation."""
from hashlib import sha256
import json,re
from psycopg.errors import RaiseException, UniqueViolation
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
from .postgres_populated_layout_preview import DEPENDENCY_REFUSALS, authorize_layout_plan_read

_HEX32=re.compile(r'^[0-9a-f]{32}$');_HEX64=re.compile(r'^[0-9a-f]{64}$');_KEY=re.compile(r'^[A-Za-z0-9._-]{8,128}$')
REQUEST='metadata.layout.populated.activate.request'
READ='metadata.layout.populated.activate.read'
CANCEL='metadata.layout.populated.activate.cancel'
PUBLIC_FUNCTIONS=frozenset((REQUEST,READ,CANCEL))
_STATUSES=('Requested','Activating','Activated','Failed','Cancelled')
_ADMISSION_REFUSALS = DEPENDENCY_REFUSALS | {
 'LAYOUT_ACTIVATION_VALIDATION_STALE', 'LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED',
 'LAYOUT_DEPENDENCY_CERTIFICATE_STALE', 'LAYOUT_SOURCE_INVENTORY_STALE',
}
RECOVERY_GUIDANCE=(
 'A persisted pre-384 validation certificate without dependencyContext is immutable. LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED refuses new admission or publication; the certificate cannot be enriched in place. Read current metadata.layout.populated.source.read, obtain a fresh current metadata.layout.populated.preview, and use a new replacement idempotency key and private generation. Re-enumerate complete current dependency decisions and follow ordinary staging, materialization, validation and activation; retain the old certificate as evidence.',
 'An exact old activate.request idempotency replay may retrieve its existing Requested identity. Duplicate retrieval is not fresh admission, validation or publication; repeating the old key does not repair an unbound certificate.',
 'Read the existing activation before recovery. A current authorized administrator can cancel Requested using metadata.layout.populated.activate.cancel with the exact expectedStatus and expectedStateVersion. Activating cannot be cancelled directly: only the existing worker lease-expiry recovery can return it to Requested with a new stateVersion, after which the administrator can cancel. The maintained worker performs bounded lease-expiry recovery; progress still requires an active worker, current authority and available capacity. This is not a client recovery route or authority bypass.',
 'A Staged generation with no persisted certificate progresses only when replace.read reports automaticProgressionSupported and current source inventory, pins, materialization and original authority still match. Old unsealed replacement rows require a fresh replacement with explicit dependency decisions; they are not adopted or enriched. A persisted eligible 384 certificate can still support a separate newly authorized explicit activation request when its current pins/context match. A persisted Validated certificate is not rewritten; stale source or authority requires a fresh current replacement workflow.'
)
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
 def execute(self,scope,program,*,replay_only=False):
  if (not isinstance(program,dict) or set(program)!= {'languageVersion','function','arguments'}
   or type(program.get('languageVersion')) is not int or program['languageVersion']!=2
   or program.get('function') not in PUBLIC_FUNCTIONS or not isinstance(program.get('arguments'),dict)):
   raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
  function,args=program['function'],program['arguments']
  if replay_only and function!=REQUEST:
   raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
  if function==REQUEST:
   if set(args)!= {'requestId','targetGenerationId','validationDigest','expectedPins','dependencyDecisions','idempotencyKey'}:
    raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
   return self.request(scope,request_id=args['requestId'],target_generation_id=args['targetGenerationId'],
    validation_digest=args['validationDigest'],expected_pins=args['expectedPins'],
    dependency_decisions=args['dependencyDecisions'],idempotency_key=args['idempotencyKey'],
    replay_only=replay_only)
  if function==READ:
   if set(args)!= {'activationId'}:raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
   return self.read(scope,args['activationId'])
  if set(args)!= {'activationId','expectedStatus','expectedStateVersion'}:
   raise ValueError('V2_LAYOUT_ACTIVATION_INVALID')
  return self.cancel(scope,args['activationId'],expected_status=args['expectedStatus'],
   expected_state_version=args['expectedStateVersion'])

 def _existing_request(self,db,scope,idempotency_key,request_digest,access,scope_digest):
  prior=db.execute('''SELECT activation_id,status,request_digest,
   verified_groups,authorization_scope_digest FROM epm.layout_replacement_activation
   WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
   (scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,idempotency_key)).fetchone()
  if prior is None:
   return None
  if (prior['request_digest']!=request_digest
   or tuple(prior['verified_groups'])!=access.groups
   or prior['authorization_scope_digest'] is None
   or prior['authorization_scope_digest']!=scope_digest):
   raise ValueError('LAYOUT_ACTIVATION_IDEMPOTENCY_CONFLICT')
  return {'activationId':prior['activation_id'],'status':prior['status'],'duplicate':True}

 def request(self,scope,*,request_id,target_generation_id,validation_digest,expected_pins,
             dependency_decisions,idempotency_key,replay_only=False):
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
    if replay_only:
     db.execute('SET TRANSACTION READ ONLY')
    PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    authorization_scope_digest=resolve_effective_dimensional_scope(
     db,self.identity,scope,access=access,
     function=REQUEST).scope_digest
    descriptor={'scope':[scope.workspace_id,scope.application_id],
     'identity':[self.identity.issuer,self.identity.subject_id],
     'verifiedGroups':list(access.groups),
     'authorizationScopeDigest':authorization_scope_digest,
     'requestId':request_id,'targetGenerationId':target_generation_id,
     'validationDigest':validation_digest,'expectedPins':pins,
     'dependencyDecisions':decisions,'idempotencyKey':idempotency_key}
    rdigest=_digest(descriptor);aid=sha256((rdigest+':activation').encode()).hexdigest()[:32]
    prior=self._existing_request(db,scope,idempotency_key,rdigest,access,authorization_scope_digest)
    if prior is not None or replay_only:
     return prior
    certificate=db.execute('''SELECT c.generation_id,c.validation_digest,c.activation_eligible,
     c.metadata_revision,c.data_revision,c.policy_revision,c.schema_epoch,c.source_commit_revision,r.status,r.plan
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
    authorize_layout_plan_read(db,self.identity,scope,access,certificate['plan'])
    token_issued_at,authority_kind=durable_authority_fields(self.identity)
    try:
     # A conflicting insert aborts only the attempted admission. The enclosing
     # transaction retains the workspace fence for an exact current lookup.
     with db.transaction():
      return db.execute('SELECT epm.layout_replacement_activation_authority_request(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS result',
       (scope.workspace_id,scope.application_id,aid,request_id,idempotency_key,rdigest,self.identity.issuer,
        self.identity.subject_id,validation_digest,Jsonb(decisions),list(access.groups),
        authorization_scope_digest,token_issued_at,authority_kind)).fetchone()['result']
    except UniqueViolation as error:
     if (error.diag.schema_name,error.diag.table_name)!=('epm','layout_replacement_activation'):
      raise
    except RaiseException as error:
     code = error.diag.message_primary
     if code in _ADMISSION_REFUSALS:
      raise ValueError(code) from error
     if code not in ('LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CONFLICT',
                     'LAYOUT_ACTIVATION_IDEMPOTENCY_CONFLICT'):
      raise
    current=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    current_digest=resolve_effective_dimensional_scope(db,self.identity,scope,
     access=current,function=REQUEST).scope_digest
    if current!=access or current_digest!=authorization_scope_digest:
     raise ValueError('LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CHANGED')
    prior=self._existing_request(db,scope,idempotency_key,rdigest,current,current_digest)
    if prior is None:
     raise ValueError('LAYOUT_ACTIVATION_REQUEST_CONFLICT')
    return prior
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
    if (tuple(r['verified_groups'])!=access.groups
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
    row=authority.execute('''SELECT x.issuer,x.subject_id,x.verified_groups,
     x.authorization_scope_digest,x.token_issued_at,x.authority_kind,
     x.status,x.claimant,x.claim_generation,r.plan
     FROM epm.layout_replacement_activation x JOIN epm.layout_replacement_request r
       USING(workspace_id,application_id,request_id)
     WHERE x.workspace_id=%s AND x.application_id=%s AND x.activation_id=%s''',
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
    # Only an immutable completed receipt can bypass the prospective source read.
    if row['status']!='Activated':
     authorize_layout_plan_read(authority,identity,scope,access,row['plan'])
    with connect_postgres(self.dsn,row_factory=dict_row) as worker:
     with worker.transaction():
      PostgresNumericFactStore._set_scope(worker,scope)
      return worker.execute('SELECT epm.layout_replacement_activation_publish(%s,%s,%s,%s,%s) AS result',
       (scope.workspace_id,scope.application_id,activation_id,claimant,claim_generation)).fetchone()['result']


def read_program_contract(function):
 if function != READ:
  return None
 from .metadata_read_contract import read_contract, read_example, obj
 identifier={'type':'string','pattern':'^[0-9a-f]{32}$'}
 digest={'type':'string','pattern':'^[0-9a-f]{64}$'}
 count={'type':'integer','minimum':0}
 pins=obj({key:count for key in _PIN_KEYS})
 receipt_fields={'activationId':identifier,'requestId':identifier,
  'committedRevision':count,'schemaEpoch':count,'projectionGeneration':count,
  'historyPreserved':{'const':True},'addedDimensionId':{'type':'string','minLength':1,'maxLength':200}}
 receipt=obj(receipt_fields,[key for key in receipt_fields if key!='addedDimensionId'])
 result=obj({'activationId':identifier,'requestId':identifier,'targetGenerationId':identifier,
  'status':{'enum':list(_STATUSES)},
  'dependencyDecisions':{'type':'array','maxItems':10000,'items':obj({
   'kind':{'enum':['rule','publication']},'id':{'type':'string','minLength':1,'maxLength':256},
   'decision':{'enum':['Compatible','Invalidate','Rebuild']}})},
  'certificate':obj({'validationDigest':digest,'activationEligible':{'type':'boolean'},'pins':pins}),
  'targetSchemaEpoch':count,'sourceProjectionGeneration':count,'targetProjectionGeneration':count,
  'stateVersion':count,'errorCode':{'type':['string','null']},
  'receipt':{'anyOf':[{'type':'null'},receipt]}})
 return read_contract(function,obj({'activationId':identifier}),result,
  owner='PostgresPopulatedLayoutActivation.read',
  examples=[read_example(function,{'activationId':'a'*32},name='Read an existing layout activation',
   binding='Use the activationId returned by the authorized activate.request operation; reading it creates no replacement or activation.')],
  semantic_rules=['Current administrator and original verified-group/dimensional-authority bindings remain authoritative.',
   'The receipt is the retained publication outcome when present, including the optional addedDimensionId of a v2 added-axis plan; it is not a request acknowledgement.',
   'Read status/certificate/current counters without automatic cancellation, reissue or migration.',
   'Construct kind/id/decision intents from every page of application.rule.list, calculated.member.list and rules.expression.list (active rows), plus facts.calculation.publication.list. Current state/content tokens are bound by the server in the certificate; they are not additional request fields.',
   'Dependency decisions bind the complete server-derived current rule/result inventory. Compatible requires an unchanged complete logical layout; it does not preserve freshness across the metadata/schema cut. Invalidate and Rebuild retain source, values and provenance and require ordinary current-owner revalidation/republication; activation queues no rebuild.', *RECOVERY_GUIDANCE])


def effect_program_contract(function):
    from .metadata_read_contract import obj, read_contract, read_example

    identifier = {'type': 'string', 'pattern': r'^[0-9a-f]{32}(?![\s\S])'}
    count = {'type': 'integer', 'minimum': 0}
    if function == CANCEL:
        contract = read_contract(CANCEL, obj({'activationId': identifier,
            'expectedStatus': {'const': 'Requested'}, 'expectedStateVersion': count}),
            obj({'activationId': identifier, 'status': {'const': 'Cancelled'}, 'stateVersion': count}),
            owner='PostgresPopulatedLayoutActivation.cancel', examples=[
                read_example(CANCEL, {'activationId': 'a' * 32, 'expectedStatus': 'Requested',
                    'expectedStateVersion': 0}, name='Cancel a pending populated-layout activation',
                    binding='Read activate.read and copy its actual activationId, Requested status and stateVersion.')],
            semantic_rules=['Only a current Requested activation at the exact stateVersion can be cancelled.',
                'A claimed activation must settle or undergo native lease-expiry recovery before it can be considered for cancellation.'])
        contract['programContract']['recovery'] = (
            'Read activate.read after an interrupted cancellation or stale version. '
            'Use the current Requested state and exact version before reviewing another cancellation.')
        return contract
    if function != REQUEST:
        return None
    read_result = read_program_contract(READ)['resultSchema']['properties']['result']['properties']
    arguments = obj({'requestId': identifier, 'targetGenerationId': identifier,
        'validationDigest': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'},
        'expectedPins': obj({key: count for key in _PIN_KEYS}),
        'dependencyDecisions': read_result['dependencyDecisions'],
        'idempotencyKey': {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'}})
    outcome = {'oneOf': [obj({'activationId': identifier, 'status': {'const': 'Requested'},
        'duplicate': {'const': False}, 'targetSchemaEpoch': count, 'targetProjectionGeneration': count}),
        obj({'activationId': identifier, 'status': {'enum': list(_STATUSES)}, 'duplicate': {'const': True}})]}
    contract = read_contract(REQUEST, arguments, outcome,
        owner='PostgresPopulatedLayoutActivation.request', examples=[
            read_example(REQUEST, {'requestId': 'a' * 32, 'targetGenerationId': 'b' * 32,
                'validationDigest': 'c' * 64, 'expectedPins': dict(zip(_PIN_KEYS, (8, 2, 3, 4, 10))),
                'dependencyDecisions': [], 'idempotencyKey': 'reviewed-activation-001'},
                name='Request activation of a verified private generation',
                binding='Read replace.read and use its validated request, target generation, eligible certificate digest and pins. Supply the complete current dependency decisions, with an empty list only for an empty inventory.')],
        semantic_rules=['Requested is a durable acknowledgement. Use activate.read for the current status and the committed receipt after publication.',
            'The first acknowledgement exposes the target schema epoch and projection generation. An exact repeat returns the original identity and its current status.',
            'Fresh activation admission and worker publication require current dimensional READ on every source coordinate in the stored plan.',
            'Current administrator authority and the original dimensional scope are checked after an overlapping submission settles.',
            *RECOVERY_GUIDANCE])
    contract['programContract']['recovery'] = (
        'Use activate.read with the original activationId. If the ID was lost, repeat only the unchanged program and its native key with the original signed admission ID. '
        'An expired signed request can retrieve an original only. '
        'LAYOUT_ACTIVATION_REQUEST_CONFLICT means an overlapping or existing activation prevents this admission. '
        'Check the relevant current tasks and replacement before reviewing new intent.')
    return contract
