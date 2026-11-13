"""Trusted registration of deployment-approved Python build environments."""
from __future__ import annotations
from dataclasses import dataclass,field
from hashlib import sha256
import json,re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .current_object_contract import new_state_token,require_state_token

_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')
_KEY=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{7,127}\Z')
_IMAGE=re.compile(r'sha256:[0-9a-f]{64}\Z')
REGISTER='python.environment.register'
READ='python.environment.read'
LIST='python.environment.list'
PROFILE_LIST='python.environment.profile.list'
def _canonical(value,code):
 try:return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
 except (TypeError,ValueError) as error:raise ValueError(code) from error

@dataclass(frozen=True)
class ApprovedPythonEnvironment:
 profile_id:str;image_digest:str;manifest:dict
 _manifest_json:str=field(init=False,repr=False)
 def __post_init__(self):
  manifest=_canonical(self.manifest,'PYTHON_ENVIRONMENT_MANIFEST_INVALID')
  if (not isinstance(self.profile_id,str) or not _ID.fullmatch(self.profile_id)
      or not isinstance(self.image_digest,str) or not _IMAGE.fullmatch(self.image_digest)
      or type(self.manifest) is not dict or len(manifest.encode())>1_048_576):
   raise ValueError('PYTHON_ENVIRONMENT_PROFILE_INVALID')
  object.__setattr__(self,'_manifest_json',manifest)

class PostgresPythonEnvironments:
 def __init__(self,dsn,*,identity,approved_profiles):
  if (not isinstance(identity,VerifiedIdentity) or not isinstance(approved_profiles,tuple)
      or any(not isinstance(p,ApprovedPythonEnvironment) for p in approved_profiles)
      or len({p.profile_id for p in approved_profiles})!=len(approved_profiles)):
   raise ValueError('PYTHON_ENVIRONMENT_CONFIGURATION_INVALID')
  assert_nonowner_role(dsn,'epm_runtime',('python_environment_definition',))
  self.dsn,self.identity=dsn,identity
  self._profiles={p.profile_id:p for p in approved_profiles}
 @staticmethod
 def catalog():
  read={'mode':'read_only','permission':'admin','previewRequired':False,
   'idempotencyRequired':False,'workClass':'short'}
  return {REGISTER:{'mode':'atomic_write','permission':'admin',
   'previewRequired':False,'idempotencyRequired':True,'workClass':'short',
   'arguments':{'environmentId':'1-200 safe characters',
    'profileId':'deployment-approved profile identity; never an image supplied by the caller',
    'expectedMetadataRevision':'exact current nonnegative revision',
    'expectedPolicyRevision':'exact current nonnegative revision',
    'expectedSchemaEpoch':'exact current nonnegative epoch'},
   'optionalArguments':{'expectedStateToken':'required to replace the current environment'},
   'result':'one current active environment, opaque state token, deployment-owned image digest and committed receipt'},
   READ:{**read,'arguments':{'environmentId':'stable environment ID'},
    'result':'current registered immutable environment'},
   LIST:{**read,'arguments':{'limit':'1-100','afterEnvironmentId':'optional keyset'},
    'result':'bounded registered environment page'},
   PROFILE_LIST:{**read,'arguments':{},
    'result':'deployment-approved registration profiles; no caller image input'}}
 def execute(self,scope,program,*,idempotency_key):
  if (type(program) is not dict or set(program)!={'languageVersion','function','arguments'}
      or program.get('languageVersion')!=2 or program.get('function')!=REGISTER
      or type(program.get('arguments')) is not dict):
   raise ValueError('PYTHON_ENVIRONMENT_PROGRAM_INVALID')
  args=program['arguments']
  required={'environmentId','profileId','expectedMetadataRevision',
            'expectedPolicyRevision','expectedSchemaEpoch'}
  if set(args) not in (required,required|{'expectedStateToken'}):
   raise ValueError('PYTHON_ENVIRONMENT_PROGRAM_INVALID')
  return self.register(scope,environment_id=args['environmentId'],
   profile_id=args['profileId'],expected_metadata_revision=args['expectedMetadataRevision'],
   expected_policy_revision=args['expectedPolicyRevision'],
   expected_schema_epoch=args['expectedSchemaEpoch'],idempotency_key=idempotency_key,
   expected_state_token=args.get('expectedStateToken'))
 def read(self,scope,program):
  if (not isinstance(scope,ApplicationScope) or type(program) is not dict
      or set(program)!={'languageVersion','function','arguments'}
      or program.get('languageVersion')!=2
      or program.get('function') not in (READ,LIST,PROFILE_LIST)
      or type(program.get('arguments')) is not dict):
   raise ValueError('PYTHON_ENVIRONMENT_PROGRAM_INVALID')
  function=program['function'];args=program['arguments']
  if function==READ:
   if set(args)!={'environmentId'} or not isinstance(args['environmentId'],str) or not _ID.fullmatch(args['environmentId']):
    raise ValueError('PYTHON_ENVIRONMENT_ARGUMENT_INVALID')
   after=None;limit=1
  elif function==LIST:
   if set(args)-{'limit','afterEnvironmentId'} or type(args.get('limit',100)) is not int or not 1<=args.get('limit',100)<=100:
    raise ValueError('PYTHON_ENVIRONMENT_ARGUMENT_INVALID')
   after=args.get('afterEnvironmentId');limit=args.get('limit',100)
   if after is not None and (not isinstance(after,str) or not _ID.fullmatch(after)):
    raise ValueError('PYTHON_ENVIRONMENT_ARGUMENT_INVALID')
  elif args:
   raise ValueError('PYTHON_ENVIRONMENT_ARGUMENT_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    db.execute('SET TRANSACTION READ ONLY');configure_statement_timeout(db,5000)
    PostgresNumericFactStore._set_scope(db,scope)
    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=function)
    if function==PROFILE_LIST:
     return {'profiles':[{'profileId':profile.profile_id,
       'environmentId':profile.manifest['environmentId'],
       'imageDigest':profile.image_digest,
       'network':profile.manifest.get('network'),
       'compilerVersions':profile.manifest.get('compilerVersions',[])}
       for profile in sorted(self._profiles.values(),key=lambda value:value.profile_id)]}
    rows=db.execute('''SELECT environment_id,state_token,status,
      manifest,manifest_digest,image_digest,updated_at
      FROM epm.python_environment_definition
      WHERE workspace_id=%s AND application_id=%s
      AND (%s::text IS NULL OR environment_id>%s)
      AND (%s::text IS NULL OR environment_id=%s)
      ORDER BY environment_id LIMIT %s''',(scope.workspace_id,scope.application_id,
      after,after,args.get('environmentId'),args.get('environmentId'),limit+1)).fetchall()
    values=[dict(row) for row in rows[:limit]]
    return ({'defined':bool(values),'environment':values[0] if values else None}
      if function==READ else {'environments':values,
       'nextAfterEnvironmentId':rows[limit-1]['environment_id'] if len(rows)>limit else None})
 def register(self,scope,*,environment_id,profile_id,expected_state_token,
              expected_metadata_revision,expected_policy_revision,
              expected_schema_epoch,idempotency_key):
  if (not isinstance(scope,ApplicationScope) or not isinstance(environment_id,str)
      or not _ID.fullmatch(environment_id)
      or not isinstance(profile_id,str) or profile_id not in self._profiles
      or any(type(v) is not int or v<0 for v in (expected_metadata_revision,
        expected_policy_revision,expected_schema_epoch))
      or not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key)):
   raise ValueError('PYTHON_ENVIRONMENT_ARGUMENT_INVALID')
  if expected_state_token is not None:
   require_state_token(expected_state_token,error='PYTHON_ENVIRONMENT_STATE_TOKEN_INVALID')
  profile=self._profiles[profile_id];manifest=json.loads(profile._manifest_json)
  # The durable environment identity is also the host launcher's allow-list
  # key.  Permitting a caller-chosen alias would create a registry entry that
  # can be admitted but can never be resolved by the isolated launcher.
  if environment_id != manifest.get('environmentId'):
   raise ValueError('PYTHON_ENVIRONMENT_PROFILE_IDENTITY_MISMATCH')
  manifest_digest=sha256(profile._manifest_json.encode()).hexdigest()
  request={'scope':[scope.workspace_id,scope.application_id],
   'identity':[self.identity.issuer,self.identity.subject_id],
   'environmentId':environment_id,'expectedStateToken':expected_state_token,
   'profileId':profile.profile_id,
   'imageDigest':profile.image_digest,'manifestDigest':manifest_digest,
   'pins':[expected_metadata_revision,expected_policy_revision,expected_schema_epoch]}
  digest=sha256(_canonical(request,'PYTHON_ENVIRONMENT_ARGUMENT_INVALID').encode()).hexdigest()
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);PostgresNumericFactStore._set_scope(db,scope)
    PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    state=db.execute('''SELECT s.metadata_revision,s.policy_revision,s.schema_epoch,
      s.commit_revision,s.processing_mode,a.status application_status
      FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
      WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
      (scope.workspace_id,scope.application_id)).fetchone()
    if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
    prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
      WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
      (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
    if prior is not None:
     if prior['command_digest']!=digest or prior['actor_id']!=self.identity.subject_id:
      raise ValueError('PYTHON_ENVIRONMENT_IDEMPOTENCY_CONFLICT')
     return prior['result']
    if state['application_status']!='Active' or state['processing_mode']!='Active':
     raise ValueError('APPLICATION_NOT_WRITABLE')
    if (state['metadata_revision']!=expected_metadata_revision or
        state['policy_revision']!=expected_policy_revision or
        state['schema_epoch']!=expected_schema_epoch):
     raise ValueError('PYTHON_ENVIRONMENT_STALE_CONTEXT')
    current=db.execute('''SELECT state_token FROM epm.python_environment_definition
      WHERE workspace_id=%s AND application_id=%s AND environment_id=%s FOR UPDATE''',
      (scope.workspace_id,scope.application_id,environment_id)).fetchone()
    if ((current is None)!=(expected_state_token is None) or current is not None
        and current['state_token']!=expected_state_token):
     raise ValueError('PYTHON_ENVIRONMENT_STATE_CONFLICT')
    revision=state['commit_revision']+1;policy_revision=state['policy_revision']+1
    state_token=new_state_token()
    result={'operationId':idempotency_key,'environmentId':environment_id,
      'stateToken':state_token,'status':'Active','profileId':profile.profile_id,
      'manifestDigest':manifest_digest,'imageDigest':profile.image_digest,
      'metadataRevision':state['metadata_revision'],'policyRevision':policy_revision,
      'schemaEpoch':state['schema_epoch']}
    db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
      WHERE workspace_id=%s AND application_id=%s''',(policy_revision,revision,
      scope.workspace_id,scope.application_id))
    db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
      operation_id,command_digest,actor_id,committed_revision,result)
      VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,
      idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
    db.execute('''INSERT INTO epm.python_environment_definition(workspace_id,
      application_id,environment_id,state_token,status,manifest,manifest_digest,
      image_digest,updated_operation_id,updated_issuer,
      updated_subject_id) VALUES(%s,%s,%s,%s,'Active',%s,%s,%s,%s,%s,%s)
      ON CONFLICT(workspace_id,application_id,environment_id) DO UPDATE SET
      state_token=excluded.state_token,status='Active',manifest=excluded.manifest,
      manifest_digest=excluded.manifest_digest,image_digest=excluded.image_digest,
      updated_operation_id=excluded.updated_operation_id,
      updated_issuer=excluded.updated_issuer,
      updated_subject_id=excluded.updated_subject_id,
      updated_at=transaction_timestamp()''',(scope.workspace_id,
      scope.application_id,environment_id,state_token,Jsonb(manifest),manifest_digest,
      profile.image_digest,idempotency_key,self.identity.issuer,
      self.identity.subject_id))
    return result
