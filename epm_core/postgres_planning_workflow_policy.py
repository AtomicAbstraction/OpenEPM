"""Current lifecycle for application cube-write policies."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import collection_token,new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .planning_workflow_policy import (
    FORMAT_V2,canonical_policy_definition,compile_planning_workflow_policy,
)
from .postgres_planning_workflow_level_selector import (
    authored_policy_identity,resolve_level_selectors,validate_level_selector_pins,
)
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore

SAVE='cube.write.policy.save';READ='cube.write.policy.read';LIST='cube.write.policy.list'
ACTIVATE='cube.write.policy.activate';DEACTIVATE='cube.write.policy.deactivate'
FUNCTIONS=frozenset((SAVE,READ,LIST,ACTIVATE,DEACTIVATE))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z');_DIGEST=re.compile(r'[0-9a-f]{64}\Z')
_SELECT='''policy_id,state_token,status,definition,canonical_digest,
 updated_operation_id,updated_issuer,updated_subject_id,updated_at'''


def catalog()->dict:
    common={'permission':'admin','requiredCapabilities':[],
            'previewRequired':False,'workClass':'short'}
    return {
        SAVE:{**common,'mode':'current_policy_write','idempotencyRequired':True,
              'arguments':{'definition':'bounded current cube-write policy'},
              'optionalArguments':{'expectedStateToken':'required to replace current policy'},
              'result':'saved current policy, state token, digest and receipt'},
        READ:{**common,'mode':'read','idempotencyRequired':False,
              'arguments':{'policyId':'stable policy ID'},'result':'verified current policy'},
        LIST:{**common,'mode':'read','idempotencyRequired':False,'arguments':{},
              'optionalArguments':{'limit':'1-100','afterPolicyId':'keyset cursor',
                                   'expectedCollectionToken':'required with cursor'},
              'result':'bounded current policies and collection token'},
        ACTIVATE:{**common,'mode':'atomic_policy_write','idempotencyRequired':True,
                  'arguments':{'policyId':'stable policy ID','expectedStateToken':'current token',
                               'canonicalDigest':'exact current digest'},
                  'result':'active current policy and receipt'},
        DEACTIVATE:{**common,'mode':'atomic_policy_write','idempotencyRequired':True,
                    'arguments':{'policyId':'stable policy ID','expectedStateToken':'current token',
                                 'canonicalDigest':'exact current digest'},
                    'result':'saved current policy and receipt'},
    }


def _program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or raw.get('languageVersion')!=2 or raw.get('function') not in FUNCTIONS
            or not isinstance(raw.get('arguments'),dict)):
        raise ValueError('PLANNING_POLICY_PROGRAM_INVALID')
    return raw['function'],raw['arguments']


class PostgresPlanningWorkflowPolicies:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('cube_write_policy_definition',))
        self.dsn,self.identity=dsn,identity

    def _prepare(self,db,scope,function,*,writable=False):
        if not isinstance(scope,ApplicationScope):raise ValueError('APPLICATION_SCOPE_INVALID')
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=function)
        state=db.execute('''SELECT a.status,s.processing_mode,s.policy_revision,
            s.commit_revision FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s'''+
            (' FOR UPDATE OF s' if writable else ''),
            (scope.workspace_id,scope.application_id)).fetchone()
        if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
        if writable and (state['status']!='Active' or state['processing_mode']!='Active'):
            raise ValueError('APPLICATION_NOT_WRITABLE')
        return state

    @staticmethod
    def _target(policy_id):
        if not isinstance(policy_id,str) or not _ID.fullmatch(policy_id):
            raise ValueError('PLANNING_POLICY_TARGET_INVALID')

    @staticmethod
    def _verify(row):
        if row is None:raise ValueError('PLANNING_POLICY_UNAVAILABLE')
        try:policy=compile_planning_workflow_policy(row['definition'])
        except (TypeError,ValueError) as error:
            raise ValueError('PLANNING_POLICY_PERSISTED_DEFINITION_INVALID') from error
        if policy.policy_id!=row['policy_id'] or policy.digest!=row['canonical_digest']:
            raise ValueError('PLANNING_POLICY_PERSISTED_DIGEST_MISMATCH')
        return policy

    @classmethod
    def _result(cls,row,*,definition=False):
        policy=cls._verify(row)
        value={'policyId':policy.policy_id,'stateToken':row['state_token'],
               'status':row['status'],'active':row['status']=='Active',
               'canonicalDigest':policy.digest,
               'actor':{'issuer':row['updated_issuer'],'subjectId':row['updated_subject_id']},
               'updatedAt':row['updated_at'],'operationId':row['updated_operation_id']}
        if policy.format_version==2:
            value['authoredIntentDigest']=policy.authored_intent_digest
            value['levelResolutions']=cls._level_resolutions(policy)
        if definition:value['definition']=row['definition']
        return value

    def save(self,scope,definition,*,expected_state_token=None,idempotency_key):
        _request_key(idempotency_key)
        if expected_state_token is not None:
            require_state_token(expected_state_token,error='PLANNING_POLICY_STATE_TOKEN_INVALID')
        is_v2=isinstance(definition,dict) and definition.get('format')==FORMAT_V2
        if is_v2:
            policy_id,_=authored_policy_identity(definition)
            if (definition.get('workspaceId'),definition.get('applicationId'))!=(
                    scope.workspace_id,scope.application_id):
                raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')
            authored=definition
        else:
            initial=compile_planning_workflow_policy(definition)
            if initial.scope!=scope:raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')
            policy_id,authored=initial.policy_id,definition
        command={'scope':[scope.workspace_id,scope.application_id],
                 'actor':[self.identity.issuer,self.identity.subject_id],'function':SAVE,
                 'definition':authored,'expectedStateToken':expected_state_token,
                 'idempotencyKey':idempotency_key};digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                app=self._prepare(db,scope,SAVE,writable=True)
                prior=self._replay(db,scope,idempotency_key,digest)
                if prior is not None:return prior
                current=self._row(db,scope,policy_id,optional=True,lock=True)
                if current is None and expected_state_token is not None:
                    raise ValueError('PLANNING_POLICY_UNAVAILABLE')
                if current is not None:
                    if expected_state_token is None:
                        raise ValueError('PLANNING_POLICY_EXPECTED_STATE_TOKEN_REQUIRED')
                    if current['state_token']!=expected_state_token:
                        raise ValueError('PLANNING_POLICY_STATE_STALE')
                sealed=resolve_level_selectors(db,scope,authored) if is_v2 else authored
                policy=compile_planning_workflow_policy(sealed)
                stored=canonical_policy_definition(policy) if is_v2 else sealed
                revision,token=app['commit_revision']+1,new_state_token()
                policy_revision=app['policy_revision']+(1 if current and current['status']=='Active' else 0)
                ids=(scope.workspace_id,scope.application_id,policy.policy_id)
                db.execute('''INSERT INTO epm.cube_write_policy_definition(
                    workspace_id,application_id,policy_id,state_token,status,definition,
                    canonical_digest,updated_operation_id,updated_issuer,updated_subject_id)
                    VALUES(%s,%s,%s,%s,'Saved',%s,%s,%s,%s,%s)
                    ON CONFLICT(workspace_id,application_id,policy_id) DO UPDATE SET
                     state_token=EXCLUDED.state_token,status='Saved',definition=EXCLUDED.definition,
                     canonical_digest=EXCLUDED.canonical_digest,
                     updated_operation_id=EXCLUDED.updated_operation_id,
                     updated_issuer=EXCLUDED.updated_issuer,
                     updated_subject_id=EXCLUDED.updated_subject_id,updated_at=clock_timestamp()''',
                    (*ids,token,Jsonb(stored),policy.digest,idempotency_key,
                     self.identity.issuer,self.identity.subject_id))
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision,revision,scope.workspace_id,scope.application_id))
                result={'policyId':policy.policy_id,'stateToken':token,'status':'Saved',
                        'canonicalDigest':policy.digest,'policyRevision':policy_revision,
                        }
                self._receipt(db,scope,idempotency_key,digest,revision,result);return result

    def read(self,scope,policy_id):
        self._target(policy_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._prepare(db,scope,READ)
                return self._result(self._row(db,scope,policy_id),definition=True)

    def read_active(self,scope):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._prepare(db,scope,READ)
                row=db.execute(f'''SELECT {_SELECT} FROM epm.cube_write_policy_definition
                    WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                return {'active':row is not None,'policy':None if row is None else self._result(row,definition=True)}

    def list(self,scope,*,limit=100,after_policy_id=None,expected_collection_token=None):
        if type(limit) is not int or not 1<=limit<=100:raise ValueError('PLANNING_POLICY_LIST_INVALID')
        if after_policy_id is not None:
            self._target(after_policy_id)
            require_state_token(expected_collection_token,error='PLANNING_POLICY_COLLECTION_TOKEN_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY');self._prepare(db,scope,LIST)
                ids=(scope.workspace_id,scope.application_id)
                all_rows=db.execute('''SELECT policy_id,state_token FROM epm.cube_write_policy_definition
                    WHERE workspace_id=%s AND application_id=%s ORDER BY policy_id''',ids).fetchall()
                token=collection_token((row['policy_id'],row['state_token']) for row in all_rows)
                if expected_collection_token is not None and token!=expected_collection_token:
                    raise ValueError('PLANNING_POLICY_LIST_STALE')
                rows=db.execute(f'''SELECT {_SELECT} FROM epm.cube_write_policy_definition
                    WHERE workspace_id=%s AND application_id=%s AND policy_id>%s
                    ORDER BY policy_id LIMIT %s''',(*ids,after_policy_id or '',limit+1)).fetchall()
                return {'policies':[self._result(row,definition=True) for row in rows[:limit]],
                        'collectionToken':token,
                        'nextAfterPolicyId':rows[limit-1]['policy_id'] if len(rows)>limit else None}

    def change(self,scope,*,policy_id,expected_state_token,canonical_digest,idempotency_key,deactivate):
        self._target(policy_id);_request_key(idempotency_key)
        require_state_token(expected_state_token,error='PLANNING_POLICY_MUTATION_INVALID')
        if not isinstance(canonical_digest,str) or not _DIGEST.fullmatch(canonical_digest):
            raise ValueError('PLANNING_POLICY_MUTATION_INVALID')
        function=DEACTIVATE if deactivate else ACTIVATE
        command={'scope':[scope.workspace_id,scope.application_id],
                 'actor':[self.identity.issuer,self.identity.subject_id],'function':function,
                 'policyId':policy_id,'expectedStateToken':expected_state_token,
                 'canonicalDigest':canonical_digest,'idempotencyKey':idempotency_key};digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                app=self._prepare(db,scope,function,writable=True)
                prior=self._replay(db,scope,idempotency_key,digest)
                if prior is not None:return prior
                row=self._row(db,scope,policy_id,lock=True);policy=self._verify(row)
                if row['state_token']!=expected_state_token:raise ValueError('PLANNING_POLICY_STATE_STALE')
                if policy.digest!=canonical_digest:raise ValueError('PLANNING_POLICY_DIGEST_MISMATCH')
                if deactivate and row['status']!='Active':raise ValueError('PLANNING_POLICY_NOT_ACTIVE')
                if not deactivate and row['status']=='Active':raise ValueError('PLANNING_POLICY_ALREADY_ACTIVE')
                if not deactivate:
                    validate_level_selector_pins(db,scope,policy)
                    other=db.execute('''SELECT policy_id FROM epm.cube_write_policy_definition
                        WHERE workspace_id=%s AND application_id=%s AND status='Active'
                        AND policy_id<>%s FOR UPDATE''',
                        (scope.workspace_id,scope.application_id,policy_id)).fetchone()
                    if other is not None:raise ValueError('PLANNING_POLICY_ANOTHER_ACTIVE')
                token,revision=new_state_token(),app['commit_revision']+1
                policy_revision=app['policy_revision']+1;status='Saved' if deactivate else 'Active'
                db.execute('''UPDATE epm.cube_write_policy_definition SET status=%s,state_token=%s,
                    updated_operation_id=%s,updated_issuer=%s,
                    updated_subject_id=%s,updated_at=clock_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND policy_id=%s''',
                    (status,token,idempotency_key,self.identity.issuer,self.identity.subject_id,
                     scope.workspace_id,scope.application_id,policy_id))
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision,revision,scope.workspace_id,scope.application_id))
                result={'policyId':policy_id,'stateToken':token,'status':status,
                        'canonicalDigest':policy.digest,'policyRevision':policy_revision,
                        }
                self._receipt(db,scope,idempotency_key,digest,revision,result);return result

    def execute_program(self,scope,program,*,idempotency_key=None):
        function,args=_program(program)
        if function==SAVE:
            if set(args)-{'definition','expectedStateToken'} or 'definition' not in args or idempotency_key is None:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            return self.save(scope,args['definition'],expected_state_token=args.get('expectedStateToken'),
                             idempotency_key=idempotency_key)
        if function in (ACTIVATE,DEACTIVATE):
            if set(args)!={'policyId','expectedStateToken','canonicalDigest'} or idempotency_key is None:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            return self.change(scope,policy_id=args['policyId'],expected_state_token=args['expectedStateToken'],
                canonical_digest=args['canonicalDigest'],idempotency_key=idempotency_key,
                deactivate=function==DEACTIVATE)
        raise ValueError('PLANNING_POLICY_WRITE_FUNCTION_INVALID')

    def read_program(self,scope,program):
        function,args=_program(program)
        if function==READ and set(args)=={'policyId'}:return self.read(scope,args['policyId'])
        if function==LIST and not set(args)-{'limit','afterPolicyId','expectedCollectionToken'}:
            if ('afterPolicyId' in args)!=('expectedCollectionToken' in args):
                raise ValueError('PLANNING_POLICY_LIST_INVALID')
            return self.list(scope,limit=args.get('limit',100),after_policy_id=args.get('afterPolicyId'),
                             expected_collection_token=args.get('expectedCollectionToken'))
        raise ValueError('PLANNING_POLICY_READ_FUNCTION_INVALID')

    @staticmethod
    def _row(db,scope,policy_id,*,optional=False,lock=False):
        row=db.execute(f'''SELECT {_SELECT} FROM epm.cube_write_policy_definition
            WHERE workspace_id=%s AND application_id=%s AND policy_id=%s'''+
            (' FOR UPDATE' if lock else ''),(scope.workspace_id,scope.application_id,policy_id)).fetchone()
        if row is None and not optional:raise ValueError('PLANNING_POLICY_UNAVAILABLE')
        return row

    def _replay(self,db,scope,operation_id,digest):
        row=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
            WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
            (scope.workspace_id,scope.application_id,operation_id)).fetchone()
        if row is None:return None
        if row['command_digest']!=digest or row['actor_id']!=self.identity.subject_id:
            raise ValueError('PLANNING_POLICY_IDEMPOTENCY_CONFLICT')
        return row['result']

    def _receipt(self,db,scope,operation_id,digest,revision,result):
        db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
            operation_id,command_digest,actor_id,committed_revision,result)
            VALUES(%s,%s,%s,%s,%s,%s,%s)''',
            (scope.workspace_id,scope.application_id,operation_id,digest,
             self.identity.subject_id,revision,Jsonb(result)))

    @staticmethod
    def _level_resolutions(policy):
        return [{'dimensionId':item.dimension_id,'hierarchyStateToken':item.hierarchy_state_token,
                 'rootMemberId':item.root_member_id,'depth':item.depth,
                 'metadataRevision':item.metadata_revision,'schemaEpoch':item.schema_epoch,
                 'memberCount':len(item.resolved_members),'resolutionDigest':item.resolution_digest}
                for item in (rule.level_selector for rule in policy.rules) if item is not None]


def _request_key(value):
    if not isinstance(value,str) or not _KEY.fullmatch(value):
        raise ValueError('PLANNING_POLICY_IDEMPOTENCY_KEY_INVALID')


def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()
