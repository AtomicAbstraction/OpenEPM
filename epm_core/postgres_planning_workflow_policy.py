"""PostgreSQL persistence for immutable planning editability policies.

This repository is intentionally not a public application-language surface.
It authenticates only ``VerifiedIdentity`` values supplied by the server and
recompiles stored JSON before returning or publishing it.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .planning_workflow_policy import (
    FORMAT_V2,PlanningWorkflowPolicy,canonical_policy_definition,
    compile_planning_workflow_policy,
)
from .postgres_planning_workflow_level_selector import (
    authored_policy_identity,resolve_level_selectors,
    validate_level_selector_pins,
)
from .postgres_access import (
    PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role,
)
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z')
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
SAVE='cube.write.policy.save'
READ='cube.write.policy.read'
LIST='cube.write.policy.list'
PUBLISH='cube.write.policy.publish'
DEACTIVATE='cube.write.policy.deactivate'
LEGACY_SAVE='planning.workflow.policy.save'
LEGACY_READ='planning.workflow.policy.read'
LEGACY_LIST='planning.workflow.policy.list'
LEGACY_PUBLISH='planning.workflow.policy.publish'
LEGACY_DEACTIVATE='planning.workflow.policy.deactivate'
LEGACY_TO_PUBLIC={
    LEGACY_SAVE:SAVE,LEGACY_READ:READ,LEGACY_LIST:LIST,
    LEGACY_PUBLISH:PUBLISH,LEGACY_DEACTIVATE:DEACTIVATE,
}
PUBLIC_TO_LEGACY={value:key for key,value in LEGACY_TO_PUBLIC.items()}


def catalog() -> dict:
    common={'permission':'admin','requiredCapabilities':[],
            'previewRequired':False,'workClass':'short'}
    public={
        SAVE:{**common,'mode':'immutable_policy_write',
              'idempotencyRequired':False,
              'arguments':{'definition':
                  'bounded exact planning workflow policy definition'},
              'result':'immutable policy version and canonical digest'},
        READ:{**common,'mode':'read','idempotencyRequired':False,
              'arguments':{'policyId':'stable policy ID',
                           'version':'positive immutable version'},
              'result':'verified immutable definition'},
        LIST:{**common,'mode':'read','idempotencyRequired':False,
              'arguments':{'limit':'optional 1-100',
                           'afterPolicyId':'optional composite cursor policy ID',
                           'afterVersion':'optional composite cursor version'},
              'result':'verified policy versions and composite cursor'},
        PUBLISH:{**common,'mode':'atomic_policy_write',
                 'idempotencyRequired':True,
                 'arguments':{'policyId':'stable policy ID',
                              'version':'positive immutable version',
                              'expectedPointerVersion':
                                  'current nonnegative pointer version'},
                 'result':'active policy pointer and receipt'},
        DEACTIVATE:{**common,'mode':'atomic_policy_write',
                    'idempotencyRequired':True,
                    'arguments':{'policyId':'currently active policy ID',
                                 'version':'currently active version',
                                 'expectedPointerVersion':
                                     'current positive pointer version'},
                    'result':'inactive policy pointer and receipt'}}
    # Legacy names remain in the raw private catalogue for admitted historical
    # artifacts.  The shared capability filter retires them from every fresh
    # public catalogue and admission path.
    return {**public,**{
        legacy:{**public[current],
                'privateCompatibilityReplacement':current}
        for legacy,current in LEGACY_TO_PUBLIC.items()}}


class PostgresPlanningWorkflowPolicies:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_nonowner_role(
            dsn,'epm_runtime',('cube_write_policy_version',
                               'cube_write_policy_state'))
        self.dsn=dsn
        self.identity=identity

    def save(self,scope: ApplicationScope,definition: object,*,
             function: str=SAVE) -> dict:
        v2=isinstance(definition,dict) and definition.get('format')==FORMAT_V2
        policy=(None if v2 else compile_planning_workflow_policy(definition))
        authored_identity=(authored_policy_identity(definition) if v2 else None)
        if policy is not None:self._require_scope(scope,policy)
        elif (not isinstance(scope,ApplicationScope)
                or definition.get('workspaceId')!=scope.workspace_id
                or definition.get('applicationId')!=scope.application_id):
            raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._prepare(db,scope,function)
                state=self._application_state(db,scope,lock=True)
                self._require_active(state)
                policy_id=(authored_identity[0] if v2 else policy.policy_id)
                version=(authored_identity[1] if v2 else policy.version)
                existing=db.execute('''SELECT definition,canonical_digest,
                    creator_issuer,creator_subject_id,created_at
                    FROM epm.cube_write_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s AND version=%s''',
                    (scope.workspace_id,scope.application_id,
                     policy_id,version)).fetchone()
                if existing:
                    verified=self._verify_row(scope,policy_id,version,existing)
                    conflict=(verified.authored_intent_digest!=authored_identity[2]
                              if v2 else verified.digest!=policy.digest)
                    if conflict:
                        raise ValueError('PLANNING_POLICY_VERSION_CONFLICT')
                    return self._saved_result(verified,existing)
                if v2:
                    definition=resolve_level_selectors(db,scope,definition)
                    policy=compile_planning_workflow_policy(definition)
                    self._require_scope(scope,policy)
                stored_definition=(canonical_policy_definition(policy)
                                   if v2 else definition)
                latest=db.execute('''SELECT max(version) AS latest_version
                    FROM epm.cube_write_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     policy.policy_id)).fetchone()['latest_version']
                if policy.version!=(latest+1 if latest is not None else 1):
                    raise ValueError('PLANNING_POLICY_VERSION_NOT_NEXT')
                row=db.execute('''INSERT INTO
                    epm.cube_write_policy_version
                    (workspace_id,application_id,policy_id,version,definition,
                     canonical_digest,creator_issuer,creator_subject_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING created_at''',
                    (scope.workspace_id,scope.application_id,
                     policy.policy_id,policy.version,Jsonb(stored_definition),
                     policy.digest,self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                return self._saved_result(policy,{
                    'creator_issuer':self.identity.issuer,
                    'creator_subject_id':self.identity.subject_id,
                    'created_at':row['created_at']})

    def read(self,scope: ApplicationScope,policy_id: str,version: int,*,
             function: str=READ) -> dict:
        self._target(policy_id,version)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db,scope,function)
                row=self._row(db,scope,policy_id,version)
                policy=self._verify_row(scope,policy_id,version,row)
                return {**self._saved_result(policy,row),
                        'definition':row['definition']}

    def read_active(self,scope: ApplicationScope) -> dict:
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db,scope,READ)
                pointer=db.execute('''SELECT active_policy_id,active_version,
                    pointer_version,state_revision
                    FROM epm.cube_write_policy_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if not pointer or pointer['active_policy_id'] is None:
                    return {'active':False,
                            'pointerVersion':(
                                pointer['pointer_version'] if pointer else 0),
                            'policy':None}
                row=self._row(db,scope,pointer['active_policy_id'],
                              pointer['active_version'])
                policy=self._verify_row(
                    scope,pointer['active_policy_id'],
                    pointer['active_version'],row)
                return {'active':True,
                        'pointerVersion':pointer['pointer_version'],
                        'stateRevision':pointer['state_revision'],
                        'policy':{**self._saved_result(policy,row),
                                  'definition':row['definition']}}

    def list(self,scope: ApplicationScope,*,limit: int=100,
             after_policy_id: str|None=None,
             after_version: int|None=None,function: str=LIST) -> dict:
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError('PLANNING_POLICY_LIST_LIMIT_INVALID')
        if (after_policy_id is None)!=(after_version is None):
            raise ValueError('PLANNING_POLICY_LIST_CURSOR_INVALID')
        if after_policy_id is not None:
            self._target(after_policy_id,after_version)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db,scope,function)
                rows=db.execute('''SELECT policy_id,version,definition,
                    canonical_digest,creator_issuer,creator_subject_id,
                    created_at FROM epm.cube_write_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND (%s::text IS NULL OR (policy_id,version)>(%s,%s))
                    ORDER BY policy_id,version LIMIT %s''',
                    (scope.workspace_id,scope.application_id,
                     after_policy_id,after_policy_id,after_version,
                     limit+1)).fetchall()
                values=[]
                for row in rows[:limit]:
                    policy=self._verify_row(
                        scope,row['policy_id'],row['version'],row)
                    values.append({**self._saved_result(policy,row),
                                   'definition':row['definition']})
                next_cursor=(
                    {'afterPolicyId':values[-1]['policyId'],
                     'afterVersion':values[-1]['version']}
                    if len(rows)>limit else None)
                return {'policies':values,'nextCursor':next_cursor}

    def execute_program(self,scope: ApplicationScope,program: object,*,
                        idempotency_key: str|None=None) -> dict:
        function,args=_program(program)
        if function in (SAVE,LEGACY_SAVE):
            if set(args)!={'definition'}:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            if idempotency_key is not None:
                raise ValueError('PLANNING_POLICY_REQUEST_KEY_UNSUPPORTED')
            return self.save(scope,args['definition'],function=function)
        if function in (PUBLISH,DEACTIVATE,LEGACY_PUBLISH,LEGACY_DEACTIVATE):
            if set(args)!={'policyId','version','expectedPointerVersion'}:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            if idempotency_key is None:
                raise ValueError('PLANNING_POLICY_IDEMPOTENCY_KEY_REQUIRED')
            method=(self.publish if function in (PUBLISH,LEGACY_PUBLISH)
                    else self.deactivate)
            return method(
                scope,policy_id=args['policyId'],version=args['version'],
                expected_pointer_version=args['expectedPointerVersion'],
                idempotency_key=idempotency_key,function=function)
        raise ValueError('PLANNING_POLICY_WRITE_FUNCTION_INVALID')

    def read_program(self,scope: ApplicationScope,program: object) -> dict:
        function,args=_program(program)
        if function in (READ,LEGACY_READ):
            if set(args)!={'policyId','version'}:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            self._target(args['policyId'],args['version'])
            return self.read(scope,args['policyId'],args['version'],
                             function=function)
        if function in (LIST,LEGACY_LIST):
            allowed={'limit','afterPolicyId','afterVersion'}
            if set(args)-allowed:
                raise ValueError('PLANNING_POLICY_ARGUMENTS_INVALID')
            return self.list(
                scope,limit=args.get('limit',100),
                after_policy_id=args.get('afterPolicyId'),
                after_version=args.get('afterVersion'),function=function)
        raise ValueError('PLANNING_POLICY_READ_FUNCTION_INVALID')

    def publish(self,scope: ApplicationScope,*,policy_id: str,version: int,
                expected_pointer_version: int,idempotency_key: str,
                function: str=PUBLISH) -> dict:
        self._target(policy_id,version)
        self._mutation_arguments(expected_pointer_version,idempotency_key)
        return self._change_pointer(
            scope,policy_id=policy_id,version=version,
            expected_pointer_version=expected_pointer_version,
            idempotency_key=idempotency_key,deactivate=False,
            function=function)

    def deactivate(self,scope: ApplicationScope,*,policy_id: str,version: int,
                   expected_pointer_version: int,
                   idempotency_key: str,function: str=DEACTIVATE) -> dict:
        self._target(policy_id,version)
        self._mutation_arguments(expected_pointer_version,idempotency_key)
        return self._change_pointer(
            scope,policy_id=policy_id,version=version,
            expected_pointer_version=expected_pointer_version,
            idempotency_key=idempotency_key,deactivate=True,
            function=function)

    def _change_pointer(self,scope,*,policy_id,version,
                        expected_pointer_version,idempotency_key,deactivate,
                        function):
        command={'scope':[scope.workspace_id,scope.application_id],
                 'actor':[self.identity.issuer,self.identity.subject_id],
                 'function':function,'policyId':policy_id,'version':version,
                 'expectedPointerVersion':expected_pointer_version,
                 'idempotencyKey':idempotency_key}
        digest=sha256(json.dumps(
            command,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._prepare(db,scope,function)
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest']!=digest
                            or prior['actor_id']!=self.identity.subject_id):
                        raise ValueError('PLANNING_POLICY_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                state=self._application_state(db,scope,lock=True)
                self._require_active(state)
                pointer=db.execute('''SELECT active_policy_id,active_version,
                    pointer_version FROM epm.cube_write_policy_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                current_version=pointer['pointer_version'] if pointer else 0
                if current_version!=expected_pointer_version:
                    raise ValueError('PLANNING_POLICY_POINTER_STALE')
                if deactivate:
                    if (not pointer
                            or pointer['active_policy_id']!=policy_id
                            or pointer['active_version']!=version):
                        raise ValueError('PLANNING_POLICY_ACTIVE_TARGET_MISMATCH')
                else:
                    row=self._row(db,scope,policy_id,version)
                    policy=self._verify_row(scope,policy_id,version,row)
                    validate_level_selector_pins(db,scope,policy)
                    if (pointer and pointer['active_policy_id']==policy_id
                            and pointer['active_version']==version):
                        raise ValueError('PLANNING_POLICY_ALREADY_ACTIVE')
                next_pointer=current_version+1
                revision=state['commit_revision']+1
                active_id=None if deactivate else policy_id
                active_version=None if deactivate else version
                if pointer:
                    db.execute('''UPDATE epm.cube_write_policy_state
                        SET active_policy_id=%s,active_version=%s,
                        pointer_version=%s,state_revision=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s''',
                        (active_id,active_version,next_pointer,revision,
                         scope.workspace_id,scope.application_id))
                else:
                    db.execute('''INSERT INTO
                        epm.cube_write_policy_state
                        (workspace_id,application_id,active_policy_id,
                         active_version,pointer_version,state_revision)
                        VALUES(%s,%s,%s,%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,active_id,
                         active_version,next_pointer,revision))
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=policy_revision+1,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                result={'operationId':idempotency_key,
                        'status':'Inactive' if deactivate else 'Active',
                        'policyId':policy_id,'version':version,
                        'canonicalDigest':(
                            None if deactivate else policy.digest),
                        'pointerVersion':next_pointer,
                        'policyRevision':state['policy_revision']+1,
                        'committedRevision':revision}
                if not deactivate and policy.format_version==2:
                    result['authoredIntentDigest']=policy.authored_intent_digest
                    result['levelResolutions']=self._level_resolutions(policy)
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     idempotency_key,digest,self.identity.subject_id,
                     revision,Jsonb(result)))
                return result

    def _prepare(self,db,scope,function):
        if not isinstance(scope,ApplicationScope):
            raise ValueError('APPLICATION_SCOPE_INVALID')
        configure_statement_timeout(db,5000)
        configure_lock_wait(db)
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,'admin')

    @staticmethod
    def _application_state(db,scope,*,lock):
        row=db.execute('''SELECT s.policy_revision,s.data_revision,
            s.commit_revision,s.processing_mode,a.status
            FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s'''
            +(' FOR UPDATE OF s' if lock else ''),
            (scope.workspace_id,scope.application_id)).fetchone()
        if row is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        return row

    @staticmethod
    def _require_active(state):
        if state['status']!='Active' or state['processing_mode']!='Active':
            raise ValueError('APPLICATION_NOT_WRITABLE')

    @staticmethod
    def _row(db,scope,policy_id,version):
        row=db.execute('''SELECT definition,canonical_digest,
            creator_issuer,creator_subject_id,created_at
            FROM epm.cube_write_policy_version
            WHERE workspace_id=%s AND application_id=%s
            AND policy_id=%s AND version=%s''',
            (scope.workspace_id,scope.application_id,
             policy_id,version)).fetchone()
        if row is None:
            raise ValueError('PLANNING_POLICY_VERSION_UNAVAILABLE')
        return row

    @staticmethod
    def _verify_row(scope,policy_id,version,row) -> PlanningWorkflowPolicy:
        try:
            policy=compile_planning_workflow_policy(row['definition'])
        except (TypeError,ValueError) as error:
            raise ValueError('PLANNING_POLICY_PERSISTED_DEFINITION_INVALID') from error
        if (policy.scope!=scope or policy.policy_id!=policy_id
                or policy.version!=version
                or policy.digest!=row['canonical_digest']):
            raise ValueError('PLANNING_POLICY_PERSISTED_DIGEST_MISMATCH')
        return policy

    @staticmethod
    def _require_scope(scope,policy):
        if not isinstance(scope,ApplicationScope) or policy.scope!=scope:
            raise ValueError('PLANNING_POLICY_SCOPE_MISMATCH')

    @staticmethod
    def _target(policy_id,version):
        if (not isinstance(policy_id,str) or not _ID.fullmatch(policy_id)
                or type(version) is not int or version<1):
            raise ValueError('PLANNING_POLICY_TARGET_INVALID')

    @staticmethod
    def _mutation_arguments(expected_pointer_version,idempotency_key):
        if (type(expected_pointer_version) is not int
                or expected_pointer_version<0):
            raise ValueError('PLANNING_POLICY_POINTER_VERSION_INVALID')
        if (not isinstance(idempotency_key,str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('PLANNING_POLICY_IDEMPOTENCY_KEY_INVALID')

    @staticmethod
    def _saved_result(policy,row):
        result={'policyId':policy.policy_id,'version':policy.version,
                'canonicalDigest':policy.digest,
                'creator':{'issuer':row['creator_issuer'],
                           'subjectId':row['creator_subject_id']},
                'createdAt':row['created_at']}
        if policy.format_version==2:
            result['authoredIntentDigest']=policy.authored_intent_digest
            result['levelResolutions']=PostgresPlanningWorkflowPolicies._level_resolutions(
                policy)
        return result

    @staticmethod
    def _level_resolutions(policy):
        selectors=[rule.level_selector for rule in policy.rules
                   if rule.level_selector is not None]
        return [{
                'dimensionId':item.dimension_id,
                'hierarchyVersion':item.hierarchy_version,
                'rootMemberId':item.root_member_id,'depth':item.depth,
                'metadataRevision':item.metadata_revision,
                'schemaEpoch':item.schema_epoch,
                'memberCount':len(item.resolved_members),
                'resolutionDigest':item.resolution_digest}
                for item in selectors]


def _program(raw: object) -> tuple[str,dict]:
    if (not isinstance(raw,dict)
            or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion']!=2
            or raw['function'] not in (
                SAVE,READ,LIST,PUBLISH,DEACTIVATE,
                LEGACY_SAVE,LEGACY_READ,LEGACY_LIST,
                LEGACY_PUBLISH,LEGACY_DEACTIVATE)
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('PLANNING_POLICY_PROGRAM_INVALID')
    return raw['function'],raw['arguments']
