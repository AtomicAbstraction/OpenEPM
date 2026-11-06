"""Receipt-backed authority for unattended fixed-core execution."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout

CREATE='execution.delegation.create'
READ='execution.delegation.read'
LIST='execution.delegation.list'
REVOKE='execution.delegation.revoke'
_ID=re.compile(r'^[A-Za-z0-9._-]{1,200}$')
_OP=re.compile(r'^[A-Za-z][A-Za-z0-9_.-]{0,199}$')
_KEY=re.compile(r'^[A-Za-z0-9._-]{8,128}$')

def _time(value):
    if type(value) is not str: raise ValueError('EXECUTION_DELEGATION_TIME_INVALID')
    try: parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as error: raise ValueError('EXECUTION_DELEGATION_TIME_INVALID') from error
    if parsed.tzinfo is None: raise ValueError('EXECUTION_DELEGATION_TIME_INVALID')
    return parsed.astimezone(timezone.utc)

def _program(raw,function):
    if (type(raw) is not dict or set(raw)!={'languageVersion','function','arguments'}
            or raw.get('languageVersion')!=2 or raw.get('function')!=function
            or type(raw.get('arguments')) is not dict):
        raise ValueError('EXECUTION_DELEGATION_PROGRAM_INVALID')
    return raw['arguments']

def catalog():
    common={'requiredCapabilities':[],'previewRequired':False,'workClass':'short'}
    return {
      CREATE:{**common,'mode':'atomic_security_write','permission':'admin','idempotencyRequired':True,
        'arguments':{'delegationId':'stable ID','version':'next positive version','issuer':'verified execution issuer','subjectId':'verified execution subject','operationScope':'1-32 exact function names','validFrom':'UTC timestamp','validUntil':'UTC timestamp','scheduleId':'optional exact schedule ID','scheduleVersion':'optional exact schedule version','expectedMetadataRevision':'current integer','expectedPolicyRevision':'current integer','expectedSchemaEpoch':'current integer'},'result':'immutable active delegation version'},
      REVOKE:{**common,'mode':'atomic_security_write','permission':'admin','idempotencyRequired':True,
        'arguments':{'delegationId':'stable ID','version':'current active version','expectedMetadataRevision':'current integer','expectedPolicyRevision':'current integer','expectedSchemaEpoch':'current integer'},'result':'revoked delegation'},
      READ:{**common,'mode':'read_only','permission':'admin','idempotencyRequired':False,'arguments':{'delegationId':'stable ID'},'result':'current delegation without credentials'},
      LIST:{**common,'mode':'read_only','permission':'admin','idempotencyRequired':False,'arguments':{'limit':'1-100','afterDelegationId':'optional keyset'},'result':'bounded delegation page'}}

class PostgresExecutionDelegations:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity): raise ValueError('Verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('execution_delegation_version','execution_delegation_state'))
        self.dsn,self.identity=dsn,identity

    def execute(self,scope,raw,*,idempotency_key):
        if not isinstance(scope,ApplicationScope): raise ValueError('APPLICATION_SCOPE_INVALID')
        function=raw.get('function') if type(raw) is dict else None
        if function not in (CREATE,REVOKE): raise ValueError('EXECUTION_DELEGATION_FUNCTION_INVALID')
        args=_program(raw,function)
        if type(idempotency_key) is not str or not _KEY.fullmatch(idempotency_key): raise ValueError('EXECUTION_DELEGATION_IDEMPOTENCY_KEY_INVALID')
        pins={'expectedMetadataRevision','expectedPolicyRevision','expectedSchemaEpoch'}
        base={'delegationId','version'}|pins
        if function==CREATE:
            required=base|{'issuer','subjectId','operationScope','validFrom','validUntil','scheduleId','scheduleVersion'}
            if set(args)!=required: raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
            operations=args['operationScope']
            if (type(operations) is not list or not 1<=len(operations)<=32
                    or any(type(v) is not str or not _OP.fullmatch(v) for v in operations)
                    or len(set(operations))!=len(operations)
                    or type(args['issuer']) is not str or not 1<=len(args['issuer'])<=300
                    or any(ord(c)<32 or ord(c)==127 for c in args['issuer'])
                    or type(args['subjectId']) is not str or not 1<=len(args['subjectId'])<=300
                    or any(ord(c)<32 or ord(c)==127 for c in args['subjectId'])):
                raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
            start,end=_time(args['validFrom']),_time(args['validUntil'])
            if end<=start: raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
            if (args['scheduleId'] is None)!=(args['scheduleVersion'] is None): raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
            if (args['scheduleId'] is not None and
                    (type(args['scheduleId']) is not str or not _ID.fullmatch(args['scheduleId'])
                     or type(args['scheduleVersion']) is not int or args['scheduleVersion']<1)):
                raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        elif set(args)!=base: raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        if (type(args.get('delegationId')) is not str or not _ID.fullmatch(args['delegationId'])
                or type(args.get('version')) is not int or args['version']<1
                or any(type(args.get(pin)) is not int or args[pin]<0 for pin in pins)):
            raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        digest=sha256(json.dumps({'scope':[scope.workspace_id,scope.application_id],'actor':[self.identity.issuer,self.identity.subject_id],'program':raw},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000); configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db,scope); PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=function)
            prior=db.execute('SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior['command_digest']!=digest or prior['actor_id']!=self.identity.subject_id: raise ValueError('EXECUTION_DELEGATION_IDEMPOTENCY_CONFLICT')
                return prior['result']
            state=db.execute('SELECT metadata_revision,policy_revision,schema_epoch,commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None or any(state[field]!=args[name] for field,name in [('metadata_revision','expectedMetadataRevision'),('policy_revision','expectedPolicyRevision'),('schema_epoch','expectedSchemaEpoch')]): raise ValueError('EXECUTION_DELEGATION_STALE_CONTEXT')
            pointer=db.execute('SELECT latest_version,active_version FROM epm.execution_delegation_state WHERE workspace_id=%s AND application_id=%s AND delegation_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id,args['delegationId'])).fetchone()
            if function==CREATE:
                if args['version']!=(pointer['latest_version']+1 if pointer else 1): raise ValueError('EXECUTION_DELEGATION_VERSION_NOT_NEXT')
                # A delegation can narrow current authority, never manufacture
                # it.  The current actor's groups come only from the verified
                # token. A different target receives only groups discovered
                # from the current Keycloak-derived managed-directory
                # projection. The stored set is an immutable upper bound.
                same_identity=(args['issuer'],args['subjectId'])==(
                    self.identity.issuer,self.identity.subject_id)
                if same_identity:
                    target_groups=PostgresAccessChecker.current_groups_in_transaction(
                        db,self.identity)
                else:
                    discovered=db.execute('''SELECT
                        epm.managed_identity_groups_for_delegation(%s,%s)
                            AS groups''',(args['issuer'],
                            args['subjectId'])).fetchone()
                    target_groups=tuple(discovered['groups'])
                target=VerifiedIdentity(args['issuer'],args['subjectId'],
                                        tuple(target_groups))
                access=PostgresAccessChecker.check_in_transaction(
                    db,target,scope,'write')
                if 'application.rule.run' in operations:
                    PostgresAccessChecker.check_in_transaction(
                        db,target,scope,'rule_run',
                        function='application.rule.run')
                authorization_scope_digest=resolve_effective_dimensional_scope(
                    db,target,scope,access=access,
                    function='execution.delegation.create').scope_digest
                status='Active'
            elif pointer is None or pointer['active_version']!=args['version']:
                raise ValueError('EXECUTION_DELEGATION_ACTIVE_VERSION_MISMATCH')
            else: status='Revoked'
            revision=state['commit_revision']+1
            result={'operationId':idempotency_key,
                'delegationId':args['delegationId'],'version':args['version'],
                'status':status,'committedRevision':revision,
                'policyRevision':state['policy_revision']+1}
            db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
            if function==CREATE:
                db.execute('INSERT INTO epm.execution_delegation_version(workspace_id,application_id,delegation_id,version,issuer,subject_id,operation_scope,valid_from,valid_until,schedule_id,schedule_version,operation_id,verified_groups,authorization_scope_digest) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,args['delegationId'],args['version'],args['issuer'],args['subjectId'],args['operationScope'],start,end,args['scheduleId'],args['scheduleVersion'],idempotency_key,list(target.groups),authorization_scope_digest))
                db.execute('INSERT INTO epm.execution_delegation_state(workspace_id,application_id,delegation_id,latest_version,active_version,state_revision) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(workspace_id,application_id,delegation_id) DO UPDATE SET latest_version=excluded.latest_version,active_version=excluded.active_version,state_revision=excluded.state_revision,revoked_at=NULL,updated_at=transaction_timestamp()', (scope.workspace_id,scope.application_id,args['delegationId'],args['version'],args['version'],revision))
            else:
                db.execute('UPDATE epm.execution_delegation_state SET active_version=NULL,state_revision=%s,revoked_at=transaction_timestamp(),updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND delegation_id=%s',(revision,scope.workspace_id,scope.application_id,args['delegationId']))
            db.execute('UPDATE epm.application_state SET policy_revision=policy_revision+1,commit_revision=%s WHERE workspace_id=%s AND application_id=%s',(revision,scope.workspace_id,scope.application_id))
            return result

    def read(self,scope,raw):
        if not isinstance(scope,ApplicationScope): raise ValueError('APPLICATION_SCOPE_INVALID')
        function=raw.get('function') if type(raw) is dict else None; args=_program(raw,function)
        if function==READ:
            if set(args)!={'delegationId'} or type(args['delegationId']) is not str or not _ID.fullmatch(args['delegationId']): raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
            after=None; limit=1
        elif function==LIST:
            if set(args)-{'limit','afterDelegationId'} or type(args.get('limit',100)) is not int or not 1<=args.get('limit',100)<=100: raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
            after=args.get('afterDelegationId'); limit=args.get('limit',100)
            if after is not None and (type(after) is not str or not _ID.fullmatch(after)): raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        else: raise ValueError('EXECUTION_DELEGATION_FUNCTION_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute('SET TRANSACTION READ ONLY'); configure_statement_timeout(db,5000); PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=function)
            rows=db.execute('''SELECT s.delegation_id,s.latest_version,s.active_version,s.state_revision,s.revoked_at,v.issuer,v.subject_id,v.operation_scope,v.valid_from,v.valid_until,v.schedule_id,v.schedule_version,v.verified_groups,v.authorization_scope_digest FROM epm.execution_delegation_state s JOIN epm.execution_delegation_version v ON (v.workspace_id,v.application_id,v.delegation_id,v.version)=(s.workspace_id,s.application_id,s.delegation_id,s.latest_version) WHERE s.workspace_id=%s AND s.application_id=%s AND (%s::text IS NULL OR s.delegation_id>%s) AND (%s::text IS NULL OR s.delegation_id=%s) ORDER BY s.delegation_id LIMIT %s''',(scope.workspace_id,scope.application_id,after,after,args.get('delegationId'),args.get('delegationId'),limit+1)).fetchall()
            values=[dict(row) for row in rows[:limit]]
            return ({'defined':bool(values),'delegation':values[0] if values else None} if function==READ else {'delegations':values,'nextAfterDelegationId':rows[limit-1]['delegation_id'] if len(rows)>limit else None})
