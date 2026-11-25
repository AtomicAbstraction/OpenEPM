"""Receipt-backed authority for unattended fixed-core execution."""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import STATE_TOKEN_PATTERN, new_state_token, require_state_token
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


def delegation_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{1,200}(?![\s\S])'}
    token = {'type': 'string', 'pattern': '^'+STATE_TOKEN_PATTERN.pattern.removesuffix(r'\Z')+r'(?![\s\S])'}
    principal = {'type': 'string', 'pattern': r'^[^\u0000-\u001f\u007f]{1,300}(?![\s\S])'}
    operations = {'type': 'array', 'minItems': 1, 'maxItems': 32, 'uniqueItems': True,
        'items': {'type': 'string', 'pattern': r'^[A-Za-z][A-Za-z0-9_.-]{0,199}(?![\s\S])'}}
    timestamp = {'type': 'string', 'format': 'date-time'}
    def nullable(schema):
        return {'anyOf': [schema, {'type': 'null'}]}

    revision = {'type': 'integer', 'minimum': 0}
    revisions = dict.fromkeys(('expectedMetadataRevision','expectedPolicyRevision','expectedSchemaEpoch'), revision)
    name = {'delegationId': 'fixture.authority'}
    pins = dict.fromkeys(revisions, 1)
    record = obj({'delegation_id': identifier, 'state_token': token,
        'status': {'enum': ['Active','Revoked']}, 'revoked_at': nullable(timestamp),
        'issuer': principal, 'subject_id': principal, 'operation_scope': operations,
        'valid_from': timestamp, 'valid_until': timestamp, 'schedule_id': nullable(identifier),
        'verified_groups': {'type': 'array', 'items': {'type': 'string'}},
        'authorization_scope_digest': token})
    if function == READ:
        arguments = obj({'delegationId': identifier})
        result = obj({'defined': {'type': 'boolean'}, 'delegation': nullable(record)})
        examples = [read_example(function, name, name='Read a current delegation',
            binding='Use a known delegation ID in the selected application. A missing definition returns defined false.')]
    elif function == LIST:
        arguments = obj({'limit': {'type': 'integer','minimum': 1,'maximum': 100,'default': 100},
                         'afterDelegationId': nullable(identifier)}, [])
        result = obj({'delegations': {'type': 'array','maxItems': 100,'items': record},
                      'nextAfterDelegationId': nullable(identifier)})
        examples = [read_example(function, {'limit': 20}, name='Read the first delegation page',
            binding='Use the current application administrator identity.'),
            read_example(function, {'limit': 20,'afterDelegationId': name['delegationId']},
                name='Continue the delegation inventory',
                binding='Copy the previous nextAfterDelegationId. A null cursor ends the list. Each page reads current state.')]
    else:
        fields = {'delegationId': identifier, 'expectedStateToken': token, **revisions}
        if function == CREATE:
            fields.update(issuer=principal,subjectId=principal,operationScope=operations,
                          validFrom=timestamp,validUntil=timestamp,scheduleId=nullable(identifier))
            arguments = obj(fields,[key for key in fields if key != 'expectedStateToken'])
            supplied = {**name, **pins, 'issuer': 'https://identity.example', 'subjectId': 'fixture-user',
                'operationScope': ['application.rule.run'], 'validFrom': '2026-01-01T00:00:00Z',
                'validUntil': '2026-01-02T00:00:00Z','scheduleId': None}
            examples = [read_example(function, supplied, name='Create scoped execution authority',
                binding='Bind current revisions, verified execution identity and the intended validity window. Admit the exact write.'),
                read_example(function, {**supplied, 'expectedStateToken': 'a'*64}, name='Replace current authority',
                    binding='Copy the current delegation state token and recheck the execution identity. Admit the changed program.')]
        else:
            arguments = obj(fields)
            examples = [read_example(function, {**name, **pins, 'expectedStateToken': 'a'*64},
                name='Revoke the current execution authority',
                binding='Read the active delegation, copy its state_token and current application revisions, then admit the exact write.')]
        result = obj({'operationId': {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'},
            'delegationId': identifier, 'stateToken': token, 'policyRevision': revision,
            'status': {'const': 'Active' if function == CREATE else 'Revoked'}})
    contract = read_contract(function,arguments,result,owner='PostgresExecutionDelegations',
        examples=examples,semantic_rules=[
            'Delegation narrows existing execution authority. It cannot grant new underlying access.',
            'An active record still needs an unexpired validity window, matching current state and current execution grants.',
            'A write result describes its original receipt. Read the current delegation to confirm present authority.',
        ])
    contract['programContract']['recovery'] = (
        'After a stale state or revision refusal, read the current delegation and application revisions before revising the intent. '
        'After an unanswered write, retain the original packet. An expired admission can recover an existing original receipt '
        'under current administration authority.')
    return contract


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
    functions = {
      CREATE:{**common,'mode':'atomic_security_write','permission':'admin','idempotencyRequired':True,
        'arguments':{'delegationId':'stable ID','issuer':'verified execution issuer','subjectId':'verified execution subject','operationScope':'1-32 exact function names','validFrom':'UTC timestamp','validUntil':'UTC timestamp','scheduleId':'exact current schedule ID, or null for an unbound delegation','expectedMetadataRevision':'current integer','expectedPolicyRevision':'current integer','expectedSchemaEpoch':'current integer'},'optionalArguments':{'expectedStateToken':'required to replace the current delegation'},'result':'current active delegation and state token'},
      REVOKE:{**common,'mode':'atomic_security_write','permission':'admin','idempotencyRequired':True,
        'arguments':{'delegationId':'stable ID','expectedStateToken':'current active delegation token','expectedMetadataRevision':'current integer','expectedPolicyRevision':'current integer','expectedSchemaEpoch':'current integer'},'result':'revoked current delegation'},
      READ:{**common,'mode':'read_only','permission':'admin','idempotencyRequired':False,'arguments':{'delegationId':'stable ID'},'result':'current delegation without credentials'},
      LIST:{**common,'mode':'read_only','permission':'admin','idempotencyRequired':False,'arguments':{'limit':'1-100','afterDelegationId':'optional keyset'},'result':'bounded delegation page'}}
    return {function: {**entry, **delegation_program_contract(function)}
            for function, entry in functions.items()}

class PostgresExecutionDelegations:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity): raise ValueError('Verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('execution_delegation_definition',))
        self.dsn,self.identity=dsn,identity

    def execute(self,scope,raw,*,idempotency_key,replay_only=False):
        if not isinstance(scope,ApplicationScope): raise ValueError('APPLICATION_SCOPE_INVALID')
        function=raw.get('function') if type(raw) is dict else None
        if function not in (CREATE,REVOKE): raise ValueError('EXECUTION_DELEGATION_FUNCTION_INVALID')
        args=_program(raw,function)
        if type(idempotency_key) is not str or not _KEY.fullmatch(idempotency_key): raise ValueError('EXECUTION_DELEGATION_IDEMPOTENCY_KEY_INVALID')
        pins={'expectedMetadataRevision','expectedPolicyRevision','expectedSchemaEpoch'}
        base={'delegationId'}|pins
        if function==CREATE:
            required=base|{'issuer','subjectId','operationScope','validFrom','validUntil','scheduleId'}
            if set(args) not in (required,required|{'expectedStateToken'}): raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
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
            if (args['scheduleId'] is not None and
                    (type(args['scheduleId']) is not str or not _ID.fullmatch(args['scheduleId']))):
                raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        elif set(args)!=base|{'expectedStateToken'}: raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        if (type(args.get('delegationId')) is not str or not _ID.fullmatch(args['delegationId'])
                or any(type(args.get(pin)) is not int or args[pin]<0 for pin in pins)):
            raise ValueError('EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        if 'expectedStateToken' in args:
            require_state_token(args['expectedStateToken'],
                error='EXECUTION_DELEGATION_ARGUMENTS_INVALID')
        digest=sha256(json.dumps({'scope':[scope.workspace_id,scope.application_id],'actor':[self.identity.issuer,self.identity.subject_id],'program':raw},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute('SET TRANSACTION READ ONLY')
            configure_statement_timeout(db,5000); configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db,scope); PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=function)
            # Serialize before reading the receipt so overlapping copies of
            # the same intent observe the commit made by the first submitter.
            if not replay_only:
                state=db.execute('''SELECT metadata_revision,policy_revision,schema_epoch,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
            prior=db.execute('SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior['command_digest']!=digest or prior['actor_id']!=self.identity.subject_id: raise ValueError('EXECUTION_DELEGATION_IDEMPOTENCY_CONFLICT')
                return prior['result']
            if replay_only:return None
            if state is None or any(state[field]!=args[name] for field,name in [('metadata_revision','expectedMetadataRevision'),('policy_revision','expectedPolicyRevision'),('schema_epoch','expectedSchemaEpoch')]): raise ValueError('EXECUTION_DELEGATION_STALE_CONTEXT')
            current=db.execute('SELECT state_token,status FROM epm.execution_delegation_definition WHERE workspace_id=%s AND application_id=%s AND delegation_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id,args['delegationId'])).fetchone()
            if function==CREATE:
                if ((current is None)!=('expectedStateToken' not in args)
                        or (current is not None and current['state_token']!=
                            args.get('expectedStateToken'))):
                    raise ValueError('EXECUTION_DELEGATION_STATE_CONFLICT')
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
            elif (current is None or current['status']!='Active'
                    or current['state_token']!=args['expectedStateToken']):
                raise ValueError('EXECUTION_DELEGATION_STATE_CONFLICT')
            else: status='Revoked'
            revision=state['commit_revision']+1
            state_token=new_state_token()
            result={'operationId':idempotency_key,
                'delegationId':args['delegationId'],'stateToken':state_token,
                'status':status,'policyRevision':state['policy_revision']+1}
            db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
            if function==CREATE:
                db.execute('''INSERT INTO epm.execution_delegation_definition(
                    workspace_id,application_id,delegation_id,state_token,status,
                    issuer,subject_id,operation_scope,valid_from,valid_until,
                    schedule_id,verified_groups,authorization_scope_digest,
                    updated_operation_id,revoked_at)
                    VALUES(%s,%s,%s,%s,'Active',%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL)
                    ON CONFLICT(workspace_id,application_id,delegation_id)
                    DO UPDATE SET state_token=EXCLUDED.state_token,status='Active',
                      issuer=EXCLUDED.issuer,subject_id=EXCLUDED.subject_id,
                      operation_scope=EXCLUDED.operation_scope,
                      valid_from=EXCLUDED.valid_from,valid_until=EXCLUDED.valid_until,
                      schedule_id=EXCLUDED.schedule_id,
                      verified_groups=EXCLUDED.verified_groups,
                      authorization_scope_digest=EXCLUDED.authorization_scope_digest,
                      updated_operation_id=EXCLUDED.updated_operation_id,revoked_at=NULL,
                      updated_at=transaction_timestamp()''',(
                    scope.workspace_id,scope.application_id,args['delegationId'],
                    state_token,args['issuer'],args['subjectId'],args['operationScope'],
                    start,end,args['scheduleId'],list(target.groups),
                    authorization_scope_digest,idempotency_key))
            else:
                db.execute('''UPDATE epm.execution_delegation_definition SET
                    state_token=%s,status='Revoked',updated_operation_id=%s,
                    revoked_at=transaction_timestamp(),
                    updated_at=transaction_timestamp() WHERE workspace_id=%s
                    AND application_id=%s AND delegation_id=%s''',(
                    state_token,idempotency_key,scope.workspace_id,
                    scope.application_id,args['delegationId']))
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
            rows=db.execute('''SELECT delegation_id,state_token,status,
                revoked_at,issuer,subject_id,operation_scope,
                valid_from,valid_until,schedule_id,verified_groups,
                authorization_scope_digest FROM epm.execution_delegation_definition
                WHERE workspace_id=%s AND application_id=%s
                  AND (%s::text IS NULL OR delegation_id>%s)
                  AND (%s::text IS NULL OR delegation_id=%s)
                ORDER BY delegation_id LIMIT %s''',(
                scope.workspace_id,scope.application_id,after,after,
                args.get('delegationId'),args.get('delegationId'),limit+1)).fetchall()
            values=[dict(row) for row in rows[:limit]]
            for value in values:
                for field in ('valid_from','valid_until','revoked_at'):
                    if value[field] is not None:
                        value[field]=value[field].isoformat()
            return ({'defined':bool(values),'delegation':values[0] if values else None} if function==READ else {'delegations':values,'nextAfterDelegationId':rows[limit-1]['delegation_id'] if len(rows)>limit else None})
