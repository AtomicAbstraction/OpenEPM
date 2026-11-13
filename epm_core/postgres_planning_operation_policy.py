"""Current lifecycle for reusable generic planning-operation policies."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import collection_token, new_state_token, require_state_token
from .persistence_contract import ApplicationScope
from .planning_operation_policy import compile_planning_operation_policy
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore

SAVE = 'planning.operation.policy.save'
READ = 'planning.operation.policy.read'
LIST = 'planning.operation.policy.list'
ACTIVATE = 'planning.operation.policy.activate'
DEACTIVATE = 'planning.operation.policy.deactivate'
FUNCTIONS = frozenset((SAVE, READ, LIST, ACTIVATE, DEACTIVATE))
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SELECT = '''policy_id,state_token,status,kind,effective_from,effective_before,
 definition,canonical_digest,updated_operation_id,
 updated_issuer,updated_subject_id,updated_at'''


def catalog() -> dict:
    common = {'permission': 'admin', 'requiredCapabilities': [],
              'previewRequired': False, 'workClass': 'short'}
    return {
        SAVE: {**common, 'mode': 'current_policy_write', 'idempotencyRequired': True,
            'arguments': {'definition': 'bounded current Seed/Driver/Rollup/Spread/Allocation policy'},
            'optionalArguments': {'expectedStateToken': 'required to replace current policy'},
            'result': 'saved current policy, state token, canonical digest and receipt'},
        READ: {**common, 'mode': 'read', 'idempotencyRequired': False,
            'arguments': {'policyId': 'stable ID'}, 'result': 'verified current policy'},
        LIST: {**common, 'mode': 'read', 'idempotencyRequired': False, 'arguments': {},
            'optionalArguments': {'limit': '1-100', 'afterPolicyId': 'keyset cursor',
                'expectedCollectionToken': 'required with cursor'},
            'result': 'bounded current policies and collection token'},
        ACTIVATE: {**common, 'mode': 'atomic_policy_write', 'idempotencyRequired': True,
            'arguments': {'policyId': 'stable ID', 'expectedStateToken': 'current token',
                'canonicalDigest': 'exact current digest'},
            'result': 'active current policy and receipt'},
        DEACTIVATE: {**common, 'mode': 'atomic_policy_write', 'idempotencyRequired': True,
            'arguments': {'policyId': 'stable ID', 'expectedStateToken': 'current token',
                'canonicalDigest': 'exact current digest'},
            'result': 'saved current policy and receipt'},
    }


def _program(program):
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') not in FUNCTIONS
            or not isinstance(program.get('arguments'), dict)):
        raise ValueError('PLANNING_OPERATION_POLICY_PROGRAM_INVALID')
    return program['function'], program['arguments']


class PostgresPlanningOperationPolicies:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn, 'epm_runtime', ('planning_operation_policy',))
        self.dsn, self.identity = dsn, identity

    def _prepare(self, db, scope, function, *, writable=False):
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'admin', function=function)
        state = db.execute('''SELECT a.status,s.processing_mode,
            s.metadata_revision,s.policy_revision,s.commit_revision
            FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s''' +
            (' FOR UPDATE OF s' if writable else ''),
            (scope.workspace_id, scope.application_id)).fetchone()
        if state is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        if writable and (state['status'] != 'Active' or state['processing_mode'] != 'Active'):
            raise ValueError('APPLICATION_NOT_WRITABLE')
        return state

    @staticmethod
    def _target(policy_id):
        if not isinstance(policy_id, str) or not _ID.fullmatch(policy_id):
            raise ValueError('PLANNING_OPERATION_POLICY_TARGET_INVALID')

    @staticmethod
    def _verify(row):
        if row is None:
            raise ValueError('PLANNING_OPERATION_POLICY_UNAVAILABLE')
        compiled = compile_planning_operation_policy(row['definition'])
        if (compiled.document['policyId'] != row['policy_id']
                or compiled.kind != row['kind']
                or compiled.digest != row['canonical_digest']):
            raise ValueError('PLANNING_OPERATION_POLICY_STORAGE_INVALID')
        return compiled

    @classmethod
    def _result(cls, row, *, definition=False):
        compiled = cls._verify(row)
        value = {'policyId': compiled.document['policyId'], 'stateToken': row['state_token'],
            'status': row['status'], 'active': row['status'] == 'Active',
            'kind': compiled.kind, 'canonicalDigest': compiled.digest,
            'effectiveFrom': compiled.document['effectiveFrom'],
            'effectiveBefore': compiled.document['effectiveBefore'],
            'actor': {'issuer': row['updated_issuer'], 'subjectId': row['updated_subject_id']},
            'updatedAt': row['updated_at'], 'operationId': row['updated_operation_id']}
        if definition:
            value['definition'] = row['definition']
        return value

    def save(self, scope: ApplicationScope, definition: object, *,
             expected_state_token: str | None = None, idempotency_key: str) -> dict:
        compiled = compile_planning_operation_policy(definition)
        _request_key(idempotency_key)
        if expected_state_token is not None:
            require_state_token(expected_state_token,
                error='PLANNING_OPERATION_POLICY_STATE_TOKEN_INVALID')
        command = {'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id], 'function': SAVE,
            'definition': compiled.document, 'expectedStateToken': expected_state_token,
            'idempotencyKey': idempotency_key}
        digest = _digest(command)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                state = self._prepare(db, scope, SAVE, writable=True)
                prior = self._replay(db, scope, idempotency_key, digest)
                if prior is not None:
                    return prior
                ids = (scope.workspace_id, scope.application_id, compiled.document['policyId'])
                current = db.execute(f'''SELECT {_SELECT} FROM epm.planning_operation_policy
                    WHERE workspace_id=%s AND application_id=%s AND policy_id=%s FOR UPDATE''', ids).fetchone()
                if current is None and expected_state_token is not None:
                    raise ValueError('PLANNING_OPERATION_POLICY_UNAVAILABLE')
                if current is not None:
                    if expected_state_token is None:
                        raise ValueError('PLANNING_OPERATION_POLICY_EXPECTED_STATE_TOKEN_REQUIRED')
                    if current['state_token'] != expected_state_token:
                        raise ValueError('PLANNING_OPERATION_POLICY_STATE_STALE')
                revision, token = state['commit_revision'] + 1, new_state_token()
                policy_revision = state['policy_revision'] + (1 if current and current['status'] == 'Active' else 0)
                db.execute('''INSERT INTO epm.planning_operation_policy(
                    workspace_id,application_id,policy_id,state_token,status,kind,
                    effective_from,effective_before,definition,canonical_digest,
                    updated_operation_id,updated_issuer,updated_subject_id)
                    VALUES(%s,%s,%s,%s,'Saved',%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(workspace_id,application_id,policy_id) DO UPDATE SET
                     state_token=EXCLUDED.state_token,status='Saved',kind=EXCLUDED.kind,
                     effective_from=EXCLUDED.effective_from,effective_before=EXCLUDED.effective_before,
                     definition=EXCLUDED.definition,canonical_digest=EXCLUDED.canonical_digest,
                     updated_operation_id=EXCLUDED.updated_operation_id,
                     updated_issuer=EXCLUDED.updated_issuer,
                     updated_subject_id=EXCLUDED.updated_subject_id,updated_at=clock_timestamp()''',
                    (*ids, token, compiled.kind, compiled.document['effectiveFrom'],
                     compiled.document['effectiveBefore'], Jsonb(compiled.document), compiled.digest,
                     idempotency_key, self.identity.issuer, self.identity.subject_id))
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, scope.workspace_id, scope.application_id))
                result = {'policyId': compiled.document['policyId'], 'stateToken': token,
                    'status': 'Saved', 'kind': compiled.kind, 'canonicalDigest': compiled.digest,
                    'policyRevision': policy_revision}
                self._receipt(db, scope, idempotency_key, digest, revision, result)
                return result

    def read(self, scope, policy_id):
        self._target(policy_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db, scope, READ)
                return self._result(self._row(db, scope, policy_id), definition=True)

    def list(self, scope, *, limit=100, after_policy_id=None,
             expected_collection_token=None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('PLANNING_OPERATION_POLICY_LIST_INVALID')
        if after_policy_id is not None:
            self._target(after_policy_id)
            require_state_token(expected_collection_token,
                error='PLANNING_OPERATION_POLICY_COLLECTION_TOKEN_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                self._prepare(db, scope, LIST)
                ids = (scope.workspace_id, scope.application_id)
                all_rows = db.execute('''SELECT policy_id,state_token FROM epm.planning_operation_policy
                    WHERE workspace_id=%s AND application_id=%s ORDER BY policy_id''', ids).fetchall()
                token = collection_token((row['policy_id'], row['state_token']) for row in all_rows)
                if expected_collection_token is not None and token != expected_collection_token:
                    raise ValueError('PLANNING_OPERATION_POLICY_LIST_STALE')
                rows = db.execute(f'''SELECT {_SELECT} FROM epm.planning_operation_policy
                    WHERE workspace_id=%s AND application_id=%s AND policy_id>%s
                    ORDER BY policy_id LIMIT %s''', (*ids, after_policy_id or '', limit + 1)).fetchall()
                return {'policies': [self._result(row, definition=True) for row in rows[:limit]],
                    'collectionToken': token,
                    'nextAfterPolicyId': rows[limit - 1]['policy_id'] if len(rows) > limit else None}

    def change(self, scope, *, policy_id, expected_state_token,
               canonical_digest, idempotency_key, deactivate):
        self._target(policy_id)
        require_state_token(expected_state_token,
            error='PLANNING_OPERATION_POLICY_MUTATION_INVALID')
        if (not isinstance(canonical_digest, str) or not re.fullmatch(r'[0-9a-f]{64}', canonical_digest)):
            raise ValueError('PLANNING_OPERATION_POLICY_MUTATION_INVALID')
        _request_key(idempotency_key)
        function = DEACTIVATE if deactivate else ACTIVATE
        command = {'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id], 'function': function,
            'policyId': policy_id, 'expectedStateToken': expected_state_token,
            'canonicalDigest': canonical_digest, 'idempotencyKey': idempotency_key}
        digest = _digest(command)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                app = self._prepare(db, scope, function, writable=True)
                prior = self._replay(db, scope, idempotency_key, digest)
                if prior is not None:
                    return prior
                row = self._row(db, scope, policy_id, lock=True)
                if row['state_token'] != expected_state_token:
                    raise ValueError('PLANNING_OPERATION_POLICY_STATE_STALE')
                compiled = self._verify(row)
                if compiled.digest != canonical_digest:
                    raise ValueError('PLANNING_OPERATION_POLICY_DIGEST_MISMATCH')
                if deactivate and row['status'] != 'Active':
                    raise ValueError('PLANNING_OPERATION_POLICY_NOT_ACTIVE')
                if not deactivate and row['status'] == 'Active':
                    raise ValueError('PLANNING_OPERATION_POLICY_ALREADY_ACTIVE')
                token, revision = new_state_token(), app['commit_revision'] + 1
                policy_revision = app['policy_revision'] + 1
                status = 'Saved' if deactivate else 'Active'
                db.execute('''UPDATE epm.planning_operation_policy SET status=%s,state_token=%s,
                    updated_operation_id=%s,updated_issuer=%s,
                    updated_subject_id=%s,updated_at=clock_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND policy_id=%s''',
                    (status, token, idempotency_key, self.identity.issuer,
                     self.identity.subject_id, scope.workspace_id, scope.application_id, policy_id))
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, scope.workspace_id, scope.application_id))
                result = {'policyId': policy_id, 'stateToken': token, 'kind': compiled.kind,
                    'canonicalDigest': compiled.digest, 'status': status,
                    'policyRevision': policy_revision}
                self._receipt(db, scope, idempotency_key, digest, revision, result)
                return result

    def execute_program(self, scope, program, *, idempotency_key=None):
        function, args = _program(program)
        if function == SAVE:
            if (set(args) - {'definition', 'expectedStateToken'} or 'definition' not in args
                    or idempotency_key is None):
                raise ValueError('PLANNING_OPERATION_POLICY_ARGUMENTS_INVALID')
            return self.save(scope, args['definition'],
                expected_state_token=args.get('expectedStateToken'), idempotency_key=idempotency_key)
        if function in (ACTIVATE, DEACTIVATE):
            if (set(args) != {'policyId', 'expectedStateToken', 'canonicalDigest'}
                    or idempotency_key is None):
                raise ValueError('PLANNING_OPERATION_POLICY_ARGUMENTS_INVALID')
            return self.change(scope, policy_id=args['policyId'],
                expected_state_token=args['expectedStateToken'], canonical_digest=args['canonicalDigest'],
                idempotency_key=idempotency_key, deactivate=function == DEACTIVATE)
        raise ValueError('PLANNING_OPERATION_POLICY_WRITE_INVALID')

    def read_program(self, scope, program):
        function, args = _program(program)
        if function == READ and set(args) == {'policyId'}:
            return self.read(scope, args['policyId'])
        if function == LIST and not set(args) - {
                'limit', 'afterPolicyId', 'expectedCollectionToken'}:
            if ('afterPolicyId' in args) != ('expectedCollectionToken' in args):
                raise ValueError('PLANNING_OPERATION_POLICY_LIST_INVALID')
            return self.list(scope, limit=args.get('limit', 100),
                after_policy_id=args.get('afterPolicyId'),
                expected_collection_token=args.get('expectedCollectionToken'))
        raise ValueError('PLANNING_OPERATION_POLICY_READ_INVALID')

    @staticmethod
    def _row(db, scope, policy_id, *, lock=False):
        row = db.execute(f'''SELECT {_SELECT} FROM epm.planning_operation_policy
            WHERE workspace_id=%s AND application_id=%s AND policy_id=%s''' +
            (' FOR UPDATE' if lock else ''),
            (scope.workspace_id, scope.application_id, policy_id)).fetchone()
        if row is None:
            raise ValueError('PLANNING_OPERATION_POLICY_UNAVAILABLE')
        return row

    def _replay(self, db, scope, operation_id, digest):
        row = db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
            WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
            (scope.workspace_id, scope.application_id, operation_id)).fetchone()
        if row is None:
            return None
        if row['command_digest'] != digest or row['actor_id'] != self.identity.subject_id:
            raise ValueError('PLANNING_OPERATION_POLICY_IDEMPOTENCY_CONFLICT')
        return row['result']

    def _receipt(self, db, scope, operation_id, digest, revision, result):
        db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
            operation_id,command_digest,actor_id,committed_revision,result)
            VALUES(%s,%s,%s,%s,%s,%s,%s)''',
            (scope.workspace_id, scope.application_id, operation_id, digest,
             self.identity.subject_id, revision, Jsonb(result)))


def _request_key(value):
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise ValueError('PLANNING_OPERATION_POLICY_IDEMPOTENCY_KEY_INVALID')


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
