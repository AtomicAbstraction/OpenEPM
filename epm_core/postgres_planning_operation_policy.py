"""Public immutable lifecycle for reusable generic planning-operation policies."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .planning_operation_policy import compile_planning_operation_policy
from .postgres_access import (
    PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role,
)
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore


SAVE = 'planning.operation.policy.save'
READ = 'planning.operation.policy.read'
LIST = 'planning.operation.policy.list'
PUBLISH = 'planning.operation.policy.publish'
DEACTIVATE = 'planning.operation.policy.deactivate'
FUNCTIONS = frozenset((SAVE, READ, LIST, PUBLISH, DEACTIVATE))
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def catalog() -> dict:
    common = {'permission': 'admin', 'requiredCapabilities': [],
              'previewRequired': False, 'workClass': 'short'}
    return {
        SAVE: {**common, 'mode': 'immutable_policy_write',
               'idempotencyRequired': False,
               'arguments': {'definition':
                   'bounded reusable Seed/Driver/Rollup/Spread/Allocation policy'},
               'result': 'immutable version and canonical digest'},
        READ: {**common, 'mode': 'read', 'idempotencyRequired': False,
               'arguments': {'policyId': 'stable ID',
                             'version': 'positive immutable version'},
               'result': 'verified immutable policy definition'},
        LIST: {**common, 'mode': 'read', 'idempotencyRequired': False,
               'arguments': {'limit': 'optional 1-100',
                             'afterPolicyId': 'optional composite cursor ID',
                             'afterVersion': 'optional composite cursor version'},
               'result': 'verified policy versions and composite cursor'},
        PUBLISH: {**common, 'mode': 'atomic_policy_write',
                  'idempotencyRequired': True,
                  'arguments': {'policyId': 'stable ID',
                                'version': 'positive version',
                                'expectedPointerVersion':
                                    'current nonnegative pointer version'},
                  'result': 'active immutable version pointer and receipt'},
        DEACTIVATE: {**common, 'mode': 'atomic_policy_write',
                     'idempotencyRequired': True,
                     'arguments': {'policyId': 'active policy ID',
                                   'version': 'active version',
                                   'expectedPointerVersion':
                                       'current positive pointer version'},
                     'result': 'inactive pointer and receipt'}}


def _program(program):
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] not in FUNCTIONS
            or not isinstance(program['arguments'], dict)):
        raise ValueError('PLANNING_OPERATION_POLICY_PROGRAM_INVALID')
    return program['function'], program['arguments']


class PostgresPlanningOperationPolicies:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn, 'epm_runtime', (
            'planning_operation_policy_version',
            'planning_operation_policy_state'))
        self.dsn, self.identity = dsn, identity

    def _prepare(self, db, scope, function):
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        access = PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'admin', function=function)
        state = db.execute('''SELECT a.status,s.processing_mode,
            s.metadata_revision,s.policy_revision,s.commit_revision
            FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if state is None or state['status'] != 'Active' or (
                state['processing_mode'] != 'Active'):
            raise ValueError('APPLICATION_NOT_WRITABLE')
        return access, state

    @staticmethod
    def _target(policy_id, version):
        if (not isinstance(policy_id, str) or not _ID.fullmatch(policy_id)
                or type(version) is not int or version < 1):
            raise ValueError('PLANNING_OPERATION_POLICY_TARGET_INVALID')

    def _verify(self, row):
        if row is None:
            raise ValueError('PLANNING_OPERATION_POLICY_UNAVAILABLE')
        compiled = compile_planning_operation_policy(row['definition'])
        if (compiled.document['policyId'] != row['policy_id']
                or compiled.document['version'] != row['version']
                or compiled.kind != row['kind']
                or compiled.digest != row['canonical_digest']):
            raise ValueError('PLANNING_OPERATION_POLICY_STORAGE_INVALID')
        return compiled

    @staticmethod
    def _result(compiled, row, *, definition=False):
        value = {'policyId': compiled.document['policyId'],
                 'version': compiled.document['version'],
                 'kind': compiled.kind, 'canonicalDigest': compiled.digest,
                 'effectiveFrom': compiled.document['effectiveFrom'],
                 'effectiveBefore': compiled.document['effectiveBefore'],
                 'creator': {'issuer': row['creator_issuer'],
                             'subjectId': row['creator_subject_id']},
                 'createdAt': row['created_at']}
        if definition:
            value['definition'] = row['definition']
        return value

    def save(self, scope: ApplicationScope, definition: object) -> dict:
        compiled = compile_planning_operation_policy(definition)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                _, state = self._prepare(db, scope, SAVE)
                row = db.execute('''SELECT policy_id,version,kind,definition,
                    canonical_digest,creator_issuer,creator_subject_id,created_at
                    FROM epm.planning_operation_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     compiled.document['policyId'],
                     compiled.document['version'])).fetchone()
                if row:
                    stored = self._verify(row)
                    if stored.digest != compiled.digest:
                        raise ValueError(
                            'PLANNING_OPERATION_POLICY_VERSION_CONFLICT')
                    return self._result(stored, row)
                pointer = db.execute('''SELECT latest_version
                    FROM epm.planning_operation_policy_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     compiled.document['policyId'])).fetchone()
                expected = pointer['latest_version'] + 1 if pointer else 1
                if compiled.document['version'] != expected:
                    raise ValueError(
                        'PLANNING_OPERATION_POLICY_VERSION_NOT_NEXT')
                row = db.execute('''INSERT INTO
                    epm.planning_operation_policy_version(
                    workspace_id,application_id,policy_id,version,kind,
                    effective_from,effective_before,definition,canonical_digest,
                    creator_issuer,creator_subject_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING policy_id,version,kind,definition,
                    canonical_digest,creator_issuer,creator_subject_id,created_at''',
                    (scope.workspace_id, scope.application_id,
                     compiled.document['policyId'],
                     compiled.document['version'], compiled.kind,
                     compiled.document['effectiveFrom'],
                     compiled.document['effectiveBefore'],
                     Jsonb(compiled.document), compiled.digest,
                     self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if pointer:
                    db.execute('''UPDATE epm.planning_operation_policy_state
                        SET latest_version=%s,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND policy_id=%s''',
                        (compiled.document['version'], scope.workspace_id,
                         scope.application_id,
                         compiled.document['policyId']))
                else:
                    db.execute('''INSERT INTO
                        epm.planning_operation_policy_state(
                        workspace_id,application_id,policy_id,latest_version,
                        active_version,pointer_version,state_revision)
                        VALUES(%s,%s,%s,%s,NULL,0,0)''',
                        (scope.workspace_id, scope.application_id,
                         compiled.document['policyId'],
                         compiled.document['version']))
                return self._result(compiled, row)

    def read(self, scope, policy_id, version):
        self._target(policy_id, version)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=READ)
                row = db.execute('''SELECT policy_id,version,kind,definition,
                    canonical_digest,creator_issuer,creator_subject_id,created_at
                    FROM epm.planning_operation_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     policy_id, version)).fetchone()
                return self._result(self._verify(row), row, definition=True)

    def list(self, scope, *, limit=100, after_policy_id=None,
             after_version=None):
        if (type(limit) is not int or not 1 <= limit <= 100
                or ((after_policy_id is None) != (after_version is None))
                or (after_policy_id is not None and (
                    not isinstance(after_policy_id, str)
                    or not _ID.fullmatch(after_policy_id)
                    or type(after_version) is not int
                    or after_version < 1))):
            raise ValueError('PLANNING_OPERATION_POLICY_LIST_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=LIST)
                rows = db.execute('''SELECT policy_id,version,kind,definition,
                    canonical_digest,creator_issuer,creator_subject_id,created_at
                    FROM epm.planning_operation_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND (%s::text IS NULL OR(policy_id,version)>(%s,%s))
                    ORDER BY policy_id,version LIMIT %s''',
                    (scope.workspace_id, scope.application_id,
                     after_policy_id, after_policy_id, after_version,
                     limit + 1)).fetchall()
                values = [self._result(self._verify(row), row, definition=True)
                          for row in rows[:limit]]
                return {'policies': values, 'nextCursor': (
                    {'afterPolicyId': values[-1]['policyId'],
                     'afterVersion': values[-1]['version']}
                    if len(rows) > limit else None)}

    def change(self, scope, *, policy_id, version,
               expected_pointer_version, idempotency_key, deactivate):
        self._target(policy_id, version)
        if (type(expected_pointer_version) is not int
                or expected_pointer_version < 0
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('PLANNING_OPERATION_POLICY_MUTATION_INVALID')
        function = DEACTIVATE if deactivate else PUBLISH
        command = {'scope': [scope.workspace_id, scope.application_id],
            'actor': [self.identity.issuer, self.identity.subject_id],
            'function': function, 'policyId': policy_id, 'version': version,
            'expectedPointerVersion': expected_pointer_version,
            'idempotencyKey': idempotency_key}
        digest = sha256(json.dumps(command, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                _, app = self._prepare(db, scope, function)
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != digest
                            or prior['actor_id'] != self.identity.subject_id):
                        raise ValueError(
                            'PLANNING_OPERATION_POLICY_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                pointer = db.execute('''SELECT latest_version,active_version,
                    pointer_version FROM epm.planning_operation_policy_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     policy_id)).fetchone()
                if pointer is None:
                    raise ValueError('PLANNING_OPERATION_POLICY_UNAVAILABLE')
                if pointer['pointer_version'] != expected_pointer_version:
                    raise ValueError(
                        'PLANNING_OPERATION_POLICY_POINTER_STALE')
                row = db.execute('''SELECT policy_id,version,kind,definition,
                    canonical_digest,creator_issuer,creator_subject_id,created_at
                    FROM epm.planning_operation_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     policy_id, version)).fetchone()
                compiled = self._verify(row)
                if deactivate:
                    if pointer['active_version'] != version:
                        raise ValueError(
                            'PLANNING_OPERATION_POLICY_ACTIVE_MISMATCH')
                    active = None
                else:
                    if pointer['active_version'] == version:
                        raise ValueError(
                            'PLANNING_OPERATION_POLICY_ALREADY_ACTIVE')
                    active = version
                next_pointer = expected_pointer_version + 1
                revision = app['commit_revision'] + 1
                policy_revision = app['policy_revision'] + 1
                db.execute('''UPDATE epm.planning_operation_policy_state
                    SET active_version=%s,pointer_version=%s,
                    state_revision=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s''',
                    (active, next_pointer, revision, scope.workspace_id,
                     scope.application_id, policy_id))
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, scope.workspace_id,
                     scope.application_id))
                result = {'policyId': policy_id, 'version': version,
                    'kind': compiled.kind,
                    'canonicalDigest': compiled.digest,
                    'status': 'Inactive' if deactivate else 'Active',
                    'pointerVersion': next_pointer,
                    'policyRevision': policy_revision,
                    'committedRevision': revision}
                db.execute('''INSERT INTO epm.operation_receipt(
                    workspace_id,application_id,operation_id,command_digest,
                    actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key, digest, self.identity.subject_id,
                     revision, Jsonb(result)))
                return result

    def execute_program(self, scope, program, *, idempotency_key=None):
        function, args = _program(program)
        if function == SAVE:
            if set(args) != {'definition'} or idempotency_key is not None:
                raise ValueError(
                    'PLANNING_OPERATION_POLICY_ARGUMENTS_INVALID')
            return self.save(scope, args['definition'])
        if function in (PUBLISH, DEACTIVATE):
            if (set(args) != {'policyId', 'version',
                              'expectedPointerVersion'}
                    or idempotency_key is None):
                raise ValueError(
                    'PLANNING_OPERATION_POLICY_ARGUMENTS_INVALID')
            return self.change(scope, policy_id=args['policyId'],
                version=args['version'],
                expected_pointer_version=args['expectedPointerVersion'],
                idempotency_key=idempotency_key,
                deactivate=function == DEACTIVATE)
        raise ValueError('PLANNING_OPERATION_POLICY_WRITE_INVALID')

    def read_program(self, scope, program):
        function, args = _program(program)
        if function == READ and set(args) == {'policyId', 'version'}:
            return self.read(scope, args['policyId'], args['version'])
        if function == LIST and not set(args) - {
                'limit', 'afterPolicyId', 'afterVersion'}:
            return self.list(scope, limit=args.get('limit', 100),
                after_policy_id=args.get('afterPolicyId'),
                after_version=args.get('afterVersion'))
        raise ValueError('PLANNING_OPERATION_POLICY_READ_INVALID')
