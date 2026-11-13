"""Incarnation-bound application retirement through the lifecycle credential.

Prepare inspects one application. Quiesce closes its admission boundary. Apply
atomically removes only that application's rows after live leases drain; the
only retained record is a minimal actor/target/terminal-outcome audit.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import re
import psycopg

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_lifecycle_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_statement_timeout, configure_lock_wait
from .postgres_reset_schema import inspect_reset_schema, EXPECTED_SCHEMA_FINGERPRINT
from .postgres_workspace_lifecycle import PostgresWorkspaceLifecycle

PREPARE = 'workspace.application.purge.prepare'
QUIESCE = 'workspace.application.purge.quiesce'
APPLY = 'workspace.application.purge.apply'
FUNCTIONS = frozenset((PREPARE, QUIESCE, APPLY))
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')


def _digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def catalog() -> dict:
    common = {'permission': 'workspace_admin', 'previewRequired': False,
              'workClass': 'medium', 'requiredCapabilities': []}
    target = {'applicationId': 'exact application ID', 'createdAt': 'exact creation timestamp returned by prepare'}
    return {
        PREPARE: {**common, 'mode': 'read_only', 'idempotencyRequired': False,
            'arguments': {'applicationId': 'exact application ID'},
            'result': 'application incarnation, revisions, scoped inventory, live leases and digest; no mutation'},
        QUIESCE: {**common, 'mode': 'atomic_write', 'idempotencyRequired': True,
            'arguments': {**target, 'manifestDigest': 'current prepare digest'},
            'result': 'one application in Deleting; existing work cannot publish and live leases must drain'},
        APPLY: {**common, 'mode': 'atomic_write', 'idempotencyRequired': True, 'workClass': 'long',
            'arguments': target,
            'result': 'minimal terminal actor receipt; all targeted application content deleted, workspace retained'},
    }


def parse(program: object) -> tuple[str, dict]:
    if (type(program) is not dict or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program.get('languageVersion')) is not int or program['languageVersion'] != 2
            or type(program.get('function')) is not str or program['function'] not in FUNCTIONS
            or type(program.get('arguments')) is not dict):
        raise ValueError('APPLICATION_PURGE_PROGRAM_INVALID')
    name, args = program['function'], program['arguments']
    if set(args) != set(catalog()[name]['arguments']):
        raise ValueError('APPLICATION_PURGE_ARGUMENTS_INVALID')
    if type(args['applicationId']) is not str or not _ID.fullmatch(args['applicationId']):
        raise ValueError('APPLICATION_PURGE_TARGET_INVALID')
    if name != PREPARE:
        try:
            timestamp = datetime.fromisoformat(args['createdAt'])
            if timestamp.tzinfo is None: raise ValueError()
        except (ValueError, TypeError, AttributeError) as error:
            raise ValueError('APPLICATION_PURGE_INCARNATION_INVALID') from error
    if name == QUIESCE and (type(args['manifestDigest']) is not str or not _HEX.fullmatch(args['manifestDigest'])):
        raise ValueError('APPLICATION_PURGE_MANIFEST_INVALID')
    return name, args


class PostgresApplicationPurge:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_lifecycle_role(dsn)
        self.dsn, self.identity = dsn, identity

    def _authorize(self, db, workspace_id: str, application_id: str, *, exclusive: bool = False,
                   applying: bool = False) -> None:
        PostgresWorkspaceLifecycle._set_workspace(db, workspace_id, application_id)
        configure_statement_timeout(db, 300000 if applying else 30000)
        configure_lock_wait(db)
        PostgresAccessChecker.lock_workspace(db, workspace_id, exclusive=exclusive)
        PostgresWorkspaceLifecycle._require_administrator(db, workspace_id, self.identity)

    @staticmethod
    def _coverage(db) -> None:
        coverage = inspect_reset_schema(db)
        if (not coverage['matchesExpected'] or coverage['externalIncomingReferences']
                or coverage['globalToWorkspaceReferences'] or coverage['otherRelations'] or coverage['cycleTables']):
            raise ValueError('APPLICATION_PURGE_SCHEMA_COVERAGE_DRIFT')

    @classmethod
    def _manifest(cls, db, workspace_id: str, application_id: str) -> dict:
        cls._coverage(db)
        inventory = db.execute('SELECT epm.application_purge_inventory(%s,%s) AS inventory',
            (workspace_id, application_id)).fetchone()['inventory']
        row = inventory.pop('target')
        manifest = {'workspaceId': workspace_id, 'applicationId': application_id, 'name': row['name'],
            'createdAt': datetime.fromisoformat(row['created_at']).isoformat(), 'status': row['status'],
            'processingMode': row['processing_mode'], 'schemaEpoch': row['schema_epoch'],
            'revisions': {'metadata': row['metadata_revision'], 'data': row['data_revision'],
                          'policy': row['policy_revision'], 'commit': row['commit_revision']},
            'schemaFingerprint': EXPECTED_SCHEMA_FINGERPRINT, **inventory}
        return {'manifest': manifest, 'manifestDigest': _digest(manifest)}

    def execute(self, workspace_id: str, program: dict, *, idempotency_key: str | None = None) -> dict:
        try:
            return self._execute(workspace_id,program,idempotency_key=idempotency_key)
        except psycopg.Error as error:
            code=error.diag.message_primary
            if code in {'APPLICATION_PURGE_INCARNATION_CHANGED','APPLICATION_PURGE_TARGET_NOT_FOUND',
                        'APPLICATION_PURGE_QUIESCE_REQUIRED','APPLICATION_PURGE_WORKERS_ACTIVE',
                        'APPLICATION_PURGE_SCOPE_DENIED','IDEMPOTENCY_KEY_REUSED'}:
                raise ValueError(code) from error
            raise

    def _execute(self, workspace_id: str, program: dict, *, idempotency_key: str | None = None) -> dict:
        name, args = parse(program)
        if type(workspace_id) is not str or not 1 <= len(workspace_id) <= 200:
            raise ValueError('APPLICATION_PURGE_WORKSPACE_INVALID')
        if name == PREPARE:
            if idempotency_key is not None: raise ValueError('APPLICATION_PURGE_READ_KEY_UNEXPECTED')
        elif type(idempotency_key) is not str or not _KEY.fullmatch(idempotency_key):
            raise ValueError('APPLICATION_PURGE_REQUEST_KEY_INVALID')
        app = args['applicationId']
        actor = sha256((self.identity.issuer + '\0' + self.identity.subject_id).encode()).hexdigest()
        digest = _digest({'workspaceId': workspace_id, 'program': program})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._authorize(db, workspace_id, app, exclusive=name == QUIESCE, applying=name == APPLY)
                if name == PREPARE: return self._manifest(db, workspace_id, app)
                # Current workspace administration is checked before every replay,
                # including after the target application no longer exists.
                if name == APPLY:
                    self._coverage(db)
                    return db.execute('SELECT epm.apply_application_purge(%s,%s,%s,%s,%s,%s,%s) AS result',
                        (workspace_id, app, args['createdAt'], idempotency_key, digest, actor,
                         EXPECTED_SCHEMA_FINGERPRINT)).fetchone()['result']
                prior = db.execute('''SELECT command_digest,actor_digest,result FROM epm.workspace_lifecycle_receipt
                    WHERE workspace_id=%s AND operation_id=%s''', (workspace_id, idempotency_key)).fetchone()
                if prior is not None:
                    if prior['command_digest'] != digest or prior['actor_digest'] != actor:
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return prior['result']
                observed = self._manifest(db, workspace_id, app)
                if datetime.fromisoformat(observed['manifest']['createdAt']) != datetime.fromisoformat(args['createdAt']):
                    raise ValueError('APPLICATION_PURGE_INCARNATION_CHANGED')
                if observed['manifestDigest'] != args['manifestDigest']:
                    raise ValueError('APPLICATION_PURGE_MANIFEST_STALE')
                db.execute('SELECT epm.quiesce_application_purge(%s,%s,%s)',
                    (workspace_id, app, args['createdAt']))
                result = {'workspaceId': workspace_id, 'applicationId': app, 'createdAt': args['createdAt'],
                          'status': 'Deleting', 'operationId': idempotency_key,
                          'activeLeases': observed['manifest']['activeLeases']}
                db.execute('''INSERT INTO epm.workspace_lifecycle_receipt
                    (workspace_id,operation_id,command_digest,actor_digest,result) VALUES (%s,%s,%s,%s,%s)''',
                    (workspace_id, idempotency_key, digest, actor, Jsonb(result)))
                return result
