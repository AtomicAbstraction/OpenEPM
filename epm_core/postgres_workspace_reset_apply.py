"""Fixed owner-credential reset executor for the isolated apply service.

This module is deliberately absent from general runtime and workspace MCP
listeners. The deployment must independently attest replacement readiness and
retirement of its workspace endpoints before constructing this executor.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import re
import time

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_reset_schema import EXPECTED_SCHEMA_FINGERPRINT
from .postgres_workspace_lifecycle import PostgresWorkspaceLifecycle
from .postgres_workspace_reset import (
    PostgresWorkspaceResetPreview, _canonical, reset_active_work_blockers)


FUNCTION = 'workspace.reset.apply'
_OPERATION = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def compile_reset_apply(program: object) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)):
        raise ValueError('V2_RESET_APPLY_ARGUMENTS_INVALID')
    args = program['arguments']
    if (set(args) != {'manifestDigest', 'expiresAt', 'signature'}
            or not isinstance(args['manifestDigest'], str)
            or not _DIGEST.fullmatch(args['manifestDigest'])
            or type(args['expiresAt']) is not int
            or not isinstance(args['signature'], str)
            or not _DIGEST.fullmatch(args['signature'])):
        raise ValueError('V2_RESET_APPLY_ARGUMENTS_INVALID')
    return args


class PostgresWorkspaceResetApply:
    def __init__(self, owner_dsn: str, *, identity: VerifiedIdentity,
                 secret: bytes, endpoint_inventory_json: str | None,
                 replacement_ready: bool = False,
                 endpoints_retired: bool = False):
        if not isinstance(owner_dsn, str) or not owner_dsn:
            raise ValueError('Migration-owner DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('A server-owned reset secret of 32+ bytes is required')
        if (type(replacement_ready) is not bool
                or type(endpoints_retired) is not bool):
            raise ValueError('Deployment readiness flags must be booleans')
        self.owner_dsn = owner_dsn
        self.identity = identity
        self.secret = secret
        self.endpoint_inventory_json = endpoint_inventory_json
        self.replacement_ready = replacement_ready
        self.endpoints_retired = endpoints_retired

    def assert_owner_role(self) -> None:
        with connect_postgres(self.owner_dsn) as db:
            owner = db.execute('''SELECT pg_get_userbyid(p.proowner)
                FROM pg_proc p WHERE p.oid =
                'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'
                ::regprocedure''').fetchone()[0]
            current = db.execute('SELECT current_user').fetchone()[0]
            if current != owner:
                raise ValueError('RESET_MIGRATION_OWNER_REQUIRED')

    def apply(self, workspace_id: str, program: object, *,
              idempotency_key: str) -> dict:
        args = compile_reset_apply(program)
        if (not isinstance(workspace_id, str)
                or not 1 <= len(workspace_id) <= 200
                or not isinstance(idempotency_key, str)
                or not _OPERATION.fullmatch(idempotency_key)):
            raise ValueError('V2_RESET_APPLY_TARGET_INVALID')
        if not self.replacement_ready:
            raise ValueError('RESET_REPLACEMENT_NOT_READY')
        if not self.endpoints_retired:
            raise ValueError('RESET_ENDPOINTS_NOT_RETIRED')
        actor = sha256((self.identity.issuer + '\0' +
                        self.identity.subject_id).encode()).hexdigest()
        preview = PostgresWorkspaceResetPreview(
            self.owner_dsn, identity=self.identity, secret=self.secret,
            endpoint_inventory_json=self.endpoint_inventory_json)
        with connect_postgres(self.owner_dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 300000)
                PostgresWorkspaceLifecycle._set_workspace(db, workspace_id)
                PostgresAccessChecker.lock_workspace(
                    db, workspace_id, exclusive=True)
                prior = db.execute('''SELECT manifest_digest,
                    schema_fingerprint,actor_digest,result FROM
                    epm.workspace_reset_receipt WHERE target_workspace_id=%s
                    AND operation_id=%s''',
                    (workspace_id, idempotency_key)).fetchone()
                if prior:
                    if (prior['manifest_digest'] != args['manifestDigest']
                            or prior['schema_fingerprint'] !=
                                EXPECTED_SCHEMA_FINGERPRINT
                            or prior['actor_digest'] != actor):
                        raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return prior['result']
                if preview._require_owner(db, workspace_id,
                                          self.identity) != 'Maintenance':
                    raise ValueError('WORKSPACE_NOT_IN_MAINTENANCE')
                signed = {'workspaceId': workspace_id,
                          'issuer': self.identity.issuer,
                          'subjectId': self.identity.subject_id,
                          'manifestDigest': args['manifestDigest'],
                          'expiresAt': args['expiresAt']}
                expected = hmac.new(self.secret,
                    b'workspace-reset-prepare-v2\x00' + _canonical(signed),
                    sha256).hexdigest()
                if (args['expiresAt'] < int(time.time())
                        or not hmac.compare_digest(expected,
                                                   args['signature'])):
                    raise ValueError('RESET_MANIFEST_INVALID_OR_EXPIRED')
                manifest = preview._manifest(db, workspace_id)
                if sha256(_canonical(manifest)).hexdigest() != args['manifestDigest']:
                    raise ValueError('RESET_MANIFEST_STALE')
                coverage = manifest['schemaCoverage']
                if (not coverage['matchesExpected']
                        or coverage['globalToWorkspaceReferences']
                        or coverage['externalIncomingReferences']
                        or coverage['otherRelations']
                        or coverage['cycleTables']):
                    raise ValueError('RESET_SCHEMA_COVERAGE_DRIFT')
                inventory = manifest['endpointInventory']
                if (inventory['source'] != 'deployment_config'
                        or not any(item['kind'] == 'workspace_mcp'
                                   for item in inventory['endpoints'])):
                    raise ValueError('RESET_ENDPOINT_INVENTORY_REQUIRED')
                if any(item['schema_epoch'] is None
                       for item in manifest['applications']):
                    raise ValueError('RESET_APPLICATION_STATE_MISSING')
                blockers=reset_active_work_blockers(manifest)
                if blockers: raise ValueError(blockers[0])
                return db.execute('''SELECT epm.delete_workspace_reset_owner_only(
                    %s,%s,%s,%s,%s) AS result''',
                    (workspace_id, idempotency_key, args['manifestDigest'],
                     EXPECTED_SCHEMA_FINGERPRINT, actor)).fetchone()['result']
