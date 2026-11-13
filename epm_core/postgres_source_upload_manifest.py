"""Fixed-core repository for immutable source/upload batch manifests.

Callers supply business metadata, never an authored creator identity.  The
verified identity injected into this repository is persisted and must own the
source batch.  Retention is metadata only and has no fact-deletion behavior.
"""
from __future__ import annotations

import json
import re

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


_BATCH = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,79}\Z')
_ORIGIN_KINDS = frozenset(
    ('file', 'mcp', 'schedule', 'system-generated'))
_RETENTION = frozenset(('retained', 'held', 'expired'))


def _canonical_schema(value: object) -> tuple[dict, str]:
    if not isinstance(value, dict):
        raise ValueError('SOURCE_UPLOAD_SCHEMA_INVALID')
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (RecursionError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError('SOURCE_UPLOAD_SCHEMA_INVALID') from error
    if len(encoded) > 65536:
        raise ValueError('SOURCE_UPLOAD_SCHEMA_INVALID')
    # Round-trip to detach mutable caller-owned mappings and normalize tuples.
    schema = json.loads(encoded)
    return schema, _canonical_digest(schema)


def _record(row: dict, *, duplicate: bool = False) -> dict:
    return {
        'batchId': row['batch_id'],
        'requestKey': row['manifest_request_key'],
        'originKind': row['manifest_origin_kind'],
        'originRef': row['manifest_origin_ref'],
        'schemaVersion': row['manifest_schema_version'],
        'schema': row['manifest_schema'],
        'schemaDigest': row['manifest_schema_digest'],
        'contentDigest': row['manifest_content_digest'],
        'manifestDigest': row['manifest_digest'],
        'creator': {'issuer': row['manifest_creator_issuer'],
                    'subjectId': row['manifest_creator_subject_id']},
        'createdAt': row['manifest_created_at'],
        'retention': {
            'status': row['manifest_retention_status'],
            'reason': row['manifest_retention_reason'],
            'issuer': row['manifest_retention_issuer'],
            'subjectId': row['manifest_retention_subject_id'],
            'updatedAt': row['manifest_retention_updated_at'],
        },
        'duplicate': duplicate,
    }


class PostgresSourceUploadManifest:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def create(self, scope: ApplicationScope, batch_id: str, *,
               request_key: str, origin_kind: str, origin_ref: str,
               schema_version: str, declared_schema: dict,
               content_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(batch_id, str) or not _BATCH.fullmatch(batch_id)
                or not isinstance(request_key, str)
                or not _KEY.fullmatch(request_key)
                or origin_kind not in _ORIGIN_KINDS
                or not isinstance(origin_ref, str)
                or not 1 <= len(origin_ref) <= 1000
                or any(ord(character) < 32 or ord(character) == 127
                       for character in origin_ref)
                or not isinstance(schema_version, str)
                or not _VERSION.fullmatch(schema_version)
                or not isinstance(content_digest, str)
                or not _DIGEST.fullmatch(content_digest)):
            raise ValueError('SOURCE_UPLOAD_MANIFEST_INVALID')
        schema, schema_digest = _canonical_schema(declared_schema)
        manifest_digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'batchId': batch_id,
            'origin': {'kind': origin_kind, 'ref': origin_ref},
            'schemaVersion': schema_version,
            'schema': schema,
            'schemaDigest': schema_digest,
            'contentDigest': content_digest,
            'creator': [self.identity.issuer, self.identity.subject_id],
        })
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                prior = db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND manifest_creator_issuer=%s
                    AND manifest_creator_subject_id=%s
                    AND manifest_request_key=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     request_key)).fetchone()
                if prior is not None:
                    if (prior['batch_id'] == batch_id
                            and prior['manifest_digest'] == manifest_digest):
                        return _record(prior, duplicate=True)
                    raise ValueError('SOURCE_UPLOAD_IDEMPOTENCY_CONFLICT')
                batch = db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     batch_id)).fetchone()
                if (batch is None or batch['issuer'] != self.identity.issuer
                        or batch['subject_id'] != self.identity.subject_id):
                    raise ValueError('SOURCE_UPLOAD_BATCH_UNAVAILABLE')
                if batch['manifest_digest'] is not None:
                    raise ValueError('SOURCE_UPLOAD_MANIFEST_ALREADY_EXISTS')
                stored = db.execute('''UPDATE epm.source_batch SET
                    manifest_request_key=%s,manifest_origin_kind=%s,
                    manifest_origin_ref=%s,manifest_schema_version=%s,
                    manifest_schema=%s,manifest_schema_digest=%s,
                    manifest_content_digest=%s,manifest_digest=%s,
                    manifest_creator_issuer=%s,
                    manifest_creator_subject_id=%s,
                    manifest_created_at=transaction_timestamp(),
                    manifest_retention_status='retained',
                    manifest_retention_reason='initial retention',
                    manifest_retention_issuer=%s,
                    manifest_retention_subject_id=%s,
                    manifest_retention_updated_at=transaction_timestamp(),
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s AND manifest_digest IS NULL
                    RETURNING *''',
                    (request_key, origin_kind, origin_ref, schema_version,
                     Jsonb(schema), schema_digest, content_digest,
                     manifest_digest, self.identity.issuer,
                     self.identity.subject_id, self.identity.issuer,
                     self.identity.subject_id, scope.workspace_id,
                     scope.application_id, batch_id)).fetchone()
                if stored is None:
                    raise ValueError('SOURCE_UPLOAD_MANIFEST_CONFLICT')
                return _record(stored)

    def read(self, scope: ApplicationScope, batch_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(batch_id, str)
                or not _BATCH.fullmatch(batch_id)):
            raise ValueError('SOURCE_UPLOAD_MANIFEST_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                row = db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s AND manifest_digest IS NOT NULL
                    AND manifest_creator_issuer=%s
                    AND manifest_creator_subject_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     batch_id, self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if row is None:
                    raise ValueError('SOURCE_UPLOAD_MANIFEST_UNAVAILABLE')
                return _record(row)

    def set_retention(self, scope: ApplicationScope, batch_id: str, *,
                      expected_status: str, status: str,
                      reason: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(batch_id, str) or not _BATCH.fullmatch(batch_id)
                or expected_status not in _RETENTION or status not in _RETENTION
                or not isinstance(reason, str) or not 1 <= len(reason) <= 500
                or any(ord(character) < 32 or ord(character) == 127
                       for character in reason)):
            raise ValueError('SOURCE_UPLOAD_RETENTION_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                current = db.execute('''SELECT * FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s AND manifest_digest IS NOT NULL
                    FOR UPDATE''', (scope.workspace_id,
                    scope.application_id, batch_id)).fetchone()
                if current is None:
                    raise ValueError('SOURCE_UPLOAD_MANIFEST_UNAVAILABLE')
                if current['manifest_retention_status'] != expected_status:
                    raise ValueError('SOURCE_UPLOAD_RETENTION_STALE')
                if (status == expected_status
                        and current['manifest_retention_reason'] == reason):
                    return _record(current, duplicate=True)
                updated = db.execute('''UPDATE epm.source_batch SET
                    manifest_retention_status=%s,
                    manifest_retention_reason=%s,
                    manifest_retention_issuer=%s,
                    manifest_retention_subject_id=%s,
                    manifest_retention_updated_at=transaction_timestamp(),
                    updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s AND manifest_retention_status=%s
                    RETURNING *''', (status, reason, self.identity.issuer,
                    self.identity.subject_id, scope.workspace_id,
                    scope.application_id, batch_id,
                    expected_status)).fetchone()
                if updated is None:
                    raise ValueError('SOURCE_UPLOAD_RETENTION_STALE')
                return _record(updated)
