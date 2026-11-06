"""PostgreSQL repository for immutable transfer diagnostic/export artifacts."""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import hmac
import json
import re
import time
import uuid

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .export_artifact_manifest import export_artifact_manifest_matches
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .source_import_diagnostics import (
    CONTRACT_VERSION as DIAGNOSTIC_CONTRACT, DiagnosticCode,
    SourceDiagnostic, source_diagnostics_digest_matches)


_ID = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_RETENTION = frozenset(('retained', 'held', 'expired'))
_TABLES = {'import': 'source_import_diagnostic_artifact',
           'export': 'fact_export_artifact'}
IMPORT_READ = 'facts.transfer.import.diagnostics.read'
IMPORT_LIST = 'facts.transfer.import.diagnostics.list'
EXPORT_READ = 'facts.transfer.export.manifest.read'
EXPORT_LIST = 'facts.transfer.export.manifest.list'
READ_FUNCTIONS = frozenset((IMPORT_READ, IMPORT_LIST, EXPORT_READ, EXPORT_LIST))


def transfer_artifact_catalog() -> dict:
    common = {'mode': 'read_only', 'permission': 'read',
              'previewRequired': False, 'idempotencyRequired': False,
              'workClass': 'short'}
    return {
        IMPORT_READ: {**common,
            'arguments': {'artifactId': 'exact 32-character hexadecimal ID'},
            'result': ('verified bounded compiled diagnostics; exact-ID reads '
                       'remain visible after expiry and return expired=true')},
        IMPORT_LIST: {**common,
            'arguments': {'limit': 'optional 1-100, default 50',
                          'includeExpired': 'optional boolean, default false',
                          'cursor': 'signed complete continuation request'},
            'result': ('bounded diagnostic-artifact summaries in stable '
                       'createdAt/artifactId order; expired excluded by default')},
        EXPORT_READ: {**common,
            'arguments': {'artifactId': 'exact 32-character hexadecimal ID'},
            'result': ('verified finalized export manifest metadata/pages only; '
                       'no exported row payload or download')},
        EXPORT_LIST: {**common,
            'arguments': {'limit': 'optional 1-100, default 50',
                          'includeExpired': 'optional boolean, default false',
                          'cursor': 'signed complete continuation request'},
            'result': ('bounded finalized-manifest summaries; no exported row '
                       'payload or download')},
    }


def _canonical(value: object, code: str) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (RecursionError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError(code) from error


def _nonnegative(value: object) -> bool:
    return type(value) is int and value >= 0


def _validated_diagnostics(value: object) -> tuple[dict, bytes]:
    required = {'contractVersion', 'sourceIdentity', 'diagnostics',
                'diagnosticCount', 'observedCount', 'errorCount',
                'warningCount', 'truncated', 'omittedCount',
                'diagnosticsPayloadBytes', 'accepted', 'diagnosticsDigest'}
    if (not isinstance(value, dict) or set(value) != required
            or value.get('contractVersion') != DIAGNOSTIC_CONTRACT
            or not isinstance(value.get('sourceIdentity'), dict)
            or set(value['sourceIdentity']) !=
               {'manifestDigest', 'contentDigest', 'schemaDigest'}
            or any(not isinstance(item, str) or not _DIGEST.fullmatch(item)
                   for item in value['sourceIdentity'].values())
            or not isinstance(value.get('diagnostics'), list)
            or any(not _nonnegative(value.get(field)) for field in (
                'diagnosticCount', 'observedCount', 'errorCount',
                'warningCount', 'omittedCount', 'diagnosticsPayloadBytes'))
            or value['diagnosticCount'] != len(value['diagnostics'])
            or not isinstance(value.get('truncated'), bool)
            or not isinstance(value.get('accepted'), bool)
            or value['accepted'] != (value['errorCount'] == 0)
            or value['errorCount'] + value['warningCount'] !=
               value['observedCount']):
        raise ValueError('TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID')
    diagnostics = value['diagnostics']
    for item in diagnostics:
        if not isinstance(item, dict):
            raise ValueError('TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID')
        try:
            code = DiagnosticCode(item.get('code'))
            coordinate = item.get('coordinate', {})
            diagnostic = SourceDiagnostic.fixed(
                code, row_index=item.get('rowIndex'),
                field=item.get('field'), coordinate=coordinate)
        except (TypeError, ValueError) as error:
            raise ValueError('TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID') from error
        if diagnostic.wire() != item:
            raise ValueError('TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID')
    summary = bool(diagnostics and
                   diagnostics[-1]['code'] == 'DIAGNOSTICS_TRUNCATED')
    emitted = len(diagnostics) - (1 if summary else 0)
    if (value['truncated'] != summary
            or (summary and value['omittedCount'] < 1)
            or (not summary and value['omittedCount'] != 0)
            or value['observedCount'] != emitted + value['omittedCount']
            or value['diagnosticsPayloadBytes'] !=
               len(_canonical(diagnostics,
                              'TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID'))
            or not source_diagnostics_digest_matches(value)):
        raise ValueError('TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID')
    encoded = _canonical(value, 'TRANSFER_DIAGNOSTIC_ARTIFACT_INVALID')
    if len(encoded) > 4194304:
        raise ValueError('TRANSFER_DIAGNOSTIC_ARTIFACT_TOO_LARGE')
    return json.loads(encoded), encoded


def _validated_export(value: object, scope: ApplicationScope,
                      expires_at: int) -> tuple[dict, bytes]:
    if (type(expires_at) is not int or not 1 <= expires_at < 2**63
            or not export_artifact_manifest_matches(
                value, scope=scope, expires_at=expires_at)):
        raise ValueError('TRANSFER_EXPORT_ARTIFACT_INVALID')
    encoded = _canonical(value, 'TRANSFER_EXPORT_ARTIFACT_INVALID')
    if len(encoded) > 16777216:
        raise ValueError('TRANSFER_EXPORT_ARTIFACT_TOO_LARGE')
    return json.loads(encoded), encoded


def _result(row: dict, artifact_field: str, *, duplicate=False) -> dict:
    return {'artifactId': row['artifact_id'],
            'artifact': row[artifact_field],
            'retention': {'status': row['retention_status'],
                          'reason': row['retention_reason'],
                          'issuer': row['retention_issuer'],
                          'subjectId': row['retention_subject_id'],
                          'updatedAt': row['retention_updated_at']},
            'expiresAt': row['expires_at_epoch'],
            'expired': bool(row.get('expired', False)),
            'createdAt': row['created_at'], 'duplicate': duplicate}


class PostgresTransferArtifacts:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes | None = None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if (cursor_secret is not None and
                (not isinstance(cursor_secret, bytes)
                 or len(cursor_secret) < 32)):
            raise ValueError('A server-owned cursor secret must be 32+ bytes')
        self.dsn = dsn
        self.identity = identity
        self.cursor_secret = cursor_secret

    def _authorization_scope_digest(self, db, scope: ApplicationScope) -> str:
        return resolve_effective_dimensional_scope(
            db, self.identity, scope,
            function='facts.transfer.export.manifest.read').scope_digest

    @staticmethod
    def _arguments(scope, idempotency_key, expires_at):
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)
                or type(expires_at) is not int
                or not 1 <= expires_at < 2**63):
            raise ValueError('TRANSFER_ARTIFACT_ARGUMENTS_INVALID')

    def save_import(self, scope: ApplicationScope, batch_id: str, *,
                    idempotency_key: str, artifact: dict,
                    expires_at: int) -> dict:
        self._arguments(scope, idempotency_key, expires_at)
        if not isinstance(batch_id, str) or not _ID.fullmatch(batch_id):
            raise ValueError('TRANSFER_ARTIFACT_ARGUMENTS_INVALID')
        artifact, _ = _validated_diagnostics(artifact)
        source = artifact['sourceIdentity']
        request_digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'batchId': batch_id, 'sourceIdentity': source,
            'artifactDigest': artifact['diagnosticsDigest'],
            'expiresAt': expires_at,
            'creator': [self.identity.issuer, self.identity.subject_id]})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                prior = db.execute('''SELECT * FROM
                    epm.source_import_diagnostic_artifact
                    WHERE workspace_id=%s AND application_id=%s
                    AND ((issuer=%s AND subject_id=%s AND idempotency_key=%s)
                         OR batch_id=%s) FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key, batch_id)).fetchone()
                if prior is not None:
                    if (prior['issuer'] == self.identity.issuer
                            and prior['subject_id'] == self.identity.subject_id
                            and prior['idempotency_key'] == idempotency_key
                            and prior['request_digest'] == request_digest):
                        self._verify_import_row(scope, prior)
                        return _result(prior, 'artifact', duplicate=True)
                    raise ValueError('TRANSFER_ARTIFACT_IDEMPOTENCY_CONFLICT')
                batch = db.execute('''SELECT issuer,subject_id,
                    manifest_digest,manifest_content_digest,
                    manifest_schema_digest FROM epm.source_batch
                    WHERE workspace_id=%s AND application_id=%s
                    AND batch_id=%s AND manifest_digest IS NOT NULL
                    FOR UPDATE''', (scope.workspace_id,
                    scope.application_id, batch_id)).fetchone()
                if (batch is None or batch['issuer'] != self.identity.issuer
                        or batch['subject_id'] != self.identity.subject_id):
                    raise ValueError('TRANSFER_SOURCE_MANIFEST_UNAVAILABLE')
                if source != {'manifestDigest': batch['manifest_digest'],
                              'contentDigest': batch['manifest_content_digest'],
                              'schemaDigest': batch['manifest_schema_digest']}:
                    raise ValueError('TRANSFER_SOURCE_IDENTITY_DRIFT')
                artifact_id = uuid.uuid4().hex
                row = db.execute('''INSERT INTO
                    epm.source_import_diagnostic_artifact
                    (workspace_id,application_id,artifact_id,batch_id,
                     issuer,subject_id,idempotency_key,request_digest,
                     source_manifest_digest,source_content_digest,
                     source_schema_digest,artifact_digest,artifact,
                     expires_at_epoch,retention_status,retention_reason,
                     retention_issuer,retention_subject_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            'retained','initial retention',%s,%s)
                    RETURNING *''', (scope.workspace_id,
                    scope.application_id, artifact_id, batch_id,
                    self.identity.issuer, self.identity.subject_id,
                    idempotency_key, request_digest,
                    source['manifestDigest'], source['contentDigest'],
                    source['schemaDigest'], artifact['diagnosticsDigest'],
                    Jsonb(artifact), expires_at, self.identity.issuer,
                    self.identity.subject_id)).fetchone()
                return _result(row, 'artifact')

    def save_export(self, scope: ApplicationScope, *, idempotency_key: str,
                    manifest: dict, expires_at: int,
                    security_revision: int = 0,
                    producer_request_id: str | None = None,
                    producer_claim_generation: int | None = None,
                    producer_worker_id: str | None = None) -> dict:
        self._arguments(scope, idempotency_key, expires_at)
        if type(security_revision) is not int or security_revision < 0:
            raise ValueError('TRANSFER_EXPORT_SECURITY_REVISION_INVALID')
        if (len({producer_request_id is None,
                 producer_claim_generation is None,
                 producer_worker_id is None})!=1
                or (producer_request_id is not None and
                    (not _ID.fullmatch(producer_request_id)
                     or type(producer_claim_generation) is not int
                     or producer_claim_generation<1
                     or not isinstance(producer_worker_id,str)
                     or not 1<=len(producer_worker_id)<=200))):
            raise ValueError('TRANSFER_EXPORT_PRODUCER_LINEAGE_INVALID')
        manifest, _ = _validated_export(manifest, scope, expires_at)
        if manifest.get('securityRevision') != security_revision:
            raise ValueError('TRANSFER_EXPORT_SECURITY_IDENTITY_DRIFT')
        request_identity = {
            'scope': [scope.workspace_id, scope.application_id],
            'manifestDigest': manifest['manifestDigest'],
            'securityRevision': security_revision,
            'expiresAt': expires_at,
            'creator': [self.identity.issuer, self.identity.subject_id]}
        if producer_request_id is not None:
            request_identity['producerRequestId']=producer_request_id
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                authorization_scope_digest = self._authorization_scope_digest(
                    db, scope)
                request_identity['authorizationScopeDigest'] = (
                    authorization_scope_digest)
                request_digest = _canonical_digest(request_identity)
                state = db.execute('''SELECT security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['security_revision'] !=
                        security_revision):
                    raise ValueError('TRANSFER_EXPORT_SECURITY_STALE')
                prior = db.execute('''SELECT * FROM epm.fact_export_artifact
                    WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s
                    FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior is not None:
                    if (prior['issuer'] == self.identity.issuer
                            and prior['subject_id'] == self.identity.subject_id
                            and prior['idempotency_key'] == idempotency_key
                            and prior['request_digest'] == request_digest
                            and prior.get('authorization_scope_digest') ==
                                authorization_scope_digest
                            and prior.get('producer_request_id')==producer_request_id
                            and (producer_request_id is None or
                                 prior.get('producer_claim_generation') is not None)):
                        self._verify_export_row(scope, prior)
                        if producer_request_id is not None:
                            db.execute('''SELECT epm.export_producer_artifact_adopt(
                              %s,%s,%s,%s,%s,%s)''',(scope.workspace_id,
                              scope.application_id,producer_request_id,
                              producer_worker_id,producer_claim_generation,
                              prior['artifact_id']))
                        return _result(prior, 'manifest', duplicate=True)
                    raise ValueError('TRANSFER_ARTIFACT_IDEMPOTENCY_CONFLICT')
                reusable = db.execute('''SELECT x.*,
                    p.status AS payload_status,p.payload_digest,
                    owner.status AS producer_status,
                    owner.artifact_id AS producer_artifact_id,
                    owner.payload_digest AS producer_payload_digest
                    FROM epm.fact_export_artifact x
                    JOIN epm.fact_export_payload p USING(
                      workspace_id,application_id,artifact_id)
                    LEFT JOIN epm.fact_export_producer_request owner
                      ON owner.workspace_id=x.workspace_id
                     AND owner.application_id=x.application_id
                     AND owner.request_id=x.producer_request_id
                    WHERE x.workspace_id=%s AND x.application_id=%s
                      AND x.issuer=%s AND x.subject_id=%s
                      AND x.manifest_digest=%s AND p.status='complete'
                      AND x.security_revision=%s
                      AND x.authorization_scope_digest=%s
                      AND x.retention_status='retained'
                      AND p.retention_status='retained'
                      AND x.expires_at_epoch>
                       extract(epoch from clock_timestamp())::bigint
                      AND p.expires_at_epoch>
                       extract(epoch from clock_timestamp())::bigint
                      AND (x.producer_request_id IS NULL OR
                       (owner.status='Completed'
                        AND owner.artifact_id=x.artifact_id
                        AND owner.payload_digest=p.payload_digest))
                    ORDER BY x.created_at,x.artifact_id LIMIT 1 FOR UPDATE OF x''',
                    (scope.workspace_id,scope.application_id,
                     self.identity.issuer,self.identity.subject_id,
                     manifest['manifestDigest'],security_revision,
                     authorization_scope_digest)).fetchone()
                if reusable is not None:
                    self._verify_export_row(scope,reusable)
                    return {**_result(reusable,'manifest',duplicate=True),
                            'reusableComplete':True,
                            'payloadDigest':reusable['payload_digest']}
                artifact_id = uuid.uuid4().hex
                row = db.execute('''INSERT INTO epm.fact_export_artifact
                    (workspace_id,application_id,artifact_id,issuer,subject_id,
                     idempotency_key,request_digest,snapshot_revision,
                     metadata_revision,security_revision,expires_at_epoch,
                     page_count,row_count,
                     row_bytes,manifest_digest,cumulative_digest,manifest,
                     retention_status,retention_reason,retention_issuer,
                     retention_subject_id,producer_request_id,
                     producer_claim_generation,authorization_scope_digest)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            %s,%s,'retained','initial retention',%s,%s,%s,%s,%s)
                    RETURNING *''', (scope.workspace_id,
                    scope.application_id, artifact_id, self.identity.issuer,
                    self.identity.subject_id, idempotency_key, request_digest,
                    manifest['snapshotRevision'], manifest['metadataRevision'],
                    security_revision, expires_at, manifest['pageCount'],
                    manifest['totalRowCount'], manifest['totalRowBytes'],
                    manifest['manifestDigest'], manifest['cumulativeDigest'],
                    Jsonb(manifest), self.identity.issuer,
                    self.identity.subject_id,producer_request_id,
                    producer_claim_generation,
                    authorization_scope_digest)).fetchone()
                if producer_request_id is not None:
                    db.execute('''SELECT epm.export_producer_assert_claim(
                      %s,%s,%s,%s,%s,%s)''',(scope.workspace_id,
                      scope.application_id,producer_request_id,
                      producer_worker_id,producer_claim_generation,
                      artifact_id))
                return _result(row, 'manifest')

    @staticmethod
    def _verify_import_row(scope, row):
        artifact, _ = _validated_diagnostics(row['artifact'])
        identity = artifact['sourceIdentity']
        if (row['workspace_id'] != scope.workspace_id
                or row['application_id'] != scope.application_id
                or identity != {
                    'manifestDigest': row['source_manifest_digest'],
                    'contentDigest': row['source_content_digest'],
                    'schemaDigest': row['source_schema_digest']}
                or artifact['diagnosticsDigest'] != row['artifact_digest']):
            raise ValueError('TRANSFER_ARTIFACT_CORRUPT')

    @staticmethod
    def _verify_export_row(scope, row):
        manifest, _ = _validated_export(
            row['manifest'], scope, row['expires_at_epoch'])
        if (row['workspace_id'] != scope.workspace_id
                or row['application_id'] != scope.application_id
                or manifest['manifestDigest'] != row['manifest_digest']
                or manifest['cumulativeDigest'] != row['cumulative_digest']
                or manifest['snapshotRevision'] != row['snapshot_revision']
                or manifest['metadataRevision'] != row['metadata_revision']
                or manifest.get('securityRevision') !=
                   row.get('security_revision')
                or manifest['pageCount'] != row['page_count']
                or manifest['totalRowCount'] != row['row_count']
                or manifest['totalRowBytes'] != row['row_bytes']):
            raise ValueError('TRANSFER_ARTIFACT_CORRUPT')

    def read(self, scope: ApplicationScope, artifact_kind: str,
             artifact_id: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or artifact_kind not in _TABLES
                or not isinstance(artifact_id, str)
                or not _ID.fullmatch(artifact_id)):
            raise ValueError('TRANSFER_ARTIFACT_ARGUMENTS_INVALID')
        table = _TABLES[artifact_kind]
        field = 'artifact' if artifact_kind == 'import' else 'manifest'
        security_sql = ('''AND security_revision=(SELECT security_revision
            FROM epm.application_state WHERE workspace_id=%s
            AND application_id=%s)''' if artifact_kind == 'export' else '')
        security_args = ((scope.workspace_id, scope.application_id)
                         if artifact_kind == 'export' else ())
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                authorization_scope_digest = (self._authorization_scope_digest(
                    db, scope) if artifact_kind == 'export' else None)
                row = db.execute(f'''SELECT *,
                    (retention_status='expired' OR expires_at_epoch<=
                     extract(epoch FROM transaction_timestamp())::bigint)
                    AS expired FROM epm.{table}
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s
                    AND issuer=%s AND subject_id=%s
                    {security_sql}
                    {"AND authorization_scope_digest=%s" if artifact_kind == 'export' else ''}
                    {"AND (producer_request_id IS NULL OR EXISTS (SELECT 1 FROM epm.fact_export_producer_request pr WHERE pr.workspace_id=fact_export_artifact.workspace_id AND pr.application_id=fact_export_artifact.application_id AND pr.request_id=fact_export_artifact.producer_request_id AND pr.status='Completed' AND pr.artifact_id=fact_export_artifact.artifact_id))" if artifact_kind == 'export' else ''}''', (scope.workspace_id,
                    scope.application_id, artifact_id,
                    self.identity.issuer, self.identity.subject_id,
                    *security_args,
                    *((authorization_scope_digest,)
                      if artifact_kind == 'export' else ()))).fetchone()
                if row is None:
                    raise ValueError('TRANSFER_ARTIFACT_UNAVAILABLE')
                (self._verify_import_row(scope, row) if artifact_kind == 'import'
                 else self._verify_export_row(scope, row))
                return _result(row, field)

    def list(self, scope: ApplicationScope, artifact_kind: str, *,
             limit: int = 50, cursor: str | None = None,
             include_expired: bool = False) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or artifact_kind not in _TABLES):
            raise ValueError('TRANSFER_ARTIFACT_LIST_INVALID')
        if cursor is None:
            if (type(limit) is not int or not 1 <= limit <= 100
                    or not isinstance(include_expired, bool)):
                raise ValueError('TRANSFER_ARTIFACT_LIST_INVALID')
            after_created = None
            after_id = None
        else:
            if limit != 50 or include_expired is not False:
                raise ValueError('TRANSFER_ARTIFACT_CURSOR_IS_COMPLETE_REQUEST')
            payload = self._unpack_cursor(cursor, scope, artifact_kind)
            limit = payload['limit']
            include_expired = payload['includeExpired']
            after_created = payload['afterCreatedAt']
            after_id = payload['afterArtifactId']
        table = _TABLES[artifact_kind]
        if artifact_kind=='export':
            from_sql=('epm.fact_export_artifact t LEFT JOIN '
              'epm.fact_export_producer_request pr ON '
              'pr.workspace_id=t.workspace_id AND '
              'pr.application_id=t.application_id AND '
              'pr.request_id=t.producer_request_id')
            visible_sql=("AND (t.producer_request_id IS NULL OR "
              "(pr.status='Completed' AND pr.artifact_id=t.artifact_id))")
            visible_sql += (" AND t.security_revision=(SELECT "
              "security_revision FROM epm.application_state s WHERE "
              "s.workspace_id=t.workspace_id AND "
              "s.application_id=t.application_id)")
            order_sql='coalesce(pr.published_at,t.created_at)';artifact_order='t.artifact_id'
        else:
            from_sql=f'epm.{table} t';visible_sql='';order_sql='created_at';artifact_order='artifact_id'
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                authorization_scope_digest = (self._authorization_scope_digest(
                    db, scope) if artifact_kind == 'export' else None)
                if artifact_kind == 'export':
                    visible_sql += ' AND t.authorization_scope_digest=%s'
                rows = db.execute(f'''SELECT t.*,{order_sql} AS publication_at,
                    (t.retention_status='expired' OR t.expires_at_epoch<=
                     extract(epoch FROM transaction_timestamp())::bigint)
                    AS expired FROM {from_sql}
                    WHERE t.workspace_id=%s AND t.application_id=%s
                    AND t.issuer=%s AND t.subject_id=%s
                    {visible_sql}
                    AND (%s OR (t.retention_status<>'expired' AND
                        t.expires_at_epoch>
                        extract(epoch FROM transaction_timestamp())::bigint))
                    AND (%s::timestamptz IS NULL OR
                        ({order_sql},{artifact_order})>(%s::timestamptz,%s::text))
                    ORDER BY {order_sql},{artifact_order} LIMIT %s''',
                    (scope.workspace_id, scope.application_id,
                     self.identity.issuer, self.identity.subject_id,
                     *((authorization_scope_digest,)
                       if artifact_kind == 'export' else ()),
                     include_expired, after_created, after_created,
                     after_id, limit + 1)).fetchall()
        visible = rows[:limit]
        values = []
        for row in visible:
            if artifact_kind == 'import':
                self._verify_import_row(scope, row)
                artifact = row['artifact']
                values.append({
                    'artifactId': row['artifact_id'],
                    'batchId': row['batch_id'],
                    'artifactDigest': row['artifact_digest'],
                    'sourceIdentity': artifact['sourceIdentity'],
                    'diagnosticCount': artifact['diagnosticCount'],
                    'observedCount': artifact['observedCount'],
                    'errorCount': artifact['errorCount'],
                    'warningCount': artifact['warningCount'],
                    'accepted': artifact['accepted'],
                    'truncated': artifact['truncated'],
                    'expiresAt': row['expires_at_epoch'],
                    'expired': row['expired'],
                    'retentionStatus': row['retention_status'],
                    'createdAt': row['created_at']})
            else:
                self._verify_export_row(scope, row)
                manifest = row['manifest']
                values.append({
                    'artifactId': row['artifact_id'],
                    'manifestDigest': row['manifest_digest'],
                    'cumulativeDigest': row['cumulative_digest'],
                    'snapshotRevision': row['snapshot_revision'],
                    'metadataRevision': row['metadata_revision'],
                    'securityRevision': row['security_revision'],
                    'pageCount': row['page_count'],
                    'rowCount': row['row_count'],
                    'rowBytes': row['row_bytes'],
                    'typeCounts': manifest['typeCounts'],
                    'expiresAt': row['expires_at_epoch'],
                    'expired': row['expired'],
                    'retentionStatus': row['retention_status'],
                    'createdAt': row['created_at']})
        has_more = len(rows) > limit
        next_cursor = None
        if has_more:
            last = visible[-1]
            cursor_time=(last['publication_at'] if 'publication_at' in last
                         else last['created_at'])
            next_cursor = self._pack_cursor({
                'scope': [scope.workspace_id, scope.application_id],
                'identity': [self.identity.issuer, self.identity.subject_id],
                'kind': artifact_kind, 'limit': limit,
                'includeExpired': include_expired,
                'afterCreatedAt': cursor_time.isoformat(),
                'afterArtifactId': last['artifact_id'],
                'expiresAt': int(time.time()) + 3600})
        return {'artifacts': values, 'nextCursor': next_cursor,
                'hasMore': has_more,
                'expiredVisibility': ('included' if include_expired
                                      else 'excluded')}

    def _pack_cursor(self, payload: dict) -> str:
        if self.cursor_secret is None:
            raise ValueError('TRANSFER_ARTIFACT_CURSOR_UNAVAILABLE')
        raw = _canonical(payload, 'TRANSFER_ARTIFACT_CURSOR_INVALID')
        signature = hmac.new(self.cursor_secret, raw, sha256).digest()
        return (base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') + '.' +
                base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii'))

    def _unpack_cursor(self, token: str, scope: ApplicationScope,
                       artifact_kind: str) -> dict:
        if (self.cursor_secret is None or not isinstance(token, str)
                or not 1 <= len(token) <= 8192 or token.count('.') != 1):
            raise ValueError('TRANSFER_ARTIFACT_CURSOR_INVALID')
        try:
            body, signature = token.split('.')
            raw = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4))
            supplied = base64.urlsafe_b64decode(
                signature + '=' * (-len(signature) % 4))
            expected = hmac.new(self.cursor_secret, raw, sha256).digest()
            payload = json.loads(raw)
        except (binascii.Error, UnicodeError, ValueError,
                json.JSONDecodeError) as error:
            raise ValueError('TRANSFER_ARTIFACT_CURSOR_INVALID') from error
        fields = {'scope', 'identity', 'kind', 'limit', 'includeExpired',
                  'afterCreatedAt', 'afterArtifactId', 'expiresAt'}
        if (not hmac.compare_digest(expected, supplied)
                or not isinstance(payload, dict) or set(payload) != fields
                or payload['scope'] != [scope.workspace_id,
                                        scope.application_id]
                or payload['identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or payload['kind'] != artifact_kind
                or type(payload['limit']) is not int
                or not 1 <= payload['limit'] <= 100
                or not isinstance(payload['includeExpired'], bool)
                or not isinstance(payload['afterCreatedAt'], str)
                or not 1 <= len(payload['afterCreatedAt']) <= 100
                or not isinstance(payload['afterArtifactId'], str)
                or not _ID.fullmatch(payload['afterArtifactId'])
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < int(time.time())):
            raise ValueError('TRANSFER_ARTIFACT_CURSOR_INVALID')
        return payload

    def set_retention(self, scope: ApplicationScope, artifact_kind: str,
                      artifact_id: str, *, expected_status: str,
                      status: str, reason: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or artifact_kind not in _TABLES
                or not isinstance(artifact_id, str)
                or not _ID.fullmatch(artifact_id)
                or expected_status not in _RETENTION or status not in _RETENTION
                or not isinstance(reason, str) or not 1 <= len(reason) <= 500
                or any(ord(character) < 32 or ord(character) == 127
                       for character in reason)):
            raise ValueError('TRANSFER_RETENTION_INVALID')
        table = _TABLES[artifact_kind]
        field = 'artifact' if artifact_kind == 'import' else 'manifest'
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                authorization_scope_digest = (self._authorization_scope_digest(
                    db, scope) if artifact_kind == 'export' else None)
                row = db.execute(f'''UPDATE epm.{table} SET
                    retention_status=%s,retention_reason=%s,
                    retention_issuer=%s,retention_subject_id=%s,
                    retention_updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s AND retention_status=%s
                    {"AND authorization_scope_digest=%s" if artifact_kind == 'export' else ''}
                    RETURNING *''', (status, reason, self.identity.issuer,
                    self.identity.subject_id, scope.workspace_id,
                    scope.application_id, artifact_id,
                    expected_status,
                    *((authorization_scope_digest,)
                      if artifact_kind == 'export' else ()))).fetchone()
                if row is None:
                    raise ValueError('TRANSFER_RETENTION_STALE')
                (self._verify_import_row(scope, row) if artifact_kind == 'import'
                 else self._verify_export_row(scope, row))
                return _result(row, field,
                               duplicate=status == expected_status)

    def execute_read_program(self, scope: ApplicationScope,
                             program: dict) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program.get('languageVersion')) is not int
                or program['languageVersion'] != 2
                or program.get('function') not in READ_FUNCTIONS
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('TRANSFER_ARTIFACT_READ_PROGRAM_INVALID')
        function, args = program['function'], program['arguments']
        artifact_kind = ('import' if function in (IMPORT_READ, IMPORT_LIST)
                         else 'export')
        if function in (IMPORT_READ, EXPORT_READ):
            if set(args) != {'artifactId'}:
                raise ValueError('TRANSFER_ARTIFACT_READ_PROGRAM_INVALID')
            return self.read(scope, artifact_kind, args['artifactId'])
        if 'cursor' in args:
            if set(args) != {'cursor'} or not isinstance(args['cursor'], str):
                raise ValueError('TRANSFER_ARTIFACT_READ_PROGRAM_INVALID')
            return self.list(scope, artifact_kind, cursor=args['cursor'])
        if (set(args) - {'limit', 'includeExpired'}
                or ('limit' in args and type(args['limit']) is not int)
                or ('includeExpired' in args
                    and not isinstance(args['includeExpired'], bool))):
            raise ValueError('TRANSFER_ARTIFACT_READ_PROGRAM_INVALID')
        return self.list(scope, artifact_kind, limit=args.get('limit', 50),
                         include_expired=args.get('includeExpired', False))
