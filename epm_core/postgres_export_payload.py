"""Durable, resumable storage for verified export payload chunks."""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import hmac
import json
import re
import time

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .export_artifact_manifest import export_artifact_manifest_matches
from .export_payload_chunk import (
    export_payload_chunk_matches, export_payload_matches)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


_ID = re.compile(r'[0-9a-f]{32}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_RETENTION = frozenset(('retained', 'held', 'expired'))
PAYLOAD_PAGE = 'facts.transfer.export.payload.page'
PUBLIC_READS = frozenset((PAYLOAD_PAGE,))


def export_payload_catalog() -> dict:
    return {PAYLOAD_PAGE: {
        'mode': 'read_only', 'permission': 'read',
        'previewRequired': False, 'idempotencyRequired': False,
        'workClass': 'short',
        'arguments': {
            'artifactId': ('exact 32-character export artifact ID on the '
                           'first request'),
            'cursor': ('signed complete continuation request; supplied alone '
                       'after the first chunk')},
        'result': ('one verified stored plaintext chunk, maximum 500 rows and '
                   '8 MiB, with typed schema/digests and signed continuation; '
                   'incomplete, held, or expired payloads are unavailable')}}


def _canonical(value: object, code: str) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (RecursionError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError(code) from error


def _validate_chunk(chunk: object, artifact_id: str,
                    manifest_digest: str) -> tuple[dict, bytes]:
    fields = {'contractVersion', 'artifactId', 'manifestDigest', 'pageIndex',
              'chunkIndex', 'pageEntryDigest', 'pageContentDigest', 'rows',
              'rowCount', 'rowBytes', 'typeCounts', 'firstKey', 'lastKey',
              'finalChunkForPage', 'ciphertextRef', 'chunkDigest'}
    if (not isinstance(chunk, dict) or set(chunk) != fields
            or chunk.get('contractVersion') != 'openepm-export-payload-v2'
            or chunk.get('artifactId') != artifact_id
            or chunk.get('manifestDigest') != manifest_digest
            or type(chunk.get('pageIndex')) is not int
            or chunk['pageIndex'] < 0
            or type(chunk.get('chunkIndex')) is not int
            or chunk['chunkIndex'] < 0
            or type(chunk.get('rowCount')) is not int
            or not 0 <= chunk['rowCount'] <= 500
            or type(chunk.get('rowBytes')) is not int
            or not 2 <= chunk['rowBytes'] <= 8388608
            or not isinstance(chunk.get('finalChunkForPage'), bool)
            or not isinstance(chunk.get('chunkDigest'), str)
            or not _DIGEST.fullmatch(chunk['chunkDigest'])):
        raise ValueError('EXPORT_PAYLOAD_CHUNK_INVALID')
    detached = json.loads(_canonical(chunk, 'EXPORT_PAYLOAD_CHUNK_INVALID'))
    unsigned = dict(detached)
    claimed = unsigned.pop('chunkDigest')
    computed = sha256(_canonical(
        unsigned, 'EXPORT_PAYLOAD_CHUNK_INVALID')).hexdigest()
    if not hmac.compare_digest(claimed, computed):
        raise ValueError('EXPORT_PAYLOAD_CHUNK_INVALID')
    encoded = _canonical(detached, 'EXPORT_PAYLOAD_CHUNK_INVALID')
    if len(encoded) > 8388608:
        raise ValueError('EXPORT_PAYLOAD_CHUNK_TOO_LARGE')
    return detached, encoded


class PostgresExportPayload:
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

    def _require_current_artifact_scope(self, db, scope, artifact_id):
        current = resolve_effective_dimensional_scope(
            db, self.identity, scope,
            function='facts.transfer.export.payload.page').scope_digest
        row = db.execute('''SELECT authorization_scope_digest FROM
            epm.fact_export_artifact WHERE workspace_id=%s
            AND application_id=%s AND artifact_id=%s''',(
            scope.workspace_id,scope.application_id,artifact_id)).fetchone()
        if (row is None or row['authorization_scope_digest'] is None
                or row['authorization_scope_digest'] != current):
            raise ValueError('EXPORT_PAYLOAD_AUTHORIZATION_SCOPE_CHANGED')

    @staticmethod
    def _scope(scope, artifact_id):
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(artifact_id, str)
                or not _ID.fullmatch(artifact_id)):
            raise ValueError('EXPORT_PAYLOAD_ARGUMENTS_INVALID')

    @staticmethod
    def _claim(db,scope,artifact_id,claim):
        if claim is None or claim==(None,None,None):return
        if (not isinstance(claim,tuple) or len(claim)!=3
                or not isinstance(claim[0],str) or not _ID.fullmatch(claim[0])
                or not isinstance(claim[1],str) or not 1<=len(claim[1])<=200
                or type(claim[2]) is not int or claim[2]<1):
            raise ValueError('EXPORT_PAYLOAD_CLAIM_INVALID')
        db.execute('''SELECT epm.export_producer_assert_claim(
          %s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,
          claim[0],claim[1],claim[2],artifact_id))

    def begin(self, scope: ApplicationScope, artifact_id: str, *,
              idempotency_key: str, payload: dict,
              producer_claim: tuple | None = None) -> dict:
        self._scope(scope, artifact_id)
        if (not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('EXPORT_PAYLOAD_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                self._require_current_artifact_scope(db,scope,artifact_id)
                self._claim(db,scope,artifact_id,producer_claim)
                export = db.execute('''SELECT * FROM epm.fact_export_artifact
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s AND security_revision=(SELECT
                      security_revision FROM epm.application_state
                      WHERE workspace_id=%s AND application_id=%s)
                    AND issuer=%s AND subject_id=%s
                    FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id, scope.workspace_id,
                     scope.application_id, self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if (export is None
                        or export['retention_status'] == 'expired'):
                    raise ValueError('EXPORT_PAYLOAD_ARTIFACT_UNAVAILABLE')
                if not export_artifact_manifest_matches(
                        export['manifest'], scope=scope,
                        expires_at=export['expires_at_epoch']):
                    raise ValueError('EXPORT_PAYLOAD_MANIFEST_CORRUPT')
                if not export_payload_matches(
                        payload, scope=scope, artifact_id=artifact_id,
                        manifest=export['manifest']):
                    raise ValueError('EXPORT_PAYLOAD_INVALID')
                request_digest = _canonical_digest({
                    'scope': [scope.workspace_id, scope.application_id],
                    'artifactId': artifact_id,
                    'manifestDigest': payload['manifestDigest'],
                    'payloadDigest': payload['payloadDigest'],
                    'idempotencyKey': idempotency_key,
                    'creator': [self.identity.issuer,
                                self.identity.subject_id]})
                prior = db.execute('''SELECT * FROM epm.fact_export_payload
                    WHERE workspace_id=%s AND application_id=%s
                    AND (artifact_id=%s OR (issuer=%s AND subject_id=%s
                    AND idempotency_key=%s)) FOR UPDATE''',
                    (scope.workspace_id, scope.application_id, artifact_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key)).fetchone()
                if prior is not None:
                    if (prior['artifact_id'] == artifact_id
                            and prior['issuer'] == self.identity.issuer
                            and prior['subject_id'] == self.identity.subject_id
                            and prior['idempotency_key'] == idempotency_key
                            and prior['request_digest'] == request_digest):
                        return self._result(prior, duplicate=True)
                    raise ValueError('EXPORT_PAYLOAD_IDEMPOTENCY_CONFLICT')
                row = db.execute('''INSERT INTO epm.fact_export_payload
                    (workspace_id,application_id,artifact_id,issuer,subject_id,
                     idempotency_key,request_digest,manifest_digest,
                     payload_digest,expected_chunk_count,row_count,row_bytes,
                     type_counts,status,storage_format,encryption_claim,
                     expires_at_epoch,retention_status,retention_reason,
                     retention_issuer,retention_subject_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                     'building','plaintext_json',false,%s,'retained',
                     'initial retention',%s,%s) RETURNING *''',
                    (scope.workspace_id, scope.application_id, artifact_id,
                     self.identity.issuer, self.identity.subject_id,
                     idempotency_key, request_digest,
                     payload['manifestDigest'], payload['payloadDigest'],
                     payload['chunkCount'], payload['rowCount'],
                     payload['rowBytes'], Jsonb(payload['typeCounts']),
                     export['expires_at_epoch'], self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                self._claim(db,scope,artifact_id,producer_claim)
                return self._result(row)

    def append(self, scope: ApplicationScope, artifact_id: str, *,
               ordinal: int, chunk: dict,
               producer_claim: tuple | None = None) -> dict:
        self._scope(scope, artifact_id)
        if type(ordinal) is not int or ordinal < 0:
            raise ValueError('EXPORT_PAYLOAD_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                self._require_current_artifact_scope(db,scope,artifact_id)
                self._claim(db,scope,artifact_id,producer_claim)
                header = db.execute('''SELECT * FROM epm.fact_export_payload
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id)).fetchone()
                if header is None:
                    raise ValueError('EXPORT_PAYLOAD_UNAVAILABLE')
                if (header['issuer'] != self.identity.issuer
                        or header['subject_id'] != self.identity.subject_id):
                    raise ValueError('EXPORT_PAYLOAD_CREATOR_REQUIRED')
                chunk, _ = _validate_chunk(
                    chunk, artifact_id, header['manifest_digest'])
                prior = db.execute('''SELECT * FROM
                    epm.fact_export_payload_chunk WHERE workspace_id=%s
                    AND application_id=%s AND artifact_id=%s AND ordinal=%s''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id, ordinal)).fetchone()
                if prior is not None:
                    if prior['chunk_digest'] == chunk['chunkDigest']:
                        return {'artifactId': artifact_id, 'ordinal': ordinal,
                                'chunkDigest': prior['chunk_digest'],
                                'duplicate': True}
                    raise ValueError('EXPORT_PAYLOAD_CHUNK_CONFLICT')
                if header['status'] != 'building':
                    raise ValueError('EXPORT_PAYLOAD_FINALIZED')
                progress = db.execute('''SELECT count(*) AS count,
                    max(page_index) AS page_index,max(chunk_index) FILTER(
                     WHERE page_index=(SELECT max(page_index) FROM
                     epm.fact_export_payload_chunk WHERE workspace_id=%s
                     AND application_id=%s AND artifact_id=%s)) AS chunk_index,
                    (array_agg(final_chunk_for_page ORDER BY ordinal DESC))[1]
                     AS final_page FROM epm.fact_export_payload_chunk
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s''',
                    (scope.workspace_id, scope.application_id, artifact_id,
                     scope.workspace_id, scope.application_id,
                     artifact_id)).fetchone()
                if ordinal != progress['count']:
                    raise ValueError('EXPORT_PAYLOAD_CHUNK_GAP')
                expected_page = (0 if ordinal == 0 else
                    progress['page_index'] + (1 if progress['final_page'] else 0))
                expected_chunk = (0 if ordinal == 0 or progress['final_page']
                                  else progress['chunk_index'] + 1)
                if (chunk['pageIndex'] != expected_page
                        or chunk['chunkIndex'] != expected_chunk
                        or ordinal >= header['expected_chunk_count']):
                    raise ValueError('EXPORT_PAYLOAD_CHUNK_ORDER_INVALID')
                db.execute('''INSERT INTO epm.fact_export_payload_chunk
                    (workspace_id,application_id,artifact_id,ordinal,
                     page_index,chunk_index,chunk_digest,page_content_digest,
                     row_count,row_bytes,type_counts,final_chunk_for_page,
                     storage_format,encryption_claim,chunk)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                     'plaintext_json',false,%s)''',
                    (scope.workspace_id, scope.application_id, artifact_id,
                     ordinal, chunk['pageIndex'], chunk['chunkIndex'],
                     chunk['chunkDigest'], chunk['pageContentDigest'],
                     chunk['rowCount'], chunk['rowBytes'],
                     Jsonb(chunk['typeCounts']),
                     chunk['finalChunkForPage'], Jsonb(chunk)))
                self._claim(db,scope,artifact_id,producer_claim)
                return {'artifactId': artifact_id, 'ordinal': ordinal,
                        'chunkDigest': chunk['chunkDigest'],
                        'duplicate': False}

    def finalize(self, scope: ApplicationScope, artifact_id: str, *,
                 producer_claim: tuple | None = None) -> dict:
        self._scope(scope, artifact_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                self._require_current_artifact_scope(db,scope,artifact_id)
                self._claim(db,scope,artifact_id,producer_claim)
                header = db.execute('''SELECT p.*,a.manifest FROM
                    epm.fact_export_payload p JOIN epm.fact_export_artifact a
                    USING(workspace_id,application_id,artifact_id)
                    WHERE p.workspace_id=%s AND p.application_id=%s
                    AND p.artifact_id=%s AND a.security_revision=(SELECT
                      security_revision FROM epm.application_state
                      WHERE workspace_id=%s AND application_id=%s)
                    AND a.issuer=%s AND a.subject_id=%s
                    FOR UPDATE OF p''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id, scope.workspace_id,
                     scope.application_id, self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if header is None:
                    raise ValueError('EXPORT_PAYLOAD_UNAVAILABLE')
                if (header['issuer'] != self.identity.issuer
                        or header['subject_id'] != self.identity.subject_id):
                    raise ValueError('EXPORT_PAYLOAD_CREATOR_REQUIRED')
                if header['status'] == 'complete':
                    return self._result(header, duplicate=True)
                rows = db.execute('''SELECT chunk FROM
                    epm.fact_export_payload_chunk WHERE workspace_id=%s
                    AND application_id=%s AND artifact_id=%s
                    ORDER BY ordinal''', (scope.workspace_id,
                    scope.application_id, artifact_id)).fetchall()
                payload = {
                    'contractVersion': 'openepm-export-payload-v2',
                    'status': 'complete', 'artifactId': artifact_id,
                    'manifestDigest': header['manifest_digest'],
                    'scope': {'workspaceId': scope.workspace_id,
                              'applicationId': scope.application_id},
                    'snapshotRevision': header['manifest']['snapshotRevision'],
                    'metadataRevision': header['manifest']['metadataRevision'],
                    'securityRevision': header['manifest']['securityRevision'],
                    'chunkCount': header['expected_chunk_count'],
                    'rowCount': header['row_count'],
                    'rowBytes': header['row_bytes'],
                    'typeCounts': header['type_counts'],
                    'chunks': [row['chunk'] for row in rows],
                    'payloadDigest': header['payload_digest']}
                if (len(rows) != header['expected_chunk_count']
                        or not export_payload_matches(
                            payload, scope=scope, artifact_id=artifact_id,
                            manifest=header['manifest'])):
                    raise ValueError('EXPORT_PAYLOAD_INCOMPLETE')
                row = db.execute('''UPDATE epm.fact_export_payload SET
                    status='complete',finalized_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s RETURNING *''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id)).fetchone()
                self._claim(db,scope,artifact_id,producer_claim)
                return self._result(row)

    def set_retention(self, scope: ApplicationScope, artifact_id: str, *,
                      expected_status: str, status: str,
                      reason: str) -> dict:
        self._scope(scope, artifact_id)
        if (expected_status not in _RETENTION or status not in _RETENTION
                or not isinstance(reason, str) or not 1 <= len(reason) <= 500):
            raise ValueError('EXPORT_PAYLOAD_RETENTION_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                self._require_current_artifact_scope(db,scope,artifact_id)
                row = db.execute('''UPDATE epm.fact_export_payload SET
                    retention_status=%s,retention_reason=%s,
                    retention_issuer=%s,retention_subject_id=%s,
                    retention_updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s AND retention_status=%s RETURNING *''',
                    (status, reason, self.identity.issuer,
                     self.identity.subject_id, scope.workspace_id,
                     scope.application_id, artifact_id,
                     expected_status)).fetchone()
                if row is None:
                    raise ValueError('EXPORT_PAYLOAD_RETENTION_STALE')
                return self._result(row)

    def progress(self, scope: ApplicationScope, artifact_id: str) -> dict:
        """Return verified internal producer progress; not a public route."""
        self._scope(scope, artifact_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                self._require_current_artifact_scope(db,scope,artifact_id)
                row = db.execute('''SELECT p.*,
                    count(c.ordinal) AS appended_count,
                    coalesce(max(c.ordinal),-1) AS max_ordinal
                    FROM epm.fact_export_payload p LEFT JOIN
                    epm.fact_export_payload_chunk c
                    USING(workspace_id,application_id,artifact_id)
                    WHERE p.workspace_id=%s AND p.application_id=%s
                    AND p.artifact_id=%s GROUP BY p.workspace_id,
                    p.application_id,p.artifact_id''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id)).fetchone()
                if row is None:
                    raise ValueError('EXPORT_PAYLOAD_UNAVAILABLE')
                if (row['issuer'] != self.identity.issuer
                        or row['subject_id'] != self.identity.subject_id):
                    raise ValueError('EXPORT_PAYLOAD_CREATOR_REQUIRED')
                if (row['appended_count'] > row['expected_chunk_count']
                        or row['max_ordinal'] != row['appended_count'] - 1):
                    raise ValueError('EXPORT_PAYLOAD_CORRUPT')
                return {**self._result(row),
                        'appendedChunkCount': row['appended_count']}

    def _pack_cursor(self, value: dict) -> str:
        if self.cursor_secret is None:
            raise ValueError('EXPORT_PAYLOAD_CURSOR_UNAVAILABLE')
        raw = _canonical(value, 'EXPORT_PAYLOAD_CURSOR_INVALID')
        signature = hmac.new(self.cursor_secret, raw, sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).rstrip(b'=').decode()

    def _unpack_cursor(self, cursor: str, scope: ApplicationScope) -> dict:
        if (self.cursor_secret is None or not isinstance(cursor, str)
                or not 1 <= len(cursor) <= 8192):
            raise ValueError('EXPORT_PAYLOAD_CURSOR_INVALID')
        try:
            padded = cursor + '=' * (-len(cursor) % 4)
            packed = base64.b64decode(
                padded, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if len(signature) != 32 or not hmac.compare_digest(
                    signature, hmac.new(self.cursor_secret, raw,
                                        sha256).digest()):
                raise ValueError
            value = json.loads(raw)
        except (binascii.Error, UnicodeError, ValueError,
                json.JSONDecodeError) as error:
            raise ValueError('EXPORT_PAYLOAD_CURSOR_INVALID') from error
        fields = {'scope', 'identity', 'artifactId', 'manifestDigest',
                  'payloadDigest', 'nextOrdinal', 'afterChunkDigest',
                  'expiresAt'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['scope'] != [scope.workspace_id,
                                      scope.application_id]
                or value['identity'] != [self.identity.issuer,
                                         self.identity.subject_id]
                or not isinstance(value['artifactId'], str)
                or not _ID.fullmatch(value['artifactId'])
                or not isinstance(value['manifestDigest'], str)
                or not _DIGEST.fullmatch(value['manifestDigest'])
                or not isinstance(value['payloadDigest'], str)
                or not _DIGEST.fullmatch(value['payloadDigest'])
                or type(value['nextOrdinal']) is not int
                or value['nextOrdinal'] < 1
                or not isinstance(value['afterChunkDigest'], str)
                or not _DIGEST.fullmatch(value['afterChunkDigest'])
                or type(value['expiresAt']) is not int
                or value['expiresAt'] <= int(time.time())):
            raise ValueError('EXPORT_PAYLOAD_CURSOR_INVALID')
        return value

    def read_chunk(self, scope: ApplicationScope, *,
                   artifact_id: str | None = None,
                   cursor: str | None = None) -> dict:
        if ((artifact_id is None) == (cursor is None)
                or not isinstance(scope, ApplicationScope)):
            raise ValueError('EXPORT_PAYLOAD_READ_ARGUMENTS_INVALID')
        cursor_value = None
        if cursor is not None:
            cursor_value = self._unpack_cursor(cursor, scope)
            artifact_id = cursor_value['artifactId']
        self._scope(scope, artifact_id)
        ordinal = 0 if cursor_value is None else cursor_value['nextOrdinal']
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                self._require_current_artifact_scope(db,scope,artifact_id)
                header = db.execute('''SELECT p.*,a.manifest,
                    a.security_revision,
                    a.retention_status AS artifact_retention,
                    a.expires_at_epoch AS artifact_expires FROM
                    epm.fact_export_payload p JOIN epm.fact_export_artifact a
                    USING(workspace_id,application_id,artifact_id)
                    WHERE p.workspace_id=%s AND p.application_id=%s
                    AND p.artifact_id=%s
                    AND a.security_revision=(SELECT security_revision FROM
                      epm.application_state WHERE workspace_id=%s
                      AND application_id=%s)
                    AND a.issuer=%s AND a.subject_id=%s
                    AND (a.producer_request_id IS NULL OR EXISTS(
                      SELECT 1 FROM epm.fact_export_producer_request pr
                      WHERE pr.workspace_id=a.workspace_id
                       AND pr.application_id=a.application_id
                       AND pr.request_id=a.producer_request_id
                       AND pr.status='Completed'
                       AND pr.artifact_id=a.artifact_id))''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id, scope.workspace_id,
                     scope.application_id, self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                now = int(time.time())
                if (header is None or header['status'] != 'complete'):
                    raise ValueError('EXPORT_PAYLOAD_INCOMPLETE')
                if (header['retention_status'] != 'retained'
                        or header['artifact_retention'] != 'retained'):
                    raise ValueError('EXPORT_PAYLOAD_RETENTION_UNAVAILABLE')
                if (header['expires_at_epoch'] <= now
                        or header['artifact_expires'] <= now):
                    raise ValueError('EXPORT_PAYLOAD_EXPIRED')
                if (header['storage_format'] != 'plaintext_json'
                        or header['encryption_claim']):
                    raise ValueError('EXPORT_PAYLOAD_STORAGE_UNSUPPORTED')
                if (not export_artifact_manifest_matches(
                        header['manifest'], scope=scope,
                        expires_at=header['artifact_expires'])
                        or header['manifest_digest'] !=
                           header['manifest']['manifestDigest']):
                    raise ValueError('EXPORT_PAYLOAD_MANIFEST_CORRUPT')
                if cursor_value is not None and (
                        cursor_value['manifestDigest'] !=
                        header['manifest_digest']
                        or cursor_value['payloadDigest'] !=
                           header['payload_digest']):
                    raise ValueError('EXPORT_PAYLOAD_CURSOR_INVALID')
                row = db.execute('''SELECT ordinal,page_index,chunk_index,
                    chunk_digest,row_count,row_bytes,chunk FROM
                    epm.fact_export_payload_chunk WHERE workspace_id=%s
                    AND application_id=%s AND artifact_id=%s AND ordinal=%s''',
                    (scope.workspace_id, scope.application_id,
                     artifact_id, ordinal)).fetchone()
                if row is None:
                    raise ValueError('EXPORT_PAYLOAD_CORRUPT')
                if cursor_value is not None:
                    prior = db.execute('''SELECT chunk_digest FROM
                        epm.fact_export_payload_chunk WHERE workspace_id=%s
                        AND application_id=%s AND artifact_id=%s
                        AND ordinal=%s''', (scope.workspace_id,
                        scope.application_id, artifact_id,
                        ordinal - 1)).fetchone()
                    if (prior is None or prior['chunk_digest'] !=
                            cursor_value['afterChunkDigest']):
                        raise ValueError('EXPORT_PAYLOAD_CURSOR_INVALID')
                chunk = row['chunk']
                if (row['chunk_digest'] != chunk.get('chunkDigest')
                        or row['row_count'] != chunk.get('rowCount')
                        or row['row_bytes'] != chunk.get('rowBytes')
                        or row['page_index'] != chunk.get('pageIndex')
                        or row['chunk_index'] != chunk.get('chunkIndex')
                        or not export_payload_chunk_matches(
                            chunk, artifact_id=artifact_id,
                            manifest=header['manifest'])):
                    raise ValueError('EXPORT_PAYLOAD_CORRUPT')
                has_more = ordinal + 1 < header['expected_chunk_count']
                next_cursor = None
                if has_more:
                    next_cursor = self._pack_cursor({
                        'scope': [scope.workspace_id, scope.application_id],
                        'identity': [self.identity.issuer,
                                     self.identity.subject_id],
                        'artifactId': artifact_id,
                        'manifestDigest': header['manifest_digest'],
                        'payloadDigest': header['payload_digest'],
                        'nextOrdinal': ordinal + 1,
                        'afterChunkDigest': row['chunk_digest'],
                        'expiresAt': min(header['expires_at_epoch'],
                                         header['artifact_expires'], now + 900)})
                return {
                    'artifactId': artifact_id,
                    'manifestDigest': header['manifest_digest'],
                    'payloadDigest': header['payload_digest'],
                    'schema': header['manifest']['schema'],
                    'snapshotRevision':
                        header['manifest']['snapshotRevision'],
                    'metadataRevision':
                        header['manifest']['metadataRevision'],
                    'securityRevision': header['security_revision'],
                    'storageFormat': 'plaintext_json',
                    'encryptionClaim': False, 'ordinal': ordinal,
                    'chunk': chunk, 'hasMore': has_more,
                    'nextCursor': next_cursor,
                    'expiresAt': header['expires_at_epoch']}

    def execute_read_program(self, scope: ApplicationScope,
                             program: dict) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program.get('languageVersion')) is not int
                or program['languageVersion'] != 2
                or program.get('function') != PAYLOAD_PAGE
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('EXPORT_PAYLOAD_READ_PROGRAM_INVALID')
        arguments = program['arguments']
        if set(arguments) == {'artifactId'}:
            if not isinstance(arguments['artifactId'], str):
                raise ValueError('EXPORT_PAYLOAD_READ_PROGRAM_INVALID')
            return self.read_chunk(scope, artifact_id=arguments['artifactId'])
        if set(arguments) == {'cursor'}:
            if not isinstance(arguments['cursor'], str):
                raise ValueError('EXPORT_PAYLOAD_READ_PROGRAM_INVALID')
            return self.read_chunk(scope, cursor=arguments['cursor'])
        raise ValueError('EXPORT_PAYLOAD_READ_PROGRAM_INVALID')

    @staticmethod
    def _result(row, *, duplicate=False):
        return {'artifactId': row['artifact_id'], 'status': row['status'],
                'manifestDigest': row['manifest_digest'],
                'payloadDigest': row['payload_digest'],
                'expectedChunkCount': row['expected_chunk_count'],
                'storageFormat': row['storage_format'],
                'encryptionClaim': row['encryption_claim'],
                'expiresAt': row['expires_at_epoch'],
                'retentionStatus': row['retention_status'],
                'duplicate': duplicate}
