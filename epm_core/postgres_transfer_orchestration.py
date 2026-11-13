"""Public fixed-core orchestration for source manifests and durable exports."""
from __future__ import annotations

import re
import time

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_export_producer_checkpoint import PostgresExportProducerCheckpoint
from .export_producer import (ExportArtifactProducer,
                              ExportProducerCheckpointed)
from .postgres_fact_export import PostgresFactExport, _EXPORT_SCHEMA
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_export_payload import PostgresExportPayload
from .postgres_source_batch import PostgresSourceBatch
from .postgres_source_upload_manifest import PostgresSourceUploadManifest
from .postgres_transfer_artifacts import PostgresTransferArtifacts


SOURCE_MANIFEST_ATTACH = 'facts.source.manifest.attach'
SOURCE_MANIFEST_READ = 'facts.source.manifest.read'
SOURCE_DIAGNOSTICS_COMPILE = 'facts.source.diagnostics.compile'
EXPORT_REQUEST = 'facts.transfer.export.request'
EXPORT_READ = 'facts.transfer.export.read'
EXPORT_CANCEL = 'facts.transfer.export.cancel'
PUBLIC_FUNCTIONS = frozenset((SOURCE_MANIFEST_ATTACH, SOURCE_MANIFEST_READ,
                              SOURCE_DIAGNOSTICS_COMPILE, EXPORT_REQUEST,
                              EXPORT_READ, EXPORT_CANCEL))
_ID = re.compile(r'[0-9a-f]{32}\Z')


def catalog() -> dict:
    return {
        SOURCE_MANIFEST_ATTACH: {
            'mode': 'durable_staging', 'permission': 'write',
            'arguments': {
                'batchId': 'caller-owned staged batch ID',
                'requestKey': '8–128 safe idempotency characters',
                'originKind': 'file, mcp, schedule or system-generated',
                'originRef': 'bounded non-control source reference',
                'schemaVersion': 'versioned declared source schema identity',
                'schema': 'bounded JSON source schema; never executable code',
                'contentDigest': 'SHA-256 of the complete acknowledged source'},
            'result': 'immutable manifest identity and retention state',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
        SOURCE_MANIFEST_READ: {
            'mode': 'read', 'permission': 'read',
            'arguments': {'batchId': 'server-issued batch ID'},
            'result': 'immutable source manifest and verified creator identity',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
        SOURCE_DIAGNOSTICS_COMPILE: {
            'mode': 'durable_staging', 'permission': 'write',
            'arguments': {
                'batchId': 'manifest-backed caller-owned batch ID',
                'rows': 'bounded raw typed source rows',
                'allowWarnings': 'explicit boolean diagnostic admission policy'},
            'result': 'immutable diagnostic artifact identity and counts',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'bounded_write'},
        EXPORT_REQUEST: {
            'mode': 'durable_query', 'permission': 'read',
            'arguments': {
                'idempotencyKey': '8–128 safe idempotency characters',
                'members': 'stable-ID equality filters',
                'expectedSnapshotRevision': 'current application commitRevision from application.state.read',
                'expectedMetadataRevision': 'current metadata revision',
                'expiresAt': 'absolute epoch, 60 seconds to 24 hours'},
            'result': 'caller-owned durable request ID and accepted status',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
        EXPORT_READ: {
            'mode': 'read', 'permission': 'read',
            'arguments': {'requestId': 'caller-owned durable request ID'},
            'result': 'bounded status, pinned revisions and finalized artifact identity',
            'previewRequired': False, 'idempotencyRequired': False,
            'workClass': 'short'},
        EXPORT_CANCEL: {
            'mode': 'technical_cancel', 'permission': 'read',
            'arguments': {'requestId': 'caller-owned durable request ID'},
            'result': 'actual status after safe cancellation attempt',
            'previewRequired': False, 'idempotencyRequired': True,
            'workClass': 'short'},
    }


class PostgresTransferOrchestration:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('TRANSFER_ORCHESTRATION_IDENTITY_INVALID')
        self.dsn = dsn
        self.identity = identity
        self.preview_secret = preview_secret

    @staticmethod
    def _program(program: object) -> tuple[str, dict]:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or program.get('languageVersion') != 2
                or program.get('function') not in PUBLIC_FUNCTIONS
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('TRANSFER_ORCHESTRATION_PROGRAM_INVALID')
        return program['function'], program['arguments']

    @staticmethod
    def _status(row: dict, *, duplicate: bool | None = None) -> dict:
        result = {
            'requestId': row['request_id'], 'status': row['status'],
            'snapshotRevision': row['snapshot_revision'],
            'metadataRevision': row['metadata_revision'],
            'securityRevision': row['security_revision'],
            'expiresAt': row['expires_at_epoch'],
            'pageCount': row['next_page'],
            'cancelRequested': row['cancel_requested'],
            'artifactId': row['artifact_id'],
            'errorCode': row['error_code'],
        }
        if duplicate is not None:
            result['duplicate'] = duplicate
        return result

    def execute(self, scope: ApplicationScope, program: object) -> dict:
        function, args = self._program(program)
        if function == SOURCE_MANIFEST_ATTACH:
            expected = {'batchId', 'requestKey', 'originKind', 'originRef',
                        'schemaVersion', 'schema', 'contentDigest'}
            if set(args) != expected:
                raise ValueError('SOURCE_MANIFEST_ARGUMENTS_INVALID')
            return PostgresSourceUploadManifest(
                self.dsn, identity=self.identity).create(
                    scope, args['batchId'], request_key=args['requestKey'],
                    origin_kind=args['originKind'], origin_ref=args['originRef'],
                    schema_version=args['schemaVersion'],
                    declared_schema=args['schema'],
                    content_digest=args['contentDigest'])
        if function == SOURCE_MANIFEST_READ:
            if set(args) != {'batchId'}:
                raise ValueError('SOURCE_MANIFEST_ARGUMENTS_INVALID')
            return PostgresSourceUploadManifest(
                self.dsn, identity=self.identity).read(scope, args['batchId'])
        if function == SOURCE_DIAGNOSTICS_COMPILE:
            if set(args) != {'batchId', 'rows', 'allowWarnings'}:
                raise ValueError('SOURCE_DIAGNOSTIC_ARGUMENTS_INVALID')
            return PostgresSourceBatch(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).diagnose(
                    scope, args['batchId'], rows=args['rows'],
                    allow_warnings=args['allowWarnings'])
        checkpoint = PostgresExportProducerCheckpoint(
            self.dsn, identity=self.identity)
        if function == EXPORT_REQUEST:
            expected = {'idempotencyKey', 'members',
                        'expectedSnapshotRevision',
                        'expectedMetadataRevision', 'expiresAt'}
            if (set(args) != expected
                    or type(args['expectedSnapshotRevision']) is not int
                    or args['expectedSnapshotRevision'] < 0
                    or type(args['expectedMetadataRevision']) is not int
                    or args['expectedMetadataRevision'] < 0
                    or type(args['expiresAt']) is not int):
                raise ValueError('EXPORT_REQUEST_ARGUMENTS_INVALID')
            prior = checkpoint.find_by_idempotency(
                scope, args['idempotencyKey'])
            if prior is not None:
                replay = checkpoint.begin(
                    scope, idempotency_key=args['idempotencyKey'], origin='mcp',
                    snapshot_revision=args['expectedSnapshotRevision'],
                    metadata_revision=args['expectedMetadataRevision'],
                    security_revision=prior['security_revision'],
                    expires_at=args['expiresAt'], schema=_EXPORT_SCHEMA,
                    members=args['members'])
                return self._status(replay, duplicate=True)
            now = int(time.time())
            if not now + 60 <= args['expiresAt'] <= now + 86400:
                raise ValueError('EXPORT_REQUEST_EXPIRY_INVALID')
            page = PostgresFactExport(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).page(
                    scope, members=args['members'], limit=1,
                    snapshot_revision=args['expectedSnapshotRevision'])
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT commit_revision,
                    metadata_revision,security_revision
                    FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
            if (state is None
                    or state['commit_revision'] !=
                       args['expectedSnapshotRevision']
                    or page['snapshotRevision'] !=
                       args['expectedSnapshotRevision']):
                raise ValueError('EXPORT_REQUEST_SNAPSHOT_STALE')
            if (state['metadata_revision'] !=
                    args['expectedMetadataRevision']
                    or page['metadataRevision'] !=
                       args['expectedMetadataRevision']):
                raise ValueError('EXPORT_REQUEST_METADATA_STALE')
            if (state['security_revision'] != page['securityRevision']):
                raise ValueError('EXPORT_REQUEST_SECURITY_STALE')
            row = checkpoint.begin(
                scope, idempotency_key=args['idempotencyKey'], origin='mcp',
                snapshot_revision=args['expectedSnapshotRevision'],
                metadata_revision=args['expectedMetadataRevision'],
                security_revision=page['securityRevision'],
                expires_at=args['expiresAt'], schema=_EXPORT_SCHEMA,
                members=args['members'])
            return self._status(row, duplicate=False)
        if (set(args) != {'requestId'}
                or not isinstance(args['requestId'], str)
                or not _ID.fullmatch(args['requestId'])):
            raise ValueError('EXPORT_REQUEST_ID_INVALID')
        if function == EXPORT_CANCEL:
            checkpoint.cancel(scope, args['requestId'])
        return self._status(checkpoint.read(scope, args['requestId']))


class PostgresTransferExportWorker:
    """Private bounded worker adapter; intentionally absent from the catalog."""
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes, worker_id: str):
        if (not isinstance(identity, VerifiedIdentity)
                or not isinstance(worker_id, str)
                or not 1 <= len(worker_id) <= 200):
            raise ValueError('TRANSFER_EXPORT_WORKER_INVALID')
        self.dsn = dsn
        self.identity = identity
        self.preview_secret = preview_secret
        self.worker_id = worker_id

    def process(self, scope: ApplicationScope, request_id: str, *,
                chunk_budget: int = 10,
                page_budget: int | None = None) -> dict:
        if type(chunk_budget) is not int or not 1 <= chunk_budget <= 10:
            raise ValueError('TRANSFER_EXPORT_CHUNK_BUDGET_INVALID')
        if (page_budget is not None and
                (type(page_budget) is not int or not 1 <= page_budget <= 100)):
            raise ValueError('TRANSFER_EXPORT_PAGE_BUDGET_INVALID')
        checkpoint = PostgresExportProducerCheckpoint(
            self.dsn, identity=self.identity)
        row = checkpoint.read(scope, request_id)
        if row['status'] == 'Cancelled':
            return {'requestId': request_id, 'status': 'cancelled'}
        producer = ExportArtifactProducer(
            PostgresFactExport(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret),
            PostgresTransferArtifacts(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret),
            PostgresExportPayload(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret))
        try:
            durable_id, prepared = producer.prepare_durable(
                checkpoint, scope, worker_id=self.worker_id,
                idempotency_key=row['idempotency_key'],
                request_identity=request_id, origin=row['origin'],
                snapshot_revision=row['snapshot_revision'],
                metadata_revision=row['metadata_revision'],
                security_revision=row['security_revision'],
                expires_at=row['expires_at_epoch'], members=row['members'],
                page_budget=page_budget)
        except ExportProducerCheckpointed as progress:
            return {'requestId': progress.request_id, 'status': 'checkpoint',
                    'preparedPageCount': progress.page_count}
        if durable_id != request_id:
            raise ValueError('TRANSFER_EXPORT_REQUEST_ID_DRIFT')
        result = producer.publish_durable(
            checkpoint, request_id, prepared,
            idempotency_key='export-' + request_id,
            worker_id=self.worker_id,chunk_budget=chunk_budget)
        return {'requestId': request_id, **result}
