"""Fixed-core bounded producer for export artifacts and payload chunks.

``prepare`` retains the bounded in-process path.  The schema-0113-backed
``prepare_durable`` path checkpoints each verified source page, resumes from
the first missing page under a fenced worker claim, and seals the manifest
before artifact/payload publication.  ``publish_durable`` marks that request
Completed only after the artifact and payload repositories report verified
completion.  Neither path exposes a partial artifact.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Callable

from .export_artifact_manifest import ExportArtifactBuilder
from .export_payload_chunk import compile_export_payload
from .persistence_contract import ApplicationScope
from .postgres_fact_export import PostgresFactExport, _EXPORT_SCHEMA


_KEY = re.compile(r'[A-Za-z0-9._-]{8,120}\Z')


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _prepared_digest(scope: ApplicationScope, request_identity: str,
                     origin: str, snapshot_revision: int,
                     metadata_revision: int, security_revision: int,
                     manifest: dict) -> str:
    return sha256(_canonical({
        'scope': [scope.workspace_id, scope.application_id],
        'requestIdentity': request_identity, 'origin': origin,
        'snapshotRevision': snapshot_revision,
        'metadataRevision': metadata_revision,
        'securityRevision': security_revision, 'schema': _EXPORT_SCHEMA,
        'manifestDigest': manifest['manifestDigest']})).hexdigest()


class ExportProducerCancelled(RuntimeError):
    pass


class ExportProducerCheckpointed(RuntimeError):
    """Bounded preparation stopped after durable source-page progress."""
    def __init__(self, request_id: str, page_count: int):
        super().__init__('EXPORT_PRODUCER_PREPARATION_CHECKPOINT')
        self.request_id = request_id
        self.page_count = page_count


@dataclass(frozen=True, slots=True)
class PreparedExport:
    scope: ApplicationScope
    request_identity: str
    origin: str
    snapshot_revision: int
    metadata_revision: int
    security_revision: int
    expires_at: int
    pages: tuple[bytes, ...]
    manifest_bytes: bytes
    preparation_digest: str

    @property
    def manifest(self) -> dict:
        return json.loads(self.manifest_bytes)

    def page_values(self) -> list[dict]:
        return [json.loads(value) for value in self.pages]


class ExportArtifactProducer:
    """Coordinate fixed source, immutable artifact, and payload repositories."""

    def __init__(self, source: PostgresFactExport, artifacts, payloads):
        for value, methods in (
                (source, ('page',)),
                (artifacts, ('save_export',)),
                (payloads, ('begin', 'progress', 'append', 'finalize'))):
            if any(not callable(getattr(value, method, None))
                   for method in methods):
                raise ValueError('EXPORT_PRODUCER_DEPENDENCY_INVALID')
        self.source = source
        self.artifacts = artifacts
        self.payloads = payloads

    def prepare(self, scope: ApplicationScope, *, request_identity: str,
                origin: str, snapshot_revision: int,
                metadata_revision: int, expires_at: int,
                security_revision: int = 0,
                members: dict[str, str] | None = None,
                page_limit: int = 50, max_pages: int = 100,
                cancelled: Callable[[], bool] | None = None) -> PreparedExport:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(request_identity, str)
                or not 8 <= len(request_identity) <= 128
                or not isinstance(origin, str) or not 1 <= len(origin) <= 500
                or type(snapshot_revision) is not int
                or snapshot_revision < 0
                or type(metadata_revision) is not int
                or metadata_revision < 0
                or type(security_revision) is not int
                or security_revision < 0
                or type(expires_at) is not int or expires_at < 1
                or type(page_limit) is not int or not 1 <= page_limit <= 50
                or type(max_pages) is not int or not 1 <= max_pages <= 100
                or (members is not None and (not isinstance(members, dict)
                    or any(not isinstance(key, str) or not key
                           or not isinstance(value, str) or not value
                           for key, value in members.items())))):
            raise ValueError('EXPORT_PRODUCER_REQUEST_INVALID')
        cancel = cancelled or (lambda: False)
        builder = ExportArtifactBuilder.begin(
            scope, snapshot_revision=snapshot_revision,
            metadata_revision=metadata_revision,
            security_revision=security_revision, expires_at=expires_at)
        pages: list[bytes] = []
        cursor = None
        for page_index in range(max_pages):
            if cancel():
                raise ExportProducerCancelled('EXPORT_PRODUCER_CANCELLED')
            page = self.source.page(
                scope, members=members, limit=page_limit, cursor=cursor,
                snapshot_revision=snapshot_revision)
            if (not PostgresFactExport.content_digest_matches(scope, page)
                    or page.get('schema') != _EXPORT_SCHEMA
                    or page.get('snapshotRevision') != snapshot_revision
                    or page.get('metadataRevision') != metadata_revision):
                raise ValueError('EXPORT_PRODUCER_SOURCE_IDENTITY_DRIFT')
            if page.get('securityRevision') != security_revision:
                raise ValueError('EXPORT_PRODUCER_SECURITY_IDENTITY_DRIFT')
            builder = builder.append(page_index=page_index,
                                     request_cursor=cursor, page=page)
            pages.append(_canonical(page))
            cursor = page['nextCursor']
            if cursor is None:
                break
        else:
            raise ValueError('EXPORT_PRODUCER_PRECHECKPOINT_LIMIT')
        manifest = builder.finalize(expires_at=expires_at).manifest()
        return PreparedExport(
            scope, request_identity, origin, snapshot_revision,
            metadata_revision, security_revision, expires_at, tuple(pages),
            _canonical(manifest), _prepared_digest(
                scope, request_identity, origin, snapshot_revision,
                metadata_revision, security_revision, manifest))

    def publish(self, prepared: PreparedExport, *,
                idempotency_key: str, chunk_budget: int = 10,
                cancelled: Callable[[], bool] | None = None,
                _producer_request_id: str | None = None,
                _producer_claim_generation: int | None = None,
                _producer_worker_id: str | None = None) -> dict:
        if (not isinstance(prepared, PreparedExport)
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)
                or type(chunk_budget) is not int
                or not 1 <= chunk_budget <= 100):
            raise ValueError('EXPORT_PRODUCER_PUBLISH_INVALID')
        manifest = prepared.manifest
        if (manifest.get('scope') != {
                'workspaceId': prepared.scope.workspace_id,
                'applicationId': prepared.scope.application_id}
                or manifest.get('snapshotRevision') !=
                   prepared.snapshot_revision
                or manifest.get('metadataRevision') !=
                   prepared.metadata_revision
                or manifest.get('expiresAt') != prepared.expires_at
                or prepared.preparation_digest != _prepared_digest(
                    prepared.scope, prepared.request_identity,
                    prepared.origin, prepared.snapshot_revision,
                    prepared.metadata_revision,
                    prepared.security_revision, manifest)):
            raise ValueError('EXPORT_PRODUCER_PREPARATION_INVALID')
        cancel = cancelled or (lambda: False)
        if cancel():
            return {'status': 'cancelled', 'preparationDigest':
                    prepared.preparation_digest, 'newEffects': False}
        lineage={} if _producer_request_id is None else {
            'producer_request_id':_producer_request_id,
            'producer_claim_generation':_producer_claim_generation,
            'producer_worker_id':_producer_worker_id}
        claim_args=({} if _producer_request_id is None else {
          'producer_claim':(_producer_request_id,_producer_worker_id,
                            _producer_claim_generation)})
        saved = self.artifacts.save_export(
            prepared.scope, idempotency_key=idempotency_key,
            manifest=manifest, expires_at=prepared.expires_at,
            security_revision=prepared.security_revision, **lineage)
        artifact_id = saved['artifactId']
        payload = compile_export_payload(
            artifact_id, prepared.scope, manifest,
            prepared.page_values())
        if saved.get('reusableComplete'):
            if saved.get('payloadDigest') != payload['payloadDigest']:
                raise ValueError('EXPORT_PRODUCER_DURABLE_IDENTITY_DRIFT')
            return {'status': 'complete', 'artifactId': artifact_id,
                    'manifestDigest': payload['manifestDigest'],
                    'payloadDigest': payload['payloadDigest'],
                    'chunkCount': payload['chunkCount'],
                    'preparationDigest': prepared.preparation_digest,
                    'duplicate': True}
        self.payloads.begin(
            prepared.scope, artifact_id,
            idempotency_key=idempotency_key + '.payload', payload=payload,
            **claim_args)
        progress = self.payloads.progress(prepared.scope, artifact_id)
        if (progress['manifestDigest'] != payload['manifestDigest']
                or progress['payloadDigest'] != payload['payloadDigest']
                or progress['expectedChunkCount'] != payload['chunkCount']):
            raise ValueError('EXPORT_PRODUCER_DURABLE_IDENTITY_DRIFT')
        if progress['status'] == 'complete':
            return {'status': 'complete', 'artifactId': artifact_id,
                    'manifestDigest': payload['manifestDigest'],
                    'payloadDigest': payload['payloadDigest'],
                    'chunkCount': payload['chunkCount'],
                    'preparationDigest': prepared.preparation_digest,
                    'duplicate': True}
        start = progress['appendedChunkCount']
        stop = min(start + chunk_budget, payload['chunkCount'])
        for ordinal in range(start, stop):
            if cancel():
                return {'status': 'cancelled', 'artifactId': artifact_id,
                        'appendedChunkCount': ordinal,
                        'preparationDigest': prepared.preparation_digest,
                        'newEffects': ordinal > start}
            self.payloads.append(
                prepared.scope, artifact_id, ordinal=ordinal,
                chunk=payload['chunks'][ordinal],**claim_args)
        if stop < payload['chunkCount']:
            return {'status': 'checkpoint', 'artifactId': artifact_id,
                    'appendedChunkCount': stop,
                    'chunkCount': payload['chunkCount'],
                    'preparationDigest': prepared.preparation_digest}
        final = self.payloads.finalize(prepared.scope,artifact_id,**claim_args)
        return {'status': 'complete', 'artifactId': artifact_id,
                'manifestDigest': final['manifestDigest'],
                'payloadDigest': final['payloadDigest'],
                'chunkCount': payload['chunkCount'],
                'preparationDigest': prepared.preparation_digest,
                'duplicate': final['duplicate']}

    def prepare_durable(self, checkpoints, scope: ApplicationScope, *,
                        worker_id: str, idempotency_key: str,
                        request_identity: str, origin: str,
                        snapshot_revision: int, metadata_revision: int,
                        expires_at: int, security_revision: int = 0,
                        members: dict[str, str] | None = None,
                        page_limit: int = 50, max_pages: int = 100,
                        page_budget: int | None = None
                        ) -> tuple[str, PreparedExport]:
        """Resume a pre-finalization export without rereading saved pages."""
        required=('begin','read','claim','pages','append','seal')
        if any(not callable(getattr(checkpoints,name,None)) for name in required):
            raise ValueError('EXPORT_PRODUCER_CHECKPOINT_INVALID')
        if (page_budget is not None and
                (type(page_budget) is not int or not 1 <= page_budget <= 100)):
            raise ValueError('EXPORT_PRODUCER_PAGE_BUDGET_INVALID')
        row=checkpoints.begin(
            scope,idempotency_key=idempotency_key,origin=origin,
            snapshot_revision=snapshot_revision,
            metadata_revision=metadata_revision,expires_at=expires_at,
            security_revision=security_revision,
            schema=_EXPORT_SCHEMA,members=members or {})
        request_id=row['request_id']
        saved=checkpoints.pages(scope,request_id)
        builder=ExportArtifactBuilder.begin(
            scope,snapshot_revision=snapshot_revision,
            metadata_revision=metadata_revision,
            security_revision=security_revision,expires_at=expires_at)
        cursor=None
        encoded=[]
        for index,page in enumerate(saved):
            if not PostgresFactExport.content_digest_matches(scope,page):
                raise ValueError('EXPORT_PRODUCER_CHECKPOINT_CORRUPT')
            builder=builder.append(page_index=index,request_cursor=cursor,page=page)
            encoded.append(_canonical(page));cursor=page['nextCursor']
        current=checkpoints.read(scope,request_id)
        if current['status'] in ('Completed','Prepared','Publishing'):
            manifest=current['manifest']
            if manifest is None: raise ValueError('EXPORT_PRODUCER_CHECKPOINT_CORRUPT')
        else:
            if (current['status'] == 'Reading'
                    and current.get('claimant') == worker_id):
                generation=current['claim_generation']
                cursor=current['expected_cursor'];index=current['next_page']
            else:
                claim=checkpoints.claim(scope,request_id,worker_id)
                if claim is None:
                    raise ValueError('EXPORT_PRODUCER_CLAIM_UNAVAILABLE')
                generation=claim['claim_generation']
                cursor=claim['expected_cursor'];index=claim['next_page']
            acquired=0
            while cursor is not None or index==0:
                if index>=max_pages: raise ValueError('EXPORT_PRODUCER_PRECHECKPOINT_LIMIT')
                page = (self.source.page(
                    scope, members=members, limit=page_limit,
                    snapshot_revision=snapshot_revision)
                    if cursor is None else
                    self.source.page(scope, cursor=cursor))
                if (not PostgresFactExport.content_digest_matches(scope,page)
                        or page.get('schema')!=_EXPORT_SCHEMA
                        or page.get('snapshotRevision')!=snapshot_revision
                        or page.get('metadataRevision')!=metadata_revision):
                    raise ValueError('EXPORT_PRODUCER_SOURCE_IDENTITY_DRIFT')
                if page.get('securityRevision') != security_revision:
                    raise ValueError('EXPORT_PRODUCER_SECURITY_IDENTITY_DRIFT')
                checkpoints.append(scope,request_id,worker_id,generation,index,
                                   cursor,page['nextCursor'],page)
                builder=builder.append(page_index=index,request_cursor=cursor,page=page)
                encoded.append(_canonical(page));cursor=page['nextCursor'];index+=1
                if cursor is None: break
                acquired += 1
                if page_budget is not None and acquired >= page_budget:
                    raise ExportProducerCheckpointed(request_id, index)
            manifest=builder.finalize(expires_at=expires_at).manifest()
            if not checkpoints.seal(scope,request_id,worker_id,generation,manifest):
                raise ValueError('EXPORT_PRODUCER_SEAL_CONFLICT')
        prepared=PreparedExport(scope,request_identity,origin,snapshot_revision,
            metadata_revision,security_revision,expires_at,tuple(encoded),
            _canonical(manifest),
            _prepared_digest(scope,request_identity,origin,snapshot_revision,
                             metadata_revision,security_revision,manifest))
        return request_id,prepared

    def publish_durable(self,checkpoints,request_id: str,
                        prepared: PreparedExport,*,idempotency_key: str,
                        worker_id: str,chunk_budget: int=10,
                        lease_seconds: int=120) -> dict:
        required=('claim_publish','complete')
        if (any(not callable(getattr(checkpoints,name,None)) for name in required)
                or not isinstance(worker_id,str) or not 1<=len(worker_id)<=200
                or type(lease_seconds)is not int or not 30<=lease_seconds<=300):
            raise ValueError('EXPORT_PRODUCER_PUBLISH_CLAIM_INVALID')
        claim=checkpoints.claim_publish(prepared.scope,request_id,worker_id,
                                        lease_seconds)
        if claim is None:
            raise ValueError('EXPORT_PRODUCER_PUBLISH_CLAIM_UNAVAILABLE')
        generation=claim['claim_generation']
        if claim.get('manifest_digest')!=prepared.manifest['manifestDigest']:
            raise ValueError('EXPORT_PRODUCER_DURABLE_IDENTITY_DRIFT')
        if claim.get('status')=='Completed':
            return {'status':'complete','artifactId':claim['artifact_id'],
                    'manifestDigest':claim['manifest_digest'],
                    'payloadDigest':claim['payload_digest'],
                    'preparationDigest':prepared.preparation_digest,
                    'duplicate':True}
        result=self.publish(prepared,idempotency_key=idempotency_key,
                            chunk_budget=chunk_budget,
                            _producer_request_id=request_id,
                            _producer_claim_generation=generation,
                            _producer_worker_id=worker_id)
        if result['status']=='complete':
            checkpoints.complete(prepared.scope,request_id,worker_id,generation,
                                 result['artifactId'],result['manifestDigest'],
                                 result['payloadDigest'])
        return result
