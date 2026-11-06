"""Transport-neutral fixed-core coordinator for durable cube aggregates.

This module does not register public functions or provide a persistence
fallback.  Its repository is expected to be the durable PostgreSQL adapter;
the native stage remains responsible for the snapshot-pinned relational scan.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from hashlib import sha256
from typing import Callable, Protocol

from .cube_aggregate_ir import CubeAggregateIR, compile_cube_aggregate
from .cube_aggregate_lifecycle import (
    AggregateCursor, AggregateCursorCodec, AggregateQueryBudgets,
    AggregateQueryRecord, AggregateQueryRepository, AggregateQueryStatus,
    AggregateSourcePins, AggregateTechnicalCertificate)
from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('CUBE_AGGREGATE_REQUEST_INVALID') from error


def _digest(value) -> str:
    return sha256(_canonical(value)).hexdigest()


class AggregateComputeStage(Protocol):
    def compute(self, scope: ApplicationScope, arguments: dict, *,
                max_groups: int, max_result_bytes: int,
                statement_timeout_ms: int) -> dict: ...


class AggregateDurableRepository(AggregateQueryRepository, Protocol):
    """Extra sealing fence implemented by the PostgreSQL repository."""

    def seal(self, current: AggregateQueryRecord) -> AggregateQueryRecord: ...


class CubeAggregateService:
    """Coordinates request, durable worker execution, read and cancellation."""

    def __init__(self, repository: AggregateDurableRepository,
                 stage: AggregateComputeStage, cursor_codec: AggregateCursorCodec,
                 *, identity: VerifiedIdentity,
                 clock: Callable[[], int] | None = None,
                 query_id_factory: Callable[[], str] | None = None):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        if not isinstance(cursor_codec, AggregateCursorCodec):
            raise ValueError('CUBE_AGGREGATE_CURSOR_CODEC_REQUIRED')
        self.repository = repository
        self.stage = stage
        self.cursor_codec = cursor_codec
        self.identity = identity
        self.clock = clock or (lambda: int(time.time()))
        self.query_id_factory = query_id_factory or (lambda: uuid.uuid4().hex)

    def _get(self, scope: ApplicationScope, query_id: str) -> AggregateQueryRecord:
        record = self.repository.get(scope, query_id)
        if record is None:
            raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')
        if (record.issuer != self.identity.issuer
                or record.subject != self.identity.subject_id):
            raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')
        return record

    def request(self, scope: ApplicationScope, arguments: dict, *,
                input_dimensions, dimension_roles,
                budgets: AggregateQueryBudgets | None = None,
                technical_lineage: dict | None = None) -> dict:
        """Validate and durably accept work without performing the scan."""
        if not isinstance(scope, ApplicationScope):
            raise ValueError('CUBE_AGGREGATE_SCOPE_INVALID')
        plan = compile_cube_aggregate(arguments, input_dimensions=input_dimensions,
                                      dimension_roles=dimension_roles)
        placement = plan.aggregation == 'generic_placement_weighted_sum'
        if placement != (technical_lineage is not None):
            raise ValueError('CUBE_AGGREGATE_PLACEMENT_LINEAGE_REQUIRED')
        if technical_lineage is not None:
            if (type(technical_lineage) is not dict
                    or technical_lineage.get('format') !=
                       'openepm-placement-lineage-v1'
                    or type(technical_lineage.get('lineageDigest')) is not str):
                raise ValueError('CUBE_AGGREGATE_PLACEMENT_LINEAGE_INVALID')
            payload={key:value for key,value in technical_lineage.items()
                     if key!='lineageDigest'}
            digest=_digest(payload)
            if (digest != technical_lineage['lineageDigest']
                    or dict(plan.generic_pins).get(
                        'placementLineageDigest') != digest):
                raise ValueError('CUBE_AGGREGATE_PLACEMENT_LINEAGE_INVALID')
        budget = budgets or AggregateQueryBudgets()
        if not isinstance(budget, AggregateQueryBudgets):
            raise ValueError('CUBE_AGGREGATE_BUDGETS_INVALID')
        accepted_at = self.clock()
        if type(accepted_at) is not int or accepted_at < 0:
            raise ValueError('CUBE_AGGREGATE_TIME_INVALID')
        query_id = self.query_id_factory()
        record = AggregateQueryRecord(query_id, scope, self.identity.issuer,
            self.identity.subject_id, _digest(plan.normalized_arguments),
            plan.plan_digest, AggregateQueryStatus.ACCEPTED, budget, accepted_at,
            accepted_at + budget.ttl_seconds)
        if technical_lineage is None:
            ready = self.repository.insert_ready(
                record, normalized_request=plan.normalized_arguments)
        else:
            ready = self.repository.insert_ready(record,
                normalized_request=plan.normalized_arguments,
                technical_lineage=technical_lineage)
        return {'queryId': query_id, 'status': ready.status.value,
                'requestDigest': record.request_digest,
                'planDigest': record.plan_digest,
                'expiresAt': record.expires_at}

    def admit(self, scope: ApplicationScope, query_id: str) -> dict:
        """Move an accepted request to the durable worker-ready state."""
        record = self._get(scope, query_id)
        if record.status == AggregateQueryStatus.READY:
            return {'queryId': query_id, 'status': record.status.value}
        if record.status != AggregateQueryStatus.ACCEPTED:
            raise ValueError('CUBE_AGGREGATE_NOT_ACCEPTED')
        updated = record.transition(AggregateQueryStatus.READY)
        if not self.repository.compare_and_transition(record, updated):
            raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
        return {'queryId': query_id, 'status': updated.status.value}

    @staticmethod
    def _certificate(record: AggregateQueryRecord, computed: dict
                     ) -> AggregateTechnicalCertificate:
        expected = {'profile', 'planDigest', 'backend', 'groupBy', 'sourcePins',
                    'hierarchyVersions', 'layout', 'rows'}
        if type(computed) is not dict or set(computed) != expected:
            raise ValueError('CUBE_AGGREGATE_COMPUTE_INVALID')
        if computed['planDigest'] != record.plan_digest or type(computed['rows']) is not list:
            raise ValueError('CUBE_AGGREGATE_COMPUTE_PLAN_MISMATCH')
        pins = computed['sourcePins']
        pin_fields = {'commit_revision', 'data_revision', 'metadata_revision',
                      'policy_revision', 'security_revision', 'schema_epoch',
                      'active_projection_generation'}
        if type(pins) is not dict or set(pins) != pin_fields:
            raise ValueError('CUBE_AGGREGATE_COMPUTE_INVALID')
        rows = computed['rows']
        row_bytes = sum(len(_canonical(row)) for row in rows)
        return AggregateTechnicalCertificate(record.plan_digest,
            computed['backend'], AggregateSourcePins(**pins),
            _digest(computed['hierarchyVersions']), _digest(rows), len(rows), row_bytes)

    def worker_run(self, scope: ApplicationScope, query_id: str,
                   arguments: dict, *, input_dimensions, dimension_roles,
                   statement_timeout_ms: int = 5000) -> dict:
        """Claim ready work, compute once, persist once, then authorize sealing."""
        if (type(statement_timeout_ms) is not int
                or not 1 <= statement_timeout_ms <= 20000):
            raise ValueError('CUBE_AGGREGATE_TIMEOUT_INVALID')
        record = self._get(scope, query_id)
        plan: CubeAggregateIR = compile_cube_aggregate(
            arguments, input_dimensions=input_dimensions,
            dimension_roles=dimension_roles)
        if (_digest(plan.normalized_arguments) != record.request_digest
                or plan.plan_digest != record.plan_digest):
            raise ValueError('CUBE_AGGREGATE_REQUEST_MISMATCH')
        # A crash after atomic row/certificate persistence but before the fresh
        # visibility fence resumes at sealing; it must never rerun the scan.
        if record.status == AggregateQueryStatus.COMPUTED:
            sealed = self.repository.seal(record)
            return {'queryId': query_id, 'status': sealed.status.value,
                    'technicalCertificate': self._certificate_wire(
                        sealed.certificate)}
        if record.status != AggregateQueryStatus.READY:
            raise ValueError('CUBE_AGGREGATE_NOT_READY')
        claimant='inline-'+sha256(query_id.encode('utf-8')).hexdigest()
        claim=self.repository.claim_query(scope,query_id,claimant,
                                          lease_seconds=30)
        if claim is None:raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
        if claim.get('normalizedRequest') != plan.normalized_arguments:
            raise ValueError('CUBE_AGGREGATE_REQUEST_MISMATCH')
        return self._worker_run_claim(
            claim,statement_timeout_ms=statement_timeout_ms)

    def worker_run_claim(self, claim: dict) -> dict:
        """Execute a dispatched lease under the fixed technical-query policy."""
        return self._worker_run_claim(claim,statement_timeout_ms=5000)

    def _worker_run_claim(self, claim: dict, *, statement_timeout_ms: int) -> dict:
        """Execute one repository-issued lease; stale workers cannot persist."""
        if type(claim) is not dict or not isinstance(
                claim.get('record'), AggregateQueryRecord):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        record=claim['record']
        if record.status != AggregateQueryStatus.RUNNING:
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        stop_watch=threading.Event();cancel_event=threading.Event()
        def watch_cancel():
            while not stop_watch.wait(.05):
                try:
                    if self.repository.claim_cancel_requested(claim):
                        cancel_event.set();return
                except Exception:
                    # A lost/stale fence cannot authorize cancellation. The
                    # live claim is checked again before any result persists.
                    return
        watcher=threading.Thread(target=watch_cancel,daemon=True);watcher.start()
        try:
            computed=self.stage.compute(record.scope,claim.get('normalizedRequest'),
                max_groups=record.budgets.max_groups,
                max_result_bytes=record.budgets.max_result_bytes,
                statement_timeout_ms=statement_timeout_ms,cancel_event=cancel_event)
        except Exception:
            if cancel_event.is_set():
                observed=self._get(record.scope,record.query_id)
                if observed.status == AggregateQueryStatus.CANCEL_REQUESTED:
                    if self.repository.settle_cancelled_claim(claim):
                        return {'queryId':record.query_id,'status':'cancelled'}
            raise
        finally:
            stop_watch.set();watcher.join(timeout=1)
        certificate=self._certificate(record,computed)
        observed=self._get(record.scope,record.query_id)
        if observed.status == AggregateQueryStatus.CANCEL_REQUESTED:
            if not self.repository.settle_cancelled_claim(claim):
                raise ValueError('CUBE_AGGREGATE_STALE_WORKER_FENCE')
            return {'queryId':record.query_id,'status':'cancelled'}
        if observed.status != AggregateQueryStatus.RUNNING:
            raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
        completed=self.repository.store_computed(observed,certificate,
            computed['rows'],claim=claim)
        sealed=self.repository.seal(completed)
        return {'queryId':record.query_id,'status':sealed.status.value,
                'technicalCertificate':self._certificate_wire(certificate)}


    @staticmethod
    def _certificate_wire(certificate: AggregateTechnicalCertificate) -> dict:
        return {'kind': 'technical-query-certificate',
                'planDigest': certificate.plan_digest,
                'backendProfile': certificate.backend_profile,
                'sourcePins': certificate.source_pins.wire(),
                'hierarchyDigest': certificate.hierarchy_digest,
                'resultDigest': certificate.result_digest,
                'groupCount': certificate.group_count,
                'resultBytes': certificate.result_bytes}

    def read(self, scope: ApplicationScope, query_id: str, *,
             cursor: str | None = None, page_size: int | None = None) -> dict:
        record = self._get(scope, query_id)
        now = self.clock()
        if now >= record.expires_at:
            if record.status == AggregateQueryStatus.SEALED:
                expired = record.transition(AggregateQueryStatus.EXPIRED)
                self.repository.compare_and_transition(record, expired)
            elif record.status in (AggregateQueryStatus.ACCEPTED,
                                   AggregateQueryStatus.READY,
                                   AggregateQueryStatus.COMPUTED,
                                   AggregateQueryStatus.RUNNING,
                                   AggregateQueryStatus.CANCEL_REQUESTED):
                terminal = (record.transition(AggregateQueryStatus.CANCELLED)
                    if record.status == AggregateQueryStatus.CANCEL_REQUESTED else
                    record.transition(AggregateQueryStatus.FAILED,
                        error_code='CUBE_AGGREGATE_REQUEST_EXPIRED'))
                self.repository.compare_and_transition(record,terminal)
            raise ValueError('CUBE_AGGREGATE_RESULT_EXPIRED')
        if record.status != AggregateQueryStatus.SEALED or record.certificate is None:
            return {'queryId': query_id, 'status': record.status.value}
        if cursor is None:
            size, after = page_size or record.budgets.page_size, 0
        else:
            decoded = self.cursor_codec.unpack(cursor, scope=scope,
                issuer=self.identity.issuer, subject=self.identity.subject_id, now=now)
            if (decoded.query_id != query_id
                    or decoded.request_digest != record.request_digest
                    or decoded.result_digest != record.certificate.result_digest):
                raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
            if page_size is not None and page_size != decoded.page_size:
                raise ValueError('CUBE_AGGREGATE_CURSOR_INVALID')
            size, after = decoded.page_size, decoded.last_ordinal
        if type(size) is not int or not 1 <= size <= record.budgets.page_size:
            raise ValueError('CUBE_AGGREGATE_PAGE_REQUEST_INVALID')
        rows, has_more = self.repository.page(record, after_ordinal=after, limit=size)
        next_cursor = None
        if has_more:
            if not rows:
                raise ValueError('CUBE_AGGREGATE_PAGE_INVALID')
            next_cursor = self.cursor_codec.pack(AggregateCursor(query_id, scope,
                record.issuer, record.subject, record.request_digest,
                record.certificate.result_digest, size, rows[-1]['ordinal'],
                record.expires_at))
        return {'queryId': query_id, 'status': record.status.value,
                'rows': list(rows), 'nextCursor': next_cursor,
                'technicalCertificate': self._certificate_wire(record.certificate)}

    def cancel(self, scope: ApplicationScope, query_id: str) -> dict:
        record = self._get(scope, query_id)
        updated = record.request_cancel()
        if updated == record:
            return {'queryId': query_id, 'status': record.status.value}
        if not self.repository.compare_and_transition(record, updated):
            raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
        return {'queryId': query_id, 'status': updated.status.value}


class CubeAggregateTechnicalWorker:
    """One bounded, scoped technical-query worker iteration."""
    def __init__(self, service: CubeAggregateService):
        if not isinstance(service,CubeAggregateService):
            raise ValueError('CUBE_AGGREGATE_SERVICE_REQUIRED')
        self.service=service

    def run_once(self, scope: ApplicationScope, *, claimant: str,
                 lease_seconds: int = 30) -> dict | None:
        repository=self.service.repository
        repository.recover_expired(scope)
        computed=repository.pending_computed(scope)
        if computed is not None:
            sealed=repository.seal(computed)
            return {'queryId':sealed.query_id,'status':sealed.status.value,
                    'technicalCertificate':self.service._certificate_wire(
                        sealed.certificate)}
        claim=repository.claim(scope,claimant,lease_seconds=lease_seconds)
        return None if claim is None else self.service.worker_run_claim(claim)
