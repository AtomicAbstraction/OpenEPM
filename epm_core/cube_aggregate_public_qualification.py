"""Qualification-only complete lifecycle adapter for public cube aggregates.

Production language routing does not import this module.  Candidate execution
requires an explicit process opt-in and remains confined to disposable
qualification deployments.  The adapter uses the real durable repository,
service, worker, persisted paging and technical certificate.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
import time
import threading
import uuid
from typing import Callable

from .cube_aggregate_acceleration import ACCELERATED, NATIVE
from .cube_aggregate_lifecycle import AggregateCursorCodec, AggregateQueryBudgets
from .cube_aggregate_native import (CandidatePgDuckDbCubeAggregateStage,
                                    NativeCubeAggregateStage)
from .cube_aggregate_service import (CubeAggregateService,
                                     CubeAggregateTechnicalWorker)
from .cube_aggregate_qualification import PairedPublicAggregateQualification
from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_cube_aggregate_repository import PostgresCubeAggregateRepository


OPT_IN = 'EPM_PGDUCKDB_PUBLIC_ROUTE_QUALIFICATION'


def _digest(value: object) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('PGDUCKDB_PUBLIC_RESULT_INVALID') from error
    return sha256(raw).hexdigest()


class CompleteAggregateLifecycleMeasurement:
    """One complete request → durable worker → persisted read measurement."""

    def __init__(self, *, scope: ApplicationScope, service,
                 worker, arguments: dict, input_dimensions: list[str],
                 dimension_roles: dict[str, str | None],
                 requested_backend: str,
                 cleanup: Callable[[str, str], None], benchmark_identity=None,
                 clock: Callable[[], float] | None = None):
        if (not isinstance(scope, ApplicationScope)
                or not hasattr(service, 'request') or not hasattr(service, 'read')
                or not hasattr(service, 'cancel') or not hasattr(worker, 'run_once')
                or type(arguments) is not dict
                or type(input_dimensions) is not list or not input_dimensions
                or type(dimension_roles) is not dict
                or requested_backend not in (NATIVE, ACCELERATED)
                or not callable(cleanup)):
            raise ValueError('PGDUCKDB_PUBLIC_HARNESS_CONFIGURATION_INVALID')
        self.scope, self.service, self.worker = scope, service, worker
        self.arguments = arguments
        self.input_dimensions = input_dimensions
        self.dimension_roles = dimension_roles
        self.requested_backend = requested_backend
        self.cleanup = cleanup
        self.benchmark_identity = benchmark_identity
        self.clock = clock or time.perf_counter

    def run(self, pair_id: str) -> dict:
        return self._run(pair_id, benchmark=False)

    def run_benchmark(self, pair_id: str) -> dict:
        if type(self.benchmark_identity) is not dict:
            raise ValueError('PGDUCKDB_BENCHMARK_IDENTITY_REQUIRED')
        return self._run(pair_id, benchmark=True)

    def run_cancellation_benchmark(self, pair_id: str, *, source_cells: int) -> dict:
        """Cancel an owned running query and prove no technical result leaked."""
        if (type(pair_id) is not str or not pair_id or type(source_cells) is not int
                or source_cells <= 0 or type(self.benchmark_identity) is not dict):
            raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_INVALID')
        query_id = None; outcome = {}; failure = []
        try:
            accepted = self.service.request(self.scope, self.arguments,
                input_dimensions=self.input_dimensions,
                dimension_roles=self.dimension_roles,
                budgets=AggregateQueryBudgets(page_size=500))
            query_id = accepted.get('queryId')
            if type(query_id) is not str or accepted.get('status') != 'ready':
                raise ValueError('PGDUCKDB_PUBLIC_REQUEST_NOT_READY')
            def work():
                try:
                    outcome['worker'] = self.worker.run_once(self.scope,
                        claimant=('qualification-cancel-' + pair_id + '-' +
                                  uuid.uuid4().hex)[:200])
                except Exception as error:
                    failure.append(error)
            thread = threading.Thread(target=work, daemon=True); thread.start()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                state = self.service.read(self.scope, query_id)
                if state.get('status') in ('running', 'cancel_requested'):
                    break
                if not thread.is_alive():
                    raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_RACE_LOST')
                time.sleep(.01)
            else:
                raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_NOT_RUNNING')
            cancelled = self.service.cancel(self.scope, query_id)
            if cancelled.get('status') not in ('cancel_requested', 'cancelled'):
                raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_FAILED')
            thread.join(timeout=20)
            if thread.is_alive():
                raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_TIMEOUT')
            terminal = self.service.read(self.scope, query_id)
            if (terminal.get('status') != 'cancelled'
                    or terminal.get('rows') is not None
                    or terminal.get('technicalCertificate') is not None):
                raise ValueError('PGDUCKDB_BENCHMARK_PARTIAL_RESULT_VISIBLE')
            plan = getattr(self.service.stage, '_qualification_explain', None)
            marker = ('DuckDBScan' if self.requested_backend == ACCELERATED
                      else 'PostgreSQL')
            if (type(plan) is not str or not plan
                    or (self.requested_backend == ACCELERATED and 'DuckDBScan' not in plan)
                    or (self.requested_backend == NATIVE and 'DuckDBScan' in plan)):
                raise ValueError('PGDUCKDB_BENCHMARK_CANCEL_BACKEND_UNPROVEN')
            return {'selectedBackend': self.requested_backend,
                'ownedBySubject': True, 'terminalStatus': 'cancelled',
                'partialResultVisible': False, 'sourceCells': source_cells,
                'backendMarker': marker, 'workerFailure':
                    (type(failure[0]).__name__ if failure else None)}
        finally:
            if query_id is not None:
                self.cleanup(query_id, 'cancelled')

    def _run(self, pair_id: str, *, benchmark: bool) -> dict:
        if type(pair_id) is not str or not pair_id:
            raise ValueError('PGDUCKDB_PUBLIC_HARNESS_PAIR_INVALID')
        query_id = None
        terminal = 'not_admitted'
        started = self.clock(); request_finished = worker_started = None
        paging_ms = 0.0
        try:
            accepted = self.service.request(self.scope, self.arguments,
                input_dimensions=self.input_dimensions,
                dimension_roles=self.dimension_roles,
                budgets=AggregateQueryBudgets(page_size=500))
            query_id = accepted.get('queryId')
            if type(query_id) is not str or accepted.get('status') != 'ready':
                raise ValueError('PGDUCKDB_PUBLIC_REQUEST_NOT_READY')
            request_finished = self.clock(); worker_started = self.clock()
            published = self.worker.run_once(self.scope,
                claimant=('qualification-' + pair_id + '-' + uuid.uuid4().hex)[:200])
            if (type(published) is not dict or published.get('queryId') != query_id
                    or published.get('status') != 'sealed'):
                raise ValueError('PGDUCKDB_PUBLIC_WORKER_NOT_SEALED')
            certificate = published.get('technicalCertificate')
            if (type(certificate) is not dict
                    or certificate.get('kind') != 'technical-query-certificate'):
                raise ValueError('PGDUCKDB_PUBLIC_CERTIFICATE_INVALID')
            rows = []
            cursor = None
            while True:
                page_started = self.clock()
                page = self.service.read(self.scope, query_id,
                    **({'cursor': cursor} if cursor else {'page_size': 500}))
                paging_ms += (self.clock() - page_started) * 1000
                if (page.get('status') != 'sealed'
                        or page.get('technicalCertificate') != certificate
                        or type(page.get('rows')) is not list):
                    raise ValueError('PGDUCKDB_PUBLIC_PERSISTED_READ_INVALID')
                rows.extend(page['rows'])
                cursor = page.get('nextCursor')
                if cursor is None:
                    break
                if type(cursor) is not str or not cursor:
                    raise ValueError('PGDUCKDB_PUBLIC_CURSOR_INVALID')
            canonical_rows = [{key: value for key, value in row.items()
                               if key != 'ordinal'} for row in rows]
            if (_digest(canonical_rows) != certificate.get('resultDigest')
                    or certificate.get('groupCount') != len(canonical_rows)
                    or type(certificate.get('sourcePins')) is not dict):
                raise ValueError('PGDUCKDB_PUBLIC_RESULT_CERTIFICATE_MISMATCH')
            terminal = 'sealed'
            response = {'selectedBackend': certificate.get('backendProfile'),
                    'result': canonical_rows,
                    'sourcePins': certificate['sourcePins']}
            if benchmark:
                telemetry = getattr(self.service.stage,
                                    '_qualification_telemetry', None)
                if (type(telemetry) is not dict
                        or type(telemetry.get('explainPlan')) is not str
                        or not telemetry['explainPlan']):
                    raise ValueError('PGDUCKDB_BENCHMARK_TELEMETRY_UNAVAILABLE')
                ended = self.clock()
                queue_ms = (worker_started - request_finished) * 1000
                total_ms = (ended - started) * 1000
                database_ms = telemetry.get('databaseMs')
                materialization_ms = telemetry.get('materializationMs')
                if (type(database_ms) not in (int, float)
                        or type(materialization_ms) not in (int, float)):
                    raise ValueError('PGDUCKDB_BENCHMARK_TELEMETRY_UNAVAILABLE')
                persistence_ms = max(0.0, total_ms - queue_ms - database_ms
                                     - materialization_ms - paging_ms)
                response['benchmark'] = {
                    **self.benchmark_identity,
                    'requestDigest': accepted.get('requestDigest'),
                    'planDigest': certificate.get('planDigest'),
                    'sourcePinsDigest': _digest(certificate['sourcePins']),
                    'resultDigest': certificate.get('resultDigest'),
                    'timings': {'queueMs': queue_ms, 'databaseMs': database_ms,
                        'materializationMs': materialization_ms,
                        'persistenceMs': persistence_ms, 'pagingMs': paging_ms,
                        'endToEndMs': total_ms},
                    'explainPlan': telemetry['explainPlan'],
                    'backendMarker': telemetry.get('backendMarker'),
                    'memoryLimitBytes': telemetry.get('memoryLimitBytes'),
                    'spillLimitBytes': telemetry.get('spillLimitBytes')}
            return response
        except Exception:
            if query_id is not None:
                try:
                    cancelled = self.service.cancel(self.scope, query_id)
                    terminal = cancelled.get('status', 'cancel_failed')
                except Exception:
                    terminal = 'cancel_failed'
            raise
        finally:
            if query_id is not None:
                self.cleanup(query_id, terminal)


def postgres_lifecycle_measurement(*, dsn: str, identity: VerifiedIdentity,
                                   preview_secret: bytes,
                                   scope: ApplicationScope, arguments: dict,
                                   input_dimensions: list[str],
                                   dimension_roles: dict[str, str | None],
                                   requested_backend: str,
                                   cleanup: Callable[[str, str], None],
                                   benchmark_identity: dict | None = None,
                                   clock=None
                                   ) -> CompleteAggregateLifecycleMeasurement:
    """Build a real lifecycle measurement in an explicitly disposable process."""
    if os.environ.get(OPT_IN) != '1':
        raise ValueError('PGDUCKDB_PUBLIC_QUALIFICATION_OPT_IN_REQUIRED')
    if (type(dsn) is not str or not dsn
            or not isinstance(identity, VerifiedIdentity)
            or type(preview_secret) is not bytes or len(preview_secret) < 32):
        raise ValueError('PGDUCKDB_PUBLIC_HARNESS_CONFIGURATION_INVALID')
    repository = PostgresCubeAggregateRepository(dsn, identity=identity)
    stage_type = (NativeCubeAggregateStage if requested_backend == NATIVE
                  else CandidatePgDuckDbCubeAggregateStage)
    telemetry = {}
    def observe(value):
        if type(value) is not dict or telemetry:
            raise ValueError('PGDUCKDB_BENCHMARK_TELEMETRY_INVALID')
        telemetry.update(value)
    stage = stage_type(dsn, identity=identity,
        qualification_observer=(observe if benchmark_identity is not None else None))
    stage._qualification_telemetry = telemetry
    service = CubeAggregateService(repository,
        stage, AggregateCursorCodec(preview_secret),
        identity=identity)
    return CompleteAggregateLifecycleMeasurement(scope=scope, service=service,
        worker=CubeAggregateTechnicalWorker(service), arguments=arguments,
        input_dimensions=input_dimensions, dimension_roles=dimension_roles,
        requested_backend=requested_backend, cleanup=cleanup,
        benchmark_identity=benchmark_identity, clock=clock)


def record_paired_complete_lifecycle(*, profile: dict, controls: dict,
                                     measurement_factory: Callable[[str],
                                         CompleteAggregateLifecycleMeasurement],
                                     pairs: int = 5, clock=None) -> dict:
    """Record order-balanced native/candidate complete lifecycle evidence."""
    if not callable(measurement_factory):
        raise ValueError('PGDUCKDB_PUBLIC_HARNESS_CONFIGURATION_INVALID')
    def run(requested, pair_id):
        measurement = measurement_factory(requested)
        if (not isinstance(measurement, CompleteAggregateLifecycleMeasurement)
                or measurement.requested_backend != requested):
            raise ValueError('PGDUCKDB_PUBLIC_MEASUREMENT_PROFILE_MISMATCH')
        return measurement.run(pair_id)
    return PairedPublicAggregateQualification(profile=profile,
        controls=controls, run=run, clock=clock).record(pairs=pairs)
