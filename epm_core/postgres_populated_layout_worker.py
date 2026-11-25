"""One bounded layout phase in the maintained fixed-worker family rotation.

The existing request, materialization and activation rows own their claims.
This adapter has no durable state, business converter or independent scheduler.
"""
from __future__ import annotations

from contextlib import contextmanager
import re
import time

import psycopg
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import (PostgresAccessChecker, assert_nonowner_role,
    durable_execution_identity, AccessDenied)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_execution_scope import tool_execution_scope, remaining_milliseconds, ToolDeadlineExpired
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout
from .postgres_populated_layout_replacement import (PostgresPopulatedLayoutReplacementWorker,
    _validated_plan, REQUEST)
from .postgres_populated_layout_materializer import PostgresPopulatedLayoutMaterializer, CHUNK_SIZE
from .populated_layout_generation_validation import MAX_COORDINATES
from .postgres_populated_layout_generation_validator import PostgresPopulatedLayoutGenerationValidator
from .postgres_populated_layout_activation import PostgresPopulatedLayoutActivator
from .postgres_populated_layout_preview import authorize_layout_plan_read

PHASES = ('Stage', 'Materialize', 'Validate', 'Activate')
PHASE_SECONDS = 60
LEASE_SECONDS = 120
STAGE_CHUNK = 500
_IDENTIFIER = re.compile(r'^[0-9a-f]{32}$')

# Only exact fixed-core refusal codes may become durable diagnostics. Database
# messages and unknown exception text are never copied into lifecycle rows/logs.
TERMINAL_CODES = frozenset({
    'LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED',
    'LAYOUT_ACTIVATION_AUTHORIZATION_SCOPE_CHANGED',
    'LAYOUT_REPLACEMENT_STAGED_MAPPING_CONFLICT',
    'LAYOUT_REPLACEMENT_PLAN_INVALID', 'LAYOUT_REPLACEMENT_SOURCE_STALE',
    'LAYOUT_MATERIALIZATION_SOURCE_STALE', 'LAYOUT_MATERIALIZATION_SOURCE_MISSING',
    'LAYOUT_GENERATION_SOURCE_PINS_STALE', 'LAYOUT_SOURCE_INVENTORY_STALE',
    'LAYOUT_DEPENDENCY_CONTEXT_STALE', 'LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED',
    'LAYOUT_DEPENDENCY_CERTIFICATE_STALE', 'LAYOUT_DEPENDENCY_INVENTORY_MISMATCH',
    'STALE_LAYOUT_DEPENDENCIES',
    'LAYOUT_VALIDATION_PUBLISH_STALE', 'LAYOUT_ACTIVATION_STALE',
    'LAYOUT_DEPENDENCY_INTENT_MISMATCH', 'LAYOUT_VALIDATION_INTENT_MISMATCH',
    'LAYOUT_ACTIVATION_SOURCE_STALE', 'LAYOUT_ACTIVATION_VALIDATION_STALE',
    'LAYOUT_ACTIVATION_AUTHORIZATION_REVOKED',
})


def _claim_shape(claim):
    if type(claim) is not dict or claim.get('phase') not in PHASES:
        raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
    for key in ('workspace_id', 'application_id', 'request_id', 'claimant'):
        if type(claim.get(key)) is not str or not claim[key]:
            raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
    if type(claim.get('claim_generation')) is not int or claim['claim_generation'] < 1:
        raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
    if not _IDENTIFIER.fullmatch(claim['request_id']):
        raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
    if claim['phase'] == 'Activate' and (type(claim.get('activation_id')) is not str
            or not _IDENTIFIER.fullmatch(claim['activation_id'])):
        raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
    if claim['phase'] == 'Materialize' and (type(claim.get('next_chunk')) is not int
            or not 0 <= claim['next_chunk'] <= (MAX_COORDINATES + CHUNK_SIZE - 1) // CHUNK_SIZE):
        raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
    # This is the established shared identity constructor, never a fallback.
    return durable_execution_identity(claim)


class PostgresPopulatedLayoutWorker:
    def __init__(self, *, worker_dsn, runtime_dsn, claimant,
                 capacity_limits=(32, 8, 2), phase_seconds=PHASE_SECONDS):
        if (type(worker_dsn) is not str or not worker_dsn or type(runtime_dsn) is not str or not runtime_dsn
                or type(claimant) is not str or not 1 <= len(claimant) <= 200
                or type(capacity_limits) is not tuple or len(capacity_limits) != 3
                or any(type(n) is not int or not 1 <= n <= 10000 for n in capacity_limits)
                or not capacity_limits[0] >= capacity_limits[1] >= capacity_limits[2]
                or type(phase_seconds) not in (int, float) or not 1 <= phase_seconds <= 90):
            raise ValueError('LAYOUT_WORKER_CONFIGURATION_INVALID')
        assert_nonowner_role(worker_dsn, 'epm_worker', ('layout_replacement_request',
            'layout_replacement_materialization', 'layout_replacement_activation'))
        self.worker_dsn=worker_dsn;self.runtime_dsn=runtime_dsn;self.claimant=claimant
        self.capacity_limits=capacity_limits;self.phase_seconds=phase_seconds;self.phase_cursor=0

    def recover(self):
        with connect_postgres(self.worker_dsn) as db, db.transaction():
            configure_lock_wait(db);configure_statement_timeout(db, 5000)
            return db.execute('SELECT epm.layout_worker_recover(%s::integer)', (100,)).fetchone()[0]

    def _claim(self, phase):
        with connect_postgres(self.worker_dsn, row_factory=dict_row) as db, db.transaction():
            configure_lock_wait(db);configure_statement_timeout(db, 5000)
            return db.execute('''SELECT epm.layout_worker_claim(
                %s,%s,%s::integer,%s::integer,%s::integer,%s::integer) AS claim''',
                (phase,self.claimant,LEASE_SECONDS,*self.capacity_limits)).fetchone()['claim']

    def advance_once(self):
        for offset in range(len(PHASES)):
            index=(self.phase_cursor+offset)%len(PHASES)
            claim=self._claim(PHASES[index])
            if claim is None:
                continue
            self.phase_cursor=(index+1)%len(PHASES)
            identity=_claim_shape(claim)
            if claim['phase'] != PHASES[index] or claim['claimant'] != self.claimant:
                raise ValueError('LAYOUT_WORKER_CLAIM_INVALID')
            try:
                with tool_execution_scope(time.monotonic()+self.phase_seconds):
                    return self._advance(claim, identity)
            except (ToolDeadlineExpired, psycopg.OperationalError,
                    psycopg.errors.QueryCanceled):
                # No failure/rollback assertion: prior private chunks or an
                # activation receipt may have committed. Read the same owner.
                return self._observe(claim, 'LAYOUT_WORKER_RETRY_SCHEDULED')
            except AccessDenied:
                return self._fail(claim, 'LAYOUT_WORKER_AUTHORIZATION_REVOKED')
            except (ValueError, psycopg.Error) as error:
                # PostgreSQL exposes a primary diagnostic but it is not a
                # safe channel unless it exactly matches this closed set.
                message=(error.diag.message_primary if isinstance(error, psycopg.Error)
                    and error.diag is not None else str(error))
                if message in TERMINAL_CODES:
                    return self._fail(claim, message)
                return self._fail(claim, 'LAYOUT_WORKER_PHASE_FAILED')
            except Exception:
                # Deterministic phase errors stop at this exact claim. Only
                # explicitly transient/uncertain transport and deadline paths
                # leave the original lease for recovery; no endless retry of
                # malformed input or failed fixed-core code.
                return self._fail(claim, 'LAYOUT_WORKER_PHASE_FAILED')
        return None

    def _advance(self, claim, identity):
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        if claim['phase']=='Stage':
            return self._stage(scope,claim,identity)
        if claim['phase']=='Materialize':
            PostgresPopulatedLayoutMaterializer(self.runtime_dsn,self.worker_dsn,
                identity=identity).materialize(scope,claim['request_id'],claimant=self.claimant,
                    merge_policy='one_to_one',claim=claim)
            return self._observe(claim)
        if claim['phase']=='Validate':
            owner=PostgresPopulatedLayoutGenerationValidator(self.runtime_dsn,identity=identity)
            decisions=claim['dependency_decisions']
            certificate=owner.validate(scope,claim['request_id'],merge_policy='one_to_one',
                affected_dependencies=[{'kind':d['kind'],'id':d['id']} for d in decisions],
                compatibility_decisions=decisions,worker_claim=claim)
            remaining_milliseconds()
            owner.persist(scope,claim['request_id'],certificate,worker_claim=claim)
            return self._observe(claim)
        PostgresPopulatedLayoutActivator(self.worker_dsn,self.runtime_dsn).publish(
            scope,claim['activation_id'],claimant=self.claimant,claim_generation=claim['claim_generation'])
        return self._observe(claim)

    @contextmanager
    def _stage_authority(self, scope, claim, identity, *, check_source=False):
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db, db.transaction():
            configure_lock_wait(db);configure_statement_timeout(db,5000)
            PostgresNumericFactStore._set_scope(db,scope)
            access=PostgresAccessChecker.check_in_transaction(db,identity,scope,'admin')
            current=resolve_effective_dimensional_scope(db,identity,scope,access=access,function=REQUEST)
            if current.scope_digest != claim['authorization_scope_digest']:
                raise ValueError('LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED')
            row=db.execute('''SELECT s.metadata_revision,s.data_revision,s.policy_revision,s.schema_epoch,
                s.commit_revision,s.commit_open FROM epm.application_state s
                WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                (scope.workspace_id,scope.application_id)).fetchone()
            pins=claim['plan']['pins']
            if (row is None or row['commit_open'] or
                [row[k] for k in ('metadata_revision','data_revision','policy_revision','schema_epoch','commit_revision')]
                !=[pins[k] for k in ('metadataRevision','dataRevision','policyRevision','schemaEpoch','sourceCommitRevision')]):
                raise ValueError('LAYOUT_REPLACEMENT_SOURCE_STALE')
            if check_source:
                authorize_layout_plan_read(db,identity,scope,access,claim['plan'])
            yield

    def _stage(self, scope, claim, identity):
        from .postgres_populated_layout_replacement import _digest
        from psycopg.types.json import Jsonb
        # Validate the admitted plan once; committed staged mappings remain the
        # sole progress owner across interrupted or reclaimed quanta.
        _validated_plan(claim['plan'])
        first_batch = True
        while True:
            remaining_milliseconds()
            with self._stage_authority(scope,claim,identity,check_source=first_batch):
                first_batch = False
                with connect_postgres(self.worker_dsn,row_factory=dict_row) as db, db.transaction():
                    configure_lock_wait(db);configure_statement_timeout(db,5000)
                    arguments=(scope.workspace_id,scope.application_id,claim['request_id'],
                        self.claimant,claim['claim_generation'])
                    renewed=db.execute('SELECT epm.layout_worker_stage_renew(%s,%s,%s,%s,%s,%s::integer) AS ok',
                        (*arguments,LEASE_SECONDS)).fetchone()['ok']
                    if not renewed:raise ValueError('LAYOUT_REPLACEMENT_STALE_WORKER')
                    remaining_milliseconds();configure_statement_timeout(db,5000)
                    mappings=db.execute('SELECT epm.layout_worker_stage_pending(%s,%s,%s,%s,%s,%s::integer) AS mappings',
                        (*arguments,STAGE_CHUNK)).fetchone()['mappings']
                    if type(mappings) is not list or len(mappings)>STAGE_CHUNK:
                        raise ValueError('LAYOUT_REPLACEMENT_PLAN_INVALID')
                    if not mappings:break
                    batch=[]
                    for mapping in mappings:
                        remaining_milliseconds()
                        if (type(mapping) is not dict or set(mapping)!={'sourceCoordinateId','targetMembers'}
                                or type(mapping['sourceCoordinateId']) is not int or mapping['sourceCoordinateId']<1
                                or type(mapping['targetMembers']) is not dict):
                            raise ValueError('LAYOUT_REPLACEMENT_PLAN_INVALID')
                        batch.append({**mapping,'targetDigest':_digest(mapping['targetMembers'])})
                    remaining_milliseconds();configure_statement_timeout(db,5000)
                    changed=db.execute('SELECT epm.layout_replacement_worker_stage_batch(%s,%s,%s,%s,%s,%s) AS changed',
                        (*arguments,Jsonb(batch))).fetchone()['changed']
                    if type(changed) is not int or changed!=len(batch):
                        raise ValueError('LAYOUT_REPLACEMENT_STALE_WORKER')
        remaining_milliseconds()
        with self._stage_authority(scope,claim,identity):
            changed=PostgresPopulatedLayoutReplacementWorker(self.worker_dsn).settle(scope,
                claim['request_id'],claimant=self.claimant,claim_generation=claim['claim_generation'],outcome='Staged')
            if not changed:raise ValueError('LAYOUT_REPLACEMENT_STALE_WORKER')
        return self._observe(claim)

    def _fail(self, claim, code):
        # Inspect first: an acknowledgement failure must never relabel a sealed
        # result. The SQL setter also requires the exact live original claim.
        before=self._observe(claim)
        if before['status'] in ('Validated','ValidationFailed','Activated','Cancelled','Failed'):
            return before
        with connect_postgres(self.worker_dsn) as db,db.transaction():
            configure_lock_wait(db);configure_statement_timeout(db,5000)
            changed=db.execute('SELECT epm.layout_worker_settle_failed(%s,%s,%s,%s,%s,%s,%s)',
                (claim['phase'],claim['workspace_id'],claim['application_id'],
                claim['activation_id'] if claim['phase']=='Activate' else claim['request_id'],
                claim['claimant'],claim['claim_generation'],code)).fetchone()[0]
        return self._observe(claim,None if changed else 'LAYOUT_WORKER_STALE_CLAIM')

    def _observe(self, claim, diagnostic=None):
        # Worker-only exact claim observation intentionally survives revoked
        # end-user READ; it is not a public disclosure or a substitute identity.
        with connect_postgres(self.worker_dsn,row_factory=dict_row) as db,db.transaction():
            configure_lock_wait(db);configure_statement_timeout(db,5000)
            row=db.execute('SELECT epm.layout_worker_observe(%s,%s,%s,%s) AS outcome',
                (claim['phase'],claim['workspace_id'],claim['application_id'],
                claim['activation_id'] if claim['phase']=='Activate' else claim['request_id'])).fetchone()['outcome']
        if type(row) is not dict:raise ValueError('LAYOUT_WORKER_OBSERVATION_UNAVAILABLE')
        terminal=row.get('status') in ('Validated','ValidationFailed','Activated','Failed','Cancelled')
        return {**row, 'layoutPhase':claim['phase'],
            **({'errorCode':diagnostic} if diagnostic and not terminal else {})}
