"""PostgreSQL repository for durable aggregate-query control and results.

Fresh Reader authorization and source pins fence result sealing and paging;
leased workers cannot persist through a stale claim.
"""
from __future__ import annotations

import json
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .cube_aggregate_lifecycle import (
    AggregateQueryBudgets, AggregateQueryRecord, AggregateQueryStatus,
    AggregateSourcePins, AggregateTechnicalCertificate,
    POSTGRES_EXACT_DIMENSIONAL_BACKEND)
from .persistence_contract import ApplicationScope
from .postgres_access import (
    AccessDenied,PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role,
    durable_authority_fields)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


_AMOUNT = re.compile(r'-?(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,8})?\Z')
_COUNT = re.compile(r'(?:0|[1-9][0-9]*)\Z', re.ASCII)
_MAX_COUNT = 9223372036854775807
_HEX32 = re.compile(r'^[0-9a-f]{32}$')
_KEY = re.compile(r'^[A-Za-z0-9._-]{8,128}$')


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('CUBE_AGGREGATE_RESULT_INVALID') from error


def _timestamp(epoch: int) -> datetime:
    if type(epoch) is not int or epoch < 0:
        raise ValueError('CUBE_AGGREGATE_TIME_INVALID')
    return datetime.fromtimestamp(epoch, timezone.utc)


def _epoch(value: datetime) -> int:
    return int(value.timestamp())


def _placement_lineage(value, normalized_request):
    placement = normalized_request.get('aggregation') == (
        'generic_placement_weighted_sum')
    if placement != (value is not None):
        raise ValueError('CUBE_AGGREGATE_PLACEMENT_LINEAGE_REQUIRED')
    if value is None:
        return None, None
    if (type(value) is not dict
            or value.get('format') != 'openepm-placement-lineage-v1'
            or type(value.get('dimensions')) is not list
            or not 1 <= len(value['dimensions']) <= 128
            or type(value.get('lineageDigest')) is not str):
        raise ValueError('CUBE_AGGREGATE_PLACEMENT_LINEAGE_INVALID')
    payload={key:item for key,item in value.items() if key!='lineageDigest'}
    digest=sha256(_canonical(payload)).hexdigest()
    if (digest != value['lineageDigest']
            or normalized_request.get('genericPins',{}).get(
                'placementLineageDigest') != digest
            or len(_canonical(value)) > 4 * 1024 * 1024):
        raise ValueError('CUBE_AGGREGATE_PLACEMENT_LINEAGE_INVALID')
    return Jsonb(value), digest


def _normalize_rows(rows, certificate):
    if not isinstance(certificate, AggregateTechnicalCertificate):
        raise ValueError('CUBE_AGGREGATE_CERTIFICATE_INVALID')
    if type(rows) not in (list, tuple) or len(rows) != certificate.group_count:
        raise ValueError('CUBE_AGGREGATE_RESULT_COUNT_MISMATCH')
    normalized = []
    size = 0
    for ordinal, row in enumerate(rows, 1):
        if type(row) is not dict or not {'members'} <= set(row) <= {
                'members', 'sumAmount', 'countPresent', 'minAmount',
                'maxAmount'}:
            raise ValueError('CUBE_AGGREGATE_RESULT_INVALID')
        members = row['members']
        if (type(members) is not dict or any(type(k) is not str or not k
                or type(v) is not str or not v for k, v in members.items())):
            raise ValueError('CUBE_AGGREGATE_RESULT_INVALID')
        if not set(row) & {'sumAmount', 'countPresent', 'minAmount',
                           'maxAmount'}:
            raise ValueError('CUBE_AGGREGATE_RESULT_INVALID')
        amount = row.get('sumAmount')
        count = row.get('countPresent')
        minimum = row.get('minAmount')
        maximum = row.get('maxAmount')
        for value in (amount, minimum, maximum):
            if value is not None and (type(value) is not str
                                      or _AMOUNT.fullmatch(value) is None):
                raise ValueError('CUBE_AGGREGATE_RESULT_INVALID')
        if ('countPresent' in row
                and (type(count) is not str
                     or _COUNT.fullmatch(count) is None
                     or int(count) > _MAX_COUNT)):
            raise ValueError('CUBE_AGGREGATE_RESULT_INVALID')
        canonical = {'members': dict(sorted(members.items()))}
        # Preserve requested null measures. For an empty scalar reduction,
        # explicit null is the semantic result; omitting it would change the
        # certified result digest and make a durable page ambiguous.
        for key, value in (('sumAmount', amount),
                           ('countPresent', count),
                           ('minAmount', minimum),
                           ('maxAmount', maximum)):
            if key in row:
                canonical[key] = value
        row_bytes = len(_canonical(canonical))
        size += row_bytes
        normalized.append((ordinal, canonical, row_bytes))
    digest = sha256(_canonical([item for _, item, _ in normalized])).hexdigest()
    if digest != certificate.result_digest or size != certificate.result_bytes:
        raise ValueError('CUBE_AGGREGATE_RESULT_CERTIFICATE_MISMATCH')
    return normalized


class PostgresCubeAggregateRepository:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        assert_nonowner_role(dsn, 'epm_runtime',
                             ('cube_aggregate_query', 'cube_aggregate_result'))
        self.dsn = dsn
        self.identity = identity

    def _require_owner(self, record):
        if (not isinstance(record, AggregateQueryRecord)
                or record.issuer != self.identity.issuer
                or record.subject != self.identity.subject_id):
            raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')

    def _authorization_scope_digest(self, db, scope):
        return resolve_effective_dimensional_scope(
            db, self.identity, scope,
            function='facts.cube.aggregate.request').scope_digest

    def _require_current_authorization_scope(self, db, scope, query_id):
        row = db.execute('''SELECT authorization_scope_digest
            FROM epm.cube_aggregate_query WHERE workspace_id=%s
            AND application_id=%s AND query_id=%s''',
            (scope.workspace_id, scope.application_id, query_id)).fetchone()
        if row is None:
            raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')
        expected = row['authorization_scope_digest']
        if (expected is None or
                self._authorization_scope_digest(db, scope) != expected):
            raise AccessDenied('CUBE_AGGREGATE_AUTHORIZATION_SCOPE_CHANGED')

    def rerun_as_task_controller(self, scope, query_id, *, idempotency_key):
        """Create a fresh owner query attempt from a terminal source query."""
        if (not isinstance(scope, ApplicationScope)
                or type(query_id) is not str or not 1 <= len(query_id) <= 200
                or query_id != query_id.strip()
                or any(ord(char) < 32 for char in query_id)
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None):
            raise ValueError('CUBE_AGGREGATE_RERUN_ARGUMENTS_INVALID')
        raw = json.dumps({'domain':'openepm-cube-aggregate-rerun-v1',
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'sourceQueryId':query_id,'idempotencyKey':idempotency_key},
            sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        new_query_id = sha256(raw).hexdigest()[:32]
        with self._authorized(scope, write=True) as db:
            authorization_scope_digest = self._authorization_scope_digest(
                db, scope)
            replay = db.execute('''SELECT query_id,status,rerun_of_query_id
                FROM epm.cube_aggregate_query WHERE workspace_id=%s
                AND application_id=%s AND issuer=%s AND subject_id=%s
                AND rerun_idempotency_key=%s''',
                (scope.workspace_id, scope.application_id,
                 self.identity.issuer, self.identity.subject_id,
                 idempotency_key)).fetchone()
            if replay is not None:
                if replay['rerun_of_query_id'] != query_id:
                    raise ValueError('CUBE_AGGREGATE_IDEMPOTENCY_CONFLICT')
                return {'queryId':replay['query_id'],
                        'status':replay['status']}
            source = db.execute('''SELECT * FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                AND issuer=%s AND subject_id=%s FOR UPDATE''',
                (scope.workspace_id, scope.application_id, query_id,
                 self.identity.issuer,
                 self.identity.subject_id)).fetchone()
            if source is None or source['status'] not in (
                    'sealed','expired','failed','cancelled'):
                raise ValueError('CUBE_AGGREGATE_RERUN_NOT_SUPPORTED')
            generation = db.execute('''SELECT coalesce(max(rerun_generation),0)+1
                AS generation FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                AND subject_id=%s AND request_digest=%s''',
                (scope.workspace_id, scope.application_id,
                 self.identity.issuer, self.identity.subject_id,
                 source['request_digest'])).fetchone()['generation']
            token_issued_at,authority_kind=durable_authority_fields(self.identity)
            inserted = db.execute('''INSERT INTO epm.cube_aggregate_query(
                workspace_id,application_id,query_id,issuer,subject_id,
                request_digest,plan_digest,normalized_request,status,max_groups,
                max_result_bytes,page_size,ttl_seconds,accepted_at,expires_at,
                rerun_generation,rerun_of_query_id,rerun_idempotency_key,
                placement_lineage,placement_lineage_digest,
                verified_groups,authorization_scope_digest,token_issued_at,
                authority_kind)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'ready',%s,%s,%s,%s,
                  transaction_timestamp(),transaction_timestamp()
                    +make_interval(secs=>%s),%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING query_id,status''',
                (scope.workspace_id, scope.application_id, new_query_id,
                 self.identity.issuer, self.identity.subject_id,
                 source['request_digest'], source['plan_digest'],
                 Jsonb(source['normalized_request']), source['max_groups'],
                 source['max_result_bytes'], source['page_size'],
                 source['ttl_seconds'], source['ttl_seconds'], generation,
                 query_id, idempotency_key, Jsonb(source['placement_lineage'])
                 if source['placement_lineage'] is not None else None,
                 source['placement_lineage_digest'], list(self.identity.groups),
                 authorization_scope_digest,token_issued_at,
                 authority_kind)).fetchone()
            return {'queryId':inserted['query_id'],
                    'status':inserted['status']}

    def request_cancel_as_task_controller(self, scope, query_id, *,
                                          allow_application_admin=False):
        """Interrupt one visible technical query under fresh authority.

        This is the universal-task controller path.  It deliberately changes
        only the native query lifecycle: no business revision or receipt is
        created, and a running lease is settled by its fenced worker.
        """
        if (not isinstance(scope, ApplicationScope) or type(query_id) is not str
                or not 1 <= len(query_id) <= 200 or query_id != query_id.strip()
                or any(ord(char) < 32 for char in query_id)
                or type(allow_application_admin) is not bool):
            raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read',
                    function='facts.cube.aggregate.request')
                row = db.execute('''SELECT issuer,subject_id,status
                    FROM epm.cube_aggregate_query WHERE workspace_id=%s
                    AND application_id=%s AND query_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     query_id)).fetchone()
                if row is None:
                    raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')
                owner = ((row['issuer'], row['subject_id']) ==
                         (self.identity.issuer, self.identity.subject_id))
                if not owner:
                    if not allow_application_admin:
                        raise ValueError('CUBE_AGGREGATE_QUERY_UNAVAILABLE')
                    try:
                        PostgresAccessChecker.check_in_transaction(
                            db, self.identity, scope, 'admin')
                    except AccessDenied as error:
                        raise ValueError(
                            'CUBE_AGGREGATE_QUERY_UNAVAILABLE') from error
                status = row['status']
                if status in ('cancel_requested', 'cancelled'):
                    return {'queryId': query_id, 'status': status}
                if status in ('sealed', 'failed', 'expired'):
                    raise ValueError('CUBE_AGGREGATE_CANCEL_NOT_AVAILABLE')
                updated = ('cancel_requested' if status == 'running'
                           else 'cancelled')
                changed = db.execute('''UPDATE epm.cube_aggregate_query
                    SET status=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND query_id=%s AND status=%s''',
                    (updated, scope.workspace_id, scope.application_id,
                     query_id, status)).rowcount
                if changed != 1:
                    raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
                return {'queryId': query_id, 'status': updated}

    @contextmanager
    def _authorized(self, scope, *, pins=None, write=False,
                    require_dimensional_safe=False, backend_profile=None):
        if not isinstance(scope, ApplicationScope):
            raise ValueError('CUBE_AGGREGATE_SCOPE_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function='facts.cube.aggregate.request')
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    security_revision,schema_epoch,
                    active_dimensional_security_policy_version
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (require_dimensional_safe and
                        state.get('active_dimensional_security_policy_version')
                        is not None and
                        backend_profile != POSTGRES_EXACT_DIMENSIONAL_BACKEND):
                    raise AccessDenied(
                        'CUBE_AGGREGATE_DIMENSIONAL_SECURITY_FILTER_REQUIRED')
                if pins is not None and any(state[key] != getattr(pins, key)
                        for key in ('metadata_revision', 'policy_revision',
                                    'security_revision', 'schema_epoch')):
                    raise ValueError('CUBE_AGGREGATE_STALE_CONTEXT')
                yield db

    @staticmethod
    def _record(row):
        if row is None:
            return None
        certificate = None
        if row['result_digest'] is not None:
            certificate = AggregateTechnicalCertificate(row['plan_digest'],
                row['backend_profile'], AggregateSourcePins(
                    row['source_commit_revision'], row['source_data_revision'],
                    row['source_metadata_revision'], row['source_policy_revision'],
                    row['source_security_revision'], row['source_schema_epoch'],
                    row['source_projection_generation']),
                row['hierarchy_digest'], row['result_digest'],
                row['result_group_count'], row['result_bytes'])
        return AggregateQueryRecord(row['query_id'],
            ApplicationScope(row['workspace_id'], row['application_id']),
            row['issuer'], row['subject_id'], row['request_digest'], row['plan_digest'],
            AggregateQueryStatus(row['status']), AggregateQueryBudgets(
                row['max_groups'], row['max_result_bytes'], row['page_size'],
                row['ttl_seconds']), _epoch(row['accepted_at']), _epoch(row['expires_at']),
            certificate, row['error_code'])

    def insert(self, record, *, normalized_request):
        if not isinstance(record, AggregateQueryRecord) or record.status != AggregateQueryStatus.ACCEPTED:
            raise ValueError('CUBE_AGGREGATE_ACCEPTED_RECORD_REQUIRED')
        if type(normalized_request) is not dict:
            raise ValueError('CUBE_AGGREGATE_REQUEST_INVALID')
        self._require_owner(record)
        with self._authorized(record.scope, write=True) as db:
            authorization_scope_digest = self._authorization_scope_digest(
                db, record.scope)
            token_issued_at,authority_kind=durable_authority_fields(self.identity)
            db.execute('''INSERT INTO epm.cube_aggregate_query(
                workspace_id,application_id,query_id,issuer,subject_id,request_digest,
                plan_digest,normalized_request,status,max_groups,max_result_bytes,page_size,
                ttl_seconds,accepted_at,expires_at,verified_groups,
                authorization_scope_digest,token_issued_at,authority_kind) VALUES
                (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (record.scope.workspace_id, record.scope.application_id, record.query_id,
                 record.issuer, record.subject, record.request_digest, record.plan_digest,
                 Jsonb(normalized_request), record.status.value, record.budgets.max_groups,
                 record.budgets.max_result_bytes, record.budgets.page_size,
                 record.budgets.ttl_seconds, _timestamp(record.accepted_at),
                 _timestamp(record.expires_at), list(self.identity.groups),
                 authorization_scope_digest,token_issued_at,authority_kind))

    def insert_ready(self, record, *, normalized_request,
                     technical_lineage=None):
        """Atomically admit an accepted request into the technical queue."""
        if (not isinstance(record, AggregateQueryRecord)
                or record.status != AggregateQueryStatus.ACCEPTED
                or type(normalized_request) is not dict):
            raise ValueError('CUBE_AGGREGATE_ACCEPTED_RECORD_REQUIRED')
        self._require_owner(record)
        lineage,lineage_digest=_placement_lineage(
            technical_lineage,normalized_request)
        ready = record.transition(AggregateQueryStatus.READY)
        with self._authorized(record.scope, write=True) as db:
            authorization_scope_digest = self._authorization_scope_digest(
                db, record.scope)
            token_issued_at,authority_kind=durable_authority_fields(self.identity)
            db.execute('''INSERT INTO epm.cube_aggregate_query(
                workspace_id,application_id,query_id,issuer,subject_id,request_digest,
                plan_digest,normalized_request,status,max_groups,max_result_bytes,page_size,
                ttl_seconds,accepted_at,expires_at,placement_lineage,
                placement_lineage_digest,verified_groups,
                authorization_scope_digest,token_issued_at,authority_kind) VALUES
                (%s,%s,%s,%s,%s,%s,%s,%s,'ready',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                (record.scope.workspace_id, record.scope.application_id, record.query_id,
                 record.issuer, record.subject, record.request_digest, record.plan_digest,
                 Jsonb(normalized_request), record.budgets.max_groups,
                 record.budgets.max_result_bytes, record.budgets.page_size,
                 record.budgets.ttl_seconds, _timestamp(record.accepted_at),
                 _timestamp(record.expires_at),lineage,lineage_digest,
                 list(self.identity.groups),authorization_scope_digest,
                 token_issued_at,authority_kind))
        return ready

    def claim(self, scope, claimant, *, lease_seconds=30):
        if (type(claimant) is not str or not 1 <= len(claimant) <= 200
                or type(lease_seconds) is not int or not 5 <= lease_seconds <= 300):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        with self._authorized(scope, write=True) as db:
            row = db.execute('''SELECT * FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                  AND subject_id=%s AND status='ready' AND expires_at>clock_timestamp()
                ORDER BY accepted_at,query_id FOR UPDATE SKIP LOCKED LIMIT 1''',
                (scope.workspace_id, scope.application_id, self.identity.issuer,
                 self.identity.subject_id)).fetchone()
            if row is None:
                return None
            generation = row['claim_generation'] + 1
            db.execute('''UPDATE epm.cube_aggregate_query SET status='running',
                claim_generation=%s,claimant=%s,last_claimant=%s,
                next_attempt_at=NULL,attempts=attempts+1,
                lease_until=clock_timestamp()+make_interval(secs=>%s),
                updated_at=transaction_timestamp() WHERE workspace_id=%s
                AND application_id=%s AND query_id=%s AND status='ready' ''',
                (generation, claimant, claimant, lease_seconds, scope.workspace_id,
                 scope.application_id, row['query_id']))
            row.update({'status':'running','claim_generation':generation,
                        'claimant':claimant,'attempts':row['attempts']+1})
            return {'record':self._record(row),
                    'normalizedRequest':row['normalized_request'],
                    'claimant':claimant,'claimGeneration':generation}

    def claim_query(self, scope, query_id, claimant, *, lease_seconds=30):
        """Claim one caller-addressed ready query for the compatibility worker."""
        if (type(query_id) is not str or not query_id
                or type(claimant) is not str or not 1 <= len(claimant) <= 200
                or type(lease_seconds) is not int or not 5 <= lease_seconds <= 300):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        with self._authorized(scope, write=True) as db:
            row=db.execute('''SELECT * FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                  AND issuer=%s AND subject_id=%s AND status='ready'
                  AND expires_at>clock_timestamp() FOR UPDATE''',(
                scope.workspace_id,scope.application_id,query_id,
                self.identity.issuer,self.identity.subject_id)).fetchone()
            if row is None:return None
            generation=row['claim_generation']+1
            changed=db.execute('''UPDATE epm.cube_aggregate_query SET status='running',
                claim_generation=%s,claimant=%s,last_claimant=%s,
                next_attempt_at=NULL,attempts=attempts+1,
                lease_until=clock_timestamp()+make_interval(secs=>%s),
                updated_at=transaction_timestamp() WHERE workspace_id=%s
                AND application_id=%s AND query_id=%s AND status='ready' ''',(
                generation,claimant,claimant,lease_seconds,scope.workspace_id,
                scope.application_id,query_id)).rowcount
            if changed!=1:raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
            row.update({'status':'running','claim_generation':generation,
                        'claimant':claimant,'attempts':row['attempts']+1})
            return {'record':self._record(row),
                    'normalizedRequest':row['normalized_request'],
                    'claimant':claimant,'claimGeneration':generation}

    def heartbeat(self, claim, *, lease_seconds=30):
        if (type(claim) is not dict or type(lease_seconds) is not int
                or not 5 <= lease_seconds <= 300):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        record=claim.get('record');self._require_owner(record)
        with self._authorized(record.scope, write=True) as db:
            changed=db.execute('''UPDATE epm.cube_aggregate_query SET
                lease_until=clock_timestamp()+make_interval(secs=>%s),
                updated_at=transaction_timestamp() WHERE workspace_id=%s
                AND application_id=%s AND query_id=%s AND status IN
                ('running','cancel_requested') AND claim_generation=%s
                AND claimant=%s AND lease_until>clock_timestamp()''',
                (lease_seconds,record.scope.workspace_id,record.scope.application_id,
                 record.query_id,claim.get('claimGeneration'),claim.get('claimant'))).rowcount
            if changed != 1: raise ValueError('CUBE_AGGREGATE_STALE_WORKER_FENCE')

    def recover_expired(self, scope):
        with self._authorized(scope, write=True) as db:
            expired_ready=db.execute('''UPDATE epm.cube_aggregate_query SET
                status='failed',error_code='CUBE_AGGREGATE_REQUEST_EXPIRED',
                updated_at=transaction_timestamp() WHERE workspace_id=%s
                AND application_id=%s AND issuer=%s AND subject_id=%s
                AND status='ready' AND expires_at<=clock_timestamp()''',
                (scope.workspace_id,scope.application_id,self.identity.issuer,
                 self.identity.subject_id)).rowcount
            rows=db.execute('''SELECT query_id,status,attempts FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND issuer=%s
                AND subject_id=%s AND status IN ('running','cancel_requested')
                AND lease_until<=clock_timestamp() FOR UPDATE SKIP LOCKED''',
                (scope.workspace_id,scope.application_id,self.identity.issuer,
                 self.identity.subject_id)).fetchall()
            for row in rows:
                status=('cancelled' if row['status']=='cancel_requested' else
                        ('ready' if row['attempts']<3 else 'failed'))
                error='CUBE_AGGREGATE_RETRY_LIMIT' if status=='failed' else None
                db.execute('''UPDATE epm.cube_aggregate_query SET status=%s,error_code=%s,
                    claimant=NULL,lease_until=NULL,claim_generation=claim_generation+1,
                    next_attempt_at=CASE WHEN %s='ready' THEN
                      clock_timestamp()+make_interval(
                        secs=>least(60,(1::bigint<<greatest(0,least(%s-1,5)))::integer))
                      ELSE NULL END,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s
                    AND application_id=%s AND query_id=%s''',(status,error,
                    status,row['attempts'],
                    scope.workspace_id,scope.application_id,row['query_id']))
            return expired_ready+len(rows)

    def pending_computed(self, scope):
        with self._authorized(scope) as db:
            row=db.execute('''SELECT * FROM epm.cube_aggregate_query WHERE
                workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s
                AND status='computed' ORDER BY updated_at,query_id LIMIT 1''',
                (scope.workspace_id,scope.application_id,self.identity.issuer,
                 self.identity.subject_id)).fetchone()
            return self._record(row)

    def claim_cancel_requested(self, claim):
        if (type(claim) is not dict or not isinstance(
                claim.get('record'), AggregateQueryRecord)
                or type(claim.get('claimant')) is not str
                or type(claim.get('claimGeneration')) is not int):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        record=claim['record']
        self._require_owner(record)
        with self._authorized(record.scope) as db:
            row=db.execute('''SELECT status FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                  AND claim_generation=%s AND claimant=%s
                  AND lease_until>clock_timestamp()''',
                (record.scope.workspace_id,record.scope.application_id,
                 record.query_id,claim['claimGeneration'],
                 claim['claimant'])).fetchone()
            return row is not None and row['status']=='cancel_requested'

    def settle_cancelled_claim(self, claim):
        """Terminally settle only the still-live generation-owned claim."""
        if (type(claim) is not dict or not isinstance(
                claim.get('record'), AggregateQueryRecord)
                or type(claim.get('claimant')) is not str
                or type(claim.get('claimGeneration')) is not int):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        record=claim['record'];self._require_owner(record)
        with self._authorized(record.scope,write=True) as db:
            changed=db.execute('''UPDATE epm.cube_aggregate_query SET
                status='cancelled',claimant=NULL,lease_until=NULL,
                updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                  AND status='cancel_requested' AND claim_generation=%s
                  AND claimant=%s AND lease_until>clock_timestamp()''',(
                record.scope.workspace_id,record.scope.application_id,
                record.query_id,claim['claimGeneration'],
                claim['claimant'])).rowcount
            return changed==1

    def get(self, scope, query_id):
        with self._authorized(scope) as db:
            row = db.execute('''SELECT * FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                  AND issuer=%s AND subject_id=%s''',
                (scope.workspace_id, scope.application_id, query_id,
                 self.identity.issuer, self.identity.subject_id)).fetchone()
            return self._record(row)

    def compare_and_transition(self, current, updated):
        if (not isinstance(current, AggregateQueryRecord)
                or not isinstance(updated, AggregateQueryRecord)
                or current.scope != updated.scope or current.query_id != updated.query_id
                or current.request_digest != updated.request_digest
                or current.plan_digest != updated.plan_digest):
            raise ValueError('CUBE_AGGREGATE_TRANSITION_RECORD_MISMATCH')
        self._require_owner(current)
        values = {'status': updated.status.value, 'error': updated.error_code}
        certificate = updated.certificate
        if certificate is not None:
            values |= {'source_commit': certificate.source_pins.commit_revision,
                'source_data': certificate.source_pins.data_revision,
                'source_metadata': certificate.source_pins.metadata_revision,
                'source_policy': certificate.source_pins.policy_revision,
                'source_security': certificate.source_pins.security_revision,
                'source_schema': certificate.source_pins.schema_epoch,
                'source_generation': certificate.source_pins.active_projection_generation,
                'backend': certificate.backend_profile,
                'hierarchy': certificate.hierarchy_digest,
                'result': certificate.result_digest,
                'groups': certificate.group_count, 'bytes': certificate.result_bytes}
        with self._authorized(current.scope, write=True,
                              require_dimensional_safe=certificate is not None,
                              backend_profile=(certificate.backend_profile
                                  if certificate is not None else None)) as db:
            result = db.execute('''UPDATE epm.cube_aggregate_query SET status=%(status)s,
                error_code=%(error)s,source_commit_revision=%(source_commit)s,
                source_data_revision=%(source_data)s,source_metadata_revision=%(source_metadata)s,
                source_policy_revision=%(source_policy)s,source_schema_epoch=%(source_schema)s,
                source_security_revision=%(source_security)s,
                source_projection_generation=%(source_generation)s,backend_profile=%(backend)s,
                hierarchy_digest=%(hierarchy)s,result_digest=%(result)s,
                result_group_count=%(groups)s,result_bytes=%(bytes)s,
                claimant=CASE WHEN %(status)s IN ('running','cancel_requested')
                    THEN claimant ELSE NULL END,
                lease_until=CASE WHEN %(status)s IN ('running','cancel_requested')
                    THEN lease_until ELSE NULL END,
                updated_at=transaction_timestamp()
                WHERE workspace_id=%(workspace)s AND application_id=%(application)s
                  AND query_id=%(query)s AND status=%(current_status)s
                  AND request_digest=%(request)s AND plan_digest=%(plan)s''',
                {'workspace': current.scope.workspace_id,
                 'application': current.scope.application_id, 'query': current.query_id,
                 'current_status': current.status.value, 'request': current.request_digest,
                 'plan': current.plan_digest, **{key: values.get(key) for key in (
                    'status','error','source_commit','source_data','source_metadata',
                    'source_policy','source_security','source_schema','source_generation','backend',
                    'hierarchy','result','groups','bytes')}})
            return result.rowcount == 1

    def store_computed(self, current, certificate, rows, *, claim=None):
        self._require_owner(current)
        if current.status != AggregateQueryStatus.RUNNING:
            raise ValueError('CUBE_AGGREGATE_RUNNING_RECORD_REQUIRED')
        if (type(claim) is not dict
                or type(claim.get('claimGeneration')) is not int
                or claim['claimGeneration'] < 1
                or type(claim.get('claimant')) is not str
                or not 1 <= len(claim['claimant']) <= 200):
            raise ValueError('CUBE_AGGREGATE_CLAIM_INVALID')
        normalized = _normalize_rows(rows, certificate)
        updated = current.transition(AggregateQueryStatus.COMPUTED,
                                     certificate=certificate)
        with self._authorized(current.scope, write=True,
                              require_dimensional_safe=True,
                              backend_profile=certificate.backend_profile) as db:
            self._require_current_authorization_scope(
                db, current.scope, current.query_id)
            observed = db.execute('''SELECT status,claim_generation,claimant,
                lease_until>clock_timestamp() AS lease_valid FROM epm.cube_aggregate_query
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s FOR UPDATE''',
                (current.scope.workspace_id, current.scope.application_id,
                 current.query_id)).fetchone()
            if observed is None or observed['status'] != 'running':
                raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
            if (observed['claim_generation'] != claim['claimGeneration']
                    or observed['claimant'] != claim.get('claimant')
                    or not observed['lease_valid']):
                raise ValueError('CUBE_AGGREGATE_STALE_WORKER_FENCE')
            db.cursor().executemany('''INSERT INTO epm.cube_aggregate_result(
                workspace_id,application_id,query_id,ordinal,members,sum_amount,
                count_present,min_amount,max_amount,empty_scalar,row_bytes)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                [(current.scope.workspace_id, current.scope.application_id,
                  current.query_id, ordinal, Jsonb(row['members']), row.get('sumAmount'),
                  row.get('countPresent'), row.get('minAmount'),
                  row.get('maxAmount'),
                  not any(row.get(key) is not None for key in
                          ('sumAmount','countPresent','minAmount','maxAmount')),
                  row_bytes)
                 for ordinal, row, row_bytes in normalized])
            values = certificate.source_pins.wire()
            result = db.execute('''UPDATE epm.cube_aggregate_query SET status='computed',
                source_commit_revision=%s,source_data_revision=%s,
                source_metadata_revision=%s,source_policy_revision=%s,
                source_security_revision=%s,source_schema_epoch=%s,
                source_projection_generation=%s,
                backend_profile=%s,hierarchy_digest=%s,result_digest=%s,
                result_group_count=%s,result_bytes=%s,claimant=NULL,lease_until=NULL,
                updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                  AND status='running' AND claim_generation=%s AND claimant=%s
                  AND lease_until>clock_timestamp()''',
                (values['commit_revision'], values['data_revision'],
                 values['metadata_revision'], values['policy_revision'],
                 values['security_revision'], values['schema_epoch'],
                 values['active_projection_generation'],
                 certificate.backend_profile, certificate.hierarchy_digest,
                 certificate.result_digest, certificate.group_count,
                 certificate.result_bytes, current.scope.workspace_id,
                 current.scope.application_id, current.query_id,
                 claim['claimGeneration'], claim['claimant']))
            if result.rowcount != 1:
                # The result rows above share this transaction.  Raising here
                # rolls them back when the lease expired, cancellation won, or
                # a replacement generation claimed the query during compute.
                raise ValueError('CUBE_AGGREGATE_STALE_WORKER_FENCE')
        return updated

    def seal(self, current):
        self._require_owner(current)
        if current.status != AggregateQueryStatus.COMPUTED or current.certificate is None:
            raise ValueError('CUBE_AGGREGATE_COMPUTED_RECORD_REQUIRED')
        # This separate transaction is the post-compute authorization fence.
        with self._authorized(current.scope, pins=current.certificate.source_pins,
                              write=True, require_dimensional_safe=True,
                              backend_profile=
                                  current.certificate.backend_profile) as db:
            self._require_current_authorization_scope(
                db, current.scope, current.query_id)
            result = db.execute('''UPDATE epm.cube_aggregate_query SET status='sealed',
                updated_at=transaction_timestamp() WHERE workspace_id=%s
                AND application_id=%s AND query_id=%s AND status='computed'
                AND result_digest=%s''', (current.scope.workspace_id,
                    current.scope.application_id, current.query_id,
                    current.certificate.result_digest))
            if result.rowcount != 1:
                raise ValueError('CUBE_AGGREGATE_STALE_CONTROL_STATE')
        return current.transition(AggregateQueryStatus.SEALED)

    def page(self, record, *, after_ordinal, limit):
        self._require_owner(record)
        if (not isinstance(record, AggregateQueryRecord)
                or record.status != AggregateQueryStatus.SEALED
                or record.certificate is None or type(after_ordinal) is not int
                or after_ordinal < 0 or type(limit) is not int
                or not 1 <= limit <= record.budgets.page_size):
            raise ValueError('CUBE_AGGREGATE_PAGE_REQUEST_INVALID')
        with self._authorized(record.scope, pins=record.certificate.source_pins,
                              require_dimensional_safe=True,
                              backend_profile=
                                  record.certificate.backend_profile) as db:
            self._require_current_authorization_scope(
                db, record.scope, record.query_id)
            current = db.execute('''SELECT status,result_digest,expires_at,
                normalized_request
                FROM epm.cube_aggregate_query WHERE workspace_id=%s AND application_id=%s
                AND query_id=%s''', (record.scope.workspace_id,
                    record.scope.application_id, record.query_id)).fetchone()
            if (current is None or current['status'] != 'sealed'
                    or current['result_digest'] != record.certificate.result_digest
                    or current['expires_at'] < datetime.now(timezone.utc)):
                raise ValueError('CUBE_AGGREGATE_RESULT_UNAVAILABLE')
            rows = db.execute('''SELECT ordinal,members,sum_amount::text,
                count_present::text,min_amount::text,max_amount::text
                FROM epm.cube_aggregate_result WHERE workspace_id=%s AND application_id=%s
                AND query_id=%s AND ordinal>%s ORDER BY ordinal LIMIT %s''',
                (record.scope.workspace_id, record.scope.application_id,
                 record.query_id, after_ordinal, limit + 1)).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        kinds = {item['kind'] for item in
                 current['normalized_request']['measures']}
        return [{'ordinal': row['ordinal'], 'members': row['members'],
                 **({'sumAmount': row['sum_amount']} if 'SumAmount' in kinds else {}),
                 **({'countPresent': row['count_present']} if 'CountPresent' in kinds else {}),
                 **({'minAmount': row['min_amount']} if 'MinAmount' in kinds else {}),
                 **({'maxAmount': row['max_amount']} if 'MaxAmount' in kinds else {})}
                for row in rows], has_more

    def delete_expired_result(self, record):
        self._require_owner(record)
        with self._authorized(record.scope, write=True) as db:
            # Retain the durable query/certificate and any rerun lineage. Only
            # the bounded page payload is disposable after native expiry.
            result = db.execute('''DELETE FROM epm.cube_aggregate_result r
                WHERE r.workspace_id=%s AND r.application_id=%s
                AND r.query_id=%s AND EXISTS(
                  SELECT 1 FROM epm.cube_aggregate_query q
                  WHERE q.workspace_id=r.workspace_id
                    AND q.application_id=r.application_id
                    AND q.query_id=r.query_id AND q.status='expired'
                    AND q.expires_at<clock_timestamp())''',
                (record.scope.workspace_id, record.scope.application_id,
                 record.query_id))
            if result.rowcount < 0:
                raise AssertionError('Unexpected aggregate-result delete count')

