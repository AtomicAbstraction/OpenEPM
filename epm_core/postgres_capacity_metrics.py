"""Bounded administrator-only operational metrics for one application."""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import timezone
from hashlib import sha256
from pathlib import Path
from typing import Literal

from psycopg.rows import dict_row

from .observability import record_operational_signal
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_calculation_impact import calculation_impact_failure_code
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


CapacityView = Literal['full', 'queues']
CAPACITY_READ_AUTHORIZATION_STALE = 'CAPACITY_READ_AUTHORIZATION_STALE'


@dataclass(frozen=True)
class _Queue:
    key: str
    table: str
    unsettled: tuple[str, ...]
    available_sql: str = 'created_at'
    timing_id: str | None = None
    leased: bool = True

    @property
    def name(self) -> str:
        first, *parts = self.key.split('_')
        return first + ''.join(word.capitalize() for word in parts)


# Native work observed by the maintained dispatcher, including its two
# sequence coordinators. A parent unit and its child Job are distinct work
# records, so queue depths are per family and have no cross-family total.
_QUEUES = (
    _Queue('business', 'job',
           ('accepted', 'ready', 'running', 'staged', 'cancel_requested'),
           timing_id='job_id'),
    _Queue('aggregate', 'cube_aggregate_query',
           ('accepted', 'ready', 'running', 'computed', 'cancel_requested'),
           'accepted_at', 'query_id'),
    _Queue('python_build', 'python_program_build',
           ('accepted', 'ready', 'running', 'cancel_requested'), timing_id='build_id'),
    _Queue('python_workflow', 'python_program_workflow',
           ('accepted', 'ready', 'running', 'cancel_requested'), timing_id='workflow_id'),
    _Queue('python_schedule', 'python_program_occurrence',
           ('ready', 'running', 'building', 'running_program', 'cancel_requested'),
           'greatest(created_at,due_at)', 'occurrence_id'),
    _Queue('application_rule', 'application_rule_workflow',
           ('accepted', 'running', 'cancel_requested')),
    _Queue('application_schedule', 'application_schedule_occurrence',
           ('ready', 'running', 'submitted', 'cancel_requested'),
           'greatest(created_at,due_at)'),
    _Queue('import_execution', 'source_import_execution',
           ('Accepted', 'Claimed', 'Publishing')),
    _Queue('export_producer', 'fact_export_producer_request',
           ('Accepted', 'Reading', 'Prepared', 'Publishing')),
    _Queue('layout_replacement_build', 'layout_replacement_request',
           ('Accepted', 'Staging', 'Staged')),
    _Queue('layout_activation', 'layout_replacement_activation',
           ('Requested', 'Activating')),
    _Queue('expression_rule_sequence', 'expression_rule_sequence',
           ('accepted', 'running', 'cancel_requested'), leased=False),
    _Queue('full_aggregate_sequence', 'full_aggregate_sequence',
           ('accepted', 'running', 'cancel_requested'), leased=False),
)

# These leases progress the owning queue without adding a second work record
# to its depth. Idle scheduled definitions have no lease and contribute zero.
_AUXILIARY_LEASES = (
    ('pythonSchedule', 'python_program_schedule_definition', 'dispatch_'),
    ('applicationSchedule', 'application_schedule_definition', 'dispatch_'),
    ('layoutReplacementBuild', 'layout_replacement_materialization', ''),
)

# Only these native owners persist an authoritative first claim time. Retain
# historical sample keys and never estimate timing from last-update fields.
_QUEUE_TIMINGS = tuple(
    (queue.key, queue.table, queue.timing_id, queue.available_sql)
    for queue in _QUEUES if queue.timing_id is not None
)


def _claim_projection(claimant: str, lease: str) -> str:
    return f'''count({claimant}) AS recorded,
      count({claimant}) FILTER (WHERE {lease}>observed_at) AS live,
      count({claimant}) FILTER (WHERE {lease}<=observed_at) AS expired'''


def _queue_summary(db, scope):
    # Every depth, age and lease count in one snapshot, after the current
    # application authorization check under READ COMMITTED.
    branches = []
    parameters = [scope.workspace_id, scope.application_id]
    for queue in _QUEUES:
        claims = (_claim_projection('claimant', 'lease_until') if queue.leased
                  else '0 AS recorded, 0 AS live, 0 AS expired')
        retained_claim = 'OR claimant IS NOT NULL' if queue.leased else ''
        branches.append(f'''SELECT %s::text AS family,
          count(*) FILTER (WHERE unsettled) AS depth,
          coalesce(greatest(0,extract(epoch FROM (max(observed_at)
            -min({queue.available_sql}) FILTER (WHERE unsettled)))),0)::bigint AS age,
          {claims}, NULL::text, NULL::text, NULL::bigint
          FROM epm.{queue.table}
          CROSS JOIN observation
          CROSS JOIN LATERAL (SELECT status=ANY(%s) AS unsettled) AS work
          WHERE {queue.table}.workspace_id=observation.workspace
            AND {queue.table}.application_id=observation.application
            AND (unsettled {retained_claim})''')
        parameters.extend((queue.name, list(queue.unsettled)))
    for name, table, prefix in _AUXILIARY_LEASES:
        claims = _claim_projection(f'{prefix}claimant', f'{prefix}lease_until')
        branches.append(f'''SELECT %s::text, 0, 0, {claims},
            NULL::text, NULL::text, NULL::bigint
          FROM epm.{table} CROSS JOIN observation
          WHERE {table}.workspace_id=observation.workspace
            AND {table}.application_id=observation.application
            AND {prefix}claimant IS NOT NULL''')
        parameters.append(name)
    # Impact events use a contiguous application watermark and a transaction
    # lock. Their immutable creation times survive failed processing attempts.
    branches.append('''SELECT 'calculationImpact',
          state.impact_epoch-state.processed_impact_epoch,
          coalesce(greatest(0,floor(extract(epoch FROM
            (observation.observed_at-min(event.created_at))))),0)::bigint,
          0, 0, 0,
          max(progress.status) FILTER (WHERE event.impact_epoch=state.processed_impact_epoch+1),
          max(progress.failure_code) FILTER (WHERE event.impact_epoch=state.processed_impact_epoch+1),
          count(event.impact_epoch)
        FROM observation
        JOIN epm.application_state state ON (state.workspace_id,state.application_id)
          =(observation.workspace,observation.application)
        LEFT JOIN epm.calculation_impact_progress progress ON
          (progress.workspace_id,progress.application_id)=(state.workspace_id,state.application_id)
          AND progress.impact_epoch>state.processed_impact_epoch
          AND progress.impact_epoch<=state.impact_epoch
          AND progress.status IN ('pending','processing','failed')
        LEFT JOIN epm.calculation_impact_event event ON
          (event.workspace_id,event.application_id,event.impact_epoch)
          =(progress.workspace_id,progress.application_id,progress.impact_epoch)
        GROUP BY observation.observed_at,state.impact_epoch,state.processed_impact_epoch''')
    union = ' UNION ALL '.join(branches)
    return db.execute(f'''WITH observation AS (
          SELECT %s::text AS workspace, %s::text AS application,
                 statement_timestamp() AS observed_at)
        SELECT family, sum(depth)::bigint AS depth, max(age) AS age,
          sum(recorded)::bigint AS recorded, sum(live)::bigint AS live,
          sum(expired)::bigint AS expired, max(head_status) AS head_status,
          max(failure_code) AS failure_code, max(event_count) AS event_count,
          (SELECT observed_at FROM observation) AS observed_at
        FROM ({union}) AS queues(family,depth,age,recorded,live,expired,
          head_status,failure_code,event_count) GROUP BY family''', parameters).fetchall()


def _calculation_impact_head(row):
    if (row is None or row['depth'] != row['event_count'] or
            (row['depth'] and row['head_status'] not in ('pending', 'failed'))):
        raise ValueError('CALCULATION_IMPACT_QUEUE_UNAVAILABLE')
    if row['head_status'] == 'failed':
        return {'status': 'failed', 'failureCode': calculation_impact_failure_code(row['failure_code'])}
    return {'status': 'pending' if row['depth'] else 'clear'}


def _queue_wait_samples(db, scope):
    samples = {}
    for name, table, identity_sql, available_sql in _QUEUE_TIMINGS:
        rows = db.execute(f'''SELECT {identity_sql} AS work_id,first_claimed_at,
          greatest(0,(extract(epoch FROM
            (first_claimed_at-({available_sql})))*1000000)::bigint)
            AS queue_wait_microseconds FROM epm.{table}
          WHERE workspace_id=%s AND application_id=%s
            AND first_claimed_at IS NOT NULL
          ORDER BY first_claimed_at DESC,work_id DESC LIMIT 1000''',
          (scope.workspace_id,scope.application_id)).fetchall()
        samples[name] = [{
            'sampleId': sha256('|'.join((scope.workspace_id,scope.application_id,
                                        name,str(row['work_id']))).encode()).hexdigest(),
            'microseconds': int(row['queue_wait_microseconds']),
            'claimedAt': row['first_claimed_at'].isoformat()
        } for row in rows]
    return samples


def _bounded_file(path):
    if not path.is_file() or path.is_symlink():
        raise ValueError('CAPACITY_RESOURCE_METRICS_UNAVAILABLE')
    raw = path.read_text()[:64].strip()
    if not raw.isdecimal():
        raise ValueError('CAPACITY_RESOURCE_METRICS_UNAVAILABLE')
    return int(raw)


class PostgresCapacityMetrics:
    def __init__(self, dsn, *, temp_root=None, cgroup_root=None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('PostgreSQL runtime DSN is required')
        self.dsn = dsn
        configured = temp_root if temp_root is not None else os.environ.get('EPM_CAPACITY_TEMP_ROOT','')
        self.temp_root = Path(configured) if configured else None
        self.cgroup_root = Path(cgroup_root or os.environ.get('EPM_CAPACITY_CGROUP_ROOT','/sys/fs/cgroup'))

    @staticmethod
    def _read_access(db, identity, scope):
        db.execute('SET TRANSACTION READ ONLY')
        configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)
        # Check directory membership only after the workspace grants are fenced.
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        return PostgresAccessChecker.check_in_transaction(db, identity, scope, 'admin')

    def _verify_current_access(self, db, identity, scope, opening):
        with db.transaction():
            if self._read_access(db, identity, scope) != opening:
                raise ValueError(CAPACITY_READ_AUTHORIZATION_STALE)

    def read(self, identity, scope, *, view: CapacityView = 'full'):
        if not isinstance(identity,VerifiedIdentity) or not isinstance(scope,ApplicationScope):
            raise ValueError('Verified identity and application scope are required')
        if view not in ('full', 'queues'):
            raise ValueError('CAPACITY_METRICS_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            opening = None
            try:
                with db.transaction():
                    opening = self._read_access(db, identity, scope)
                    if view == 'full' and (self.temp_root is None or not self.temp_root.is_dir()
                                           or self.temp_root.is_symlink()):
                        raise ValueError('CAPACITY_TEMP_ROOT_UNAVAILABLE')
                    summary = {row['family']: row for row in _queue_summary(db, scope)}
                    impact_row = summary.get('calculationImpact')
                    impact = _calculation_impact_head(impact_row)
                    observed_at = impact_row['observed_at'].astimezone(timezone.utc)
                    if view == 'full':
                        database = db.execute('''SELECT numbackends,temp_bytes,temp_files FROM
                          pg_stat_database WHERE datname=current_database()''').fetchone()
                        queue_wait_samples = _queue_wait_samples(db, scope)
                if view == 'full':
                    # Allow grant changes to proceed while sampling the host.
                    stat = os.statvfs(self.temp_root)
                    current = _bounded_file(self.cgroup_root/'memory.current')
                    maximum_path = self.cgroup_root/'memory.max'
                    maximum_raw = maximum_path.read_text()[:64].strip() if maximum_path.is_file() else ''
                    maximum = int(maximum_raw) if maximum_raw.isdecimal() else None
            except (OSError, ValueError):
                if opening is not None:
                    self._verify_current_access(db, identity, scope, opening)
                raise
            # The workspace grant fence ends with the first transaction.
            # Directory reconciliation can change effective groups even before that.
            self._verify_current_access(db, identity, scope, opening)
        depths = {}
        queue_oldest_age = {}
        claim_counts = {}
        families = {queue.name: queue.key for queue in _QUEUES}
        families['calculationImpact'] = 'calculation_impact'
        for name, key in families.items():
            row = summary[name]
            depths[name] = row['depth']
            queue_oldest_age[name] = row['age']
            claim_counts[name] = {'activeClaims': row['recorded'],
                                  'liveClaims': row['live'],
                                  'expiredClaims': row['expired']}
            record_operational_signal('queue_oldest_age', row['age'], family=key)
        workers = {
            key: sum(family[key] for family in claim_counts.values())
            for key in ('activeClaims', 'liveClaims', 'expiredClaims')
        }
        result = {
            'scope': {'workspaceId':scope.workspace_id,'applicationId':scope.application_id},
            'queueObservedAt': observed_at.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            'metricScopes': {
                'queueDepths':'authorized_application_only',
                'workers':'authorized_application_only',
                'queueOldestAgeSeconds':'authorized_application_fixed_family_only',
                'calculationImpact':'authorized_application_only'},
            'queueDepths': depths,
            'queueOldestAgeSeconds': queue_oldest_age,
            'workers': {**workers, 'byFamily': claim_counts},
            'calculationImpact': impact,
        }
        if view == 'queues':
            return result

        used = (stat.f_blocks-stat.f_bavail)*stat.f_frsize
        total = stat.f_blocks*stat.f_frsize
        record_operational_signal('disk_used_ratio', used/total if total else 1)
        result['metricScopes'].update({
            'connections':'postgresql_database_wide',
            'databaseTemp':'postgresql_database_wide_cumulative',
            'queueWaitSamples':'authorized_application_bounded_technical_only',
            'memory':'serving_container_cgroup_only',
            'temporaryDisk':'serving_container_dedicated_tmpfs_only',
        })
        result.update({
            'connections': int(database['numbackends']),
            'queueWaitSamples': queue_wait_samples,
            'memoryGiB': round(current/1024**3,6),
            'memoryLimitGiB': round(maximum/1024**3,6) if maximum else None,
            'temporaryDiskGiB': round(used/1024**3,6),
            'databaseTempBytes': int(database['temp_bytes']),
            'databaseTempFiles': int(database['temp_files']),
        })
        return result
