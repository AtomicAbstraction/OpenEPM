"""Bounded administrator-only operational metrics for one application."""
from __future__ import annotations
from hashlib import sha256
import os
from pathlib import Path
from psycopg.rows import dict_row
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .observability import record_operational_signal

_QUEUES=(
 ('business','job',('accepted','ready','running','staged','cancel_requested')),
 ('aggregate','cube_aggregate_query',('accepted','ready','running','computed','cancel_requested')),
 ('pythonBuild','python_program_build',('accepted','ready','running','cancel_requested')),
 ('pythonWorkflow','python_program_workflow',('accepted','ready','running','cancel_requested')),
 ('pythonSchedule','python_program_occurrence',('ready','running','building','running_program','cancel_requested')))

# Every durable family exposes the same claimant/lease shape even though its
# state vocabulary differs.  Capacity evidence must not call only ordinary
# business jobs "workers" while six other queues are actively claimed.
_CLAIMS=tuple((name,table) for name,table,_statuses in _QUEUES)

_QUEUE_TIMINGS=(
 ('business','job','job_id','created_at'),
 ('aggregate','cube_aggregate_query','query_id','accepted_at'),
 ('python_build','python_program_build','build_id','created_at'),
 ('python_workflow','python_program_workflow','workflow_id','created_at'),
 ('python_schedule','python_program_occurrence','occurrence_id',
  'greatest(created_at,due_at)'))

# The starvation signal must include work which has never been claimed.  Keep
# this application-scoped and return only one bounded numeric value per fixed
# family; work IDs, principals and payloads never enter operational metrics.
_QUEUE_AGES=(
 ('business','job','created_at',('accepted','ready','running','staged','cancel_requested')),
 ('aggregate','cube_aggregate_query','accepted_at',('accepted','ready','running','computed','cancel_requested')),
 ('pythonBuild','python_program_build','created_at',('accepted','ready','running','cancel_requested')),
 ('pythonWorkflow','python_program_workflow','created_at',('accepted','ready','running','cancel_requested')),
 ('pythonSchedule','python_program_occurrence','greatest(created_at,due_at)',
  ('ready','running','building','running_program','cancel_requested')))

def _bounded_file(path):
 if not path.is_file() or path.is_symlink():raise ValueError('CAPACITY_RESOURCE_METRICS_UNAVAILABLE')
 raw=path.read_text()[:64].strip()
 if not raw.isdecimal():raise ValueError('CAPACITY_RESOURCE_METRICS_UNAVAILABLE')
 return int(raw)

class PostgresCapacityMetrics:
 def __init__(self,dsn,*,temp_root=None,cgroup_root=None):
  if not isinstance(dsn,str) or not dsn:raise ValueError('PostgreSQL runtime DSN is required')
  self.dsn=dsn
  configured=temp_root if temp_root is not None else os.environ.get('EPM_CAPACITY_TEMP_ROOT','')
  self.temp_root=Path(configured) if configured else None
  self.cgroup_root=Path(cgroup_root or os.environ.get('EPM_CAPACITY_CGROUP_ROOT','/sys/fs/cgroup'))
  if self.temp_root is None or not self.temp_root.is_dir() or self.temp_root.is_symlink():
   raise ValueError('CAPACITY_TEMP_ROOT_UNAVAILABLE')
 def read(self,identity,scope):
  if not isinstance(identity,VerifiedIdentity) or not isinstance(scope,ApplicationScope):
   raise ValueError('Verified identity and application scope are required')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope)
    PostgresAccessChecker.check_in_transaction(db,identity,scope,'admin')
    depths={}
    for name,table,statuses in _QUEUES:
     depths[name]=db.execute(f'''SELECT count(*) AS count FROM epm.{table}
      WHERE workspace_id=%s AND application_id=%s AND status=ANY(%s)''',
      (scope.workspace_id,scope.application_id,list(statuses))).fetchone()['count']
    database=db.execute('''SELECT numbackends,temp_bytes,temp_files FROM
     pg_stat_database WHERE datname=current_database()''').fetchone()
    claim_counts={}
    for name,table in _CLAIMS:
     row=db.execute(f'''SELECT count(*) AS active,count(*) FILTER(
      WHERE lease_until<=clock_timestamp()) AS expired FROM epm.{table}
      WHERE workspace_id=%s AND application_id=%s AND claimant IS NOT NULL''',
      (scope.workspace_id,scope.application_id)).fetchone()
     claim_counts[name]={'activeClaims':int(row['active']),
                         'expiredClaims':int(row['expired'])}
    queue_wait_samples={}
    for name,table,identity_sql,available_sql in _QUEUE_TIMINGS:
     rows=db.execute(f'''SELECT {identity_sql} AS work_id,first_claimed_at,
      greatest(0,(extract(epoch FROM
       (first_claimed_at-({available_sql})))*1000000)::bigint)
       AS queue_wait_microseconds FROM epm.{table}
      WHERE workspace_id=%s AND application_id=%s
        AND first_claimed_at IS NOT NULL
      ORDER BY first_claimed_at DESC,work_id DESC LIMIT 1000''',
      (scope.workspace_id,scope.application_id)).fetchall()
     queue_wait_samples[name]=[{
      'sampleId':sha256(('|'.join((scope.workspace_id,scope.application_id,
                                  name,str(row['work_id'])))).encode()).hexdigest(),
      'microseconds':int(row['queue_wait_microseconds']),
      'claimedAt':row['first_claimed_at'].isoformat()}
      for row in rows]
    queue_oldest_age={}
    for name,table,available_sql,statuses in _QUEUE_AGES:
     row=db.execute(f'''SELECT coalesce(greatest(0,extract(epoch FROM
      (clock_timestamp()-min({available_sql})))),0)::bigint AS seconds
      FROM epm.{table} WHERE workspace_id=%s AND application_id=%s
       AND status=ANY(%s)''',
      (scope.workspace_id,scope.application_id,list(statuses))).fetchone()
     queue_oldest_age[name]=int(row['seconds'])
     family={'pythonBuild':'python_build','pythonWorkflow':'python_workflow',
             'pythonSchedule':'python_schedule'}.get(name,name)
     record_operational_signal('queue_oldest_age',queue_oldest_age[name],family=family)
  stat=os.statvfs(self.temp_root);used=(stat.f_blocks-stat.f_bavail)*stat.f_frsize
  total=stat.f_blocks*stat.f_frsize
  record_operational_signal('disk_used_ratio',used/total if total else 1)
  current=_bounded_file(self.cgroup_root/'memory.current')
  maximum_path=self.cgroup_root/'memory.max'
  maximum_raw=maximum_path.read_text()[:64].strip() if maximum_path.is_file() else ''
  maximum=int(maximum_raw) if maximum_raw.isdecimal() else None
  return {'scope':{'workspaceId':scope.workspace_id,'applicationId':scope.application_id},
   'metricScopes':{'connections':'postgresql_database_wide','databaseTemp':'postgresql_database_wide_cumulative',
    'queueDepths':'authorized_application_only','workers':'authorized_application_only',
    'queueOldestAgeSeconds':'authorized_application_fixed_family_only',
    'queueWaitSamples':'authorized_application_bounded_technical_only',
    'memory':'serving_container_cgroup_only','temporaryDisk':'serving_container_dedicated_tmpfs_only'},
   'connections':int(database['numbackends']),'queueDepths':depths,
   'queueOldestAgeSeconds':queue_oldest_age,
   'queueWaitSamples':queue_wait_samples,
   'workers':{'activeClaims':sum(row['activeClaims'] for row in claim_counts.values()),
              'expiredClaims':sum(row['expiredClaims'] for row in claim_counts.values()),
              'byFamily':claim_counts},
   'memoryGiB':round(current/1024**3,6),'memoryLimitGiB':round(maximum/1024**3,6) if maximum else None,
   'temporaryDiskGiB':round(used/1024**3,6),'databaseTempBytes':int(database['temp_bytes']),
   'databaseTempFiles':int(database['temp_files'])}
