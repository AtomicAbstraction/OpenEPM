"""Bounded, nonblocking candidate selection for durable sequence coordinators.

The cursor is a scheduling hint only. All business pins, status and progress
remain in PostgreSQL and are validated again by ordinary admission/publication.
"""
import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker
from .postgres_access import VerifiedExecutionIdentity
from .postgres_numeric_store import PostgresNumericFactStore

MAX_CANDIDATES = 128
_TABLES = frozenset(('expression_rule_sequence', 'full_aggregate_sequence'))


def durable_sequence_identity(row):
    """Rebuild only a sequence authority that was proven at admission."""
    kind = row['authority_kind']
    issued_at = row['token_issued_at']
    issuer = row['issuer']
    if kind == 'HumanToken':
        if type(issued_at) is not int or issued_at <= 0:
            raise ValueError('TOKEN_ISSUE_TIME_UNAVAILABLE')
    elif kind == 'Technical':
        if issued_at is not None or not issuer.startswith('urn:openepm:'):
            raise ValueError('TECHNICAL_AUTHORITY_INVALID')
    else:
        raise ValueError('TOKEN_ISSUE_TIME_UNAVAILABLE')
    return VerifiedExecutionIdentity(
        issuer, row['subject_id'], tuple(row['verified_groups']),
        issued_at=issued_at,
        authorization_scope_digest=row['authorization_scope_digest'])


def probe_scope(runtime_dsn, scope):
    """Return a busy partition, or None; release every probe lock before return.

    The runtime role supplies scoped row-lock privileges; the worker role gains
    no metadata write rights. A successful probe is not authorization or a lease.
    """
    with connect_postgres(runtime_dsn, row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db, scope)
            if not PostgresAccessChecker.try_lock_workspace(db, scope.workspace_id):
                return 'workspace'
            try:
                with db.transaction():
                    db.execute('''SELECT 1 FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s
                        FOR SHARE NOWAIT''', (scope.workspace_id, scope.application_id)).fetchone()
            except psycopg.errors.LockNotAvailable:
                return 'application'
    return None


def select_candidate(worker, runtime_dsn, table, scope, cursor):
    if table not in _TABLES:
        raise ValueError('SEQUENCE_DISPATCH_TABLE_INVALID')
    skipped_workspaces = []; skipped_apps = []
    def new_round():
        return {'before': worker.execute('SELECT clock_timestamp() AS cutoff').fetchone()['cutoff'],
                'after': None}
    cursor = cursor or new_round()
    refreshed = False
    query = sql.SQL('''SELECT s.* FROM {table} s
        LEFT JOIN epm.job j ON j.workspace_id=s.workspace_id
          AND j.application_id=s.application_id
          AND j.job_id=(s.job_ids->>s.current_step)
        WHERE s.status IN ('accepted','running','cancel_requested')
          AND (%s::text IS NULL OR s.workspace_id=%s)
          AND (%s::text IS NULL OR s.application_id=%s)
          AND s.updated_at<=%s::timestamptz
          AND (%s::timestamptz IS NULL OR
              (s.updated_at,s.sequence_id,s.workspace_id,s.application_id)>
              (%s::timestamptz,%s::text,%s::text,%s::text))
          AND (jsonb_array_length(s.job_ids)<=s.current_step OR j.job_id IS NULL
               OR j.status IN ('published','failed','cancelled','needs_inspection'))
          AND (s.status='cancel_requested' OR NOT (s.workspace_id=ANY(%s::text[])))
          AND (s.status='cancel_requested' OR NOT EXISTS(SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
              skip(workspace_id text,application_id text)
              WHERE skip.workspace_id=s.workspace_id AND skip.application_id=s.application_id))
        ORDER BY s.updated_at,s.sequence_id,s.workspace_id,s.application_id
        LIMIT 1 FOR UPDATE OF s SKIP LOCKED''').format(table=sql.Identifier('epm', table))
    for _ in range(MAX_CANDIDATES):
        after = cursor['after'] or (None, None, None, None)
        row = worker.execute(query, (
            scope.workspace_id if scope else None, scope.workspace_id if scope else None,
            scope.application_id if scope else None, scope.application_id if scope else None,
            cursor['before'], after[0], *after, skipped_workspaces, Jsonb(skipped_apps))).fetchone()
        if row is None:
            if refreshed:
                return None, None
            cursor = new_round(); refreshed = True
            continue
        cursor = {'before': cursor['before'],
                  'after': (row['updated_at'], row['sequence_id'], row['workspace_id'], row['application_id'])}
        # Cancellation settlement makes no new business admission and must not
        # require an active/unlocked application to finish an existing request.
        if row['status'] == 'cancel_requested':
            return row, cursor
        candidate_scope = ApplicationScope(row['workspace_id'], row['application_id'])
        busy = probe_scope(runtime_dsn, candidate_scope)
        if busy == 'workspace':
            skipped_workspaces.append(row['workspace_id'])
        elif busy == 'application':
            skipped_apps.append({'workspace_id': row['workspace_id'], 'application_id': row['application_id']})
        else:
            return row, cursor
    return None, cursor
