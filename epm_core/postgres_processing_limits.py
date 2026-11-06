"""Server-owned lock budgets and transport-independent busy classification.

This bounds each database lock wait, not total operation time or computation.
Shorter deployment/session limits are preserved; zero never disables this gate.
"""
from functools import wraps

import psycopg
from .postgres_connection import connection_policy
from .postgres_execution_policy import tool_execution_policy, http_admission_policy
from .postgres_execution_scope import remaining_milliseconds

LOCK_WAIT_MS = 2000
BUSY_CODE = 'PROCESSING_LOCK_BUSY_RETRY'


class ProcessingBusy(psycopg.errors.LockNotAvailable):
    """No new effect is promised; retry the same request after contention ends."""

    def __init__(self):
        super().__init__(BUSY_CODE)


def configure_lock_wait(db):
    # pg_settings.setting uses the setting's native unit (milliseconds here),
    # regardless of SHOW formatting. SET LOCAL expires with this transaction.
    db.execute('''SELECT set_config('lock_timeout',
        least(coalesce(nullif(setting::bigint,0),%s),%s)::text,true)
        FROM pg_settings WHERE name='lock_timeout' ''', (LOCK_WAIT_MS, LOCK_WAIT_MS))


def configure_statement_timeout(db, maximum_ms):
    """Apply a fixed operation cap without weakening session/tool limits."""
    if type(maximum_ms) is not int or maximum_ms <= 0:
        raise ValueError('A positive fixed statement budget is required')
    remaining = remaining_milliseconds()
    cap = min(maximum_ms, remaining) if remaining is not None else maximum_ms
    db.execute('''SELECT set_config('statement_timeout',
        least(coalesce(nullif(setting::bigint,0),%s),%s)::text,true)
        FROM pg_settings WHERE name='statement_timeout' ''', (cap, cap))


def lock_busy_boundary(function):
    """Translate only lock contention, after the failed transaction unwinds."""
    @wraps(function)
    def bounded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ProcessingBusy:
            raise
        except psycopg.errors.LockNotAvailable as error:
            raise ProcessingBusy() from error
    return bounded


def policy():
    return {'connection': connection_policy(),
        'mcpTool': tool_execution_policy(),
        'httpAdmission': http_admission_policy(),
        'lockWaitMilliseconds': LOCK_WAIT_MS,
        'shorterSessionLimitsPreserved': True,
        'busyCode': BUSY_CODE,
        'busyIsQueued': False,
        'retry': 'reuse the same request key; re-preview only if inputs became stale',
        'scope': 'per database lock wait; not a wall-clock or computation budget'}
