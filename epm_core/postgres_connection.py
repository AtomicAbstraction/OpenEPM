"""Fixed connection-attempt budget for application and deployment processes.

The driver enforces this separately for each host/address after name resolution.
It is not a DNS, statement, transaction, or total-operation deadline. Two seconds
is the driver's minimum effective timeout, so replacing even an opaque service
profile's timeout cannot lengthen a shorter effective setting. Do not retry here:
admission, durable receipts and worker recovery own their respective retry rules.
"""
import psycopg
from .postgres_execution_scope import remaining_milliseconds
from .postgres_pilot_write_gate import evaluate_write_gate

CONNECT_ATTEMPT_SECONDS = 2


def connect_postgres(conninfo="", **kwargs):
    """Keep native connection options and exception types; cap initial startup."""
    kwargs['connect_timeout'] = CONNECT_ATTEMPT_SECONDS
    remaining_milliseconds()
    db = psycopg.connect(conninfo, **kwargs)
    try:
        remaining = remaining_milliseconds()
        write_gate = evaluate_write_gate()
        if remaining is not None or not write_gate.writes_admitted:
            # Configure before the business transaction, preserving first-statement
            # SET TRANSACTION isolation and all native connection adapters/options.
            autocommit = db.autocommit
            db.autocommit = True
            if remaining is not None:
                db.execute('''SELECT set_config(s.name,
                    least(coalesce(nullif(s.setting::bigint,0),b.ms),b.ms)::text,false)
                    FROM pg_settings s JOIN (VALUES
                        ('statement_timeout',%s),('transaction_timeout',%s),
                        ('client_connection_check_interval',100)) AS b(name,ms)
                    ON s.name=b.name''', (remaining, remaining))
            if not write_gate.writes_admitted:
                db.execute("SELECT set_config('default_transaction_read_only',"
                           "'on',false)")
            db.autocommit = autocommit
        return db
    except BaseException:
        db.close()
        raise


def connection_policy():
    return {
        'attemptTimeoutSeconds': CONNECT_ATTEMPT_SECONDS,
        'scope': 'per host/address connection attempt after DNS resolution',
        'totalOperationDeadline': False,
        'automaticRetry': False,
        'serverOwned': True,
        'shorterEffectiveLimitsPreserved': True,
        'pilotWriteGate': {
            'optIn': 'EPM_PILOT_REQUIRE_WRITE_GATE=1',
            'failureMode': 'read-only PostgreSQL sessions',
            'enforcement': 'before first business transaction',
        },
    }
