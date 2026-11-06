"""Worker-only global dispatcher for the aggregate technical queue."""
from psycopg.rows import dict_row

from .postgres_access import assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout


class PostgresCubeAggregateDispatch:
    def __init__(self, dsn: str):
        assert_nonowner_role(dsn, 'epm_worker', ('cube_aggregate_query',))
        self.dsn = dsn

    def recover(self) -> int:
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute(
                    'SELECT epm.cube_aggregate_worker_recover()').fetchone()[0]

    def claim(self, claimant: str, *, lease_seconds: int = 30,
              capacity_limits: tuple[int, int, int] = (32, 8, 2)) -> dict | None:
        if (type(claimant) is not str or not 1 <= len(claimant) <= 200
                or type(lease_seconds) is not int or not 5 <= lease_seconds <= 300
                or type(capacity_limits) is not tuple or len(capacity_limits) != 3
                or any(type(value) is not int or not 1 <= value <= 10000
                       for value in capacity_limits)
                or not capacity_limits[0] >= capacity_limits[1] >= capacity_limits[2]):
            raise ValueError('CUBE_AGGREGATE_WORKER_CLAIM_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                row = db.execute('''SELECT * FROM epm.cube_aggregate_worker_claim(
                    %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                    (claimant, lease_seconds, *capacity_limits)).fetchone()
                if row is None:
                    return None
                authority = db.execute('''SELECT * FROM
                    epm.cube_aggregate_worker_authority(%s,%s,%s,%s,%s)''',
                    (row['workspace_id'],row['application_id'],row['query_id'],
                     row['claim_generation'],claimant)).fetchone()
                if authority is None:
                    raise ValueError('CUBE_AGGREGATE_WORKER_AUTHORITY_UNPROVEN')
                epoch=db.execute('''SELECT * FROM
                    epm.cube_aggregate_worker_session_authority(
                    %s,%s,%s,%s,%s)''',(
                    row['workspace_id'],row['application_id'],
                    row['query_id'],row['claim_generation'],
                    claimant)).fetchone()
                if epoch is None:
                    raise ValueError('CUBE_AGGREGATE_WORKER_AUTHORITY_UNPROVEN')
                return {**dict(row),**dict(authority),**dict(epoch)}

    def settle_failed(self, claim: dict, error_code: str) -> bool:
        required = {'workspace_id', 'application_id', 'query_id',
                    'claim_generation', 'claimant'}
        if (type(claim) is not dict or not required <= set(claim)
                or error_code not in ('CUBE_AGGREGATE_AUTHORIZATION_REVOKED',
                                      'CUBE_AGGREGATE_COMPUTE_FAILED')):
            raise ValueError('CUBE_AGGREGATE_WORKER_SETTLEMENT_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute('''SELECT epm.cube_aggregate_worker_settle(
                    %s,%s,%s,%s,%s,%s)''',
                    (claim['workspace_id'], claim['application_id'],
                     claim['query_id'], claim['claim_generation'],
                     claim['claimant'], error_code)).fetchone()[0]

    def reconcile_unexpected(self, claim: dict) -> dict:
        """Resolve an uncertain worker outcome before any retry is admitted."""
        required = {'workspace_id', 'application_id', 'query_id',
                    'claim_generation', 'claimant'}
        if type(claim) is not dict or not required <= set(claim):
            raise ValueError('CUBE_AGGREGATE_WORKER_UNEXPECTED_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                row = db.execute('''SELECT * FROM
                    epm.cube_aggregate_worker_unexpected(%s,%s,%s,%s,%s)''',
                    (claim['workspace_id'], claim['application_id'],
                     claim['query_id'], claim['claim_generation'],
                     claim['claimant'])).fetchone()
                if row is None or row['outcome'] not in {
                        'ready','computed','sealed','cancelled','failed',
                        'expired','stale'}:
                    raise ValueError(
                        'CUBE_AGGREGATE_WORKER_UNEXPECTED_INVALID')
                return {'status':row['outcome'],
                        'errorCode':row['error_code']}

    def expire(self, *, limit: int = 100,
               payload_retention_seconds: int = 900) -> dict:
        if (type(limit) is not int or not 1 <= limit <= 1000
                or type(payload_retention_seconds) is not int
                or not 60 <= payload_retention_seconds <= 604800):
            raise ValueError('CUBE_AGGREGATE_EXPIRY_POLICY_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                row = db.execute('''SELECT * FROM
                    epm.cube_aggregate_worker_expire(%s,%s)''',
                    (limit, payload_retention_seconds)).fetchone()
                return {'expiredCount': row['expired_count'],
                        'payloadQueryCount': row['payload_query_count']}
