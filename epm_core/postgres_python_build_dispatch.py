"""Worker-only global dispatcher for isolated Python plan builds."""
from psycopg.rows import dict_row

from .postgres_access import assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout


_ERRORS = frozenset((
    'PYTHON_BUILD_AUTHORIZATION_REVOKED',
    'PYTHON_BUILD_CAPABILITY_UNAVAILABLE',
    'PYTHON_SANDBOX_RUNTIME_UNAVAILABLE',
    'PYTHON_BUILD_WORKER_FAILED'))


class PostgresPythonBuildDispatch:
    def __init__(self, dsn: str):
        assert_nonowner_role(dsn, 'epm_worker', ('python_program_build',))
        self.dsn = dsn

    def recover(self) -> int:
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                recovered = db.execute(
                    'SELECT epm.python_build_worker_recover()').fetchone()[0]
                expired = db.execute(
                    'SELECT epm.python_impact_expire()').fetchone()[0]
                return recovered + expired

    def claim(self, claimant: str, *, lease_seconds: int = 90,
              capacity_limits: tuple[int, int, int] = (10, 5, 2)) -> dict | None:
        if (type(claimant) is not str or not 1 <= len(claimant) <= 200
                or type(lease_seconds) is not int or not 65 <= lease_seconds <= 300
                or type(capacity_limits) is not tuple or len(capacity_limits) != 3
                or any(type(value) is not int or not 1 <= value <= 10000
                       for value in capacity_limits)
                or not capacity_limits[0] >= capacity_limits[1] >= capacity_limits[2]):
            raise ValueError('PYTHON_BUILD_WORKER_CLAIM_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                row = db.execute('''SELECT * FROM epm.python_build_worker_claim(
                    %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                    (claimant, lease_seconds, *capacity_limits)).fetchone()
                return None if row is None else dict(row)

    def settle_failed(self, claim: dict, error_code: str) -> bool:
        required = {'workspace_id', 'application_id', 'build_id',
                    'claim_generation', 'claimant'}
        if (type(claim) is not dict or not required <= set(claim)
                or error_code not in _ERRORS):
            raise ValueError('PYTHON_BUILD_WORKER_SETTLEMENT_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute('''SELECT epm.python_build_worker_settle(
                    %s,%s,%s,%s,%s,%s)''',
                    (claim['workspace_id'], claim['application_id'],
                     claim['build_id'], claim['claim_generation'],
                     claim['claimant'], error_code)).fetchone()[0]
