"""Worker-only fair claims for durable sealed-plan workflow advancement."""
from psycopg.rows import dict_row

from .postgres_access import assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


class PostgresPythonWorkflowDispatch:
    def __init__(self,dsn: str):
        assert_nonowner_role(dsn,'epm_worker',('python_program_workflow',))
        self.dsn=dsn

    def recover(self) -> int:
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute('SELECT epm.python_workflow_worker_recover()').fetchone()[0]

    def claim(self,claimant: str,*,lease_seconds: int=65,
              capacity_limits: tuple[int,int,int]=(32,8,2)) -> dict | None:
        if (type(claimant) is not str or not 1<=len(claimant)<=200
                or type(lease_seconds) is not int or not 30<=lease_seconds<=300
                or type(capacity_limits) is not tuple or len(capacity_limits)!=3
                or any(type(v) is not int or not 1<=v<=10000 for v in capacity_limits)
                or not capacity_limits[0]>=capacity_limits[1]>=capacity_limits[2]):
            raise ValueError('PYTHON_WORKFLOW_WORKER_CLAIM_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000);configure_lock_wait(db)
                row=db.execute('''SELECT * FROM epm.python_workflow_worker_claim(
                    %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                    (claimant,lease_seconds,
                    *capacity_limits)).fetchone()
                if row is None:return None
                authority=db.execute('''SELECT * FROM
                    epm.python_workflow_worker_authority(%s,%s,%s,%s,%s)''',(
                    row['workspace_id'],row['application_id'],row['workflow_id'],
                    row['claim_generation'],claimant)).fetchone()
                if authority is None:
                    raise ValueError('PYTHON_WORKFLOW_WORKER_AUTHORITY_UNPROVEN')
                epoch=db.execute('''SELECT * FROM
                    epm.python_workflow_worker_session_authority(
                    %s,%s,%s,%s,%s)''',(
                    row['workspace_id'],row['application_id'],
                    row['workflow_id'],row['claim_generation'],
                    claimant)).fetchone()
                if epoch is None:
                    raise ValueError('PYTHON_WORKFLOW_WORKER_AUTHORITY_UNPROVEN')
                return {**dict(row),**dict(authority),**dict(epoch)}

    def release(self,claim: dict) -> bool:
        required={'workspace_id','application_id','workflow_id',
                  'claim_generation','claimant'}
        if type(claim) is not dict or not required<=set(claim):
            raise ValueError('PYTHON_WORKFLOW_WORKER_RELEASE_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute('''SELECT epm.python_workflow_worker_release(
                    %s,%s,%s,%s,%s)''',(claim['workspace_id'],
                    claim['application_id'],claim['workflow_id'],
                    claim['claim_generation'],claim['claimant'])).fetchone()[0]

    def renew(self,claim: dict,*,lease_seconds: int=65) -> bool:
        required={'workspace_id','application_id','workflow_id',
                  'claim_generation','claimant'}
        if (type(claim) is not dict or not required<=set(claim)
                or type(lease_seconds) is not int or not 30<=lease_seconds<=300):
            raise ValueError('PYTHON_WORKFLOW_WORKER_RENEW_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_statement_timeout(db,5000);configure_lock_wait(db)
                return db.execute('''SELECT epm.python_workflow_worker_renew(
                    %s,%s,%s,%s,%s,%s::integer)''',(claim['workspace_id'],
                    claim['application_id'],claim['workflow_id'],
                    claim['claim_generation'],claim['claimant'],
                    lease_seconds)).fetchone()[0]

    def settle_unexpected(self,claim: dict,error_code: str) -> str | None:
        required={'workspace_id','application_id','workflow_id',
                  'claim_generation','claimant'}
        if (type(claim) is not dict or not required<=set(claim)
                or type(error_code) is not str
                or not 1<=len(error_code)<=200):
            raise ValueError('PYTHON_WORKFLOW_WORKER_SETTLEMENT_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                row=db.execute('''SELECT epm.python_workflow_worker_unexpected(
                    %s,%s,%s,%s,%s,%s)''',(claim['workspace_id'],
                    claim['application_id'],claim['workflow_id'],
                    claim['claim_generation'],claim['claimant'],
                    error_code)).fetchone()
                return None if row is None else row[0]

    def settle_failed(self,claim: dict,error_code: str) -> bool:
        required={'workspace_id','application_id','workflow_id',
                  'claim_generation','claimant'}
        if (type(claim) is not dict or not required<=set(claim)
                or error_code not in ('PYTHON_WORKFLOW_AUTHORIZATION_REVOKED',
                                      'PYTHON_WORKFLOW_STALE_CONTEXT')):
            raise ValueError('PYTHON_WORKFLOW_WORKER_SETTLEMENT_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute('''SELECT epm.python_workflow_worker_settle(
                    %s,%s,%s,%s,%s,%s)''',(claim['workspace_id'],
                    claim['application_id'],claim['workflow_id'],
                    claim['claim_generation'],claim['claimant'],
                    error_code)).fetchone()[0]
