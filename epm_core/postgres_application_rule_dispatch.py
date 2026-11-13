"""Worker-only fair claims for durable generic application-rule workflows."""
from psycopg.rows import dict_row

from .postgres_access import assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


class PostgresApplicationRuleDispatch:
    def __init__(self,dsn: str):
        assert_nonowner_role(dsn,'epm_worker',('application_rule_workflow',))
        self.dsn=dsn

    def recover(self) -> int:
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute(
                    'SELECT epm.application_rule_worker_recover()').fetchone()[0]

    def claim(self,claimant: str,*,lease_seconds: int=65,
              capacity_limits: tuple[int,int,int]=(32,8,2)) -> dict | None:
        if (type(claimant) is not str or not 1<=len(claimant)<=200
                or type(lease_seconds) is not int or not 30<=lease_seconds<=300
                or type(capacity_limits) is not tuple or len(capacity_limits)!=3
                or any(type(v) is not int or not 1<=v<=10000
                       for v in capacity_limits)
                or not capacity_limits[0]>=capacity_limits[1]>=capacity_limits[2]):
            raise ValueError('APPLICATION_RULE_WORKER_CLAIM_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000);configure_lock_wait(db)
                row=db.execute('''SELECT * FROM epm.application_rule_worker_claim(
                    %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                    (claimant,lease_seconds,*capacity_limits)).fetchone()
                if row is None:return None
                authority=db.execute('''SELECT * FROM
                    epm.application_rule_worker_authority(%s,%s,%s,%s,%s)''',(
                    row['workspace_id'],row['application_id'],row['workflow_id'],
                    row['claim_generation'],claimant)).fetchone()
                if authority is None:
                    raise ValueError('APPLICATION_RULE_WORKER_AUTHORITY_UNPROVEN')
                epoch=db.execute('''SELECT * FROM
                    epm.application_rule_worker_session_authority(
                    %s,%s,%s,%s,%s)''',(
                    row['workspace_id'],row['application_id'],
                    row['workflow_id'],row['claim_generation'],
                    claimant)).fetchone()
                if epoch is None:
                    raise ValueError('APPLICATION_RULE_WORKER_AUTHORITY_UNPROVEN')
                return {**dict(row),**dict(authority),**dict(epoch)}

    @staticmethod
    def _validate(claim,code):
        required={'workspace_id','application_id','workflow_id',
                  'claim_generation','claimant'}
        if type(claim) is not dict or not required<=set(claim):
            raise ValueError(code)

    def release(self,claim: dict) -> bool:
        self._validate(claim,'APPLICATION_RULE_WORKER_RELEASE_INVALID')
        return self._control('application_rule_worker_release',claim)

    def renew(self,claim: dict,*,lease_seconds: int=65) -> bool:
        self._validate(claim,'APPLICATION_RULE_WORKER_RENEW_INVALID')
        if type(lease_seconds) is not int or not 30<=lease_seconds<=300:
            raise ValueError('APPLICATION_RULE_WORKER_RENEW_INVALID')
        return self._control('application_rule_worker_renew',claim,lease_seconds)

    def settle_failed(self,claim: dict,error_code: str) -> bool:
        self._validate(claim,'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID')
        if error_code not in ('APPLICATION_RULE_AUTHORIZATION_REVOKED',
                              'APPLICATION_RULE_STALE_CONTEXT'):
            raise ValueError('APPLICATION_RULE_WORKER_SETTLEMENT_INVALID')
        return self._control('application_rule_worker_settle',claim,error_code)

    def settle_unexpected(self,claim: dict,error_code: str) -> str | None:
        self._validate(claim,'APPLICATION_RULE_WORKER_SETTLEMENT_INVALID')
        if type(error_code) is not str or not 1<=len(error_code)<=200:
            raise ValueError('APPLICATION_RULE_WORKER_SETTLEMENT_INVALID')
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                row=db.execute('''SELECT epm.application_rule_worker_unexpected(
                    %s,%s,%s,%s,%s,%s)''',(claim['workspace_id'],
                    claim['application_id'],claim['workflow_id'],
                    claim['claim_generation'],claim['claimant'],
                    error_code)).fetchone()
                return None if row is None else row[0]

    def _control(self,function,claim,extra=None):
        arguments=(claim['workspace_id'],claim['application_id'],
            claim['workflow_id'],claim['claim_generation'],claim['claimant'])
        if extra is not None:arguments+= (extra,)
        placeholders=','.join(['%s']*len(arguments))
        with connect_postgres(self.dsn) as db:
            with db.transaction():
                configure_lock_wait(db)
                return db.execute(
                    f'SELECT epm.{function}({placeholders})',arguments).fetchone()[0]
