"""Worker-only global dispatch for durable snapshot export production."""
from __future__ import annotations

from psycopg.rows import dict_row

from .postgres_access import assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


class PostgresTransferExportDispatch:
    def __init__(self,dsn: str):
        assert_nonowner_role(dsn,'epm_worker',
                             ('fact_export_producer_request',))
        self.dsn=dsn

    def claim(self,claimant: str,*,lease_seconds: int=120,
              capacity_limits: tuple[int,int,int]=(32,8,2))->dict|None:
        if (type(claimant) is not str or not 1<=len(claimant)<=200
                or type(lease_seconds) is not int
                or not 30<=lease_seconds<=300
                or type(capacity_limits) is not tuple
                or len(capacity_limits)!=3
                or any(type(value) is not int or not 1<=value<=10000
                       for value in capacity_limits)
                or not capacity_limits[0]>=capacity_limits[1]>=capacity_limits[2]):
            raise ValueError('EXPORT_PRODUCER_WORKER_CLAIM_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            row=db.execute('''SELECT * FROM epm.export_producer_worker_claim(
                %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                (claimant,lease_seconds,*capacity_limits)).fetchone()
            if row is None:return None
            epoch=db.execute('''SELECT * FROM
                epm.export_producer_worker_session_authority(
                %s,%s,%s,%s,%s)''',(
                row['workspace_id'],row['application_id'],
                row['request_id'],row['claim_generation'],
                claimant)).fetchone()
            if epoch is None:
                raise ValueError('EXPORT_PRODUCER_WORKER_AUTHORITY_UNPROVEN')
            return {**dict(row),**dict(epoch)}

    def settle_failed(self,claim: dict,error_code: str)->bool:
        required={'workspace_id','application_id','request_id',
                  'claim_generation','claimant'}
        if (type(claim) is not dict or not required<=set(claim)
                or type(error_code) is not str
                or not error_code.isascii() or not error_code.replace('_','').isalnum()
                or error_code.upper()!=error_code or not 3<=len(error_code)<=128):
            raise ValueError('EXPORT_PRODUCER_WORKER_SETTLEMENT_INVALID')
        with connect_postgres(self.dsn) as db,db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            return db.execute('''SELECT epm.export_producer_worker_settle_failed(
                %s,%s,%s,%s,%s,%s)''',(claim['workspace_id'],
                claim['application_id'],claim['request_id'],
                claim['claim_generation'],claim['claimant'],
                error_code)).fetchone()[0]
