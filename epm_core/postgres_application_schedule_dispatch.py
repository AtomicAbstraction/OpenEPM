"""Worker-only fair claims for generic schedules and their occurrences."""
from __future__ import annotations

from psycopg.rows import dict_row

from .postgres_access import assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


class PostgresApplicationScheduleDispatch:
    def __init__(self,dsn: str):
        assert_nonowner_role(dsn,"epm_worker",(
            "application_schedule_state","application_schedule_occurrence"))
        self.dsn=dsn

    def recover(self) -> dict:
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_lock_wait(db)
            row=db.execute(
                "SELECT * FROM epm.application_schedule_dispatch_recover()"
                ).fetchone()
            return {"scheduleClaims":row["schedule_claims"],
                    "occurrenceClaims":row["occurrence_claims"]}

    @staticmethod
    def _claim_arguments(claimant,lease_seconds,capacity_limits,code):
        if (type(claimant) is not str or not 1<=len(claimant)<=200
                or type(lease_seconds) is not int or not 30<=lease_seconds<=300
                or type(capacity_limits) is not tuple
                or len(capacity_limits)!=3
                or any(type(value) is not int or not 1<=value<=10_000
                       for value in capacity_limits)
                or not (capacity_limits[0]>=capacity_limits[1]
                        >=capacity_limits[2])):
            raise ValueError(code)
        return (claimant,lease_seconds,*capacity_limits)

    def _claim(self,function,claimant,lease_seconds,capacity_limits,code):
        arguments=self._claim_arguments(claimant,lease_seconds,
                                        capacity_limits,code)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            row=db.execute(f'''SELECT * FROM epm.{function}(
                %s,%s::integer,%s::integer,%s::integer,%s::integer)''',
                arguments).fetchone()
            return None if row is None else {**dict(row),"claimant":claimant}

    def claim_schedule(self,claimant: str,*,lease_seconds: int=65,
                       capacity_limits: tuple[int,int,int]=(32,8,2)):
        return self._claim("application_schedule_worker_claim",claimant,
            lease_seconds,capacity_limits,
            "APPLICATION_SCHEDULE_WORKER_CLAIM_INVALID")

    def claim_occurrence(self,claimant: str,*,lease_seconds: int=65,
                         capacity_limits: tuple[int,int,int]=(32,8,2)):
        return self._claim("application_schedule_occurrence_worker_claim",
            claimant,lease_seconds,capacity_limits,
            "APPLICATION_SCHEDULE_OCCURRENCE_CLAIM_INVALID")

    @staticmethod
    def _validate(claim,key,code):
        required={"workspace_id","application_id",key,"claimant"}
        generation=("dispatch_generation" if key=="schedule_id"
                    else "claim_generation")
        if type(claim) is not dict or not required|{generation}<=set(claim):
            raise ValueError(code)
        return generation

    def _control(self,function,claim,key,code,extra=()):
        generation=self._validate(claim,key,code)
        values=(claim["workspace_id"],claim["application_id"],claim[key],
                claim[generation],claim["claimant"],*extra)
        placeholders=",".join(["%s"]*len(values))
        with connect_postgres(self.dsn) as db:
          with db.transaction():
            configure_lock_wait(db)
            return db.execute(f"SELECT epm.{function}({placeholders})",
                              values).fetchone()[0]

    def renew_schedule(self,claim,*,lease_seconds=65):
        if type(lease_seconds) is not int or not 30<=lease_seconds<=300:
            raise ValueError("APPLICATION_SCHEDULE_WORKER_RENEW_INVALID")
        return self._control("application_schedule_worker_renew",claim,
            "schedule_id","APPLICATION_SCHEDULE_WORKER_RENEW_INVALID",
            (lease_seconds,))

    def release_schedule(self,claim):
        return self._control("application_schedule_worker_release",claim,
            "schedule_id","APPLICATION_SCHEDULE_WORKER_RELEASE_INVALID")

    def block_schedule(self,claim,error_code):
        if error_code not in ("APPLICATION_SCHEDULE_AUTHORITY_INVALID",
                              "APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED",
                              "APPLICATION_SCHEDULE_DEFINITION_CORRUPT",
                              "TOKEN_ISSUE_TIME_UNAVAILABLE",
                              "TECHNICAL_AUTHORITY_INVALID"):
            raise ValueError("APPLICATION_SCHEDULE_WORKER_BLOCK_INVALID")
        return self._control("application_schedule_worker_block",claim,
            "schedule_id","APPLICATION_SCHEDULE_WORKER_BLOCK_INVALID",
            (error_code,))

    def settle_schedule_unexpected(self,claim):
        return self._control(
            "application_schedule_worker_settle_unexpected",claim,
            "schedule_id","APPLICATION_SCHEDULE_WORKER_SETTLEMENT_INVALID",
            ("APPLICATION_SCHEDULE_WORKER_FAILED",))

    def renew_occurrence(self,claim,*,lease_seconds=65):
        if type(lease_seconds) is not int or not 30<=lease_seconds<=300:
            raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_RENEW_INVALID")
        return self._control(
            "application_schedule_occurrence_worker_renew",claim,
            "occurrence_id","APPLICATION_SCHEDULE_OCCURRENCE_RENEW_INVALID",
            (lease_seconds,))

    def release_occurrence(self,claim):
        return self._control(
            "application_schedule_occurrence_worker_release",claim,
            "occurrence_id","APPLICATION_SCHEDULE_OCCURRENCE_RELEASE_INVALID")

    def settle_occurrence_unexpected(self,claim):
        return self._control(
            "application_schedule_occurrence_worker_settle_unexpected",claim,
            "occurrence_id",
            "APPLICATION_SCHEDULE_OCCURRENCE_SETTLEMENT_INVALID",
            ("APPLICATION_SCHEDULE_WORKER_FAILED",))
