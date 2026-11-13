"""Server-owned progression of generic application schedule occurrences."""
from __future__ import annotations

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_schedule import execution_bindings,validate_definition
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied
from .postgres_application_rule_workflow import PostgresApplicationRuleRun
from .postgres_application_schedule_dispatch import (
    PostgresApplicationScheduleDispatch)
from .postgres_application_schedules import PostgresApplicationSchedules
from .postgres_connection import connect_postgres
from .postgres_language_v2 import PostgresLanguageV2
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


class PostgresApplicationScheduleWorker:
    def __init__(self,*,worker_dsn: str,runtime_dsn: str,
                 preview_secret: bytes,worker_id: str,
                 capacity_limits: tuple[int,int,int]=(32,8,2)):
        if (not all(type(value) is str and value for value in
                    (worker_dsn,runtime_dsn,worker_id))
                or type(preview_secret) is not bytes or len(preview_secret)<32
                or type(capacity_limits) is not tuple or len(capacity_limits)!=3
                or any(type(value) is not int or not 1<=value<=10_000
                       for value in capacity_limits)
                or not capacity_limits[0]>=capacity_limits[1]>=
                       capacity_limits[2]):
            raise ValueError("APPLICATION_SCHEDULE_WORKER_CONFIGURATION_INVALID")
        self.worker_dsn=worker_dsn;self.runtime_dsn=runtime_dsn
        self.preview_secret=preview_secret;self.worker_id=worker_id
        self.capacity_limits=capacity_limits
        self.dispatch=PostgresApplicationScheduleDispatch(worker_dsn)

    @staticmethod
    def _scope(db,scope):
        configure_statement_timeout(db,5000);configure_lock_wait(db)
        PostgresNumericFactStore._set_scope(db,scope)

    def _schedule_principal(self,scope,schedule_id):
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            row=db.execute('''SELECT execution_issuer,execution_subject,
                    execution_groups,authorization_scope_digest,
                    execution_token_issued_at,execution_authority_kind
                FROM epm.application_schedule_definition
                WHERE workspace_id=%s AND application_id=%s
                  AND schedule_id=%s AND status='Active' ''',(scope.workspace_id,
                scope.application_id,schedule_id)).fetchone()
            if row is None:raise ValueError("APPLICATION_SCHEDULE_INACTIVE")
            return PostgresApplicationSchedules._execution_identity(row)

    def materialize_once(self):
        claim=self.dispatch.claim_schedule(self.worker_id,
            capacity_limits=self.capacity_limits)
        if claim is None:return None
        scope=ApplicationScope(claim["workspace_id"],claim["application_id"])
        settled=False
        try:
            identity=self._schedule_principal(scope,claim["schedule_id"])
            result=PostgresApplicationSchedules(self.runtime_dsn,
                identity=identity).materialize_due(scope,claim["schedule_id"],
                                                   dispatch_claim=claim)
            if result["status"]=="Blocked":
                settled=self.dispatch.block_schedule(
                    claim,result["reasonCode"])
            return result
        except ValueError as error:
            if str(error) in ("APPLICATION_SCHEDULE_DEFINITION_CORRUPT",
                              "TOKEN_ISSUE_TIME_UNAVAILABLE",
                              "TECHNICAL_AUTHORITY_INVALID"):
                settled=self.dispatch.block_schedule(claim,str(error))
                return {"scheduleId":claim["schedule_id"],"status":"Blocked",
                        "reasonCode":str(error),"occurrences":[]}
            outcome=self.dispatch.settle_schedule_unexpected(claim)
            settled=outcome is not None
            if not settled:raise ValueError("APPLICATION_SCHEDULE_STALE_DISPATCH_CLAIM")
            return {"scheduleId":claim["schedule_id"],
                    "status":"Blocked" if outcome=="blocked" else "Retry",
                    "reasonCode":"APPLICATION_SCHEDULE_WORKER_RETRY_LIMIT"
                      if outcome=="blocked" else
                      "APPLICATION_SCHEDULE_WORKER_FAILED",
                    "occurrences":[]}
        except Exception:
            outcome=self.dispatch.settle_schedule_unexpected(claim)
            settled=outcome is not None
            if not settled:raise ValueError("APPLICATION_SCHEDULE_STALE_DISPATCH_CLAIM")
            return {"scheduleId":claim["schedule_id"],
                    "status":"Blocked" if outcome=="blocked" else "Retry",
                    "reasonCode":"APPLICATION_SCHEDULE_WORKER_RETRY_LIMIT"
                      if outcome=="blocked" else
                      "APPLICATION_SCHEDULE_WORKER_FAILED",
                    "occurrences":[]}
        finally:
            if not settled:self.dispatch.release_schedule(claim)

    def _occurrence_row(self,scope,occurrence_id,schema_epoch):
        with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            row=db.execute('''SELECT o.*,s.definition,s.definition_digest,
                s.execution_issuer,s.execution_subject,s.execution_groups,
                s.authorization_scope_digest,s.execution_token_issued_at,
                s.execution_authority_kind,s.delegation_id,
                s.delegation_state_token FROM epm.application_schedule_occurrence o
                JOIN epm.application_state incarnation ON
                  incarnation.workspace_id=o.workspace_id
                  AND incarnation.application_id=o.application_id
                JOIN epm.application_schedule_definition s ON
                  (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
                  (o.workspace_id,o.application_id,o.schedule_id,
                   o.schedule_state_token)
                WHERE o.workspace_id=%s AND o.application_id=%s
                  AND o.occurrence_id=%s AND incarnation.schema_epoch=%s
                  AND incarnation.processing_mode='Active' ''',(scope.workspace_id,
                scope.application_id,occurrence_id,schema_epoch)).fetchone()
            if row is None:
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
            return row

    def _update(self,scope,claim,*,status,workflow_id=None,error_code=None,
                result=None,next_poll=False):
        with connect_postgres(self.runtime_dsn) as db:
          with db.transaction():
            self._scope(db,scope)
            changed=db.execute('''UPDATE epm.application_schedule_occurrence
                SET status=%s,
                    application_rule_workflow_id=COALESCE(
                      %s,application_rule_workflow_id),
                    error_code=%s,result=%s,
                    inspection_origin_status=NULL,
                    next_attempt_at=CASE WHEN %s THEN
                      clock_timestamp()+interval '5 seconds' ELSE NULL END,
                    claimant=NULL,lease_until=NULL,
                    updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s AND claim_generation=%s
                  AND claimant=%s AND lease_until>clock_timestamp()
                  AND EXISTS(SELECT 1 FROM epm.application_state incarnation
                    WHERE incarnation.workspace_id=%s AND incarnation.application_id=%s
                     AND incarnation.schema_epoch=%s AND incarnation.processing_mode='Active')''',(
                status,workflow_id,error_code,Jsonb(result or {}),next_poll,
                scope.workspace_id,scope.application_id,claim["occurrence_id"],
                claim["claim_generation"],claim["claimant"],scope.workspace_id,
                scope.application_id,claim["schema_epoch"])).rowcount
            if changed!=1:
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_STALE_CLAIM")
        return {"occurrenceId":claim["occurrence_id"],"status":status,
                **({} if workflow_id is None else {"workflowId":workflow_id}),
                **({} if error_code is None else {"errorCode":error_code})}

    @staticmethod
    def _mapped_status(workflow_status):
        return {"accepted":"submitted","running":"submitted",
            "cancel_requested":"cancel_requested","published":"published",
            "partially_published":"partially_published","failed":"failed",
            "cancelled":"cancelled","needs_inspection":"needs_inspection"
            }.get(workflow_status)

    def advance_once(self):
        claim=self.dispatch.claim_occurrence(self.worker_id,
            capacity_limits=self.capacity_limits)
        if claim is None:return None
        scope=ApplicationScope(claim["workspace_id"],claim["application_id"])
        fence=None
        try:
            # The occurrence's owning schedule is immutable.  Resolve that
            # stable identifier first, then acquire its admission fence and
            # re-read the full exact-current occurrence under the fence.
            with connect_postgres(self.runtime_dsn,row_factory=dict_row) as lookup:
              with lookup.transaction():
                self._scope(lookup,scope)
                owner=lookup.execute('''SELECT schedule_id FROM
                    epm.application_schedule_occurrence WHERE workspace_id=%s
                    AND application_id=%s AND occurrence_id=%s''',(
                    scope.workspace_id,scope.application_id,
                    claim["occurrence_id"])).fetchone()
            if owner is None:
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
            schedule_id=owner["schedule_id"]
            # Hold the same schedule-scoped advisory fence used by Save,
            # Activate and Deactivate until the exact child workflow has been
            # admitted and linked.  This closes the read→admit race without
            # sharing a database transaction across service boundaries.
            fence=connect_postgres(self.runtime_dsn,autocommit=True)
            configure_statement_timeout(fence,5000);configure_lock_wait(fence)
            fence.execute('''SELECT pg_advisory_lock(hashtextextended(
                'epm.application.schedule:'||%s||':'||%s||':'||%s,0))''',(
                scope.workspace_id,scope.application_id,schedule_id))
            row=self._occurrence_row(scope,claim["occurrence_id"],claim["schema_epoch"])
            identity=PostgresApplicationSchedules._execution_identity(row)
            language=PostgresLanguageV2(self.runtime_dsn,identity=identity,
                                        preview_secret=self.preview_secret)
            service=PostgresApplicationRuleRun(
                self.runtime_dsn,identity=identity,language=language)
            if row["status"]=="cancel_requested":
                if row["application_rule_workflow_id"] is not None:
                    service.advance_existing(
                        scope,row["application_rule_workflow_id"])
                workflow=PostgresApplicationSchedules(
                    self.runtime_dsn,identity=identity
                ).reconcile_cancel_requested(scope,claim["occurrence_id"])
            elif row["application_rule_workflow_id"] is None:
                definition=validate_definition(row["definition"])
                target=definition["target"]
                workflow=service.run(scope,target["ruleId"],
                    bindings=execution_bindings(definition),
                    expected_state_token=target["stateToken"],
                    expected_program_digest=target["programDigest"],
                    idempotency_key="schedule-rule-"+claim["occurrence_id"])
            else:
                workflow=service.advance_existing(
                    scope,row["application_rule_workflow_id"])
            mapped=self._mapped_status(workflow["status"])
            if mapped is None:
                raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_STATUS_INVALID")
            return self._update(scope,claim,status=mapped,
                workflow_id=workflow["workflowId"],result=workflow,
                next_poll=mapped in ("submitted","cancel_requested"))
        except AccessDenied:
            return self._update(scope,claim,status="failed",
                error_code="APPLICATION_SCHEDULE_AUTHORIZATION_REVOKED")
        except ValueError as error:
            if str(error) in ("TOKEN_ISSUE_TIME_UNAVAILABLE",
                              "TECHNICAL_AUTHORITY_INVALID"):
                return self._update(scope,claim,status="needs_inspection",
                    error_code=str(error))
            if str(error) in ("APPLICATION_RULE_NOT_ACTIVE",
                    "APPLICATION_RULE_EXPECTED_STATE_MISMATCH",
                    "APPLICATION_RULE_STALE_DURING_SEAL",
                    "APPLICATION_RULE_METADATA_STALE",
                    "APPLICATION_RULE_WORKFLOW_PUBLICATION_STALE",
                    "APPLICATION_RULE_WORKFLOW_CONTEXT_STALE"):
                return self._update(scope,claim,status="failed",
                    error_code="APPLICATION_SCHEDULE_TARGET_STALE")
            return self._settle_occurrence_unexpected(claim)
        except Exception:
            return self._settle_occurrence_unexpected(claim)
        finally:
            if fence is not None:
                try:
                    fence.execute('''SELECT pg_advisory_unlock(hashtextextended(
                        'epm.application.schedule:'||%s||':'||%s||':'||%s,0))''',(
                        scope.workspace_id,scope.application_id,schedule_id))
                finally:
                    fence.close()

    def _settle_occurrence_unexpected(self,claim):
        outcome=self.dispatch.settle_occurrence_unexpected(claim)
        if outcome is None:
            raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_STALE_CLAIM")
        return {"occurrenceId":claim["occurrence_id"],
                "status":"needs_inspection" if outcome=="needs_inspection"
                         else "retry",
                "errorCode":"APPLICATION_SCHEDULE_WORKER_FAILED"}
