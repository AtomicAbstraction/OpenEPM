"""Durable generic schedules for exact published application rules.

The repository owns immutable schedule versions, their publication pointer and
server-time occurrence materialization.  It does not execute a rule; workers
consume the exact persisted occurrence and schedule contract in later layers.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_schedule import (canonical_digest,execution_bindings,
                                   validate_definition)
from .recurrence import CatchUpPolicy,due_from_interval
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
                              VerifiedExecutionIdentity,VerifiedIdentity,
                              assert_nonowner_role)
from .postgres_application_rules import PostgresApplicationRules
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import (configure_lock_wait,
                                         configure_statement_timeout)
from .python_program_execution import FunctionValidator


SAVE="schedule.version.save"
PUBLISH="schedule.version.publish"
DEACTIVATE="schedule.version.deactivate"
READ="schedule.version.read"
LIST="schedule.version.list"
FUNCTIONS=frozenset((SAVE,PUBLISH,DEACTIVATE,READ,LIST))
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_HEX32=re.compile(r"[0-9a-f]{32}\Z")


def _digest(value: object) -> str:
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":"),
                             ensure_ascii=True,allow_nan=False).encode("ascii")).hexdigest()


def catalog() -> dict:
    common={"requiredCapabilities":[],"previewRequired":False,
            "workClass":"short"}
    mutation={**common,"mode":"atomic_configuration","permission":"admin",
              "idempotencyRequired":True}
    read={**common,"mode":"read_only","permission":"read",
          "idempotencyRequired":False}
    revisions={"expectedMetadataRevision":"current metadata revision",
        "expectedPolicyRevision":"current policy revision",
        "expectedSchemaEpoch":"current schema epoch"}
    return {
        SAVE:{**mutation,"arguments":{"definition":
                "openepm-application-schedule-v1 definition",
                "expectedStateRevision":"current schedule state revision",
                **revisions},"result":"immutable exact schedule version"},
        PUBLISH:{**mutation,"arguments":{"scheduleId":"stable schedule ID",
                "version":"exact immutable version",
                "expectedStateRevision":"current schedule state revision",
                **revisions},"result":"active schedule pointer"},
        DEACTIVATE:{**mutation,"arguments":{"scheduleId":"stable schedule ID",
                "expectedStateRevision":"current schedule state revision",
                **revisions},"result":"inactive schedule pointer"},
        READ:{**read,"arguments":{"scheduleId":"stable schedule ID"},
             "optionalArguments":{"version":"exact immutable version"},
             "result":"schedule definition and publication state"},
        LIST:{**read,"arguments":{},"optionalArguments":{
                "limit":"1-100","afterScheduleId":"keyset cursor"},
             "result":"bounded schedule-definition page"}}


def _occurrence_id(scope: ApplicationScope,schedule_id: str,version: int,
                   due_at: datetime) -> str:
    """Return the stable identity of one exact scheduled due instant."""
    if (not isinstance(scope,ApplicationScope)
            or type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None
            or type(version) is not int or version<1
            or type(due_at) is not datetime or due_at.tzinfo is None
            or due_at.utcoffset()!=timezone.utc.utcoffset(due_at)):
        raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_INVALID")
    raw=json.dumps([scope.workspace_id,scope.application_id,schedule_id,version,
        due_at.astimezone(timezone.utc).isoformat()],separators=(",",":"),
        ensure_ascii=True).encode("ascii")
    return sha256(raw).hexdigest()[:32]


class PostgresApplicationSchedules:
    """Persist exact schedule definitions after fixed-core qualification."""

    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",(
            "application_schedule_version","application_schedule_state",
            "application_schedule_occurrence"))
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope: ApplicationScope) -> None:
        if not isinstance(scope,ApplicationScope):
            raise ValueError("APPLICATION_SCHEDULE_SCOPE_INVALID")
        configure_statement_timeout(db,5000);configure_lock_wait(db)
        PostgresNumericFactStore._set_scope(db,scope)

    @staticmethod
    def _arguments(program: object,function: str) -> dict:
        if (type(program) is not dict
                or set(program)!={"languageVersion","function","arguments"}
                or program.get("languageVersion")!=2
                or program.get("function")!=function
                or type(program.get("arguments")) is not dict):
            raise ValueError("APPLICATION_SCHEDULE_PROGRAM_INVALID")
        return program["arguments"]

    def execute(self,scope: ApplicationScope,program: object,*,
            idempotency_key: str | None=None,
            registry: FunctionValidator | None=None,
            compiler_version: str="application-rule-v1") -> dict:
        function=program.get("function") if type(program) is dict else None
        if function not in FUNCTIONS:
            raise ValueError("APPLICATION_SCHEDULE_FUNCTION_INVALID")
        arguments=self._arguments(program,function)
        revisions={"expectedMetadataRevision","expectedPolicyRevision",
                   "expectedSchemaEpoch"}
        if function==SAVE:
            if set(arguments)!={"definition","expectedStateRevision",*revisions}:
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            if registry is None:
                raise ValueError("APPLICATION_SCHEDULE_REGISTRY_REQUIRED")
            return self.save_version(scope,arguments["definition"],
                expected_state_revision=arguments["expectedStateRevision"],
                expected_metadata_revision=arguments["expectedMetadataRevision"],
                expected_policy_revision=arguments["expectedPolicyRevision"],
                expected_schema_epoch=arguments["expectedSchemaEpoch"],
                idempotency_key=idempotency_key,registry=registry,
                compiler_version=compiler_version)
        if function in (PUBLISH,DEACTIVATE):
            required={"scheduleId","expectedStateRevision",*revisions}
            if function==PUBLISH:required.add("version")
            if set(arguments)!=required:
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            return self.set_publication(scope,arguments["scheduleId"],
                version=(arguments["version"] if function==PUBLISH else None),
                expected_state_revision=arguments["expectedStateRevision"],
                expected_metadata_revision=arguments["expectedMetadataRevision"],
                expected_policy_revision=arguments["expectedPolicyRevision"],
                expected_schema_epoch=arguments["expectedSchemaEpoch"],
                idempotency_key=idempotency_key)
        if idempotency_key is not None:
            raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_UNEXPECTED")
        if function==READ:
            if (set(arguments)-{"scheduleId","version"}
                    or "scheduleId" not in arguments):
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            return self.read(scope,arguments["scheduleId"],
                             version=arguments.get("version"))
        if set(arguments)-{"limit","afterScheduleId"}:
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        return self.list(scope,limit=arguments.get("limit",100),
                         after_schedule_id=arguments.get("afterScheduleId"))

    @staticmethod
    def _revisions(value: dict,expected_metadata: int,
                   expected_policy: int,expected_schema: int) -> None:
        if (value is None
                or value["metadata_revision"]!=expected_metadata
                or value["policy_revision"]!=expected_policy
                or value["schema_epoch"]!=expected_schema):
            raise ValueError("APPLICATION_SCHEDULE_STALE_CONTEXT")

    @staticmethod
    def _execution_identity(row: dict) -> VerifiedExecutionIdentity:
        kind=row.get("execution_authority_kind")
        issued_at=row.get("execution_token_issued_at")
        issuer=row["execution_issuer"]
        if kind=="HumanToken":
            if type(issued_at) is not int or issued_at<=0:
                raise ValueError("TOKEN_ISSUE_TIME_UNAVAILABLE")
        elif kind=="Technical":
            if issued_at is not None or not issuer.startswith("urn:openepm:"):
                raise ValueError("TECHNICAL_AUTHORITY_INVALID")
        else:
            raise ValueError("TOKEN_ISSUE_TIME_UNAVAILABLE")
        return VerifiedExecutionIdentity(row["execution_issuer"],
            row["execution_subject"],tuple(row.get("execution_groups") or ()),
            issued_at=issued_at,
            authorization_scope_digest=row["authorization_scope_digest"])

    @staticmethod
    def _assert_authorization_scope(db,scope: ApplicationScope,row: dict,
            *,function: str) -> str:
        identity=PostgresApplicationSchedules._execution_identity(row)
        access=PostgresAccessChecker.check_in_transaction(
            db,identity,scope,"write")
        PostgresAccessChecker.check_in_transaction(
            db,identity,scope,"rule_run",function="application.rule.run")
        current=resolve_effective_dimensional_scope(
            db,identity,scope,access=access,function=function).scope_digest
        if (row.get("authorization_scope_digest") is None
                or row["authorization_scope_digest"]!=current):
            raise AccessDenied(
                "APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED")
        return current

    @staticmethod
    def _result(row: dict,pointer: dict | None) -> dict:
        active=(pointer is not None and pointer["active_version"]==row["version"])
        return {"scheduleId":row["schedule_id"],"version":row["version"],
            "definition":row["definition"],
            "definitionDigest":row["definition_digest"],
            "status":"Published" if active else "Saved",
            "stateRevision":0 if pointer is None else pointer["state_revision"],
            "createdRevision":row["created_revision"],
            "createdAt":row["created_at"].isoformat()}

    def request_cancel_as_task_controller(self,scope: ApplicationScope,
            occurrence_id: str,*,allow_application_admin: bool=False) -> dict:
        """Fence one occurrence and request cancellation of its child.

        The universal task service may expose current application-admin
        control, but ordinary callers remain limited to the exact delegated
        schedule principal.  Incrementing ``claim_generation`` makes an
        already-running wrapper worker stale before it can publish another
        wrapper transition.  A child workflow admitted just before that fence
        is recovered by its deterministic operation key by the next worker.
        """
        if (not isinstance(scope,ApplicationScope)
                or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None
                or type(allow_application_admin) is not bool):
            raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(
                db,scope.workspace_id)
            row=db.execute('''SELECT o.*,v.execution_issuer,v.execution_subject,
                v.rule_id,v.rule_version,v.publication_operation_id
                FROM epm.application_schedule_occurrence o
                JOIN epm.application_schedule_version v ON
                  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
                  (o.workspace_id,o.application_id,o.schedule_id,
                   o.schedule_version)
                WHERE o.workspace_id=%s AND o.application_id=%s
                  AND o.occurrence_id=%s FOR UPDATE OF o''',(
                scope.workspace_id,scope.application_id,
                occurrence_id)).fetchone()
            if row is None:
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
            owner=((row["execution_issuer"],row["execution_subject"])==
                   (self.identity.issuer,self.identity.subject_id))
            if owner:
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"write")
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"rule_run")
            elif allow_application_admin:
                try:
                    PostgresAccessChecker.check_in_transaction(
                        db,self.identity,scope,"admin")
                except AccessDenied as error:
                    raise ValueError(
                        "APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE") from error
            else:
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
            terminal=("published","partially_published","failed","cancelled",
                      "needs_inspection")
            if row["status"] in terminal or row["status"]=="cancel_requested":
                status=row["status"]
            else:
                status=("cancelled" if row["status"]=="ready"
                        else "cancel_requested")
                changed=db.execute('''UPDATE epm.application_schedule_occurrence
                    SET status=%s,claim_generation=claim_generation+1,
                        claimant=NULL,lease_until=NULL,next_attempt_at=NULL,
                        updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND occurrence_id=%s AND status=%s''',(status,
                    scope.workspace_id,scope.application_id,occurrence_id,
                    row["status"])).rowcount
                if changed!=1:
                    raise ValueError(
                        "APPLICATION_SCHEDULE_OCCURRENCE_STALE_CONTROL_STATE")
            child_id=row["application_rule_workflow_id"]
            if status=="cancel_requested":
                from .postgres_application_rule_workflow import workflow_id
                expected=workflow_id(scope,VerifiedIdentity(
                    row["execution_issuer"],row["execution_subject"]),
                    "schedule-rule-"+occurrence_id)
                child=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s
                      AND idempotency_key=%s AND issuer=%s AND subject_id=%s
                    FOR UPDATE''',(scope.workspace_id,scope.application_id,
                    "schedule-rule-"+occurrence_id,row["execution_issuer"],
                    row["execution_subject"])).fetchone()
                if child is not None and (
                        child["workflow_id"]!=expected
                        or child["rule_id"]!=row["rule_id"]
                        or child["rule_version"]!=row["rule_version"]
                        or child["publication_operation_id"]!=
                            row["publication_operation_id"]
                        or (child_id is not None
                            and child_id!=child["workflow_id"])):
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                if child_id is not None and child is None:
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                if child is not None:
                    child_id=child["workflow_id"]
                    if row["application_rule_workflow_id"] is None:
                        db.execute('''UPDATE epm.application_schedule_occurrence
                            SET application_rule_workflow_id=%s
                            WHERE workspace_id=%s AND application_id=%s
                              AND occurrence_id=%s''',(child_id,
                            scope.workspace_id,scope.application_id,
                            occurrence_id))
                    child_status=("cancelled" if child["status"]=="accepted"
                        else "cancel_requested" if child["status"]=="running"
                        else child["status"])
                    if child_status!=child["status"]:
                        db.execute('''UPDATE epm.application_rule_workflow SET
                            status=%s,updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                              AND workflow_id=%s AND status=%s''',(
                            child_status,scope.workspace_id,
                            scope.application_id,child_id,child["status"]))
                    checkpoints=child["result"].get("checkpoints",[])
                    pending=next((item for item in reversed(checkpoints)
                        if isinstance(item,dict)
                        and item.get("committed") is False),None)
                    if child_status=="cancel_requested" and pending is not None:
                        job=db.execute('''SELECT status FROM epm.job
                            WHERE workspace_id=%s AND application_id=%s
                              AND job_id=%s AND issuer=%s AND subject_id=%s
                            FOR UPDATE''',(scope.workspace_id,
                            scope.application_id,pending.get("jobId"),
                            row["execution_issuer"],
                            row["execution_subject"])).fetchone()
                        if job is None:
                            raise ValueError(
                                "APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                        job_status=("cancelled" if job["status"] in
                            ("accepted","ready") else "cancel_requested"
                            if job["status"] in ("running","staged")
                            else job["status"])
                        if job_status!=job["status"]:
                            db.execute('''UPDATE epm.job SET status=%s,
                                claim_generation=claim_generation+1,
                                claimant=NULL,lease_until=NULL,
                                updated_at=transaction_timestamp()
                                WHERE workspace_id=%s AND application_id=%s
                                  AND job_id=%s''',(job_status,
                                scope.workspace_id,scope.application_id,
                                pending["jobId"]))
            return {"occurrenceId":occurrence_id,"status":status,
                "workflowId":child_id}

    def reconcile_cancel_requested(self,scope: ApplicationScope,
            occurrence_id: str) -> dict:
        """Settle only the exact occurrence-owned cancelled child.

        This worker-only-style fixed-core boundary performs no admission or
        publication.  It exists so a durable cancellation remains effective
        after the delegated execution principal loses ordinary access.
        """
        if (not isinstance(scope,ApplicationScope)
                or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None):
            raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope)
            row=db.execute('''SELECT o.*,v.execution_issuer,v.execution_subject,
                v.rule_id,v.rule_version,v.publication_operation_id
                FROM epm.application_schedule_occurrence o
                JOIN epm.application_schedule_version v ON
                 (v.workspace_id,v.application_id,v.schedule_id,v.version)=
                 (o.workspace_id,o.application_id,o.schedule_id,
                  o.schedule_version)
                WHERE o.workspace_id=%s AND o.application_id=%s
                  AND o.occurrence_id=%s FOR UPDATE OF o''',(
                scope.workspace_id,scope.application_id,
                occurrence_id)).fetchone()
            if row is None or row["status"]!="cancel_requested":
                raise ValueError("APPLICATION_SCHEDULE_CANCEL_NOT_REQUESTED")
            from .postgres_application_rule_workflow import workflow_id
            expected=workflow_id(scope,VerifiedIdentity(
                row["execution_issuer"],row["execution_subject"]),
                "schedule-rule-"+occurrence_id)
            child=db.execute('''SELECT * FROM epm.application_rule_workflow
                WHERE workspace_id=%s AND application_id=%s
                  AND idempotency_key=%s AND issuer=%s AND subject_id=%s
                FOR UPDATE''',(scope.workspace_id,scope.application_id,
                "schedule-rule-"+occurrence_id,row["execution_issuer"],
                row["execution_subject"])).fetchone()
            if child is None:
                if row["application_rule_workflow_id"] is not None:
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                return {"occurrenceId":occurrence_id,"status":"cancelled",
                    "workflowId":None,"workflowStatus":"cancelled"}
            if (child["workflow_id"]!=expected
                    or row["application_rule_workflow_id"] not in (
                        None,child["workflow_id"])
                    or child["rule_id"]!=row["rule_id"]
                    or child["rule_version"]!=row["rule_version"]
                    or child["publication_operation_id"]!=
                        row["publication_operation_id"]):
                raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
            result=dict(child["result"]);checkpoints=result.get("checkpoints",[])
            pending=next((item for item in reversed(checkpoints)
                if isinstance(item,dict) and item.get("committed") is False),None)
            committed=sum(1 for item in checkpoints if isinstance(item,dict)
                          and item.get("committed") is True)
            child_status=child["status"]
            if child_status in ("published","partially_published","failed",
                                "cancelled"):
                settled=child_status
            elif child_status=="needs_inspection":
                raise ValueError("APPLICATION_SCHEDULE_CHILD_NEEDS_INSPECTION")
            elif pending is None:
                settled="partially_published" if committed else "cancelled"
            else:
                job=db.execute('''SELECT status,receipt_revision FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                      AND issuer=%s AND subject_id=%s''',(scope.workspace_id,
                    scope.application_id,pending.get("jobId"),
                    row["execution_issuer"],row["execution_subject"])).fetchone()
                if job is None:
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                if job["status"] in ("accepted","ready","running","staged",
                                     "cancel_requested"):
                    return {"occurrenceId":occurrence_id,
                        "status":"cancel_requested",
                        "workflowId":child["workflow_id"],
                        "workflowStatus":"cancel_requested"}
                if job["status"]=="published" and job["receipt_revision"] is not None:
                    for item in checkpoints:
                        if item is pending:
                            item["committed"]=True
                            item["receiptId"]=pending["jobId"]
                    result["checkpoints"]=checkpoints;committed+=1
                settled="partially_published" if committed else "cancelled"
            if child_status not in ("published","partially_published",
                                    "failed","cancelled"):
                db.execute('''UPDATE epm.application_rule_workflow SET
                    status=%s,result=%s,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                      AND workflow_id=%s''',(settled,Jsonb(result),
                    scope.workspace_id,scope.application_id,
                    child["workflow_id"]))
            return {"occurrenceId":occurrence_id,"status":settled,
                "workflowId":child["workflow_id"],"workflowStatus":settled}

    def reconcile_needs_inspection(self,scope: ApplicationScope,
            occurrence_id: str,*,idempotency_key: str,
            allow_application_admin: bool=False) -> dict:
        """Validate an uncertain occurrence and restore its exact intent.

        Reconciliation executes no rule and submits no child.  It validates
        the immutable schedule, the stored retry origin and any deterministic
        child before making ordinary worker processing claimable again.
        """
        if (not isinstance(scope,ApplicationScope)
                or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None
                or type(allow_application_admin) is not bool):
            raise ValueError("APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(
                db,scope.workspace_id)
            row=db.execute('''SELECT o.*,v.definition,v.definition_digest,
                v.execution_issuer,v.execution_subject,v.delegation_id,
                v.delegation_version FROM epm.application_schedule_occurrence o
                JOIN epm.application_schedule_version v ON
                  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
                  (o.workspace_id,o.application_id,o.schedule_id,
                   o.schedule_version)
                WHERE o.workspace_id=%s AND o.application_id=%s
                  AND o.occurrence_id=%s FOR UPDATE OF o''',(
                scope.workspace_id,scope.application_id,
                occurrence_id)).fetchone()
            if row is None:
                raise ValueError("APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE")
            owner=((row["execution_issuer"],row["execution_subject"])==
                   (self.identity.issuer,self.identity.subject_id))
            try:
                if owner:
                    PostgresAccessChecker.check_in_transaction(
                        db,self.identity,scope,"rule_run")
                elif allow_application_admin:
                    PostgresAccessChecker.check_in_transaction(
                        db,self.identity,scope,"admin")
                else:
                    raise AccessDenied("schedule occurrence owner required")
            except AccessDenied as error:
                raise ValueError(
                    "APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE") from error
            prior=row["result"].get("reconciliation")
            if (isinstance(prior,dict)
                    and prior.get("operationId")==idempotency_key):
                if prior.get("actor")!=[
                        self.identity.issuer,self.identity.subject_id]:
                    raise ValueError(
                        "APPLICATION_SCHEDULE_RECONCILE_IDEMPOTENCY_CONFLICT")
                return {"occurrenceId":occurrence_id,
                    "status":prior["resultStatus"],
                    "originStatus":prior["originStatus"],
                    "workflowId":prior.get("workflowId")}
            if (row["status"]!="needs_inspection"
                    or row["claimant"] is not None
                    or row["lease_until"] is not None
                    or row["inspection_origin_status"] not in (
                        "running","submitted","cancel_requested")):
                raise ValueError(
                    "APPLICATION_SCHEDULE_RECONCILE_NOT_AVAILABLE")
            definition=validate_definition(row["definition"])
            if (canonical_digest(definition)!=row["definition_digest"]
                    or definition["scheduleId"]!=row["schedule_id"]
                    or definition["version"]!=row["schedule_version"]):
                raise ValueError("APPLICATION_SCHEDULE_DEFINITION_CORRUPT")
            from .postgres_application_rule_workflow import workflow_id
            expected=workflow_id(scope,VerifiedIdentity(
                row["execution_issuer"],row["execution_subject"]),
                "schedule-rule-"+occurrence_id)
            child=db.execute('''SELECT workflow_id,status,issuer,subject_id,
                rule_id,rule_version,publication_operation_id,idempotency_key
                FROM epm.application_rule_workflow WHERE workspace_id=%s
                  AND application_id=%s AND idempotency_key=%s
                  AND issuer=%s AND subject_id=%s''',(
                scope.workspace_id,scope.application_id,
                "schedule-rule-"+occurrence_id,row["execution_issuer"],
                row["execution_subject"])).fetchone()
            target=definition["target"]
            if child is not None and (
                    child["workflow_id"]!=expected
                    or child["rule_id"]!=target["ruleId"]
                    or child["rule_version"]!=target["version"]
                    or child["publication_operation_id"]!=
                        target["publicationOperationId"]):
                raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
            linked=row["application_rule_workflow_id"]
            if linked is not None and (
                    child is None or linked!=child["workflow_id"]):
                raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
            origin=row["inspection_origin_status"]
            terminal={"published":"published",
                "partially_published":"partially_published",
                "failed":"failed","cancelled":"cancelled"}
            if child is not None and child["status"] in terminal:
                restored=terminal[child["status"]]
            elif child is not None and child["status"]=="needs_inspection":
                raise ValueError(
                    "APPLICATION_SCHEDULE_CHILD_NEEDS_INSPECTION")
            elif origin=="cancel_requested":
                restored="cancel_requested"
            elif child is None:
                if origin=="submitted":
                    raise ValueError(
                        "APPLICATION_SCHEDULE_WORKFLOW_MISSING")
                restored="running"
            else:
                restored="submitted"
            if restored not in terminal and origin!="cancel_requested":
                allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                    scope.workspace_id,scope.application_id,
                    row["delegation_id"],row["delegation_version"],
                    row["execution_issuer"],row["execution_subject"],
                    "application.rule.run",row["schedule_id"],
                    row["schedule_version"])).fetchone()
                if allowed is None or allowed["allowed"] is not True:
                    restored="failed"
            result=dict(row["result"]);result["reconciliation"]={
                "operationId":idempotency_key,
                "actor":[self.identity.issuer,self.identity.subject_id],
                "originStatus":origin,"resultStatus":restored,
                "workflowId":None if child is None else child["workflow_id"]}
            changed=db.execute('''UPDATE epm.application_schedule_occurrence
                SET status=%s,application_rule_workflow_id=COALESCE(
                  application_rule_workflow_id,%s),
                  inspection_origin_status=NULL,
                  error_code=CASE WHEN %s='failed' THEN
                    'APPLICATION_SCHEDULE_AUTHORIZATION_REVOKED' ELSE NULL END,
                  result=%s,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s AND status='needs_inspection'
                  AND claimant IS NULL AND lease_until IS NULL''',(
                restored,None if child is None else child["workflow_id"],
                restored,Jsonb(result),scope.workspace_id,scope.application_id,
                occurrence_id)).rowcount
            if changed!=1:
                raise ValueError("APPLICATION_SCHEDULE_STALE_CONTROL_STATE")
            return {"occurrenceId":occurrence_id,"status":restored,
                "originStatus":origin,
                "workflowId":None if child is None else child["workflow_id"]}

    def save_version(self,scope: ApplicationScope,definition: object,*,
            expected_state_revision: int,expected_metadata_revision: int,
            expected_policy_revision: int,expected_schema_epoch: int,
            idempotency_key: str,registry: FunctionValidator,
            compiler_version: str) -> dict:
        canonical=validate_definition(definition)
        if (type(expected_state_revision) is not int or expected_state_revision<0
                or any(type(item) is not int or item<0 for item in (
                    expected_metadata_revision,expected_policy_revision,
                    expected_schema_epoch))
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None
                or not callable(getattr(registry,"validate_operation",None))
                or type(compiler_version) is not str or not compiler_version):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        target=canonical["target"]
        command={"scope":[scope.workspace_id,scope.application_id],
            "identity":[self.identity.issuer,self.identity.subject_id],
            "tokenIssuedAt":self.identity.issued_at,
            "function":SAVE,"definition":canonical,
            "expectedStateRevision":expected_state_revision,
            "expectedMetadataRevision":expected_metadata_revision,
            "expectedPolicyRevision":expected_policy_revision,
            "expectedSchemaEpoch":expected_schema_epoch}
        command_digest=_digest(command);definition_digest=canonical_digest(canonical)
        # A completed retry must not be rejected merely because its own first
        # commit advanced policy state.  Authorization is current, while the
        # original receipt remains the exact effect/idempotency authority.
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"admin",function=SAVE)
            prior=db.execute('''SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if (prior["command_digest"]!=command_digest
                        or prior["actor_id"]!=self.identity.subject_id):
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
        # This validates parameter/POV bindings, member-list publications and
        # every operation through the same authoritative rule compiler.  The
        # returned plan is intentionally not stored here: execution seals the
        # immutable target again against then-current context and authority.
        PostgresApplicationRules(self.dsn,identity=self.identity
            ).seal_published_version(scope,target["ruleId"],target["version"],
                publication_operation_id=target["publicationOperationId"],
                published_revision=target["publishedRevision"],
                program_digest=target["programDigest"],registry=registry,
                bindings=execution_bindings(canonical),
                compiler_version=compiler_version)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(
                db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"admin",function=SAVE)
            prior=db.execute('''SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if (prior["command_digest"]!=command_digest
                        or prior["actor_id"]!=self.identity.subject_id):
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            state=db.execute('''SELECT metadata_revision,policy_revision,
                schema_epoch,commit_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',(
                scope.workspace_id,scope.application_id)).fetchone()
            self._revisions(state,expected_metadata_revision,
                            expected_policy_revision,expected_schema_epoch)
            pointer=db.execute('''SELECT * FROM epm.application_schedule_state
                WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s
                FOR UPDATE''',(scope.workspace_id,scope.application_id,
                               canonical["scheduleId"])).fetchone()
            current=pointer or {"latest_version":0,"active_version":None,
                                "state_revision":0}
            if current["state_revision"]!=expected_state_revision:
                raise ValueError("APPLICATION_SCHEDULE_STALE_STATE")
            if canonical["version"]!=current["latest_version"]+1:
                raise ValueError("APPLICATION_SCHEDULE_STALE_VERSION")
            proof=db.execute('''SELECT v.program_digest,r.committed_revision,
                r.result FROM epm.expression_rule_version v
                JOIN epm.operation_receipt r ON r.workspace_id=v.workspace_id
                  AND r.application_id=v.application_id
                  AND r.operation_id=%s
                WHERE v.workspace_id=%s AND v.application_id=%s
                  AND v.rule_id=%s AND v.version=%s''',(
                target["publicationOperationId"],scope.workspace_id,
                scope.application_id,target["ruleId"],target["version"])).fetchone()
            receipt=None if proof is None else proof["result"]
            if (proof is None or proof["program_digest"]!=target["programDigest"]
                    or proof["committed_revision"]!=target["publishedRevision"]
                    or type(receipt) is not dict
                    or receipt.get("status")!="Published"
                    or receipt.get("ruleId")!=target["ruleId"]
                    or receipt.get("version")!=target["version"]
                    or receipt.get("programDigest")!=target["programDigest"]):
                raise ValueError("APPLICATION_SCHEDULE_TARGET_INVALID")
            delegation=canonical["delegation"]
            authority=db.execute('''SELECT issuer,subject_id,verified_groups,
                    authorization_scope_digest
                FROM epm.execution_delegation_version
                WHERE workspace_id=%s AND application_id=%s
                  AND delegation_id=%s AND version=%s''',(
                scope.workspace_id,scope.application_id,
                delegation["delegationId"],delegation["version"])).fetchone()
            allowed=(authority is not None and db.execute(
                '''SELECT epm.execution_delegation_is_current(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                    scope.workspace_id,scope.application_id,
                    delegation["delegationId"],delegation["version"],
                    authority["issuer"],authority["subject_id"],
                    "application.rule.run",canonical["scheduleId"],
                    canonical["version"])).fetchone()["allowed"])
            if not allowed:raise ValueError("APPLICATION_SCHEDULE_AUTHORITY_INVALID")
            if (authority["issuer"],authority["subject_id"])==(
                    self.identity.issuer,self.identity.subject_id):
                if (type(self.identity.issued_at) is not int
                        or self.identity.issued_at<=0):
                    raise ValueError(
                        "DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED")
                execution_token_issued_at=self.identity.issued_at
                execution_authority_kind="HumanToken"
            elif authority["issuer"].startswith("urn:openepm:"):
                execution_token_issued_at=None
                execution_authority_kind="Technical"
            else:
                raise ValueError("DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED")
            authority_row={"execution_issuer":authority["issuer"],
                "execution_subject":authority["subject_id"],
                "execution_groups":authority["verified_groups"],
                "execution_token_issued_at":execution_token_issued_at,
                "execution_authority_kind":execution_authority_kind,
                "authorization_scope_digest":
                    authority["authorization_scope_digest"]}
            self._assert_authorization_scope(db,scope,authority_row,
                function=SAVE)
            revision=state["commit_revision"]+1
            result={"operationId":idempotency_key,
                "scheduleId":canonical["scheduleId"],
                "version":canonical["version"],"status":"Saved",
                "definitionDigest":definition_digest,
                "committedRevision":revision,
                "policyRevision":state["policy_revision"]+1}
            db.execute('''INSERT INTO epm.operation_receipt(
                workspace_id,application_id,operation_id,command_digest,
                actor_id,committed_revision,result)
                VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                scope.workspace_id,scope.application_id,idempotency_key,
                command_digest,self.identity.subject_id,revision,Jsonb(result)))
            db.execute('''INSERT INTO epm.application_schedule_version(
                workspace_id,application_id,schedule_id,version,definition,
                definition_digest,rule_id,rule_version,rule_program_digest,
                publication_operation_id,published_revision,execution_issuer,
                execution_subject,delegation_id,delegation_version,operation_id,
                created_revision,execution_groups,authorization_scope_digest,
                execution_token_issued_at,execution_authority_kind)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                %s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,
                canonical["scheduleId"],canonical["version"],Jsonb(canonical),
                definition_digest,target["ruleId"],target["version"],
                target["programDigest"],target["publicationOperationId"],
                target["publishedRevision"],authority["issuer"],
                authority["subject_id"],delegation["delegationId"],
                delegation["version"],idempotency_key,revision,
                authority["verified_groups"],
                authority["authorization_scope_digest"],
                execution_token_issued_at,execution_authority_kind))
            if pointer:
                db.execute('''UPDATE epm.application_schedule_state SET
                    latest_version=%s,state_revision=state_revision+1,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s
                    AND application_id=%s AND schedule_id=%s''',(
                    canonical["version"],scope.workspace_id,
                    scope.application_id,canonical["scheduleId"]))
            else:
                db.execute('''INSERT INTO epm.application_schedule_state(
                    workspace_id,application_id,schedule_id,latest_version,
                    active_version,state_revision) VALUES(%s,%s,%s,%s,NULL,1)''',(
                    scope.workspace_id,scope.application_id,
                    canonical["scheduleId"],canonical["version"]))
            db.execute('''UPDATE epm.application_state SET
                policy_revision=policy_revision+1,commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s''',(
                revision,scope.workspace_id,scope.application_id))
            return result

    def set_publication(self,scope: ApplicationScope,schedule_id: str,*,
            version: int | None,expected_state_revision: int,
            expected_metadata_revision: int,expected_policy_revision: int,
            expected_schema_epoch: int,idempotency_key: str) -> dict:
        function=PUBLISH if version is not None else DEACTIVATE
        if (type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None
                or type(expected_state_revision) is not int
                or expected_state_revision<1
                or (version is not None and (type(version) is not int or version<1))
                or any(type(item) is not int or item<0 for item in (
                    expected_metadata_revision,expected_policy_revision,
                    expected_schema_epoch))
                or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        command={"scope":[scope.workspace_id,scope.application_id],
            "identity":[self.identity.issuer,self.identity.subject_id],
            "function":function,"scheduleId":schedule_id,"version":version,
            "expectedStateRevision":expected_state_revision,
            "expectedMetadataRevision":expected_metadata_revision,
            "expectedPolicyRevision":expected_policy_revision,
            "expectedSchemaEpoch":expected_schema_epoch}
        command_digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(
                db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"admin",function=function)
            prior=db.execute('''SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if (prior["command_digest"]!=command_digest
                        or prior["actor_id"]!=self.identity.subject_id):
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            state=db.execute('''SELECT metadata_revision,policy_revision,
                schema_epoch,commit_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',(
                scope.workspace_id,scope.application_id)).fetchone()
            self._revisions(state,expected_metadata_revision,
                            expected_policy_revision,expected_schema_epoch)
            pointer=db.execute('''SELECT * FROM epm.application_schedule_state
                WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s
                FOR UPDATE''',(scope.workspace_id,scope.application_id,
                               schedule_id)).fetchone()
            if pointer is None:raise ValueError("APPLICATION_SCHEDULE_UNAVAILABLE")
            if pointer["state_revision"]!=expected_state_revision:
                raise ValueError("APPLICATION_SCHEDULE_STALE_STATE")
            if function==PUBLISH:
                row=db.execute('''SELECT * FROM epm.application_schedule_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND schedule_id=%s AND version=%s''',(
                    scope.workspace_id,scope.application_id,schedule_id,
                    version)).fetchone()
                if row is None:raise ValueError("APPLICATION_SCHEDULE_VERSION_UNAVAILABLE")
                if pointer["active_version"]==version:
                    raise ValueError("APPLICATION_SCHEDULE_ALREADY_ACTIVE")
                allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                    %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                    scope.workspace_id,scope.application_id,row["delegation_id"],
                    row["delegation_version"],row["execution_issuer"],
                    row["execution_subject"],"application.rule.run",schedule_id,
                    version)).fetchone()["allowed"]
                if not allowed:raise ValueError("APPLICATION_SCHEDULE_AUTHORITY_INVALID")
                self._assert_authorization_scope(db,scope,row,
                    function=PUBLISH)
            elif pointer["active_version"] is None:
                raise ValueError("APPLICATION_SCHEDULE_ALREADY_INACTIVE")
            revision=state["commit_revision"]+1
            result={"operationId":idempotency_key,"scheduleId":schedule_id,
                "version":version if function==PUBLISH else pointer["active_version"],
                "status":"Published" if function==PUBLISH else "Deactivated",
                "committedRevision":revision,
                "policyRevision":state["policy_revision"]+1}
            db.execute('''INSERT INTO epm.operation_receipt(
                workspace_id,application_id,operation_id,command_digest,
                actor_id,committed_revision,result)
                VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                scope.workspace_id,scope.application_id,idempotency_key,
                command_digest,self.identity.subject_id,revision,Jsonb(result)))
            db.execute('''UPDATE epm.application_schedule_state SET
                active_version=%s,state_revision=state_revision+1,
                last_due_at=CASE WHEN active_version IS DISTINCT FROM %s
                                 THEN NULL ELSE last_due_at END,
                dispatch_error_code=NULL,
                updated_at=transaction_timestamp() WHERE workspace_id=%s
                AND application_id=%s AND schedule_id=%s''',(
                version,version,scope.workspace_id,scope.application_id,schedule_id))
            db.execute('''UPDATE epm.application_state SET
                policy_revision=policy_revision+1,commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s''',(
                revision,scope.workspace_id,scope.application_id))
            return result

    def materialize_due(self,scope: ApplicationScope,schedule_id: str,*,
                        dispatch_claim: dict | None=None) -> dict:
        """Materialize due instants from server time without executing a rule.

        This is a trusted coordinator boundary, not a public application
        function.  The schedule row is locked so concurrent ticks serialize;
        the occurrence identity and unique due constraint make a replay safe
        even if the first response is lost.  No business revision is changed.
        """
        if (not isinstance(scope,ApplicationScope)
                or type(schedule_id) is not str
                or _ID.fullmatch(schedule_id) is None):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        if dispatch_claim is not None:
            required={"workspace_id","application_id","schedule_id",
                      "dispatch_generation","claimant"}
            if (type(dispatch_claim) is not dict
                    or not required<=set(dispatch_claim)
                    or (dispatch_claim["workspace_id"],
                        dispatch_claim["application_id"],
                        dispatch_claim["schedule_id"])!=(scope.workspace_id,
                            scope.application_id,schedule_id)
                    or type(dispatch_claim["dispatch_generation"]) is not int
                    or dispatch_claim["dispatch_generation"]<1
                    or type(dispatch_claim["claimant"]) is not str
                    or not 1<=len(dispatch_claim["claimant"])<=200):
                raise ValueError("APPLICATION_SCHEDULE_DISPATCH_CLAIM_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope)
            row=db.execute('''SELECT s.active_version,s.last_due_at,
                s.dispatch_generation,s.dispatch_claimant,
                s.dispatch_lease_until,v.*,
                clock_timestamp() AS server_now
                FROM epm.application_schedule_state s
                JOIN epm.application_schedule_version v ON
                  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
                  (s.workspace_id,s.application_id,s.schedule_id,
                   s.active_version)
                WHERE s.workspace_id=%s AND s.application_id=%s
                  AND s.schedule_id=%s FOR UPDATE OF s''',(
                scope.workspace_id,scope.application_id,schedule_id)).fetchone()
            if row is None:
                raise ValueError("APPLICATION_SCHEDULE_INACTIVE")
            if dispatch_claim is not None and (
                    row["dispatch_generation"]!=
                        dispatch_claim["dispatch_generation"]
                    or row["dispatch_claimant"]!=dispatch_claim["claimant"]
                    or row["dispatch_lease_until"] is None
                    or row["dispatch_lease_until"]<=row["server_now"]):
                raise ValueError("APPLICATION_SCHEDULE_STALE_DISPATCH_CLAIM")
            definition=validate_definition(row["definition"])
            if (definition["scheduleId"]!=schedule_id
                    or definition["version"]!=row["active_version"]
                    or canonical_digest(definition)!=row["definition_digest"]):
                raise ValueError("APPLICATION_SCHEDULE_DEFINITION_CORRUPT")
            allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                %s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(
                scope.workspace_id,scope.application_id,row["delegation_id"],
                row["delegation_version"],row["execution_issuer"],
                row["execution_subject"],"application.rule.run",schedule_id,
                row["active_version"])).fetchone()
            if allowed is None or allowed["allowed"] is not True:
                return {"scheduleId":schedule_id,"version":row["active_version"],
                    "status":"Blocked","reasonCode":
                    "APPLICATION_SCHEDULE_AUTHORITY_INVALID","occurrences":[]}
            try:
                self._assert_authorization_scope(db,scope,row,
                    function="schedule.materialize")
            except AccessDenied:
                return {"scheduleId":schedule_id,"version":row["active_version"],
                    "status":"Blocked","reasonCode":
                    "APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED",
                    "occurrences":[]}
            recurrence=definition["recurrence"]
            first_due=datetime.fromisoformat(
                recurrence["firstDueAt"].replace("Z","+00:00"))
            policy=CatchUpPolicy(recurrence["catchUpPolicy"])
            due=due_from_interval(first_due_at=first_due,
                interval_seconds=recurrence["intervalSeconds"],
                last_due_at=row["last_due_at"],through=row["server_now"],
                policy=policy,maximum=recurrence["maxCatchUp"])
            if not due and policy is CatchUpPolicy.SKIP:
                skipped=due_from_interval(first_due_at=first_due,
                    interval_seconds=recurrence["intervalSeconds"],
                    last_due_at=row["last_due_at"],through=row["server_now"],
                    policy=CatchUpPolicy.LATEST,maximum=1)
                if skipped:
                    db.execute('''UPDATE epm.application_schedule_state
                        SET last_due_at=%s,updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                          AND schedule_id=%s AND active_version=%s''',(
                        skipped[-1],scope.workspace_id,scope.application_id,
                        schedule_id,row["active_version"]))
                    return {"scheduleId":schedule_id,
                        "version":row["active_version"],"status":"Skipped",
                        "throughDueAt":skipped[-1].isoformat(),"occurrences":[]}
            if not due:
                return {"scheduleId":schedule_id,"version":row["active_version"],
                    "status":"NotDue","occurrences":[]}
            occurrences=[]
            for instant in due:
                occurrence_id=_occurrence_id(scope,schedule_id,
                    row["active_version"],instant)
                inserted=db.execute('''INSERT INTO
                    epm.application_schedule_occurrence(
                      workspace_id,application_id,occurrence_id,schedule_id,
                      schedule_version,due_at,status)
                    VALUES(%s,%s,%s,%s,%s,%s,'ready')
                    ON CONFLICT(workspace_id,application_id,schedule_id,
                                schedule_version,due_at) DO NOTHING
                    RETURNING occurrence_id''',(
                    scope.workspace_id,scope.application_id,occurrence_id,
                    schedule_id,row["active_version"],instant)).fetchone()
                existing=inserted or db.execute('''SELECT occurrence_id FROM
                    epm.application_schedule_occurrence WHERE workspace_id=%s
                    AND application_id=%s AND schedule_id=%s
                    AND schedule_version=%s AND due_at=%s''',(
                    scope.workspace_id,scope.application_id,schedule_id,
                    row["active_version"],instant)).fetchone()
                if existing is None or existing["occurrence_id"]!=occurrence_id:
                    raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_CONFLICT")
                occurrences.append({"occurrenceId":occurrence_id,
                    "dueAt":instant.isoformat(),"status":"ready",
                    "created":inserted is not None})
            db.execute('''UPDATE epm.application_schedule_state
                SET last_due_at=%s,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                  AND schedule_id=%s AND active_version=%s''',(
                due[-1],scope.workspace_id,scope.application_id,schedule_id,
                row["active_version"]))
            return {"scheduleId":schedule_id,"version":row["active_version"],
                "status":"Materialized","occurrences":occurrences}

    def read(self,scope: ApplicationScope,schedule_id: str,*,
             version: int | None=None) -> dict:
        if (type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None
                or (version is not None and (type(version) is not int or version<1))):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"read",function=READ)
            pointer=db.execute('''SELECT * FROM epm.application_schedule_state
                WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s''',(
                scope.workspace_id,scope.application_id,schedule_id)).fetchone()
            selected=version if version is not None else (
                None if pointer is None else pointer["latest_version"])
            row=None if selected is None else db.execute('''SELECT *
                FROM epm.application_schedule_version WHERE workspace_id=%s
                AND application_id=%s AND schedule_id=%s AND version=%s''',(
                scope.workspace_id,scope.application_id,schedule_id,selected)).fetchone()
            return {"defined":row is not None,
                    "schedule":None if row is None else self._result(row,pointer)}

    def list(self,scope: ApplicationScope,*,limit: int=100,
             after_schedule_id: str | None=None) -> dict:
        if (type(limit) is not int or not 1<=limit<=100
                or (after_schedule_id is not None
                    and (type(after_schedule_id) is not str
                         or _ID.fullmatch(after_schedule_id) is None))):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"read",function=LIST)
            rows=db.execute('''SELECT v.*,s.active_version,s.state_revision
                FROM epm.application_schedule_state s
                JOIN epm.application_schedule_version v ON
                  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
                  (s.workspace_id,s.application_id,s.schedule_id,s.latest_version)
                WHERE s.workspace_id=%s AND s.application_id=%s
                  AND (%s::text IS NULL OR s.schedule_id>%s)
                ORDER BY s.schedule_id LIMIT %s''',(
                scope.workspace_id,scope.application_id,after_schedule_id,
                after_schedule_id,limit+1)).fetchall()
            values=[self._result(row,row) for row in rows[:limit]]
            return {"schedules":values,"nextAfterScheduleId":(
                values[-1]["scheduleId"] if len(rows)>limit else None)}
