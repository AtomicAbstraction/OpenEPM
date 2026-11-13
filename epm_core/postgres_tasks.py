"""Authorized universal task projection over native durable work stores.

Native Job, CubeAggregate, PythonBuild, PythonWorkflow, import execution and
generic application-workflow stores remain
authoritative; this service never resumes, automatically reruns or undoes work.
"""
from __future__ import annotations

import re

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import PostgresJobQueue
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import lock_busy_boundary


_TASK_ID = re.compile(
    r"(?:[0-9a-f]{32}|[abcefgilpqrstuvw]:[0-9a-f]{32}|"
    r"x:[0-9a-f]{32}|"
    r"d:[0-9a-f]{64}|"
    r"[hy]:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299})")
_MAX_VISIBILITY_SCAN = 10_000
_WORKFLOW_HIDDEN = frozenset((
    "APPLICATION_WORKFLOW_ACTIVITY_NOT_ASSIGNED",
    "APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE",
    "APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE",
    "APPLICATION_WORKFLOW_SELECTION_NOT_ASSIGNED",
))


class PostgresTaskService:
    """Read and interrupt bounded task projections in one application."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL runtime DSN is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn = dsn
        self.identity = identity

    def _authorized(self, db, scope: ApplicationScope, permission: str) -> bool:
        try:
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, permission)
            return True
        except AccessDenied:
            return False

    @lock_busy_boundary
    def list(self, scope: ApplicationScope, *, after_sequence: int = 0,
             limit: int = 100, attention_only: bool = False) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or type(after_sequence) is not int or after_sequence < 0
                or type(limit) is not int or not 1 <= limit <= 500
                or type(attention_only) is not bool):
            raise ValueError("A scoped bounded task cursor is required")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read")
                administrator = self._authorized(db, scope, "admin")
                rows = db.execute("""SELECT task_id,sequence,task_class,
                    source_family,source_id,function_name,resource_class,status,
                    interruptible,rerun_supported,human_occurrence_id,
                    human_activity_id,workflow_occurrence_id,
                    workflow_activity_id,issuer,subject_id,created_at,updated_at
                    FROM epm.task WHERE workspace_id=%s AND application_id=%s
                    AND (%s=0 OR sequence<%s)
                    AND (NOT %s OR status=ANY(%s::text[]))
                    ORDER BY sequence DESC LIMIT %s""",
                    (scope.workspace_id, scope.application_id, after_sequence,
                     after_sequence, attention_only,
                     ['Failed','Interrupted','Rejected','Stale'],
                     _MAX_VISIBILITY_SCAN + 1)).fetchall()
                candidates = rows[:_MAX_VISIBILITY_SCAN]
                visible = []
                for row in candidates:
                    if administrator or self._visible(db, scope, row):
                        visible.append(row)
                        if len(visible) > limit:
                            break
                page = visible[:limit]
                scan_exhausted = len(rows) > _MAX_VISIBILITY_SCAN
                has_more = len(visible) > limit or scan_exhausted
                if len(visible) > limit:
                    next_sequence = page[-1]["sequence"]
                elif candidates:
                    next_sequence = candidates[-1]["sequence"]
                else:
                    next_sequence = after_sequence
                return {"tasks": [self._task_row(row) for row in page],
                        "nextSequence": next_sequence,
                        "hasMore": has_more}

    @lock_busy_boundary
    def read(self, scope: ApplicationScope, task_id: str, *,
             after_event: int = 0, event_limit: int = 100) -> dict:
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise ValueError("TASK_ID_INVALID")
        if (type(after_event) is not int or after_event < 0
                or type(event_limit) is not int or not 1 <= event_limit <= 500):
            raise ValueError("A bounded task event cursor is required")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read")
                administrator = self._authorized(db, scope, "admin")
                row = db.execute("""SELECT task_id,sequence,task_class,
                    source_family,source_id,function_name,resource_class,status,
                    interruptible,rerun_supported,issuer,subject_id,
                    human_occurrence_id,human_activity_id,
                    workflow_occurrence_id,workflow_activity_id,
                    created_at,updated_at
                    FROM epm.task
                    WHERE workspace_id=%s AND application_id=%s AND task_id=%s""",
                    (scope.workspace_id, scope.application_id, task_id)).fetchone()
                if (row is None or (not administrator
                        and not self._visible(db, scope, row))):
                    raise ValueError("TASK_UNAVAILABLE")
                events = db.execute("""SELECT event_ordinal,status,
                    claim_generation,receipt_revision,error_code,occurred_at
                    FROM epm.task_event WHERE workspace_id=%s
                    AND application_id=%s AND task_id=%s AND event_ordinal>%s
                    ORDER BY event_ordinal LIMIT %s""",
                    (scope.workspace_id, scope.application_id, task_id,
                     after_event, event_limit + 1)).fetchall()
                page = events[:event_limit]
                result = self._task_row(row)
                result["events"] = [self._event_row(event) for event in page]
                result["nextEvent"] = (page[-1]["event_ordinal"] if page
                                       else after_event)
                result["hasMoreEvents"] = len(events) > event_limit
                return result

    @lock_busy_boundary
    def logs(self, scope: ApplicationScope, task_id: str, *,
             after_event: int = 0, event_limit: int = 100,
             after_character: int = 0,
             character_limit: int = 16_384) -> dict:
        """Read bounded authoritative diagnostics for one visible task.

        Lifecycle diagnostics come from the immutable universal task events.
        A sealed Python build additionally exposes its already bounded native
        build log to its owner; application-administrator task visibility does
        not broaden the native artifact's owner-only content authorization.
        """
        task = self.read(scope, task_id, after_event=after_event,
                         event_limit=event_limit)
        if (type(after_character) is not int or after_character < 0
                or type(character_limit) is not int
                or not 1 <= character_limit <= 16_384):
            raise ValueError("TASK_LOG_CURSOR_INVALID")
        source_log = None
        if task["sourceFamily"] == "PythonBuild":
            from .postgres_python_program_repository import (
                PostgresPythonProgramRepository)
            try:
                page = PostgresPythonProgramRepository(
                    self.dsn, None, identity=self.identity
                ).read_build_log(
                    scope, task["sourceId"],
                    after_character=after_character,
                    character_limit=character_limit)
            except ValueError as error:
                if str(error) != "PYTHON_BUILD_ARTIFACT_UNAVAILABLE":
                    raise
            else:
                source_log = {"kind": "PythonBuild", **page}
        return {"taskId": task_id,
                "lifecycle": {"events": task["events"],
                              "nextEvent": task["nextEvent"],
                              "hasMore": task["hasMoreEvents"]},
                "sourceLog": source_log}

    @lock_busy_boundary
    def interrupt(self, scope: ApplicationScope, task_id: str) -> dict:
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise ValueError("TASK_ID_INVALID")
        # Resolve visibility and source family first.  The native family method
        # performs the authoritative current write/admin check and row lock.
        task = self.read(scope, task_id, event_limit=1)
        if task["sourceFamily"] == "Job":
            native = PostgresJobQueue(
                self.dsn, identity=self.identity).request_cancel(
                    scope, task["sourceId"], allow_application_admin=True)
            committed = native["status"] == "published"
        elif task["sourceFamily"] == "CubeAggregate":
            from .postgres_cube_aggregate_repository import (
                PostgresCubeAggregateRepository)
            native = PostgresCubeAggregateRepository(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(
                scope, task["sourceId"], allow_application_admin=True)
            committed = False
        elif task["sourceFamily"] == "PythonBuild":
            from .postgres_python_program_repository import (
                PostgresPythonProgramRepository)
            native = PostgresPythonProgramRepository(
                self.dsn, None, identity=self.identity
            ).request_cancel_as_task_controller(
                scope, task["sourceId"], allow_application_admin=True)
            native = {"status": native.status.value}
            committed = False
        elif task["sourceFamily"] == "PythonWorkflow":
            from .postgres_python_workflow import PostgresPythonWorkflowStore
            workflow = PostgresPythonWorkflowStore(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(
                scope, task["sourceId"], allow_application_admin=True)
            pending = next((item for item in reversed(workflow.checkpoints)
                            if not item.committed), None)
            if (workflow.status.value == "cancel_requested"
                    and pending is not None):
                PostgresJobQueue(
                    self.dsn, identity=self.identity).request_cancel(
                        scope, pending.job_id, allow_application_admin=True)
            native = {"status": workflow.status.value}
            committed = workflow.committed_units > 0
        elif task["sourceFamily"] == "ApplicationRuleWorkflow":
            from .postgres_application_rule_workflow import (
                PostgresApplicationRuleWorkflowStore)
            workflow=PostgresApplicationRuleWorkflowStore(
                self.dsn,identity=self.identity
            ).request_cancel_as_task_controller(
                scope,task["sourceId"],allow_application_admin=True)
            pending=next((item for item in reversed(workflow.checkpoints)
                          if not item.committed),None)
            if workflow.status.value=="cancel_requested" and pending is not None:
                PostgresJobQueue(self.dsn,identity=self.identity).request_cancel(
                    scope,pending.job_id,allow_application_admin=True)
            native={"status":workflow.status.value}
            committed=workflow.committed_units>0
        elif task["sourceFamily"] == "ApplicationScheduleOccurrence":
            from .postgres_application_schedules import (
                PostgresApplicationSchedules)
            native=PostgresApplicationSchedules(
                self.dsn,identity=self.identity
            ).request_cancel_as_task_controller(
                scope,task["sourceId"],allow_application_admin=True)
            committed=native["status"] in (
                "published","partially_published")
        elif task["sourceFamily"] == "ImportExecution":
            from .postgres_import_execution import PostgresImportExecution
            native = PostgresImportExecution(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(
                scope, task["sourceId"], allow_application_admin=True)
            committed = native["status"] == "Completed"
        elif task["sourceFamily"] == "PythonScheduleOccurrence":
            from .postgres_python_schedules import PostgresPythonSchedules
            native = PostgresPythonSchedules(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(scope, task["sourceId"])
            committed = native["status"] == "published"
        elif task["sourceFamily"] == "ExportProducer":
            from .postgres_export_producer_checkpoint import (
                PostgresExportProducerCheckpoint)
            native = PostgresExportProducerCheckpoint(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(
                scope, task["sourceId"], allow_application_admin=True)
            committed = False
        elif task["sourceFamily"] == "TransferCleanup":
            from .postgres_transfer_cleanup import PostgresTransferCleanup
            native = PostgresTransferCleanup(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(scope, task["sourceId"])
            committed = False
        elif task["sourceFamily"] == "LayoutReplacementBuild":
            from .postgres_populated_layout_replacement import (
                PostgresPopulatedLayoutReplacements)
            native = PostgresPopulatedLayoutReplacements(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(scope, task["sourceId"])
            committed = False
        elif task["sourceFamily"] == "LayoutActivation":
            from .postgres_populated_layout_activation import (
                PostgresPopulatedLayoutActivation)
            native = PostgresPopulatedLayoutActivation(
                self.dsn, identity=self.identity
            ).request_cancel_as_task_controller(scope, task["sourceId"])
            committed = native["status"] == "Activated"
        elif task["sourceFamily"] == "ExpressionRuleSequence":
            from .postgres_expression_sequence import PostgresExpressionSequence
            native = PostgresExpressionSequence.request_cancel_as_task_controller(
                self.dsn,identity=self.identity,scope=scope,
                sequence_id=task["sourceId"])
            committed = native["committedEffectsRemain"]
        elif task["sourceFamily"] == "FullAggregateSequence":
            from .postgres_full_sequence import PostgresFullAggregateSequence
            native = PostgresFullAggregateSequence.request_cancel_as_task_controller(
                self.dsn,identity=self.identity,scope=scope,
                sequence_id=task["sourceId"])
            committed = native["committedEffectsRemain"]
        elif task["sourceFamily"] == "SourceBatch":
            from .postgres_source_batch import PostgresSourceBatch
            native = PostgresSourceBatch.request_cancel_as_task_controller(
                self.dsn, identity=self.identity, scope=scope,
                batch_id=task["sourceId"])
            committed = native["committedEffectsRemain"]
        elif task["sourceFamily"] == "ApplicationWorkflowOccurrence":
            from .postgres_application_workflow_occurrences import (
                PostgresApplicationWorkflowOccurrences)
            native = PostgresApplicationWorkflowOccurrences(
                self.dsn, identity=self.identity
            )._request_cancel_as_task_controller(
                scope, task["sourceId"], allow_application_admin=True)
            committed = False
        else:
            raise ValueError("TASK_NOT_INTERRUPTIBLE")
        normalized_native = native["status"]
        if (task["sourceFamily"] == "ImportExecution"
                and native.get("cancelRequested")
                and native["status"] == "Claimed"):
            normalized_native = "cancel_requested"
        return {"taskId": task_id,
                "status": self._normalized(normalized_native),
                "nativeStatus": native["status"],
                "committedEffectsRemain": committed}

    @lock_busy_boundary
    def rerun(self, scope: ApplicationScope, task_id: str, *,
              idempotency_key: str) -> dict:
        """Create a new request from a supported terminal task.

        The source task is never resumed, replayed or undone.  Each supported
        native family owns the exact validation and creation of the new work.
        """
        if not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id):
            raise ValueError("TASK_ID_INVALID")
        task = self.read(scope, task_id, event_limit=1)
        if not task["rerunSupported"]:
            raise ValueError("TASK_RERUN_NOT_SUPPORTED")
        if task["sourceFamily"] == "Job":
            native = PostgresJobQueue(
                self.dsn, identity=self.identity
            ).rerun_as_task_controller(
                scope, task["sourceId"], idempotency_key=idempotency_key,
                allow_application_admin=True)
            new_task_id = native["jobId"]
            native = {**native, "operationId": idempotency_key,
                      "committedRevision": None}
        elif task["sourceFamily"] == "PythonBuild":
            from .postgres_python_program_repository import (
                PostgresPythonProgramRepository)
            build = PostgresPythonProgramRepository(
                self.dsn, None, identity=self.identity
            ).rerun_as_task_controller(
                scope, task["sourceId"], idempotency_key=idempotency_key)
            new_task_id = "p:" + build.build_id
            native = {"status": build.status.value,
                      "operationId": idempotency_key,
                      "committedRevision": None}
        elif task["sourceFamily"] == "CubeAggregate":
            from .postgres_cube_aggregate_repository import (
                PostgresCubeAggregateRepository)
            native = PostgresCubeAggregateRepository(
                self.dsn, identity=self.identity
            ).rerun_as_task_controller(
                scope, task["sourceId"], idempotency_key=idempotency_key)
            new_task_id = "c:" + native["queryId"]
            native = {**native, "operationId": idempotency_key,
                      "committedRevision": None}
        elif task["sourceFamily"] == "PythonWorkflow":
            from .postgres_python_workflow import PostgresPythonWorkflowStore
            workflow = PostgresPythonWorkflowStore(
                self.dsn, identity=self.identity
            ).rerun_as_task_controller(
                scope, task["sourceId"], idempotency_key=idempotency_key)
            new_task_id = "w:" + workflow.workflow_id
            native = {"status": workflow.status.value,
                      "operationId": idempotency_key,
                      "committedRevision": None}
        elif task["sourceFamily"] == "ExportProducer":
            from .postgres_export_producer_checkpoint import (
                PostgresExportProducerCheckpoint)
            export = PostgresExportProducerCheckpoint(
                self.dsn, identity=self.identity
            ).rerun_as_task_controller(
                scope, task["sourceId"], idempotency_key=idempotency_key)
            new_task_id = "e:" + export["request_id"]
            native = {"status": export["status"],
                      "operationId": idempotency_key,
                      "committedRevision": None}
        else:
            raise ValueError("TASK_RERUN_NOT_SUPPORTED")
        created = self.read(scope, new_task_id, event_limit=1)
        return {"sourceTaskId": task_id,
                "taskId": new_task_id,
                "status": created["status"],
                "nativeStatus": native["status"],
                "operationId": native["operationId"],
                "committedRevision": native["committedRevision"]}

    def _visible(self, db, scope: ApplicationScope, row) -> bool:
        if row["source_family"] == "ApplicationWorkflowActivity":
            from .postgres_application_workflow_occurrences import (
                authorize_workflow_activity_task_in_transaction)
            try:
                authorize_workflow_activity_task_in_transaction(
                    db, scope, self.identity,
                    row["workflow_occurrence_id"],row["workflow_activity_id"])
                return True
            except ValueError as error:
                if str(error) in _WORKFLOW_HIDDEN:
                    return False
                raise
        # Domain-era HumanActivity rows can survive only as non-actionable
        # audit history after schema 235. Their source relations no longer
        # exist, so visibility falls back to the verified originating subject.
        return ((row["issuer"], row["subject_id"]) ==
                (self.identity.issuer, self.identity.subject_id))

    @staticmethod
    def _normalized(native: str) -> str:
        value = {"accepted": "Accepted", "ready": "Waiting",
                 "running": "Running", "staged": "Running",
                 "cancel_requested": "InterruptRequested",
                 "cancelled": "Interrupted", "published": "Succeeded",
                 "failed": "Failed",
                 "needs_inspection": "NeedsInspection",
                 "computed": "Running", "sealed": "Succeeded", "expired": "Succeeded",
                 "expired": "Succeeded",
                 "partially_published": "PartiallySucceeded",
                 "business_published": "Running",
                 "progress_committed": "Succeeded",
                 "Blocked": "Waiting", "Ready": "Waiting",
                 "Completed": "Succeeded",
                 "Cancelled": "Interrupted", "Accepted": "Accepted",
                 "Claimed": "Running", "Reading": "Running",
                 "Prepared": "Running", "Publishing": "Running",
                 "Failed": "Failed", "building": "Running",
                 "running_program": "Running", "Pending": "Waiting"}.get(native)
        if value is None:
            raise ValueError("UNKNOWN_TASK_STATUS")
        return value

    @staticmethod
    def _task_row(row) -> dict:
        return {"taskId": row["task_id"], "sequence": row["sequence"],
                "taskClass": row["task_class"],
                "sourceFamily": row["source_family"],
                "sourceId": row["source_id"],
                "function": row["function_name"],
                "resourceClass": row["resource_class"],
                "status": row["status"],
                "interruptible": row["interruptible"],
                "rerunSupported": row["rerun_supported"],
                "createdAt": row["created_at"].isoformat(),
                "updatedAt": row["updated_at"].isoformat()}

    @staticmethod
    def _event_row(row) -> dict:
        return {"event": row["event_ordinal"], "status": row["status"],
                "claimGeneration": row["claim_generation"],
                "receiptRevision": row["receipt_revision"],
                "errorCode": row["error_code"],
                "occurredAt": row["occurred_at"].isoformat()}
