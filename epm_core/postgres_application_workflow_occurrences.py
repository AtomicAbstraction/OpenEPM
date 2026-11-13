"""Fixed-core state boundary for domain-neutral application workflows.

This private service starts exact published workflows, exposes only currently
assigned ready work, reads durable state, completes evidence-backed activities,
returns reviews to configured ancestors and cancels active occurrences. It does
not execute destinations; evidence validation remains server-owned and
function-specific.
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import json
import re
from typing import Collection

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_assignment import compile_application_assignment_set
from .application_workflow import Activity,ApplicationWorkflow
from .current_object_contract import new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_application_workflows import PostgresApplicationWorkflows
from .postgres_application_workflow_evidence import validate_workflow_evidence
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_selection_preview import resolve_selection_in_transaction


START="application.workflow.occurrence.start"
READ="application.workflow.occurrence.read"
WORKLIST="application.workflow.worklist"
EVIDENCE_OPTIONS="application.workflow.activity.evidence.list"
CANCEL="application.workflow.occurrence.cancel"
COMPLETE="application.workflow.activity.complete"
RETURN="application.workflow.activity.return"
FUNCTIONS=frozenset((START,READ,WORKLIST,EVIDENCE_OPTIONS,COMPLETE,RETURN,CANCEL))
MUTATIONS=frozenset((START,COMPLETE,RETURN,CANCEL))
READS=frozenset((READ,WORKLIST,EVIDENCE_OPTIONS))
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z")
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_OCCURRENCE=re.compile(r"[0-9a-f]{32}\Z")
_MAX_WORKLIST_SCAN=10_000
_MAX_EVIDENCE_SCAN=1_000
_EVIDENCE_ACTION_LABELS={
    "application.rule.run":"Application rule run",
    "facts.numeric.batch":"Numeric data update",
}
_TABLES=("application_workflow_definition",
    "application_workflow_assignment_pin","application_workflow_occurrence",
    "application_workflow_activity","application_workflow_event",
    "application_workflow_evidence_link","application_assignment_definition")


def catalog()->dict:
    common={"previewRequired":False,"workClass":"short",
            "requiredCapabilities":[]}
    mutation={**common,"idempotencyRequired":True}
    read={**common,"permission":"read","idempotencyRequired":False,
          "mode":"read"}
    return {
        START:{**mutation,"permission":"admin","mode":"atomic_workflow_transition",
            "arguments":{"flowId":"stable workflow ID",
                "expectedStateToken":"exact active workflow state token",
                "expectedMetadataRevision":"current metadata revision",
                "expectedPolicyRevision":"current policy revision",
                "expectedSchemaEpoch":"current schema epoch"},
            "result":"durable occurrence and initial Ready activities"},
        READ:{**read,"arguments":{"occurrenceId":"stable occurrence ID"},
            "optionalArguments":{"eventLimit":"1-500",
                "afterEventOrdinal":"nonnegative event cursor"},
            "result":"occurrence, activities and bounded event page"},
        WORKLIST:{**read,"arguments":{},"optionalArguments":{
            "limit":"1-100","afterOccurrenceId":"keyset cursor",
            "afterActivityId":"paired keyset cursor"},
            "result":"currently assigned Ready activities"},
        EVIDENCE_OPTIONS:{**read,"arguments":{
            "occurrenceId":"stable occurrence ID",
            "activityId":"stable activity ID"},"optionalArguments":{
            "limit":"1-100",
            "beforeCommittedRevision":"descending evidence cursor"},
            "result":"eligible current receipt choices for one assigned activity"},
        COMPLETE:{**mutation,"permission":"read",
            "mode":"atomic_workflow_transition","arguments":{
                "occurrenceId":"stable occurrence ID",
                "activityId":"stable activity ID",
                "expectedActivityStateToken":"exact current activity state token",
                "evidence":"typed configured evidence reference"},
            "result":"receipt-backed activity transition"},
        RETURN:{**mutation,"permission":"read",
            "mode":"atomic_workflow_transition","arguments":{
                "occurrenceId":"stable occurrence ID",
                "activityId":"stable review activity ID",
                "expectedActivityStateToken":"exact current activity state token",
                "reason":"bounded return reason"},
            "result":"receipt-backed return and invalidation transition"},
        CANCEL:{**mutation,"permission":"admin",
            "mode":"atomic_workflow_transition","arguments":{
                "occurrenceId":"stable occurrence ID",
                "expectedOccurrenceStateToken":"exact current occurrence state token"},
            "result":"receipt-backed occurrence cancellation"}}


def _identifier(value: object,code: str)->str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _revision(value: object,code: str)->int:
    if type(value) is not int or value<0:raise ValueError(code)
    return value


def _key(value: object)->str:
    if type(value) is not str or _KEY.fullmatch(value) is None:
        raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_KEY_INVALID")
    return value


def _occurrence_id(value: object)->str:
    if type(value) is not str or _OCCURRENCE.fullmatch(value) is None:
        raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_ID_INVALID")
    return value


def _program(value: object)->tuple[str,dict]:
    if (type(value) is not dict
            or set(value)!={"languageVersion","function","arguments"}
            or value.get("languageVersion")!=2
            or value.get("function") not in FUNCTIONS
            or type(value.get("arguments")) is not dict):
        raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_PROGRAM_INVALID")
    return value["function"],value["arguments"]


def _review_return_invalidation(model: ApplicationWorkflow,review_id: str,
                                rows: Collection[dict])->tuple[str,list[str]]:
    """Return the configured ancestor and descendants that need resetting.

    The graph contract already proves that the return target is an ancestor of
    the review.  Runtime state still determines which strict descendants need
    a versioned change: rows that are already Blocked with no prior completion
    or return state must remain untouched.
    """
    review=next((item for item in model.activities
                 if item.activity_id==review_id),None)
    if review is None or review.kind!="Review" or review.return_to is None:
        raise ValueError("APPLICATION_WORKFLOW_RETURN_UNAVAILABLE")
    descendants:set[str]=set()
    changed=True
    while changed:
        changed=False
        for candidate in model.activities:
            if (candidate.activity_id not in descendants
                    and candidate.activity_id!=review.return_to
                    and (review.return_to in candidate.depends_on
                         or any(parent in descendants
                                for parent in candidate.depends_on))):
                descendants.add(candidate.activity_id);changed=True
    if review_id not in descendants:
        raise ValueError("APPLICATION_WORKFLOW_RETURN_TARGET_INVALID")
    by_id={row["activity_id"]:row for row in rows}
    invalidated=[]
    for activity_id in sorted(descendants-{review_id}):
        row=by_id.get(activity_id)
        if row is None:
            raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_UNAVAILABLE")
        if (row["status"]!="Blocked" or row.get("operation_id") is not None
                or row.get("completed_by_issuer") is not None
                or row.get("completed_by_subject_id") is not None
                or row.get("completed_at") is not None
                or row.get("returned_to_activity_id") is not None):
            invalidated.append(activity_id)
    return review.return_to,invalidated


def authorize_workflow_activity_task_in_transaction(db,scope: ApplicationScope,
        identity: VerifiedIdentity,occurrence_id: str,activity_id: str)->None:
    """Recheck current assignment entitlement for a projected task.

    The universal task log is only a projection.  Visibility is therefore
    resolved from the current immutable workflow, published assignment and
    pinned multidimensional selection inside the caller's transaction.
    """
    service=object.__new__(PostgresApplicationWorkflowOccurrences)
    service.identity=identity
    occurrence=service._occurrence(db,scope,_occurrence_id(occurrence_id),
                                   lock=False)
    model=service._occurrence_model(db,scope,occurrence)
    activity=service._activity(model,_identifier(
        activity_id,"APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID"))
    state=service._context(db,scope,lock=False)
    resolved=resolve_selection_in_transaction(
        db,scope,model.normalized()["selection"],state["metadata_revision"])
    now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
    groups=PostgresAccessChecker.current_groups_in_transaction(db,identity)
    service._assignment(db,scope,activity,resolved["members"],
        require_entitlement=True,now=now,groups=groups)


class PostgresApplicationWorkflowOccurrences:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",_TABLES)
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope: ApplicationScope)->None:
        PostgresApplicationWorkflows._scope(db,scope)

    @staticmethod
    def _context(db,scope: ApplicationScope,*,lock: bool)->dict:
        return PostgresApplicationWorkflows._context(db,scope,lock=lock)

    @staticmethod
    def _active(state: dict)->None:
        if (state["application_status"]!="Active"
                or state["processing_mode"]!="Active"):
            raise ValueError("APPLICATION_NOT_WRITABLE")

    def _prepare(self,db,scope: ApplicationScope,permission: str,
                 function: str):
        self._scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        return PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,permission,function=function)

    def _prior(self,db,scope: ApplicationScope,operation_id: str,
               digest: str)->dict|None:
        row=db.execute("""SELECT command_digest,actor_id,result
            FROM epm.operation_receipt WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s""",(
            scope.workspace_id,scope.application_id,operation_id)).fetchone()
        if row is None:return None
        if (row["command_digest"]!=digest
                or row["actor_id"]!=self.identity.subject_id):
            raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_CONFLICT")
        return row["result"]

    def _receipt(self,db,scope: ApplicationScope,operation_id: str,
                 digest: str,revision: int,result: dict)->None:
        db.execute("""INSERT INTO epm.operation_receipt(workspace_id,
            application_id,operation_id,command_digest,actor_id,
            committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""",(
            scope.workspace_id,scope.application_id,operation_id,digest,
            self.identity.subject_id,revision,Jsonb(result)))

    @staticmethod
    def _workflow(db,scope: ApplicationScope,flow_id: str,state_token: str
                  )->ApplicationWorkflow:
        row=db.execute("""SELECT * FROM epm.application_workflow_definition
            WHERE workspace_id=%s AND application_id=%s AND flow_id=%s
              AND state_token=%s AND status='Active'""",(scope.workspace_id,
            scope.application_id,flow_id,state_token)).fetchone()
        if row is None:raise ValueError("APPLICATION_WORKFLOW_CURRENT_UNAVAILABLE")
        return PostgresApplicationWorkflows._verified(scope,row)

    @staticmethod
    def _occurrence(db,scope: ApplicationScope,value: str,*,lock: bool)->dict:
        row=db.execute("""SELECT * FROM epm.application_workflow_occurrence
            WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s"""+
            (" FOR UPDATE" if lock else ""),(scope.workspace_id,
            scope.application_id,value)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_UNAVAILABLE")
        return row

    @classmethod
    def _occurrence_model(cls,db,scope: ApplicationScope,row: dict
                          )->ApplicationWorkflow:
        model=cls._workflow(db,scope,row["flow_id"],row["flow_state_token"])
        if model.digest!=row["flow_digest"]:
            raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_DEFINITION_STALE")
        return model

    @staticmethod
    def _activity(model: ApplicationWorkflow,activity_id: str)->Activity:
        for item in model.activities:
            if item.activity_id==activity_id:return item
        raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_UNAVAILABLE")

    def _assignment(self,db,scope: ApplicationScope,activity: Activity,
                    resolved_members: dict[str,list[str]],*,
                    require_entitlement: bool,now: datetime,
                    groups: tuple[str,...]=())->dict:
        ref=activity.assignment_ref
        row=db.execute("""SELECT * FROM epm.application_assignment_definition
            WHERE workspace_id=%s AND application_id=%s
              AND assignment_set_id=%s AND state_token=%s
              AND definition_digest=%s AND status='Active'""",(scope.workspace_id,
            scope.application_id,ref.assignment_set_id,ref.state_token,
            ref.digest)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE")
        model=compile_application_assignment_set(row["definition"])
        if (model.scope!=scope or model.assignment_set_id!=ref.assignment_set_id
                or model.digest!=ref.digest):
            raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE")
        assignment=model.assignment(ref.assignment_id)
        if (now<model.effective_from
                or model.effective_to is not None and now>model.effective_to):
            raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE")
        for dimension,members in assignment.member_selectors:
            selected=resolved_members.get(dimension)
            if selected is None or not set(selected)<=set(members):
                raise ValueError("APPLICATION_WORKFLOW_SELECTION_NOT_ASSIGNED")
        if require_entitlement:
            issuer_matches=self.identity.issuer==row["updater_issuer"]
            if activity.kind=="Action":
                principal=(self.identity.subject_id in assignment.subjects
                    or bool(set(groups)&set(assignment.groups)))
            else:
                principal=any((reviewer.kind=="Subject"
                    and reviewer.identifier==self.identity.subject_id)
                    or (reviewer.kind=="Group"
                    and reviewer.identifier in groups)
                    for reviewer in assignment.reviewer_chain)
            if not issuer_matches or not principal:
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_NOT_ASSIGNED")
        return {"assignmentSetId":model.assignment_set_id,
            "stateToken":row["state_token"],"digest":model.digest,
            "assignmentId":assignment.assignment_id,
            "assignmentCreatorIssuer":row["updater_issuer"],
            "kind":activity.kind}

    def start(self,scope: ApplicationScope,*,flow_id: str,
              expected_state_token: str,expected_metadata_revision: int,
              expected_policy_revision: int,expected_schema_epoch: int,
              idempotency_key: str,
              available_functions: Collection[str])->dict:
        flow_id=_identifier(flow_id,"APPLICATION_WORKFLOW_FLOW_ID_INVALID")
        expected_state_token=require_state_token(expected_state_token,
            error="APPLICATION_WORKFLOW_STATE_TOKEN_INVALID")
        metadata=_revision(expected_metadata_revision,
            "APPLICATION_WORKFLOW_METADATA_REVISION_INVALID")
        policy=_revision(expected_policy_revision,
            "APPLICATION_WORKFLOW_POLICY_REVISION_INVALID")
        schema=_revision(expected_schema_epoch,
            "APPLICATION_WORKFLOW_SCHEMA_EPOCH_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":START,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"flowId":flow_id,
            "expectedStateToken":expected_state_token,
            "expectedMetadataRevision":metadata,
            "expectedPolicyRevision":policy,"expectedSchemaEpoch":schema}
        digest=_canonical_digest(command)
        derived=sha256(json.dumps({"namespace":
            "openepm-application-workflow-occurrence-v1","scope":command["scope"],
            "flowId":flow_id,"stateToken":expected_state_token,
            "idempotencyKey":operation_id},
            sort_keys=True,separators=(",",":")).encode()).hexdigest()[:32]
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._prepare(db,scope,"admin",START)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:return prior
            state=self._context(db,scope,lock=True);self._active(state)
            PostgresApplicationWorkflows._assert_context(
                state,metadata,policy,schema)
            model=self._workflow(db,scope,flow_id,expected_state_token)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,metadata)
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            for activity in model.activities:
                self._assignment(db,scope,activity,resolved["members"],
                    require_entitlement=False,now=now)
            revision=state["commit_revision"]+1
            ready=list(model.start_activity_ids)
            occurrence_token=new_state_token()
            result={"operationId":operation_id,"function":START,
                "status":"Active","occurrenceId":derived,
                "occurrenceStateToken":occurrence_token,"flowId":flow_id,
                "flowStateToken":expected_state_token,
                "definitionDigest":model.digest,"readyActivityIds":ready,
                "committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""INSERT INTO epm.application_workflow_occurrence(
                workspace_id,application_id,occurrence_id,flow_id,flow_state_token,
                flow_digest,status,last_event_ordinal,state_token,started_revision,
                started_operation_id,last_operation_id,started_by_issuer,
                started_by_subject_id) VALUES(%s,%s,%s,%s,%s,%s,'Active',1,%s,
                %s,%s,%s,%s,%s)""",(scope.workspace_id,scope.application_id,
                derived,flow_id,expected_state_token,model.digest,
                occurrence_token,revision,operation_id,operation_id,
                self.identity.issuer,self.identity.subject_id))
            for activity in model.activities:
                activity_token=new_state_token()
                db.execute("""INSERT INTO epm.application_workflow_activity(
                    workspace_id,application_id,occurrence_id,flow_id,
                    activity_id,kind,status,transition_ordinal,state_token)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,1,%s)""",(
                    scope.workspace_id,scope.application_id,derived,flow_id,
                    activity.activity_id,activity.kind,
                    "Ready" if activity.activity_id in ready else "Blocked",
                    activity_token))
            self._event(db,scope,derived,1,"OccurrenceStarted",None,
                operation_id,digest,revision)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            return result

    def read(self,scope: ApplicationScope,value: str,*,event_limit: int=100,
             after_event_ordinal: int=0)->dict:
        value=_occurrence_id(value)
        if type(event_limit) is not int or not 1<=event_limit<=500:
            raise ValueError("APPLICATION_WORKFLOW_EVENT_LIMIT_INVALID")
        if type(after_event_ordinal) is not int or after_event_ordinal<0:
            raise ValueError("APPLICATION_WORKFLOW_EVENT_CURSOR_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            self._prepare(db,scope,"read",READ)
            occurrence=self._occurrence(db,scope,value,lock=False)
            activities=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                ORDER BY activity_id""",(scope.workspace_id,
                scope.application_id,value)).fetchall()
            events=db.execute("""SELECT * FROM epm.application_workflow_event
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s AND event_ordinal>%s
                ORDER BY event_ordinal LIMIT %s""",(
                scope.workspace_id,scope.application_id,value,
                after_event_ordinal,event_limit+1)).fetchall()
            more=len(events)>event_limit;events=events[:event_limit]
            result=self._result(occurrence,activities,events)
            result["nextEventOrdinal"]=(events[-1]["event_ordinal"]
                if more and events else None)
            return result

    def worklist(self,scope: ApplicationScope,*,limit: int=100,
                 after_occurrence_id: str|None=None,
                 after_activity_id: str|None=None,
                 available_functions: Collection[str])->dict:
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError("APPLICATION_WORKFLOW_WORKLIST_LIMIT_INVALID")
        if (after_occurrence_id is None)!=(after_activity_id is None):
            raise ValueError("APPLICATION_WORKFLOW_WORKLIST_CURSOR_INVALID")
        if after_occurrence_id is not None:
            _occurrence_id(after_occurrence_id)
            _identifier(after_activity_id,
                "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"read",WORKLIST)
            state=self._context(db,scope,lock=False)
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            rows=db.execute("""SELECT a.*,o.flow_digest,o.flow_state_token,
                  o.state_token AS occurrence_state_token
                FROM epm.application_workflow_activity a
                JOIN epm.application_workflow_occurrence o USING(
                  workspace_id,application_id,occurrence_id,flow_id)
                WHERE a.workspace_id=%s AND a.application_id=%s
                  AND o.status='Active' AND a.status='Ready'
                  AND (%s::text IS NULL OR
                    (a.occurrence_id,a.activity_id)>(%s,%s))
                ORDER BY a.occurrence_id,a.activity_id LIMIT %s""",(
                scope.workspace_id,scope.application_id,after_occurrence_id,
                after_occurrence_id,after_activity_id,
                _MAX_WORKLIST_SCAN+1)).fetchall()
            cache={};values=[];last=None;more=len(rows)>_MAX_WORKLIST_SCAN
            for row in rows[:_MAX_WORKLIST_SCAN]:
                key=(row["flow_id"],row["flow_state_token"])
                if key not in cache:
                    model=self._workflow(db,scope,*key)
                    if model.digest!=row["flow_digest"]:
                        raise ValueError(
                            "APPLICATION_WORKFLOW_OCCURRENCE_DEFINITION_STALE")
                    resolved=PostgresApplicationWorkflows._validate_references(
                        db,scope,model,available_functions,
                        state["metadata_revision"])
                    cache[key]=(model,resolved)
                model,resolved=cache[key]
                activity=self._activity(model,row["activity_id"])
                try:resolution=self._assignment(db,scope,activity,
                    resolved["members"],require_entitlement=True,now=now,
                    groups=access.groups)
                except ValueError as error:
                    if str(error) in ("APPLICATION_WORKFLOW_ACTIVITY_NOT_ASSIGNED",
                            "APPLICATION_WORKFLOW_ASSIGNMENT_NOT_EFFECTIVE",
                            "APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE"):
                        last=row;continue
                    raise
                if len(values)==limit:more=True;break
                values.append({"occurrenceId":row["occurrence_id"],
                    "occurrenceStateToken":row["occurrence_state_token"],
                    "flowId":row["flow_id"],
                    "flowStateToken":row["flow_state_token"],
                    "definitionDigest":row["flow_digest"],
                    "activityId":row["activity_id"],
                    "activityStateToken":row["state_token"],
                    "name":activity.name,"kind":activity.kind,
                    "destination":dict(activity.destination),
                    "assignmentResolution":resolution})
                last=row
            cursor=({"afterOccurrenceId":last["occurrence_id"],
                "afterActivityId":last["activity_id"]}
                if more and last is not None else None)
            return {"items":values,"nextCursor":cursor}

    def evidence_options(self,scope: ApplicationScope,*,occurrence_id: str,
            activity_id: str,limit: int=50,
            before_committed_revision: int|None=None,
            available_functions: Collection[str])->dict:
        """List only receipts the fixed validator accepts for assigned work.

        Operation identities are opaque selection values.  The caller receives
        bounded business-safe labels and cannot supply function, currentness,
        compiler or result claims.
        """
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,
            "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_LIMIT_INVALID")
        if (before_committed_revision is not None
                and (type(before_committed_revision) is not int
                     or before_committed_revision<1)):
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_CURSOR_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            access=self._prepare(db,scope,"read",EVIDENCE_OPTIONS)
            state=self._context(db,scope,lock=False)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=False)
            if occurrence["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            row=db.execute("""SELECT * FROM epm.application_workflow_activity
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s AND activity_id=%s""",(
                scope.workspace_id,scope.application_id,occurrence_id,
                activity_id)).fetchone()
            if row is None or row["status"]!="Ready":
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_STALE")
            model=self._occurrence_model(db,scope,occurrence)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,state["metadata_revision"])
            activity=self._activity(model,activity_id)
            now=db.execute(
                "SELECT transaction_timestamp() AS now").fetchone()["now"]
            self._assignment(db,scope,activity,resolved["members"],
                require_entitlement=True,now=now,groups=access.groups)
            contract=dict(activity.evidence_contract)
            if contract.get("kind")!="OperationReceipt":
                return {"items":[],"nextBeforeCommittedRevision":None}
            allowed=list(contract["allowedFunctions"])
            rows=db.execute("""SELECT o.operation_id,o.committed_revision,
                    o.committed_at,COALESCE(j.function_name,
                      o.result->>'function') AS function_name
                FROM epm.operation_receipt o
                LEFT JOIN epm.job j ON j.workspace_id=o.workspace_id
                  AND j.application_id=o.application_id
                  AND j.job_id=o.operation_id
                WHERE o.workspace_id=%s AND o.application_id=%s
                  AND (%s::bigint IS NULL OR o.committed_revision<%s)
                  AND COALESCE(j.function_name,o.result->>'function')=ANY(%s)
                ORDER BY o.committed_revision DESC LIMIT %s""",(
                scope.workspace_id,scope.application_id,
                before_committed_revision,before_committed_revision,allowed,
                _MAX_EVIDENCE_SCAN+1)).fetchall()
            overflow=len(rows)>_MAX_EVIDENCE_SCAN
            more=overflow
            examined=rows[:_MAX_EVIDENCE_SCAN]
            items=[]
            last_examined_revision=None
            for position,candidate in enumerate(examined):
                last_examined_revision=candidate["committed_revision"]
                try:
                    certificate=validate_workflow_evidence(db,scope,
                        self.identity,activity,{"kind":"OperationReceipt",
                        "operationId":candidate["operation_id"]},
                        resolved_selection=resolved)
                except ValueError as error:
                    if str(error).startswith("APPLICATION_WORKFLOW_EVIDENCE_"):
                        continue
                    raise
                items.append({
                    "selectionKey":candidate["operation_id"],
                    "label":_EVIDENCE_ACTION_LABELS[
                        certificate.normalized["function"]],
                    "occurredAt":candidate["committed_at"].isoformat(),
                    "outcome":"Committed",
                    "current":certificate.normalized.get(
                        "currentAtValidation",True) is True,
                })
                if len(items)==limit:
                    more=overflow or position+1<len(examined)
                    break
            cursor=(last_examined_revision if more else None)
            return {"items":items,
                "nextBeforeCommittedRevision":cursor}

    def cancel(self,scope: ApplicationScope,*,occurrence_id: str,
               expected_occurrence_state_token: str,
               idempotency_key: str)->dict:
        occurrence_id=_occurrence_id(occurrence_id)
        expected=require_state_token(expected_occurrence_state_token,
            error="APPLICATION_WORKFLOW_OCCURRENCE_STATE_TOKEN_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":CANCEL,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"occurrenceId":occurrence_id,
            "expectedOccurrenceStateToken":expected}
        digest=_canonical_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._prepare(db,scope,"admin",CANCEL)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:return prior
            state=self._context(db,scope,lock=True);self._active(state)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=True)
            if (occurrence["status"]!="Active"
                    or occurrence["state_token"]!=expected):
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            ordinal=occurrence["last_event_ordinal"]+1
            occurrence_token=new_state_token()
            activity_seed=new_state_token()
            revision=state["commit_revision"]+1
            result={"operationId":operation_id,"function":CANCEL,
                "status":"Cancelled","occurrenceId":occurrence_id,
                "occurrenceStateToken":occurrence_token,
                "committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""UPDATE epm.application_workflow_occurrence SET
                status='Cancelled',last_event_ordinal=%s,state_token=%s,
                last_operation_id=%s,
                cancelled_at=transaction_timestamp() WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s""",(ordinal,
                occurrence_token,operation_id,scope.workspace_id,scope.application_id,
                occurrence_id))
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Cancelled',transition_ordinal=transition_ordinal+1,
                state_token=encode(sha256(convert_to(%s||E'\n'||activity_id,
                  'UTF8')),'hex'),
                returned_to_activity_id=NULL WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND status IN('Blocked','Ready','Returned')""",(
                activity_seed,scope.workspace_id,scope.application_id,occurrence_id))
            self._event(db,scope,occurrence_id,ordinal,
                "OccurrenceCancelled",None,operation_id,digest,revision)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            return result

    def _request_cancel_as_task_controller(self,scope: ApplicationScope,
            occurrence_id: str,*,allow_application_admin: bool=False)->dict:
        """Cancel one active occurrence through its governed transition.

        Universal-task control never edits workflow state itself.  It derives
        one stable operation identity from the exact occurrence state and
        delegates to ``cancel``; an acknowledgement retry therefore returns
        the original receipt rather than creating another transition.
        """
        if not allow_application_admin:
            raise ValueError("APPLICATION_WORKFLOW_TASK_ADMIN_REQUIRED")
        occurrence_id=_occurrence_id(occurrence_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            self._prepare(db,scope,"read",READ)
            row=self._occurrence(db,scope,occurrence_id,lock=False)
            if row["status"]=="Cancelled":
                receipt=db.execute("""SELECT result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                      AND operation_id=%s""",(scope.workspace_id,
                    scope.application_id,row["last_operation_id"])).fetchone()
                if (receipt is None
                        or receipt["result"].get("function")!=CANCEL):
                    raise ValueError("APPLICATION_WORKFLOW_TASK_CANCEL_UNAVAILABLE")
                return receipt["result"]
            if row["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_TASK_NOT_INTERRUPTIBLE")
            expected=row["state_token"]
        return self.cancel(scope,occurrence_id=occurrence_id,
            expected_occurrence_state_token=expected,
            idempotency_key=("task-cancel-"+occurrence_id+"-"+expected))

    def complete(self,scope: ApplicationScope,*,occurrence_id: str,
                 activity_id: str,expected_activity_state_token: str,
                 evidence: object,idempotency_key: str,
                 available_functions: Collection[str])->dict:
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,
            "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        expected=require_state_token(expected_activity_state_token,
            error="APPLICATION_WORKFLOW_ACTIVITY_STATE_TOKEN_INVALID")
        if type(evidence) is not dict:
            raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":COMPLETE,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"occurrenceId":occurrence_id,
            "activityId":activity_id,"expectedActivityStateToken":expected,
            "evidence":evidence}
        digest=_canonical_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            access=self._prepare(db,scope,"read",COMPLETE)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:return prior
            state=self._context(db,scope,lock=True);self._active(state)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=True)
            if occurrence["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            row=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s FOR UPDATE""",(scope.workspace_id,
                scope.application_id,occurrence_id,activity_id)).fetchone()
            if (row is None or row["status"]!="Ready"
                    or row["state_token"]!=expected):
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_STALE")
            model=self._occurrence_model(db,scope,occurrence)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,
                state["metadata_revision"])
            activity=self._activity(model,activity_id)
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            assignment=self._assignment(db,scope,activity,
                resolved["members"],require_entitlement=True,now=now,
                groups=access.groups)
            certificate=validate_workflow_evidence(
                db,scope,self.identity,activity,evidence,
                resolved_selection=resolved)
            if certificate.evidence_operation_id==operation_id:
                raise ValueError("APPLICATION_WORKFLOW_EVIDENCE_SELF_REFERENCE")
            rows=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                ORDER BY activity_id FOR UPDATE""",(scope.workspace_id,
                scope.application_id,occurrence_id)).fetchall()
            states={item["activity_id"]:item["status"] for item in rows}
            states[activity_id]="Completed"
            ready=[]
            for candidate in model.activities:
                if (states[candidate.activity_id] in ("Blocked","Returned")
                        and all(states[parent]=="Completed"
                                for parent in candidate.depends_on)):
                    ready.append(candidate.activity_id)
                    states[candidate.activity_id]="Ready"
            completed=all(value=="Completed" for value in states.values())
            activity_ordinal=occurrence["last_event_ordinal"]+1
            last_event_ordinal=(activity_ordinal+1 if completed
                                else activity_ordinal)
            occurrence_token=new_state_token()
            activity_token=new_state_token()
            ready_seed=new_state_token()
            revision=state["commit_revision"]+1
            result={"operationId":operation_id,"function":COMPLETE,
                "status":"Completed" if completed else "Active",
                "occurrenceId":occurrence_id,
                "occurrenceStateToken":occurrence_token,
                "activityId":activity_id,"activityStateToken":activity_token,
                "evidenceDigest":certificate.digest,
                "readyActivityIds":ready,"committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Completed',transition_ordinal=transition_ordinal+1,
                state_token=%s,
                operation_id=%s,completed_by_issuer=%s,
                completed_by_subject_id=%s,
                completed_at=transaction_timestamp(),
                returned_to_activity_id=NULL WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s""",(activity_token,operation_id,self.identity.issuer,
                self.identity.subject_id,scope.workspace_id,
                scope.application_id,occurrence_id,activity_id))
            if ready:
                db.execute("""UPDATE epm.application_workflow_activity SET
                    status='Ready',transition_ordinal=transition_ordinal+1,
                    state_token=encode(sha256(convert_to(%s||E'\n'||activity_id,
                      'UTF8')),'hex'),
                    operation_id=NULL,completed_by_issuer=NULL,
                    completed_by_subject_id=NULL,completed_at=NULL,
                    returned_to_activity_id=NULL WHERE workspace_id=%s
                      AND application_id=%s AND occurrence_id=%s
                      AND activity_id=ANY(%s::text[])""",(ready_seed,scope.workspace_id,
                    scope.application_id,occurrence_id,ready))
            db.execute("""UPDATE epm.application_workflow_occurrence SET
                status=%s,last_event_ordinal=%s,state_token=%s,last_operation_id=%s,
                completed_at=CASE WHEN %s THEN transaction_timestamp()
                                  ELSE NULL END
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s""",("Completed" if completed else
                "Active",last_event_ordinal,occurrence_token,operation_id,completed,
                scope.workspace_id,scope.application_id,occurrence_id))
            self._event(db,scope,occurrence_id,activity_ordinal,
                "ActivityCompleted",activity_id,operation_id,digest,revision,
                evidence={"artifactEvidence":certificate.normalized,
                    "assignmentResolution":assignment},
                evidence_digest=certificate.digest)
            if certificate.evidence_operation_id is not None:
                db.execute("""INSERT INTO
                    epm.application_workflow_evidence_link(workspace_id,
                    application_id,occurrence_id,activity_id,
                    completion_operation_id,evidence_operation_id,
                    evidence_committed_revision,validator_id,
                    validator_version,evidence_digest)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
                    scope.workspace_id,scope.application_id,occurrence_id,
                    activity_id,operation_id,
                    certificate.evidence_operation_id,
                    certificate.evidence_committed_revision,
                    certificate.validator_id,certificate.validator_version,
                    certificate.digest))
            if completed:
                self._event(db,scope,occurrence_id,last_event_ordinal,
                    "OccurrenceCompleted",None,operation_id,digest,revision)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            return result

    def return_review(self,scope: ApplicationScope,*,occurrence_id: str,
                      activity_id: str,expected_activity_state_token: str,
                      reason: str,idempotency_key: str,
                      available_functions: Collection[str])->dict:
        occurrence_id=_occurrence_id(occurrence_id)
        activity_id=_identifier(activity_id,
            "APPLICATION_WORKFLOW_ACTIVITY_ID_INVALID")
        expected=require_state_token(expected_activity_state_token,
            error="APPLICATION_WORKFLOW_ACTIVITY_STATE_TOKEN_INVALID")
        if (type(reason) is not str or not 1<=len(reason)<=1000
                or reason!=reason.strip() or "\x00" in reason):
            raise ValueError("APPLICATION_WORKFLOW_RETURN_REASON_INVALID")
        operation_id=_key(idempotency_key)
        command={"function":RETURN,"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"occurrenceId":occurrence_id,
            "activityId":activity_id,"expectedActivityStateToken":expected,
            "reason":reason}
        digest=_canonical_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            access=self._prepare(db,scope,"read",RETURN)
            prior=self._prior(db,scope,operation_id,digest)
            if prior is not None:return prior
            state=self._context(db,scope,lock=True);self._active(state)
            occurrence=self._occurrence(db,scope,occurrence_id,lock=True)
            if occurrence["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_OCCURRENCE_STALE")
            model=self._occurrence_model(db,scope,occurrence)
            resolved=PostgresApplicationWorkflows._validate_references(
                db,scope,model,available_functions,
                state["metadata_revision"])
            activity=self._activity(model,activity_id)
            if activity.kind!="Review" or activity.return_to is None:
                raise ValueError("APPLICATION_WORKFLOW_RETURN_UNAVAILABLE")
            now=db.execute("SELECT transaction_timestamp() AS now").fetchone()["now"]
            assignment=self._assignment(db,scope,activity,
                resolved["members"],require_entitlement=True,now=now,
                groups=access.groups)
            rows=db.execute("""SELECT * FROM
                epm.application_workflow_activity WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                ORDER BY activity_id FOR UPDATE""",(scope.workspace_id,
                scope.application_id,occurrence_id)).fetchall()
            by_id={row["activity_id"]:row for row in rows}
            review=by_id.get(activity_id);target=by_id.get(activity.return_to)
            if (review is None or review["status"]!="Ready"
                    or review["state_token"]!=expected):
                raise ValueError("APPLICATION_WORKFLOW_ACTIVITY_STALE")
            if target is None or target["status"]!="Completed":
                raise ValueError("APPLICATION_WORKFLOW_RETURN_TARGET_STALE")
            return_target,invalidated=_review_return_invalidation(
                model,activity_id,rows)
            ordinal=occurrence["last_event_ordinal"]+1
            occurrence_token=new_state_token()
            target_token=new_state_token();review_token=new_state_token()
            invalidated_seed=new_state_token()
            revision=state["commit_revision"]+1
            evidence={"kind":"ReviewReturn","reason":reason,
                "targetActivityId":return_target,
                "actor":{"issuer":self.identity.issuer,
                    "subjectId":self.identity.subject_id},
                "returnedAt":now.isoformat(),
                "assignmentResolution":assignment}
            evidence_digest=_canonical_digest(evidence)
            result={"operationId":operation_id,"function":RETURN,
                "status":"Active","occurrenceId":occurrence_id,
                "occurrenceStateToken":occurrence_token,"activityId":activity_id,
                "activityStateToken":review_token,
                "returnedToActivityId":return_target,
                "invalidatedActivityIds":invalidated,
                "evidenceDigest":evidence_digest,
                "committedRevision":revision}
            self._receipt(db,scope,operation_id,digest,revision,result)
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Ready',transition_ordinal=transition_ordinal+1,
                state_token=%s,
                operation_id=NULL,completed_by_issuer=NULL,
                completed_by_subject_id=NULL,completed_at=NULL,
                returned_to_activity_id=NULL WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s""",(target_token,scope.workspace_id,
                scope.application_id,occurrence_id,return_target))
            db.execute("""UPDATE epm.application_workflow_activity SET
                status='Returned',transition_ordinal=transition_ordinal+1,
                state_token=%s,
                operation_id=%s,completed_by_issuer=NULL,
                completed_by_subject_id=NULL,completed_at=NULL,
                returned_to_activity_id=%s WHERE workspace_id=%s
                  AND application_id=%s AND occurrence_id=%s
                  AND activity_id=%s""",(review_token,operation_id,return_target,
                scope.workspace_id,scope.application_id,occurrence_id,
                activity_id))
            if invalidated:
                db.execute("""UPDATE epm.application_workflow_activity SET
                    status='Blocked',transition_ordinal=transition_ordinal+1,
                    state_token=encode(sha256(convert_to(%s||E'\n'||activity_id,
                      'UTF8')),'hex'),
                    operation_id=NULL,completed_by_issuer=NULL,
                    completed_by_subject_id=NULL,completed_at=NULL,
                    returned_to_activity_id=NULL WHERE workspace_id=%s
                      AND application_id=%s AND occurrence_id=%s
                      AND activity_id=ANY(%s::text[])""",(invalidated_seed,scope.workspace_id,
                    scope.application_id,occurrence_id,invalidated))
            db.execute("""UPDATE epm.application_workflow_occurrence SET
                last_event_ordinal=%s,state_token=%s,last_operation_id=%s
                WHERE workspace_id=%s AND application_id=%s
                  AND occurrence_id=%s""",(ordinal,occurrence_token,operation_id,
                scope.workspace_id,scope.application_id,occurrence_id))
            self._event(db,scope,occurrence_id,ordinal,"ActivityReturned",
                activity_id,operation_id,digest,revision,evidence=evidence,
                evidence_digest=evidence_digest)
            db.execute("""UPDATE epm.application_state SET commit_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",(revision,
                scope.workspace_id,scope.application_id))
            return result

    def execute_program(self,scope: ApplicationScope,program: dict,*,
                        idempotency_key: str|None,
                        available_functions: Collection[str])->dict:
        """Validate the public transport envelope and delegate to fixed core."""
        function,arguments=_program(program)
        if function in MUTATIONS:
            if idempotency_key is None:
                raise ValueError(
                    "APPLICATION_WORKFLOW_OCCURRENCE_IDEMPOTENCY_REQUIRED")
        elif idempotency_key is not None:
            raise ValueError(
                "APPLICATION_WORKFLOW_OCCURRENCE_READ_KEY_FORBIDDEN")
        if function==START:
            expected={"flowId","expectedStateToken",
                "expectedMetadataRevision","expectedPolicyRevision",
                "expectedSchemaEpoch"}
            if set(arguments)!=expected:
                raise ValueError("APPLICATION_WORKFLOW_START_ARGUMENTS_INVALID")
            return self.start(scope,flow_id=arguments["flowId"],
                expected_state_token=arguments["expectedStateToken"],
                expected_metadata_revision=arguments["expectedMetadataRevision"],
                expected_policy_revision=arguments["expectedPolicyRevision"],
                expected_schema_epoch=arguments["expectedSchemaEpoch"],
                idempotency_key=idempotency_key,
                available_functions=available_functions)
        if function==READ:
            if not {"occurrenceId"}<=set(arguments)<= {
                    "occurrenceId","eventLimit","afterEventOrdinal"}:
                raise ValueError("APPLICATION_WORKFLOW_READ_ARGUMENTS_INVALID")
            return self.read(scope,arguments["occurrenceId"],
                event_limit=arguments.get("eventLimit",100),
                after_event_ordinal=arguments.get("afterEventOrdinal",0))
        if function==WORKLIST:
            if not set(arguments)<= {"limit","afterOccurrenceId",
                                      "afterActivityId"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_WORKLIST_ARGUMENTS_INVALID")
            return self.worklist(scope,limit=arguments.get("limit",100),
                after_occurrence_id=arguments.get("afterOccurrenceId"),
                after_activity_id=arguments.get("afterActivityId"),
                available_functions=available_functions)
        if function==EVIDENCE_OPTIONS:
            if not {"occurrenceId","activityId"}<=set(arguments)<= {
                    "occurrenceId","activityId","limit",
                    "beforeCommittedRevision"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_EVIDENCE_LIST_ARGUMENTS_INVALID")
            return self.evidence_options(scope,
                occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"],
                limit=arguments.get("limit",50),
                before_committed_revision=arguments.get(
                    "beforeCommittedRevision"),
                available_functions=available_functions)
        if function==COMPLETE:
            if set(arguments)!={"occurrenceId","activityId",
                    "expectedActivityStateToken","evidence"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_COMPLETE_ARGUMENTS_INVALID")
            return self.complete(scope,occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"],
                expected_activity_state_token=arguments["expectedActivityStateToken"],
                evidence=arguments["evidence"],idempotency_key=idempotency_key,
                available_functions=available_functions)
        if function==RETURN:
            if set(arguments)!={"occurrenceId","activityId",
                    "expectedActivityStateToken","reason"}:
                raise ValueError(
                    "APPLICATION_WORKFLOW_RETURN_ARGUMENTS_INVALID")
            return self.return_review(scope,
                occurrence_id=arguments["occurrenceId"],
                activity_id=arguments["activityId"],
                expected_activity_state_token=arguments["expectedActivityStateToken"],
                reason=arguments["reason"],idempotency_key=idempotency_key,
                available_functions=available_functions)
        if set(arguments)!={"occurrenceId","expectedOccurrenceStateToken"}:
            raise ValueError("APPLICATION_WORKFLOW_CANCEL_ARGUMENTS_INVALID")
        return self.cancel(scope,occurrence_id=arguments["occurrenceId"],
            expected_occurrence_state_token=arguments["expectedOccurrenceStateToken"],
            idempotency_key=idempotency_key)

    def _event(self,db,scope: ApplicationScope,occurrence_id: str,
               ordinal: int,event_type: str,activity_id: str|None,
               operation_id: str,command_digest: str,revision: int,*,
               evidence: dict|None=None,evidence_digest: str|None=None)->None:
        db.execute("""INSERT INTO epm.application_workflow_event(workspace_id,
            application_id,occurrence_id,event_ordinal,event_type,activity_id,
            operation_id,actor_issuer,actor_subject_id,command_digest,
            evidence,evidence_digest,committed_revision)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
            scope.workspace_id,scope.application_id,occurrence_id,ordinal,
            event_type,activity_id,operation_id,self.identity.issuer,
            self.identity.subject_id,command_digest,
            Jsonb(evidence) if evidence is not None else None,
            evidence_digest,revision))

    @staticmethod
    def _result(occurrence: dict,activities: list[dict],
                events: list[dict])->dict:
        def instant(value):
            return value.isoformat() if hasattr(value,"isoformat") else value
        return {"occurrenceId":occurrence["occurrence_id"],
            "flowId":occurrence["flow_id"],
            "flowStateToken":occurrence["flow_state_token"],
            "definitionDigest":occurrence["flow_digest"],
            "status":occurrence["status"],
            "occurrenceStateToken":occurrence["state_token"],
            "lastEventOrdinal":occurrence["last_event_ordinal"],
            "startedRevision":occurrence["started_revision"],
            "startedAt":instant(occurrence["started_at"]),
            "completedAt":instant(occurrence["completed_at"]),
            "cancelledAt":instant(occurrence["cancelled_at"]),
            "activities":[{"activityId":row["activity_id"],
                "kind":row["kind"],"status":row["status"],
                "activityStateToken":row["state_token"],
                "operationId":row["operation_id"],
                "completedAt":instant(row["completed_at"]),
                "returnedToActivityId":row["returned_to_activity_id"]}
                for row in activities],
            "events":[{"ordinal":row["event_ordinal"],
                "eventType":row["event_type"],
                "activityId":row["activity_id"],
                "operationId":row["operation_id"],
                "actor":{"issuer":row["actor_issuer"],
                    "subjectId":row["actor_subject_id"]},
                "evidence":row["evidence"],
                "evidenceDigest":row["evidence_digest"],
                "committedRevision":row["committed_revision"],
                "createdAt":instant(row["created_at"])} for row in events]}
