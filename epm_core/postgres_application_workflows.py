"""Receipt-backed current lifecycle for domain-neutral workflows.

The repository stores one current workflow definition per stable flow ID.  It
does not execute activities or validate completion evidence; those state-machine
boundaries are separate so merely saving a definition can never create business
effects.
"""
from __future__ import annotations

import re
from collections.abc import Collection

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_workflow import ApplicationWorkflow,compile_application_workflow
from .current_object_contract import collection_token,new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_application_assignments import PostgresApplicationAssignments
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_selection_preview import resolve_selection_in_transaction


SAVE="application.workflow.save"
ACTIVATE="application.workflow.activate"
DEACTIVATE="application.workflow.deactivate"
READ="application.workflow.read"
LIST="application.workflow.list"
MUTATIONS=frozenset((SAVE,ACTIVATE,DEACTIVATE))
READS=frozenset((READ,LIST))
FUNCTIONS=MUTATIONS|READS
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z")
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")


def catalog() -> dict:
    common={"previewRequired":False,"workClass":"short",
            "requiredCapabilities":[]}
    revisions={"expectedMetadataRevision":"current metadata revision",
        "expectedPolicyRevision":"current policy revision",
        "expectedSchemaEpoch":"current schema epoch"}
    mutation={**common,"permission":"admin","idempotencyRequired":True}
    read={**common,"permission":"read","idempotencyRequired":False}
    return {
        SAVE:{**mutation,"mode":"current_workflow_write","arguments":{
            "definition":"canonical application-task-flow v2",
            **revisions},"optionalArguments":{"expectedStateToken":
            "required to replace current workflow"},
            "result":"current workflow and state token"},
        ACTIVATE:{**mutation,"mode":"atomic_policy_write","arguments":{
            "flowId":"stable workflow ID","expectedStateToken":
            "current workflow state token",**revisions},
            "result":"active current workflow and fresh state token"},
        DEACTIVATE:{**mutation,"mode":"atomic_policy_write","arguments":{
            "flowId":"stable workflow ID",
            "expectedStateToken":"current workflow state token",
            **revisions},"result":"saved current workflow and fresh state token"},
        READ:{**read,"mode":"read","arguments":{"flowId":"stable workflow ID"},
            "result":"verified current workflow definition"},
        LIST:{**read,"mode":"read","arguments":{},"optionalArguments":{
            "limit":"1-100","afterFlowId":"keyset cursor"},
            "result":"bounded latest workflow definitions"}}


def _identifier(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError("APPLICATION_WORKFLOW_FLOW_ID_INVALID")
    return value


def _revision(value: object,code: str) -> int:
    if type(value) is not int or value<0:raise ValueError(code)
    return value


def _program(value: object) -> tuple[str,dict]:
    if (type(value) is not dict
            or set(value)!={"languageVersion","function","arguments"}
            or value.get("languageVersion")!=2
            or value.get("function") not in FUNCTIONS
            or type(value.get("arguments")) is not dict):
        raise ValueError("APPLICATION_WORKFLOW_PROGRAM_INVALID")
    return value["function"],value["arguments"]


class PostgresApplicationWorkflows:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",(
            "application_workflow_definition",
            "application_workflow_assignment_pin"))
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope: ApplicationScope) -> None:
        if not isinstance(scope,ApplicationScope):
            raise ValueError("APPLICATION_WORKFLOW_SCOPE_INVALID")
        configure_lock_wait(db);configure_statement_timeout(db,5000)
        PostgresNumericFactStore._set_scope(db,scope)

    @staticmethod
    def _context(db,scope: ApplicationScope,*,lock: bool) -> dict:
        row=db.execute("""SELECT s.metadata_revision,s.policy_revision,
            s.schema_epoch,s.commit_revision,s.processing_mode,
            a.status application_status
            FROM epm.application_state s JOIN epm.application a
              USING(workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s"""+
            (" FOR UPDATE OF s" if lock else ""),
            (scope.workspace_id,scope.application_id)).fetchone()
        if row is None:raise ValueError("APPLICATION_UNAVAILABLE")
        return row

    @staticmethod
    def _assert_context(state: dict,metadata: int,policy: int,schema: int)->None:
        if (state["metadata_revision"]!=metadata
                or state["policy_revision"]!=policy
                or state["schema_epoch"]!=schema):
            raise ValueError("APPLICATION_WORKFLOW_STALE_CONTEXT")

    @staticmethod
    def _verified(scope: ApplicationScope,row: dict)->ApplicationWorkflow:
        try:model=compile_application_workflow(row["definition"])
        except (TypeError,ValueError) as error:
            raise ValueError(
                "APPLICATION_WORKFLOW_PERSISTED_DEFINITION_INVALID") from error
        if (model.scope!=scope or model.flow_id!=row["flow_id"]
                or model.digest!=row["definition_digest"]):
            raise ValueError("APPLICATION_WORKFLOW_PERSISTED_DIGEST_MISMATCH")
        return model

    @staticmethod
    def _functions(value: Collection[str] | None)->frozenset[str]:
        if (value is None or isinstance(value,(str,bytes))
                or any(type(item) is not str for item in value)):
            raise ValueError("APPLICATION_WORKFLOW_FUNCTION_CATALOG_REQUIRED")
        return frozenset(value)-FUNCTIONS

    @classmethod
    def _validate_references(cls,db,scope: ApplicationScope,
            model: ApplicationWorkflow,available_functions: Collection[str],
            metadata_revision: int) -> dict:
        functions=cls._functions(available_functions)
        selection=model.normalized()["selection"]
        resolved=resolve_selection_in_transaction(db,scope,selection,
                                                  metadata_revision)
        assignment_cache={}
        for activity in model.activities:
            ref=activity.assignment_ref
            key=(ref.assignment_set_id,ref.state_token,ref.digest)
            if key not in assignment_cache:
                row=db.execute("""SELECT *
                    FROM epm.application_assignment_definition
                    WHERE workspace_id=%s AND application_id=%s
                      AND assignment_set_id=%s AND state_token=%s
                      AND definition_digest=%s AND status='Active'""",(scope.workspace_id,
                    scope.application_id,*key)).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE")
                assignment_cache[key]=PostgresApplicationAssignments._verified(
                    scope,row)
            if ref.assignment_id not in {
                    item.assignment_id for item in assignment_cache[key].assignments}:
                raise ValueError("APPLICATION_WORKFLOW_ASSIGNMENT_UNAVAILABLE")
            destination=dict(activity.destination)
            if destination["kind"]=="CubeView":
                view=db.execute("""SELECT canonical_digest
                    FROM epm.saved_grid_definition WHERE workspace_id=%s
                      AND application_id=%s AND grid_id=%s""",(
                    scope.workspace_id,scope.application_id,
                    destination["viewId"])).fetchone()
                if view is None or view["canonical_digest"]!=destination["digest"]:
                    raise ValueError("APPLICATION_WORKFLOW_VIEW_UNAVAILABLE")
            elif destination["kind"]=="Artifact":
                kind=destination["artifactKind"]
                read_function={
                    "ApplicationRule":"application.rule.read",
                    "CalculatedMember":"calculated.member.read",
                    "ApplicationSequence":"rules.numeric_sequence.read",
                    "ApplicationSchedule":"schedule.read"}[kind]
                if read_function not in functions:
                    raise ValueError("APPLICATION_WORKFLOW_FUNCTION_UNAVAILABLE")
                if kind=="ApplicationSchedule":
                    artifact=db.execute("""SELECT definition_digest digest
                        FROM epm.application_schedule_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND schedule_id=%s AND state_token=%s
                          AND status='Active'""",(
                        scope.workspace_id,scope.application_id,
                        destination["artifactId"],
                        destination["stateToken"])).fetchone()
                else:
                    stored_function={
                        "ApplicationRule":"application.rule.plan",
                        "CalculatedMember":"calculated.member.definition",
                        "ApplicationSequence":"rules.numeric_sequence.template"
                    }[kind]
                    artifact=db.execute("""SELECT program_digest digest
                        FROM epm.expression_rule_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND rule_id=%s AND state_token=%s AND status='Active'
                          AND program->>'function'=%s""",(
                        scope.workspace_id,scope.application_id,
                        destination["artifactId"],destination["stateToken"],
                        stored_function)).fetchone()
                if (artifact is None or artifact["digest"]!=destination["digest"]):
                    raise ValueError("APPLICATION_WORKFLOW_ARTIFACT_UNAVAILABLE")
            elif destination["function"] not in functions:
                raise ValueError("APPLICATION_WORKFLOW_FUNCTION_UNAVAILABLE")
            evidence=dict(activity.evidence_contract)
            if evidence["kind"]=="OperationReceipt" and not set(
                    evidence["allowedFunctions"])<=functions:
                raise ValueError("APPLICATION_WORKFLOW_FUNCTION_UNAVAILABLE")
        return resolved

    @staticmethod
    def _result(scope: ApplicationScope,row: dict)->dict:
        model=PostgresApplicationWorkflows._verified(scope,row)
        return {"flowId":model.flow_id,"stateToken":row["state_token"],
            "name":model.name,"definition":row["definition"],
            "definitionDigest":model.digest,
            "status":row["status"],
            "updatedBy":{"issuer":row["updater_issuer"],
                       "subjectId":row["updater_subject_id"]},
            "updatedAt":row["updated_at"].isoformat()}

    def execute(self,scope: ApplicationScope,program: object,*,
            idempotency_key: str|None=None,
            available_functions: Collection[str]|None=None)->dict:
        function,args=_program(program)
        if function in READS:
            if idempotency_key is not None:
                raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_UNEXPECTED")
            return self.read_program(scope,program)
        if type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None:
            raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_KEY_INVALID")
        revisions={"expectedMetadataRevision","expectedPolicyRevision",
                   "expectedSchemaEpoch"}
        if function==SAVE:
            required={"definition",*revisions}
            if set(args) not in (required,required|{"expectedStateToken"}):
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            model=compile_application_workflow(args["definition"])
            if not isinstance(scope,ApplicationScope) or model.scope!=scope:
                raise ValueError("APPLICATION_WORKFLOW_SCOPE_MISMATCH")
            flow_id=model.flow_id;expected_token=args.get("expectedStateToken")
        else:
            if set(args)!={"flowId","expectedStateToken",*revisions}:
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            flow_id=_identifier(args["flowId"]);model=None
            expected_token=args["expectedStateToken"]
        if expected_token is not None:
            require_state_token(expected_token,error="APPLICATION_WORKFLOW_STATE_TOKEN_INVALID")
        metadata=_revision(args["expectedMetadataRevision"],
            "APPLICATION_WORKFLOW_METADATA_REVISION_INVALID")
        policy=_revision(args["expectedPolicyRevision"],
            "APPLICATION_WORKFLOW_POLICY_REVISION_INVALID")
        schema=_revision(args["expectedSchemaEpoch"],
            "APPLICATION_WORKFLOW_SCHEMA_EPOCH_INVALID")
        command_digest=_canonical_digest({"scope":[scope.workspace_id,
            scope.application_id],"identity":[self.identity.issuer,
            self.identity.subject_id],"program":program})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            state=self._context(db,scope,lock=True)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"write")
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin")
            prior=db.execute("""SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                  AND application_id=%s AND operation_id=%s""",(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior["command_digest"]!=command_digest or prior["actor_id"]!=self.identity.subject_id:
                    raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            if state["application_status"]!="Active" or state["processing_mode"]!="Active":
                raise ValueError("APPLICATION_NOT_WRITABLE")
            self._assert_context(state,metadata,policy,schema)
            current=db.execute("""SELECT * FROM epm.application_workflow_definition
                WHERE workspace_id=%s AND application_id=%s AND flow_id=%s
                FOR UPDATE""",(scope.workspace_id,scope.application_id,flow_id)).fetchone()
            if ((current is None)!=(expected_token is None)
                    or current is not None and current["state_token"]!=expected_token):
                raise ValueError("STALE_APPLICATION_WORKFLOW_STATE_TOKEN")
            if function==SAVE and current is not None and db.execute(
                    """SELECT 1 FROM epm.application_workflow_occurrence
                       WHERE workspace_id=%s AND application_id=%s AND flow_id=%s
                         AND status='Active' LIMIT 1""",(scope.workspace_id,
                         scope.application_id,flow_id)).fetchone() is not None:
                raise ValueError("APPLICATION_WORKFLOW_ACTIVE_OCCURRENCES")
            if function==ACTIVATE and current["status"]=="Active":
                raise ValueError("APPLICATION_WORKFLOW_ALREADY_ACTIVE")
            if function==DEACTIVATE and current["status"]!="Active":
                raise ValueError("APPLICATION_WORKFLOW_NOT_ACTIVE")
            if function==SAVE:
                assert model is not None
                self._validate_references(db,scope,model,available_functions,metadata)
                definition=model.normalized();digest=model.digest;name=model.name;status="Saved"
            else:
                definition=current["definition"];digest=current["definition_digest"]
                name=current["name"];status="Active" if function==ACTIVATE else "Saved"
            commit=state["commit_revision"]+1
            next_policy=state["policy_revision"]+(function!=SAVE)
            token=new_state_token()
            result={"operationId":idempotency_key,"flowId":flow_id,
                "stateToken":token,"status":status,"definitionDigest":digest,
                "metadataRevision":metadata,"policyRevision":next_policy,
                "schemaEpoch":schema}
            db.execute("""UPDATE epm.application_state SET policy_revision=%s,
                commit_revision=%s WHERE workspace_id=%s AND application_id=%s""",
                (next_policy,commit,scope.workspace_id,scope.application_id))
            db.execute("""INSERT INTO epm.operation_receipt(workspace_id,
                application_id,operation_id,command_digest,actor_id,
                committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""",(
                scope.workspace_id,scope.application_id,idempotency_key,
                command_digest,self.identity.subject_id,commit,Jsonb(result)))
            db.execute("""INSERT INTO epm.application_workflow_definition(
                workspace_id,application_id,flow_id,state_token,status,name,
                definition,definition_digest,updated_operation_id,
                updater_issuer,updater_subject_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(workspace_id,application_id,flow_id)
                DO UPDATE SET state_token=EXCLUDED.state_token,
                  status=EXCLUDED.status,name=EXCLUDED.name,
                  definition=EXCLUDED.definition,
                  definition_digest=EXCLUDED.definition_digest,
                  updated_operation_id=EXCLUDED.updated_operation_id,
                  updater_issuer=EXCLUDED.updater_issuer,
                  updater_subject_id=EXCLUDED.updater_subject_id,
                  updated_at=transaction_timestamp()""",(scope.workspace_id,
                scope.application_id,flow_id,token,status,name,Jsonb(definition),
                digest,idempotency_key,self.identity.issuer,
                self.identity.subject_id))
            if function==SAVE:
                db.execute("""DELETE FROM epm.application_workflow_assignment_pin
                    WHERE workspace_id=%s AND application_id=%s AND flow_id=%s""",
                    (scope.workspace_id,scope.application_id,flow_id))
                for item in model.activities:
                    db.execute("""INSERT INTO epm.application_workflow_assignment_pin(
                        workspace_id,application_id,flow_id,activity_id,
                        assignment_set_id,assignment_state_token,assignment_digest,
                        assignment_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",(
                        scope.workspace_id,scope.application_id,flow_id,
                        item.activity_id,item.assignment_ref.assignment_set_id,
                        item.assignment_ref.state_token,item.assignment_ref.digest,
                        item.assignment_ref.assignment_id))
            return result

    def read_program(self,scope: ApplicationScope,program: object)->dict:
        function,args=_program(program)
        if function not in READS:
            raise ValueError("APPLICATION_WORKFLOW_READ_FUNCTION_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"read",function=function)
            state=self._context(db,scope,lock=False)
            if function==READ:
                if set(args)!={"flowId"}:
                    raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
                row=db.execute("""SELECT * FROM epm.application_workflow_definition
                    WHERE workspace_id=%s AND application_id=%s AND flow_id=%s""",
                    (scope.workspace_id,scope.application_id,
                     _identifier(args["flowId"]))).fetchone()
                if row is None:raise ValueError("APPLICATION_WORKFLOW_UNAVAILABLE")
                return {**self._result(scope,row),
                    "metadataRevision":state["metadata_revision"],
                    "policyRevision":state["policy_revision"],
                    "schemaEpoch":state["schema_epoch"],
                    "commitRevision":state["commit_revision"]}
            if set(args)-{"limit","afterFlowId","collectionToken"}:
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            limit=args.get("limit",100);after=args.get("afterFlowId")
            if type(limit) is not int or not 1<=limit<=100:
                raise ValueError("APPLICATION_WORKFLOW_LIST_LIMIT_INVALID")
            if after is not None:_identifier(after)
            rows=db.execute("""SELECT * FROM epm.application_workflow_definition
                WHERE workspace_id=%s AND application_id=%s ORDER BY flow_id""",
                (scope.workspace_id,scope.application_id)).fetchall()
            token=collection_token((row["flow_id"],row["state_token"]) for row in rows)
            if "collectionToken" in args and args["collectionToken"]!=token:
                raise ValueError("APPLICATION_WORKFLOW_COLLECTION_CHANGED")
            page=[row for row in rows if after is None or row["flow_id"]>after]
            values=[self._result(scope,row) for row in page[:limit]]
            return {"workflows":values,"collectionToken":token,
                "nextAfterFlowId":(values[-1]["flowId"] if len(page)>limit else None),
                "metadataRevision":state["metadata_revision"],
                "policyRevision":state["policy_revision"],
                "schemaEpoch":state["schema_epoch"],
                "commitRevision":state["commit_revision"]}
