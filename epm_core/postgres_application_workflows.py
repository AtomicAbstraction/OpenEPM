"""Receipt-backed lifecycle for domain-neutral application workflows.

The repository stores immutable workflow definitions and their publication
pointer.  It does not execute activities or validate completion evidence; those
state-machine boundaries are separate so merely saving a definition can never
create business effects.
"""
from __future__ import annotations

import re
from collections.abc import Collection

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_workflow import ApplicationWorkflow,compile_application_workflow
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_application_assignments import PostgresApplicationAssignments
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_selection_preview import resolve_selection_in_transaction


SAVE="application.workflow.save"
PUBLISH="application.workflow.publish"
DEACTIVATE="application.workflow.deactivate"
READ="application.workflow.read"
LIST="application.workflow.list"
MUTATIONS=frozenset((SAVE,PUBLISH,DEACTIVATE))
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
        SAVE:{**mutation,"mode":"immutable_workflow_write","arguments":{
            "definition":"canonical application-task-flow v2",
            "expectedStateRevision":"current workflow state revision",
            **revisions},"result":"immutable workflow version and receipt"},
        PUBLISH:{**mutation,"mode":"atomic_policy_write","arguments":{
            "flowId":"stable workflow ID","version":"exact immutable version",
            "expectedStateRevision":"current workflow state revision",
            **revisions},"result":"active workflow pointer and receipt"},
        DEACTIVATE:{**mutation,"mode":"atomic_policy_write","arguments":{
            "flowId":"stable workflow ID",
            "expectedStateRevision":"current workflow state revision",
            **revisions},"result":"inactive workflow pointer and receipt"},
        READ:{**read,"mode":"read","arguments":{"flowId":"stable workflow ID"},
            "optionalArguments":{"version":"exact immutable version"},
            "result":"verified workflow definition and publication state"},
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


def _version(value: object) -> int:
    if type(value) is not int or value<1:
        raise ValueError("APPLICATION_WORKFLOW_VERSION_INVALID")
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
            "application_workflow_version","application_workflow_state",
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
                or model.version!=row["version"]
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
            key=(ref.assignment_set_id,ref.version,ref.digest)
            if key not in assignment_cache:
                row=db.execute("""SELECT v.*,s.active_version
                    FROM epm.application_assignment_version v
                    JOIN epm.application_assignment_state s USING(
                      workspace_id,application_id,assignment_set_id)
                    WHERE v.workspace_id=%s AND v.application_id=%s
                      AND v.assignment_set_id=%s AND v.version=%s
                      AND v.definition_digest=%s""",(scope.workspace_id,
                    scope.application_id,*key)).fetchone()
                if row is None or row["active_version"]!=ref.version:
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
                      AND application_id=%s AND grid_id=%s AND version=%s""",(
                    scope.workspace_id,scope.application_id,
                    destination["viewId"],destination["version"])).fetchone()
                if view is None or view["canonical_digest"]!=destination["digest"]:
                    raise ValueError("APPLICATION_WORKFLOW_VIEW_UNAVAILABLE")
            elif destination["kind"]=="Artifact":
                kind=destination["artifactKind"]
                read_function={
                    "ApplicationRule":"application.rule.version.read",
                    "CalculatedMember":"calculated.member.version.read",
                    "ApplicationSequence":"rules.numeric_sequence.version.read",
                    "ApplicationSchedule":"schedule.version.read"}[kind]
                if read_function not in functions:
                    raise ValueError("APPLICATION_WORKFLOW_FUNCTION_UNAVAILABLE")
                if kind=="ApplicationSchedule":
                    artifact=db.execute("""SELECT v.definition_digest digest
                        FROM epm.application_schedule_version v
                        JOIN epm.application_schedule_state s
                          USING(workspace_id,application_id,schedule_id)
                        WHERE v.workspace_id=%s AND v.application_id=%s
                          AND v.schedule_id=%s AND v.version=%s
                          AND s.active_version=v.version""",(
                        scope.workspace_id,scope.application_id,
                        destination["artifactId"],
                        destination["version"])).fetchone()
                else:
                    stored_function={
                        "ApplicationRule":"application.rule.plan",
                        "CalculatedMember":"calculated.member.definition",
                        "ApplicationSequence":"rules.numeric_sequence.template"
                    }[kind]
                    artifact=db.execute("""SELECT v.program_digest digest
                        FROM epm.expression_rule_version v
                        JOIN epm.expression_rule_publication p
                          USING(workspace_id,application_id,rule_id,version)
                        WHERE v.workspace_id=%s AND v.application_id=%s
                          AND v.rule_id=%s AND v.version=%s
                          AND v.program->>'function'=%s""",(
                        scope.workspace_id,scope.application_id,
                        destination["artifactId"],destination["version"],
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
    def _result(scope: ApplicationScope,row: dict,pointer: dict|None)->dict:
        model=PostgresApplicationWorkflows._verified(scope,row)
        active=pointer is not None and pointer["active_version"]==model.version
        return {"flowId":model.flow_id,"version":model.version,
            "name":model.name,"definition":row["definition"],
            "definitionDigest":model.digest,
            "status":"Published" if active else "Saved",
            "stateRevision":0 if pointer is None else pointer["state_revision"],
            "createdRevision":row["created_revision"],
            "creator":{"issuer":row["creator_issuer"],
                       "subjectId":row["creator_subject_id"]},
            "createdAt":row["created_at"].isoformat()}

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
                   "expectedSchemaEpoch","expectedStateRevision"}
        if function==SAVE:
            if set(args)!={"definition",*revisions}:
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            model=compile_application_workflow(args["definition"])
            if not isinstance(scope,ApplicationScope) or model.scope!=scope:
                raise ValueError("APPLICATION_WORKFLOW_SCOPE_MISMATCH")
            flow_id,version=model.flow_id,model.version
        elif function==PUBLISH:
            if set(args)!={"flowId","version",*revisions}:
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            flow_id=_identifier(args["flowId"]);version=_version(args["version"])
            model=None
        else:
            if set(args)!={"flowId",*revisions}:
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            flow_id=_identifier(args["flowId"]);version=None;model=None
        expected_state=_revision(args["expectedStateRevision"],
            "STALE_APPLICATION_WORKFLOW_STATE_REVISION")
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
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(
                db,scope.workspace_id)
            state=self._context(db,scope,lock=True)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"write")
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin")
            prior=db.execute("""SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                  AND application_id=%s AND operation_id=%s""",(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if (prior["command_digest"]!=command_digest
                        or prior["actor_id"]!=self.identity.subject_id):
                    raise ValueError("APPLICATION_WORKFLOW_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            if (state["application_status"]!="Active"
                    or state["processing_mode"]!="Active"):
                raise ValueError("APPLICATION_NOT_WRITABLE")
            self._assert_context(state,metadata,policy,schema)
            pointer=db.execute("""SELECT * FROM epm.application_workflow_state
                WHERE workspace_id=%s AND application_id=%s AND flow_id=%s
                FOR UPDATE""",(scope.workspace_id,scope.application_id,
                flow_id)).fetchone()
            current=0 if pointer is None else pointer["state_revision"]
            if current!=expected_state:
                raise ValueError("STALE_APPLICATION_WORKFLOW_STATE_REVISION")
            commit=state["commit_revision"]+1;next_state=current+1
            next_policy=state["policy_revision"]
            if function==SAVE:
                assert model is not None
                latest=0 if pointer is None else pointer["latest_version"]
                if model.version!=latest+1:
                    raise ValueError("APPLICATION_WORKFLOW_VERSION_NOT_NEXT")
                self._validate_references(db,scope,model,available_functions,
                                          metadata)
                definition=model.normalized()
                result={"operationId":idempotency_key,"flowId":flow_id,
                    "version":model.version,"status":"Saved",
                    "definitionDigest":model.digest,"stateRevision":next_state,
                    "metadataRevision":metadata,"policyRevision":next_policy,
                    "schemaEpoch":schema,"committedRevision":commit}
            elif function==PUBLISH:
                row=db.execute("""SELECT * FROM epm.application_workflow_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND flow_id=%s AND version=%s""",(scope.workspace_id,
                    scope.application_id,flow_id,version)).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_WORKFLOW_VERSION_UNAVAILABLE")
                model=self._verified(scope,row)
                self._validate_references(db,scope,model,available_functions,
                                          metadata)
                if pointer is not None and pointer["active_version"]==version:
                    raise ValueError("APPLICATION_WORKFLOW_VERSION_ALREADY_PUBLISHED")
                next_policy+=1
                result={"operationId":idempotency_key,"flowId":flow_id,
                    "version":version,"status":"Published",
                    "definitionDigest":model.digest,"stateRevision":next_state,
                    "policyRevision":next_policy,"committedRevision":commit}
            else:
                if pointer is None or pointer["active_version"] is None:
                    raise ValueError("APPLICATION_WORKFLOW_NOT_PUBLISHED")
                version=pointer["active_version"];next_policy+=1
                result={"operationId":idempotency_key,"flowId":flow_id,
                    "version":version,"status":"Inactive",
                    "stateRevision":next_state,"policyRevision":next_policy,
                    "committedRevision":commit}
            db.execute("""UPDATE epm.application_state SET policy_revision=%s,
                commit_revision=%s WHERE workspace_id=%s AND application_id=%s""",
                (next_policy,commit,scope.workspace_id,scope.application_id))
            db.execute("""INSERT INTO epm.operation_receipt(workspace_id,
                application_id,operation_id,command_digest,actor_id,
                committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""",(
                scope.workspace_id,scope.application_id,idempotency_key,
                command_digest,self.identity.subject_id,commit,Jsonb(result)))
            if function==SAVE:
                db.execute("""INSERT INTO epm.application_workflow_version(
                    workspace_id,application_id,flow_id,version,name,definition,
                    definition_digest,operation_id,created_revision,
                    creator_issuer,creator_subject_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
                    scope.workspace_id,scope.application_id,flow_id,model.version,
                    model.name,Jsonb(definition),model.digest,idempotency_key,
                    commit,self.identity.issuer,self.identity.subject_id))
                for item in model.activities:
                    db.execute("""INSERT INTO
                        epm.application_workflow_assignment_pin(workspace_id,
                        application_id,flow_id,flow_version,activity_id,
                        assignment_set_id,assignment_version,assignment_digest,
                        assignment_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
                        scope.workspace_id,scope.application_id,flow_id,
                        model.version,item.activity_id,
                        item.assignment_ref.assignment_set_id,
                        item.assignment_ref.version,item.assignment_ref.digest,
                        item.assignment_ref.assignment_id))
            active=(version if function==PUBLISH else None if function==DEACTIVATE
                    else pointer["active_version"] if pointer else None)
            latest=(model.version if function==SAVE else pointer["latest_version"])
            db.execute("""INSERT INTO epm.application_workflow_state(
                workspace_id,application_id,flow_id,latest_version,
                active_version,state_revision,operation_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(workspace_id,application_id,flow_id)
                DO UPDATE SET latest_version=EXCLUDED.latest_version,
                  active_version=EXCLUDED.active_version,
                  state_revision=EXCLUDED.state_revision,
                  operation_id=EXCLUDED.operation_id,
                  updated_at=transaction_timestamp()""",(scope.workspace_id,
                scope.application_id,flow_id,latest,active,next_state,
                idempotency_key))
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
                if set(args) not in ({"flowId"},{"flowId","version"}):
                    raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
                flow_id=_identifier(args["flowId"])
                requested=_version(args["version"]) if "version" in args else None
                pointer=db.execute("""SELECT * FROM epm.application_workflow_state
                    WHERE workspace_id=%s AND application_id=%s AND flow_id=%s""",(
                    scope.workspace_id,scope.application_id,flow_id)).fetchone()
                version=requested if requested is not None else (
                    pointer["active_version"] if pointer
                    and pointer["active_version"] is not None else
                    pointer["latest_version"] if pointer else None)
                if version is None:
                    raise ValueError("APPLICATION_WORKFLOW_VERSION_UNAVAILABLE")
                row=db.execute("""SELECT * FROM epm.application_workflow_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND flow_id=%s AND version=%s""",(scope.workspace_id,
                    scope.application_id,flow_id,version)).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_WORKFLOW_VERSION_UNAVAILABLE")
                return {**self._result(scope,row,pointer),
                    "metadataRevision":state["metadata_revision"],
                    "policyRevision":state["policy_revision"],
                    "schemaEpoch":state["schema_epoch"],
                    "commitRevision":state["commit_revision"]}
            if set(args)-{"limit","afterFlowId"}:
                raise ValueError("APPLICATION_WORKFLOW_ARGUMENTS_INVALID")
            limit=args.get("limit",100);after=args.get("afterFlowId")
            if type(limit) is not int or not 1<=limit<=100:
                raise ValueError("APPLICATION_WORKFLOW_LIST_LIMIT_INVALID")
            if after is not None:_identifier(after)
            rows=db.execute("""SELECT DISTINCT ON(v.flow_id) v.*,
                s.latest_version,s.active_version,s.state_revision
                FROM epm.application_workflow_version v
                JOIN epm.application_workflow_state s USING(
                  workspace_id,application_id,flow_id)
                WHERE v.workspace_id=%s AND v.application_id=%s
                  AND v.version=s.latest_version
                  AND (%s::text IS NULL OR v.flow_id>%s)
                ORDER BY v.flow_id,v.version DESC LIMIT %s""",(
                scope.workspace_id,scope.application_id,after,after,
                limit+1)).fetchall()
            values=[self._result(scope,row,row) for row in rows[:limit]]
            return {"workflows":values,"nextAfterFlowId":(
                values[-1]["flowId"] if len(rows)>limit else None),
                "metadataRevision":state["metadata_revision"],
                "policyRevision":state["policy_revision"],
                "schemaEpoch":state["schema_epoch"],
                "commitRevision":state["commit_revision"]}
