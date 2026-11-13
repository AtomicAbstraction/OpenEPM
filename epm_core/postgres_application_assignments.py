"""Receipt-backed domain-neutral application-assignment lifecycle.

Assignments identify responsible principals and review chains over explicit
multidimensional member scopes.  They never grant cube access or execute a
business function.  Every later read, write and task transition remains
subject to current fixed-core authorization.
"""
from __future__ import annotations

import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_assignment import (
    ApplicationAssignmentSet,compile_application_assignment_set)
from .current_object_contract import collection_token,new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


SAVE="application.assignment.save"
ACTIVATE="application.assignment.activate"
DEACTIVATE="application.assignment.deactivate"
READ="application.assignment.read"
LIST="application.assignment.list"
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
        SAVE:{**mutation,"mode":"current_assignment_write","arguments":{
            "definition":"canonical application-assignment-set v1",
            **revisions},"optionalArguments":{
            "expectedStateToken":"required to replace current assignment"},
            "result":"current assignment and state token"},
        ACTIVATE:{**mutation,"mode":"atomic_policy_write","arguments":{
            "assignmentSetId":"stable assignment-set ID",
            "expectedStateToken":"current assignment state token",
            **revisions},"result":"active assignment and fresh state token"},
        DEACTIVATE:{**mutation,"mode":"atomic_policy_write","arguments":{
            "assignmentSetId":"stable assignment-set ID",
            "expectedStateToken":"current assignment state token",
            **revisions},"result":"saved assignment and fresh state token"},
        READ:{**read,"mode":"read","arguments":{
            "assignmentSetId":"stable assignment-set ID"},
            "result":"verified current assignment definition"},
        LIST:{**read,"mode":"read","arguments":{},"optionalArguments":{
            "limit":"1-100","afterAssignmentSetId":"keyset cursor"},
            "result":"bounded latest assignment definitions"}}


def _identifier(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError("APPLICATION_ASSIGNMENT_SET_ID_INVALID")
    return value


def _revision(value: object,code: str) -> int:
    if type(value) is not int or value<0:
        raise ValueError(code)
    return value


def _program(value: object) -> tuple[str,dict]:
    if (type(value) is not dict
            or set(value)!={"languageVersion","function","arguments"}
            or value.get("languageVersion")!=2
            or value.get("function") not in FUNCTIONS
            or type(value.get("arguments")) is not dict):
        raise ValueError("APPLICATION_ASSIGNMENT_PROGRAM_INVALID")
    return value["function"],value["arguments"]


class PostgresApplicationAssignments:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",(
            "application_assignment_definition",))
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope: ApplicationScope) -> None:
        if not isinstance(scope,ApplicationScope):
            raise ValueError("APPLICATION_ASSIGNMENT_SCOPE_INVALID")
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
            raise ValueError("APPLICATION_ASSIGNMENT_STALE_CONTEXT")

    @staticmethod
    def _validate_member_scope(db,scope: ApplicationScope,
            model: ApplicationAssignmentSet) -> None:
        selectors={(dimension,member) for assignment in model.assignments
            for dimension,members in assignment.member_selectors
            for member in members}
        dimensions={dimension for dimension,_ in selectors}
        if dimensions:
            rows=db.execute("""SELECT dimension_id FROM epm.dimension
                WHERE workspace_id=%s AND application_id=%s
                  AND status='Active' AND dimension_id=ANY(%s)""",(
                scope.workspace_id,scope.application_id,
                sorted(dimensions))).fetchall()
            if {row["dimension_id"] for row in rows}!=dimensions:
                raise ValueError("APPLICATION_ASSIGNMENT_DIMENSION_UNAVAILABLE")
        for dimension in sorted(dimensions):
            expected={member for axis,member in selectors if axis==dimension}
            rows=db.execute("""SELECT member_id FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s AND status='Active'
                  AND member_id=ANY(%s)""",(scope.workspace_id,
                scope.application_id,dimension,sorted(expected))).fetchall()
            if {row["member_id"] for row in rows}!=expected:
                raise ValueError("APPLICATION_ASSIGNMENT_MEMBER_UNAVAILABLE")

    @staticmethod
    def _verified(scope: ApplicationScope,row: dict) -> ApplicationAssignmentSet:
        try:model=compile_application_assignment_set(row["definition"])
        except (TypeError,ValueError) as error:
            raise ValueError(
                "APPLICATION_ASSIGNMENT_PERSISTED_DEFINITION_INVALID") from error
        if (model.scope!=scope or model.assignment_set_id!=row["assignment_set_id"]
                or model.digest!=row["definition_digest"]):
            raise ValueError("APPLICATION_ASSIGNMENT_PERSISTED_DIGEST_MISMATCH")
        return model

    @classmethod
    def _result(cls,scope: ApplicationScope,row: dict)->dict:
        model=cls._verified(scope,row)
        return {"assignmentSetId":model.assignment_set_id,
            "stateToken":row["state_token"],"name":model.name,
            "definition":row["definition"],"definitionDigest":model.digest,
            "status":row["status"],
            "updatedBy":{"issuer":row["updater_issuer"],
                       "subjectId":row["updater_subject_id"]},
            "updatedAt":row["updated_at"].isoformat()}

    def execute(self,scope: ApplicationScope,program: object,*,
            idempotency_key: str|None=None)->dict:
        function,args=_program(program)
        if function in READS:
            if idempotency_key is not None:
                raise ValueError("APPLICATION_ASSIGNMENT_IDEMPOTENCY_UNEXPECTED")
            return self.read_program(scope,program)
        if type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None:
            raise ValueError("APPLICATION_ASSIGNMENT_IDEMPOTENCY_KEY_INVALID")
        revisions={"expectedMetadataRevision","expectedPolicyRevision",
                   "expectedSchemaEpoch"}
        if function==SAVE:
            required={"definition",*revisions}
            if set(args) not in (required,required|{"expectedStateToken"}):
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            model=compile_application_assignment_set(args["definition"])
            if not isinstance(scope,ApplicationScope) or model.scope!=scope:
                raise ValueError("APPLICATION_ASSIGNMENT_SCOPE_MISMATCH")
            set_id=model.assignment_set_id
            expected_token=args.get("expectedStateToken")
        else:
            if set(args)!={"assignmentSetId","expectedStateToken",*revisions}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            set_id=_identifier(args["assignmentSetId"]);model=None
            expected_token=args["expectedStateToken"]
        if expected_token is not None:
            require_state_token(expected_token,
                error="APPLICATION_ASSIGNMENT_STATE_TOKEN_INVALID")
        metadata=_revision(args["expectedMetadataRevision"],
            "APPLICATION_ASSIGNMENT_METADATA_REVISION_INVALID")
        policy=_revision(args["expectedPolicyRevision"],
            "APPLICATION_ASSIGNMENT_POLICY_REVISION_INVALID")
        schema=_revision(args["expectedSchemaEpoch"],
            "APPLICATION_ASSIGNMENT_SCHEMA_EPOCH_INVALID")
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
                if prior["command_digest"]!=command_digest or prior["actor_id"]!=self.identity.subject_id:
                    raise ValueError("APPLICATION_ASSIGNMENT_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            if state["application_status"]!="Active" or state["processing_mode"]!="Active":
                raise ValueError("APPLICATION_NOT_WRITABLE")
            self._assert_context(state,metadata,policy,schema)
            current=db.execute("""SELECT * FROM epm.application_assignment_definition
                WHERE workspace_id=%s AND application_id=%s
                  AND assignment_set_id=%s FOR UPDATE""",(
                scope.workspace_id,scope.application_id,set_id)).fetchone()
            if ((current is None)!=(expected_token is None)
                    or current is not None and current["state_token"]!=expected_token):
                raise ValueError("STALE_APPLICATION_ASSIGNMENT_STATE_TOKEN")
            if function==ACTIVATE and current["status"]=="Active":
                raise ValueError("APPLICATION_ASSIGNMENT_ALREADY_ACTIVE")
            if function==DEACTIVATE and current["status"]!="Active":
                raise ValueError("APPLICATION_ASSIGNMENT_NOT_ACTIVE")
            if function==SAVE:
                assert model is not None
                self._validate_member_scope(db,scope,model)
                definition=model.normalized();digest=model.digest
                name=model.name;status="Saved"
            else:
                definition=current["definition"];digest=current["definition_digest"]
                name=current["name"];status="Active" if function==ACTIVATE else "Saved"
            commit=state["commit_revision"]+1
            next_policy=state["policy_revision"]+(function!=SAVE)
            token=new_state_token()
            result={"operationId":idempotency_key,"assignmentSetId":set_id,
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
            db.execute("""INSERT INTO epm.application_assignment_definition(
                workspace_id,application_id,assignment_set_id,state_token,status,
                name,definition,definition_digest,updated_operation_id,
                updater_issuer,updater_subject_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(workspace_id,application_id,assignment_set_id)
                DO UPDATE SET state_token=EXCLUDED.state_token,
                  status=EXCLUDED.status,name=EXCLUDED.name,
                  definition=EXCLUDED.definition,
                  definition_digest=EXCLUDED.definition_digest,
                  updated_operation_id=EXCLUDED.updated_operation_id,
                  updater_issuer=EXCLUDED.updater_issuer,
                  updater_subject_id=EXCLUDED.updater_subject_id,
                  updated_at=transaction_timestamp()""",(scope.workspace_id,
                scope.application_id,set_id,token,status,name,Jsonb(definition),
                digest,idempotency_key,self.identity.issuer,
                self.identity.subject_id))
            return result

    def read_program(self,scope: ApplicationScope,program: object)->dict:
        function,args=_program(program)
        if function not in READS:
            raise ValueError("APPLICATION_ASSIGNMENT_READ_FUNCTION_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"read",function=function)
            state=self._context(db,scope,lock=False)
            if function==READ:
                if set(args)!={"assignmentSetId"}:
                    raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
                row=db.execute("""SELECT * FROM epm.application_assignment_definition
                    WHERE workspace_id=%s AND application_id=%s
                      AND assignment_set_id=%s""",(scope.workspace_id,
                    scope.application_id,_identifier(args["assignmentSetId"]))).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_ASSIGNMENT_UNAVAILABLE")
                return {**self._result(scope,row),
                    "metadataRevision":state["metadata_revision"],
                    "policyRevision":state["policy_revision"],
                    "schemaEpoch":state["schema_epoch"],
                    "commitRevision":state["commit_revision"]}
            if set(args)-{"limit","afterAssignmentSetId","collectionToken"}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            limit=args.get("limit",100);after=args.get("afterAssignmentSetId")
            if type(limit) is not int or not 1<=limit<=100:
                raise ValueError("APPLICATION_ASSIGNMENT_LIST_LIMIT_INVALID")
            if after is not None:_identifier(after)
            rows=db.execute("""SELECT * FROM epm.application_assignment_definition
                WHERE workspace_id=%s AND application_id=%s
                ORDER BY assignment_set_id""",(scope.workspace_id,
                scope.application_id)).fetchall()
            token=collection_token((row["assignment_set_id"],row["state_token"])
                                   for row in rows)
            if "collectionToken" in args and args["collectionToken"]!=token:
                raise ValueError("APPLICATION_ASSIGNMENT_COLLECTION_CHANGED")
            page=[row for row in rows
                  if after is None or row["assignment_set_id"]>after]
            values=[self._result(scope,row) for row in page[:limit]]
            return {"assignmentSets":values,"collectionToken":token,
                "nextAfterAssignmentSetId":(values[-1]["assignmentSetId"]
                    if len(page)>limit else None),
                "metadataRevision":state["metadata_revision"],
                "policyRevision":state["policy_revision"],
                "schemaEpoch":state["schema_epoch"],
                "commitRevision":state["commit_revision"]}
