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
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout


SAVE="application.assignment.save"
PUBLISH="application.assignment.publish"
DEACTIVATE="application.assignment.deactivate"
READ="application.assignment.read"
LIST="application.assignment.list"
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
        SAVE:{**mutation,"mode":"immutable_assignment_write","arguments":{
            "definition":"canonical application-assignment-set v1",
            "expectedStateRevision":"current assignment-set state revision",
            **revisions},"result":"immutable assignment version and receipt"},
        PUBLISH:{**mutation,"mode":"atomic_policy_write","arguments":{
            "assignmentSetId":"stable assignment-set ID",
            "version":"exact immutable version",
            "expectedStateRevision":"current assignment-set state revision",
            **revisions},"result":"active assignment pointer and receipt"},
        DEACTIVATE:{**mutation,"mode":"atomic_policy_write","arguments":{
            "assignmentSetId":"stable assignment-set ID",
            "expectedStateRevision":"current assignment-set state revision",
            **revisions},"result":"inactive assignment pointer and receipt"},
        READ:{**read,"mode":"read","arguments":{
            "assignmentSetId":"stable assignment-set ID"},
            "optionalArguments":{"version":"exact immutable version"},
            "result":"verified assignment definition and publication state"},
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


def _version(value: object) -> int:
    if type(value) is not int or value<1:
        raise ValueError("APPLICATION_ASSIGNMENT_VERSION_INVALID")
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
            "application_assignment_version","application_assignment_state"))
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
                or model.version!=row["version"]
                or model.digest!=row["definition_digest"]):
            raise ValueError("APPLICATION_ASSIGNMENT_PERSISTED_DIGEST_MISMATCH")
        return model

    @classmethod
    def _result(cls,scope: ApplicationScope,row: dict,pointer: dict|None)->dict:
        model=cls._verified(scope,row)
        active=pointer is not None and pointer["active_version"]==model.version
        return {"assignmentSetId":model.assignment_set_id,
            "version":model.version,"name":model.name,
            "definition":row["definition"],"definitionDigest":model.digest,
            "status":"Published" if active else "Saved",
            "stateRevision":0 if pointer is None else pointer["state_revision"],
            "createdRevision":row["created_revision"],
            "creator":{"issuer":row["creator_issuer"],
                       "subjectId":row["creator_subject_id"]},
            "createdAt":row["created_at"].isoformat()}

    def execute(self,scope: ApplicationScope,program: object,*,
            idempotency_key: str|None=None)->dict:
        function,args=_program(program)
        if function in READS:
            if idempotency_key is not None:
                raise ValueError("APPLICATION_ASSIGNMENT_IDEMPOTENCY_UNEXPECTED")
            return self.read_program(scope,program)
        if (type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None):
            raise ValueError("APPLICATION_ASSIGNMENT_IDEMPOTENCY_KEY_INVALID")
        revisions={"expectedMetadataRevision","expectedPolicyRevision",
                   "expectedSchemaEpoch","expectedStateRevision"}
        if function==SAVE:
            if set(args)!={"definition",*revisions}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            model=compile_application_assignment_set(args["definition"])
            if not isinstance(scope,ApplicationScope) or model.scope!=scope:
                raise ValueError("APPLICATION_ASSIGNMENT_SCOPE_MISMATCH")
            set_id,version=model.assignment_set_id,model.version
        elif function==PUBLISH:
            if set(args)!={"assignmentSetId","version",*revisions}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            set_id=_identifier(args["assignmentSetId"])
            version=_version(args["version"]);model=None
        else:
            if set(args)!={"assignmentSetId",*revisions}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            set_id=_identifier(args["assignmentSetId"]);version=None;model=None
        expected_state=_revision(args["expectedStateRevision"],
            "STALE_APPLICATION_ASSIGNMENT_STATE_REVISION")
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
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"write")
            PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"admin")
            prior=db.execute("""SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                  AND application_id=%s AND operation_id=%s""",(
                scope.workspace_id,scope.application_id,
                idempotency_key)).fetchone()
            if prior:
                if (prior["command_digest"]!=command_digest
                        or prior["actor_id"]!=self.identity.subject_id):
                    raise ValueError("APPLICATION_ASSIGNMENT_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            if (state["application_status"]!="Active"
                    or state["processing_mode"]!="Active"):
                raise ValueError("APPLICATION_NOT_WRITABLE")
            self._assert_context(state,metadata,policy,schema)
            pointer=db.execute("""SELECT * FROM epm.application_assignment_state
                WHERE workspace_id=%s AND application_id=%s
                  AND assignment_set_id=%s FOR UPDATE""",(
                scope.workspace_id,scope.application_id,set_id)).fetchone()
            current=0 if pointer is None else pointer["state_revision"]
            if current!=expected_state:
                raise ValueError("STALE_APPLICATION_ASSIGNMENT_STATE_REVISION")
            commit=state["commit_revision"]+1
            next_state=current+1
            next_policy=state["policy_revision"]
            if function==SAVE:
                assert model is not None
                latest=0 if pointer is None else pointer["latest_version"]
                if model.version!=latest+1:
                    raise ValueError("APPLICATION_ASSIGNMENT_VERSION_NOT_NEXT")
                self._validate_member_scope(db,scope,model)
                definition=model.normalized()
                result={"operationId":idempotency_key,"assignmentSetId":set_id,
                    "version":model.version,"status":"Saved",
                    "definitionDigest":model.digest,"stateRevision":next_state,
                    "metadataRevision":metadata,"policyRevision":next_policy,
                    "schemaEpoch":schema,"committedRevision":commit}
            elif function==PUBLISH:
                row=db.execute("""SELECT * FROM epm.application_assignment_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND assignment_set_id=%s AND version=%s""",(
                    scope.workspace_id,scope.application_id,set_id,
                    version)).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_ASSIGNMENT_VERSION_UNAVAILABLE")
                self._verified(scope,row)
                if pointer is not None and pointer["active_version"]==version:
                    raise ValueError("APPLICATION_ASSIGNMENT_VERSION_ALREADY_PUBLISHED")
                next_policy+=1
                result={"operationId":idempotency_key,"assignmentSetId":set_id,
                    "version":version,"status":"Published",
                    "definitionDigest":row["definition_digest"],
                    "stateRevision":next_state,"policyRevision":next_policy,
                    "committedRevision":commit}
            else:
                if pointer is None or pointer["active_version"] is None:
                    raise ValueError("APPLICATION_ASSIGNMENT_NOT_PUBLISHED")
                version=pointer["active_version"];next_policy+=1
                result={"operationId":idempotency_key,"assignmentSetId":set_id,
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
                db.execute("""INSERT INTO epm.application_assignment_version(
                    workspace_id,application_id,assignment_set_id,version,name,
                    definition,definition_digest,operation_id,created_revision,
                    creator_issuer,creator_subject_id)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",(
                    scope.workspace_id,scope.application_id,set_id,model.version,
                    model.name,Jsonb(definition),model.digest,idempotency_key,
                    commit,self.identity.issuer,self.identity.subject_id))
            active=(version if function==PUBLISH else None if function==DEACTIVATE
                    else pointer["active_version"] if pointer else None)
            latest=(model.version if function==SAVE
                    else pointer["latest_version"])
            db.execute("""INSERT INTO epm.application_assignment_state(
                workspace_id,application_id,assignment_set_id,latest_version,
                active_version,state_revision,operation_id)
                VALUES(%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(workspace_id,application_id,assignment_set_id)
                DO UPDATE SET latest_version=EXCLUDED.latest_version,
                  active_version=EXCLUDED.active_version,
                  state_revision=EXCLUDED.state_revision,
                  operation_id=EXCLUDED.operation_id,
                  updated_at=transaction_timestamp()""",(scope.workspace_id,
                scope.application_id,set_id,latest,active,next_state,
                idempotency_key))
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
                if set(args) not in ({"assignmentSetId"},
                                     {"assignmentSetId","version"}):
                    raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
                set_id=_identifier(args["assignmentSetId"])
                requested=_version(args["version"]) if "version" in args else None
                pointer=db.execute("""SELECT *
                    FROM epm.application_assignment_state
                    WHERE workspace_id=%s AND application_id=%s
                      AND assignment_set_id=%s""",(scope.workspace_id,
                    scope.application_id,set_id)).fetchone()
                version=requested if requested is not None else (
                    pointer["active_version"] if pointer
                    and pointer["active_version"] is not None else
                    pointer["latest_version"] if pointer else None)
                if version is None:
                    raise ValueError("APPLICATION_ASSIGNMENT_VERSION_UNAVAILABLE")
                row=db.execute("""SELECT *
                    FROM epm.application_assignment_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND assignment_set_id=%s AND version=%s""",(
                    scope.workspace_id,scope.application_id,set_id,
                    version)).fetchone()
                if row is None:
                    raise ValueError("APPLICATION_ASSIGNMENT_VERSION_UNAVAILABLE")
                return {**self._result(scope,row,pointer),
                    "metadataRevision":state["metadata_revision"],
                    "policyRevision":state["policy_revision"],
                    "schemaEpoch":state["schema_epoch"],
                    "commitRevision":state["commit_revision"]}
            if set(args)-{"limit","afterAssignmentSetId"}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            limit=args.get("limit",100);after=args.get("afterAssignmentSetId")
            if type(limit) is not int or not 1<=limit<=100:
                raise ValueError("APPLICATION_ASSIGNMENT_LIST_LIMIT_INVALID")
            if after is not None:_identifier(after)
            rows=db.execute("""SELECT DISTINCT ON(v.assignment_set_id) v.*,
                s.latest_version,s.active_version,s.state_revision
                FROM epm.application_assignment_version v
                JOIN epm.application_assignment_state s USING(
                  workspace_id,application_id,assignment_set_id)
                WHERE v.workspace_id=%s AND v.application_id=%s
                  AND v.version=s.latest_version
                  AND (%s::text IS NULL OR v.assignment_set_id>%s)
                ORDER BY v.assignment_set_id,v.version DESC LIMIT %s""",(
                scope.workspace_id,scope.application_id,after,after,
                limit+1)).fetchall()
            values=[self._result(scope,row,row) for row in rows[:limit]]
            return {"assignmentSets":values,
                "nextAfterAssignmentSetId":(values[-1]["assignmentSetId"]
                    if len(rows)>limit else None),
                "metadataRevision":state["metadata_revision"],
                "policyRevision":state["policy_revision"],
                "schemaEpoch":state["schema_epoch"],
                "commitRevision":state["commit_revision"]}
