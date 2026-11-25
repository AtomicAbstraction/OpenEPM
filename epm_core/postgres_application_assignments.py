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
    FORMAT, ApplicationAssignmentSet, assignment_definition_schema,
    assignment_identifier_schema, compile_application_assignment_set)
from .current_object_contract import (
    STATE_TOKEN_PATTERN, new_state_token, require_state_token)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_definition_lifecycle import (
    governance_revisions, read_governance_definition, read_governance_definition_page)
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


def assignment_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = assignment_identifier_schema()
    nullable_identifier = {"anyOf": [identifier, {"type": "null"}]}
    token = {"type": "string", "pattern": "^" + STATE_TOKEN_PATTERN.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    revision = {"type": "integer", "minimum": 0}
    revisions = {"metadataRevision": revision, "policyRevision": revision, "schemaEpoch": revision}
    expected = dict.fromkeys(("expectedMetadataRevision", "expectedPolicyRevision", "expectedSchemaEpoch"), revision)
    observed = {**revisions, "commitRevision": revision}
    summary = {"assignmentSetId": identifier, "stateToken": token, "definitionDigest": token,
               "status": {"enum": ["Saved", "Active"]}}
    definition = assignment_definition_schema()
    record = {**summary, "name": {"type": "string", "minLength": 1, "maxLength": 200},
              "definition": definition,
              "updatedBy": obj({"issuer": {"type": "string"}, "subjectId": {"type": "string"}}),
              "updatedAt": {"type": "string"}}
    example_id = "example-assignment"
    proof_token = "a" * 64
    if function == LIST:
        arguments = obj({"limit": {**revision, "minimum": 1, "maximum": 100},
                        "afterAssignmentSetId": nullable_identifier, "collectionToken": token}, [])
        result = obj({"assignmentSets": {"type": "array", "maxItems": 100, "items": obj(record)},
                      "collectionToken": token, "nextAfterAssignmentSetId": nullable_identifier, **observed})
        examples = [
            read_example(function, {"limit": 1}, name="List the first bounded assignment page",
                         binding="Choose a currently readable application in discovery."),
            read_example(function, {"limit": 1, "afterAssignmentSetId": example_id, "collectionToken": proof_token},
                         name="Continue the same assignment collection",
                         binding="Copy nextAfterAssignmentSetId and collectionToken from the previous page. A null cursor ends the list.")]
    elif function == READ:
        arguments = obj({"assignmentSetId": identifier})
        result = obj({**record, **observed})
        examples = [read_example(function, {"assignmentSetId": example_id}, name="Inspect the current assignment set",
            binding="Replace example-assignment with an assignmentSetId from an authorized list in the same application.")]
    else:
        pins = dict.fromkeys(expected, 1)
        if function == SAVE:
            arguments = obj({"definition": definition, **expected,
                             "expectedStateToken": {"anyOf": [token, {"type": "null"}]}}, ["definition", *expected])
            example_definition = {"format": FORMAT, "workspaceId": "example-workspace", "applicationId": "example-application",
                "assignmentSetId": example_id, "name": "Scoped review", "effectiveFrom": "2026-01-01T00:00:00+00:00",
                "effectiveTo": None, "assignments": [{"assignmentId": "review", "name": "Review inputs",
                    "subjects": ["example-subject"], "groups": [], "memberSelectors": {},
                    "reviewerChain": [{"kind": "Subject", "id": "example-reviewer"}],
                    "dueAt": "2035-01-01T00:00:00+00:00", "controls": {"reassignable": False,
                        "maxReassignments": 0, "delegationAllowed": False, "maxDelegationDepth": 0,
                        "delegationExpiresAt": None}}]}
            create = {"definition": example_definition, **pins}
            binding = ("Bind the definition to the routed application, known principals, intended dates and current "
                       "metadata, policy and schema revisions from application.state.read.")
            examples = [read_example(function, create, name="Save a new assignment definition", binding=binding),
                        read_example(function, {**create, "expectedStateToken": proof_token},
                            name="Replace the exact current assignment definition", binding=binding +
                            " Use the stateToken and exact definition from application.assignment.read before editing.")]
        else:
            arguments = obj({"assignmentSetId": identifier, "expectedStateToken": token, **expected})
            examples = [read_example(function, {"assignmentSetId": example_id, "expectedStateToken": proof_token, **pins},
                name="Activate the exact saved assignment" if function == ACTIVATE else "Deactivate the exact active assignment",
                binding="Use assignmentSetId, stateToken and revision pins from an exact current assignment read.")]
        result = obj({**summary, **revisions, "status": {"const": "Active" if function == ACTIVATE else "Saved"},
            "operationId": {"type": "string", "pattern": "^" + _KEY.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}})
    contract = read_contract(function, arguments, result, owner="PostgresApplicationAssignments",
        examples=examples, semantic_rules=[
            "Assignment definitions express responsibility and review. Execution and data access each require their own current grants.",
            "The compiler checks identifiers, date ranges, uniqueness, and member-reference limits. Save also verifies referenced dimensions and members.",
            "Save leaves the definition in Saved state. Activate and Deactivate change workflow availability and advance the policy revision.",
            "A workflow can pin an exact assignment state. Changing that assignment returns APPLICATION_ASSIGNMENT_WORKFLOW_REFERENCE_CONFLICT and leaves both definitions intact.",
            "Reads and list pages return definitions and revision pins from the same database snapshot. "
            "Mutation results are exact operation receipts.",
            *(["Current dimensional READ covers all member scopes before a complete assignment definition is returned. Protected and absent definitions share the same unavailable outcome. Protected list continuations bind the current actor and scope."] if function in READS else []),
        ])
    contract["programContract"]["recovery"] = (
        "Restart list discovery on APPLICATION_ASSIGNMENT_COLLECTION_CHANGED. On a stale write, read the current definition "
        "and revisions before proposing a new intent. Retry the exact signed packet to recover an unanswered operation. "
        "After admission expires, current administrators can recover its original receipt only if it committed.")
    return contract


def catalog() -> dict:
    common={"previewRequired":False,"workClass":"short",
            "requiredCapabilities":[]}
    revisions={"expectedMetadataRevision":"current metadata revision",
        "expectedPolicyRevision":"current policy revision",
        "expectedSchemaEpoch":"current schema epoch"}
    mutation={**common,"permission":"admin","idempotencyRequired":True}
    read={**common,"permission":"read","idempotencyRequired":False}
    functions = {
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
            "limit":"1-100","afterAssignmentSetId":"keyset cursor",
            "collectionToken":"collection pin returned by the previous page"},
            "result":"bounded latest assignment definitions"}}
    return {function: {**entry, **assignment_program_contract(function)}
            for function, entry in functions.items()}


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
            idempotency_key: str|None=None,replay_only: bool=False)->dict|None:
        function,args=_program(program)
        if function in READS:
            if idempotency_key is not None or replay_only:
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
        if function != SAVE or expected_token is not None:
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
            if replay_only:db.execute("SET TRANSACTION READ ONLY")
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(
                db,scope.workspace_id)
            state=None if replay_only else self._context(db,scope,lock=True)
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
            if replay_only:return None
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
            # Assignment and workflow definition writers share this locked
            # application state. Preserve the exact pin checked by the FK.
            if current is not None and db.execute("""SELECT 1
                FROM epm.application_workflow_assignment_pin
                WHERE workspace_id=%s AND application_id=%s
                  AND assignment_set_id=%s LIMIT 1""",
                (scope.workspace_id,scope.application_id,set_id)).fetchone():
                raise ValueError("APPLICATION_ASSIGNMENT_WORKFLOW_REFERENCE_CONFLICT")
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
            access = PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,"read",function=function)
            if function==READ:
                if set(args)!={"assignmentSetId"}:
                    raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
                row = read_governance_definition(db, scope, 'Assignment', _identifier(args['assignmentSetId']),
                    identity=self.identity, function=function, access=access)
                if row is None:
                    raise ValueError("APPLICATION_ASSIGNMENT_UNAVAILABLE")
                return {**self._result(scope, row), **governance_revisions(row)}
            if set(args)-{"limit","afterAssignmentSetId","collectionToken"}:
                raise ValueError("APPLICATION_ASSIGNMENT_ARGUMENTS_INVALID")
            limit=args.get("limit",100);after=args.get("afterAssignmentSetId")
            if type(limit) is not int or not 1<=limit<=100:
                raise ValueError("APPLICATION_ASSIGNMENT_LIST_LIMIT_INVALID")
            if after is not None:_identifier(after)
            page, token, revisions = read_governance_definition_page(db, scope, 'Assignment',
                after=after, limit=limit, identity=self.identity, function=function, access=access)
            if "collectionToken" in args and args["collectionToken"]!=token:
                raise ValueError("APPLICATION_ASSIGNMENT_COLLECTION_CHANGED")
            values=[self._result(scope,row) for row in page[:limit]]
            return {"assignmentSets":values,"collectionToken":token,
                "nextAfterAssignmentSetId":(values[-1]["assignmentSetId"]
                    if len(page)>limit else None),
                **revisions}
