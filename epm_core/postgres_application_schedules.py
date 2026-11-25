"""One current durable schedule definition for an active application rule."""
from __future__ import annotations

from datetime import datetime,timezone
from hashlib import sha256
import json,re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_schedule import (
    CANCELLATION_POLICY, FORMAT, SCHEDULE_ID_PATTERN as _ID, canonical_digest,
    execution_bindings, schedule_definition_schema, schedule_identifier_schema, validate_definition)
from .current_object_contract import STATE_TOKEN_PATTERN,new_state_token,require_state_token
from .recurrence import CatchUpPolicy,due_from_interval
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
    VerifiedExecutionIdentity,VerifiedIdentity,assert_nonowner_role)
from .postgres_application_rules import PostgresApplicationRules
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .python_program_execution import FunctionValidator

SAVE="schedule.save";ACTIVATE="schedule.activate";DEACTIVATE="schedule.deactivate"
READ="schedule.read";LIST="schedule.list"
FUNCTIONS=frozenset((SAVE,ACTIVATE,DEACTIVATE,READ,LIST))
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_HEX32=re.compile(r"[0-9a-f]{32}\Z")


def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("ascii")).hexdigest()


def schedule_program_contract(function: str) -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = schedule_identifier_schema()
    token = {"type": "string", "pattern": "^" + STATE_TOKEN_PATTERN.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    revision = {"type": "integer", "minimum": 0}
    expected = dict.fromkeys(("expectedMetadataRevision", "expectedPolicyRevision", "expectedSchemaEpoch"), revision)
    page_size = {"type": "integer", "minimum": 1, "maximum": 100}
    definition = schedule_definition_schema()
    example_id = "example-schedule"
    example_token = "a" * 64
    current = {"scheduleId": example_id}
    if function in (READ, LIST):
        record = obj({"scheduleId": identifier, "stateToken": token, "definition": definition,
            "definitionDigest": token, "status": {"enum": ["Saved", "Active"]},
            "targetStatus": {"enum": ["Current", "Stale"]},
            "effectiveStatus": {"enum": ["Saved", "Active", "Blocked"]},
            "reasonCode": {"enum": [None, "APPLICATION_SCHEDULE_TARGET_STALE"]},
            "updatedAt": {"type": "string"}})
    if function == LIST:
        cursor = {"anyOf": [identifier, {"type": "null"}]}
        arguments = obj({"limit": {**page_size, "default": 100}, "afterScheduleId": cursor}, [])
        result = obj({"schedules": {"type": "array", "maxItems": 100, "items": record}, "nextAfterScheduleId": cursor})
        examples = [read_example(function, {"limit": 20}, name="Read the first schedule page",
            binding="Choose a currently readable application in discovery."),
            read_example(function, {"limit": 20, "afterScheduleId": example_id}, name="Continue a schedule list",
            binding="Copy nextAfterScheduleId from the prior response. A null cursor ends the list. Each page reads current state.")]
    elif function == READ:
        sequence = {"type": "integer", "minimum": 1, "maximum": 2**63 - 1}
        occurrence = {"type": "string", "pattern": r"^[0-9a-f]{32}(?![\s\S])"}
        page_request = obj({"expectedStateToken": token, "limit": page_size, "afterSequence": sequence},
                           ["expectedStateToken", "limit"])
        row = obj({"occurrenceId": occurrence, "taskId": {"type": "string", "pattern": r"^v:[0-9a-f]{32}(?![\s\S])"},
            "sequence": sequence, "dueAt": {"type": "string"}, "nativeStatus": {"type": "string"},
            "status": {"type": "string"}, "scheduleStateToken": token, "currentPin": {"type": "boolean"},
            "workflowId": {"anyOf": [occurrence, {"type": "null"}]}})
        page = obj({"scheduleStateToken": token, "items": {"type": "array", "maxItems": 100, "items": row},
            "hasMore": {"type": "boolean"}, "nextAfterSequence": {"type": ["integer", "null"], "minimum": 1, "maximum": 2**63 - 1}})
        arguments = obj({"scheduleId": identifier, "occurrences": page_request}, ["scheduleId"])
        result = {"oneOf": [obj({"defined": {"const": False}, "schedule": {"type": "null"}}),
            obj({"defined": {"const": True}, "schedule": record, "occurrences": page}, ["defined", "schedule"])]}
        first = {"expectedStateToken": example_token, "limit": 20}
        binding = "Use scheduleId and schedule.stateToken from a definition read in the same application."
        examples = [read_example(function, current, name="Inspect the current schedule definition",
            binding="Replace example-schedule with a scheduleId from an authorized list."),
            read_example(function, {**current, "occurrences": first}, name="Read the first visible occurrence page", binding=binding),
            read_example(function, {**current, "occurrences": {**first, "afterSequence": 10}},
                name="Continue the visible occurrence history", binding=binding +
                " Use nextAfterSequence only from the previous visible page with the same current schedule token.")]
    else:
        pins = dict.fromkeys(expected, 1)
        receipt = {"operationId": {"type": "string", "pattern": "^" + _KEY.pattern.removesuffix(r"\Z") + r"(?![\s\S])"},
            "scheduleId": identifier, "stateToken": token, "policyRevision": revision,
            "status": {"const": "Active" if function == ACTIVATE else "Saved"}}
        if function == SAVE:
            arguments = obj({"definition": definition, **expected, "expectedStateToken": {"type": ["string", "null"], "pattern": token["pattern"]}},
                            ["definition", *expected])
            result = obj({**receipt, "definitionDigest": token})
            create = {"definition": {"format": FORMAT, **current, "target": {"kind": "ApplicationRule",
                "ruleId": "example-rule", "stateToken": example_token, "programDigest": "b" * 64},
                "bindings": {}, "pov": [], "recurrence": {"kind": "FixedInterval", "intervalSeconds": 3600,
                    "firstDueAt": "2035-01-01T00:00:00Z", "catchUpPolicy": "latest", "maxCatchUp": 1},
                "retryPolicy": {"maxAttempts": 3, "backoffSeconds": 60, "needsInspectionAfter": True},
                "cancellationPolicy": CANCELLATION_POLICY, "delegation": {"delegationId": "example-delegation",
                    "stateToken": "c" * 64}}, **pins}
            binding = ("Use ruleId, stateToken and programDigest from application.rule.read, current execution delegation "
                "scoped to the schedule and application.rule.run, exact rule bindings and a chosen UTC due time. "
                "Use revision pins from application.state.read and obtain admission for the exact effect.")
            examples = [read_example(function, create, name="Save a new schedule", binding=binding),
                read_example(function, {**create, "expectedStateToken": example_token}, name="Replace the exact current schedule",
                    binding=binding + " Start with the definition and stateToken from schedule.read.")]
        else:
            arguments = obj({"scheduleId": identifier, "expectedStateToken": token, **expected})
            result = obj(receipt)
            examples = [read_example(function, {**current, "expectedStateToken": example_token, **pins},
                name="Activate the exact saved schedule" if function == ACTIVATE else "Deactivate the exact active schedule",
                binding="Use schedule.read for the current schedule token, application.state.read for revision pins, and obtain admission for the exact effect.")]
    contract = read_contract(function, arguments, result, owner="PostgresApplicationSchedules", examples=examples,
        semantic_rules=[
            "Save leaves the schedule Saved. Lifecycle changes rotate its token and advance the policy revision.",
            "The fixed owner checks current authority, schedule semantics, pinned rule and delegation, revision fences and exact receipts.",
            "Each occurrence page uses the current schedule token and current task visibility. Each item retains its original schedule token.",
            "Definition listing is a bounded live keyset walk. Reads do not materialize or control worker occurrences.",
        ])
    contract["programContract"]["recovery"] = (
        "On APPLICATION_SCHEDULE_STALE_CONTEXT or APPLICATION_SCHEDULE_OCCURRENCE_CURSOR_INVALID, read the current "
        "schedule without a cursor and restart the visible history from its first page. For a stale effect, refresh "
        "the current schedule, rule, delegation and application pins before proposing a new intent. Resolve unknown "
        "outcomes through the exact original operation receipt or authorized replay of the original admission.")
    return contract


def catalog():
    common={"requiredCapabilities":[],"previewRequired":False,"workClass":"short"}
    mutation={**common,"mode":"atomic_configuration","permission":"admin",
              "idempotencyRequired":True}
    read={**common,"mode":"read_only","permission":"read","idempotencyRequired":False}
    revisions={"expectedMetadataRevision":"current metadata revision",
        "expectedPolicyRevision":"current policy revision",
        "expectedSchemaEpoch":"current schema epoch"}
    functions = {
      SAVE:{**mutation,"arguments":{"definition":"current schedule definition",**revisions},
        "optionalArguments":{"expectedStateToken":"required to replace current schedule"},
        "result":"current Saved schedule and state token"},
      ACTIVATE:{**mutation,"arguments":{"scheduleId":"stable schedule ID",
        "expectedStateToken":"current schedule state token",**revisions},
        "result":"current Active schedule and rotated state token"},
      DEACTIVATE:{**mutation,"arguments":{"scheduleId":"stable schedule ID",
        "expectedStateToken":"current schedule state token",**revisions},
        "result":"current Saved schedule and rotated state token"},
      READ:{**read,"arguments":{"scheduleId":"stable schedule ID"},
        "optionalArguments":{"occurrences":
            "{expectedStateToken: current schedule token, limit: integer 1-100, afterSequence?: positive integer from this schedule's visible page}"},
        "result":"current schedule definition, lifecycle state and target currentness; optional bounded owner/admin-visible occurrence task page, with original pins distinct from current schedule"},
      LIST:{**read,"arguments":{},"optionalArguments":{"limit":"1-100",
        "afterScheduleId":"stable keyset cursor"},
        "result":"current schedule page with effective target state"}}
    return {function: {**entry, **schedule_program_contract(function)} for function, entry in functions.items()}


def _occurrence_id(scope,schedule_id,state_token,due_at,*,schema_epoch):
    if (not isinstance(scope,ApplicationScope) or type(schedule_id) is not str
            or _ID.fullmatch(schedule_id) is None or type(schema_epoch) is not int
            or schema_epoch<0 or type(state_token) is not str
            or re.fullmatch(r"[0-9a-f]{64}",state_token) is None
            or type(due_at) is not datetime or due_at.tzinfo is None
            or due_at.utcoffset()!=timezone.utc.utcoffset(due_at)):
        raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_INVALID")
    raw=json.dumps(["openepm-application-occurrence-v3",scope.workspace_id,
        scope.application_id,schema_epoch,schedule_id,state_token,
        due_at.astimezone(timezone.utc).isoformat()],separators=(",",":"),
        ensure_ascii=True).encode("ascii")
    return sha256(raw).hexdigest()[:32]


class PostgresApplicationSchedules:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",(
            "application_schedule_definition","application_schedule_occurrence"))
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def _scope(db,scope):
        if not isinstance(scope,ApplicationScope):raise ValueError("APPLICATION_SCHEDULE_SCOPE_INVALID")
        configure_statement_timeout(db,5000);configure_lock_wait(db)
        PostgresNumericFactStore._set_scope(db,scope)

    @staticmethod
    def _arguments(program,function):
        if (type(program) is not dict or set(program)!={"languageVersion","function","arguments"}
                or program.get("languageVersion")!=2 or program.get("function")!=function
                or type(program.get("arguments")) is not dict):
            raise ValueError("APPLICATION_SCHEDULE_PROGRAM_INVALID")
        return program["arguments"]

    @staticmethod
    def _revisions(value,metadata,policy,schema):
        if (value is None or value["metadata_revision"]!=metadata
                or value["policy_revision"]!=policy or value["schema_epoch"]!=schema):
            raise ValueError("APPLICATION_SCHEDULE_STALE_CONTEXT")

    @staticmethod
    def _execution_identity(row):
        kind=row.get("execution_authority_kind");issued=row.get("execution_token_issued_at")
        issuer=row["execution_issuer"]
        if kind=="HumanToken":
            if type(issued) is not int or issued<=0:raise ValueError("TOKEN_ISSUE_TIME_UNAVAILABLE")
        elif kind=="Technical":
            if issued is not None or not issuer.startswith("urn:openepm:"):
                raise ValueError("TECHNICAL_AUTHORITY_INVALID")
        else:raise ValueError("TOKEN_ISSUE_TIME_UNAVAILABLE")
        return VerifiedExecutionIdentity(issuer,row["execution_subject"],
            tuple(row.get("execution_groups") or ()),issued_at=issued,
            authorization_scope_digest=row["authorization_scope_digest"])

    @staticmethod
    def _assert_authorization_scope(db,scope,row,*,function):
        identity=PostgresApplicationSchedules._execution_identity(row)
        access=PostgresAccessChecker.check_in_transaction(db,identity,scope,"write")
        PostgresAccessChecker.check_in_transaction(db,identity,scope,"rule_run",
            function="application.rule.run")
        current=resolve_effective_dimensional_scope(db,identity,scope,access=access,
            function=function).scope_digest
        if row.get("authorization_scope_digest")!=current:
            raise AccessDenied("APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED")
        return current

    @staticmethod
    def _result(row):
        target=row["definition"].get("target",{})
        target_current=(row.get("current_rule_state_token") is not None
            and row.get("current_rule_status")=="Active"
            and row["current_rule_state_token"]==row["rule_state_token"]
            and row.get("current_rule_program_digest")==row["rule_program_digest"]
            and target.get("stateToken")==row["rule_state_token"]
            and target.get("programDigest")==row["rule_program_digest"])
        return {"scheduleId":row["schedule_id"],"stateToken":row["state_token"],
            "definition":row["definition"],"definitionDigest":row["definition_digest"],
            "status":row["status"],"targetStatus":"Current" if target_current else "Stale",
            "effectiveStatus":row["status"] if target_current else "Blocked",
            "reasonCode":None if target_current else "APPLICATION_SCHEDULE_TARGET_STALE",
            "updatedAt":row["updated_at"].isoformat()}

    @staticmethod
    def _read_columns():
        return '''schedule.*,rule.state_token AS current_rule_state_token,
            rule.status AS current_rule_status,
            rule.program_digest AS current_rule_program_digest FROM
            epm.application_schedule_definition schedule LEFT JOIN
            epm.expression_rule_definition rule ON
              rule.workspace_id=schedule.workspace_id AND
              rule.application_id=schedule.application_id AND
              rule.rule_id=schedule.rule_id'''

    @staticmethod
    def _cancel_stale_occurrences(db,scope,schedule_id,current_token):
        """Stop fresh work without claiming that an admitted effect vanished.

        The caller holds application_state. Linked work remains claimable for
        control/receipt reconciliation after rotation. Preserve parked intent;
        no parent/job locks or per-occurrence scans are added to definition save.
        """
        db.execute('''UPDATE epm.application_schedule_occurrence SET
            status=CASE
              WHEN status='needs_inspection' THEN 'needs_inspection'
              WHEN application_rule_workflow_id IS NOT NULL THEN 'cancel_requested'
              WHEN status='ready' AND claim_generation=0 AND attempt_count=0
                THEN 'cancelled'
              ELSE 'needs_inspection' END,
            inspection_origin_status=CASE
              WHEN status='needs_inspection' OR
                (application_rule_workflow_id IS NULL AND NOT
                  (status='ready' AND claim_generation=0 AND attempt_count=0))
                THEN 'cancel_requested' ELSE NULL END,
            claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
            next_attempt_at=NULL,error_code='APPLICATION_SCHEDULE_TARGET_STALE',
            updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s
              AND schedule_state_token<>%s AND status IN
              ('ready','running','submitted','cancel_requested','needs_inspection')''',
            (scope.workspace_id,scope.application_id,schedule_id,current_token))

    @staticmethod
    def _cancellation_disposition(row,parent):
        if parent is not None and parent['status'] in (
                'published','partially_published','failed','cancelled'):
            return parent['status']
        # A parked cancellation is not automatically rearmed by replacement.
        if row['status']=='needs_inspection':
            return 'needs_inspection'
        if parent is not None:
            return ('needs_inspection' if parent['status']=='needs_inspection'
                    else 'cancel_requested')
        if (row['application_rule_workflow_id'] is None and row['status']=='ready'
                and row['claim_generation']==0 and row['attempt_count']==0):
            return 'cancelled'
        return 'needs_inspection'

    @staticmethod
    def _lock_schedule(db,scope,schedule_id):
        """Serialize definition changes with worker child admission."""
        db.execute('''SELECT pg_advisory_xact_lock(hashtextextended(
            'epm.application.schedule:'||%s||':'||%s||':'||%s,0))''',(
            scope.workspace_id,scope.application_id,schedule_id))

    def execute(self,scope,program,*,idempotency_key=None,registry=None,
                compiler_version="application-rule-v1",replay_only=False):
        function=program.get("function") if type(program) is dict else None
        if function not in FUNCTIONS:raise ValueError("APPLICATION_SCHEDULE_FUNCTION_INVALID")
        args=self._arguments(program,function)
        if replay_only and function not in (SAVE,ACTIVATE,DEACTIVATE):
            raise ValueError("OPERATION_ADMISSION_EXPIRED")
        replay={"replay_only":True} if replay_only else {}
        rev={"expectedMetadataRevision","expectedPolicyRevision","expectedSchemaEpoch"}
        if function==SAVE:
            if set(args) not in ({"definition",*rev},{"definition","expectedStateToken",*rev}):
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            if registry is None and not replay_only:raise ValueError("APPLICATION_SCHEDULE_REGISTRY_REQUIRED")
            return self.save(scope,args["definition"],expected_state_token=args.get("expectedStateToken"),
                expected_metadata_revision=args["expectedMetadataRevision"],
                expected_policy_revision=args["expectedPolicyRevision"],
                expected_schema_epoch=args["expectedSchemaEpoch"],idempotency_key=idempotency_key,
                registry=registry,compiler_version=compiler_version,**replay)
        if function in (ACTIVATE,DEACTIVATE):
            if set(args)!={"scheduleId","expectedStateToken",*rev}:
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            return self.set_active(scope,args["scheduleId"],active=function==ACTIVATE,
                expected_state_token=args["expectedStateToken"],
                expected_metadata_revision=args["expectedMetadataRevision"],
                expected_policy_revision=args["expectedPolicyRevision"],
                expected_schema_epoch=args["expectedSchemaEpoch"],idempotency_key=idempotency_key,**replay)
        if idempotency_key is not None:raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_UNEXPECTED")
        if function==READ:
            if set(args)=={"scheduleId","occurrences"}:
                self._occurrence_arguments(args["occurrences"])
                return self.read(scope,args["scheduleId"],occurrences=args["occurrences"])
            if set(args)!={"scheduleId"}:raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            return self.read(scope,args["scheduleId"])
        if set(args)-{"limit","afterScheduleId"}:raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        return self.list(scope,limit=args.get("limit",100),after_schedule_id=args.get("afterScheduleId"))

    def save(self,scope,definition,*,expected_state_token,
             expected_metadata_revision,expected_policy_revision,expected_schema_epoch,
             idempotency_key,registry,compiler_version,replay_only=False):
        canonical=validate_definition(definition)
        if expected_state_token is not None:
            require_state_token(expected_state_token,error="APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        if (any(type(v) is not int or v<0 for v in (expected_metadata_revision,
                expected_policy_revision,expected_schema_epoch))
                or type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None
                or not replay_only and not callable(getattr(registry,"validate_operation",None))
                or type(compiler_version) is not str or not compiler_version):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        target=canonical["target"]
        command={"scope":[scope.workspace_id,scope.application_id],
            "identity":[self.identity.issuer,self.identity.subject_id],"function":SAVE,
            "definition":canonical,"expectedStateToken":expected_state_token,
            "expectedMetadataRevision":expected_metadata_revision,
            "expectedPolicyRevision":expected_policy_revision,
            "expectedSchemaEpoch":expected_schema_epoch}
        command_digest=_digest(command);definition_digest=canonical_digest(canonical)
        # Return an already committed exact retry before revalidating mutable
        # current dependencies.  The receipt is the effect authority; a later
        # rule edit must not turn a successful retry into an ambiguous failure.
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin",function=SAVE)
            prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
                WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior["command_digest"]!=command_digest or prior["actor_id"]!=self.identity.subject_id:
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            if replay_only:return None
        sealed=PostgresApplicationRules(self.dsn,identity=self.identity).seal_published(
            scope,target["ruleId"],registry=registry,bindings=execution_bindings(canonical),
            compiler_version=compiler_version,expected_state_token=target["stateToken"],
            expected_program_digest=target["programDigest"])
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin",function=SAVE)
            prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
                WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior["command_digest"]!=command_digest or prior["actor_id"]!=self.identity.subject_id:
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            state=db.execute('''SELECT metadata_revision,policy_revision,schema_epoch,commit_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',(
                scope.workspace_id,scope.application_id)).fetchone()
            self._revisions(state,expected_metadata_revision,expected_policy_revision,expected_schema_epoch)
            self._lock_schedule(db,scope,canonical["scheduleId"])
            current=db.execute('''SELECT * FROM epm.application_schedule_definition
                WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s FOR UPDATE''',(
                scope.workspace_id,scope.application_id,canonical["scheduleId"])).fetchone()
            if ((current is None)!=(expected_state_token is None)
                    or current is not None and current["state_token"]!=expected_state_token):
                raise ValueError("APPLICATION_SCHEDULE_STATE_CONFLICT")
            if (current is not None and current["dispatch_claimant"] is not None
                    and current["dispatch_lease_until"] is not None
                    and current["dispatch_lease_until"]>datetime.now(timezone.utc)):
                raise ValueError("APPLICATION_SCHEDULE_BUSY")
            rule=db.execute('''SELECT state_token,status,program_digest
                FROM epm.expression_rule_definition WHERE workspace_id=%s AND application_id=%s
                  AND rule_id=%s''',(scope.workspace_id,scope.application_id,target["ruleId"])).fetchone()
            if (rule is None or rule["status"]!="Active" or rule["state_token"]!=target["stateToken"]
                    or rule["program_digest"]!=target["programDigest"]):
                raise ValueError("APPLICATION_SCHEDULE_TARGET_INVALID")
            delegation=canonical["delegation"]
            authority=db.execute('''SELECT issuer,subject_id,verified_groups,authorization_scope_digest
                FROM epm.execution_delegation_definition WHERE workspace_id=%s AND application_id=%s
                  AND delegation_id=%s AND state_token=%s AND status='Active' ''',(
                scope.workspace_id,scope.application_id,delegation["delegationId"],
                delegation["stateToken"])).fetchone()
            allowed=(authority is not None and db.execute('''SELECT epm.execution_delegation_is_current(
                %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(scope.workspace_id,
                scope.application_id,delegation["delegationId"],delegation["stateToken"],
                authority["issuer"],authority["subject_id"],"application.rule.run",
                canonical["scheduleId"])).fetchone()["allowed"])
            if not allowed:raise ValueError("APPLICATION_SCHEDULE_AUTHORITY_INVALID")
            if (authority["issuer"],authority["subject_id"])==(
                    self.identity.issuer,self.identity.subject_id):
                if type(self.identity.issued_at) is not int or self.identity.issued_at<=0:
                    raise ValueError("DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED")
                token_issued,authority_kind=self.identity.issued_at,"HumanToken"
            elif authority["issuer"].startswith("urn:openepm:"):
                token_issued,authority_kind=None,"Technical"
            else:raise ValueError("DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED")
            authority_row={"execution_issuer":authority["issuer"],
                "execution_subject":authority["subject_id"],"execution_groups":authority["verified_groups"],
                "authorization_scope_digest":authority["authorization_scope_digest"],
                "execution_token_issued_at":token_issued,"execution_authority_kind":authority_kind}
            self._assert_authorization_scope(db,scope,authority_row,function=SAVE)
            revision=state["commit_revision"]+1;token=new_state_token()
            result={"operationId":idempotency_key,"scheduleId":canonical["scheduleId"],
                "stateToken":token,"status":"Saved","definitionDigest":definition_digest,
                "policyRevision":state["policy_revision"]+1}
            db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
                command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                scope.workspace_id,scope.application_id,idempotency_key,command_digest,
                self.identity.subject_id,revision,Jsonb(result)))
            db.execute('''INSERT INTO epm.application_schedule_definition(
                workspace_id,application_id,schedule_id,state_token,status,definition,definition_digest,
                rule_id,rule_state_token,rule_program_digest,execution_issuer,
                execution_subject,delegation_id,delegation_state_token,updated_operation_id,
                execution_groups,authorization_scope_digest,execution_token_issued_at,
                execution_authority_kind,last_due_at,dispatch_generation,dispatch_claimant,
                dispatch_lease_until,dispatch_error_code,dispatch_failure_count,dispatch_next_attempt_at)
                VALUES(%s,%s,%s,%s,'Saved',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                  NULL,0,NULL,NULL,NULL,0,NULL)
                ON CONFLICT(workspace_id,application_id,schedule_id) DO UPDATE SET
                  state_token=EXCLUDED.state_token,status='Saved',definition=EXCLUDED.definition,
                  definition_digest=EXCLUDED.definition_digest,rule_id=EXCLUDED.rule_id,
                  rule_state_token=EXCLUDED.rule_state_token,rule_program_digest=EXCLUDED.rule_program_digest,
                  execution_issuer=EXCLUDED.execution_issuer,
                  execution_subject=EXCLUDED.execution_subject,delegation_id=EXCLUDED.delegation_id,
                  delegation_state_token=EXCLUDED.delegation_state_token,
                  updated_operation_id=EXCLUDED.updated_operation_id,
                  execution_groups=EXCLUDED.execution_groups,
                  authorization_scope_digest=EXCLUDED.authorization_scope_digest,
                  execution_token_issued_at=EXCLUDED.execution_token_issued_at,
                  execution_authority_kind=EXCLUDED.execution_authority_kind,last_due_at=NULL,
                  dispatch_claimant=NULL,dispatch_lease_until=NULL,dispatch_error_code=NULL,
                  dispatch_failure_count=0,dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()''',(
                scope.workspace_id,scope.application_id,canonical["scheduleId"],token,Jsonb(canonical),
                definition_digest,target["ruleId"],target["stateToken"],target["programDigest"],
                authority["issuer"],authority["subject_id"],
                delegation["delegationId"],delegation["stateToken"],idempotency_key,
                authority["verified_groups"],authority["authorization_scope_digest"],token_issued,authority_kind))
            self._cancel_stale_occurrences(db,scope,canonical["scheduleId"],token)
            db.execute('''UPDATE epm.application_state SET policy_revision=policy_revision+1,
                commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(
                revision,scope.workspace_id,scope.application_id))
            return result

    def set_active(self,scope,schedule_id,*,active,expected_state_token,
                   expected_metadata_revision,expected_policy_revision,expected_schema_epoch,
                   idempotency_key,replay_only=False):
        if (type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None
                or type(active) is not bool or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None
                or any(type(v) is not int or v<0 for v in (expected_metadata_revision,
                    expected_policy_revision,expected_schema_epoch))):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        require_state_token(expected_state_token,error="APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        function=ACTIVATE if active else DEACTIVATE
        command={"scope":[scope.workspace_id,scope.application_id],
            "identity":[self.identity.issuer,self.identity.subject_id],"function":function,
            "scheduleId":schedule_id,"expectedStateToken":expected_state_token,
            "expectedMetadataRevision":expected_metadata_revision,
            "expectedPolicyRevision":expected_policy_revision,"expectedSchemaEpoch":expected_schema_epoch}
        digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute("SET TRANSACTION READ ONLY")
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin",function=function)
            prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
                WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior["command_digest"]!=digest or prior["actor_id"]!=self.identity.subject_id:
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
            if replay_only:return None
            state=db.execute('''SELECT metadata_revision,policy_revision,schema_epoch,commit_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',(
                scope.workspace_id,scope.application_id)).fetchone()
            self._revisions(state,expected_metadata_revision,expected_policy_revision,expected_schema_epoch)
            self._lock_schedule(db,scope,schedule_id)
            row=db.execute('''SELECT * FROM epm.application_schedule_definition WHERE workspace_id=%s
                AND application_id=%s AND schedule_id=%s FOR UPDATE''',(
                scope.workspace_id,scope.application_id,schedule_id)).fetchone()
            if row is None:raise ValueError("APPLICATION_SCHEDULE_UNAVAILABLE")
            if row["state_token"]!=expected_state_token:raise ValueError("APPLICATION_SCHEDULE_STATE_CONFLICT")
            desired="Active" if active else "Saved"
            if row["status"]==desired:raise ValueError(
                "APPLICATION_SCHEDULE_ALREADY_ACTIVE" if active else "APPLICATION_SCHEDULE_ALREADY_INACTIVE")
            if active:
                target=row["definition"]["target"]
                rule=db.execute('''SELECT state_token,status,program_digest
                    FROM epm.expression_rule_definition WHERE workspace_id=%s AND application_id=%s
                      AND rule_id=%s''',(scope.workspace_id,scope.application_id,row["rule_id"])).fetchone()
                if (rule is None or rule["status"]!="Active" or rule["state_token"]!=row["rule_state_token"]
                        or rule["program_digest"]!=row["rule_program_digest"]
                        or target["stateToken"]!=row["rule_state_token"]):
                    raise ValueError("APPLICATION_SCHEDULE_TARGET_STALE")
                allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                    %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(scope.workspace_id,
                    scope.application_id,row["delegation_id"],row["delegation_state_token"],
                    row["execution_issuer"],row["execution_subject"],"application.rule.run",schedule_id
                    )).fetchone()["allowed"]
                if not allowed:raise ValueError("APPLICATION_SCHEDULE_AUTHORITY_INVALID")
                self._assert_authorization_scope(db,scope,row,function=ACTIVATE)
            revision=state["commit_revision"]+1;token=new_state_token()
            result={"operationId":idempotency_key,"scheduleId":schedule_id,"stateToken":token,
                "status":desired,"policyRevision":state["policy_revision"]+1}
            db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
                command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                scope.workspace_id,scope.application_id,idempotency_key,digest,self.identity.subject_id,
                revision,Jsonb(result)))
            db.execute('''UPDATE epm.application_schedule_definition SET state_token=%s,status=%s,
                updated_operation_id=%s,last_due_at=NULL,dispatch_error_code=NULL,
                dispatch_failure_count=0,dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s''',(
                token,desired,idempotency_key,scope.workspace_id,scope.application_id,schedule_id))
            self._cancel_stale_occurrences(db,scope,schedule_id,token)
            db.execute('''UPDATE epm.application_state SET policy_revision=policy_revision+1,
                commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(
                revision,scope.workspace_id,scope.application_id))
            return result

    def materialize_due(self,scope,schedule_id,*,dispatch_claim=None):
        if not isinstance(scope,ApplicationScope) or type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None:
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        if dispatch_claim is not None:
            required={"workspace_id","application_id","schedule_id","dispatch_generation","claimant","schema_epoch"}
            if type(dispatch_claim) is not dict or not required<=set(dispatch_claim):
                raise ValueError("APPLICATION_SCHEDULE_DISPATCH_CLAIM_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            row=db.execute('''SELECT s.*,state.schema_epoch,clock_timestamp() AS server_now
                FROM epm.application_schedule_definition s JOIN epm.application_state state
                  USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s
                  AND s.schedule_id=%s AND s.status='Active' AND state.processing_mode='Active'
                FOR UPDATE OF s''',(scope.workspace_id,scope.application_id,schedule_id)).fetchone()
            if row is None:raise ValueError("APPLICATION_SCHEDULE_INACTIVE")
            if dispatch_claim is not None and ((dispatch_claim["workspace_id"],dispatch_claim["application_id"],
                    dispatch_claim["schedule_id"])!=(scope.workspace_id,scope.application_id,schedule_id)
                    or row["schema_epoch"]!=dispatch_claim["schema_epoch"]
                    or row["dispatch_generation"]!=dispatch_claim["dispatch_generation"]
                    or row["dispatch_claimant"]!=dispatch_claim["claimant"]
                    or row["dispatch_lease_until"] is None or row["dispatch_lease_until"]<=row["server_now"]):
                raise ValueError("APPLICATION_SCHEDULE_STALE_DISPATCH_CLAIM")
            definition=validate_definition(row["definition"])
            if definition["scheduleId"]!=schedule_id or canonical_digest(definition)!=row["definition_digest"]:
                raise ValueError("APPLICATION_SCHEDULE_DEFINITION_CORRUPT")
            target=definition["target"]
            rule=db.execute('''SELECT state_token,status,program_digest FROM
                epm.expression_rule_definition WHERE workspace_id=%s AND application_id=%s
                  AND rule_id=%s''',(scope.workspace_id,scope.application_id,row["rule_id"])).fetchone()
            if (rule is None or rule["status"]!="Active"
                    or rule["state_token"]!=row["rule_state_token"]
                    or rule["program_digest"]!=row["rule_program_digest"]
                    or target["stateToken"]!=row["rule_state_token"]
                    or target["programDigest"]!=row["rule_program_digest"]):
                return {"scheduleId":schedule_id,"stateToken":row["state_token"],
                    "status":"Blocked","reasonCode":"APPLICATION_SCHEDULE_TARGET_STALE",
                    "occurrences":[]}
            allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(scope.workspace_id,scope.application_id,
                row["delegation_id"],row["delegation_state_token"],row["execution_issuer"],
                row["execution_subject"],"application.rule.run",schedule_id)).fetchone()["allowed"]
            if not allowed:return {"scheduleId":schedule_id,"stateToken":row["state_token"],
                "status":"Blocked","reasonCode":"APPLICATION_SCHEDULE_AUTHORITY_INVALID","occurrences":[]}
            try:self._assert_authorization_scope(db,scope,row,function="schedule.materialize")
            except AccessDenied:return {"scheduleId":schedule_id,"stateToken":row["state_token"],
                "status":"Blocked","reasonCode":"APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED","occurrences":[]}
            recurrence=definition["recurrence"]
            first=datetime.fromisoformat(recurrence["firstDueAt"].replace("Z","+00:00"))
            policy=CatchUpPolicy(recurrence["catchUpPolicy"])
            due=due_from_interval(first_due_at=first,interval_seconds=recurrence["intervalSeconds"],
                last_due_at=row["last_due_at"],through=row["server_now"],policy=policy,
                maximum=recurrence["maxCatchUp"])
            if not due and policy is CatchUpPolicy.SKIP:
                skipped=due_from_interval(first_due_at=first,interval_seconds=recurrence["intervalSeconds"],
                    last_due_at=row["last_due_at"],through=row["server_now"],
                    policy=CatchUpPolicy.LATEST,maximum=1)
                if skipped:
                    db.execute('''UPDATE epm.application_schedule_definition SET last_due_at=%s,
                        updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s
                          AND schedule_id=%s AND state_token=%s''',(skipped[-1],scope.workspace_id,
                        scope.application_id,schedule_id,row["state_token"]))
                    return {"scheduleId":schedule_id,"stateToken":row["state_token"],
                        "status":"Skipped","throughDueAt":skipped[-1].isoformat(),"occurrences":[]}
            if not due:return {"scheduleId":schedule_id,"stateToken":row["state_token"],
                "status":"NotDue","occurrences":[]}
            occurrences=[]
            for instant in due:
                occurrence_id=_occurrence_id(scope,schedule_id,row["state_token"],instant,
                    schema_epoch=row["schema_epoch"])
                inserted=db.execute('''INSERT INTO epm.application_schedule_occurrence(
                    workspace_id,application_id,occurrence_id,schedule_id,schedule_state_token,due_at,status)
                    VALUES(%s,%s,%s,%s,%s,%s,'ready') ON CONFLICT(workspace_id,application_id,
                    schedule_id,schedule_state_token,due_at) DO NOTHING RETURNING occurrence_id''',(
                    scope.workspace_id,scope.application_id,occurrence_id,schedule_id,row["state_token"],instant
                    )).fetchone()
                existing=inserted or db.execute('''SELECT occurrence_id FROM epm.application_schedule_occurrence
                    WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s
                      AND schedule_state_token=%s AND due_at=%s''',(scope.workspace_id,scope.application_id,
                    schedule_id,row["state_token"],instant)).fetchone()
                if existing is None or existing["occurrence_id"]!=occurrence_id:
                    raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_CONFLICT")
                occurrences.append({"occurrenceId":occurrence_id,"dueAt":instant.isoformat(),
                    "status":"ready","created":inserted is not None})
            db.execute('''UPDATE epm.application_schedule_definition SET last_due_at=%s,
                updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s
                  AND schedule_id=%s AND state_token=%s''',(due[-1],scope.workspace_id,
                scope.application_id,schedule_id,row["state_token"]))
            return {"scheduleId":schedule_id,"stateToken":row["state_token"],
                "status":"Materialized","occurrences":occurrences}

    @staticmethod
    def _control_row(db,scope,occurrence_id):
        # The task preserves the original actor across schedule replacement.
        # Its visibility does not grant execution authority for a new effect.
        return db.execute('''SELECT o.*,t.issuer AS execution_issuer,
            t.subject_id AS execution_subject
            FROM epm.application_schedule_occurrence o JOIN epm.task t
              ON (t.workspace_id,t.application_id,t.source_id)=
                 (o.workspace_id,o.application_id,o.occurrence_id)
             AND t.source_family='ApplicationScheduleOccurrence'
             AND t.task_id='v:'||o.occurrence_id
            WHERE o.workspace_id=%s AND o.application_id=%s
              AND o.occurrence_id=%s FOR UPDATE OF o''',
            (scope.workspace_id,scope.application_id,occurrence_id)).fetchone()

    def _authorize_control(self,db,scope,row,*,allow_application_admin,error_code):
        if row is None:raise ValueError(error_code)
        owner=(row['execution_issuer'],row['execution_subject'])==(
            self.identity.issuer,self.identity.subject_id)
        try:
            if owner:
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                    'rule_run',function='application.rule.run')
            elif allow_application_admin:
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
            else:
                raise AccessDenied('owner required')
        except AccessDenied as error:
            raise ValueError(error_code) from error

    def _cancel_parent_after_occurrence(self,scope,parent,*,allow_application_admin):
        """The occurrence transaction is closed before parent/job controls."""
        from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
        from .postgres_jobs import PostgresJobQueue
        if parent['status'] not in ('accepted','running','cancel_requested'):
            return
        current=PostgresApplicationRuleWorkflowStore(self.dsn,identity=self.identity
            ).request_cancel_as_task_controller(scope,parent['workflow_id'],
                allow_application_admin=allow_application_admin)
        pending=next((item for item in reversed(current.checkpoints)
                      if not item.committed),None)
        if current.status.value=='cancel_requested' and pending is not None:
            PostgresJobQueue(self.dsn,identity=self.identity).request_cancel(
                scope,pending.job_id,allow_application_admin=allow_application_admin)

    def request_cancel_as_task_controller(self,scope,occurrence_id,*,allow_application_admin=False):
        if (not isinstance(scope,ApplicationScope) or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None or type(allow_application_admin) is not bool):
            raise ValueError('APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE')
        from .postgres_job_origin import schedule_control_parent
        parent=None
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            row=self._control_row(db,scope,occurrence_id)
            self._authorize_control(db,scope,row,allow_application_admin=allow_application_admin,
                error_code='APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE')
            initial_status=row['status']
            status=initial_status
            if status not in ('published','partially_published','failed','cancelled','needs_inspection'):
                parent=schedule_control_parent(db,scope,row)
                status=self._cancellation_disposition(row,parent)
                if status!=row['status']:
                    db.execute('''UPDATE epm.application_schedule_occurrence SET status=%s,
                        inspection_origin_status=%s,claim_generation=claim_generation+1,
                        claimant=NULL,lease_until=NULL,next_attempt_at=NULL,error_code=%s,
                        updated_at=transaction_timestamp() WHERE workspace_id=%s
                          AND application_id=%s AND occurrence_id=%s''',
                        (status,'cancel_requested' if status=='needs_inspection' else None,
                         'APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED'
                         if status=='needs_inspection' else None,
                         scope.workspace_id,scope.application_id,occurrence_id))
            committed=(True if status in ('published','partially_published') else
                False if initial_status=='ready' and status=='cancelled' and parent is None else None)
            result={'occurrenceId':occurrence_id,'status':status,
                    'workflowId':row['application_rule_workflow_id'],
                    'committedEffectsRemain':committed}
        if parent is not None and status=='cancel_requested':
            try:
                self._cancel_parent_after_occurrence(scope,parent,
                    allow_application_admin=allow_application_admin)
            except ValueError as error:
                if str(error)!='PYTHON_WORKFLOW_CANCEL_NOT_AVAILABLE':raise
                # Publication can win after our observation. Only a newly
                # observed terminal parent explains this precise race.
                observed=self.reconcile_cancel_requested(scope,occurrence_id,
                    allow_application_admin=allow_application_admin)
                if observed['status'] not in ('published','partially_published','failed','cancelled'):
                    raise
                result.update(status=observed['status'], committedEffectsRemain=(
                    True if observed['status'] in ('published','partially_published') else None))
        return result

    def reconcile_cancel_requested(self,scope,occurrence_id,*,allow_application_admin=False):
        if (not isinstance(scope,ApplicationScope) or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None or type(allow_application_admin) is not bool):
            raise ValueError('APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE')
        from .postgres_job_origin import schedule_control_parent
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            row=self._control_row(db,scope,occurrence_id)
            self._authorize_control(db,scope,row,allow_application_admin=allow_application_admin,
                error_code='APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE')
            if row['status']!='cancel_requested':
                raise ValueError('APPLICATION_SCHEDULE_CANCEL_NOT_REQUESTED')
            child=schedule_control_parent(db,scope,row)
            if child is None:
                raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED')
            status=(child['status'] if child['status'] in (
                'cancelled','failed','published','partially_published') else 'cancel_requested')
            return {'occurrenceId':occurrence_id,'status':status,
                'workflowId':child['workflow_id'],'workflowStatus':status}

    def reconcile_needs_inspection(self,scope,occurrence_id,*,idempotency_key,
                                   allow_application_admin=False):
        if (not isinstance(scope,ApplicationScope) or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None or type(allow_application_admin) is not bool):
            raise ValueError('APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE')
        from .postgres_job_origin import schedule_control_parent,require_rule_execution_authority
        from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            # A requested execution resume shares the delegation/definition
            # fence, acquired before the occurrence, never after its parent.
            db.execute('''SELECT schema_epoch FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                (scope.workspace_id,scope.application_id)).fetchone()
            row=self._control_row(db,scope,occurrence_id)
            self._authorize_control(db,scope,row,allow_application_admin=allow_application_admin,
                error_code='APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE')
            prior=row['result'].get('reconciliation')
            if isinstance(prior,dict) and prior.get('operationId')==idempotency_key:
                if prior.get('actor')!=[self.identity.issuer,self.identity.subject_id]:
                    raise ValueError('APPLICATION_SCHEDULE_RECONCILE_IDEMPOTENCY_CONFLICT')
                return {'occurrenceId':occurrence_id,'status':prior['resultStatus'],
                    'originStatus':prior['originStatus'],'workflowId':prior.get('workflowId')}
            if (row['status']!='needs_inspection' or row['claimant'] is not None
                    or row['lease_until'] is not None or row['inspection_origin_status'] not in
                    ('running','submitted','cancel_requested')):
                raise ValueError('APPLICATION_SCHEDULE_RECONCILE_NOT_AVAILABLE')
            origin=row['inspection_origin_status']
            child=schedule_control_parent(db,scope,row)
            status='needs_inspection';error='APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED'
            if child is not None:
                if child['status'] in ('published','partially_published','failed','cancelled'):
                    status=child['status'];error=None
                elif origin=='cancel_requested':
                    status='cancel_requested';error=None
                else:
                    try:
                        require_rule_execution_authority(db,scope,child)
                        PostgresApplicationRuleWorkflowStore._verify_current(db,scope,child)
                    except AccessDenied:
                        error='APPLICATION_SCHEDULE_AUTHORIZATION_REVOKED'
                    except ValueError as failure:
                        if str(failure) not in (
                                'APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED',
                                'APPLICATION_RULE_EXECUTION_ORIGIN_INVALID',
                                'APPLICATION_RULE_WORKFLOW_PUBLICATION_STALE',
                                'APPLICATION_RULE_WORKFLOW_OWNER_CERTIFICATE_STALE',
                                'APPLICATION_RULE_WORKFLOW_CONTEXT_STALE'):
                            raise
                        error=str(failure)
                    else:
                        status=origin;error=None
            result=dict(row['result']);result['reconciliation']={
                'operationId':idempotency_key,
                'actor':[self.identity.issuer,self.identity.subject_id],
                'originStatus':origin,'resultStatus':status,
                'workflowId':None if child is None else child['workflow_id']}
            db.execute('''UPDATE epm.application_schedule_occurrence SET status=%s,error_code=%s,
                inspection_origin_status=%s,claimant=NULL,lease_until=NULL,next_attempt_at=NULL,
                result=%s,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s''',
                (status,error,origin if status=='needs_inspection' else None,Jsonb(result),
                 scope.workspace_id,scope.application_id,occurrence_id))
            return {'occurrenceId':occurrence_id,'status':status,'originStatus':origin,
                'workflowId':None if child is None else child['workflow_id']}

    @staticmethod
    def _occurrence_arguments(value):
        if (type(value) is not dict
                or set(value) not in ({"expectedStateToken","limit"},
                    {"expectedStateToken","limit","afterSequence"})
                or type(value.get("limit")) is not int or not 1<=value["limit"]<=100
                or "afterSequence" in value and (
                    type(value["afterSequence"]) is not int
                    or not 1<=value["afterSequence"]<=9223372036854775807)):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        require_state_token(value["expectedStateToken"],
            error="APPLICATION_SCHEDULE_ARGUMENTS_INVALID")

    def _occurrence_page(self,db,scope,schedule_id,state_token,request,access):
        from .postgres_tasks import PostgresTaskService
        tasks=PostgresTaskService(self.dsn,identity=self.identity)
        administrator=access.role == "Administrator" and tasks._authorized(db,scope,"admin")
        # This fixed source family uses originating-subject visibility. The SQL
        # prefilter bounds work without exposing hidden counts or cursors; the
        # existing task service remains the final visibility decision.
        source='''FROM epm.application_schedule_occurrence occurrence
            JOIN epm.task task ON task.workspace_id=occurrence.workspace_id
             AND task.application_id=occurrence.application_id
             AND task.source_family='ApplicationScheduleOccurrence'
             AND task.source_id=occurrence.occurrence_id
            WHERE occurrence.workspace_id=%s AND occurrence.application_id=%s
             AND occurrence.schedule_id=%s
             AND (%s OR (task.issuer=%s AND task.subject_id=%s))'''
        parameters=(scope.workspace_id,scope.application_id,schedule_id,
            administrator,self.identity.issuer,self.identity.subject_id)
        after=request.get("afterSequence")
        if after is not None:
            cursor=db.execute('''SELECT task.source_family,task.issuer,
                task.subject_id '''+source+''' AND task.sequence=%s''',
                (*parameters,after)).fetchone()
            if cursor is None or not (administrator or tasks._visible(db,scope,cursor)):
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_CURSOR_INVALID")
        rows=db.execute('''SELECT occurrence.occurrence_id,occurrence.due_at,
            occurrence.status AS native_status,occurrence.schedule_state_token,
            occurrence.application_rule_workflow_id,task.task_id,task.sequence,
            task.status,task.source_family,task.issuer,task.subject_id '''+source+'''
            AND (%s::bigint IS NULL OR task.sequence<%s)
            ORDER BY task.sequence DESC LIMIT %s''',
            (*parameters,after,after,request["limit"]+1)).fetchall()
        visible=[row for row in rows if administrator or tasks._visible(db,scope,row)]
        items=[{"occurrenceId":row["occurrence_id"],"taskId":row["task_id"],
            "sequence":row["sequence"],"dueAt":row["due_at"].isoformat(),
            "nativeStatus":row["native_status"],"status":row["status"],
            "scheduleStateToken":row["schedule_state_token"],
            "currentPin":row["schedule_state_token"]==state_token,
            "workflowId":row["application_rule_workflow_id"]}
            for row in visible[:request["limit"]]]
        has_more=len(visible)>request["limit"]
        return {"scheduleStateToken":state_token,"items":items,"hasMore":has_more,
            "nextAfterSequence":items[-1]["sequence"] if has_more else None}

    def read(self,scope,schedule_id,*,occurrences=None):
        if type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None:
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        if occurrences is not None:self._occurrence_arguments(occurrences)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=READ)
            row=db.execute('''SELECT '''+self._read_columns()+''' WHERE
                schedule.workspace_id=%s AND schedule.application_id=%s
                AND schedule.schedule_id=%s''',(scope.workspace_id,
                scope.application_id,schedule_id)).fetchone()
            result={"defined":row is not None,"schedule":None if row is None else self._result(row)}
            if row is not None and occurrences is not None:
                if row["state_token"]!=occurrences["expectedStateToken"]:
                    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=READ)
                    raise ValueError("APPLICATION_SCHEDULE_STALE_CONTEXT")
                page=self._occurrence_page(db,scope,schedule_id,row["state_token"],occurrences,access)
                # READ COMMITTED may observe a definition change between page
                # statements. Never attach that page to a different current pin.
                current=db.execute('''SELECT '''+self._read_columns()+''' WHERE
                    schedule.workspace_id=%s AND schedule.application_id=%s
                    AND schedule.schedule_id=%s''',(scope.workspace_id,
                    scope.application_id,schedule_id)).fetchone()
                if current is None or current["state_token"]!=row["state_token"]:
                    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=READ)
                    raise ValueError("APPLICATION_SCHEDULE_STALE_CONTEXT")
                result["schedule"]=self._result(current)
                result["occurrences"]=page
            # Directory changes can commit independently of the workspace
            # fence. Never return history built with an earlier visibility role.
            final_access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=READ)
            if "occurrences" in result and final_access.role != access.role:
                raise ValueError("APPLICATION_SCHEDULE_STALE_CONTEXT")
            return result

    def list(self,scope,*,limit=100,after_schedule_id=None):
        if (type(limit) is not int or not 1<=limit<=100 or after_schedule_id is not None
                and (type(after_schedule_id) is not str or _ID.fullmatch(after_schedule_id) is None)):
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=LIST)
            rows=db.execute('''SELECT '''+self._read_columns()+''' WHERE
                schedule.workspace_id=%s AND schedule.application_id=%s
                AND (%s::text IS NULL OR schedule.schedule_id>%s)
                ORDER BY schedule.schedule_id LIMIT %s''',(scope.workspace_id,scope.application_id,
                after_schedule_id,after_schedule_id,limit+1)).fetchall()
            values=[self._result(row) for row in rows[:limit]]
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=LIST)
            return {"schedules":values,"nextAfterScheduleId":
                values[-1]["scheduleId"] if len(rows)>limit else None}
