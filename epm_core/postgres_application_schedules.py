"""One current durable schedule definition for an active application rule."""
from __future__ import annotations

from datetime import datetime,timezone
from hashlib import sha256
import json,re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .application_schedule import canonical_digest,execution_bindings,validate_definition
from .current_object_contract import new_state_token,require_state_token
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
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_HEX32=re.compile(r"[0-9a-f]{32}\Z")


def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("ascii")).hexdigest()


def catalog():
    common={"requiredCapabilities":[],"previewRequired":False,"workClass":"short"}
    mutation={**common,"mode":"atomic_configuration","permission":"admin",
              "idempotencyRequired":True}
    read={**common,"mode":"read_only","permission":"read","idempotencyRequired":False}
    revisions={"expectedMetadataRevision":"current metadata revision",
        "expectedPolicyRevision":"current policy revision",
        "expectedSchemaEpoch":"current schema epoch"}
    return {
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
        "result":"current schedule definition, lifecycle state and target currentness"},
      LIST:{**read,"arguments":{},"optionalArguments":{"limit":"1-100",
        "afterScheduleId":"stable keyset cursor"},
        "result":"current schedule page with effective target state"}}


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
        db.execute('''UPDATE epm.application_schedule_occurrence SET
            status='cancelled',claim_generation=claim_generation+1,claimant=NULL,
            lease_until=NULL,next_attempt_at=NULL,
            error_code='APPLICATION_SCHEDULE_TARGET_STALE',updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s
              AND schedule_state_token<>%s AND status IN
              ('ready','running','submitted','cancel_requested')''',(
            scope.workspace_id,scope.application_id,schedule_id,current_token))

    @staticmethod
    def _lock_schedule(db,scope,schedule_id):
        """Serialize definition changes with worker child admission."""
        db.execute('''SELECT pg_advisory_xact_lock(hashtextextended(
            'epm.application.schedule:'||%s||':'||%s||':'||%s,0))''',(
            scope.workspace_id,scope.application_id,schedule_id))

    def execute(self,scope,program,*,idempotency_key=None,registry=None,
                compiler_version="application-rule-v1"):
        function=program.get("function") if type(program) is dict else None
        if function not in FUNCTIONS:raise ValueError("APPLICATION_SCHEDULE_FUNCTION_INVALID")
        args=self._arguments(program,function)
        rev={"expectedMetadataRevision","expectedPolicyRevision","expectedSchemaEpoch"}
        if function==SAVE:
            if set(args) not in ({"definition",*rev},{"definition","expectedStateToken",*rev}):
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            if registry is None:raise ValueError("APPLICATION_SCHEDULE_REGISTRY_REQUIRED")
            return self.save(scope,args["definition"],expected_state_token=args.get("expectedStateToken"),
                expected_metadata_revision=args["expectedMetadataRevision"],
                expected_policy_revision=args["expectedPolicyRevision"],
                expected_schema_epoch=args["expectedSchemaEpoch"],idempotency_key=idempotency_key,
                registry=registry,compiler_version=compiler_version)
        if function in (ACTIVATE,DEACTIVATE):
            if set(args)!={"scheduleId","expectedStateToken",*rev}:
                raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            return self.set_active(scope,args["scheduleId"],active=function==ACTIVATE,
                expected_state_token=args["expectedStateToken"],
                expected_metadata_revision=args["expectedMetadataRevision"],
                expected_policy_revision=args["expectedPolicyRevision"],
                expected_schema_epoch=args["expectedSchemaEpoch"],idempotency_key=idempotency_key)
        if idempotency_key is not None:raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_UNEXPECTED")
        if function==READ:
            if set(args)!={"scheduleId"}:raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
            return self.read(scope,args["scheduleId"])
        if set(args)-{"limit","afterScheduleId"}:raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        return self.list(scope,limit=args.get("limit",100),after_schedule_id=args.get("afterScheduleId"))

    def save(self,scope,definition,*,expected_state_token,
             expected_metadata_revision,expected_policy_revision,expected_schema_epoch,
             idempotency_key,registry,compiler_version):
        canonical=validate_definition(definition)
        if expected_state_token is not None:
            require_state_token(expected_state_token,error="APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        if (any(type(v) is not int or v<0 for v in (expected_metadata_revision,
                expected_policy_revision,expected_schema_epoch))
                or type(idempotency_key) is not str or _KEY.fullmatch(idempotency_key) is None
                or not callable(getattr(registry,"validate_operation",None))
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
                   idempotency_key):
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
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin",function=function)
            prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
                WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(
                scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if prior:
                if prior["command_digest"]!=digest or prior["actor_id"]!=self.identity.subject_id:
                    raise ValueError("APPLICATION_SCHEDULE_IDEMPOTENCY_CONFLICT")
                return prior["result"]
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

    def request_cancel_as_task_controller(self,scope,occurrence_id,*,allow_application_admin=False):
        if (not isinstance(scope,ApplicationScope) or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None or type(allow_application_admin) is not bool):
            raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            row=db.execute('''SELECT o.*,s.execution_issuer,s.execution_subject,
                s.rule_id,s.rule_state_token FROM
                epm.application_schedule_occurrence o JOIN epm.application_schedule_definition s
                  ON (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
                     (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
                WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s FOR UPDATE OF o''',(
                scope.workspace_id,scope.application_id,occurrence_id)).fetchone()
            if row is None:raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE")
            owner=(row["execution_issuer"],row["execution_subject"])==(
                self.identity.issuer,self.identity.subject_id)
            try:
                if owner:PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"rule_run")
                elif allow_application_admin:PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin")
                else:raise AccessDenied("owner required")
            except AccessDenied as error:
                raise ValueError("APPLICATION_SCHEDULE_OCCURRENCE_UNAVAILABLE") from error
            terminal=("published","partially_published","failed","cancelled","needs_inspection")
            status=row["status"]
            if status not in terminal and status!="cancel_requested":
                status="cancelled" if status=="ready" else "cancel_requested"
                db.execute('''UPDATE epm.application_schedule_occurrence SET status=%s,
                    claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,next_attempt_at=NULL,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s
                      AND occurrence_id=%s''',(status,scope.workspace_id,scope.application_id,occurrence_id))
            child_id=row["application_rule_workflow_id"]
            if status=="cancel_requested":
                child=db.execute('''SELECT * FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND idempotency_key=%s
                      AND issuer=%s AND subject_id=%s FOR UPDATE''',(scope.workspace_id,
                    scope.application_id,"schedule-rule-"+occurrence_id,
                    row["execution_issuer"],row["execution_subject"])).fetchone()
                if (child is not None and (child["rule_id"]!=row["rule_id"]
                        or child["rule_state_token"]!=row["rule_state_token"]
                        or child_id not in (None,child["workflow_id"]))):
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                if child_id is not None and child is None:
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                if child is not None:
                    child_id=child["workflow_id"]
                    if row["application_rule_workflow_id"] is None:
                        db.execute('''UPDATE epm.application_schedule_occurrence SET
                            application_rule_workflow_id=%s WHERE workspace_id=%s
                              AND application_id=%s AND occurrence_id=%s''',(child_id,
                            scope.workspace_id,scope.application_id,occurrence_id))
                    child_status=("cancelled" if child["status"]=="accepted"
                        else "cancel_requested" if child["status"]=="running"
                        else child["status"])
                    if child_status!=child["status"]:
                        db.execute('''UPDATE epm.application_rule_workflow SET status=%s,
                            updated_at=transaction_timestamp() WHERE workspace_id=%s
                              AND application_id=%s AND workflow_id=%s''',(child_status,
                            scope.workspace_id,scope.application_id,child_id))
                    checkpoints=child["result"].get("checkpoints",[])
                    pending=next((item for item in reversed(checkpoints)
                        if isinstance(item,dict) and item.get("committed") is False),None)
                    if child_status=="cancel_requested" and pending is not None:
                        job=db.execute('''SELECT status FROM epm.job WHERE workspace_id=%s
                            AND application_id=%s AND job_id=%s AND issuer=%s
                              AND subject_id=%s FOR UPDATE''',(scope.workspace_id,
                            scope.application_id,pending.get("jobId"),row["execution_issuer"],
                            row["execution_subject"])).fetchone()
                        if job is None:raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                        job_status=("cancelled" if job["status"] in ("accepted","ready")
                            else "cancel_requested" if job["status"] in ("running","staged")
                            else job["status"])
                        if job_status!=job["status"]:
                            db.execute('''UPDATE epm.job SET status=%s,
                                claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
                                updated_at=transaction_timestamp() WHERE workspace_id=%s
                                  AND application_id=%s AND job_id=%s''',(job_status,
                                scope.workspace_id,scope.application_id,pending["jobId"]))
            return {"occurrenceId":occurrence_id,"status":status,"workflowId":child_id}

    def reconcile_cancel_requested(self,scope,occurrence_id):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope)
            row=db.execute('''SELECT o.*,s.execution_issuer,s.execution_subject,
                s.rule_id,s.rule_state_token,s.delegation_id,s.delegation_state_token,
                s.definition,s.definition_digest FROM
                epm.application_schedule_occurrence o JOIN epm.application_schedule_definition s
                  ON (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
                     (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
                WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s FOR UPDATE OF o''',(
                scope.workspace_id,scope.application_id,occurrence_id)).fetchone()
            if row is None or row["status"]!="cancel_requested":
                raise ValueError("APPLICATION_SCHEDULE_CANCEL_NOT_REQUESTED")
            child=None
            if row["application_rule_workflow_id"] is not None:
                child=db.execute('''SELECT workflow_id,status FROM epm.application_rule_workflow
                    WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s''',(
                    scope.workspace_id,scope.application_id,row["application_rule_workflow_id"])).fetchone()
                if child is None:raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
            if child is None or child["status"] in ("cancelled","failed"):
                status="cancelled" if child is None else child["status"]
            elif child["status"] in ("published","partially_published"):status=child["status"]
            else:status="cancel_requested"
            return {"occurrenceId":occurrence_id,"status":status,
                "workflowId":None if child is None else child["workflow_id"],"workflowStatus":status}

    def reconcile_needs_inspection(self,scope,occurrence_id,*,idempotency_key,
                                   allow_application_admin=False):
        if (not isinstance(scope,ApplicationScope) or type(occurrence_id) is not str
                or _HEX32.fullmatch(occurrence_id) is None or type(idempotency_key) is not str
                or _KEY.fullmatch(idempotency_key) is None or type(allow_application_admin) is not bool):
            raise ValueError("APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            row=db.execute('''SELECT o.*,s.execution_issuer,s.execution_subject,
                s.rule_id,s.rule_state_token,s.delegation_id,s.delegation_state_token,
                s.definition,s.definition_digest FROM
                epm.application_schedule_occurrence o LEFT JOIN epm.application_schedule_definition s
                  ON (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
                     (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
                WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s FOR UPDATE OF o''',(
                scope.workspace_id,scope.application_id,occurrence_id)).fetchone()
            if row is None:
                raise ValueError("APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE")
            prior=row["result"].get("reconciliation")
            if isinstance(prior,dict) and prior.get("operationId")==idempotency_key:
                if prior.get("actor")!=[self.identity.issuer,self.identity.subject_id]:
                    raise ValueError("APPLICATION_SCHEDULE_RECONCILE_IDEMPOTENCY_CONFLICT")
                return {"occurrenceId":occurrence_id,"status":prior["resultStatus"],
                    "originStatus":prior["originStatus"],"workflowId":prior.get("workflowId")}
            if (row["status"]!="needs_inspection" or row["claimant"] is not None
                    or row["lease_until"] is not None or row["inspection_origin_status"] not in
                    ("running","submitted","cancel_requested")):
                raise ValueError("APPLICATION_SCHEDULE_RECONCILE_NOT_AVAILABLE")
            origin=row["inspection_origin_status"]
            child=None
            if row["execution_issuer"] is None:
                status="failed";error="APPLICATION_SCHEDULE_TARGET_STALE"
            else:
                definition=validate_definition(row["definition"])
                if (definition["scheduleId"]!=row["schedule_id"]
                        or canonical_digest(definition)!=row["definition_digest"]):
                    raise ValueError("APPLICATION_SCHEDULE_DEFINITION_CORRUPT")
                owner=(row["execution_issuer"],row["execution_subject"])==(
                    self.identity.issuer,self.identity.subject_id)
                try:
                    if owner:PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"rule_run")
                    elif allow_application_admin:PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"admin")
                    else:raise AccessDenied("owner required")
                except AccessDenied as denied:
                    raise ValueError("APPLICATION_SCHEDULE_RECONCILE_UNAVAILABLE") from denied
                child=db.execute('''SELECT workflow_id,status,rule_id,rule_state_token
                    FROM epm.application_rule_workflow WHERE workspace_id=%s
                      AND application_id=%s AND idempotency_key=%s AND issuer=%s
                      AND subject_id=%s''',(scope.workspace_id,scope.application_id,
                    "schedule-rule-"+occurrence_id,row["execution_issuer"],
                    row["execution_subject"])).fetchone()
                if child is not None and (child["rule_id"]!=row["rule_id"]
                        or child["rule_state_token"]!=row["rule_state_token"]
                        or row["application_rule_workflow_id"] not in
                           (None,child["workflow_id"])):
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                if row["application_rule_workflow_id"] is not None and child is None:
                    raise ValueError("APPLICATION_SCHEDULE_WORKFLOW_CONFLICT")
                status=(child["status"] if child and child["status"] in
                    ("published","partially_published","failed","cancelled") else origin or "running")
                if status not in ("published","partially_published","failed","cancelled") and origin!="cancel_requested":
                    allowed=db.execute('''SELECT epm.execution_delegation_is_current(
                        %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',(scope.workspace_id,
                        scope.application_id,row["delegation_id"],row["delegation_state_token"],
                        row["execution_issuer"],row["execution_subject"],"application.rule.run",
                        row["schedule_id"])).fetchone()["allowed"]
                    if not allowed:status="failed"
                error=("APPLICATION_SCHEDULE_AUTHORIZATION_REVOKED"
                       if status=="failed" and (child is None or child["status"]!="failed") else None)
            result=dict(row["result"]);result["reconciliation"]={
                "operationId":idempotency_key,
                "actor":[self.identity.issuer,self.identity.subject_id],
                "originStatus":origin,"resultStatus":status,
                "workflowId":None if child is None else child["workflow_id"]}
            db.execute('''UPDATE epm.application_schedule_occurrence SET status=%s,error_code=%s,
                inspection_origin_status=NULL,claimant=NULL,lease_until=NULL,
                application_rule_workflow_id=COALESCE(application_rule_workflow_id,%s),
                result=%s,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s''',(
                status,error,None if child is None else child["workflow_id"],Jsonb(result),
                scope.workspace_id,scope.application_id,occurrence_id))
            return {"occurrenceId":occurrence_id,"status":status,"originStatus":origin,
                "workflowId":None if child is None else child["workflow_id"]}

    def read(self,scope,schedule_id):
        if type(schedule_id) is not str or _ID.fullmatch(schedule_id) is None:
            raise ValueError("APPLICATION_SCHEDULE_ARGUMENTS_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute("SET TRANSACTION READ ONLY");self._scope(db,scope)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,"read",function=READ)
            row=db.execute('''SELECT '''+self._read_columns()+''' WHERE
                schedule.workspace_id=%s AND schedule.application_id=%s
                AND schedule.schedule_id=%s''',(scope.workspace_id,
                scope.application_id,schedule_id)).fetchone()
            return {"defined":row is not None,"schedule":None if row is None else self._result(row)}

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
            return {"schedules":values,"nextAfterScheduleId":
                values[-1]["scheduleId"] if len(rows)>limit else None}
