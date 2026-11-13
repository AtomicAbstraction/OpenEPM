"""One current application-scoped structural statement definition per ID."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_statement_definition import StatementDefinition
from .current_object_contract import collection_token, new_state_token, require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout

SAVE = "consolidation.statement.definition.save"
READ = "consolidation.statement.definition.read"
LIST = "consolidation.statement.definition.list"
ACTIVATE = "consolidation.statement.definition.activate"
DEACTIVATE = "consolidation.statement.definition.deactivate"
FUNCTIONS = frozenset((SAVE, READ, LIST, ACTIVATE, DEACTIVATE))
_ID = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SELECT = """definition_id,state_token,status,definition,canonical_digest,
 updated_operation_id,updated_issuer,updated_subject_id,updated_at"""


def catalog() -> dict:
    common = {"requiredCapabilities": ["financial_consolidation"],
              "previewRequired": False, "workClass": "short"}
    return {
        SAVE: {**common, "mode": "atomic_policy_write", "permission": "admin",
            "idempotencyRequired": True,
            "arguments": {"definition": "bounded current structural definition"},
            "optionalArguments": {"expectedStateToken": "required to replace an existing definition"},
            "result": "saved current definition, state token, digest and receipt"},
        READ: {**common, "mode": "read", "permission": "read",
            "idempotencyRequired": False, "arguments": {"definitionId": "stable definition ID"},
            "result": "verified current definition"},
        LIST: {**common, "mode": "read", "permission": "read",
            "idempotencyRequired": False, "arguments": {},
            "optionalArguments": {"limit": "1-100", "afterDefinitionId": "keyset cursor",
                "expectedCollectionToken": "required with cursor"},
            "result": "bounded current definitions and collection token"},
        ACTIVATE: {**common, "mode": "atomic_policy_write", "permission": "admin",
            "idempotencyRequired": True,
            "arguments": {"definitionId": "stable definition ID",
                "expectedStateToken": "current opaque token", "definitionDigest": "exact digest"},
            "result": "active current definition and receipt"},
        DEACTIVATE: {**common, "mode": "atomic_policy_write", "permission": "admin",
            "idempotencyRequired": True,
            "arguments": {"definitionId": "stable definition ID",
                "expectedStateToken": "current opaque token", "definitionDigest": "exact digest"},
            "result": "saved current definition and receipt"},
    }


class PostgresStatementDefinitions:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime", ("statement_definition",))
        self.dsn, self.identity = dsn, identity

    def execute_program(self, scope: ApplicationScope, program: object, *,
                        idempotency_key: str | None = None) -> dict:
        function, args = _program(program)
        if idempotency_key is None:
            raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
        if function == SAVE:
            if set(args) - {"definition", "expectedStateToken"} or "definition" not in args:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            return self.save(scope, args["definition"],
                expected_state_token=args.get("expectedStateToken"), idempotency_key=idempotency_key)
        if function in (ACTIVATE, DEACTIVATE):
            if set(args) != {"definitionId", "expectedStateToken", "definitionDigest"}:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            method = self.activate if function == ACTIVATE else self.deactivate
            return method(scope, definition_id=args["definitionId"],
                expected_state_token=args["expectedStateToken"],
                definition_digest=args["definitionDigest"], idempotency_key=idempotency_key)
        raise ValueError("STATEMENT_DEFINITION_WRITE_FUNCTION_INVALID")

    def read_program(self, scope: ApplicationScope, program: object) -> dict:
        function, args = _program(program)
        if function == READ:
            if set(args) != {"definitionId"}:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            return self.read(scope, args["definitionId"])
        if function == LIST:
            if set(args) - {"limit", "afterDefinitionId", "expectedCollectionToken"}:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            if ("afterDefinitionId" in args) != ("expectedCollectionToken" in args):
                raise ValueError("STATEMENT_DEFINITION_LIST_CONTINUATION_PIN_REQUIRED")
            return self.list(scope, limit=args.get("limit", 100),
                after_definition_id=args.get("afterDefinitionId"),
                expected_collection_token=args.get("expectedCollectionToken"))
        raise ValueError("STATEMENT_DEFINITION_READ_FUNCTION_INVALID")

    def save(self, scope: ApplicationScope, raw: object, *,
             expected_state_token: str | None = None, idempotency_key: str) -> dict:
        definition = StatementDefinition.parse(raw)
        _request_key(idempotency_key)
        if expected_state_token is not None:
            require_state_token(expected_state_token, error="STATEMENT_DEFINITION_STATE_TOKEN_INVALID")
        command = {"scope": [scope.workspace_id, scope.application_id],
            "actor": [self.identity.issuer, self.identity.subject_id], "function": SAVE,
            "definition": definition.normalized(), "expectedStateToken": expected_state_token,
            "idempotencyKey": idempotency_key}
        digest = _digest(command)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                state = self._prepare(db, scope, SAVE, "admin", lock_state=True)
                prior = self._replay(db, scope, idempotency_key, digest)
                if prior is not None:
                    return prior
                self._require_active(state)
                ids = (scope.workspace_id, scope.application_id, definition.definition_id)
                current = db.execute(f"""SELECT {_SELECT} FROM epm.statement_definition
                    WHERE workspace_id=%s AND application_id=%s AND definition_id=%s FOR UPDATE""",
                    ids).fetchone()
                if current is None and expected_state_token is not None:
                    raise ValueError("STATEMENT_DEFINITION_UNAVAILABLE")
                if current is not None:
                    if expected_state_token is None:
                        raise ValueError("STATEMENT_DEFINITION_EXPECTED_STATE_TOKEN_REQUIRED")
                    if current["state_token"] != expected_state_token:
                        raise ValueError("STATEMENT_DEFINITION_STATE_STALE")
                revision, state_token = state["commit_revision"] + 1, new_state_token()
                db.execute("""INSERT INTO epm.statement_definition
                    (workspace_id,application_id,definition_id,state_token,status,definition,
                     canonical_digest,updated_operation_id,updated_issuer,updated_subject_id)
                    VALUES(%s,%s,%s,%s,'Saved',%s,%s,%s,%s,%s)
                    ON CONFLICT(workspace_id,application_id,definition_id) DO UPDATE SET
                     state_token=EXCLUDED.state_token,status='Saved',definition=EXCLUDED.definition,
                     canonical_digest=EXCLUDED.canonical_digest,updated_operation_id=EXCLUDED.updated_operation_id,
                     updated_issuer=EXCLUDED.updated_issuer,updated_subject_id=EXCLUDED.updated_subject_id,
                     updated_at=clock_timestamp()""",
                    (*ids, state_token, Jsonb(definition.normalized()), definition.digest,
                     idempotency_key, self.identity.issuer, self.identity.subject_id))
                db.execute("UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s",
                    (revision, scope.workspace_id, scope.application_id))
                result = {"operationId": idempotency_key, "status": "Saved",
                    "definitionId": definition.definition_id, "stateToken": state_token,
                    "definitionDigest": definition.digest, "declaredCoverageComplete": False}
                self._receipt(db, scope, idempotency_key, digest, revision, result)
                return result

    def read(self, scope: ApplicationScope, definition_id: str) -> dict:
        _target(definition_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._prepare(db, scope, READ, "read")
                return self._record(self._row(db, scope, definition_id))

    def list(self, scope: ApplicationScope, *, limit: int = 100,
             after_definition_id: str | None = None,
             expected_collection_token: str | None = None) -> dict:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("STATEMENT_DEFINITION_LIST_LIMIT_INVALID")
        if after_definition_id is not None:
            _target(after_definition_id)
            require_state_token(expected_collection_token,
                error="STATEMENT_DEFINITION_COLLECTION_TOKEN_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._prepare(db, scope, LIST, "read")
                ids = (scope.workspace_id, scope.application_id)
                states = db.execute("""SELECT definition_id,state_token FROM epm.statement_definition
                    WHERE workspace_id=%s AND application_id=%s ORDER BY definition_id""", ids).fetchall()
                token = collection_token((row["definition_id"], row["state_token"]) for row in states)
                if expected_collection_token is not None and token != expected_collection_token:
                    raise ValueError("STATEMENT_DEFINITION_LIST_STALE")
                rows = db.execute(f"""SELECT {_SELECT} FROM epm.statement_definition
                    WHERE workspace_id=%s AND application_id=%s AND definition_id>%s
                    ORDER BY definition_id LIMIT %s""",
                    (*ids, after_definition_id or "", limit + 1)).fetchall()
                values = [self._record(row) for row in rows[:limit]]
                return {"definitions": values, "collectionToken": token,
                    "nextAfterDefinitionId": (rows[limit - 1]["definition_id"]
                        if len(rows) > limit else None)}

    def read_active_exact(self, scope: ApplicationScope, definition_id: str,
                          state_token: str, definition_digest: str, *, function: str = READ) -> dict:
        _target(definition_id, state_token, definition_digest)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._prepare(db, scope, function, "read")
                row = self._row(db, scope, definition_id)
                if (row["status"] != "Active" or row["state_token"] != state_token
                        or row["canonical_digest"] != definition_digest):
                    raise ValueError("STATEMENT_DEFINITION_ACTIVE_STALE")
                return self._record(row)

    def activate(self, scope: ApplicationScope, *, definition_id: str,
                 expected_state_token: str, definition_digest: str,
                 idempotency_key: str) -> dict:
        return self._change_status(scope, definition_id=definition_id,
            expected_state_token=expected_state_token, definition_digest=definition_digest,
            idempotency_key=idempotency_key, active=True)

    def deactivate(self, scope: ApplicationScope, *, definition_id: str,
                   expected_state_token: str, definition_digest: str,
                   idempotency_key: str) -> dict:
        return self._change_status(scope, definition_id=definition_id,
            expected_state_token=expected_state_token, definition_digest=definition_digest,
            idempotency_key=idempotency_key, active=False)

    def _change_status(self, scope, *, definition_id, expected_state_token,
                       definition_digest, idempotency_key, active):
        _target(definition_id, expected_state_token, definition_digest)
        _request_key(idempotency_key)
        function = ACTIVATE if active else DEACTIVATE
        command = {"scope": [scope.workspace_id, scope.application_id],
            "actor": [self.identity.issuer, self.identity.subject_id], "function": function,
            "definitionId": definition_id, "expectedStateToken": expected_state_token,
            "definitionDigest": definition_digest, "idempotencyKey": idempotency_key}
        digest = _digest(command)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                state = self._prepare(db, scope, function, "admin", lock_state=True)
                prior = self._replay(db, scope, idempotency_key, digest)
                if prior is not None:
                    return prior
                self._require_active(state)
                row = self._row(db, scope, definition_id, lock=True)
                if row["state_token"] != expected_state_token:
                    raise ValueError("STATEMENT_DEFINITION_STATE_STALE")
                if row["canonical_digest"] != definition_digest:
                    raise ValueError("STATEMENT_DEFINITION_DIGEST_MISMATCH")
                if active and row["status"] == "Active":
                    raise ValueError("STATEMENT_DEFINITION_ALREADY_ACTIVE")
                if not active and row["status"] != "Active":
                    raise ValueError("STATEMENT_DEFINITION_NOT_ACTIVE")
                if active:
                    other = db.execute("""SELECT definition_id FROM epm.statement_definition
                        WHERE workspace_id=%s AND application_id=%s AND status='Active'
                        AND definition_id<>%s LIMIT 1""",
                        (scope.workspace_id, scope.application_id, definition_id)).fetchone()
                    if other:
                        raise ValueError("STATEMENT_DEFINITION_OTHER_ACTIVE")
                revision = state["commit_revision"] + 1
                policy_revision, state_token = state["policy_revision"] + 1, new_state_token()
                status = "Active" if active else "Saved"
                db.execute("""UPDATE epm.statement_definition SET status=%s,state_token=%s,
                    updated_operation_id=%s,updated_issuer=%s,
                    updated_subject_id=%s,updated_at=clock_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND definition_id=%s""",
                    (status, state_token, idempotency_key, self.identity.issuer,
                     self.identity.subject_id, scope.workspace_id, scope.application_id, definition_id))
                db.execute("""UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s""",
                    (policy_revision, revision, scope.workspace_id, scope.application_id))
                result = {"operationId": idempotency_key, "status": status,
                    "definitionId": definition_id, "stateToken": state_token,
                    "definitionDigest": definition_digest, "policyRevision": policy_revision,
                    }
                from .postgres_calculation_impact import object_impact, record_calculation_impact
                impact = object_impact(source_kind="definition", operation_id=idempotency_key,
                    causal_revision=revision, domain="definition", object_type="statement-definition",
                    object_id=definition_id, change="activate" if active else "deactivate",
                    reason="definition_changed", old_presence="present", new_presence="present")
                result["impactDigest"] = impact.digest
                self._receipt(db, scope, idempotency_key, digest, revision, result)
                record_calculation_impact(db, scope, operation_id=idempotency_key, impact=impact)
                return result

    def _prepare(self, db, scope, function, permission, *, lock_state=False):
        if not isinstance(scope, ApplicationScope):
            raise ValueError("APPLICATION_SCOPE_INVALID")
        configure_statement_timeout(db, 5000)
        configure_lock_wait(db)
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        state = self._application_state(db, scope, lock=True) if lock_state else None
        PostgresAccessChecker.check_in_transaction(db, self.identity, scope, permission, function=function)
        return state

    @staticmethod
    def _application_state(db, scope, *, lock):
        row = db.execute("""SELECT s.policy_revision,s.commit_revision,s.processing_mode,a.status
            FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s""" +
            (" FOR UPDATE OF s" if lock else ""),
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_UNAVAILABLE")
        return row

    @staticmethod
    def _require_active(state):
        if state["status"] != "Active" or state["processing_mode"] != "Active":
            raise ValueError("APPLICATION_NOT_WRITABLE")

    def _replay(self, db, scope, operation_id, digest):
        row = db.execute("""SELECT command_digest,actor_id,result FROM epm.operation_receipt
            WHERE workspace_id=%s AND application_id=%s AND operation_id=%s""",
            (scope.workspace_id, scope.application_id, operation_id)).fetchone()
        if not row:
            return None
        if row["command_digest"] != digest or row["actor_id"] != self.identity.subject_id:
            raise ValueError("STATEMENT_DEFINITION_IDEMPOTENCY_CONFLICT")
        return row["result"]

    def _receipt(self, db, scope, operation_id, digest, revision, result):
        db.execute("""INSERT INTO epm.operation_receipt
            (workspace_id,application_id,operation_id,command_digest,actor_id,
             committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
            (scope.workspace_id, scope.application_id, operation_id, digest,
             self.identity.subject_id, revision, Jsonb(result)))

    @staticmethod
    def _row(db, scope, definition_id, *, lock=False):
        row = db.execute(f"""SELECT {_SELECT} FROM epm.statement_definition
            WHERE workspace_id=%s AND application_id=%s AND definition_id=%s""" +
            (" FOR UPDATE" if lock else ""),
            (scope.workspace_id, scope.application_id, definition_id)).fetchone()
        if row is None:
            raise ValueError("STATEMENT_DEFINITION_UNAVAILABLE")
        return row

    @staticmethod
    def _record(row):
        try:
            definition = StatementDefinition.parse(row["definition"])
        except (TypeError, ValueError) as error:
            raise ValueError("STATEMENT_DEFINITION_PERSISTED_INVALID") from error
        if definition.definition_id != row["definition_id"] or definition.digest != row["canonical_digest"]:
            raise ValueError("STATEMENT_DEFINITION_PERSISTED_DIGEST_MISMATCH")
        return {"definitionId": definition.definition_id, "stateToken": row["state_token"],
            "status": row["status"], "active": row["status"] == "Active",
            "definitionDigest": definition.digest, "definition": row["definition"],
            "operationId": row["updated_operation_id"],
            "actor": {"issuer": row["updated_issuer"], "subjectId": row["updated_subject_id"]},
            "updatedAt": row["updated_at"]}


def _program(raw) -> tuple[str, dict]:
    if (not isinstance(raw, dict) or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2 or raw.get("function") not in FUNCTIONS
            or not isinstance(raw.get("arguments"), dict)):
        raise ValueError("STATEMENT_DEFINITION_PROGRAM_INVALID")
    return raw["function"], raw["arguments"]


def _target(definition_id, state_token=None, definition_digest=None):
    if not isinstance(definition_id, str) or not _ID.fullmatch(definition_id):
        raise ValueError("STATEMENT_DEFINITION_TARGET_INVALID")
    if state_token is not None:
        require_state_token(state_token, error="STATEMENT_DEFINITION_TARGET_INVALID")
    if (definition_digest is not None and (not isinstance(definition_digest, str)
            or not _DIGEST.fullmatch(definition_digest))):
        raise ValueError("STATEMENT_DEFINITION_TARGET_INVALID")


def _request_key(value):
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise ValueError("STATEMENT_DEFINITION_IDEMPOTENCY_KEY_INVALID")


def _digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
