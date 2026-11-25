"""Shared application context: one current decision per stable identifier."""
from __future__ import annotations

import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .current_object_contract import STATE_TOKEN_PATTERN, collection_token, new_state_token, require_state_token
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout

CREATE = "application.decision.create"
REPLACE = "application.decision.replace"
WITHDRAW = "application.decision.withdraw"
READ = "application.decision.read"
LIST = "application.decision.list"
WRITES = frozenset((CREATE, REPLACE, WITHDRAW))
READS = frozenset((READ, LIST))
FUNCTIONS = WRITES | READS
_ID = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_CONTENT = ("title", "text", "provenance", "rationale", "sourceReference")
_TEXT_LIMITS = {"title": 200, "text": 8000, "rationale": 2000, "sourceReference": 1000}
_PROVENANCE = ("UserDecision", "AgentInterpretation")
_SELECT = """decision_id,title,decision_text,rationale,source_reference,
    provenance,status,state_token,content_digest,updated_issuer,
    updated_subject_id,updated_at,updated_operation_id"""


def decision_program_contract(function: str) -> dict:
    from .metadata_read_contract import DIALECT, read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = {"type": "string", "pattern": "^" + _ID.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    token = {"type": "string", "pattern": "^" + STATE_TOKEN_PATTERN.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    content = {name: {"type": "string", "minLength": int(name in ("title", "text")),
        "maxLength": limit, "pattern": r"^[^\u0000]*(?![\s\S])",
        "description": f"The native policy limits this field to {limit} UTF-8 bytes."}
        for name, limit in _TEXT_LIMITS.items()}
    content["provenance"] = {"enum": list(_PROVENANCE)}
    identity = {"decisionId": identifier, "stateToken": token, "contentDigest": token}
    summary = {**identity, "status": {"enum": ["Active", "Withdrawn"]},
        "title": content["title"], "provenance": content["provenance"],
        "actor": obj({"issuer": {"type": "string"}, "subjectId": {"type": "string"}}),
        "updatedAt": {"type": "string", "format": "date-time"}, "operationId": {"type": "string"}}
    sample_id, sample_token = "example-freight-treatment", "a" * 64
    if function == LIST:
        arguments = obj({"limit": {"type": "integer", "minimum": 1, "maximum": 100},
                         "afterDecisionId": identifier, "expectedCollectionToken": token}, [])
        arguments["allOf"] = [{"if": {"required": ["afterDecisionId"]},
                                "then": {"required": ["expectedCollectionToken"]}}]
        result = obj({"items": {"type": "array", "maxItems": 100, "items": obj(summary)},
                      "collectionToken": token, "nextAfterDecisionId": {"anyOf": [identifier, {"type": "null"}]}})
        examples = [read_example(function, {"limit": 1}, name="List current decision summaries",
                        binding="Select the application with current administrator access."),
                    read_example(function, {"limit": 1, "afterDecisionId": sample_id,
                        "expectedCollectionToken": sample_token}, name="Continue the same decision collection",
                        binding="Copy nextAfterDecisionId and collectionToken from the previous page. A null cursor ends the list.")]
    elif function == READ:
        arguments = obj({"decisionId": identifier})
        result = obj({**summary, **content})
        examples = [read_example(function, {"decisionId": sample_id}, name="Read the current decision and rationale",
                                 binding="Use a decisionId from a current list in the same application.")]
    else:
        fields, sample = {"decisionId": identifier}, {"decisionId": sample_id}
        required = ["decisionId"]
        binding = "Choose a new stable decision ID in the selected application."
        if function != CREATE:
            fields["expectedStateToken"] = token
            sample["expectedStateToken"] = sample_token
            required.append("expectedStateToken")
            binding = "Copy the decisionId and stateToken from the same current decision read."
        if function != WITHDRAW:
            fields.update(content)
            required.extend(("title", "text", "provenance"))
            sample.update(title="Freight treatment", text="Keep freight in its own responsibility centre.",
                          provenance="UserDecision", rationale="The administrator approved separate tracking.")
        arguments = obj(fields, required)
        result = obj({**identity, "status": {"const": "Withdrawn" if function == WITHDRAW else "Active"},
            "operationId": {"type": "string", "pattern": "^" + _KEY.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}})
        action = {CREATE: "Record", REPLACE: "Replace", WITHDRAW: "Withdraw"}[function]
        examples = [read_example(function, sample, name=f"{action} a decision",
                                 binding=binding + " Request signed operation admission for the unchanged program.")]
    contract = read_contract(function, arguments, result, owner="PostgresApplicationDecisions", examples=examples,
        semantic_rules=[
            "Current application administrator authority is required for reads and effects.",
            "Each stable ID identifies one current decision. Read returns that decision. List returns summaries; withdrawn decisions remain visible with their status.",
            "UserDecision records an approved decision. AgentInterpretation identifies an inference. Recording either leaves facts and formulas unchanged.",
            "The fixed owner checks nonblank required text and the declared UTF-8 byte limits.",
        ])
    if function in WRITES:
        contract["resultSchema"] = {"$schema": DIALECT, **obj({
            "languageVersion": {"type": "integer", "const": 2}, "function": {"const": function},
            **result["properties"]})}
    contract["programContract"]["recovery"] = (
        "Restart a stale list from its first page. Read the current decision after a state conflict before reviewing a new edit. "
        "Reconcile an interrupted write using the same signed admission and unchanged program. After expiry, "
        "that request can retrieve only its committed receipt under current administrator authority.")
    return contract


def _descriptors() -> dict:
    common = {"permission": "admin", "previewRequired": False,
              "workClass": "short", "requiredCapabilities": []}
    content = {"title": "1–200 UTF-8 bytes", "text": "1–8000 UTF-8 bytes",
               "provenance": "UserDecision or AgentInterpretation"}
    optional = {"rationale": "up to 2000 UTF-8 bytes",
                "sourceReference": "up to 1000 UTF-8 bytes; plain text"}
    return {
        CREATE: {**common, "mode": "atomic_context_write", "idempotencyRequired": True,
                 "arguments": {"decisionId": "stable ID", **content},
                 "optionalArguments": optional, "result": "current decision and receipt"},
        REPLACE: {**common, "mode": "atomic_context_write", "idempotencyRequired": True,
                  "arguments": {"decisionId": "stable ID", "expectedStateToken": "current opaque token", **content},
                  "optionalArguments": optional, "result": "replacement current decision and receipt"},
        WITHDRAW: {**common, "mode": "atomic_context_write", "idempotencyRequired": True,
                   "arguments": {"decisionId": "stable ID", "expectedStateToken": "current opaque token"},
                   "result": "current decision marked Withdrawn and receipt"},
        READ: {**common, "mode": "read_only", "idempotencyRequired": False,
               "arguments": {"decisionId": "stable ID"}, "result": "current decision"},
        LIST: {**common, "mode": "read_only", "idempotencyRequired": False,
               "arguments": {}, "optionalArguments": {"limit": "1–100; default 25",
                   "afterDecisionId": "keyset cursor", "expectedCollectionToken": "required with cursor"},
               "result": "bounded current summaries, collectionToken and nextAfterDecisionId"},
    }


def catalog() -> dict:
    return {function: {**specification, **decision_program_contract(function)}
            for function, specification in _descriptors().items()}


def _integer(value: object, label: str, *, minimum: int = 1, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"APPLICATION_DECISION_{label}_INVALID")
    return value


def _text(value: object, label: str, maximum: int, *, required: bool = False) -> str:
    if (type(value) is not str or "\x00" in value or len(value.encode("utf-8")) > maximum
            or (required and not value.strip())):
        raise ValueError(f"APPLICATION_DECISION_{label}_INVALID")
    return value


def parse(program: object, allowed: frozenset[str]) -> tuple[str, dict]:
    if (type(program) is not dict or set(program) != {"languageVersion", "function", "arguments"}
            or type(program.get("languageVersion")) is not int or program["languageVersion"] != 2
            or not isinstance(program.get("function"), str) or program["function"] not in allowed
            or type(program.get("arguments")) is not dict):
        raise ValueError("APPLICATION_DECISION_PROGRAM_INVALID")
    function, args = program["function"], dict(program["arguments"])
    spec = _descriptors()[function]
    required, optional = set(spec["arguments"]), set(spec.get("optionalArguments", {}))
    if not required <= set(args) or set(args) - required - optional:
        raise ValueError("APPLICATION_DECISION_ARGUMENTS_INVALID")
    for name in ("decisionId", "afterDecisionId"):
        if name in args and (type(args[name]) is not str or not _ID.fullmatch(args[name])):
            raise ValueError("APPLICATION_DECISION_ID_INVALID")
    for name in ("expectedStateToken", "expectedCollectionToken"):
        if name in args:
            require_state_token(args[name], error="APPLICATION_DECISION_STATE_TOKEN_INVALID")
    if "limit" in args:
        _integer(args["limit"], "LIMIT", maximum=100)
    if "afterDecisionId" in args and "expectedCollectionToken" not in args:
        raise ValueError("APPLICATION_DECISION_CONTINUATION_PIN_REQUIRED")
    if function in (CREATE, REPLACE):
        for name, maximum in _TEXT_LIMITS.items():
            args[name] = _text(args.get(name, ""), name.upper(), maximum, required=name in ("title", "text"))
        if args["provenance"] not in _PROVENANCE:
            raise ValueError("APPLICATION_DECISION_PROVENANCE_INVALID")
    return function, args


def _record(row: dict) -> dict:
    return {"decisionId": row["decision_id"], "title": row["title"],
            "text": row["decision_text"], "rationale": row["rationale"],
            "sourceReference": row["source_reference"], "provenance": row["provenance"],
            "status": row["status"], "stateToken": row["state_token"],
            "actor": {"issuer": row["updated_issuer"], "subjectId": row["updated_subject_id"]},
            "updatedAt": row["updated_at"].isoformat(), "operationId": row["updated_operation_id"],
            "contentDigest": row["content_digest"]}


class PostgresApplicationDecisions:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime", ("application_decision",))
        self.dsn, self.identity = dsn, identity

    def _authorize(self, db, scope: ApplicationScope, function: str) -> None:
        configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin", function=function)

    def execute(self, scope: ApplicationScope, program: dict, *, idempotency_key: str) -> dict:
        function, args = parse(program, WRITES)
        digest = self._intent_digest(scope, program, idempotency_key)
        ids = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._authorize(db, scope, function)
                state = db.execute("""SELECT s.commit_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s""", ids).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                prior = self._original_receipt(db, scope, idempotency_key, digest)
                if prior is not None:
                    return prior
                if state["status"] != "Active" or state["processing_mode"] != "Active":
                    raise ValueError("APPLICATION_NOT_ACTIVE")
                current = db.execute(f"""SELECT {_SELECT} FROM epm.application_decision
                    WHERE workspace_id=%s AND application_id=%s AND decision_id=%s FOR UPDATE""",
                    (*ids, args["decisionId"])).fetchone()
                if function == CREATE:
                    if current is not None:
                        raise ValueError("APPLICATION_DECISION_ALREADY_EXISTS")
                else:
                    if current is None:
                        raise ValueError("APPLICATION_DECISION_NOT_FOUND")
                    if args["expectedStateToken"] != current["state_token"]:
                        raise ValueError("APPLICATION_DECISION_STATE_CONFLICT")
                    if function == WITHDRAW:
                        if current["status"] == "Withdrawn":
                            raise ValueError("APPLICATION_DECISION_ALREADY_WITHDRAWN")
                        record = _record(current)
                        args.update({key: record[key] for key in _CONTENT})
                status = "Withdrawn" if function == WITHDRAW else "Active"
                content = {key: args[key] for key in _CONTENT}
                content_digest = _canonical_digest({**content, "status": status})
                state_token, revision = new_state_token(), state["commit_revision"] + 1
                result = {"languageVersion": 2, "function": function, "decisionId": args["decisionId"],
                          "status": status, "stateToken": state_token, "contentDigest": content_digest,
                          "operationId": idempotency_key}
                db.execute("UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s",
                           (revision, *ids))
                db.execute("""INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (*ids, idempotency_key, digest, self.identity.subject_id, revision, Jsonb(result)))
                db.execute("""INSERT INTO epm.application_decision
                    (workspace_id,application_id,decision_id,title,decision_text,rationale,source_reference,
                     provenance,status,state_token,content_digest,updated_operation_id,
                     updated_issuer,updated_subject_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,decision_id) DO UPDATE SET
                      title=EXCLUDED.title,decision_text=EXCLUDED.decision_text,rationale=EXCLUDED.rationale,
                      source_reference=EXCLUDED.source_reference,provenance=EXCLUDED.provenance,
                      status=EXCLUDED.status,state_token=EXCLUDED.state_token,content_digest=EXCLUDED.content_digest,
                      updated_operation_id=EXCLUDED.updated_operation_id,
                      updated_issuer=EXCLUDED.updated_issuer,updated_subject_id=EXCLUDED.updated_subject_id,
                      updated_at=clock_timestamp()""",
                    (*ids, args["decisionId"], args["title"], args["text"], args["rationale"],
                     args["sourceReference"], args["provenance"], status, state_token, content_digest,
                     idempotency_key, self.identity.issuer, self.identity.subject_id))
                return result

    def _intent_digest(self, scope: ApplicationScope, program: dict, operation_id: str) -> str:
        if type(operation_id) is not str or not _KEY.fullmatch(operation_id):
            raise ValueError("APPLICATION_DECISION_IDEMPOTENCY_KEY_INVALID")
        return _canonical_digest({"scope": [scope.workspace_id, scope.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id], "program": program})

    def _original_receipt(self, db, scope: ApplicationScope, operation_id: str, digest: str) -> dict | None:
        prior = db.execute("""SELECT command_digest,actor_id,result FROM epm.operation_receipt
            WHERE workspace_id=%s AND application_id=%s AND operation_id=%s""",
            (scope.workspace_id, scope.application_id, operation_id)).fetchone()
        if prior is None:
            return None
        if prior["command_digest"] != digest or prior["actor_id"] != self.identity.subject_id:
            raise ValueError("IDEMPOTENCY_KEY_REUSED")
        return prior["result"]

    def replay(self, scope: ApplicationScope, program: dict, *, idempotency_key: str) -> dict | None:
        function, _ = parse(program, WRITES)
        digest = self._intent_digest(scope, program, idempotency_key)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._authorize(db, scope, function)
                return self._original_receipt(db, scope, idempotency_key, digest)

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        function, args = parse(program, READS)
        ids = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._authorize(db, scope, function)
                state = db.execute("SELECT commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR SHARE", ids).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if function == READ:
                    row = db.execute(f"SELECT {_SELECT} FROM epm.application_decision WHERE workspace_id=%s AND application_id=%s AND decision_id=%s",
                                     (*ids, args["decisionId"])).fetchone()
                    result = None if row is None else _record(row)
                    # The workspace fence does not serialize native identity
                    # directory updates. Check current authority at publication.
                    PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin", function=function)
                    if result is None:
                        raise ValueError("APPLICATION_DECISION_NOT_FOUND")
                    return result
                all_rows = db.execute("SELECT decision_id,state_token FROM epm.application_decision WHERE workspace_id=%s AND application_id=%s ORDER BY decision_id", ids).fetchall()
                current_collection_token = collection_token(
                    (row["decision_id"], row["state_token"]) for row in all_rows)
                if ("expectedCollectionToken" in args
                        and args["expectedCollectionToken"] != current_collection_token):
                    PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin", function=function)
                    raise ValueError("APPLICATION_DECISION_LIST_STALE")
                limit = args.get("limit", 25)
                rows = db.execute(f"""SELECT {_SELECT} FROM epm.application_decision
                    WHERE workspace_id=%s AND application_id=%s AND decision_id>%s
                    ORDER BY decision_id LIMIT %s""", (*ids, args.get("afterDecisionId", ""), limit + 1)).fetchall()
                items = [{key: value for key, value in _record(row).items()
                          if key not in ("text", "rationale", "sourceReference")} for row in rows[:limit]]
                PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin", function=function)
                return {"items": items, "collectionToken": current_collection_token,
                        "nextAfterDecisionId": rows[limit - 1]["decision_id"] if len(rows) > limit else None}
