"""Shared application context: one current decision per stable identifier."""
from __future__ import annotations

import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .current_object_contract import collection_token, new_state_token, require_state_token
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
_ID = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_CONTENT = ("title", "text", "provenance", "rationale", "sourceReference")
_SELECT = """decision_id,title,decision_text,rationale,source_reference,
    provenance,status,state_token,content_digest,updated_issuer,
    updated_subject_id,updated_at,updated_operation_id"""


def catalog() -> dict:
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
    spec = catalog()[function]
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
        for name, maximum in (("title", 200), ("text", 8000), ("rationale", 2000), ("sourceReference", 1000)):
            args[name] = _text(args.get(name, ""), name.upper(), maximum, required=name in ("title", "text"))
        if args["provenance"] not in ("UserDecision", "AgentInterpretation"):
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
        if type(idempotency_key) is not str or not _KEY.fullmatch(idempotency_key):
            raise ValueError("APPLICATION_DECISION_IDEMPOTENCY_KEY_INVALID")
        digest = _canonical_digest({"scope": [scope.workspace_id, scope.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id], "program": program})
        ids = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._authorize(db, scope, function)
                state = db.execute("""SELECT s.commit_revision,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s""", ids).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                prior = db.execute("""SELECT command_digest,actor_id,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s""", (*ids, idempotency_key)).fetchone()
                if prior is not None:
                    if prior["command_digest"] != digest or prior["actor_id"] != self.identity.subject_id:
                        raise ValueError("IDEMPOTENCY_KEY_REUSED")
                    return prior["result"]
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
                    if row is None:
                        raise ValueError("APPLICATION_DECISION_NOT_FOUND")
                    return _record(row)
                all_rows = db.execute("SELECT decision_id,state_token FROM epm.application_decision WHERE workspace_id=%s AND application_id=%s ORDER BY decision_id", ids).fetchall()
                current_collection_token = collection_token(
                    (row["decision_id"], row["state_token"]) for row in all_rows)
                if ("expectedCollectionToken" in args
                        and args["expectedCollectionToken"] != current_collection_token):
                    raise ValueError("APPLICATION_DECISION_LIST_STALE")
                limit = args.get("limit", 25)
                rows = db.execute(f"""SELECT {_SELECT} FROM epm.application_decision
                    WHERE workspace_id=%s AND application_id=%s AND decision_id>%s
                    ORDER BY decision_id LIMIT %s""", (*ids, args.get("afterDecisionId", ""), limit + 1)).fetchall()
                items = [{key: value for key, value in _record(row).items()
                          if key not in ("text", "rationale", "sourceReference")} for row in rows[:limit]]
                return {"items": items, "collectionToken": current_collection_token,
                        "nextAfterDecisionId": rows[limit - 1]["decision_id"] if len(rows) > limit else None}
