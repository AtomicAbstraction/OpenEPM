"""Authoritative, transport-neutral cell editability inspection."""
from __future__ import annotations

import re

from psycopg.rows import dict_row

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_cube_query import _FILTER_ID
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import (
    authorize_coordinates, coordinate_read_allowed,
)
from .postgres_fact_batch import validate_coordinates
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import WORKFLOW_ROLE_UNBOUND, enforce_active_planning_policy
from .postgres_processing_limits import configure_statement_timeout


FUNCTION = "facts.cell.editability.read"
_ACTIONS = {"set": "Set", "add": "Add", "clear": "Clear"}
_UNAVAILABLE = "CELL_UNAVAILABLE"
_REASON = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_REVISION_ERRORS = {
    "metadata_revision": "STALE_METADATA_REVISION",
    "policy_revision": "STALE_POLICY_REVISION",
    "security_revision": "STALE_SECURITY_REVISION",
}
_MESSAGES = {
    WORKFLOW_ROLE_UNBOUND: "No current group assignment both links a planning duty and permits writing this cell.",
    _UNAVAILABLE: "The selected cell is unavailable.",
    "CALCULATED_RESULT_READ_ONLY":
        "Calculated result cells are read-only; update an authorized raw input cell or run its governing rule.",
    "APPLICATION_GRANT_REQUIRED":
        "Your current application role does not allow cell writeback.",
    "APPLICATION_NOT_WRITABLE":
        "The application is not currently writable.",
    "WORKSPACE_NOT_WRITABLE":
        "The workspace is not currently writable.",
    "PLANNING_INTERSECTION_LOCKED":
        "This cell is locked by the current planning workflow.",
}


def _program(program: object) -> tuple[dict[str, str], str, str, str]:
    if (not isinstance(program, dict)
            or set(program) != {"languageVersion", "function", "arguments"}
            or type(program.get("languageVersion")) is not int
            or program["languageVersion"] != 2
            or program.get("function") != FUNCTION
            or not isinstance(program.get("arguments"), dict)):
        raise ValueError("CELL_EDITABILITY_PROGRAM_INVALID")
    arguments = program["arguments"]
    if (set(arguments) != {"coordinate", "source", "action", "kind"}
            or not isinstance(arguments["coordinate"], dict)
            or not arguments["coordinate"]
            or any(not isinstance(identifier, str) or not _FILTER_ID.fullmatch(identifier)
                   for pair in arguments["coordinate"].items() for identifier in pair)
            or arguments["source"] not in ("raw", "calculated")
            or arguments["action"] not in tuple(_ACTIONS)
            or arguments["kind"] not in ("numeric", "text")
            or (arguments["kind"] == "text"
                and arguments["action"] == "add")):
        raise ValueError("CELL_EDITABILITY_ARGUMENTS_INVALID")
    return (arguments["coordinate"], arguments["source"],
            arguments["action"], arguments["kind"])


def _reason(error: Exception) -> str:
    value = str(error)
    if value.startswith("PLANNING_WRITE_DENIED:0:"):
        value = value.split(":", 2)[2]
    reason = value.split(":", 1)[0]
    return reason if _REASON.fullmatch(reason) else _UNAVAILABLE


def _result(allowed: bool, reason: str, *, evidence: dict | None = None) -> dict:
    message = (_MESSAGES.get(reason)
               or ("This cell is editable under the current server policy."
                   if allowed else
                   "The current server policy does not allow this cell writeback. "
                   f"Reason: {reason}."))
    return {"editable": allowed, "reasonCode": reason, "message": message,
            "policy": evidence}


def _revisions(db, scope):
    state = db.execute("""SELECT metadata_revision, policy_revision, security_revision
        FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None:
        raise ValueError("APPLICATION_UNAVAILABLE")
    return state


class PostgresCellEditability:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn, self.identity = dsn, identity

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        members, source, action, kind = _program(program)
        coordinate = Coordinate.from_mapping(members)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=FUNCTION)
                if source == "calculated":
                    return _result(False, "CALCULATED_RESULT_READ_ONLY")
                revisions = _revisions(db, scope)
                decision = self._raw_decision(db, scope, coordinate, action, kind, access)
                current = _revisions(db, scope)
                for field, error in _REVISION_ERRORS.items():
                    if current[field] != revisions[field]:
                        raise ValueError(error)
                if PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, "read", function=FUNCTION) != access:
                    raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
                return decision

    def _raw_decision(self, db, scope, coordinate, action, kind, read_access):
        try:
            validate_coordinates(db, scope, ({
                "series_key": coordinate.series_key,
                "members": dict(coordinate.members)},))
        except ValueError as error:
            if str(error) not in ("COORDINATE_DIMENSIONS_MISMATCH", "COORDINATE_MEMBER_UNAVAILABLE"):
                raise
            return _result(False, _UNAVAILABLE)
        if not coordinate_read_allowed(
                db, self.identity, scope, coordinate, expected_access=read_access):
            return _result(False, _UNAVAILABLE)
        try:
            access = PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "write",
                function="facts.numeric.batch" if kind == "numeric" else "facts.text.batch")
            if access != read_access:
                raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
            authorize_coordinates(db, self.identity, scope, (coordinate,),
                                  kind=AccessKind.WRITE, expected_access=access)
            evidence = enforce_active_planning_policy(
                db, scope, writes=((coordinate, _ACTIONS[action]),), workflow_role=access.role, identity=self.identity)
        except (AccessDenied, ValueError) as error:
            if str(error) in (CUBE_READ_AUTHORIZATION_STALE, "DIMENSIONAL_SECURITY_REVISION_CHANGED"):
                raise
            return _result(False, _reason(error))
        return _result(True, evidence["reasonCode"], evidence=evidence)


def editability_program_contract() -> dict:
    from .metadata_read_contract import obj, read_contract, read_example
    from .postgres_planning_write_guard import planning_write_evidence_schema

    identifier = {"type": "string", "minLength": 1,
                  "pattern": "^" + _FILTER_ID.pattern.removesuffix(r"\Z") + r"(?![\s\S])"}
    arguments = obj({
        "coordinate": {"type": "object", "minProperties": 1,
                       "propertyNames": identifier, "additionalProperties": identifier},
        "source": {"enum": ["raw", "calculated"]},
        "action": {"enum": list(_ACTIONS)},
        "kind": {"enum": ["numeric", "text"]},
    })
    arguments["if"] = {"properties": {"kind": {"const": "text"}}}
    arguments["then"] = {"properties": {"action": {"enum": ["set", "clear"]}}}
    evidence = planning_write_evidence_schema()
    result = {
        **obj({"editable": {"type": "boolean"}, "message": {"type": "string", "minLength": 1},
               "reasonCode": {"type": "string", "pattern": r"^[A-Z][A-Z0-9_]{0,127}(?![\s\S])"},
               "policy": {"anyOf": [evidence, {"type": "null"}]}}),
        "if": {"properties": {"editable": {"const": True}}},
        "then": {"properties": {"policy": evidence}},
        "else": {"properties": {"policy": {"type": "null"}}},
    }
    raw = {"coordinate": {"Metric": "Input"}, "source": "raw", "action": "set", "kind": "numeric"}
    return read_contract(FUNCTION, arguments, result, owner="PostgresCellEditability.read",
        examples=[
            read_example(FUNCTION, raw, name="Inspect raw numeric writeback",
                binding="Use one current member on every active fact axis of the selected application."),
            read_example(FUNCTION, {**raw, "source": "calculated"}, name="Inspect a calculated cell",
                binding="Pass the coordinate already returned by an authorized result read. This response describes the calculated layer's write policy."),
        ], semantic_rules=[
            "Raw decisions use the current full coordinate, dimensional READ and WRITE, application role and active planning policy.",
            "An unreadable or unavailable raw cell returns CELL_UNAVAILABLE and no policy evidence. Obtain authorized current metadata before selecting a new coordinate.",
            "Calculated cells are read-only. A calculated decision describes the layer without locating a publication or checking for a value.",
            "An editable response is a current inspection. Preview, admission and publication independently enforce write authorization.",
        ])


def catalog() -> dict:
    return {FUNCTION: {
        **editability_program_contract(),
        "mode": "read", "permission": "read",
        "arguments": {
            "coordinate": "one complete stable-ID coordinate",
            "source": "raw or calculated",
            "action": "set, add or clear",
            "kind": "numeric or text; text does not support add",
        },
        "result": ("current server-authoritative editability decision and "
                   "meaningful reason; the write path rechecks the same policy"),
        "previewRequired": False, "idempotencyRequired": False,
        "workClass": "short",
    }}
