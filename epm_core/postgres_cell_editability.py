"""Authoritative, transport-neutral cell editability inspection."""
from __future__ import annotations

from psycopg.rows import dict_row

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_security_enforcement import authorize_coordinate
from .postgres_fact_batch import validate_coordinates
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy


FUNCTION = "facts.cell.editability.read"
_ACTIONS = {"set": "Set", "add": "Add", "clear": "Clear"}
_MESSAGES = {
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
            or program.get("languageVersion") != 2
            or program.get("function") != FUNCTION
            or not isinstance(program.get("arguments"), dict)):
        raise ValueError("CELL_EDITABILITY_PROGRAM_INVALID")
    arguments = program["arguments"]
    if (set(arguments) != {"coordinate", "source", "action", "kind"}
            or not isinstance(arguments["coordinate"], dict)
            or not arguments["coordinate"]
            or any(not isinstance(axis, str) or not axis
                   or not isinstance(member, str) or not member
                   for axis, member in arguments["coordinate"].items())
            or arguments["source"] not in ("raw", "calculated")
            or arguments["action"] not in _ACTIONS
            or arguments["kind"] not in ("numeric", "text")
            or (arguments["kind"] == "text"
                and arguments["action"] == "add")):
        raise ValueError("CELL_EDITABILITY_ARGUMENTS_INVALID")
    return (arguments["coordinate"], arguments["source"],
            arguments["action"], arguments["kind"])


def _reason(error: Exception) -> str:
    value = str(error)
    if value.startswith("PLANNING_WRITE_DENIED:0:"):
        return value.split(":", 2)[2]
    return value.split(":", 1)[0]


def _result(allowed: bool, reason: str, *, evidence: dict | None = None) -> dict:
    message = (_MESSAGES.get(reason)
               or ("This cell is editable under the current server policy."
                   if allowed else
                   "The current server policy does not allow this cell writeback. "
                   f"Reason: {reason}."))
    return {"editable": allowed, "reasonCode": reason, "message": message,
            "policy": evidence}


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
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=FUNCTION)
                if source == "calculated":
                    return _result(False, "CALCULATED_RESULT_READ_ONLY")
                try:
                    validate_coordinates(db, scope, ({
                        "series_key": coordinate.series_key,
                        "members": dict(coordinate.members)},))
                    access = PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, "write",
                        function=("facts.numeric.batch" if kind == "numeric"
                                  else "facts.text.batch"))
                    authorize_coordinate(db, self.identity, scope, coordinate,
                                         kind=AccessKind.WRITE)
                    evidence = enforce_active_planning_policy(
                        db, scope, writes=((coordinate, _ACTIONS[action]),),
                        workflow_role=access.role)
                except (AccessDenied, ValueError) as error:
                    return _result(False, _reason(error))
                return _result(True, evidence["reasonCode"], evidence=evidence)


def catalog() -> dict:
    return {FUNCTION: {
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
