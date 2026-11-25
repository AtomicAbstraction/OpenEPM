"""Authorized, bounded inspection of application operation receipts."""
from __future__ import annotations

import re
from psycopg.rows import dict_row

from .application_workflow import _ID as _WORKFLOW_IDENTIFIER, _text_schema
from .application_authorization_actions import action_allows_operation
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_application_workflow_occurrences import RETURN as WORKFLOW_RETURN
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout

READ = "application.operation.receipt.read"
RECEIPT_AUTHORIZATION_STALE = "OPERATION_RECEIPT_AUTHORIZATION_STALE"
_ID_MAX_LENGTH = 200
_ID_BODY = r"[^\u0000]+"
_OPERATION_ID = re.compile(_ID_BODY)
_SAFE_OUTCOME_FIELDS = (
    "function", "status", "changedCount", "setCount", "clearCount",
    "committedCount", "rejectedCount", "occurrenceId", "activityId",
    "jobId", "batchId", "requestId", "activationId", "resultKey",
)


def read_program_contract() -> dict:
    from .metadata_read_contract import read_contract, read_example
    from .postgres_numeric_catalog import obj

    identifier = {"type": "string", "minLength": 1, "maxLength": _ID_MAX_LENGTH,
                  "pattern": "^" + _ID_BODY + r"(?![\s\S])"}
    outcome = obj({**dict.fromkeys(_SAFE_OUTCOME_FIELDS,
        {"type": ["string", "integer", "boolean"]}),
        "returnedToActivityId": _text_schema(_WORKFLOW_IDENTIFIER)}, [])
    outcome["dependentSchemas"] = {"returnedToActivityId": {
        "required": ["function"], "properties": {"function": {"const": WORKFLOW_RETURN}},
    }}
    contract = read_contract(READ, obj({"operationId": identifier}), obj({
        "operationId": identifier,
        "actorId": identifier,
        "commandDigest": {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"},
        "committedRevision": {"type": "integer", "minimum": 1, "maximum": 2**63 - 1},
        "committedAt": {"type": "string", "format": "date-time"},
        "outcome": outcome,
    }), owner="PostgresOperationReceipts", examples=[
        read_example(READ, {"operationId": "example-operation"},
            name="Inspect the recorded outcome of an exact operation",
            binding="Use the receipt reference from the original operation in this application. For a job or batch, follow its published outcome contract for the exact receipt reference."),
    ], semantic_rules=[
        "Under legacy authorization this read uses the current application READ grant. Application decision receipts additionally require effective administrator access.",
        "Under group authorization a policy manager can inspect their own planning policy receipt while they hold the action that recorded it. Other receipts are unavailable through this read.",
        "The core rechecks effective application access before disclosure.",
        "An unavailable receipt returns OPERATION_RECEIPT_NOT_FOUND, including a decision receipt outside the caller's access.",
        "The optional outcome fields summarize the original commit. Use the operation's current status for currentness and further permitted action.",
        "A workflow return receipt can include the original returnedToActivityId. Compare it to the reviewed return target when reconciling the original action.",
    ])
    contract["programContract"]["recovery"] = (
        "For OPERATION_RECEIPT_NOT_FOUND, check the original operation's authorized status. "
        "Keep the original admitted request for reconciliation if its outcome remains unknown. "
        "For OPERATION_RECEIPT_AUTHORIZATION_STALE, refresh current access and read the same receipt again."
    )
    return contract


def catalog() -> dict:
    return {READ: {
        "mode": "read_only", "permission": "read",
        "previewRequired": False, "idempotencyRequired": False,
        "workClass": "short",
        "arguments": {"operationId": "exact application operation identity"},
        "result": "bounded receipt identity, actor, revision, time and safe outcome summary",
        **read_program_contract(),
    }}


class PostgresOperationReceipts:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime", ("operation_receipt",))
        self.dsn = dsn
        self.identity = identity

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if (type(program) is not dict
                or set(program) != {"languageVersion", "function", "arguments"}
                or type(program.get("languageVersion")) is not int
                or program.get("languageVersion") != 2
                or program.get("function") != READ
                or type(program.get("arguments")) is not dict
                or set(program["arguments"]) != {"operationId"}):
            raise ValueError("OPERATION_RECEIPT_READ_PROGRAM_INVALID")
        operation_id = program["arguments"]["operationId"]
        if (type(operation_id) is not str or len(operation_id) > _ID_MAX_LENGTH
                or _OPERATION_ID.fullmatch(operation_id) is None):
            raise ValueError("OPERATION_RECEIPT_ID_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=READ)
                row = db.execute("""SELECT operation_id,command_digest,actor_id,
                    committed_revision,committed_at,result
                    FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                      AND operation_id=%s""", (
                        scope.workspace_id, scope.application_id,
                        operation_id)).fetchone()
                if row is not None and access.authorization_model == 'group_assignments':
                    from .postgres_planning_workflow_policy import ACTIVATE, DEACTIVATE, SAVE
                    result = row['result'] if isinstance(row['result'], dict) else {}
                    function = result.get('function')
                    if (function not in (SAVE, ACTIVATE, DEACTIVATE)
                            or row['actor_id'] != self.identity.subject_id
                            or result.get('actorIssuer') != self.identity.issuer
                            or not action_allows_operation(access.actions, function)):
                        row = None
                elif (row is not None and type(row['result']) is dict
                        and isinstance(row['result'].get('function'), str)
                        and row['result'].get('function', '').startswith('application.decision.')):
                    # Preserve the existing application administrator gate and
                    # project a denied private receipt like an absent receipt.
                    try:
                        PostgresAccessChecker.check_in_transaction(
                            db, self.identity, scope, "admin", function=READ)
                    except AccessDenied:
                        row = None
                current = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=READ)
                if current != access:
                    raise ValueError(RECEIPT_AUTHORIZATION_STALE)
        if row is None:
            raise ValueError("OPERATION_RECEIPT_NOT_FOUND")
        result = row["result"] if type(row["result"]) is dict else {}
        outcome = {key: result[key] for key in _SAFE_OUTCOME_FIELDS
                   if key in result and type(result[key]) in (str, int, bool)}
        target = result.get("returnedToActivityId")
        if (result.get("function") == WORKFLOW_RETURN and type(target) is str
                and _WORKFLOW_IDENTIFIER.fullmatch(target) is not None):
            outcome["returnedToActivityId"] = target
        return {
            "operationId": row["operation_id"],
            "commandDigest": row["command_digest"],
            "actorId": row["actor_id"],
            "committedRevision": row["committed_revision"],
            "committedAt": row["committed_at"].isoformat(),
            "outcome": outcome,
        }
