"""Authorized, bounded inspection of application operation receipts."""
from __future__ import annotations

import re
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout

READ = "application.operation.receipt.read"
_OPERATION_ID = re.compile(r"[^\x00]{1,200}\Z")
_SAFE_OUTCOME_FIELDS = (
    "function", "status", "changedCount", "setCount", "clearCount",
    "committedCount", "rejectedCount", "occurrenceId", "activityId",
    "jobId", "batchId", "requestId", "activationId", "resultKey",
)


def catalog() -> dict:
    return {READ: {
        "mode": "read_only", "permission": "read",
        "previewRequired": False, "idempotencyRequired": False,
        "workClass": "short",
        "arguments": {"operationId": "exact application operation identity"},
        "result": "bounded receipt identity, actor, revision, time and safe outcome summary",
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
                or program.get("languageVersion") != 2
                or program.get("function") != READ
                or type(program.get("arguments")) is not dict
                or set(program["arguments"]) != {"operationId"}):
            raise ValueError("OPERATION_RECEIPT_READ_PROGRAM_INVALID")
        operation_id = program["arguments"]["operationId"]
        if type(operation_id) is not str or _OPERATION_ID.fullmatch(operation_id) is None:
            raise ValueError("OPERATION_RECEIPT_ID_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=READ)
                row = db.execute("""SELECT operation_id,command_digest,actor_id,
                    committed_revision,committed_at,result
                    FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                      AND operation_id=%s""", (
                        scope.workspace_id, scope.application_id,
                        operation_id)).fetchone()
                if (row is not None and type(row['result']) is dict
                        and isinstance(row['result'].get('function'), str)
                        and row['result'].get('function', '').startswith('application.decision.')):
                    # Decision context, including its audit projection, remains
                    # private to current effective application administrators.
                    PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'admin', function=READ)
        if row is None:
            raise ValueError("OPERATION_RECEIPT_NOT_FOUND")
        result = row["result"] if type(row["result"]) is dict else {}
        outcome = {key: result[key] for key in _SAFE_OUTCOME_FIELDS
                   if key in result and type(result[key]) in (str, int, bool)}
        return {
            "operationId": row["operation_id"],
            "commandDigest": row["command_digest"],
            "actorId": row["actor_id"],
            "committedRevision": row["committed_revision"],
            "committedAt": row["committed_at"].isoformat(),
            "outcome": outcome,
        }
