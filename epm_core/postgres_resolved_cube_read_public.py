"""Public W09 adapter for direct and durable resolved cube reads."""
from __future__ import annotations

from .cube_aggregate_lifecycle import AggregateCursorCodec
from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_resolved_cube_read import (
    FUNCTION as DIRECT, PostgresResolvedCubeRead)
from .resolved_cube_read_technical import ResolvedCubeReadTechnicalService


REQUEST = "facts.cube.resolved.request"
RESULT_READ = "facts.cube.resolved.result.read"
CANCEL = "facts.cube.resolved.cancel"
BINDING_LIST = "facts.cube.resolved.binding.list"
FUNCTIONS = frozenset({DIRECT, REQUEST, RESULT_READ, CANCEL, BINDING_LIST})


def catalog() -> dict[str, dict[str, object]]:
    common = {"permission": "read", "previewRequired": False,
              "idempotencyRequired": False}
    return {
        DIRECT: {**common, "mode": "read", "workClass": "short",
            "arguments": {
                "format": "openepm-resolved-cube-read-v1",
                "selection": "complete coordinate-layout selection",
                "source": "own or active effective binding",
                "outputGrain": "all active fact dimensions",
                "freshness": "current or allow_stale",
                "dynamicFallback": "explicit boolean",
                "delivery": "direct",
                "presentation": "page size and missing/zero suppression",
                "limits": "bounded rows, sources and timeout"},
            "result": "bounded authorized snapshot with typed resolved rows, presentation, origin, currentness and lineage"},
        REQUEST: {**common, "mode": "durable_technical_query",
            "workClass": "medium",
            "arguments": {"query": "openepm-resolved-cube-read-v1 with technical_query delivery"},
            "optionalArguments": {"pageSize": "1-500", "ttlSeconds": "1-900"},
            "result": "durable resolved-read query identity"},
        RESULT_READ: {**common, "mode": "read", "workClass": "short",
            "arguments": {"queryId": "accepted resolved-read query"},
            "optionalArguments": {"cursor": "signed result cursor",
                                  "pageSize": "1-500"},
            "result": "durable status or fixed certified result page"},
        CANCEL: {**common, "mode": "technical_control", "workClass": "short",
            "arguments": {"queryId": "accepted resolved-read query"},
            "result": "durable cancellation state"},
        BINDING_LIST: {**common, "mode": "read", "workClass": "bounded_read",
            "arguments": {"limit": "1-100 active bindings",
                          "afterBindingId": "optional continuation"},
            "result": "authorized active effective bindings and stage summaries"},
    }


def _program(raw: object) -> tuple[str, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") not in FUNCTIONS
            or not isinstance(raw.get("arguments"), dict)):
        raise ValueError("RESOLVED_READ_PUBLIC_PROGRAM_INVALID")
    function, arguments = raw["function"], raw["arguments"]
    if function == DIRECT:
        return function, arguments
    if function == BINDING_LIST:
        if (set(arguments) - {"limit", "afterBindingId"}
                or type(arguments.get("limit", 100)) is not int
                or not 1 <= arguments.get("limit", 100) <= 100
                or ("afterBindingId" in arguments
                    and not isinstance(arguments["afterBindingId"], str))):
            raise ValueError("RESOLVED_READ_PUBLIC_ARGUMENTS_INVALID")
        return function, arguments
    if function == REQUEST:
        if (set(arguments) - {"query", "pageSize", "ttlSeconds"}
                or "query" not in arguments
                or not isinstance(arguments["query"], dict)
                or ("pageSize" in arguments
                    and type(arguments["pageSize"]) is not int)
                or ("ttlSeconds" in arguments
                    and type(arguments["ttlSeconds"]) is not int)):
            raise ValueError("RESOLVED_READ_PUBLIC_ARGUMENTS_INVALID")
    elif function == RESULT_READ:
        if (set(arguments) - {"queryId", "cursor", "pageSize"}
                or "queryId" not in arguments
                or not isinstance(arguments["queryId"], str)
                or ("cursor" in arguments
                    and not isinstance(arguments["cursor"], str))
                or ("pageSize" in arguments
                    and type(arguments["pageSize"]) is not int)):
            raise ValueError("RESOLVED_READ_PUBLIC_ARGUMENTS_INVALID")
    elif (set(arguments) != {"queryId"}
          or not isinstance(arguments["queryId"], str)):
        raise ValueError("RESOLVED_READ_PUBLIC_ARGUMENTS_INVALID")
    return function, arguments


class PostgresResolvedCubeReadPublic:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("Verified identity is required")
        self.dsn = dsn
        self.identity = identity
        self.technical = ResolvedCubeReadTechnicalService(
            dsn, identity=identity,
            cursor_codec=AggregateCursorCodec(cursor_secret))

    def execute(self, scope: ApplicationScope, raw: object) -> dict[str, object]:
        function, arguments = _program(raw)
        if function == BINDING_LIST:
            return self._bindings(scope, function, arguments)
        if function == DIRECT:
            return PostgresResolvedCubeRead(
                self.dsn, identity=self.identity).read(scope, raw)
        if function == REQUEST:
            return self.technical.request(scope, {
                "languageVersion": 2, "function": DIRECT,
                "arguments": arguments["query"]},
                page_size=arguments.get("pageSize", 500),
                ttl_seconds=arguments.get("ttlSeconds", 900))
        if function == RESULT_READ:
            return self.technical.read(scope, arguments["queryId"],
                cursor=arguments.get("cursor"),
                page_size=arguments.get("pageSize"))
        return self.technical.cancel(scope, arguments["queryId"])

    def _bindings(self, scope: ApplicationScope, function: str,
                  arguments: dict) -> dict[str, object]:
        with connect_postgres(self.dsn) as db, db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=function)
            rows = db.execute("""SELECT binding_id,state_token,
                binding_digest,metadata_revision,binding
                FROM epm.resolved_read_binding_definition
                WHERE workspace_id=%s AND application_id=%s
                  AND status='Active' AND binding_id>%s
                ORDER BY binding_id LIMIT %s""", (
                scope.workspace_id, scope.application_id,
                arguments.get("afterBindingId", ""),
                arguments.get("limit", 100) + 1)).fetchall()
            PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "read", function=function)
        limit = arguments.get("limit", 100)
        page = rows[:limit]
        return {"format": "openepm-resolved-binding-list-v1",
                "bindings": [{"bindingId": row["binding_id"],
                    "stateToken": row["state_token"],
                    "bindingDigest": row["binding_digest"],
                    "metadataRevision": row["metadata_revision"],
                    "stages": [{"stageId": stage["stageId"],
                                "kind": stage["kind"]}
                               for stage in row["binding"]["stages"]]}
                    for row in page],
                "nextAfterBindingId": (page[-1]["binding_id"]
                    if len(rows) > limit else None)}
