"""Public W09 adapter for direct and durable resolved cube reads."""
from __future__ import annotations

from psycopg.rows import dict_row

from .cube_aggregate_lifecycle import (
    AUTHORIZATION_REVOKED, AggregateCursorCodec, AggregateQueryStatus, MAX_GROUPS, MAX_PAGE_SIZE,
    RESULT_TTL_SECONDS, STALE_CONTEXT)
from .cube_aggregate_public_contract import (
    CURSOR, DIGEST, ID, REVISION, bounded, mapping, technical_certificate_schema)
from .cube_view_contract import (
    FORMAT as VIEW_FORMAT, data_source_schema, structural_schema as cube_view_schema)
from .metadata_read_contract import obj, read_contract, read_example
from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_resolved_cube_read import (
    FUNCTION as DIRECT, PostgresResolvedCubeRead)
from .resolved_cube_read_technical import ResolvedCubeReadTechnicalService
from .resolved_cube_read_contract import (
    FORMAT as RESOLVED_FORMAT, FRESHNESS, ORIGINS)
from .selection_contract import (
    FORMAT as SELECTION_FORMAT, MAX_DIMENSIONS, SELECTION_METADATA_STALE, selection_identifier_schema,
    structural_schema_definitions)
from .cube_view_read_contract import FORMAT as VIEW_READ_FORMAT


REQUEST = "facts.cube.resolved.request"
RESULT_READ = "facts.cube.resolved.result.read"
CANCEL = "facts.cube.resolved.cancel"
BINDING_LIST = "facts.cube.resolved.binding.list"
FUNCTIONS = frozenset({DIRECT, REQUEST, RESULT_READ, CANCEL, BINDING_LIST})

BOOLEAN = {"type": "boolean"}
SUPPRESSION = obj({"missing": BOOLEAN, "zero": BOOLEAN})
CURRENTNESS = {"enum": ["current", "stale"]}
RESULT_TOKEN = {"anyOf": [DIGEST, {"type": "null"}]}
SNAPSHOT = obj(dict.fromkeys(("metadataRevision", "dataRevision", "policyRevision",
    "commitRevision", "securityRevision", "impactEpoch", "processedImpactEpoch"), REVISION))


def _resolved_query_schema(delivery):
    identifier = selection_identifier_schema()
    max_rows = MAX_PAGE_SIZE if delivery == "direct" else MAX_GROUPS
    hierarchy = obj({"dimensionId": identifier, "hierarchyId": identifier,
        "hierarchyStateToken": DIGEST,
        "membershipSemantics": {"enum": ["unique_member", "placement"]}})
    effective = obj({"semantics": {"const": "effective"}, "bindingId": identifier,
        "bindingStateToken": DIGEST, "hierarchies": {"type": "array",
            "maxItems": MAX_DIMENSIONS, "items": hierarchy}})
    fields = {"format": {"const": RESOLVED_FORMAT},
        "selection": {"$ref": "#/$defs/cubeSelection"},
        "source": {"oneOf": [obj({"semantics": {"const": "own"}}), effective]},
        "outputGrain": {"type": "array", "minItems": 1, "maxItems": MAX_DIMENSIONS,
            "uniqueItems": True, "items": identifier},
        "freshness": {"enum": sorted(FRESHNESS)}, "dynamicFallback": {"type": "boolean"},
        "delivery": {"const": delivery},
        "limits": obj({"maxRows": bounded(max_rows), "maxSourceRows": bounded(1_000_000),
                       "timeoutMs": bounded(120_000, minimum=100)}),
        "presentation": obj({"pageSize": bounded(max_rows), "suppression": SUPPRESSION})}
    return obj(fields, [key for key in fields if key != "presentation"])


def _presence_value(fields):
    row = obj({**fields, "present": BOOLEAN, "value": {"type": ["string", "null"]}})
    row["if"] = {"properties": {"present": {"const": True}}}
    row["then"] = {"properties": {"value": {"type": "string"}}}
    row["else"] = {"properties": {"value": {"type": "null"}}}
    return row


def _resolved_row_schema(*, technical=False):
    fields = {"members": mapping(ID, minProperties=1, maxProperties=MAX_DIMENSIONS),
        "resultUnit": {"type": "string", "pattern": r"^[A-Za-z][A-Za-z0-9:._-]{0,199}(?![\s\S])"},
        "origin": {"enum": sorted(ORIGINS)}, "currentness": CURRENTNESS,
        "resultStateToken": RESULT_TOKEN,
        "lineage": {"type": "array", "items": {"type": "object"}}}
    if technical:
        fields["ordinal"] = bounded(MAX_GROUPS)
    return _presence_value(fields)


def _technical_result_schema():
    return {"oneOf": [
        obj({"queryId": ID, "status": {"enum": [status.value for status in AggregateQueryStatus
                                                  if status != AggregateQueryStatus.SEALED]}}),
        obj({"queryId": ID, "status": {"const": "failed"},
             "errorCode": {"enum": [SELECTION_METADATA_STALE, AUTHORIZATION_REVOKED, STALE_CONTEXT]}}),
        obj({"queryId": ID, "status": {"const": "sealed"}, "rows": {"type": "array",
             "maxItems": MAX_PAGE_SIZE, "items": _resolved_row_schema(technical=True)},
             "nextCursor": {"anyOf": [CURSOR, {"type": "null"}]},
             "technicalCertificate": technical_certificate_schema()})]}


def _definition_status_schema():
    execution = obj({**dict.fromkeys(("defined", "valid", "active", "sourceCurrent", "executable"), BOOLEAN),
        "resultCurrent": {"type": ["boolean", "null"]}, "reason": {"type": ["string", "null"]},
        "status": {"enum": ["Active", "Inactive", "Unavailable"]}},
        ["defined", "valid", "active", "sourceCurrent", "resultCurrent", "executable", "reason"])
    status = {"execution": execution, "resultDefinitionValid": BOOLEAN,
              "resultDefinitionReason": {"type": ["string", "null"]}}
    return {"anyOf": [obj(status, ["resultDefinitionValid", "resultDefinitionReason"]), {"type": "null"}]}


def _direct_result_schema():
    definition = selection_identifier_schema()
    stage_evidence = {
        "dynamic": obj({"stageId": definition, "compilerVersion": ID,
            "planDigest": DIGEST, "resolutionDigest": DIGEST}),
        "materialized": obj({"stageId": definition, "resultStateToken": DIGEST,
            "presence": {"enum": ["empty", "present"]}, "definitionStatus": _definition_status_schema()}),
        "hierarchy": obj({"stageId": definition, "contributionDigest": DIGEST}),
    }
    stage = {"sourceDigest": DIGEST, "currentness": CURRENTNESS}
    stages = [obj({**stage, "stage": {"const": "input"}, "resolutionDigest": DIGEST})]
    stages.extend(obj({**stage, "stage": {"const": kind},
        "definitions": {"type": "array", "maxItems": 256, "items": evidence}})
        for kind, evidence in stage_evidence.items())
    return obj({"format": {"const": "openepm-resolved-cube-read-result-v1"},
        "requestDigest": DIGEST, "executionDigest": DIGEST, "snapshot": SNAPSHOT,
        "sourceRows": bounded(1_000_000, minimum=0), "persisted": {"const": False},
        "rows": {"type": "array", "maxItems": MAX_PAGE_SIZE, "items": _resolved_row_schema()},
        "stages": {"type": "array", "items": {"oneOf": stages}},
        "presentation": obj({"pageSize": bounded(MAX_PAGE_SIZE), "suppression": SUPPRESSION,
                             "rowCount": bounded(MAX_PAGE_SIZE, minimum=0)})})


def _view_result_schema():
    layers = {layer: {"type": "array", "minItems": 1, "items": _presence_value({
        "unit": {"type": ["string", "null"]}, "origin": {"const": origin},
        "currentness": {"const": "current"}, "resultStateToken": token})}
        for layer, origin, token in (("raw", "input", {"type": "null"}),
                                    ("calculated", "materialized", DIGEST))}
    revisions = obj(dict.fromkeys(("metadata", "data", "policy"), REVISION))
    calculation = obj({"resultKey": ID, "resultStateToken": DIGEST,
        "resultCurrentness": obj({"basis": {"enum": ["legacy_revisions", "scoped_manifest"]},
            "freshness": {"const": "current"}, "matchesAtRead": {"const": True},
            "impactBarrier": obj({"impactEpoch": REVISION, "processedImpactEpoch": REVISION,
                                  "pending": {"const": False}}),
            "definitionStatus": _definition_status_schema()}),
        "inputRevisionStatus": obj({"matchesAtRead": {"const": True}, "expected": revisions,
            "observed": revisions, "observedCommitRevision": REVISION,
            "revisionMatchesAtRead": BOOLEAN})})
    fields = {"format": {"const": VIEW_READ_FORMAT},
        "viewDigest": DIGEST, "requestDigest": DIGEST, "dataSource": data_source_schema(),
        "readPolicy": obj({"semantics": {"enum": ["stored", "own"]}}),
        "snapshot": SNAPSHOT, "resolutionDigest": DIGEST, "complete": {"const": True},
        "presentation": obj({"pageSize": bounded(MAX_PAGE_SIZE), "suppression": SUPPRESSION,
                             "rowCount": bounded(MAX_PAGE_SIZE, minimum=0)}), "calculation": calculation}
    branches = []
    for kind, included in (("raw", ("raw",)), ("calculated", ("calculated",)),
                           ("combined", ("raw", "calculated"))):
        row = obj({"members": mapping(ID, minProperties=1, maxProperties=MAX_DIMENSIONS),
                   "values": obj({layer: layers[layer] for layer in included})})
        branch = {**fields, "dataSource": {"allOf": [fields["dataSource"],
            {"properties": {"kind": {"const": kind}}}]},
            "rows": {"type": "array", "maxItems": MAX_PAGE_SIZE, "items": row}}
        if kind == "raw":
            del branch["calculation"]
        branches.append(obj(branch))
    return {"oneOf": branches}


def _resolved_query_example(delivery):
    return {"format": RESOLVED_FORMAT, "selection": {"format": SELECTION_FORMAT,
        "metadataRevision": 1, "dimensions": [{"dimensionId": "custom-axis",
            "include": {"kind": "members", "memberIds": ["member-a", "member-b"]}, "exclude": None}]},
        "source": {"semantics": "own"}, "outputGrain": ["custom-axis"], "freshness": "current",
        "dynamicFallback": False, "delivery": delivery,
        "limits": {"maxRows": 2, "maxSourceRows": 2, "timeoutMs": 5000}}


def _view_example():
    return {"format": VIEW_READ_FORMAT,
        "view": {"format": VIEW_FORMAT, "viewId": "example-view", "name": "Example view",
            "selection": {"format": SELECTION_FORMAT, "metadataRevision": 1, "dimensions": [
                {"dimensionId": "Measure", "include": {"kind": "member", "memberId": "Revenue"},
                 "exclude": None},
                {"dimensionId": "Period", "include": {"kind": "members", "memberIds": ["P1", "P2"]},
                 "exclude": None}]},
            "layout": {"rows": ["Measure"], "columns": ["Period"], "pages": [], "filters": []},
            "dataSource": {"kind": "combined", "resultKey": "example.result"},
            "suppression": {"missing": False, "zero": False}, "pageSize": 100},
        "readPolicy": {"semantics": "stored"},
        "limits": {"maxRows": 500, "maxSourceRows": 100000, "timeoutMs": 30000}}


VIEW_EXAMPLE_BINDING = ("Replace the complete example view with the unchanged definition returned "
                        "by an authorized grid.definition.read. Choose a current read policy separately.")


def _direct_program_contract():
    view = obj({"format": {"const": VIEW_READ_FORMAT}, "view": cube_view_schema(),
        # The native owner provides actionable domain errors for unsupported
        # policies and layer combinations. The string shape is structural.
        "readPolicy": obj({"semantics": {"type": "string", "examples": ["stored", "own"],
            "description": "Use stored for any layer or own for raw. The native owner checks this policy."}}),
        "limits": obj({"maxRows": bounded(MAX_PAGE_SIZE), "maxSourceRows": bounded(100_000),
                       "timeoutMs": bounded(30_000, minimum=100)})})
    arguments = {"type": "object", "required": ["format"],
        "if": {"properties": {"format": {"const": VIEW_READ_FORMAT}}},
        "then": view, "else": _resolved_query_schema("direct")}
    examples = [read_example(DIRECT, _resolved_query_example("direct"),
        name="Read the current own values of a small complete selection",
        binding="Rebind every selected axis, member ID and the metadata revision using the authorized application."),
        read_example(DIRECT, _view_example(), name="Read the stored layers of an existing saved view",
                     binding=VIEW_EXAMPLE_BINDING)]
    contract = read_contract(DIRECT, arguments,
        {"oneOf": [_direct_result_schema(), _view_result_schema()]},
        owner="PostgresResolvedCubeRead", examples=examples, definitions=structural_schema_definitions(),
        semantic_rules=[
            "A direct resolved query uses the full fact grain and an explicit own or effective source. Bind effective reads to the current approved definition and hierarchy state.",
            "A saved-view read carries the complete canonical view and a separate read policy. Stored supports raw, calculated and combined. Own is available for raw alone. Use a governed binding for effective semantics.",
            "In group-assigned applications this operation accepts a current, unchanged saved raw view with stored semantics. Its views.run scope must cover the view, and facts.read must cover each returned cell.",
            "Both forms read one authorized revision cut. Direct results finish within their limits. A successful saved-view result reports complete=true and keeps its raw and calculated values separate.",
            "Exact text, present zero, absence and stale currentness have distinct meanings. A current read refuses stale calculations. Neither read publishes calculations or saves a view."])
    contract["resultSchema"].pop("$defs")
    contract["programContract"]["recovery"] = (
        "On a stale revision or changed snapshot, refresh the scoped state and selection. "
        "Review calculation status when current results are required. For a larger resolved read, use the durable request and status family.")
    return contract


def resolved_read_program_contract(function):
    if function not in FUNCTIONS:
        return None
    if function == DIRECT:
        return _direct_program_contract()
    definitions = None
    reference = {"queryId": "example-resolved-query"}
    query_binding = "Use the queryId returned by the resolved read request for the same application and actor."
    rules = ["Use the current application READ grant. The fixed core checks the query owner on every status, page and cancel request."]
    recovery = "Read the original query status to determine its current outcome. For a stale or expired result, review the current context before starting a new query."
    if function == REQUEST:
        arguments = obj({"query": _resolved_query_schema("technical_query"), "pageSize": bounded(MAX_PAGE_SIZE),
                         "ttlSeconds": bounded(RESULT_TTL_SECONDS)}, ["query"])
        result = obj({"queryId": ID, "status": {"const": "ready"},
                      "requestDigest": DIGEST, "expiresAt": REVISION})
        examples = [read_example(function, {"query": _resolved_query_example("technical_query"), "pageSize": 1},
            name="Request two own coordinates as a technical read",
            binding="Rebind the complete selection, current metadata revision and output axes to the authorized application.")]
        rules.extend(["Select own input or bind an active effective-read definition and its exact current pins.",
                      "The worker computes asynchronously within fixed bounds. Admission returns a query ID and expiry. Repeated requests can create new technical queries."])
        definitions = structural_schema_definitions()
    elif function == RESULT_READ:
        arguments = obj({"queryId": ID, "cursor": CURSOR, "pageSize": bounded(MAX_PAGE_SIZE)}, ["queryId"])
        result = _technical_result_schema()
        examples = [read_example(function, reference, name="Read the original query status or first sealed page",
                                 binding=query_binding),
            read_example(function, {**reference, "cursor": "example-signed-cursor"},
                         name="Continue the sealed resolved result",
                         binding=query_binding + " Pass the exact non-null nextCursor from the prior page.")]
        rules.extend(["Only sealed results contain rows and a technical certificate. A null nextCursor ends the result.",
                      "A failed result with CUBE_SELECTION_METADATA_STALE means the accepted selection revision changed before computation could complete. Refresh the application layout and submit a new query after reviewing the selection.",
                      "A failed result with CUBE_AGGREGATE_STALE_CONTEXT means the result could not be sealed under its original metadata, security or policy context. Review the current scope before requesting a new result.",
                      "CUBE_AGGREGATE_AUTHORIZATION_REVOKED records that the query lost its admitted access before sealing. Read the original status under current access before starting a replacement query.",
                      "The continuation is bound to the query, original actor, application and established page size.",
                      "A present value is exact text. Zero and empty text remain present. Absence carries a null value. Each row identifies its unit, origin and currentness."])
    elif function == CANCEL:
        arguments = obj({"queryId": ID})
        result = obj({"queryId": ID, "status": {"enum": ["cancel_requested", "cancelled"]}})
        examples = [read_example(function, reference, name="Cancel an in-flight resolved technical query",
                                 binding=query_binding)]
        rules.append("Cancellation changes technical query state. Poll the same query after a cancel_requested response.")
    else:
        identifier = selection_identifier_schema()
        arguments = obj({"limit": bounded(100), "afterBindingId": {"type": "string"}}, [])
        stage = obj({"stageId": identifier, "kind": {"enum": ["calculated_member", "hierarchy_node"]}})
        binding = obj({"bindingId": identifier, "stateToken": DIGEST, "bindingDigest": DIGEST,
            "metadataRevision": REVISION, "stages": {"type": "array", "minItems": 1,
                                                     "maxItems": 256, "items": stage}})
        result = obj({"format": {"const": "openepm-resolved-binding-list-v1"},
            "bindings": {"type": "array", "maxItems": 100, "items": binding},
            "nextAfterBindingId": {"anyOf": [identifier, {"type": "null"}]}})
        examples = [read_example(function, {"limit": 10}, name="Find current effective-read bindings",
                                 binding="Select an application and use its current READ grant."),
            read_example(function, {"limit": 10, "afterBindingId": "example-binding"},
                         name="Continue the active binding list",
                         binding="Use the previous response's non-null nextAfterBindingId in the same application.")]
        rules = ["Each page rechecks the current application READ grant and lists active bindings only.",
                 "A null nextAfterBindingId ends the current page sequence. Each page observes current bindings. Effective execution separately rechecks its selected binding and hierarchy pins."]
        recovery = "Rediscover the active binding and the current hierarchy context after a stale binding or metadata error."
    owner = "PostgresResolvedCubeReadPublic" if function == BINDING_LIST else "ResolvedCubeReadTechnicalService"
    contract = read_contract(function, arguments, result, owner=owner, examples=examples,
                             semantic_rules=rules, definitions=definitions)
    contract["resultSchema"].pop("$defs", None)
    contract["programContract"]["recovery"] = recovery
    return contract


def catalog() -> dict[str, dict[str, object]]:
    common = {"permission": "read", "previewRequired": False,
              "idempotencyRequired": False}
    functions = {
        DIRECT: {**common, "mode": "read", "workClass": "short",
            "canonicalViewRead": VIEW_READ_FORMAT,
            "canonicalViewReadArguments": {
                "format": VIEW_READ_FORMAT,
                "view": "unchanged complete openepm-cube-view-v1",
                "readPolicy": "{semantics: stored} for raw/calculated/combined; {semantics: own} for raw; effective uses the separate governed binding contract",
                "limits": "maxRows 1-500, maxSourceRows 1-100000, timeoutMs 100-30000; complete bounded read or error"},
            "canonicalViewReadProgramExample": {"languageVersion": 2, "function": DIRECT,
                                                "arguments": _view_example()},
            "canonicalViewReadExampleContext": VIEW_EXAMPLE_BINDING,
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
    for function in FUNCTIONS:
        functions[function].update(resolved_read_program_contract(function))
    return functions


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
        self.cursor_secret = cursor_secret
        self.technical = ResolvedCubeReadTechnicalService(
            dsn, identity=identity,
            cursor_codec=AggregateCursorCodec(cursor_secret))

    def execute(self, scope: ApplicationScope, raw: object) -> dict[str, object]:
        function, arguments = _program(raw)
        if function == BINDING_LIST:
            return self._bindings(scope, function, arguments)
        if function == DIRECT:
            return PostgresResolvedCubeRead(
                self.dsn, identity=self.identity,
                cursor_secret=self.cursor_secret).read(scope, raw)
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
        with connect_postgres(self.dsn, row_factory=dict_row) as db, db.transaction():
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
