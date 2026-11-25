"""Selected raw-fact writes using shared hierarchy, expression and publication cores."""
from __future__ import annotations

from decimal import Decimal

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_cube_select import PostgresCubeSelect, arguments as selection_arguments
from .postgres_cube_query import PostgresCubeQuery
from .postgres_jobs import _canonical_digest, _require_python_job_authority
from .postgres_numeric_sequence_expression import (
    compile_expression, instructions, evaluate_partitions,
    COMPILER as EXPRESSION_COMPILER, PLAN_DIGEST as EXPRESSION_PLAN)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout

FUNCTION = "facts.numeric.transform"
COMPILER = "selected-numeric-transform-v1"
MAX_TARGETS = 10_000
MAX_INSTRUCTIONS = 250_000
MAX_CANDIDATE_BYTES = 16 * 1024 * 1024
PLAN_DIGEST = _canonical_digest({"function": FUNCTION, "version": 1,
    "selection": "full-coordinate-existing-numeric-facts",
    "expression": (EXPRESSION_COMPILER, EXPRESSION_PLAN),
    "rounding": "half_even_8", "targets": MAX_TARGETS,
    "instructions": MAX_INSTRUCTIONS, "candidateBytes": MAX_CANDIDATE_BYTES,
    "publication": "all-selected-facts-one-atomic-commit"})


def authorize_rows(db, scope, identity, rows):
    """Resolve current grants/tags set-wise, then use the shared policy evaluator."""
    from .dimensional_security_policy import AccessKind, ResolvedMemberSecurity, evaluate_coordinate
    from .postgres_access import AccessDenied
    from .postgres_dimensional_scope import resolve_effective_dimensional_scope
    authority = resolve_effective_dimensional_scope(db, identity, scope)
    if authority.policy is None:
        return
    layout = db.execute("""SELECT l.dimensions FROM epm.coordinate_layout l
        JOIN epm.application_state s USING(workspace_id,application_id,schema_epoch)
        WHERE l.workspace_id=%s AND l.application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if layout is None:
        raise ValueError("APPLICATION_LAYOUT_UNAVAILABLE")
    dimensions = tuple(layout["dimensions"])
    requested = sorted({(axis, member) for row in rows for axis, member in row["members"].items()})
    tags = db.execute("""SELECT i.dimension_id,i.member_id,m.read_security_tags,m.write_security_tags
        FROM jsonb_to_recordset(%s::jsonb) i(dimension_id text,member_id text)
        LEFT JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
          AND m.dimension_id=i.dimension_id AND m.member_id=i.member_id AND m.status='Active'""",
        (Jsonb([{"dimension_id": axis, "member_id": member} for axis, member in requested]),
         scope.workspace_id, scope.application_id)).fetchall()
    if any(row["read_security_tags"] is None or row["write_security_tags"] is None for row in tags):
        raise ValueError("DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE")
    members = {(row["dimension_id"], row["member_id"]): ResolvedMemberSecurity(
        row["dimension_id"], row["member_id"], tuple(row["read_security_tags"]),
        tuple(row["write_security_tags"])) for row in tags}
    for row in rows:
        if tuple(sorted(row["members"])) != dimensions:
            raise ValueError("DIMENSIONAL_COORDINATE_LAYOUT_MISMATCH")
        resolved = tuple(members[(axis, row["members"][axis])] for axis in dimensions)
        for kind in (AccessKind.READ, AccessKind.WRITE):
            if authority.privileges is not None:
                decision = authority.privileges.coordinate_decision(resolved, kind, dimensions, authority.policy)
            else:
                decision = evaluate_coordinate(resolved, kind=kind, expected_dimensions=dimensions,
                    policy=authority.policy, read_assignments=authority.read_assignments,
                    write_assignments=authority.write_assignments,
                    application_administrator=authority.access.role == "Administrator",
                    workspace_administrator=authority.access.workspace_administrator)
            if not decision.allowed:
                raise AccessDenied(decision.reason)


def compile_program(raw):
    if (type(raw) is not dict or set(raw) != {"languageVersion", "function", "arguments"}
            or type(raw["languageVersion"]) is not int or raw["languageVersion"] != 2
            or raw["function"] != FUNCTION or type(raw["arguments"]) is not dict):
        raise ValueError("NUMERIC_TRANSFORM_PROGRAM_INVALID")
    args = raw["arguments"]
    if set(args) != {"selection", "expression", "rounding", "expectedMetadataRevision"}:
        raise ValueError("NUMERIC_TRANSFORM_ARGUMENTS_INVALID")
    if args["rounding"] != "half_even_8":
        raise ValueError("NUMERIC_TRANSFORM_ROUNDING_INVALID")
    revision = args["expectedMetadataRevision"]
    if type(revision) is not int or revision < 0:
        raise ValueError("NUMERIC_TRANSFORM_METADATA_REVISION_INVALID")
    if type(args["selection"]) is not dict or set(args["selection"]) != {"grain", "selectors"}:
        raise ValueError("NUMERIC_TRANSFORM_SELECTION_INVALID")
    selected = selection_arguments(args["selection"])
    selection = {key: selected[key] for key in ("grain", "selectors")}
    expression = compile_expression(args["expression"], 0)
    return {"version": 1, "function": FUNCTION, "arguments": {
        "selection": selection, "expression": expression,
        "rounding": "half_even_8", "expectedMetadataRevision": revision}}


def decode_program(normalized):
    try:
        checked = compile_program({"languageVersion": 2, "function": FUNCTION,
                                   "arguments": normalized["arguments"]})
        if _canonical_digest(checked) != _canonical_digest(normalized):
            raise ValueError("noncanonical")
        return checked
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("NUMERIC_TRANSFORM_NORMALIZED_PROGRAM_INVALID") from error


def prepare(db, scope, normalized, *, identity, workflow_role, fact_state=None):
    """Resolve/evaluate a candidate without publishing; reusable by private Test.

    Private Test may provide a trusted server-only fact_state implementing
    select_existing_facts(db, scope, member_sets, snapshot_revision, limit) with
    CubeQuery row shape, and numeric_inputs(db, scope, rows) with FactBatch input
    shape. Metadata/hierarchy resolution, typing, authorization, coordinate/CAS/
    detail validation and arithmetic stay here. No provider crosses the public
    wire. This function has no receipt, revision or fact-write path.
    """
    from .postgres_numeric_sequence import (
        initial_state, enforce_sequence_dimensional_security,
        enforce_sequence_target_policy)
    state = db.execute("""SELECT metadata_revision,data_revision,policy_revision,
        commit_revision,processing_mode,a.status FROM epm.application_state
        JOIN epm.application a USING(workspace_id,application_id)
        WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None:
        raise ValueError("APPLICATION_UNAVAILABLE")
    if state["status"] != "Active" or state["processing_mode"] != "Active":
        raise ValueError("APPLICATION_NOT_WRITABLE")
    args = normalized["arguments"]
    if state["metadata_revision"] != args["expectedMetadataRevision"]:
        raise ValueError("STALE_METADATA_REVISION")
    selected, state_tokens = PostgresCubeSelect._resolve(
        db, scope, args["selection"], state["metadata_revision"])
    source = (PostgresCubeQuery._page(db, scope, {}, "", state["commit_revision"],
        state["commit_revision"], False, MAX_TARGETS + 1, member_sets=selected)
        if fact_state is None else fact_state.select_existing_facts(db, scope,
            member_sets=selected, snapshot_revision=state["commit_revision"], limit=MAX_TARGETS + 1))
    if len(source) > MAX_TARGETS:
        raise ValueError("NUMERIC_TRANSFORM_SELECTED_FACT_BUDGET")
    source = sorted(source, key=lambda row: row["seriesKey"])
    if len({row["seriesKey"] for row in source}) != len(source):
        raise ValueError("NUMERIC_TRANSFORM_DUPLICATE_SOURCE_COORDINATE")
    rows = [{"ordinal": ordinal + 1, "series_key": row["seriesKey"],
        "members": row["members"], "op": "set", "literal": None,
        "reference": None, "expected_change_id": row["numericChangeId"]}
        for ordinal, row in enumerate(row for row in source if row["kind"] == "numeric")]
    if not rows:
        raise ValueError("NUMERIC_TRANSFORM_NO_MATCHING_NUMERIC_FACTS")
    expanded = {"function": FUNCTION, "statements": rows}
    enforce_sequence_dimensional_security(db, identity, scope, expanded)
    initial = initial_state(db, scope, expanded, fact_state=fact_state)
    enforce_sequence_target_policy(db, scope, expanded, workflow_role)
    tape = instructions([{"ordinal": 1, "series_key": "current", "op": "set",
                          "expression": args["expression"]}])
    if len(tape) * len(rows) > MAX_INSTRUCTIONS:
        raise ValueError("NUMERIC_TRANSFORM_INSTRUCTION_BUDGET")
    partitions = [{"partition_key": row["series_key"], "states": {
        "current": initial[row["series_key"]]}} for row in rows]
    trace = evaluate_partitions(db, tape, partitions) if partitions else []
    effects = [{"ordinal": row["ordinal"], "amount": format(value["amount"], ".8f"),
        "before_amount": format(value["before_amount"], ".8f")}
        for row, value in zip(rows, trace, strict=True)]
    candidate = {"normalized": expanded, "initial": initial, "trace": effects,
        "revisions": {key: state[key] for key in
                      ("metadata_revision", "data_revision", "policy_revision")},
        "hierarchyStateTokens": state_tokens,
        "selectedMemberCounts": {axis: len(ids) for axis, ids in selected.items()}}
    import json
    if len(json.dumps(candidate, ensure_ascii=True).encode("ascii")) > MAX_CANDIDATE_BYTES:
        raise ValueError("NUMERIC_TRANSFORM_CANDIDATE_BYTE_BUDGET")
    return candidate


def preview(language, scope, raw):
    normalized = compile_program(raw)
    with connect_postgres(language.dsn, row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db, scope)
            access = PostgresAccessChecker.check_in_transaction(
                db, language.identity, scope, "write", function=FUNCTION)
            candidate = prepare(db, scope, normalized,
                identity=language.identity, workflow_role=access.role)
            current = db.execute("""SELECT metadata_revision,data_revision,policy_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id, scope.application_id)).fetchone()
            if dict(current) != candidate["revisions"]:
                raise ValueError("NUMERIC_TRANSFORM_SOURCE_CHANGED")
    token, digest = language._sign_preview(scope, FUNCTION, normalized, candidate["revisions"],
        extra={"compilerVersion": COMPILER, "planDigest": PLAN_DIGEST})
    return {"languageVersion": 2, "function": FUNCTION, "previewToken": token,
        "programDigest": digest, "revisionVector": candidate["revisions"],
        "targetCount": len(candidate["trace"]),
        "hierarchyStateTokens": candidate["hierarchyStateTokens"],
        "selectedMemberCounts": candidate["selectedMemberCounts"],
        "compilerVersion": COMPILER, "rounding": "half_even_8",
        "effect": "raw-fact-write", "candidateDigest": _canonical_digest(candidate)}


def _require_pins(db, scope, job):
    current = db.execute("""SELECT metadata_revision,data_revision,policy_revision
        FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if current is None or any(current[key] != job["expected_" + key]
                             for key in current):
        raise ValueError("STALE_JOB_INPUT_REVISION")


def stage(dsn, scope, claim, identity):
    """Persist bounded computation without an application mutation fence.

    A lost worker may leave a private candidate, never a partial business effect.
    Every later claim verifies the original pins before reusing the candidate.
    """
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with db.transaction():
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            access = PostgresAccessChecker.check_in_transaction(
                db, identity, scope, "write", function=FUNCTION)
            job = db.execute("""SELECT *,lease_until>clock_timestamp() live FROM epm.job
                WHERE workspace_id=%s AND application_id=%s AND job_id=%s""",
                (scope.workspace_id, scope.application_id, claim["job_id"])).fetchone()
            if (job is None or job["issuer"] != identity.issuer
                    or job["subject_id"] != identity.subject_id):
                raise ValueError("JOB_UNAVAILABLE")
            if job["status"] == "published":
                return
            if (job["status"] != "running" or not job["live"]
                    or job["claim_generation"] != claim["claim_generation"]
                    or job["claimant"] != claim["claimant"]):
                raise ValueError("STALE_WORKER_FENCE")
            _require_python_job_authority(db, scope, job)
            normalized = decode_program(job["normalized_program"])
            if (job["function_name"] != FUNCTION or job["compiler_version"] != COMPILER
                    or job["plan_digest"] != PLAN_DIGEST
                    or job["program_digest"] != _canonical_digest(normalized)):
                raise ValueError("UNSUPPORTED_NUMERIC_JOB_PROGRAM")
            _require_pins(db, scope, job)
            if db.execute("""SELECT 1 FROM epm.numeric_transform_candidate
                WHERE workspace_id=%s AND application_id=%s AND job_id=%s""",
                (scope.workspace_id, scope.application_id, claim["job_id"])).fetchone():
                return
            candidate = prepare(db, scope, normalized,
                identity=identity, workflow_role=access.role)
            _require_pins(db, scope, job)
            from .postgres_numeric_sequence import check_publication_fence
            check_publication_fence(db, scope, job, claim["job_id"])
            db.execute("""INSERT INTO epm.numeric_transform_candidate
                (workspace_id,application_id,job_id,program_digest,candidate_digest,candidate)
                VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (scope.workspace_id, scope.application_id, claim["job_id"],
                 job["program_digest"], _canonical_digest(candidate), Jsonb(candidate)))


def prepared_job(db, scope, job, identity):
    """Load trusted private work and recheck its current publication authority."""
    from .postgres_numeric_sequence import enforce_sequence_dimensional_security, initial_state
    _require_pins(db, scope, job)
    row = db.execute("""SELECT program_digest,candidate_digest,candidate
        FROM epm.numeric_transform_candidate WHERE workspace_id=%s
        AND application_id=%s AND job_id=%s""",
        (scope.workspace_id, scope.application_id, job["job_id"])).fetchone()
    if (row is None or row["program_digest"] != job["program_digest"]
            or row["candidate_digest"] != _canonical_digest(row["candidate"])):
        raise ValueError("NUMERIC_TRANSFORM_CANDIDATE_INVALID")
    candidate = row["candidate"]
    normalized = candidate["normalized"]
    enforce_sequence_dimensional_security(db, identity, scope, normalized)
    initial = initial_state(db, scope, normalized)
    if initial != candidate["initial"]:
        raise ValueError("NUMERIC_TRANSFORM_SOURCE_CHANGED")
    trace = [{**value, "amount": Decimal(value["amount"]),
              "before_amount": Decimal(value["before_amount"])}
             for value in candidate["trace"]]
    return normalized, initial, trace, None, {"effect": "raw-fact-write",
        "candidateDigest": row["candidate_digest"], "compilerVersion": COMPILER}


def program_schema():
    """Compose the selection and ordered-expression owners' wire shapes."""
    from .postgres_cube_select import catalog as selection_catalog
    from .postgres_numeric_catalog import definitions, obj, program_schema as envelope
    fields = selection_catalog()["facts.cube.select"]["arguments"]
    expression = definitions()["expression"]
    # Transform has one independent expression per selected existing fact;
    # compile_expression(..., 0) has no earlier statement to reference.
    expression["oneOf"] = [node for node in expression["oneOf"]
        if node["properties"]["op"]["const"] not in ("StatementAmount", "StatementPresent")]
    return envelope(FUNCTION, obj({
        "selection": obj({"grain": fields["grain"], "selectors": fields["selectors"]}),
        "expression": {"$ref": "#/$defs/expression"},
        "expectedMetadataRevision": {"type": "integer", "minimum": 0},
        "rounding": {"const": "half_even_8"}}), {"expression": expression})


def program_contract():
    """Describe distinct public stages without changing native execution."""
    from .postgres_cube_select import catalog as selection_catalog
    from .postgres_jobs import job_submission_schema
    from .postgres_numeric_catalog import obj
    from .postgres_planning_write_guard import planning_write_evidence_schema

    selected = selection_catalog()["facts.cube.select"]["programContract"]["resultSchema"]["properties"]
    digest = {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"}
    revision = {"type": "integer", "minimum": 0}
    count = {"type": "integer", "minimum": 1, "maximum": MAX_TARGETS}
    preview_schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **obj({
        "languageVersion": {"type": "integer", "const": 2},
        "function": {"const": FUNCTION}, "previewToken": {"type": "string", "minLength": 1},
        "programDigest": digest,
        "revisionVector": obj({key: revision for key in
            ("metadata_revision", "data_revision", "policy_revision")}),
        "targetCount": count, "hierarchyStateTokens": selected["hierarchyStateTokens"],
        "selectedMemberCounts": selected["selectedMemberCounts"],
        "compilerVersion": {"const": COMPILER}, "rounding": {"const": "half_even_8"},
        "effect": {"const": "raw-fact-write"}, "candidateDigest": digest})}
    published_schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", **obj({
        "changedCount": count, "statementCount": count,
        "committedRevision": {"type": "integer", "minimum": 1},
        "planningPolicy": planning_write_evidence_schema(), "impactDigest": digest,
        "effect": {"const": "raw-fact-write"}, "candidateDigest": digest,
        "compilerVersion": {"const": COMPILER}})}
    submission_schema = job_submission_schema()
    example = {"languageVersion": 2, "function": FUNCTION, "arguments": {
        "selection": {"grain": {"mode": "full_coordinate", "dimensions": ["Metric"]},
            "selectors": {"Metric": {"kind": "Members", "memberIds": ["A"]}}},
        "expression": {"op": "Multiply", "left": {"op": "CurrentAmount"},
            "right": {"op": "RatioLiteral", "decimal": "2"}},
        "expectedMetadataRevision": 7, "rounding": "half_even_8"}}
    from copy import deepcopy
    hierarchy_example = deepcopy(example)
    hierarchy_example["arguments"]["selection"]["selectors"]["Metric"] = {
        "kind": "Leaves", "rootMemberId": "Total", "includeSelf": False}
    return {"version": 1, "programSchema": program_schema(),
        "resultSchema": submission_schema, "resultSchemaScope": "envelope",
        "outputSchemas": {
            "preview": {"schema": preview_schema, "scope": "envelope",
                "surface": "preview_v2_program or browser /api/preview; no job or fact is published"},
            "submission": {"schema": submission_schema, "scope": "envelope",
                "surface": "submit_v2_program or browser /api/submit; durable acceptance or matching original job"},
            "publishedResult": {"schema": published_schema, "scope": "result",
                "surface": "read_v2_job result when status is published; also the operation receipt result, not the worker wrapper"}},
        "examples": [
            {"id": "double-existing-member", "program": example,
             "prerequisites": "Selected application has exactly the active fact axis Metric, active member A, metadata revision 7, an existing numeric value 7.25000000 at A, current read/write grants and open planning scope. No selected coordinate has text or supporting detail. These are fixture prerequisites, not default product metadata.",
             "expected": {"targetCount": 1, "changedCount": 1, "amountAtA": "14.50000000"}},
            {"id": "double-current-hierarchy-leaves", "program": hierarchy_example,
             "prerequisites": "Same single-axis application at metadata revision 7, with Total above active leaves A and B, and its current hierarchy state already built. A and B each hold an authorized numeric value without supporting detail; planning scope is open. Shared hierarchy paths still select each fact once.",
             "expected": {"targetCount": 2, "changedCount": 2}}],
        "execution": {
            "discovery": "Read application.state.read and authorized dimension/member metadata. Bind the complete active fact grain, intended stable selectors and current metadataRevision; replace the illustrative IDs/revision before using another application.",
            "workflow": "Inspect preview targetCount and pins, obtain operation admission, submit the unchanged program with that preview and admission identity, then read the returned jobId under current authority.",
            "recovery": "Preserve the original program, identity, ordered dependencies and operation ID. Read a known job before retrying an uncertain submission; do not replace it with a new operation. Native replay does not promise that an expired transport admission remains valid."},
        "semanticRules": [
            "Existing numeric facts only; every unmentioned axis and full coordinate is retained. Empty, text-only or missing selection rejects rather than materializing cells.",
            "Use the shared ordered expression profile without StatementAmount/StatementPresent or external source nodes. The native compiler enforces amount-valued results, numeric type rules, finite amount/ratio decimal ranges, at most64 nodes and depth12.",
            "CurrentAmount reads pinned input for each fact independently. Exact rational evaluation rounds half_even_8 once at its write boundary; lazy branches retain the native evaluation rules.",
            "Shape validation does not replace native trimmed/non-NUL IDs, selector-axis membership,500 total explicit members,16KB normalized selection, current full grain/metadata/hierarchy, authority, policy, CAS or work-budget checks.",
            "Selectors use unique members from current hierarchy state; shared paths never duplicate a fact. Preview exposes the server-resolved hierarchy tokens, not caller-selectable historical versions.",
            "No selected detail-backed writes, no absent-cell materialization, no text coercion and no partial publication. Stale metadata/data/policy pins reject; accepted work is never silently rebased.",
            "Signed previewToken binds the current compiler and execution plan. Old-plan previews cannot admit new work; pending old-plan jobs fail before private candidate reuse. Terminal job cleanup retires private candidates. Completed original receipts remain recoverable without evaluating or replacing their stored result.",
            "Preview targetCount and published changedCount count selected existing numeric coordinates, including same-value writes. Transform publishes one statement per selected coordinate; these counts are not changed-value comparisons.",
            "Output schemas describe the current compiler's stages. Previously retained job results are read without reinterpretation; schema presence does not authorize resubmission or establish old-job upgrade compatibility."]}


def catalog():
    return {FUNCTION: {"mode": "durable_write", "permission": "write",
        "arguments": {"selection": "full grain + member/hierarchy selectors",
            "expression": "amount-valued shared numeric expression with CurrentAmount/CurrentPresent",
            "expectedMetadataRevision": "nonnegative integer", "rounding": "half_even_8"},
        "result": "one atomic stored numeric-fact effect; durable job and operation receipt",
        "previewRequired": True, "idempotencyRequired": True, "workClass": "medium",
        "programContract": program_contract(),
        "semantics": {"source": "existing numeric facts only; other axes preserved",
            "emptySelection": "NUMERIC_TRANSFORM_NO_MATCHING_NUMERIC_FACTS; no job or effect",
            "missingAndText": "unchanged", "detail": "selected detail-backed coordinates rejected",
            "hierarchy": "current sealed state resolved and pinned by the core; unique members, no shared-path duplication",
            "bounds": {"selectedExistingFacts": MAX_TARGETS, "instructions": MAX_INSTRUCTIONS,
                       "candidateBytes": MAX_CANDIDATE_BYTES},
            "pins": "metadata, data and policy revisions; stale accepted input is never rebased",
            "replay": "same identity/key/program/dependencies returns original job",
            "stages": {"compile": True, "evaluate": True, "publish": True}}}}
