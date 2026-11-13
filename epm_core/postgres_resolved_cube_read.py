"""PostgreSQL planning adapter for W08 resolved cube reads."""
from __future__ import annotations

from hashlib import sha256
from itertools import product
import json
from decimal import Decimal

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .calculated_member_contract import calculated_member_digest
from .dimensional_security_policy import AccessKind
from .hierarchy_node_contract import (
    compile_hierarchy_node, effective_edge_operator,
    resolve_hierarchy_contributions)
from .postgres_calculated_members import (
    expression_program_for_definition, load_current_dependency_template,
    verify_calculated_member_pin)
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_cube_query import PostgresCubeQuery
from .postgres_dimensional_security_enforcement import (
    authorize_coordinates, filter_read_rows)
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_resolved_read_bindings import (
    read_current_resolved_read_binding)
from .postgres_selection_preview import resolve_selection_in_transaction
from .resolved_cube_read_contract import (
    ResolvedCubeReadPlan, compile_resolved_cube_read,
    validate_resolved_rows)
from .resolved_cube_read_planner import (
    ResolvedCubeReadExecution, compile_resolved_read_execution)


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def load_resolved_read_snapshot(db, scope: ApplicationScope) -> dict[str, int]:
    row = db.execute("""SELECT metadata_revision,data_revision,
        policy_revision,commit_revision,security_revision,impact_epoch,
        processed_impact_epoch FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s""", (
        scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise ValueError("APPLICATION_UNAVAILABLE")
    return {"metadataRevision": row["metadata_revision"],
        "dataRevision": row["data_revision"],
        "policyRevision": row["policy_revision"],
        "commitRevision": row["commit_revision"],
        "securityRevision": row["security_revision"],
        "impactEpoch": row["impact_epoch"],
        "processedImpactEpoch": row["processed_impact_epoch"]}


def _targets(plan: ResolvedCubeReadPlan, resolved_members: dict[str, list[str]],
        target: dict[str, str]) -> list[dict[str, str]]:
    grain = plan.normalized["outputGrain"]
    axis = target["dimensionId"]
    if axis not in grain or not set(grain) <= set(resolved_members):
        raise ValueError("RESOLVED_READ_GRAIN_RESOLUTION_INVALID")
    choices = []
    for dimension in grain:
        members = ([target["memberId"]] if dimension == axis
                   else resolved_members[dimension])
        if not members:
            return []
        choices.append(members)
    count = 1
    for members in choices:
        count *= len(members)
        if count > plan.normalized["limits"]["maxRows"]:
            raise ValueError("RESOURCE_LIMIT")
    return [{dimension: member for dimension, member in zip(grain, values)}
            for values in product(*choices)]


def _calculated_owner(db, scope, stage, active_dimensions):
    from .postgres_jobs import _canonical_digest
    row = db.execute("""SELECT * FROM epm.expression_rule_definition
        WHERE workspace_id=%s AND application_id=%s AND rule_id=%s
          AND status='Active'""",
        (scope.workspace_id, scope.application_id, stage["definitionId"])).fetchone()
    if (row is None or row["state_token"] != stage["definitionStateToken"]
            or not isinstance(row.get("program"), dict)
            or row["program"].get("function") != "calculated.member.definition"
            or _canonical_digest(row["program"]) != row["program_digest"]):
        raise ValueError("RESOLVED_READ_CALCULATION_UNAVAILABLE")
    definition = row["program"]["arguments"]
    if (definition.get("evaluation") != stage["evaluation"]
            or definition.get("resultUnit") != stage["resultUnit"]):
        raise ValueError("RESOLVED_READ_CALCULATION_UNAVAILABLE")
    digest = calculated_member_digest(definition, active_dimensions=active_dimensions)
    return row, definition, digest


def _require_materialized_binding(status, stage, definition_digest):
    manifest = status.get("manifestCurrentnessStatus")
    if (not isinstance(manifest, dict) or not manifest.get("certificateValid")
            or manifest.get("stage") != "materialize"
            or manifest.get("definitionId") != stage["definitionId"]
            or manifest.get("definitionStateToken") != stage["definitionStateToken"]
            or manifest.get("definitionDigest") != definition_digest):
        raise ValueError("RESOLVED_READ_CALCULATION_BINDING_MISMATCH")
    return manifest


def _calculated_stage(db, scope: ApplicationScope,
        plan: ResolvedCubeReadPlan, stage: dict,
        resolved_members: dict[str, list[str]]) -> list[dict[str, object]]:
    active = [item["dimensionId"] for item in plan.normalized["selection"]["dimensions"]]
    row, definition, definition_digest = _calculated_owner(db, scope, stage, active)
    from .postgres_python_definitions import assert_source_active
    from .postgres_definition_lifecycle import definition_state_axes, resolution_context
    axes = definition_state_axes(row, resolution_context(db, scope, [row]))
    result_state_token = None
    currentness = "current"
    source_digest = definition_digest
    if stage["evaluation"] == "materialized":
        from .postgres_calculation_status import published_result_status
        result_key = definition.get("resultKey")
        pointer = db.execute("""SELECT state_token FROM epm.calculation_result_state
            WHERE workspace_id=%s AND application_id=%s AND result_key=%s""", (
            scope.workspace_id, scope.application_id, result_key)).fetchone()
        status = None
        if pointer is not None:
            result_state_token = pointer['state_token']
            status = published_result_status(db, scope, result_key, result_state_token)
            manifest = _require_materialized_binding(status, stage, definition_digest)
            source_digest = manifest['templateDigest']
        currentness = 'current' if status is not None and status['matchesAtRead'] else 'stale'
    else:
        assert_source_active(db, scope, row)
        template = load_current_dependency_template(db, scope, definition,
            expected_definition_digest=definition_digest)
        source_digest = template.digest
    return [{"bindingId": plan.normalized["source"]["bindingId"],
        "bindingStateToken": plan.normalized["source"]["bindingStateToken"],
        "stageId": stage["stageId"], "dependsOn": stage["dependsOn"],
        "targetMembers": target, "kind": stage["evaluation"],
        "definitionDigest": definition_digest,
        "sourceDigest": source_digest, "resultUnit": stage["resultUnit"],
        "currentness": currentness, "resultStateToken": result_state_token,
        "dynamicSupported": axes["execution"]["executable"],
        "lineage": [{"definitionId": stage["definitionId"],
            "definitionStateToken": stage["definitionStateToken"]}]}
        for target in (_targets(plan, resolved_members, stage["target"]) or [None])]


def _hierarchy_stage(plan: ResolvedCubeReadPlan, stage: dict,
        resolved_members: dict[str, list[str]]) -> list[dict[str, object]]:
    definition_digest = _digest({"plan": stage["definition"],
                                 "rootMemberId": stage["rootMemberId"]})
    return [{"bindingId": plan.normalized["source"]["bindingId"],
        "bindingStateToken": plan.normalized["source"]["bindingStateToken"],
        "stageId": stage["stageId"], "dependsOn": stage["dependsOn"],
        "targetMembers": target, "kind": "hierarchy",
        "definitionDigest": definition_digest,
        "sourceDigest": definition_digest,
        "resultUnit": stage["definition"]["resultUnit"],
        "currentness": "current", "resultStateToken": None,
        "dynamicSupported": True,
        "lineage": [{"hierarchyId": stage["definition"]["hierarchyId"],
            "hierarchyStateToken": stage["definition"]["hierarchyStateToken"],
            "membershipSemantics":
                stage["definition"]["membershipSemantics"]}]}
        for target in (_targets(plan, resolved_members, stage["target"]) or [None])]


def compile_current_resolved_read(db, scope: ApplicationScope, *,
        plan: ResolvedCubeReadPlan, snapshot: dict[str, int],
        resolved_members: dict[str, list[str]]) -> ResolvedCubeReadExecution:
    if plan.normalized["source"]["semantics"] == "own":
        return compile_resolved_read_execution(plan, snapshot=snapshot,
                                               bindings=[])
    current = read_current_resolved_read_binding(db, scope,
        binding_id=plan.normalized["source"]["bindingId"],
        expected_state_token=plan.normalized["source"]["bindingStateToken"])
    stages = current["binding"].normalized["stages"]
    metadata_changed = current["metadataRevision"] != snapshot["metadataRevision"]
    if metadata_changed and any(stage["kind"] != "calculated_member"
            or stage["evaluation"] != "materialized" for stage in stages):
        raise ValueError("RESOLVED_READ_BINDING_STALE")
    bindings = []
    for stage in stages:
        if stage["kind"] == "calculated_member":
            bindings.extend(_calculated_stage(db, scope, plan, stage,
                                              resolved_members))
        else:
            bindings.extend(_hierarchy_stage(plan, stage, resolved_members))
    if metadata_changed:
        if any(item["resultStateToken"] is None for item in bindings):
            raise ValueError("RESOLVED_READ_BINDING_STALE")
        # Only the exact certified stored results may cross an unrelated
        # metadata cut. A stale binding cannot authorize recomputation.
        bindings = [{**item, "dynamicSupported": False} for item in bindings]
    return compile_resolved_read_execution(plan, snapshot=snapshot,
                                           bindings=bindings)


def _dynamic_rows(db, scope: ApplicationScope, identity: VerifiedIdentity, *,
        stage: dict[str, object], snapshot: dict[str, int],
        active_dimensions: list[str], max_source_rows: int
        ) -> tuple[list[dict[str, object]], int, dict]:
    """Evaluate one active dynamic definition inside the caller's cut."""
    from .postgres_expression import (compile_expression_program,
        compiler_for, evaluate_dynamic_expression, resolve_published_inputs)
    from .selected_domain_contract import selected_domain_digest
    from .selection_contract import selection_digest

    row = db.execute("""SELECT v.state_token,v.program,
        v.program_digest,v.metadata_revision,s.policy_revision
        FROM epm.expression_rule_definition v
        JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE v.workspace_id=%s AND v.application_id=%s AND v.rule_id=%s
          AND v.status='Active'""", (
        scope.workspace_id, scope.application_id,
        stage["definitionId"])).fetchone()
    if (row is None or row["state_token"] != stage["definitionStateToken"]
            or row["metadata_revision"] != snapshot["metadataRevision"]
            or row["policy_revision"] != snapshot["policyRevision"]
            or row["program"].get("function") !=
               "calculated.member.definition"):
        raise ValueError("RESOLVED_READ_CALCULATION_UNAVAILABLE")
    definition = row["program"]["arguments"]
    if definition["evaluation"] not in {"dynamic", "materialized"}:
        raise ValueError("RESOLVED_READ_CALCULATION_UNAVAILABLE")
    resolved = resolve_selection_in_transaction(db, scope,
        definition["sourceSelection"], snapshot["metadataRevision"])
    evaluation = definition["evaluation"]
    program = expression_program_for_definition(definition,
        result_key=("dynamic." + row["program_digest"][:32]
                    if evaluation == "dynamic" else definition["resultKey"]))
    selected_domain = program["arguments"]["selectedDomain"]
    pin = {"definitionId": stage["definitionId"],
        "stateToken": row["state_token"],
        "programDigest": row["program_digest"],
        "definitionDigest": calculated_member_digest(definition,
            active_dimensions=tuple(resolved["members"])),
        "policyRevision": row["policy_revision"],
        "sourceSelectionDigest": selection_digest(
            definition["sourceSelection"]),
        "selectedDomainDigest": selected_domain_digest(selected_domain,
            active_dimensions=tuple(resolved["members"])),
        "resolutionDigest": resolved["resolutionDigest"]}
    inputs = resolve_published_inputs(db, scope,
        program["arguments"]["expression"])
    expression = compile_expression_program(program,
        expected_target_state_token=None, published_inputs=inputs,
        calculated_member=pin)
    verify_calculated_member_pin(db, scope, pin, expression,
                                 evaluation=evaluation)
    rows = evaluate_dynamic_expression(
        db, scope, identity, expression, max_rows=max_source_rows)
    compiler, plan_digest = compiler_for(expression)
    unit = definition["resultUnit"]
    mapped = [{"members": {axis: item["members"][axis]
                for axis in active_dimensions},
        "present": True,
        "value": item["value"]["decimal"], "resultUnit": unit,
        "origin": "dynamic", "currentness": "current",
        "resultStateToken": None,
        "lineage": [{"definitionId": stage["definitionId"],
            "definitionStateToken": row["state_token"],
            "sourceMembers": item["sourceMembers"],
            "sourceChangeId": item["sourceChangeId"],
            "sourceLineage": item["sourceLineage"]}]}
        for item in rows]
    return mapped, len(rows), {"compilerVersion": compiler,
        "planDigest": plan_digest,
        "resolutionDigest": resolved["resolutionDigest"]}


def _bound_calculated_rows(rows, *, stage, targets, origin, currentness,
        result_state_token, definition_status=None):
    """Represent absent owned targets only within the fixed bounded read domain."""
    selected = {tuple(sorted(target.items())): target for target in targets}
    bounded = [item for item in rows
               if tuple(sorted(item["members"].items())) in selected]
    present = {tuple(sorted(item["members"].items())) for item in bounded}
    lineage = {"definitionId": stage["definitionId"],
        "definitionStateToken": stage["definitionStateToken"]}
    if definition_status is not None:
        lineage["definitionStatus"] = definition_status
    bounded.extend({"members": dict(target), "present": False, "value": None,
        "resultUnit": stage["resultUnit"], "origin": origin,
        "currentness": currentness, "resultStateToken": result_state_token,
        "lineage": [dict(lineage)]}
        for key, target in selected.items() if key not in present)
    return bounded


def _materialized_rows(db, scope: ApplicationScope, *, stage: dict,
        result_state_tokens: list[str], active_dimensions: list[str],
        freshness: str, max_source_rows: int,
        targets: list[dict[str, str]] | None = None
        ) -> tuple[list[dict[str, object]], int, dict]:
    """Read one exact current result state; never repairs it during read."""
    if len(result_state_tokens) != 1:
        raise ValueError("RESOLVED_READ_STATE_INVALID")
    result_state_token = result_state_tokens[0]
    pointers=db.execute("""SELECT result_key,payload_kind FROM
        epm.calculation_result_state WHERE workspace_id=%s
        AND application_id=%s AND state_token=%s""",(
        scope.workspace_id,scope.application_id,result_state_token)).fetchall()
    if len(pointers)!=1:
        raise ValueError("RESOLVED_READ_STATE_CHANGED")
    result_key=pointers[0]["result_key"]
    _, definition, definition_digest = _calculated_owner(db, scope, stage, active_dimensions)
    if definition.get("resultKey") != result_key:
        raise ValueError("RESOLVED_READ_CALCULATION_BINDING_MISMATCH")
    table, column = (("calculation_ratio_result_current", "ratio")
                     if stage["resultUnit"] == "ratio"
                     else ("calculation_result_current", "amount"))
    from .postgres_calculation_status import published_result_status
    status = published_result_status(db, scope, result_key, result_state_token)
    _require_materialized_binding(status, stage, definition_digest)
    if ('current' if status['matchesAtRead'] else 'stale') != freshness:
        raise ValueError('RESOLVED_READ_STATE_CHANGED')
    # No requested targets still requires the exact owner/head checks above.
    # It does not require scanning unrelated payload coordinates.
    rows = ([] if targets == [] else db.execute(f"""SELECT c.members,r.{column} AS value,
        r.source_change_id FROM epm.{table} r JOIN epm.coordinate c
          USING(workspace_id,application_id,coordinate_id)
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.result_key=%s ORDER BY c.series_key LIMIT %s""", (
        scope.workspace_id, scope.application_id, result_key,
        max_source_rows + 1)).fetchall())
    if len(rows) > max_source_rows:
        raise ValueError("RESOURCE_LIMIT")
    mapped = [{"members": {axis: item["members"][axis]
                for axis in active_dimensions},
        "present": True, "value": format(Decimal(item["value"]), "f"),
        "resultUnit": stage["resultUnit"], "origin": "materialized",
        "currentness": freshness, "resultStateToken": result_state_token,
        "lineage": [{"definitionId": stage["definitionId"],
            "definitionStateToken": stage["definitionStateToken"],
            "sourceChangeId": item["source_change_id"],
            "definitionStatus": status.get("definitionStatus")}]}
        for item in rows]
    if targets is not None:
        mapped = _bound_calculated_rows(mapped, stage=stage, targets=targets,
            origin="materialized", currentness=freshness,
            result_state_token=result_state_token,
            definition_status=status.get("definitionStatus"))
    return mapped, len(rows), {"resultStateToken": result_state_token,
        "presence": "empty" if pointers[0]["payload_kind"] == "empty" else "present",
        "definitionStatus": status.get("definitionStatus")}


def _hierarchy_rows(db, scope: ApplicationScope, identity: VerifiedIdentity, *,
        stage: dict, targets: list[dict[str, str]],
        snapshot: dict[str, int], max_source_rows: int,
        overlay: dict[tuple[tuple[str, str], ...], dict[str, object]]
        ) -> tuple[list[dict[str, object]], int, dict]:
    """Resolve hierarchy nodes from authorized own inputs without publishing."""
    plan = compile_hierarchy_node(stage["definition"])
    if not plan.normalized["resultUnit"].startswith("amount"):
        raise ValueError("HIERARCHY_NODE_UNIT_UNSUPPORTED")
    dimension = plan.normalized["dimensionId"]
    hierarchy = db.execute("""SELECT metadata_revision,membership_semantics
        FROM epm.hierarchy_state WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s AND hierarchy_id=%s
        AND state_token=%s""", (scope.workspace_id, scope.application_id,
        dimension, plan.normalized["hierarchyId"],
        plan.normalized["hierarchyStateToken"])).fetchone()
    if (hierarchy is None
            or hierarchy["metadata_revision"] != snapshot["metadataRevision"]
            or hierarchy["membership_semantics"] !=
               plan.normalized["membershipSemantics"]):
        raise ValueError("HIERARCHY_NODE_BINDING_STALE")
    relation_rows = db.execute("""SELECT r.parent_member_id,
        r.child_member_id,r.relationship_id,
        r.aggregation_operator_override,m.aggregation_operator
        AS member_operator FROM epm.relationship r JOIN epm.member m
          ON m.workspace_id=r.workspace_id
         AND m.application_id=r.application_id
         AND m.dimension_id=r.dimension_id
         AND m.member_id=r.child_member_id
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.dimension_id=%s AND r.hierarchy_id=%s
          AND r.status='Active' AND m.status='Active'
        ORDER BY r.parent_member_id,r.relationship_id""", (
        scope.workspace_id, scope.application_id, dimension,
        plan.normalized["hierarchyId"])).fetchall()
    placement = plan.normalized["membershipSemantics"] == "placement"
    children3: dict[str, list[tuple[str, str, str, str]]] = {}
    for row in relation_rows:
        operator, source = effective_edge_operator(plan,
            relationship_id=row["relationship_id"],
            member_operator=row["member_operator"],
            relationship_override=row["aggregation_operator_override"],
            placement=placement)
        if operator in {"NeverAggregate", "Formula"}:
            raise ValueError("HIERARCHY_NODE_OPERATOR_NOT_ADDITIVE")
        children3.setdefault(row["parent_member_id"], []).append((
            row["child_member_id"], row["relationship_id"], operator, source))
    authored_overrides = set(plan.normalized.get("ruleOperatorOverrides", {}))
    resolved_relationships = {row["relationship_id"] for row in relation_rows}
    if not authored_overrides <= resolved_relationships:
        raise ValueError("HIERARCHY_NODE_RULE_OVERRIDE_TARGET_UNAVAILABLE")
    contributions = resolve_hierarchy_contributions(plan,
        root_member_id=stage["rootMemberId"], children=children3)
    source_members = sorted(set(contributions.sum_weights)
                            | set(contributions.count_weights))
    result = []
    source_count = 0
    for target in targets:
        fixed = {axis: member for axis, member in target.items()
                 if axis != dimension}
        rows = db.execute("""SELECT c.members,n.amount,n.change_id,
            n.last_revision FROM epm.coordinate c
            JOIN epm.numeric_cell_current n
              USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              AND c.members @> %s::jsonb
              AND c.members->>%s=ANY(%s::text[])
            ORDER BY c.series_key LIMIT %s""", (scope.workspace_id,
            scope.application_id, Jsonb(fixed), dimension, source_members,
            max_source_rows - source_count + 1)).fetchall()
        source_count += len(rows)
        if source_count > max_source_rows:
            raise ValueError("RESOURCE_LIMIT")
        source_coordinates = [{**fixed, dimension: member}
                              for member in source_members]
        authorize_coordinates(db, identity, scope,
            [*(Coordinate.from_mapping(item) for item in source_coordinates),
             Coordinate.from_mapping(target)], kind=AccessKind.READ)
        own_values = {row["members"][dimension]: Decimal(row["amount"])
                      for row in rows}
        overlay_lineage = []
        currentness = "current"
        for coordinate in source_coordinates:
            prior = overlay.get(tuple(sorted(coordinate.items())))
            if prior is not None:
                if prior["currentness"] == "stale":
                    currentness = "stale"
                if not str(prior["resultUnit"]).startswith("amount"):
                    raise ValueError("HIERARCHY_NODE_UNIT_MISMATCH")
                if prior["present"]:
                    own_values[coordinate[dimension]] = Decimal(prior["value"])
                else:
                    own_values.pop(coordinate[dimension], None)
                overlay_lineage.append({"members": coordinate,
                    "origin": prior["origin"], "present": prior["present"],
                    "resultStateToken": prior["resultStateToken"],
                    "lineage": prior["lineage"]})
        present = [
            (own_values[member], weight)
            for member, weight in contributions.sum_weights.items()
            if member in own_values and own_values[member] is not None]
        value = (None if not present else sum(
            (amount * weight for amount, weight in present), Decimal(0)))
        result.append({"members": target, "present": value is not None,
            "value": None if value is None else format(value, ".8f"),
            "resultUnit": plan.normalized["resultUnit"],
            "origin": "hierarchy",
            "currentness": currentness, "resultStateToken": None,
            "lineage": [{"hierarchyId": plan.normalized["hierarchyId"],
                "hierarchyStateToken": plan.normalized["hierarchyStateToken"],
                "contributionDigest": contributions.digest,
                "upstream": overlay_lineage,
                "sourceChanges": [{"changeId": row["change_id"],
                    "lastRevision": row["last_revision"]}
                    for row in rows]}]})
    return result, source_count, {"contributionDigest": contributions.digest}


def _within_selection(row: dict[str, object],
        resolved_members: dict[str, list[str]]) -> bool:
    members = row["members"]
    return all(members.get(axis) in selected
               for axis, selected in resolved_members.items())


def _within_targets(row: dict[str, object], targets: list[dict[str, str]]) -> bool:
    members = row["members"]
    return any(all(members.get(axis) == member
                   for axis, member in target.items()) for target in targets)


def _reduce_technical_rows(rows: list[dict[str, object]], *,
        output_grain: list[str], max_rows: int) -> list[dict[str, object]]:
    """Exact bounded amount reduction after full-grain effective resolution."""
    groups: dict[tuple[str, ...], list[dict[str, object]]] = {}
    for row in rows:
        key = tuple(row["members"][axis] for axis in output_grain)
        groups.setdefault(key, []).append(row)
    if len(groups) > max_rows:
        raise ValueError("RESOURCE_LIMIT")
    result = []
    for key, items in sorted(groups.items()):
        units = {item["resultUnit"] for item in items}
        if len(units) != 1 or not next(iter(units)).startswith("amount"):
            raise ValueError("RESOLVED_READ_REDUCTION_UNIT_UNSUPPORTED")
        present = [item for item in items if item["present"]]
        value = (None if not present else format(sum(
            (Decimal(item["value"]) for item in present), Decimal(0)), "f"))
        state_tokens = {item["resultStateToken"] for item in items}
        origins = {item["origin"] for item in items}
        result.append({"members": dict(zip(output_grain, key)),
            "present": bool(present), "value": value,
            "resultUnit": next(iter(units)),
            "origin": next(iter(origins)) if len(origins) == 1 else "hierarchy",
            "currentness": "stale" if any(
                item["currentness"] == "stale" for item in items) else "current",
            "resultStateToken": next(iter(state_tokens))
                if len(state_tokens) == 1 else None,
            "lineage": [{"reduction": "sum",
                "sources": [{"members": item["members"],
                    "origin": item["origin"],
                    "resultStateToken": item["resultStateToken"]}
                    for item in items]}]})
    return result


def _execute_direct_in_transaction(db, scope: ApplicationScope,
        identity: VerifiedIdentity, *, plan: ResolvedCubeReadPlan,
        execution: ResolvedCubeReadExecution, snapshot: dict[str, int],
        resolved: dict, dimensions: list[str], authorized: list[dict],
        raw_source_count: int, binding: dict | None,
        technical: bool = False) -> dict[str, object]:
    from .resolved_cube_read_execution import execute_resolved_read

    rows = []
    for item in authorized:
        if item["kind"] == "numeric":
            value, unit = item["amount"], "amount"
        elif item["kind"] == "text":
            value, unit = item["text"], "text"
        elif item["kind"] == "missing":
            numeric = bool(item.get("numericChangeId"))
            text = bool(item.get("textChangeId"))
            if numeric == text:
                raise ValueError("RESOLVED_READ_MISSING_UNIT_AMBIGUOUS")
            value, unit = None, "amount" if numeric else "text"
        else:
            continue
        rows.append({"members": {axis: item["members"][axis]
            for axis in plan.normalized["outputGrain"]},
            "present": item["kind"] != "missing", "value": value,
            "resultUnit": unit,
            "origin": "input", "currentness": "current",
            "resultStateToken": None,
            "lineage": [{"changeId": item["changeId"],
                "lastRevision": item["lastRevision"]}]})
    stages_by_id = ({} if binding is None else {
        item["stageId"]: item for item in binding["stages"]})
    computed_targets = [target
        for stage in execution.normalized["stages"]
        if stage["stage"] != "input" for target in stage["targets"]]
    stage_outputs: dict[tuple[tuple[str, str], ...], dict[str, object]] = {}

    def stage_reader(stage, pinned_snapshot, remaining):
        if stage["stage"] == "input":
            result = [item for item in rows
                if not _within_targets(item, computed_targets)]
            if len(result) > remaining:
                raise ValueError("RESOURCE_LIMIT")
            return {"snapshot": pinned_snapshot,
                "sourceRows": raw_source_count, "rows": result,
                "evidence": {
                    "resolutionDigest": resolved["resolutionDigest"],
                    "currentness": stage["currentness"]}}
        result = []
        evidence = []
        source_rows = 0
        for stage_id in stage["stageIds"]:
            definition = stages_by_id[stage_id]
            stage_targets = stage["stageTargets"][stage_id]
            if stage["stage"] == "dynamic":
                produced, consumed, proof = _dynamic_rows(db, scope, identity,
                    stage=definition, snapshot=pinned_snapshot,
                    active_dimensions=dimensions,
                    max_source_rows=remaining - source_rows)
                produced = _bound_calculated_rows(produced, stage=definition,
                    targets=stage_targets, origin="dynamic", currentness="current",
                    result_state_token=None)
            elif stage["stage"] == "materialized":
                produced, consumed, proof = _materialized_rows(db, scope,
                    stage=definition,
                    result_state_tokens=stage["resultStateTokens"],
                    active_dimensions=dimensions,
                    freshness=stage["currentness"],
                    max_source_rows=remaining - source_rows,
                    targets=stage_targets)
            elif stage["stage"] == "hierarchy":
                produced, consumed, proof = _hierarchy_rows(
                    db, scope, identity, stage=definition,
                    targets=stage_targets, snapshot=pinned_snapshot,
                    max_source_rows=remaining - source_rows,
                    overlay=stage_outputs)
            else:
                raise ValueError("RESOLVED_READ_STAGE_UNSUPPORTED")
            source_rows += consumed
            if source_rows > remaining:
                raise ValueError("RESOURCE_LIMIT")
            # Stage adapters may inspect a wider source domain. Only exact
            # owned targets can shadow raw values in downstream stages.
            produced = [item for item in produced
                        if _within_targets(item, stage_targets)]
            for item in produced:
                stage_outputs[tuple(sorted(item["members"].items()))] = item
            result.extend(item for item in produced
                if _within_selection(item, resolved["members"])
                and _within_targets(item, stage_targets))
            evidence.append({"stageId": stage_id, **proof})
        result = filter_read_rows(db, identity, scope, result)
        if len(result) > remaining:
            raise ValueError("RESOURCE_LIMIT")
        return {"snapshot": pinned_snapshot,
            "sourceRows": source_rows,
            "rows": result, "evidence": {"definitions": evidence,
                "currentness": ("stale" if any(item["currentness"] == "stale"
                    for item in result) else stage["currentness"])}}

    return execute_resolved_read(plan, execution, stage_reader=stage_reader,
                                 technical=technical)


FUNCTION = "facts.cube.resolved.read"


class PostgresResolvedCubeRead:
    """Bounded direct resolved read; large/reduced work uses technical query."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL runtime DSN is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn = dsn
        self.identity = identity

    def read(self, scope: ApplicationScope, program: object) -> dict[str, object]:
        return self._read(scope, program, technical=False)

    def read_technical(self, scope: ApplicationScope,
                       program: object) -> dict[str, object]:
        """Worker-only execution; persistence remains in the durable repository."""
        return self._read(scope, program, technical=True)

    def _read(self, scope: ApplicationScope, program: object, *,
              technical: bool) -> dict[str, object]:
        if (not isinstance(program, dict)
                or set(program) != {"languageVersion", "function", "arguments"}
                or program.get("languageVersion") != 2
                or program.get("function") != FUNCTION
                or not isinstance(program.get("arguments"), dict)):
            raise ValueError("RESOLVED_READ_PROGRAM_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            # The established calculated-member compiler uses a session-local
            # membership relation.  Create it before the immutable business
            # read cut; the subsequent transaction can remain READ ONLY.
            with db.transaction():
                db.execute('''CREATE TEMP TABLE IF NOT EXISTS
                    epm_selected_domain_member(
                    dimension_id text NOT NULL,member_id text NOT NULL,
                    PRIMARY KEY(dimension_id,member_id))
                    ON COMMIT PRESERVE ROWS''')
            with db.transaction():
                # Authorization rechecks intentionally require READ COMMITTED.
                # Source revision pins below therefore fail the whole read if a
                # concurrent commit crosses this transaction.
                db.execute("SET TRANSACTION READ ONLY")
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read")
                dimensions = _dimensions_for_read(db, scope)
                requested_plan = compile_resolved_cube_read(program["arguments"],
                    active_dimensions=dimensions)
                expected_delivery = "technical_query" if technical else "direct"
                if requested_plan.normalized["delivery"] != expected_delivery:
                    raise ValueError("RESOLVED_READ_TECHNICAL_QUERY_REQUIRED")
                reduce_output=(technical and set(
                    requested_plan.normalized["outputGrain"])!=set(dimensions))
                plan=(ResolvedCubeReadPlan({**requested_plan.normalized,
                    "outputGrain":list(dimensions),"limits":{
                        **requested_plan.normalized["limits"],"maxRows":min(
                            requested_plan.normalized["limits"][
                                "maxSourceRows"],100_000)}})
                    if reduce_output else requested_plan)
                configure_statement_timeout(
                    db, plan.normalized["limits"]["timeoutMs"])
                snapshot = load_resolved_read_snapshot(db, scope)
                if plan.normalized["selection"]["metadataRevision"] != \
                        snapshot["metadataRevision"]:
                    raise ValueError("STALE_METADATA_REVISION")
                authority = resolve_effective_dimensional_scope(
                    db, self.identity, scope, function=FUNCTION)
                resolved = resolve_selection_in_transaction(db, scope,
                    plan.normalized["selection"], snapshot["metadataRevision"],
                    authority=authority)
                execution = compile_current_resolved_read(db, scope,
                    plan=plan, snapshot=snapshot,
                    resolved_members=resolved["members"])
                raw = PostgresCubeQuery._page(db, scope, {}, "",
                    snapshot["commitRevision"], snapshot["commitRevision"],
                    not plan.normalized["presentation"]["suppression"][
                        "missing"], plan.normalized["limits"]["maxRows"] + 1,
                    member_sets=resolved["members"])
                if len(raw) > plan.normalized["limits"]["maxRows"]:
                    raise ValueError("RESOURCE_LIMIT")
                authorized = filter_read_rows(db, self.identity, scope, raw)
                binding = (None if plan.normalized["source"]["semantics"] ==
                    "own" else read_current_resolved_read_binding(
                        db, scope,
                        binding_id=plan.normalized["source"]["bindingId"],
                        expected_state_token=plan.normalized["source"][
                            "bindingStateToken"])[
                            "binding"].normalized)
                result = _execute_direct_in_transaction(db, scope,
                    self.identity, plan=plan, execution=execution,
                    snapshot=snapshot, resolved=resolved,
                    dimensions=dimensions, authorized=authorized,
                    raw_source_count=len(raw), binding=binding,
                    technical=technical)
                after = load_resolved_read_snapshot(db, scope)
                final_authority = resolve_effective_dimensional_scope(
                    db, self.identity, scope, function=FUNCTION)
                if (after != snapshot
                        or final_authority.scope_digest != authority.scope_digest):
                    raise ValueError("RESOLVED_READ_SNAPSHOT_CHANGED")
                if technical:
                    if reduce_output:
                        reduced = _reduce_technical_rows(result["rows"],
                            output_grain=requested_plan.normalized[
                                "outputGrain"],max_rows=requested_plan.normalized[
                                    "limits"]["maxRows"])
                        result["rows"] = validate_resolved_rows(
                            reduced, plan=requested_plan, snapshot=snapshot)
                        result["requestDigest"]=requested_plan.digest
                    state = db.execute("""SELECT schema_epoch,
                        active_projection_generation FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s""", (
                        scope.workspace_id, scope.application_id)).fetchone()
                    result["technicalPins"] = {
                        "schemaEpoch": state["schema_epoch"],
                        "activeProjectionGeneration":
                            state["active_projection_generation"]}
                return result


def _dimensions_for_read(db, scope: ApplicationScope) -> list[str]:
    row = db.execute("""SELECT l.dimensions FROM epm.application_state s
        JOIN epm.coordinate_layout l
          USING(workspace_id,application_id,schema_epoch)
        WHERE s.workspace_id=%s AND s.application_id=%s""", (
        scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise ValueError("COORDINATE_LAYOUT_UNAVAILABLE")
    return list(row["dimensions"])
