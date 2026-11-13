"""Fail-closed lowering from generic aggregation to the qualified legacy IR."""

from __future__ import annotations

from typing import Mapping, Sequence

from .cube_aggregate_ir import CubeAggregateIR, compile_cube_aggregate
from .generic_aggregate_contract import GenericAggregatePlan


_MEASURE = {"sum": "SumAmount", "count_present": "CountPresent"}


def lower_generic_aggregate(
    plan: GenericAggregatePlan,
    *,
    resolved_members: Mapping[str, Sequence[str]],
    configured_operators: Mapping[str, Mapping[str, str]],
    selection_pins: Mapping[str, object],
    placement_contributions: Mapping[str, Mapping[str, object]] | None = None,
) -> CubeAggregateIR:
    """Reuse the exact current engine only for semantics it already proves.

    Selection/member-list/hierarchy resolution and authorization happen before
    this boundary.  This adapter does not pretend that placement or weighted
    member operators are ordinary unique-coordinate SUM operations.
    """
    value = plan.normalized
    dimensions = tuple(
        item["dimensionId"] for item in value["selection"]["dimensions"]
    )
    placement = value["membershipSemantics"] == "placement"
    if set(resolved_members) != set(dimensions) or set(configured_operators) != set(dimensions):
        raise ValueError("GENERIC_AGGREGATE_RESOLUTION_INCOMPLETE")
    expected_pins = {"selectionId","resolutionDigest",
                     "metadataRevision","policyRevision"}
    if placement:
        expected_pins.add("placementLineageDigest")
    if (not isinstance(selection_pins, Mapping)
            or set(selection_pins) != expected_pins):
        raise ValueError("GENERIC_AGGREGATE_SELECTION_PINS_INVALID")
    selectors = {}
    weights = {}
    placement_weights = {}
    total = 0
    for dimension in dimensions:
        members = list(resolved_members[dimension])
        if not members or len(members) != len(set(members)):
            raise ValueError("GENERIC_AGGREGATE_RESOLUTION_INVALID")
        operators = configured_operators[dimension]
        if set(operators) != set(members):
            raise ValueError("GENERIC_AGGREGATE_OPERATOR_RESOLUTION_INCOMPLETE")
        if dimension in value["reduceDimensions"]:
            if placement:
                contribution = ((placement_contributions or {}).get(dimension))
                if (not isinstance(contribution, Mapping)
                        or set(contribution) != {"weights", "lineageDigest"}
                        or not isinstance(contribution["weights"], Mapping)
                        or set(contribution["weights"]) != set(members)):
                    raise ValueError(
                        "GENERIC_AGGREGATE_PLACEMENT_RESOLUTION_INCOMPLETE")
                placement_weights[dimension] = dict(contribution["weights"])
            else:
                if any(operator == "NeverAggregate"
                       for operator in operators.values()):
                    raise ValueError("GENERIC_AGGREGATE_NEVER_AGGREGATE")
                if any(operator == "Formula" for operator in operators.values()):
                    raise ValueError("GENERIC_AGGREGATE_FORMULA_NOT_QUALIFIED")
                weights[dimension] = {
                    member: {"Add": 1, "Subtract": -1, "Ignore": 0}[operator]
                    for member, operator in operators.items()}
        total += len(members)
        selectors[dimension] = {"kind": "Members", "memberIds": members}
    if total > 500:
        raise ValueError("GENERIC_AGGREGATE_RESOLUTION_BUDGET")
    grouped = value["groupBy"]
    reduced = value["reduceDimensions"]
    fixed = set(dimensions) - set(grouped) - set(reduced)
    if any(len(resolved_members[dimension]) != 1 for dimension in fixed):
        raise ValueError("GENERIC_AGGREGATE_FIXED_DIMENSION_NOT_SINGLETON")
    arguments = {
        "source": "raw_numeric",
        "grain": {
            "inputDimensions": list(dimensions),
            "groupBy": list(grouped),
            "reduceDimensions": list(reduced),
        },
        "selectors": selectors,
        "measures": [{"kind": _MEASURE[item]} for item in value["measures"]],
        "missing": "exclude",
        "aggregation": ("generic_placement_weighted_sum" if placement else
            "generic_unique_member_weighted_sum"
            if any(weight != 1 for by_member in weights.values()
                   for weight in by_member.values())
            else "generic_unique_member_sum"),
        "genericPins": dict(selection_pins),
    }
    if arguments["aggregation"] == "generic_unique_member_weighted_sum":
        arguments["operatorWeights"] = weights
    if placement:
        arguments["placementWeights"] = placement_weights
    # The generic compiler is intentionally role-neutral.  Passing None here
    # avoids reintroducing the legacy financial-role reduction prohibition.
    return compile_cube_aggregate(
        arguments,
        input_dimensions=dimensions,
        dimension_roles={dimension: None for dimension in dimensions},
    )


def lower_unique_member_aggregate(
    plan: GenericAggregatePlan,
    *,
    resolved_members: Mapping[str, Sequence[str]],
    configured_operators: Mapping[str, Mapping[str, str]],
    selection_pins: Mapping[str, object],
) -> CubeAggregateIR:
    """Compatibility name retained for already-qualified callers and tests."""
    return lower_generic_aggregate(plan, resolved_members=resolved_members,
        configured_operators=configured_operators, selection_pins=selection_pins)
