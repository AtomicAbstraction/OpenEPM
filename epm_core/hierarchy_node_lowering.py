"""Lower a resolved hierarchy-node binding into the fixed aggregate engine."""

from __future__ import annotations

from typing import Mapping

from .cube_aggregate_ir import CubeAggregateIR, compile_cube_aggregate
from .hierarchy_node_contract import HierarchyContributions, HierarchyNodePlan


def lower_hierarchy_node(
    plan: HierarchyNodePlan,
    *,
    contributions: HierarchyContributions,
    fixed_members: Mapping[str, str],
    metadata_revision: int,
    policy_revision: int,
) -> CubeAggregateIR:
    """Create one exact node-value reduction over fixed remaining axes."""

    dimension = plan.normalized["dimensionId"]
    if dimension in fixed_members:
        raise ValueError("HIERARCHY_NODE_FIXED_AXIS_CONFLICT")
    if (
        not fixed_members
        or any(
            not isinstance(axis, str)
            or not axis
            or not isinstance(member, str)
            or not member
            for axis, member in fixed_members.items()
        )
    ):
        raise ValueError("HIERARCHY_NODE_FIXED_GRAIN_INVALID")
    members = sorted(contributions.sum_weights)
    if not members or len(members) > 500:
        raise ValueError("HIERARCHY_NODE_RESOLUTION_BUDGET")
    dimensions = sorted((*fixed_members, dimension))
    selectors = {
        axis: {"kind": "Members", "memberIds": [fixed_members[axis]]}
        for axis in fixed_members
    }
    selectors[dimension] = {"kind": "Members", "memberIds": members}
    pins = {
        "nodeDefinitionDigest": plan.digest,
        "contributionDigest": contributions.digest,
        "hierarchyId": plan.normalized["hierarchyId"],
        "hierarchyStateToken": plan.normalized["hierarchyStateToken"],
        "metadataRevision": metadata_revision,
        "policyRevision": policy_revision,
    }
    if plan.normalized["membershipSemantics"] == "placement":
        pins["placementLineageDigest"] = contributions.digest
        aggregation = "hierarchy_placement_weighted_sum"
        weight_field = {
            "placementWeights": {
                dimension: {
                    member: {
                        "sumWeight": contributions.sum_weights[member],
                        "countWeight": contributions.count_weights[member],
                    }
                    for member in members
                }
            }
        }
    else:
        aggregation = "hierarchy_unique_member_weighted_sum"
        weight_field = {
            "operatorWeights": {
                dimension: {
                    member: contributions.sum_weights[member] for member in members
                }
            }
        }
    return compile_cube_aggregate(
        {
            "source": "raw_numeric",
            "grain": {
                "inputDimensions": dimensions,
                "groupBy": [],
                "reduceDimensions": [dimension],
            },
            "selectors": selectors,
            "measures": [{"kind": "SumAmount"}, {"kind": "CountPresent"}],
            "missing": "exclude",
            "aggregation": aggregation,
            "hierarchyPins": pins,
            **weight_field,
        },
        input_dimensions=dimensions,
        dimension_roles={axis: None for axis in dimensions},
    )
