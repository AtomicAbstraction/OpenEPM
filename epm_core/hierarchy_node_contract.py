"""Typed hierarchy-node semantics shared by dynamic and stored calculations."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
from typing import Mapping, Sequence
from .current_object_contract import require_state_token


FORMAT = "openepm-hierarchy-node-v1"
POLICIES = frozenset({"own_only", "children_only", "own_plus_children"})
MEMBERSHIP = frozenset({"unique_member", "placement"})
OPERATORS = {"Add": 1, "Subtract": -1, "Ignore": 0}


def _identifier(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(code)
    return value


@dataclass(frozen=True, slots=True)
class HierarchyNodePlan:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class HierarchyContributions:
    """Resolved canonical or placement-aware source coefficients."""

    sum_weights: dict[str, int]
    count_weights: dict[str, int]
    placement_paths: tuple[tuple[str, tuple[str, ...], int], ...]
    effective_operators: dict[str, dict[str, str]]

    @property
    def lineage(self) -> dict[str, object]:
        payload = {
            "format": "openepm-hierarchy-node-lineage-v1",
            "sumWeights": self.sum_weights,
            "countWeights": self.count_weights,
            "placementPaths": [
                {"memberId": member, "path": list(path), "weight": weight}
                for member, path, weight in self.placement_paths
            ],
            "effectiveOperators": self.effective_operators,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return {**payload, "lineageDigest": sha256(encoded).hexdigest()}

    @property
    def digest(self) -> str:
        return self.lineage["lineageDigest"]


def compile_hierarchy_node(value: object) -> HierarchyNodePlan:
    required = {
        "format",
        "dimensionId",
        "hierarchyId",
        "hierarchyStateToken",
        "membershipSemantics",
        "sourceSemantics",
        "defaultInternalPolicy",
        "nodePolicies",
        "resultUnit",
        "missing",
    }
    if (not isinstance(value, dict)
            or set(value) not in {frozenset(required),
                                  frozenset(required | {"ruleOperatorOverrides"})}):
        raise ValueError("HIERARCHY_NODE_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("HIERARCHY_NODE_FORMAT_UNSUPPORTED")
    dimension_id = _identifier(value["dimensionId"], "HIERARCHY_NODE_DIMENSION_INVALID")
    hierarchy_id = _identifier(value["hierarchyId"], "HIERARCHY_NODE_HIERARCHY_INVALID")
    state_token = require_state_token(value["hierarchyStateToken"],
        error="HIERARCHY_NODE_HIERARCHY_INVALID")
    membership = value["membershipSemantics"]
    if membership not in MEMBERSHIP:
        raise ValueError("HIERARCHY_NODE_MEMBERSHIP_INVALID")
    source = value["sourceSemantics"]
    if source not in {"own", "effective"}:
        raise ValueError("HIERARCHY_NODE_SOURCE_INVALID")
    default_policy = value["defaultInternalPolicy"]
    if default_policy not in POLICIES:
        raise ValueError("HIERARCHY_NODE_POLICY_INVALID")
    policies = value["nodePolicies"]
    if (
        not isinstance(policies, dict)
        or len(policies) > 4096
        or any(
            _identifier(member_id, "HIERARCHY_NODE_POLICY_INVALID") != member_id
            or policy not in POLICIES
            for member_id, policy in policies.items()
        )
    ):
        raise ValueError("HIERARCHY_NODE_POLICY_INVALID")
    result_unit = _identifier(value["resultUnit"], "HIERARCHY_NODE_UNIT_INVALID")
    if value["missing"] != "preserve":
        raise ValueError("HIERARCHY_NODE_MISSING_UNSUPPORTED")
    if source == "own" and (policies or default_policy != "own_only"):
        raise ValueError("HIERARCHY_NODE_OWN_POLICY_INVALID")
    overrides = value.get("ruleOperatorOverrides")
    if overrides is not None and (
        not isinstance(overrides, dict)
        or not 1 <= len(overrides) <= 4096
        or any(
            _identifier(relationship_id,
                        "HIERARCHY_NODE_RULE_OVERRIDE_INVALID")
            != relationship_id
            or operator not in OPERATORS
            for relationship_id, operator in overrides.items()
        )
    ):
        raise ValueError("HIERARCHY_NODE_RULE_OVERRIDE_INVALID")
    normalized = {
            "format": FORMAT,
            "dimensionId": dimension_id,
            "hierarchyId": hierarchy_id,
            "hierarchyStateToken": state_token,
            "membershipSemantics": membership,
            "sourceSemantics": source,
            "defaultInternalPolicy": default_policy,
            "nodePolicies": dict(sorted(policies.items())),
            "resultUnit": result_unit,
            "missing": "preserve",
        }
    # Preserve the canonical digest of existing v1 definitions.  The optional
    # field is emitted only when an authored published rule actually overrides
    # at least one stable relationship identity.
    if overrides is not None:
        normalized["ruleOperatorOverrides"] = dict(sorted(overrides.items()))
    return HierarchyNodePlan(normalized)


def effective_edge_operator(plan: HierarchyNodePlan, *, relationship_id: str,
        member_operator: str, relationship_override: str | None,
        placement: bool) -> tuple[str, str]:
    """Resolve member < placement < published-rule operator precedence."""
    if not isinstance(plan, HierarchyNodePlan):
        raise ValueError("HIERARCHY_NODE_PLAN_INVALID")
    relationship_id = _identifier(
        relationship_id, "HIERARCHY_NODE_RELATIONSHIP_INVALID")
    if member_operator not in {*OPERATORS, "NeverAggregate", "Formula"}:
        raise ValueError("HIERARCHY_NODE_OPERATOR_INVALID")
    if relationship_override is not None and relationship_override not in {
            *OPERATORS, "NeverAggregate", "Formula"}:
        raise ValueError("HIERARCHY_NODE_OPERATOR_INVALID")
    rule = plan.normalized.get("ruleOperatorOverrides", {})
    if relationship_id in rule:
        return rule[relationship_id], "published_rule"
    if placement and relationship_override is not None:
        return relationship_override, "relationship"
    return member_operator, "member"


def evaluate_tree_nodes(
    plan: HierarchyNodePlan,
    *,
    root_member_id: str,
    children: Mapping[str, Sequence[tuple[str, str]]],
    own_values: Mapping[str, Decimal | None],
) -> Decimal | None:
    """Independent exact oracle for one tree/placement hierarchy.

    ``None`` is absent.  A present Decimal zero remains present.  This oracle
    deliberately rejects shared children in unique-member mode: the database
    lowering must normalize contribution identities rather than choose a path.
    """

    root = _identifier(root_member_id, "HIERARCHY_NODE_MEMBER_INVALID")
    normalized_children: dict[str, tuple[tuple[str, str], ...]] = {}
    parents: dict[str, int] = {}
    for parent, edges in children.items():
        _identifier(parent, "HIERARCHY_NODE_MEMBER_INVALID")
        normalized: list[tuple[str, str]] = []
        for child, operator in edges:
            _identifier(child, "HIERARCHY_NODE_MEMBER_INVALID")
            if operator not in OPERATORS:
                raise ValueError("HIERARCHY_NODE_OPERATOR_INVALID")
            normalized.append((child, operator))
            parents[child] = parents.get(child, 0) + 1
        if len({child for child, _ in normalized}) != len(normalized):
            raise ValueError("HIERARCHY_NODE_DUPLICATE_EDGE")
        normalized_children[parent] = tuple(normalized)
    if (
        plan.normalized["membershipSemantics"] == "unique_member"
        and any(count > 1 for count in parents.values())
    ):
        raise ValueError("HIERARCHY_NODE_SHARED_MEMBER_REQUIRES_NORMALIZATION")

    policies = plan.normalized["nodePolicies"]
    default_policy = plan.normalized["defaultInternalPolicy"]
    visiting: set[str] = set()
    memo: dict[str, Decimal | None] = {}

    def evaluate(member_id: str) -> Decimal | None:
        if member_id in memo:
            return memo[member_id]
        if member_id in visiting:
            raise ValueError("HIERARCHY_NODE_CYCLE")
        visiting.add(member_id)
        edges = normalized_children.get(member_id, ())
        policy = policies.get(member_id, default_policy if edges else "own_only")
        if not edges and policy == "children_only":
            raise ValueError("HIERARCHY_NODE_CHILDREN_ONLY_LEAF")
        present = False
        total = Decimal(0)
        own = own_values.get(member_id)
        if policy in {"own_only", "own_plus_children"} and own is not None:
            if not isinstance(own, Decimal):
                raise ValueError("HIERARCHY_NODE_VALUE_INVALID")
            total += own
            present = True
        if policy in {"children_only", "own_plus_children"}:
            for child, operator in edges:
                child_value = evaluate(child)
                if child_value is not None and OPERATORS[operator] != 0:
                    total += child_value * OPERATORS[operator]
                    present = True
        visiting.remove(member_id)
        memo[member_id] = total if present else None
        return memo[member_id]

    return evaluate(root)


def resolve_hierarchy_contributions(
    plan: HierarchyNodePlan,
    *,
    root_member_id: str,
    children: Mapping[str, Sequence[tuple[str, str, str] | tuple[str, str, str, str]]],
) -> HierarchyContributions:
    """Resolve effective-node source coefficients without reading facts.

    Each edge is ``(child_member_id, relationship_id, operator)``.  Placement
    mode retains and combines every selected path.  Unique-member mode counts
    one canonical member once and rejects conflicting path coefficients rather
    than choosing an arbitrary path.
    """

    root = _identifier(root_member_id, "HIERARCHY_NODE_MEMBER_INVALID")
    normalized: dict[str, tuple[tuple[str, str, str, str], ...]] = {}
    effective_operators: dict[str, dict[str, str]] = {}
    seen_relationships: set[str] = set()
    for parent, edges in children.items():
        _identifier(parent, "HIERARCHY_NODE_MEMBER_INVALID")
        values: list[tuple[str, str, str, str]] = []
        for edge in edges:
            if len(edge) == 3:
                child, relationship_id, operator = edge
                source = "resolved"
            elif len(edge) == 4:
                child, relationship_id, operator, source = edge
            else:
                raise ValueError("HIERARCHY_NODE_EDGE_INVALID")
            _identifier(child, "HIERARCHY_NODE_MEMBER_INVALID")
            _identifier(relationship_id, "HIERARCHY_NODE_RELATIONSHIP_INVALID")
            if operator not in OPERATORS:
                raise ValueError("HIERARCHY_NODE_OPERATOR_INVALID")
            if source not in {"member", "relationship", "published_rule", "resolved"}:
                raise ValueError("HIERARCHY_NODE_OPERATOR_SOURCE_INVALID")
            if relationship_id in seen_relationships:
                raise ValueError("HIERARCHY_NODE_DUPLICATE_EDGE")
            seen_relationships.add(relationship_id)
            values.append((child, relationship_id, operator, source))
        if len({relationship_id for _, relationship_id, _, _ in values}) != len(values):
            raise ValueError("HIERARCHY_NODE_DUPLICATE_EDGE")
        normalized[parent] = tuple(values)

    policies = plan.normalized["nodePolicies"]
    default_policy = plan.normalized["defaultInternalPolicy"]
    placements: list[tuple[str, tuple[str, ...], int]] = []
    visiting: set[str] = set()

    def walk(member_id: str, path: tuple[str, ...], coefficient: int) -> None:
        if member_id in visiting:
            raise ValueError("HIERARCHY_NODE_CYCLE")
        edges = normalized.get(member_id, ())
        policy = policies.get(member_id, default_policy if edges else "own_only")
        if not edges and policy == "children_only":
            raise ValueError("HIERARCHY_NODE_CHILDREN_ONLY_LEAF")
        if policy in {"own_only", "own_plus_children"} and coefficient:
            placements.append((member_id, path, coefficient))
        if policy in {"children_only", "own_plus_children"}:
            visiting.add(member_id)
            for child, relationship_id, operator, source in edges:
                effective_operators[relationship_id] = {
                    "operator": operator, "source": source}
                walk(
                    child,
                    (*path, relationship_id),
                    coefficient * OPERATORS[operator],
                )
            visiting.remove(member_id)

    walk(root, (), 1)
    if plan.normalized["membershipSemantics"] == "placement":
        sum_weights: dict[str, int] = {}
        count_weights: dict[str, int] = {}
        for member, _, coefficient in placements:
            sum_weights[member] = sum_weights.get(member, 0) + coefficient
            count_weights[member] = count_weights.get(member, 0) + abs(coefficient)
    else:
        by_member: dict[str, set[int]] = {}
        for member, _, coefficient in placements:
            if coefficient:
                by_member.setdefault(member, set()).add(coefficient)
        if any(len(weights) != 1 for weights in by_member.values()):
            raise ValueError("HIERARCHY_NODE_UNIQUE_PATH_OPERATOR_AMBIGUOUS")
        sum_weights = {member: next(iter(weights)) for member, weights in by_member.items()}
        count_weights = {member: 1 for member in by_member}
    return HierarchyContributions(
        dict(sorted(sum_weights.items())),
        dict(sorted(count_weights.items())),
        tuple(sorted(placements)),
        dict(sorted(effective_operators.items())),
    )
