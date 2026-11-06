"""Exact bounded placement contributions for generic hierarchy aggregation."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Mapping, Sequence


MAX_PLACEMENT_PATHS = 500
MAX_PLACEMENT_DEPTH = 32
MAX_PLACEMENT_LINEAGE_BYTES = 4 * 1024 * 1024
_SIGN = {"Add": 1, "Subtract": -1}


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def resolve_placement_contributions(
    selector: Mapping[str, object],
    *,
    selected_members: Sequence[str],
    member_operators: Mapping[str, str],
    relationships: Sequence[Mapping[str, object]],
) -> dict:
    """Resolve paths and their signed/count contributions for one reduced axis.

    A relationship override applies to that child placement; otherwise the
    child's member default applies.  Operators therefore compose along a path.
    Ignored paths contribute neither amount nor presence.  NeverAggregate and
    Formula fail closed until a different governed calculation primitive owns
    them.  The returned path list is canonical and digestible plan evidence.
    """
    if not isinstance(selector, Mapping) or selector.get("kind") != "hierarchy":
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTOR_UNSUPPORTED")
    if selector.get("operator") not in {"children", "descendants", "leaves"}:
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTOR_UNSUPPORTED")
    root = selector.get("memberId")
    if not isinstance(root, str) or root not in member_operators:
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_ROOT_UNAVAILABLE")
    selected = list(selected_members)
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTION_INVALID")

    children: dict[str, list[dict]] = {member: [] for member in member_operators}
    relationship_ids: set[str] = set()
    for raw in relationships:
        if set(raw) != {"relationshipId", "parentMemberId", "childMemberId",
                       "aggregationOperatorOverride"}:
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_METADATA_INVALID")
        relationship_id = raw["relationshipId"]
        parent = raw["parentMemberId"]
        child = raw["childMemberId"]
        override = raw["aggregationOperatorOverride"]
        if (not isinstance(relationship_id, str) or relationship_id in relationship_ids
                or parent not in children or child not in children or parent == child
                or (override is not None and override not in
                    {"Add", "Subtract", "Ignore", "NeverAggregate", "Formula"})):
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_METADATA_INVALID")
        relationship_ids.add(relationship_id)
        children[parent].append(dict(raw))
    for edges in children.values():
        edges.sort(key=lambda item: item["relationshipId"])

    paths: list[dict] = []

    def append_path(member: str, edges: list[dict]) -> None:
        if len(paths) == MAX_PLACEMENT_PATHS:
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_PATH_LIMIT")
        sign = 1
        ignored = False
        steps = []
        if not edges:
            operators = [member_operators[member]]
        else:
            operators = []
            for edge in edges:
                operator = (edge["aggregationOperatorOverride"]
                            or member_operators[edge["childMemberId"]])
                operators.append(operator)
                steps.append({"relationshipId": edge["relationshipId"],
                              "parentMemberId": edge["parentMemberId"],
                              "childMemberId": edge["childMemberId"],
                              "effectiveOperator": operator})
        for operator in operators:
            if operator == "NeverAggregate":
                raise ValueError("GENERIC_AGGREGATE_NEVER_AGGREGATE")
            if operator == "Formula":
                raise ValueError("GENERIC_AGGREGATE_FORMULA_NOT_QUALIFIED")
            if operator == "Ignore":
                ignored = True
            else:
                sign *= _SIGN[operator]
        paths.append({"memberId": member, "steps": steps,
                      "sumWeight": 0 if ignored else sign,
                      "countWeight": 0 if ignored else 1})

    operator = selector["operator"]
    if selector.get("includeSelf"):
        append_path(root, [])
    if operator == "children":
        for edge in children[root]:
            append_path(edge["childMemberId"], [edge])
    else:
        def walk(member: str, edges: list[dict], seen: frozenset[str]) -> None:
            if len(edges) >= MAX_PLACEMENT_DEPTH:
                raise ValueError("GENERIC_AGGREGATE_PLACEMENT_DEPTH_LIMIT")
            for edge in children[member]:
                child = edge["childMemberId"]
                if child in seen:
                    raise ValueError("GENERIC_AGGREGATE_PLACEMENT_CYCLE")
                path = [*edges, edge]
                if operator == "descendants" or not children[child]:
                    append_path(child, path)
                walk(child, path, seen | {child})
        walk(root, [], frozenset({root}))

    allowed = set(selected)
    paths = [path for path in paths if path["memberId"] in allowed]
    if {path["memberId"] for path in paths} != allowed:
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTION_MISMATCH")
    paths.sort(key=lambda item: (item["memberId"],
        [step["relationshipId"] for step in item["steps"]]))
    weights = {member: {"sumWeight": 0, "countWeight": 0}
               for member in selected}
    for path in paths:
        item = weights[path["memberId"]]
        item["sumWeight"] += path["sumWeight"]
        item["countWeight"] += path["countWeight"]
    artifact = {"format": "openepm-placement-contributions-v1",
                "rootMemberId": root, "selectorOperator": operator,
                "includeSelf": selector["includeSelf"], "paths": paths,
                "weights": weights}
    return {**artifact, "lineageDigest": _digest(artifact)}


def combine_placement_lineage(
    contributions: Mapping[str, Mapping[str, object]],
) -> dict:
    """Return one canonical, bounded, independently inspectable artifact."""
    if not isinstance(contributions, Mapping) or not contributions:
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_LINEAGE_INVALID")
    dimensions = []
    for dimension in sorted(contributions):
        item = contributions[dimension]
        required = {"format", "rootMemberId", "selectorOperator", "includeSelf",
                    "paths", "weights", "lineageDigest"}
        if (not isinstance(dimension, str) or not dimension
                or not isinstance(item, Mapping) or set(item) != required
                or item["format"] != "openepm-placement-contributions-v1"):
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_LINEAGE_INVALID")
        payload = {key: item[key] for key in required - {"lineageDigest"}}
        if _digest(payload) != item["lineageDigest"]:
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_LINEAGE_INVALID")
        dimensions.append({"dimensionId": dimension, **dict(item)})
    artifact = {"format": "openepm-placement-lineage-v1",
                "dimensions": dimensions}
    encoded = json.dumps(artifact, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > MAX_PLACEMENT_LINEAGE_BYTES:
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_LINEAGE_LIMIT")
    return {**artifact, "lineageDigest": sha256(encoded).hexdigest()}


def resolve_sealed_placement_contributions(
    placements: Sequence[Mapping[str, object]],
    *,
    member_operators: Mapping[str, str],
    relationships: Sequence[Mapping[str, object]],
) -> dict:
    """Resolve sealed direct or member-list placement identities to weights."""
    if (not isinstance(placements, Sequence) or isinstance(placements, (str, bytes))
            or not placements or len(placements) > MAX_PLACEMENT_PATHS):
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTION_INVALID")
    edges: dict[str, dict] = {}
    for raw in relationships:
        if (not isinstance(raw, Mapping)
                or set(raw) != {"relationshipId", "parentMemberId",
                                "childMemberId", "aggregationOperatorOverride"}):
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_METADATA_INVALID")
        relationship_id = raw["relationshipId"]
        if (not isinstance(relationship_id, str) or relationship_id in edges
                or raw["parentMemberId"] not in member_operators
                or raw["childMemberId"] not in member_operators):
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_METADATA_INVALID")
        edges[relationship_id] = dict(raw)
    paths = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for raw in placements:
        if (not isinstance(raw, Mapping)
                or set(raw) != {"memberId", "pathRelationshipIds"}
                or raw["memberId"] not in member_operators
                or not isinstance(raw["pathRelationshipIds"], list)
                or len(raw["pathRelationshipIds"]) > MAX_PLACEMENT_DEPTH
                or any(not isinstance(item, str)
                       for item in raw["pathRelationshipIds"])):
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTION_INVALID")
        member = raw["memberId"]
        path_ids = tuple(raw["pathRelationshipIds"])
        key = (member, path_ids)
        if key in seen:
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_SELECTION_INVALID")
        seen.add(key)
        steps = []
        prior_child = None
        operators = []
        for relationship_id in path_ids:
            edge = edges.get(relationship_id)
            if edge is None or (prior_child is not None
                    and edge["parentMemberId"] != prior_child):
                raise ValueError("GENERIC_AGGREGATE_PLACEMENT_PATH_INVALID")
            prior_child = edge["childMemberId"]
            operator = (edge["aggregationOperatorOverride"]
                        or member_operators[edge["childMemberId"]])
            operators.append(operator)
            steps.append({"relationshipId": relationship_id,
                          "parentMemberId": edge["parentMemberId"],
                          "childMemberId": edge["childMemberId"],
                          "effectiveOperator": operator})
        if path_ids and prior_child != member:
            raise ValueError("GENERIC_AGGREGATE_PLACEMENT_PATH_INVALID")
        if not path_ids:
            operators = [member_operators[member]]
        sign = 1
        ignored = False
        for operator in operators:
            if operator == "NeverAggregate":
                raise ValueError("GENERIC_AGGREGATE_NEVER_AGGREGATE")
            if operator == "Formula":
                raise ValueError("GENERIC_AGGREGATE_FORMULA_NOT_QUALIFIED")
            if operator == "Ignore":
                ignored = True
            else:
                sign *= _SIGN[operator]
        paths.append({"memberId": member, "steps": steps,
                      "sumWeight": 0 if ignored else sign,
                      "countWeight": 0 if ignored else 1})
    paths.sort(key=lambda item: (item["memberId"],
        [step["relationshipId"] for step in item["steps"]]))
    weights = {item["memberId"]: {"sumWeight": 0, "countWeight": 0}
               for item in paths}
    for path in paths:
        weights[path["memberId"]]["sumWeight"] += path["sumWeight"]
        weights[path["memberId"]]["countWeight"] += path["countWeight"]
    artifact = {"format": "openepm-placement-contributions-v1",
                "rootMemberId": None, "selectorOperator": "composed",
                "includeSelf": False, "paths": paths, "weights": weights}
    return {**artifact, "lineageDigest": _digest(artifact)}
