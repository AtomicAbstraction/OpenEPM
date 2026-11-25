"""Bounded deterministic evaluation for canonical member-list expressions.

The evaluator is metadata-only.  It never reads facts, writes business data or
accepts SQL.  PostgreSQL adapters supply one authorized, revision-pinned
metadata snapshot and the fixed core evaluates the already-canonical IR.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
import json
from typing import Mapping, Sequence

from .member_list_contract import canonical_member_list_definition


MAX_EVALUATED_MEMBERS = 100_000
MAX_EVALUATED_PLACEMENTS = 100_000
MAX_PLACEMENT_DEPTH = 32


def _unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _typed(value: object, kind: str | None) -> object:
    if value is None:
        return None
    if kind == "Decimal":
        if not isinstance(value, str):
            raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_CORRUPT")
        try:
            return Decimal(value)
        except InvalidOperation as error:
            raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_CORRUPT") from error
    if kind == "Date":
        if not isinstance(value, str):
            raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_CORRUPT")
        try:
            return date.fromisoformat(value)
        except ValueError as error:
            raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_CORRUPT") from error
    return value


def _matches(actual: object, operator: str, expected: object, kind: str | None) -> bool:
    if operator == "exists":
        return (actual is not None) is expected
    if actual is None:
        return False
    left = _typed(actual, kind)
    if operator == "in":
        return left in [_typed(item, kind) for item in expected]
    right = _typed(expected, kind)
    if operator == "eq":
        return left == right
    if operator == "ne":
        return left != right
    if operator == "lt":
        return left < right
    if operator == "lte":
        return left <= right
    if operator == "gt":
        return left > right
    if operator == "gte":
        return left >= right
    if operator == "contains":
        return isinstance(left, str) and isinstance(right, str) and right in left
    if operator == "starts_with":
        return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
    raise ValueError("MEMBER_LIST_ATTRIBUTE_OPERATOR_INVALID")


def _named_graph_indexes(graph, member_ids):
    if (not isinstance(graph, Mapping) or set(graph) != {"hierarchyId", "members", "relationships"}
            or not isinstance(graph["members"], (list, tuple))
            or not set(graph["members"]) <= member_ids):
        raise ValueError("MEMBER_LIST_HIERARCHY_METADATA_INVALID")
    nodes = set(graph["members"])
    children = {member: [] for member in nodes}
    parents = {member: [] for member in nodes}
    seen = set()
    for edge in graph["relationships"]:
        if (not isinstance(edge, Mapping)
                or set(edge) != {"relationshipId", "parentMemberId", "childMemberId"}
                or edge["relationshipId"] in seen
                or edge["parentMemberId"] not in nodes or edge["childMemberId"] not in nodes
                or edge["parentMemberId"] == edge["childMemberId"]):
            raise ValueError("MEMBER_LIST_RELATIONSHIP_INVALID")
        seen.add(edge["relationshipId"])
        children[edge["parentMemberId"]].append(dict(edge))
        parents[edge["childMemberId"]].append(dict(edge))
    for index in (children, parents):
        for edges in index.values():
            edges.sort(key=lambda edge: edge["relationshipId"])
    return nodes, children, parents


def _graph_levels(nodes, children, parents):
    """Validate the complete operative DAG and compute its bottom-up height."""
    remaining = {member: len(children[member]) for member in nodes}
    levels = {member: 0 for member in nodes}
    ready = sorted(member for member in nodes if not remaining[member])
    visited = 0
    while ready:
        member = ready.pop()
        visited += 1
        for edge in parents[member]:
            parent = edge["parentMemberId"]
            levels[parent] = max(levels[parent], levels[member] + 1)
            remaining[parent] -= 1
            if remaining[parent] == 0:
                ready.append(parent)
    if visited != len(nodes):
        raise ValueError("MEMBER_LIST_HIERARCHY_CYCLE")
    return levels


def navigation_graph_key(node):
    """Bind each topology query to its complete relevant subgraph."""
    return json.dumps(node, sort_keys=True, separators=(",", ":"))


def _navigation_graph(graphs, node):
    if graphs is None:
        return None
    return graphs.get(navigation_graph_key(node), graphs.get(node["hierarchyId"]))


def _navigation_result(node, members, graph, *, placements=False, legacy=False):
    """The shared semantic authority for native navigation and browse projection.

    Browser paths are occurrence metadata, never financial contribution paths.
    Structural classification precedes every expression's output filters.
    """
    operation = node["operation"]
    if operation == "top":
        raise ValueError("MEMBER_LIST_SCOPE_TOP_NOT_COORDINATE")
    if graph is None:
        if node["scope"] == "dimension" and operation == "all":
            result = sorted(members)
            return ([{"memberId": member, "pathRelationshipIds": [],
                      "pathMemberIds": [member], "generation": None, "level": None}
                     for member in result] if placements else result)
        raise ValueError("MEMBER_LIST_HIERARCHY_UNAVAILABLE")
    nodes, outgoing, incoming = _named_graph_indexes(graph, set(members))
    levels = _graph_levels(nodes, outgoing, incoming)
    roots = sorted(member for member in nodes if not incoming[member])
    children = {member: sorted({edge["childMemberId"] for edge in outgoing[member]})
                for member in nodes}
    parents = {member: sorted({edge["parentMemberId"] for edge in incoming[member]})
               for member in nodes}
    anchor = node["anchor"]
    member = anchor["memberId"] if anchor else None
    if member is not None and member not in nodes:
        if legacy and operation == "is_base" and member in members:
            return []
        raise ValueError("MEMBER_LIST_HIERARCHY_MEMBER_UNAVAILABLE")
    path = anchor["pathRelationshipIds"] if anchor else None
    path_members = None
    if path is not None:
        by_id = {edge["relationshipId"]: edge for edges in outgoing.values() for edge in edges}
        path_members = []
        for key in path:
            edge = by_id.get(key)
            if edge is None or (path_members and path_members[-1] != edge["parentMemberId"]):
                raise ValueError("MEMBER_LIST_NAVIGATION_PATH_STALE")
            if not path_members:
                path_members.append(edge["parentMemberId"])
            path_members.append(edge["childMemberId"])
        if not path:
            path_members = [member]
        if path_members[-1] != member or path_members[0] not in roots:
            raise ValueError("MEMBER_LIST_NAVIGATION_PATH_STALE")

    def walk(start, index):
        pending = list(reversed(index[start])); result = []; seen = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current); result.append(current)
            pending.extend(reversed(index[current]))
        return result

    occurrences = None
    def all_occurrences():
        nonlocal occurrences
        if occurrences is not None:
            return occurrences
        occurrences = []
        pending = [(root, [], [root]) for root in reversed(roots)]
        while pending:
            current, edges, nodes_path = pending.pop()
            if len(edges) > MAX_PLACEMENT_DEPTH:
                raise ValueError("MEMBER_LIST_PLACEMENT_DEPTH_LIMIT")
            occurrences.append({"memberId": current, "pathRelationshipIds": edges,
                "pathMemberIds": nodes_path, "generation": len(edges) + 2,
                "level": levels[current]})
            if len(occurrences) > MAX_EVALUATED_PLACEMENTS:
                raise ValueError("MEMBER_LIST_EVALUATION_PLACEMENT_LIMIT_EXCEEDED")
            for edge in reversed(outgoing[current]):
                child = edge["childMemberId"]
                pending.append((child, [*edges, edge["relationshipId"]], [*nodes_path, child]))
        return occurrences

    generation = None
    if operation == "all":
        result = sorted(members if node["scope"] == "dimension" else nodes)
    elif operation == "unplaced":
        result = sorted(set(members) - nodes)
    elif operation == "roots" or operation == "children" and member is None:
        result = roots
    elif operation == "leaves" or operation == "leaf_descendants" and member is None:
        result = sorted(value for value in nodes if not children[value])
    elif operation == "descendants" and member is None:
        result = sorted(nodes)
    elif operation == "self":
        result = [member]
    elif operation == "is_base":
        result = [member] if not children[member] else []
    elif operation == "children":
        result = children[member]
    elif operation == "descendants":
        result = walk(member, children)
    elif operation == "leaf_descendants":
        result = [value for value in walk(member, children) if not children[value]]
    elif operation in {"parents", "ancestors", "siblings"}:
        if path_members is not None:
            if operation == "parents":
                result = path_members[-2:-1]
            elif operation == "ancestors":
                result = list(reversed(path_members[:-1]))
            else:
                result = [value for value in (children[path_members[-2]] if len(path_members) > 1 else roots)
                          if value != member]
        else:
            if operation == "siblings" and len(parents[member]) > 1 and not node["allParents"]:
                raise ValueError("MEMBER_LIST_NAVIGATION_PATH_REQUIRED")
            if operation == "parents":
                result = parents[member]
            elif operation == "ancestors":
                result = walk(member, parents)
            else:
                result = sorted({value for parent in parents[member] for value in children[parent]
                                 if value != member}) if parents[member] else ([] if legacy else [value for value in roots if value != member])
    elif operation == "same_level":
        result = sorted(value for value in nodes if levels[value] == levels[member] and value != member)
    elif operation == "same_generation":
        if member is None:
            result = []  # The structural top is generation 1, not a coordinate.
            generation = 1
        else:
            generations = {row["generation"] for row in all_occurrences() if row["memberId"] == member}
            if path is None and len(generations) != 1:
                raise ValueError("MEMBER_LIST_NAVIGATION_PATH_REQUIRED")
            generation = len(path) + 2 if path is not None else next(iter(generations))
            result = _unique([row["memberId"] for row in all_occurrences()
                              if row["generation"] == generation and row["memberId"] != member])
    else:
        raise ValueError("MEMBER_LIST_NAVIGATION_INVALID")
    if node["includeSelf"] and member not in result and (legacy or operation != "leaf_descendants" or not children[member]):
        result = [member, *result]
    if not placements:
        return result
    selected = set(result)
    projected = [row for row in all_occurrences() if row["memberId"] in selected
                 and (generation is None or row["generation"] == generation)]
    if path is not None and operation in {"self", "is_base", "children", "descendants", "leaf_descendants"}:
        projected = [row for row in projected if row["pathRelationshipIds"][:len(path)] == path
                     and (not path or row["pathMemberIds"][:len(path_members)] == path_members)]
    if path_members is not None and operation in {"parents", "ancestors"}:
        projected = [row for row in projected if row["pathRelationshipIds"] == path[:len(row["pathRelationshipIds"])]
                     and row["pathMemberIds"] == path_members[:len(row["pathMemberIds"])]]
    if path_members is not None and operation == "siblings":
        projected = [row for row in projected if row["pathRelationshipIds"][:-1] == path[:-1]
                     and len(row["pathRelationshipIds"]) == len(path)
                     and row["pathMemberIds"][:-1] == path_members[:-1]]
    projected.extend({"memberId": value, "pathRelationshipIds": [], "pathMemberIds": [value],
                      "generation": None, "level": None} for value in result if value not in nodes)
    return projected


def resolve_member_list_parameters(canonical, parameters, *, member_ids=None):
    """Validate parameter values before loading metadata and again against it.

    Storage may first validate scalar types to bound its member lookup. The
    evaluator supplies the loaded IDs to perform the final existence check.
    """
    declarations = {item["name"]: item for item in canonical["parameters"]}
    supplied = dict(parameters or {})
    if set(supplied) - set(declarations):
        raise ValueError("MEMBER_LIST_PARAMETER_UNDECLARED")
    for name, declaration in declarations.items():
        if declaration["required"] and name not in supplied:
            raise ValueError("MEMBER_LIST_PARAMETER_REQUIRED")
        if name in supplied:
            value = supplied[name]
            if declaration["type"] == "Member":
                if not isinstance(value, str) or (member_ids is not None and value not in member_ids):
                    raise ValueError("MEMBER_LIST_PARAMETER_MEMBER_INVALID")
            elif declaration["type"] == "Boolean":
                if type(value) is not bool:
                    raise ValueError("MEMBER_LIST_PARAMETER_VALUE_INVALID")
            elif not isinstance(value, str):
                raise ValueError("MEMBER_LIST_PARAMETER_VALUE_INVALID")

    return declarations, supplied


def evaluate_member_list(
    definition: object,
    *,
    members: Mapping[str, str],
    relationships: Sequence[tuple[str, str]],
    attributes: Mapping[str, Mapping[str, object]],
    attribute_types: Mapping[str, str],
    parameters: Mapping[str, object] | None = None,
    hierarchy_id: str = "primary",
    hierarchy_graphs: Mapping[str, Mapping] | None = None,
) -> list[str]:
    """Evaluate one canonical definition against a pinned metadata snapshot.

    Returned IDs are unique and ordered deterministically.  Set operations
    preserve the source order; hierarchy scans use member-ID order unless an
    explicit order expression says otherwise.
    """

    canonical = canonical_member_list_definition(definition)
    if not isinstance(members, Mapping) or len(members) > MAX_EVALUATED_MEMBERS:
        raise ValueError("MEMBER_LIST_EVALUATION_MEMBER_LIMIT_EXCEEDED")
    member_ids = set(members)
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in members.items()):
        raise ValueError("MEMBER_LIST_METADATA_INVALID")
    legacy_edges = set()
    for parent, child in relationships:
        if parent not in member_ids or child not in member_ids or parent == child:
            raise ValueError("MEMBER_LIST_RELATIONSHIP_INVALID")
        legacy_edges.add((parent, child))
    fallback_graph = {"hierarchyId": hierarchy_id, "members": sorted(member_ids),
        "relationships": [{"relationshipId": f"legacy-edge-{index}",
            "parentMemberId": parent, "childMemberId": child}
            for index, (parent, child) in enumerate(sorted(legacy_edges))]}
    declarations, supplied = resolve_member_list_parameters(
        canonical, parameters, member_ids=member_ids)

    def evaluate(node: Mapping[str, object]) -> list[str]:
        kind = node["kind"]
        if kind == "navigation":
            graph = _navigation_graph(hierarchy_graphs, node)
            if graph is None and hierarchy_graphs is None and node["hierarchyId"] in {hierarchy_id, canonical["dimensionId"]}:
                graph = fallback_graph
            return _navigation_result(node, members, graph)
        if kind == "explicit":
            result = list(node["memberIds"])
            if not set(result) <= member_ids:
                raise ValueError("MEMBER_LIST_MEMBER_UNAVAILABLE")
            return result
        if kind == "parameter":
            declaration = declarations[node["name"]]
            if declaration["type"] != "Member":
                raise ValueError("MEMBER_LIST_PARAMETER_NOT_MEMBER")
            return [] if node["name"] not in supplied else [supplied[node["name"]]]
        if kind in {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}:
            graph = (hierarchy_graphs.get(node["hierarchyId"]) if hierarchy_graphs is not None else
                     fallback_graph if node["hierarchyId"] in {hierarchy_id, canonical["dimensionId"]} else None)
            operation = {"base": "is_base", "leaves": "leaf_descendants"}.get(kind, kind)
            # Existing durable expression shape; execute through the native
            # traversal while retaining its historical scope and include-self.
            return _navigation_result({"operation": operation, "scope": "hierarchy",
                "anchor": {"memberId": node["memberId"], "pathRelationshipIds": None},
                "includeSelf": node["includeSelf"], "allParents": kind == "siblings"},
                members, graph, legacy=True)
        if kind == "attribute":
            attribute = node["attributeId"]
            if attribute not in attribute_types:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_UNAVAILABLE")
            return [member for member in sorted(member_ids)
                    if _matches(attributes.get(member, {}).get(attribute),
                                node["operator"], node["value"],
                                attribute_types[attribute])]
        if kind in {"union", "intersection"}:
            values = [evaluate(item) for item in node["items"]]
            if kind == "union":
                return _unique([member for value in values for member in value])
            allowed = set.intersection(*(set(value) for value in values[1:]))
            return [member for member in values[0] if member in allowed]
        if kind == "difference":
            removed = set(evaluate(node["subtract"]))
            return [member for member in evaluate(node["source"])
                    if member not in removed]
        if kind == "order":
            result = evaluate(node["source"])
            reverse = node["direction"] == "descending"
            if node["by"] == "member_id":
                return sorted(result, reverse=reverse)
            if node["by"] == "name":
                return sorted(result, key=lambda member: (members[member], member),
                              reverse=reverse)
            attribute = node["attributeId"]
            if attribute not in attribute_types:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_UNAVAILABLE")
            populated = [member for member in result
                         if attributes.get(member, {}).get(attribute) is not None]
            missing = [member for member in result if member not in set(populated)]
            populated.sort(key=lambda member: (
                _typed(attributes[member][attribute], attribute_types[attribute]),
                member), reverse=reverse)
            return populated + sorted(missing)
        raise ValueError("MEMBER_LIST_EXPRESSION_KIND_UNSUPPORTED")

    result = evaluate(canonical["expression"])
    if len(result) > MAX_EVALUATED_MEMBERS:
        raise ValueError("MEMBER_LIST_EVALUATION_RESULT_LIMIT_EXCEEDED")
    return result


def evaluate_member_list_placements(
    definition: object,
    *,
    members: Mapping[str, str],
    relationships: Sequence[Mapping[str, str]],
    attributes: Mapping[str, Mapping[str, object]],
    attribute_types: Mapping[str, str],
    parameters: Mapping[str, object] | None = None,
    hierarchy_id: str = "primary",
    hierarchy_graphs: Mapping[str, Mapping] | None = None,
    browsing: bool = False,
) -> list[dict]:
    """Evaluate the same member-list IR without erasing hierarchy placements.

    Hierarchy paths retain stable relationship IDs.  Union deduplicates only
    identical placements; intersection and difference use member membership
    while retaining the first/source expression's paths.  This makes an
    attribute filter over a hierarchy preserve every qualified placement.
    Parent, ancestor and sibling selectors remain unavailable for placement execution
    because they do not define a downward contribution path.
    """
    canonical = canonical_member_list_definition(definition)
    if not isinstance(members, Mapping) or len(members) > MAX_EVALUATED_MEMBERS:
        raise ValueError("MEMBER_LIST_EVALUATION_MEMBER_LIMIT_EXCEEDED")
    member_ids = set(members)
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in members.items()):
        raise ValueError("MEMBER_LIST_METADATA_INVALID")
    children: dict[str, list[dict]] = {member: [] for member in member_ids}
    relationship_ids: set[str] = set()
    for raw in relationships:
        if (not isinstance(raw, Mapping)
                or set(raw) != {"relationshipId", "parentMemberId", "childMemberId"}):
            raise ValueError("MEMBER_LIST_PLACEMENT_RELATIONSHIP_INVALID")
        relationship_id = raw["relationshipId"]
        parent = raw["parentMemberId"]
        child = raw["childMemberId"]
        if (not isinstance(relationship_id, str) or not relationship_id
                or relationship_id in relationship_ids or parent not in member_ids
                or child not in member_ids or parent == child):
            raise ValueError("MEMBER_LIST_PLACEMENT_RELATIONSHIP_INVALID")
        relationship_ids.add(relationship_id)
        children[parent].append(dict(raw))
    for values in children.values():
        values.sort(key=lambda item: item["relationshipId"])

    declarations, supplied = resolve_member_list_parameters(
        canonical, parameters, member_ids=member_ids)
    def direct(values: Sequence[str]) -> list[dict]:
        return [{"memberId": member, "pathRelationshipIds": []}
                for member in values]

    def unique(values: Sequence[dict]) -> list[dict]:
        seen: set[tuple[str, tuple[str, ...]]] = set()
        result: list[dict] = []
        for item in values:
            key = (item["memberId"], tuple(item["pathRelationshipIds"]))
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    def hierarchy(node: Mapping[str, object]) -> list[dict]:
        if hierarchy_graphs is not None:
            graph = hierarchy_graphs.get(node["hierarchyId"])
            if graph is None:
                raise ValueError("MEMBER_LIST_HIERARCHY_UNAVAILABLE")
            node_members, node_children, _ = _named_graph_indexes(graph, member_ids)
        else:
            if node["hierarchyId"] not in {hierarchy_id, canonical["dimensionId"]}:
                raise ValueError("MEMBER_LIST_HIERARCHY_UNAVAILABLE")
            node_members, node_children = member_ids, children
        root = node["memberId"]
        kind = node["kind"]
        if root not in node_members:
            if kind == "base" and root in member_ids:
                return []
            raise ValueError("MEMBER_LIST_HIERARCHY_MEMBER_UNAVAILABLE")
        if kind == "base":
            return [] if node_children[root] else direct([root])
        if kind not in {"children", "descendants", "leaves"}:
            raise ValueError("MEMBER_LIST_PLACEMENT_SELECTOR_UNSUPPORTED")
        result = direct([root]) if node["includeSelf"] else []
        if kind == "children":
            result.extend({"memberId": edge["childMemberId"],
                           "pathRelationshipIds": [edge["relationshipId"]]}
                          for edge in node_children[root])
            return result

        def walk(member: str, path: list[str], seen: frozenset[str]) -> None:
            if len(path) >= MAX_PLACEMENT_DEPTH:
                raise ValueError("MEMBER_LIST_PLACEMENT_DEPTH_LIMIT")
            for edge in node_children[member]:
                child = edge["childMemberId"]
                if child in seen:
                    raise ValueError("MEMBER_LIST_PLACEMENT_CYCLE")
                next_path = [*path, edge["relationshipId"]]
                if kind == "descendants" or not node_children[child]:
                    result.append({"memberId": child,
                                   "pathRelationshipIds": next_path})
                    if len(result) > MAX_EVALUATED_PLACEMENTS:
                        raise ValueError(
                            "MEMBER_LIST_EVALUATION_PLACEMENT_LIMIT_EXCEEDED")
                walk(child, next_path, seen | {child})
        walk(root, [], frozenset({root}))
        return result

    def evaluate(node: Mapping[str, object]) -> list[dict]:
        kind = node["kind"]
        if kind == "navigation":
            if not browsing:
                raise ValueError("MEMBER_LIST_PLACEMENT_SELECTOR_UNSUPPORTED")
            graph = _navigation_graph(hierarchy_graphs, node)
            if graph is None and hierarchy_graphs is None and node["hierarchyId"] in {hierarchy_id, canonical["dimensionId"]}:
                graph = {"hierarchyId": node["hierarchyId"], "members": sorted(member_ids),
                         "relationships": list(relationships)}
            return _navigation_result(node, members, graph, placements=True)
        if kind == "explicit":
            if not set(node["memberIds"]) <= member_ids:
                raise ValueError("MEMBER_LIST_MEMBER_UNAVAILABLE")
            return direct(node["memberIds"])
        if kind == "parameter":
            declaration = declarations[node["name"]]
            if declaration["type"] != "Member":
                raise ValueError("MEMBER_LIST_PARAMETER_NOT_MEMBER")
            return direct([] if node["name"] not in supplied
                          else [supplied[node["name"]]])
        if kind in {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}:
            return hierarchy(node)
        if kind == "attribute":
            attribute = node["attributeId"]
            if attribute not in attribute_types:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_UNAVAILABLE")
            return direct([member for member in sorted(member_ids)
                if _matches(attributes.get(member, {}).get(attribute),
                            node["operator"], node["value"],
                            attribute_types[attribute])])
        if kind in {"union", "intersection"}:
            values = [evaluate(item) for item in node["items"]]
            if kind == "union":
                return unique([item for value in values for item in value])
            allowed = set.intersection(*({item["memberId"] for item in value}
                                         for value in values[1:]))
            return [item for item in values[0] if item["memberId"] in allowed]
        if kind == "difference":
            removed = {item["memberId"] for item in evaluate(node["subtract"])}
            return [item for item in evaluate(node["source"])
                    if item["memberId"] not in removed]
        if kind == "order":
            result = evaluate(node["source"])
            reverse = node["direction"] == "descending"
            if node["by"] == "member_id":
                return sorted(result, key=lambda item: (
                    item["memberId"], item["pathRelationshipIds"]), reverse=reverse)
            if node["by"] == "name":
                return sorted(result, key=lambda item: (
                    members[item["memberId"]], item["memberId"],
                    item["pathRelationshipIds"]), reverse=reverse)
            attribute = node["attributeId"]
            if attribute not in attribute_types:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_UNAVAILABLE")
            populated = [item for item in result if attributes.get(
                item["memberId"], {}).get(attribute) is not None]
            missing = [item for item in result if item not in populated]
            populated.sort(key=lambda item: (
                _typed(attributes[item["memberId"]][attribute],
                       attribute_types[attribute]), item["memberId"],
                item["pathRelationshipIds"]), reverse=reverse)
            return populated + sorted(missing, key=lambda item: (
                item["memberId"], item["pathRelationshipIds"]))
        raise ValueError("MEMBER_LIST_EXPRESSION_KIND_UNSUPPORTED")

    result = evaluate(canonical["expression"])
    if len(result) > MAX_EVALUATED_PLACEMENTS:
        raise ValueError("MEMBER_LIST_EVALUATION_PLACEMENT_LIMIT_EXCEEDED")
    return result
