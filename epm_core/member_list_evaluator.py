"""Bounded deterministic evaluation for canonical member-list expressions.

The evaluator is metadata-only.  It never reads facts, writes business data or
accepts SQL.  PostgreSQL adapters supply one authorized, revision-pinned
metadata snapshot and the fixed core evaluates the already-canonical IR.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Mapping, Sequence

from .member_list_contract import canonical_member_list_version


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


def evaluate_member_list(
    definition: object,
    *,
    members: Mapping[str, str],
    relationships: Sequence[tuple[str, str]],
    attributes: Mapping[str, Mapping[str, object]],
    attribute_types: Mapping[str, str],
    parameters: Mapping[str, object] | None = None,
    hierarchy_id: str = "primary",
) -> list[str]:
    """Evaluate one canonical definition against a pinned metadata snapshot.

    Returned IDs are unique and ordered deterministically.  Set operations
    preserve the source order; hierarchy scans use member-ID order unless an
    explicit order expression says otherwise.
    """

    canonical = canonical_member_list_version(definition)
    if not isinstance(members, Mapping) or len(members) > MAX_EVALUATED_MEMBERS:
        raise ValueError("MEMBER_LIST_EVALUATION_MEMBER_LIMIT_EXCEEDED")
    member_ids = set(members)
    if any(not isinstance(key, str) or not isinstance(value, str)
           for key, value in members.items()):
        raise ValueError("MEMBER_LIST_METADATA_INVALID")
    children: dict[str, list[str]] = {member: [] for member in member_ids}
    parents: dict[str, list[str]] = {member: [] for member in member_ids}
    for parent, child in relationships:
        if parent not in member_ids or child not in member_ids or parent == child:
            raise ValueError("MEMBER_LIST_RELATIONSHIP_INVALID")
        children[parent].append(child)
        parents[child].append(parent)
    for index in (children, parents):
        for values in index.values():
            values[:] = sorted(set(values))

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
                if not isinstance(value, str) or value not in member_ids:
                    raise ValueError("MEMBER_LIST_PARAMETER_MEMBER_INVALID")
            elif declaration["type"] == "Boolean":
                if type(value) is not bool:
                    raise ValueError("MEMBER_LIST_PARAMETER_VALUE_INVALID")
            elif not isinstance(value, str):
                raise ValueError("MEMBER_LIST_PARAMETER_VALUE_INVALID")

    def walk(start: str, index: Mapping[str, Sequence[str]]) -> list[str]:
        pending = list(reversed(index[start]))
        result: list[str] = []
        seen: set[str] = set()
        while pending:
            member = pending.pop()
            if member in seen:
                continue
            seen.add(member)
            result.append(member)
            pending.extend(reversed(index[member]))
        return result

    def evaluate(node: Mapping[str, object]) -> list[str]:
        kind = node["kind"]
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
        if kind in {"children", "descendants", "ancestors", "siblings", "leaves"}:
            if node["hierarchyId"] not in {hierarchy_id, canonical["dimensionId"]}:
                raise ValueError("MEMBER_LIST_HIERARCHY_UNAVAILABLE")
            member = node["memberId"]
            if member not in member_ids:
                raise ValueError("MEMBER_LIST_MEMBER_UNAVAILABLE")
            if kind == "children":
                result = list(children[member])
            elif kind == "descendants":
                result = walk(member, children)
            elif kind == "ancestors":
                result = walk(member, parents)
            elif kind == "siblings":
                result = sorted({sibling for parent in parents[member]
                                 for sibling in children[parent] if sibling != member})
            else:
                result = [candidate for candidate in walk(member, children)
                          if not children[candidate]]
            if node["includeSelf"] and member not in result:
                result.insert(0, member)
            return result
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
) -> list[dict]:
    """Evaluate the same member-list IR without erasing hierarchy placements.

    Hierarchy paths retain stable relationship IDs.  Union deduplicates only
    identical placements; intersection and difference use member membership
    while retaining the first/source expression's paths.  This makes an
    attribute filter over a hierarchy preserve every qualified placement.
    Ancestor and sibling selectors remain unavailable for placement execution
    because they do not define a downward contribution path.
    """
    canonical = canonical_member_list_version(definition)
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
                if not isinstance(value, str) or value not in member_ids:
                    raise ValueError("MEMBER_LIST_PARAMETER_MEMBER_INVALID")
            elif declaration["type"] == "Boolean":
                if type(value) is not bool:
                    raise ValueError("MEMBER_LIST_PARAMETER_VALUE_INVALID")
            elif not isinstance(value, str):
                raise ValueError("MEMBER_LIST_PARAMETER_VALUE_INVALID")

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
        if node["hierarchyId"] not in {hierarchy_id, canonical["dimensionId"]}:
            raise ValueError("MEMBER_LIST_HIERARCHY_UNAVAILABLE")
        root = node["memberId"]
        if root not in member_ids:
            raise ValueError("MEMBER_LIST_MEMBER_UNAVAILABLE")
        kind = node["kind"]
        if kind not in {"children", "descendants", "leaves"}:
            raise ValueError("MEMBER_LIST_PLACEMENT_SELECTOR_UNSUPPORTED")
        result = direct([root]) if node["includeSelf"] else []
        if kind == "children":
            result.extend({"memberId": edge["childMemberId"],
                           "pathRelationshipIds": [edge["relationshipId"]]}
                          for edge in children[root])
            return result

        def walk(member: str, path: list[str], seen: frozenset[str]) -> None:
            if len(path) >= MAX_PLACEMENT_DEPTH:
                raise ValueError("MEMBER_LIST_PLACEMENT_DEPTH_LIMIT")
            for edge in children[member]:
                child = edge["childMemberId"]
                if child in seen:
                    raise ValueError("MEMBER_LIST_PLACEMENT_CYCLE")
                next_path = [*path, edge["relationshipId"]]
                if kind == "descendants" or not children[child]:
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
        if kind in {"children", "descendants", "ancestors", "siblings", "leaves"}:
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
