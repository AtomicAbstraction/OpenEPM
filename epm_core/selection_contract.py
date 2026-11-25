"""Canonical complete-grain cube selection contract."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Iterable


FORMAT = "openepm-cube-selection-v1"
SELECTION_METADATA_STALE = "CUBE_SELECTION_METADATA_STALE"
INLINE_EXPRESSION_FORMAT = "openepm-member-list-expression-v1"
MAX_DIMENSIONS = 128
MAX_EXPLICIT_MEMBERS = 10_000
MAX_PARAMETERS = 100
_MAX_ATTRIBUTE_VALUES = 100
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_HIERARCHY_OPERATORS = frozenset(("children", "parents", "descendants", "ancestors",
                                  "siblings", "leaves", "base"))
_ATTRIBUTE_OPERATORS = frozenset(("eq", "ne", "lt", "lte", "gt", "gte", "contains",
                                  "starts_with", "in", "exists"))


def selection_identifier_schema() -> dict:
    return {"type": "string", "pattern": _ID.pattern.removesuffix("$") + r"(?![\s\S])"}


def selection_parameters_schema() -> dict:
    return {"type": "object", "maxProperties": MAX_PARAMETERS,
        "propertyNames": selection_identifier_schema(),
        "additionalProperties": {"type": ["string", "integer", "boolean", "null"]}}


def structural_schema_definitions() -> dict:
    """Describe the canonical selector variants and reuse the native inline expression schema."""
    from .member_list_contract import structural_schema_definitions as member_list_schemas
    from .postgres_numeric_catalog import obj

    identifier = selection_identifier_schema()
    scalar = {"type": ["string", "integer", "boolean", "null"]}
    hierarchy = obj({"kind": {"const": "hierarchy"},
        "operator": {"enum": sorted(_HIERARCHY_OPERATORS)}, "hierarchyId": identifier,
        "memberId": identifier, "includeSelf": {"type": "boolean"}})
    hierarchy["allOf"] = [{
        "if": {"properties": {"operator": {"const": "base"}}},
        "then": {"properties": {"includeSelf": {"const": False}}}}]
    attribute = obj({"kind": {"const": "attribute"}, "attributeId": identifier,
        "operator": {"enum": sorted(_ATTRIBUTE_OPERATORS)},
        "value": {"anyOf": [scalar, {"type": "array", "minItems": 1,
            "maxItems": _MAX_ATTRIBUTE_VALUES, "items": scalar}]}})
    attribute["allOf"] = [{
        "if": {"properties": {"operator": {"const": "in"}}},
        "then": {"properties": {"value": {"type": "array"}}},
        "else": {"properties": {"value": scalar}}}]
    selector = {"oneOf": [
        obj({"kind": {"const": "member"}, "memberId": identifier}),
        obj({"kind": {"const": "members"}, "memberIds": {"type": "array",
            "minItems": 1, "maxItems": MAX_EXPLICIT_MEMBERS, "uniqueItems": True, "items": identifier}}),
        hierarchy,
        attribute,
        obj({"kind": {"const": "member_list"}, "listId": identifier,
            "parameters": selection_parameters_schema()}),
        obj({"kind": {"const": "inline_expression"}, "expressionFormat": {"const": INLINE_EXPRESSION_FORMAT},
            "expression": {"$ref": "#/$defs/memberListExpression"}}),
    ]}
    selector_ref = {"$ref": "#/$defs/cubeSelector"}
    selection = obj({"format": {"const": FORMAT}, "metadataRevision": {"type": "integer", "minimum": 1},
        "dimensions": {"type": "array", "minItems": 1, "maxItems": MAX_DIMENSIONS,
            "items": obj({"dimensionId": identifier, "include": selector_ref,
                "exclude": {"anyOf": [selector_ref, {"type": "null"}]}})}})
    return {"cubeSelection": selection, "cubeSelector": selector,
        "memberListExpression": member_list_schemas(parameters=False)["memberListExpression"]}


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(code)
    return value


def _exact(value: object, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(code)
    return value


def _parameter_value(value: object) -> object:
    if isinstance(value, float) or value is not None and not isinstance(value, (str, int, bool)):
        raise ValueError("CUBE_SELECTION_PARAMETER_VALUE_INVALID")
    return value


def _selector(value: object, *, allow_member_list: bool = True) -> dict[str, Any]:
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise ValueError("CUBE_SELECTION_SELECTOR_INVALID")
    kind = value["kind"]
    if kind == "member":
        item = _exact(value, {"kind", "memberId"}, "CUBE_SELECTION_MEMBER_INVALID")
        return {"kind": kind, "memberId": _id(item["memberId"], "CUBE_SELECTION_MEMBER_INVALID")}
    if kind == "members":
        item = _exact(value, {"kind", "memberIds"}, "CUBE_SELECTION_MEMBERS_INVALID")
        members = item["memberIds"]
        if not isinstance(members, list) or not 1 <= len(members) <= MAX_EXPLICIT_MEMBERS:
            raise ValueError("CUBE_SELECTION_MEMBERS_INVALID")
        result = [_id(member, "CUBE_SELECTION_MEMBERS_INVALID") for member in members]
        if len(result) != len(set(result)):
            raise ValueError("CUBE_SELECTION_MEMBERS_DUPLICATE")
        return {"kind": kind, "memberIds": result}
    if kind == "hierarchy":
        item = _exact(
            value,
            {"kind", "operator", "hierarchyId", "memberId", "includeSelf"},
            "CUBE_SELECTION_HIERARCHY_INVALID",
        )
        if (item["operator"] not in _HIERARCHY_OPERATORS
                or not isinstance(item["includeSelf"], bool)
                or item["operator"] == "base" and item["includeSelf"]):
            raise ValueError("CUBE_SELECTION_HIERARCHY_INVALID")
        return {
            "kind": kind,
            "operator": item["operator"],
            "hierarchyId": _id(item["hierarchyId"], "CUBE_SELECTION_HIERARCHY_INVALID"),
            "memberId": _id(item["memberId"], "CUBE_SELECTION_HIERARCHY_INVALID"),
            "includeSelf": item["includeSelf"],
        }
    if kind == "attribute":
        item = _exact(
            value,
            {"kind", "attributeId", "operator", "value"},
            "CUBE_SELECTION_ATTRIBUTE_INVALID",
        )
        if item["operator"] not in _ATTRIBUTE_OPERATORS:
            raise ValueError("CUBE_SELECTION_ATTRIBUTE_INVALID")
        raw = item["value"]
        if item["operator"] == "in":
            if not isinstance(raw, list) or not 1 <= len(raw) <= _MAX_ATTRIBUTE_VALUES:
                raise ValueError("CUBE_SELECTION_ATTRIBUTE_INVALID")
            normalized: object = [_parameter_value(entry) for entry in raw]
        else:
            normalized = _parameter_value(raw)
        return {
            "kind": kind,
            "attributeId": _id(item["attributeId"], "CUBE_SELECTION_ATTRIBUTE_INVALID"),
            "operator": item["operator"],
            "value": normalized,
        }
    if kind == "member_list" and allow_member_list:
        item = _exact(
            value,
            {"kind", "listId", "parameters"},
            "CUBE_SELECTION_MEMBER_LIST_INVALID",
        )
        parameters = item["parameters"]
        if not isinstance(parameters, dict) or len(parameters) > MAX_PARAMETERS:
            raise ValueError("CUBE_SELECTION_MEMBER_LIST_INVALID")
        normalized_parameters = {
            _id(name, "CUBE_SELECTION_PARAMETER_NAME_INVALID"): _parameter_value(parameter)
            for name, parameter in parameters.items()
        }
        return {
            "kind": kind,
            "listId": _id(item["listId"], "CUBE_SELECTION_MEMBER_LIST_INVALID"),
            "parameters": dict(sorted(normalized_parameters.items())),
        }
    if kind == "inline_expression":
        item = _exact(
            value,
            {"kind", "expressionFormat", "expression"},
            "CUBE_SELECTION_INLINE_EXPRESSION_INVALID",
        )
        if item["expressionFormat"] != INLINE_EXPRESSION_FORMAT:
            raise ValueError("CUBE_SELECTION_INLINE_EXPRESSION_FORMAT_UNSUPPORTED")
        from .member_list_contract import canonical_member_list_expression
        return {"kind": kind,
                "expressionFormat": INLINE_EXPRESSION_FORMAT,
                "expression": canonical_member_list_expression(
                    item["expression"])}
    raise ValueError("CUBE_SELECTION_SELECTOR_KIND_UNSUPPORTED")


def canonical_selection(
    value: object, *, active_dimensions: Iterable[str] | None = None,
    expected_metadata_revision: int | None = None,
) -> dict[str, Any]:
    item = _exact(
        value,
        {"format", "metadataRevision", "dimensions"},
        "CUBE_SELECTION_INVALID",
    )
    if item["format"] != FORMAT:
        raise ValueError("CUBE_SELECTION_FORMAT_UNSUPPORTED")
    if type(item["metadataRevision"]) is not int or item["metadataRevision"] < 1:
        raise ValueError("CUBE_SELECTION_METADATA_REVISION_INVALID")
    if expected_metadata_revision is not None:
        if type(expected_metadata_revision) is not int or expected_metadata_revision < 1:
            raise ValueError("CUBE_SELECTION_METADATA_REVISION_INVALID")
        if item["metadataRevision"] != expected_metadata_revision:
            raise ValueError(SELECTION_METADATA_STALE)
    dimensions = item["dimensions"]
    if not isinstance(dimensions, list) or not 1 <= len(dimensions) <= MAX_DIMENSIONS:
        raise ValueError("CUBE_SELECTION_DIMENSIONS_INVALID")
    normalized = []
    seen: set[str] = set()
    for raw in dimensions:
        dimension = _exact(
            raw,
            {"dimensionId", "include", "exclude"},
            "CUBE_SELECTION_DIMENSION_INVALID",
        )
        dimension_id = _id(dimension["dimensionId"], "CUBE_SELECTION_DIMENSION_INVALID")
        if dimension_id in seen:
            raise ValueError("CUBE_SELECTION_DIMENSION_DUPLICATE")
        seen.add(dimension_id)
        include = _selector(dimension["include"])
        exclude = None if dimension["exclude"] is None else _selector(dimension["exclude"])
        normalized.append(
            {"dimensionId": dimension_id, "include": include, "exclude": exclude}
        )
    if active_dimensions is not None:
        expected = list(active_dimensions)
        if any(not isinstance(axis, str) for axis in expected) or len(expected) != len(set(expected)):
            raise ValueError("CUBE_SELECTION_ACTIVE_DIMENSIONS_INVALID")
        if seen != set(expected):
            raise ValueError("CUBE_SELECTION_GRAIN_INCOMPLETE")
    normalized.sort(key=lambda entry: entry["dimensionId"])
    return {
        "format": FORMAT,
        "metadataRevision": item["metadataRevision"],
        "dimensions": normalized,
    }


def selection_digest(value: object, *, active_dimensions: Iterable[str] | None = None) -> str:
    canonical = canonical_selection(value, active_dimensions=active_dimensions)
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return sha256(encoded).hexdigest()
