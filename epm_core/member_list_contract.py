"""Canonical, domain-neutral member-list expression contract.

Clients compose this IR.  The fixed core validates and canonicalizes it before
the one current definition can be persisted, evaluated or referenced.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Any


FORMAT = "openepm-member-list-v1"
MAX_DEPTH = 16
MAX_NODES = 1_000
MAX_MEMBER_REFERENCES = 10_000
MAX_SET_ITEMS = 64

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_PARAMETER_TYPES = frozenset({"Member", "String", "Decimal", "Boolean", "Date"})
_HIERARCHY_KINDS = frozenset(
    {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}
)
_ATTRIBUTE_OPERATORS = frozenset(
    {"eq", "ne", "lt", "lte", "gt", "gte", "contains", "starts_with", "in", "exists"}
)


@dataclass
class _Budget:
    nodes: int = 0
    member_references: int = 0


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"MEMBER_LIST_{label}_INVALID")
    return value


def _exact_keys(value: object, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(code)
    return value


def _typed_scalar(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    # Binary floating point is never part of the authoritative IR. Decimal and
    # date values travel as validated strings and are typed by their attribute
    # or parameter definition during admission.
    raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_INVALID")


def _expression(
    value: object,
    *,
    parameters: frozenset[str],
    budget: _Budget,
    depth: int,
) -> dict[str, Any]:
    if depth > MAX_DEPTH:
        raise ValueError("MEMBER_LIST_EXPRESSION_DEPTH_EXCEEDED")
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise ValueError("MEMBER_LIST_EXPRESSION_INVALID")
    budget.nodes += 1
    if budget.nodes > MAX_NODES:
        raise ValueError("MEMBER_LIST_EXPRESSION_NODE_LIMIT_EXCEEDED")
    kind = value["kind"]

    if kind == "explicit":
        item = _exact_keys(value, {"kind", "memberIds"}, "MEMBER_LIST_EXPLICIT_INVALID")
        members = item["memberIds"]
        if (
            not isinstance(members, list)
            or not members
            or len(members) > MAX_MEMBER_REFERENCES
        ):
            raise ValueError("MEMBER_LIST_EXPLICIT_INVALID")
        normalized = [_identifier(member, "MEMBER_ID") for member in members]
        if len(normalized) != len(set(normalized)):
            raise ValueError("MEMBER_LIST_EXPLICIT_DUPLICATE")
        budget.member_references += len(normalized)
        if budget.member_references > MAX_MEMBER_REFERENCES:
            raise ValueError("MEMBER_LIST_MEMBER_REFERENCE_LIMIT_EXCEEDED")
        return {"kind": kind, "memberIds": normalized}

    if kind in _HIERARCHY_KINDS:
        item = _exact_keys(
            value,
            {"kind", "hierarchyId", "memberId", "includeSelf"},
            "MEMBER_LIST_HIERARCHY_SELECTOR_INVALID",
        )
        if (not isinstance(item["includeSelf"], bool)
                or kind == "base" and item["includeSelf"]):
            raise ValueError("MEMBER_LIST_HIERARCHY_SELECTOR_INVALID")
        budget.member_references += 1
        if budget.member_references > MAX_MEMBER_REFERENCES:
            raise ValueError("MEMBER_LIST_MEMBER_REFERENCE_LIMIT_EXCEEDED")
        return {
            "kind": kind,
            "hierarchyId": _identifier(item["hierarchyId"], "HIERARCHY_ID"),
            "memberId": _identifier(item["memberId"], "MEMBER_ID"),
            "includeSelf": item["includeSelf"],
        }

    if kind == "attribute":
        item = _exact_keys(
            value,
            {"kind", "attributeId", "operator", "value"},
            "MEMBER_LIST_ATTRIBUTE_SELECTOR_INVALID",
        )
        operator = item["operator"]
        if operator not in _ATTRIBUTE_OPERATORS:
            raise ValueError("MEMBER_LIST_ATTRIBUTE_OPERATOR_INVALID")
        raw = item["value"]
        if operator == "exists":
            if not isinstance(raw, bool):
                raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_INVALID")
            normalized_value: object = raw
        elif operator == "in":
            if not isinstance(raw, list) or not raw or len(raw) > 100:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_VALUE_INVALID")
            normalized_value = [_typed_scalar(entry) for entry in raw]
        else:
            normalized_value = _typed_scalar(raw)
        return {
            "kind": kind,
            "attributeId": _identifier(item["attributeId"], "ATTRIBUTE_ID"),
            "operator": operator,
            "value": normalized_value,
        }

    if kind == "parameter":
        item = _exact_keys(value, {"kind", "name"}, "MEMBER_LIST_PARAMETER_INVALID")
        name = _identifier(item["name"], "PARAMETER_NAME")
        if name not in parameters:
            raise ValueError("MEMBER_LIST_PARAMETER_UNDECLARED")
        return {"kind": kind, "name": name}

    if kind in {"union", "intersection"}:
        item = _exact_keys(value, {"kind", "items"}, "MEMBER_LIST_SET_OPERATION_INVALID")
        values = item["items"]
        if not isinstance(values, list) or not 2 <= len(values) <= MAX_SET_ITEMS:
            raise ValueError("MEMBER_LIST_SET_OPERATION_INVALID")
        return {
            "kind": kind,
            "items": [
                _expression(entry, parameters=parameters, budget=budget, depth=depth + 1)
                for entry in values
            ],
        }

    if kind == "difference":
        item = _exact_keys(
            value,
            {"kind", "source", "subtract"},
            "MEMBER_LIST_DIFFERENCE_INVALID",
        )
        return {
            "kind": kind,
            "source": _expression(
                item["source"], parameters=parameters, budget=budget, depth=depth + 1
            ),
            "subtract": _expression(
                item["subtract"], parameters=parameters, budget=budget, depth=depth + 1
            ),
        }

    if kind == "order":
        item = _exact_keys(
            value,
            {"kind", "source", "by", "direction", "attributeId"},
            "MEMBER_LIST_ORDER_INVALID",
        )
        if item["by"] not in {"member_id", "name", "attribute"}:
            raise ValueError("MEMBER_LIST_ORDER_INVALID")
        if item["direction"] not in {"ascending", "descending"}:
            raise ValueError("MEMBER_LIST_ORDER_INVALID")
        attribute = item["attributeId"]
        if (item["by"] == "attribute") != (attribute is not None):
            raise ValueError("MEMBER_LIST_ORDER_INVALID")
        return {
            "kind": kind,
            "source": _expression(
                item["source"], parameters=parameters, budget=budget, depth=depth + 1
            ),
            "by": item["by"],
            "direction": item["direction"],
            "attributeId": _identifier(attribute, "ATTRIBUTE_ID")
            if attribute is not None
            else None,
        }

    raise ValueError("MEMBER_LIST_EXPRESSION_KIND_UNSUPPORTED")


def canonical_member_list_definition(value: object) -> dict[str, Any]:
    fields = {"format", "listId", "dimensionId", "name",
              "parameters", "expression"}
    if (not isinstance(value, dict)
            or set(value) not in (fields, fields | {"limits"})):
        raise ValueError("MEMBER_LIST_DEFINITION_INVALID")
    item = value
    if item["format"] != FORMAT:
        raise ValueError("MEMBER_LIST_FORMAT_UNSUPPORTED")
    if not isinstance(item["name"], str) or not 1 <= len(item["name"].strip()) <= 200:
        raise ValueError("MEMBER_LIST_NAME_INVALID")
    raw_parameters = item["parameters"]
    if not isinstance(raw_parameters, list) or len(raw_parameters) > 100:
        raise ValueError("MEMBER_LIST_PARAMETERS_INVALID")
    parameters = []
    names: set[str] = set()
    for raw in raw_parameters:
        parameter = _exact_keys(
            raw, {"name", "type", "required"}, "MEMBER_LIST_PARAMETER_DEFINITION_INVALID"
        )
        name = _identifier(parameter["name"], "PARAMETER_NAME")
        if name in names or parameter["type"] not in _PARAMETER_TYPES or not isinstance(
            parameter["required"], bool
        ):
            raise ValueError("MEMBER_LIST_PARAMETER_DEFINITION_INVALID")
        names.add(name)
        parameters.append(
            {"name": name, "type": parameter["type"], "required": parameter["required"]}
        )
    budget = _Budget()
    expression = _expression(
        item["expression"], parameters=frozenset(names), budget=budget, depth=1
    )
    result = {
        "format": FORMAT,
        "listId": _identifier(item["listId"], "ID"),
        "dimensionId": _identifier(item["dimensionId"], "DIMENSION_ID"),
        "name": item["name"].strip(),
        "parameters": parameters,
        "expression": expression,
        "limits": {
            "nodeCount": budget.nodes,
            "memberReferenceCount": budget.member_references,
        },
    }
    if "limits" in item and item["limits"] != result["limits"]:
        raise ValueError("MEMBER_LIST_LIMITS_INVALID")
    return result


def iter_member_list_nodes(node):
    """Visit a canonical native expression through its admitted child slots."""
    yield node
    for child in node.get("items", []):
        yield from iter_member_list_nodes(child)
    for key in ("source", "subtract"):
        if key in node:
            yield from iter_member_list_nodes(node[key])


def canonical_member_list_expression(value: object) -> dict[str, Any]:
    """Canonicalize one parameter-free reusable member-set expression.

    Inline cube selectors deliberately reuse the exact member-list AST and
    budgets without creating or persisting a hidden list definition. Named
    parameterized lists remain explicit current-definition references.
    """
    budget = _Budget()
    return _expression(
        value, parameters=frozenset(), budget=budget, depth=1)


def member_list_digest(value: object) -> str:
    canonical = canonical_member_list_definition(value)
    payload = {key: value for key, value in canonical.items() if key != "limits"}
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return sha256(encoded).hexdigest()
