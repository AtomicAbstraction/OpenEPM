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
NAVIGATION_OPERATIONS = (
    "top", "all", "roots", "unplaced", "leaves", "self", "is_base", "children",
    "descendants", "leaf_descendants", "parents", "ancestors", "siblings",
    "same_level", "same_generation",
)
NAVIGATION_FIELDS = {"kind", "operation", "scope", "hierarchyId", "anchor",
                     "includeSelf", "allParents"}
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

    if kind == "navigation":
        item = _exact_keys(value, NAVIGATION_FIELDS, "MEMBER_LIST_NAVIGATION_INVALID")
        operation, scope = item["operation"], item["scope"]
        anchor, hierarchy = item["anchor"], item["hierarchyId"]
        if (operation not in NAVIGATION_OPERATIONS or scope not in {"dimension", "hierarchy"}
                or type(item["includeSelf"]) is not bool
                or type(item["allParents"]) is not bool):
            raise ValueError("MEMBER_LIST_NAVIGATION_INVALID")
        if hierarchy is not None:
            hierarchy = _identifier(hierarchy, "HIERARCHY_ID")
        if hierarchy is None and (scope == "hierarchy" or operation not in {"top", "all"}):
            raise ValueError("MEMBER_LIST_NAVIGATION_HIERARCHY_REQUIRED")
        if scope == "dimension" and operation not in {"top", "all", "leaves", "unplaced"}:
            raise ValueError("MEMBER_LIST_NAVIGATION_SCOPE_INVALID")
        if anchor is not None:
            anchor = _exact_keys(anchor, {"memberId", "pathRelationshipIds"},
                                 "MEMBER_LIST_NAVIGATION_ANCHOR_INVALID")
            path = anchor["pathRelationshipIds"]
            if path is not None:
                if type(path) is not list or len(path) > 32:
                    raise ValueError("MEMBER_LIST_NAVIGATION_PATH_INVALID")
                path = [_identifier(edge, "RELATIONSHIP_ID") for edge in path]
                if len(path) != len(set(path)):
                    raise ValueError("MEMBER_LIST_NAVIGATION_PATH_INVALID")
            anchor = {"memberId": _identifier(anchor["memberId"], "MEMBER_ID"),
                      "pathRelationshipIds": path}
            budget.member_references += 1
            if budget.member_references > MAX_MEMBER_REFERENCES:
                raise ValueError("MEMBER_LIST_MEMBER_REFERENCE_LIMIT_EXCEEDED")
        if (anchor is not None and operation in {"top", "all", "roots", "unplaced", "leaves"}
                or anchor is None and operation in {"self", "is_base", "parents", "ancestors", "siblings", "same_level"}
                or scope == "dimension" and anchor is not None):
            raise ValueError("MEMBER_LIST_NAVIGATION_ANCHOR_INVALID")
        if item["includeSelf"] and (anchor is None or operation not in {
                "children", "descendants", "leaf_descendants", "parents", "ancestors",
                "siblings", "same_level", "same_generation"}):
            raise ValueError("MEMBER_LIST_NAVIGATION_INCLUDE_SELF_INVALID")
        if item["allParents"] and (operation not in {"parents", "ancestors", "siblings"}
                or anchor is not None and anchor["pathRelationshipIds"] is not None):
            raise ValueError("MEMBER_LIST_NAVIGATION_ALL_PARENTS_INVALID")
        return {"kind": kind, "operation": operation, "scope": scope,
                "hierarchyId": hierarchy, "anchor": anchor,
                "includeSelf": item["includeSelf"], "allParents": item["allParents"]}

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


def structural_schema_definitions(*, parameters=True):
    """Structural projection of this module's canonical IR, not an evaluator."""
    from .postgres_numeric_catalog import obj
    identifier = {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'}
    scalar = {'type': ['string', 'boolean', 'integer', 'null']}
    node = {'$ref': '#/$defs/memberListExpression'}
    path = {'anyOf': [{'type': 'array', 'maxItems': 32, 'uniqueItems': True,
        'items': identifier}, {'type': 'null'}]}
    anchor = {'anyOf': [obj({'memberId': identifier, 'pathRelationshipIds': path}),
        {'type': 'null'}]}
    navigation = obj({'kind': {'const': 'navigation'},
        'operation': {'enum': list(NAVIGATION_OPERATIONS)},
        'scope': {'enum': ['dimension', 'hierarchy']},
        'hierarchyId': {'anyOf': [identifier, {'type': 'null'}]},
        'anchor': anchor, 'includeSelf': {'type': 'boolean'},
        'allParents': {'type': 'boolean'}})
    navigation['allOf'] = [
        {'if': {'properties': {'scope': {'const': 'dimension'}}},
         'then': {'properties': {'operation': {'enum': ['top', 'all', 'leaves', 'unplaced']}, 'anchor': {'type': 'null'}}}},
        {'if': {'properties': {'hierarchyId': {'type': 'null'}}},
         'then': {'properties': {'scope': {'const': 'dimension'}, 'operation': {'enum': ['top', 'all']}}}},
        {'if': {'properties': {'operation': {'enum': ['top', 'all', 'roots', 'unplaced', 'leaves']}}},
         'then': {'properties': {'anchor': {'type': 'null'}}}},
        {'if': {'properties': {'operation': {'enum': ['self', 'is_base', 'parents', 'ancestors', 'siblings', 'same_level']}}},
         'then': {'properties': {'anchor': {'type': 'object'}}}},
        {'if': {'properties': {'includeSelf': {'const': True}}},
         'then': {'properties': {'anchor': {'type': 'object'},
             'operation': {'enum': ['children', 'descendants', 'leaf_descendants', 'parents', 'ancestors', 'siblings', 'same_level', 'same_generation']}}}},
        {'if': {'properties': {'allParents': {'const': True}}},
         'then': {'properties': {'operation': {'enum': ['parents', 'ancestors', 'siblings']},
             'anchor': {'anyOf': [{'type': 'null'}, {'type': 'object',
                 'properties': {'pathRelationshipIds': {'type': 'null'}}}]}}}}]
    hierarchy = obj({'kind': {'enum': sorted(_HIERARCHY_KINDS)},
        'hierarchyId': identifier, 'memberId': identifier, 'includeSelf': {'type': 'boolean'}})
    hierarchy['allOf'] = [{'if': {'properties': {'kind': {'const': 'base'}}},
        'then': {'properties': {'includeSelf': {'const': False}}}}]
    attribute = obj({'kind': {'const': 'attribute'}, 'attributeId': identifier,
        'operator': {'enum': sorted(_ATTRIBUTE_OPERATORS)},
        'value': {'anyOf': [scalar, {'type': 'array', 'minItems': 1, 'maxItems': 100, 'items': scalar}]}})
    attribute['allOf'] = [
        {'if': {'properties': {'operator': {'const': 'exists'}}}, 'then': {'properties': {'value': {'type': 'boolean'}}}},
        {'if': {'properties': {'operator': {'const': 'in'}}}, 'then': {'properties': {'value': {'type': 'array'}}}},
        {'if': {'properties': {'operator': {'not': {'enum': ['exists', 'in']}}}}, 'then': {'properties': {'value': scalar}}}]
    order = obj({'kind': {'const': 'order'}, 'source': node,
        'by': {'enum': ['member_id', 'name', 'attribute']},
        'direction': {'enum': ['ascending', 'descending']},
        'attributeId': {'anyOf': [identifier, {'type': 'null'}]}})
    order['allOf'] = [{'if': {'properties': {'by': {'const': 'attribute'}}},
        'then': {'properties': {'attributeId': identifier}},
        'else': {'properties': {'attributeId': {'type': 'null'}}}}]
    variants = [navigation, hierarchy, attribute, order,
        obj({'kind': {'const': 'explicit'}, 'memberIds': {'type': 'array',
            'minItems': 1, 'maxItems': MAX_MEMBER_REFERENCES, 'uniqueItems': True, 'items': identifier}}),
        obj({'kind': {'enum': ['union', 'intersection']}, 'items': {'type': 'array',
            'minItems': 2, 'maxItems': MAX_SET_ITEMS, 'items': node}}),
        obj({'kind': {'const': 'difference'}, 'source': node, 'subtract': node})]
    if parameters:
        variants.append(obj({'kind': {'const': 'parameter'}, 'name': identifier}))
    definition = obj({'format': {'const': FORMAT}, 'listId': identifier,
        'dimensionId': identifier, 'name': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'parameters': {'type': 'array', 'maxItems': 100, 'items': obj({
            'name': identifier, 'type': {'enum': sorted(_PARAMETER_TYPES)}, 'required': {'type': 'boolean'}})},
        'expression': node, 'limits': obj({
            'nodeCount': {'type': 'integer', 'minimum': 1, 'maximum': MAX_NODES},
            'memberReferenceCount': {'type': 'integer', 'minimum': 0, 'maximum': MAX_MEMBER_REFERENCES}})})
    return {'memberListExpression': {'oneOf': variants}, 'memberListDefinition': definition}
