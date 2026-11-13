"""Pinned interpretation of one current sparse applicability relation.

The relation stores generic typed business tuples.  This contract gives those
columns rule-local meaning without copying rows into authored operations.
Every source anchor is a complete cube coordinate; target and operand columns
are explicit overrides which inherit all unspecified anchor dimensions.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Iterable


FORMAT = "openepm-applicability-domain-v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_TOKEN = re.compile(r"^[0-9a-f]{64}$")
_VALUE_TYPES = frozenset(("Amount", "Ratio", "String", "Boolean"))
_NUMERIC_KINDS = frozenset(("Amount", "Ratio"))


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _member_bindings(value: object, *, code: str,
                     allowed_dimensions: set[str], complete: bool) -> list[dict]:
    if not isinstance(value, list) or (complete and not value):
        raise ValueError(code)
    result = []
    dimensions = set()
    for item in value:
        if (not isinstance(item, dict)
                or set(item) != {"dimensionId", "columnId"}):
            raise ValueError(code)
        dimension = _identifier(item["dimensionId"], code)
        column = _identifier(item["columnId"], code)
        if dimension not in allowed_dimensions or dimension in dimensions:
            raise ValueError(code)
        dimensions.add(dimension)
        result.append({"dimensionId": dimension, "columnId": column})
    if complete and dimensions != allowed_dimensions:
        raise ValueError("APPLICABILITY_DOMAIN_ANCHOR_INCOMPLETE")
    return sorted(result, key=lambda item: item["dimensionId"])


def canonical_applicability_domain(value: object, *,
                                   active_dimensions: Iterable[str],
                                   relation_columns: Iterable[dict]) -> dict:
    dimensions = tuple(active_dimensions)
    if (not dimensions or len(dimensions) != len(set(dimensions))
            or any(not isinstance(item, str) or _ID.fullmatch(item) is None
                   for item in dimensions)):
        raise ValueError("APPLICABILITY_DOMAIN_ACTIVE_DIMENSIONS_INVALID")
    columns = tuple(relation_columns)
    if (not columns or any(not isinstance(item, dict)
            or set(item) != {"columnId", "type", "dimensionId"}
            for item in columns)):
        raise ValueError("APPLICABILITY_DOMAIN_RELATION_COLUMNS_INVALID")
    column_types = {item["columnId"]: item["type"] for item in columns}
    column_dimensions = {item["columnId"]: item["dimensionId"]
                         for item in columns}
    if len(column_types) != len(columns):
        raise ValueError("APPLICABILITY_DOMAIN_RELATION_COLUMNS_INVALID")
    required = {"format", "relationId", "relationStateToken",
        "relationDigest", "anchorMemberColumns", "targetMemberColumns",
        "operands", "values", "missingPolicy", "maxRows"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("APPLICABILITY_DOMAIN_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("APPLICABILITY_DOMAIN_FORMAT_UNSUPPORTED")
    relation_id = _identifier(value["relationId"],
                              "APPLICABILITY_DOMAIN_RELATION_ID_INVALID")
    if (not isinstance(value["relationStateToken"], str)
            or _TOKEN.fullmatch(value["relationStateToken"]) is None
            or not isinstance(value["relationDigest"], str)
            or _TOKEN.fullmatch(value["relationDigest"]) is None):
        raise ValueError("APPLICABILITY_DOMAIN_RELATION_PIN_INVALID")
    active = set(dimensions)
    anchors = _member_bindings(value["anchorMemberColumns"],
        code="APPLICABILITY_DOMAIN_ANCHOR_INVALID",
        allowed_dimensions=active, complete=True)
    targets = _member_bindings(value["targetMemberColumns"],
        code="APPLICABILITY_DOMAIN_TARGET_INVALID",
        allowed_dimensions=active, complete=False)

    def require_member_columns(bindings: list[dict], code: str) -> None:
        for binding in bindings:
            column_id = binding["columnId"]
            if (column_types.get(column_id) != "Member"
                    or column_dimensions.get(column_id) !=
                       binding["dimensionId"]):
                raise ValueError(code)

    require_member_columns(anchors, "APPLICABILITY_DOMAIN_ANCHOR_INVALID")
    require_member_columns(targets, "APPLICABILITY_DOMAIN_TARGET_INVALID")
    operands = value["operands"]
    if not isinstance(operands, list) or len(operands) > 32:
        raise ValueError("APPLICABILITY_DOMAIN_OPERANDS_INVALID")
    normalized_operands = []
    operand_ids = set()
    for operand in operands:
        if (not isinstance(operand, dict) or set(operand) != {
                "operandId", "memberColumns", "numericKind", "missing"}):
            raise ValueError("APPLICABILITY_DOMAIN_OPERAND_INVALID")
        operand_id = _identifier(operand["operandId"],
                                 "APPLICABILITY_DOMAIN_OPERAND_INVALID")
        if operand_id in operand_ids or operand["numericKind"] not in _NUMERIC_KINDS:
            raise ValueError("APPLICABILITY_DOMAIN_OPERAND_INVALID")
        if operand["missing"] not in ("error", "skip"):
            raise ValueError("APPLICABILITY_DOMAIN_OPERAND_INVALID")
        bindings = _member_bindings(operand["memberColumns"],
            code="APPLICABILITY_DOMAIN_OPERAND_INVALID",
            allowed_dimensions=active, complete=False)
        require_member_columns(bindings, "APPLICABILITY_DOMAIN_OPERAND_INVALID")
        operand_ids.add(operand_id)
        normalized_operands.append({"operandId": operand_id,
            "memberColumns": bindings, "numericKind": operand["numericKind"],
            "missing": operand["missing"]})
    normalized_operands.sort(key=lambda item: item["operandId"])
    values = value["values"]
    if not isinstance(values, list) or len(values) > 32:
        raise ValueError("APPLICABILITY_DOMAIN_VALUES_INVALID")
    normalized_values = []
    value_ids = set()
    for item in values:
        if not isinstance(item, dict) or set(item) != {
                "valueId", "columnId", "type"}:
            raise ValueError("APPLICABILITY_DOMAIN_VALUE_INVALID")
        value_id = _identifier(item["valueId"],
                               "APPLICABILITY_DOMAIN_VALUE_INVALID")
        column_id = _identifier(item["columnId"],
                                "APPLICABILITY_DOMAIN_VALUE_INVALID")
        if (value_id in value_ids or item["type"] not in _VALUE_TYPES
                or column_types.get(column_id) != item["type"]
                or column_dimensions.get(column_id) is not None):
            raise ValueError("APPLICABILITY_DOMAIN_VALUE_INVALID")
        value_ids.add(value_id)
        normalized_values.append({"valueId": value_id,
            "columnId": column_id, "type": item["type"]})
    normalized_values.sort(key=lambda item: item["valueId"])
    if value["missingPolicy"] not in ("exclude_unmatched", "error_unmatched"):
        raise ValueError("APPLICABILITY_DOMAIN_MISSING_POLICY_INVALID")
    if type(value["maxRows"]) is not int or not 1 <= value["maxRows"] <= 100_000:
        raise ValueError("APPLICABILITY_DOMAIN_ROW_BUDGET_INVALID")
    return {"format": FORMAT, "relationId": relation_id,
        "relationStateToken": value["relationStateToken"],
        "relationDigest": value["relationDigest"],
        "anchorMemberColumns": anchors, "targetMemberColumns": targets,
        "operands": normalized_operands, "values": normalized_values,
        "missingPolicy": value["missingPolicy"], "maxRows": value["maxRows"]}


def normalize_applicability_domain(value: object) -> dict:
    """Normalize the authored profile before current relation resolution.

    Column declarations are inferred only to validate internal shape. Runtime
    resolution must call ``canonical_applicability_domain`` with the actual
    current relation columns before any SQL is built or executed.
    """
    if not isinstance(value,dict):
        raise ValueError("APPLICABILITY_DOMAIN_INVALID")
    anchors=value.get("anchorMemberColumns")
    if not isinstance(anchors,list):
        raise ValueError("APPLICABILITY_DOMAIN_ANCHOR_INVALID")
    dimensions=[];specifications={}
    def member_columns(items):
        if not isinstance(items,list):
            raise ValueError("APPLICABILITY_DOMAIN_INVALID")
        for item in items:
            if not isinstance(item,dict):
                raise ValueError("APPLICABILITY_DOMAIN_INVALID")
            column=item.get("columnId");dimension=item.get("dimensionId")
            prior=specifications.get(column)
            specification=("Member",dimension)
            if prior is not None and prior!=specification:
                raise ValueError("APPLICABILITY_DOMAIN_COLUMN_ROLE_CONFLICT")
            specifications[column]=specification
    for item in anchors:
        if isinstance(item,dict):dimensions.append(item.get("dimensionId"))
    member_columns(anchors)
    member_columns(value.get("targetMemberColumns"))
    operands=value.get("operands")
    if not isinstance(operands,list):
        raise ValueError("APPLICABILITY_DOMAIN_OPERANDS_INVALID")
    for operand in operands:
        if not isinstance(operand,dict):
            raise ValueError("APPLICABILITY_DOMAIN_OPERAND_INVALID")
        member_columns(operand.get("memberColumns"))
    values=value.get("values")
    if not isinstance(values,list):
        raise ValueError("APPLICABILITY_DOMAIN_VALUES_INVALID")
    for item in values:
        if not isinstance(item,dict):
            raise ValueError("APPLICABILITY_DOMAIN_VALUE_INVALID")
        column=item.get("columnId");specification=(item.get("type"),None)
        prior=specifications.get(column)
        if prior is not None and prior!=specification:
            raise ValueError("APPLICABILITY_DOMAIN_COLUMN_ROLE_CONFLICT")
        specifications[column]=specification
    columns=[{"columnId":column,"type":kind,"dimensionId":dimension}
             for column,(kind,dimension) in specifications.items()]
    return canonical_applicability_domain(value,
        active_dimensions=tuple(dimensions),relation_columns=columns)


def applicability_domain_digest(value: object, *,
                                active_dimensions: Iterable[str],
                                relation_columns: Iterable[dict]) -> str:
    canonical = canonical_applicability_domain(value,
        active_dimensions=tuple(active_dimensions),
        relation_columns=tuple(relation_columns))
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(encoded).hexdigest()
