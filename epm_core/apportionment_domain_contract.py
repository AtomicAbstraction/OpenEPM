"""Pinned interpretation of grouped apportionment business rows.

The underlying applicability relation is current application metadata.  Rows
describe allocation groups/components/recipients, never client work batches.
"""
from __future__ import annotations

import re
from typing import Iterable

from .applicability_domain_contract import canonical_applicability_domain


FORMAT = "openepm-apportionment-domain-v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")
MAX_ROWS = 100_000
MAX_GROUPS = 10_000


def _identifier(value: object, code: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def canonical_apportionment_domain(value: object, *,
                                   active_dimensions: Iterable[str],
                                   relation_columns: Iterable[dict]) -> dict:
    required = {"format", "relationId", "relationStateToken",
        "relationDigest", "anchorMemberColumns", "targetMemberColumns",
        "operands", "groupColumnId", "componentColumnId",
        "formulaColumnId", "weightColumnId", "quantumColumnId",
        "roundingColumnId", "tieDimensions", "maxRows", "maxGroups"}
    if type(value) is not dict or set(value) != required:
        raise ValueError("APPORTIONMENT_DOMAIN_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("APPORTIONMENT_DOMAIN_FORMAT_UNSUPPORTED")
    dimensions = tuple(active_dimensions)
    columns = tuple(relation_columns)
    # Reuse the authoritative full-anchor, target and operand validation by
    # projecting the shared portion into an applicability domain.
    shared = canonical_applicability_domain({
        "format": "openepm-applicability-domain-v1",
        "relationId": value["relationId"],
        "relationStateToken": value["relationStateToken"],
        "relationDigest": value["relationDigest"],
        "anchorMemberColumns": value["anchorMemberColumns"],
        "targetMemberColumns": value["targetMemberColumns"],
        "operands": value["operands"], "values": [],
        "missingPolicy": "error_unmatched", "maxRows": value["maxRows"]},
        active_dimensions=dimensions, relation_columns=columns)
    by_id = {item["columnId"]: item for item in columns}
    scalar = {}
    expected = {"groupColumnId": "String", "componentColumnId": "String",
        "formulaColumnId": "String", "weightColumnId": "Ratio",
        "quantumColumnId": "Amount", "roundingColumnId": "String"}
    for field, kind in expected.items():
        column = _identifier(value[field], "APPORTIONMENT_DOMAIN_COLUMN_INVALID")
        descriptor = by_id.get(column)
        if (descriptor is None or descriptor.get("type") != kind
                or descriptor.get("dimensionId") is not None):
            raise ValueError("APPORTIONMENT_DOMAIN_COLUMN_INVALID")
        scalar[field] = column
    if len(set(scalar.values())) != len(scalar):
        raise ValueError("APPORTIONMENT_DOMAIN_COLUMN_INVALID")
    ties = value["tieDimensions"]
    if (type(ties) is not list or not 1 <= len(ties) <= len(dimensions)
            or len(ties) != len(set(ties))
            or any(type(item) is not str or item not in dimensions
                   for item in ties)):
        raise ValueError("APPORTIONMENT_DOMAIN_TIE_DIMENSIONS_INVALID")
    if (type(value["maxRows"]) is not int
            or not 1 <= value["maxRows"] <= MAX_ROWS
            or type(value["maxGroups"]) is not int
            or not 1 <= value["maxGroups"] <= min(value["maxRows"], MAX_GROUPS)):
        raise ValueError("APPORTIONMENT_DOMAIN_BOUND_INVALID")
    if (not isinstance(value["relationStateToken"], str)
            or _TOKEN.fullmatch(value["relationStateToken"]) is None
            or not isinstance(value["relationDigest"], str)
            or _TOKEN.fullmatch(value["relationDigest"]) is None):
        raise ValueError("APPORTIONMENT_DOMAIN_RELATION_PIN_INVALID")
    return {"format": FORMAT,
        "relationId": shared["relationId"],
        "relationStateToken": shared["relationStateToken"],
        "relationDigest": shared["relationDigest"],
        "anchorMemberColumns": shared["anchorMemberColumns"],
        "targetMemberColumns": shared["targetMemberColumns"],
        "operands": shared["operands"], **scalar,
        "tieDimensions": sorted(ties), "maxRows": value["maxRows"],
        "maxGroups": value["maxGroups"]}


def normalize_apportionment_domain(value: object) -> dict:
    """Structural public-boundary check; storage resolution validates columns."""
    if type(value) is not dict:
        raise ValueError("APPORTIONMENT_DOMAIN_INVALID")
    anchors = value.get("anchorMemberColumns")
    targets = value.get("targetMemberColumns")
    operands = value.get("operands")
    if not all(type(item) is list for item in (anchors, targets, operands)):
        raise ValueError("APPORTIONMENT_DOMAIN_INVALID")
    dimensions = sorted({item.get("dimensionId") for item in anchors
        if type(item) is dict and type(item.get("dimensionId")) is str})
    member_columns = [item for item in anchors + targets + [binding
        for operand in operands if type(operand) is dict
        for binding in operand.get("memberColumns", [])]
        if type(item) is dict]
    scalar_types = {value.get("groupColumnId"): "String",
        value.get("componentColumnId"): "String",
        value.get("formulaColumnId"): "String",
        value.get("weightColumnId"): "Ratio",
        value.get("quantumColumnId"): "Amount",
        value.get("roundingColumnId"): "String"}
    columns = {item.get("columnId"): {"columnId": item.get("columnId"),
        "type": "Member", "dimensionId": item.get("dimensionId")}
        for item in member_columns}
    for column, kind in scalar_types.items():
        columns[column] = {"columnId": column, "type": kind,
                           "dimensionId": None}
    return canonical_apportionment_domain(value,
        active_dimensions=dimensions, relation_columns=columns.values())
