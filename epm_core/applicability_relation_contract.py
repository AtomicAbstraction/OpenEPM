"""Canonical current sparse applicability and mapping relation.

The relation stores business tuples, not execution partitions.  A calculation
can join one current relation set-wise; row count, transport pages and worker
chunks never become rule identities.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re


FORMAT = "openepm-applicability-relation-v1"
MAX_COLUMNS = 128
MAX_ROWS = 100_000
MAX_BYTES = 16 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_TYPES = frozenset(("Member", "Amount", "Ratio", "String", "Boolean"))


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _decimal(value: object, *, ratio: bool) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("APPLICABILITY_RELATION_VALUE_INVALID")
    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError) as error:
        raise ValueError("APPLICABILITY_RELATION_VALUE_INVALID") from error
    if not number.is_finite():
        raise ValueError("APPLICABILITY_RELATION_VALUE_INVALID")
    _, digits, exponent = number.as_tuple()
    integer_digits = max(0, len(digits) + exponent)
    scale = max(0, -exponent)
    if ((ratio and (integer_digits > 8 or scale > 12))
            or (not ratio and (integer_digits > 20 or scale > 8))):
        raise ValueError("APPLICABILITY_RELATION_VALUE_INVALID")
    return format(number, "f")


def canonical_applicability_relation(value: object) -> dict:
    required = {"format", "relationId", "name", "columns", "rows"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("APPLICABILITY_RELATION_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("APPLICABILITY_RELATION_FORMAT_UNSUPPORTED")
    name = value["name"]
    if (not isinstance(name, str) or name != name.strip()
            or not 1 <= len(name) <= 200):
        raise ValueError("APPLICABILITY_RELATION_NAME_INVALID")
    raw_columns = value["columns"]
    if not isinstance(raw_columns, list) or not 1 <= len(raw_columns) <= MAX_COLUMNS:
        raise ValueError("APPLICABILITY_RELATION_COLUMNS_INVALID")
    columns = []
    seen = set()
    for raw in raw_columns:
        if (not isinstance(raw, dict)
                or set(raw) != {"columnId", "type", "dimensionId"}
                or raw.get("type") not in _TYPES):
            raise ValueError("APPLICABILITY_RELATION_COLUMN_INVALID")
        column_id = _identifier(raw["columnId"],
                                "APPLICABILITY_RELATION_COLUMN_INVALID")
        if column_id in seen:
            raise ValueError("APPLICABILITY_RELATION_COLUMN_DUPLICATE")
        seen.add(column_id)
        dimension = raw["dimensionId"]
        if ((raw["type"] == "Member") != (dimension is not None)
                or dimension is not None and (not isinstance(dimension, str)
                    or _ID.fullmatch(dimension) is None)):
            raise ValueError("APPLICABILITY_RELATION_COLUMN_INVALID")
        columns.append({"columnId": column_id, "type": raw["type"],
                        "dimensionId": dimension})
    columns.sort(key=lambda item: item["columnId"])
    specifications = {item["columnId"]: item for item in columns}
    raw_rows = value["rows"]
    if not isinstance(raw_rows, list) or not 1 <= len(raw_rows) <= MAX_ROWS:
        raise ValueError("APPLICABILITY_RELATION_ROWS_INVALID")
    rows = []
    row_ids = set()
    tuples = set()
    for raw in raw_rows:
        if not isinstance(raw, dict) or set(raw) != {"rowId", "values"}:
            raise ValueError("APPLICABILITY_RELATION_ROW_INVALID")
        row_id = _identifier(raw["rowId"], "APPLICABILITY_RELATION_ROW_INVALID")
        if row_id in row_ids:
            raise ValueError("APPLICABILITY_RELATION_ROW_DUPLICATE")
        values = raw["values"]
        if not isinstance(values, dict) or set(values) != set(specifications):
            raise ValueError("APPLICABILITY_RELATION_ROW_GRAIN_INVALID")
        normalized = {}
        for column_id, specification in specifications.items():
            item = values[column_id]
            kind = specification["type"]
            if kind == "Member":
                normalized[column_id] = _identifier(
                    item, "APPLICABILITY_RELATION_VALUE_INVALID")
            elif kind in ("Amount", "Ratio"):
                normalized[column_id] = _decimal(item, ratio=kind == "Ratio")
            elif kind == "Boolean":
                if type(item) is not bool:
                    raise ValueError("APPLICABILITY_RELATION_VALUE_INVALID")
                normalized[column_id] = item
            else:
                if (not isinstance(item, str) or "\x00" in item
                        or len(item) > 32_768):
                    raise ValueError("APPLICABILITY_RELATION_VALUE_INVALID")
                normalized[column_id] = item
        identity = tuple((key, json.dumps(normalized[key], sort_keys=True))
                         for key in sorted(normalized))
        if identity in tuples:
            raise ValueError("APPLICABILITY_RELATION_TUPLE_DUPLICATE")
        tuples.add(identity); row_ids.add(row_id)
        rows.append({"rowId": row_id,
                     "values": {key: normalized[key] for key in sorted(normalized)}})
    rows.sort(key=lambda item: item["rowId"])
    result = {"format": FORMAT,
        "relationId": _identifier(value["relationId"],
                                  "APPLICABILITY_RELATION_ID_INVALID"),
        "name": name, "columns": columns, "rows": rows}
    if len(json.dumps(result, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")) > MAX_BYTES:
        raise ValueError("APPLICABILITY_RELATION_SIZE_EXCEEDED")
    return result


def applicability_relation_digest(value: object) -> str:
    canonical = canonical_applicability_relation(value)
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(encoded).hexdigest()
