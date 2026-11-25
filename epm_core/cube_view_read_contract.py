"""Ephemeral analytical read intent over the unchanged canonical view owner."""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
import json

from .cube_view_contract import canonical_cube_view, cube_view_digest

FORMAT = "openepm-cube-view-read-v1"


def compile_cube_view_read(value, *, active_dimensions, expected_metadata_revision=None):
    if (not isinstance(value, dict)
            or set(value) != {"format", "view", "readPolicy", "limits"}
            or value.get("format") != FORMAT):
        raise ValueError("CUBE_VIEW_READ_INVALID")
    view = canonical_cube_view(value["view"], active_dimensions=active_dimensions,
        expected_metadata_revision=expected_metadata_revision)
    policy = value["readPolicy"]
    if (not isinstance(policy, dict) or set(policy) != {"semantics"}
            or policy["semantics"] not in {"stored", "own"}):
        raise ValueError("CUBE_VIEW_READ_POLICY_UNSUPPORTED_USE_RESOLVED_BINDING")
    if policy["semantics"] == "own" and view["dataSource"]["kind"] != "raw":
        raise ValueError("CUBE_VIEW_READ_SOURCE_POLICY_MISMATCH")
    limits = value["limits"]
    if (not isinstance(limits, dict)
            or set(limits) != {"maxRows", "maxSourceRows", "timeoutMs"}
            or type(limits["maxRows"]) is not int
            or not 1 <= limits["maxRows"] <= 500
            or type(limits["maxSourceRows"]) is not int
            or not 1 <= limits["maxSourceRows"] <= 100_000
            or type(limits["timeoutMs"]) is not int
            or not 100 <= limits["timeoutMs"] <= 30_000
            or view["pageSize"] > limits["maxRows"]):
        raise ValueError("CUBE_VIEW_READ_LIMITS_INVALID")
    return {"format": FORMAT, "view": view,
            "readPolicy": dict(policy), "limits": dict(limits)}


def cube_view_read_digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _raw_value(row):
    if row.get("origin") == "input":
        return {"present": row["present"], "value": row["value"],
                "unit": row["resultUnit"], "origin": "input",
                "currentness": row["currentness"], "resultStateToken": None}
    kind = row.get("kind")
    if kind == "numeric":
        value, unit = row["amount"], "amount"
    elif kind == "text":
        value, unit = row["text"], "text"
    elif kind == "missing":
        value, unit = None, None
    else:
        raise ValueError("CUBE_VIEW_RAW_VALUE_INVALID")
    return {"present": kind != "missing", "value": value, "unit": unit,
            "origin": "input", "currentness": "current",
            "resultStateToken": None}


def _calculated_value(row, token):
    if isinstance(row.get("value"), dict):
        value = row["value"].get("decimal")
        unit = row.get("resultUnit")
    else:
        value = row.get("amount")
        unit = row.get("outputUnit", "amount")
    if not isinstance(value, str):
        raise ValueError("CUBE_VIEW_CALCULATED_VALUE_INVALID")
    return {"present": True, "value": value, "unit": unit,
            "origin": "materialized", "currentness": "current",
            "resultStateToken": token}


def assemble_cube_view_rows(plan, *, raw_rows, calculated_rows, result_token):
    """Keep selected layers separate, including missing, zero and typed units.

    The input adapters have already applied coordinate authorization. This
    function never fills a missing calculation with raw data or invents a sum.
    """
    view = plan["view"]
    dimensions = [item["dimensionId"] for item in view["selection"]["dimensions"]]
    kind = view["dataSource"]["kind"]
    layers = ["raw"] if kind == "raw" else ["calculated"] if kind == "calculated" else ["raw", "calculated"]
    by_coordinate = {}
    for layer, rows, convert in (
        ("raw", raw_rows, _raw_value),
        ("calculated", calculated_rows,
         lambda row: _calculated_value(row, result_token)),
    ):
        if layer not in layers:
            continue
        for row in rows:
            members = row["members"]
            if set(members) != set(dimensions):
                raise ValueError("CUBE_VIEW_READ_GRAIN_INVALID")
            key = tuple(members[dimension] for dimension in dimensions)
            output = by_coordinate.setdefault(key, {"members": dict(members),
                "values": {name: [] for name in layers}})
            value = convert(row)
            if any(prior["unit"] == value["unit"] for prior in output["values"][layer]):
                raise ValueError("CUBE_VIEW_READ_VALUE_COLLISION")
            output["values"][layer].append(value)
    if len(by_coordinate) > plan["limits"]["maxRows"]:
        raise ValueError("RESOURCE_LIMIT")
    result = []
    for key in sorted(by_coordinate):
        row = by_coordinate[key]
        for layer in layers:
            if not row["values"][layer]:
                row["values"][layer] = [{"present": False, "value": None,
                    "unit": None, "origin": "input" if layer == "raw" else "materialized",
                    "currentness": "current", "resultStateToken":
                        None if layer == "raw" else result_token}]
        values = [item for layer in layers for item in row["values"][layer]]
        present = [item for item in values if item["present"]]
        if view["suppression"]["missing"] and not present:
            continue
        if (view["suppression"]["zero"] and present
                and all(item["unit"] != "text" and Decimal(item["value"]) == 0
                        for item in present)):
            continue
        result.append(row)
    return result


def view_read_identity(plan):
    return {"viewDigest": cube_view_digest(plan["view"]),
            "requestDigest": cube_view_read_digest(plan),
            "dataSource": plan["view"]["dataSource"],
            "readPolicy": plan["readPolicy"]}
