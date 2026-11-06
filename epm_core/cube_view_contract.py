"""Canonical presentation-neutral multidimensional view contract."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Iterable

from .selection_contract import canonical_selection


FORMAT = "openepm-cube-view-v1"
MAX_DIMENSIONS = 128
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RESULT_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(code)
    return value


def _axis(value: object, name: str, *, required: bool = False) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_DIMENSIONS or required and not value:
        raise ValueError(f"CUBE_VIEW_{name.upper()}_INVALID")
    result = [_id(item, f"CUBE_VIEW_{name.upper()}_INVALID") for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"CUBE_VIEW_{name.upper()}_DUPLICATE")
    return result


def canonical_cube_view(
    value: object, *, active_dimensions: Iterable[str] | None = None
) -> dict[str, Any]:
    required = {
        "format", "viewId", "version", "name", "selection", "layout",
        "dataSource", "suppression", "pageSize",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("CUBE_VIEW_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("CUBE_VIEW_FORMAT_UNSUPPORTED")
    view_id = _id(value["viewId"], "CUBE_VIEW_ID_INVALID")
    if type(value["version"]) is not int or value["version"] < 1:
        raise ValueError("CUBE_VIEW_VERSION_INVALID")
    if not isinstance(value["name"], str) or not 1 <= len(value["name"].strip()) <= 200:
        raise ValueError("CUBE_VIEW_NAME_INVALID")
    selection = canonical_selection(value["selection"], active_dimensions=active_dimensions)
    selected_dimensions = {item["dimensionId"] for item in selection["dimensions"]}

    layout = value["layout"]
    if not isinstance(layout, dict) or set(layout) != {"pages", "rows", "columns", "filters"}:
        raise ValueError("CUBE_VIEW_LAYOUT_INVALID")
    pages = _axis(layout["pages"], "pages")
    rows = _axis(layout["rows"], "rows", required=True)
    columns = _axis(layout["columns"], "columns", required=True)
    filters = _axis(layout["filters"], "filters")
    placed = pages + rows + columns + filters
    if len(placed) != len(set(placed)):
        raise ValueError("CUBE_VIEW_LAYOUT_DIMENSION_DUPLICATE")
    if set(placed) != selected_dimensions:
        raise ValueError("CUBE_VIEW_LAYOUT_GRAIN_INCOMPLETE")

    source = value["dataSource"]
    if not isinstance(source, dict) or set(source) != {"kind", "resultKey"}:
        raise ValueError("CUBE_VIEW_DATA_SOURCE_INVALID")
    if source["kind"] not in {"raw", "calculated", "combined"}:
        raise ValueError("CUBE_VIEW_DATA_SOURCE_INVALID")
    result_key = source["resultKey"]
    if source["kind"] == "raw":
        if result_key is not None:
            raise ValueError("CUBE_VIEW_RESULT_KEY_INVALID")
    elif not isinstance(result_key, str) or not _RESULT_KEY.fullmatch(result_key):
        raise ValueError("CUBE_VIEW_RESULT_KEY_INVALID")

    suppression = value["suppression"]
    if (
        not isinstance(suppression, dict)
        or set(suppression) != {"missing", "zero"}
        or any(not isinstance(suppression[key], bool) for key in suppression)
    ):
        raise ValueError("CUBE_VIEW_SUPPRESSION_INVALID")
    if type(value["pageSize"]) is not int or not 1 <= value["pageSize"] <= 500:
        raise ValueError("CUBE_VIEW_PAGE_SIZE_INVALID")
    return {
        "format": FORMAT,
        "viewId": view_id,
        "version": value["version"],
        "name": value["name"].strip(),
        "selection": selection,
        "layout": {"pages": pages, "rows": rows, "columns": columns, "filters": filters},
        "dataSource": {"kind": source["kind"], "resultKey": result_key},
        "suppression": {"missing": suppression["missing"], "zero": suppression["zero"]},
        "pageSize": value["pageSize"],
    }


def cube_view_digest(value: object, *, active_dimensions: Iterable[str] | None = None) -> str:
    canonical = canonical_cube_view(value, active_dimensions=active_dimensions)
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return sha256(encoded).hexdigest()
