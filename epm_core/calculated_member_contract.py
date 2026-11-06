"""Generic calculated-member definition independent of business domain."""

from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any, Iterable

from .postgres_expression import _expression
from .selection_contract import canonical_selection


FORMAT = "openepm-calculated-member-v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RESULT_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(code)
    return value


def canonical_calculated_member(
    value: object, *, active_dimensions: Iterable[str]
) -> dict[str, Any]:
    required = {
        "format", "definitionId", "version", "name", "target", "evaluation",
        "sourceSelection", "expression", "dependencies", "resultUnit",
        "resultKey", "maxSourceCells", "maxOutputCells",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("CALCULATED_MEMBER_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("CALCULATED_MEMBER_FORMAT_UNSUPPORTED")
    definition_id = _id(value["definitionId"], "CALCULATED_MEMBER_ID_INVALID")
    if type(value["version"]) is not int or value["version"] < 1:
        raise ValueError("CALCULATED_MEMBER_VERSION_INVALID")
    if not isinstance(value["name"], str) or not 1 <= len(value["name"].strip()) <= 200:
        raise ValueError("CALCULATED_MEMBER_NAME_INVALID")
    target = value["target"]
    if not isinstance(target, dict) or set(target) != {"dimensionId", "memberId"}:
        raise ValueError("CALCULATED_MEMBER_TARGET_INVALID")
    target = {
        "dimensionId": _id(target["dimensionId"], "CALCULATED_MEMBER_TARGET_INVALID"),
        "memberId": _id(target["memberId"], "CALCULATED_MEMBER_TARGET_INVALID"),
    }
    dimensions = list(active_dimensions)
    if target["dimensionId"] not in dimensions:
        raise ValueError("CALCULATED_MEMBER_TARGET_INVALID")
    selection = canonical_selection(value["sourceSelection"], active_dimensions=dimensions)
    try:
        expression, expression_type = _expression(value["expression"])
    except ValueError as error:
        raise ValueError("CALCULATED_MEMBER_EXPRESSION_INVALID") from error
    if expression_type not in {"amount", "ratio"}:
        raise ValueError("CALCULATED_MEMBER_RESULT_TYPE_INVALID")
    if value["resultUnit"] != expression_type:
        raise ValueError("CALCULATED_MEMBER_RESULT_TYPE_INVALID")
    dependencies = value["dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) > 100:
        raise ValueError("CALCULATED_MEMBER_DEPENDENCIES_INVALID")
    normalized_dependencies = []
    seen = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict) or set(dependency) != {"definitionId", "version"}:
            raise ValueError("CALCULATED_MEMBER_DEPENDENCIES_INVALID")
        dependency_id = _id(
            dependency["definitionId"], "CALCULATED_MEMBER_DEPENDENCIES_INVALID"
        )
        if type(dependency["version"]) is not int or dependency["version"] < 1:
            raise ValueError("CALCULATED_MEMBER_DEPENDENCIES_INVALID")
        key = (dependency_id, dependency["version"])
        if key in seen or dependency_id == definition_id:
            raise ValueError("CALCULATED_MEMBER_DEPENDENCIES_INVALID")
        seen.add(key)
        normalized_dependencies.append({"definitionId": key[0], "version": key[1]})
    normalized_dependencies.sort(key=lambda item: (item["definitionId"], item["version"]))
    if value["evaluation"] not in {"dynamic", "materialized"}:
        raise ValueError("CALCULATED_MEMBER_EVALUATION_INVALID")
    result_key = value["resultKey"]
    if value["evaluation"] == "dynamic":
        if result_key is not None:
            raise ValueError("CALCULATED_MEMBER_RESULT_KEY_INVALID")
    elif not isinstance(result_key, str) or not _RESULT_KEY.fullmatch(result_key):
        raise ValueError("CALCULATED_MEMBER_RESULT_KEY_INVALID")
    for key, maximum in (("maxSourceCells", 1_000_000), ("maxOutputCells", 100_000)):
        if type(value[key]) is not int or not 1 <= value[key] <= maximum:
            raise ValueError("CALCULATED_MEMBER_BUDGET_INVALID")
    return {
        "format": FORMAT,
        "definitionId": definition_id,
        "version": value["version"],
        "name": value["name"].strip(),
        "target": target,
        "evaluation": value["evaluation"],
        "sourceSelection": selection,
        "expression": expression,
        "dependencies": normalized_dependencies,
        "resultUnit": expression_type,
        "resultKey": result_key,
        "maxSourceCells": value["maxSourceCells"],
        "maxOutputCells": value["maxOutputCells"],
    }


def calculated_member_digest(value: object, *, active_dimensions: Iterable[str]) -> str:
    canonical = canonical_calculated_member(value, active_dimensions=active_dimensions)
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def validate_calculated_member_graph(
    definitions: Iterable[dict[str, Any]], *, max_depth: int = 16,
    max_total_source_cells: int = 1_000_000,
) -> tuple[tuple[str, int], ...]:
    """Return dependency-first order after exact-version and cost validation."""
    items = list(definitions)
    if not 1 <= len(items) <= 1_000:
        raise ValueError("CALCULATED_MEMBER_GRAPH_SIZE_INVALID")
    by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("CALCULATED_MEMBER_GRAPH_INVALID")
        key = (item.get("definitionId"), item.get("version"))
        if (
            not isinstance(key[0], str)
            or type(key[1]) is not int
            or key in by_key
            or not isinstance(item.get("dependencies"), list)
        ):
            raise ValueError("CALCULATED_MEMBER_GRAPH_INVALID")
        by_key[key] = item
    visiting: set[tuple[str, int]] = set()
    visited: set[tuple[str, int]] = set()
    order: list[tuple[str, int]] = []
    total = 0

    def visit(key: tuple[str, int], depth: int) -> None:
        nonlocal total
        if key in visited:
            return
        if key in visiting:
            raise ValueError("CALCULATED_MEMBER_DEPENDENCY_CYCLE")
        if depth > max_depth:
            raise ValueError("CALCULATED_MEMBER_DEPENDENCY_DEPTH_LIMIT")
        item = by_key.get(key)
        if item is None:
            raise ValueError("CALCULATED_MEMBER_DEPENDENCY_UNAVAILABLE")
        visiting.add(key)
        for dependency in item["dependencies"]:
            visit((dependency["definitionId"], dependency["version"]), depth + 1)
        visiting.remove(key)
        visited.add(key)
        total += item["maxSourceCells"]
        if total > max_total_source_cells:
            raise ValueError("CALCULATED_MEMBER_GRAPH_COST_LIMIT")
        order.append(key)

    for key in sorted(by_key):
        visit(key, 1)
    return tuple(order)
