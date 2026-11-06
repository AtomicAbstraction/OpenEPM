"""Role-neutral aggregate intent over a complete multidimensional selection."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Iterable

from .selection_contract import canonical_selection


FORMAT = "openepm-cube-aggregate-v1"
MEASURES = frozenset({"sum", "count_present"})


def _axes(value: object, code: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or not (0 if empty else 1) <= len(value) <= 128:
        raise ValueError(code)
    if any(not isinstance(item, str) or not item for item in value) or len(value) != len(set(value)):
        raise ValueError(code)
    return list(value)


@dataclass(frozen=True, slots=True)
class GenericAggregatePlan:
    normalized: dict[str, Any]

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.normalized, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        return sha256(encoded).hexdigest()


def compile_generic_aggregate(
    value: object, *, active_dimensions: Iterable[str]
) -> GenericAggregatePlan:
    required = {
        "format", "selection", "groupBy", "reduceDimensions", "measures",
        "membershipSemantics", "memberOperatorPolicy", "missing",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("GENERIC_AGGREGATE_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("GENERIC_AGGREGATE_FORMAT_UNSUPPORTED")
    dimensions = list(active_dimensions)
    selection = canonical_selection(value["selection"], active_dimensions=dimensions)
    grouped = _axes(value["groupBy"], "GENERIC_AGGREGATE_GRAIN_INVALID", empty=True)
    reduced = _axes(
        value["reduceDimensions"], "GENERIC_AGGREGATE_GRAIN_INVALID", empty=True
    )
    if set(grouped) & set(reduced) or not set(grouped + reduced) <= set(dimensions):
        raise ValueError("GENERIC_AGGREGATE_GRAIN_INVALID")
    measures = value["measures"]
    if (
        not isinstance(measures, list)
        or not 1 <= len(measures) <= len(MEASURES)
        or any(item not in MEASURES for item in measures)
        or len(measures) != len(set(measures))
    ):
        raise ValueError("GENERIC_AGGREGATE_MEASURES_INVALID")
    if value["membershipSemantics"] not in {"unique_member", "placement"}:
        raise ValueError("GENERIC_AGGREGATE_MEMBERSHIP_INVALID")
    if value["membershipSemantics"] == "placement" and not reduced:
        raise ValueError("GENERIC_AGGREGATE_PLACEMENT_REDUCTION_REQUIRED")
    if value["memberOperatorPolicy"] != "configured":
        raise ValueError("GENERIC_AGGREGATE_OPERATOR_POLICY_INVALID")
    if value["missing"] != "exclude":
        raise ValueError("GENERIC_AGGREGATE_MISSING_POLICY_UNSUPPORTED")
    return GenericAggregatePlan({
        "format": FORMAT,
        "selection": selection,
        "groupBy": grouped,
        "reduceDimensions": sorted(reduced),
        "measures": sorted(measures),
        "membershipSemantics": value["membershipSemantics"],
        "memberOperatorPolicy": "configured",
        "missing": "exclude",
    })
