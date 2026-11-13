"""Current-state W08 contract for coherent mixed cube retrieval.

The contract describes *what* must be read.  PostgreSQL adapters resolve the
selection, authority, definitions, current results and hierarchy contributions at
one read cut.  Existing raw scan and layer-report contracts deliberately keep
their prior meanings.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
from typing import Iterable

from .current_object_contract import is_state_token, require_state_token
from .selection_contract import canonical_selection


FORMAT = "openepm-resolved-cube-read-v1"
ORIGINS = frozenset({"input", "materialized", "dynamic", "hierarchy"})
_UNIT = re.compile(r"[A-Za-z][A-Za-z0-9:._-]{0,199}\Z")
FRESHNESS = frozenset({"current", "allow_stale"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _axes(value: object, active: tuple[str, ...]) -> list[str]:
    if (not isinstance(value, list) or not 1 <= len(value) <= len(active)
            or len(value) != len(set(value))
            or any(not isinstance(item, str) or item not in active
                   for item in value)):
        raise ValueError("RESOLVED_READ_GRAIN_INVALID")
    return list(value)


def _source(value: object, active: tuple[str, ...]) -> dict:
    if value == {"semantics": "own"}:
        return {"semantics": "own"}
    required = {"semantics", "bindingId", "bindingStateToken", "hierarchies"}
    if (not isinstance(value, dict) or set(value) != required
            or value.get("semantics") != "effective"
            or not isinstance(value.get("bindingId"), str)
            or _ID.fullmatch(value["bindingId"]) is None
            or not isinstance(value.get("hierarchies"), list)):
        raise ValueError("RESOLVED_READ_SOURCE_INVALID")
    rows = []
    seen = set()
    for item in value["hierarchies"]:
        if (not isinstance(item, dict) or set(item) != {
                "dimensionId", "hierarchyId", "hierarchyStateToken",
                "membershipSemantics"}
                or item["dimensionId"] not in active
                or not isinstance(item["hierarchyId"], str)
                or _ID.fullmatch(item["hierarchyId"]) is None
                or require_state_token(item["hierarchyStateToken"],
                    error="RESOLVED_READ_SOURCE_INVALID")
                    != item["hierarchyStateToken"]
                or item["membershipSemantics"] not in {
                    "unique_member", "placement"}
                or item["dimensionId"] in seen):
            raise ValueError("RESOLVED_READ_SOURCE_INVALID")
        seen.add(item["dimensionId"])
        rows.append(dict(item))
    return {"semantics": "effective", "bindingId": value["bindingId"],
        "bindingStateToken": require_state_token(value["bindingStateToken"],
            error="RESOLVED_READ_SOURCE_INVALID"),
        "hierarchies": sorted(rows, key=lambda item: item["dimensionId"])}


@dataclass(frozen=True, slots=True)
class ResolvedCubeReadPlan:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return sha256(_canonical(self.normalized)).hexdigest()


def compile_resolved_cube_read(value: object, *,
        active_dimensions: Iterable[str]) -> ResolvedCubeReadPlan:
    """Validate one bounded, complete mixed-read intent.

    A caller chooses own input or a current effective binding explicitly.
    It never selects a physical engine or asks a read to publish calculations.
    """
    required = {"format", "selection", "source", "outputGrain",
                "freshness", "dynamicFallback", "delivery", "limits"}
    if (not isinstance(value, dict)
            or (set(value) != required
                and set(value) != required | {"presentation"})):
        raise ValueError("RESOLVED_READ_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("RESOLVED_READ_FORMAT_UNSUPPORTED")
    active = tuple(active_dimensions)
    if (not active or len(active) != len(set(active))
            or any(not isinstance(item, str) or not item for item in active)):
        raise ValueError("RESOLVED_READ_DIMENSIONS_INVALID")
    selection = canonical_selection(value["selection"],
                                    active_dimensions=active)
    grain = _axes(value["outputGrain"], active)
    if value["freshness"] not in FRESHNESS:
        raise ValueError("RESOLVED_READ_FRESHNESS_INVALID")
    if not isinstance(value["dynamicFallback"], bool):
        raise ValueError("RESOLVED_READ_DYNAMIC_POLICY_INVALID")
    if value["delivery"] not in {"direct", "technical_query"}:
        raise ValueError("RESOLVED_READ_DELIVERY_INVALID")
    limits = value["limits"]
    if (not isinstance(limits, dict)
            or set(limits) != {"maxRows", "maxSourceRows", "timeoutMs"}
            or type(limits["maxRows"]) is not int
            or not 1 <= limits["maxRows"] <= 100_000
            or type(limits["maxSourceRows"]) is not int
            or not 1 <= limits["maxSourceRows"] <= 1_000_000
            or type(limits["timeoutMs"]) is not int
            or not 100 <= limits["timeoutMs"] <= 120_000):
        raise ValueError("RESOLVED_READ_LIMITS_INVALID")
    if value["delivery"] == "direct" and limits["maxRows"] > 500:
        raise ValueError("RESOLVED_READ_TECHNICAL_QUERY_REQUIRED")
    if value["delivery"] == "direct" and set(grain) != set(active):
        raise ValueError("RESOLVED_READ_TECHNICAL_QUERY_REQUIRED")
    presentation = value.get("presentation", {"pageSize": limits["maxRows"],
        "suppression": {"missing": False, "zero": False}})
    if (not isinstance(presentation, dict)
            or set(presentation) != {"pageSize", "suppression"}
            or type(presentation["pageSize"]) is not int
            or not 1 <= presentation["pageSize"] <= limits["maxRows"]
            or not isinstance(presentation["suppression"], dict)
            or set(presentation["suppression"]) != {"missing", "zero"}
            or type(presentation["suppression"]["missing"]) is not bool
            or type(presentation["suppression"]["zero"]) is not bool):
        raise ValueError("RESOLVED_READ_PRESENTATION_INVALID")
    return ResolvedCubeReadPlan({"format": FORMAT,
        "selection": selection, "source": _source(value["source"], active),
        "outputGrain": grain, "freshness": value["freshness"],
        "dynamicFallback": value["dynamicFallback"],
        "delivery": value["delivery"],
        "presentation": {"pageSize": presentation["pageSize"],
            "suppression": dict(presentation["suppression"])},
        "limits": dict(limits)})


def apply_resolved_presentation(rows: list[dict[str, object]], *,
        plan: ResolvedCubeReadPlan) -> list[dict[str, object]]:
    """Apply saved-view suppression after coherent resolution and authorization."""
    suppression = plan.normalized["presentation"]["suppression"]
    result = []
    for row in rows:
        if not row["present"]:
            if not suppression["missing"]:
                result.append(row)
            continue
        if suppression["zero"] and row["resultUnit"] != "text":
            try:
                if Decimal(row["value"]) == 0:
                    continue
            except (InvalidOperation, ValueError):
                raise ValueError("RESOLVED_READ_ROW_INVALID") from None
        result.append(row)
    return result


def validate_resolved_rows(rows: object, *, plan: ResolvedCubeReadPlan,
        snapshot: object) -> list[dict[str, object]]:
    """Validate adapter output before it crosses the public boundary."""
    if (not isinstance(snapshot, dict) or set(snapshot) != {
            "metadataRevision", "dataRevision", "policyRevision",
            "commitRevision", "securityRevision", "impactEpoch",
            "processedImpactEpoch"}
            or any(type(value) is not int or value < 0
                   for value in snapshot.values())
            or snapshot["processedImpactEpoch"] > snapshot["impactEpoch"]):
        raise ValueError("RESOLVED_READ_SNAPSHOT_INVALID")
    if not isinstance(rows, list) or len(rows) > plan.normalized["limits"]["maxRows"]:
        raise ValueError("RESOLVED_READ_RESULT_LIMIT")
    grain = plan.normalized["outputGrain"]
    seen = set()
    result = []
    for row in rows:
        required = {"members", "present", "value", "resultUnit", "origin",
                    "currentness", "resultStateToken", "lineage"}
        if (not isinstance(row, dict) or set(row) != required
                or not isinstance(row["members"], dict)
                or set(row["members"]) != set(grain)
                or any(not isinstance(value, str) or not value
                       for value in row["members"].values())
                or not isinstance(row["present"], bool)
                or (row["present"] and not isinstance(row["value"], str))
                or (not row["present"] and row["value"] is not None)
                or not isinstance(row["resultUnit"], str)
                or _UNIT.fullmatch(row["resultUnit"]) is None
                or row["origin"] not in ORIGINS
                or row["currentness"] not in {"current", "stale"}
                or (row["resultStateToken"] is not None
                    and not is_state_token(row["resultStateToken"]))
                or not isinstance(row["lineage"], list)):
            raise ValueError("RESOLVED_READ_ROW_INVALID")
        if (plan.normalized["freshness"] == "current"
                and row["currentness"] != "current"):
            raise ValueError("CALCULATION_REQUIRED")
        key = tuple(row["members"][axis] for axis in grain)
        if key in seen:
            raise ValueError("RESOLVED_READ_TARGET_COLLISION")
        seen.add(key)
        result.append({**row, "members": {
            axis: row["members"][axis] for axis in grain}})
    return result
