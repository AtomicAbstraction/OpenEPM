"""Fixed typed W06 business-impact descriptors.

Writers describe committed semantic effects; they never name SQL, dependency
rows or calculation instances.  The durable matcher owns reverse-index fanout.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json


FORMAT = "openepm-calculation-impact-v1"
SOURCE_KINDS = frozenset({
    "numeric_fact", "text_fact", "line_detail", "source_replace",
    "numeric_transform", "calculation_publication", "journal",
    "metadata", "attribute", "hierarchy", "calendar", "definition",
    "layout", "lifecycle", "elimination", "ownership",
})
DOMAINS = frozenset({
    "numeric_fact", "text_fact", "line_detail", "calculation_result",
    "dimension", "member", "attribute", "hierarchy", "calendar", "definition",
    "layout", "application", "ownership",
})
CHANGES = frozenset({
    "set", "add", "clear", "insert", "update", "delete", "replace",
    "activate", "deactivate", "publish", "withdraw",
})
REASONS = frozenset({
    "data_changed", "upstream_changed", "membership_changed",
    "hierarchy_changed", "definition_changed", "calendar_changed",
    "unit_policy_changed",
})
def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _id(value: object, code: str) -> str:
    # Metadata stable IDs predate the stricter operation-ID alphabet and may
    # contain spaces or Unicode.  Preserve them exactly while rejecting
    # whitespace-only, padded or control-bearing values.
    if (not isinstance(value, str) or not 1 <= len(value) <= 200
            or value != value.strip()
            or any(ord(character) < 32 for character in value)):
        raise ValueError(code)
    return value


def _scope(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("CALCULATION_IMPACT_SCOPE_INVALID")
    result = []
    seen = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"dimensionId", "memberId"}:
            raise ValueError("CALCULATION_IMPACT_SCOPE_INVALID")
        axis = _id(item["dimensionId"], "CALCULATION_IMPACT_SCOPE_INVALID")
        member = _id(item["memberId"], "CALCULATION_IMPACT_SCOPE_INVALID")
        if axis in seen:
            raise ValueError("CALCULATION_IMPACT_SCOPE_INVALID")
        seen.add(axis)
        result.append({"dimensionId": axis, "memberId": member})
    return sorted(result, key=lambda item: item["dimensionId"])


def _effect(value: object) -> dict[str, object]:
    required = {"domain", "change", "objectType", "objectId", "scope",
                "reason", "oldPresence", "newPresence"}
    if (not isinstance(value, dict) or set(value) != required
            or value["domain"] not in DOMAINS
            or value["change"] not in CHANGES
            or value["reason"] not in REASONS
            or value["oldPresence"] not in {"absent", "present", "unknown"}
            or value["newPresence"] not in {"absent", "present", "unknown"}):
        raise ValueError("CALCULATION_IMPACT_EFFECT_INVALID")
    return {
        "domain": value["domain"], "change": value["change"],
        "objectType": _id(value["objectType"],
                          "CALCULATION_IMPACT_EFFECT_INVALID"),
        "objectId": _id(value["objectId"],
                        "CALCULATION_IMPACT_EFFECT_INVALID"),
        "scope": _scope(value["scope"]), "reason": value["reason"],
        "oldPresence": value["oldPresence"],
        "newPresence": value["newPresence"],
    }


@dataclass(frozen=True, slots=True)
class CalculationImpact:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return sha256(_canonical(self.normalized)).hexdigest()


def compile_calculation_impact(value: object) -> CalculationImpact:
    required = {"format", "sourceKind", "sourceId", "causalRevision",
                "effects"}
    if (not isinstance(value, dict) or set(value) != required
            or value["format"] != FORMAT
            or value["sourceKind"] not in SOURCE_KINDS
            or not isinstance(value["causalRevision"], int)
            or isinstance(value["causalRevision"], bool)
            or value["causalRevision"] < 1
            or not isinstance(value["effects"], list)
            or not 1 <= len(value["effects"]) <= 500):
        raise ValueError("CALCULATION_IMPACT_INVALID")
    effects = [_effect(item) for item in value["effects"]]
    encoded = [_canonical(item) for item in effects]
    if len(encoded) != len(set(encoded)):
        raise ValueError("CALCULATION_IMPACT_EFFECT_DUPLICATE")
    return CalculationImpact({
        "format": FORMAT,
        "sourceKind": value["sourceKind"],
        "sourceId": _id(value["sourceId"], "CALCULATION_IMPACT_INVALID"),
        "causalRevision": value["causalRevision"],
        "effects": sorted(effects, key=_canonical),
    })


def fact_effect(*, domain: str, change: str, object_id: str,
        members: dict[str, str], old_present: bool,
        new_present: bool) -> dict[str, object]:
    """Build one exact numeric/text coordinate effect for fixed writers."""
    if domain not in {"numeric_fact", "text_fact"}:
        raise ValueError("CALCULATION_IMPACT_FACT_DOMAIN_INVALID")
    return {
        "domain": domain, "change": change,
        "objectType": domain, "objectId": object_id,
        "scope": [{"dimensionId": axis, "memberId": member}
                  for axis, member in sorted(members.items())],
        "reason": "data_changed",
        "oldPresence": "present" if old_present else "absent",
        "newPresence": "present" if new_present else "absent",
    }
