"""Canonical selected-domain profile for set-based expression execution.

The profile keeps the authored selection compact. Resolved member identities
belong to an execution manifest, not to the immutable formula definition.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Iterable

from .selection_contract import canonical_selection, selection_digest


FORMAT = "openepm-selected-domain-v1"
ANCHOR = "existing_present_cells"
SOURCE_LAYER = "raw"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


def canonical_selected_domain(value: object, *, active_dimensions: Iterable[str]) -> dict:
    dimensions = tuple(active_dimensions)
    if (not dimensions or len(dimensions) != len(set(dimensions))
            or any(not isinstance(axis, str) or not _ID.fullmatch(axis)
                   for axis in dimensions)):
        raise ValueError("SELECTED_DOMAIN_ACTIVE_DIMENSIONS_INVALID")
    required = {
        "format", "sourceSelection", "sourceSelectionDigest", "anchorGrain",
        "sourceLayer", "targetMapping", "missingPolicy", "resultUnit",
        "maxSourceCells", "maxOutputCells",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("SELECTED_DOMAIN_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("SELECTED_DOMAIN_FORMAT_UNSUPPORTED")
    selection = canonical_selection(
        value["sourceSelection"], active_dimensions=dimensions)
    digest = selection_digest(selection, active_dimensions=dimensions)
    if value["sourceSelectionDigest"] != digest:
        raise ValueError("SELECTED_DOMAIN_SELECTION_DIGEST_MISMATCH")
    if value["anchorGrain"] != ANCHOR or value["sourceLayer"] != SOURCE_LAYER:
        raise ValueError("SELECTED_DOMAIN_SOURCE_PROFILE_UNSUPPORTED")
    target = value["targetMapping"]
    if (not isinstance(target, dict)
            or set(target) != {"mode", "dimensionId", "memberId"}
            or target["mode"] != "single_member_override"
            or not isinstance(target["dimensionId"], str)
            or not isinstance(target["memberId"], str)
            or not _ID.fullmatch(target["dimensionId"])
            or not _ID.fullmatch(target["memberId"])
            or target["dimensionId"] not in dimensions):
        raise ValueError("SELECTED_DOMAIN_TARGET_MAPPING_INVALID")
    missing = value["missingPolicy"]
    if missing != {"primary": "exclude_absent", "relative": "error"}:
        raise ValueError("SELECTED_DOMAIN_MISSING_POLICY_UNSUPPORTED")
    if value["resultUnit"] not in {"amount", "ratio"}:
        raise ValueError("SELECTED_DOMAIN_RESULT_UNIT_INVALID")
    for key, maximum in (("maxSourceCells", 1_000_000),
                         ("maxOutputCells", 100_000)):
        if type(value[key]) is not int or not 1 <= value[key] <= maximum:
            raise ValueError("SELECTED_DOMAIN_BUDGET_INVALID")
    return {
        "format": FORMAT,
        "sourceSelection": selection,
        "sourceSelectionDigest": digest,
        "anchorGrain": ANCHOR,
        "sourceLayer": SOURCE_LAYER,
        "targetMapping": {
            "mode": "single_member_override",
            "dimensionId": target["dimensionId"],
            "memberId": target["memberId"],
        },
        "missingPolicy": {"primary": "exclude_absent", "relative": "error"},
        "resultUnit": value["resultUnit"],
        "maxSourceCells": value["maxSourceCells"],
        "maxOutputCells": value["maxOutputCells"],
    }


def from_calculated_member(definition: object, *, active_dimensions: Iterable[str]) -> dict:
    from .calculated_member_contract import canonical_calculated_member
    dimensions = tuple(active_dimensions)
    calculated = canonical_calculated_member(
        definition, active_dimensions=dimensions)
    value = {
        "format": FORMAT,
        "sourceSelection": calculated["sourceSelection"],
        "sourceSelectionDigest": selection_digest(
            calculated["sourceSelection"], active_dimensions=dimensions),
        "anchorGrain": ANCHOR,
        "sourceLayer": SOURCE_LAYER,
        "targetMapping": {
            "mode": "single_member_override",
            **calculated["target"],
        },
        "missingPolicy": {"primary": "exclude_absent", "relative": "error"},
        "resultUnit": calculated["resultUnit"],
        "maxSourceCells": calculated["maxSourceCells"],
        "maxOutputCells": calculated["maxOutputCells"],
    }
    return canonical_selected_domain(value, active_dimensions=dimensions)


def selected_domain_digest(value: object, *, active_dimensions: Iterable[str]) -> str:
    canonical = canonical_selected_domain(
        value, active_dimensions=tuple(active_dimensions))
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(encoded).hexdigest()
