"""Canonical generic effects produced by an editable multidimensional view."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
from typing import Any, Iterable


FORMAT = "openepm-cube-effect-batch-v1"
MAX_EFFECTS = 10_000
MAX_TEXT = 32_768
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")


def _id(value: object, code: str, *, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 200
        or (not value and not empty)
        or (value and not _ID.fullmatch(value))
    ):
        raise ValueError(code)
    return value


def _decimal(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("CUBE_EFFECT_NUMERIC_VALUE_INVALID")
    try:
        parsed = Decimal(value)
    except (InvalidOperation, ValueError):
        raise ValueError("CUBE_EFFECT_NUMERIC_VALUE_INVALID") from None
    if not parsed.is_finite():
        raise ValueError("CUBE_EFFECT_NUMERIC_VALUE_INVALID")
    normalized = format(parsed, "f")
    if len(normalized) > 200:
        raise ValueError("CUBE_EFFECT_NUMERIC_VALUE_INVALID")
    return normalized


def _coordinate(value: object, active_dimensions: Iterable[str] | None) -> dict[str, str]:
    if not isinstance(value, dict) or not value:
        raise ValueError("CUBE_EFFECT_COORDINATE_INVALID")
    coordinate = {
        _id(dimension, "CUBE_EFFECT_COORDINATE_INVALID"): _id(
            member, "CUBE_EFFECT_COORDINATE_INVALID"
        )
        for dimension, member in value.items()
    }
    if active_dimensions is not None and set(coordinate) != set(active_dimensions):
        raise ValueError("CUBE_EFFECT_COORDINATE_GRAIN_INCOMPLETE")
    return dict(sorted(coordinate.items()))


def _value(fact_kind: str, action: str, value: object) -> object:
    if action == "clear":
        if value is not None:
            raise ValueError("CUBE_EFFECT_CLEAR_VALUE_FORBIDDEN")
        return None
    if fact_kind == "numeric":
        return _decimal(value)
    if action == "add":
        raise ValueError("CUBE_EFFECT_ADD_NUMERIC_ONLY")
    if fact_kind == "text":
        if not isinstance(value, str) or len(value) > MAX_TEXT or "\x00" in value:
            raise ValueError("CUBE_EFFECT_TEXT_VALUE_INVALID")
        return value
    raise ValueError("CUBE_EFFECT_FACT_KIND_UNSUPPORTED")


def canonical_effect_batch(
    value: object, *, active_dimensions: Iterable[str] | None = None
) -> dict[str, Any]:
    required = {
        "format", "viewDigest", "expectedMetadataRevision", "expectedDataRevision",
        "effects",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("CUBE_EFFECT_BATCH_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("CUBE_EFFECT_FORMAT_UNSUPPORTED")
    if not isinstance(value["viewDigest"], str) or not _DIGEST.fullmatch(value["viewDigest"]):
        raise ValueError("CUBE_EFFECT_VIEW_DIGEST_INVALID")
    for key in ("expectedMetadataRevision", "expectedDataRevision"):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError("CUBE_EFFECT_REVISION_INVALID")
    effects = value["effects"]
    if not isinstance(effects, list) or not 1 <= len(effects) <= MAX_EFFECTS:
        raise ValueError("CUBE_EFFECT_COUNT_INVALID")
    normalized = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for raw in effects:
        if not isinstance(raw, dict) or set(raw) != {
            "coordinate", "factKind", "action", "value", "expectedChangeId"
        }:
            raise ValueError("CUBE_EFFECT_INVALID")
        coordinate = _coordinate(raw["coordinate"], active_dimensions)
        coordinate_key = tuple(coordinate.items())
        if coordinate_key in seen:
            raise ValueError("CUBE_EFFECT_COORDINATE_DUPLICATE")
        seen.add(coordinate_key)
        if raw["factKind"] not in {"numeric", "text"}:
            raise ValueError("CUBE_EFFECT_FACT_KIND_UNSUPPORTED")
        if raw["action"] not in {"set", "add", "clear"}:
            raise ValueError("CUBE_EFFECT_ACTION_UNSUPPORTED")
        normalized.append({
            "coordinate": coordinate,
            "factKind": raw["factKind"],
            "action": raw["action"],
            "value": _value(raw["factKind"], raw["action"], raw["value"]),
            "expectedChangeId": _id(
                raw["expectedChangeId"], "CUBE_EFFECT_CHANGE_ID_INVALID", empty=True
            ),
        })
    return {
        "format": FORMAT,
        "viewDigest": value["viewDigest"],
        "expectedMetadataRevision": value["expectedMetadataRevision"],
        "expectedDataRevision": value["expectedDataRevision"],
        "effects": normalized,
    }


def effect_batch_digest(
    value: object, *, active_dimensions: Iterable[str] | None = None
) -> str:
    canonical = canonical_effect_batch(value, active_dimensions=active_dimensions)
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    return sha256(encoded).hexdigest()
