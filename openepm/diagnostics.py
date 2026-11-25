"""Bounded, transport-neutral diagnostics for authored application source.

Only fixed validators construct these messages. Runtime exception strings,
source excerpts, parameters and credentials are not diagnostic payloads.
Positions use one-based lines and UTF-16 columns, with exclusive end positions.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import json
from typing import Any


FORMAT = "openepm-diagnostics-v1"
MAX_DIAGNOSTICS = 100
MAX_DIAGNOSTIC_BYTES = 262_144
_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_STAGES = frozenset(("syntax", "source", "build", "semantic", "test", "run"))
_MESSAGE_LIMIT = 512
_PATH_LIMIT = 500
_SPAN_LIMIT = 1_048_577
_SPAN_KEYS = ("startLine", "startColumn", "endLine", "endColumn")
_ITEM_REQUIRED = ("code", "message", "stage", "severity")
_ITEM_OPTIONAL = ("span", "path", "hint")
_PAYLOAD_KEYS = ("format", "sourceDigest", "positionEncoding", "truncated", "diagnostics")


class MetadataAuthoringError(ValueError):
    """Fixed metadata classification; never carries caller names or values."""

    def __init__(self, code: str, kind: str):
        self.code, self.kind = code, kind
        super().__init__(code)


def metadata_failure(error: Exception):
    """One safe repair vocabulary for SDK and fixed-core metadata resolution."""
    if type(error) is not MetadataAuthoringError:
        return None
    if type(error.code) is not str or type(error.kind) is not str:
        return None
    labels = {"dimension": "dimension", "member": "member", "hierarchy": "hierarchy", "attribute": "attribute",
              "member_list": "member list", "applicability_relation": "applicability relation"}
    if error.kind in labels:
        kind = labels[error.kind]
        options = {
            "METADATA_NAME_REQUIRED": (
                f"A nonempty {kind} name or ID is required.",
                f"Supply the {kind}'s exact name or stable ID from the application metadata."),
            "METADATA_NAME_UNAVAILABLE": (
                f"The {kind} is unavailable in the authorized metadata snapshot.",
                f"Check the {kind} name or ID and your access, then refresh metadata and save again."),
            "METADATA_NAME_AMBIGUOUS": (
                f"The {kind} name matches more than one authorized object.",
                f"Use the intended {kind}'s unique stable ID from the application metadata."),
        }
        if error.code in options:
            return error.code, *options[error.code]
    if (error.code, error.kind) == ("METADATA_HIERARCHY_UNAVAILABLE", "hierarchy"):
        return (error.code, "A hierarchy built for the current metadata revision is unavailable.",
                "Build the dimension hierarchy at the current metadata revision, then save again.")
    if (error.code, error.kind) == ("AUTHORING_METADATA_CONTEXT_UNAVAILABLE", "context"):
        return (error.code, "The authorized application metadata snapshot is unavailable or stale.",
                "Refresh the application metadata and start a new validation build.")
    return None


def _text(value: object, maximum: int) -> str:
    if (type(value) is not str or not value or len(value) > maximum
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("DIAGNOSTIC_TEXT_INVALID")
    return value


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    message: str
    stage: str
    span: tuple[int, int, int, int] | None = None
    path: str | None = None
    hint: str | None = None
    severity: str = "error"

    def __post_init__(self) -> None:
        if type(self.code) is not str or not _CODE.fullmatch(self.code):
            raise ValueError("DIAGNOSTIC_CODE_INVALID")
        _text(self.message, _MESSAGE_LIMIT)
        if (type(self.stage) is not str or self.stage not in _STAGES
                or type(self.severity) is not str
                or self.severity not in ("error", "warning")):
            raise ValueError("DIAGNOSTIC_KIND_INVALID")
        if self.path is not None:
            _text(self.path, _PATH_LIMIT)
        if self.hint is not None:
            _text(self.hint, _MESSAGE_LIMIT)
        if self.span is not None:
            if (type(self.span) is not tuple or len(self.span) != 4
                    or any(type(value) is not int or not 1 <= value <= _SPAN_LIMIT
                           for value in self.span)
                    or self.span[2:] < self.span[:2]):
                raise ValueError("DIAGNOSTIC_SPAN_INVALID")

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message,
            "stage": self.stage, "severity": self.severity}
        if self.span is not None:
            result["span"] = dict(zip(_SPAN_KEYS, self.span))
        if self.path is not None:
            result["path"] = self.path
        if self.hint is not None:
            result["hint"] = self.hint
        return result


def diagnostic_payload(source_digest: str, diagnostics: tuple[Diagnostic, ...],
                       *, truncated: bool = False) -> dict[str, Any]:
    if (type(source_digest) is not str or not _DIGEST.fullmatch(source_digest)
            or type(diagnostics) is not tuple
            or not 1 <= len(diagnostics) <= MAX_DIAGNOSTICS
            or any(not isinstance(item, Diagnostic) for item in diagnostics)
            or type(truncated) is not bool):
        raise ValueError("DIAGNOSTIC_PAYLOAD_INVALID")
    result = {"format": FORMAT, "sourceDigest": source_digest,
        "positionEncoding": "utf-16", "truncated": truncated,
        "diagnostics": [item.to_wire() for item in diagnostics]}
    if len(json.dumps(result, ensure_ascii=True).encode('ascii')) > MAX_DIAGNOSTIC_BYTES:
        raise ValueError('DIAGNOSTIC_PAYLOAD_LIMIT')
    return result


def validate_diagnostic_payload(value: object) -> dict[str, Any]:
    """Validate and copy diagnostics received across a process/transport boundary."""
    if (type(value) is not dict or set(value) != set(_PAYLOAD_KEYS)
            or value["format"] != FORMAT or value["positionEncoding"] != "utf-16"
            or type(value["diagnostics"]) is not list
            or not 1 <= len(value["diagnostics"]) <= MAX_DIAGNOSTICS):
        raise ValueError("DIAGNOSTIC_PAYLOAD_INVALID")
    items = []
    for raw in value["diagnostics"]:
        if (type(raw) is not dict or not set(_ITEM_REQUIRED) <= set(raw)
                or set(raw) - set(_ITEM_REQUIRED + _ITEM_OPTIONAL)):
            raise ValueError("DIAGNOSTIC_PAYLOAD_INVALID")
        span = raw.get("span")
        if span is not None:
            keys = _SPAN_KEYS
            if type(span) is not dict or set(span) != set(keys):
                raise ValueError("DIAGNOSTIC_SPAN_INVALID")
            span = tuple(span[key] for key in keys)
        items.append(Diagnostic(raw["code"], raw["message"], raw["stage"], span,
            raw.get("path"), raw.get("hint"), raw["severity"]))
    return diagnostic_payload(value["sourceDigest"], tuple(items),
                              truncated=value["truncated"])


def diagnostic_payload_schema() -> dict:
    """Project this owner's bounded wire shape; byte/span ordering stay native."""
    def closed(properties, required=None):
        return {"type": "object", "properties": properties,
            "required": list(properties) if required is None else list(required),
            "additionalProperties": False}
    def text_schema(maximum):
        return {"type": "string", "minLength": 1, "maxLength": maximum,
                "not": {"pattern": r"[\u0000-\u001f\u007f]"}}
    item = closed({"code": {"type": "string", "pattern": r"^[A-Z][A-Z0-9_]{2,127}(?![\s\S])"},
        "message": text_schema(_MESSAGE_LIMIT), "stage": {"enum": sorted(_STAGES)},
        "severity": {"enum": ["error", "warning"]},
        "span": closed({key: {"type": "integer", "minimum": 1, "maximum": _SPAN_LIMIT}
                        for key in _SPAN_KEYS}),
        "path": text_schema(_PATH_LIMIT), "hint": text_schema(_MESSAGE_LIMIT)}, _ITEM_REQUIRED)
    return closed({"format": {"const": FORMAT},
        "sourceDigest": {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"},
        "positionEncoding": {"const": "utf-16"}, "truncated": {"type": "boolean"},
        "diagnostics": {"type": "array", "minItems": 1,
                        "maxItems": MAX_DIAGNOSTICS, "items": item}})


class SourceValidationError(ValueError):
    """A fixed-validator failure carrying a safe structured diagnostic set."""

    code = "PYTHON_SOURCE_VALIDATION_FAILED"

    def __init__(self, payload: dict[str, Any]):
        self.diagnostics = validate_diagnostic_payload(payload)
        super().__init__(self.code)
