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
        _text(self.message, 512)
        if (type(self.stage) is not str or self.stage not in _STAGES
                or type(self.severity) is not str
                or self.severity not in ("error", "warning")):
            raise ValueError("DIAGNOSTIC_KIND_INVALID")
        if self.path is not None:
            _text(self.path, 500)
        if self.hint is not None:
            _text(self.hint, 512)
        if self.span is not None:
            if (type(self.span) is not tuple or len(self.span) != 4
                    or any(type(value) is not int or not 1 <= value <= 1_048_577
                           for value in self.span)
                    or self.span[2:] < self.span[:2]):
                raise ValueError("DIAGNOSTIC_SPAN_INVALID")

    def to_wire(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message,
            "stage": self.stage, "severity": self.severity}
        if self.span is not None:
            result["span"] = dict(zip(("startLine", "startColumn", "endLine",
                                        "endColumn"), self.span))
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
    if (type(value) is not dict or set(value) != {
            "format", "sourceDigest", "positionEncoding", "truncated", "diagnostics"}
            or value["format"] != FORMAT or value["positionEncoding"] != "utf-16"
            or type(value["diagnostics"]) is not list
            or not 1 <= len(value["diagnostics"]) <= MAX_DIAGNOSTICS):
        raise ValueError("DIAGNOSTIC_PAYLOAD_INVALID")
    items = []
    for raw in value["diagnostics"]:
        if (type(raw) is not dict or not {"code", "message", "stage", "severity"} <= set(raw)
                or set(raw) - {"code", "message", "stage", "severity", "span", "path", "hint"}):
            raise ValueError("DIAGNOSTIC_PAYLOAD_INVALID")
        span = raw.get("span")
        if span is not None:
            keys = ("startLine", "startColumn", "endLine", "endColumn")
            if type(span) is not dict or set(span) != set(keys):
                raise ValueError("DIAGNOSTIC_SPAN_INVALID")
            span = tuple(span[key] for key in keys)
        items.append(Diagnostic(raw["code"], raw["message"], raw["stage"], span,
            raw.get("path"), raw.get("hint"), raw["severity"]))
    return diagnostic_payload(value["sourceDigest"], tuple(items),
                              truncated=value["truncated"])


class SourceValidationError(ValueError):
    """A fixed-validator failure carrying a safe structured diagnostic set."""

    code = "PYTHON_SOURCE_VALIDATION_FAILED"

    def __init__(self, payload: dict[str, Any]):
        self.diagnostics = validate_diagnostic_payload(payload)
        super().__init__(self.code)
