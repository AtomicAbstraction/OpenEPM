"""Deterministic presentation contract for dimensional security tags.

``Security String`` is an administrator-facing serialization of the existing
typed read/write tag arrays.  It is never evaluated as an expression and never
replaces the active dimensional-security policy.  Trusted callers must resolve
the tag catalogue and persist the returned arrays through the governed
security writer.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import AbstractSet, Iterable


_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,19}\Z")
_STRING = re.compile(r"read=([^;]*);write=([^;]*)\Z")
_MAX_TAGS_PER_KIND = 100
_MAX_SECURITY_STRING_LENGTH = 8192


@dataclass(frozen=True, slots=True)
class SecurityTagSets:
    read_tags: tuple[str, ...]
    write_tags: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_canonical(self.read_tags, "read")
        _validate_canonical(self.write_tags, "write")


def _validate_canonical(tags: tuple[str, ...], label: str) -> None:
    if (not isinstance(tags, tuple)
            or len(tags) > _MAX_TAGS_PER_KIND
            or tuple(sorted(set(tags))) != tags
            or any(not isinstance(tag, str) or not _TAG.fullmatch(tag)
                   for tag in tags)):
        raise ValueError(f"SECURITY_STRING_{label.upper()}_TAGS_INVALID")


def _parse_tags(value: str, label: str) -> tuple[str, ...]:
    if not value:
        return ()
    parts = value.split(",")
    if (len(parts) > _MAX_TAGS_PER_KIND
            or any(not _TAG.fullmatch(tag) for tag in parts)
            or len(parts) != len(set(parts))):
        raise ValueError(f"SECURITY_STRING_{label.upper()}_TAGS_INVALID")
    return tuple(sorted(parts))


def parse_security_string(
        value: str, *, known_tags: AbstractSet[str] | None = None,
        allow_empty: bool = True) -> SecurityTagSets:
    """Parse one bounded string into canonical typed tag sets.

    The only accepted non-empty grammar is ``read=a,b;write=c``.  Values are
    stable tag IDs, not user IDs, group labels, SQL, regular expressions or
    Boolean expressions.  An empty string is accepted only as an explicit
    untagged value and is normalized by :func:`render_security_string`.
    """
    if (not isinstance(value, str)
            or len(value) > _MAX_SECURITY_STRING_LENGTH
            or value != value.strip()
            or any(ord(character) < 32 for character in value)):
        raise ValueError("SECURITY_STRING_INVALID")
    if not value:
        if not allow_empty:
            raise ValueError("SECURITY_STRING_EMPTY_NOT_ALLOWED")
        result = SecurityTagSets((), ())
    else:
        match = _STRING.fullmatch(value)
        if match is None:
            raise ValueError("SECURITY_STRING_INVALID")
        result = SecurityTagSets(
            _parse_tags(match.group(1), "read"),
            _parse_tags(match.group(2), "write"),
        )
    if known_tags is not None:
        if (not isinstance(known_tags, AbstractSet)
                or any(not isinstance(tag, str) or not _TAG.fullmatch(tag)
                       for tag in known_tags)):
            raise ValueError("SECURITY_TAG_CATALOG_INVALID")
        unknown = (set(result.read_tags) | set(result.write_tags)) - known_tags
        if unknown:
            raise ValueError("SECURITY_STRING_UNKNOWN_TAG")
    return result


def render_security_string(read_tags: Iterable[str],
                           write_tags: Iterable[str]) -> str:
    """Render typed tags in one stable order for UI, MCP and digest use."""
    try:
        read = tuple(sorted(read_tags))
        write = tuple(sorted(write_tags))
    except TypeError as error:
        raise ValueError("SECURITY_STRING_TAGS_INVALID") from error
    values = SecurityTagSets(read, write)
    return (f"read={','.join(values.read_tags)};"
            f"write={','.join(values.write_tags)}")

