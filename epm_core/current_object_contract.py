"""Shared current-object concurrency primitives.

Product objects have one current record.  A state token identifies only that
record's current mutation state: it cannot retrieve old content and must rotate
for every successful create, replace, activation-state change, delete/recreate,
or edit/revert transition.  Content digests may repeat after an edit/revert;
state tokens must not.
"""
from __future__ import annotations

from hashlib import sha256
import re
import secrets
from typing import Iterable


STATE_TOKEN_BYTES = 32
STATE_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def require_stable_identifier(value: object, label: str) -> str:
    """Validate one bounded current-object or metadata stable identifier."""
    if (not isinstance(value, str) or not 1 <= len(value) <= 200
            or value != value.strip() or "\x00" in value):
        raise ValueError(
            f"{label} must be a nonempty stable ID of at most 200 characters")
    return value


def new_state_token() -> str:
    """Return a fresh opaque mutation token with 256 bits of entropy."""
    return secrets.token_hex(STATE_TOKEN_BYTES)


def is_state_token(value: object) -> bool:
    return isinstance(value, str) and STATE_TOKEN_PATTERN.fullmatch(value) is not None


def require_state_token(value: object, *, error: str) -> str:
    if not is_state_token(value):
        raise ValueError(error)
    return value


def collection_token(items: Iterable[tuple[str, str]]) -> str:
    """Digest a complete current ID/token set for continuation fencing.

    Callers must supply the full authorized collection, not just one page.
    Sorting here prevents query-plan order from changing the token. Duplicate
    stable IDs are rejected because they would violate one-current-row state.
    """
    normalized = sorted(items)
    if any(not isinstance(identifier, str) or not identifier for identifier, _ in normalized):
        raise ValueError("CURRENT_OBJECT_ID_INVALID")
    if any(not is_state_token(token) for _, token in normalized):
        raise ValueError("CURRENT_OBJECT_STATE_TOKEN_INVALID")
    identifiers = [identifier for identifier, _ in normalized]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("CURRENT_OBJECT_DUPLICATE_ID")
    source = "\n".join(f"{identifier}:{token}" for identifier, token in normalized)
    return sha256(source.encode("utf-8")).hexdigest()
