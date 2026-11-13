"""Server-issued, expiring identities for idempotent application effects.

The opaque key contains only version, expiry, nonce and an HMAC.  Scope,
verified actor, function and exact intent digest are authenticated inputs, not
client claims.  Once the key expires, fixed core rejects it without retaining
an unbounded tombstone or historical business payload.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import re
import secrets
import time

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity


_KEY = re.compile(r"oa1_([0-9a-z]{1,13})_([0-9a-f]{32})_([A-Za-z0-9_-]{43})\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_TTL_SECONDS = 86_400


@dataclass(frozen=True, slots=True)
class OperationAdmission:
    operation_id: str
    expires_at: int
    intent_digest: str


def _material(scope: ApplicationScope, identity: VerifiedIdentity, *,
        function: str, intent_digest: str, expires_at: int,
        nonce: str) -> bytes:
    # Canonical structured encoding avoids delimiter ambiguity even when an
    # externally assigned stable ID contains control or punctuation bytes.
    return json.dumps({
        "applicationId": scope.application_id,
        "expiresAt": expires_at,
        "function": function,
        "intentDigest": intent_digest,
        "issuer": identity.issuer,
        "nonce": nonce,
        "subjectId": identity.subject_id,
        "version": "openepm-operation-admission-v1",
        "workspaceId": scope.workspace_id,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def issue_operation_admission(secret: bytes, scope: ApplicationScope,
        identity: VerifiedIdentity, *, function: str, intent_digest: str,
        ttl_seconds: int = 900, now: int | None = None,
        nonce: str | None = None) -> OperationAdmission:
    if (not isinstance(secret, bytes) or len(secret) < 32
            or not isinstance(identity, VerifiedIdentity)
            or not isinstance(function, str) or not 1 <= len(function) <= 200
            or _DIGEST.fullmatch(intent_digest) is None
            or type(ttl_seconds) is not int
            or not 1 <= ttl_seconds <= MAX_TTL_SECONDS):
        raise ValueError("OPERATION_ADMISSION_ARGUMENT_INVALID")
    issued_at = int(time.time()) if now is None else now
    if type(issued_at) is not int or issued_at < 0:
        raise ValueError("OPERATION_ADMISSION_ARGUMENT_INVALID")
    nonce_value = secrets.token_hex(16) if nonce is None else nonce
    if (not isinstance(nonce_value, str)
            or re.fullmatch(r"[0-9a-f]{32}", nonce_value) is None):
        raise ValueError("OPERATION_ADMISSION_ARGUMENT_INVALID")
    expires_at = issued_at + ttl_seconds
    encoded_expiry = base36(expires_at)
    signature = hmac.new(secret, _material(scope, identity,
        function=function, intent_digest=intent_digest,
        expires_at=expires_at, nonce=nonce_value), sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    operation_id = f"oa1_{encoded_expiry}_{nonce_value}_{encoded_signature}"
    return OperationAdmission(operation_id=operation_id,
        expires_at=expires_at, intent_digest=intent_digest)


def validate_operation_admission(secret: bytes, scope: ApplicationScope,
        identity: VerifiedIdentity, *, operation_id: str, function: str,
        intent_digest: str, now: int | None = None) -> OperationAdmission:
    if (not isinstance(secret, bytes) or len(secret) < 32
            or not isinstance(identity, VerifiedIdentity)
            or not isinstance(operation_id, str)
            or not isinstance(function, str) or not 1 <= len(function) <= 200
            or not isinstance(intent_digest, str)
            or _DIGEST.fullmatch(intent_digest) is None):
        raise ValueError("OPERATION_ADMISSION_INVALID")
    matched = _KEY.fullmatch(operation_id)
    if matched is None:
        raise ValueError("OPERATION_ADMISSION_INVALID")
    try:
        expires_at = int(matched.group(1), 36)
        supplied = base64.urlsafe_b64decode(matched.group(3) + "=")
    except (ValueError, TypeError) as error:
        raise ValueError("OPERATION_ADMISSION_INVALID") from error
    current = int(time.time()) if now is None else now
    if type(current) is not int or current < 0:
        raise ValueError("OPERATION_ADMISSION_INVALID")
    expected = hmac.new(secret, _material(scope, identity,
        function=function, intent_digest=intent_digest,
        expires_at=expires_at, nonce=matched.group(2)), sha256).digest()
    if not hmac.compare_digest(supplied, expected):
        raise ValueError("OPERATION_ADMISSION_MISMATCH")
    if expires_at < current:
        raise ValueError("OPERATION_ADMISSION_EXPIRED")
    return OperationAdmission(operation_id=operation_id,
        expires_at=expires_at, intent_digest=intent_digest)


def is_signed_operation_id(value: object) -> bool:
    return isinstance(value, str) and value.startswith("oa1_")


def base36(value: int) -> str:
    if type(value) is not int or value < 0:
        raise ValueError("OPERATION_ADMISSION_ARGUMENT_INVALID")
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if value == 0:
        return "0"
    result = ""
    while value:
        value, remainder = divmod(value, 36)
        result = alphabet[remainder] + result
    return result
