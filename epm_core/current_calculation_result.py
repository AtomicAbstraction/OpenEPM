"""Current-only calculation result identity and continuation fencing.

A logical ``result_key`` has one public state.  The opaque state token is a
concurrency/currentness fence, never a locator for an older payload.  Paged
reads bind both result and authorization state and must restart if either
changes between pages.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from hashlib import sha256

from .current_object_contract import require_state_token
from .persistence_contract import ApplicationScope


_RESULT_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_AFTER = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CURSOR_BYTES = 16_384


def require_result_key(value: object) -> str:
    if not isinstance(value, str) or _RESULT_KEY.fullmatch(value) is None:
        raise ValueError("CALCULATION_RESULT_KEY_INVALID")
    return value


def current_result_fence(*, result_key: object, result_state_token: object,
                         authorization_state_token: object) -> dict[str, str]:
    return {
        "resultKey": require_result_key(result_key),
        "resultStateToken": require_state_token(
            result_state_token, error="CALCULATION_RESULT_STATE_TOKEN_INVALID"),
        "authorizationStateToken": require_state_token(
            authorization_state_token,
            error="CALCULATION_RESULT_AUTHORIZATION_TOKEN_INVALID"),
    }


def pack_current_result_cursor(secret: bytes, *, function: str,
                               scope: ApplicationScope,
                               identity: tuple[str, str], fence: dict,
                               query_digest: str, after: str, limit: int,
                               expires_at: int) -> str:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("CALCULATION_RESULT_CURSOR_SECRET_INVALID")
    normalized = current_result_fence(
        result_key=fence.get("resultKey"),
        result_state_token=fence.get("resultStateToken"),
        authorization_state_token=fence.get("authorizationStateToken"))
    if (not isinstance(function, str) or not function
            or not all(isinstance(item, str) and item for item in identity)
            or not isinstance(query_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", query_digest) is None
            or not isinstance(after, str) or _AFTER.fullmatch(after) is None
            or type(limit) is not int or not 1 <= limit <= 500
            or type(expires_at) is not int or expires_at <= int(time.time())):
        raise ValueError("CALCULATION_RESULT_CURSOR_INVALID")
    payload = {
        "format": "openepm-current-calculation-result-cursor-v1",
        "function": function,
        "scope": [scope.workspace_id, scope.application_id],
        "identity": list(identity),
        **normalized,
        "queryDigest": query_digest,
        "after": after,
        "limit": limit,
        "expiresAt": expires_at,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(
        raw + hmac.new(secret, raw, sha256).digest()).decode()


def unpack_current_result_cursor(secret: bytes, token: object, *,
                                 function: str, scope: ApplicationScope,
                                 identity: tuple[str, str]) -> dict:
    if (not isinstance(secret, bytes) or len(secret) < 32
            or not isinstance(token, str) or len(token) > _MAX_CURSOR_BYTES):
        raise ValueError("CALCULATION_RESULT_CURSOR_INVALID")
    try:
        packed = base64.b64decode(token, altchars=b"-_", validate=True)
        raw, signature = packed[:-32], packed[-32:]
        if len(raw) == 0 or not hmac.compare_digest(
                signature, hmac.new(secret, raw, sha256).digest()):
            raise ValueError("signature")
        payload = json.loads(raw)
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error,
            json.JSONDecodeError) as error:
        raise ValueError("CALCULATION_RESULT_CURSOR_INVALID") from error
    expected = {"format", "function", "scope", "identity", "resultKey",
                "resultStateToken", "authorizationStateToken", "queryDigest",
                "after", "limit", "expiresAt"}
    if (not isinstance(payload, dict) or set(payload) != expected
            or payload["format"] != "openepm-current-calculation-result-cursor-v1"
            or payload["function"] != function
            or payload["scope"] != [scope.workspace_id, scope.application_id]
            or payload["identity"] != list(identity)
            or not isinstance(payload["queryDigest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", payload["queryDigest"]) is None
            or not isinstance(payload["after"], str)
            or _AFTER.fullmatch(payload["after"]) is None
            or type(payload["limit"]) is not int
            or not 1 <= payload["limit"] <= 500
            or type(payload["expiresAt"]) is not int
            or payload["expiresAt"] < int(time.time())):
        raise ValueError("CALCULATION_RESULT_CURSOR_INVALID")
    current_result_fence(
        result_key=payload["resultKey"],
        result_state_token=payload["resultStateToken"],
        authorization_state_token=payload["authorizationStateToken"])
    return payload


def require_current_result_fence(cursor: dict, *, result_state_token: object,
                                 authorization_state_token: object) -> None:
    current = current_result_fence(
        result_key=cursor.get("resultKey"),
        result_state_token=result_state_token,
        authorization_state_token=authorization_state_token)
    if current["resultStateToken"] != cursor.get("resultStateToken"):
        raise ValueError("CALCULATION_RESULT_CURSOR_STALE_RESTART")
    if current["authorizationStateToken"] != cursor.get(
            "authorizationStateToken"):
        raise ValueError("CALCULATION_RESULT_AUTHORIZATION_CHANGED_RESTART")
