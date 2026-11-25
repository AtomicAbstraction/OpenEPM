#!/usr/bin/env python3
"""Verify the offline-root-signed Open EPM release/SDK key policy."""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from urllib.parse import urlsplit

try:
    from scripts.build_openepm_sdk_release import verify_ed25519
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from build_openepm_sdk_release import verify_ed25519


class TrustPolicyError(ValueError):
    pass


FORMAT = "openepm-signing-trust-policy-v1"
POLICY_FIELDS = {"format", "status", "sequence", "issuedAt", "expiresAt",
                 "publicationUri", "rotationPolicy", "keys", "revocations"}
KEY_FIELDS = {"keyId", "publicKey", "purposes", "state", "validFrom",
              "validUntil", "overlapUntil"}
REVOCATION_FIELDS = {"keyId", "revokedAt", "reason", "replacementKeyId"}
ROTATION = {"maximumKeyAgeDays": 90, "maximumOverlapDays": 14,
            "emergencyRevocationSlaHours": 4}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")
MAXIMUM_POLICY_BYTES = 1024 * 1024
MAXIMUM_PUBLIC_KEY_BYTES = 16 * 1024
MAXIMUM_SIGNATURE_BYTES = 1024
MAXIMUM_KEYS = 128
MAXIMUM_REVOCATIONS = 4096


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def instant(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise TrustPolicyError(f"{label} must be an exact UTC instant")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TrustPolicyError(f"{label} must be an exact UTC instant") from error
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise TrustPolicyError(f"{label} must be an exact second UTC instant")
    return parsed


def referenced_key(root: Path, record: object, label: str) -> Path:
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise TrustPolicyError(f"invalid {label} reference")
    relative, digest = record["path"], record["sha256"]
    parsed = PurePosixPath(relative) if isinstance(relative, str) else None
    if (parsed is None or parsed.is_absolute() or ".." in parsed.parts
            or len(parsed.parts) != 1 or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None):
        raise TrustPolicyError(f"unsafe {label} reference")
    path = root / parsed.as_posix()
    if (not path.is_file() or path.is_symlink()
            or not 1 <= path.stat().st_size <= MAXIMUM_PUBLIC_KEY_BYTES
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
        raise TrustPolicyError(f"{label} identity mismatch")
    return path


def read_signed_payload(path: Path, label: str, *, expected_sha256: str | None = None,
                        maximum_bytes: int = MAXIMUM_POLICY_BYTES) -> bytes:
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise TrustPolicyError(f"{label} is not a regular file")
            payload = stream.read(maximum_bytes + 1)
    except OSError as error:
        raise TrustPolicyError(f"{label} is unavailable or symbolic") from error
    if not 1 <= len(payload) <= maximum_bytes:
        raise TrustPolicyError(f"{label} trust material is unavailable or invalid")
    if expected_sha256 is not None and hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise TrustPolicyError(f"{label} differs from the expected digest")
    return payload


def selected_key_bytes(policy: dict, key_id: str, path: Path) -> bytes:
    record = next(key for key in policy["keys"] if key["keyId"] == key_id)
    return read_signed_payload(path, f"key {key_id}", expected_sha256=record["publicKey"]["sha256"],
                               maximum_bytes=MAXIMUM_PUBLIC_KEY_BYTES)


def verify_signature(content: Path | bytes, signature: Path, public_key: Path | bytes,
                     label: str) -> None:
    payload = read_signed_payload(content, label) if isinstance(content, Path) else content
    if (not signature.is_file() or signature.is_symlink()
            or not 1 <= signature.stat().st_size <= MAXIMUM_SIGNATURE_BYTES):
        raise TrustPolicyError(f"{label} trust material is unavailable or invalid")
    if isinstance(public_key, Path):
        public_key = read_signed_payload(public_key, label, maximum_bytes=MAXIMUM_PUBLIC_KEY_BYTES)
    try:
        verify_ed25519(payload, signature, public_key)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise TrustPolicyError(f"{label} signature is invalid") from error


def verify(policy_path: Path, *, signature_path: Path, root_public_key: Path,
           now: datetime, minimum_sequence: int) -> dict:
    if now.tzinfo != timezone.utc or now.microsecond:
        raise TrustPolicyError("verification time must be an exact second UTC instant")
    if type(minimum_sequence) is not int or minimum_sequence < 1:
        raise TrustPolicyError("minimum trust-policy sequence is invalid")
    payload = read_signed_payload(policy_path, "signing trust policy")
    verify_signature(payload, signature_path, root_public_key, "signing trust policy")
    try:
        policy = json.loads(payload.decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TrustPolicyError(f"signing trust policy is invalid: {error}") from error
    if (not isinstance(policy, dict) or set(policy) != POLICY_FIELDS
            or policy.get("format") != FORMAT or policy.get("status") != "active"
            or type(policy.get("sequence")) is not int
            or policy["sequence"] < minimum_sequence
            or policy.get("rotationPolicy") != ROTATION
            or canonical(policy) != payload):
        raise TrustPolicyError("signing trust policy contract is invalid or rolled back")
    issued, expires = instant(policy["issuedAt"], "issuedAt"), instant(
        policy["expiresAt"], "expiresAt")
    if not issued <= now < expires or expires > issued + timedelta(days=90):
        raise TrustPolicyError("signing trust policy is not currently valid")
    parsed_uri = urlsplit(policy.get("publicationUri", ""))
    if (parsed_uri.scheme != "https" or not parsed_uri.hostname
            or parsed_uri.username is not None or parsed_uri.password is not None
            or parsed_uri.fragment):
        raise TrustPolicyError("signing trust policy publication URI is invalid")
    keys, revocations = policy.get("keys"), policy.get("revocations")
    if (not isinstance(keys, list) or not 1 <= len(keys) <= MAXIMUM_KEYS
            or not isinstance(revocations, list)
            or len(revocations) > MAXIMUM_REVOCATIONS):
        raise TrustPolicyError("signing trust policy key inventory is invalid")
    by_id: dict[str, dict] = {}
    for key in keys:
        if not isinstance(key, dict) or set(key) != KEY_FIELDS:
            raise TrustPolicyError("signing trust key record is invalid")
        key_id, purposes, state = key["keyId"], key["purposes"], key["state"]
        if (not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None
                or key_id in by_id or not isinstance(purposes, list)
                or not purposes or len(purposes) != len(set(purposes))
                or not set(purposes).issubset({"release", "sdk"})
                or state not in {"active", "overlap", "revoked"}):
            raise TrustPolicyError("signing trust key identity is invalid")
        valid_from = instant(key["validFrom"], f"{key_id}.validFrom")
        valid_until = instant(key["validUntil"], f"{key_id}.validUntil")
        if valid_until <= valid_from or valid_until > valid_from + timedelta(days=90):
            raise TrustPolicyError("signing key age exceeds the selected policy")
        overlap = key["overlapUntil"]
        if state == "overlap":
            overlap_at = instant(overlap, f"{key_id}.overlapUntil")
            if not issued <= overlap_at <= issued + timedelta(days=14):
                raise TrustPolicyError("signing key overlap exceeds the selected policy")
        elif overlap is not None:
            raise TrustPolicyError("non-overlap key contains overlap metadata")
        referenced_key(policy_path.parent, key["publicKey"], f"key {key_id}")
        by_id[key_id] = key
    revoked: set[str] = set()
    for record in revocations:
        if (not isinstance(record, dict) or set(record) != REVOCATION_FIELDS
                or record.get("keyId") not in by_id
                or record["keyId"] in revoked
                or by_id[record["keyId"]]["state"] != "revoked"
                or not isinstance(record.get("reason"), str)
                or not record["reason"].strip()
                or (record.get("replacementKeyId") is not None
                    and record["replacementKeyId"] not in by_id)):
            raise TrustPolicyError("signing key revocation record is invalid")
        instant(record["revokedAt"], f"{record['keyId']}.revokedAt")
        revoked.add(record["keyId"])
    if revoked != {key_id for key_id, key in by_id.items()
                   if key["state"] == "revoked"}:
        raise TrustPolicyError("revoked signing keys lack exact history")
    for purpose in ("release", "sdk"):
        if not any(purpose in key["purposes"] and key["state"] == "active"
                   and instant(key["validFrom"], "validFrom") <= now
                   < instant(key["validUntil"], "validUntil")
                   for key in keys):
            raise TrustPolicyError(f"no current active {purpose} signing key")
    return policy


def select_key(policy_path: Path, policy: dict, *, key_id: str,
               purpose: str, now: datetime) -> Path:
    for key in policy["keys"]:
        if key["keyId"] != key_id:
            continue
        if (purpose not in key["purposes"] or key["state"] == "revoked"
                or not instant(key["validFrom"], "validFrom") <= now
                < instant(key["validUntil"], "validUntil")
                or (key["state"] == "overlap" and now >= instant(
                    key["overlapUntil"], "overlapUntil"))):
            break
        return referenced_key(policy_path.parent, key["publicKey"],
                              f"key {key_id}")
    raise TrustPolicyError("requested signing key is absent, expired or revoked")


def eligible_keys(policy_path: Path, policy: dict, *, purpose: str,
                  now: datetime) -> list[tuple[str, Path]]:
    if purpose not in {"release", "sdk"}:
        raise TrustPolicyError("signing key purpose is invalid")
    result = []
    for key in policy["keys"]:
        try:
            path = select_key(policy_path, policy, key_id=key["keyId"],
                              purpose=purpose, now=now)
        except TrustPolicyError:
            continue
        result.append((key["keyId"], path))
    if not result:
        raise TrustPolicyError(f"no eligible {purpose} signing key")
    return result
