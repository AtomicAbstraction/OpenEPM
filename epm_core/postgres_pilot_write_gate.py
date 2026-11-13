"""Replay-safe signed write-admission defence for a pilot activation.

This is one layer of the activation boundary, not the database privilege gate.
When enabled it makes every newly opened application connection read-only unless
the current, trusted executor has signed either a ``finalizing``/``active``
green-slot authority or a ``rolled-back`` blue-slot authority. A
``rolling-back`` blue authority remains closed. Finalizing is the bounded
publication interval after the routing pointer is durable; host controls still
keep external ingress stopped until the candidate has been verified.
The host adapter must independently revoke mutation privileges and terminate
all old service sessions before quiescence; it restores the reviewed grants
only after the irreversible activation decision.

The authority directory is a fixed root-owned read-only mount. A separate
shared persistent checkpoint prevents a previously valid open authority
from being replayed after a newer close, including after process restart.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from threading import Lock
from typing import Mapping
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SHA = re.compile(r"^[0-9a-f]{64}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
MAX_STATE_BYTES = 64 * 1024
AUTHORITY_DIRECTORY = Path("/run/openepm-pilot")
CHECKPOINT_DIRECTORY = Path("/var/lib/openepm/write-gate")
GATE_FILENAME = "write-gate.json"
TRUST_FILENAME = "executor-trust.json"
CHECKPOINT_FILENAME = "write-gate-checkpoint.json"
LOCK_FILENAME = "write-gate-checkpoint.lock"
GATE_KEYS = {
    "format", "generation", "previousGateSha256", "state", "slot",
    "authorityState", "activationId", "executionContractSha256",
    "authorityEventSha256", "trustRegistrySha256", "keyId", "keyVersion",
    "gateSha256", "signature",
}
TRUST_KEYS = {
    "format", "keyId", "keyVersion", "role", "publicKeyBase64",
    "notBeforeUtc", "expiresAtUtc", "revoked", "trustRegistrySha256",
}
CHECKPOINT_KEYS = {
    "format", "activationId", "executionContractSha256", "generation",
    "gateSha256", "checkpointSha256",
}
_CHECKPOINT_LOCK = Lock()


@dataclass(frozen=True)
class WriteGateDecision:
    required: bool
    writes_admitted: bool
    reason: str
    generation: int | None = None


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise ValueError("UTC authority time is invalid")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc)


def _required(environment: Mapping[str, str]) -> bool:
    value = environment.get("EPM_PILOT_REQUIRE_WRITE_GATE")
    return value not in (None, "0")


def _expected(environment: Mapping[str, str], name: str,
              pattern: re.Pattern[str]) -> str:
    value = environment.get(name)
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")
    return value


def _open_directory(path: Path, *, writable: bool, owner_uid: int) -> int:
    if not path.is_absolute():
        raise ValueError("write-gate directory is not absolute")
    descriptor = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_CLOEXEC", 0))
    try:
        for component in path.parts[1:]:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) \
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) \
                    or metadata.st_uid not in (0, owner_uid) \
                    or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError("write-gate directory ancestry is unsafe")
        final = os.fstat(descriptor)
        mode = stat.S_IMODE(final.st_mode)
        if writable:
            if final.st_uid != owner_uid or mode != 0o700:
                raise ValueError("write-gate checkpoint directory is unsafe")
        elif final.st_uid != owner_uid or mode & 0o222:
            raise ValueError("write-gate authority directory is unsafe")
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_file(directory_fd: int, filename: str, *, public: bool,
               owner_uid: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(filename, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 \
                or metadata.st_uid != owner_uid \
                or metadata.st_size < 1 or metadata.st_size > MAX_STATE_BYTES \
                or mode & 0o222 \
                or (not public and mode & (stat.S_IRGRP | stat.S_IROTH)):
            raise ValueError(f"protected {filename} is unsafe")
        chunks: list[bytes] = []
        remaining = MAX_STATE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0:
            raise ValueError(f"protected {filename} is oversized")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_canonical_json(directory_fd: int, filename: str, *, public: bool,
                         owner_uid: int) -> dict:
    raw = _read_file(directory_fd, filename, public=public, owner_uid=owner_uid)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or raw != _canonical(value):
        raise ValueError(f"protected {filename} is not canonical")
    return value


def _write_checkpoint(directory_fd: int, value: dict) -> None:
    payload = _canonical(value)
    temporary = f".{CHECKPOINT_FILENAME}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL \
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise OSError("checkpoint write made no progress")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, CHECKPOINT_FILENAME, src_dir_fd=directory_fd,
                   dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def _checkpoint(directory_fd: int, gate: dict) -> None:
    try:
        current = _read_canonical_json(
            directory_fd, CHECKPOINT_FILENAME, public=False,
            owner_uid=os.getuid())
    except FileNotFoundError:
        current = None
    if current is not None:
        if set(current) != CHECKPOINT_KEYS \
                or current.get("format") \
                    != "openepm-macos-pilot-write-gate-checkpoint-v1" \
                or current.get("activationId") != gate["activationId"] \
                or current.get("executionContractSha256") \
                    != gate["executionContractSha256"] \
                or not isinstance(current.get("generation"), int) \
                or isinstance(current.get("generation"), bool) \
                or current["generation"] < 1 \
                or SHA.fullmatch(str(current.get("gateSha256"))) is None \
                or current.get("checkpointSha256") != _digest({
                    key: value for key, value in current.items()
                    if key != "checkpointSha256"}):
            raise ValueError("write-gate checkpoint is invalid")
        if gate["generation"] < current["generation"] \
                or gate["generation"] == current["generation"] \
                and gate["gateSha256"] != current["gateSha256"] \
                or gate["generation"] > current["generation"] + 1 \
                or gate["generation"] == current["generation"] + 1 \
                and gate["previousGateSha256"] != current["gateSha256"]:
            raise ValueError("write-gate authority rolled back or equivocated")
        if gate["generation"] == current["generation"]:
            return
    elif gate["generation"] != 1 or gate["previousGateSha256"] != "0" * 64:
        raise ValueError("initial write-gate authority is not the chain root")
    body = {
        "format": "openepm-macos-pilot-write-gate-checkpoint-v1",
        "activationId": gate["activationId"],
        "executionContractSha256": gate["executionContractSha256"],
        "generation": gate["generation"], "gateSha256": gate["gateSha256"],
    }
    _write_checkpoint(directory_fd, {**body, "checkpointSha256": _digest(body)})


def _checkpoint_lock(directory_fd: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) \
        | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(LOCK_FILENAME, flags, 0o600, dir_fd=directory_fd)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 \
            or metadata.st_uid != os.getuid() \
            or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(descriptor)
        raise ValueError("write-gate checkpoint lock is unsafe")
    # Connection creation must never wait behind a paused peer. Contention is
    # an unavailable authority and therefore fails closed immediately.
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def evaluate_write_gate(environment: Mapping[str, str] | None = None, *,
        authority_directory: Path = AUTHORITY_DIRECTORY,
        checkpoint_directory: Path = CHECKPOINT_DIRECTORY,
        authority_owner_uid: int = 0,
        now: datetime | None = None) -> WriteGateDecision:
    """Return an explainable decision; any opted-in error is read-only."""
    env = os.environ if environment is None else environment
    if not _required(env):
        return WriteGateDecision(False, True, "write gate is not required")
    authority_fd: int | None = None
    checkpoint_fd: int | None = None
    try:
        expected_activation = _expected(
            env, "EPM_PILOT_WRITE_GATE_ACTIVATION_ID", IDENTITY)
        expected_contract = _expected(
            env, "EPM_PILOT_WRITE_GATE_EXECUTION_CONTRACT_SHA256", SHA)
        expected_trust = _expected(
            env, "EPM_PILOT_WRITE_GATE_TRUST_REGISTRY_SHA256", SHA)
        expected_event = _expected(
            env, "EPM_PILOT_WRITE_GATE_AUTHORITY_EVENT_SHA256", SHA)
        authority_fd = _open_directory(Path(authority_directory), writable=False,
                                       owner_uid=authority_owner_uid)
        checkpoint_fd = _open_directory(Path(checkpoint_directory), writable=True,
                                        owner_uid=os.getuid())
        trust = _read_canonical_json(authority_fd, TRUST_FILENAME, public=True,
                                     owner_uid=authority_owner_uid)
        if set(trust) != TRUST_KEYS \
                or trust.get("format") \
                    != "openepm-macos-pilot-executor-trust-v1" \
                or trust.get("role") != "executor" \
                or not isinstance(trust.get("keyId"), str) \
                or IDENTITY.fullmatch(trust["keyId"]) is None \
                or not isinstance(trust.get("keyVersion"), int) \
                or isinstance(trust.get("keyVersion"), bool) \
                or trust["keyVersion"] < 1 \
                or not isinstance(trust.get("revoked"), bool) \
                or trust.get("trustRegistrySha256") != _digest({
                    key: value for key, value in trust.items()
                    if key != "trustRegistrySha256"}) \
                or trust["trustRegistrySha256"] != expected_trust:
            raise ValueError("executor trust registry is invalid")
        instant = datetime.now(timezone.utc) if now is None else now
        if instant.tzinfo is None or trust["revoked"] \
                or not (_utc(trust["notBeforeUtc"]) <= instant
                        < _utc(trust["expiresAtUtc"])):
            raise ValueError("executor trust is not current")
        try:
            public_bytes = base64.b64decode(trust["publicKeyBase64"], validate=True)
            if len(public_bytes) != 32:
                raise ValueError("executor public key length differs")
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        except (TypeError, ValueError) as error:
            raise ValueError("executor public key is invalid") from error

        gate = _read_canonical_json(authority_fd, GATE_FILENAME, public=True,
                                    owner_uid=authority_owner_uid)
        generation = gate.get("generation")
        key_version = gate.get("keyVersion")
        if set(gate) != GATE_KEYS \
                or gate.get("format") != "openepm-macos-pilot-write-gate-v1" \
                or not isinstance(generation, int) or isinstance(generation, bool) \
                or generation < 1 \
                or SHA.fullmatch(str(gate.get("previousGateSha256"))) is None \
                or gate.get("state") not in ("open", "closed") \
                or gate.get("slot") not in ("blue", "green") \
                or gate.get("authorityState") not in (
                    "preparing", "read-only", "rolling-back", "rolled-back",
                    "committed", "finalizing", "active") \
                or gate.get("activationId") != expected_activation \
                or gate.get("executionContractSha256") != expected_contract \
                or gate.get("authorityEventSha256") != expected_event \
                or gate.get("trustRegistrySha256") != expected_trust \
                or gate.get("keyId") != trust["keyId"] \
                or not isinstance(key_version, int) \
                or isinstance(key_version, bool) \
                or key_version != trust["keyVersion"]:
            raise ValueError("write-gate authority differs")
        unsigned = {key: value for key, value in gate.items()
                    if key not in ("gateSha256", "signature")}
        claimed = gate.get("gateSha256")
        signature = gate.get("signature")
        if claimed != _digest(unsigned) \
                or not isinstance(signature, str) \
                or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
            raise ValueError("write-gate digest or signature is invalid")
        public_key.verify(bytes.fromhex(signature),
                          _canonical({**unsigned, "gateSha256": claimed}))
        admitted = gate["state"] == "open" and (
            gate["slot"] == "green"
            and gate["authorityState"] in ("finalizing","active")
            or gate["slot"] == "blue"
            and gate["authorityState"] == "rolled-back")
        with _CHECKPOINT_LOCK:
            lock_fd = _checkpoint_lock(checkpoint_fd)
            try:
                _checkpoint(checkpoint_fd, gate)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
        return WriteGateDecision(True, admitted,
            "signed slot-specific write gate is open" if admitted
            else "signed write gate is closed", generation)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError,
            InvalidSignature) as error:
        return WriteGateDecision(True, False,
            f"write gate failed closed: {type(error).__name__}")
    finally:
        if checkpoint_fd is not None:
            os.close(checkpoint_fd)
        if authority_fd is not None:
            os.close(authority_fd)


def writes_admitted(environment: Mapping[str, str] | None = None, **kwargs) -> bool:
    return evaluate_write_gate(environment, **kwargs).writes_admitted
