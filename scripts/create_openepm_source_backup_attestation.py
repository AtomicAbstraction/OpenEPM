#!/usr/bin/env python3
"""Create and verify a transferable source-host backup attestation."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
BUNDLE = re.compile(r"openepm-base-[0-9]{8}T[0-9]{6}Z-[0-9]+\Z")
FORMAT = "openepm-source-backup-attestation-v3"
BASE_FIELDS = {"format", "sourceHostIdentity", "bundle",
    "preBackupPopulatedSignature", "manifestSha256", "payloads",
    "encryptedArtifactSha256", "encryptedPayloadCount", "totalBytes",
    "attestationHmac"}
FIELDS = BASE_FIELDS
CHUNK = 1024 * 1024
MAX_TREE_FILES = 100_000
MAX_TREE_BYTES = 100 * 1024 * 1024 * 1024


class AttestationError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()








def protected_key(path: Path) -> bytes:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or os.stat(path, follow_symlinks=False).st_mode & 0o077):
        raise AttestationError("attestation key must be an absolute protected file")
    key = path.read_bytes()
    if not 32 <= len(key) <= 4096:
        raise AttestationError("attestation key size is invalid")
    return key


def host_identity(path: Path = Path("/etc/machine-id")) -> str:
    try:
        value = path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as error:
        raise AttestationError("source host identity is unavailable") from error
    if not re.fullmatch(r"[0-9a-f]{32}", value) or value == "0" * 32:
        raise AttestationError("source host identity is invalid")
    return hashlib.sha256(("openepm-clean-host-v1:" + value).encode()).hexdigest()


def _bundle(root: Path, name: str, maximum_bytes: int) -> tuple[Path, dict, list[dict]]:
    if (not root.is_absolute() or root.is_symlink() or not root.is_dir()
            or not isinstance(name, str) or not BUNDLE.fullmatch(name)
            or type(maximum_bytes) is not int or maximum_bytes < 1):
        raise AttestationError("backup source or bound is invalid")
    bundle = root / name
    if bundle.is_symlink() or not bundle.is_dir():
        raise AttestationError("backup bundle is unavailable")
    manifest_path = bundle / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise AttestationError("backup manifest is unavailable")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AttestationError("backup manifest is invalid") from error
    payloads = manifest.get("payloads") if isinstance(manifest, dict) else None
    if not isinstance(payloads, list) or not payloads:
        raise AttestationError("backup manifest has no payloads")
    records, names, total = [], set(), 0
    for item in payloads:
        name_value = item.get("name") if isinstance(item, dict) else None
        cipher = item.get("cipherSha256") if isinstance(item, dict) else None
        parsed = PurePosixPath(name_value) if isinstance(name_value, str) else None
        if (parsed is None or parsed.is_absolute() or len(parsed.parts) != 1
                or not name_value.endswith(".enc") or name_value in names
                or not isinstance(cipher, str) or not SHA256.fullmatch(cipher)):
            raise AttestationError("encrypted payload record is invalid")
        path = bundle / name_value
        if path.is_symlink() or not path.is_file():
            raise AttestationError("encrypted payload is unavailable")
        size = path.stat().st_size
        total += size
        if size < 1 or total > maximum_bytes or digest(path) != cipher:
            raise AttestationError("encrypted payload identity is invalid")
        names.add(name_value)
        records.append({"name": name_value, "sha256": cipher, "sizeBytes": size})
    records.sort(key=lambda item: item["name"])
    return manifest_path, manifest, records


def create(*, backup_root: Path, bundle: str, key_file: Path,
           population_signature: str, maximum_bytes: int,
           machine_id: Path = Path("/etc/machine-id")) -> dict:
    if not isinstance(population_signature, str) or not SHA256.fullmatch(
            population_signature):
        raise AttestationError("population signature is invalid")
    manifest_path, manifest, payloads = _bundle(
        backup_root, bundle, maximum_bytes)
    value = {"format": FORMAT,
        "sourceHostIdentity": host_identity(machine_id),
        "bundle": bundle, "preBackupPopulatedSignature": population_signature,
        "manifestSha256": digest(manifest_path), "payloads": payloads,
        "encryptedArtifactSha256": hashlib.sha256(canonical(payloads)).hexdigest(),
        "encryptedPayloadCount": len(payloads),
        "totalBytes": sum(item["sizeBytes"] for item in payloads)}
    value["attestationHmac"] = hmac.new(
        protected_key(key_file), canonical(value), hashlib.sha256).hexdigest()
    return value


def verify(value: object, *, backup_root: Path, key_file: Path,
           maximum_bytes: int) -> dict:
    if (not isinstance(value, dict)
            or value.get("format") != FORMAT
            or set(value) != FIELDS):
        raise AttestationError("source backup attestation is invalid")
    signature = value.get("attestationHmac")
    unsigned = {key: item for key, item in value.items()
                if key != "attestationHmac"}
    if (not isinstance(signature, str) or not SHA256.fullmatch(signature)
            or not hmac.compare_digest(signature, hmac.new(
                protected_key(key_file), canonical(unsigned),
                hashlib.sha256).hexdigest())):
        raise AttestationError("source backup attestation HMAC is invalid")
    identity = value.get("sourceHostIdentity")
    population = value.get("preBackupPopulatedSignature")
    if (not isinstance(identity, str) or not SHA256.fullmatch(identity)
            or not isinstance(population, str) or not SHA256.fullmatch(population)):
        raise AttestationError("source backup identities are invalid")
    manifest_path, manifest, payloads = _bundle(
        backup_root, value.get("bundle"), maximum_bytes)
    expected = {"manifestSha256": digest(manifest_path), "payloads": payloads,
        "encryptedArtifactSha256": hashlib.sha256(canonical(payloads)).hexdigest(),
        "encryptedPayloadCount": len(payloads),
        "totalBytes": sum(item["sizeBytes"] for item in payloads)}
    if any(value.get(key) != item for key, item in expected.items()):
        raise AttestationError("transferred backup differs from source attestation")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--population-signature", required=True)
    parser.add_argument("--maximum-bytes", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.output.exists() or arguments.output.is_symlink():
        parser.error("output already exists")
    try:
        value = create(backup_root=arguments.backup_root.resolve(),
            bundle=arguments.bundle, key_file=arguments.key_file,
            population_signature=arguments.population_signature,
            maximum_bytes=arguments.maximum_bytes)
    except AttestationError as error:
        parser.error(str(error))
    arguments.output.write_bytes(canonical(value) + b"\n")
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
