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
LEGACY_FORMAT = "openepm-source-backup-attestation-v1"
FORMAT = "openepm-source-backup-attestation-v2"
BASE_FIELDS = {"format", "sourceHostIdentity", "bundle",
    "preBackupPopulatedSignature", "manifestSha256", "payloads",
    "encryptedArtifactSha256", "encryptedPayloadCount", "totalBytes",
    "attestationHmac"}
FIELDS = BASE_FIELDS | {"notebookRecovery"}
CHUNK = 1024 * 1024
MAX_TREE_FILES = 100_000
MAX_TREE_BYTES = 100 * 1024 * 1024 * 1024
PRODUCTION_NOTEBOOK_ROOT = Path("/var/lib/openepm/notebooks/current")


class AttestationError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    """Match the release backup's deterministic auxiliary-tree identity."""
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise AttestationError("notebook storage root is invalid")
    entries, total = [], 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "secrets/backup_encryption_key":
            continue
        mode = path.lstat().st_mode
        if (not relative or relative.startswith("/") or ".." in relative.split("/")
                or path.name == "backup_encryption_key"):
            raise AttestationError("notebook storage contains an unsupported entry")
        if stat.S_ISDIR(mode):
            entries.append((relative, path, True))
        elif stat.S_ISREG(mode):
            size = path.stat().st_size
            total += size
            entries.append((relative, path, False))
        else:
            raise AttestationError("notebook storage contains an unsupported entry")
        if len(entries) > MAX_TREE_FILES or total > MAX_TREE_BYTES:
            raise AttestationError("notebook storage exceeds backup limits")
    value = hashlib.sha256()
    for relative, path, directory in entries:
        value.update(("d\0" if directory else "f\0").encode())
        value.update(relative.encode("utf-8")); value.update(b"\0")
        if not directory:
            value.update(str(path.stat().st_size).encode()); value.update(b"\0")
            with path.open("rb") as stream:
                while block := stream.read(CHUNK):
                    value.update(block)
    return value.hexdigest()


def _notebook_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 1024:
        raise AttestationError("notebook recovery path is invalid")
    parsed = PurePosixPath(value)
    if (parsed.is_absolute() or not parsed.parts
            or any(part in ("", ".", "..") for part in parsed.parts)
            or not value.endswith(".ipynb") or "\x00" in value):
        raise AttestationError("notebook recovery path is invalid")
    return parsed


def notebook_recovery(manifest: dict, *, storage_root: Path,
                      username: str, relative_path: str) -> dict:
    match = re.fullmatch(r"u-([0-9a-f]{32})", username)
    if match is None:
        raise AttestationError("notebook recovery username is invalid")
    relative = _notebook_path(relative_path)
    if not storage_root.is_absolute() or storage_root.is_symlink() \
            or not storage_root.is_dir():
        raise AttestationError("notebook storage root is invalid")
    payloads = manifest.get("payloads") if isinstance(manifest, dict) else None
    records = [item for item in payloads or [] if isinstance(item, dict)
               and item.get("name") == "notebooks.tar.enc"]
    if len(records) != 1 or not isinstance(records[0].get("treeSha256"), str) \
            or not SHA256.fullmatch(records[0]["treeSha256"]):
        raise AttestationError("backup manifest has no notebook tree identity")
    current_tree = tree_digest(storage_root)
    if current_tree != records[0]["treeSha256"]:
        raise AttestationError("live notebook tree differs from backup snapshot")
    target = storage_root / "users" / match.group(1) / Path(*relative.parts)
    current = storage_root
    for part in ("users", match.group(1), *relative.parts):
        current = current / part
        try:
            mode = current.lstat().st_mode
        except OSError as error:
            raise AttestationError("source notebook is unavailable") from error
        if stat.S_ISLNK(mode):
            raise AttestationError("source notebook path is symbolic")
    if not target.is_file() or target.stat().st_size > 1024 * 1024:
        raise AttestationError("source notebook is unavailable or oversized")
    try:
        value = json.loads(target.read_text(encoding="utf-8"))
        canonical_content = json.dumps(value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False).encode("ascii")
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError,
            ValueError) as error:
        raise AttestationError("source notebook is invalid JSON") from error
    if (not isinstance(value, dict) or not isinstance(value.get("cells"), list)
            or type(value.get("nbformat")) is not int
            or value["nbformat"] < 4):
        raise AttestationError("source notebook JSON is not a notebook")
    if tree_digest(storage_root) != current_tree:
        raise AttestationError("notebook tree changed during attestation")
    return {"hubUsername": username, "relativePath": relative.as_posix(),
        "canonicalContentSha256": hashlib.sha256(canonical_content).hexdigest(),
        "notebookTreeSha256": current_tree}


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
           machine_id: Path = Path("/etc/machine-id"),
           notebook_storage_root: Path | None = None,
           notebook_username: str | None = None,
           notebook_relative_path: str | None = None) -> dict:
    if not isinstance(population_signature, str) or not SHA256.fullmatch(
            population_signature):
        raise AttestationError("population signature is invalid")
    manifest_path, manifest, payloads = _bundle(
        backup_root, bundle, maximum_bytes)
    configured = (notebook_storage_root, notebook_username,
                  notebook_relative_path)
    if any(item is not None for item in configured) \
            and not all(item is not None for item in configured):
        raise AttestationError("notebook recovery arguments must be all or none")
    recovery = None if notebook_storage_root is None else notebook_recovery(
        manifest, storage_root=notebook_storage_root,
        username=notebook_username, relative_path=notebook_relative_path)
    value = {"format": FORMAT if recovery is not None else LEGACY_FORMAT,
        "sourceHostIdentity": host_identity(machine_id),
        "bundle": bundle, "preBackupPopulatedSignature": population_signature,
        "manifestSha256": digest(manifest_path), "payloads": payloads,
        "encryptedArtifactSha256": hashlib.sha256(canonical(payloads)).hexdigest(),
        "encryptedPayloadCount": len(payloads),
        "totalBytes": sum(item["sizeBytes"] for item in payloads)}
    if recovery is not None:
        value["notebookRecovery"] = recovery
    value["attestationHmac"] = hmac.new(
        protected_key(key_file), canonical(value), hashlib.sha256).hexdigest()
    return value


def verify(value: object, *, backup_root: Path, key_file: Path,
           maximum_bytes: int) -> dict:
    if (not isinstance(value, dict)
            or value.get("format") not in (LEGACY_FORMAT, FORMAT)
            or set(value) != (BASE_FIELDS if value.get("format") == LEGACY_FORMAT
                              else FIELDS)):
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
    if value["format"] == FORMAT:
        recovery = value.get("notebookRecovery")
        if (not isinstance(recovery, dict) or set(recovery) != {
                "hubUsername", "relativePath", "canonicalContentSha256",
                "notebookTreeSha256"}
                or re.fullmatch(r"u-[0-9a-f]{32}",
                                recovery.get("hubUsername", "")) is None
                or _notebook_path(recovery.get("relativePath", "")).as_posix()
                    != recovery.get("relativePath")
                or not isinstance(recovery.get("canonicalContentSha256"), str)
                or not SHA256.fullmatch(recovery["canonicalContentSha256"])
                or not isinstance(recovery.get("notebookTreeSha256"), str)
                or not SHA256.fullmatch(recovery["notebookTreeSha256"])):
            raise AttestationError("notebook recovery attestation is invalid")
        records = [item for item in manifest.get("payloads", [])
                   if isinstance(item, dict)
                   and item.get("name") == "notebooks.tar.enc"]
        if len(records) != 1 or records[0].get("treeSha256") != \
                recovery["notebookTreeSha256"]:
            raise AttestationError(
                "notebook recovery differs from backup manifest")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backup-root", type=Path, required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--population-signature", required=True)
    parser.add_argument("--maximum-bytes", type=int, required=True)
    parser.add_argument("--notebook-username")
    parser.add_argument("--notebook-relative-path")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.output.exists() or arguments.output.is_symlink():
        parser.error("output already exists")
    try:
        value = create(backup_root=arguments.backup_root.resolve(),
            bundle=arguments.bundle, key_file=arguments.key_file,
            population_signature=arguments.population_signature,
            maximum_bytes=arguments.maximum_bytes,
            notebook_storage_root=(PRODUCTION_NOTEBOOK_ROOT
                if arguments.notebook_username is not None
                or arguments.notebook_relative_path is not None else None),
            notebook_username=arguments.notebook_username,
            notebook_relative_path=arguments.notebook_relative_path)
    except AttestationError as error:
        parser.error(str(error))
    arguments.output.write_bytes(canonical(value) + b"\n")
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
