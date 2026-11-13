"""Build and verify a signed, deterministic Open EPM SDK release envelope.

The private signing key is supplied by the release operator and is never copied
into the output.  Ed25519 is delegated to the host OpenSSL implementation so
this release tool does not add a runtime dependency to the public SDK.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

try:
    from scripts.build_openepm_sdk_wheel import VERSION, WHEEL, build
except ModuleNotFoundError as error:
    # Release entrypoints are supported both as imported project modules and
    # as direct ``python3 scripts/<entrypoint>.py`` operator commands.  The
    # latter puts ``scripts/`` rather than the repository root on sys.path.
    if error.name != "scripts":
        raise
    from build_openepm_sdk_wheel import VERSION, WHEEL, build


FORMAT = "openepm-sdk-release-v1"
MANIFEST = "openepm-sdk-release.json"
SIGNATURE = "openepm-sdk-release.json.ed25519"
CHECKSUMS = "SHA256SUMS"


def openssl_binary() -> str:
    """Resolve an OpenSSL implementation that actually supports Ed25519.

    macOS /usr/bin/openssl is LibreSSL on supported developer hosts and does
    not implement Ed25519 key generation or pkeyutl signing.  Capability, not
    the executable name or version string, is the release requirement.
    """
    configured = os.environ.get("OPEN_EPM_OPENSSL")
    if configured:
        candidates = [configured]
    else:
        candidates = [shutil.which("openssl"),
                      "/opt/homebrew/opt/openssl@3/bin/openssl",
                      "/usr/local/opt/openssl@3/bin/openssl"]
    observed: set[str] = set()
    for candidate in candidates:
        if not candidate:
            continue
        path = str(Path(candidate).expanduser().resolve())
        if path in observed or not Path(path).is_file():
            continue
        observed.add(path)
        probe = subprocess.run(
            [path, "list", "-public-key-algorithms"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False)
        if probe.returncode == 0 and b"ED25519" in probe.stdout.upper():
            return path
    raise ValueError("OPEN_EPM_SDK_ED25519_OPENSSL_UNAVAILABLE")


def _hash(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _run(*arguments: str) -> None:
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=False)
    if result.returncode:
        raise ValueError("OPEN_EPM_SDK_SIGNATURE_INVALID")


def _tracked_sources(source_root: Path) -> dict[str, str]:
    paths = [source_root / "pyproject.toml",
             source_root / "scripts/build_openepm_sdk_wheel.py",
             source_root / "scripts/build_openepm_sdk_release.py"]
    paths.extend(sorted((source_root / "openepm").glob("*.py")))
    if any(not path.is_file() or path.is_symlink() for path in paths):
        raise ValueError("OPEN_EPM_SDK_RELEASE_SOURCE_INVALID")
    return {path.relative_to(source_root).as_posix(): _hash(path) for path in paths}


def build_release(source_root: Path, destination: Path, *, source_commit: str,
                  private_key: Path, public_key: Path,
                  signing_key_id: str) -> dict:
    source_root, destination = source_root.resolve(), destination.resolve()
    if (not isinstance(source_commit, str) or len(source_commit) != 40
            or any(character not in "0123456789abcdef" for character in source_commit)
            or not isinstance(signing_key_id, str)
            or not 1 <= len(signing_key_id) <= 200
            or any(ord(character) < 33 or ord(character) > 126
                   for character in signing_key_id)):
        raise ValueError("OPEN_EPM_SDK_RELEASE_IDENTITY_INVALID")
    if (not private_key.is_file() or private_key.is_symlink()
            or not public_key.is_file() or public_key.is_symlink()):
        raise ValueError("OPEN_EPM_SDK_SIGNING_KEY_INVALID")
    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
    wheel = build(source_root, destination)
    sources = _tracked_sources(source_root)
    source_digest = sha256(_canonical(sources)).hexdigest()
    manifest = {
        "format": FORMAT,
        "package": {"name": "openepm-sdk", "version": VERSION,
                    "filename": WHEEL, "sha256": _hash(wheel),
                    "sizeBytes": wheel.stat().st_size,
                    "pythonTag": "py3-none-any"},
        "source": {"declaredCommit": source_commit,
                   "commitProvenance": "operator-declared; file hashes are authoritative",
                   "treeDigest": source_digest, "files": sources},
        "build": {"dependencyFree": True, "publicPackageOnly": "openepm",
                  "trustedCoreIncluded": False,
                  "databaseDriverIncluded": False,
                  "reproducibleTimestamp": "2026-10-28T00:00:00Z"},
        "signing": {"algorithm": "Ed25519", "keyId": signing_key_id,
                    "publicKeySha256": _hash(public_key)},
    }
    manifest_path = destination / MANIFEST
    manifest_path.write_bytes(_canonical(manifest))
    signature_path = destination / SIGNATURE
    openssl = openssl_binary()
    _run(openssl, "pkeyutl", "-sign", "-rawin", "-inkey",
         str(private_key.resolve()), "-in", str(manifest_path),
         "-out", str(signature_path))
    _run(openssl, "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
         str(public_key.resolve()), "-in", str(manifest_path),
         "-sigfile", str(signature_path))
    checksums = destination / CHECKSUMS
    checksums.write_text("".join(
        f"{_hash(destination / name)}  {name}\n"
        for name in (WHEEL, MANIFEST, SIGNATURE)), encoding="ascii")
    verify_release(destination, public_key=public_key)
    return manifest


def verify_release(directory: Path, *, public_key: Path) -> dict:
    directory, public_key = directory.resolve(), public_key.resolve()
    expected_names = {WHEEL, MANIFEST, SIGNATURE, CHECKSUMS}
    actual_names = {path.name for path in directory.iterdir() if path.is_file()}
    if actual_names != expected_names or not public_key.is_file() or public_key.is_symlink():
        raise ValueError("OPEN_EPM_SDK_RELEASE_FILES_INVALID")
    manifest_path = directory / MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("OPEN_EPM_SDK_RELEASE_MANIFEST_INVALID") from error
    if _canonical(manifest) != manifest_path.read_bytes():
        raise ValueError("OPEN_EPM_SDK_RELEASE_MANIFEST_NONCANONICAL")
    if (not isinstance(manifest, dict) or set(manifest) !=
            {"format", "package", "source", "build", "signing"}
            or manifest.get("format") != FORMAT
            or manifest.get("package", {}).get("name") != "openepm-sdk"
            or manifest.get("package", {}).get("version") != VERSION
            or manifest.get("package", {}).get("filename") != WHEEL
            or manifest.get("package", {}).get("sha256") != _hash(directory / WHEEL)
            or manifest.get("package", {}).get("sizeBytes") !=
                (directory / WHEEL).stat().st_size
            or manifest.get("signing", {}).get("algorithm") != "Ed25519"
            or manifest.get("signing", {}).get("publicKeySha256") != _hash(public_key)):
        raise ValueError("OPEN_EPM_SDK_RELEASE_MANIFEST_INVALID")
    expected_checksums = "".join(
        f"{_hash(directory / name)}  {name}\n"
        for name in (WHEEL, MANIFEST, SIGNATURE))
    if (directory / CHECKSUMS).read_text(encoding="ascii") != expected_checksums:
        raise ValueError("OPEN_EPM_SDK_RELEASE_CHECKSUM_INVALID")
    _run(openssl_binary(), "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey",
         str(public_key), "-in", str(manifest_path),
         "-sigfile", str(directory / SIGNATURE))
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--signing-key-id", required=True)
    arguments = parser.parse_args()
    build_release(arguments.source_root, arguments.destination,
                  source_commit=arguments.source_commit,
                  private_key=arguments.private_key,
                  public_key=arguments.public_key,
                  signing_key_id=arguments.signing_key_id)
    print(arguments.destination.resolve() / MANIFEST)


if __name__ == "__main__":
    main()
