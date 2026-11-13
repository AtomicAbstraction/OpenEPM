#!/usr/bin/env python3
"""Build and self-verify an offline-root-signed Open EPM trust-policy bundle.

The operator supplies pre-provisioned public keys and an offline root private
key. This tool never generates, copies or retains private key material.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

try:
    from scripts.build_openepm_sdk_release import openssl_binary
    from scripts.openepm_signing_trust_policy import (
        FORMAT, ROTATION, TrustPolicyError, canonical, verify,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from build_openepm_sdk_release import openssl_binary
    from openepm_signing_trust_policy import (  # type: ignore[no-redef]
        FORMAT, ROTATION, TrustPolicyError, canonical, verify,
    )


class PolicyBuildError(ValueError):
    pass


INPUT_FORMAT = "openepm-signing-trust-policy-input-v1"
POLICY_NAME = "signing-trust-policy.json"
SIGNATURE_NAME = "signing-trust-policy.sig"
INPUT_FIELDS = {"format", "sequence", "issuedAt", "expiresAt",
                "publicationUri", "keys", "revocations"}
INPUT_KEY_FIELDS = {"keyId", "publicKey", "purposes", "state", "validFrom",
                    "validUntil", "overlapUntil"}


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PolicyBuildError(f"signing policy input is invalid: {error}") from error
    if (not isinstance(value, dict) or set(value) != INPUT_FIELDS
            or value.get("format") != INPUT_FORMAT):
        raise PolicyBuildError("signing policy input fields are invalid")
    return value


def public_key(source_root: Path, value: object, output: Path,
               seen: set[str]) -> dict:
    parsed = PurePosixPath(value) if isinstance(value, str) else None
    if (parsed is None or parsed.is_absolute() or ".." in parsed.parts
            or len(parsed.parts) != 1 or parsed.name in seen):
        raise PolicyBuildError("public key path is unsafe or repeated")
    source = source_root / parsed.name
    if not source.is_file() or source.is_symlink():
        raise PolicyBuildError("public key is missing or symbolic")
    seen.add(parsed.name)
    destination = output / parsed.name
    shutil.copyfile(source, destination)
    destination.chmod(0o444)
    return {"path": parsed.name,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()}


def build(input_path: Path, *, output: Path, root_private_key: Path,
          root_public_key: Path, now: datetime) -> dict:
    if output.exists() or output.is_symlink():
        raise PolicyBuildError("output directory already exists")
    for path, label in ((root_private_key, "offline root private key"),
                        (root_public_key, "offline root public key")):
        if not path.is_file() or path.is_symlink():
            raise PolicyBuildError(f"{label} is missing or symbolic")
    source = load(input_path)
    keys = source.get("keys")
    if not isinstance(keys, list) or not keys:
        raise PolicyBuildError("signing policy input key inventory is invalid")
    output.mkdir(mode=0o700)
    try:
        records = []
        seen: set[str] = set()
        for key in keys:
            if not isinstance(key, dict) or set(key) != INPUT_KEY_FIELDS:
                raise PolicyBuildError("signing policy input key is invalid")
            record = dict(key)
            record["publicKey"] = public_key(input_path.parent,
                key["publicKey"], output, seen)
            records.append(record)
        policy = {"format": FORMAT, "status": "active",
            "sequence": source["sequence"], "issuedAt": source["issuedAt"],
            "expiresAt": source["expiresAt"],
            "publicationUri": source["publicationUri"],
            "rotationPolicy": ROTATION, "keys": records,
            "revocations": source["revocations"]}
        policy_path = output / POLICY_NAME
        signature_path = output / SIGNATURE_NAME
        policy_path.write_bytes(canonical(policy))
        policy_path.chmod(0o444)
        result = subprocess.run([openssl_binary(), "pkeyutl", "-sign",
            "-rawin", "-inkey", str(root_private_key.resolve()), "-in",
            str(policy_path.resolve()), "-out", str(signature_path.resolve())],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False)
        if result.returncode:
            raise PolicyBuildError("offline root could not sign the trust policy")
        signature_path.chmod(0o444)
        try:
            verified = verify(policy_path, signature_path=signature_path,
                root_public_key=root_public_key, now=now,
                minimum_sequence=source["sequence"])
        except TrustPolicyError as error:
            raise PolicyBuildError(
                f"generated signing trust policy did not self-verify: {error}") from error
        if verified != policy:
            raise PolicyBuildError("generated signing trust policy changed during verification")
        return policy
    except Exception:
        if output.exists():
            shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline-root-private-key", type=Path, required=True)
    parser.add_argument("--offline-root-public-key", type=Path, required=True)
    arguments = parser.parse_args()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        policy = build(arguments.input.resolve(), output=arguments.output,
            root_private_key=arguments.offline_root_private_key.resolve(),
            root_public_key=arguments.offline_root_public_key.resolve(), now=now)
    except (PolicyBuildError, OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"output": str(arguments.output.resolve()),
                      "sequence": policy["sequence"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
