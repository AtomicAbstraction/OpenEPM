#!/usr/bin/env python3
"""Establish publisher trust before the operations image is executed."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    from scripts.openepm_signing_trust_policy import (
        TrustPolicyError, eligible_keys, verify as verify_trust_policy,
        verify_signature,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from openepm_signing_trust_policy import (  # type: ignore[no-redef]
        TrustPolicyError, eligible_keys, verify as verify_trust_policy,
        verify_signature,
    )


class BootstrapError(ValueError):
    pass


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapError("duplicate signed manifest key")
        result[key] = value
    return result


def verify(*, manifest_path: Path, manifest_signature: Path,
           inventory_path: Path, architecture: str, selected_operations: str,
           root_public_key: Path, trust_policy_path: Path,
           trust_policy_signature: Path, minimum_sequence: int,
           now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    try:
        policy = verify_trust_policy(trust_policy_path,
            signature_path=trust_policy_signature,
            root_public_key=root_public_key, now=now,
            minimum_sequence=minimum_sequence)
        release_keys = eligible_keys(trust_policy_path, policy,
                                     purpose="release", now=now)
    except TrustPolicyError as error:
        raise BootstrapError(f"signing trust policy is invalid: {error}") from error
    matched = []
    for key_id, public_key in release_keys:
        try:
            verify_signature(manifest_path, manifest_signature, public_key,
                             "release manifest")
        except TrustPolicyError:
            continue
        matched.append(key_id)
    if len(matched) != 1:
        raise BootstrapError(
            "release manifest must match exactly one eligible signing key")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BootstrapError("signed release manifest is invalid") from error
    if (not isinstance(manifest, dict)
            or manifest.get("format") != "openepm-release-manifest-v3"
            or manifest.get("status") != "final-qualified"):
        raise BootstrapError("manifest is not a qualified v3 release")
    architectures = manifest.get("architectures")
    if (not isinstance(architectures, list) or architecture not in architectures
            or len(architectures) != len(set(architectures))):
        raise BootstrapError("host architecture is not qualified")
    images = manifest.get("images")
    operations = images.get("operations") if isinstance(images, dict) else None
    if (not isinstance(operations, dict)
            or set(operations) != {"reference", "digests"}
            or not isinstance(operations["reference"], str)
            or not isinstance(operations["digests"], dict)
            or set(operations["digests"]) != set(architectures)):
        raise BootstrapError("operations image identity is incomplete")
    digest = operations["digests"].get(architecture)
    if (not isinstance(digest, str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None
            or selected_operations != operations["reference"] + "@" + digest):
        raise BootstrapError("selected operations image differs from signed manifest")
    artifacts = manifest.get("artifacts")
    record = artifacts.get("inventory") if isinstance(artifacts, dict) else None
    if (not isinstance(record, dict)
            or set(record) != {"path", "sha256"}
            or not isinstance(record.get("sha256"), str)):
        raise BootstrapError("signed release inventory identity is missing")
    if (not inventory_path.is_file() or inventory_path.is_symlink()
            or hashlib.sha256(inventory_path.read_bytes()).hexdigest()
                != record["sha256"]):
        raise BootstrapError("release inventory differs from signed manifest")
    return policy["sequence"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-signature", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--selected-operations", required=True)
    parser.add_argument("--trusted-root-public-key", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--trust-policy-signature", type=Path, required=True)
    parser.add_argument("--minimum-trust-policy-sequence", type=int, required=True)
    arguments = parser.parse_args()
    try:
        sequence = verify(manifest_path=arguments.manifest,
            manifest_signature=arguments.manifest_signature,
            inventory_path=arguments.inventory,
            architecture=arguments.architecture,
            selected_operations=arguments.selected_operations,
            root_public_key=arguments.trusted_root_public_key,
            trust_policy_path=arguments.trust_policy,
            trust_policy_signature=arguments.trust_policy_signature,
            minimum_sequence=arguments.minimum_trust_policy_sequence)
    except BootstrapError as error:
        parser.error(str(error))
    print(sequence)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
