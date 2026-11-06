#!/usr/bin/env python3
"""Validate the installed trusted-notebook launcher profile for one release."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


class ProfileError(ValueError):
    pass


FIELDS = {
    "profileId", "image", "network", "baseDomain", "maximumActive",
    "idleSeconds", "storageRoot",
}


def validate(
    path: Path,
    *,
    expected_image: str,
    expected_network: str,
    expected_base_domain: str,
    expected_maximum_active: int,
    expected_idle_seconds: int,
) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError(f"cannot read notebook launcher profile: {error}") from error
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ProfileError("notebook launcher profile fields are invalid")
    if (not isinstance(expected_maximum_active, int)
            or isinstance(expected_maximum_active, bool)
            or not 1 <= expected_maximum_active <= 100):
        raise ProfileError("expected notebook maximumActive is invalid")
    if (not isinstance(expected_idle_seconds, int)
            or isinstance(expected_idle_seconds, bool)
            or not 300 <= expected_idle_seconds <= 86400):
        raise ProfileError("expected notebook idleSeconds is invalid")
    expected = {
        "profileId": "openepm-notebook-v1",
        "image": expected_image,
        "network": expected_network,
        "baseDomain": expected_base_domain,
        "maximumActive": expected_maximum_active,
        "idleSeconds": expected_idle_seconds,
        "storageRoot": "/var/lib/openepm/notebooks/current",
    }
    if value != expected:
        differing = sorted(key for key in FIELDS if value.get(key) != expected[key])
        raise ProfileError(
            "notebook launcher profile differs from the release: "
            + ", ".join(differing)
        )
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--expected-image", required=True)
    parser.add_argument("--expected-network", required=True)
    parser.add_argument("--expected-base-domain", required=True)
    parser.add_argument("--expected-maximum-active", type=int, required=True)
    parser.add_argument("--expected-idle-seconds", type=int, required=True)
    arguments = parser.parse_args()
    try:
        validate(
            arguments.profile,
            expected_image=arguments.expected_image,
            expected_network=arguments.expected_network,
            expected_base_domain=arguments.expected_base_domain,
            expected_maximum_active=arguments.expected_maximum_active,
            expected_idle_seconds=arguments.expected_idle_seconds,
        )
    except ProfileError as error:
        raise SystemExit(str(error)) from error
    print("notebook_launcher_profile=verified")


if __name__ == "__main__":
    main()
