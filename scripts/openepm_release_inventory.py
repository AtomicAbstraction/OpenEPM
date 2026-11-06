#!/usr/bin/env python3
"""Strict resolver for the credential-free portable release inventory."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

FIELDS = ("composeProfiles", "services", "databases", "roles", "secrets",
          "healthDependencies")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class InventoryError(ValueError):
    pass


def load(path: Path) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError(f"duplicate inventory key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(path.read_text("utf-8"), object_pairs_hook=unique)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InventoryError(f"invalid release inventory: {error}") from error
    if (not isinstance(value, dict) or set(value) != {"format", "profiles"}
            or value.get("format") != "openepm-release-inventory-v1"
            or not isinstance(value.get("profiles"), dict)
            or set(value["profiles"]) != {"disabled", "managed"}):
        raise InventoryError("release inventory root is invalid")
    for mode, profile in value["profiles"].items():
        if not isinstance(profile, dict) or set(profile) != set(FIELDS):
            raise InventoryError(f"{mode} inventory fields are invalid")
        for field in FIELDS[:-1]:
            items = profile[field]
            if (not isinstance(items, list) or not items
                    or len(items) != len(set(items))
                    or any(not isinstance(item, str)
                           or IDENTIFIER.fullmatch(item) is None for item in items)):
                raise InventoryError(f"{mode} {field} inventory is invalid")
        dependencies = profile["healthDependencies"]
        if (not isinstance(dependencies, dict)
                or set(dependencies) != set(profile["services"])):
            raise InventoryError(f"{mode} health dependency coverage differs from services")
        allowed = set(profile["services"]) | {"identity-jwks", "python-coordinator",
            "sandbox-launcher", "notebook-launcher"}
        for service, items in dependencies.items():
            if (not isinstance(items, list) or len(items) != len(set(items))
                    or any(item not in allowed or item == service for item in items)):
                raise InventoryError(f"{mode} health dependencies are invalid")
    disabled, managed = value["profiles"]["disabled"], value["profiles"]["managed"]
    for field in FIELDS[:-1]:
        if not set(disabled[field]).issubset(managed[field]):
            raise InventoryError(f"managed {field} loses required disabled entries")
    return value


def resolve(path: Path, mode: str) -> dict:
    value = load(path)
    if mode not in value["profiles"]:
        raise InventoryError("notebook mode must be disabled or managed")
    return value["profiles"][mode]


def assert_observed(expected: dict, observed: dict) -> None:
    if observed != expected:
        raise InventoryError("observed release inventory differs from authority")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--mode", choices=("disabled", "managed"), required=True)
    parser.add_argument("--field", choices=FIELDS)
    arguments = parser.parse_args()
    try:
        profile = resolve(arguments.inventory, arguments.mode)
    except InventoryError as error:
        parser.error(str(error))
    if arguments.field:
        value = profile[arguments.field]
        if isinstance(value, list):
            print(" ".join(value))
        else:
            print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps({"format": "openepm-resolved-release-inventory-v1",
            "mode": arguments.mode, "inventorySha256": hashlib.sha256(
                arguments.inventory.read_bytes()).hexdigest(),
            **profile}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
