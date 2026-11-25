#!/usr/bin/env python3
"""Strict resolver for the credential-free portable release inventory."""
from __future__ import annotations

import argparse
from copy import deepcopy
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
    try:
        return parse(path.read_text("utf-8"))
    except (OSError, UnicodeError) as error:
        raise InventoryError(f"invalid release inventory: {error}") from error


def parse(source: str) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError(f"duplicate inventory key: {key}")
            result[key] = value
        return result
    try:
        value = json.loads(source, object_pairs_hook=unique)
    except (json.JSONDecodeError, RecursionError) as error:
        raise InventoryError(f"invalid release inventory: {error}") from error
    if (not isinstance(value, dict) or set(value) != {"format", "profile", "optionalProfiles"}
            or value.get("format") != "openepm-release-inventory-v2"
            or not isinstance(value.get("profile"), dict)):
        raise InventoryError("release inventory root is invalid")
    for mode, profile in (("current", value["profile"]),):
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
            "sandbox-launcher"}
        for service, items in dependencies.items():
            if (not isinstance(items, list) or len(items) != len(set(items))
                    or any(item not in allowed or item == service for item in items)):
                raise InventoryError(f"{mode} health dependencies are invalid")
    optional = value["optionalProfiles"]
    if (not isinstance(optional, dict) or set(optional) != {"workspace"}
            or optional["workspace"] != {
                "services": ["workspace"],
                "requiredEnvironment": ["EPM_PG_WORKSPACE_ID"],
                "healthDependencies": {"workspace": ["db", "identity-jwks"]}}
            or "workspace" in value["profile"]["services"]):
        raise InventoryError("optional workspace profile contract is invalid")
    return value


def resolve(path: Path, *, optional_profiles: tuple[str, ...] = ()) -> dict:
    return resolve_inventory(load(path), optional_profiles=optional_profiles)


def resolve_inventory(value: dict, *, optional_profiles: tuple[str, ...] = ()) -> dict:
    """Resolve a previously validated inventory without changing the source profile."""
    if (len(set(optional_profiles)) != len(optional_profiles)
            or any(name not in value["optionalProfiles"] for name in optional_profiles)):
        raise InventoryError("unknown or repeated optional profile")
    profile = deepcopy(value["profile"])
    for name in optional_profiles:
        extension = value["optionalProfiles"][name]
        profile["composeProfiles"].append(name)
        profile["services"].extend(extension["services"])
        profile["healthDependencies"].update(deepcopy(extension["healthDependencies"]))
    return profile



def assert_observed(expected: dict, observed: dict) -> None:
    if observed != expected:
        raise InventoryError("observed release inventory differs from authority")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--field", choices=FIELDS)
    parser.add_argument("--optional-profile", action="append", default=[])
    arguments = parser.parse_args()
    try:
        inventory_bytes = arguments.inventory.read_bytes()
        inventory = parse(inventory_bytes.decode("utf-8"))
        profile = resolve_inventory(inventory, optional_profiles=tuple(arguments.optional_profile))
    except (OSError, UnicodeError, InventoryError) as error:
        parser.error(str(error))
    if arguments.field:
        value = profile[arguments.field]
        if isinstance(value, list):
            print(" ".join(value))
        else:
            print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps({"format": "openepm-resolved-release-inventory-v2",
            "inventorySha256": hashlib.sha256(inventory_bytes).hexdigest(),
            "packagedServices": sorted(set(inventory["profile"]["services"]) |
                {service for optional in inventory["optionalProfiles"].values()
                 for service in optional["services"]}),
            "enabledServices": profile["services"],
            "optionalProfiles": inventory["optionalProfiles"],
            **profile}, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
