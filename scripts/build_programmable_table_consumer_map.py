#!/usr/bin/env python3
"""Build the V00 PostgreSQL table ownership and active-consumer inventory."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema" / "postgres"
CORE = ROOT / "epm_core"
OUTPUT = ROOT / "docs" / "qualifications" / "programmable-table-consumer-map-2026-11-02.json"
CREATE = re.compile(
    r"\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?epm\.([a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)
REFERENCE = re.compile(r"\bepm\.([a-z_][a-z0-9_]*)\b", re.IGNORECASE)
RENAME = re.compile(
    r"\bALTER\s+TABLE\s+epm\.([a-z_][a-z0-9_]*)\s+RENAME\s+TO\s+([a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)


def build() -> dict:
    migrations = sorted(SCHEMA.glob("[0-9][0-9][0-9][0-9]_*.sql"))
    owners: dict[str, str] = {}
    touched_by: dict[str, set[str]] = {}
    for path in migrations:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        for name in CREATE.findall(text):
            owners.setdefault(name.lower(), relative)
        for name in REFERENCE.findall(text):
            touched_by.setdefault(name.lower(), set()).add(relative)
        for old_name, new_name in RENAME.findall(text):
            old_name = old_name.lower()
            new_name = new_name.lower()
            if old_name not in owners:
                raise ValueError(f"rename source has no table owner: {old_name}")
            if new_name in owners:
                raise ValueError(f"rename target already has a table owner: {new_name}")
            owners[new_name] = owners.pop(old_name)
            history = touched_by.pop(old_name, set())
            history.add(relative)
            touched_by.setdefault(new_name, set()).update(history)
    consumers: dict[str, set[str]] = {name: set() for name in owners}
    for path in sorted(CORE.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        for name in set(item.lower() for item in REFERENCE.findall(text)):
            if name in consumers:
                consumers[name].add(relative)
    rows = [{
        "table": f"epm.{name}",
        "ownerMigration": owners[name],
        "migrationConsumers": sorted(touched_by.get(name, set())),
        "activePythonConsumers": sorted(consumers[name]),
    } for name in sorted(owners)]
    digest = sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "format": "openepm-programmable-table-consumer-map-v1",
        "migrationCount": len(migrations),
        "tableCount": len(rows),
        "tableMapDigest": digest,
        "tables": rows,
        "interpretation": {
            "ownerMigration": "first migration containing CREATE TABLE for the table",
            "migrationConsumers": "all migration files containing an epm.<table> reference",
            "activePythonConsumers": "top-level epm_core modules containing an epm.<table> reference",
            "retirementAuthority": False,
        },
    }


def main() -> None:
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
