"""Compare fresh and upgraded Open EPM schemas using canonical catalog rows.

The caller constructs both owned targets through the release migration path.
This verifier is read-only: it proves exact migrations, structure, constraints,
roles and privileges and refuses to normalize differences away.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

# Support both packaged module execution and a direct operator invocation from
# an unrelated working directory.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_fresh_baseline import (
    schema_fingerprint, schema_fingerprint_objects)
from scripts.apply_postgres_migrations import DEFAULT_DIR


def canonical_migrations(directory: Path = DEFAULT_DIR) -> list[dict]:
    rows = []
    for path in sorted(directory.glob("*.sql")):
        version_text, separator, description = path.stem.partition("_")
        if (not separator or len(version_text) != 4
                or not version_text.isdigit() or not description):
            raise ValueError("SCHEMA_EQUIVALENCE_MIGRATION_NAME_INVALID")
        rows.append({"version": int(version_text),
                     "checksum": hashlib.sha256(path.read_bytes()).hexdigest()})
    if [row["version"] for row in rows] != list(range(1, len(rows) + 1)):
        raise ValueError("SCHEMA_EQUIVALENCE_MIGRATION_CHAIN_INVALID")
    return rows


def snapshot(dsn: str) -> dict:
    with connect_postgres(dsn) as db:
        migrations = [
            {"version": version, "checksum": checksum}
            for version, checksum in db.execute(
                "SELECT version,checksum FROM epm.schema_migration "
                "ORDER BY version").fetchall()]
        unvalidated = [
            {"relation": relation, "constraint": name, "type": kind}
            for relation, name, kind in db.execute('''SELECT
              n.nspname||'.'||c.relname,x.conname,x.contype::text
              FROM pg_constraint x JOIN pg_class c ON c.oid=x.conrelid
              JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='epm' AND NOT x.convalidated
              ORDER BY 1,2''').fetchall()]
        objects = schema_fingerprint_objects(db)
        encoded = json.dumps(objects, separators=(",", ":"),
                             ensure_ascii=False).encode()
        return {
            "schemaFingerprint": schema_fingerprint(db),
            "objectCount": len(objects),
            "objectListDigest": hashlib.sha256(encoded).hexdigest(),
            "migrations": migrations,
            "unvalidatedConstraints": unvalidated,
        }


def compare(fresh: dict, upgraded: dict, expected: list[dict]) -> dict:
    for label, value in (("fresh", fresh), ("upgraded", upgraded)):
        if value.get("migrations") != expected:
            raise ValueError(f"SCHEMA_EQUIVALENCE_{label.upper()}_CHAIN_MISMATCH")
        if value.get("unvalidatedConstraints") != []:
            raise ValueError(
                f"SCHEMA_EQUIVALENCE_{label.upper()}_CONSTRAINTS_UNVALIDATED")
    for field in ("schemaFingerprint", "objectCount", "objectListDigest"):
        if fresh.get(field) != upgraded.get(field):
            raise ValueError(f"SCHEMA_EQUIVALENCE_{field.upper()}_MISMATCH")
    return {
        "format": "openepm-postgres-schema-equivalence-v1",
        "status": "passed",
        "migrationCount": len(expected),
        "schemaFingerprint": fresh["schemaFingerprint"],
        "objectCount": fresh["objectCount"],
        "objectListDigest": fresh["objectListDigest"],
        "allConstraintsValidated": True,
        "privilegesAndRolesIncluded": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh-dsn", required=True)
    parser.add_argument("--upgraded-dsn", required=True)
    parser.add_argument("--migrations-dir", type=Path, default=DEFAULT_DIR)
    args = parser.parse_args()
    result = compare(snapshot(args.fresh_dsn), snapshot(args.upgraded_dsn),
                     canonical_migrations(args.migrations_dir))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
