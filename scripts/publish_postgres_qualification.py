#!/usr/bin/env python3
"""Verify and publish one current owned-PostgreSQL qualification proof."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.qualify_native_member_selection import core_source_binding, source_hashes


class PublicationError(RuntimeError):
    pass


def migration_hashes() -> dict[str, str]:
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT / "schema" / "postgres").glob("*.sql"))}


def publish(source: Path, output: Path, expected_format: str,
            expected_suite: str) -> dict:
    if (not source.is_absolute() or source.is_symlink() or not source.is_file()
            or not output.is_absolute() or output.is_symlink() or output.is_dir()):
        raise PublicationError("ABSOLUTE_REGULAR_PATH_REQUIRED")
    value = json.loads(source.read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or value.get("format") != expected_format
            or value.get("testSuite") != expected_suite):
        raise PublicationError("QUALIFICATION_IDENTITY_INVALID")
    count = value.get("testsRun")
    ids = value.get("testScenarioIds")
    if (not isinstance(count, int) or count < 1 or not isinstance(ids, list)
            or len(ids) != count or len(set(ids)) != count
            or any(value.get(field) != 0 for field in ("failures", "errors", "skipped"))):
        raise PublicationError("QUALIFICATION_RESULTS_INVALID")
    cleanup = value.get("cleanup") or {}
    residue = value.get("databaseRoleCleanup") or {}
    if (cleanup.get("cleanupVerified") is not True or cleanup.get("pending") != []
            or cleanup.get("status") != "complete"
            or residue.get("remainingOwnedDatabases") != 0
            or residue.get("remainingOwnedRoles") != 0
            or value.get("sharedApplicationReadOrMutation") is not False):
        raise PublicationError("QUALIFICATION_CLEANUP_OR_SCOPE_INVALID")
    if value.get("sourceSha256") != source_hashes():
        raise PublicationError("CURRENT_SOURCE_BINDING_STALE")
    if value.get("coreSource") != core_source_binding():
        raise PublicationError("CURRENT_CORE_TREE_BINDING_STALE")
    migrations = migration_hashes()
    if (value.get("migrationSha256") != migrations
            or value.get("freshMigrationCount") != len(migrations)):
        raise PublicationError("CURRENT_MIGRATION_BINDING_STALE")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--format", required=True)
    parser.add_argument("--suite", required=True)
    args = parser.parse_args()
    value = publish(args.input.resolve(), args.output.resolve(), args.format, args.suite)
    print(json.dumps({"output": str(args.output.resolve()), "testsRun": value["testsRun"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
