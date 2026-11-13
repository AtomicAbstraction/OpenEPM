#!/usr/bin/env python3
"""Verify and atomically publish a source-bound scoped qualification."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PublicationError(RuntimeError):
    pass


def publish(source: Path, output: Path, expected_format: str) -> dict:
    if (not source.is_absolute() or source.is_symlink() or not source.is_file()
            or not output.is_absolute() or output.is_symlink() or output.is_dir()):
        raise PublicationError("ABSOLUTE_REGULAR_PATH_REQUIRED")
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("format") != expected_format:
        raise PublicationError("QUALIFICATION_FORMAT_INVALID")
    hashes = value.get("sourceHashes")
    if not isinstance(hashes, dict) or not hashes:
        raise PublicationError("SOURCE_HASHES_REQUIRED")
    for relative, expected in hashes.items():
        path = ROOT / relative
        if (not isinstance(relative, str) or Path(relative).is_absolute()
                or not isinstance(expected, str) or len(expected) != 64
                or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise PublicationError(f"CURRENT_SOURCE_BINDING_STALE:{relative}")
    checks = value.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise PublicationError("CHECKS_REQUIRED")
    for name, check in checks.items():
        if isinstance(check, dict):
            if not isinstance(check.get("passed"), int) or check["passed"] < 1:
                raise PublicationError(f"CHECK_NOT_PASSED:{name}")
        elif not isinstance(check, str) or "pass" not in check.lower():
            raise PublicationError(f"CHECK_NOT_PASSED:{name}")
    cleanup = value.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("verified") is not True:
        raise PublicationError("CLEANUP_NOT_VERIFIED")
    for item in cleanup.get("removed", []):
        if (not isinstance(item, dict) or item.get("absent") is not True
                or not isinstance(item.get("path"), str)
                or Path(item["path"]).exists()):
            raise PublicationError("CLEANUP_ITEM_NOT_VERIFIED")
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
    args = parser.parse_args()
    value = publish(args.input.resolve(), args.output.resolve(), args.format)
    print(json.dumps({"format": value["format"], "output": str(args.output.resolve())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
