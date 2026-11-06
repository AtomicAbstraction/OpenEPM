#!/usr/bin/env python3
"""Fail-closed completion check for the consolidated Open EPM plan."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTER = ROOT / "docs/consolidated-acceptance-register-2026-10-28.json"
EXPECTED_PACKAGES = [f"P{number:02d}" for number in range(29)]
ALLOWED_STATUSES = {
    "not_started", "in_progress", "implemented_unverified",
    "verified_for_stated_scope", "blocked", "closed",
}


class CompletionRegisterError(ValueError):
    pass


def evaluate(value: object) -> dict:
    if not isinstance(value, dict):
        raise CompletionRegisterError("REGISTER_OBJECT_REQUIRED")
    if value.get("format") != "openepm-consolidated-acceptance-v1":
        raise CompletionRegisterError("REGISTER_FORMAT_UNSUPPORTED")
    packages = value.get("packages")
    if not isinstance(packages, list):
        raise CompletionRegisterError("PACKAGES_ARRAY_REQUIRED")
    identities = [item.get("id") for item in packages
                  if isinstance(item, dict)]
    if len(packages) != len(identities) or identities != EXPECTED_PACKAGES:
        raise CompletionRegisterError("PACKAGE_INVENTORY_INVALID")
    statuses = [item.get("status") for item in packages]
    if any(status not in ALLOWED_STATUSES for status in statuses):
        raise CompletionRegisterError("PACKAGE_STATUS_INVALID")

    declared = value.get("statusValues")
    if not isinstance(declared, list) or set(declared) != ALLOWED_STATUSES:
        raise CompletionRegisterError("STATUS_VOCABULARY_INVALID")
    completion = value.get("completion")
    if not isinstance(completion, dict):
        raise CompletionRegisterError("COMPLETION_OBJECT_REQUIRED")
    deferred = value.get("deferred")
    if not isinstance(deferred, list) or not deferred:
        raise CompletionRegisterError("DEFERRED_INVENTORY_REQUIRED")
    for item in deferred:
        if (not isinstance(item, dict)
                or not item.get("requirement")
                or not item.get("status")
                or item.get("mustNotBeReportedAsPassed") is not True):
            raise CompletionRegisterError("DEFERRED_ITEM_INVALID")

    unresolved = [item["id"] for item in packages[:28]
                  if item["status"] != "closed"]
    p28_closed = packages[28]["status"] == "closed"
    derived_all_product_closed = not unresolved
    flags = {
        "allP00P27Closed": completion.get("allP00P27Closed") is True,
        "p28PilotDocumented": completion.get("p28PilotDocumented") is True,
        "sharedResetPerformed": completion.get("sharedResetPerformed") is True,
        "wholeRebuildComplete": completion.get("wholeRebuildComplete") is True,
    }
    if bool(completion.get("allP00P27Closed")) != derived_all_product_closed:
        raise CompletionRegisterError("PRODUCT_PACKAGE_COMPLETION_CONTRADICTED")
    if bool(completion.get("p28PilotDocumented")) != p28_closed:
        raise CompletionRegisterError("P28_COMPLETION_CONTRADICTED")
    complete = derived_all_product_closed and p28_closed and all(flags.values())
    return {
        "format": "openepm-completion-check-v1",
        "complete": complete,
        "unresolvedPackages": unresolved,
        "unmetCompletionFlags": [name for name, passed in flags.items()
                                 if not passed],
        "deferredRequirements": [item["requirement"] for item in deferred],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--register", type=Path, default=DEFAULT_REGISTER)
    arguments = parser.parse_args()
    try:
        value = json.loads(arguments.register.read_text(encoding="utf-8"))
        result = evaluate(value)
    except (OSError, UnicodeError, json.JSONDecodeError,
            CompletionRegisterError) as error:
        print(json.dumps({"format": "openepm-completion-check-v1",
            "complete": False, "error": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
