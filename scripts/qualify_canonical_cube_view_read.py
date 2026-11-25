#!/usr/bin/env python3
"""Run canonical-view SQL and UI proof in the owned fresh-database harness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_cube_view_suppression_paging as harness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    harness.TESTS = (
        "tests.test_cube_view_read_integration.CubeViewReadIntegrationTests.test_native_selection_layers_missing_zero_currentness_and_no_business_effects",
        "tests.test_cube_view_read_integration.CubeViewReadIntegrationTests.test_restricted_native_selection_and_revoked_grant_fail_closed",
        "tests.test_postgres_numeric_store.PostgresNumericStoreTests.test_calculation_scan_pages_pin_current_state_and_recheck_grant",
        "tests.test_postgres_numeric_store.PostgresNumericStoreTests.test_resolved_read_applies_typed_suppression_to_authorized_snapshot",
    )
    harness.SOURCES = tuple(dict.fromkeys((*harness.SOURCES, *(ROOT / path for path in (
        "epm_core/cube_view_read_contract.py", "epm_core/postgres_cube_view_read.py",
        "epm_core/cube_view_contract.py", "tests/test_cube_view_read_contract.py",
        "tests/test_cube_view_read_integration.py", "web-ui/src/grid-read-contract.ts",
        "web-ui/src/grid-read-contract.test.ts", "scripts/qualify_canonical_cube_view_read.py")))))
    result = harness.qualify(image=args.database_image, output=args.output.resolve())
    result["format"] = "openepm-canonical-cube-view-read-qualification-v1"
    result["browserValidation"].pop("focusedTests", None)
    # These are prior-run narrative fields in the reused harness, not evidence
    # from this execution. Keep only this run's tests, hashes and cleanup proof.
    result.pop("correctedHarnessAttempts", None)
    result.pop("authorizationValidation", None)
    result["scope"] = "Fresh owned PostgreSQL low-level fixture plus mocked UI/typecheck; no shared application data or clone."
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "output": str(args.output.resolve()), "cleanup": result["cleanup"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
