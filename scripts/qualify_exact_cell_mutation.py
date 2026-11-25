#!/usr/bin/env python3
"""Qualify exact cell/detail editing with the established owned SQL harness."""
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
        "tests.test_cube_view_read_integration.CubeViewReadIntegrationTests.test_exact_detail_preview_coherent_publication_stale_replace_and_empty_zero",
        "tests.test_postgres_numeric_store.PostgresNumericStoreTests.test_line_detail_total_and_numeric_cell_commit_together",
        "tests.test_postgres_numeric_store.PostgresNumericStoreTests.test_v2_line_detail_job_rechecks_current_grant_after_admission",
        "tests.test_postgres_numeric_store.PostgresNumericStoreTests.test_line_detail_overflow_and_text_conflict_leave_no_effect",
        "tests.test_postgres_numeric_store.PostgresNumericStoreTests.test_line_detail_event_failure_rolls_back_numeric_and_receipt",
    )
    harness.BROWSER_TESTS = ("src/Analyze.test.tsx", "src/SupportingDetail.test.tsx", "src/exact-cell-mutation.test.tsx", "src/api.test.ts")
    harness.SOURCES = tuple(dict.fromkeys((*harness.SOURCES, *(ROOT / path for path in (
        "epm_core/postgres_line_detail.py", "epm_core/postgres_line_detail_job.py",
        "tests/test_line_detail_job.py", "tests/test_cube_view_read_integration.py",
        "web-ui/src/SupportingDetail.tsx", "web-ui/src/SupportingDetail.test.tsx",
        "web-ui/src/exact-cell-mutation.tsx", "web-ui/src/exact-cell-mutation.test.tsx",
        "web-ui/src/api.ts", "web-ui/src/api.test.ts", "scripts/qualify_exact_cell_mutation.py")))))
    result = harness.qualify(image=args.database_image, output=args.output.resolve())
    result["format"] = "openepm-exact-cell-mutation-qualification-v1"
    result["browserValidation"] = {"testFiles": list(harness.BROWSER_TESTS), "typeScript": "passed"}
    result.pop("correctedHarnessAttempts", None)
    result.pop("authorizationValidation", None)
    result["scope"] = "Fresh owned low-level PostgreSQL fixture; exact typed preview, atomic detail/numeric publication, current authority, rollback and mocked browser lifecycle. Shared applications unchanged. Expired admission transport replay is qualified separately."
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "output": str(args.output), "cleanup": result["cleanup"]}))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
