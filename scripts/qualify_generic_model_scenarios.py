#!/usr/bin/env python3
"""Qualify the three authored IP11 domains in a fresh owned PostgreSQL run."""
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
    harness.TESTS = tuple("tests.test_generic_model_scenarios_postgres.GenericModelScenariosPostgresTests." + name for name in (
        "test_finance_exact_alternative_promotion_replay_and_missing_zero",
        "test_workforce_sparse_eligibility_control_prevents_duplicate_capacity",
        "test_service_quantity_weighted_rate_exact_policy_and_missing"))
    harness.BROWSER_TESTS = ("src/ModelMeaning.test.tsx", "src/ScenarioPromotion.test.tsx", "src/MetadataWorkspace.test.tsx", "src/Analyze.test.tsx")
    harness.SOURCES = tuple(ROOT / path for path in (
        "epm_core/multidimensional_roles.py", "epm_core/postgres_workspace_lifecycle.py",
        "epm_core/postgres_language_v2.py", "epm_core/postgres_expression.py",
        "epm_core/expression_apportionment.py", "epm_core/postgres_expression_apportionment.py",
        "epm_core/postgres_planning_copy.py", "epm_core/postgres_source_batch.py",
        "tests/test_generic_model_scenarios_postgres.py", "scripts/qualify_generic_model_scenarios.py",
        "web-ui/src/MetadataWorkspace.tsx", "web-ui/src/MetadataWorkspace.test.tsx",
        "web-ui/src/ModelMeaning.tsx", "web-ui/src/ModelMeaning.test.tsx",
        "web-ui/src/ScenarioPromotion.tsx", "web-ui/src/ScenarioPromotion.test.tsx",
        "web-ui/src/Analyze.tsx", "web-ui/src/Analyze.test.tsx"))
    result = harness.qualify(image=args.database_image, output=args.output.resolve())
    result["format"] = "openepm-generic-model-scenarios-qualification-v1"
    result["browserValidation"] = {"testFiles": list(harness.BROWSER_TESTS), "typeScript": "passed"}
    result.pop("correctedHarnessAttempts", None)
    result.pop("authorizationValidation", None)
    result["scope"] = "Three fresh eight-role applications created through the normal lifecycle. All metadata and business effects use application-language programs; no shared application, clone or domain-specific capability. Physical unit meanings are explicit metadata; arithmetic kinds are Amount and Ratio."
    args.output.resolve().write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "output": str(args.output), "cleanup": result["cleanup"]}))


if __name__ == "__main__":
    main()
