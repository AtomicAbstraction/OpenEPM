#!/usr/bin/env python3
"""Build the explicit enterprise PostgreSQL test disposition inventory.

The legacy monolithic integration class contains current programmable-platform
coverage, historical migration fixtures, and tests for retired public domain
contracts.  This inventory makes that distinction executable and reviewable.
New tests are deliberately left unclassified until this builder and its policy
are reviewed and the checked-in inventory is regenerated.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from epm_core.postgres_capability_contract import (
    CONSOLIDATION_FUNCTIONS, RETIRED_PUBLIC_FUNCTIONS)


SOURCE=ROOT/'tests/test_postgres_numeric_store.py'
OUTPUT=ROOT/'docs/qualifications/enterprise-postgres-test-inventory-2026-11-05.json'
CLASS='PostgresNumericStoreTests'

# These cases qualify historical schema construction or require an external
# dump/restore topology. They remain required evidence, but not in the normal
# disposable database integration job.
HISTORICAL_SCHEMA_TESTS={
    'test_coordinate_layout_upgrade_preserves_populated_facts_and_rejects_bad_grain',
    'test_coordinate_layout_upgrade_serializes_post_backfill_coordinate_write',
    'test_cube_selection_upgrade_seals_populated_legacy_hierarchy_without_changing_facts',
    'test_fact_publication_upgrade_rejects_corruption_and_preserves_valid_history',
    'test_generic_provenance_upgrade_preserves_legacy_and_records_new',
    'test_generic_publication_upgrade_preserves_history_and_rejects_corruption',
    'test_job_keyed_control_populated85_upgrade',
    'test_projection_generation_populated_76_upgrade_preserves_history',
    'test_raw_operation_membership_populated_83_upgrade',
}
ARTIFACT_QUALIFICATION_TESTS={
    'test_saved_ordered_accepted_job_restores_before_publication',
}

# Tests whose helper indirection hides a retired contract from the method body.
# Keep this list explicit: it is a disposition decision, not a substring rule.
RETIRED_TRANSITIVE_TESTS={
    'test_acquisition_value_fx_stages_preserve_posted_layer',
    'test_application_taskflow_public_lifecycle_live',
    'test_capability_full_sequence_disable_advance_and_cancel',
    'test_complete_planning_comparison_journey_live',
    'test_company_nci_all_relationships_publication_and_restore',
    'test_composed_period_nci_exact_sources_publication_and_restore',
    'test_forecast_occurrence_claim_0135_no_ambiguity',
    'test_forecast_occurrence_universal_task_lifecycle_live',
    'test_forecast_schedule_claim_0136_no_ambiguity',
    'test_full_aggregate_planning_policy_live',
    'test_full_contribution_planning_policy_live',
    'test_full_sequence_fences_metadata_committed_in_step_preview_window',
    'test_full_sequence_fences_target_committed_in_step_preview_window',
    'test_functional_full_v8_sequence_recovers_all_durable_boundaries',
    'test_ic_elimination_planning_policy_live',
    'test_local_period_nci_no_value_actual_source_versioning_restore_and_correction',
    'test_lower_company_nci_pinned_multilevel_publication_and_restore',
    'test_ordered_numeric_statements_respect_closed_planning_slice',
    'test_public_assignment_oidc_group_worklist_live',
    'test_own_source_pva_recovery_and_competing_publishers',
    'test_same_application_disjoint_calculation_translations_compute_concurrently',
    'test_same_application_disjoint_forecasts_prepare_concurrently',
    'test_same_application_disjoint_full_aggregates_compute_concurrently',
    'test_same_application_disjoint_full_contributions_compute_concurrently',
    'test_same_application_disjoint_rollups_compute_concurrently',
    'test_same_application_disjoint_period_nci_compute_concurrently',
    'test_sequence_fairness_continues_after_post_probe_full_lock_race',
    'test_sequence_fairness_skips_older_locked_full_application',
}


def _methods() -> list[tuple[str,int,str]]:
    text=SOURCE.read_text(encoding='utf-8')
    tree=ast.parse(text)
    klass=next(node for node in tree.body
               if isinstance(node,ast.ClassDef) and node.name==CLASS)
    lines=text.splitlines(keepends=True)
    result=[]
    for node in klass.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name.startswith('test_'):
            source=''.join(lines[node.lineno-1:node.end_lineno])
            result.append((node.name,node.lineno,source))
    return sorted(result)


def build() -> dict:
    retired=RETIRED_PUBLIC_FUNCTIONS|CONSOLIDATION_FUNCTIONS
    rows=[]
    for name,line,source in _methods():
        referenced=sorted(function for function in retired if function in source)
        if name in ARTIFACT_QUALIFICATION_TESTS:
            disposition='artifact_qualification'
            rationale='requires packaged dump/restore topology'
        elif name in HISTORICAL_SCHEMA_TESTS:
            disposition='historical_compatibility'
            rationale='constructs and upgrades a superseded schema generation'
        elif referenced:
            disposition='historical_retired_contract'
            rationale='directly references retired public function(s)'
        elif name in RETIRED_TRANSITIVE_TESTS:
            disposition='historical_retired_contract'
            rationale='fixture/helper transitively exercises a retired public contract'
        else:
            disposition='active_disposable_integration'
            rationale='current programmable-platform database behavior'
        rows.append({'test':name,'line':line,'disposition':disposition,
                     'rationale':rationale,
                     'retiredFunctions':referenced})
    digest=sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    counts={}
    for row in rows:counts[row['disposition']]=counts.get(row['disposition'],0)+1
    return {'format':'openepm-enterprise-postgres-test-inventory-v1',
            'source':SOURCE.relative_to(ROOT).as_posix(),
            'class':CLASS,'testCount':len(rows),
            'dispositionCounts':dict(sorted(counts.items())),
            'inventoryDigest':digest,'tests':rows,
            'policy':{
                'unknownTestsFail':True,
                'activeSelectionMustNotSkip':True,
                'historicalTestsRemainPreserved':True,
                'artifactQualificationRunsSeparately':True}}


def main() -> None:
    OUTPUT.write_text(json.dumps(build(),indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
