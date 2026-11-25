#!/usr/bin/env python3
"""Qualify the ordered-expression boundary on owned disposable PostgreSQL.

Reuse the maintained full-migration and OwnedDockerRun cleanup harness. The
legacy-state cases reconstruct the previously observed defect in a bounded
test fixture; they do not restore a database or run an old installed release.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness


SUITE = 'ordered-expression-profile'
MODULE = 'tests.test_ordered_expression_profile_postgres'
CLASS = 'OrderedExpressionProfilePostgresTests'
REQUIRED_NATIVE_CASES = {
    'test_fresh_foreign_nodes_fail_in_both_adapters_without_business_work',
    'test_reconstructed_committed_witness_remains_readable_and_replays_receipt',
    'test_reconstructed_pending_witness_fails_under_restored_worker_guard',
    'test_supported_exact_rational_golden_publishes_and_replays_unchanged',
}
SOURCE_FILES = (
    'epm_core/postgres_numeric_sequence_expression.py',
    'epm_core/postgres_numeric_sequence.py',
    'epm_core/postgres_numeric_iteration.py',
    'epm_core/postgres_numeric_transform.py',
    'epm_core/postgres_expression_apportionment.py',
    'epm_core/postgres_expression.py',
    'epm_core/postgres_jobs.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'platform_postgres_web_http.py',
    'tests/test_ordered_expression_profile.py',
    'tests/test_ordered_expression_profile_postgres.py',
    'tests/test_expired_operation_replay_postgres.py',
    'tests/test_source_change_review_postgres.py',
    'tests/test_postgres_numeric_store.py',
    'tests/test_postgres_numeric_transform.py',
    'tests/test_expression_apportionment_postgres.py',
    'tests/test_python_expression_impact_postgres.py',
    'tests/test_python_impact_mixed_postgres.py',
    'tests/test_python_impact_postgres.py',
    'tests/numeric_sequence_fixture.py',
    'tests/numeric_sequence_expression_fixture.py',
    'tests/numeric_iteration_fixture.py',
    'tests/composite_fact_batch_live_fixture.py',
    'tests/mcp_inline_fixture.py',
    'tests/disposable_storage_fixture.py',
    'scripts/apply_postgres_migrations.py',
    'scripts/qualify_ordered_expression_profile.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)


def selected_tests():
    """Keep regressions explicit: the affected callers share one evaluator."""
    store = 'tests.test_postgres_numeric_store.PostgresNumericStoreTests.'
    transform = 'tests.test_postgres_numeric_transform.PostgresNumericTransformTests.'
    apportionment = ('tests.test_expression_apportionment_postgres.'
                     'ExpressionApportionmentPostgresTests.')
    return (
        MODULE + '.' + CLASS,
        store + 'test_ordered_numeric_statements_preserve_events_and_atomic_projection',
        store + 'test_ordered_typed_expressions_late_lease_rollback_and_retry',
        store + 'test_ordered_typed_expressions_reject_active_missing_zero_and_overflow',
        store + 'test_ordered_typed_expressions_enforce_and_execute_work_bounds',
        store + 'test_ordered_numeric_statements_recheck_downgraded_grant',
        store + 'test_numeric_iteration_converges_exactly_and_restores_admitted_work',
        store + 'test_numeric_iteration_nonconvergence_presence_and_exact_threshold',
        store + 'test_numeric_iteration_complete_vector_and_iteration_local_references',
        transform + 'test_transform_atomic_scope_replay_and_private_stage',
        transform + 'test_shared_kernel_half_even_overflow_and_stale_inputs',
        transform + 'test_lost_worker_preserves_only_private_candidate_then_retries_once',
        apportionment + 'test_exact_projection_cent_boundary_selected_if_and_ordinary_rounding',
        apportionment + 'test_quantized_and_combined_overflow_division_and_inactive_branch',
        apportionment + 'test_signed_sparse_components_private_run_replay_and_lineage',
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    from tests.test_ordered_expression_profile_postgres import OrderedExpressionProfilePostgresTests

    if set(unittest.defaultTestLoader.getTestCaseNames(
            OrderedExpressionProfilePostgresTests)) != REQUIRED_NATIVE_CASES:
        raise harness.QualificationError('ORDERED_EXPRESSION_SCENARIOS_CHANGED')
    harness.TEST_SUITES[SUITE] = (
        MODULE, CLASS, 'openepm-ordered-expression-profile-qualification-v1')
    harness.TEST_CASES[SUITE] = selected_tests()
    harness.SOURCE_FILES = SOURCE_FILES
    # Neither an ambient supplied DSN nor optional restore settings may redirect
    # this qualification toward an existing database or historical snapshot.
    saved = {name: value for name, value in os.environ.items()
             if name.startswith('EPM_TEST_')}
    for name in saved:
        os.environ.pop(name, None)
    try:
        proof = harness.qualify(output=args.output,
            database_image=args.database_image, test_suite=SUITE)
    finally:
        for name in tuple(os.environ):
            if name.startswith('EPM_TEST_'):
                os.environ.pop(name, None)
        os.environ.update(saved)
    proof['invocation']['argv'] = [sys.executable, '-B', '-m',
        'scripts.qualify_ordered_expression_profile', '--execute',
        '--database-image', args.database_image, '--output', str(args.output)]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* settings excluded; names and values not retained.'
    proof['observations'] = OrderedExpressionProfilePostgresTests.observations
    proof['scope'] = {
        'change': 'Reject operations outside the existing ordered-expression profile before compilation, lowering or SQL execution; no new source-text semantics.',
        'adapters': 'New boundary cases use the real browser dispatcher and MCP application facade with the verified-identity fixture seam; supported caller regressions also use direct fixed-core paths.',
        'legacyState': 'Bounded reconstruction of the unsupported SourceTextPredicate witness, matched to retained pre-fix native evidence. Completed receipt/recovery and pending-job refusal are tested after restoring the guard.',
        'compatibility': 'Ordered v1/v2 results, exact rational/half-even behavior, presence, selected-branch errors, lazy unselected branches, iteration, transform and prepared apportionment use existing numerical oracles.',
        'fixture': 'Fresh fully migrated PostgreSQL and disposable sparse custom-axis kernel applications. Existing fixtures may seed metadata/data through their established isolated core fixture paths.',
        'excludedClaims': 'No database snapshot restore, external HTTP/OIDC authentication, rendered browser, installed upgrade, deployment, full tape-shape validation or full IP-01-AC-02 acceptance.',
        'cleanup': 'The delegated harness verifies fixture database/role cleanup and removes its exact owned container and volume. The campaign-owned image is retained only until final qualification cleanup.',
    }
    harness.write_json(args.output, proof)
    print(f'Passed {proof["testsRun"]} native expression cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
