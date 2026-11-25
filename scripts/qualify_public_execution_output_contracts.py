#!/usr/bin/env python3
"""Qualify four execution output owners on owned disposable PostgreSQL.

The maintained full-migration harness owns services and cleanup. Primary cases
exercise public adapters; selected established kernel cases retain deeper
arithmetic/recovery evidence. No supplied database or historical snapshot is used.
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
from scripts.qualify_public_mutation_contracts import SOURCE_FILES as MUTATION_SOURCES


SUITE = 'public-execution-output-contracts'
MODULE = 'tests.test_public_execution_output_contracts_postgres'
CLASS = 'PublicExecutionOutputContractsPostgresTests'
FORMAT = 'openepm-public-execution-output-contract-qualification-v1'
REQUIRED_CASES = frozenset((
    'test_two_sequence_examples_publish_exact_events_and_replay',
    'test_iteration_examples_distinguish_publication_from_tokenless_nonconvergence',
    'test_native_iteration_delta_can_exceed_cell_amount_width',
    'test_current_rebuild_and_retired_cleanup_examples_cover_all_output_stages',
    'test_abandoned_cleanup_example_binds_a_real_cancelled_rebuild',
    'test_current_authority_fences_native_publication_and_owned_recovery',
    'test_stale_ordered_and_rebuild_inputs_fail_without_rebasing',
))
SUPPORT_CLASS = 'tests.test_postgres_numeric_store.PostgresNumericStoreTests'
LIFECYCLE_CLASS = 'tests.test_ordered_execution_lifecycle_postgres.OrderedExecutionLifecyclePostgresTests'
LIFECYCLE_CASES = (
    'test_authentic_old_preview_bindings_cannot_admit_new_work',
    'test_completed_legacy_results_replay_exactly_under_current_authority',
    'test_pending_legacy_jobs_fail_before_evaluation_and_retire_private_candidate',
)
PYTHON_CLASS = 'tests.test_python_expired_replay_postgres.PythonExpiredReplayPostgresTests'
PYTHON_CASES = (
    'test_two_unit_published_child_lost_checkpoint_recovers_original_without_rebuilding',
    'test_old_child_replay_rechecks_delegation_after_parent_authorization',
)
SUPPORT_CASES = (
    'test_numeric_iteration_nonconvergence_presence_and_exact_threshold',
    'test_numeric_iteration_complete_vector_and_iteration_local_references',
    'test_numeric_iteration_criterion_uses_final_vector_not_intermediate_statements',
    'test_staged_projection_recovery_bounded_exact_repair',
    'test_projection_cleanup_unicode_byte_budget',
    'test_postgres_job_expired_lease_recovery_checks_receipt',
)
SOURCE_FILES = tuple(dict.fromkeys((*MUTATION_SOURCES,
    'epm_core/postgres_numeric_sequence.py',
    'epm_core/postgres_numeric_iteration.py',
    'epm_core/postgres_numeric_catalog.py',
    'epm_core/postgres_fact_reconstruction_job.py',
    'epm_core/postgres_projection_cleanup.py',
    'epm_core/postgres_operation_receipts.py',
    'tests/test_ordered_numeric_output_contracts.py',
    'tests/test_numeric_sequence_expression_contract.py',
    'tests/numeric_sequence_expression_fixture.py',
    'tests/test_projection_recovery_output_contracts.py',
    'tests/numeric_iteration_fixture.py',
    'tests/staged_projection_recovery_fixture.py',
    'tests/projection_cleanup_fixture.py',
    'tests/projection_generation_fixture.py',
    'tests/test_public_execution_output_contracts_postgres.py',
    'tests/test_ordered_execution_lifecycle.py',
    'tests/ordered_execution_legacy_fixture.py',
    'tests/test_ordered_execution_lifecycle_postgres.py',
    'tests/test_ordered_expression_profile.py',
    'tests/test_python_expired_replay_postgres.py',
    'tests/test_python_save_validation_postgres.py',
    'tests/test_python_diagnostics_postgres.py',
    'scripts/qualify_public_execution_output_contracts.py',
)))


def selected_tests():
    return (*(MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_CASES)),
        *(SUPPORT_CLASS + '.' + name for name in SUPPORT_CASES),
        *(LIFECYCLE_CLASS + '.' + name for name in LIFECYCLE_CASES),
        *(PYTHON_CLASS + '.' + name for name in PYTHON_CASES))


def validate_scenarios():
    from tests.test_public_execution_output_contracts_postgres import PublicExecutionOutputContractsPostgresTests
    from tests.test_ordered_execution_lifecycle_postgres import OrderedExecutionLifecyclePostgresTests
    loader = unittest.TestLoader()
    selected = selected_tests()
    if (set(loader.getTestCaseNames(PublicExecutionOutputContractsPostgresTests)) != REQUIRED_CASES
            or set(loader.getTestCaseNames(OrderedExecutionLifecyclePostgresTests)) != set(LIFECYCLE_CASES)
            or len(selected) != 18 or len(set(selected)) != 18
            or tuple(harness.scenario_ids(loader.loadTestsFromNames(selected))) != selected):
        raise harness.QualificationError('EXECUTION_OUTPUT_SCENARIOS_CHANGED')
    return selected


def supporting_fixture_cleanup():
    from tests.test_postgres_numeric_store import PostgresNumericStoreTests
    from tests.test_ordered_execution_lifecycle_postgres import OrderedExecutionLifecyclePostgresTests
    from tests.test_python_expired_replay_postgres import PythonExpiredReplayPostgresTests
    status = getattr(PostgresNumericStoreTests, 'cleanup_status', None)
    if status != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}:
        raise harness.QualificationError('EXECUTION_OUTPUT_SUPPORTING_CLEANUP_INCOMPLETE')
    lifecycle = getattr(OrderedExecutionLifecyclePostgresTests, 'cleanup_status', None)
    python = getattr(PythonExpiredReplayPostgresTests, 'cleanup_status', None)
    if (lifecycle != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}
            or python != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0, 'remainingExtraRoles': 0}):
        raise harness.QualificationError('EXECUTION_LIFECYCLE_SUPPORTING_CLEANUP_INCOMPLETE')
    return {SUPPORT_CLASS: dict(status), LIFECYCLE_CLASS: dict(lifecycle), PYTHON_CLASS: dict(python)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    selected = validate_scenarios()
    from tests.test_public_execution_output_contracts_postgres import PublicExecutionOutputContractsPostgresTests
    from tests.test_ordered_execution_lifecycle_postgres import OrderedExecutionLifecyclePostgresTests
    from tests.test_python_expired_replay_postgres import PythonExpiredReplayPostgresTests

    harness.TEST_SUITES[SUITE] = (MODULE, CLASS, FORMAT)
    harness.TEST_CASES[SUITE] = selected
    harness.SOURCE_FILES = SOURCE_FILES

    def finalize_proof(proof):
        if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
                or proof.get('testScenarioIds') != list(selected)):
            raise harness.QualificationError('EXECUTION_OUTPUT_PROOF_SCENARIOS_CHANGED')
        proof['supportingFixtureCleanup'] = supporting_fixture_cleanup()
        observations = PublicExecutionOutputContractsPostgresTests.observations
        required = {'two-sequence-examples', 'two-iteration-examples', 'wide-native-delta',
            'rebuild-and-retired-cleanup', 'abandoned-cleanup', 'current-authority', 'stale-source'}
        if len(observations) != len(required) or {item.get('scenario') for item in observations} != required:
            raise harness.QualificationError('EXECUTION_OUTPUT_OBSERVATIONS_INCOMPLETE')
        proof['observations'] = observations
        lifecycle = OrderedExecutionLifecyclePostgresTests.observations
        python = PythonExpiredReplayPostgresTests.lifecycle_observations
        if (len(lifecycle) != 3 or {item.get('scenario') for item in lifecycle} != {
                'old-preview-refusal', 'completed-legacy-replay', 'pending-legacy-refusal'}
                or len(python) != 2 or {item.get('scenario') for item in python} != {
                'python-old-child-recovery', 'python-revocation-between-authorize-and-replay'}):
            raise harness.QualificationError('EXECUTION_LIFECYCLE_OBSERVATIONS_INCOMPLETE')
        schema = OrderedExecutionLifecyclePostgresTests.schema_proof
        if (not isinstance(schema, dict) or not schema.get('before') or not schema.get('after')
                or schema.get('appliedMigrationChainUnchanged') is not True):
            raise harness.QualificationError('EXECUTION_LIFECYCLE_SCHEMA_PROOF_INCOMPLETE')
        proof['lifecycleObservations'] = lifecycle
        proof['pythonLifecycleObservations'] = python
        proof['lifecycleSchemaGraph'] = schema
        proof['invocation']['argv'] = [sys.executable, '-B', '-m',
            'scripts.qualify_public_execution_output_contracts', '--execute',
            '--database-image', args.database_image, '--output', str(args.output)]
        proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* settings excluded; names and values not retained.'
        proof['scope'] = {
            'functions': ['facts.numeric.sequence', 'facts.numeric.iterate',
                'facts.numeric.transform', 'facts.projections.rebuild', 'facts.projections.cleanup'],
            'outputContractFunctions': ['facts.numeric.sequence', 'facts.numeric.iterate',
                'facts.projections.rebuild', 'facts.projections.cleanup'],
            'executionLifecycleFunctions': ['facts.numeric.sequence', 'facts.numeric.iterate',
                'facts.numeric.transform'],
            'examples': 'All seven current published examples: two sequence, convergent and nonconvergent iteration, one current V2 rebuild and retired/abandoned cleanup. Stable coordinates are explicitly rebound; cleanup IDs come from real published/cancelled V2 rebuilds. Original and bound program digests retained.',
            'outputs': 'Actual browser dispatcher/MCP facade previews, submissions, replay envelopes, job checkpoint result fields and published results are validated against the discovered owner schemas. Exact stored receipt results match current direct execution results; public receipt reads expose only their established safe summary.',
            'nonconvergence': 'Native nonconvergent preview creates no job or business effect and has no signed preview fields. A legitimate outer admission alone does not confer native convergence; missing-preview submission is refused. Native opposite-limit amounts produce the valid 21-digit absolute delta.',
            'amountBoundaries': 'A 17-statement public sequence previews and publishes both NUMERIC(28,8) endpoints, large interior fractions, signed half-even ties, add-boundary rounding and current/prior references with exact event values and original replay. Both adapters reject one-unit expression overflow beyond either endpoint with all scoped rows unchanged. Exact prepared-result consumers remain covered by their separate existing tests.',
            'recovery': 'Current rebuild checkpoints leave active reads/history unchanged until activation; cleanup removes only the bound inactive generation and retains current history/reads. A cancelled rebuild retains its last ready checkpoint without becoming ready again. Exact original replay creates no duplicate effects; expired outer admission is refused and known job reads remain available.',
            'authorityAndStaleness': 'Public current-grant revocation fences publication/replay/read; another Reader cannot inspect the owner job. Accepted ordered targets reject changed CAS, rebuild rejects changed source commit, and accepted cleanup tolerates later ordinary writes while target/schema stay fixed.',
            'supportingKernel': 'Six existing native cases retain exact convergence thresholds, presence semantics, vector/local-reference/final-vector criteria, bounded staged reconstruction, Unicode cleanup byte budgets, and ambiguous receipt recovery that remains needs_inspection. Their privileged fixture setup, technical lease fault and direct fixture-owner publication seams are explicit; no snapshot restore is enabled.',
            'executionLifecycle': 'Three separate native cases cover sequence/iteration/transform: authentic unbound or old-plan previews cannot create jobs; current previews publish exact values; reconstructed original-plan completed jobs preserve their original amounts/receipts under exact replay, changed dependency order/intent/authority and current grant revocation are refused; pending old-plan jobs fail before evaluation, with the existing terminal trigger retiring the actual private transform candidate. Only test code temporarily restores the old final SQL division and plan identities. No old evaluator or snapshot is shipped.',
            'pythonLifecycle': 'Two existing-fixture scenarios retain a completed old-plan transform child after a lost second-unit checkpoint: recovery uses the same original job without preview or rebuild, and a real public delegation revocation between parent authorization and original-job lookup is rechecked before checkpointing. Current source/delegation setup and trusted builder launcher remain fixture seams, not OS sandbox proof.',
            'schemaGraph': 'Before/after schema fingerprint and actual migration chain observations bind only the seven new primary cases. Supporting kernel cases use their separately owned database and cleanup proof.',
            'schemaGraphScenarioIds': [MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_CASES)],
            'lifecycleSchemaGraphScenarioIds': [LIFECYCLE_CLASS + '.' + name for name in LIFECYCLE_CASES],
            'fixture': 'Fresh isolated sparse custom-axis fixture with declared identity seam. Current browser/MCP discovery confirms these four generic primitives require no application capability; no retired mode controls or flag changes are used. Seed writes, grants, cancellation and tested effects use public application-language workflows. SQL only observes the new primary cases.',
            'excludedClaims': 'No HTTP/OIDC, rendered UI, installed MCP host, public eight-axis bootstrap, pre-origin/unresolved legacy job replay, historical V1/saved-program upgrade or resubmission, actual host/database upgrade, actual oversized single-row cleanup, performance threshold, deployment, all-function coverage or complete IP-01-AC-02 acceptance. Reconstructed old-plan states use the current proven ordinary/Python origin contract; expired outer ordered admissions remain refused.',
            'cleanup': 'The maintained OwnedDockerRun removes its exact container/volume, primary and supporting fixture owners prove databases/roles gone, and finalization cannot publish evidence if that cleanup or final source checks fail. The supplied existing database image is preserved.',
        }

    saved = {name: value for name, value in os.environ.items() if name.startswith('EPM_TEST_')}
    for name in saved:
        os.environ.pop(name, None)
    try:
        proof = harness.qualify(output=args.output, database_image=args.database_image,
            test_suite=SUITE, finalize_proof=finalize_proof)
    finally:
        for name in tuple(os.environ):
            if name.startswith('EPM_TEST_'):
                os.environ.pop(name, None)
        os.environ.update(saved)
    print(f'Passed {proof["testsRun"]} selected execution output cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
