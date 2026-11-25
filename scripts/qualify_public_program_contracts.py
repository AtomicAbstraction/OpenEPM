#!/usr/bin/env python3
"""Qualify selected public contracts on owned disposable PostgreSQL.

Reuse the maintained full-migration/OwnedDockerRun harness. This is a bounded
contract and native-owner regression, not qualification of every public function.
No supplied database, template, snapshot restore or shared application is used.
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


SUITE = 'public-program-contracts'
MODULE = 'tests.test_public_contract_diagnostics_postgres'
CLASS = 'PublicContractDiagnosticsPostgresTests'
READ_CLASS = 'tests.test_public_read_program_contracts.PublicReadContractPostgresTests'
REQUIRED_DIAGNOSTIC_CASES = frozenset((
    'test_common_errors_are_canonical_nonreflecting_and_leave_full_state_unchanged',
    'test_six_owner_structural_errors_fail_before_admission_or_business_work',
    'test_valid_cube_read_still_enforces_current_grants_and_wrong_scope',
))
REQUIRED_READ_CASES = frozenset((
    'test_published_read_examples_match_adapter_shapes',
    'test_schema_does_not_bypass_native_stale_reference_or_authorization',
))
COPY_CASE = ('tests.test_slice_copy_contract.SliceCopyPostgresTests.'
    'test_public_catalogue_mcp_browser_exact_replay_and_concurrent_identity')
RECOVERY_CASE = ('tests.test_postgres_numeric_store.PostgresNumericStoreTests.'
    'test_projection_cleanup_retired_preserves_current_history_and_mvcc')

SOURCE_FILES = (
    'epm_core/public_program_contracts.py',
    'epm_core/public_program_diagnostics.py',
    'epm_core/mcp_diagnostics.py',
    'epm_core/metadata_read_contract.py',
    'epm_core/python_execution_contract.py',
    'epm_core/postgres_capability_contract.py',
    'epm_core/processing_operation_registry.py',
    'epm_core/postgres_cube_select.py',
    'epm_core/slice_copy_contract.py',
    'epm_core/postgres_planning_copy.py',
    'epm_core/postgres_fact_reconstruction_job.py',
    'epm_core/postgres_projection_cleanup.py',
    'epm_core/postgres_numeric_catalog.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'platform_postgres_web_http.py',
    'tests/test_public_contract_diagnostics_postgres.py',
    'tests/test_public_read_program_contracts.py',
    'tests/test_slice_copy_contract.py',
    'tests/test_expired_operation_replay_postgres.py',
    'tests/test_source_change_review_postgres.py',
    'tests/test_postgres_numeric_store.py',
    # The new fixture borrows only schema observation methods from this class.
    # None of its four ordered-expression tests are selected by this runner.
    'tests/test_ordered_expression_profile_postgres.py',
    'tests/test_ordered_expression_profile.py',
    'tests/numeric_sequence_expression_fixture.py',
    'tests/numeric_sequence_fixture.py',
    'tests/fact_reconstruction_fixture.py',
    'tests/fact_reconstruction_publication_fixture.py',
    'tests/staged_projection_recovery_fixture.py',
    'tests/projection_cleanup_fixture.py',
    'tests/projection_generation_fixture.py',
    'tests/mcp_inline_fixture.py',
    'tests/disposable_storage_fixture.py',
    'scripts/apply_postgres_migrations.py',
    'scripts/qualify_public_program_contracts.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)


def selected_tests():
    return (
        *(MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_DIAGNOSTIC_CASES)),
        *(READ_CLASS + '.' + name for name in sorted(REQUIRED_READ_CASES)),
        COPY_CASE,
        RECOVERY_CASE,
    )


def validate_scenarios():
    """Reject missing/extra primary cases before any service can be started."""
    from tests.test_public_contract_diagnostics_postgres import PublicContractDiagnosticsPostgresTests
    from tests.test_public_read_program_contracts import PublicReadContractPostgresTests

    loader = unittest.TestLoader()
    for owner, required in ((PublicContractDiagnosticsPostgresTests, REQUIRED_DIAGNOSTIC_CASES),
                            (PublicReadContractPostgresTests, REQUIRED_READ_CASES)):
        if set(loader.getTestCaseNames(owner)) != required:
            raise harness.QualificationError('PUBLIC_CONTRACT_SCENARIOS_CHANGED')
    selected = selected_tests()
    if (len(selected) != 7 or len(set(selected)) != 7
            or tuple(harness.scenario_ids(loader.loadTestsFromNames(selected))) != selected):
        raise harness.QualificationError('PUBLIC_CONTRACT_SCENARIOS_CHANGED')
    return selected


def supporting_fixture_cleanup():
    """Retain each supporting fixture's own exact database/role cleanup check."""
    from tests.test_public_read_program_contracts import PublicReadContractPostgresTests
    from tests.test_slice_copy_contract import SliceCopyPostgresTests
    from tests.test_postgres_numeric_store import PostgresNumericStoreTests

    owners = (
        (READ_CLASS, PublicReadContractPostgresTests.fixture),
        ('tests.test_slice_copy_contract.SliceCopyPostgresTests',
         SliceCopyPostgresTests.fixture_class.fixture_class.fixture),
        ('tests.test_postgres_numeric_store.PostgresNumericStoreTests', PostgresNumericStoreTests),
    )
    result = {}
    for name, owner in owners:
        status = getattr(owner, 'cleanup_status', None)
        if status != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}:
            raise harness.QualificationError('PUBLIC_CONTRACT_SUPPORTING_CLEANUP_INCOMPLETE')
        result[name] = dict(status)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    selected = validate_scenarios()
    from tests.test_public_contract_diagnostics_postgres import PublicContractDiagnosticsPostgresTests

    harness.TEST_SUITES[SUITE] = (
        MODULE, CLASS, 'openepm-public-program-contract-qualification-v1')
    harness.TEST_CASES[SUITE] = selected
    harness.SOURCE_FILES = SOURCE_FILES

    def finalize_proof(proof):
        # The maintained harness invokes this after owned cleanup and before
        # its final source check and sole canonical proof write.
        if (proof.get('testSuite') != SUITE
                or proof.get('format') != 'openepm-public-program-contract-qualification-v1'
                or proof.get('testScenarioIds') != list(selected)):
            raise harness.QualificationError('PUBLIC_CONTRACT_PROOF_SCENARIOS_CHANGED')
        proof['supportingFixtureCleanup'] = supporting_fixture_cleanup()
        proof['invocation']['argv'] = [sys.executable, '-B', '-m',
            'scripts.qualify_public_program_contracts', '--execute',
            '--database-image', args.database_image, '--output', str(args.output)]
        proof['invocation']['ambientTestSettings'] = (
            'All EPM_TEST_* settings excluded; names and values not retained.')
        proof['observations'] = PublicContractDiagnosticsPostgresTests.observations
        proof['scope'] = {
            'change': 'Fixed unknown/version guidance and bounded structural diagnostics from the explicitly qualified owner schemas; native semantics and authority remain mandatory.',
            'diagnostics': 'Three new cases use the real browser dispatcher and MCP application facade with the verified-identity fixture seam, full scoped row equality, a valid cube read and native grant/scope refusals.',
            'readExamples': 'Two cases bind current read-owner first examples and the workflow occurrence example to native result schemas, pagination, current references and authorization. Workflow reads bind the occurrence ID returned by the typed authoring flow. Privileged grant removal in the negative fixture is an explicit test seam.',
            'copy': 'One current generic slice-copy case uses native MCP/browser/core calls, exact source publication, result-schema validation, replay and concurrent identity. No retired planning-copy alias is revived.',
            'rebuildAndCleanup': 'One existing case accepts and completes current V2 staged rebuild and derived-generation cleanup, preserving exact current values/history, MVCC readback and original replay. Its historical V1 admission helper is not invoked.',
            'schemaGraph': 'Before/after physical schema and canonical migration observations apply only to the fixture for the three new diagnostic cases; supporting classes have their own fresh full-migration databases, not this same physical fingerprint.',
            'schemaGraphScenarioIds': [MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_DIAGNOSTIC_CASES)],
            'fixture': 'Disposable sparse custom-axis kernel applications; established supporting fixtures use privileged sparse metadata setup and fixed-core seeds. No public eight-axis bootstrap or unaided client journey is claimed.',
            'excludedClaims': 'No external HTTP/OIDC, installed MCP host, rendered browser, snapshot restore, installed upgrade, deployment, all-function parser coverage or full IP-01-AC-02 acceptance. The separate ordered18 runner retains ordered/iteration/exact-arithmetic qualification.',
            'cleanup': 'The maintained owner removes its exact container/volume and primary fixture database/roles; each supporting fixture records its own database/role cleanup. The supplied preexisting PostgreSQL image is preserved. Separately campaign-owned OIDC images are removed and evidenced outside this runner.',
        }

    # Clear every ambient fixture switch, including optional logical restores.
    # The established owner alone supplies its freshly generated loopback DSN.
    saved = {name: value for name, value in os.environ.items() if name.startswith('EPM_TEST_')}
    for name in saved:
        os.environ.pop(name, None)
    try:
        proof = harness.qualify(output=args.output,
            database_image=args.database_image, test_suite=SUITE,
            finalize_proof=finalize_proof)
    finally:
        for name in tuple(os.environ):
            if name.startswith('EPM_TEST_'):
                os.environ.pop(name, None)
        os.environ.update(saved)
    print(f'Passed {proof["testsRun"]} selected public contract cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
