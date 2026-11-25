#!/usr/bin/env python3
"""Qualify owner-supplied public read contracts on an owned disposable PostgreSQL.

Reuse the maintained ownership, full-migration and cleanup harness. No supplied
database DSN, shared application, deployment or public-family retirement occurs.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness


SUITE = 'public-read-contract'
SOURCE_FILES = (
    'epm_core/metadata_read_contract.py',
    'epm_core/expired_operation_replay.py',
    'epm_core/postgres_export_producer_checkpoint.py',
    'epm_core/postgres_transfer_orchestration.py',
    'tests/test_expired_operation_replay_postgres.py',
    'tests/test_expired_operation_replay_discovery.py',
    'tests/test_schedule_occurrence_read_postgres.py',
    'tests/test_source_change_review_postgres.py',
    'epm_core/public_program_contracts.py',
    'epm_core/public_program_diagnostics.py',
    'epm_core/postgres_application_capabilities.py',
    'epm_core/postgres_metadata.py',
    'epm_core/postgres_capability_contract.py',
    'epm_core/processing_operation_registry.py',
    'epm_core/application_catalog_projection.py',
    'epm_core/postgres_calculation_inspection.py',
    'epm_core/postgres_operation_receipts.py',
    'epm_core/postgres_planning_copy.py',
    'epm_core/slice_copy_contract.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'platform_postgres_web_http.py',
    'openepm/discovery_contract.py',
    'openepm/functions.py',
    'tests/test_public_read_program_contracts.py',
    'tests/source_definition_authoring_fixture.py',
    'scripts/programmable_source_authoring.py',
    'tests/test_postgres_numeric_store.py',
    'tests/disposable_storage_fixture.py',
    'scripts/qualify_public_read_contract.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    from epm_core.public_program_contracts import READ_FUNCTIONS
    from tests.test_expired_operation_replay_postgres import ExpiredOperationReplayPostgresTests

    harness.TEST_SUITES[SUITE] = (
        'tests.test_public_read_program_contracts',
        'PublicReadContractPostgresTests',
        'openepm-public-read-contract-qualification-v1',
    )
    harness.TEST_CASES[SUITE] = (
        'tests.test_public_read_program_contracts.PublicReadContractPostgresTests',
        'tests.test_expired_operation_replay_postgres.ExpiredOperationReplayPostgresTests',
    )
    harness.SOURCE_FILES = SOURCE_FILES
    def finalize_proof(proof):
        replay_fixture = ExpiredOperationReplayPostgresTests.fixture_class.fixture
        cleanup = getattr(replay_fixture, 'cleanup_status', None)
        if cleanup != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}:
            raise harness.QualificationError('PUBLIC_READ_REPLAY_FIXTURE_CLEANUP_INCOMPLETE')
        proof['supportingFixtureCleanup'] = {'expiredOperationReplay': cleanup}
        proof['invocation']['argv'] = [sys.executable, '-B', '-m',
            'scripts.qualify_public_read_contract', '--execute',
            '--database-image', args.database_image, '--output', str(args.output)]
        proof['scope'] = {
            'testedReadExamples': sorted(READ_FUNCTIONS | {'application.workflow.occurrence.read'}),
            'coveredAdapters': 'Fixed core, real Browser dispatcher and MCP application facade with verified fixture identities.',
            'fixture': 'Fresh migrated disposable PostgreSQL with sparse kernel applications. Public programs supply the current calculation binding and original copy operation.',
            'authority': 'Stale metadata, unknown references and current grant revocation are refused by the fixed core.',
            'recoveryRegression': 'Expired original requests reconcile retained outcomes. A structurally valid change to the reviewed state token is refused on Browser and MCP.',
            'remainingQualification': 'External MCP hosts, signed HTTP sessions, rendered Browser and deployed images are outside this run.',
        }

    proof = harness.qualify(output=args.output, database_image=args.database_image,
        test_suite=SUITE, finalize_proof=finalize_proof)
    print(f'Passed {proof["testsRun"]} isolated cases; cleanup verified; evidence: {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
