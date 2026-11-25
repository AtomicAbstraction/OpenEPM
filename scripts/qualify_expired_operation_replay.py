#!/usr/bin/env python3
"""Qualify expired exact-operation replay semantics on an owned disposable PostgreSQL.

Reuse the maintained ownership, full-migration and cleanup harness. No supplied
database DSN, shared application, deployment or public-family retirement occurs.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness


SUITE = 'expired-operation-replay'
SOURCE_FILES = (
    'epm_core/postgres_source_batch.py',
    'epm_core/postgres_source_upload_manifest.py',
    'epm_core/postgres_transfer_orchestration.py',
    'epm_core/expired_operation_replay.py',
    'epm_core/postgres_planning_copy.py',
    'epm_core/postgres_application_schedules.py',
    'epm_core/postgres_application_workflow_occurrences.py',
    'tests/test_schedule_occurrence_read_postgres.py',
    'epm_core/operation_admission_contract.py',
    'epm_core/postgres_import_execution.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'epm_core/postgres_jobs.py',
    'platform_postgres_web_http.py',
    'tests/test_expired_operation_replay_postgres.py',
    'tests/test_operation_admission_contract.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_dimensional_security_enforcement.py',
    'epm_core/postgres_dimensional_security.py',
    'epm_core/postgres_access.py',
    'epm_core/persistence_contract.py',
    'epm_core/postgres_line_detail.py',
    'epm_core/postgres_numeric_store.py',
    'tests/test_source_change_review_postgres.py',
    'tests/test_postgres_numeric_store.py',
    'tests/disposable_storage_fixture.py',
    'scripts/qualify_expired_operation_replay.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    from tests.test_expired_operation_replay_postgres import ExpiredOperationReplayPostgresTests
    required={
        'test_expired_csv_chunk_replays_exact_native_rows_without_staging',
        'test_expired_seal_only_reads_already_ready_exact_batch',
        'test_expired_manifest_exact_outer_request_key_and_foreign_batch_refusal',
        'test_expired_export_cancel_stays_rejected_and_owned_status_reconciles',
    }
    if not required <= set(unittest.defaultTestLoader.getTestCaseNames(
            ExpiredOperationReplayPostgresTests)):
        raise ValueError('SOURCE_STAGING_REPLAY_SCENARIOS_NOT_DISCOVERED')
    harness.TEST_SUITES[SUITE] = (
        'tests.test_expired_operation_replay_postgres',
        'ExpiredOperationReplayPostgresTests',
        'openepm-expired-operation-replay-qualification-v1',
    )
    harness.TEST_CASES[SUITE] = (
        'tests.test_expired_operation_replay_postgres.ExpiredOperationReplayPostgresTests',
    )
    harness.SOURCE_FILES = SOURCE_FILES
    proof = harness.qualify(output=args.output,
        database_image=args.database_image, test_suite=SUITE)
    proof['invocation']['argv'] = [sys.executable, '-m',
        'scripts.qualify_expired_operation_replay', '--execute',
        '--database-image', args.database_image, '--output', str(args.output)]
    proof['scope'] = {
        'currentFix': 'An expired exact admission authenticates only existing request/receipt lookup; missing original never becomes a new effect.',
        'coveredAdapters': 'Real browser dispatcher, MCP application facade with identity fixture seam, and direct fixed core for numeric/detail jobs, schedule lifecycle and workflow occurrence transitions; browser dispatcher for source begin, CSV append, seal, manifest attach, import request, publication, slice-copy prepare and export request.',
        'fixture': 'Fresh migrated PostgreSQL and disposable sparse custom-axis kernel applications; not public eight-axis application creation.',
        'transport': 'No external MCP host, HTTP session verification, live browser or deployed image claim.',
        'authority': 'MAC binds original scope/actor/function/program; every existing owner lookup retains its current transaction permission and actor-bound receipt checks. Expired/new unsupported families still reject.',
        'stagingIdentity': 'Append uses existing owned batch/chunk index/canonical row digest; seal uses existing ready batch/exact totals; neither stores an outer admission receipt. Manifest retains the signed outer key as native requestKey. Replay may only inspect an existing exact native result.',
        'stagingResponseLimits': 'Duplicate append retains current cumulative totals, not a fabricated historical acknowledgement. Seal retains native ready-only response; published/cancelled states fail explicitly instead of being relabelled ready.',
        'exportCancellation': 'Expired cancellation is not replay-enabled: both accepted and unsent original packets are refused without changing export/task rows. Current owner-authorized browser/MCP status reads reconcile cancellation; foreign owners and revoked grants are refused. Status does not attribute a particular cancellation intent.',
    }
    harness.write_json(args.output, proof)
    print(f'Passed {proof["testsRun"]} isolated cases; cleanup verified; evidence: {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
