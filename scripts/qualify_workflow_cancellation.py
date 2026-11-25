#!/usr/bin/env python3
"""Qualify exact cancellation outcomes using the maintained native harness.

The harness owns one disposable PostgreSQL service, cleanup and the sole proof
write. The two source/build fixtures use separately observed allocations.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import importlib
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.qualify_public_sequence_replacement import SOURCE_FILES as RULE_SOURCES
from scripts.qualify_source_transfer_roundtrip import observed_runtime, validate_schema

SUITE = 'workflow-cancellation'
FORMAT = 'openepm-workflow-cancellation-qualification-v1'
MODULE = 'tests.test_workflow_cancellation_postgres'
RULE_CLASS = 'RuleCancellationPostgresTests'
PYTHON_CLASS = 'PythonCancellationPostgresTests'
COMMON = (
    'test_published_lost_tail_preserves_receipts_and_remaining_unit',
    'test_ready_tail_cancelled_with_current_authority',
    'test_cancel_wins_before_fresh_admission',
    'test_admission_row_lock_orders_cancel',
    'test_child_publication_cancel_races',
    'test_worker_denial_parks_and_explicit_control_rearms',
    'test_worker_lease_recovery_preserves_cancel_intent',
)
CASE_NAMES = {
    RULE_CLASS: COMMON,
    PYTHON_CLASS: (*COMMON, 'test_legacy_exact_and_unprovable_tail_dispositions'),
}
SCENARIOS = tuple(MODULE + '.' + owner + '.' + case
                  for owner, cases in CASE_NAMES.items() for case in cases)
CLEAN = {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}
SOURCE_FILES = tuple(dict.fromkeys((*RULE_SOURCES,
    'scripts/qualify_workflow_cancellation.py',
    'scripts/qualify_calculation_currentness.py',
    'tests/test_workflow_cancellation_postgres.py',
    'tests/test_workflow_cancellation_proof.py',
    'tests/test_python_expired_replay_postgres.py',
    'tests/test_python_builder_runtime.py',
    'tests/test_cancel_tail_recovery.py',
    'tests/test_workflow_cancellation_parking.py',
    'tests/test_task_latest_diagnostic.py',
    'epm_core/python_plan_runner.py',
    'epm_core/python_program_execution.py',
    'epm_core/postgres_python_workflow.py',
    'epm_core/postgres_python_run.py',
    'epm_core/postgres_job_origin.py',
    'epm_core/postgres_python_workflow_dispatch.py',
    'epm_core/postgres_application_rule_dispatch.py',
    'epm_core/postgres_worker_service.py',
    'epm_core/postgres_tasks.py',
)))


def fixture_types():
    module = importlib.import_module(MODULE)
    return {name: getattr(module, name) for name in CASE_NAMES}


def validate_selection(fixtures):
    loader = unittest.TestLoader()
    if set(fixtures) != set(CASE_NAMES):
        raise harness.QualificationError('CANCELLATION_FIXTURE_INVENTORY_CHANGED')
    for name, fixture in fixtures.items():
        if set(loader.getTestCaseNames(fixture)) != set(CASE_NAMES[name]):
            raise harness.QualificationError('CANCELLATION_SCENARIOS_CHANGED')
    actual = tuple(harness.scenario_ids(loader.loadTestsFromNames(SCENARIOS)))
    if actual != SCENARIOS or len(set(actual)) != len(SCENARIOS):
        raise harness.QualificationError('CANCELLATION_SCENARIOS_CHANGED')


def finalize(proof, *, fixtures, runtime, output):
    if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
            or proof.get('testScenarioIds') != list(SCENARIOS)
            or proof.get('testsRun') != len(SCENARIOS)
            or any(proof.get(key) != 0 for key in ('failures', 'errors', 'skipped'))
            or set(fixtures) != set(CASE_NAMES)):
        raise harness.QualificationError('CANCELLATION_PROOF_SCENARIOS_CHANGED')
    schemas, cleanups, observations, allocations = {}, {}, {}, set()
    for name, fixture in fixtures.items():
        schema = validate_schema(getattr(fixture, 'schema_proof', None), proof['migrationSha256'])
        # Underlying setup helpers reuse class attributes across allocations.
        # Only the observation captured at this fixture's own teardown proves
        # its cleanup; the last helper's mutable database_name cannot do so.
        allocation = getattr(fixture, 'allocation_name', None)
        if not isinstance(allocation, str) or not allocation.startswith('epm_disposable_'):
            raise harness.QualificationError('CANCELLATION_ALLOCATION_UNPROVEN')
        allocation_digest = sha256(allocation.encode()).hexdigest()
        cleanup = getattr(fixture, 'cleanup_status', None)
        if (allocation_digest in allocations
                or allocation_digest != getattr(fixture, 'allocation_sha256', None)
                or allocation_digest != schema.get('allocationSha256')
                or cleanup != {**CLEAN, 'remainingExtraRoles': 0, 'allocationSha256': allocation_digest}
                or getattr(fixture, 'fixture_cleanup_status', None) != CLEAN):
            raise harness.QualificationError('CANCELLATION_FIXTURE_CLEANUP_INCOMPLETE')
        values = getattr(fixture, 'observations', None)
        if (type(values) is not list or len(values) != len(CASE_NAMES[name])
                or any(type(row) is not dict for row in values)
                or {row.get('case') for row in values} != set(CASE_NAMES[name])):
            raise harness.QualificationError('CANCELLATION_OBSERVATIONS_INCOMPLETE')
        allocations.add(allocation_digest)
        schemas[name] = deepcopy(schema)
        cleanups[name] = {**cleanup, 'allocationSha256': allocation_digest}
        observations[name] = deepcopy(values)
    if (proof.get('schemaGraph') != schemas[RULE_CLASS]
            or proof.get('databaseRoleCleanup') != CLEAN
            or any(proof.get('extraFixtureCleanup', {}).get(key) != 0 for key in CLEAN)):
        raise harness.QualificationError('CANCELLATION_PRIMARY_FIXTURE_MISMATCH')
    identity = proof.get('ownedRunIdentity') or {}
    cleanup = proof.get('cleanup') or {}
    if (set(identity) != {'runId', 'context', 'daemonId'}
            or type(identity.get('runId')) is not str or not identity['runId']
            or identity['runId'] != cleanup.get('runId')
            or cleanup.get('cleanupVerified') is not True
            or cleanup.get('status') != 'complete' or cleanup.get('pending') != []
            or cleanup.get('runOutcome') != 'succeeded'
            or any(identity[k] != runtime['docker'][k] for k in ('context', 'daemonId'))
            or proof.get('localPostgresImage') != runtime['image']['id']
            or observed_runtime(runtime['image']['id']) != runtime):
        raise harness.QualificationError('CANCELLATION_RUNTIME_CHANGED')
    proof['fixtureSchemas'] = schemas
    proof['allFixtureCleanup'] = cleanups
    proof['cancellationObservations'] = observations
    proof['hostRuntimeImage'] = deepcopy(runtime)
    proof['invocation']['argv'] = [sys.executable, '-B', '-m',
        'scripts.qualify_workflow_cancellation', '--execute', '--database-image',
        runtime['image']['id'], '--output', str(output)]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; values never retained.'
    proof['scope'] = {
        'criterion': 'IP-09-AC-04 component; complete cancellation acceptance requires all remaining worker, legacy and presentation gates.',
        'fixture': 'Two actual disposable native source/build allocations; fixed-core and facade calls use verified fixture identities. Existing trusted builder and privileged setup seams are explicit, not HTTP/OIDC or packaged sandbox qualification.',
        'effects': 'Existing parent/child receipt and cancellation owners, no compensation or rollback claim. Committed counts are the receipt-confirmed prefix; remaining includes unresolved units whose effect is not yet proven.',
        'races': 'Declared exact method inventory; deterministic event gates exercise actual admission/publication transactions. Each retained observation describes its actual winner and protected effects.',
        'legacy': 'Bounded retained descriptor reconstruction in the named case only; no shared old population inventory, customer upgrade or retirement approval. The unprovable old tail is first retained ready and uncontrolled, then the original child independently publishes through its fixed worker. The parent remains cancel_requested with receipt-confirmed checkpoint counts and publicly described unresolved remaining units; no unproved linkage or exact physical-effect total is inferred.',
        'schema': 'Separate before/after applied migration chain and physical fingerprint for each actual allocation, observed before real teardown; no borrowed fingerprint.',
        'cleanup': 'Existing harness owns services and sole proof publication; both original fixture database/role cleanups and coordinator-role cleanup must pass.',
        'exclusions': 'No installed release, broad source regression, performance, shared application mutation or completed package claim.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fixtures = fixture_types()
    validate_selection(fixtures)
    previous = {key: value for key, value in os.environ.items() if key.startswith('EPM_TEST_')}
    try:
        for key in previous:
            os.environ.pop(key)
        runtime = observed_runtime(args.database_image)
        with mock.patch.dict(harness.TEST_SUITES, {SUITE: (MODULE, RULE_CLASS, FORMAT)}), \
                mock.patch.dict(harness.TEST_CASES, {SUITE: SCENARIOS}), \
                mock.patch.object(harness, 'SOURCE_FILES', SOURCE_FILES):
            proof = harness.qualify(output=args.output, database_image=args.database_image,
                test_suite=SUITE, finalize_proof=lambda value:
                    finalize(value, fixtures=fixtures, runtime=runtime, output=args.output))
    finally:
        for key in tuple(os.environ):
            if key.startswith('EPM_TEST_'):
                os.environ.pop(key, None)
        os.environ.update(previous)
    print(f'Passed {proof["testsRun"]} native cancellation cases; owned cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
