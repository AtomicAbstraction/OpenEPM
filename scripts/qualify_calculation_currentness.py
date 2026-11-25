#!/usr/bin/env python3
"""Retain actual schemas and cleanup for the existing three currentness cases.

The maintained native harness owns the sole PostgreSQL service and proof write.
This wrapper observes the existing disposable fixture's lifecycle; it neither
changes test bodies nor adds a public-client or authorization claim.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.qualify_source_transfer_roundtrip import observed_runtime, validate_schema
from epm_core.postgres_fresh_baseline import canonical_chain_digest, schema_fingerprint


SUITE = 'impact-submit-race'
FORMAT = 'openepm-impact-submit-race-qualification-v1'
SCENARIOS = (
    'tests.test_calculation_semantic_fanout_postgres.CalculationSemanticFanoutPostgresTests.'
    'test_scoped_currentness_agrees_across_readers_before_and_after_relevant_and_unrelated_impacts',
    'tests.test_postgres_numeric_store.PostgresNumericStoreTests.'
    'test_typed_expression_compiles_exact_set_stage_and_publishes',
    'tests.test_postgres_calculation_dependencies.PostgresCalculationDependenciesTests.'
    'test_w07_partition_publication_is_cas_and_lost_ack_safe',
)
CLEAN = {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}
SOURCE_FILES = tuple(dict.fromkeys((*harness.SOURCE_FILES,
    'scripts/qualify_calculation_currentness.py',
    'scripts/qualify_source_transfer_roundtrip.py',
    'tests/test_calculation_currentness_proof.py',
    'epm_core/postgres_fresh_baseline.py',
    'epm_core/postgres_calculation_status.py',
    'epm_core/postgres_calculation_dependencies.py',
    'epm_core/postgres_calculation_impact.py',
    'epm_core/postgres_calculation_scan.py',
    'epm_core/postgres_cube_layer_report.py',
    'epm_core/postgres_scale.py',
    'epm_core/postgres_resolved_cube_read.py',
    'epm_core/resolved_cube_read_planner.py',
)))


def validate_scenarios():
    selected = harness.TEST_CASES.get(SUITE)
    if (selected != SCENARIOS or len(set(selected)) != 3
            or tuple(harness.scenario_ids(
                unittest.TestLoader().loadTestsFromNames(selected))) != SCENARIOS):
        raise harness.QualificationError('CURRENTNESS_SCENARIOS_CHANGED')
    return SCENARIOS


def schema_observation(fixture):
    """Read the real applied chain and existing canonical physical fingerprint."""
    from psycopg.rows import tuple_row
    expected = [{'version': int(path.name.split('_', 1)[0]),
                 'sha256': sha256(path.read_bytes()).hexdigest()}
                for path in sorted((ROOT / 'schema/postgres').glob('*.sql'))]
    if not expected or [row['version'] for row in expected] != list(range(1, len(expected) + 1)):
        raise harness.QualificationError('CURRENTNESS_CANONICAL_CHAIN_INVALID')
    with fixture.psycopg.connect(fixture.test_dsn, row_factory=tuple_row) as db:
        db.execute('SET TRANSACTION READ ONLY')
        actual = [{'version': version, 'sha256': checksum} for version, checksum in
                  db.execute('SELECT version,checksum FROM epm.schema_migration ORDER BY version').fetchall()]
        physical = schema_fingerprint(db)
    if actual != expected:
        raise harness.QualificationError('CURRENTNESS_APPLIED_CHAIN_MISMATCH')
    return {'canonicalMigrations': actual, 'canonicalChainDigest': canonical_chain_digest(actual),
            'migrationCount': len(actual), 'maximumVersion': actual[-1]['version'],
            'schemaFingerprint': physical}


@contextmanager
def observe_fixture_lifecycle(fixture_type):
    """Observe each actual allocation once; every original cleanup still runs.

    The first selected class uses an owned subclass; the remaining two each
    allocate through this same base class. Allocation identity, not mutable
    class attributes after the suite, binds the three separate databases.
    """
    setup_descriptor = fixture_type.__dict__['setUpClass']
    teardown_descriptor = fixture_type.__dict__['tearDownClass']
    if not isinstance(setup_descriptor, classmethod) or not isinstance(teardown_descriptor, classmethod):
        raise harness.QualificationError('CURRENTNESS_FIXTURE_LIFECYCLE_CHANGED')
    original_setup, original_teardown = setup_descriptor.__func__, teardown_descriptor.__func__
    records = []
    allocations = {}

    def teardown(cls):
        record = allocations.get(getattr(cls, 'database_name', None))
        previous_status = getattr(cls, 'cleanup_status', None)
        try:
            if record is not None and not record['afterAttempted']:
                record['afterAttempted'] = True
                if record['schema']['before'] is not None:
                    record['schema']['after'] = schema_observation(cls)
                    record['schema']['appliedMigrationChainUnchanged'] = (
                        record['schema']['before']['canonicalMigrations'] ==
                        record['schema']['after']['canonicalMigrations'])
        except BaseException:
            if record is not None:
                record['lifecycleFailureObserved'] = True
            raise
        finally:
            succeeded = False
            try:
                original_teardown(cls)
                succeeded = True
            finally:
                if record is not None:
                    record['originalTeardownCalls'] += 1
                    record['lifecycleFailureObserved'] |= not succeeded
                    status = getattr(cls, 'cleanup_status', None)
                    # A retained status from a previous allocation is not proof.
                    if succeeded and status is not previous_status and status == CLEAN:
                        record['cleanup'] = deepcopy(status)
                    else:
                        record['cleanup'] = None

    def setup(cls):
        old_allocation = getattr(cls, 'database_name', None)
        try:
            original_setup(cls)
        except BaseException:
            # The actual fixture already registers idempotent cleanup. Ensure
            # partial allocation cleanup also runs before propagation here.
            if getattr(cls, 'database_name', None) not in (None, old_allocation):
                original_teardown(cls)
            raise
        allocation = getattr(cls, 'database_name', None)
        if (not isinstance(allocation, str) or not allocation.startswith('epm_disposable_')
                or allocation in allocations or len(records) >= len(SCENARIOS)):
            original_teardown(cls)
            raise harness.QualificationError('CURRENTNESS_FIXTURE_ALLOCATION_CHANGED')
        record = {'scenarioId': SCENARIOS[len(records)],
                  'fixtureOwnerClass': cls.__module__ + '.' + cls.__qualname__,
                  'allocationSha256': sha256(allocation.encode('utf-8')).hexdigest(),
                  'schema': {'before': None, 'after': None,
                             'physicalFingerprintEqualityRequired': False,
                             'appliedMigrationChainUnchanged': False,
                             'scope': 'Actual separate disposable fixture; physical fingerprint includes mutable sequence and fixture-role state.'},
                  'afterAttempted': False, 'originalTeardownCalls': 0,
                  'lifecycleFailureObserved': False, 'cleanup': None}
        records.append(record)
        allocations[allocation] = record
        try:
            record['schema']['before'] = schema_observation(cls)
        except BaseException:
            record['lifecycleFailureObserved'] = True
            teardown(cls)
            raise

    try:
        fixture_type.setUpClass = classmethod(setup)
        fixture_type.tearDownClass = classmethod(teardown)
        yield records
    finally:
        fixture_type.setUpClass = setup_descriptor
        fixture_type.tearDownClass = teardown_descriptor


def finalize(proof, *, records, runtime, output):
    if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
            or proof.get('testScenarioIds') != list(SCENARIOS) or proof.get('testsRun') != 3
            or any(proof.get(key) != 0 for key in ('failures', 'errors', 'skipped'))):
        raise harness.QualificationError('CURRENTNESS_PROOF_SCENARIOS_CHANGED')
    if (len(records) != 3 or [row['scenarioId'] for row in records] != list(SCENARIOS)
            or len({row['allocationSha256'] for row in records}) != 3):
        raise harness.QualificationError('CURRENTNESS_FIXTURE_OBSERVATIONS_INCOMPLETE')
    schemas, cleanup = {}, {}
    for row in records:
        if (row['originalTeardownCalls'] < 1 or row['cleanup'] != CLEAN
                or not row['afterAttempted'] or row.get('lifecycleFailureObserved') is not False):
            raise harness.QualificationError('CURRENTNESS_FIXTURE_CLEANUP_INCOMPLETE')
        schemas[row['scenarioId']] = validate_schema(row['schema'], proof['migrationSha256'])
        cleanup[row['scenarioId']] = {**row['cleanup'], 'allocationSha256': row['allocationSha256'],
                                      'fixtureOwnerClass': row['fixtureOwnerClass'],
                                      'originalTeardownCalls': row['originalTeardownCalls']}
    identity = proof.get('ownedRunIdentity') or {}
    if (set(identity) != {'runId', 'context', 'daemonId'}
            or not isinstance(identity['runId'], str) or not identity['runId']
            or identity['runId'] != proof.get('cleanup', {}).get('runId')
            or proof.get('cleanup', {}).get('cleanupVerified') is not True
            or any(identity[k] != runtime['docker'][k] for k in ('context', 'daemonId'))
            or proof.get('localPostgresImage') != runtime['image']['id']):
        raise harness.QualificationError('CURRENTNESS_RUNTIME_IDENTITY_MISMATCH')
    if observed_runtime(runtime['image']['id']) != runtime:
        raise harness.QualificationError('CURRENTNESS_RUNTIME_CHANGED')
    proof['fixtureSchemas'] = deepcopy(schemas)
    proof['schemaGraph'] = deepcopy(schemas[SCENARIOS[0]])
    proof['allFixtureCleanup'] = cleanup
    proof['hostRuntimeImage'] = deepcopy(runtime)
    proof['invocation']['argv'] = [sys.executable, '-B', '-m',
        'scripts.qualify_calculation_currentness', '--execute', '--database-image',
        runtime['image']['id'], '--output', str(output)]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; values never retained.'
    proof['scope'] = {
        'criterion': 'IP-04-AC-02',
        'tests': 'The three existing impact-submit-race methods and their exact original IDs; no changed assertions or injected business results.',
        'currentness': 'Actual full/scan/layer/status/resolved/consumer reads across pending, unrelated, relevant and foreign-producer transitions; scoped-manifest and legacy-revision differences retained.',
        'effects': 'Existing typed expression submit revision and required-epoch publication CAS/lost-ack fences remain separate supporting cases.',
        'schema': 'Each of three distinct actual allocations has before/after applied chain and physical fingerprint, captured before its real teardown. Primary schemaGraph is only the first fixture; no borrowed physical fingerprint.',
        'fixture': 'Disposable native component qualification with explicit verified identity, direct fixed-core calls and existing privileged technical metadata/manifest setup. Not a public bootstrap or browser/MCP/OIDC end-to-end journey.',
        'cleanup': 'Original fixture cleanup is never skipped, including duplicate callbacks. Each allocation must have fresh exact zero remaining database/role evidence before the maintained harness sole write.',
        'excludedClaims': 'No UI, installed client, source-wide acceptance, performance target, deployment, shared business mutation, snapshot restore or new architecture.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    validate_scenarios()
    from tests.test_postgres_numeric_store import PostgresNumericStoreTests
    saved_env = {key: value for key, value in os.environ.items() if key.startswith('EPM_TEST_')}
    saved_sources = harness.SOURCE_FILES
    try:
        for key in saved_env:
            os.environ.pop(key, None)
        harness.SOURCE_FILES = SOURCE_FILES
        runtime = observed_runtime(args.database_image)
        with observe_fixture_lifecycle(PostgresNumericStoreTests) as records:
            proof = harness.qualify(output=args.output, database_image=args.database_image,
                test_suite=SUITE, finalize_proof=lambda result:
                    finalize(result, records=records, runtime=runtime, output=args.output))
    finally:
        harness.SOURCE_FILES = saved_sources
        for key in tuple(os.environ):
            if key.startswith('EPM_TEST_'):
                os.environ.pop(key, None)
        os.environ.update(saved_env)
    print(f'Passed {proof["testsRun"]} currentness cases; all fixture cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
