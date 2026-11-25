#!/usr/bin/env python3
"""Qualify complete layout discovery on the maintained owned PostgreSQL harness.

Two selected public-adapter cases share one actual schema lifetime. This does
not claim HTTP/OIDC, the signed restart fixture, or large-scale performance.
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
from scripts.qualify_public_mutation_contracts import (
    SOURCE_FILES as MUTATION_SOURCES, host_observation, validate_schema_graph)

SUITE = 'populated-layout-source'
MODULE = 'tests.test_populated_layout_source_postgres'
CLASS = 'PopulatedLayoutSourcePostgresTests'
FORMAT = 'openepm-populated-layout-source-qualification-v1'
REQUIRED_CASES = frozenset((
    'test_complete_public_inventory_includes_registration_only_and_builds_existing_plan',
    'test_current_admin_and_dimensional_read_revoke_regrant_are_all_or_refuse',
))
SOURCE_FILES = tuple(dict.fromkeys((*MUTATION_SOURCES,
    'epm_core/postgres_populated_layout_preview.py',
    'epm_core/populated_layout_mapping.py',
    'epm_core/postgres_populated_layout_replacement.py',
    'epm_core/postgres_dimensional_security_policies.py',
    'epm_core/postgres_dimensional_scope.py',
    'epm_core/postgres_processing_limits.py',
    'epm_core/postgres_execution_scope.py',
    'epm_core/postgres_execution_policy.py',
    'epm_core/dimensional_access_registry.py',
    'tests/test_postgres_populated_layout_preview.py',
    'tests/test_populated_layout_preview_public.py',
    'tests/test_populated_layout_source_postgres.py',
    'tests/test_populated_layout_source_qualification.py',
    'scripts/qualify_populated_layout_source.py',
)))
REQUIRED_OBSERVATIONS = {
    'complete-source-and-public-preview': {
        'sourceCoordinates': 5, 'rawScanCoordinates': 4, 'numericZero': True,
        'textBlank': True, 'detailEmptyPresent': True, 'clearedCoordinate': True,
        'registeredCalculatedTargetWithoutRawFact': True,
        'publicConstruction': True, 'canonicalPlanUnchanged': True},
    'current-authority-all-or-refuse': {
        'requireAssignmentAdministratorEnforced': True,
        'configuredAdministratorBypassEnforced': True,
        'noFilteredPartialSuccess': True, 'exactRegrantWithoutPublication': True,
        'readerAndWrongApplicationRefused': True},
}


def validate_scenarios():
    from tests.test_populated_layout_source_postgres import PopulatedLayoutSourcePostgresTests
    loader = unittest.TestLoader()
    selected = tuple(MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_CASES))
    if (set(loader.getTestCaseNames(PopulatedLayoutSourcePostgresTests)) != REQUIRED_CASES
            or len(selected) != 2
            or tuple(harness.scenario_ids(loader.loadTestsFromNames(selected))) != selected):
        raise harness.QualificationError('LAYOUT_SOURCE_SCENARIOS_CHANGED')
    return selected


def finalize(proof, *, selected, host, database_image, output):
    from tests.test_populated_layout_source_postgres import PopulatedLayoutSourcePostgresTests as fixture
    if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
            or proof.get('testScenarioIds') != list(selected) or proof.get('testsRun') != 2
            or any(type(proof.get(key)) is not int or proof[key] != 0 for key in ('failures', 'errors', 'skipped'))):
        raise harness.QualificationError('LAYOUT_SOURCE_PROOF_SCENARIOS_CHANGED')
    cleanup = proof.get('cleanup') or {}
    owned = proof.get('ownedRunIdentity') or {}
    if (proof.get('databaseRoleCleanup') != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}
            or cleanup.get('cleanupVerified') is not True
            or cleanup.get('status') != 'complete' or cleanup.get('runOutcome') != 'succeeded'
            or cleanup.get('pending') != []
            or any(type(owned.get(key)) is not str or not owned[key] for key in ('runId', 'context', 'daemonId'))
            or cleanup.get('runId') != owned['runId']):
        raise harness.QualificationError('LAYOUT_SOURCE_CLEANUP_INCOMPLETE')
    if proof.get('schemaGraph') != fixture.schema_proof:
        raise harness.QualificationError('LAYOUT_SOURCE_SCHEMA_OWNER_MISMATCH')
    validate_schema_graph(proof.get('schemaGraph'), proof.get('migrationSha256', {}))
    if host_observation() != host:
        raise harness.QualificationError('LAYOUT_SOURCE_HOST_CHANGED')
    observations = fixture.observations
    if (not isinstance(observations, list) or len(observations) != 2
            or {item.get('scenario') for item in observations} != set(REQUIRED_OBSERVATIONS)):
        raise harness.QualificationError('LAYOUT_SOURCE_OBSERVATIONS_INCOMPLETE')
    for item in observations:
        digest = item.get('snapshotSha256')
        if (item.get('allScopedRowsUnchangedDuringRead') is not True
                or type(item.get('scopedTableCount')) is not int or item['scopedTableCount'] < 1
                or type(digest) is not str or len(digest) != 64
                or any(char not in '0123456789abcdef' for char in digest)
                or any(type(item.get(key)) is not type(expected) or item[key] != expected
                       for key, expected in REQUIRED_OBSERVATIONS[item['scenario']].items())):
            raise harness.QualificationError('LAYOUT_SOURCE_OBSERVATION_MISMATCH')
    proof['host'] = host
    proof['observations'] = observations
    proof['invocation']['argv'] = [sys.executable, '-B', '-m',
        'scripts.qualify_populated_layout_source', '--execute',
        '--database-image', database_image, '--output', str(output)]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* settings excluded; names and values not retained.'
    proof['scope'] = {
        'functions': ['metadata.layout.populated.source.read', 'metadata.layout.populated.preview'],
        'construction': 'Actual public browser dispatcher/MCP facade inventory and preview use all physical source coordinates, including a target registered by public expression publication without a raw fact. Public numeric zero, blank text, empty detail and cleared coordinates retain exact physical IDs and member maps. The existing canonical plan and request validator remain unchanged.',
        'authority': 'Current Administrator plus current exact-coordinate READ are required. Active require_assignment denies the whole inventory after public assignment revoke; exact regrant restores it. Explicit administrator bypass follows the same current policy owner. Reader and wrong-application access refuse. Read phases preserve all scoped rows.',
        'schemaGraphScenarioIds': list(selected),
        'schemaGraph': 'Both cases share this actual before/after schema and canonical migration observation. Mutable physical fingerprints are retained; canonical migrations must agree. Host, immutable image, configuration and cleanup belong to this same maintained run.',
        'fixture': 'Isolated sparse one-axis fixture, inherited privileged bootstrap and explicit verified-identity seam. New metadata, data, policy and grants use current public workflows; SQL only observes exact scoped rows.',
        'limits': 'One coordinate SELECT snapshot, at most 100000 rows and 32 MiB public envelope, no pagination. Later registration-only rows can invalidate preview despite unchanged five pins. Byte/count/deadline failure tests are separate pure owner evidence; these two native cases do not qualify the maximum-size performance envelope.',
        'excludedClaims': 'No HTTP/OIDC, rendered UI, installed MCP client, replacement activation/restart, historical upgrade, whole catalogue or criterion acceptance.',
        'cleanup': 'The sole maintained OwnedDockerRun finalizer publishes only after its exact database/roles/container/volume cleanup. The supplied preexisting PostgreSQL image is preserved.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    selected = validate_scenarios()
    host = host_observation()
    harness.TEST_SUITES[SUITE] = (MODULE, CLASS, FORMAT)
    harness.TEST_CASES[SUITE] = selected
    harness.SOURCE_FILES = SOURCE_FILES
    saved = {key: value for key, value in os.environ.items() if key.startswith('EPM_TEST_')}
    for key in saved:
        os.environ.pop(key, None)
    try:
        proof = harness.qualify(output=args.output, database_image=args.database_image,
            test_suite=SUITE, finalize_proof=lambda proof: finalize(proof,
                selected=selected, host=host, database_image=args.database_image, output=args.output))
    finally:
        for key in tuple(os.environ):
            if key.startswith('EPM_TEST_'):
                os.environ.pop(key, None)
        os.environ.update(saved)
    print(f'Passed {proof["testsRun"]} layout source cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
