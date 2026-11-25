#!/usr/bin/env python3
"""Qualify the source-owned ApplicationRule after public legacy retirement.

The existing native harness owns the disposable PostgreSQL resource, mandatory
cleanup and sole proof write. All selected cases share one observed allocation.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
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
from scripts.qualify_source_transfer_roundtrip import observed_runtime, validate_schema

SUITE = 'ip01-current-rule-cutover'
FORMAT = 'openepm-ip01-current-rule-cutover-v1'
MODULE = 'tests.test_public_numeric_sequence_owner'
CLASS = 'PublicSequenceReplacementPostgresTests'
PREFIX = MODULE + '.' + CLASS + '.'
SCENARIOS = tuple(PREFIX + name for name in (
    'test_catalog_adapter_first_read_pages_and_current_authority',
    'test_changed_save_clears_owner_and_does_not_touch_other_application',
    'test_revocation_after_admission_prevents_publication',
    'test_same_app_concurrent_write_fences_the_sealed_ordered_effect',
    'test_two_applications_run_exact_order_and_reconcile_original_identity',
    'test_reviewed_template_counterpart_has_exact_typed_ordered_result',
    'test_current_application_rule_objects_page_and_recheck_pins_and_grants',
    'test_current_rule_reads_refuse_directory_changes_before_response',
    'test_repeated_and_cleared_target_requires_deliberately_refreshed_cas',
))
EXPECTED_OBSERVATIONS = {
    'reviewed-template-counterpart': {'case': 'reviewed-template-counterpart',
        'templateInserted': False, 'typedBindings': ['Amount', 'Ratio', 'Member'],
        'atomicOrderedEvents': ['100.00000001', '125.00000001', None, '125.00000001'],
        'originalReplayNoEffects': True, 'legacyOwnerStillUnsupported': True},
    'current-rule-object-pagination': {'case': 'current-rule-object-pagination',
        'emptyAndTwoPagesBothFacades': True, 'exactIds': ['a-rule', 'z-rule'],
        'terminalEmpty': True, 'stalePolicyContinuationRefused': True,
        'orderedFilterHasExactPagesAndEmptyResult': True,
        'filterChangeAndMissingTokenRefused': True,
        'differentOperationExcludedBeforePaging': True,
        'missingPinsRefused': True, 'otherApplicationEmpty': True, 'revokedReadRefused': True},
    'current-rule-directory-change': {'case': 'current-rule-directory-change',
        'publishedListBrowserRefused': True, 'readOnlyMcpInspectionRefused': True,
        'directGrantAllowsFreshReads': True, 'scopedRowsUnchanged': True},
    'explicit-repeated-cleared-cas': {'case': 'explicit-repeated-cleared-cas',
        'oldPreviewRefusedWithoutEffect': True, 'repeatedWorkflowFailedWithoutPublication': True,
        'deliberateSourceRefreshRequired': True, 'clearedRetainsNonemptyChangeId': True,
        'originalCompletedReplayPreserved': True, 'clearedChangeIdReadPublicly': True,
        'automaticLegacyRuntimeCasClaimed': False},
}
OBSERVATIONS = frozenset(EXPECTED_OBSERVATIONS)
SOURCE_FILES = tuple(dict.fromkeys((*harness.SOURCE_FILES,
    'epm_core/postgres_saved_numeric_sequence.py',
    'epm_core/postgres_definition_lifecycle.py',
    'epm_core/postgres_application_rules.py',
    'epm_core/postgres_application_rule_workflow.py',
    'epm_core/postgres_numeric_sequence.py',
    'epm_core/postgres_numeric_sequence_expression.py',
    'epm_core/postgres_numeric_catalog.py',
    'epm_core/postgres_cube_query.py',
    'epm_core/postgres_python_environments.py',
    'epm_core/postgres_python_build_artifact.py',
    'epm_core/postgres_python_build_validator.py',
    'epm_core/postgres_python_definitions.py',
    'epm_core/postgres_python_program_repository.py',
    'epm_core/current_python_contract.py',
    'epm_core/postgres_capability_contract.py',
    'epm_core/application_catalog_projection.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'epm_core/postgres_application_capabilities.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_jobs.py',
    'epm_core/postgres_access.py',
    'epm_core/postgres_fresh_baseline.py',
    'openepm/model.py', 'openepm/functions.py',
    'platform_postgres_web_http.py',
    'tests/test_public_numeric_sequence_owner.py',
    'tests/test_python_definition_sources_postgres.py',
    'tests/test_python_save_validation_postgres.py',
    'tests/test_python_diagnostics_postgres.py',
    'tests/test_public_sequence_replacement_proof.py',
    'scripts/qualify_ip01_current_rule.py',
    'scripts/qualify_source_transfer_roundtrip.py',
    'scripts/qualify_source_staging_correction.py',
    'scripts/qualify_public_program_contracts.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)))


def validate_selection():
    observed = tuple(harness.scenario_ids(
        unittest.TestLoader().loadTestsFromNames(SCENARIOS)))
    if observed != SCENARIOS or len(set(observed)) != len(SCENARIOS):
        raise harness.QualificationError('SEQUENCE_REPLACEMENT_SELECTION_CHANGED')
    return observed


def finalize(proof, *, fixture, runtime, output):
    if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
            or proof.get('testScenarioIds') != list(SCENARIOS)
            or proof.get('testsRun') != len(SCENARIOS)
            or any(proof.get(key) != 0 for key in ('failures', 'errors', 'skipped'))):
        raise harness.QualificationError('SEQUENCE_REPLACEMENT_PROOF_CHANGED')
    schema = validate_schema(getattr(fixture, 'schema_proof', None), proof['migrationSha256'])
    allocation = getattr(fixture, 'replacement_allocation', None)
    from hashlib import sha256
    if (not isinstance(allocation, str) or not allocation.startswith('epm_disposable_')
            or fixture.fixture.database_name != allocation
            or schema.get('allocationSha256') != sha256(allocation.encode()).hexdigest()
            or proof.get('schemaGraph') != schema
            or proof.get('databaseRoleCleanup') != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}
            or fixture.fixture.cleanup_status != proof['databaseRoleCleanup']
            or proof.get('extraFixtureCleanup', {}).get('remainingOwnedDatabases') != 0
            or proof.get('extraFixtureCleanup', {}).get('remainingOwnedRoles') != 0):
        raise harness.QualificationError('SEQUENCE_REPLACEMENT_FIXTURE_CLEANUP_INCOMPLETE')
    observations = getattr(fixture, 'replacement_observations', None)
    if (type(observations) is not list or len(observations) != len(OBSERVATIONS)
            or any(type(row) is not dict for row in observations)
            or {row.get('case') for row in observations} != OBSERVATIONS
            or any(row != EXPECTED_OBSERVATIONS[row['case']] for row in observations)):
        raise harness.QualificationError('SEQUENCE_REPLACEMENT_OBSERVATIONS_INCOMPLETE')
    identity = proof.get('ownedRunIdentity') or {}
    if (set(identity) != {'runId', 'context', 'daemonId'}
            or type(identity['runId']) is not str or not identity['runId']
            or identity['runId'] != proof.get('cleanup', {}).get('runId')
            or proof.get('cleanup', {}).get('cleanupVerified') is not True
            or any(identity[k] != runtime['docker'][k] for k in ('context', 'daemonId'))
            or proof.get('localPostgresImage') != runtime['image']['id']
            or observed_runtime(runtime['image']['id']) != runtime):
        raise harness.QualificationError('SEQUENCE_REPLACEMENT_RUNTIME_CHANGED')
    proof['hostRuntimeImage'] = deepcopy(runtime)
    proof['replacementObservations'] = deepcopy(observations)
    proof['invocation']['argv'] = [sys.executable, '-B', '-m',
        'scripts.qualify_ip01_current_rule', '--execute', '--database-image',
        runtime['image']['id'], '--output', str(output)]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; values not retained.'
    proof['scope'] = {
        'criterion': 'IP-01-AC-05 post-retirement current-rule component; independent acceptance and signed integration remain separate.',
        'replacement': 'Reviewed in-memory legacy template compared to a source-owned ApplicationRule with Amount/Ratio/Member parameters and one ordered atomic unit; no legacy owner inserted or enabled.',
        'authoringDiscovery': 'The old diagnostic-driven lifecycle case is excluded because retired names are absent from public discovery. Separate cutover proof verifies refusal and history. This suite checks current catalog pages, exact source-owned ordered execution, reconciliation and authority.',
        'pagination': 'Actual current ApplicationRule objects, empty/two pages/terminal empty, pinned revisions, stale continuation and revoked READ through browser dispatcher/MCP facade. Function discovery remains a separate original case.',
        'cas': 'Repeated and cleared target writes require deliberately reviewed current first-touch change IDs and a new saved/validated/activated source. No automatic legacy runtime CAS equivalence.',
        'recovery': 'Original completed workflow replay remains unchanged after source replacement. Existing selected cases fence changed source, revoked pending work and a competing write. No actual legacy pending job or customer reference migration is claimed.',
        'fixture': 'Existing opted-in disposable native source fixture, trusted in-process broker/builder, actual fixed-core execution and verified-identity transport seam. Existing setup and supporting cases include privileged native metadata/security fixture operations; this is not public bootstrap or HTTP/OIDC.',
        'schema': 'Actual before/after schema of the same named allocation, internally bound by digest; no borrowed fingerprint or snapshot restore.',
        'retirement': 'The public names/routes are closed in the exact tested source. Historical reads and stale-call refusal are qualified by the companion IP-01 retirement proof; no deployed old population was asserted by the owner.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    validate_selection()
    runtime = observed_runtime(args.database_image)
    fixture = getattr(importlib.import_module(MODULE), CLASS)
    previous = {key: value for key, value in os.environ.items() if key.startswith('EPM_TEST_')}
    try:
        for key in previous:
            os.environ.pop(key)
        with mock.patch.dict(harness.TEST_SUITES, {SUITE: (MODULE, CLASS, FORMAT)}), \
                mock.patch.dict(harness.TEST_CASES, {SUITE: SCENARIOS}), \
                mock.patch.object(harness, 'SOURCE_FILES', SOURCE_FILES):
            proof = harness.qualify(output=args.output,
                database_image=args.database_image, test_suite=SUITE,
                finalize_proof=lambda value: finalize(value,
                    fixture=fixture, runtime=runtime, output=args.output))
    finally:
        for key in tuple(os.environ):
            if key.startswith('EPM_TEST_'):
                os.environ.pop(key)
        os.environ.update(previous)
    print(f'Passed {proof["testsRun"]} native replacement preparation cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
