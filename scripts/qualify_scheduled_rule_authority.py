#!/usr/bin/env python3
"""Qualify scheduled authority and its retained cancellation boundaries.

The maintained native harness owns the disposable service and sole proof write.
This parent-owned wrapper adds observations, not another service lifecycle.
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
from scripts import qualify_workflow_cancellation as cancellation
from scripts.qualify_source_transfer_roundtrip import observed_runtime, validate_schema

SUITE = 'scheduled-rule-authority'
FORMAT = 'openepm-scheduled-rule-authority-qualification-v1'
MODULE = 'tests.test_scheduled_rule_authority_postgres'
PRIMARY = 'ScheduledRuleAuthorityPostgresTests'
NEW_CASES = (
    'test_expired_materialized_occurrence_cannot_create_parent',
    'test_expired_admitted_child_cannot_publish',
    'test_revocation_blocks_resume_but_preserves_original_receipt_control',
    'test_atomic_parent_admission_and_lost_ack_replay',
    'test_publication_and_revocation_share_application_fence',
    'test_rotation_preserves_linked_control_and_stale_token_fault_recovery',
    'test_legacy_upgrade_preserves_receipts_and_refuses_unproven_origins',
    'test_current_admin_control_refuses_mismatched_attached_child',
)
READ_CASES = (
    'test_public_adapter_pages_use_exact_native_tasks_and_do_not_admit_work',
    'test_current_owner_admin_visibility_matches_task_read_and_revocation',
    'test_old_pin_history_is_distinct_and_cursor_is_schedule_scoped',
    'test_concurrent_definition_rotation_refuses_mixed_pin_page',
)
CASE_NAMES = {PRIMARY: (*NEW_CASES, *READ_CASES), **cancellation.CASE_NAMES}
SCENARIOS = tuple(MODULE + '.' + PRIMARY + '.' + case for case in CASE_NAMES[PRIMARY]) + cancellation.SCENARIOS
HISTORICAL_UPGRADE_CASE = 'test_legacy_upgrade_preserves_receipts_and_refuses_unproven_origins'
CURRENT_SUITE = 'scheduled-rule-authority-current'
CURRENT_FORMAT = 'openepm-scheduled-rule-current-authority-qualification-v1'
CURRENT_CASE_NAMES = {PRIMARY: tuple(case for case in CASE_NAMES[PRIMARY]
    if case != HISTORICAL_UPGRADE_CASE), **cancellation.CASE_NAMES}
CURRENT_SCENARIOS = tuple(MODULE + '.' + PRIMARY + '.' + case
    for case in CURRENT_CASE_NAMES[PRIMARY]) + cancellation.SCENARIOS
CLEAN = {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}
SOURCE_FILES = tuple(dict.fromkeys((*cancellation.SOURCE_FILES,
    'scripts/qualify_scheduled_rule_authority.py',
    'tests/test_scheduled_rule_authority_postgres.py',
    'tests/test_scheduled_rule_authority_proof.py',
    'tests/python_occurrence_native_outcomes.py',
    'tests/test_scheduled_rule_upgrade_fixture.py',
    'tests/test_scheduled_rule_upgrade_fixture_checks.py',
    'tests/source_transfer_js_fixture.py',
    'tests/test_schedule_occurrence_read_postgres.py',
    'tests/test_scheduled_rule_authority.py',
    'tests/test_application_schedule_tasks.py',
    'tests/test_application_schedule_reconciliation.py',
    'tests/test_application_schedule_worker_reconciliation.py',
    'epm_core/postgres_application_schedule_worker.py',
    'epm_core/postgres_application_schedule_dispatch.py',
    'epm_core/postgres_application_schedules.py',
    'epm_core/postgres_execution_delegations.py',
    'epm_core/postgres_calculation_impact.py',
)))


# Current Python schedules are a separate selection with their own genuine
# 385-to-386 predecessor; they never consume or re-label the Rule382-to383 proof.
from tests.python_occurrence_native_outcomes import FRESH_CASES, fresh_required_outcomes

PYTHON_SUITE = 'python-scheduled-authority'
PYTHON_FORMAT = 'openepm-python-scheduled-authority-qualification-v1'
PYTHON_MODULE = 'tests.test_python_scheduled_authority_postgres'
PYTHON_CLASS = 'PythonScheduledAuthorityPostgresTests'
PYTHON_CASES = (
    'test_expired_precreated_schedule_before_build',
    'test_revoked_precreated_schedule_before_build',
    'test_accepted_and_sealed_build_recheck_authority',
    'test_admitted_child_and_next_unit_recheck_expiry',
    'test_publication_revocation_orders',
    'test_occurrence_build_and_run_lost_ack_replay',
    'test_completed_occurrence_receipts_after_authority_change',
) + FRESH_CASES
PYTHON_SCENARIOS = tuple(PYTHON_MODULE + '.' + PYTHON_CLASS + '.' + name for name in PYTHON_CASES)
PYTHON_SOURCE_FILES = tuple(dict.fromkeys((*SOURCE_FILES,
    'tests/test_python_scheduled_authority_postgres.py',
    'tests/python_occurrence_native_cases.py',
    'tests/python_occurrence_native_outcomes.py',
    'tests/python_occurrence_capacity_fixture.py',
    'tests/python_occurrence_upgrade_fixture.py',
    'tests/test_python_occurrence_native_checks.py',
    'tests/test_python_occurrence_upgrade_checks.py',
    'tests/source_transfer_js_fixture.py',
    'tests/public_documentation_source_runtime.py',
    'epm_core/postgres_python_occurrence_control.py',
    'tests/test_python_program_schedules.py',
    'epm_core/postgres_python_schedules.py',
    'epm_core/postgres_python_schedule_worker.py',
    'epm_core/postgres_python_build_public.py',
    'epm_core/postgres_python_program_repository.py',
    'epm_core/python_build_worker.py',
    'epm_core/python_execution_contract.py',
)))


def python_fixture():
    return getattr(importlib.import_module(PYTHON_MODULE), PYTHON_CLASS)


def validate_python_selection(fixture):
    module = importlib.import_module(PYTHON_MODULE)
    loader = unittest.TestLoader()
    actual = tuple(harness.scenario_ids(loader.loadTestsFromNames(PYTHON_SCENARIOS)))
    discovered = tuple(harness.scenario_ids(loader.loadTestsFromModule(module)))
    if (tuple(loader.getTestCaseNames(fixture)) != tuple(sorted(PYTHON_CASES))
            or actual != PYTHON_SCENARIOS or len(set(actual)) != len(PYTHON_CASES)
            or set(discovered) != set(PYTHON_SCENARIOS) or len(discovered) != len(PYTHON_CASES)):
        raise harness.QualificationError('PYTHON_SCHEDULE_SCENARIOS_CHANGED')


def python_required_outcomes():
    return [
        {'databaseExpiryObserved': True, 'unchangedPins': True, 'automaticMaterialization': None,
         'explicitMaterialization': 'technical-only', 'occurrenceStatus': 'failed',
         'errorCode': 'PYTHON_SCHEDULE_AUTHORIZATION_REVOKED', 'planBuilds': 0,
         'parents': 0, 'jobs': 0, 'currentReadBothFacades': True, 'noBusinessEffects': True},
        {'publicRevocation': True, 'occurrenceStatus': 'failed',
         'errorCode': 'PYTHON_SCHEDULE_AUTHORIZATION_REVOKED', 'planBuilds': 0, 'jobs': 0,
         'noBusinessEffects': True, 'currentReadBothFacades': True, 'deniedCurrentRead': True, 'wrongScopeReadRefused': True},
        {'outcomes': [{'stage': stage, 'change': change,
            'buildStatus': 'sealed' if stage == 'sealed' else 'failed',
            'occurrenceStatus': 'failed', 'errorCode': 'PYTHON_SCHEDULE_BUILD_FAILED'
                if stage != 'sealed' else 'PYTHON_SCHEDULE_AUTHORIZATION_REVOKED',
            'buildRefusalCode': None if stage == 'sealed' else (
                'PYTHON_BUILD_STALE_CONTEXT' if stage == 'before-seal' and change == 'revoked'
                else 'PYTHON_EXECUTION_DELEGATION_INVALID'),
            'parents': 0, 'jobs': 0, 'noBusinessEffects': True}
            for stage in ('accepted', 'before-seal', 'sealed') for change in ('expired', 'revoked')]},
        {'databaseExpiryObserved': True, 'childStatus': 'failed',
         'childError': 'PYTHON_EXECUTION_DELEGATION_INVALID', 'childReceipt': False,
         'nextUnitAdmissionRefused': True, 'committedUnits': 1, 'remainingUnits': 1,
         'originalReceiptPreserved': True, 'childCount': 1, 'noBusinessEffects': True,
         'cancellationOutcomes': [
            {'outerStatus': 'cancelled', 'errorCode': None, 'parentStatus': 'cancelled',
             'committedUnits': 0, 'remainingUnits': 2, 'originalResultBothFacades': True,
             'noBusinessEffects': True},
            {'outerStatus': 'failed', 'errorCode': 'PYTHON_SCHEDULE_WORKFLOW_PARTIALLY_PUBLISHED',
             'parentStatus': 'partially_published', 'committedUnits': 1, 'remainingUnits': 1,
             'originalResultBothFacades': True, 'noBusinessEffects': True}]},
        {'orders': [{'winner': 'revocation', 'childStatus': 'failed', 'receipt': False,
            'actualApplicationRowBlockingObserved': False, 'newNumericEvents': 0, 'childCount': 2,
            'cancellationOutcome': {'outerStatus': 'failed',
                'errorCode': 'PYTHON_SCHEDULE_WORKFLOW_PARTIALLY_PUBLISHED',
                'parentStatus': 'partially_published', 'committedUnits': 1, 'remainingUnits': 1,
                'originalResultBothFacades': True, 'noBusinessEffects': True}},
            {'winner': 'publication', 'childStatus': 'published', 'receipt': True,
            'actualApplicationRowBlockingObserved': True, 'newNumericEvents': 1, 'childCount': 2,
            'cancellationOutcome': {'outerStatus': 'failed',
                'errorCode': 'PYTHON_SCHEDULE_WORKFLOW_PARTIALLY_PUBLISHED',
                'parentStatus': 'partially_published', 'committedUnits': 2, 'remainingUnits': 0,
                'originalResultBothFacades': True, 'noBusinessEffects': True}}]},
        {'buildAcknowledgementLost': True, 'runAcknowledgementLost': True,
         'originalBuildAndParentRecovered': True, 'atomicLinksPresentBeforeRetry': True,
         'secondAdmissionAttempt': False, 'freshPreviewOrSubmit': False,
         'planBuilds': 1, 'parents': 1, 'jobs': 1, 'noDuplicateEffects': True,
         'cancellationPhaseHandoffs': [{'stage': stage, 'acceptedIdentityRetained': True,
             'concurrentCancelPreserved': True, 'controlGenerationAdvanced': True,
             'staleAdmissionPhasePreservedControl': True, 'newControlEligibleWithoutDelay': True,
             'originalControlSettledWithoutRearm': True, 'initialOuterStatus': 'cancel_requested',
             'finalOuterStatus': 'cancelled', 'noBusinessEffects': True}
             for stage in ('build', 'workflow')], 'sealedBuildRetainedWithoutRun': True},
        {'outcomes': [{'change': change, 'outerStatus': 'published', 'parentStatus': 'published',
            'committedUnits': 2, 'remainingUnits': 0, 'currentReadBothFacades': True,
            'originalReceiptsPreserved': True, 'freshBuildRefused': True,
            'planBuilds': 1, 'parents': 1, 'jobs': 2, 'noDuplicateEffects': True}
            for change in ('expired', 'revoked')],
         'linkedReadDenial': {'outerStatus': 'needs_inspection',
             'errorCode': 'PYTHON_SCHEDULE_WORKFLOW_READ_UNAVAILABLE',
             'exactWorkflowIdRetained': True, 'privateResultWithheld': True,
             'regrantedOriginalResultBothFacades': True, 'parentStatus': 'published',
             'committedUnits': 2, 'remainingUnits': 0, 'originalReceiptsPreserved': True,
             'planBuilds': 1, 'parents': 1, 'jobs': 2, 'noNewBusinessEffects': True}},
    ] + fresh_required_outcomes()


def validate_python_observations(values):
    if (type(values) is not list or len(values) != len(PYTHON_CASES) or any(type(row) is not dict for row in values)
            or {row.get('case') for row in values} != set(PYTHON_CASES)):
        raise harness.QualificationError('PYTHON_SCHEDULE_OBSERVATIONS_INCOMPLETE')
    by_case = {row['case']: row for row in values}
    # Canonical JSON preserves false/zero type differences as well as exact
    # nested outcome counts, which ordinary Python equality would conflate.
    import json
    for case, expected in zip(PYTHON_CASES, python_required_outcomes(), strict=True):
        actual = {key: by_case[case].get(key) for key in expected}
        if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise harness.QualificationError('PYTHON_SCHEDULE_OBSERVATION_OUTCOME_INVALID')
    for index in (0, 1, 3):
        drain = by_case[PYTHON_CASES[index]].get('setupDrain')
        if (type(drain) is not dict or type(drain.get('processedCount')) is not int
                or not 0 <= drain['processedCount'] <= 10000
                or type(drain.get('scopedTablesChecked')) is not int
                or drain['scopedTablesChecked'] < 8
                or drain.get('fanoutCount') != 0 or drain.get('quiescent') is not True):
            raise harness.QualificationError('PYTHON_SCHEDULE_SETUP_IMPACT_PROOF_INVALID')
        expected = {'childStatus': 'ready', 'childReceipt': False,
            'onlyWatermarkAndProgressChanged': True} if index == 3 else {'noChild': True}
        if any(drain.get(key) != value for key, value in expected.items()):
            raise harness.QualificationError('PYTHON_SCHEDULE_SETUP_IMPACT_PROOF_INVALID')


def finalize_python(proof, *, fixture, runtime, output, baseline, baseline_manifest):
    if (proof.get('format') != PYTHON_FORMAT or proof.get('testSuite') != PYTHON_SUITE
            or proof.get('testScenarioIds') != list(PYTHON_SCENARIOS) or proof.get('testsRun') != len(PYTHON_CASES)
            or any(proof.get(key) != 0 for key in ('failures', 'errors', 'skipped'))
            or proof.get('populatedUpgrade') is not None):
        raise harness.QualificationError('PYTHON_SCHEDULE_PROOF_SCENARIOS_CHANGED')
    schema = validate_schema(getattr(fixture, 'schema_proof', None), proof['migrationSha256'])
    allocation = getattr(fixture, 'allocation_name', None)
    if not isinstance(allocation, str) or not allocation.startswith('epm_disposable_'):
        raise harness.QualificationError('PYTHON_SCHEDULE_ALLOCATION_UNPROVEN')
    digest = sha256(allocation.encode()).hexdigest()
    cleanup = getattr(fixture, 'cleanup_status', None)
    if (digest != getattr(fixture, 'allocation_sha256', None)
            or digest != schema.get('allocationSha256')
            or cleanup != {**CLEAN, 'remainingExtraRoles': 0, 'allocationSha256': digest}
            or getattr(fixture, 'fixture_cleanup_status', None) != CLEAN
            or proof.get('schemaGraph') != schema or proof.get('databaseRoleCleanup') != CLEAN
            or any(proof.get('extraFixtureCleanup', {}).get(key) != 0 for key in CLEAN)):
        raise harness.QualificationError('PYTHON_SCHEDULE_FIXTURE_CLEANUP_INCOMPLETE')
    values = getattr(fixture, 'observations', None)
    validate_python_observations(values)
    from tests.python_occurrence_upgrade_fixture import validate_upgrade_proof
    upgrade = validate_upgrade_proof(getattr(fixture, 'occurrence_upgrade_proof', None),
        migrations=proof['migrationSha256'], baseline=baseline, other_allocations={digest})
    upgrade_observation = next(row for row in values if row['case'] == PYTHON_CASES[-1])
    if upgrade_observation['outcomes'] != upgrade['outcomes']:
        raise harness.QualificationError('PYTHON_OCCURRENCE_UPGRADE_OUTCOMES_CHANGED')
    proof['pythonOccurrenceUpgrade'] = upgrade
    proof['historicalSourceSnapshot'] = dict(baseline)
    identity, lifecycle = proof.get('ownedRunIdentity') or {}, proof.get('cleanup') or {}
    if (set(identity) != {'runId', 'context', 'daemonId'}
            or type(identity.get('runId')) is not str or not identity['runId']
            or identity['runId'] != lifecycle.get('runId')
            or lifecycle.get('cleanupVerified') is not True or lifecycle.get('status') != 'complete'
            or lifecycle.get('pending') != [] or lifecycle.get('runOutcome') != 'succeeded'
            or any(identity[key] != runtime['docker'][key] for key in ('context', 'daemonId'))
            or proof.get('localPostgresImage') != runtime['image']['id']
            or observed_runtime(runtime['image']['id']) != runtime):
        raise harness.QualificationError('PYTHON_SCHEDULE_RUNTIME_CHANGED')
    proof['fixtureSchemas'] = {PYTHON_CLASS: deepcopy(schema)}
    proof['allFixtureCleanup'] = {PYTHON_CLASS: deepcopy(cleanup)}
    proof['authorityObservations'] = {PYTHON_CLASS: deepcopy(values)}
    proof['hostRuntimeImage'] = deepcopy(runtime)
    proof['invocation']['argv'] = [sys.executable, '-B', '-m', 'scripts.qualify_scheduled_rule_authority',
        '--component', 'python', '--execute', '--database-image', runtime['image']['id'],
        '--output', str(output), '--python-baseline-manifest', str(baseline_manifest),
        '--python-baseline-manifest-sha256', baseline['snapshotManifestSha256']]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; only explicitly verified385 baseline arguments introduced.'
    proof['scope'] = {
        'criterion': 'IP-09-AC-03 current Python schedule authority component; no whole-criterion promotion.',
        'scenarios': 'Seven retained current-authority cases plus the explicitly selected atomic occurrence/control cases; original Rule27 selection remains separate.',
        'clientSeam': 'Actual PostgreSQL/fixed core/MCP/browser dispatch with verified fixture identity and maintained trusted source builder; no installed HTTP/OIDC or OS sandbox claim.',
        'authority': 'Actual database-clock expiry and public delegation revocation at build/run/publication boundaries; current authorized receipt reads remain distinct from fresh execution.',
        'faults': 'Actual postcommit lost replies retain atomic child links; two-order native INSERT/link/control barriers and real lease expiry. No fabricated receipt, altered clock or business SQL mutation.',
        'cancellation': 'Existing outer states retain the exact inner result: partial publication is failed with a specific reason and unchanged receipt-confirmed counts; unresolved control remains cancel_requested. Sealed technical builds are retained without admitting a run.',
        'schema': 'Primary current allocation before/after fingerprints plus separate genuine385-to386 allocation before/after/afterQualification; each retains its own source, row transformation and cleanup.',
        'cleanup': 'Original fixture cleanup, distinct coordinator role and same maintained native harness service cleanup before sole proof write.',
        'exclusions': 'No shared application, automatic retirement, release promotion, broad source/UI/performance claim or universal rollback assertion. Genuine385-to386 allocation is separate from fresh current cases; no earlier upgrade path is inferred.',
    }


def run_python_component(args):
    from tests.python_occurrence_upgrade_fixture import validate_baseline_manifest, ENV_MANIFEST, ENV_SHA
    baseline = validate_baseline_manifest(args.python_baseline_manifest, args.python_baseline_manifest_sha256)
    fixture = python_fixture(); validate_python_selection(fixture)
    previous = {key: value for key, value in os.environ.items() if key.startswith('EPM_TEST_')}
    try:
        for key in previous:
            os.environ.pop(key)
        os.environ[ENV_MANIFEST] = str(args.python_baseline_manifest)
        os.environ[ENV_SHA] = args.python_baseline_manifest_sha256
        runtime = observed_runtime(args.database_image)
        def finish(value):
            if validate_baseline_manifest(args.python_baseline_manifest, args.python_baseline_manifest_sha256) != baseline:
                raise harness.QualificationError('PYTHON_OCCURRENCE_BASELINE_CHANGED')
            finalize_python(value, fixture=fixture, runtime=runtime, output=args.output,
                baseline=baseline, baseline_manifest=args.python_baseline_manifest)
        with mock.patch.dict(harness.TEST_SUITES, {PYTHON_SUITE: (PYTHON_MODULE, PYTHON_CLASS, PYTHON_FORMAT)}), \
                mock.patch.dict(harness.TEST_CASES, {PYTHON_SUITE: PYTHON_SCENARIOS}), \
                mock.patch.object(harness, 'SOURCE_FILES', PYTHON_SOURCE_FILES):
            proof = harness.qualify(output=args.output, database_image=args.database_image,
                test_suite=PYTHON_SUITE, finalize_proof=finish)
    finally:
        for key in tuple(os.environ):
            if key.startswith('EPM_TEST_'):
                os.environ.pop(key, None)
        os.environ.update(previous)
    print(f'Passed {proof["testsRun"]} current Python schedule cases; owned cleanup verified; {args.output}')
    return 0


def fixture_types():
    return {PRIMARY: getattr(importlib.import_module(MODULE), PRIMARY),
            **cancellation.fixture_types()}


def _exact_outcomes(actual, expected):
    import json
    selected = {key: actual.get(key) for key in expected}
    if json.dumps(selected, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_OBSERVATION_OUTCOME_INVALID')


def _current_cancellation_outcomes(name, values):
    # These are the already asserted native outcomes, not a replacement for
    # their actual receipt/row comparisons or a reconstruction of business work.
    python = name == cancellation.PYTHON_CLASS
    expected = {
        cancellation.COMMON[0]: {'committedUnits': 2, 'remainingUnits': 1,
            'childReceiptCount': 2, 'originalJobs': 2, 'otherApplicationUnchanged': True,
            'thirdUnitAdmitted': False, 'expiredOriginalReplayBothFacades': True},
        cancellation.COMMON[1]: {'committedUnits': 1, 'remainingUnits': 2,
            'childStatus': 'cancelled', 'currentControlRevocationRefused': True,
            'revokedOriginalReplayBothFacadesRefused': True,
            'restoredControlReconcilesOriginal': True, 'thirdUnitAdmitted': False},
        cancellation.COMMON[2]: {'committedUnits': 0, 'remainingUnits': 3, 'childJobs': 0,
            'freshAdmissionError': 'PYTHON_JOB_EXECUTION_AUTHORITY_INVALID' if python
                else 'APPLICATION_RULE_JOB_ADMISSION_INVALID'},
        cancellation.COMMON[3]: {'actualParentRowBlockingObserved': True,
            'admissionWonBeforeCancel': True, 'childJobs': 1, 'committedUnits': 0,
            'remainingUnits': 3, 'childStatus': 'cancelled'},
        cancellation.COMMON[4]: {'races': [
            {'winner': 'cancel', 'childStatus': 'cancelled', 'committedUnits': 1,
                'remainingUnits': 2, 'actualJobRowBlockingObserved': False},
            {'winner': 'publication', 'childStatus': 'published', 'committedUnits': 2,
                'remainingUnits': 1, 'actualJobRowBlockingObserved': True}],
            'thirdUnitAdmitted': False, 'privateCandidateNotClaimedAsBusinessEffect': True},
        cancellation.COMMON[5]: {'controls': [
            {'control': 'task.interrupt' if task else 'direct-cancel',
                'directCancelDuringActiveClaim': True, 'activeClaimFencePreserved': True,
                'realClaimHistoryQuanta': 0 if task else 101,
                'latestDiagnosticBeyondFirstPage': not task,
                'attentionFilterTracksParkedState': True, 'workerFailuresBeforeParking': 3,
                'automaticClaimExcluded': True, 'deniedRearmRefused': True,
                'finalCommittedUnits': 2, 'finalRemainingUnits': 1} for task in (False, True)],
            'attachedUncertainChild': {'parentStatus': 'cancel_requested', 'childStatus': 'needs_inspection',
                'workerFailuresBeforeParking': 3, 'committedUnits': 1, 'remainingUnits': 2,
                'automaticClaimExcluded': True, 'thirdUnitAdmitted': False,
                'technicalFixtureMutation': 'one exact-owned ready job status only; no receipt/data fabrication',
                'publishedWithoutReceiptNativeQualified': False},
            'newChildOrEffectDuringRecovery': False},
        cancellation.COMMON[6]: {'expiredNativeClaims': 3, 'automaticClaimExcluded': True,
            'staleGenerationSettlementRefused': True, 'rearmControl': 'task.interrupt',
            'finalCommittedUnits': 2, 'finalRemainingUnits': 1,
            'technicalFixtureMutation': 'exact-owned-claim-lease-expiry-only'},
    }
    if python:
        expected['test_legacy_exact_and_unprovable_tail_dispositions'] = {
            'reconstruction': 'prior-five-field-hashed-authority-only',
            'outcomes': [
                {'function': 'facts.numeric.transform', 'status': 'partially_published',
                    'committedUnits': 2, 'remainingUnits': 1, 'checkpointCount': 2},
                {'function': 'facts.numeric.scale', 'status': 'cancel_requested',
                    'committedUnits': 1, 'remainingUnits': 2, 'checkpointCount': 1}],
            'customerRowsMigrated': False, 'otherLegacyFamiliesNativeQualified': False,
            'unprovableTailRemainsUncontrolled': True,
            'unprovenTailIndependentPublication': {'originalChildStatus': 'published',
                'actualReceiptVerified': True, 'parentStatus': 'cancel_requested',
                'confirmedCommittedUnits': 1, 'notYetConfirmedUnits': 2,
                'parentCountNotClaimedAsPhysicalEffectTotal': True, 'thirdUnitAdmitted': False,
                'publicReadBothFacades': True, 'publicCountSchemaBothFacades': True},
        }
    for row in values:
        _exact_outcomes(row, expected[row['case']])


def _rule_selection(current_only):
    if type(current_only) is not bool:
        raise harness.QualificationError('SCHEDULE_AUTHORITY_SELECTION_INVALID')
    return ((CURRENT_FORMAT, CURRENT_SUITE, CURRENT_CASE_NAMES, CURRENT_SCENARIOS)
        if current_only else (FORMAT, SUITE, CASE_NAMES, SCENARIOS))


def validate_selection(fixtures, *, current_only=False):
    _, _, selected_names, selected_scenarios = _rule_selection(current_only)
    cancellation.validate_selection({key: fixtures[key] for key in cancellation.CASE_NAMES
                                    if key in fixtures})
    if set(fixtures) != set(CASE_NAMES):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_FIXTURE_INVENTORY_CHANGED')
    loader = unittest.TestLoader()
    if set(loader.getTestCaseNames(fixtures[PRIMARY])) != set(CASE_NAMES[PRIMARY]):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_SCENARIOS_CHANGED')
    actual = tuple(harness.scenario_ids(loader.loadTestsFromNames(selected_scenarios)))
    expected_count = 26 if current_only else 27
    if current_only and selected_scenarios != tuple(value for value in SCENARIOS
            if value != MODULE + '.' + PRIMARY + '.' + HISTORICAL_UPGRADE_CASE):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_SCENARIOS_CHANGED')
    if (actual != selected_scenarios or len(set(actual)) != expected_count
            or len(selected_names[PRIMARY]) + len(cancellation.SCENARIOS) != expected_count):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_SCENARIOS_CHANGED')


def _observations(name, values, *, current_only=False):
    _, _, selected_names, _ = _rule_selection(current_only)
    expected = selected_names[name]
    if (type(values) is not list or len(values) != len(expected)
            or any(type(row) is not dict for row in values)
            or {row.get('case') for row in values} != set(expected)):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_OBSERVATIONS_INCOMPLETE')
    if name != PRIMARY:
        if current_only:
            _current_cancellation_outcomes(name, values)
        return
    by_case = {row['case']: row for row in values}
    required = {
        NEW_CASES[0]: {'authorityExpiryObservedByDatabaseClock': True,
            'policyAndMetadataUnchanged': True, 'parentCount': 0, 'childCount': 0,
            'occurrenceStatus': 'failed', 'errorCode': 'APPLICATION_SCHEDULE_AUTHORIZATION_REVOKED'},
        NEW_CASES[1]: {'authorityExpiryObservedByDatabaseClock': True,
            'policyAndMetadataUnchanged': True, 'childStatus': 'failed',
            'childError': 'APPLICATION_RULE_SCHEDULE_AUTHORITY_UNAVAILABLE',
            'childReceipt': False, 'childCount': 1, 'expiredNextUnitAdmissionRefused': True,
            'priorPublishedReceiptPreserved': True},
        NEW_CASES[2]: {'revokedFreshResumeRefused': True, 'currentOwnerControlWithoutDelegation': True,
            'originalReceiptUnchanged': True, 'bothFacadeReceiptCounts': [1, 1],
            'committedUnits': 1, 'remainingUnits': 1, 'childCount': 1,
            'terminalAfterRevocation': {'outerStatus': 'published', 'parentStatus': 'published',
                'committedUnits': 2, 'remainingUnits': 0, 'childCount': 2,
                'originalReceiptsPreserved': True, 'bothFacadeCounts': [2, 0],
                'noNewBusinessEffects': True}},
        NEW_CASES[3]: {'storedForeignKeySurvivedLostAck': True,
            'exactReplayWithoutSealPreviewSubmit': True, 'directCallerCannotAdoptScheduledParent': True,
            'parentCount': 1, 'childCount': 1},
        NEW_CASES[4]: {'orders': [
            {'winner': 'revocation', 'childStatus': 'failed', 'receipt': False,
             'actualApplicationRowBlockingObserved': False},
            {'winner': 'publication', 'childStatus': 'published', 'receipt': True,
             'actualApplicationRowBlockingObserved': True}]},
        NEW_CASES[5]: {'paths': [
            {'faultInjected': False, 'outerStatus': 'partially_published', 'committedUnits': 1,
             'remainingUnits': 1, 'nextUnitAdmitted': False},
            {'faultInjected': True, 'outerStatus': 'needs_inspection', 'committedUnits': 1,
             'remainingUnits': 1, 'nextUnitAdmitted': False}]},
        NEW_CASES[6]: {'original382To383': True, 'separateAllocation': True,
            'businessAndReceiptBytesPreserved': True},
        NEW_CASES[7]: {'declaredFault': 'one-owned-pending-checkpoint-job-id',
            'mismatchedChildRefused': True, 'cancelIntentDurable': True,
            'originalAndForeignJobsRemainReady': True, 'validCurrentAdministratorControl': True},
        **{case: {'originalMethod': case, 'originalAssertionsCompleted': True} for case in READ_CASES},
    }
    setup = by_case[NEW_CASES[1]].get('priorSetupImpactDrain', {})
    if (type(setup) is not dict or set(setup) != {'processedCount', 'fanoutCount', 'quiescent',
            'childStatus', 'childReceipt', 'scopedTablesChecked', 'onlyWatermarkAndProgressChanged'}
            or type(setup.get('processedCount')) is not int or not 0 <= setup['processedCount'] <= 10_000
            or type(setup.get('scopedTablesChecked')) is not int or setup['scopedTablesChecked'] <= 0
            or any(setup.get(key) != value for key, value in {'fanoutCount': 0, 'quiescent': True,
                'childStatus': 'ready', 'childReceipt': False, 'onlyWatermarkAndProgressChanged': True}.items())):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_SETUP_IMPACT_PROOF_INVALID')
    if current_only:
        _exact_outcomes(setup, {'fanoutCount': 0, 'quiescent': True, 'childStatus': 'ready',
            'childReceipt': False, 'onlyWatermarkAndProgressChanged': True})
    for case in expected:
        expected_fields = required[case]
        if current_only:
            _exact_outcomes(by_case[case], expected_fields)
        elif any(by_case[case].get(key) != value for key, value in expected_fields.items()):
            raise harness.QualificationError('SCHEDULE_AUTHORITY_OBSERVATION_OUTCOME_INVALID')


def finalize(proof, *, fixtures, runtime, output, baseline, baseline_manifest, current_only=False):
    proof_format, suite, selected_names, selected_scenarios = _rule_selection(current_only)
    if (proof.get('format') != proof_format or proof.get('testSuite') != suite
            or proof.get('testScenarioIds') != list(selected_scenarios)
            or proof.get('testsRun') != (26 if current_only else 27)
            or any(proof.get(key) != 0 for key in ('failures', 'errors', 'skipped'))
            or set(fixtures) != set(CASE_NAMES)
            or (current_only and any(type(proof.get(key)) is not int
                for key in ('testsRun', 'failures', 'errors', 'skipped')))):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_PROOF_SCENARIOS_CHANGED')
    schemas, cleanups, observations, allocations = {}, {}, {}, set()
    for name, fixture in fixtures.items():
        schema = validate_schema(getattr(fixture, 'schema_proof', None), proof['migrationSha256'])
        allocation = getattr(fixture, 'allocation_name', None)
        if not isinstance(allocation, str) or not allocation.startswith('epm_disposable_'):
            raise harness.QualificationError('SCHEDULE_AUTHORITY_ALLOCATION_UNPROVEN')
        digest = sha256(allocation.encode()).hexdigest()
        cleanup = getattr(fixture, 'cleanup_status', None)
        if (digest in allocations or digest != getattr(fixture, 'allocation_sha256', None)
                or digest != schema.get('allocationSha256')
                or cleanup != {**CLEAN, 'remainingExtraRoles': 0, 'allocationSha256': digest}
                or getattr(fixture, 'fixture_cleanup_status', None) != CLEAN):
            raise harness.QualificationError('SCHEDULE_AUTHORITY_FIXTURE_CLEANUP_INCOMPLETE')
        values = getattr(fixture, 'observations', None)
        _observations(name, values, current_only=current_only)
        allocations.add(digest)
        schemas[name], cleanups[name], observations[name] = deepcopy(schema), deepcopy(cleanup), deepcopy(values)
    if (proof.get('schemaGraph') != schemas[PRIMARY] or proof.get('databaseRoleCleanup') != CLEAN
            or any(proof.get('extraFixtureCleanup', {}).get(key) != 0 for key in CLEAN)):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_PRIMARY_FIXTURE_MISMATCH')
    if current_only:
        if (baseline is not None or baseline_manifest is not None
                or getattr(fixtures[PRIMARY], 'upgrade_proof', None) is not None
                or any(proof.get(key) is not None for key in
                    ('populatedUpgrade', 'historicalSourceSnapshot', 'pythonOccurrenceUpgrade',
                     'populatedTemplateUpgrade', 'populatedProducerUpgrade'))):
            raise harness.QualificationError('SCHEDULE_CURRENT_UPGRADE_NOT_SELECTED')
    else:
        from tests.test_scheduled_rule_upgrade_fixture import validate_upgrade_proof
        upgrade = validate_upgrade_proof(getattr(fixtures[PRIMARY], 'upgrade_proof', None),
            migrations=proof['migrationSha256'], baseline=baseline, other_allocations=allocations)
        upgrade_observation = next(row for row in observations[PRIMARY] if row['case'] == NEW_CASES[6])
        if (proof.get('populatedUpgrade') != upgrade
                or upgrade_observation.get('outcomes') != upgrade['outcomes']):
            raise harness.QualificationError('SCHEDULE_AUTHORITY_UPGRADE_CAPTURE_MISMATCH')
    identity, cleanup = proof.get('ownedRunIdentity') or {}, proof.get('cleanup') or {}
    if (set(identity) != {'runId', 'context', 'daemonId'}
            or type(identity.get('runId')) is not str or not identity['runId']
            or identity['runId'] != cleanup.get('runId')
            or cleanup.get('cleanupVerified') is not True or cleanup.get('status') != 'complete'
            or cleanup.get('pending') != [] or cleanup.get('runOutcome') != 'succeeded'
            or any(identity[k] != runtime['docker'][k] for k in ('context', 'daemonId'))
            or proof.get('localPostgresImage') != runtime['image']['id']
            or observed_runtime(runtime['image']['id']) != runtime):
        raise harness.QualificationError('SCHEDULE_AUTHORITY_RUNTIME_CHANGED')
    proof['fixtureSchemas'], proof['allFixtureCleanup'] = schemas, cleanups
    proof['authorityObservations'] = observations
    if not current_only:
        proof['populatedUpgrade'] = deepcopy(upgrade)
        proof['historicalSourceSnapshot'] = deepcopy(baseline)
    proof['hostRuntimeImage'] = deepcopy(runtime)
    if current_only:
        proof['invocation']['argv'] = [sys.executable, '-B', '-m', 'scripts.qualify_scheduled_rule_authority',
            '--component', 'rule-current', '--execute', '--database-image', runtime['image']['id'],
            '--output', str(output)]
        proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; no historical baseline or credential value retained.'
    else:
        proof['invocation']['argv'] = [sys.executable, '-B', '-m', 'scripts.qualify_scheduled_rule_authority',
            '--execute', '--database-image', runtime['image']['id'], '--output', str(output),
            '--baseline-manifest', str(baseline_manifest),
            '--baseline-manifest-sha256', baseline['snapshotManifestSha256']]
        proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; only exact owned historical source inputs supplied. Values of credentials never retained.'
    proof['scope'] = {
        'criterion': 'IP-09-AC-03 scheduled authority component plus exact preserved IP-09-AC-04 cancellation cases; no whole criterion promotion.',
        'scenarios': '8 new authority/upgrade cases, 4 unchanged schedule-read bodies, and all15 unchanged cancellation IDs.',
        'clientSeam': 'Disposable fixed-core and MCP/browser facade calls with verified fixture identity and maintained trusted source builder; no HTTP/OIDC or packaged sandbox claim.',
        'authority': 'Current delegation checked for new effects; original receipts and currently authorized control remain separate. Expiry is observed at actual database clock without policy-revision mutation.',
        'upgrade': 'Separate actual populated382 allocation admitted by immutable captured382 owners in an isolated process, then383 migration and current-owner checks. No reconstructed business SQL or old whole-release/customer-population claim.',
        'faults': 'Only declared lost acknowledgements, one pending-checkpoint identity corruption and a control-read exception; actual owners retain every admission/publication/authorization decision.',
        'cancellation': 'All15 original cases retained, including honestly unresolved legacy child outcomes. Receipt-confirmed prefix is not a universal physical-effect total and remaining is not proof of no effects.',
        'cleanup': 'Each actual allocation/schema/role cleanup independently bound; original fixture cleanup unconditional, subprocess gone before private handoff removal; maintained harness owns sole service lifecycle and proof write.',
        'exclusions': 'No shared application mutation, automatic legacy migration/retirement, installed deployment, full source/UI regression or package acceptance.',
    }

    if current_only:
        proof['scope'].update(
            scenarios='Seven current Rule authority cases, four unchanged schedule reads, and all15 original Python/Rule cancellation IDs; exact26 selection.',
            upgrade='Not selected. The historical Rule27/default remains the separate genuine382-to383 qualification; this result makes no upgrade claim.',
            faults='Existing declared lost replies, exact owned pending-checkpoint/uncertain-child/lease faults and actual admission/publication barriers; all native assertions retained.',
            cleanup='Three separately observed current fixture allocations; each original fixture and coordinator-role cleanup must pass. The maintained harness owns the only service lifecycle/final proof write.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--component', choices=('rule', 'python', 'rule-current'), default='rule')
    parser.add_argument('--baseline-manifest', type=Path)
    parser.add_argument('--baseline-manifest-sha256')
    parser.add_argument('--python-baseline-manifest', type=Path)
    parser.add_argument('--python-baseline-manifest-sha256')
    args = parser.parse_args()
    if args.component == 'python':
        if args.baseline_manifest is not None or args.baseline_manifest_sha256 is not None:
            parser.error('Python component does not consume the Rule historical baseline')
        if args.python_baseline_manifest is None or args.python_baseline_manifest_sha256 is None:
            parser.error('Python component requires its explicit genuine385 baseline and digest')
        return run_python_component(args)
    if args.python_baseline_manifest is not None or args.python_baseline_manifest_sha256 is not None:
        parser.error('Rule component does not consume a Python baseline')
    current_only = args.component == 'rule-current'
    if current_only:
        if args.baseline_manifest is not None or args.baseline_manifest_sha256 is not None:
            parser.error('Current Rule component does not consume a historical baseline')
        baseline = None
    else:
        if args.baseline_manifest is None or args.baseline_manifest_sha256 is None:
            parser.error('Rule component requires an explicit historical baseline and digest')
        from tests.test_scheduled_rule_upgrade_fixture import validate_baseline_manifest
        baseline = validate_baseline_manifest(args.baseline_manifest, args.baseline_manifest_sha256)
    proof_format, suite, _, selected_scenarios = _rule_selection(current_only)
    fixtures = fixture_types(); validate_selection(fixtures, current_only=current_only)
    previous = {key: value for key, value in os.environ.items() if key.startswith('EPM_TEST_')}
    try:
        for key in previous:
            os.environ.pop(key)
        if not current_only:
            os.environ['EPM_TEST_SCHEDULE_BASELINE_MANIFEST'] = str(args.baseline_manifest)
            os.environ['EPM_TEST_SCHEDULE_BASELINE_MANIFEST_SHA256'] = args.baseline_manifest_sha256
        runtime = observed_runtime(args.database_image)
        def finish(value):
            if not current_only:
                current = validate_baseline_manifest(args.baseline_manifest, args.baseline_manifest_sha256)
                if current != baseline:
                    raise harness.QualificationError('SCHEDULE_AUTHORITY_BASELINE_SOURCE_CHANGED')
            finalize(value, fixtures=fixtures, runtime=runtime, output=args.output, baseline=baseline,
                baseline_manifest=args.baseline_manifest, current_only=current_only)
        with mock.patch.dict(harness.TEST_SUITES, {suite: (MODULE, PRIMARY, proof_format)}), \
                mock.patch.dict(harness.TEST_CASES, {suite: selected_scenarios}), \
                mock.patch.object(harness, 'SOURCE_FILES', SOURCE_FILES):
            proof = harness.qualify(output=args.output, database_image=args.database_image,
                test_suite=suite, finalize_proof=finish)
    finally:
        for key in tuple(os.environ):
            if key.startswith('EPM_TEST_'):
                os.environ.pop(key, None)
        os.environ.update(previous)
    print(f'Passed {proof["testsRun"]} native schedule/cancellation cases; owned cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
