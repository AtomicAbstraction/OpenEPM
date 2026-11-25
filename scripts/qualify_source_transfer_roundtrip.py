#!/usr/bin/env python3
"""Exact source-review, partial-transfer and JS-roundtrip native cases.

The maintained harness exclusively owns Docker, PostgreSQL and final proof
publication. The extra JS adapter has no listener/client and owns its scratch.
No image build/pull, shared application, backup restore or OIDC is performed.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.audit_disposable_docker_cleanup_candidates import context_identity
from scripts.qualify_source_staging_correction import SOURCE_FILES as SOURCE_SOURCES
from epm_core.postgres_fresh_baseline import canonical_chain_digest


SUITE = 'source-transfer-roundtrip'
MODULE = 'tests.test_source_transfer_roundtrip_postgres'
CLASS = 'SourceTransferRoundtripPostgresTests'
REVIEW_MODULE = 'tests.test_source_change_review_postgres'
REVIEW_CLASS = 'SourceChangeReviewPostgresTests'
FORMAT = 'openepm-source-transfer-roundtrip-qualification-v1'
NEW_CASES = frozenset((
    'test_replaced_source_requires_its_own_preview_before_publication',
    'test_incomplete_500_of_525_cannot_seal_preview_or_request_publication',
    'test_governed_export_existing_js_converter_reimports_exact_values_and_replays',
))
REVIEW_CASES = frozenset((
    'test_detail_numeric_companions_and_empty_detail_omission_are_exact',
    'test_preview_rejects_a_fact_change_between_examples_and_final_fence',
    'test_preview_withholds_examples_after_directory_membership_changes',
    'test_bounded_examples_keep_true_counts_and_detail_companions_inside_byte_limit',
    'test_replace_examples_match_exact_zero_empty_text_clear_and_replay',
    'test_merge_and_exact_replace_preserve_outside_scope_and_stale_target_rejects',
    'test_write_permission_never_reveals_read_denied_clear_coordinate',
))
OBSERVATIONS = frozenset(('incomplete-500-of-525', 'governed-js-roundtrip', 'source-preview-boundary'))
SOURCE_FILES = tuple(dict.fromkeys((*SOURCE_SOURCES,
    'epm_core/postgres_transfer_orchestration.py',
    'epm_core/postgres_export_producer_checkpoint.py',
    'epm_core/postgres_export_payload.py', 'epm_core/export_producer.py',
    'epm_core/export_artifact_manifest.py', 'epm_core/export_payload_chunk.py',
    'tests/test_source_change_review_postgres.py',
    'tests/test_source_transfer_roundtrip_postgres.py',
    'tests/source_transfer_js_fixture.py', 'tests/source_transfer_converter.mjs',
    'tests/test_source_transfer_roundtrip_qualification.py',
    'scripts/qualify_source_transfer_roundtrip.py',
    'web-ui/src/DataLoad.tsx', 'web-ui/src/DataExport.tsx',
    'web-ui/package.json', 'web-ui/package-lock.json',
)))


def selected_cases():
    # The primary helper composes SourceChangeReview setup. Execute it first;
    # the selected review methods then receive their own final setup/schema
    # record, rather than allowing a later helper setup to overwrite it.
    return tuple(
        module + '.' + owner + '.' + name
        for module, owner, names in (
            (MODULE, CLASS, NEW_CASES), (REVIEW_MODULE, REVIEW_CLASS, REVIEW_CASES))
        for name in sorted(names))


def validate_scenarios():
    from tests.test_source_transfer_roundtrip_postgres import SourceTransferRoundtripPostgresTests
    from tests.test_source_change_review_postgres import SourceChangeReviewPostgresTests
    loader = unittest.TestLoader()
    for owner, names in ((SourceTransferRoundtripPostgresTests, NEW_CASES),
                         (SourceChangeReviewPostgresTests, REVIEW_CASES)):
        if set(loader.getTestCaseNames(owner)) != names:
            raise harness.QualificationError('SOURCE_TRANSFER_SCENARIOS_CHANGED')
    selected = selected_cases()
    if (len(selected) != len(set(selected)) or
            tuple(harness.scenario_ids(loader.loadTestsFromNames(selected))) != selected):
        raise harness.QualificationError('SOURCE_TRANSFER_SCENARIOS_CHANGED')
    return selected


def ui_source_binding():
    names = sorted(p.relative_to(ROOT).as_posix()
        for p in (ROOT / 'web-ui/src').rglob('*') if p.is_file())
    names += ['web-ui/package.json', 'web-ui/package-lock.json']
    return {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def observed_runtime(image):
    identity = context_identity(harness.docker)
    command = harness.bound_command(harness.docker, identity['context'])
    actual = json.loads(command('image', 'inspect', image))[0]
    return {'docker': identity, 'image': {
        'id': actual['Id'], 'architecture': actual['Architecture'], 'os': actual['Os']},
        'host': {'system': platform.system(), 'release': platform.release(),
            'architecture': platform.machine(), 'logicalCpuCount': os.cpu_count()},
        'daemon': {field: json.loads(command('info', '--format', template))
            for field, template in (
                ('architecture', '{{json .Architecture}}'),
                ('os', '{{json .OSType}}'), ('serverVersion', '{{json .ServerVersion}}'))}}


def validate_schema(value, migrations):
    expected = [{'version': int(name.split('_', 1)[0]), 'sha256': checksum}
                for name, checksum in sorted(migrations.items())]
    if (not isinstance(value, dict) or value.get('appliedMigrationChainUnchanged') is not True or
            value.get('physicalFingerprintEqualityRequired') is not False):
        raise harness.QualificationError('SOURCE_TRANSFER_SCHEMA_OBSERVATION_INCOMPLETE')
    for phase in ('before', 'after'):
        observation = value.get(phase) or {}
        fingerprint = observation.get('schemaFingerprint')
        if (observation.get('canonicalMigrations') != expected or
                observation.get('canonicalChainDigest') != canonical_chain_digest(expected) or
                observation.get('migrationCount') != len(expected) or
                not isinstance(fingerprint, str) or len(fingerprint) != 64 or
                any(c not in '0123456789abcdef' for c in fingerprint)):
            raise harness.QualificationError('SOURCE_TRANSFER_SCHEMA_OBSERVATION_INCOMPLETE')
    return value


def finalize(proof, *, selected, runtime, ui_before, output):
    from tests.test_source_transfer_roundtrip_postgres import SourceTransferRoundtripPostgresTests as primary
    from tests.test_source_change_review_postgres import SourceChangeReviewPostgresTests as review
    if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE or
            proof.get('testScenarioIds') != list(selected) or proof.get('testsRun') != len(selected)):
        raise harness.QualificationError('SOURCE_TRANSFER_PROOF_SCENARIOS_CHANGED')
    cleanup = getattr(review.fixture, 'cleanup_status', None)
    if cleanup != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}:
        raise harness.QualificationError('SOURCE_TRANSFER_REVIEW_CLEANUP_INCOMPLETE')
    observations = primary.observations
    if (len(observations) != 3 or {x.get('scenario') for x in observations} != OBSERVATIONS):
        raise harness.QualificationError('SOURCE_TRANSFER_OBSERVATIONS_INCOMPLETE')
    partial = next(x for x in observations if x['scenario'] == 'incomplete-500-of-525')
    if (partial.get('expectedRows') != 525 or partial.get('acceptedRows') != 500 or
            partial.get('acceptedChunks') != 1 or partial.get('browserMcpRefusals') != 6 or
            partial.get('publicationExecutions') != 0 or partial.get('numericEvents') != 0 or
            partial.get('fullScopedRowsUnchangedAfterEach') is not True or
            partial.get('previewWasNeverIssued') is not True or
            partial.get('refusalCodes') != ['SOURCE_BATCH_CONTENT_MISMATCH',
                'SOURCE_BATCH_NOT_READY', 'IMPORT_EXECUTION_BATCH_NOT_READY']):
        raise harness.QualificationError('SOURCE_TRANSFER_PARTIAL_PROOF_INCOMPLETE')
    source = next(x for x in observations if x['scenario'] == 'source-preview-boundary')
    if (source.get('distinctReadySources') != 2 or
            source.get('publishedNumericEvents') != 1 or
            source.get('originalSourceARemainsReadyUnchanged') is not True or
            source.get('synchronousBrowserMcpRefusals') != 2 or
            source.get('refusalCode') != 'SOURCE_PREVIEW_STALE_OR_MISMATCHED' or
            source.get('technicalTables') != ['source_import_execution', 'task', 'task_cursor', 'task_event'] or
            source.get('taskCursorAdmissionDelta') != 1 or
            source.get('taskCursorSettlementDelta') != 0 or
            source.get('taskEventNativeStatuses') != ['Accepted', 'Claimed', 'Failed'] or
            source.get('taskEventClaimGenerations') != [0, 1, 1] or
            source.get('taskMutableFields') != ['status', 'native_status', 'interruptible', 'updated_at'] or
            source.get('technicalMutableFields') != ['status', 'claim_generation',
                'attempt_count', 'error_code', 'updated_at'] or
            not all(source.get(key) is True for key in (
                'authenticPreviewAUsedForB', 'fullScopedRowsUnchangedOnSynchronousRefusal',
                'governedRequestAcceptedThenFailed', 'exactOwnedExecutionAndTaskProjectionOnly',
                'businessSourceRevisionsReceiptsUnchanged', 'freshBPreviewCompleted',
                'exactBPublicReadbackBothChannels', 'sameBPacketReplayUnchanged'))):
        raise harness.QualificationError('SOURCE_TRANSFER_SOURCE_PREVIEW_PROOF_INCOMPLETE')
    converted = next(x for x in observations if x['scenario'] == 'governed-js-roundtrip')
    if (converted.get('exportedRows') != 8 or converted.get('reimportedRows') != 8 or
            converted.get('readbackRows') != 9 or converted.get('outsideScopeRowsPreserved') != 1 or
            not all(converted.get(key) is True for key in (
                'explicitClearBeforeReimport', 'actualGovernedExport',
                'independentPayloadChannelCursors', 'sameAcceptedPacketAfterExpiry',
                'samePublicationReceipt', 'fullScopedRowsUnchangedOnReplay',
                'noFloatConversion', 'browserMcpReadbackEqual'))):
        raise harness.QualificationError('SOURCE_TRANSFER_ROUNDTRIP_PROOF_INCOMPLETE')
    lifecycle = converted.get('converterLifecycle', {})
    if (not all(lifecycle.get(key) is True for key in (
            'serverClosed', 'processGroupGone', 'scratchRemoved', 'sharedCachesUnchanged')) or
            lifecycle.get('listenersStarted') != 0 or lifecycle.get('applicationRequests') != 0):
        raise harness.QualificationError('SOURCE_TRANSFER_CONVERTER_CLEANUP_INCOMPLETE')
    schemas = {
        MODULE + '.' + CLASS: validate_schema(primary.schema_proof, proof['migrationSha256']),
        REVIEW_MODULE + '.' + REVIEW_CLASS: validate_schema(review.schema_proof, proof['migrationSha256']),
    }
    if proof.get('schemaGraph') != primary.schema_proof:
        raise harness.QualificationError('SOURCE_TRANSFER_PRIMARY_SCHEMA_MISMATCH')
    # The maintained harness finalizes after OwnedDockerRun has removed its
    # manifest. Compare its retained identity with this run's cleanup and both
    # actual runtime observations; never recreate or rely on the removed file.
    run_identity, run_cleanup = proof.get('ownedRunIdentity'), proof.get('cleanup')
    if (not isinstance(run_identity, dict) or
            set(run_identity) != {'runId', 'context', 'daemonId'} or
            any(not isinstance(value, str) or not value for value in run_identity.values()) or
            len(run_identity['runId']) != 32 or
            any(c not in '0123456789abcdef' for c in run_identity['runId']) or
            not isinstance(run_cleanup, dict) or
            run_cleanup.get('runId') != run_identity['runId'] or
            run_cleanup.get('cleanupVerified') is not True or
            run_cleanup.get('readOnly') is not False or
            run_cleanup.get('status') != 'complete' or run_cleanup.get('pending') != [] or
            run_cleanup.get('runOutcome') != 'succeeded' or
            any(run_identity[key] != runtime['docker'][key] for key in ('context', 'daemonId')) or
            proof.get('localPostgresImage') != runtime['image']['id'] or
            observed_runtime(runtime['image']['id']) != runtime):
        raise harness.QualificationError('SOURCE_TRANSFER_RUNTIME_CHANGED')
    ui_after = ui_source_binding()
    if ui_before != ui_after:
        raise harness.QualificationError('SOURCE_TRANSFER_UI_OWNER_CHANGED')
    proof.update(observations=observations, fixtureSchemas=schemas,
        supportingFixtureCleanup={REVIEW_MODULE + '.' + REVIEW_CLASS: cleanup},
        hostRuntimeImage=runtime, uiOwnerSourceSha256=ui_before, uiOwnerSourceUnchanged=True)
    proof['invocation']['argv'] = [sys.executable, '-B', '-m',
        'scripts.qualify_source_transfer_roundtrip', '--execute', '--database-image',
        runtime['image']['id'], '--output', str(output)]
    proof['invocation']['ambientTestSettings'] = 'All EPM_TEST_* excluded and restored; values never retained.'
    proof['scope'] = {
        'sourceReviewCases': list(selected[3:]),
        'additionalCases': list(selected[:3]),
        'schemaObservation': 'Each exact physical fixture is independently bracketed before/after its selected cases. All actual canonical migrations must match source; mutable physical fingerprint equality is not required.',
        'sourceReview': 'Merge/exact replace, omission/zero/blank/detail companion distinctions, preview revision and authorization fences, bounded examples and current independent READ filtering. The sparse fixture uses a native fixed-store competitor and verified identities.',
        'partialTransfer': 'Exactly500 acknowledged rows of declared525 remain staging. Browser dispatcher and MCP facade refuse seal, preview and import request, preserving every scoped physical row after all six refusals.',
        'sourcePreview': 'Two distinct ready sources A/B share target revisions. Authentic A preview cannot publish B: direct browser dispatcher/MCP facade refuses with all scoped rows unchanged; governed import admits one technical execution and its exact task projection (Accepted then Claimed then Failed; cursor increases once at admission and stays unchanged at settlement), preserving all unrelated task and business/source/revision/receipt rows. Fresh B preview then publishes exact B values in both channels, and its original request replays without changes.',
        'roundtrip': 'Actual governed native export request/worker/manifest/payload uses independent browser/MCP cursor chains. The existing JS streamCompleteExportBundle and exportBundleToCsv consume those actual pages. An explicit reviewed exact-scope empty replacement clears only those eight rows; public CSV staging/import restores them with exact values and leaves the unrelated ninth row. Same accepted publication packet after expiry returns original receipt with full state unchanged.',
        'javascript': 'Existing installed Node/Vite load exact product TSX owners with configFile/envFile=false, no listeners/HMR/watchers/application requests and owned scratch. This is function execution, not rendered browser UX or a production bundle build.',
        'excludedClaims': 'No real OIDC, external HTTP/installed MCP client, full public application bootstrap, every import/export option, all-role matrix, browser workflow or whole criterion acceptance. The prior525 correction component remains separate evidence; this run does not borrow its later schema fingerprint.',
        'cleanup': 'Sole maintained OwnedDockerRun removes its container/volume; both exact fixture databases/roles and converter process/scratch are verified before the sole proof publication. The supplied preexisting image and shared caches are preserved.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    selected = validate_scenarios()
    runtime = observed_runtime(args.database_image)
    ui_before = ui_source_binding()
    harness.TEST_SUITES[SUITE] = (MODULE, CLASS, FORMAT)
    harness.TEST_CASES[SUITE] = selected
    harness.SOURCE_FILES = SOURCE_FILES
    saved = {name: value for name, value in os.environ.items() if name.startswith('EPM_TEST_')}
    for name in saved:
        os.environ.pop(name, None)
    try:
        proof = harness.qualify(output=args.output, database_image=runtime['image']['id'],
            test_suite=SUITE, finalize_proof=lambda proof: finalize(proof,
                selected=selected, runtime=runtime, ui_before=ui_before, output=args.output))
    finally:
        for name in tuple(os.environ):
            if name.startswith('EPM_TEST_'):
                os.environ.pop(name, None)
        os.environ.update(saved)
    print(f'Passed {proof["testsRun"]} isolated source/transfer cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
