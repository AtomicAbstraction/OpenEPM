#!/usr/bin/env python3
"""Qualify mutation contracts and expression disclosure on owned PostgreSQL.

The existing full-migration OwnedDockerRun harness owns service lifetime and
cleanup. This runner binds selected public-adapter tests and supporting kernel
cases; it is not whole-catalogue or installed-client acceptance.
"""
from __future__ import annotations

import argparse
import os
import platform
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.qualify_public_program_contracts import SOURCE_FILES as CONTRACT_SOURCES
from epm_core.postgres_fresh_baseline import canonical_chain_digest


SUITE = 'public-mutation-contracts'
MODULE = 'tests.test_public_mutation_contracts_postgres'
CLASS = 'PublicMutationContractsPostgresTests'
FORMAT = 'openepm-public-mutation-contract-qualification-v1'
UPGRADE_CASE = 'test_populated_layout_genuine_384_upgrade_preserves_unbound_requests_and_valid_certificates'
WORKER_CASES = ('test_layout_worker_public_replacement_validation_and_explicit_activation', 'test_layout_worker_current_authority_and_dependency_refusal', 'test_layout_worker_guarded_private_control_and_exact_retrieval', 'test_layout_worker_materialization_recovery_precedes_old_chunk', 'test_layout_worker_materialization_chunk_precedes_recovery', 'test_layout_worker_stage_and_validation_lease_recovery', 'test_layout_worker_capacity_workspace_fairness_and_phase_progress')
WORKER_OBSERVATIONS = {'layout-worker-public-lifecycle': ('maintainedWorkerTick', 'explicitActivation', 'actualReadCertificate', 'exactTypedValues', 'exactReceiptRetrieval', 'noPhaseBusinessEffect', 'sealedActivationCannotCancel'), 'layout-worker-current-authority-dependency': ('revokedActorNeverClaimed', 'currentAdministratorControl', 'currentPublicationTokenChanged', 'staleCertificateRefused', 'exactTechnicalFailureEvents', 'noFailureBusinessEffect'), 'layout-worker-private-control': ('exactStateVersion', 'staleVersionNoEffect', 'pendingActivationRefused', 'deliberateActivationCancel', 'privateEvidencePreserved', 'exactCancelledRetrieval', 'noWorkerReissue'), 'layout-worker-recovery-before-chunk': ('realDatabaseClockExpiry', 'originalClaimStale', 'exactGenerationAdvance', 'noStalePrivateWrite', 'noRecoveryBusinessEffect', 'currentContinuationCertified'), 'layout-worker-chunk-before-recovery': ('actualPrivateSQLBeforePause', 'realVisibleLeaseExpiry', 'recoverySkippedLockedClaim', 'exactBeforeCommitSnapshot', 'originalRenewalCommitted', 'originalOwnerCompleted', 'joinedOwnedThread', 'currentCertificateValid'), 'layout-worker-stage-validation-recovery': ('realStageAndValidationLeases', 'realDatabaseClockExpiry', 'exactGenerationFences', 'acknowledgedStagePreserved', 'interruptedCommittedPrefix', 'exactMissingMappingsCompleted', 'originalSingleRowStaleGenerationRefused', 'staleStageNoEffect', 'staleCertificatePublishNoEffect', 'liveStageAndValidationCancellationRefused', 'currentCertificateValidated'), 'layout-worker-capacity-fairness': ('globalCapacity', 'workspaceCapacityWithDistinctApplications', 'applicationCapacity', 'independentWorkspaceProgress', 'blockedClaimsNoEffect', 'allKnownClaimsSettled', 'extraApplicationPublicSetup')}
REQUIRED_CASES = frozenset((
    UPGRADE_CASE, *WORKER_CASES,
    'test_all_six_published_batch_examples_have_exact_typed_public_readback',
    'test_both_published_transform_examples_use_current_grain_and_hierarchy',
    'test_structural_errors_are_canonical_and_create_no_work',
    'test_semantically_invalid_structural_shapes_have_no_effect',
    'test_lost_ack_exact_replay_preserves_owner_and_expiry_boundaries',
    'test_public_revocation_fences_publication_and_job_read_is_owner_only',
    'test_batch_target_cas_and_transform_vector_staleness_remain_distinct',
    'test_public_expression_disclosure_revoke_regrant_zero_count_and_cursor',
    'test_public_expression_disclosure_empty_visible_result_hides_selectors',
    'test_supporting_detail_read_denial_preserves_write_and_regrant_restores_exact_cells',
    'test_metadata_applicability_current_contracts_and_collection_pins',
    'test_metadata_attribute_typed_values_usage_and_keyset_contracts',
    'test_metadata_authoring_calendar_current_scope_contracts',
    'test_discovered_dimension_and_member_edits_preserve_stable_coordinates',
    'test_discovered_relationship_edits_preserve_placement',
    'test_discovered_hierarchy_build_receipts_and_publication_fences',
    'test_discovered_model_state_edits_follow_lifecycle_dependencies',
    'test_discovered_security_tag_edits_preserve_dependency_guards',
    'test_security_tag_dependency_upgrade_preserves_existing_references',
    'test_metadata_hierarchy_edges_and_members_pinned_contracts',
    'test_metadata_relationship_preview_is_exact_and_read_only',
    'test_metadata_member_selection_and_current_list_contracts',
    'test_metadata_security_tag_current_pages_and_revocation',
    'test_metadata_populated_layout_public_read_contract_lifecycle',
    'test_layout_source_preview_and_replacement_recheck_dimensional_read',
    'test_populated_layout_repeated_projection_preserves_current_values_and_evidence',
    'test_populated_layout_current_dependencies_are_complete_and_decisions_are_bound',
    'test_populated_layout_cancellation_uses_exact_state_in_both_channels',
    'test_populated_layout_current_parent_without_child_blocks_and_other_app_is_independent',
    'test_populated_layout_registration_after_validation_is_fenced_with_unchanged_pins',
))

METADATA_FAMILIES = {'metadata-applicability': ('metadata.applicability_relation.list', 'metadata.applicability_relation.read'), 'metadata-attributes': ('metadata.attribute-definition.list', 'metadata.attribute-definition.usage.read', 'metadata.attribute-value.read'), 'metadata-authoring-calendar': ('metadata.authoring.context', 'metadata.calendar.period.read'), 'metadata-hierarchy-edges': ('metadata.hierarchy.list', 'metadata.hierarchy.members.list', 'metadata.hierarchy.read', 'metadata.relationship.list'), 'metadata-relationship-preview': ('metadata.hierarchy.relationships.preview',), 'metadata-member-selection-lists': ('metadata.member.select', 'metadata.member_list.evaluate', 'metadata.member_list.list', 'metadata.member_list.read'), 'metadata-security-tags': ('metadata.security-tag.list',), 'metadata-populated-layout-lifecycle': ('metadata.layout.populated.preview', 'metadata.layout.populated.replace.read', 'metadata.layout.populated.activate.read')}
LAYOUT_OBSERVATIONS = {'layout-cancellation-current-state': (
    'pendingActivationRefusesPrivateCancellation', 'cancellationCheckedByBothFacades',
    'staleRepeatLeavesOriginalOutcome', 'publishedStateAndPrivateEvidencePreserved'),
    'layout-current-projection-and-preserved-evidence': ('identityRemapAddedAxisReorder', 'exactZeroBlankAndSupportingDetail', 'registrationOnlyAndHistoricalCoordinateSeparation', 'currentDefinitionsAndCalculatedValuesPreserved', 'noFreshnessOrAutomaticRebuildClaim', 'exactPriorReceiptReplayAfterLaterActivation', 'currentRevocationAndRegrantFenceReplay', 'publicOnlyPagedDependencyConstruction', 'staleDefinitionContinuationRefused'), 'layout-current-dependency-fences': ('exactCompleteCurrentDependencies', 'unboundCertificateRefused', 'alteredDecisionRefused', 'actualCurrentResultRotationRefusesPublication', 'allRefusalSnapshotsUnchanged'), 'layout-current-parent-conflicts': ('bothCurrentRuleAndPythonOwners', 'actualAcceptedParentWithNoChild', 'noBusinessOrReceiptOnRefusal', 'distinctApplicationIndependent', 'explicitCancellationThenActivation', 'genericPythonSourceRetainedAndStalePlanRefused'), 'layout-dimensional-read-authority': ('unchangedLayoutPins', 'mixedCoordinateReadRefused', 'previouslySignedReplacementRefused', 'noDeniedReadOrAdmissionEffect', 'exactRegrantRestored', 'bothPublicFacades', 'olderStageRefused', 'olderMaterializationRefused', 'olderValidationAndCertificateRefused', 'olderActivationAdmissionAndPublicationRefused'), 'layout-current-complete-inventory-fence': ('actualPublicExpressionAdmission', 'actualFixedPublisherRegistrationBeforeBusinessPublication', 'metadataDataPolicySchemaCommitPinsUnchanged', 'registeredCoordinateNotOmitted', 'fencedActivationRefusedWithoutAnyFurtherRowChange')}

SUPPORT_CLASS = 'tests.test_postgres_numeric_transform.PostgresNumericTransformTests'
SUPPORT_CASES = (
    'test_transform_atomic_scope_replay_and_private_stage',
    'test_shared_kernel_half_even_overflow_and_stale_inputs',
    'test_hierarchy_shared_paths_text_absence_and_unmentioned_axes',
    'test_selected_detail_rejection_and_no_target_no_materialization',
    'test_lost_worker_preserves_only_private_candidate_then_retries_once',
)
DETAIL_CASES = ('test_line_detail_total_and_numeric_cell_commit_together', 'test_v2_line_detail_job_publishes_total_atomically_and_replays', 'test_v2_line_detail_job_rechecks_current_grant_after_admission', 'test_line_detail_overflow_and_text_conflict_leave_no_effect', 'test_same_application_disjoint_detail_povs_prepare_concurrently', 'test_line_detail_event_failure_rolls_back_numeric_and_receipt')
SOURCE_FILES = tuple(dict.fromkeys((*CONTRACT_SOURCES,
    'epm_core/cube_aggregate_lifecycle.py',
    'epm_core/cube_aggregate_native.py',
    'epm_core/cube_aggregate_service.py',
    'epm_core/observability.py',
    'epm_core/persistence_contract.py',
    'epm_core/postgres_access.py',
    'epm_core/postgres_application_rule_dispatch.py',
    'epm_core/postgres_application_rule_workflow.py',
    'epm_core/postgres_application_schedule_worker.py',
    'epm_core/postgres_cube_aggregate_dispatch.py',
    'epm_core/postgres_cube_aggregate_repository.py',
    'epm_core/postgres_expression_sequence.py',
    'epm_core/postgres_full_sequence.py',
    'epm_core/postgres_import_execution.py',
    'epm_core/postgres_jobs.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_populated_layout_worker.py',
    'epm_core/postgres_python_build_dispatch.py',
    'epm_core/postgres_python_run.py',
    'epm_core/postgres_python_schedule_worker.py',
    'epm_core/postgres_python_workflow_dispatch.py',
    'epm_core/postgres_service_startup.py',
    'epm_core/postgres_transfer_export_dispatch.py',
    'epm_core/postgres_transfer_orchestration.py',
    'epm_core/resolved_cube_read_technical.py',
    'docs/lp10-durable-work-inventory.json',
    'epm_core/postgres_populated_layout_worker.py',
    'epm_core/postgres_worker_service.py',
    'epm_core/postgres_access.py',
    'epm_core/postgres_processing_limits.py',
    'epm_core/postgres_execution_scope.py',
    'tests/populated_layout_worker_native_fixture.py',
    'tests/test_populated_layout_worker_admission.py',
    'tests/test_populated_layout_worker_progression.py',
    'tests/test_populated_layout_worker_controls.py',
    'tests/test_populated_layout_worker_sql_guards.py',
    'tests/test_populated_layout_stage_continuation.py',
    'tests/test_populated_layout_worker_native_fixture_checks.py',
    'platform_postgres_mcp_server.py',
    'platform_postgres_router_mcp_server.py',

    'epm_core/postgres_numeric_transform.py',
    'epm_core/postgres_numeric_sequence.py',
    'epm_core/postgres_numeric_sequence_expression.py',
    'epm_core/postgres_jobs.py',
    'epm_core/postgres_planning_write_guard.py',
    'epm_core/postgres_expression.py',
    'epm_core/postgres_calculation_visibility.py',
    'epm_core/postgres_calculation_scan.py',
    'epm_core/postgres_scale.py',
    'epm_core/postgres_cube_layer_report.py',
    'epm_core/postgres_security_language.py',
    'epm_core/postgres_line_detail.py',
    'epm_core/postgres_line_detail_job.py',
    'epm_core/postgres_fact_export.py',
    'epm_core/postgres_cube_query.py',
    'epm_core/postgres_dimensional_security.py',
    'epm_core/postgres_dimensional_security_enforcement.py',
    'tests/test_line_detail_job.py',
    'tests/pov_detail_concurrency_fixture.py',
    'epm_core/postgres_grants.py',
    'epm_core/postgres_numeric_batch.py',
    'epm_core/postgres_text_batch.py',
    'epm_core/persistence_contract.py',
    'epm_core/expired_operation_replay.py',
    'tests/test_public_mutation_contracts_postgres.py',
    'tests/test_postgres_numeric_transform.py',
    'tests/cube_selection_fixture.py',
    'scripts/qualify_public_mutation_contracts.py',
    'epm_core/postgres_metadata.py',
    'epm_core/postgres_member_attributes.py',
    'epm_core/postgres_dimensional_scope.py',
    'epm_core/postgres_applicability_relations.py',
    'epm_core/applicability_relation_contract.py',
    'epm_core/postgres_attribute_catalog.py',
    'epm_core/postgres_authoring_context.py',
    'epm_core/postgres_calendar.py',
    'epm_core/postgres_hierarchies.py',
    'epm_core/postgres_member_lists.py',
    'epm_core/postgres_member_selection.py',
    'epm_core/member_list_contract.py',
    'epm_core/postgres_metadata_hierarchy_patch.py',
    'epm_core/postgres_populated_layout_preview.py',
    'epm_core/postgres_populated_layout_replacement.py',
    'epm_core/postgres_populated_layout_materializer.py',
    'epm_core/postgres_populated_layout_generation_validator.py',
    'epm_core/postgres_populated_layout_activation.py',
    'epm_core/populated_layout_mapping.py',
    'epm_core/metadata_read_contract.py',
    'tests/populated_layout_signed_mcp_fixture.py',
    'tests/test_layout_receipt_replay_postgres.py',
    'tests/test_metadata_discovery_contracts.py',
    'tests/test_native_member_selection_postgres.py',
    'tests/test_metadata_native_contract_qualification.py',
    'tests/test_populated_layout_upgrade_fixture.py',
    'tests/test_populated_layout_upgrade_fixture_checks.py',
    'tests/test_scheduled_rule_upgrade_fixture.py',
    'tests/source_transfer_js_fixture.py',
    'scripts/qualify_calculation_currentness.py',
    'scripts/qualify_source_transfer_roundtrip.py',
    'scripts/apply_postgres_migrations.py',
    'epm_core/populated_layout_generation_validation.py',
    'epm_core/postgres_expression_rules.py',
    'epm_core/postgres_calculated_members.py',
    'epm_core/postgres_application_rules.py',
    'epm_core/postgres_application_rule_workflow.py',
    'epm_core/postgres_python_run.py',
    'epm_core/postgres_python_workflow.py',
    'epm_core/postgres_python_build_public.py',
    'epm_core/postgres_python_program_repository.py',
    'epm_core/postgres_python_build_validator.py',
    'epm_core/postgres_python_environment_startup.py',
    'epm_core/python_plan_runner.py',
    'epm_core/python_execution_contract.py',
    'epm_core/python_build_worker.py',
    'epm_core/python_build_capability.py',
    'epm_core/python_sandbox_launcher.py',
    'tests/source_definition_authoring_fixture.py',
    'tests/public_documentation_source_runtime.py',
    'tests/public_documentation_python_example.py',
    'tests/public_documentation_test_support.py',
    'scripts/programmable_uat_sample_contract.py',
    'deploy/macos-pilot/programmable-sample-contents.json',
    'scripts/programmable_source_authoring.py',
    'scripts/provision_programmable_uat_sample_contents.py',
)))


def selected_tests():
    return (*(MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_CASES)),
            *(SUPPORT_CLASS + '.' + name for name in (*SUPPORT_CASES, *DETAIL_CASES)))


def validate_scenarios():
    from tests.test_public_mutation_contracts_postgres import PublicMutationContractsPostgresTests

    loader = unittest.TestLoader()
    selected = selected_tests()
    if (set(loader.getTestCaseNames(PublicMutationContractsPostgresTests)) != REQUIRED_CASES
            or len(set(selected)) != len(selected)
            or tuple(harness.scenario_ids(loader.loadTestsFromNames(selected))) != selected):
        raise harness.QualificationError('PUBLIC_MUTATION_SCENARIOS_CHANGED')
    return selected


def supporting_fixture_cleanup():
    from tests.test_postgres_numeric_transform import PostgresNumericTransformTests

    status = getattr(PostgresNumericTransformTests.fixture_class, 'cleanup_status', None)
    if status != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}:
        raise harness.QualificationError('PUBLIC_MUTATION_SUPPORTING_CLEANUP_INCOMPLETE')
    return {SUPPORT_CLASS: dict(status)}


def validate_metadata_observations(observations):
    metadata = [row for row in observations if row.get('scenario') in METADATA_FAMILIES]
    if (len(metadata) != len(METADATA_FAMILIES)
            or {row['scenario'] for row in metadata} != set(METADATA_FAMILIES)):
        raise harness.QualificationError('METADATA_READ_OBSERVATIONS_INCOMPLETE')
    from epm_core.public_program_contracts import public_program_contract
    for row in metadata:
        functions = METADATA_FAMILIES[row['scenario']]
        if (row.get('functions') != sorted(functions)
                or any(row.get(key) is not True for key in (
                    'actualProgramAndResultSchemas', 'bothPublicFacades',
                    'publicCurrentGrantRevokeRegrant', 'wrongScopeAndMalformedRefused',
                    'allScopedRowsUnchangedDuringReads', 'allPublishedExamplesExecuted'))):
            raise harness.QualificationError('METADATA_READ_OBSERVATIONS_INCOMPLETE')
        records = row.get('readObservations')
        if not isinstance(records, list) or not 1 <= len(records) <= 1024:
            raise harness.QualificationError('METADATA_READ_OBSERVATIONS_INCOMPLETE')
        from tests.test_public_mutation_contracts_postgres import digest
        for record in records:
            function = record.get('function')
            dependencies = ({'metadata.layout.populated.source.read'} if row['scenario'] == 'metadata-populated-layout-lifecycle' else
                {'metadata.hierarchy.read'} if row['scenario'] in ('metadata-relationship-preview', 'metadata-member-selection-lists') else set())
            if function not in set(functions) | dependencies:
                raise harness.QualificationError('METADATA_READ_FUNCTION_CHANGED')
            contract = public_program_contract(function)
            if (set(record) != {'function', 'channel', 'programSchemaSha256', 'resultSchemaSha256',
                    'publishedExamplesSha256', 'programSha256', 'resultSha256', 'snapshotSha256', 'scopedTableCount'}
                    or record.get('programSchemaSha256') != digest(contract['programSchema'])
                    or record.get('resultSchemaSha256') != digest(contract['resultSchema'])
                    or record.get('publishedExamplesSha256') != digest(contract['programContract']['examples'])
                    or record.get('channel') not in ('browser', 'mcp')
                    or type(record.get('scopedTableCount')) is not int or record['scopedTableCount'] < 1
                    or any(not isinstance(record.get(key), str) or len(record[key]) != 64
                        or any(char not in '0123456789abcdef' for char in record[key])
                        for key in ('programSha256', 'resultSha256', 'snapshotSha256'))):
                raise harness.QualificationError('METADATA_READ_SOURCE_OR_STATE_BINDING_INVALID')
        for function in functions:
            if {record['channel'] for record in records if record['function'] == function} != {'browser', 'mcp'}:
                raise harness.QualificationError('METADATA_READ_CHANNEL_MISSING')
        validate_metadata_examples(row, functions)
    return metadata


def validate_metadata_examples(row, functions):
    from epm_core.public_program_contracts import public_program_contract
    from tests.test_public_mutation_contracts_postgres import (
        digest, metadata_example_bindings, metadata_example_value)
    expected = {(function, index): example['program'] for function in functions
        for index, example in enumerate(public_program_contract(function)['programContract']['examples'])}
    values = row.get('publishedExampleObservations')
    if type(values) is not list or len(values) != len(expected):
        raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLES_INCOMPLETE')
    observed = set(); indexes = set()
    def valid_hash(value):
        return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    for value in values:
        if (type(value) is not dict or set(value) != {'function', 'exampleIndex', 'originalProgramSha256',
                'boundProgramSha256', 'fieldSubstitutions', 'readObservationIndexes'}
                or type(value['exampleIndex']) is not int):
            raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_SHAPE')
        key = (value['function'], value['exampleIndex'])
        if key not in expected or key in observed:
            raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_IDENTITY')
        observed.add(key); original = expected[key]
        fields = value['fieldSubstitutions']; allowed = metadata_example_bindings(*key)
        if (value['originalProgramSha256'] != digest(original) or not valid_hash(value['boundProgramSha256'])
                or type(fields) is not dict or set(fields) != set(allowed)):
            raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_BINDING')
        for pointer, detail in fields.items():
            if (type(detail) is not dict or set(detail) != {'kind', 'originalValueSha256', 'boundValueSha256'}
                    or detail['kind'] != allowed[pointer]
                    or detail['originalValueSha256'] != digest(metadata_example_value(original, pointer))
                    or not valid_hash(detail['boundValueSha256'])):
                raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_SUBSTITUTION')
        if not fields and value['boundProgramSha256'] != value['originalProgramSha256']:
            raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_UNBOUND_CHANGE')
        references = value['readObservationIndexes']
        if type(references) is not dict or set(references) != {'browser', 'mcp'}:
            raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_CHANNELS')
        for channel, index in references.items():
            if type(index) is not int or not 0 <= index < len(row['readObservations']) or index in indexes:
                raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_READ_REFERENCE')
            indexes.add(index); record = row['readObservations'][index]
            if (record['function'] != key[0] or record['channel'] != channel
                    or record['programSha256'] != value['boundProgramSha256']):
                raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLE_NOT_EXECUTED')
    if observed != set(expected):
        raise harness.QualificationError('METADATA_PUBLISHED_EXAMPLES_INCOMPLETE')


def validate_layout_observations(observations):
    rows = [row for row in observations if row.get('scenario') in LAYOUT_OBSERVATIONS]
    if len(rows) != len(LAYOUT_OBSERVATIONS) or {row['scenario'] for row in rows} != set(LAYOUT_OBSERVATIONS):
        raise harness.QualificationError('LAYOUT_CURRENT_OBSERVATIONS_INCOMPLETE')
    for row in rows:
        if any(row.get(key) is not True for key in LAYOUT_OBSERVATIONS[row['scenario']]):
            raise harness.QualificationError('LAYOUT_CURRENT_OBSERVATION_UNPROVEN')
    inventory = next(row for row in rows if row['scenario'] == 'layout-current-complete-inventory-fence')
    if inventory.get('faultScope') != 'existing post-durable-window interruption; no SQL business mutation':
        raise harness.QualificationError('LAYOUT_CURRENT_FAULT_SCOPE_CHANGED')
    return rows


def validate_worker_observations(observations):
    rows = [row for row in observations if row.get('scenario') in WORKER_OBSERVATIONS]
    if len(rows) != len(WORKER_OBSERVATIONS) or {row['scenario'] for row in rows} != set(WORKER_OBSERVATIONS):
        raise harness.QualificationError('LAYOUT_WORKER_OBSERVATIONS_INCOMPLETE')
    for row in rows:
        if any(row.get(key) is not True for key in WORKER_OBSERVATIONS[row['scenario']]):
            raise harness.QualificationError('LAYOUT_WORKER_OBSERVATION_UNPROVEN')
        if row['scenario'] in ('layout-worker-public-lifecycle', 'layout-worker-capacity-fairness') and row.get('phases') != ['Stage','Materialize','Validate','Activate']:
            raise harness.QualificationError('LAYOUT_WORKER_PHASES_UNPROVEN')
    return rows


def validate_schema_graph(value, migrations):
    expected = [{'version': int(name.split('_', 1)[0]), 'sha256': checksum}
                for name, checksum in sorted(migrations.items())]
    if (not expected or not isinstance(value, dict)
            or value.get('appliedMigrationChainUnchanged') is not True
            or value.get('physicalFingerprintEqualityRequired') is not False):
        raise harness.QualificationError('PUBLIC_MUTATION_SCHEMA_OBSERVATION_INCOMPLETE')
    for phase in ('before', 'after'):
        observation = value.get(phase) or {}
        fingerprint = observation.get('schemaFingerprint')
        if (observation.get('canonicalMigrations') != expected
                or observation.get('canonicalChainDigest') != canonical_chain_digest(expected)
                or observation.get('migrationCount') != len(expected)
                or observation.get('maximumVersion') != expected[-1]['version']
                or not isinstance(fingerprint, str) or len(fingerprint) != 64
                or any(c not in '0123456789abcdef' for c in fingerprint)):
            raise harness.QualificationError('PUBLIC_MUTATION_SCHEMA_OBSERVATION_INCOMPLETE')
    return value


def host_observation():
    return {'system': platform.system(), 'release': platform.release(),
            'architecture': platform.machine(), 'logicalCpuCount': os.cpu_count()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--layout-baseline-manifest', required=True, type=Path)
    parser.add_argument('--layout-baseline-manifest-sha256', required=True)
    args = parser.parse_args()
    from tests import test_populated_layout_upgrade_fixture as upgrade
    baseline = upgrade.validate_baseline_manifest(args.layout_baseline_manifest, args.layout_baseline_manifest_sha256)
    selected = validate_scenarios()
    host = host_observation()
    from tests.test_public_mutation_contracts_postgres import PublicMutationContractsPostgresTests

    from tests.test_postgres_numeric_transform import PostgresNumericTransformTests

    harness.TEST_SUITES[SUITE] = (MODULE, CLASS, FORMAT)
    harness.TEST_CASES[SUITE] = selected
    harness.SOURCE_FILES = SOURCE_FILES

    def finalize_proof(proof):
        if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
                or proof.get('testScenarioIds') != list(selected) or proof.get('testsRun') != len(selected)):
            raise harness.QualificationError('PUBLIC_MUTATION_PROOF_SCENARIOS_CHANGED')
        proof['supportingFixtureCleanup'] = supporting_fixture_cleanup()
        migrations = proof.get('migrationSha256', {})
        if proof.get('schemaGraph') != PublicMutationContractsPostgresTests.schema_proof:
            raise harness.QualificationError('PUBLIC_MUTATION_PRIMARY_SCHEMA_MISMATCH')
        validate_schema_graph(proof.get('schemaGraph'), migrations)
        proof['supportingSchemaGraphs'] = {SUPPORT_CLASS: validate_schema_graph(
            PostgresNumericTransformTests.schema_proof, migrations)}
        if host_observation() != host:
            raise harness.QualificationError('PUBLIC_MUTATION_HOST_CHANGED')
        proof['host'] = host
        observations = PublicMutationContractsPostgresTests.observations
        required_observations = {
            'six-published-batch-examples', 'two-published-transform-examples',
            'three-owner-structural-refusals', 'native-semantic-refusals',
            'lost-ack-and-expiry', 'current-authority-and-owner-read', 'target-cas-versus-vector',
            'public-expression-disclosure-revoke-regrant',
            'public-expression-disclosure-empty-result', 'supporting-detail-current-read-denial', *METADATA_FAMILIES, *LAYOUT_OBSERVATIONS, *WORKER_OBSERVATIONS, 'populated-layout-384-to385'}
        if (len(observations) != len(required_observations)
                or {item.get('scenario') for item in observations} != required_observations):
            raise harness.QualificationError('PUBLIC_MUTATION_OBSERVATIONS_INCOMPLETE')
        validate_metadata_observations(observations)
        validate_layout_observations(observations)
        validate_worker_observations(observations)
        from hashlib import sha256
        allocation_ids = {sha256(owner.database_name.encode()).hexdigest() for owner in
            (PublicMutationContractsPostgresTests.fixture, PostgresNumericTransformTests.fixture_class)}
        try:
            proof['layoutUpgrade'] = upgrade.validate_upgrade_proof(PublicMutationContractsPostgresTests.layout_upgrade_proof,
                migrations=migrations, baseline=baseline, other_allocations=allocation_ids)
        except (AssertionError, KeyError, TypeError, ValueError):
            raise harness.QualificationError('PUBLIC_MUTATION_UPGRADE_PROOF_INVALID') from None
        upgraded = [row for row in observations if row['scenario'] == 'populated-layout-384-to385']
        expected_upgrade = {'original384To385': True, 'separateAllocation': True,
            'allScopedPreexistingFieldsPreserved': True, **proof['layoutUpgrade']['outcomes']}
        if (len(upgraded) != 1 or {k:v for k,v in upgraded[0].items() if k not in
                ('scenario','scope','identityVerification','externalTransportOrInstalledHostClaimed')} != expected_upgrade):
            raise harness.QualificationError('PUBLIC_MUTATION_UPGRADE_OBSERVATION_MISMATCH')
        if upgrade.validate_baseline_manifest(args.layout_baseline_manifest, args.layout_baseline_manifest_sha256) != baseline:
            raise harness.QualificationError('PUBLIC_MUTATION_UPGRADE_BASELINE_CHANGED')
        proof['observations'] = observations
        proof['invocation']['argv'] = [sys.executable, '-B', '-m',
            'scripts.qualify_public_mutation_contracts', '--execute',
            '--database-image', args.database_image, '--output', str(args.output),
            '--layout-baseline-manifest', str(args.layout_baseline_manifest),
            '--layout-baseline-manifest-sha256', args.layout_baseline_manifest_sha256]
        proof['invocation']['ambientTestSettings'] = (
            'Ambient EPM_TEST_* settings excluded; only explicit validated layout baseline arguments supplied for the upgrade case; restored afterward.')
        proof['scope'] = {
            'functions': ['facts.numeric.batch', 'facts.text.batch', 'facts.numeric.transform',
                          'facts.expression.calculate', 'facts.calculation.read',
                          'facts.calculation.scan', 'facts.cube.layer-report.scan',
                          'facts.line-detail.replace', 'facts.export.page', 'facts.cube.scan',
                          'metadata.dimension.create', 'metadata.dimension.rename', 'metadata.dimension.describe',
                          'metadata.member.create', 'metadata.member.rename', 'metadata.member.describe',
                          'metadata.relationship.create', 'metadata.relationship.rename', 'metadata.relationship.describe',
                          'metadata.hierarchy.build',
                          'metadata.dimension.status.set', 'metadata.member.status.set',
                          'metadata.relationship.status.set', 'metadata.member.aggregation-operator.set',
                          'metadata.relationship.aggregation-operator.set',
                          'metadata.security-tag.create', 'metadata.security-tag.update', 'metadata.security-tag.status.set',
                          'metadata.member.security-tags.set',
                          *(function for functions in METADATA_FAMILIES.values() for function in functions)],
            'metadataDiscovery': 'Eight new family scenarios validate all twenty current metadata program/result contracts against authorized browser-dispatcher and MCP catalogue schemas. Actual reads include exact typed attributes/usage, current definitions, hierarchy nodes/edges and signed selection pages, revision/collection boundaries, calendar missingness, symbolic authoring context, public-populated preview and actual replacement/activation lifecycle. Every read/refusal compares all scoped physical rows; setup, role changes and requested lifecycle effects are separately bracketed. Signed cursors and previews are not compared as independently issued byte strings. Supporting source.read is separately named dependency coverage, not silently counted among twenty.',
            'metadataScenarioFunctions': {name: list(functions) for name, functions in METADATA_FAMILIES.items()},
            'metadataSupportingPublicRead': ['metadata.layout.populated.source.read'],
            'populatedLayoutCurrentOwners': 'Four additional cases retain the original29 scenarios and use current public browser/MCP reads to construct all dependency decisions, including pinned rule pagination and current result tokens. Existing fixed staging/materialization/validation/activation proves identity, remap, added axis and reorder with exact zero, blank text, supporting detail and registration-only preservation. Current definitions/results/receipts are retained; existing metadata/schema currentness becomes stale without automatic rebuild. Exact prior receipt replay remains current-authority checked after later activations. Missing/altered dependencies, changed result identity, Rule/Python parents without children and a real expression target registration with unchanged revision pins refuse activation without further effects. The ordinary current Python builder fixture executes reviewed source in-process and makes no OS isolation claim; fixed eager-quantum and post-durable-window interruptions are named recovery seams. No SQL business rows are fabricated.',
            'metadataBoundary': 'Business setup uses current public MCP metadata/calendar effects with actual operation admissions after the original sparse fixture bootstrap. All twenty read functions use both facades. Nine dimension, member and relationship write examples execute through the public adapters with current revisions, exact replay and coordinate or placement readback. The layout case reuses the actual fixed-core worker/materializer/validator/activator recipe of the maintained signed/replay fixtures in the same owned allocation.',
            'publicExamples': 'All current examples across the twenty scoped metadata read functions execute through both facades, including explicit-member and dimension-top selection and the member-list retirement dependency page. Per-example original/bound program digests, exact documented field substitution digests and two actual read-record references are retained. The six batch examples and both transform examples use their documented stable-ID/revision/CAS bindings. Examples do not provision metadata or confer authority.',
            'outputs': 'Actual browser dispatcher and MCP facade preview/submission/replay responses and published job result fields are validated against their current owner schemas. Full job-read wire timestamps and worker-internal wrappers are not newly schema-qualified.',
            'recovery': 'A discarded accepted acknowledgement is recovered by the original exact packet. Batch expired replay is lookup-only; transform expired admission remains refused while authorized known-ID status read remains available. No automatic re-admission or missing-original creation is allowed.',
            'authorityAndErrors': 'Real public grant revocation fences publication, read and replay. Nonowner job read is refused. Structural and native semantic preview errors leave exact scoped physical rows unchanged; failed publication preserves exact business rows while job/task settlement is permitted.',
            'staleInputs': 'Batch target CAS allows unrelated writes and rejects changed targets; transform pins the full metadata/data/policy vector and rejects intervening data writes.',
            'calculationDisclosure': 'Actual current public expression fanout, zero source mapped to a visible output and SumAmount/CountPresent reduction publish through browser preview/admission/submit and the fixed worker. Browser dispatcher/MCP full, scan and layer reads retain authorized values/currentness while current Reader tag revoke/regrant hides/restores contributor provenance and selectors. Present zero counts and missing input does not; old scan continuations refuse the changed security revision. A separately protected output proves empty visible results reveal no source selectors. Read phases compare every scoped physical row; assignment changes are restricted to the exact Reader assignment, one security revision, and one receipt/audit. No retired producer is invoked.',
            'supportingDetailRead': 'Two exact cell-owned supporting-detail sets publish through public line-detail.replace preview/admission/submit and the fixed worker, with exact replay. Current READ denial while WRITE remains assigned yields complete filtered empty scan/export results, not absence. Four original per-channel/function continuations refuse security-revision changes. Public regrant restores exact ordered items, totals, public numeric IDs and source references without publication; read-only native observations separately check matching detail/numeric IDs and authoritative READ/WRITE decisions. Caller-authored preview remains no-effect and contains only its new replacement proposal. Every read phase compares all scoped rows; assignment deltas bind exact principal/write-preserving grant/security revision/receipt/audit. There is no per-line ACL or standalone detail-read API.',
            'supportingKernel': 'Five existing transform cases retain atomic/private-stage recovery, half-even and overflow, hierarchy shared paths with untouched text/missing cells/other axes, supporting-detail refusal, and rollback/retry after an injected worker interruption. Their direct-core calls and privileged setup are explicit supporting fixture seams.',
            'schemaGraph': 'Primary before/after physical schema and canonical migration observations bind the named scenarios in schemaGraphScenarioIds. Supporting transform/detail before/after observations bind their separately owned database and all eleven selected kernel cases. Physical changes from the fault trigger, sequence and role state are retained. The same maintained run supplies actual host, immutable PostgreSQL image, configuration and invocation.',
            'schemaGraphScenarioIds': [MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_CASES) if name != UPGRADE_CASE],
            'upgradeSchemaGraphScenarioIds': [MODULE + '.' + CLASS + '.' + UPGRADE_CASE],
            'supportingSchemaGraphScenarioIds': {SUPPORT_CLASS: [SUPPORT_CLASS + '.' + name for name in (*SUPPORT_CASES, *DETAIL_CASES)]},
            'supportingDetailKernel': 'Six unchanged NumericStore methods execute through the existing composed transform fixture: exact Decimal sum/coherent identity, empty complete-set present zero, exact receipt replay, public job atomicity, current-grant refusal, overflow/text conflict, concurrent disjoint POV preparation and one losing stale full-set replacement, plus injected detail-event rollback. Direct kernel setup and privileged fault injection remain explicitly bounded fixture seams; other business reductions are not redefined.',
            'fixture': 'Fresh isolated sparse custom-axis kernel applications, inherited privileged metadata setup and explicit verified-identity seam. New authored seed writes, hierarchy metadata and grants pass through public application-language workflows.',
            'excludedClaims': 'No external HTTP/OIDC or installed MCP client, rendered UI, public eight-axis bootstrap, snapshot restore, any other historical upgrade, deployment, performance threshold, all-function contract coverage or complete IP-01-AC-02 acceptance.',
            'populatedLayout384Upgrade': 'A separate owned allocation is populated by actual immutable384 source in an isolated subprocess, then migrated to385 after that process group exits. Exact original columns and all other scoped rows are preserved; only declared unverified authority/null intent and existing Stage classification are added. Old replacement replay is retrieval-only; unsealed private phases cannot resume. Exact current-authorized control, real lease expiry, original sealed receipts and a new deliberate activation against an eligible384 certificate are exercised. A fresh explicit385 request progresses through the maintained worker and separate activation. Historical383-to384 proof is not re-claimed; no deployed daemon or external-client claim.',
            'populatedLayoutWorker': 'Seven current native cases exercise actual maintained worker ticks, authority and dependency refusal, exact private control/replay, both real chunk-versus-recovery orders, Stage/Validate lease recovery, and shared capacity/fairness. No business SQL reconstruction, synthetic lease time or implicit activation. Actual current primary schema is observed around all selected cases.',
            'cleanup': 'Existing OwnedDockerRun removes only its exact container and volume; primary and supporting fixtures verify their databases/roles are gone. The supplied preexisting PostgreSQL image is preserved; any separately owned campaign images have separate cleanup evidence.',
        }

    saved = {name: value for name, value in os.environ.items() if name.startswith('EPM_TEST_')}
    for name in saved:
        os.environ.pop(name, None)
    try:
        os.environ[upgrade.ENV_MANIFEST] = str(args.layout_baseline_manifest)
        os.environ[upgrade.ENV_SHA] = args.layout_baseline_manifest_sha256
        proof = harness.qualify(output=args.output, database_image=args.database_image,
            test_suite=SUITE, finalize_proof=finalize_proof)
    finally:
        for name in tuple(os.environ):
            if name.startswith('EPM_TEST_'):
                os.environ.pop(name, None)
        os.environ.update(saved)
    print(f'Passed {proof["testsRun"]} selected mutation cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
