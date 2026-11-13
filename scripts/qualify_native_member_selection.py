#!/usr/bin/env python3
"""Reproduce native member-selection and scoped-identity SQL qualification.

Requires Python 3.12 and an existing local PostgreSQL 18 image. --execute creates
one new labelled container/volume on a random loopback port; it never connects
to a caller-provided/shared database. OwnedDockerRun owns every Docker effect.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import secrets
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))
if str(ROOT / 'tests') not in sys.path:
    sys.path.insert(0, str(ROOT / 'tests'))

from scripts.audit_disposable_docker_cleanup_candidates import (
    CleanupError, OwnedDockerRun, bound_command, docker, write_json)

TEST_SUITES = {
    'security-identity-display': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-security-identity-display-qualification-v1'),
    'calculation-dependencies': ('tests.test_postgres_calculation_dependencies',
                                'PostgresCalculationDependenciesTests',
                                'openepm-calculation-dependencies-qualification-v1'),
    'application-purge': ('tests.test_application_purge',
                          'PostgresApplicationPurgeTests',
                          'openepm-application-purge-qualification-v1'),
    'semantic-impact-fanout': ('tests.test_calculation_semantic_fanout_postgres',
                               'CalculationSemanticFanoutPostgresTests',
                               'openepm-semantic-impact-fanout-qualification-v1'),
    'documented-owned-rule': ('tests.test_documented_owned_rule_postgres',
                               'DocumentedOwnedRulePostgresTests',
                               'openepm-documented-owned-rule-qualification-v1'),
    'typed-expression-impact': ('tests.test_python_expression_unit_impact_postgres',
                                'TypedPythonExpressionImpactPostgresTests',
                                'openepm-typed-expression-impact-qualification-v1'),
    'python-value-semantics': ('tests.test_python_expression_impact_postgres',
                               'PythonExpressionImpactPostgresTests',
                               'openepm-python-value-semantics-qualification-v1'),
    'python-numeric-boundary': ('tests.test_python_expression_impact_postgres',
                                'PythonExpressionImpactPostgresTests',
                                'openepm-python-numeric-boundary-qualification-v1'),
    'python-aggregate-intermediate': (
        'tests.test_python_expression_impact_postgres',
        'PythonExpressionImpactPostgresTests',
        'openepm-python-aggregate-intermediate-qualification-v1'),
    'numeric-rational-intermediate': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-numeric-rational-intermediate-qualification-v1'),
    'apportionment-order-parity': (
        'tests.test_expression_apportionment_postgres',
        'ExpressionApportionmentPostgresTests',
        'openepm-apportionment-order-parity-qualification-v1'),
    'aggregate-weight-semantics': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-aggregate-weight-semantics-qualification-v1'),
    'hierarchy-operator-precedence': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-hierarchy-operator-precedence-qualification-v1'),
    'fact-effect-semantics': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-fact-effect-semantics-qualification-v1'),
    'private-test-run-parity': (
        'tests.test_python_expression_unit_impact_postgres',
        'TypedPythonExpressionImpactPostgresTests',
        'openepm-private-test-run-parity-qualification-v1'),
    'temporal-calendar-boundary': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-temporal-calendar-boundary-qualification-v1'),
    'typed-unit-grain': (
        'tests.test_python_expression_unit_impact_postgres',
        'TypedPythonExpressionImpactPostgresTests',
        'openepm-typed-unit-grain-qualification-v1'),
    'missing-input-source-conflict': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-missing-input-source-conflict-qualification-v1'),
    'dependency-failure-atomicity': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-dependency-failure-atomicity-qualification-v1'),
    'semantic-invalidation-matrix': (
        'tests.test_calculation_semantic_fanout_postgres',
        'CalculationSemanticFanoutPostgresTests',
        'openepm-semantic-invalidation-matrix-qualification-v1'),
    'empty-selection-invalidation': (
        'tests.test_calculation_semantic_fanout_postgres',
        'CalculationSemanticFanoutPostgresTests',
        'openepm-empty-selection-invalidation-qualification-v1'),
    'impact-submit-race': (
        'tests.test_calculation_semantic_fanout_postgres',
        'CalculationSemanticFanoutPostgresTests',
        'openepm-impact-submit-race-qualification-v1'),
    'resolved-layer-meaning': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-resolved-layer-meaning-qualification-v1'),
    'cross-family-stale-state': (
        'tests.test_named_hierarchies_postgres',
        'NamedHierarchiesPostgresTests',
        'openepm-cross-family-stale-state-qualification-v1'),
    'uncertain-response-replay': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-uncertain-response-replay-qualification-v1'),
    'cell-editability': (
        'tests.test_cell_editability_postgres',
        'CellEditabilityPostgresTests',
        'openepm-cell-editability-qualification-v1'),
    'application-switch-isolation': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-application-switch-isolation-qualification-v1'),
    'workflow-schedule-authority': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-workflow-schedule-authority-qualification-v1'),
    'dimensional-disclosure': (
        'tests.test_native_member_selection_postgres',
        'NativeMemberSelectionPostgresTests',
        'openepm-dimensional-disclosure-qualification-v1'),
    'source-lifecycle': (
        'tests.test_python_expression_unit_impact_postgres',
        'TypedPythonExpressionImpactPostgresTests',
        'openepm-source-lifecycle-qualification-v1'),
    'source-replacement': (
        'tests.test_python_definition_sources_postgres',
        'PythonDefinitionSourcePostgresTests',
        'openepm-source-replacement-qualification-v1'),
    'source-deletion': (
        'tests.test_definition_owner_lifecycle_postgres',
        'DefinitionOwnerLifecyclePostgresTests',
        'openepm-source-deletion-qualification-v1'),
    'reference-retirement': (
        'tests.test_postgres_numeric_store',
        'PostgresNumericStoreTests',
        'openepm-reference-retirement-qualification-v1'),
    'source-output-replacement': (
        'tests.test_definition_owner_lifecycle_postgres',
        'DefinitionOwnerLifecyclePostgresTests',
        'openepm-source-output-replacement-qualification-v1'),
    'definition-deactivation': (
        'tests.test_python_definition_sources_postgres',
        'PythonDefinitionSourcePostgresTests',
        'openepm-definition-deactivation-qualification-v1'),
    'technical-artifact-expiry': (
        'tests.test_python_definition_sources_postgres',
        'PythonDefinitionSourcePostgresTests',
        'openepm-technical-artifact-expiry-qualification-v1'),
    'native-selection': ('tests.test_native_member_selection_postgres',
                         'NativeMemberSelectionPostgresTests',
                         'openepm-native-member-selection-qualification-v1'),
    'metadata-scope-materialization': (
        'tests.test_native_member_selection_postgres',
        'NativeMemberSelectionPostgresTests',
        'openepm-metadata-scope-materialization-qualification-v1'),
    'typed-definitions': ('tests.test_python_definition_sources_postgres',
                          'PythonDefinitionSourcePostgresTests',
                          'openepm-typed-definition-qualification-v1'),
    'definition-ownership': ('tests.test_definition_owner_lifecycle_postgres',
                             'DefinitionOwnerLifecyclePostgresTests',
                             'openepm-definition-owner-qualification-v1'),
    'orphan-reconciliation': (
        'tests.test_definition_owner_lifecycle_postgres',
        'DefinitionOwnerLifecyclePostgresTests',
        'openepm-orphan-reconciliation-qualification-v1'),
    'receipt-retention': ('tests.test_operation_receipt_retention_postgres',
                          'OperationReceiptRetentionPostgresTests',
                          'openepm-receipt-retention-qualification-v1'),
}
TEST_CASES = {
    'security-identity-display':
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_security_audit_inspection_is_admin_only_paginated_and_safe',
    'python-value-semantics':
        'tests.test_python_expression_impact_postgres.'
        'PythonExpressionImpactPostgresTests.'
        'test_source_value_missing_zero_clear_and_text_are_distinct',
    'python-numeric-boundary':
        'tests.test_python_expression_impact_postgres.'
        'PythonExpressionImpactPostgresTests.'
        'test_numeric_28_8_endpoints_and_first_overflow_step_are_exact',
    'python-aggregate-intermediate':
        'tests.test_python_expression_impact_postgres.'
        'PythonExpressionImpactPostgresTests.'
        'test_large_aggregate_intermediates_are_exact_or_explicit',
    'numeric-rational-intermediate':
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_ordered_typed_expressions_exact_rationals_and_lazy_presence',
    'apportionment-order-parity':
        'tests.test_expression_apportionment_postgres.'
        'ExpressionApportionmentPostgresTests.'
        'test_half_even_residual_recipients_ignore_caller_enumeration',
    'aggregate-weight-semantics':
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_generic_unique_member_operators_execute_exactly',
    'hierarchy-operator-precedence': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_w04_hierarchy_node_executes_parent_own_plus_children_natively',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_w04_published_rule_override_wins_relationship_and_member',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_w08_resolved_read_executes_published_hierarchy_binding',
    ),
    'fact-effect-semantics': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_exact_set_add_clear_snapshot_and_idempotency',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_source_replace_clears_only_the_selected_multidimensional_slice',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_same_application_disjoint_source_replacements_prepare_concurrently',
    ),
    'private-test-run-parity':
        'tests.test_python_expression_unit_impact_postgres.'
        'TypedPythonExpressionImpactPostgresTests.'
        'test_owned_five_checkpoint_definition_matches_exact_oracle_and_publication',
    'temporal-calendar-boundary':
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_w04_temporal_calculated_member_dynamic_equals_materialized',
    'typed-unit-grain':
        'tests.test_python_expression_unit_impact_postgres.'
        'TypedPythonExpressionImpactPostgresTests.'
        'test_private_new_driver_currency_and_required_count_use_same_contract',
    'missing-input-source-conflict': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_applicability_relation_expression_publication_is_set_oriented',
        'tests.test_aicompanies_rule_reconstruction.'
        'AIcompaniesRuleReconstructionTests.'
        'test_activation_disposition_is_fail_closed',
        'tests.test_aicompanies_rule_reconstruction.'
        'AIcompaniesRuleReconstructionTests.'
        'test_inactive_proposal_saves_relation_but_not_rule',
    ),
    'dependency-failure-atomicity': (
        'tests.test_calculation_work_contract.'
        'CalculationWorkContractTests.test_cycle_and_bound_fail_closed',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_expression_uses_declared_alternate_member_in_pinned_generation',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_typed_expression_late_failure_rolls_back_publication',
    ),
    'semantic-invalidation-matrix': (
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_scoped_currentness_agrees_across_readers_before_and_after_relevant_and_unrelated_impacts',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_attribute_value_writer_invalidates_only_its_compiled_selector',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_empty_nested_hierarchy_selection_gains_member_on_exact_relationship_change',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_calendar_writer_invalidates_compiled_temporal_dependency',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_calculated_member_deactivation_invalidates_own_and_definition_dependents',
    ),
    'empty-selection-invalidation': (
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_empty_named_attribute_selection_retains_its_semantic_watch',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_empty_selected_axes_publish_complete_empty_without_broadening',
    ),
    'impact-submit-race': (
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_scoped_currentness_agrees_across_readers_before_and_after_relevant_and_unrelated_impacts',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_typed_expression_compiles_exact_set_stage_and_publishes',
        'tests.test_postgres_calculation_dependencies.'
        'PostgresCalculationDependenciesTests.'
        'test_w07_partition_publication_is_cas_and_lost_ack_safe',
    ),
    'resolved-layer-meaning': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_w08_resolved_own_read_preserves_raw_cube_semantics',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_typed_expression_compiles_exact_set_stage_and_publishes',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_w08_resolved_read_executes_published_hierarchy_binding',
        'tests.test_cube_layer_report.'
        'CubeLayerReportTests.'
        'test_rows_preserve_layers_zero_presence_and_lineage_without_final_sum',
        'tests.test_resolved_cube_read_contract.'
        'ResolvedCubeReadContractTests.'
        'test_public_contract_and_execution_plan_use_current_result_tokens',
        'tests.test_cube_aggregate_repository.'
        'CubeAggregateRepositoryTests.'
        'test_resolved_rows_persist_current_state_tokens_not_generation_locators',
        'tests.test_resolved_cube_read_contract.'
        'ResolvedCubeReadContractTests.'
        'test_own_and_effective_sources_are_explicit_and_canonical',
        'tests.test_resolved_cube_read_planner.'
        'ResolvedCubeReadPlannerTests.'
        'test_stale_stored_result_requires_work_or_explicit_dynamic_fallback',
    ),
    'cross-family-stale-state': (
        'tests.test_named_hierarchies_postgres.'
        'NamedHierarchiesPostgresTests.'
        'test_membership_default_switch_aliases_replay_and_stale_reads',
        'tests.test_source_evidence_postgres.'
        'SourceEvidencePostgresTests.'
        'test_cutover_rejects_stale_preview_without_partial_target',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_rule_origin_closure_stales_direct_and_transitive_consumers_on_owner_change',
    ),
    'uncertain-response-replay': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_exact_set_add_clear_snapshot_and_idempotency',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_exact_numeric_replay_survives_same_subject_token_refresh',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_fixed_batch_receipt_replay_survives_preview_expiry_without_new_admission',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_source_batch_replace_is_staged_exact_and_retryable',
    ),
    'cell-editability': (
        'tests.test_cell_editability_postgres.'
        'CellEditabilityPostgresTests.'
        'test_raw_calculated_policy_and_lock_use_one_authoritative_guard',
    ),
    'application-switch-isolation': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_pg_mcp_router_discovers_and_isolates_applications',
    ),
    'workflow-schedule-authority': (
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_generic_application_schedule_persists_exact_rule_and_authority',
    ),
    'dimensional-disclosure': (
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_dimensional_policy_denies_hidden_child_and_edge_without_false_base',
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_native_aggregate_filters_hidden_values_counts_and_group_keys_before_reduction',
        'tests.test_postgres_dimensional_security.'
        'PostgresDimensionalSecurityResolverTests.'
        'test_visible_page_skips_denied_candidates_without_leaking_positions',
        'tests.test_postgres_dimensional_security.'
        'PostgresDimensionalSecurityResolverTests.'
        'test_visible_page_fails_closed_when_completeness_budget_is_exhausted',
        'tests.test_cube_layer_report.'
        'CubeLayerReportSecurityTests.'
        'test_denied_expression_source_removes_provenance_but_preserves_output_and_currentness',
    ),
    'source-lifecycle': (
        'tests.test_python_expression_unit_impact_postgres.'
        'TypedPythonExpressionImpactPostgresTests.'
        'test_owned_five_checkpoint_definition_matches_exact_oracle_and_publication',
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_application_rule_private_test_activate_and_expiry_keeps_definition',
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_application_rule_source_validation_activation_and_deactivation',
    ),
    'source-replacement': (
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_compiled_run_rejects_changed_publication_after_inspection',
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_source_replacement_physically_discards_obsolete_compiled_payload',
    ),
    'source-deletion': (
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_application_rule_source_delete_removes_owned_definition_and_preserves_facts',
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_calculated_member_source_delete_removes_owned_definition_and_preserves_facts',
    ),
    'reference-retirement': (
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_inactive_never_run_consumer_blocks_native_list_delete',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_saved_view_blocks_member_retirement_until_explicit_view_delete',
        'tests.test_postgres_numeric_store.'
        'PostgresNumericStoreTests.'
        'test_generic_application_schedule_persists_exact_rule_and_authority',
    ),
    'source-output-replacement': (
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_output_id_and_kind_change_require_explicit_delete_and_leave_no_orphan',
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_extra_same_kind_and_cross_kind_owners_and_detach_are_rejected',
    ),
    'definition-deactivation': (
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_application_rule_source_validation_activation_and_deactivation',
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_calculated_member_source_validation_activation_and_deactivation',
        'tests.test_calculation_semantic_fanout_postgres.'
        'CalculationSemanticFanoutPostgresTests.'
        'test_calculated_member_deactivation_invalidates_own_and_definition_dependents',
    ),
    'technical-artifact-expiry': (
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_application_rule_private_test_activate_and_expiry_keeps_definition',
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_calculated_member_private_test_activate_and_expiry_keeps_definition',
        'tests.test_python_definition_sources_postgres.'
        'PythonDefinitionSourcePostgresTests.'
        'test_logically_expired_test_cannot_activate_before_cleanup',
    ),
    'metadata-scope-materialization': (
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_authoring_bootstrap_and_dynamic_reference_binding_are_scoped_read_only',
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_authoring_reference_application_scope_and_stale_revision_are_exact',
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_dimensional_policy_denies_hidden_child_and_edge_without_false_base',
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_cursor_pages_and_actor_application_isolation_then_stale_metadata',
        'tests.test_native_member_selection_postgres.'
        'NativeMemberSelectionPostgresTests.'
        'test_cycle_and_cross_application_relationship_reject_atomically',
    ),
    'orphan-reconciliation': (
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_legacy_orphaned_application_rule_remains_inspectable_but_not_executable',
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_unresolved_application_rule_retires_only_against_exact_active_replacement',
        'tests.test_definition_owner_lifecycle_postgres.'
        'DefinitionOwnerLifecyclePostgresTests.'
        'test_populated_365_migration_preserves_unclassified_payloads_and_business_facts',
    ),
}
TEST_MODULE = TEST_SUITES['native-selection'][0]
SOURCE_FILES = (
    'tests/test_postgres_calculation_dependencies.py',
    'tests/test_application_purge.py',
    'tests/test_calculation_semantic_fanout_postgres.py',
    'platform_postgres_router_mcp_http.py',
    'platform_postgres_router_mcp_server.py',
    'platform_postgres_workspace_mcp_http.py',
    'platform_postgres_workspace_mcp_server.py',
    'platform_postgres_mcp_http.py',
    'platform_postgres_mcp_server.py',
    'tests/qualify_postgres_compose_signed.py',
    'scripts/bootstrap_macos_pilot_application.py',
    'scripts/qualify_macos_pilot_mcp_oauth.py',
    'scripts/serve_openepm_postgres_worker.py',
    'tests/test_documented_owned_rule_postgres.py',
    'tests/public_documentation_python_example.py',
    'tests/public_documentation_source_runtime.py',
    'tests/public_documentation_test_support.py',
    'tests/source_definition_authoring_fixture.py',
    'scripts/programmable_source_authoring.py',
    'scripts/programmable_uat_sample_contract.py',
    'scripts/provision_programmable_uat_sample_contents.py',
    'deploy/macos-pilot/programmable-sample-contents.json',
    'public-landing/documentation/pages/mcp-first-bounded-read.html',
    'public-landing/documentation/pages/mcp-prompt-register-builder.html',
    'public-landing/documentation/pages/mcp-prompt-build-sealed-plan.html',
    'public-landing/documentation/pages/mcp-prompt-run-sealed-plan.html',
    'public-landing/documentation/pages/mcp-prompt-create-member-list.html',
    'public-landing/documentation/pages/mcp-guide-python-authoring.html',
    'tests/test_python_impact_postgres.py',
    'tests/test_python_impact_mixed_postgres.py',
    'tests/mcp_inline_fixture.py',
    'tests/disposable_storage_fixture.py',
    'tests/test_python_expression_unit_impact_postgres.py',
    'tests/test_python_expression_impact_postgres.py',
    'tests/test_python_impact_workflow_postgres.py',
    'tests/test_user_authored_consolidation_expression.py',
    'tests/expression_applicability_relation_live_fixture.py',
    'tests/test_aicompanies_rule_reconstruction.py',
    'scripts/aicompanies_rule_reconstruction.py',
    'epm_core/calculation_work_contract.py',
    'tests/test_calculation_work_contract.py',
    'examples/user_authored_consolidation_expression.py',
    'epm_core/postgres_expression.py',
    'epm_core/postgres_python_expression_impact.py',
    'epm_core/postgres_python_impact.py',
    'tests/test_native_member_selection_postgres.py',
    'tests/test_postgres_numeric_store.py',
    'tests/test_cube_layer_report.py',
    'tests/test_cube_aggregate_repository.py',
    'tests/test_resolved_cube_read_contract.py',
    'tests/test_resolved_cube_read_planner.py',
    'tests/pov_source_replace_concurrency_fixture.py',
    'tests/test_definition_owner_lifecycle_postgres.py',
    'tests/test_operation_receipt_retention_postgres.py',
    'tests/test_reset_source_evidence_graph_identity_migration.py',
    'tests/test_python_definition_sources_postgres.py',
    'tests/test_python_save_validation_postgres.py',
    'tests/test_python_diagnostics_postgres.py',
    'epm_core/postgres_member_selection.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_member_attributes.py',
    'epm_core/member_list_evaluator.py',
    'epm_core/member_list_contract.py',
    'epm_core/selection_resolver.py',
    'epm_core/selection_contract.py',
    'epm_core/postgres_selection_preview.py',
    'epm_core/postgres_authoring_context.py',
    'epm_core/postgres_authoring_references.py',
    'epm_core/postgres_python_program_repository.py',
    'epm_core/postgres_python_build_validator.py',
    'epm_core/python_build_capability.py',
    'epm_core/python_build_broker_http.py',
    'epm_core/python_program_execution.py',
    'openepm/metadata_references.py',
    'openepm/model.py',
    'openepm/authoring.py',
    'openepm/builder_runtime.py',
    'pyproject.toml',
    'requirements-postgres.lock',
    'epm_core/postgres_populated_layout_preview.py',
    'schema/postgres/0365_dimension_scoped_member_identity.sql',
    'scripts/apply_postgres_migrations.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
    'scripts/qualify_native_member_selection.py',
)
FIXTURE_ENVIRONMENT = (
    'EPM_TEST_POSTGRES_DISPOSABLE', 'EPM_TEST_POSTGRES_DSN',
    'EPM_TEST_POSTGRES_TEMPLATE_DATABASE', 'EPM_TEST_POSTGRES_OWNED_HOST',
)


class QualificationError(RuntimeError):
    pass


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in SOURCE_FILES}


def core_source_binding():
    """Bind all current core/SDK modules, including otherwise unlisted helpers.

    The fingerprint is SHA256 of canonical sorted [relative path, file SHA256]
    pairs. Store one tree identity rather than duplicating an entire file index
    in each current qualification artifact.
    """
    entries = [[path.relative_to(ROOT).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()]
               for folder in ('epm_core', 'openepm')
               for path in (ROOT / folder).rglob('*.py') if path.is_file()]
    entries.sort()
    encoded = json.dumps(entries, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    return {'format': 'openepm-python-source-tree-v1', 'roots': ['epm_core', 'openepm'],
            'fileCount': len(entries), 'sha256': hashlib.sha256(encoded).hexdigest()}


def scenario_ids(suite):
    result = []
    for item in suite:
        result.extend(scenario_ids(item) if isinstance(item, unittest.TestSuite)
                      else [item.id()])
    return result


def qualify(*, output: Path, database_image: str, test_suite: str='native-selection'):
    import psycopg
    from psycopg.conninfo import make_conninfo

    if sys.version_info[:2] != (3, 12):
        raise QualificationError('PYTHON_3_12_REQUIRED')
    if not sys.dont_write_bytecode:
        raise QualificationError('PYTHONDONTWRITEBYTECODE_1_REQUIRED')
    if not output.is_absolute() or output.is_symlink() or output.is_dir():
        raise QualificationError('PROOF_REQUIRES_ABSOLUTE_REGULAR_FILE_PATH')
    if not database_image or database_image.startswith('-'):
        raise QualificationError('LOCAL_DATABASE_IMAGE_REQUIRED')
    if test_suite not in TEST_SUITES:
        raise QualificationError('FIXED_TEST_SUITE_REQUIRED')
    module_name,class_name,proof_format=TEST_SUITES[test_suite]
    saved_environment = {name: os.environ.get(name) for name in FIXTURE_ENVIRONMENT}
    manifest = output.with_name(output.name + '.run.json')
    proof = None
    try:
        with OwnedDockerRun(manifest, purpose=test_suite+'-postgres') as owned:
            command = bound_command(docker, owned.manifest['context'])
            # Inspect only: no pull/build and no unpinned mutable image execution.
            image = json.loads(command('image', 'inspect', database_image))[0]
            config = image.get('Config') or {}
            if ('PG_MAJOR=18' not in (config.get('Env') or [])
                    or set(config.get('Volumes') or {}) != {'/var/lib/postgresql'}):
                raise QualificationError('POSTGRES_18_EXPLICIT_STORAGE_LAYOUT_REQUIRED')
            image_id = image['Id']
            name = 'openepm-native-selection-' + owned.manifest['runId'][:12]
            volume = owned.volume(name + '-data')
            password = secrets.token_urlsafe(32)
            container = owned.container(name,
                '-e', 'POSTGRES_PASSWORD=' + password,
                '--mount', 'type=volume,source=' + volume + ',target=/var/lib/postgresql',
                '-p', '127.0.0.1::5432', image_id)
            item = json.loads(command('container', 'inspect', container))[0]
            ports = item['NetworkSettings']['Ports']['5432/tcp']
            if len(ports) != 1 or ports[0]['HostIp'] != '127.0.0.1':
                raise QualificationError('DISPOSABLE_LOOPBACK_BINDING_REQUIRED')
            dsn = make_conninfo(host='127.0.0.1', port=ports[0]['HostPort'],
                               user='postgres', password=password, dbname='postgres')
            server_version = None
            for _ in range(100):
                try:
                    with psycopg.connect(dsn, connect_timeout=1) as db:
                        server_version = db.execute('SHOW server_version').fetchone()[0]
                    break
                except psycopg.OperationalError:
                    time.sleep(.2)
            if server_version is None:
                raise QualificationError('DISPOSABLE_POSTGRES_NOT_READY')
            os.environ['EPM_TEST_POSTGRES_DISPOSABLE'] = '1'
            os.environ['EPM_TEST_POSTGRES_DSN'] = dsn
            os.environ.pop('EPM_TEST_POSTGRES_TEMPLATE_DATABASE', None)
            os.environ.pop('EPM_TEST_POSTGRES_OWNED_HOST', None)
            before_sources = source_hashes()
            before_core = core_source_binding()
            migrations = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted((ROOT / 'schema/postgres').glob('*.sql'))}
            selected = TEST_CASES.get(test_suite, module_name)
            suite = (unittest.defaultTestLoader.loadTestsFromNames(selected)
                     if isinstance(selected, tuple)
                     else unittest.defaultTestLoader.loadTestsFromName(selected))
            scenarios = scenario_ids(suite)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
            fixture_class=getattr(importlib.import_module(module_name),class_name)
            fixture_owner = getattr(fixture_class, 'fixture_class', fixture_class)
            fixture = getattr(fixture_owner,'fixture',fixture_owner)
            database_cleanup = getattr(fixture, 'cleanup_status', None)
            with psycopg.connect(dsn) as check:
                extra_databases=getattr(fixture_owner,'owned_database_names',[])
                extra_roles=getattr(fixture_owner,'owned_role_names',[])
                remaining_extra_databases=check.execute('SELECT count(*) FROM pg_database WHERE datname=ANY(%s)',(extra_databases,)).fetchone()[0]
                remaining_extra_roles=check.execute('SELECT count(*) FROM pg_roles WHERE rolname=ANY(%s)',(extra_roles,)).fetchone()[0]
            if remaining_extra_databases or remaining_extra_roles:
                raise QualificationError('EXTRA_FIXTURE_DATABASE_ROLE_CLEANUP_INCOMPLETE')
            if database_cleanup != {'remainingOwnedDatabases': 0, 'remainingOwnedRoles': 0}:
                raise QualificationError('FIXTURE_DATABASE_ROLE_CLEANUP_INCOMPLETE')
            if not result.wasSuccessful() or result.skipped or result.testsRun != len(scenarios):
                raise QualificationError('FIXED_POSTGRES_SUITE_QUALIFICATION_FAILED')
            if before_sources != source_hashes() or before_core != core_source_binding():
                raise QualificationError('TESTED_SOURCE_CHANGED_DURING_RUN')
            proof = {
                'format': proof_format, 'testSuite':test_suite,
                'testsRun': result.testsRun, 'failures': 0, 'errors': 0, 'skipped': 0,
                'testScenarioIds': scenarios,
                'invocation': {
                    'cwd': str(ROOT),
                    'argv': [sys.executable, '-m', 'scripts.qualify_native_member_selection',
                             '--execute', '--test-suite', test_suite, '--database-image', database_image, '--output', str(output)],
                    'callerEnvironment': {'PYTHONDONTWRITEBYTECODE': '1'},
                    'fixtureEnvironment': {
                        'EPM_TEST_POSTGRES_DISPOSABLE': '1',
                        'EPM_TEST_POSTGRES_DSN': 'generated in memory; never retained',
                        'EPM_TEST_POSTGRES_TEMPLATE_DATABASE': 'unset',
                        'EPM_TEST_POSTGRES_OWNED_HOST': 'unset'}},
                'runtime': {'python': sys.version, 'psycopg': psycopg.__version__,
                            'postgres': server_version},
                'configuration': {'requestedLocalImage': database_image,
                                  'loopbackHost': '127.0.0.1', 'portAllocation': 'docker-dynamic',
                                  'freshFullMigrationChain': True, 'templateDatabase': None},
                'sourceSha256': before_sources, 'coreSource': before_core,
                'migrationSha256': migrations,
                'freshMigrationCount': len(fixture.migration_ids),
                'populatedUpgrade':getattr(fixture_class,'upgrade_proof',None),
                'populatedTemplateUpgrade':getattr(fixture_class,'template_upgrade_proof',None),
                'populatedProducerUpgrade':getattr(fixture_class,'producer_upgrade_proof',None),
                'schemaGraph':getattr(fixture_class,'schema_proof',None),
                'extraFixtureCleanup':{'ownedDatabasesChecked':len(extra_databases),'ownedRolesChecked':len(extra_roles),
                    'remainingOwnedDatabases':remaining_extra_databases,'remainingOwnedRoles':remaining_extra_roles},
                'databaseRoleCleanup': database_cleanup, 'localPostgresImage': image_id,
                'externalAuthenticationClaimed': False,
                'sharedApplicationReadOrMutation': False,
            }
        if not owned.report or not owned.report['cleanupVerified']:
            raise QualificationError('DOCKER_CLEANUP_PENDING')
        if (proof['sourceSha256'] != source_hashes()
                or proof['coreSource'] != core_source_binding()):
            raise QualificationError('TESTED_SOURCE_CHANGED_BEFORE_PROOF')
        proof['cleanup'] = owned.report
        # A failed run never overwrites the last accepted current proof.
        write_json(output, proof)
        return proof
    except BaseException:
        if 'owned' in locals() and owned.report is not None:
            print(json.dumps({'status':'failed','testSuite':test_suite,
                              'cleanup':owned.report},sort_keys=True),file=sys.stderr)
        raise
    finally:
        for name, previous in saved_environment.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--test-suite',choices=tuple(TEST_SUITES),default='native-selection')
    parser.add_argument('--database-image', default='postgres:18.6-bookworm')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'status': 'planned', 'testModule':TEST_SUITES[args.test_suite][0],'testSuite':args.test_suite,
            'databaseImage': args.database_image, 'sharedDatabaseUsed': False,
            'executionRequires': '--execute --output /absolute/current-proof.json',
            'fixtureEnvironmentNames': list(FIXTURE_ENVIRONMENT)}, sort_keys=True))
        return 0
    if args.output is None:
        parser.error('--execute requires --output /absolute/current-proof.json')
    try:
        proof = qualify(output=args.output, database_image=args.database_image,test_suite=args.test_suite)
    except (QualificationError, CleanupError) as failure:
        print(str(failure), file=sys.stderr)
        return 1
    print(json.dumps({'status': 'passed', 'testsRun': proof['testsRun'],
                      'cleanupVerified': proof['cleanup']['cleanupVerified'],
                      'output': str(args.output)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
