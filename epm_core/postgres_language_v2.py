"""Typed PostgreSQL V2 program admission and fixed-core dispatch.

Callers supply structured programs, never SQL or a role. The server owns the
preview secret and verified provider identity. This covers a bounded subset
of the target language; full planning and consolidation parity is still open.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .postgres_capability_contract import describe_catalog
from .postgres_processing_limits import lock_busy_boundary, policy as processing_policy
from .postgres_application_capabilities import (PostgresApplicationCapabilities,
    READ as _CAPABILITY_READ, STATE_READ as _APPLICATION_STATE_READ,
    IDENTITY_READ as _IDENTITY_READ,
    HISTORY as _CAPABILITY_HISTORY, CONFIGURE as _CAPABILITY_CONFIGURE)

from .persistence_contract import (ApplicationScope, Coordinate, MutationKind,
                                   NumericCell, NumericMutation, TextMutation,
                                   TextMutationKind)
from .postgres_cell_editability import (
    FUNCTION as _CELL_EDITABILITY_READ, PostgresCellEditability,
    catalog as _cell_editability_catalog,
)
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .operation_admission_contract import (
    OperationAdmission, is_signed_operation_id,
    issue_operation_admission as issue_signed_operation_admission,
    validate_operation_admission)
from .postgres_cube_query import PostgresCubeQuery
from .postgres_cube_layer_report import (
    FUNCTION as _LAYER_REPORT_SCAN,
    PostgresCubeLayerReport)
from .cube_aggregate_lifecycle import AggregateCursorCodec, AggregateQueryBudgets
from .cube_aggregate_service import CubeAggregateService
from .cube_aggregate_native import NativeCubeAggregateStage
from .postgres_cube_aggregate_repository import PostgresCubeAggregateRepository
from .postgres_populated_layout_preview import (
    FUNCTION as _POPULATED_LAYOUT_PREVIEW,
    PostgresPopulatedLayoutPreview,
)
from .postgres_hierarchies import (catalog as named_hierarchy_catalog,
    MUTATIONS as NAMED_HIERARCHY_MUTATIONS, READS as NAMED_HIERARCHY_READS)
from .postgres_metadata_hierarchy_patch import (
    APPLY as _HIERARCHY_RELATIONSHIPS_APPLY,
    PREVIEW as _HIERARCHY_RELATIONSHIPS_PREVIEW,
    PostgresHierarchyRelationshipPatch,
    catalog as hierarchy_relationship_patch_catalog,
)
from .postgres_populated_layout_replacement import (
    PostgresPopulatedLayoutReplacements,
    REQUEST as _LAYOUT_REPLACE_REQUEST,
    READ as _LAYOUT_REPLACE_READ,
    CANCEL as _LAYOUT_REPLACE_CANCEL,
    PUBLIC_FUNCTIONS as _LAYOUT_REPLACE_FUNCTIONS,
)
from .postgres_populated_layout_activation import (
    PostgresPopulatedLayoutActivation,
    REQUEST as _LAYOUT_ACTIVATE_REQUEST,
    READ as _LAYOUT_ACTIVATE_READ,
    CANCEL as _LAYOUT_ACTIVATE_CANCEL,
    PUBLIC_FUNCTIONS as _LAYOUT_ACTIVATE_FUNCTIONS,
)
from .postgres_python_program_repository import (
    PostgresPythonPrograms, SAVE as _PYTHON_PROGRAM_SAVE,
    READ as _PYTHON_PROGRAM_READ, LIST as _PYTHON_PROGRAM_LIST,
    ACTIVATE as _PYTHON_PROGRAM_ACTIVATE,
    DEACTIVATE as _PYTHON_PROGRAM_DEACTIVATE,
    DELETE as _PYTHON_PROGRAM_DELETE)
from .postgres_python_environments import (PostgresPythonEnvironments,
    ApprovedPythonEnvironment, REGISTER as _PYTHON_ENVIRONMENT_REGISTER,
    READ as _PYTHON_ENVIRONMENT_READ, LIST as _PYTHON_ENVIRONMENT_LIST,
    PROFILE_LIST as _PYTHON_ENVIRONMENT_PROFILE_LIST)
from .postgres_python_build_public import (
    PostgresPythonBuildPublic, BUILD as _PYTHON_PROGRAM_BUILD,
    TEST as _PYTHON_PROGRAM_TEST)
from .postgres_python_build_artifact import PostgresPythonBuildArtifact
from .postgres_python_run import PostgresPythonRun, RUN as _PYTHON_PROGRAM_RUN
from .postgres_python_schedules import (PostgresPythonSchedules,
    FUNCTIONS as _PYTHON_SCHEDULE_FUNCTIONS,catalog as python_schedule_catalog,
    READ as _PYTHON_SCHEDULE_READ,LIST as _PYTHON_SCHEDULE_LIST,
    OCCURRENCE_READ as _PYTHON_OCCURRENCE_READ)
from .postgres_execution_delegations import (PostgresExecutionDelegations,
    catalog as execution_delegation_catalog, CREATE as _DELEGATION_CREATE,
    READ as _DELEGATION_READ, LIST as _DELEGATION_LIST,
    REVOKE as _DELEGATION_REVOKE)
from .postgres_planning_workflow_policy import (
    PostgresPlanningWorkflowPolicies,
    catalog as planning_workflow_policy_catalog,
    SAVE as _PLANNING_POLICY_SAVE,READ as _PLANNING_POLICY_READ,
    LIST as _PLANNING_POLICY_LIST,ACTIVATE as _PLANNING_POLICY_ACTIVATE,
    DEACTIVATE as _PLANNING_POLICY_DEACTIVATE,
)
from .postgres_saved_grids import (PostgresSavedGrids,
    catalog as saved_grid_catalog,SAVE as _SAVED_GRID_SAVE,
    DELETE as _SAVED_GRID_DELETE,
    READ as _SAVED_GRID_READ,LIST as _SAVED_GRID_LIST)
from .postgres_member_lists import (PostgresMemberLists,
    catalog as member_list_catalog,SAVE as _MEMBER_LIST_SAVE,
    READ as _MEMBER_LIST_READ,LIST as _MEMBER_LIST_LIST,
    ACTIVATE as _MEMBER_LIST_ACTIVATE,
    DEACTIVATE as _MEMBER_LIST_DEACTIVATE,
    DELETE as _MEMBER_LIST_DELETE,
    ADOPT_CONFIGURATION as _MEMBER_LIST_ADOPT_CONFIGURATION,
    EVALUATE as _MEMBER_LIST_EVALUATE)
from .postgres_applicability_relations import (
    PostgresApplicabilityRelations,
    catalog as applicability_relation_catalog,
    SAVE as _APPLICABILITY_RELATION_SAVE,
    READ as _APPLICABILITY_RELATION_READ,
    LIST as _APPLICABILITY_RELATION_LIST,
    ACTIVATE as _APPLICABILITY_RELATION_ACTIVATE,
    DEACTIVATE as _APPLICABILITY_RELATION_DEACTIVATE,
    DELETE as _APPLICABILITY_RELATION_DELETE)
from .postgres_member_selection import (PostgresMemberSelection,
    catalog as member_selection_catalog, SELECT as _MEMBER_SELECT)
from .postgres_selection_preview import (PostgresSelectionPreview,
    catalog as selection_preview_catalog,PREVIEW as _SELECTION_PREVIEW)
from .postgres_resolved_cube_read_public import (
    PostgresResolvedCubeReadPublic,
    FUNCTIONS as _RESOLVED_READ_FUNCTIONS,
    catalog as resolved_cube_read_catalog)
from .postgres_calculation_inspection import (
    PostgresCalculationInspection,
    FUNCTIONS as _CALCULATION_INSPECTION_FUNCTIONS,
    RECALCULATE as _CALCULATION_RECALCULATE,
    catalog as calculation_inspection_catalog)
from .postgres_sealed_selections import (PostgresSealedSelections,
    catalog as sealed_selection_catalog,SEAL as _SELECTION_SEAL,
    READ as _SEALED_SELECTION_READ)
from .postgres_generic_aggregate import (PostgresGenericAggregate,
    catalog as generic_aggregate_catalog,
    REQUEST as _GENERIC_AGGREGATE_REQUEST,
    READ as _GENERIC_AGGREGATE_READ,CANCEL as _GENERIC_AGGREGATE_CANCEL,
    LINEAGE as _GENERIC_AGGREGATE_LINEAGE)
from .postgres_calculated_members import (
    PostgresCalculatedMembers,catalog as calculated_member_catalog,
    SAVE as _CALCULATED_MEMBER_SAVE,
    PUBLISH as _CALCULATED_MEMBER_PUBLISH,
    READ as _CALCULATED_MEMBER_READ,
    LIST as _CALCULATED_MEMBER_LIST,
    EVALUATE as _CALCULATED_MEMBER_EVALUATE,
    MATERIALIZE as _CALCULATED_MEMBER_MATERIALIZE)
from .postgres_application_rules import (
    PostgresApplicationRules, catalog as application_rule_catalog,
    SAVE as _APPLICATION_RULE_SAVE,
    PUBLISH as _APPLICATION_RULE_PUBLISH,
    RETIRE as _APPLICATION_RULE_RETIRE,
    READ as _APPLICATION_RULE_READ,
    LIST as _APPLICATION_RULE_LIST,
    RUN as _APPLICATION_RULE_RUN,
    RUN_READ as _APPLICATION_RULE_RUN_READ,
    RUN_CANCEL as _APPLICATION_RULE_RUN_CANCEL,
    RUN_RECONCILE as _APPLICATION_RULE_RUN_RECONCILE)
from .postgres_application_schedules import (
    PostgresApplicationSchedules,catalog as application_schedule_catalog,
    FUNCTIONS as _APPLICATION_SCHEDULE_FUNCTIONS,
    SAVE as _APPLICATION_SCHEDULE_SAVE)
from .postgres_application_assignments import (
    PostgresApplicationAssignments,catalog as application_assignment_catalog,
    READS as _APPLICATION_ASSIGNMENT_READS)
from .postgres_application_workflows import (
    PostgresApplicationWorkflows,catalog as application_workflow_catalog,
    READS as _APPLICATION_WORKFLOW_READS)
from .postgres_application_workflow_occurrences import (
    PostgresApplicationWorkflowOccurrences,
    catalog as application_workflow_occurrence_catalog,
    READS as _APPLICATION_WORKFLOW_OCCURRENCE_READS)
from .postgres_operation_receipts import (
    PostgresOperationReceipts, READ as _OPERATION_RECEIPT_READ,
    catalog as operation_receipt_catalog)
from .postgres_application_decisions import (
    PostgresApplicationDecisions, READS as _APPLICATION_DECISION_READS,
    catalog as application_decision_catalog)
from .postgres_planning_operation_policy import (
    PostgresPlanningOperationPolicies,
    catalog as planning_operation_policy_catalog,
    READ as _PLANNING_OPERATION_POLICY_READ,
    LIST as _PLANNING_OPERATION_POLICY_LIST,
)
from .postgres_planning_driver_policy_public import (
    PostgresPublishedPlanningDriver,
    catalog as published_driver_policy_catalog,
    PREVIEW as _PLANNING_DRIVER_POLICY_PREVIEW,
    RUN as _PLANNING_DRIVER_POLICY_RUN,
)
from .postgres_planning_seed_policy_public import (
    PostgresPublishedPlanningSeed,
    catalog as published_seed_policy_catalog,
    PREVIEW as _PLANNING_SEED_POLICY_PREVIEW,
    RUN as _PLANNING_SEED_POLICY_RUN,
    LINEAGE_READ as _PLANNING_SEED_LINEAGE_READ,
)
from .postgres_planning_rollup_policy_public import (
    PostgresPublishedPlanningRollup,
    catalog as published_rollup_policy_catalog,
    PREVIEW as _PLANNING_ROLLUP_POLICY_PREVIEW,
    RUN as _PLANNING_ROLLUP_POLICY_RUN,
)
from .postgres_planning_spread_policy_public import (
    PostgresPublishedPlanningSpread,
    catalog as published_spread_policy_catalog,
    PREVIEW as _PLANNING_SPREAD_POLICY_PREVIEW,
    RUN as _PLANNING_SPREAD_POLICY_RUN,
)
from .postgres_planning_allocation_policy_public import (
    PostgresPublishedPlanningAllocation,
    catalog as published_allocation_policy_catalog,
    PREVIEW as _PLANNING_ALLOCATION_POLICY_PREVIEW,
    RUN as _PLANNING_ALLOCATION_POLICY_RUN,
)
from .postgres_fact_export import PostgresFactExport
from .postgres_consolidation_assess import (
    PostgresConsolidationAssessment,
    FUNCTION as _CONSOLIDATION_ASSESS_FUNCTION,
    METHOD_PREVIEW_FUNCTION as _CONSOLIDATION_METHOD_PREVIEW_FUNCTION)
from .postgres_consolidation_method_coverage import (
    PostgresConsolidationMethodCoverage)
from .consolidation_method_coverage import (
    FUNCTION as _CONSOLIDATION_METHOD_COVERAGE)
from .postgres_proportional_contribution import (
    PostgresProportionalContributionPreview,
    FUNCTION as _PROPORTIONAL_CONTRIBUTION_PREVIEW)
from .postgres_equity_method_contribution import (
    PostgresEquityMethodContributionPreview,
    FUNCTION as _EQUITY_METHOD_CONTRIBUTION_PREVIEW)
from .postgres_equity_method_publication import PostgresEquityMethodPublication
from .consolidation_equity_method_publication import (
    PUBLIC_FUNCTION as _EQUITY_METHOD_PUBLICATION, compile_publication)
from .postgres_proportional_publication import PostgresProportionalPublication
from .consolidation_proportional_publication import (
    PUBLIC_FUNCTION as _PROPORTIONAL_PUBLICATION,
    compile_publication as compile_proportional_publication)
from .postgres_consolidation_method_total import PostgresConsolidationMethodTotal
from .consolidation_method_total import (
    PUBLIC_FUNCTION as _METHOD_TOTAL_PUBLICATION,
    compile_total as compile_method_total)
from .postgres_cash_flow_reconciliation import (
    PostgresCashFlowReconciliation,
    FUNCTION as _CASH_FLOW_RECONCILIATION_INSPECT)
from .postgres_cash_flow_publication import (
    PostgresCashFlowPublication,
    INSPECT as _CASH_FLOW_PUBLICATION_INSPECT,
    REQUEST as _CASH_FLOW_PUBLICATION_REQUEST,
    READ as _CASH_FLOW_PUBLICATION_READ)
from .postgres_equity_rollforward import (
    PostgresEquityRollforward,
    FUNCTION as _EQUITY_ROLLFORWARD_INSPECT)
from .postgres_inventory_unrealized_profit import (
    PostgresInventoryUnrealizedProfit,
    FUNCTION as _INVENTORY_UNREALIZED_PROFIT_INSPECT)
from .postgres_inventory_unrealized_publication import (
    PostgresInventoryUnrealizedPublication,PostgresInventoryUnrealizedSchedules,
    REQUEST as _INVENTORY_UNREALIZED_REQUEST,
    READ as _INVENTORY_UNREALIZED_READ,
    SCHEDULE_READ as _INVENTORY_UNREALIZED_SCHEDULE_READ,
    SCHEDULE_LIST as _INVENTORY_UNREALIZED_SCHEDULE_LIST,
    schedule_catalog as inventory_unrealized_schedule_catalog,
    compile_publication as _compile_inventory_unrealized)
from .postgres_fixed_asset_unrealized_profit import (
    PostgresFixedAssetUnrealizedProfit,
    FUNCTION as _FIXED_ASSET_UNREALIZED_PROFIT_INSPECT)
from .postgres_disposal_candidate import (
    PostgresDisposalCandidate, FUNCTION as _DISPOSAL_MEASURE_INSPECT)
from .postgres_retained_control_disposal import (
    PostgresRetainedControlDisposal,
    FUNCTION as _RETAINED_CONTROL_DISPOSAL_INSPECT)
from .postgres_statement_reconciliation import (
    PostgresStatementReconciliation,
    FUNCTION as _STATEMENT_RECONCILIATION_PREVIEW)
from .postgres_statement_pack import (PostgresStatementPack,
    FUNCTION as _STATEMENT_PACK_PREVIEW)
from .postgres_bound_statement_pack import (PostgresBoundStatementPack,
    FUNCTION as _BOUND_STATEMENT_PACK_PREVIEW,
    catalog as bound_statement_pack_catalog)
from .postgres_statement_definitions import (
    PostgresStatementDefinitions,
    catalog as statement_definition_catalog,
    SAVE as _STATEMENT_DEFINITION_SAVE,
    READ as _STATEMENT_DEFINITION_READ,
    LIST as _STATEMENT_DEFINITION_LIST,
    ACTIVATE as _STATEMENT_DEFINITION_ACTIVATE,
    DEACTIVATE as _STATEMENT_DEFINITION_DEACTIVATE)
from .postgres_financial_close import (
    PostgresFinancialClose, catalog as financial_close_catalog,
    REQUEST as _FINANCIAL_CLOSE_REQUEST, READ as _FINANCIAL_CLOSE_READ,
    REOPEN as _FINANCIAL_CLOSE_REOPEN)
from .postgres_contribution_input import (
    PostgresContributionInputPrivate,
    PUBLIC_FUNCTION as _CERTIFIED_FULL_CONTRIBUTION)
from .consolidation_contribution_input import compile_full_contribution_input
from .postgres_ic_pair_inspect import (
    PostgresIntercompanyPairInspector,
    FUNCTION as _IC_PAIR_INSPECT_FUNCTION)
from .postgres_ic_residual_resolution import (
    PostgresIntercompanyResidualResolution,
    FUNCTION as _IC_RESIDUAL_RESOLUTION_FUNCTION)
from .postgres_ic_elimination_preview import (
    PostgresIntercompanyEliminationPreview,
    FUNCTION as _IC_ELIMINATION_PREVIEW_FUNCTION)
from .postgres_ic_elimination import (
    PostgresIntercompanyElimination,
    POST_FUNCTION as _IC_ELIMINATION_PUBLISH_FUNCTION,
    READ_FUNCTION as _IC_ELIMINATION_READ_FUNCTION,
    WITHDRAW_FUNCTION as _IC_ELIMINATION_WITHDRAW_FUNCTION)
from .postgres_ic_adjusted_balance import (
    PostgresIcAdjustedBalance,
    FUNCTION as _IC_ADJUSTED_BALANCE_READ_FUNCTION)
from .postgres_nci_inspect import (
    PostgresNciAttributionInspector,
    FUNCTION as _NCI_ATTRIBUTION_INSPECT)
from .postgres_period_nci_publication import (PUBLISH as _PERIOD_ATTRIBUTION_PUBLISH,
    WITHDRAW as _PERIOD_ATTRIBUTION_WITHDRAW,
    compile_attribution,validate_attribution)
from .postgres_company_nci import PostgresCompanyNciInspector, FUNCTION as _COMPANY_NCI_INSPECT
from .postgres_period_nci_basis import PostgresPeriodNciBasis, READS as _PERIOD_BASIS_READS
from .postgres_period_nci import FUNCTION as _PERIOD_NCI_INSPECT, PostgresPeriodNciInspector
from .postgres_period_policy_governance import (PostgresPeriodPolicyGovernance,
    _READS as _PERIOD_GOVERNANCE_READS)
from .postgres_period_policy_cases import (PostgresPeriodPolicyCases,
    EVALUATE as _PERIOD_CASE_EVALUATE, RECORD as _PERIOD_CASE_RECORD, READ as _PERIOD_CASE_READ)
from .postgres_acquisition_nci import (
    PostgresAcquisitionNciInspector, PostgresAcquisitionStepInspector,
    FUNCTION as _ACQUISITION_NCI_INSPECT,
    STEP_FUNCTION as _ACQUISITION_STEP_INSPECT)
from .postgres_policy_cases import (
    PostgresPolicyCaseEvaluator,
    FUNCTION as _POLICY_ACQUISITION_CASES_EVALUATE,
    RECORD_FUNCTION as _POLICY_ACQUISITION_CASES_RECORD,
    READ_FUNCTION as _POLICY_ACQUISITION_CASES_READ)
from .postgres_policy_case_reviews import (
    PostgresPolicyCaseReviews,
    REVIEW_FUNCTION as _POLICY_ACQUISITION_REVIEW_RECORD,
    READ_FUNCTION as _POLICY_ACQUISITION_REVIEW_READ,
    EVIDENCE_FUNCTION as _POLICY_ACQUISITION_EVIDENCE_INSPECT)
from .postgres_policy_approvals import (
    PostgresPolicyApprovals,APPROVE as _POLICY_APPROVE,
    READ as _POLICY_APPROVAL_READ)
from .postgres_policy_activation import (
    PostgresPolicyActivation,ACTIVATE as _POLICY_ACTIVATE,
    WITHDRAW as _POLICY_WITHDRAW,READ as _POLICY_ACTIVATION_READ,
    RESOLVE as _POLICY_ACTIVATION_RESOLVE,
    CURRENT as _POLICY_ACTIVATION_CURRENT)
from .postgres_policy_source_artifacts import (
    PostgresPolicySourceArtifacts,
    CAPTURE_FUNCTION as _POLICY_SOURCE_ARTIFACT_CAPTURE,
    READ_FUNCTION as _POLICY_SOURCE_ARTIFACT_READ,
    CONTENT_FUNCTION as _POLICY_SOURCE_ARTIFACT_CONTENT_READ,
    CLIENT_PDF_PAGE_FUNCTION as _POLICY_SOURCE_ARTIFACT_CLIENT_PDF_PAGE_READ)
from .postgres_consolidation_full import (
    FUNCTION as _FULL_CONTRIBUTION_FUNCTION,
    TYPED_FUNCTION as _TYPED_FULL_CONTRIBUTION_FUNCTION,
    COMPILER as _FULL_CONTRIBUTION_COMPILER,
    TYPED_COMPILER as _TYPED_FULL_CONTRIBUTION_COMPILER,
    PLAN_DIGEST as _FULL_CONTRIBUTION_PLAN_DIGEST,
    TYPED_PLAN_DIGEST as _TYPED_FULL_CONTRIBUTION_PLAN_DIGEST,
    compile_full_contribution, compile_typed_full_contribution,
    validate_full_contribution, validate_typed_full_contribution)
from .postgres_consolidation_aggregate import (
    FUNCTION as _FULL_AGGREGATE_FUNCTION,
    full_compiler_for,
    authorize_full_aggregate, compile_full_aggregate,
    validate_full_aggregate)
from .postgres_full_sequence import (
    PostgresFullAggregateSequence,
    FUNCTION as _FULL_SEQUENCE_RUN,
    READ as _FULL_SEQUENCE_READ,
    CANCEL as _FULL_SEQUENCE_CANCEL)
from .postgres_full_tree_plan import (
    PostgresFullTreePlanner,
    FUNCTION as _FULL_TREE_PLAN)
from .postgres_calculation_scan import (
    PostgresCalculationScan,
    FUNCTION as _CALCULATION_SCAN_FUNCTION)
from .postgres_expression import (
    FUNCTION as _EXPRESSION_FUNCTION,
    compile_expression_program, compiler_for, expression_references,
    enforce_expression_dimensional_security,
    resolve_published_inputs,
    source_count as expression_source_count)
from .expression_currency_member_set import (
    COMPILER as _CURRENCY_MEMBER_SET_COMPILER,
    PLAN_DIGEST as _CURRENCY_MEMBER_SET_PLAN_DIGEST,
    normalize_request as normalize_currency_member_set_request,
    preview_contract as currency_member_set_preview_contract,
    resolve_and_seal as resolve_currency_member_set,
    validate_admission as validate_currency_member_set_admission)
from .expression_hierarchy_member_set import (
    COMPILER as _HIERARCHY_REDUCTION_COMPILER,
    PLAN_DIGEST as _HIERARCHY_REDUCTION_PLAN_DIGEST,
    normalize_request as normalize_hierarchy_reduction_request,
    cardinality as hierarchy_reduction_cardinality,
    resolve as resolve_hierarchy_reduction,
    validate_admission as validate_hierarchy_reduction_admission)
from .expression_hierarchy_two_axis import (
    COMPILER as _TWO_AXIS_HIERARCHY_REDUCTION_COMPILER,
    PLAN_DIGEST as _TWO_AXIS_HIERARCHY_REDUCTION_PLAN_DIGEST,
    normalize_request as normalize_two_axis_hierarchy_reduction_request,
    cardinality as two_axis_hierarchy_reduction_cardinality,
    resolve as resolve_two_axis_hierarchy_reduction,
    validate_admission as validate_two_axis_hierarchy_reduction_admission)
from .postgres_expression_rules import (
    PostgresExpressionRules, SAVE as _RULE_SAVE,
    PUBLISH as _RULE_PUBLISH, READ as _RULE_READ,
    LIST as _RULE_LIST,
    RUN as _RULE_RUN, verify_published_rule)
from .postgres_expression_sequence import (
    PostgresExpressionSequence,
    FUNCTION as _RULE_SEQUENCE_RUN,
    READ as _RULE_SEQUENCE_READ,
    CANCEL as _RULE_SEQUENCE_CANCEL)
from .postgres_equity_rollforward_chain import (
    PostgresEquityRollforwardChain,
    INSPECT as _EQUITY_CHAIN_INSPECT,
    REQUEST as _EQUITY_CHAIN_REQUEST,
    READ as _EQUITY_CHAIN_READ)
from .postgres_adjusted_scan import (
    PostgresAdjustedScan,
    FUNCTION as _ADJUSTED_SCAN_FUNCTION)
from .postgres_jobs import (PostgresJobQueue, _canonical_digest,
                            _numeric_program, _text_program)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_currency_settings import (
    PostgresCurrencySettings, SAVE as _CURRENCY_SETTINGS_SAVE,
    READ as _CURRENCY_SETTINGS_READ)
from .postgres_currency_rates import (
    PostgresCurrencyRates, FUNCTION as _CURRENCY_RATE_RESOLVE)
from .postgres_currency_amount_preview import (
    PostgresCurrencyAmountPreview,
    FUNCTION as _CURRENCY_AMOUNT_TRANSLATE_PREVIEW)
from .postgres_currency_amount_publication import (
    FUNCTION as _CURRENCY_AMOUNT_TRANSLATE_PUBLISH,
    preview as _currency_amount_publish_preview,
    submit as _currency_amount_publish_submit)
from .postgres_currency_translation import (
    PostgresCurrencyTranslation,
    FUNCTION as _CURRENCY_TRANSLATION_INSPECT)
from .postgres_financial_member_policy import (
    PostgresFinancialMemberPolicy,
    ACCOUNT_SET as _FINANCIAL_ACCOUNT_SET,
    ENTITY_SET as _FINANCIAL_ENTITY_SET,
    READ as _FINANCIAL_POLICY_READ)
from .postgres_currency_publication import (
    FUNCTION as _CURRENCY_TRANSLATION_PUBLISH,
    COMPILER as _CURRENCY_TRANSLATION_COMPILER,
    PLAN_DIGEST as _CURRENCY_TRANSLATION_PLAN_DIGEST,
    compile_translation, target_coordinate,
    enforce_translation_dimensional_security)
from .postgres_currency_calculation_translation import (
    FUNCTION as _CALCULATION_TRANSLATION_PUBLISH,
    COMPILER as _CALCULATION_TRANSLATION_COMPILER,
    PLAN_DIGEST as _CALCULATION_TRANSLATION_PLAN_DIGEST,
    compile_calculation_translation, validate_calculation_translation,
    enforce_calculation_translation_dimensional_security)
from .postgres_consolidation_translated import (
    FUNCTION as _TRANSLATED_FULL_FUNCTION,
    COMPILER as _TRANSLATED_FULL_COMPILER,
    PLAN_DIGEST as _TRANSLATED_FULL_PLAN_DIGEST,
    compile_translated_full, validate_translated_full,
    enforce_translated_full_dimensional_security)
from .postgres_metadata import PostgresMetadataStore
from .postgres_attribute_catalog import (
    PostgresAttributeCatalog,
    DEFINITION_CREATE as _ATTRIBUTE_DEFINITION_CREATE,
    DEFINITION_UPDATE as _ATTRIBUTE_DEFINITION_UPDATE,
    DEFINITION_STATUS as _ATTRIBUTE_DEFINITION_STATUS,
    DEFINITION_LIST as _ATTRIBUTE_DEFINITION_LIST,
    DEFINITION_USAGE as _ATTRIBUTE_DEFINITION_USAGE,
    VALUE_SET as _ATTRIBUTE_VALUE_SET,
    VALUES_REPLACE as _ATTRIBUTE_VALUES_REPLACE,
    VALUE_READ as _ATTRIBUTE_VALUE_READ)
from .postgres_semantic_attributes import (
    PostgresSemanticAttributes,
    CREATE as _SEMANTIC_CREATE, UPDATE as _SEMANTIC_UPDATE,
    SET as _SEMANTIC_SET,
    LIST as _SEMANTIC_LIST, READ as _SEMANTIC_READ,
    REL_CREATE as _REL_SEMANTIC_CREATE,
    REL_UPDATE as _REL_SEMANTIC_UPDATE,
    REL_SET as _REL_SEMANTIC_SET,
    REL_LIST as _REL_SEMANTIC_LIST,
    REL_READ as _REL_SEMANTIC_READ)
from .postgres_generic_facts import (
    PostgresGenericFacts, CREATE as _GENERIC_CREATE,
    UPDATE as _GENERIC_UPDATE,
    TABLE_DELETE as _GENERIC_TABLE_DELETE,
    SET as _GENERIC_SET, DELETE as _GENERIC_DELETE,
    BULK as _GENERIC_BULK,
    LIST as _GENERIC_LIST, READ as _GENERIC_READ,
    SCAN as _GENERIC_SCAN,
    SNAPSHOT_SCAN as _GENERIC_SNAPSHOT_SCAN)
from .postgres_source_batch import PostgresSourceBatch
from .postgres_transfer_orchestration import (
    PostgresTransferOrchestration,
    PUBLIC_FUNCTIONS as _TRANSFER_ORCHESTRATION_FUNCTIONS,
    catalog as transfer_orchestration_catalog)
from .postgres_source_evidence import (
    PostgresSourceEvidence, catalog as source_evidence_catalog,
    WRITE_FUNCTIONS as _SOURCE_EVIDENCE_WRITES,
    READ_FUNCTIONS as _SOURCE_EVIDENCE_READS)
from .postgres_source_evidence_cutover import (
    PostgresSourceEvidenceCutover,
    catalog as source_evidence_cutover_catalog,
    PREVIEW as _SOURCE_EVIDENCE_CUTOVER_PREVIEW,
    APPLY as _SOURCE_EVIDENCE_CUTOVER_APPLY)
from .postgres_import_execution import (
    PostgresImportExecutionPublic,
    PUBLIC_FUNCTIONS as _IMPORT_EXECUTION_FUNCTIONS,
    catalog as import_execution_catalog)
from .postgres_transfer_artifacts import (
    PostgresTransferArtifacts, READ_FUNCTIONS as _TRANSFER_ARTIFACT_READS,
    transfer_artifact_catalog)
from .postgres_export_payload import (
    PostgresExportPayload, PUBLIC_READS as _EXPORT_PAYLOAD_READS,
    export_payload_catalog)
from .postgres_scale import (compile_scale_program, _scale_candidate,
                             enforce_scale_dimensional_security,
                             PostgresScaleReader,
                             _COMPILER as _SCALE_COMPILER,
                             _PLAN_DIGEST as _SCALE_PLAN_DIGEST)
from .postgres_planning_spread import (
    FUNCTION as _SPREAD_FUNCTION,COMPILER as _SPREAD_COMPILER,
    PLAN_DIGEST as _SPREAD_PLAN_DIGEST,compile_spread_program,
    validate_spread_inputs,enforce_spread_dimensional_security,
    CALENDAR_FUNCTION as _CALENDAR_SPREAD_FUNCTION,
    CALENDAR_COMPILER as _CALENDAR_SPREAD_COMPILER,
    CALENDAR_PLAN_DIGEST as _CALENDAR_SPREAD_PLAN_DIGEST,
    compile_calendar_spread_program)
from .postgres_planning_locks import (
    ALL_FUNCTIONS as _CUBE_WRITE_SCOPE_TRANSITIONS,
    PUBLIC_READ as _CUBE_WRITE_SCOPE_READ,
    PUBLIC_WORKLIST as _CUBE_WRITE_SCOPE_WORKLIST,
    PostgresPlanningLocks)
from .postgres_planning_copy import (
    FUNCTION as _COPY_FUNCTION,PostgresScenarioCopy)
from .postgres_planning_allocation import (
    FUNCTION as _ALLOCATION_FUNCTION,COMPILER as _ALLOCATION_COMPILER,
    PLAN_DIGEST as _ALLOCATION_PLAN_DIGEST,
    compile_allocation_program,validate_allocation_inputs,
    enforce_allocation_dimensional_security)
from .postgres_planning_rollup import (
    FUNCTION as _ROLLUP_FUNCTION, COMPILER as _ROLLUP_COMPILER,
    PLAN_DIGEST as _ROLLUP_PLAN_DIGEST, compile_rollup_program,
    PLACEMENT_COMPILER as _ROLLUP_PLACEMENT_COMPILER,
    PLACEMENT_PLAN_DIGEST as _ROLLUP_PLACEMENT_PLAN_DIGEST,
    RECURSIVE_PLACEMENT_COMPILER as _ROLLUP_RECURSIVE_PLACEMENT_COMPILER,
    RECURSIVE_PLACEMENT_PLAN_DIGEST as _ROLLUP_RECURSIVE_PLACEMENT_PLAN_DIGEST,
    current_hierarchy_state_token, validate_rollup_inputs,
    enforce_rollup_dimensional_security)
from .postgres_planning_group import (
    FUNCTION as _GROUP_FUNCTION, COMPILER as _GROUP_COMPILER,
    PLAN_DIGEST as _GROUP_PLAN_DIGEST, compile_group_program,
    validate_group_inputs,enforce_group_dimensional_security)
from .postgres_planning_group_bulk import (
    FUNCTION as _BULK_GROUP_FUNCTION, COMPILER as _BULK_GROUP_COMPILER,
    PLAN_DIGEST as _BULK_GROUP_PLAN_DIGEST, compile_bulk_group,
    validate_bulk_inputs,enforce_bulk_group_dimensional_security)
from .postgres_ownership import (
    PostgresOwnershipValues,
    WRITE_FUNCTION as _OWNERSHIP_WRITE_FUNCTION,
    READ_FUNCTION as _OWNERSHIP_READ_FUNCTION,
    SCOPE_READ_FUNCTION as _OWNERSHIP_SCOPE_READ_FUNCTION)
from .postgres_calendar import (
    PostgresCalendarPeriods,
    SET_FUNCTION as _CALENDAR_SET_FUNCTION,
    READ_FUNCTION as _CALENDAR_READ_FUNCTION)
from .postgres_policy_drafts import (
    PostgresPolicyDrafts,
    CREATE_FUNCTION as _POLICY_DRAFT_CREATE_FUNCTION,
    READ_FUNCTION as _POLICY_DRAFT_READ_FUNCTION,
    ELECTIONS_FUNCTION as _POLICY_DRAFT_ELECTIONS_FUNCTION)
from .postgres_manual_journal import (
    PostgresManualJournal,
    POST_FUNCTION as _JOURNAL_POST_FUNCTION,
    REVERSE_FUNCTION as _JOURNAL_REVERSE_FUNCTION,
    READ_FUNCTION as _JOURNAL_READ_FUNCTION,
    BALANCE_READ_FUNCTION as _JOURNAL_BALANCE_READ_FUNCTION,
    ADJUSTED_READ_FUNCTION as _ADJUSTED_BALANCE_READ_FUNCTION)
from .postgres_expression_journal import (
    FUNCTION as _EXPRESSION_JOURNAL_PUBLISH,
    COMPILER as _EXPRESSION_JOURNAL_COMPILER,
    PLAN_DIGEST as _EXPRESSION_JOURNAL_PLAN_DIGEST,
    compile_program as compile_expression_journal,
    validate_in_transaction as validate_expression_journal)
from .postgres_cta_bridge import (PostgresCtaBridge,
    PREVIEW as _CTA_PREVIEW,FUNCTION as _CTA_POST,READ as _CTA_READ)
from .postgres_cta_close_handoff import (
    PostgresCtaCloseHandoff,FUNCTION as _CTA_CLOSE_HANDOFF)
from .postgres_consolidation_layout import (PostgresConsolidationLayout,
    CONFIGURE as _CONSOLIDATION_LAYOUT_CONFIGURE,
    READ as _CONSOLIDATION_LAYOUT_READ)


from .postgres_acquisition_journal import (
    FUNCTION as _ACQ_POST, COMPILER as _ACQ_COMPILER, compile_program as compile_acquisition_journal)
from .postgres_acquisition_journal_effects import (
    PLAN_DIGEST as _ACQ_PLAN_DIGEST, validate_in_transaction as validate_acquisition_journal)
from .postgres_acquisition_journal_history import (
    PostgresAcquisitionJournalHistory, READ as _ACQ_READ, BALANCE as _ACQ_BALANCE, REVERSE as _ACQ_REVERSE)


def compile_numeric_program(program: object) -> tuple[NumericMutation, ...]:
    """Resolve exact V2 syntax into typed, bounded fixed-core mutations."""
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != 'facts.numeric.batch'
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'mutations'}):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    rows = program['arguments']['mutations']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise ValueError('V2_MUTATION_BATCH_BOUNDS')
    mutations = []
    for row in rows:
        if (not isinstance(row, dict)
                or not {'coordinate', 'op', 'expectedChangeId'} <= set(row)
                or set(row) - {'coordinate', 'op', 'expectedChangeId', 'value'}
                or not isinstance(row['expectedChangeId'], str)
                or len(row['expectedChangeId']) > 200):
            raise ValueError('V2_MUTATION_INVALID')
        try:
            coordinate = Coordinate.from_mapping(row['coordinate'])
            kind = MutationKind(row['op'])
            if kind == MutationKind.CLEAR:
                if 'value' in row:
                    raise ValueError('Clear has no value')
                amount = None
            else:
                value = row.get('value')
                if (not isinstance(value, dict)
                        or set(value) != {'type', 'decimal'}
                        or value['type'] != 'AmountLiteral'):
                    raise ValueError('AmountLiteral required')
                amount = NumericCell.from_wire(
                    present=True, amount=value['decimal']).amount
            mutations.append(NumericMutation(
                coordinate, kind, amount, row['expectedChangeId']))
        except (TypeError, ValueError) as error:
            raise ValueError('V2_MUTATION_INVALID') from error
    result = tuple(mutations)
    if len({item.coordinate for item in result}) != len(result):
        raise ValueError('V2_DUPLICATE_COORDINATE')
    return result


def compile_text_program(program: object) -> tuple[TextMutation, ...]:
    """Resolve a bounded, typed text batch into fixed-core mutations."""
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != 'facts.text.batch'
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'mutations'}):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    rows = program['arguments']['mutations']
    if not isinstance(rows, list) or not 1 <= len(rows) <= 500:
        raise ValueError('V2_MUTATION_BATCH_BOUNDS')
    mutations = []
    for row in rows:
        if (not isinstance(row, dict)
                or not {'coordinate', 'op', 'expectedChangeId'} <= set(row)
                or set(row) - {'coordinate', 'op', 'expectedChangeId', 'value'}
                or not isinstance(row['expectedChangeId'], str)
                or len(row['expectedChangeId']) > 200):
            raise ValueError('V2_MUTATION_INVALID')
        try:
            coordinate = Coordinate.from_mapping(row['coordinate'])
            kind = TextMutationKind(row['op'])
            if kind == TextMutationKind.CLEAR:
                if 'value' in row:
                    raise ValueError('Clear has no value')
                value = None
            else:
                literal = row.get('value')
                if (not isinstance(literal, dict)
                        or set(literal) != {'type', 'text'}
                        or literal['type'] != 'TextLiteral'):
                    raise ValueError('TextLiteral required')
                value = literal['text']
            mutations.append(TextMutation(
                coordinate, kind, value, row['expectedChangeId']))
        except (TypeError, ValueError) as error:
            raise ValueError('V2_MUTATION_INVALID') from error
    result = tuple(mutations)
    if len({item.coordinate for item in result}) != len(result):
        raise ValueError('V2_DUPLICATE_COORDINATE')
    return result


class PostgresLanguageV2:
    """Preview and admit V2 programs against a current scoped revision vector."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes,
                 approved_python_profiles: tuple[ApprovedPythonEnvironment, ...] = ()):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(preview_secret, bytes) or len(preview_secret) < 32:
            raise ValueError('A server-owned preview secret of 32+ bytes is required')
        self.dsn = dsn
        self.identity = identity
        self.preview_secret = preview_secret
        if (not isinstance(approved_python_profiles, tuple)
                or any(not isinstance(item, ApprovedPythonEnvironment)
                       for item in approved_python_profiles)):
            raise ValueError('PYTHON_ENVIRONMENT_CONFIGURATION_INVALID')
        self.approved_python_profiles = approved_python_profiles

    def _aggregate_service(self) -> CubeAggregateService:
        """Build the fixed-core aggregate boundary for the verified subject."""
        return CubeAggregateService(
            PostgresCubeAggregateRepository(self.dsn, identity=self.identity),
            NativeCubeAggregateStage(self.dsn, identity=self.identity),
            AggregateCursorCodec(self.preview_secret), identity=self.identity)

    def issue_operation_admission(self, scope: ApplicationScope,
            program: dict, *, ttl_seconds: int = 900,
            now: int | None = None) -> OperationAdmission:
        """Issue an expiring operation identity for one exact typed intent.

        Issuance does not authorize or execute the operation. Public adapters
        must first apply their normal current authorization check; submission
        then rechecks authorization and authenticates this exact scope, actor,
        function and canonical program digest.
        """
        specification = (self.catalog()["functions"].get(program.get("function"))
                         if isinstance(program, dict) else None)
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {"languageVersion", "function", "arguments"}
                or program.get("languageVersion") != 2
                or not isinstance(program.get("function"), str)
                or not isinstance(program.get("arguments"), dict)
                or not isinstance(specification, dict)
                or specification.get("idempotencyRequired") is not True):
            raise ValueError("OPERATION_ADMISSION_PROGRAM_INVALID")
        return issue_signed_operation_admission(
            self.preview_secret, scope, self.identity,
            function=program["function"],
            intent_digest=_canonical_digest(program),
            ttl_seconds=ttl_seconds, now=now)

    def _validate_signed_operation_id(self, scope: ApplicationScope,
            program: dict, operation_id: str, *,
            now: int | None = None) -> None:
        """Authenticate signed IDs while legacy IDs remain bounded migration input."""
        if is_signed_operation_id(operation_id):
            validate_operation_admission(
                self.preview_secret, scope, self.identity,
                operation_id=operation_id,
                function=program.get("function") if isinstance(program, dict) else "",
                intent_digest=_canonical_digest(program), now=now)

    def _aggregate_layout(self, scope: ApplicationScope) -> tuple[list, dict]:
        """Resolve trusted active axes after a fresh current read grant check."""
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,
                    'read',function='facts.cube.aggregate.request')
                rows=db.execute('''SELECT dimension_id,model_role FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s AND status='Active'
                    AND model_role IS DISTINCT FROM 'Currency' ORDER BY dimension_id''',
                    (scope.workspace_id,scope.application_id)).fetchall()
        roles={row['dimension_id']:row['model_role'] for row in rows}
        return list(roles),roles

    @staticmethod
    def catalog() -> dict:
        """Machine-readable contracts implemented by this PostgreSQL slice."""
        from .postgres_python_impact import catalog_limits as python_impact_limits
        catalog = {'languageVersion': 2, 'functions': {
            **transfer_artifact_catalog(),
            **export_payload_catalog(),
            **transfer_orchestration_catalog(),
            **source_evidence_catalog(),
            **source_evidence_cutover_catalog(),
            **import_execution_catalog(),
            **execution_delegation_catalog(),
            **_cell_editability_catalog(),
            **planning_workflow_policy_catalog(),
            **saved_grid_catalog(),
            **member_list_catalog(),
            **applicability_relation_catalog(),
            **selection_preview_catalog(),
            **member_selection_catalog(),
            **sealed_selection_catalog(),
            **generic_aggregate_catalog(),
            **planning_operation_policy_catalog(),
            **published_driver_policy_catalog(),
            **published_seed_policy_catalog(),
            **published_rollup_policy_catalog(),
            **published_spread_policy_catalog(),
            **published_allocation_policy_catalog(),
            **hierarchy_relationship_patch_catalog(),
            **inventory_unrealized_schedule_catalog(),
            **PostgresPythonEnvironments.catalog(),
            **PostgresApplicationCapabilities.catalog(),
            **PostgresPeriodPolicyCases.catalog(),
            **PostgresPeriodPolicyGovernance.catalog(),
            **PostgresPeriodNciBasis.catalog(),
            **PostgresCompanyNciInspector.catalog(),
            **PostgresStatementReconciliation.catalog(),
            **PostgresStatementPack.catalog(),
            **bound_statement_pack_catalog(),
            **statement_definition_catalog(),
            **PostgresConsolidationLayout.catalog(),
            **financial_close_catalog(),
            _POPULATED_LAYOUT_PREVIEW: {
                'mode': 'read_only', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'medium',
                'arguments': {
                    'expectedPins': 'exact metadata/data/policy/schema/commit revision vector',
                    'targetAxes': '1-200 explicit member axes; no implicit defaults',
                    'axisMapping': 'complete source-axis to target-axis or null mapping',
                    'coordinateMappings': 'complete bounded old-to-new coordinate mapping',
                    'targetMetadata': 'optional plan-v2 definition of exactly one new Custom leaf axis and explicitly mapped members'},
                'result': 'read-only deterministic impact summary and sealed plan/preview digests',
                'workflowRoute':{
                    'stages':['metadata.layout.populated.replace.request',
                        'metadata.layout.populated.replace.read',
                        'metadata.layout.populated.activate.request',
                        'metadata.layout.populated.activate.read'],
                    'boundary':'replacement builds and validates a private generation before a separate eligible activation request atomically switches the layout; cancellation remains available before each publication boundary'}},
            _LAYOUT_REPLACE_REQUEST: {
                'mode': 'durable_workflow', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'medium',
                'arguments': {'preview': 'exact current populated-layout preview certificate',
                    'plan': 'complete canonical explicit coordinate mapping plan, maximum 100,000 coordinates',
                    'idempotencyKey': '8-128 safe characters'},
                'result': 'durable private replacement request and target generation identity; no activation'},
            _LAYOUT_REPLACE_READ: {
                'mode': 'read_only', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
                'arguments': {'requestId': 'exact 32-character hexadecimal request identity'},
                'result': 'bounded technical state, pins, digests and staged-coordinate count'},
            _LAYOUT_REPLACE_CANCEL: {
                'mode': 'technical_control', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
                'arguments': {'requestId': 'exact 32-character hexadecimal request identity',
                    'expectedStatus': 'exact Accepted or Staging state pin'},
                'result': 'Cancelled only before staged completion; no active layout effect'},
            _LAYOUT_ACTIVATE_REQUEST: {
                'mode': 'durable_workflow', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
                'arguments': {'requestId': 'exact validated 32-character request identity',
                    'targetGenerationId': 'exact validated private generation identity',
                    'validationDigest': 'exact eligible validation certificate digest',
                    'expectedPins': 'exact metadata/data/policy/schema/commit source revision vector',
                    'dependencyDecisions': '0-10,000 explicit compatible/invalidate/rebuild rule or publication decisions',
                    'idempotencyKey': '8-128 safe characters'},
                'result': 'durable Requested activation identity; a private worker owns publication'},
            _LAYOUT_ACTIVATE_READ: {
                'mode': 'read_only', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
                'arguments': {'activationId': 'exact 32-character activation identity'},
                'result': 'bounded state, certificate pins, private generation and committed receipt if activated'},
            _LAYOUT_ACTIVATE_CANCEL: {
                'mode': 'technical_control', 'permission': 'admin',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
                'arguments': {'activationId': 'exact 32-character activation identity',
                    'expectedStatus': 'exact Requested state pin',
                    'expectedStateVersion': 'exact nonnegative lifecycle version'},
                'result': 'Cancelled only while Requested; activation publication is never relabelled cancelled'},
            _PERIOD_ATTRIBUTION_PUBLISH:{'mode':'durable_write','permission':'write','previewRequired':True,'idempotencyRequired':True,'workClass':'medium',
                'arguments':{'definitionId':'exact owner basis declaration','expectedDefinitionDigest':'exact SHA256',
                    'source':'single-kind current resultKey/generationId/publishedRevision',
                    'sources':'composed kind: exact component definitionId/source pin list','relationshipId':'direct contribution relationship',
                    'parentMembers':'complete published source grain','expectedPolicyRevision':'current integer',
                    'decisions':'company only: complete relationshipId/Full/controlConfirmed list',
                    'includeParentSource':'company only: explicit Boolean matching Full sources',
                    'lowerCompanies':'propagated company only: exact grouped relationshipId/presentation pins under explicit policy election',
                    'targetAccounts':'distinct nci/controlling active leaf Accounts','resultKey':'stable attribution publication key'},
                'result':'sealed separate NCI/controlling outputs, exact source lineage and no raw or acquisition-journal changes'},
            _PERIOD_ATTRIBUTION_WITHDRAW:{'mode':'durable_write','permission':'write','previewRequired':True,'idempotencyRequired':True,'workClass':'medium',
                'arguments':{'resultKey':'existing attribution key',
                    'resultStateToken':'exact current attribution state token',
                    'reason':'10–2000 characters'},
                'result':'empty current withdrawal result; prior result is not addressable'},
            _ACQ_POST: {
                'mode':'durable_write','permission':'admin',
                'arguments':{
                    'acquisitionKey':'unique economic acquisition key, 8–128 safe characters',
                    'policyId':'approved policy ID','policyStateToken':'exact approved current policy token',
                    'candidateFunction':'approved single-step NCI or bounded 100%-final step candidate',
                    'selections':'exact approved election map','effectiveOn':'operational ISO date',
                    'activationId':'exact current activation event ID','relationshipId':'active direct Entity placement',
                    'targetMembers':'parent full grain except Account; Currency is not an axis',
                    'currencyMemberId':'same active functional currency for parent/child',
                    'sources':'exact named coordinate/expectedChangeId map; raw unadjusted numeric inputs, signed child net-assets credit',
                    'accounts':'distinct explicit account IDs for netAssetsOffset/goodwill/investmentOffset and NCI or remeasurement',
                    'expectedInvestmentChangeId':'current parent book-investment change ID',
                    'controlConfirmed':'literal true','priorControlConfirmed':'literal false',
                    'fairValueBasisConfirmed':'literal true','reason':'explicit 1–500 character reason'},
                'result':'durable job; atomic balanced AcquisitionInvestmentOffset journal, not a full financial close',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'},
            _ACQ_READ: {'mode':'read_only','permission':'read',
                'arguments':{'journalId':'original or reversal journal ID'},
                'result':'immutable scoped history, lines, correction link, separate policy/raw-source currentness and current revisionVector',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _ACQ_BALANCE: {'mode':'read_only','permission':'read',
                'arguments':{'members':'full historical coordinate','currencyDimensionId':'recorded Currency registry ID',
                    'currencyMemberId':'recorded currency ID','snapshotRevision':'optional committed snapshot'},
                'result':'exact separate acquisition-layer signed balance; never implicitly merged with raw/manual data',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _ACQ_REVERSE: {'mode':'atomic_adjustment','permission':'admin',
                'arguments':{'journalId':'original acquisition journal ID','reason':'explicit correction reason',
                    'expectedMetadataRevision':'current nonnegative integer',
                    'expectedDataRevision':'current nonnegative integer','expectedPolicyRevision':'current nonnegative integer'},
                'result':'idempotent exact historical negation, including after policy withdrawal; current planning locks apply',
                'previewRequired':False,'idempotencyRequired':True,'workClass':'short'},
            _FINANCIAL_ACCOUNT_SET: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'accountMemberId': 'active Account member ID',
                    'accountType': 'typed AccountType or null to clear',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _FINANCIAL_ENTITY_SET: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'entityMemberId': 'active Entity member ID',
                    'currencyMemberId': 'active Currency member ID or null',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _FINANCIAL_POLICY_READ: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'dimensionRole': 'Account or Entity',
                    'memberId': 'active member ID'},
                'result': 'typed AccountType or Entity default Currency',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.member.numeric-kind.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active dimension ID',
                    'memberId': 'active member ID',
                    'numericValueKind': 'amount, ratio, or null to clear',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.aggregation-operator.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active dimension ID',
                              'memberId': 'active member ID',
                              'aggregationOperator': ('Add, Subtract, Ignore, '
                                  'NeverAggregate or Formula'),
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _CURRENCY_SETTINGS_SAVE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'applicationCurrencyMemberId': 'active Currency member ID',
                    'balanceRateAccountMemberId': 'active leaf Account member ID',
                    'flowRateAccountMemberId': 'active leaf Account member ID',
                    'fromCurrencyDimensionId': 'active Custom dimension ID',
                    'toCurrencyDimensionId': 'different active Custom dimension ID',
                    'entityNoneMemberId': 'active Entity member ID',
                    'entityCurrencyValueMemberId': 'active Value member ID',
                    'ytdViewMemberId': 'active View member ID',
                    'icpNoneMemberId': 'active ICP member ID',
                    'balanceMethod': 'PVA or VAL',
                    'flowMethod': 'PVA or VAL',
                    'expectedMetadataRevision': 'nonnegative integer',
                    'expectedPolicyRevision': 'nonnegative integer'},
                'result': 'unreviewed settings and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _CURRENCY_SETTINGS_READ: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {},
                'result': 'current settings, revision and freshness status',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _CURRENCY_RATE_RESOLVE: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'coordinate': 'complete active fact POV without Currency',
                    'fromCurrencyMemberId': 'active Currency member ID',
                    'toCurrencyMemberId': 'active Currency member ID',
                    'rateKind': 'balance or flow'},
                'result': 'Unreviewed exact rational factor and source cells',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _CURRENCY_AMOUNT_TRANSLATE_PREVIEW: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'coordinate': 'one complete present Amount coordinate without Currency',
                    'sourceAmount': 'exact current Amount decimal',
                    'sourceChangeId': 'exact current source-cell identity',
                    'fromCurrencyMemberId': 'source Entity default Currency member',
                    'toCurrencyMemberId': 'different active target Currency member',
                    'rateKind': 'balance or flow',
                    'expectedRate': 'exact strategy, rational factor and 1–2 source change IDs returned by currency.rate.resolve',
                    'expectedDataRevision': 'exact current data revision',
                    'rounding': 'literal half-even-final-8'},
                'result': 'no-effect exact Amount × pinned resolved Rate with source/rate/unit/revision lineage; no consolidation translation or publication',
                'operationalPublication':{
                    'function':'currency.amount.translate.publish',
                    'boundary':'separate previewed durable generic-Amount current-result replacement with exact source, rate, unit and current-state pins; no statutory FX or CTA semantics'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _CURRENCY_AMOUNT_TRANSLATE_PUBLISH: {
                'mode':'durable_job','permission':'write',
                'arguments': {
                    'coordinate':'one complete present immutable raw Amount coordinate without Currency',
                    'sourceAmount':'exact current Amount decimal','sourceChangeId':'exact current source identity',
                    'fromCurrencyMemberId':'source Entity default Currency','toCurrencyMemberId':'different target Currency',
                    'rateKind':'balance or flow','expectedRate':'resolved exact factor and source changes',
                    'expectedDataRevision':'exact source/rate data revision','rounding':'half-even-final-8',
                    'resultKey':'stable named current calculation result',
                    'rows':'alternative 1–100 unique complete row intents; each row has the preceding source/rate/unit pins'},
                'result':'one atomically replaced exact generic current result with opaque state token and content digest; raw facts unchanged; no statutory FX/CTA semantics',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'},
            'facts.cube.aggregate.read': {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'queryId': 'accepted aggregate query ID'},
                'optionalArguments': {
                    'cursor': 'signed subject-bound continuation cursor',
                    'pageSize': '1–500 rows, fixed by the first page'},
                'result': 'durable status or one bounded persisted result page with a technical query certificate; never a business receipt',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'facts.cube.aggregate.request': {
                'mode': 'durable_technical_query', 'permission': 'read',
                'arguments': {'query': 'bounded raw numeric aggregate intent'},
                'optionalArguments': {'limits': 'lower maxGroups, maxResultBytes, pageSize and ttlSeconds budgets'},
                'result': 'durable ready query ID; a technical worker computes asynchronously without a business receipt or revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'medium',
            },
            'facts.cube.aggregate.cancel': {
                'mode': 'technical_control', 'permission': 'read',
                'arguments': {'queryId': 'accepted aggregate query ID'},
                'result': 'durable cancellation state; no business revision or receipt',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _PYTHON_PROGRAM_SAVE: {
                'mode': 'atomic_rule_authoring', 'permission': 'rule_design',
                'arguments': {'definition': 'current Python source definition with stable program ID, source, entry point, parameter schema and exact environment state token',
                    'expectedMetadataRevision': 'current revision',
                    'expectedPolicyRevision': 'current revision',
                    'expectedSchemaEpoch': 'current schema epoch'},
                'optionalArguments': {'expectedStateToken': 'required exact token when replacing the current source',
                    'validationParameters': 'bounded sample parameter object; defaults to {}'},
                'result': 'current inactive source, state/source tokens, receipt and atomically queued Validation build',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short'},
            _PYTHON_PROGRAM_ACTIVATE: {
                'mode': 'atomic_rule_publication', 'permission': 'rule_publish',
                'arguments': {'programId': 'saved program ID',
                    'expectedStateToken': 'exact current program state token',
                    'expectedMetadataRevision': 'current revision',
                    'expectedPolicyRevision': 'current revision',
                    'expectedSchemaEpoch': 'current schema epoch'},
                'optionalArguments': {'validationBuildId': 'exact reviewed caller-owned current Validation or ImpactTest build; required for typed definition activation'},
                'result': 'active current source and receipt after sealed Validation or completed ImpactTest of this exact source',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short'},
            _PYTHON_PROGRAM_DEACTIVATE: {
                'mode': 'atomic_rule_publication', 'permission': 'rule_publish',
                'arguments': {'programId': 'currently published program ID',
                    'expectedStateToken': 'exact current program state token',
                    'expectedMetadataRevision': 'current revision',
                    'expectedPolicyRevision': 'current revision',
                    'expectedSchemaEpoch': 'current schema epoch'},
                'result': 'inactive current source and operation receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short'},
            _PYTHON_PROGRAM_DELETE: {
                'mode': 'atomic_rule_publication', 'permission': 'rule_publish',
                'arguments': {'programId': 'inactive current program ID',
                    'expectedStateToken': 'exact current program state token',
                    'expectedMetadataRevision': 'current revision',
                    'expectedPolicyRevision': 'current revision',
                    'expectedSchemaEpoch': 'current schema epoch'},
                'result': 'deleted current source and operation receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short'},
            _PYTHON_PROGRAM_READ: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'programId': 'program ID'},
                'result': 'authorized current source and lifecycle state',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short'},
            _PYTHON_PROGRAM_LIST: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'limit': 'optional 1-100',
                    'afterProgramId': 'optional keyset cursor'},
                'result': 'bounded current publication summaries',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short'},
            _PYTHON_PROGRAM_BUILD: {
                'mode': 'durable_technical_build', 'permission': 'rule_run',
                'arguments': {'programId': 'published program ID',
                    'programSourceToken': 'exact current source token',
                    'parameters': 'bounded typed JSON parameter object',
                    'expectedMetadataRevision': 'current revision',
                    'expectedPolicyRevision': 'current revision',
                    'expectedSchemaEpoch': 'current schema epoch',
                    'delegationId': 'current execution delegation ID',
                    'delegationStateToken': 'exact current delegation state token',
                    'scheduleId': 'required field, exact schedule ID or null for a direct build',
                    'scheduleStateToken': 'required field, exact current schedule token or null for a direct build'},
                'result': 'durable build ID and technical status; no business effect or receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'medium'},
            _PYTHON_PROGRAM_TEST: {
                'mode': 'durable_technical_build', 'permission': 'rule_design',
                'arguments': {'programId': 'saved program ID, active or inactive',
                    'programSourceToken': 'exact current source token',
                    'parameters': 'bounded typed parameter values',
                    'expectedMetadataRevision': 'current revision',
                    'expectedPolicyRevision': 'current revision',
                    'expectedSchemaEpoch': 'current schema epoch'},
                'optionalArguments': {'definitionParameters': 'explicit returned-definition runtime bindings, distinct from builder parameters; default {}'},
                'result': 'ImpactTest build/task ID; sealed status includes complete private Impact artifact, never live writes',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'medium',
                'limits': python_impact_limits()},
            _PYTHON_PROGRAM_RUN: {
                'mode': 'durable_business_workflow', 'permission': 'rule_run',
                'arguments': {'buildId': 'caller-owned sealed build ID'},
                'result': 'checkpointed workflow',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'medium',
                'limits': {
                    'atomicProfiles': {
                        'single': '1 op',
                        'sameFact': '2-500 ops; numeric OR text; max 500 mutations; unique coords',
                        'mixedFact': '3-100 ops; numeric+text+detail; max 500 mutations; reject cross-type/repeat-detail; same-family chains',
                    },
                    'publication': '1 transaction + receipt/unit',
                    'unsupported': 'other multi-op units fail closed',
                }},
            _CURRENCY_TRANSLATION_INSPECT: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'coordinate': 'complete Entity Currency YTD fact POV',
                    'fromCurrencyMemberId': 'active Currency member ID',
                    'toCurrencyMemberId': 'active Currency member ID',
                    'rateKind': 'balance or flow',
                    'method': 'configured PVA or VAL for the rate kind'},
                'result': 'Unreviewed exact translation and period lineage; no publication',
                'operationalPublication':{
                    'function':'currency.translation.publish',
                    'boundary':'separate previewed durable publication with current source, rate, revision and authorization checks'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _NCI_ATTRIBUTION_INSPECT: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'resultKey': 'current translated Full result key',
                    'resultStateToken': 'opaque current translated Full result-state token',
                    'relationshipId': 'one direct Full child placement'},
                'result': 'Unreviewed candidate split from a stage-matched translated Full result, including IC-aware layers, with missing policy inputs; no posting',
                'operationalPublication':{
                    'function':'consolidation.nci.period.publish',
                    'boundary':'requires a separate active governed period policy, saved basis definition and current source pins'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _PERIOD_NCI_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'policyId':'current effective policy draft','effectiveOn':'selected period final date',
                    'selections':'complete elections, including periodNciAttribution=pro_rata_full_method and negativeBasisTreatment=allow_signed_attribution',
                    'expectedPolicyRevision':'current nonnegative revision','relationshipId':'unambiguous active direct placement',
                    'scenarioId':'active Scenario','yearId':'active Year','periodId':'configured Period',
                    'method':'Full','controlConfirmed':'true accountable caller confirmation',
                    'basisKind':'period_profit_ytd or net_assets_at_period_end','basisEligibilityConfirmed':'true caller confirmation, not machine certification',
                    'basisAmount':'exact signed Amount string','ownershipPercent':'exact POWN string'},
                'result':'DraftUnreviewed exact candidate NCI/owner split and calendar/ownership lineage; YTD requires complete contiguous fiscal periods, constant POWN and policy coverage; no operational source eligibility, approval or posting',
                'operationalPublication':{
                    'function':'consolidation.nci.period.publish',
                    'boundary':'requires separate approved policy governance, owner-declared basis definition and current operational source'},
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _ACQUISITION_NCI_INSPECT: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'policyId': 'effective IFRS or US_GAAP draft ID',
                    'effectiveOn': 'acquisition date, ISO format',
                    'selections': 'complete draft choices including nciAcquisitionMeasurement',
                    'expectedPolicyRevision': 'current policy revision',
                    'acquisitionType': 'single_step',
                    'nciInstrumentClass': 'present_ownership_proportionate_liquidation',
                    'controlConfirmed': 'literal true after independent control assessment',
                    'relationshipId': 'active direct Entity placement with recorded POWN',
                    'scenarioId': 'active ownership Scenario member',
                    'yearId': 'active ownership Year member',
                    'periodId': 'active ownership Period member with a configured fiscal range containing effectiveOn',
                    'ownershipPercent': 'exact decimal string matching recorded POWN above 0 through 100',
                    'considerationTransferred': 'nonnegative exact amount string',
                    'identifiableNetAssets': 'nonnegative exact amount string',
                    'nciFairValue': 'exact amount string for fair_value; null for proportionate_share'},
                'result': 'unreviewed acquisition-date NCI/goodwill candidate, family choice check, recorded ownership and fiscal-period lineage, pinned draft digests; no posting',
                'operationalPublication':{
                    'function':'consolidation.acquisition.journal.publish',
                    'boundary':'separate active approved policy variant and current raw operational sources; candidate amounts are not posted inputs'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _ACQUISITION_STEP_INSPECT: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'policyId': 'effective IFRS or US_GAAP draft ID',
                    'effectiveOn': 'acquisition date, ISO format',
                    'selections': 'complete draft election map',
                    'expectedPolicyRevision': 'current policy revision',
                    'relationshipId': 'active direct Entity placement',
                    'scenarioId': 'active ownership Scenario member',
                    'yearId': 'active ownership Year member',
                    'periodId': 'fiscal period containing effectiveOn',
                    'priorControlConfirmed': 'literal false',
                    'controlConfirmed': 'literal true',
                    'priorInterestPercent': 'previously held positive interest',
                    'additionalInterestPercent': 'new positive interest',
                    'finalOwnershipPercent': 'literal decimal 100 matching POWN',
                    'priorInterestCarryingAmount': 'nonnegative amount',
                    'priorInterestFairValue': 'nonnegative amount',
                    'considerationTransferred': 'nonnegative amount',
                    'identifiableNetAssets': 'nonnegative amount'},
                'result': 'unreviewed 100%-ownership step-acquisition goodwill and remeasurement candidate with caller-declared prior interest/control/valuation; no posting',
                'operationalPublication':{
                    'function':'consolidation.acquisition.journal.publish',
                    'boundary':'separate active approved policy variant and current raw operational sources; nonzero prior OCI uses an explicit user-authored expression and calculation-journal route'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _POLICY_ACQUISITION_CASES_EVALUATE: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'cases': '1–20 distinct caseId entries with candidate, expected outcome and sourceRefs; optional captured valueLocator verification requires Administrator content access'},
                'result': 'single-transaction exact comparison, optional deterministic captured-source value checks, lineage and digest; UnreviewedTechnicalFixture, no accounting publication',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _POLICY_ACQUISITION_CASES_RECORD: {
                'mode': 'atomic_policy_write', 'permission': 'admin',
                'arguments': {
                    'cases': '1–20 exact acquisition case definitions; all expectations must match',
                    'expectedPolicyRevision': 'current policy revision',
                    'expectedCommitRevision': 'current application commit revision'},
                'result': 'immutable unreviewed technical case bundle and receipt; no accounting execution authorization',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _POLICY_ACQUISITION_CASES_READ: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'operationId': 'case-bundle record operation ID'},
                'result': 'immutable case evidence, actor and conservative currentness; no accounting execution authorization',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _POLICY_ACQUISITION_REVIEW_RECORD: {
                'mode': 'atomic_policy_write', 'permission': 'admin',
                'arguments': {
                    'bundleOperationId': 'current immutable technical case bundle',
                    'expectedEvaluationDigest': 'exact bundle digest',
                    'expectedPolicyRevision': 'current policy revision',
                    'expectedCommitRevision': 'current commit revision',
                    'decision': 'Attest or Reject',
                    'sourceValuesChecked': 'literal Boolean reviewer assertion',
                    'controlAssessmentChecked': 'literal Boolean reviewer assertion',
                    'qualificationRef': 'reviewer-supplied qualification reference; not system-verified',
                    'reviewEvidenceRefs': '1–10 reviewer-supplied evidence references',
                    'rationale': '10–2000 character reviewer rationale'},
                'result': 'immutable distinct-identity reviewer attestation or rejection; neither activates accounting',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _POLICY_ACQUISITION_REVIEW_READ: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'bundleOperationId': 'reviewed case bundle ID'},
                'result': 'immutable reviewer/source identities, claims, references and currentness; no accounting authorization',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _POLICY_ACQUISITION_EVIDENCE_INSPECT: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'bundleOperationId': 'immutable case bundle ID'},
                'result': 'revision-pinned source coverage and review blockers; this read has no effects and reports whether the separate governed review, approval, activation, resolution and publication stages are eligible',
                'workflowRoute': {
                    'stages': [
                        _POLICY_ACQUISITION_REVIEW_RECORD,
                        _POLICY_APPROVE,
                        _POLICY_ACTIVATE,
                        _POLICY_ACTIVATION_RESOLVE,
                        'consolidation.acquisition.journal.publish'],
                    'boundary': 'each stage requires its own current revisions, exact immutable evidence pins and applicable distinct identity; only the final previewed durable publisher may create accounting effects'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _POLICY_APPROVE:{
                'mode':'atomic_policy_write','permission':'workspace_admin',
                'arguments':{'bundleOperationId':'current reviewed bundle',
                    'expectedReviewOperationId':'exact independent review',
                    'expectedEvaluationDigest':'exact bundle digest',
                    'expectedPolicyRevision':'current policy revision',
                    'expectedCommitRevision':'current commit revision',
                    'sourceProvenanceConfirmed':'literal true owner assessment',
                    'reviewerQualificationConfirmed':'literal true owner assessment',
                    'accountingJudgmentConfirmed':'literal true owner assessment',
                    'approvalEvidenceArtifactIds':'1–10 captured supporting artifacts',
                    'rationale':'explicit approval rationale'},
                'result':'distinct workspace-administrator approval of exact evidence; activation remains separate',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short'},
            _POLICY_APPROVAL_READ:{
                'mode':'read_only','permission':'read',
                'arguments':{'approvalId':'immutable approval operation ID'},
                'result':'exact policy/election and review/support pins with accountable owner assertions; no activation',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short'},
            _POLICY_ACTIVATE:{
                'mode':'atomic_policy_write','permission':'workspace_admin',
                'arguments':{'approvalId':'immutable owner approval',
                    'expectedApprovalDigest':'exact approval manifest digest',
                    'policyBindingDigest':'one approved function/core/election binding',
                    'effectiveFrom':'explicit operational start date',
                    'effectiveBefore':'exclusive operational end date within draft',
                    'expectedActiveEventId':'current variant event ID or empty for first activation',
                    'expectedPolicyRevision':'current policy revision',
                    'expectedCommitRevision':'current commit revision',
                    'reason':'explicit activation reason'},
                'result':'immutable activation event and guarded variant pointer; posting remains separate',
                'previewRequired':False,'idempotencyRequired':True,'workClass':'short'},
            _POLICY_WITHDRAW:{
                'mode':'atomic_policy_write','permission':'workspace_admin',
                'arguments':{'variantKey':'scoped functional policy variant',
                    'expectedActivationId':'exact active activation ID',
                    'expectedActiveEventId':'exact current event ID',
                    'expectedPolicyRevision':'current policy revision',
                    'expectedCommitRevision':'current commit revision',
                    'reason':'explicit withdrawal reason'},
                'result':'immutable withdrawal and policy revision fence; history retained',
                'previewRequired':False,'idempotencyRequired':True,'workClass':'short'},
            _POLICY_ACTIVATION_READ:{
                'mode':'read_only','permission':'read',
                'arguments':{'eventId':'activation or withdrawal event ID'},
                'result':'immutable event and current pointer status',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _POLICY_ACTIVATION_RESOLVE:{
                'mode':'read_only','permission':'read',
                'arguments':{'policyId':'approved policy ID','policyStateToken':'exact current opaque token',
                    'candidateFunction':'approved acquisition function',
                    'selections':'exact election map','effectiveOn':'operational date',
                    'expectedPolicyRevision':'current policy revision'},
                'result':'exact active governed variant and date-specific selection digest; this read has no effects and the separate consolidation.acquisition.journal.publish path may consume the resolved variant',
                'operationalPublication':{
                    'function':'consolidation.acquisition.journal.publish',
                    'boundary':'separate previewed durable publication requires the resolved active approved variant and current raw operational sources; policy candidates are not posting inputs'},
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _POLICY_ACTIVATION_CURRENT:{
                'mode':'read_only','permission':'read',
                'arguments':{'policyId':'policy ID','policyStateToken':'exact current opaque token',
                    'candidateFunction':'acquisition function','selections':'election map'},
                'result':'discover current event/status/revisions, including withdrawn or never-activated variants; use resolve for operational validation',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _POLICY_SOURCE_ARTIFACT_CAPTURE: {
                'mode': 'atomic_policy_write', 'permission': 'admin',
                'arguments': {
                    'sourceRef': 'claimed source URI or internal reference',
                    'sourceVersion': 'caller-declared source version',
                    'mediaType': 'bounded supported document media type',
                    'contentBase64': '1–4194304 original bytes encoded as base64',
                    'expectedSha256': 'lowercase SHA-256 of decoded bytes',
                    'clientPdfExtraction': 'optional client-produced bounded JSON extraction artifact for a PDF; retained as unreviewed until human attestation',
                    'expectedPolicyRevision': 'current policy revision',
                    'expectedCommitRevision': 'current commit revision'},
                'result': 'immutable received bytes and server-verified digest; external origin and accounting remain unverified',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'medium',
            },
            _POLICY_SOURCE_ARTIFACT_READ: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {'artifactId': 'captured artifact operation ID'},
                'result': 'immutable source metadata and digest, without content',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _POLICY_SOURCE_ARTIFACT_CONTENT_READ: {
                'mode': 'read_only', 'permission': 'admin',
                'arguments': {'artifactId': 'captured artifact operation ID'},
                'result': 'verified original received bytes as base64 for authorized review; origin not verified',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'medium',
            },
            _POLICY_SOURCE_ARTIFACT_CLIENT_PDF_PAGE_READ: {
                'mode':'read_only','permission':'admin',
                'arguments':{'artifactId':'captured PDF artifact ID',
                             'extractionArtifactId':'paired client extraction artifact ID',
                             'page':'one-based page number, 1–100'},
                'result':'bounded client-supplied page text/hash/extractor identity for human review; no server PDF parsing or source-truth claim',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'medium',
            },
            _IC_PAIR_INSPECT_FUNCTION: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'leftMembers': 'complete raw Entity/ICP/Account coordinate',
                    'rightMembers': 'complete reciprocal raw coordinate'},
                'result': 'Unreviewed raw and posted-journal-layer pair magnitudes/residuals with separate provenance; publication still uses raw matching',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _IC_RESIDUAL_RESOLUTION_FUNCTION: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed reciprocal pair, exact Currency, source change IDs, revision pins, chosen adjustment side and exact declared adjustment'},
                'result':'caller-directed exact mismatch-resolution candidate with counterparty lineage; no cause, policy, FX or posting inference',
                'executionRoute':{
                    'authoring':['rules.expression.save',
                        'rules.expression.activate'],
                    'calculation':'rules.expression.run',
                    'publication':'consolidation.journal.from_calculation.publish'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CASH_FLOW_RECONCILIATION_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed mapping version, exact Currency unit, complete source coordinates/change IDs and current metadata/data/policy pins'},
                'result':'exact opening + classified movements = closing reconciliation with source lineage; no publication or accounting-policy claim',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CASH_FLOW_PUBLICATION_INSPECT: {
                'mode':'read_only','permission':'rule_run',
                'arguments':{'definition':'versioned explicit Unreviewed cash-flow mapping with source, balance-generation, Currency/Period/View/grain, hierarchy and revision pins',
                             'ruleIds':'four published immutable mapping rules'},
                'result':'validated Operating/Investing/Financing/reconciliation calculated-generation plan; no effects',
                'operationalPublication':{
                    'function':'consolidation.cash_flow.publication.request',
                    'boundary':'separate previewed durable four-checkpoint sequence using the same inspected mapping and published rule versions'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CASH_FLOW_PUBLICATION_REQUEST: {
                'mode':'durable_sequence','permission':'rule_run',
                'arguments':{'definition':'same inspected cash-flow mapping',
                             'ruleIds':'four published immutable mapping rules'},
                'result':'durable sequence ID with four calculated-generation checkpoints',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'bounded_write',
            },
            _CASH_FLOW_PUBLICATION_READ: {
                'mode':'read','permission':'read',
                'arguments':{'sequenceId':'caller-owned durable cash-flow sequence'},
                'result':'calculated outputs and current source, balance-generation, context and output staleness',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _EQUITY_ROLLFORWARD_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed rollforward version, exact Currency unit, component opening/closing/movement coordinates and current revision/change pins'},
                'result':'exact opening + explicitly classified movements = closing per equity component with lineage; no publication or accounting-policy claim',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _EQUITY_CHAIN_INSPECT: {
                'mode':'read_only','permission':'rule_run',
                'arguments':{'definition':'bounded Unreviewed multi-period chain with certified prior-close, hierarchy and revision pins',
                             'ruleIds':'2–8 published expression rules in period order'},
                'optionalArguments':{'bindings':'per-rule exact parameter bindings'},
                'result':'validated atomic-period chain plan and dependencies; no effects',
                'operationalPublication':{
                    'function':'consolidation.equity.rollforward.chain.request',
                    'boundary':'separate previewed durable sequence using the same inspected chain, certified prior close and published rule versions'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _EQUITY_CHAIN_REQUEST: {
                'mode':'durable_sequence','permission':'rule_run',
                'arguments':{'definition':'same inspected multi-period chain',
                             'ruleIds':'2–8 published expression rules in period order'},
                'optionalArguments':{'bindings':'per-rule exact parameter bindings'},
                'result':'durable sequence ID with one calculated-generation checkpoint per period',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'bounded_write',
            },
            _EQUITY_CHAIN_READ: {
                'mode':'read','permission':'read',
                'arguments':{'sequenceId':'caller-owned durable chain sequence'},
                'result':'period checkpoints, current publication pointers and transitive stale status',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _INVENTORY_UNREALIZED_PROFIT_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed positive-magnitude inventory creation/release schedule with exact Currency, source change IDs, ratios and revision pins'},
                'result':'exact half-even-final-8 unrealized-profit creation/release candidate with lineage; no posting or accounting-policy claim',
                'operationalPublication':{
                    'function':'consolidation.inventory.unrealized_profit.request',
                    'boundary':'separate previewed durable calculated-generation publication with an active immutable schedule, explicit targets and current source pins'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _INVENTORY_UNREALIZED_REQUEST:{'mode':'durable_write','permission':'write',
                'arguments':{'definition':'exact inspected schedule','targetMembers':'explicit Opening/Creation/Release/Closing full-grain coordinates','resultKey':'publication key','expectedPublicationRevision':'exact pointer'},
                'result':'four-row typed-unit calculated generation; Unreviewed and non-certified',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'bounded_write'},
            _INVENTORY_UNREALIZED_READ:{'mode':'read','permission':'read',
                'arguments':{'resultKey':'published result key'},'result':'immutable publication receipt',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _FIXED_ASSET_UNREALIZED_PROFIT_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed positive-magnitude fixed-asset schedule with explicit depreciation/disposal ratios, exact Currency, source change IDs and revision pins'},
                'result':'exact half-even-step-8 creation, excess-depreciation adjustment and disposal-release candidates with lineage; no posting or accounting-policy claim',
                'executionRoute':{
                    'authoring':['rules.expression.save',
                        'rules.expression.activate'],
                    'calculation':'rules.expression.run',
                    'publication':'consolidation.journal.from_calculation.publish'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _DISPOSAL_MEASURE_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed loss-of-control disposal with exact ownership/calendar/numeric source pins, Currency and revisions'},
                'result':'exact full or partial-with-loss-of-control derecognition gain/loss candidate with lineage; no control assessment, valuation approval or posting',
                'executionRoute':{
                    'authoring':['rules.expression.save',
                        'rules.expression.activate'],
                    'calculation':'rules.expression.run',
                    'publication':'consolidation.journal.from_calculation.publish'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _RETAINED_CONTROL_DISPOSAL_INSPECT: {
                'mode':'read_only','permission':'read',
                'arguments':{'definition':'bounded Unreviewed partial disposal retaining control with exact ownership/calendar/numeric source pins, Currency and revisions'},
                'result':'exact parent-equity/NCI reattribution candidate with lineage and no gain/loss, control assessment, policy inference or posting',
                'executionRoute':{
                    'authoring':['rules.expression.save',
                        'rules.expression.activate'],
                    'calculation':'rules.expression.run',
                    'publication':'consolidation.journal.from_calculation.publish'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _IC_ELIMINATION_PREVIEW_FUNCTION: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'leftMembers': 'complete raw left Entity/ICP/Account POV',
                    'rightMembers': 'complete reciprocal raw POV',
                    'parentEntityId': 'one direct reporting parent Entity',
                    'leftRelationshipId': 'unique Full left placement',
                    'rightRelationshipId': 'unique Full right placement',
                    'scenarioId': 'active Scenario member',
                    'yearId': 'active Year member',
                    'periodId': 'active Period member',
                    'decisions': 'complete direct-scope Full/control decisions'},
                'result': 'Unreviewed matched source-offset candidate and visible residual; no posting',
                'operationalPublication':{
                    'function':'consolidation.ic.elimination.publish',
                    'boundary':'separate preview-bound atomic publication with exact source change IDs, revisions, matched magnitude and visible residual'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _IC_ELIMINATION_PUBLISH_FUNCTION: {
                'mode': 'atomic_adjustment', 'permission': 'admin',
                'arguments': {
                    'scope': 'same group and source pair as the preview',
                    'expectedRevisions': 'exact preview version vector',
                    'expectedSourceChangeIds': 'both source change IDs',
                    'expectedMatchedMagnitude': 'exact decimal string',
                    'expectedSignedResidual': 'exact decimal string'},
                'result': 'immutable parent-scoped unreviewed IC generation, two balanced lines and current pointer',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _IC_ELIMINATION_READ_FUNCTION: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'parentEntityId': 'current IC pair parent Entity',
                    'pairKey': 'current IC pair key'},
                'result': 'current state token, lines, residual, status and source freshness',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _IC_ELIMINATION_WITHDRAW_FUNCTION: {
                'mode': 'atomic_adjustment', 'permission': 'admin',
                'arguments': {
                    'parentEntityId': 'current IC pair parent Entity',
                    'pairKey': 'current IC pair key',
                    'resultStateToken': 'exact current IC state token',
                    'expectedDataRevision': 'current application data revision',
                    'expectedCommitRevision': 'current application commit revision'},
                'result': 'current withdrawn state with no offset lines and unchanged raw facts; not a journal reversal',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _IC_ADJUSTED_BALANCE_READ_FUNCTION: {
                'mode': 'read_only', 'permission': 'read',
                'arguments': {
                    'parentEntityId': 'one direct reporting parent Entity',
                    'members': 'complete active raw source coordinate'},
                'result': 'current unreviewed raw-based IC offset, separate posted-journal adjustment and layered amount; Value models require configured Entity Currency/YTD stage; stale generations rejected',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _CURRENCY_TRANSLATION_PUBLISH: {
                'mode': 'durable_job', 'permission': 'write',
                'arguments': {
                    'coordinate': 'complete own-entity Entity Currency YTD POV; never includes descendants',
                    'sourceLayer':'optional explicit acquisition layer with optional manual/IC; distinct own-source stage; omitted retains raw behavior',
                    'icParentEntityId':'required only for IC modes: direct consolidation parent for leaf, or own Entity for own-parent input',
                    'fromCurrencyMemberId': 'Entity default Currency ID',
                    'toCurrencyMemberId': 'active target Currency ID',
                    'rateKind': 'AccountType-derived balance or flow',
                    'method': 'configured PVA or VAL',
                    'targetValueMemberId': 'Value member named for target Currency',
                    'resultKey': '8–128 safe characters'},
                'result': 'Unreviewed translated calculation generation',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'medium',
            },
            _CALCULATION_TRANSLATION_PUBLISH: {
                'mode': 'durable_job', 'permission': 'write',
                'arguments': {
                    'sourceMembers': 'complete lower Full Value-stage POV',
                    'sourceLayer': 'optional translated_full (default), existing IC modes, or explicit raw_plus_acquisition_journal with optional manual_journal and/or ic_elimination before the acquisition_journal suffix',
                    'sourceBasis': 'optional translated_full for a translated lower Full, or local_full for an IC/acquisition-aware local Full (default inferred from sourceLayer)',
                    'fromCurrencyMemberId': 'lower Entity default Currency ID',
                    'toCurrencyMemberId': 'active target Currency ID',
                    'rateKind': 'AccountType-derived balance or flow',
                    'method': 'configured PVA or VAL',
                    'targetValueMemberId': 'Value member named for target Currency',
                    'periodPins': 'current same-stage lower Full generations for selected fiscal periods',
                    'resultKey': '8–128 safe characters'},
                'result': 'Unreviewed exact-rational translated lower Full generation with explicit source stage and pinned period lineage',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'medium',
            },
            _TRANSLATED_FULL_FUNCTION: {
                'mode': 'durable_job', 'permission': 'write',
                'arguments': {
                    'parentMembers': 'complete target parent fact POV',
                    'sourceLayer': 'optional translated_full (default), existing IC modes, or explicit acquisition layer',
                    'ownSourcePolicy':'optional explicit_layered_fx_v1 with an acquisition layer: permits stage-matched own-parent and leaf FX pins; otherwise retains prior layered guards',
                    'targetCurrencyMemberId': 'parent default Currency ID',
                    'scenarioId': 'active Scenario member ID',
                    'yearId': 'active Year member ID',
                    'periodId': 'active Period member ID',
                    'decisions': 'every direct Full placement with pinned leaf FX, lower Full, or translated lower Full generation',
                    'parentTranslation': 'pinned parent identity translation or null',
                    'resultKey': '8–128 safe characters'},
                'result': 'Unreviewed pre-NCI translated Full parent generation',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'medium',
            },
            'metadata.dimension.create': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'stable ID', 'name': 'display name',
                              'modelRole': 'known role or null',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'shortDescription': 'text, at most 500 characters',
                    'detailedDescription': 'text, at most 10000 characters'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.create': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active dimension ID',
                              'memberId': 'stable ID', 'name': 'display name',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'shortDescription': 'text, at most 500 characters',
                    'detailedDescription': 'text, at most 10000 characters'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.dimension.rename': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'name': 'new display name',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.rename': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'memberId': 'active stable ID',
                              'name': 'new display name',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.dimension.describe': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'shortDescription': 'text, at most 500 characters',
                              'detailedDescription': 'text, at most 10000 characters',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'updated semantic descriptions, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.describe': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'memberId': 'active stable ID',
                              'shortDescription': 'text, at most 500 characters',
                              'detailedDescription': 'text, at most 10000 characters',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'updated semantic descriptions, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.security-tags.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'memberId': 'active stable ID',
                              'readTags': 'unique exact tags, each 1–20 characters',
                              'writeTags': 'unique exact tags, each 1–20 characters',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'inert member security inputs, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.security-string.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'memberId': 'active stable ID',
                              'securityString': 'canonical read=...;write=... using known dimension tags',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'normalized member security arrays, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.dimension.security-string.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable ID',
                              'securityString': 'canonical read=...;write=... using known dimension tags',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'normalized dimension security arrays, metadata and security revisions, and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.relationship.security-string.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'relationshipId': 'active stable ID',
                              'securityString': 'canonical read=...;write=... using tags from the relationship dimension',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'normalized relationship security arrays, metadata and security revisions, and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.security-tag.create': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable dimension ID',
                              'tagId': 'stable exact tag ID, 1–20 characters',
                              'displayName': 'display name, 1–200 characters',
                              'shortDescription': 'text, at most 500 characters',
                              'semanticDescription': 'text, at most 10000 characters',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'catalogue row, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.security-tag.update': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable dimension ID',
                              'tagId': 'existing stable exact tag ID',
                              'displayName': 'display name, 1–200 characters',
                              'shortDescription': 'text, at most 500 characters',
                              'semanticDescription': 'text, at most 10000 characters',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'updated catalogue row, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.security-tag.status.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active stable dimension ID',
                              'tagId': 'existing stable exact tag ID',
                              'status': 'Active or Inactive',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'catalogue status, metadata revision and atomic receipt; in-use inactivation is rejected',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.member.status.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'stable dimension ID',
                              'memberId': 'stable member ID',
                              'status': 'Active or Inactive',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt; inactivation rejects live references',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.dimension.status.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'stable dimension ID',
                    'status': 'Active or Inactive',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt; inactivation requires no active members or live dependencies',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.dimension.delete': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'inactive stable ID with no dependencies',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'dimension removed, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.relationship.create': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'dimensionId': 'active dimension ID',
                              'relationshipId': 'stable ID',
                              'parentMemberId': 'active parent ID',
                              'childMemberId': 'active child ID',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'hierarchyId': 'named hierarchy ID; omission resolves only default',
                    'status': 'Active or Inactive; defaults to Active',
                    'name': 'display name; defaults to stable ID',
                    'shortDescription': 'text, at most 500 characters',
                    'detailedDescription': 'semantic text, at most 10000 characters'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.relationship.rename': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'relationshipId': 'active stable relationship ID',
                              'name': 'new display name',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.relationship.describe': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'relationshipId': 'active stable relationship ID',
                              'shortDescription': 'text, at most 500 characters',
                              'detailedDescription': 'text, at most 10000 characters',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'updated semantic descriptions, metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.relationship.status.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {'relationshipId': 'stable relationship ID',
                              'status': 'Active or Inactive',
                              'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'new metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'metadata.relationship.aggregation-operator.set': {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'relationshipId': 'active stable relationship ID',
                    'aggregationOperatorOverride': ('null, Add, Subtract, '
                        'Ignore, NeverAggregate or Formula'),
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'metadata revision and atomic receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            **named_hierarchy_catalog(),
            'metadata.hierarchy.build': {
                'mode':'atomic_write','permission':'admin',
                'arguments':{'dimensionId':'active dimension stable ID',
                             'expectedMetadataRevision':'nonnegative integer'},
                'optionalArguments': {
                    'membershipSemantics': 'unique_member or placement',
                    'hierarchyId': 'named hierarchy ID; omission resolves only default',
                    'expectedStateToken': ('required opaque current token when '
                        'replacing an existing build; omit only for first build')},
                'result':'one current closure, fresh state token and atomic receipt',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _ATTRIBUTE_DEFINITION_CREATE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'scope': 'Dimension, Member or Relationship',
                    'attributeId': 'immutable stable ID',
                    'defaultName': 'immutable default name',
                    'displayName': 'mutable display name',
                    'shortDescription': 'text, at most 500 characters',
                    'semanticDescription': 'text, at most 10000 characters',
                    'valueType': 'Text, Decimal, Boolean or MemberReference',
                    'validationConstraints': 'bounded typed constraint object',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope'},
                'result': 'current state token, metadata revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _ATTRIBUTE_DEFINITION_UPDATE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'scope': 'Dimension, Member or Relationship',
                    'attributeId': 'immutable stable ID',
                    'displayName': 'mutable display name',
                    'shortDescription': 'text, at most 500 characters',
                    'semanticDescription': 'text, at most 10000 characters',
                    'valueType': 'Text, Decimal, Boolean or MemberReference',
                    'validationConstraints': 'bounded typed constraint object',
                    'expectedStateToken': 'exact current opaque state token',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope'},
                'result': 'new current state token, metadata revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _ATTRIBUTE_DEFINITION_STATUS: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'scope': 'Dimension, Member or Relationship',
                    'attributeId': 'immutable stable ID',
                    'status': 'Active or Inactive',
                    'expectedStateToken': 'exact current opaque state token',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope'},
                'result': 'new current state token, metadata revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _ATTRIBUTE_VALUE_SET: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'scope': 'Dimension, Member or Relationship',
                    'attributeId': 'active stable definition ID',
                    'objectId': 'dimension, member or relationship stable ID',
                    'value': 'typed value or null to clear',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope'},
                'result': 'metadata revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _ATTRIBUTE_VALUES_REPLACE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'scope': 'Member',
                    'dimensionId': 'stable dimension ID',
                    'attributeIds': (
                        'complete declared active attribute-ID set to replace'),
                    'rows': (
                        'member rows with objectId and typed values; omitted '
                        'declared values are cleared'),
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {},
                'result': (
                    'content digest, one metadata revision and one receipt'),
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _ATTRIBUTE_DEFINITION_LIST: {
                'mode': 'read', 'permission': 'read',
                'arguments': {'scope': 'Dimension, Member or Relationship'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope',
                    'status': 'Active or Inactive',
                    'query': 'bounded ID, display-name or semantic search',
                    'limit': '1–500',
                    'afterAttributeId': 'exclusive stable-ID cursor'},
                'result': 'revision-pinned definition page',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _ATTRIBUTE_DEFINITION_USAGE: {
                'mode': 'read', 'permission': 'read',
                'arguments': {
                    'scope': 'Dimension, Member or Relationship',
                    'attributeId': 'stable definition ID'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope'},
                'result': 'definition, exact value count and bounded object sample',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _ATTRIBUTE_VALUE_READ: {
                'mode': 'read', 'permission': 'read',
                'arguments': {
                    'scope': 'Dimension, Member or Relationship',
                    'attributeId': 'stable definition ID',
                    'objectId': 'dimension, member or relationship stable ID'},
                'optionalArguments': {
                    'dimensionId': 'required for Member or Relationship scope'},
                'result': 'definition, presence and typed value at one object',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _SEMANTIC_CREATE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'dimensionId': 'active dimension ID',
                    'slot': 'member Custom01–Custom30 slot number',
                    'displayName': 'unique display name, at most 200 characters',
                    'semanticDefinition': 'required meaning, at most 2000 characters',
                    'populationGuidance': 'text, at most 2000 characters',
                    'restrictions': 'text, at most 2000 characters',
                    'valueType': 'Text, Decimal, Boolean or MemberReference',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'allowedValues': 'at most 100 distinct Text values',
                    'referenceDimensionId': 'required for MemberReference'},
                'result': 'typed semantic definition, revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _SEMANTIC_UPDATE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'dimensionId': 'active dimension ID',
                    'slot': 'defined Member Custom01–Custom30 slot number',
                    'displayName': 'unique display name, at most 200 characters',
                    'semanticDefinition': 'required meaning, at most 2000 characters',
                    'populationGuidance': 'text, at most 2000 characters',
                    'restrictions': 'text, at most 2000 characters',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'updated description, revision and receipt; value type is immutable',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _SEMANTIC_SET: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'dimensionId': 'active dimension ID',
                    'memberId': 'active member ID',
                    'slot': 'defined semantic slot number',
                    'value': 'typed value or null to clear; Decimal is a string',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'member attribute, revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _SEMANTIC_LIST: {
                'mode': 'read', 'permission': 'read',
                'arguments': {'dimensionId': 'active dimension ID'},
                'result': 'typed semantic definitions and metadata revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _SEMANTIC_READ: {
                'mode': 'read', 'permission': 'read',
                'arguments': {'dimensionId': 'active dimension ID',
                              'memberId': 'active member ID'},
                'result': 'member attributes, definitions and metadata revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _REL_SEMANTIC_CREATE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'dimensionId': 'active dimension ID',
                    'slot': 'relationship Custom01–Custom20 slot number',
                    'displayName': 'unique display name, at most 200 characters',
                    'semanticDefinition': 'required meaning, at most 2000 characters',
                    'populationGuidance': 'text, at most 2000 characters',
                    'restrictions': 'text, at most 2000 characters',
                    'valueType': 'Text, Decimal, Boolean or MemberReference',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'optionalArguments': {
                    'allowedValues': 'at most 100 distinct Text values',
                    'referenceDimensionId': 'required for MemberReference'},
                'result': 'typed relationship semantic definition, revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _REL_SEMANTIC_UPDATE: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'dimensionId': 'active dimension ID',
                    'slot': 'defined Relationship Custom01–Custom20 slot number',
                    'displayName': 'unique display name, at most 200 characters',
                    'semanticDefinition': 'required meaning, at most 2000 characters',
                    'populationGuidance': 'text, at most 2000 characters',
                    'restrictions': 'text, at most 2000 characters',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'updated description, revision and receipt; value type is immutable',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _REL_SEMANTIC_SET: {
                'mode': 'atomic_write', 'permission': 'admin',
                'arguments': {
                    'dimensionId': 'active dimension ID',
                    'relationshipId': 'active relationship ID',
                    'slot': 'defined semantic slot number',
                    'value': 'typed value or null to clear; Decimal is a string',
                    'expectedMetadataRevision': 'nonnegative integer'},
                'result': 'relationship attribute, revision and receipt',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _REL_SEMANTIC_LIST: {
                'mode': 'read', 'permission': 'read',
                'arguments': {'dimensionId': 'active dimension ID'},
                'result': 'typed relationship semantic definitions and metadata revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _REL_SEMANTIC_READ: {
                'mode': 'read', 'permission': 'read',
                'arguments': {'dimensionId': 'active dimension ID',
                              'relationshipId': 'active relationship ID'},
                'result': 'relationship attributes, endpoints, definitions and revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.dimension.resolve': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'reference': 'stable ID or unique name'},
                'result': 'resolved active dimension',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.dimension.list': {
                'mode': 'read', 'permission': 'read', 'arguments': {},
                'optionalArguments': {
                    'limit': '1–500; defaults to 100',
                    'afterDimensionId': 'stable ID from prior page',
                    'expectedMetadataRevision': 'revision from prior page'},
                'result': 'bounded dimensions with descriptions, statuses and revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.member.resolve': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'dimension': 'stable ID or unique name',
                              'reference': 'stable ID or unique name'},
                'result': 'resolved active member including numericValueKind as numeric_value_kind',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.member.list': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'dimension': 'active dimension stable ID or unique name'},
                'optionalArguments': {
                    'limit': '1–500; defaults to 100',
                    'afterMemberId': 'stable ID from prior page',
                    'expectedMetadataRevision': 'revision from prior page'},
                'result': ('bounded members with descriptions, statuses, '
                           'numeric_value_kind, exact custom values and revision'),
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.security-tag.list': {
                'mode': 'read', 'permission': 'read',
                'arguments': {
                    'dimension': 'active dimension stable ID or unique name'},
                'optionalArguments': {
                    'status': 'Active or Inactive; omission returns both',
                    'limit': '1–500; defaults to 100',
                    'afterTagId': 'stable tag ID from prior page',
                    'expectedMetadataRevision': 'revision from prior page'},
                'result': 'bounded dimension tag catalogue with descriptions, status and revision',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'metadata.relationship.list': {
                'mode': 'read', 'permission': 'read',
                'arguments': {
                    'dimension': 'active dimension stable ID or unique name'},
                'optionalArguments': {
                    'hierarchyId': 'named hierarchy; omission resolves default only',
                    'status': 'Active or Inactive; omission returns both',
                    'limit': '1–500; defaults to 100',
                    'cursor': 'opaque signed sole continuation argument'},
                'result': ('bounded current relationship records with endpoints, '
                           'semantic fields, exact custom values and revision; '
                           'does not assert membership in a hierarchy version'),
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'facts.numeric.sequence': {
                'mode': 'durable_write', 'permission': 'write',
                'effect': 'atomic ordered numeric statements',
                'arguments': {'statements': '1–500 ordered set/add/clear statements at full coordinates; first touch requires expectedChangeId; later touches omit it; values are AmountLiteral, earlier present StatementValue or NumericExpression',
                    'rounding': 'omit for original literal/reference v1; half_even_8 required for v2 typed amount/ratio arithmetic, comparisons, If, CurrentAmount/Present and StatementAmount/Present'},
                'workBound': '500 statements/coordinates; expression limits: 64 nodes, depth 12, 2,048 program nodes; exact NUMERIC(28,8)',
                'preview': 'signed revision/CAS snapshot with intermediate presence/value',
                'idempotency': 'same identity/scope/key/program returns its job',
                'job': 'durable queue; one atomic statement/event receipt',
                'result': 'statementCount, changedCount of distinct targets, committedRevision',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short'},
            'facts.numeric.batch': {
                'mode': 'durable_write', 'permission': 'write',
                'arguments': {'mutations': '1–500 typed Set/Add/Clear rows'},
                'result': 'jobId then atomic receipt',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'facts.text.batch': {
                'mode': 'durable_write', 'permission': 'write',
                'arguments': {'mutations': '1–500 typed Set/Clear TextLiteral rows'},
                'result': 'jobId then atomic receipt',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'facts.line-detail.replace': {
                'mode': 'durable_write', 'permission': 'write',
                'arguments': {'coordinate': 'one full stable-ID coordinate',
                    'items': '0–500 exact description/amount rows',
                    'expectedCellChangeId': 'current numeric total CAS identity',
                    'expectedDetailChangeId': 'current supporting-detail CAS identity'},
                'result': 'jobId then one atomic detail-plus-total receipt',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'facts.cube.scan': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'members': 'stable-ID equality filters',
                              'limit': '1–500',
                              'cursor': 'opaque signed continuation',
                              'snapshotRevision': 'optional committed revision on the first page',
                              'includeMissing': 'optional boolean, retain raw event tombstones',
                              'includeZero': 'optional boolean, retain present numeric zero'},
                'result': 'authorization-complete snapshot-pinned raw numeric/text page with explicit missing/zero inclusion; fails closed if more than 10,000 raw candidates are required to prove one visible page',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'bounded_read',
            },
            _LAYER_REPORT_SCAN: {
                'mode': 'read', 'permission': 'read',
                'arguments': {
                    'members': 'optional stable-ID equality filters',
                    'snapshotRevision': 'optional committed raw/journal snapshot',
                    'resultKey': 'one current untyped calculated publication',
                    'resultStateToken': 'required current calculated-result state token',
                    'limit': '1–500',
                    'cursor': 'opaque signed complete continuation'},
                'result': 'separate raw, manualJournal, adjusted and current-state-pinned calculated layers; no inferred final balance',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'facts.export.page': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'members': 'stable-ID equality filters',
                              'limit': '1–50 typed rows',
                              'cursor': 'opaque signed continuation, omit members and snapshotRevision when supplied',
                              'snapshotRevision': 'optional committed revision'},
                'result': 'snapshot-pinned AmountLiteral/TextLiteral/LineDetailLiteral source rows',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _ADJUSTED_SCAN_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'members':'stable-ID equality filters',
                             'limit':'1–500',
                             'cursor':'opaque signed continuation',
                             'snapshotRevision':'optional committed revision'},
                'result':'paged raw numeric plus manual-journal adjustments',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            'facts.numeric.scale': {
                'mode': 'durable_calculation', 'permission': 'write',
                'arguments': {'sourceMembers': 'stable-ID equality filters',
                              'factor': 'exact RatioLiteral',
                              'resultKey': 'named output publication'},
                'result': 'current result with opaque state token and atomic replacement',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            _EXPRESSION_FUNCTION: {
                'mode': 'durable_calculation', 'permission': 'write',
                'arguments': {'resultKey': 'stable named current result'},
                'optionalArguments': {
                    'sourceMembers': 'stable-ID equality filters for scalar profiles; required complete full-coordinate anchor for apportionment; sourceDomain and currency member-set profiles use their own declared source grain',
                    'expression': 'bounded typed arithmetic tree: SourceAmount, SourceValue(memberOverrides, measureDimensionId, valueType amount or ratio matching active member numericValueKind) for present raw driver cells, PublishedAmount or PublishedRatio(resultKey, optional memberOverrides), RelationOperand or RelationValue only with applicabilityDomain, AmountLiteral, RatioLiteral, Add, Subtract, Multiply, Divide(nonzero ratio or amount/amount deriving ratio), Compare(same unit; eq/ne/lt/le/gt/ge), If(boolean test, same-unit branches); dynamic division is not allowed inside Compare, zero denominators fail preview and worker publication, and lookup cells are required at each selected full coordinate',
                    'applicabilityDomain': 'v39 alternative source grain: exact current active sparse business relation pin (relationId, relationStateToken and relationDigest), one anchor member column for every active dimension, optional target overrides, named amount/ratio operand coordinate overrides with explicit error/skip missingness, typed scalar relation values, exclusive targets and maxRows; it contains no batches, partitions, chunks, leases or worker controls',
                    'apportionment': 'v36 alternative to expression: one complete sourceMembers anchor, version 1, explicit power-of-ten quantum 1 through 0.00000001, ordered tieDimensions and Amount control; 1–8 components each with stable componentId, Amount expression, sourceRounding exact or half_even, and sparse targets with memberOverrides and positive Ratio weight; ComponentAmount is local to an acyclic component dependency graph and references the signed quantized component input; <=64 distinct live inputs, <=500 distinct targets, <=2000 contributions and <=8 SourceValue lookups per expression; current authorization, exact conservation and deterministic largest remainder; result layer only',
                    'sourceMemberSets': 'bounded explicit stable member IDs on selected source dimensions; combines with sourceMembers and is sealed into the compiler plan without caller cell enumeration',
                    'SourceTextPredicate': "v28 boolean expression node allowed as If.test: exact eq/ne against one present raw text cell selected by memberOverrides, UTF-8 text length <=32768 and missingPolicy='error'; present empty text remains distinct from missing; numeric and text raw lookups share an eight-lookup bound",
                    'targetMembers': 'active target member IDs on declared source axes, distinct from selected source members; scalar SDK remaps may change all fixed sourceMembers axes (at most 32); member-set fanout bounds are unchanged and result coordinates are materialized in the effect transaction',
                    'resultUnit': "exact {'type':'Ratio','scale':12} required only when the expression result is Ratio; target Measure member must declare numericValueKind ratio",
                    'reduceSelection': "v26 alternative to enumerated reduceMemberSet: exactly one non-Currency dimension with kind Children, Descendants or Leaves; membershipSemantics UniqueMember; rootMemberId; distinct targetMemberId; measures exactly ['SumAmount','CountPresent'] or ['AverageAmount','CountPresent']; trusted preview resolves and seals the current hierarchy state and at most 100 active unique members and therefore at most 100 present full-grain sources",
                    'reduceSelections': "v27 alternative with exactly two distinct non-Currency dimensions; each selector uses the current hierarchy with Children/Descendants/Leaves, UniqueMember, root and target; measures are SumAmount+CountPresent or AverageAmount+CountPresent; trusted preview seals <=100 members per axis and <=500 present cartesian sources",
                    'contextDependencies': "v32 bounded OwnershipValue and CalendarPeriod current-source pins, resolved and sealed by the fixed core; requires contextAssertions",
                    'contextAssertions': "v32 bounded boolean audit claims whose assurance must remain CallerDeclaredUnverified; assertions never select policy, authorize effects, or alter arithmetic"},
                'sealedEvidence': 'v26 preview returns the exact admitted sealedProgram, explicit hierarchy and metadata pins, sorted resolved members, membership and fact-layout digests, distinct present-source count and grouped-output count; complete fixed non-reduced grain permits exactly zero or one output intersection',
                'result': 'atomically replaced current exact Amount or scale-12 Ratio result with opaque result-state token/content digest, current published-input provenance and optional target coordinate mapping; hierarchy reductions expose selector context and CountPresent lineage and produce zero or one output intersection without caller cell enumeration',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'facts.calculation.read': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'resultKey': 'named output publication'},
                'result': 'current result-state token and bounded exact rows',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'facts.calculation.publication.list': {
                'mode': 'read', 'permission': 'read',
                'arguments': {'limit': 'optional 1–100',
                              'afterResultKey': 'optional stable keyset cursor'},
                'result': 'bounded current result-state catalogue',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            _CALCULATION_SCAN_FUNCTION: {
                'mode': 'read', 'permission': 'read',
                'arguments': {'resultKey': 'named output publication',
                              'members': 'stable-ID equality filters',
                              'limit': '1–500',
                              'cursor': 'opaque signed continuation',
                              'includeZero': 'optional boolean, retain present calculated zero'},
                'result': 'authorization-complete current result-state-pinned calculated page; fails closed if more than 10,000 candidates are required to prove one visible page',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'bounded_read',
            },
            'facts.planning.spread.equal': {
                'mode':'durable_calculation','permission':'write',
                'arguments':{'source':'one full-coordinate numeric input',
                             'targetDimension':'axis to rebind',
                             'targetMembers':'1–500 active stable IDs',
                             'resultKey':'named output publication'},
                'result':'immutable conserving planning generation',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _CALENDAR_SPREAD_FUNCTION: {
                'mode':'durable_calculation','permission':'write',
                'arguments':{'source':'one full-coordinate numeric input',
                             'yearId':'source Year member',
                             'firstOrdinal':'first mapped fiscal period',
                             'lastOrdinal':'last mapped fiscal period',
                             'resultKey':'stable named current result'},
                'result':'atomically replaced current conserving spread in fiscal period order with opaque state/content evidence',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _ALLOCATION_FUNCTION: {
                'mode':'durable_calculation','permission':'write',
                'arguments':{
                    'source':'one full-coordinate numeric source',
                    'basisTemplate':'full-coordinate numeric basis template',
                    'targetDimension':'axis to rebind',
                    'targetMembers':'1–500 active stable IDs',
                    'resultKey':'stable named current result',
                    'conservationScope':'sourceCoordinate',
                    'roundingPolicy':'largestRemainderStableMember'},
                'result':'atomically replaced current exactly conserved allocation with opaque state/content evidence and basis lineage',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _ROLLUP_FUNCTION: {
                'mode':'durable_calculation','permission':'write',
                'arguments':{'dimension':'hierarchy axis stable ID',
                             'parent':'active parent member stable ID',
                             'otherMembers':'one active member on every other axis',
                             'placementPaths':'optional 1–100 ordered relationship-ID paths, depth 1–32',
                             'resultKey':'stable named current result'},
                'result':'atomically replaced exact hierarchy leaf sum with current state/content evidence and copied per-source lineage',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _GROUP_FUNCTION: {
                'mode':'durable_calculation','permission':'write',
                'arguments':{'dimension':'one active cube axis stable ID',
                             'sourceMembers':'2–500 distinct active member IDs',
                             'targetMember':'distinct active member ID on that axis',
                             'otherMembers':'one active member on every other axis',
                             'resultKey':'stable named current result'},
                'result':'one atomically replaced exact numeric sum with current state/content evidence and copied per-source lineage',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _BULK_GROUP_FUNCTION: {
                'mode':'durable_calculation','permission':'write',
                'arguments':{'dimension':'one active cube axis stable ID',
                             'sourceMembers':'2–500 distinct active member IDs',
                             'targetMember':'distinct active member ID on that axis',
                             'otherMemberSets':'2–100 complete coordinate maps on all other axes; at most 10000 source cells',
                             'resultKey':'one stable named multi-row current result'},
                'result':'atomically replaced exact per-target sums with current state/content evidence and copied per-source lineage',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _OWNERSHIP_WRITE_FUNCTION: {
                'mode':'atomic_policy_input','permission':'admin',
                'arguments':{'relationshipId':'active direct Entity placement',
                             'scenarioId':'active Scenario member',
                             'yearId':'active Year member',
                             'periodId':'active Period member',
                             'account':'POWN, PCON, PCTRL, DOWN, Active, Method or Consol1–3',
                             'op':'Set or Clear',
                             'value':'exact AmountLiteral for Set',
                             'expectedChangeId':'current value change ID',
                             'expectedMetadataRevision':'nonnegative integer',
                             'expectedPolicyRevision':'nonnegative integer'},
                'result':'exact ownership input, policy revision and receipt',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _OWNERSHIP_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'relationshipId':'active direct Entity placement',
                             'scenarioId':'active Scenario member',
                             'yearId':'active Year member',
                             'periodId':'active Period member',
                             'account':'ownership input name'},
                'result':'explicit present/missing value and change ID',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _OWNERSHIP_SCOPE_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'parentEntityId':'active Entity member',
                             'scenarioId':'active Scenario member',
                             'yearId':'active Year member',
                             'periodId':'active Period member',
                             'afterRelationshipId':'optional keyset cursor',
                             'limit':'optional 1–200 direct relationships',
                             'expectedMetadataRevision':'optional page fence',
                             'expectedPolicyRevision':'optional page fence'},
                'result':'bounded direct placements and explicit ownership inputs with revisions; no method assessment',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CONSOLIDATION_ASSESS_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{
                    'parentEntityId':'active parent Entity stable ID',
                    'scenarioId':'active Scenario stable ID',
                    'yearId':'active Year stable ID',
                    'periodId':'active Period stable ID',
                    'decisions':'one explicit Full, Equity, Proportional or None method and control decision per direct relationship, up to 200'},
                'result':'period-sensitive structural issues and labeled ownership fallbacks; never an executable accounting policy',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CONSOLIDATION_METHOD_PREVIEW_FUNCTION: {
                'mode':'read','permission':'admin',
                'arguments':{
                    'parentEntityId':'active parent Entity stable ID',
                    'scenarioId':'active Scenario stable ID',
                    'yearId':'active Year stable ID',
                    'periodId':'active Period stable ID',
                    'effectiveOn':'ISO date inside the current policy applicability interval',
                    'policyId':'explicit policy ID',
                    'policyStateToken':'exact current policy state token',
                    'policyDigest':'exact effective policy digest',
                    'expectedMetadataRevision':'exact metadata fence',
                    'expectedPolicyRevision':'exact ownership/policy fence',
                    'expectedCommitRevision':'exact application fence',
                    'decisions':'one explicit method, control decision and five ownership change IDs per direct placement'},
                'result':'bounded exact period ownership/method assessment with lineage; invalid or structurally ineligible decisions are never substituted',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CONSOLIDATION_METHOD_COVERAGE: {
                'mode':'read_only','permission':'admin',
                'arguments':{
                    'methodPreviewProgram':'exact current explicit direct-scope method preview',
                    'expectedMethodPreviewDigest':'exact preview digest',
                    'publicationPins':'one current immutable Full, Equity or Proportional publication for every non-None placement',
                    'expectedDataRevision':'current raw-source revision'},
                'result':'Unreviewed structural placement coverage and statement-pack source handoff; no equations, aggregation, posting or certification',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _PROPORTIONAL_CONTRIBUTION_PREVIEW: {
                'mode':'read','permission':'admin',
                'arguments':{
                    'relationshipId':'one active direct proportional Entity placement',
                    'methodPreviewProgram':'complete pinned period method-preview program',
                    'expectedMethodPreviewDigest':'exact current method-preview digest',
                    'sourceMembers':'one complete present child numeric coordinate',
                    'targetMembers':'same grain with only child Entity changed to parent',
                    'sourceAmount':'exact current AmountLiteral decimal',
                    'sourceChangeId':'exact current source-cell identity',
                    'currencyDimensionId':'active Currency registry dimension',
                    'currencyMemberId':'shared child/parent functional currency',
                    'expectedDataRevision':'exact current data revision',
                    'rounding':'literal half-even-final-8'},
                'result':'Unreviewed no-effect Amount × period PCON candidate with exact ownership, source, currency, grain, policy and revision lineage; durable publication uses consolidation.proportional.contribution.publish.certified',
                'operationalPublication':{
                    'function':'consolidation.proportional.contribution.publish.certified',
                    'boundary':'separate preview-bound durable publication with the same relationship, method assessment, source identity, currency and revision pins'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _EQUITY_METHOD_CONTRIBUTION_PREVIEW: {
                'mode':'read','permission':'admin',
                'arguments':{
                    'relationshipId':'one active direct Equity-method Entity placement',
                    'methodPreviewProgram':'complete pinned period method-preview program',
                    'expectedMethodPreviewDigest':'exact current method-preview digest',
                    'openingCarryingValue':'present parent carrying Amount, members and change ID',
                    'postAcquisitionResult':'present child post-acquisition result Amount, members and change ID',
                    'postAcquisitionOci':'present child post-acquisition OCI Amount, members and change ID',
                    'targetMembers':'the pinned opening carrying-value coordinate',
                    'currencyDimensionId':'active Currency registry dimension',
                    'currencyMemberId':'shared child/parent functional currency',
                    'expectedDataRevision':'exact current data revision',
                    'rounding':'literal half-even-final-8'},
                'result':'Unreviewed no-effect Equity-method opening carrying value plus exact period POWN shares of explicit post-acquisition result and OCI, with source, ownership, currency, grain, policy and revision lineage; durable publication uses consolidation.equity.contribution.publish.certified',
                'operationalPublication':{
                    'function':'consolidation.equity.contribution.publish.certified',
                    'boundary':'separate preview-bound durable publication with the same method assessment, source identities, ownership, currency and revision pins'},
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _FULL_CONTRIBUTION_FUNCTION: {
                'mode':'durable_write','permission':'write',
                'arguments':{
                    'relationshipId':'active, uniquely placed direct Entity edge',
                    'scenarioId':'active Scenario stable ID',
                    'yearId':'active Year stable ID',
                    'periodId':'active Period stable ID',
                    'sourceMembers':'one complete numeric child coordinate with active leaf Account',
                    'resultKey':'8–128 safe characters',
                    'controlConfirmed':'literal true; explicit caller decision',
                    'currencyAlignedConfirmed':'literal true; caller confirms no FX is required'},
                'result':'one immutable pre-NCI, untranslated, uneliminated 100%-PCON contribution and receipt',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _TYPED_FULL_CONTRIBUTION_FUNCTION: {
                'mode':'durable_write','permission':'admin',
                'arguments':{
                    'relationshipId':'active, uniquely placed direct Entity edge',
                    'scenarioId':'active Scenario stable ID',
                    'yearId':'active Year stable ID',
                    'periodId':'active Period stable ID',
                    'sourceMembers':'one complete numeric child coordinate; Currency is not an axis',
                    'currencyDimensionId':'active Currency registry dimension',
                    'currencyMemberId':'aligned active child/parent functional Currency member',
                    'policyId':'exact applicable policy draft identity',
                    'policyStateToken':'exact current policy state token',
                    'policyDigest':'exact applicable policy draft digest',
                    'effectiveOn':'ISO date inside the policy applicability interval',
                    'resultKey':'8–128 safe characters',
                    'controlConfirmed':'literal true; explicit caller decision',
                    'currencyAlignedConfirmed':'literal true; fixed core revalidates alignment',
                    'sourceLayer':'optional v2 raw_plus_ic_elimination, or v3 raw_plus_manual_journal_plus_ic_elimination including every current immutable journal line at the exact source coordinate',
                    'icResultStateToken':'required exact current IC result state token for v2/v3; callers cannot select journal IDs or a journal subset'},
                'result':'one current typed-Currency pre-NCI Full contribution; v1 raw, v2 bound to current IC-adjusted state, or v3 bound to current journal-and-IC-adjusted state with ordered journal lineage',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _CERTIFIED_FULL_CONTRIBUTION: {
                'mode':'durable_write','permission':'write',
                'arguments':{'certificate':'sealed Full-only contribution input with exact method-preview, policy, ownership, source and publication pins'},
                'result':'durable exact Full contribution job and immutable receipt; Equity and Proportional use their dedicated contribution publishers',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _EQUITY_METHOD_PUBLICATION: {
                'mode':'durable_write','permission':'admin',
                'arguments':{'previewProgram':'exact Equity contribution preview program',
                    'expectedPreviewDigest':'current exact preview digest',
                    'resultKey':'8-128 safe calculated result identity',
                    'expectedPublicationRevision':'current pointer revision or zero'},
                'result':'durable Unreviewed calculated Equity carrying-value generation; no authoritative facts, dividends, impairment or FX',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'},
            _PROPORTIONAL_PUBLICATION: {
                'mode':'durable_write','permission':'admin',
                'arguments':{'previewProgram':'exact Proportional contribution preview program',
                    'expectedPreviewDigest':'current exact preview digest',
                    'resultKey':'8-128 safe calculated result identity',
                    'expectedPublicationRevision':'current pointer revision or zero'},
                'result':'durable Unreviewed calculated Proportional contribution; no authoritative facts, journal, elimination, NCI or FX',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'},
            _METHOD_TOTAL_PUBLICATION: {
                'mode':'durable_write','permission':'admin',
                'arguments':{'coverageProgram':'exact mixed-method coverage inspector program',
                    'expectedCoverageDigest':'current complete coverage digest',
                    'targetMembers':'one complete parent output coordinate; Currency is a typed output unit, not an axis',
                    'currencyDimensionId':'active Currency dimension',
                    'currencyMemberId':'single output Currency member',
                    'transformedAxes':'exactly ["Entity","Account"]; explicit placement child-to-parent and Account member remaps only, with no hierarchy traversal',
                    'resultKey':'8-128 safe calculated result identity',
                    'expectedTargetStateToken':'current opaque result-state token, or null when the result does not yet exist'},
                'result':'current exact Unreviewed calculated mixed-method parent total with opaque result-state evidence and explicit source-to-target Account lineage; no authoritative facts, hierarchy traversal or statement certification',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'},
            _FULL_AGGREGATE_FUNCTION: {
                'mode':'durable_write','permission':'write',
                'arguments':{
                    'parentMembers':'one complete active parent coordinate with leaf Account',
                    'decisions':'one explicit Full method and control confirmation for every active direct child Entity relationship, 1–200',
                    'scenarioId':'active Scenario stable ID',
                    'yearId':'active Year stable ID',
                    'periodId':'active Period stable ID',
                    'includeParentSource':'explicit Boolean; a present parent source must be included',
                    'sourceLayer':'raw; raw_functional validates active aligned parent/child currencies without requiring IC, Value or View; optional explicit manual/IC modes; or raw_plus_acquisition_journal with optional manual_journal and/or ic_elimination before the acquisition_journal suffix. Acquisition modes preserve sparse missing/present zero, require aligned functional currency and current unreversed acquisition pins; IC still uses raw matching basis. Value models require current Entity Currency/YTD settings',
                    'publishedChildren':'optional current Full child results pinned by opaque result-state token at the same accounting stage; IC mode applies new offsets only to remaining raw children',
                    'resultKey':'8–128 safe characters',
                    'currencyAlignedConfirmed':'literal true; caller confirms no FX is required'},
                'result':'one current exact unreviewed parent sum with opaque result-state/content evidence and each child, ownership and selected source-layer lineage',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _FULL_SEQUENCE_RUN: {
                'mode':'durable_sequence','permission':'write',
                'arguments':{'steps':'2–8 ordered Full aggregate programs; each step names prior child steps by relationship ID and step index'},
                'result':'durable sequence ID and bounded ordered job status; every published stage remains Unreviewed',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _FULL_TREE_PLAN: {
                'mode':'read','permission':'read',
                'arguments':{
                    'rootMembers':'complete root coordinate with active Scenario, Year, Period and Entity members',
                    'scenarioId':'root Scenario member ID',
                    'yearId':'root Year member ID',
                    'periodId':'root Period member ID',
                    'sourceLayer':'one explicit raw/manual/IC/acquisition source layer for all steps',
                    'currencyAlignedConfirmed':'literal true; caller asserts no FX is needed',
                    'decisions':'Full and controlConfirmed:true for every active descendant placement',
                    'parentSourceChoices':'explicit boolean for each internal Entity member',
                    'resultKeys':'unique safe result key for each internal Entity member',
                    'expectedMetadataRevision':'current nonnegative metadata revision'},
                'result':'bounded postorder V2 full.sequence.run program; caller previews and submits it separately; accounting remains Unreviewed',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
                'workflowRoute':{
                    'stages':[_FULL_SEQUENCE_RUN,_FULL_SEQUENCE_READ,
                              _FULL_SEQUENCE_CANCEL],
                    'boundary':'tree planning has no effects; the caller separately previews and submits the exact planned durable sequence, monitors it through read and may request cancellation under the current sequence policy; every published stage remains Unreviewed'},
            },
            _FULL_SEQUENCE_READ: {
                'mode':'read','permission':'read',
                'arguments':{'sequenceId':'caller-owned durable sequence ID'},
                'result':'per-step job IDs, current step, terminal state and error',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _FULL_SEQUENCE_CANCEL: {
                'mode':'atomic_sequence_control','permission':'write',
                'arguments':{'sequenceId':'caller-owned durable sequence ID'},
                'result':'cancelled or cancel-requested sequence status',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _CALENDAR_SET_FUNCTION: {
                'mode':'atomic_metadata_write','permission':'admin',
                'arguments':{'yearId':'active Year member',
                             'periodId':'active Period member',
                             'ordinal':'1–366 within Year',
                             'startsOn':'ISO date, inclusive',
                             'endsBefore':'ISO date, exclusive',
                             'expectedChangeId':'current mapping change ID',
                             'expectedMetadataRevision':'nonnegative integer'},
                'result':'explicit fiscal range, metadata revision and receipt',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _CALENDAR_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'yearId':'active Year member',
                             'periodId':'active Period member'},
                'result':'explicit mapped range or undefined, with revision',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _POLICY_DRAFT_CREATE_FUNCTION: {
                'mode':'atomic_policy_write','permission':'admin',
                'arguments':{'policyId':'stable policy ID',
                             'family':'IFRS, US_GAAP or CUSTOM',
                             'effectiveFrom':'inclusive ISO date',
                             'effectiveBefore':'exclusive ISO date',
                             'requiredElections':'explicit named choice sets',
                             'sourceRefs':'source references',
                             'expectedStateToken':'null to create; exact current opaque token to replace',
                             'expectedPolicyRevision':'nonnegative integer'},
                'result':'one current draft definition with a new opaque state token; not executable accounting policy',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _POLICY_DRAFT_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'policyId':'stable policy ID',
                             'effectiveOn':'ISO date'},
                'result':'effective draft or undefined; never execution authorization',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _POLICY_DRAFT_ELECTIONS_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'policyId':'stable policy ID',
                             'effectiveOn':'ISO date',
                             'selections':'exact name-to-choice map for every required draft election',
                             'expectedPolicyRevision':'current nonnegative policy revision'},
                'result':'canonical draft and selection digests; DraftUnreviewed, never accounting execution authorization',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _RULE_SAVE: {
                'mode':'atomic_rule_authoring','permission':'rule_design',
                'arguments':{'ruleId':'stable saved-rule ID',
                             'calculation':'typed facts.expression.calculate arguments; optional parameters map names to amount/ratio or a member declaration with dimensionId and active sampleMemberId; numeric expression nodes use Parameter and sourceMembers, targetMembers or PublishedAmount.memberOverrides may use MemberParameter',
                             'expectedStateToken':'null to create; exact current opaque token to replace',
                             'expectedMetadataRevision':'current revision',
                             'expectedPolicyRevision':'current revision'},
                'result':'saved current definition with a new state token; not executable until activated',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _RULE_PUBLISH: {
                'mode':'atomic_rule_publication','permission':'rule_publish',
                'arguments':{'ruleId':'saved-rule ID',
                             'expectedStateToken':'exact current saved-definition token',
                             'expectedMetadataRevision':'current revision',
                             'expectedPolicyRevision':'current revision'},
                'result':'active current definition with a rotated state token, policy revision and receipt',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _RULE_READ: {
                'mode':'read','permission':'read',
                'arguments':{'ruleId':'saved-rule ID'},
                'result':'current definition, state token and activation status',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _RULE_LIST: {
                'mode':'read','permission':'read',
                'arguments':{},
                'optionalArguments':{
                    'limit':'1–100 current rules; default 100',
                    'afterRuleId':'last ruleId from previous page',
                    'expectedMetadataRevision':'required with afterRuleId',
                    'expectedPolicyRevision':'required with afterRuleId'},
                'result':'current active rule IDs, state tokens, result keys, typed parameter declarations and revision-pinned next page; saved inactive definitions omitted',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _RULE_RUN: {
                'mode':'durable_calculation','permission':'rule_run',
                'arguments':{'ruleId':'current published immutable expression rule'},
                'optionalArguments':{'bindings':'exact decimal strings or active stable member IDs for every declared parameter'},
                'result':'revision-pinned expression generation with saved-rule provenance',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _RULE_SEQUENCE_RUN: {
                'mode':'durable_sequence','permission':'rule_run',
                'arguments':{'ruleIds':'2–8 distinct published expression rules in execution order'},
                'optionalArguments':{'bindings':'rule ID to exact decimal or active stable-member binding map for each parameterized step'},
                'result':'durable sequence ID, per-step job IDs and terminal status',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'bounded_write',
            },
            _RULE_SEQUENCE_READ: {
                'mode':'read','permission':'read',
                'arguments':{'sequenceId':'caller-owned durable sequence ID'},
                'result':'step progress, job IDs and terminal error',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _RULE_SEQUENCE_CANCEL: {
                'mode':'atomic_sequence_control','permission':'write',
                'arguments':{'sequenceId':'caller-owned durable sequence ID'},
                'result':'cancelled or cancel-requested sequence status',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _JOURNAL_POST_FUNCTION: {
                'mode':'atomic_adjustment','permission':'admin',
                'arguments':{'reason':'explicit 1–500 character reason',
                             'lines':'2–100 full-coordinate signed AmountLiteral rows',
                             'expectedMetadataRevision':'nonnegative integer',
                             'expectedPolicyRevision':'nonnegative integer',
                             'expectedDataRevision':'nonnegative integer'},
                'result':'balanced immutable manual adjustment and receipt',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _EXPRESSION_JOURNAL_PUBLISH: {
                'mode':'durable_atomic_adjustment','permission':'admin',
                'arguments':{
                    'reason':'explicit 1–500 character reason',
                    'lines':'2–100 current typed calculation-result mappings to full target coordinates with exact +1/-1 multiplier and source role',
                    'expectedMetadataRevision':'nonnegative current revision',
                    'expectedDataRevision':'nonnegative current revision',
                    'expectedPolicyRevision':'nonnegative current revision'},
                'result':'one exact balanced immutable manual journal with structured calculation-generation, unit and dependency lineage; no accounting-policy inference',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            _CTA_PREVIEW: {
                'mode':'read_only_preview','permission':'admin',
                'arguments':{'bridgeVersion':'1 legacy, 2 coordinate-Currency source-bound, or 3 typed-unit/non-Currency-grain source-bound',
                    'sources':'v2/v3 exact generation/member/unit pins',
                    'ctaMembers':'full explicit CTA coordinate',
                    'offsetMembers':'full explicit balancing coordinate',
                    'outputCurrencyDimensionId':'v3 typed-unit Currency role; absent from coordinates',
                    'outputCurrencyMemberId':'v3 exact common output Currency unit',
                    'layoutStateToken':'v2/v3 exact current server-owned layout state token',
                    'layoutDigest':'v2/v3 active layout digest',
                    'effectivePeriod':'explicit scenario/year/period axes and members',
                    'expectedMetadataRevision':'current revision',
                    'expectedPolicyRevision':'current revision',
                    'expectedDataRevision':'current revision','reason':'audit reason'},
                'result':'unreviewed exact reconciled bridge digest; no effect',
                'operationalPublication':{
                    'function':'consolidation.cta.bridge.post',
                    'boundary':'separate preview-bound atomic adjustment using the exact bridge digest, sources, layout, effective period and revision pins'},
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _CTA_POST: {
                'mode':'atomic_adjustment','permission':'admin',
                'arguments':{'bridge':'same strict arguments as preview',
                    'expectedBridgeDigest':'exact preview digest'},
                'result':'balanced v1/v2 journal or v3 authoritative typed-unit effects plus explicit bridge',
                'previewRequired':True,'idempotencyRequired':True,'workClass':'short'},
            _CTA_READ:{'mode':'read','permission':'read',
                'arguments':{'bridgeId':'immutable CTA bridge identity'},
                'result':'stored source-bound bridge and current deep staleness',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _CTA_CLOSE_HANDOFF:{'mode':'read','permission':'read',
                'arguments':{'bridgeId':'immutable posted CTA bridge identity'},
                'result':'exact posted lines, reconciliation source, close scope and revision pins; Unreviewed and no effects',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            _JOURNAL_REVERSE_FUNCTION: {
                'mode':'atomic_adjustment','permission':'admin',
                'arguments':{'journalId':'original posted journal ID',
                             'reason':'explicit correction reason',
                             'expectedMetadataRevision':'nonnegative integer',
                             'expectedPolicyRevision':'nonnegative integer',
                             'expectedDataRevision':'nonnegative integer'},
                'result':'linked immutable opposite journal and receipt',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'short',
            },
            _JOURNAL_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'journalId':'posted journal ID'},
                'result':'scoped immutable lines and reversal link',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _JOURNAL_BALANCE_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'members':'one full finance coordinate',
                             'snapshotRevision':'optional committed revision'},
                'result':'exact net manual-journal adjustment at snapshot',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            _ADJUSTED_BALANCE_READ_FUNCTION: {
                'mode':'read','permission':'read',
                'arguments':{'members':'one full finance coordinate',
                             'snapshotRevision':'optional committed revision'},
                'result':'raw numeric source plus manual journal adjustment',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            'cube.write.scope.lock': {
                'mode':'reviewed_policy_write','permission':'admin',
                'arguments':{'scopeMembers':'stable-ID equality filter',
                             'scopeAll':'explicit whole-application flag',
                             'reason':'required audit reason'},
                'result':'locked slice, policy revision and receipt',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            'cube.write.scope.submit': {
                'mode':'reviewed_workflow_write','permission':'write',
                'arguments':{'scopeMembers':'stable-ID equality filter',
                             'scopeAll':'explicit whole-application flag',
                             'reviewerIssuer':'verified reviewer issuer',
                             'reviewerSubjectId':'assigned administrator',
                             'reason':'required submission reason'},
                'result':'submitted, locked slice and assigned reviewer',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            'cube.write.scope.approve': {
                'mode':'reviewed_workflow_write','permission':'admin',
                'arguments':{'lockId':'submission lock ID',
                             'expectedSubmissionStateToken':'exact current submission token',
                             'reason':'required decision reason'},
                'result':'approved submission, locked slice and receipt',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            'cube.write.scope.reopen': {
                'mode':'reviewed_policy_write','permission':'admin',
                'arguments':{'lockId':'server-issued lock ID',
                             'expectedStateToken':'exact current lock token',
                             'reason':'required audit reason'},
                'result':'open slice, policy revision and receipt',
                'previewRequired':True,'idempotencyRequired':True,
                'workClass':'short',
            },
            'cube.write.scope.read': {
                'mode':'read','permission':'read',
                'arguments':{'lockId':'server-issued lock ID'},
                'result':'exact lock scope and status',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            'cube.write.scope.worklist': {
                'mode':'read','permission':'read',
                'arguments':{
                    'limit':'optional 1–100, default 100',
                    'afterLockId':'optional prior page lock ID',
                    'includeResolved':'optional boolean, default false'},
                'result':'current verified-principal cube write-scope submissions',
                'previewRequired':False,'idempotencyRequired':False,
                'workClass':'short',
            },
            'facts.source.begin': {
                'mode': 'durable_staging', 'permission': 'write',
                'arguments': {'idempotencyKey': '8–128 safe characters',
                              'mode': 'merge or replace',
                              'scopeMembers': 'stable-ID equality scope',
                              'scopeAll': 'explicit whole-application flag',
                              'expectedMetadataRevision': 'nonnegative integer',
                              'expectedDataRevision': 'nonnegative integer'},
                'result': 'durable batchId', 'previewRequired': False,
                'idempotencyRequired': True, 'workClass': 'short',
            },
            'facts.source.append': {
                'mode': 'durable_staging', 'permission': 'write',
                'arguments': {'batchId': 'server-issued ID',
                              'chunkIndex': 'ordered 0–999',
                              'rows': '1–500 full-coordinate AmountLiteral/TextLiteral/LineDetailLiteral rows'},
                'result': 'cumulative row count and digest',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'facts.source.csv.append': {
                'mode': 'durable_staging', 'permission': 'write',
                'arguments': {'batchId': 'server-issued ID',
                              'chunkIndex': 'ordered 0–999',
                              'csvText': 'UTF-8 CSV with axis.<dimensionId>, literalType, value and sourceRef columns; at most 500 rows'},
                'result': 'cumulative staged row count and digest',
                'previewRequired': False, 'idempotencyRequired': True,
                'workClass': 'short',
            },
            'facts.source.seal': {
                'mode': 'durable_staging', 'permission': 'write',
                'arguments': {'batchId': 'server-issued ID',
                              'expectedRows': 'acknowledged row count',
                              'expectedContentDigest': 'acknowledged digest'},
                'result': 'ready batch', 'previewRequired': False,
                'idempotencyRequired': True, 'workClass': 'short',
            },
            'facts.source.cancel': {
                'mode': 'durable_write', 'permission': 'write',
                'arguments': {'batchId': 'caller-owned staging batch'},
                'result': 'idempotent terminal batch state and whether committed effects remain',
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'facts.source.preview': {
                'mode': 'preview', 'permission': 'write',
                'arguments': {'batchId': 'ready batch'},
                'optionalArguments': {
                    'allowWarnings': 'explicit boolean; default false'},
                'result': 'set/clear counts and signed token',
                'operationalPublication':{
                    'function':'facts.source.publish',
                    'boundary':'separate preview-token-bound durable publication of the same ready source batch under current authorization'},
                'previewRequired': False, 'idempotencyRequired': False,
                'workClass': 'short',
            },
            'facts.source.publish': {
                'mode': 'durable_write', 'permission': 'write',
                'arguments': {'batchId': 'ready batch',
                              'previewToken': 'signed preview token'},
                'result': 'atomic receipt and exact set/clear counts',
                'previewRequired': True, 'idempotencyRequired': True,
                'workClass': 'bounded_write',
            },
            _COPY_FUNCTION: {
                'mode':'durable_staging','permission':'write',
                'arguments':{
                    'scenarioDimension':'active generic axis',
                    'sourceMember':'active source scenario ID',
                    'targetMember':'active target scenario ID',
                    'filterMembers':'stable-ID filters on other axes',
                    'mode':'merge or exact-target-scope replace',
                    'expectedMetadataRevision':'nonnegative integer',
                    'expectedDataRevision':'nonnegative integer',
                    'idempotencyKey':'8–128 safe characters'},
                'result':'ready numeric/text/supporting-detail source batch with copy provenance',
                'previewRequired':False,'idempotencyRequired':True,
                'workClass':'bounded_write',
            },
            **PostgresGenericFacts.catalog(),
        }}
        from .postgres_saved_numeric_sequence import catalog as saved_sequence_catalog
        catalog['functions'].update(saved_sequence_catalog())
        catalog['functions'].update(calculated_member_catalog())
        catalog['functions'].update(resolved_cube_read_catalog())
        catalog['functions'].update(calculation_inspection_catalog())
        catalog['functions'].update(application_rule_catalog())
        catalog['functions'].update(application_schedule_catalog())
        catalog['functions'].update(application_assignment_catalog())
        catalog['functions'].update(application_workflow_catalog())
        catalog['functions'].update(application_workflow_occurrence_catalog())
        catalog['functions'].update(operation_receipt_catalog())
        catalog['functions'].update(application_decision_catalog())
        from .postgres_numeric_iteration import catalog as iteration_catalog
        catalog['functions'].update(iteration_catalog())
        from .postgres_authoring_context import catalog as authoring_context_catalog
        catalog['functions'].update(authoring_context_catalog())
        from .postgres_numeric_transform import catalog as numeric_transform_catalog
        catalog['functions'].update(numeric_transform_catalog())
        from .postgres_numeric_catalog import enrich as enrich_numeric_catalog
        enrich_numeric_catalog(catalog)
        from .expression_apportionment import catalog_program_schema
        catalog['functions'][_EXPRESSION_FUNCTION]['programSchema'] = catalog_program_schema()
        catalog['functions'][_EXPRESSION_FUNCTION]['semanticRules'] = [
            'Choose exactly one profile: expression (scalar and existing reduction variants), apportionment, or CurrencyConvert member-set selection. expression and apportionment are mutually exclusive.',
            'Apportionment accepts exactly sourceMembers, resultKey and apportionment; its sourceMembers covers every active fact axis. Scalar sourceMembers may be empty alongside sourceMemberSets, or omitted only for an explicit sourceDomain plus missingDefault. A sparse-relation expression instead accepts exactly applicabilityDomain, expression and resultKey.',
            'An applicabilityDomain is stable business mapping data, not calculation work. Pin the current active relation state and digest; never create relation rows or multiple rules to represent batches, partitions, chunks, leases or workers.',
            'programSchema describes profile discriminants and apportionment structure; the fixed compiler remains authoritative for typed expressions, current metadata, lineage, quantum alignment, exact conservation and byte/work bounds.']
        from .postgres_cube_select import catalog as cube_select_catalog
        catalog['functions'].update(cube_select_catalog())
        from .postgres_fact_reconstruction_job import catalog as reconstruction_catalog
        catalog['functions'].update(reconstruction_catalog())
        from .postgres_projection_cleanup import catalog as cleanup_catalog
        catalog['functions'].update(cleanup_catalog())
        catalog['functions'].update(python_schedule_catalog())
        catalog['processingPolicy'] = processing_policy()
        return describe_catalog(catalog)

    def execute_generic(self, scope: ApplicationScope, program: dict, *,
                        idempotency_key: str) -> dict:
        if not isinstance(program, dict) or program.get('function') not in (
                _GENERIC_CREATE, _GENERIC_UPDATE,
                _GENERIC_TABLE_DELETE,
                _GENERIC_SET, _GENERIC_DELETE, _GENERIC_BULK):
            raise ValueError('V2_GENERIC_FACT_FUNCTION_UNSUPPORTED')
        result = PostgresGenericFacts(
            self.dsn, identity=self.identity).execute(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2, 'function': program['function'],
                'result': result}

    def execute_metadata(self, scope: ApplicationScope, program: dict, *,
                         idempotency_key: str) -> dict:
        from .postgres_python_definitions import RETIRED_PUBLIC_AUTHORING
        if isinstance(program, dict) and program.get('function') in RETIRED_PUBLIC_AUTHORING:
            raise ValueError('PYTHON_SOURCE_AUTHORING_REQUIRED')
        if (isinstance(program, dict) and program.get('function') in
                _SOURCE_EVIDENCE_WRITES):
            result = PostgresSourceEvidence(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).execute(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict) and program.get('function') ==
                _SOURCE_EVIDENCE_CUTOVER_APPLY):
            result = PostgresSourceEvidenceCutover(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).apply(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program,dict) and program.get('function') in
                (_MEMBER_LIST_SAVE,_MEMBER_LIST_ACTIVATE,
                 _MEMBER_LIST_DEACTIVATE,_MEMBER_LIST_DELETE,
                 _MEMBER_LIST_ADOPT_CONFIGURATION)):
            result=PostgresMemberLists(
                self.dsn,identity=self.identity).execute(
                    scope,program,idempotency_key=idempotency_key)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_APPLICABILITY_RELATION_SAVE,
                 _APPLICABILITY_RELATION_ACTIVATE,
                 _APPLICABILITY_RELATION_DEACTIVATE,
                 _APPLICABILITY_RELATION_DELETE)):
            result=PostgresApplicabilityRelations(
                self.dsn,identity=self.identity).execute(
                    scope,program,idempotency_key=idempotency_key)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_SAVED_GRID_SAVE,_SAVED_GRID_DELETE)):
            service=PostgresSavedGrids(self.dsn,identity=self.identity)
            operation=(service.save if program['function']==_SAVED_GRID_SAVE
                       else service.delete)
            result=operation(scope,program,idempotency_key=idempotency_key)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program, dict) and program.get('function') ==
                _HIERARCHY_RELATIONSHIPS_APPLY):
            result = PostgresHierarchyRelationshipPatch(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).apply(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict) and program.get('function') in (
                _FINANCIAL_ACCOUNT_SET, _FINANCIAL_ENTITY_SET)):
            result = PostgresFinancialMemberPolicy(
                self.dsn, identity=self.identity).execute(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _CURRENCY_SETTINGS_SAVE):
            result = PostgresCurrencySettings(
                self.dsn, identity=self.identity).save(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2,
                    'function': _CURRENCY_SETTINGS_SAVE, 'result': result}
        if (isinstance(program, dict) and program.get('function') in (
                _ATTRIBUTE_DEFINITION_CREATE,
                _ATTRIBUTE_DEFINITION_UPDATE,
                _ATTRIBUTE_DEFINITION_STATUS,
                _ATTRIBUTE_VALUE_SET,
                _ATTRIBUTE_VALUES_REPLACE)):
            result = PostgresAttributeCatalog(
                self.dsn, identity=self.identity).execute(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if isinstance(program, dict) and program.get('function') in (
                _SEMANTIC_CREATE, _SEMANTIC_UPDATE, _SEMANTIC_SET,
                _REL_SEMANTIC_CREATE, _REL_SEMANTIC_UPDATE,
                _REL_SEMANTIC_SET):
            result = PostgresSemanticAttributes(
                self.dsn, identity=self.identity).execute(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        fields = {
            'metadata.dimension.create': {'dimensionId','name','modelRole',
                                          'expectedMetadataRevision'},
            'metadata.member.create': {'dimensionId','memberId','name',
                                       'expectedMetadataRevision'},
            'metadata.dimension.rename': {'dimensionId','name',
                                          'expectedMetadataRevision'},
            'metadata.member.rename': {'dimensionId','memberId','name',
                                       'expectedMetadataRevision'},
            'metadata.dimension.describe': {'dimensionId',
                'shortDescription','detailedDescription',
                'expectedMetadataRevision'},
            'metadata.member.describe': {'dimensionId','memberId',
                'shortDescription','detailedDescription',
                'expectedMetadataRevision'},
            'metadata.member.security-tags.set': {
                'dimensionId','memberId','readTags','writeTags',
                'expectedMetadataRevision'},
            'metadata.member.security-string.set': {
                'dimensionId','memberId','securityString',
                'expectedMetadataRevision'},
            'metadata.dimension.security-string.set': {
                'dimensionId','securityString','expectedMetadataRevision'},
            'metadata.relationship.security-string.set': {
                'relationshipId','securityString','expectedMetadataRevision'},
            'metadata.security-tag.create': {
                'dimensionId','tagId','displayName','shortDescription',
                'semanticDescription','expectedMetadataRevision'},
            'metadata.security-tag.update': {
                'dimensionId','tagId','displayName','shortDescription',
                'semanticDescription','expectedMetadataRevision'},
            'metadata.security-tag.status.set': {
                'dimensionId','tagId','status','expectedMetadataRevision'},
            'metadata.member.status.set': {'dimensionId','memberId','status',
                                           'expectedMetadataRevision'},
            'metadata.dimension.status.set': {'dimensionId','status',
                                             'expectedMetadataRevision'},
            'metadata.dimension.delete': {'dimensionId',
                                          'expectedMetadataRevision'},
            'metadata.member.numeric-kind.set': {
                'dimensionId','memberId','numericValueKind',
                'expectedMetadataRevision'},
            'metadata.member.aggregation-operator.set': {
                'dimensionId','memberId','aggregationOperator',
                'expectedMetadataRevision'},
            'metadata.relationship.create': {'dimensionId','relationshipId',
                'parentMemberId','childMemberId','expectedMetadataRevision'},
            'metadata.relationship.rename': {'relationshipId','name',
                'expectedMetadataRevision'},
            'metadata.relationship.describe': {'relationshipId',
                'shortDescription','detailedDescription',
                'expectedMetadataRevision'},
            'metadata.relationship.status.set': {'relationshipId','status',
                'expectedMetadataRevision'},
            'metadata.relationship.aggregation-operator.set': {
                'relationshipId','aggregationOperatorOverride',
                'expectedMetadataRevision'},
            'metadata.hierarchy.build': {'dimensionId',
                                         'expectedMetadataRevision'},
            **{name: required | {'expectedMetadataRevision'} for name, required in NAMED_HIERARCHY_MUTATIONS.items()},
        }
        optional = {
            'metadata.dimension.create': {'shortDescription',
                                          'detailedDescription'},
            'metadata.member.create': {'shortDescription',
                                       'detailedDescription'},
            'metadata.relationship.create': {'name', 'shortDescription',
                                             'detailedDescription', 'hierarchyId', 'status'},
            'metadata.hierarchy.build': {'membershipSemantics', 'hierarchyId',
                                         'expectedStateToken'},
        }
        if (not isinstance(program,dict)
                or set(program) != {'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] not in fields
                or not isinstance(program['arguments'],dict)
                or not fields[program['function']].issubset(
                    program['arguments'])
                or not set(program['arguments']).issubset(
                    fields[program['function']] |
                    optional.get(program['function'], set()))
                or not isinstance(idempotency_key,str)
                or not 1 <= len(idempotency_key) <= 200):
            raise ValueError('V2_METADATA_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
        function, args = program['function'], program['arguments']
        digest = sha256(json.dumps(program,sort_keys=True,
            separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
        metadata = PostgresMetadataStore(self.dsn,identity=self.identity)
        common = {'operation_id':idempotency_key,
                  'command_digest':digest,
                  'actor_id':self.identity.subject_id,
                  'expected_metadata_revision':args['expectedMetadataRevision']}
        if function in NAMED_HIERARCHY_MUTATIONS:
            receipt = metadata.hierarchy_mutation(scope, function, args, **common)
        elif function == 'metadata.dimension.create':
            receipt = metadata.create_dimension(scope,
                dimension_id=args['dimensionId'],name=args['name'],
                model_role=args['modelRole'],
                short_description=args.get('shortDescription',''),
                detailed_description=args.get('detailedDescription',''),
                **common)
        elif function == 'metadata.member.create':
            receipt = metadata.create_member(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                name=args['name'],
                short_description=args.get('shortDescription',''),
                detailed_description=args.get('detailedDescription',''),
                **common)
        elif function == 'metadata.dimension.rename':
            receipt = metadata.rename_dimension(scope,
                dimension_id=args['dimensionId'],name=args['name'],**common)
        elif function == 'metadata.member.rename':
            receipt = metadata.rename_member(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                name=args['name'],**common)
        elif function == 'metadata.dimension.describe':
            receipt = metadata.describe_dimension(scope,
                dimension_id=args['dimensionId'],
                short_description=args['shortDescription'],
                detailed_description=args['detailedDescription'],**common)
        elif function == 'metadata.member.describe':
            receipt = metadata.describe_member(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                short_description=args['shortDescription'],
                detailed_description=args['detailedDescription'],**common)
        elif function == 'metadata.member.security-tags.set':
            receipt = metadata.set_member_security_tags(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                read_tags=args['readTags'],write_tags=args['writeTags'],
                **common)
        elif function == 'metadata.member.security-string.set':
            receipt = metadata.set_member_security_string(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                security_string=args['securityString'], **common)
        elif function == 'metadata.dimension.security-string.set':
            receipt = metadata.set_dimension_security_string(scope,
                dimension_id=args['dimensionId'],
                security_string=args['securityString'], **common)
        elif function == 'metadata.relationship.security-string.set':
            receipt = metadata.set_relationship_security_string(scope,
                relationship_id=args['relationshipId'],
                security_string=args['securityString'], **common)
        elif function == 'metadata.security-tag.create':
            receipt=metadata.create_security_tag(scope,
                dimension_id=args['dimensionId'],tag_id=args['tagId'],
                display_name=args['displayName'],
                short_description=args['shortDescription'],
                semantic_description=args['semanticDescription'],**common)
        elif function == 'metadata.security-tag.update':
            receipt=metadata.update_security_tag(scope,
                dimension_id=args['dimensionId'],tag_id=args['tagId'],
                display_name=args['displayName'],
                short_description=args['shortDescription'],
                semantic_description=args['semanticDescription'],**common)
        elif function == 'metadata.security-tag.status.set':
            receipt=metadata.set_security_tag_status(scope,
                dimension_id=args['dimensionId'],tag_id=args['tagId'],
                status=args['status'],**common)
        elif function == 'metadata.member.status.set':
            receipt = metadata.set_member_status(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                status=args['status'],**common)
        elif function == 'metadata.dimension.status.set':
            receipt = metadata.set_dimension_status(scope,
                dimension_id=args['dimensionId'],status=args['status'],
                **common)
        elif function == 'metadata.dimension.delete':
            receipt = metadata.delete_dimension(scope,
                dimension_id=args['dimensionId'], **common)
        elif function == 'metadata.member.numeric-kind.set':
            receipt = metadata.set_member_numeric_kind(scope,
                dimension_id=args['dimensionId'],member_id=args['memberId'],
                numeric_value_kind=args['numericValueKind'],**common)
        elif function == 'metadata.member.aggregation-operator.set':
            receipt = metadata.set_member_aggregation_operator(
                scope, dimension_id=args['dimensionId'],
                member_id=args['memberId'],
                aggregation_operator=args['aggregationOperator'], **common)
        elif function == 'metadata.hierarchy.build':
            result = metadata.build_hierarchy(
                scope, dimension_id=args['dimensionId'],
                membership_semantics=args.get('membershipSemantics'),
                hierarchy_id=args.get('hierarchyId'),
                expected_state_token=args.get('expectedStateToken'), **common)
            return {'languageVersion':2,'function':function,
                    'result':{'operationId':idempotency_key, **result}}
        elif function == 'metadata.relationship.status.set':
            receipt = metadata.set_relationship_status(scope,
                relationship_id=args['relationshipId'],
                status=args['status'],**common)
        elif function == 'metadata.relationship.rename':
            receipt = metadata.rename_relationship(
                scope, relationship_id=args['relationshipId'],
                name=args['name'], **common)
        elif function == 'metadata.relationship.describe':
            receipt = metadata.describe_relationship(
                scope, relationship_id=args['relationshipId'],
                short_description=args['shortDescription'],
                detailed_description=args['detailedDescription'], **common)
        elif function == 'metadata.relationship.aggregation-operator.set':
            receipt = metadata.set_relationship_aggregation_operator(
                scope, relationship_id=args['relationshipId'],
                aggregation_operator_override=
                    args['aggregationOperatorOverride'], **common)
        else:
            receipt = metadata.link_members(scope,
                dimension_id=args['dimensionId'],
                relationship_id=args['relationshipId'],
                name=args.get('name'),
                short_description=args.get('shortDescription', ''),
                detailed_description=args.get('detailedDescription', ''),
                parent_member_id=args['parentMemberId'],
                child_member_id=args['childMemberId'],
                hierarchy_id=args.get('hierarchyId'), status=args.get('status', 'Active'), **common)
        return {'languageVersion':2,'function':function,
                'result':{'operationId':receipt.operation_id,
                          'committedRevision':receipt.committed_revision,
                          'changedCount':receipt.changed_count}}

    def execute_ownership(self, scope: ApplicationScope, program: dict, *,
                          idempotency_key: str) -> dict:
        result=PostgresOwnershipValues(
            self.dsn,identity=self.identity).apply(
                scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':_OWNERSHIP_WRITE_FUNCTION,
                'result':result}

    def execute_calendar(self,scope: ApplicationScope,program: dict,*,
                         idempotency_key: str) -> dict:
        result=PostgresCalendarPeriods(
            self.dsn,identity=self.identity).set(
                scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':_CALENDAR_SET_FUNCTION,
                'result':result}

    def execute_policy_draft(self,scope: ApplicationScope,program: dict,*,
                             idempotency_key: str) -> dict:
        result=PostgresPolicyDrafts(self.dsn,identity=self.identity).create(
            scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':_POLICY_DRAFT_CREATE_FUNCTION,
                'result':result}

    def execute_period_nci_basis(self,scope: ApplicationScope,program: dict,*,idempotency_key: str) -> dict:
        result=PostgresPeriodNciBasis(self.dsn,identity=self.identity).execute(scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],'result':result}

    def execute_period_policy_governance(self,scope: ApplicationScope,program: dict,*,idempotency_key: str) -> dict:
        result=PostgresPeriodPolicyGovernance(self.dsn,identity=self.identity).execute(
            scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],'result':result}

    def execute_period_policy_case_record(self,scope: ApplicationScope,program: dict,*,idempotency_key: str) -> dict:
        result=PostgresPeriodPolicyCases(self.dsn,identity=self.identity).record(
            scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':_PERIOD_CASE_RECORD,'result':result}

    def execute_policy_case_record(self, scope: ApplicationScope,
                                   program: dict, *,
                                   idempotency_key: str) -> dict:
        result = PostgresPolicyCaseEvaluator(
            self.dsn, identity=self.identity).record(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2,
                'function': _POLICY_ACQUISITION_CASES_RECORD,
                'result': result}

    def execute_policy_case_review(self, scope: ApplicationScope,
                                   program: dict, *,
                                   idempotency_key: str) -> dict:
        result = PostgresPolicyCaseReviews(
            self.dsn, identity=self.identity).record(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2,
                'function': _POLICY_ACQUISITION_REVIEW_RECORD,
                'result': result}

    def execute_policy_source_artifact(self, scope: ApplicationScope,
                                       program: dict, *,
                                       idempotency_key: str) -> dict:
        result = PostgresPolicySourceArtifacts(
            self.dsn, identity=self.identity).capture(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2,
                'function': _POLICY_SOURCE_ARTIFACT_CAPTURE,
                'result': result}

    def execute_policy_approval(self,scope: ApplicationScope,program: dict,*,
                                idempotency_key: str) -> dict:
        result=PostgresPolicyApprovals(self.dsn,identity=self.identity).approve(
            scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':_POLICY_APPROVE,'result':result}

    def execute_policy_activation(self,scope: ApplicationScope,program: dict,*,
                                  idempotency_key: str) -> dict:
        result=PostgresPolicyActivation(self.dsn,identity=self.identity).execute(
            scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],'result':result}

    def execute_application_decision(self, scope: ApplicationScope,
                                     program: dict, *, idempotency_key: str) -> dict:
        return PostgresApplicationDecisions(self.dsn, identity=self.identity).execute(
            scope, program, idempotency_key=idempotency_key)

    def execute_expression_rule(self, scope: ApplicationScope,
                                program: dict, *, idempotency_key: str) -> dict:
        from .postgres_python_definitions import RETIRED_PUBLIC_AUTHORING
        if isinstance(program, dict) and program.get('function') in RETIRED_PUBLIC_AUTHORING:
            raise ValueError('PYTHON_SOURCE_AUTHORING_REQUIRED')
        from .postgres_saved_numeric_sequence import PostgresSavedNumericSequences, SAVE as saved_save, PUBLISH as saved_publish
        function=program.get('function')
        if function == _CALCULATION_RECALCULATE:
            result = PostgresCalculationInspection(
                self.dsn, identity=self.identity).recalculate(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': function,
                    'result': result}
        if function in (_APPLICATION_RULE_RUN,
                        _APPLICATION_RULE_RUN_CANCEL,
                        _APPLICATION_RULE_RUN_RECONCILE):
            from .postgres_application_rule_workflow import (
                PostgresApplicationRuleRun,parse_program)
            service=PostgresApplicationRuleRun(
                self.dsn,identity=self.identity,language=self)
            if function==_APPLICATION_RULE_RUN:
                request=parse_program(program,function)
                result=service.run(scope,request['ruleId'],
                                   bindings=request['bindings'],
                                   expected_state_token=request.get('expectedStateToken'),
                                   expected_program_digest=request.get('expectedProgramDigest'),
                                   idempotency_key=idempotency_key)
            elif function==_APPLICATION_RULE_RUN_CANCEL:
                result=service.cancel(scope,parse_program(program,function))
            else:
                result=service.reconcile(scope,parse_program(program,function),
                                         idempotency_key=idempotency_key)
            return {'languageVersion':2,'function':function,'result':result}
        rules=(PostgresSavedNumericSequences if function in (saved_save,saved_publish)
               else PostgresApplicationRules if function in (
                   _APPLICATION_RULE_SAVE,_APPLICATION_RULE_PUBLISH,
                   _APPLICATION_RULE_RETIRE)
               else PostgresCalculatedMembers if function in (
                   _CALCULATED_MEMBER_SAVE,_CALCULATED_MEMBER_PUBLISH)
               else PostgresExpressionRules)
        result = rules(self.dsn, identity=self.identity).execute(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2, 'function': program['function'],
                'result': result}

    def execute_application_schedule(self,scope: ApplicationScope,
            program: dict,*,idempotency_key: str | None=None) -> dict:
        function=program.get('function') if isinstance(program,dict) else None
        registry=None
        if function==_APPLICATION_SCHEDULE_SAVE:
            from .postgres_python_build_validator import (
                PostgresPythonBuildOperationValidator)
            arguments=(program.get('arguments')
                       if isinstance(program.get('arguments'),dict) else {})
            registry=PostgresPythonBuildOperationValidator(
                self.dsn,identity=self.identity,
                preview_secret=self.preview_secret,
                metadata_revision=arguments.get('expectedMetadataRevision'),
                policy_revision=arguments.get('expectedPolicyRevision'),
                schema_epoch=arguments.get('expectedSchemaEpoch'),language=self)
        result=PostgresApplicationSchedules(
            self.dsn,identity=self.identity).execute(
                scope,program,idempotency_key=idempotency_key,
                registry=registry)
        return {'languageVersion':2,'function':function,'result':result}

    def execute_application_assignment(self,scope: ApplicationScope,
            program: dict,*,idempotency_key: str | None=None) -> dict:
        """Execute the domain-neutral assignment lifecycle through fixed core.

        The adapter performs no assignment interpretation of its own.  The
        repository remains responsible for exact program validation, current
        authorization, revision fences, receipts and persisted-digest checks.
        """
        function=program.get('function') if isinstance(program,dict) else None
        result=PostgresApplicationAssignments(
            self.dsn,identity=self.identity).execute(
                scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':function,'result':result}

    def execute_application_workflow(self,scope: ApplicationScope,
            program: dict,*,idempotency_key: str | None=None) -> dict:
        """Manage a domain-neutral workflow definition through fixed core."""
        function=program.get('function') if isinstance(program,dict) else None
        result=PostgresApplicationWorkflows(
            self.dsn,identity=self.identity).execute(
                scope,program,idempotency_key=idempotency_key,
                available_functions=self.catalog()['functions'])
        return {'languageVersion':2,'function':function,'result':result}

    def execute_application_workflow_occurrence(self,scope: ApplicationScope,
            program: dict,*,idempotency_key: str|None=None) -> dict:
        """Execute one bounded generic workflow occurrence operation."""
        function=program.get('function') if isinstance(program,dict) else None
        result=PostgresApplicationWorkflowOccurrences(
            self.dsn,identity=self.identity).execute_program(
                scope,program,idempotency_key=idempotency_key,
                available_functions=self.catalog()['functions'])
        return {'languageVersion':2,'function':function,'result':result}

    def execute_python_program(self, scope: ApplicationScope,
                               program: dict, *, idempotency_key: str) -> dict:
        function=program.get('function') if isinstance(program,dict) else None
        if function==_PYTHON_ENVIRONMENT_REGISTER:
            if not self.approved_python_profiles:
                raise ValueError('PYTHON_ENVIRONMENT_CONFIGURATION_UNAVAILABLE')
            result=PostgresPythonEnvironments(self.dsn,identity=self.identity,
                approved_profiles=self.approved_python_profiles).execute(
                scope,program,idempotency_key=idempotency_key)
        else:
            service=(PostgresPythonSchedules if function in _PYTHON_SCHEDULE_FUNCTIONS
                else PostgresPythonPrograms)
            result = service(self.dsn, identity=self.identity).execute(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2, 'function': program['function'],
                'result': result}

    def execute_python_build(self, scope: ApplicationScope, program: dict, *,
                             idempotency_key: str) -> dict:
        result = PostgresPythonBuildPublic(
            self.dsn, identity=self.identity).execute(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2, 'function': program['function'],
                'result': result}

    def read_python_build(self, scope: ApplicationScope, build_id: str) -> dict:
        return PostgresPythonBuildPublic(
            self.dsn, identity=self.identity).read(scope, build_id)

    def read_python_build_artifact(self, scope: ApplicationScope, *,
                                   build_id: str, section: str,
                                   cursor: str | None = None) -> dict:
        return PostgresPythonBuildArtifact(self.dsn, identity=self.identity,
            cursor_secret=self.preview_secret).read(scope, build_id=build_id,
                section=section, cursor=cursor)

    def cancel_python_build(self, scope: ApplicationScope, build_id: str) -> dict:
        return PostgresPythonBuildPublic(
            self.dsn, identity=self.identity).cancel(scope, build_id)

    def execute_python_run(self, scope: ApplicationScope, program: dict, *,
                           idempotency_key: str) -> dict:
        result=PostgresPythonRun(self.dsn,identity=self.identity,
            admission=self).run(scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':_PYTHON_PROGRAM_RUN,
                'result':result}

    def read_python_workflow(self, scope: ApplicationScope,
                             workflow_id: str) -> dict:
        return PostgresPythonRun(self.dsn,identity=self.identity,
            admission=self).read(scope,workflow_id)

    def cancel_python_workflow(self, scope: ApplicationScope,
                               workflow_id: str) -> dict:
        return PostgresPythonRun(self.dsn,identity=self.identity,
            admission=self).cancel(scope,workflow_id)

    def execute_execution_delegation(self,scope: ApplicationScope,program: dict,
                                     *,idempotency_key: str) -> dict:
        result=PostgresExecutionDelegations(self.dsn,identity=self.identity).execute(
            scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],'result':result}

    def execute_planning_workflow_policy(
            self,scope: ApplicationScope,program: dict,*,
            idempotency_key: str|None=None) -> dict:
        result=PostgresPlanningWorkflowPolicies(
            self.dsn,identity=self.identity).execute_program(
                scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],
                'result':result}

    def execute_statement_definition(
            self,scope: ApplicationScope,program: dict,*,
            idempotency_key: str|None=None) -> dict:
        result=PostgresStatementDefinitions(
            self.dsn,identity=self.identity).execute_program(
                scope,program,idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],
                'result':result}

    def execute_planning_operation_policy(
            self, scope: ApplicationScope, program: dict, *,
            idempotency_key: str | None = None) -> dict:
        if isinstance(program, dict) and program.get('function') in (
                _PLANNING_DRIVER_POLICY_PREVIEW,
                _PLANNING_DRIVER_POLICY_RUN,
                _PLANNING_SEED_POLICY_PREVIEW,
                _PLANNING_SEED_POLICY_RUN,
                _PLANNING_SEED_LINEAGE_READ,
                _PLANNING_ROLLUP_POLICY_PREVIEW,
                _PLANNING_ROLLUP_POLICY_RUN,
                _PLANNING_SPREAD_POLICY_PREVIEW,
                _PLANNING_SPREAD_POLICY_RUN,
                _PLANNING_ALLOCATION_POLICY_PREVIEW,
                _PLANNING_ALLOCATION_POLICY_RUN):
            driver = program['function'] in (
                _PLANNING_DRIVER_POLICY_PREVIEW,
                _PLANNING_DRIVER_POLICY_RUN)
            service_class = (PostgresPublishedPlanningDriver if driver else
                PostgresPublishedPlanningSeed if program['function'] in (
                    _PLANNING_SEED_POLICY_PREVIEW,
                    _PLANNING_SEED_POLICY_RUN,
                    _PLANNING_SEED_LINEAGE_READ)
                else PostgresPublishedPlanningRollup if program['function'] in (
                    _PLANNING_ROLLUP_POLICY_PREVIEW,
                    _PLANNING_ROLLUP_POLICY_RUN)
                else PostgresPublishedPlanningSpread if program['function'] in (
                    _PLANNING_SPREAD_POLICY_PREVIEW,
                    _PLANNING_SPREAD_POLICY_RUN)
                else PostgresPublishedPlanningAllocation)
            service = service_class(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret)
            if program['function'] == _PLANNING_SEED_LINEAGE_READ:
                if idempotency_key is not None:
                    raise ValueError('PLANNING_SEED_LINEAGE_KEY_UNSUPPORTED')
                result = service.read_lineage(scope,program)
                return {'languageVersion':2,'function':program['function'],
                        'result':result}
            if program['function'] in (
                    _PLANNING_DRIVER_POLICY_PREVIEW,
                    _PLANNING_SEED_POLICY_PREVIEW,
                    _PLANNING_ROLLUP_POLICY_PREVIEW,
                    _PLANNING_SPREAD_POLICY_PREVIEW,
                    _PLANNING_ALLOCATION_POLICY_PREVIEW):
                if idempotency_key is not None:
                    raise ValueError('PLANNING_POLICY_PREVIEW_KEY_UNSUPPORTED')
                result = service.preview(scope, program)
            else:
                if idempotency_key is None:
                    raise ValueError('PLANNING_POLICY_RUN_KEY_REQUIRED')
                result = service.run(
                    scope, program, idempotency_key=idempotency_key)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        result = PostgresPlanningOperationPolicies(
            self.dsn, identity=self.identity).execute_program(
                scope, program, idempotency_key=idempotency_key)
        return {'languageVersion': 2, 'function': program['function'],
                'result': result}

    def execute_inventory_unrealized_schedule(
            self,scope: ApplicationScope,program: dict,* ,
            idempotency_key: str|None=None) -> dict:
        service=PostgresInventoryUnrealizedSchedules(
            self.dsn,identity=self.identity)
        if (isinstance(program,dict) and program.get('function') in
                (_INVENTORY_UNREALIZED_SCHEDULE_READ,
                 _INVENTORY_UNREALIZED_SCHEDULE_LIST)):
            if idempotency_key is not None:
                raise ValueError(
                    'INVENTORY_UNREALIZED_SCHEDULE_READ_KEY_UNSUPPORTED')
            result=service.read_program(scope,program)
        else:
            result=service.execute_program(scope,program,
                idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program.get('function'),
                'result':result}

    def cancel_expression_sequence(self, scope: ApplicationScope,
                                   program: dict) -> dict:
        result = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).cancel(scope, program)
        return {'languageVersion': 2, 'function': _RULE_SEQUENCE_CANCEL,
                'result': result}

    def cancel_full_sequence(self, scope: ApplicationScope,
                             program: dict) -> dict:
        result = PostgresFullAggregateSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).cancel(scope, program)
        return {'languageVersion': 2, 'function': _FULL_SEQUENCE_CANCEL,
                'result': result}

    def execute_journal(self, scope: ApplicationScope, program: dict, *,
                        idempotency_key: str) -> dict:
        if isinstance(program,dict) and program.get('function')==(
                _CONSOLIDATION_LAYOUT_CONFIGURE):
            result=PostgresConsolidationLayout(
                self.dsn,identity=self.identity).configure(
                    scope,program,idempotency_key=idempotency_key)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if isinstance(program,dict) and program.get('function')==_CTA_POST:
            if (set(program)!={'languageVersion','function','arguments'}
                    or program.get('languageVersion')!=2
                    or type(program.get('arguments')) is not dict
                    or set(program['arguments'])!={'bridge','expectedBridgeDigest'}
                    or type(program['arguments']['bridge']) is not dict
                    or type(program['arguments']['expectedBridgeDigest']) is not str):
                raise ValueError('CTA_PUBLIC_PROGRAM_INVALID')
            bridge=program['arguments']['bridge'];service=PostgresCtaBridge(
                self.dsn,identity=self.identity)
            handler=(service.post_v3 if bridge.get('bridgeVersion')==3
                     else service.post_v2 if bridge.get('bridgeVersion')==2
                     else service.post)
            result=handler(scope,bridge,
                    idempotency_key=idempotency_key,
                    expected_bridge_digest=program['arguments']['expectedBridgeDigest'])
            return {'languageVersion':2,'function':_CTA_POST,'result':result}
        if isinstance(program,dict) and program.get('function')==_ACQ_REVERSE:
            result=PostgresAcquisitionJournalHistory(self.dsn,identity=self.identity).reverse(
                scope,program,idempotency_key=idempotency_key)
        else:
            result = PostgresManualJournal(
                self.dsn, identity=self.identity).execute(
                    scope, program, idempotency_key=idempotency_key)
        return {'languageVersion':2,'function':program['function'],
                'result':result}

    def execute_ic_elimination(self, scope: ApplicationScope, program: dict,
                               *, idempotency_key: str) -> dict:
        service = PostgresIntercompanyElimination(
            self.dsn, identity=self.identity)
        function = program.get('function') if isinstance(program,dict) else None
        if function == _IC_ELIMINATION_PUBLISH_FUNCTION:
            result = service.publish(scope,program,
                                     idempotency_key=idempotency_key)
        elif function == _IC_ELIMINATION_WITHDRAW_FUNCTION:
            result = service.withdraw(scope,program,
                                      idempotency_key=idempotency_key)
        else:
            raise ValueError('IC_ELIMINATION_FUNCTION_UNSUPPORTED')
        return {'languageVersion':2,'function':function,'result':result}

    def execute_source(self, scope: ApplicationScope, program: dict) -> dict:
        """Execute only catalogued staged-load programs through fixed core."""
        if (isinstance(program, dict)
                and program.get('function') in _IMPORT_EXECUTION_FUNCTIONS):
            result = PostgresImportExecutionPublic(
                self.dsn, identity=self.identity).execute(scope, program)
            return {'languageVersion': 2,
                    'function': program['function'], 'result': result}
        if (isinstance(program, dict)
                and program.get('function') in
                    _TRANSFER_ORCHESTRATION_FUNCTIONS):
            result = PostgresTransferOrchestration(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).execute(scope, program)
            return {'languageVersion': 2,
                    'function': program['function'], 'result': result}
        if (isinstance(program,dict)
                and program.get('function')==_COPY_FUNCTION):
            result=PostgresScenarioCopy(
                self.dsn,identity=self.identity).prepare(scope,program)
            return {'languageVersion':2,'function':_COPY_FUNCTION,
                    'result':result}
        fields = {
            'facts.source.begin': {'idempotencyKey','mode','scopeMembers',
                                   'scopeAll','expectedMetadataRevision',
                                   'expectedDataRevision'},
            'facts.source.append': {'batchId','chunkIndex','rows'},
            'facts.source.csv.append': {'batchId','chunkIndex','csvText'},
            'facts.source.seal': {'batchId','expectedRows',
                                  'expectedContentDigest'},
            'facts.source.cancel': {'batchId'},
            'facts.source.preview': ({'batchId'},
                                     {'batchId', 'allowWarnings'}),
            'facts.source.publish': {'batchId','previewToken'},
        }
        if (not isinstance(program,dict)
                or set(program) != {'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] not in fields
                or not isinstance(program['arguments'],dict)
                or (set(program['arguments']) not in
                    (fields[program['function']]
                     if isinstance(fields[program['function']], tuple)
                     else (fields[program['function']],)))):
            raise ValueError('V2_SOURCE_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
        function = program['function']
        args = program['arguments']
        source = PostgresSourceBatch(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret)
        if function == 'facts.source.begin':
            result = source.begin(
                scope, idempotency_key=args['idempotencyKey'],
                mode=args['mode'], scope_members=args['scopeMembers'],
                scope_all=args['scopeAll'],
                expected_metadata_revision=args['expectedMetadataRevision'],
                expected_data_revision=args['expectedDataRevision'])
        elif function == 'facts.source.csv.append':
            result = source.append_csv(
                scope, args['batchId'], chunk_index=args['chunkIndex'],
                csv_text=args['csvText'])
        elif function == 'facts.source.append':
            raw_rows = args['rows']
            if not isinstance(raw_rows,list) or not 1 <= len(raw_rows) <= 500:
                raise ValueError('V2_SOURCE_ROWS_INVALID')
            rows = []
            for row in raw_rows:
                if (not isinstance(row,dict)
                        or set(row) != {'members','value','sourceRef'}
                        or not isinstance(row['value'],dict)
                        or row['value'].get('type') not in
                            ('AmountLiteral','TextLiteral',
                             'LineDetailLiteral')):
                    raise ValueError('V2_SOURCE_ROW_INVALID')
                literal=row['value']
                if literal['type']=='AmountLiteral':
                    if set(literal) != {'type','decimal'}:
                        raise ValueError('V2_SOURCE_ROW_INVALID')
                    rows.append({'members':row['members'],
                                 'amount':literal['decimal'],
                                 'sourceRef':row['sourceRef']})
                elif literal['type']=='TextLiteral':
                    if set(literal) != {'type','text'}:
                        raise ValueError('V2_SOURCE_ROW_INVALID')
                    rows.append({'members':row['members'],
                                 'text':literal['text'],
                                 'sourceRef':row['sourceRef']})
                else:
                    if (set(literal) != {'type','items'}
                            or not isinstance(literal['items'],list)):
                        raise ValueError('V2_SOURCE_ROW_INVALID')
                    items=[]
                    for item in literal['items']:
                        if (not isinstance(item,dict)
                                or set(item) != {'description','decimal'}):
                            raise ValueError('V2_SOURCE_ROW_INVALID')
                        items.append({'description':item['description'],
                                      'amount':item['decimal']})
                    rows.append({'members':row['members'],
                                 'detail':items,
                                 'sourceRef':row['sourceRef']})
            result = source.append(scope,args['batchId'],
                                   chunk_index=args['chunkIndex'],
                                   rows=rows)
        elif function == 'facts.source.seal':
            result = source.seal(
                scope,args['batchId'],expected_rows=args['expectedRows'],
                expected_content_digest=args['expectedContentDigest'])
        elif function == 'facts.source.cancel':
            result = source.cancel(scope, args['batchId'])
        elif function == 'facts.source.preview':
            result = source.preview(
                scope, args['batchId'],
                allow_warnings=args.get('allowWarnings', False))
        else:
            result = source.publish(
                scope,args['batchId'],preview_token=args['previewToken'])
        return {'languageVersion':2,'function':function,'result':result}

    def execute_read(self, scope: ApplicationScope, program: dict) -> dict:
        if (isinstance(program, dict)
                and program.get('function') == _CELL_EDITABILITY_READ):
            result = PostgresCellEditability(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2, 'function': _CELL_EDITABILITY_READ,
                    'result': result}
        if isinstance(program, dict) and program.get('function') == 'metadata.authoring.context':
            from .postgres_authoring_context import read_context
            return {'languageVersion': 2, 'function': 'metadata.authoring.context',
                    'result': read_context(self.dsn, scope, self.identity, program)}
        if (isinstance(program, dict) and program.get('function') in
                _SOURCE_EVIDENCE_READS):
            result = PostgresSourceEvidence(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict) and program.get('function') ==
                _SOURCE_EVIDENCE_CUTOVER_PREVIEW):
            result = PostgresSourceEvidenceCutover(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        function=program.get('function') if isinstance(program,dict) else None
        if function in _CALCULATION_INSPECTION_FUNCTIONS:
            result = PostgresCalculationInspection(
                self.dsn, identity=self.identity).execute(scope, program)
            return {'languageVersion': 2, 'function': function,
                    'result': result}
        if function in _RESOLVED_READ_FUNCTIONS:
            result = PostgresResolvedCubeReadPublic(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).execute(scope, program)
            return {'languageVersion': 2, 'function': function,
                    'result': result}
        if function == _OPERATION_RECEIPT_READ:
            result = PostgresOperationReceipts(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2, 'function': function,
                    'result': result}
        if function in _APPLICATION_ASSIGNMENT_READS:
            return self.execute_application_assignment(scope,program)
        if function in _APPLICATION_WORKFLOW_READS:
            return self.execute_application_workflow(scope,program)
        if function in _APPLICATION_WORKFLOW_OCCURRENCE_READS:
            return self.execute_application_workflow_occurrence(scope,program)
        if (isinstance(program,dict) and program.get('function') in
                (_GENERIC_AGGREGATE_REQUEST,_GENERIC_AGGREGATE_READ,
                 _GENERIC_AGGREGATE_CANCEL,_GENERIC_AGGREGATE_LINEAGE)):
            result=PostgresGenericAggregate(self.dsn,identity=self.identity,
                aggregate_service=self._aggregate_service()).execute(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_SELECTION_SEAL,_SEALED_SELECTION_READ)):
            result=PostgresSealedSelections(
                self.dsn,identity=self.identity).execute(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if isinstance(program, dict) and program.get('function') == _MEMBER_SELECT:
            result = PostgresMemberSelection(self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': _MEMBER_SELECT, 'result': result}
        if (isinstance(program,dict)
                and program.get('function')==_SELECTION_PREVIEW):
            result=PostgresSelectionPreview(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_MEMBER_LIST_READ,_MEMBER_LIST_LIST,
                 _MEMBER_LIST_EVALUATE)):
            result=PostgresMemberLists(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_APPLICABILITY_RELATION_READ,
                 _APPLICABILITY_RELATION_LIST)):
            result=PostgresApplicabilityRelations(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_SAVED_GRID_READ,_SAVED_GRID_LIST)):
            result=PostgresSavedGrids(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program, dict) and program.get('function') ==
                _HIERARCHY_RELATIONSHIPS_PREVIEW):
            result = PostgresHierarchyRelationshipPatch(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program,dict) and program.get('function')==
                _CONSOLIDATION_LAYOUT_READ):
            result=PostgresConsolidationLayout(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if (isinstance(program,dict) and program.get('function')==_CTA_READ):
            if (set(program)!={'languageVersion','function','arguments'}
                    or program.get('languageVersion')!=2
                    or not isinstance(program.get('arguments'),dict)
                    or set(program['arguments'])!={'bridgeId'}):
                raise ValueError('CTA_PUBLIC_PROGRAM_INVALID')
            result=PostgresCtaBridge(
                self.dsn,identity=self.identity).read(
                    scope,program['arguments']['bridgeId'])
            return {'languageVersion':2,'function':_CTA_READ,'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_CTA_CLOSE_HANDOFF):
            result=PostgresCtaCloseHandoff(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':_CTA_CLOSE_HANDOFF,
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') in _EXPORT_PAYLOAD_READS):
            result = PostgresExportPayload(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).execute_read_program(
                    scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') in _TRANSFER_ARTIFACT_READS):
            result = PostgresTransferArtifacts(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).execute_read_program(
                    scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') in _LAYOUT_REPLACE_FUNCTIONS):
            result = PostgresPopulatedLayoutReplacements(
                self.dsn, identity=self.identity).execute(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') in _LAYOUT_ACTIVATE_FUNCTIONS):
            result = PostgresPopulatedLayoutActivation(
                self.dsn, identity=self.identity).execute(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _POPULATED_LAYOUT_PREVIEW):
            result = PostgresPopulatedLayoutPreview(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _POPULATED_LAYOUT_PREVIEW, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _STATEMENT_RECONCILIATION_PREVIEW):
            result = PostgresStatementReconciliation(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _STATEMENT_RECONCILIATION_PREVIEW,
                    'result': result}
        if (isinstance(program,dict) and program.get('function')==
                _STATEMENT_PACK_PREVIEW):
            result=PostgresStatementPack(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':_STATEMENT_PACK_PREVIEW,
                    'result':result}
        if (isinstance(program,dict) and program.get('function')==
                _BOUND_STATEMENT_PACK_PREVIEW):
            result=PostgresBoundStatementPack(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,
                    'function':_BOUND_STATEMENT_PACK_PREVIEW,
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') == _FINANCIAL_CLOSE_READ):
            result = PostgresFinancialClose(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': _FINANCIAL_CLOSE_READ,
                    'result': result}
        if (isinstance(program,dict) and program.get('function') in
                (_PYTHON_ENVIRONMENT_READ,_PYTHON_ENVIRONMENT_LIST,
                 _PYTHON_ENVIRONMENT_PROFILE_LIST)):
            result=PostgresPythonEnvironments(self.dsn,identity=self.identity,
                approved_profiles=self.approved_python_profiles).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_DELEGATION_READ,_DELEGATION_LIST)):
            result=PostgresExecutionDelegations(self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_PLANNING_POLICY_READ,_PLANNING_POLICY_LIST)):
            result=PostgresPlanningWorkflowPolicies(
                self.dsn,identity=self.identity).read_program(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_STATEMENT_DEFINITION_READ,_STATEMENT_DEFINITION_LIST)):
            result=PostgresStatementDefinitions(
                self.dsn,identity=self.identity).read_program(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program, dict) and program.get('function') in
                (_PLANNING_OPERATION_POLICY_READ,
                 _PLANNING_OPERATION_POLICY_LIST)):
            result = PostgresPlanningOperationPolicies(
                self.dsn, identity=self.identity).read_program(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program,dict) and program.get('function') in
                (_INVENTORY_UNREALIZED_SCHEDULE_READ,
                 _INVENTORY_UNREALIZED_SCHEDULE_LIST)):
            result=PostgresInventoryUnrealizedSchedules(
                self.dsn,identity=self.identity).read_program(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program, dict) and program.get('function') in
                (_PYTHON_PROGRAM_READ, _PYTHON_PROGRAM_LIST)):
            registry = PostgresPythonPrograms(self.dsn, identity=self.identity)
            result = (registry.read(scope, program)
                      if program['function'] == _PYTHON_PROGRAM_READ
                      else registry.list(scope, program))
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program,dict) and program.get('function') in
                (_PYTHON_SCHEDULE_READ,_PYTHON_SCHEDULE_LIST,
                 _PYTHON_OCCURRENCE_READ)):
            result=PostgresPythonSchedules(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program, dict) and program.get('function') in
                ('facts.cube.aggregate.request','facts.cube.aggregate.read',
                 'facts.cube.aggregate.cancel')):
            function = program['function']
            if (set(program) != {'languageVersion', 'function', 'arguments'}
                    or type(program.get('languageVersion')) is not int
                    or program['languageVersion'] != 2
                    or type(program.get('arguments')) is not dict):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            args = program['arguments']
            if function == 'facts.cube.aggregate.request':
                if (set(args)-{'query','limits'} or 'query' not in args
                        or type(args['query']) is not dict
                        or ('limits' in args and type(args['limits']) is not dict)):
                    raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
                limits=args.get('limits',{})
                if set(limits)-{'maxGroups','maxResultBytes','pageSize','ttlSeconds'}:
                    raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
                try:
                    budgets=AggregateQueryBudgets(
                        limits.get('maxGroups',100000),
                        limits.get('maxResultBytes',33554432),
                        limits.get('pageSize',500),limits.get('ttlSeconds',900))
                except (TypeError,ValueError) as error:
                    raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED') from error
                dimensions,roles=self._aggregate_layout(scope)
                result=self._aggregate_service().request(scope,args['query'],
                    input_dimensions=dimensions,dimension_roles=roles,budgets=budgets)
            elif function == 'facts.cube.aggregate.cancel':
                if set(args) != {'queryId'} or type(args['queryId']) is not str:
                    raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
                result = self._aggregate_service().cancel(scope, args['queryId'])
            else:
                if (set(args) - {'queryId', 'cursor', 'pageSize'}
                        or 'queryId' not in args
                        or type(args['queryId']) is not str
                        or ('cursor' in args and type(args['cursor']) is not str)
                        or ('pageSize' in args and type(args['pageSize']) is not int)):
                    raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
                result = self._aggregate_service().read(scope, args['queryId'],
                    cursor=args.get('cursor'), page_size=args.get('pageSize'))
            return {'languageVersion': 2, 'function': function, 'result': result}
        if isinstance(program,dict) and program.get('function')==_COMPANY_NCI_INSPECT:
            return {'languageVersion':2,'function':_COMPANY_NCI_INSPECT,'result':PostgresCompanyNciInspector(self.dsn,identity=self.identity).read(scope,program)}
        if isinstance(program,dict) and isinstance(program.get('function'),str) and program['function'] in _PERIOD_BASIS_READS:
            result=PostgresPeriodNciBasis(self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if isinstance(program,dict) and isinstance(program.get('function'),str) and program['function'] in _PERIOD_GOVERNANCE_READS:
            result=PostgresPeriodPolicyGovernance(self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if isinstance(program,dict) and program.get('function') in (_PERIOD_CASE_EVALUATE,_PERIOD_CASE_READ):
            service=PostgresPeriodPolicyCases(self.dsn,identity=self.identity)
            result=(service.evaluate(scope,program) if program['function']==_PERIOD_CASE_EVALUATE else service.read(scope,program))
            return {'languageVersion':2,'function':program['function'],'result':result}
        if isinstance(program,dict) and program.get('function')==_CAPABILITY_HISTORY:
            return {'languageVersion':2,'function':_CAPABILITY_HISTORY,'result':
                PostgresApplicationCapabilities(self.dsn,identity=self.identity,
                    preview_secret=self.preview_secret).history(scope,program)}
        if isinstance(program,dict) and program.get('function')==_CAPABILITY_READ:
            return {'languageVersion':2,'function':_CAPABILITY_READ,'result':
                PostgresApplicationCapabilities(self.dsn,identity=self.identity,
                    preview_secret=self.preview_secret).read(scope,program)}
        if (isinstance(program,dict)
                and program.get('function')==_APPLICATION_STATE_READ):
            return {'languageVersion':2,'function':_APPLICATION_STATE_READ,
                'result':PostgresApplicationCapabilities(
                    self.dsn,identity=self.identity,
                    preview_secret=self.preview_secret).state_read(scope,program)}
        if isinstance(program,dict) and program.get('function')==_IDENTITY_READ:
            return {'languageVersion':2,'function':_IDENTITY_READ,'result':
                PostgresApplicationCapabilities(self.dsn,identity=self.identity,
                    preview_secret=self.preview_secret).identity_current(
                        scope,program)}
        if isinstance(program,dict) and program.get('function') in (_ACQ_READ,_ACQ_BALANCE):
            result=PostgresAcquisitionJournalHistory(self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if isinstance(program,dict) and program.get('function') in (
                _POLICY_ACTIVATION_READ,_POLICY_ACTIVATION_RESOLVE,
                _POLICY_ACTIVATION_CURRENT):
            result=PostgresPolicyActivation(self.dsn,identity=self.identity).read(
                scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if isinstance(program,dict) and program.get('function')==_POLICY_APPROVAL_READ:
            result=PostgresPolicyApprovals(self.dsn,identity=self.identity).read(
                scope,program)
            return {'languageVersion':2,'function':_POLICY_APPROVAL_READ,
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') == 'facts.export.page'):
            if (set(program) != {'languageVersion', 'function', 'arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion'] != 2
                    or not isinstance(program['arguments'], dict)
                    or set(program['arguments']) -
                    {'members', 'limit', 'cursor', 'snapshotRevision'}):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            args = program['arguments']
            result = PostgresFactExport(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).page(
                    scope, members=args.get('members'),
                    limit=args.get('limit', 50), cursor=args.get('cursor'),
                    snapshot_revision=args.get('snapshotRevision'))
            return {'languageVersion': 2, 'function': 'facts.export.page',
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _NCI_ATTRIBUTION_INSPECT):
            result = PostgresNciAttributionInspector(
                self.dsn, identity=self.identity).inspect(scope, program)
            return {'languageVersion': 2,
                    'function': _NCI_ATTRIBUTION_INSPECT, 'result': result}
        if isinstance(program,dict) and program.get('function')==_PERIOD_NCI_INSPECT:
            result=PostgresPeriodNciInspector(self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,'function':_PERIOD_NCI_INSPECT,'result':result}
        if (isinstance(program, dict)
                and program.get('function') == _ACQUISITION_NCI_INSPECT):
            result = PostgresAcquisitionNciInspector(
                self.dsn, identity=self.identity).inspect(scope, program)
            return {'languageVersion': 2,
                    'function': _ACQUISITION_NCI_INSPECT, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _ACQUISITION_STEP_INSPECT):
            result = PostgresAcquisitionStepInspector(
                self.dsn, identity=self.identity).inspect(scope, program)
            return {'languageVersion': 2,
                    'function': _ACQUISITION_STEP_INSPECT, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _POLICY_ACQUISITION_CASES_EVALUATE):
            result = PostgresPolicyCaseEvaluator(
                self.dsn, identity=self.identity).evaluate(scope, program)
            return {'languageVersion': 2,
                    'function': _POLICY_ACQUISITION_CASES_EVALUATE,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _POLICY_ACQUISITION_CASES_READ):
            result = PostgresPolicyCaseEvaluator(
                self.dsn, identity=self.identity).read_record(scope, program)
            return {'languageVersion': 2,
                    'function': _POLICY_ACQUISITION_CASES_READ,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _POLICY_ACQUISITION_REVIEW_READ):
            result = PostgresPolicyCaseReviews(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _POLICY_ACQUISITION_REVIEW_READ,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _POLICY_ACQUISITION_EVIDENCE_INSPECT):
            result = PostgresPolicyCaseReviews(
                self.dsn, identity=self.identity).inspect_evidence(
                    scope, program)
            return {'languageVersion': 2,
                    'function': _POLICY_ACQUISITION_EVIDENCE_INSPECT,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _POLICY_SOURCE_ARTIFACT_CLIENT_PDF_PAGE_READ):
            result = PostgresPolicySourceArtifacts(
                self.dsn,identity=self.identity).read_client_pdf_page(
                    scope,program)
            return {'languageVersion':2,
                    'function':_POLICY_SOURCE_ARTIFACT_CLIENT_PDF_PAGE_READ,
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') in
                (_POLICY_SOURCE_ARTIFACT_READ,
                 _POLICY_SOURCE_ARTIFACT_CONTENT_READ)):
            function = program['function']
            result = PostgresPolicySourceArtifacts(
                self.dsn, identity=self.identity).read(scope, program,
                    content=function == _POLICY_SOURCE_ARTIFACT_CONTENT_READ)
            return {'languageVersion': 2,
                    'function': function, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _IC_PAIR_INSPECT_FUNCTION):
            result = PostgresIntercompanyPairInspector(
                self.dsn, identity=self.identity).inspect(scope, program)
            return {'languageVersion': 2,
                    'function': _IC_PAIR_INSPECT_FUNCTION, 'result': result}
        if (isinstance(program,dict)
                and program.get('function')==_IC_RESIDUAL_RESOLUTION_FUNCTION):
            result=PostgresIntercompanyResidualResolution(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,
                    'function':_IC_RESIDUAL_RESOLUTION_FUNCTION,'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_CASH_FLOW_RECONCILIATION_INSPECT):
            result=PostgresCashFlowReconciliation(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,
                    'function':_CASH_FLOW_RECONCILIATION_INSPECT,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_EQUITY_ROLLFORWARD_INSPECT):
            result=PostgresEquityRollforward(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,
                    'function':_EQUITY_ROLLFORWARD_INSPECT,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_INVENTORY_UNREALIZED_PROFIT_INSPECT):
            result=PostgresInventoryUnrealizedProfit(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,
                    'function':_INVENTORY_UNREALIZED_PROFIT_INSPECT,
                    'result':result}
        if (isinstance(program,dict) and program.get('function')==_INVENTORY_UNREALIZED_READ):
            args=program.get('arguments') if set(program)=={'languageVersion','function','arguments'} else None
            if program.get('languageVersion')!=2 or not isinstance(args,dict) or set(args)!={'resultKey'}:
                raise ValueError('INVENTORY_UNREALIZED_READ_INVALID')
            result=PostgresInventoryUnrealizedPublication(
                self.dsn,identity=self.identity).read(scope,args['resultKey'])
            return {'languageVersion':2,'function':_INVENTORY_UNREALIZED_READ,'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_FIXED_ASSET_UNREALIZED_PROFIT_INSPECT):
            result=PostgresFixedAssetUnrealizedProfit(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,
                    'function':_FIXED_ASSET_UNREALIZED_PROFIT_INSPECT,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_DISPOSAL_MEASURE_INSPECT):
            result=PostgresDisposalCandidate(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,'function':_DISPOSAL_MEASURE_INSPECT,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_RETAINED_CONTROL_DISPOSAL_INSPECT):
            result=PostgresRetainedControlDisposal(
                self.dsn,identity=self.identity).inspect(scope,program)
            return {'languageVersion':2,
                    'function':_RETAINED_CONTROL_DISPOSAL_INSPECT,
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _IC_ELIMINATION_PREVIEW_FUNCTION):
            result = PostgresIntercompanyEliminationPreview(
                self.dsn, identity=self.identity).preview(scope, program)
            return {'languageVersion': 2,
                    'function': _IC_ELIMINATION_PREVIEW_FUNCTION,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _IC_ELIMINATION_READ_FUNCTION):
            result = PostgresIntercompanyElimination(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _IC_ELIMINATION_READ_FUNCTION,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _IC_ADJUSTED_BALANCE_READ_FUNCTION):
            result = PostgresIcAdjustedBalance(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _IC_ADJUSTED_BALANCE_READ_FUNCTION,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _FINANCIAL_POLICY_READ):
            result = PostgresFinancialMemberPolicy(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _FINANCIAL_POLICY_READ, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _CURRENCY_TRANSLATION_INSPECT):
            result = PostgresCurrencyTranslation(
                self.dsn, identity=self.identity).inspect(scope, program)
            return {'languageVersion': 2,
                    'function': _CURRENCY_TRANSLATION_INSPECT, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _CURRENCY_RATE_RESOLVE):
            result = PostgresCurrencyRates(
                self.dsn, identity=self.identity).resolve(scope, program)
            return {'languageVersion': 2,
                    'function': _CURRENCY_RATE_RESOLVE, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _CURRENCY_AMOUNT_TRANSLATE_PREVIEW):
            result = PostgresCurrencyAmountPreview(
                self.dsn, identity=self.identity).preview(scope, program)
            return {'languageVersion': 2,
                    'function': _CURRENCY_AMOUNT_TRANSLATE_PREVIEW,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _CURRENCY_SETTINGS_READ):
            result = PostgresCurrencySettings(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2,
                    'function': _CURRENCY_SETTINGS_READ, 'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _RULE_SEQUENCE_READ):
            result = PostgresExpressionSequence(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': _RULE_SEQUENCE_READ,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') in (
                    _EQUITY_CHAIN_INSPECT, _EQUITY_CHAIN_READ)):
            service = PostgresEquityRollforwardChain(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret)
            result = (service.inspect(scope, program)
                      if program['function'] == _EQUITY_CHAIN_INSPECT
                      else service.read(scope, program))
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') in (
                    _CASH_FLOW_PUBLICATION_INSPECT,
                    _CASH_FLOW_PUBLICATION_READ)):
            service = PostgresCashFlowPublication(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret)
            result = (service.inspect(scope, program)
                      if program['function'] ==
                        _CASH_FLOW_PUBLICATION_INSPECT
                      else service.read(scope, program))
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _FULL_SEQUENCE_READ):
            result = PostgresFullAggregateSequence(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': _FULL_SEQUENCE_READ,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') == _FULL_TREE_PLAN):
            result = PostgresFullTreePlanner(
                self.dsn, identity=self.identity).plan(scope, program)
            return {'languageVersion': 2, 'function': _FULL_TREE_PLAN,
                    'result': result}
        if isinstance(program,dict) and program.get('function')=='facts.cube.select':
            from .postgres_cube_select import PostgresCubeSelect
            result=PostgresCubeSelect(self.dsn,identity=self.identity,cursor_secret=self.preview_secret).select(scope,program)
            return {'languageVersion':2,'function':'facts.cube.select','result':result}
        from .postgres_saved_numeric_sequence import PostgresSavedNumericSequences, READ as saved_read, LIST as saved_list
        if isinstance(program,dict) and program.get('function') in (saved_read,saved_list):
            rules=PostgresSavedNumericSequences(self.dsn,identity=self.identity)
            result=(rules.read if program['function']==saved_read else rules.list_published)(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_CALCULATED_MEMBER_READ,_CALCULATED_MEMBER_LIST)):
            rules=PostgresCalculatedMembers(self.dsn,identity=self.identity)
            result=(rules.read if program['function']==_CALCULATED_MEMBER_READ
                    else rules.list_published)(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                _APPLICATION_DECISION_READS):
            result=PostgresApplicationDecisions(self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':program['function'],'result':result}
        if (isinstance(program,dict) and program.get('function') in
                (_APPLICATION_RULE_READ,_APPLICATION_RULE_LIST)):
            rules=PostgresApplicationRules(self.dsn,identity=self.identity)
            result=(rules.read if program['function']==_APPLICATION_RULE_READ
                    else rules.list_published)(scope,program)
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict) and program.get('function')==
                _APPLICATION_RULE_RUN_READ):
            from .postgres_application_rule_workflow import (
                PostgresApplicationRuleRun,parse_program)
            result=PostgresApplicationRuleRun(self.dsn,
                identity=self.identity,language=self).read(
                    scope,parse_program(program,_APPLICATION_RULE_RUN_READ))
            return {'languageVersion':2,'function':_APPLICATION_RULE_RUN_READ,
                    'result':result}
        if (isinstance(program,dict) and program.get('function')==
                _CALCULATED_MEMBER_EVALUATE):
            result=PostgresCalculatedMembers(
                self.dsn,identity=self.identity).evaluate(scope,program)
            return {'languageVersion':2,
                    'function':_CALCULATED_MEMBER_EVALUATE,'result':result}
        if isinstance(program, dict) and program.get('function') == _RULE_READ:
            result = PostgresExpressionRules(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2, 'function': _RULE_READ,
                    'result': result}
        if isinstance(program, dict) and program.get('function') == _RULE_LIST:
            result = PostgresExpressionRules(
                self.dsn, identity=self.identity).list_published(
                    scope, program)
            return {'languageVersion': 2, 'function': _RULE_LIST,
                    'result': result}
        if isinstance(program, dict) and program.get('function') in (
                _ATTRIBUTE_DEFINITION_LIST,
                _ATTRIBUTE_DEFINITION_USAGE,
                _ATTRIBUTE_VALUE_READ):
            result = PostgresAttributeCatalog(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if isinstance(program, dict) and program.get('function') in (
                _SEMANTIC_LIST, _SEMANTIC_READ,
                _REL_SEMANTIC_LIST, _REL_SEMANTIC_READ):
            result = PostgresSemanticAttributes(
                self.dsn, identity=self.identity).read(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _CONSOLIDATION_ASSESS_FUNCTION):
            result = PostgresConsolidationAssessment(
                self.dsn, identity=self.identity).assess(scope, program)
            return {'languageVersion': 2,
                    'function': _CONSOLIDATION_ASSESS_FUNCTION,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _CONSOLIDATION_METHOD_PREVIEW_FUNCTION):
            result = PostgresConsolidationAssessment(
                self.dsn, identity=self.identity).preview_method(scope, program)
            return {'languageVersion': 2,
                    'function': _CONSOLIDATION_METHOD_PREVIEW_FUNCTION,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _CONSOLIDATION_METHOD_COVERAGE):
            result = PostgresConsolidationMethodCoverage(
                self.dsn, identity=self.identity).inspect(scope, program)
            return {'languageVersion': 2,
                    'function': _CONSOLIDATION_METHOD_COVERAGE,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _PROPORTIONAL_CONTRIBUTION_PREVIEW):
            result = PostgresProportionalContributionPreview(
                self.dsn, identity=self.identity).preview(scope, program)
            return {'languageVersion': 2,
                    'function': _PROPORTIONAL_CONTRIBUTION_PREVIEW,
                    'result': result}
        if (isinstance(program, dict)
                and program.get('function') ==
                _EQUITY_METHOD_CONTRIBUTION_PREVIEW):
            result = PostgresEquityMethodContributionPreview(
                self.dsn, identity=self.identity).preview(scope, program)
            return {'languageVersion': 2,
                    'function': _EQUITY_METHOD_CONTRIBUTION_PREVIEW,
                    'result': result}
        if isinstance(program, dict) and program.get('function') in (
                _GENERIC_LIST, _GENERIC_READ, _GENERIC_SCAN,
                _GENERIC_SNAPSHOT_SCAN):
            result = PostgresGenericFacts(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': program['function'],
                    'result': result}
        if (isinstance(program,dict)
                and program.get('function')==_ADJUSTED_SCAN_FUNCTION):
            if (set(program)!={'languageVersion','function','arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion']!=2
                    or not isinstance(program['arguments'],dict)
                    or set(program['arguments']) -
                    {'members','limit','cursor','snapshotRevision'}):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            args=program['arguments']
            result=PostgresAdjustedScan(
                self.dsn,identity=self.identity,
                cursor_secret=self.preview_secret).scan_adjusted(
                    scope,members=args.get('members'),
                    limit=args.get('limit',100),cursor=args.get('cursor'),
                    snapshot_revision=args.get('snapshotRevision'))
            return {'languageVersion':2,'function':_ADJUSTED_SCAN_FUNCTION,
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') == _LAYER_REPORT_SCAN):
            result = PostgresCubeLayerReport(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).read(scope, program)
            return {'languageVersion': 2, 'function': _LAYER_REPORT_SCAN,
                    'result': result}
        if (isinstance(program,dict)
                and program.get('function') in
                (_JOURNAL_BALANCE_READ_FUNCTION,
                 _ADJUSTED_BALANCE_READ_FUNCTION)):
            function=program['function']
            result=PostgresManualJournal(
                self.dsn,identity=self.identity).read_balance(scope,program)
            return {'languageVersion':2,'function':function,'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_JOURNAL_READ_FUNCTION):
            result=PostgresManualJournal(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':_JOURNAL_READ_FUNCTION,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_POLICY_DRAFT_READ_FUNCTION):
            result=PostgresPolicyDrafts(
                self.dsn,identity=self.identity).read_effective(scope,program)
            return {'languageVersion':2,'function':_POLICY_DRAFT_READ_FUNCTION,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_POLICY_DRAFT_ELECTIONS_FUNCTION):
            result=PostgresPolicyDrafts(
                self.dsn,identity=self.identity).validate_elections(
                    scope,program)
            return {'languageVersion':2,
                    'function':_POLICY_DRAFT_ELECTIONS_FUNCTION,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_CALENDAR_READ_FUNCTION):
            result=PostgresCalendarPeriods(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':_CALENDAR_READ_FUNCTION,
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_OWNERSHIP_SCOPE_READ_FUNCTION):
            result=PostgresOwnershipValues(
                self.dsn,identity=self.identity).read_scope(scope,program)
            return {'languageVersion':2,
                    'function':_OWNERSHIP_SCOPE_READ_FUNCTION,'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_OWNERSHIP_READ_FUNCTION):
            result=PostgresOwnershipValues(
                self.dsn,identity=self.identity).read(scope,program)
            return {'languageVersion':2,'function':_OWNERSHIP_READ_FUNCTION,
                    'result':result}
        if (isinstance(program,dict) and program.get('function') in
                ('metadata.dimension.resolve','metadata.member.resolve')):
            fields={'metadata.dimension.resolve':{'reference'},
                    'metadata.member.resolve':{'dimension','reference'}}
            function=program['function']
            if (set(program) != {'languageVersion','function','arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion'] != 2
                    or not isinstance(program['arguments'],dict)
                    or set(program['arguments']) != fields[function]):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            metadata=PostgresMetadataStore(self.dsn,identity=self.identity)
            args=program['arguments']
            result=(metadata.resolve_dimension(scope,args['reference'])
                    if function == 'metadata.dimension.resolve'
                    else metadata.resolve_member(scope,args['dimension'],
                                                 args['reference']))
            return {'languageVersion':2,'function':function,'result':result}
        if isinstance(program, dict) and program.get('function') in NAMED_HIERARCHY_READS:
            if (set(program) != {'languageVersion', 'function', 'arguments'}
                    or type(program['languageVersion']) is not int or program['languageVersion'] != 2):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            metadata = PostgresMetadataStore(self.dsn, identity=self.identity)
            result = metadata.read_hierarchy(scope, program['function'], program['arguments'])
            return {'languageVersion': 2, 'function': program['function'], 'result': result}
        if (isinstance(program, dict) and program.get('function') in
                ('metadata.dimension.list', 'metadata.member.list',
                 'metadata.relationship.list','metadata.security-tag.list')):
            function = program['function']
            relationship = function == 'metadata.relationship.list'
            security_tag = function == 'metadata.security-tag.list'
            if relationship and isinstance(program.get('arguments'), dict):
                fields = set(program['arguments'])
                valid_relationship_args = (fields == {'cursor'} or
                    ('dimension' in fields and
                     fields <= {'dimension', 'status', 'limit', 'hierarchyId'}))
            else:
                valid_relationship_args = True
            required = ({'dimension'} if function in (
                            'metadata.member.list','metadata.security-tag.list')
                        else set())
            optional = ({'limit', 'expectedMetadataRevision',
                         ('cursor' if relationship else
                          'afterTagId' if security_tag else
                          'afterMemberId' if function == 'metadata.member.list'
                          else 'afterDimensionId')})
            if relationship:
                optional.update({'dimension', 'status', 'hierarchyId'})
            if security_tag:
                optional.add('status')
            if (set(program) != {'languageVersion', 'function', 'arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion'] != 2
                    or not isinstance(program['arguments'], dict)
                    or not valid_relationship_args
                    or not required <= set(program['arguments'])
                    or set(program['arguments']) - (required | optional)):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            args = program['arguments']
            metadata = PostgresMetadataStore(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret if relationship else None)
            common = {'limit': args.get('limit', 100),
                      'expected_metadata_revision':
                          args.get('expectedMetadataRevision')}
            if function == 'metadata.dimension.list':
                result = metadata.list_dimensions(
                    scope, after_dimension_id=args.get('afterDimensionId'),
                    **common)
            elif function == 'metadata.member.list':
                result = metadata.list_members(
                    scope, args['dimension'],
                    after_member_id=args.get('afterMemberId'), **common)
            elif function == 'metadata.security-tag.list':
                result=metadata.list_security_tags(
                    scope,args['dimension'],status=args.get('status'),
                    after_tag_id=args.get('afterTagId'),**common)
            else:
                result = metadata.list_relationships(
                    scope, args.get('dimension'), status=args.get('status'),
                    limit=args.get('limit', 100), cursor=args.get('cursor'),
                    hierarchy_id=args.get('hierarchyId'))
            return {'languageVersion': 2, 'function': function,
                    'result': result}
        if (isinstance(program,dict)
                and program.get('function')==_CUBE_WRITE_SCOPE_READ):
            if (set(program)!={'languageVersion','function','arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion']!=2
                    or not isinstance(program['arguments'],dict)
                    or set(program['arguments'])!={'lockId'}):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            result=PostgresPlanningLocks(
                self.dsn,identity=self.identity,
                preview_secret=self.preview_secret).read(
                    scope,program['arguments']['lockId'])
            return {'languageVersion':2,'function':program['function'],
                    'result':result}
        if (isinstance(program,dict)
                and program.get('function')==_CUBE_WRITE_SCOPE_WORKLIST):
            optional={'limit','afterLockId','includeResolved'}
            if (set(program)!={'languageVersion','function','arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion']!=2
                    or not isinstance(program['arguments'],dict)
                    or set(program['arguments'])-optional):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            args=program['arguments']
            result=PostgresPlanningLocks(
                self.dsn,identity=self.identity,
                preview_secret=self.preview_secret).worklist(
                    scope,limit=args.get('limit',100),
                    after_lock_id=args.get('afterLockId'),
                    include_resolved=args.get('includeResolved',False))
            return {'languageVersion':2,
                    'function':program['function'],'result':result}
        if (isinstance(program, dict)
                and program.get('function') == 'facts.calculation.read'):
            if (set(program) != {'languageVersion', 'function', 'arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion'] != 2
                    or not isinstance(program['arguments'], dict)
                    or set(program['arguments']) != {'resultKey'}):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            result = PostgresScaleReader(
                self.dsn, identity=self.identity).read_published(
                    scope, program['arguments']['resultKey'])
            return {'languageVersion': 2,
                    'function': 'facts.calculation.read', 'result': result}
        if (isinstance(program,dict) and program.get('function')==
                'facts.calculation.publication.list'):
            args=(program.get('arguments') if
                  set(program)=={'languageVersion','function','arguments'}
                  and program.get('languageVersion')==2 else None)
            if (not isinstance(args,dict) or set(args)-
                    {'limit','afterResultKey'}):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            result=PostgresScaleReader(
                self.dsn,identity=self.identity).list_published(
                    scope,limit=args.get('limit',100),
                    after_result_key=args.get('afterResultKey'))
            return {'languageVersion':2,
                    'function':'facts.calculation.publication.list',
                    'result':result}
        if (isinstance(program, dict)
                and program.get('function') == _CALCULATION_SCAN_FUNCTION):
            if (set(program) != {'languageVersion', 'function', 'arguments'}
                    or type(program['languageVersion']) is not int
                    or program['languageVersion'] != 2
                    or not isinstance(program['arguments'], dict)
                    or (set(program['arguments']) != {'cursor'}
                        and (not {'resultKey'} <= set(program['arguments'])
                             or set(program['arguments']) -
                             {'resultKey', 'members', 'limit',
                              'includeZero'}))):
                raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
            args = program['arguments']
            result = PostgresCalculationScan(
                self.dsn, identity=self.identity,
                cursor_secret=self.preview_secret).scan_published(
                    scope, result_key=args.get('resultKey'),
                    members=args.get('members'), limit=args.get('limit'),
                    cursor=args.get('cursor'),
                    include_zero=args.get('includeZero', True))
            return {'languageVersion': 2,
                    'function': _CALCULATION_SCAN_FUNCTION,
                    'result': result}
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != 'facts.cube.scan'
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) - {'members', 'limit', 'cursor',
                                                 'snapshotRevision',
                                                 'includeMissing',
                                                 'includeZero'}):
            raise ValueError('V2_READ_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
        args = program['arguments']
        result = PostgresCubeQuery(
            self.dsn, identity=self.identity,
            cursor_secret=self.preview_secret).scan(
                scope, members=args.get('members'),
                limit=args.get('limit'), cursor=args.get('cursor'),
                snapshot_revision=args.get('snapshotRevision'),
                include_missing=args.get('includeMissing', False),
                include_zero=args.get('includeZero', True))
        return {'languageVersion': 2, 'function': 'facts.cube.scan',
                'result': result}

    @lock_busy_boundary
    def preview(self, scope: ApplicationScope, program: dict) -> dict:
        from .postgres_composite_fact_batch import FUNCTION as composite_function,preview as composite_preview
        if isinstance(program,dict) and program.get('function')==composite_function:
            return composite_preview(self,scope,program)
        from .postgres_line_detail_job import FUNCTION as detail_function, preview as detail_preview
        if isinstance(program,dict) and program.get('function')==_CTA_PREVIEW:
            if (set(program)!={'languageVersion','function','arguments'}
                    or program.get('languageVersion')!=2
                    or type(program.get('arguments')) is not dict):
                raise ValueError('CTA_PUBLIC_PROGRAM_INVALID')
            service=PostgresCtaBridge(self.dsn,identity=self.identity)
            version=program['arguments'].get('bridgeVersion')
            handler=(service.preview_v3 if version==3 else
                     service.preview_v2 if version==2 else service.preview)
            result=handler(
                    scope,program['arguments'])
            return {'languageVersion':2,'function':_CTA_PREVIEW,'result':result}
        if isinstance(program,dict) and program.get('function')==detail_function:
            return detail_preview(self,scope,program)
        from .postgres_projection_cleanup import FUNCTION as cleanup_function, preview as cleanup_preview
        if isinstance(program,dict) and program.get('function')==cleanup_function:
            return cleanup_preview(self,scope,program)
        from .postgres_fact_reconstruction_job import FUNCTION as recovery_function, preview as recovery_preview
        if isinstance(program, dict) and program.get('function') == recovery_function:
            return recovery_preview(self, scope, program)
        from .postgres_numeric_iteration import FUNCTION as iteration_function,preview as iteration_preview
        if isinstance(program,dict) and program.get('function')==iteration_function:
            return iteration_preview(self,scope,program)
        if isinstance(program,dict) and program.get('function')==_CURRENCY_AMOUNT_TRANSLATE_PUBLISH:
            return _currency_amount_publish_preview(self,scope,program)
        from .postgres_saved_numeric_sequence import RUN as saved_run,preview as preview_saved
        if isinstance(program,dict) and program.get('function')==saved_run:
            return preview_saved(self,scope,program)
        if isinstance(program, dict) and program.get('function') == 'facts.numeric.transform':
            from .postgres_numeric_transform import preview
            return preview(self, scope, program)
        if isinstance(program, dict) and program.get('function') == 'facts.numeric.sequence':
            from .postgres_numeric_sequence import preview
            return preview(self, scope, program)
        if isinstance(program,dict) and program.get('function') in (_PERIOD_ATTRIBUTION_PUBLISH,_PERIOD_ATTRIBUTION_WITHDRAW):
            return self._preview_period_attribution(scope,program)
        if isinstance(program,dict) and program.get('function')==_INVENTORY_UNREALIZED_REQUEST:
            doc,candidate,state=PostgresInventoryUnrealizedPublication(
                self.dsn,identity=self.identity).inspect(scope,program)
            revisions={key:state[key] for key in ('metadata_revision','data_revision','policy_revision')}
            token,digest=self._sign_preview(scope,_INVENTORY_UNREALIZED_REQUEST,doc,revisions)
            return {'languageVersion':2,'function':_INVENTORY_UNREALIZED_REQUEST,
                'programDigest':digest,'revisionVector':revisions,
                'candidate':candidate,'previewToken':token}
        if isinstance(program,dict) and program.get('function')==_CAPABILITY_CONFIGURE:
            return PostgresApplicationCapabilities(self.dsn,identity=self.identity,
                preview_secret=self.preview_secret).preview(scope,program)
        if isinstance(program,dict) and program.get('function')==_ACQ_POST:
            return self._preview_acquisition_journal(scope,program)
        if (isinstance(program,dict) and
                program.get('function')==_EXPRESSION_JOURNAL_PUBLISH):
            return self._preview_expression_journal(scope,program)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CALCULATION_TRANSLATION_PUBLISH):
            return self._preview_calculation_translation(scope,program)
        if (isinstance(program, dict)
                and program.get('function') == _TRANSLATED_FULL_FUNCTION):
            return self._preview_translated_full(scope,program)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CURRENCY_TRANSLATION_PUBLISH):
            return self._preview_translation(scope,program)
        if (isinstance(program, dict)
                and program.get('function') == _RULE_SEQUENCE_RUN):
            return PostgresExpressionSequence(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
        if (isinstance(program, dict)
                and program.get('function') == _EQUITY_CHAIN_REQUEST):
            return PostgresEquityRollforwardChain(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CASH_FLOW_PUBLICATION_REQUEST):
            return PostgresCashFlowPublication(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
        if (isinstance(program, dict)
                and program.get('function') == _FULL_SEQUENCE_RUN):
            return PostgresFullAggregateSequence(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
        if (isinstance(program, dict)
                and program.get('function') == _RULE_RUN):
            definition, pin = PostgresExpressionRules(
                self.dsn, identity=self.identity).resolve_published(
                    scope, program)
            return self._preview_expression(
                scope, definition, saved_rule=pin,
                preview_function=_RULE_RUN)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CALCULATED_MEMBER_MATERIALIZE):
            definition, pin = PostgresCalculatedMembers(
                self.dsn, identity=self.identity).prepare_materialization(
                    scope, program)
            return self._preview_expression(
                scope, definition, calculated_member=pin,
                preview_function=_CALCULATED_MEMBER_MATERIALIZE,
                request_digest=_canonical_digest(program))
        if (isinstance(program, dict)
                and program.get('function') ==
                _FULL_AGGREGATE_FUNCTION):
            return self._preview_full_aggregate(scope, program)
        if (isinstance(program, dict)
                and program.get('function') ==
                _FULL_CONTRIBUTION_FUNCTION):
            return self._preview_full_contribution(scope, program)
        if (isinstance(program, dict)
                and program.get('function') ==
                _TYPED_FULL_CONTRIBUTION_FUNCTION):
            return self._preview_full_contribution(scope,program,typed=True)
        if (isinstance(program,dict)
                and program.get('function')==_CERTIFIED_FULL_CONTRIBUTION):
            return self._preview_certified_full_contribution(scope,program)
        if (isinstance(program,dict)
                and program.get('function')==_EQUITY_METHOD_PUBLICATION):
            plan,candidate,state=PostgresEquityMethodPublication(
                self.dsn,identity=self.identity).inspect(scope,program)
            revisions={key:state[key] for key in
                ('metadata_revision','data_revision','policy_revision')}
            token,digest=self._sign_preview(scope,_EQUITY_METHOD_PUBLICATION,
                plan.document,revisions)
            return {'languageVersion':2,'function':_EQUITY_METHOD_PUBLICATION,
                'programDigest':digest,'revisionVector':revisions,
                'candidate':candidate,'previewToken':token}
        if (isinstance(program,dict)
                and program.get('function')==_PROPORTIONAL_PUBLICATION):
            plan,candidate,state=PostgresProportionalPublication(
                self.dsn,identity=self.identity).inspect(scope,program)
            revisions={key:state[key] for key in
                ('metadata_revision','data_revision','policy_revision')}
            token,digest=self._sign_preview(scope,_PROPORTIONAL_PUBLICATION,
                plan.document,revisions)
            return {'languageVersion':2,'function':_PROPORTIONAL_PUBLICATION,
                'programDigest':digest,'revisionVector':revisions,
                'candidate':candidate,'previewToken':token}
        if (isinstance(program,dict)
                and program.get('function')==_METHOD_TOTAL_PUBLICATION):
            plan,candidate,state=PostgresConsolidationMethodTotal(
                self.dsn,identity=self.identity).inspect(scope,program)
            revisions={key:state[key] for key in
                ('metadata_revision','data_revision','policy_revision')}
            token,digest=self._sign_preview(scope,_METHOD_TOTAL_PUBLICATION,
                plan.document,revisions)
            return {'languageVersion':2,'function':_METHOD_TOTAL_PUBLICATION,
                'programDigest':digest,'revisionVector':revisions,
                'candidate':candidate,'previewToken':token}
        if (isinstance(program, dict)
                and program.get('function') == _ROLLUP_FUNCTION):
            return self._preview_rollup(scope, program)
        if (isinstance(program, dict)
                and program.get('function') == _GROUP_FUNCTION):
            return self._preview_group(scope, program)
        if (isinstance(program, dict)
                and program.get('function') == _BULK_GROUP_FUNCTION):
            return self._preview_bulk_group(scope, program)
        if (isinstance(program,dict)
                and program.get('function')==_ALLOCATION_FUNCTION):
            return self._preview_allocation(scope,program)
        if (isinstance(program,dict) and program.get('function') in
                _CUBE_WRITE_SCOPE_TRANSITIONS):
            return PostgresPlanningLocks(
                self.dsn,identity=self.identity,
                preview_secret=self.preview_secret).preview(scope,program)
        if (isinstance(program, dict) and program.get('function') in
                (_FINANCIAL_CLOSE_REQUEST, _FINANCIAL_CLOSE_REOPEN)):
            return PostgresFinancialClose(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).preview(scope, program)
        if isinstance(program,dict) and program.get('function') in (
                _SPREAD_FUNCTION,_CALENDAR_SPREAD_FUNCTION):
            return self._preview_spread(scope,program)
        if (isinstance(program, dict)
                and program.get('function') == _EXPRESSION_FUNCTION):
            return self._preview_expression(scope, program)
        if isinstance(program, dict) and program.get('function') == (
                'facts.numeric.scale'):
            return self._preview_scale(scope, program)
        if (isinstance(program, dict)
                and program.get('function') == 'facts.text.batch'):
            function = 'facts.text.batch'
            mutations = compile_text_program(program)
            normalized = _text_program(mutations)
        else:
            function = 'facts.numeric.batch'
            mutations = compile_numeric_program(program)
            normalized = _numeric_program(mutations)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                dimensions = db.execute('''SELECT dimension_id FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s AND status='Active'
                    AND model_role IS DISTINCT FROM 'Currency' ''',
                    (scope.workspace_id, scope.application_id)).fetchall()
                active_axes = {row['dimension_id'] for row in dimensions}
                if any(set(dict(item.coordinate.members)) != active_axes
                       for item in mutations):
                    raise ValueError('COORDINATE_DIMENSIONS_MISMATCH')
                pairs = list({(dimension, member)
                              for item in mutations
                              for dimension, member in item.coordinate.members})
                found = db.execute('''SELECT input.dimension_id,input.member_id,
                    m.member_id IS NOT NULL AS active
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS input(dimension_id text,member_id text)
                    LEFT JOIN epm.member m ON m.workspace_id=%s
                    AND m.application_id=%s
                    AND m.dimension_id=input.dimension_id
                    AND m.member_id=input.member_id AND m.status='Active' ''',
                    (Jsonb([{'dimension_id': d, 'member_id': m}
                            for d, m in pairs]),
                     scope.workspace_id, scope.application_id)).fetchall()
                if any(not row['active'] for row in found):
                    raise ValueError('COORDINATE_MEMBER_UNAVAILABLE')
                current = db.execute('''SELECT input.series_key,c.members,
                    COALESCE(n.change_id,'') AS change_id,
                    COALESCE(t.change_id,'') AS text_change_id,
                    COALESCE(n.present,false) AS numeric_present,
                    COALESCE(t.present,false) AS text_present,
                    d.coordinate_id IS NOT NULL AS has_detail
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS input(series_key text)
                    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
                    AND c.application_id=%s AND c.series_key=input.series_key
                    LEFT JOIN epm.numeric_cell_current n ON
                    n.workspace_id=c.workspace_id
                    AND n.application_id=c.application_id
                    AND n.coordinate_id=c.coordinate_id
                    LEFT JOIN epm.text_cell_current t ON
                    t.workspace_id=c.workspace_id
                    AND t.application_id=c.application_id
                    AND t.coordinate_id=c.coordinate_id
                    LEFT JOIN epm.line_detail_current d ON
                    d.workspace_id=c.workspace_id
                    AND d.application_id=c.application_id
                    AND d.coordinate_id=c.coordinate_id''',
                    (Jsonb([{'series_key': item.coordinate.series_key}
                            for item in mutations]),
                     scope.workspace_id, scope.application_id)).fetchall()
                by_key = {row['series_key']: row for row in current}
                for item in mutations:
                    row = by_key[item.coordinate.series_key]
                    if row['members'] is not None and row['members'] != dict(
                            item.coordinate.members):
                        raise ValueError('COORDINATE_HASH_COLLISION')
                    change_id = (row['text_change_id'] if function ==
                                 'facts.text.batch' else row['change_id'])
                    if item.expected_change_id != change_id:
                        raise ValueError('STALE_CELL_CHANGE_ID')
                    if row['has_detail']:
                        raise ValueError('COORDINATE_HAS_LINE_DETAIL')
                    if (function == 'facts.numeric.batch'
                            and row['text_present']
                            and item.kind != MutationKind.CLEAR):
                        raise ValueError('COORDINATE_HAS_TEXT_VALUE')
                    if (function == 'facts.text.batch'
                            and row['numeric_present']
                            and item.kind != TextMutationKind.CLEAR):
                        raise ValueError('COORDINATE_HAS_NUMERIC_VALUE')
                from .postgres_planning_write_guard import (
                    enforce_active_planning_policy)
                from .postgres_dimensional_security_enforcement import (
                    authorize_coordinates)
                from .dimensional_security_policy import AccessKind
                actions = ({MutationKind.SET: 'Set', MutationKind.ADD: 'Add',
                            MutationKind.CLEAR: 'Clear'}
                           if function == 'facts.numeric.batch' else
                           {TextMutationKind.SET: 'Set',
                            TextMutationKind.CLEAR: 'Clear'})
                authorize_coordinates(
                    db, self.identity, scope,
                    (item.coordinate for item in mutations),
                    kind=AccessKind.WRITE)
                enforce_active_planning_policy(
                    db, scope,
                    writes=tuple((item.coordinate, actions[item.kind])
                                 for item in mutations),
                    workflow_role=access.role)
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        token, digest = self._sign_preview(
            scope, function, normalized, revisions)
        return {'languageVersion': 2, 'function': function,
                'programDigest': digest,
                'revisionVector': revisions, 'previewToken': token,
                'changedCount': len(mutations)}

    @lock_busy_boundary
    def replay_batch(self, scope: ApplicationScope, program: dict, *,
                     idempotency_key: str,
                     depends_on_job_ids: tuple[str, ...] = ()) -> dict | None:
        """Return an identical durable fact-batch job before a fresh preview.

        Browser and MCP transports can lose an acknowledgement after the job
        commits.  Replaying must therefore happen before current cell change
        IDs are previewed again; otherwise the successful first publication
        makes its own retry appear stale.
        """
        if (not isinstance(program,dict) or program.get('function') not in
                ('facts.numeric.batch','facts.text.batch')):
            return None
        function=program['function']
        mutations=(compile_text_program(program) if function=='facts.text.batch'
                   else compile_numeric_program(program))
        return PostgresJobQueue(self.dsn,identity=self.identity).replay_batch(
            scope,idempotency_key=idempotency_key,function_name=function,
            mutations=mutations,depends_on_job_ids=depends_on_job_ids)

    @lock_busy_boundary
    def replay_spread(self, scope: ApplicationScope, program: dict, *,
                      idempotency_key: str,
                      depends_on_job_ids: tuple[str,...] = ()) -> dict | None:
        """Rebuild an accepted spread with its original publication pin."""
        if (not isinstance(program,dict) or program.get('function') not in
                (_SPREAD_FUNCTION,_CALENDAR_SPREAD_FUNCTION)):
            return None
        function=program['function']
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                prior=db.execute('''SELECT function_name,normalized_program
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    self.identity.issuer,self.identity.subject_id,
                    idempotency_key)).fetchone()
                if prior is None:
                    return None
                if prior['function_name']!=function:
                    raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
                expected=prior['normalized_program'].get(
                    'expectedPublicationRevision')
                if type(expected) is not int or expected<0:
                    raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
                plan=(compile_calendar_spread_program(
                    db,scope,program,expected_publication_revision=expected)
                    if function==_CALENDAR_SPREAD_FUNCTION else
                    compile_spread_program(
                        program,expected_publication_revision=expected))
        return PostgresJobQueue(self.dsn,identity=self.identity).replay(
            scope,idempotency_key=idempotency_key,function_name=function,
            normalized_program=plan.normalized_program,
            compiler_version=(_CALENDAR_SPREAD_COMPILER
                              if function==_CALENDAR_SPREAD_FUNCTION
                              else _SPREAD_COMPILER),
            plan_digest=(_CALENDAR_SPREAD_PLAN_DIGEST
                         if function==_CALENDAR_SPREAD_FUNCTION
                         else _SPREAD_PLAN_DIGEST),
            depends_on_job_ids=depends_on_job_ids)

    @lock_busy_boundary
    def submit(self, scope: ApplicationScope, program: dict, *,
               preview_token: str, idempotency_key: str,
               depends_on_job_ids: tuple[str, ...] = (),
               _execution_authority: dict | None = None) -> dict:
        self._validate_signed_operation_id(scope, program, idempotency_key)
        from .postgres_job_origin import bind_public_operation
        _execution_authority = bind_public_operation(
            _execution_authority, scope, self.identity, program)
        from .postgres_composite_fact_batch import FUNCTION as composite_function,submit as composite_submit
        if isinstance(program,dict) and program.get('function')==composite_function:
            return composite_submit(self,scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,depends_on_job_ids=depends_on_job_ids,
                execution_authority=_execution_authority)
        from .postgres_line_detail_job import FUNCTION as detail_function, submit as detail_submit
        if (isinstance(program, dict) and program.get('function') in
                (_FINANCIAL_CLOSE_REQUEST, _FINANCIAL_CLOSE_REOPEN)):
            if depends_on_job_ids:
                raise ValueError('FINANCIAL_CLOSE_DEPENDENCIES_UNSUPPORTED')
            return PostgresFinancialClose(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).apply(
                    scope, program, preview_token=preview_token,
                    idempotency_key=idempotency_key)
        if isinstance(program,dict) and program.get('function')==detail_function:
            return detail_submit(self,scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=_execution_authority)
        from .postgres_projection_cleanup import FUNCTION as cleanup_function, submit as cleanup_submit
        if isinstance(program,dict) and program.get('function')==cleanup_function:
            return cleanup_submit(self,scope,program,preview_token,idempotency_key,depends_on_job_ids)
        from .postgres_fact_reconstruction_job import FUNCTION as recovery_function, submit as recovery_submit
        if isinstance(program, dict) and program.get('function') == recovery_function:
            return recovery_submit(self, scope, program, preview_token, idempotency_key, depends_on_job_ids)
        from .postgres_numeric_iteration import FUNCTION as iteration_function,submit as iteration_submit
        if isinstance(program,dict) and program.get('function')==iteration_function:
            return iteration_submit(self,scope,program,preview_token,idempotency_key,depends_on_job_ids,
                execution_authority=_execution_authority)
        from .postgres_saved_numeric_sequence import RUN as saved_run,submit as submit_saved
        if isinstance(program,dict) and program.get('function')==saved_run:
            return submit_saved(self,scope,program,preview_token,idempotency_key,depends_on_job_ids)
        if isinstance(program, dict) and program.get('function') in ('facts.numeric.sequence','facts.numeric.transform'):
            from .postgres_numeric_sequence import submit
            return submit(self, scope, program, preview_token, idempotency_key, depends_on_job_ids,
                execution_authority=_execution_authority)
        if isinstance(program,dict) and program.get('function') in (_PERIOD_ATTRIBUTION_PUBLISH,_PERIOD_ATTRIBUTION_WITHDRAW):
            return self._submit_period_attribution(scope,program,preview_token=preview_token,idempotency_key=idempotency_key,depends_on_job_ids=depends_on_job_ids)
        if isinstance(program,dict) and program.get('function')==_INVENTORY_UNREALIZED_REQUEST:
            if depends_on_job_ids:raise ValueError('INVENTORY_UNREALIZED_DEPENDENCIES_UNSUPPORTED')
            doc=_compile_inventory_unrealized(program)
            payload=self._unpack_preview(scope,_INVENTORY_UNREALIZED_REQUEST,preview_token)
            if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                or payload['programDigest']!=_canonical_digest(doc)):
                raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
            return PostgresInventoryUnrealizedPublication(
                self.dsn,identity=self.identity).admit(scope,program,idempotency_key=idempotency_key)
        if isinstance(program,dict) and program.get('function')==_CURRENCY_AMOUNT_TRANSLATE_PUBLISH:
            return _currency_amount_publish_submit(self,scope,program,preview_token,idempotency_key,depends_on_job_ids)
        if isinstance(program,dict) and program.get('function')==_CAPABILITY_CONFIGURE:
            if depends_on_job_ids:
                raise ValueError('APPLICATION_CAPABILITY_DEPENDENCIES_UNSUPPORTED')
            return PostgresApplicationCapabilities(self.dsn,identity=self.identity,
                preview_secret=self.preview_secret).apply(scope,program,
                    preview_token=preview_token,idempotency_key=idempotency_key)
        if isinstance(program,dict) and program.get('function')==_ACQ_POST:
            return self._submit_acquisition_journal(scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program,dict) and
                program.get('function')==_EXPRESSION_JOURNAL_PUBLISH):
            return self._submit_expression_journal(scope,program,
                preview_token=preview_token,idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CALCULATION_TRANSLATION_PUBLISH):
            return self._submit_calculation_translation(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') == _TRANSLATED_FULL_FUNCTION):
            return self._submit_translated_full(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CURRENCY_TRANSLATION_PUBLISH):
            return self._submit_translation(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') == _RULE_SEQUENCE_RUN):
            if depends_on_job_ids:
                raise ValueError('RULE_SEQUENCE_EXTERNAL_JOB_DEPENDENCY_UNSUPPORTED')
            return PostgresExpressionSequence(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).submit(
                    scope, program, preview_token=preview_token,
                    idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') == _EQUITY_CHAIN_REQUEST):
            if depends_on_job_ids:
                raise ValueError(
                    'EQUITY_CHAIN_EXTERNAL_JOB_DEPENDENCY_UNSUPPORTED')
            return PostgresEquityRollforwardChain(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).submit(
                    scope, program, preview_token=preview_token,
                    idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CASH_FLOW_PUBLICATION_REQUEST):
            if depends_on_job_ids:
                raise ValueError(
                    'CASH_FLOW_EXTERNAL_JOB_DEPENDENCY_UNSUPPORTED')
            return PostgresCashFlowPublication(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).submit(
                    scope, program, preview_token=preview_token,
                    idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') == _FULL_SEQUENCE_RUN):
            if depends_on_job_ids:
                raise ValueError('FULL_SEQUENCE_EXTERNAL_JOB_DEPENDENCY_UNSUPPORTED')
            return PostgresFullAggregateSequence(
                self.dsn, identity=self.identity,
                preview_secret=self.preview_secret).submit(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') == _RULE_RUN):
            definition, pin = PostgresExpressionRules(
                self.dsn, identity=self.identity).resolve_published(
                    scope, program)
            return self._submit_expression(
                scope, definition, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                saved_rule=pin, preview_function=_RULE_RUN)
        if (isinstance(program, dict)
                and program.get('function') ==
                _CALCULATED_MEMBER_MATERIALIZE):
            definition, pin = PostgresCalculatedMembers(
                self.dsn, identity=self.identity).prepare_materialization(
                    scope, program)
            return self._submit_expression(
                scope, definition, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                calculated_member=pin,
                preview_function=_CALCULATED_MEMBER_MATERIALIZE,
                request_digest=_canonical_digest(program))
        if (isinstance(program, dict)
                and program.get('function') ==
                _FULL_AGGREGATE_FUNCTION):
            return self._submit_full_aggregate(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') ==
                _FULL_CONTRIBUTION_FUNCTION):
            return self._submit_full_contribution(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') ==
                _TYPED_FULL_CONTRIBUTION_FUNCTION):
            return self._submit_full_contribution(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,typed=True)
        if (isinstance(program,dict)
                and program.get('function')==_CERTIFIED_FULL_CONTRIBUTION):
            return self._submit_certified_full_contribution(scope,program,
                preview_token=preview_token,idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program,dict)
                and program.get('function')==_EQUITY_METHOD_PUBLICATION):
            if depends_on_job_ids:raise ValueError('EQUITY_PUBLICATION_DEPENDENCIES_UNSUPPORTED')
            plan=compile_publication(program)
            payload=self._unpack_preview(scope,_EQUITY_METHOD_PUBLICATION,preview_token)
            if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                    or payload['programDigest']!=_canonical_digest(plan.document)):
                raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
            return PostgresEquityMethodPublication(
                self.dsn,identity=self.identity).admit(scope,program,
                    idempotency_key=idempotency_key)
        if (isinstance(program,dict)
                and program.get('function')==_PROPORTIONAL_PUBLICATION):
            if depends_on_job_ids:raise ValueError('PROPORTIONAL_PUBLICATION_DEPENDENCIES_UNSUPPORTED')
            plan=compile_proportional_publication(program)
            payload=self._unpack_preview(scope,_PROPORTIONAL_PUBLICATION,preview_token)
            if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                    or payload['programDigest']!=_canonical_digest(plan.document)):
                raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
            return PostgresProportionalPublication(
                self.dsn,identity=self.identity).admit(scope,program,
                    idempotency_key=idempotency_key)
        if (isinstance(program,dict)
                and program.get('function')==_METHOD_TOTAL_PUBLICATION):
            if depends_on_job_ids:raise ValueError('METHOD_TOTAL_DEPENDENCIES_UNSUPPORTED')
            plan=compile_method_total(program)
            payload=self._unpack_preview(scope,_METHOD_TOTAL_PUBLICATION,preview_token)
            if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                    or payload['programDigest']!=_canonical_digest(plan.document)):
                raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
            return PostgresConsolidationMethodTotal(
                self.dsn,identity=self.identity).admit(scope,program,
                    idempotency_key=idempotency_key)
        if (isinstance(program, dict)
                and program.get('function') == _ROLLUP_FUNCTION):
            return self._submit_rollup(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') == _GROUP_FUNCTION):
            return self._submit_group(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') == _BULK_GROUP_FUNCTION):
            return self._submit_bulk_group(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program,dict)
                and program.get('function')==_ALLOCATION_FUNCTION):
            return self._submit_allocation(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if isinstance(program,dict) and program.get('function') in (
                _SPREAD_FUNCTION,_CALENDAR_SPREAD_FUNCTION):
            return self._submit_spread(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids)
        if (isinstance(program, dict)
                and program.get('function') == _EXPRESSION_FUNCTION):
            return self._submit_expression(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=_execution_authority)
        if isinstance(program, dict) and program.get('function') == (
                'facts.numeric.scale'):
            return self._submit_scale(
                scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=_execution_authority)
        if (isinstance(program, dict)
                and program.get('function') == 'facts.text.batch'):
            function = 'facts.text.batch'
            mutations = compile_text_program(program)
            normalized = _text_program(mutations)
        else:
            function = 'facts.numeric.batch'
            mutations = compile_numeric_program(program)
            normalized = _numeric_program(mutations)
        queue = PostgresJobQueue(self.dsn, identity=self.identity)
        previous=queue.replay_batch(scope,idempotency_key=idempotency_key,
            function_name=function,mutations=mutations,
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=_execution_authority)
        if previous is not None:return previous
        payload = self._unpack_preview(scope, function, preview_token)
        if (set(payload) != {'scope', 'identity', 'function', 'programDigest',
                             'revisions', 'expiresAt'}
                or payload['programDigest'] != _canonical_digest(normalized)):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        submit = (queue.submit_text if function == 'facts.text.batch'
                  else queue.submit_numeric)
        return submit(
            scope, idempotency_key=idempotency_key, mutations=mutations,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=_execution_authority)

    def apply_planning_lock(self,scope: ApplicationScope,program: dict,*,
                            preview_token: str,
                            idempotency_key: str|None=None) -> dict:
        return PostgresPlanningLocks(
            self.dsn,identity=self.identity,
            preview_secret=self.preview_secret).apply(
                scope,program,preview_token=preview_token,
                idempotency_key=idempotency_key)

    def replay_planning_lock(self,scope: ApplicationScope,
                             program: dict,*,
                             idempotency_key: str|None=None) -> dict|None:
        return PostgresPlanningLocks(
            self.dsn,identity=self.identity,
            preview_secret=self.preview_secret).replay(
                scope,program,idempotency_key=idempotency_key)

    def _sign_preview(self, scope: ApplicationScope, function: str,
                      normalized: dict, revisions: dict,
                      *, extra: dict | None = None) -> tuple[str, str]:
        digest = _canonical_digest(normalized)
        payload = {'scope': [scope.workspace_id, scope.application_id],
                   'identity': [self.identity.issuer, self.identity.subject_id],
                   'function': function, 'programDigest': digest,
                   'revisions': revisions, 'expiresAt': int(time.time()) + 300,
                   **(extra or {})}
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False).encode('utf-8')
        signature = hmac.new(self.preview_secret, raw, sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).decode('ascii'), digest

    def _unpack_preview(self, scope: ApplicationScope, function: str,
                        preview_token: str, *, allow_expired: bool = False) -> dict:
        if not isinstance(preview_token, str) or len(preview_token) > 4096:
            raise ValueError('INVALID_V2_PREVIEW_TOKEN')
        try:
            packed = base64.b64decode(preview_token, altchars=b'-_',
                                      validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.preview_secret, raw, sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('INVALID_V2_PREVIEW_TOKEN') from error
        if (not isinstance(payload, dict)
                or payload.get('scope') != [scope.workspace_id,
                                            scope.application_id]
                or payload.get('identity') != [self.identity.issuer,
                                               self.identity.subject_id]
                or payload.get('function') != function
                or type(payload.get('expiresAt')) is not int
                or (not allow_expired and payload['expiresAt'] < time.time())
                or not isinstance(payload.get('revisions'), dict)
                or set(payload['revisions']) != {'metadata_revision',
                                                 'data_revision',
                                                 'policy_revision'}
                or any(type(value) is not int or value < 0
                       for value in payload['revisions'].values())):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        return payload

    def _preview_expression(self, scope: ApplicationScope,
                            program: dict, *,
                            saved_rule: dict | None = None,
                            driver_policy: dict | None = None,
                            calculated_member: dict | None = None,
                            preview_function: str = _EXPRESSION_FUNCTION,
                            request_digest: str | None = None) -> dict:
        if (isinstance(program, dict) and isinstance(program.get('arguments'), dict)
                and 'apportionmentDomain' in program['arguments']):
            if saved_rule or driver_policy or calculated_member or request_digest is not None:
                raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
            return self._preview_relation_apportionment(scope, program)
        if (isinstance(program, dict) and isinstance(program.get('arguments'), dict)
                and 'apportionment' in program['arguments']):
            if saved_rule or driver_policy or calculated_member or request_digest is not None:
                raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
            return self._preview_apportionment(scope, program)
        if (isinstance(program,dict)
                and isinstance(program.get('arguments'),dict)
                and 'reduceSelections' in program['arguments']):
            return self._preview_two_axis_hierarchy_reduction(scope,program)
        if (isinstance(program,dict)
                and isinstance(program.get('arguments'),dict)
                and 'reduceSelection' in program['arguments']):
            return self._preview_hierarchy_reduction(scope,program)
        if (isinstance(program,dict)
                and isinstance(program.get('arguments'),dict)
                and 'selection' in program['arguments']):
            return self._preview_currency_member_set(scope,program)
        syntax = compile_expression_program(
            program, expected_target_state_token=None,
            saved_rule=saved_rule, driver_policy=driver_policy,
            calculated_member=calculated_member)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                if saved_rule:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'rule_run')
                    verify_published_rule(db, scope, saved_rule, program)
                if calculated_member:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'rule_run')
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer = db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     syntax.result_key)).fetchone()
                expected = pointer['state_token'] if pointer else None
                inputs = resolve_published_inputs(db, scope,
                                                   syntax.expression)
                sealed_context=()
                if syntax.context_dependencies:
                    from .expression_context_dependencies import resolve
                    sealed_context=resolve(db,scope,syntax.context_dependencies)
                plan = compile_expression_program(
                    program, expected_target_state_token=expected,
                    published_inputs=inputs, saved_rule=saved_rule,
                    driver_policy=driver_policy,
                    sealed_context_dependencies=sealed_context or None,
                    calculated_member=calculated_member)
                if calculated_member:
                    from .postgres_calculated_members import (
                        verify_materialization_pin)
                    verify_materialization_pin(
                        db, scope, calculated_member, plan)
                count = expression_source_count(db, scope, plan,
                    identity=self.identity)
                enforce_expression_dimensional_security(
                    db, self.identity, scope, plan, count)
                compiler, plan_digest = compiler_for(plan)
                resource_class = ('medium'
                    if plan.applicability_domain and count > 500 else 'short')
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        token, digest = self._sign_preview(
            scope, preview_function, plan.normalized_program,
            revisions, extra={
                'expectedTargetStateToken': expected,
                'resourceClass': resource_class,
                **({'publishedInputs': list(inputs)} if inputs else {}),
                **({'contextDependencies':list(sealed_context)}
                   if sealed_context else {}),
                **({'requestDigest': request_digest}
                   if request_digest is not None else {})})
        return {'languageVersion': 2, 'function': preview_function,
                'programDigest': digest, 'revisionVector': revisions,
                'expectedTargetStateToken': expected,
                'compilerVersion': compiler, 'planDigest': plan_digest,
                'estimatedRows': count, 'engine': 'postgres_exact_sql',
                'resourceClass': resource_class,
                'rounding': 'half-even-final-8', 'previewToken': token,
                'publishedInputs': list(inputs),
                **({'contextDependencies':list(sealed_context)}
                   if sealed_context else {}),
                **({'savedRule': saved_rule} if saved_rule else {}),
                **({'calculatedMember': calculated_member}
                   if calculated_member else {})}

    def _submit_expression(self, scope: ApplicationScope,
                           program: dict, *, preview_token: str,
                           idempotency_key: str,
                           depends_on_job_ids: tuple[str, ...],
                           saved_rule: dict | None = None,
                           driver_policy: dict | None = None,
                           calculated_member: dict | None = None,
                           preview_function: str = _EXPRESSION_FUNCTION,
                           request_digest: str | None = None,
                           execution_authority: dict | None = None) -> dict:
        if (isinstance(program, dict) and (
                program.get('operation') == 'RelationApportionment'
                or isinstance(program.get('arguments'), dict)
                and 'apportionmentDomain' in program['arguments'])):
            if saved_rule or driver_policy or calculated_member or request_digest is not None:
                raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
            return self._submit_relation_apportionment(scope, program,
                preview_token=preview_token,idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=execution_authority)
        if (isinstance(program, dict) and (program.get('operation') == 'Apportionment'
                or isinstance(program.get('arguments'), dict)
                and 'apportionment' in program['arguments'])):
            if saved_rule or driver_policy or calculated_member or request_digest is not None:
                raise ValueError('EXPRESSION_APPORTIONMENT_REQUEST_INVALID')
            return self._submit_apportionment(scope, program, preview_token=preview_token,
                idempotency_key=idempotency_key, depends_on_job_ids=depends_on_job_ids,
                execution_authority=execution_authority)
        if (isinstance(program,dict)
                and program.get('hierarchyTwoAxisReductionContext') is not None):
            return self._submit_two_axis_hierarchy_reduction(scope,program,
                preview_token=preview_token,idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=execution_authority)
        if (isinstance(program,dict)
                and program.get('hierarchyReductionContext') is not None):
            return self._submit_hierarchy_reduction(scope,program,
                preview_token=preview_token,idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=execution_authority)
        if (isinstance(program,dict)
                and program.get('operation')=='CurrencyConvertMemberSet'):
            return self._submit_currency_member_set(scope,program,
                preview_token=preview_token,idempotency_key=idempotency_key,
                depends_on_job_ids=depends_on_job_ids,
                execution_authority=execution_authority)
        payload = self._unpack_preview(
            scope, preview_function, preview_token)
        base_fields = {'scope', 'identity', 'function', 'programDigest',
                       'revisions', 'expiresAt',
                       'expectedTargetStateToken'}
        optional = ({'requestDigest'} if request_digest is not None else set())
        allowed=base_fields|optional|{
            'publishedInputs','contextDependencies','resourceClass'}
        if (not (base_fields|optional) <= set(payload) or set(payload)-allowed
                or (request_digest is not None
                    and payload.get('requestDigest') != request_digest)
                or ('publishedInputs' in payload
                    and not isinstance(payload['publishedInputs'], list))
                or ('contextDependencies' in payload
                    and not isinstance(payload['contextDependencies'],list))
                or ('resourceClass' in payload
                    and payload['resourceClass'] not in ('short','medium'))):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan = compile_expression_program(
            program, expected_target_state_token=
            payload['expectedTargetStateToken'],
            published_inputs=tuple(payload['publishedInputs'])
            if 'publishedInputs' in payload else None,
            saved_rule=saved_rule, driver_policy=driver_policy,
            sealed_context_dependencies=tuple(payload['contextDependencies'])
                if 'contextDependencies' in payload else None,
            calculated_member=calculated_member)
        if (expression_references(plan.expression)
                and plan.published_inputs is None):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        if bool(plan.context_dependencies) != ('contextDependencies' in payload):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        resource_class = payload.get('resourceClass','short')
        if (plan.applicability_domain and 'resourceClass' not in payload
                or not plan.applicability_domain
                and resource_class != 'short'
                or plan.applicability_domain
                and resource_class not in ('short','medium')):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        if payload['programDigest'] != _canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        compiler, plan_digest = compiler_for(plan)
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(
            scope, idempotency_key=idempotency_key,
            function_name=_EXPRESSION_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=compiler,
            plan_digest=plan_digest,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class=resource_class,
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def _preview_hierarchy_reduction(self,scope:ApplicationScope,
                                     program:dict)->dict:
        normalize_hierarchy_reduction_request(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',(
                    scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                result_key=program['arguments']['resultKey']
                pointer=db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    result_key)).fetchone()
                expected=pointer['state_token'] if pointer else None
                plan=resolve_hierarchy_reduction(db,scope,program,state,
                    expected_target_state_token=expected)
                output_count=expression_source_count(db,scope,plan,
                    identity=self.identity)
                counts=hierarchy_reduction_cardinality(db,scope,plan)
                if counts['groupedOutputCount']!=output_count:
                    raise ValueError(
                        'EXPRESSION_HIERARCHY_REDUCTION_CARDINALITY_MISMATCH')
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(scope,_EXPRESSION_FUNCTION,
            plan.normalized_program,revisions,
            extra={'expectedTargetStateToken':expected})
        return {'languageVersion':2,'function':_EXPRESSION_FUNCTION,
            'programDigest':digest,'revisionVector':revisions,
            'expectedTargetStateToken':expected,
            'estimatedRows':counts['groupedOutputCount'],
            'estimatedPresentSources':counts['presentSourceCount'],
            'presentSourceCount':counts['presentSourceCount'],
            'groupedOutputCount':counts['groupedOutputCount'],
            'compiler':_HIERARCHY_REDUCTION_COMPILER,
            'engine':'postgres_exact_sql','rounding':'half-even-final-8',
            'sealedProgram':plan.normalized_program,'previewToken':token}

    def _preview_two_axis_hierarchy_reduction(self,scope:ApplicationScope,
                                               program:dict)->dict:
        normalize_two_axis_hierarchy_reduction_request(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id) WHERE s.workspace_id=%s
                    AND s.application_id=%s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                result_key=program['arguments']['resultKey']
                pointer=db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',(
                    scope.workspace_id,scope.application_id,result_key)).fetchone()
                expected=pointer['state_token'] if pointer else None
                plan=resolve_two_axis_hierarchy_reduction(db,scope,program,state,
                    expected_target_state_token=expected)
                output_count=expression_source_count(db,scope,plan,
                    identity=self.identity)
                counts=two_axis_hierarchy_reduction_cardinality(db,scope,plan)
                if counts['groupedOutputCount']!=output_count:
                    raise ValueError(
                        'EXPRESSION_HIERARCHY_TWO_AXIS_CARDINALITY_MISMATCH')
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(scope,_EXPRESSION_FUNCTION,
            plan.normalized_program,revisions,
            extra={'expectedTargetStateToken':expected})
        return {'languageVersion':2,'function':_EXPRESSION_FUNCTION,
            'programDigest':digest,'revisionVector':revisions,
            'expectedTargetStateToken':expected,
            'estimatedRows':counts['groupedOutputCount'],
            'estimatedPresentSources':counts['presentSourceCount'],
            'presentSourceCount':counts['presentSourceCount'],
            'groupedOutputCount':counts['groupedOutputCount'],
            'compiler':_TWO_AXIS_HIERARCHY_REDUCTION_COMPILER,
            'engine':'postgres_exact_sql','rounding':'half-even-final-8',
            'sealedProgram':plan.normalized_program,'previewToken':token}

    def _submit_hierarchy_reduction(self,scope:ApplicationScope,program:dict,
            *,preview_token:str,idempotency_key:str,
            depends_on_job_ids:tuple[str,...],
            execution_authority:dict|None=None)->dict:
        payload=self._unpack_preview(scope,_EXPRESSION_FUNCTION,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                'revisions','expiresAt','expectedTargetStateToken'}
                or payload['expectedTargetStateToken']!=program.get(
                    'expectedTargetStateToken')):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=validate_hierarchy_reduction_admission(
            program,payload['programDigest'])
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_EXPRESSION_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=_HIERARCHY_REDUCTION_COMPILER,
            plan_digest=_HIERARCHY_REDUCTION_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class='short',depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def _submit_two_axis_hierarchy_reduction(self,scope:ApplicationScope,
            program:dict,*,preview_token:str,idempotency_key:str,
            depends_on_job_ids:tuple[str,...],
            execution_authority:dict|None=None)->dict:
        payload=self._unpack_preview(scope,_EXPRESSION_FUNCTION,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                'revisions','expiresAt','expectedTargetStateToken'}
                or payload['expectedTargetStateToken']!=program.get(
                    'expectedTargetStateToken')):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=validate_two_axis_hierarchy_reduction_admission(
            program,payload['programDigest'])
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_EXPRESSION_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=_TWO_AXIS_HIERARCHY_REDUCTION_COMPILER,
            plan_digest=_TWO_AXIS_HIERARCHY_REDUCTION_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class='short',depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def _preview_relation_apportionment(self, scope, program):
        from .postgres_expression_apportionment import (
            normalize_relation_program, relation_admission_program,
            materialize_relation_requests, _current_state)
        from .expression_apportionment import (
            RELATION_COMPILER, RELATION_PLAN_DIGEST, input_coordinates,
            target_coordinates)
        from .postgres_dimensional_security_enforcement import authorize_coordinates
        from .dimensional_security_policy import AccessKind
        from .postgres_fact_batch import validate_coordinates
        from .postgres_planning_write_guard import enforce_active_planning_policy
        request = normalize_relation_program(program)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 15000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write',
                    function=_EXPRESSION_FUNCTION)
                state = _current_state(db, scope)
                pointer = db.execute("""SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s""", (
                    scope.workspace_id, scope.application_id,
                    request['resultKey'])).fetchone()
                expected = pointer['state_token'] if pointer else None
                groups, resolved = materialize_relation_requests(
                    db, scope, request)
                inputs = sorted({item for group in groups
                    for item in input_coordinates(group)},
                    key=lambda item: item.series_key)
                targets = sorted({item for group in groups
                    for item in target_coordinates(group)},
                    key=lambda item: item.series_key)
                declared = [{'ordinal': index,
                    'series_key': item.series_key,
                    'members': dict(item.members)}
                    for index, item in enumerate((*inputs, *targets), 1)]
                validate_coordinates(db, scope, declared)
                authorize_coordinates(db, self.identity, scope, inputs,
                                      kind=AccessKind.READ)
                authorize_coordinates(db, self.identity, scope, targets,
                                      kind=AccessKind.WRITE)
                enforce_active_planning_policy(db, scope,
                    writes=tuple((target, 'Set') for target in targets),
                    workflow_role=access.role)
                normalized = relation_admission_program(request,
                    expected_target_state_token=expected,
                    schema_epoch=state['schema_epoch'])
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        resource_class = 'medium' if len(targets) > 500 else 'short'
        token, program_digest = self._sign_preview(scope,
            _EXPRESSION_FUNCTION, normalized, revisions,
            extra={'expectedTargetStateToken': expected,
                   'schemaEpoch': state['schema_epoch'],
                   'resourceClass': resource_class})
        return {'languageVersion': 2, 'function': _EXPRESSION_FUNCTION,
            'programDigest': program_digest, 'revisionVector': revisions,
            'expectedTargetStateToken': expected,
            'schemaEpoch': state['schema_epoch'],
            'compilerVersion': RELATION_COMPILER,
            'planDigest': RELATION_PLAN_DIGEST,
            'estimatedRows': len(targets),
            'estimatedGroups': resolved['groupCount'],
            'engine': 'postgres_exact_rational_relation_apportionment',
            'rounding': 'relation-declared-quantum-largest-remainder',
            'resourceClass': resource_class,
            'sealedProgram': normalized, 'previewToken': token}

    def _submit_relation_apportionment(self, scope, program, *, preview_token,
            idempotency_key, depends_on_job_ids, execution_authority=None):
        from .postgres_expression_apportionment import (
            normalize_relation_program, relation_admission_program,
            validate_relation_admission, replay)
        from .expression_apportionment import (
            RELATION_COMPILER, RELATION_PLAN_DIGEST)
        previous = replay(self.dsn, self.identity, scope, program,
            idempotency_key=idempotency_key,
            dependencies=depends_on_job_ids,
            execution_authority=execution_authority)
        if previous is not None:
            return previous
        payload = self._unpack_preview(
            scope, _EXPRESSION_FUNCTION, preview_token)
        if set(payload) != {'scope', 'identity', 'function', 'programDigest',
                'revisions', 'expiresAt', 'expectedTargetStateToken',
                'schemaEpoch', 'resourceClass'}:
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        if program.get('languageVersion') == 2:
            program = relation_admission_program(
                normalize_relation_program(program),
                expected_target_state_token=
                    payload['expectedTargetStateToken'],
                schema_epoch=payload['schemaEpoch'])
        normalized = validate_relation_admission(
            program, payload['programDigest'])
        revisions = payload['revisions']
        resource_class = payload['resourceClass']
        if resource_class not in ('short', 'medium'):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(scope,
            idempotency_key=idempotency_key,
            function_name=_EXPRESSION_FUNCTION,
            normalized_program=normalized,
            compiler_version=RELATION_COMPILER,
            plan_digest=RELATION_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class=resource_class,
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def _preview_apportionment(self, scope, program):
        from .postgres_expression_apportionment import (
            normalize_program, admission_program, prepare, _current_state, COMPILER, PLAN_DIGEST)
        request = normalize_program(program)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=_EXPRESSION_FUNCTION)
                state = _current_state(db, scope)
                pointer = db.execute("""SELECT committed_revision AS published_revision FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s AND result_key=%s""",
                    (scope.workspace_id, scope.application_id, request['resultKey'])).fetchone()
                expected = pointer['published_revision'] if pointer else 0
                prepared = prepare(db, scope, self.identity, request, role=access.role)
                normalized = admission_program(request,
                    expected_publication_revision=expected, schema_epoch=state['schema_epoch'])
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        token, program_digest = self._sign_preview(scope, _EXPRESSION_FUNCTION,
            normalized, revisions, extra={'expectedPublicationRevision': expected,
                                         'schemaEpoch': state['schema_epoch']})
        return {'languageVersion': 2, 'function': _EXPRESSION_FUNCTION,
            'programDigest': program_digest, 'revisionVector': revisions,
            'expectedPublicationRevision': expected, 'schemaEpoch': state['schema_epoch'],
            'compilerVersion': COMPILER, 'planDigest': PLAN_DIGEST,
            'estimatedRows': len(prepared['rows']), 'engine': 'postgres_exact_rational_apportionment',
            'rounding': 'declared-quantum-largest-remainder',
            'sealedProgram': normalized, 'previewToken': token}

    def _submit_apportionment(self, scope, program, *, preview_token,
                              idempotency_key, depends_on_job_ids, execution_authority=None):
        from .postgres_expression_apportionment import (
            normalize_program, admission_program, validate_admission, replay, COMPILER, PLAN_DIGEST)
        previous = replay(self.dsn, self.identity, scope, program, idempotency_key=idempotency_key,
            dependencies=depends_on_job_ids, execution_authority=execution_authority)
        if previous is not None:
            return previous
        payload = self._unpack_preview(scope, _EXPRESSION_FUNCTION, preview_token)
        if set(payload) != {'scope', 'identity', 'function', 'programDigest',
                'revisions', 'expiresAt', 'expectedPublicationRevision', 'schemaEpoch'}:
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        if program.get('languageVersion') == 2:
            program = admission_program(normalize_program(program),
                expected_publication_revision=payload['expectedPublicationRevision'],
                schema_epoch=payload['schemaEpoch'])
        normalized = validate_admission(program, payload['programDigest'])
        if (normalized['expectedPublicationRevision'] != payload['expectedPublicationRevision']
                or normalized['schemaEpoch'] != payload['schemaEpoch']):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(scope,
            idempotency_key=idempotency_key, function_name=_EXPRESSION_FUNCTION,
            normalized_program=normalized, compiler_version=COMPILER, plan_digest=PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'], resource_class='short',
            depends_on_job_ids=depends_on_job_ids, execution_authority=execution_authority)

    def _preview_currency_member_set(self,scope:ApplicationScope,
                                     program:dict)->dict:
        if (set(program)!={'languageVersion','function','arguments'}
                or program.get('languageVersion')!=2
                or program.get('function')!=_EXPRESSION_FUNCTION):
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_REQUEST_INVALID')
        request=normalize_currency_member_set_request(program['arguments'])
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision,
                    s.schema_epoch FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id) WHERE s.workspace_id=%s
                    AND s.application_id=%s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                if state is None or state['status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer=db.execute('''SELECT committed_revision AS published_revision FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    request['resultKey'])).fetchone()
                expected=pointer['published_revision'] if pointer else 0
                sealed=resolve_currency_member_set(
                    db,scope,self.identity,request,state)
                contract=currency_member_set_preview_contract(sealed,
                    expected_publication_revision=expected)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(scope,_EXPRESSION_FUNCTION,
            contract['sealedProgram'],revisions,
            extra={'expectedPublicationRevision':expected})
        if digest!=contract['programDigest']:
            raise ValueError('EXPRESSION_CURRENCY_MEMBER_SET_DIGEST_MISMATCH')
        return {'languageVersion':2,'function':_EXPRESSION_FUNCTION,
            'programDigest':digest,'revisionVector':revisions,
            'expectedPublicationRevision':expected,
            'estimatedRows':contract['estimatedRows'],
            'compiler':_CURRENCY_MEMBER_SET_COMPILER,
            'engine':'postgres_exact_sql','rounding':'half-even-final-8',
            'sealedProgram':contract['sealedProgram'],'previewToken':token}

    def _submit_currency_member_set(self,scope:ApplicationScope,program:dict,
            *,preview_token:str,idempotency_key:str,
            depends_on_job_ids:tuple[str,...],
            execution_authority:dict|None=None)->dict:
        payload=self._unpack_preview(scope,_EXPRESSION_FUNCTION,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                'revisions','expiresAt','expectedPublicationRevision'}
                or payload['expectedPublicationRevision']!=program.get(
                    'expectedPublicationRevision')):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        normalized=validate_currency_member_set_admission(
            program,payload['programDigest'])
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_EXPRESSION_FUNCTION,normalized_program=normalized,
            compiler_version=_CURRENCY_MEMBER_SET_COMPILER,
            plan_digest=_CURRENCY_MEMBER_SET_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class='short',depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def _preview_scale(self, scope: ApplicationScope, program: dict) -> dict:
        syntax = compile_scale_program(
            program, expected_target_state_token=None)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer = db.execute('''SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     syntax.result_key)).fetchone()
                expected_token = pointer['state_token'] if pointer else None
                plan = compile_scale_program(
                    program,
                    expected_target_state_token=expected_token)
                candidate=_scale_candidate(db,scope,plan)
                enforce_scale_dimensional_security(
                    db,self.identity,scope,candidate)
                count=len(candidate)
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision', 'policy_revision')}
        token, digest = self._sign_preview(
            scope, 'facts.numeric.scale', plan.normalized_program, revisions,
            extra={'expectedTargetStateToken': expected_token})
        return {'languageVersion': 2, 'function': 'facts.numeric.scale',
                'programDigest': digest, 'revisionVector': revisions,
                'expectedTargetStateToken': expected_token,
                'engine': 'postgres_exact_sql',
                'rounding': 'half-even-8', 'estimatedRows': count,
                'previewToken': token}

    def _submit_scale(self, scope: ApplicationScope, program: dict, *,
                      preview_token: str, idempotency_key: str,
                      depends_on_job_ids: tuple[str, ...], execution_authority=None) -> dict:
        payload = self._unpack_preview(
            scope, 'facts.numeric.scale', preview_token)
        if (set(payload) != {'scope', 'identity', 'function', 'programDigest',
                             'revisions', 'expiresAt',
                             'expectedTargetStateToken'}):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan = compile_scale_program(
            program, expected_target_state_token=
            payload['expectedTargetStateToken'])
        if payload['programDigest'] != _canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(
            scope, idempotency_key=idempotency_key,
            function_name='facts.numeric.scale',
            normalized_program=plan.normalized_program,
            compiler_version=_SCALE_COMPILER,
            plan_digest=_SCALE_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids,
            execution_authority=execution_authority)

    def _preview_spread(self,scope: ApplicationScope,program: dict) -> dict:
        function=program['function']
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                compile_plan=(lambda state_token:
                    compile_calendar_spread_program(
                        db,scope,program,
                        expected_target_state_token=state_token)
                    if function==_CALENDAR_SPREAD_FUNCTION else
                    compile_spread_program(
                        program,expected_target_state_token=state_token))
                syntax=compile_plan(None)
                pointer=db.execute('''SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected_pointer=(pointer['state_token']
                                  if pointer else None)
                plan=compile_plan(expected_pointer)
                source=validate_spread_inputs(db,scope,plan)
                enforce_spread_dimensional_security(
                    db,self.identity,scope,plan)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(
            scope,function,plan.normalized_program,revisions,
            extra={'expectedTargetStateToken':expected_pointer})
        return {'languageVersion':2,'function':function,
                'programDigest':digest,'revisionVector':revisions,
                'expectedTargetStateToken':expected_pointer,
                'sourceAmount':format(source['amount'],'f'),
                'targetCount':len(plan.target_members),
                'conservesSourceTotal':True,
                'engine':'postgres_exact_sql','previewToken':token}

    def _submit_spread(self,scope: ApplicationScope,program: dict,*,
                       preview_token: str,idempotency_key: str,
                       depends_on_job_ids: tuple[str,...]) -> dict:
        function=program['function']
        payload=self._unpack_preview(scope,function,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                           'revisions','expiresAt',
                           'expectedTargetStateToken'}):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        if function==_CALENDAR_SPREAD_FUNCTION:
            with connect_postgres(self.dsn,row_factory=dict_row) as db:
                with db.transaction():
                    PostgresNumericFactStore._set_scope(db,scope)
                    PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                    PostgresAccessChecker.check_in_transaction(
                        db,self.identity,scope,'write')
                    plan=compile_calendar_spread_program(
                        db,scope,program,expected_target_state_token=
                            payload['expectedTargetStateToken'])
        else:
            plan=compile_spread_program(
                program,expected_target_state_token=
                    payload['expectedTargetStateToken'])
        if payload['programDigest']!=_canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=function,
            normalized_program=plan.normalized_program,
            compiler_version=(_CALENDAR_SPREAD_COMPILER
                              if function==_CALENDAR_SPREAD_FUNCTION
                              else _SPREAD_COMPILER),
            plan_digest=(_CALENDAR_SPREAD_PLAN_DIGEST
                         if function==_CALENDAR_SPREAD_FUNCTION
                         else _SPREAD_PLAN_DIGEST),
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _preview_allocation(self,scope: ApplicationScope,
                            program: dict) -> dict:
        syntax=compile_allocation_program(
            program,expected_target_state_token=None)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer=db.execute('''SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected_pointer=(pointer['state_token']
                                  if pointer else None)
                plan=compile_allocation_program(
                    program,expected_target_state_token=expected_pointer)
                source,basis_total=validate_allocation_inputs(
                    db,scope,plan)
                enforce_allocation_dimensional_security(
                    db,self.identity,scope,plan)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(
            scope,_ALLOCATION_FUNCTION,plan.normalized_program,revisions,
            extra={'expectedTargetStateToken':expected_pointer})
        return {'languageVersion':2,'function':_ALLOCATION_FUNCTION,
                'programDigest':digest,'revisionVector':revisions,
                'expectedTargetStateToken':expected_pointer,
                'sourceAmount':format(source['amount'],'f'),
                'totalBasis':format(basis_total,'f'),
                'targetCount':len(plan.target_members),
                'conservesSourceTotal':True,
                'engine':'postgres_exact_sql','previewToken':token}

    def _submit_allocation(self,scope: ApplicationScope,program: dict,*,
                           preview_token: str,idempotency_key: str,
                           depends_on_job_ids: tuple[str,...]) -> dict:
        payload=self._unpack_preview(
            scope,_ALLOCATION_FUNCTION,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                           'revisions','expiresAt',
                           'expectedTargetStateToken'}):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=compile_allocation_program(
            program,expected_target_state_token=
                payload['expectedTargetStateToken'])
        if payload['programDigest']!=_canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_ALLOCATION_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=_ALLOCATION_COMPILER,
            plan_digest=_ALLOCATION_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _preview_rollup(self, scope: ApplicationScope,
                        program: dict) -> dict:
        if (not isinstance(program, dict)
                or not isinstance(program.get('arguments'), dict)
                or not isinstance(program['arguments'].get('dimension'), str)):
            raise ValueError('V2_ROLLUP_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                hierarchy_state_token = current_hierarchy_state_token(
                    db, scope, program['arguments']['dimension'])
                syntax = compile_rollup_program(
                    program, hierarchy_state_token=hierarchy_state_token,
                    expected_target_state_token=None)
                pointer = db.execute('''SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     syntax.result_key)).fetchone()
                expected_token = pointer['state_token'] if pointer else None
                plan = compile_rollup_program(
                    program, hierarchy_state_token=hierarchy_state_token,
                    expected_target_state_token=expected_token)
                summary = validate_rollup_inputs(db, scope, plan)
                enforce_rollup_dimensional_security(
                    db,self.identity,scope,plan)
                revisions = {key: state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token, digest = self._sign_preview(
            scope, _ROLLUP_FUNCTION, plan.normalized_program, revisions,
            extra={'expectedTargetStateToken':expected_token,
                   'hierarchyStateToken':hierarchy_state_token})
        return {'languageVersion':2,'function':_ROLLUP_FUNCTION,
                'programDigest':digest,'revisionVector':revisions,
                'compilerVersion':(_ROLLUP_RECURSIVE_PLACEMENT_COMPILER
                    if plan.placement_paths else _ROLLUP_PLACEMENT_COMPILER
                    if plan.placement_ids else _ROLLUP_COMPILER),
                'expectedTargetStateToken':expected_token,
                'hierarchyStateToken':hierarchy_state_token,
                'sourceCount':summary['sourceCount'],
                'amount':format(summary['amount'],'f'),
                'target':summary['target'],
                'engine':'postgres_exact_sql','previewToken':token}

    def _preview_group(self, scope: ApplicationScope,
                       program: dict) -> dict:
        syntax=compile_group_program(
            program,expected_target_state_token=None)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer=db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected_token=pointer['state_token'] if pointer else None
                plan=compile_group_program(
                    program,expected_target_state_token=expected_token)
                summary=validate_group_inputs(db,scope,plan)
                enforce_group_dimensional_security(
                    db,self.identity,scope,plan)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(
            scope,_GROUP_FUNCTION,plan.normalized_program,revisions,
            extra={'expectedTargetStateToken':expected_token})
        return {'languageVersion':2,'function':_GROUP_FUNCTION,
                'programDigest':digest,'revisionVector':revisions,
                'expectedTargetStateToken':expected_token,
                'sourceCount':summary['sourceCount'],
                'amount':format(summary['amount'],'f'),
                'target':summary['target'],
                'engine':'postgres_exact_sql','previewToken':token}

    def _submit_group(self, scope: ApplicationScope, program: dict, *,
                      preview_token: str, idempotency_key: str,
                      depends_on_job_ids: tuple[str,...]) -> dict:
        payload=self._unpack_preview(scope,_GROUP_FUNCTION,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                           'revisions','expiresAt',
                           'expectedTargetStateToken'}):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=compile_group_program(
            program,expected_target_state_token=payload[
                'expectedTargetStateToken'])
        if payload['programDigest']!=_canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_GROUP_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=_GROUP_COMPILER,
            plan_digest=_GROUP_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _preview_bulk_group(self, scope: ApplicationScope,
                            program: dict) -> dict:
        syntax = compile_bulk_group(
            program, expected_target_state_token=None)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 20000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer = db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected_token = pointer['state_token'] if pointer else None
                plan = compile_bulk_group(
                    program,expected_target_state_token=expected_token)
                summary = validate_bulk_inputs(db,scope,plan)
                enforce_bulk_group_dimensional_security(
                    db,self.identity,scope,plan)
                revisions = {key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest = self._sign_preview(
            scope,_BULK_GROUP_FUNCTION,plan.normalized_program,revisions,
            extra={'expectedTargetStateToken':expected_token})
        return {'languageVersion':2,'function':_BULK_GROUP_FUNCTION,
                'programDigest':digest,'revisionVector':revisions,
                'expectedTargetStateToken':expected_token,
                'rowCount':summary['rowCount'],
                'sourceCount':summary['sourceCount'],
                'rows':[{'target':row['target'],
                         'amount':format(row['amount'],'.8f')}
                        for row in summary['rows']],
                'engine':'postgres_exact_sql','previewToken':token}

    def _submit_bulk_group(self, scope: ApplicationScope, program: dict, *,
                           preview_token: str, idempotency_key: str,
                           depends_on_job_ids: tuple[str,...]) -> dict:
        payload = self._unpack_preview(
            scope,_BULK_GROUP_FUNCTION,preview_token)
        if (set(payload) != {'scope','identity','function','programDigest',
                             'revisions','expiresAt',
                             'expectedTargetStateToken'}):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan = compile_bulk_group(program,
            expected_target_state_token=payload[
                'expectedTargetStateToken'])
        if payload['programDigest'] != _canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_BULK_GROUP_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=_BULK_GROUP_COMPILER,
            plan_digest=_BULK_GROUP_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _submit_rollup(self, scope: ApplicationScope, program: dict, *,
                       preview_token: str, idempotency_key: str,
                       depends_on_job_ids: tuple[str,...]) -> dict:
        payload = self._unpack_preview(
            scope, _ROLLUP_FUNCTION, preview_token)
        if (set(payload) != {'scope','identity','function','programDigest',
                             'revisions','expiresAt',
                             'expectedTargetStateToken',
                             'hierarchyStateToken'}
                or not isinstance(payload['hierarchyStateToken'],str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                    payload['hierarchyStateToken'])):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan = compile_rollup_program(
            program, hierarchy_state_token=payload['hierarchyStateToken'],
            expected_target_state_token=
                payload['expectedTargetStateToken'])
        if payload['programDigest'] != _canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(
            scope, idempotency_key=idempotency_key,
            function_name=_ROLLUP_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=(_ROLLUP_RECURSIVE_PLACEMENT_COMPILER
                              if plan.placement_paths else _ROLLUP_PLACEMENT_COMPILER
                              if plan.placement_ids else _ROLLUP_COMPILER),
            plan_digest=(_ROLLUP_RECURSIVE_PLACEMENT_PLAN_DIGEST
                         if plan.placement_paths else _ROLLUP_PLACEMENT_PLAN_DIGEST
                         if plan.placement_ids else _ROLLUP_PLAN_DIGEST),
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _preview_full_aggregate(self, scope: ApplicationScope,
                                program: dict) -> dict:
        syntax = compile_full_aggregate(
            program, expected_target_state_token=None)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=_FULL_AGGREGATE_FUNCTION)
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer = db.execute('''SELECT state_token
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     syntax.result_key)).fetchone()
                expected_pointer = (pointer['state_token']
                                    if pointer else None)
                plan = compile_full_aggregate(
                    program,
                    expected_target_state_token=expected_pointer)
                authorize_full_aggregate(
                    db,self.identity,scope,plan)
                summary = validate_full_aggregate(db, scope, plan)
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision',
                    'policy_revision')}
        token, digest = self._sign_preview(
            scope, _FULL_AGGREGATE_FUNCTION,
            plan.normalized_program, revisions,
            extra={'expectedTargetStateToken': expected_pointer})
        return {'languageVersion': 2,
                'function': _FULL_AGGREGATE_FUNCTION,
                'programDigest': digest, 'revisionVector': revisions,
                'expectedTargetStateToken': expected_pointer,
                'amount': format(summary['amount'], '.8f'),
                'sourceCount': len(summary['sources']),
                'sourceLayer': summary['sourceLayer'],
                'parentMembers': dict(summary['target'].members),
                'sources': summary['sources'],
                'accountingStage': plan.normalized_program[
                    'accountingStage'],
                'accountingPolicyStatus': 'Unreviewed',
                'engine': 'postgres_exact_sql',
                'previewToken': token}

    def _submit_full_aggregate(self, scope: ApplicationScope,
                               program: dict, *, preview_token: str,
                               idempotency_key: str,
                               depends_on_job_ids: tuple[str, ...]) -> dict:
        payload = self._unpack_preview(
            scope, _FULL_AGGREGATE_FUNCTION, preview_token)
        if (set(payload) != {'scope', 'identity', 'function',
                             'programDigest', 'revisions', 'expiresAt',
                             'expectedTargetStateToken'}
                or (payload['expectedTargetStateToken'] is not None and
                    not isinstance(payload['expectedTargetStateToken'],str))):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan = compile_full_aggregate(
            program, expected_target_state_token=
                payload['expectedTargetStateToken'])
        if payload['programDigest'] != _canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(
            scope, idempotency_key=idempotency_key,
            function_name=_FULL_AGGREGATE_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=full_compiler_for(plan)[0],
            plan_digest=full_compiler_for(plan)[1],
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _preview_translated_full(self, scope: ApplicationScope,
                                 program: dict) -> dict:
        syntax=compile_translated_full(
            program,expected_publication_revision=0)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write', function=_TRANSLATED_FULL_FUNCTION)
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer=db.execute('''SELECT committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected=(pointer['published_revision'] if pointer else 0)
                plan=compile_translated_full(
                    program,expected_publication_revision=expected)
                summary=validate_translated_full(db,scope,plan)
                enforce_translated_full_dimensional_security(
                    db, self.identity, scope, plan, summary)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(
            scope,_TRANSLATED_FULL_FUNCTION,
            plan.normalized_program,revisions,
            extra={'expectedPublicationRevision':expected})
        return {'languageVersion':2,'function':_TRANSLATED_FULL_FUNCTION,
            'programDigest':digest,'revisionVector':revisions,
            'expectedPublicationRevision':expected,
            'targetMembers':dict(summary['target'].members),
            'amount':format(summary['amount'],'.8f'),
            'sources':summary['sources'],
            'sourceLayer':plan.source_layer,
            'accountingStage':plan.accounting_stage,
            'accountingPolicyStatus':'Unreviewed',
            'previewToken':token}

    def _submit_translated_full(self, scope: ApplicationScope,
                                program: dict, *, preview_token: str,
                                idempotency_key: str,
                                depends_on_job_ids: tuple[str, ...]) -> dict:
        payload=self._unpack_preview(
            scope,_TRANSLATED_FULL_FUNCTION,preview_token)
        if (set(payload)!={'scope','identity','function',
                           'programDigest','revisions','expiresAt',
                           'expectedPublicationRevision'}
                or type(payload['expectedPublicationRevision']) is not int
                or payload['expectedPublicationRevision']<0):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=compile_translated_full(program,
            expected_publication_revision=payload[
                'expectedPublicationRevision'])
        if payload['programDigest']!=_canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_TRANSLATED_FULL_FUNCTION,
            normalized_program=plan.normalized_program,
            compiler_version=_TRANSLATED_FULL_COMPILER,
            plan_digest=_TRANSLATED_FULL_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class='medium',
            depends_on_job_ids=depends_on_job_ids)

    def _preview_calculation_translation(self,scope:ApplicationScope,
                                         program:dict) -> dict:
        syntax=compile_calculation_translation(
            program,expected_publication_revision=0)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write', function=_CALCULATION_TRANSLATION_PUBLISH)
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer=db.execute('''SELECT committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected=(pointer['published_revision'] if pointer else 0)
                plan=compile_calculation_translation(
                    program,expected_publication_revision=expected)
                summary=validate_calculation_translation(
                    db,scope,plan,self.identity,self.dsn)
                enforce_calculation_translation_dimensional_security(
                    db, self.identity, scope, plan, summary)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(
            scope,_CALCULATION_TRANSLATION_PUBLISH,
            plan.normalized_program,revisions,
            extra={'expectedPublicationRevision':expected})
        return {'languageVersion':2,
            'function':_CALCULATION_TRANSLATION_PUBLISH,
            'programDigest':digest,'revisionVector':revisions,
            'expectedPublicationRevision':expected,
            'sourceAmount':summary['sourceAmount'],
            'sourceLayer':plan.source_layer,
            'sourceBasis':plan.source_basis,
            'targetMembers':dict(summary['target'].members),
            'amount':format(summary['amount'],'.8f'),
            'exactAmount':summary['exactAmount'],
            'periods':summary['periods'],
            'accountingStage':plan.accounting_stage,
            'accountingPolicyStatus':'Unreviewed',
            'previewToken':token}

    def _submit_calculation_translation(self,scope:ApplicationScope,
                                        program:dict,*,preview_token:str,
                                        idempotency_key:str,
                                        depends_on_job_ids:tuple[str,...]
                                        ) -> dict:
        payload=self._unpack_preview(
            scope,_CALCULATION_TRANSLATION_PUBLISH,preview_token)
        if (set(payload)!={'scope','identity','function',
                           'programDigest','revisions','expiresAt',
                           'expectedPublicationRevision'}
                or type(payload['expectedPublicationRevision']) is not int
                or payload['expectedPublicationRevision']<0):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=compile_calculation_translation(program,
            expected_publication_revision=payload[
                'expectedPublicationRevision'])
        if payload['programDigest']!=_canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_CALCULATION_TRANSLATION_PUBLISH,
            normalized_program=plan.normalized_program,
            compiler_version=_CALCULATION_TRANSLATION_COMPILER,
            plan_digest=_CALCULATION_TRANSLATION_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class='medium',
            depends_on_job_ids=depends_on_job_ids)

    def _preview_translation(self, scope: ApplicationScope,
                             program: dict) -> dict:
        syntax=compile_translation(
            program,expected_publication_revision=0)
        inspection=PostgresCurrencyTranslation(
            self.dsn,identity=self.identity).inspect(
                scope,syntax.inspect_program,source_layer=syntax.source_layer,ic_parent=syntax.ic_parent)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write', function=_CURRENCY_TRANSLATION_PUBLISH, arguments={'sourceLayer':syntax.source_layer})
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(state[database]!=inspection[result]
                       for result,database in (
                        ('metadataRevision','metadata_revision'),
                        ('dataRevision','data_revision'),
                        ('policyRevision','policy_revision'))):
                    raise ValueError('STALE_TRANSLATION_INSPECTION')
                pointer=db.execute('''SELECT committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     syntax.result_key)).fetchone()
                expected=(pointer['published_revision'] if pointer else 0)
                plan=compile_translation(
                    program,expected_publication_revision=expected)
                target=target_coordinate(db,scope,plan)
                enforce_translation_dimensional_security(
                    db, self.identity, scope, inspection, target)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(
            scope,_CURRENCY_TRANSLATION_PUBLISH,
            plan.normalized_program,revisions,
            extra={'expectedPublicationRevision':expected})
        return {'languageVersion':2,
            'function':_CURRENCY_TRANSLATION_PUBLISH,
            'programDigest':digest,'revisionVector':revisions,
            'expectedPublicationRevision':expected,
            'sourceAmount':inspection['periods'][-1]['sourceAmount'],
            'targetMembers':dict(target.members),
            'amount':inspection['roundedAmount'],
            'exactAmount':inspection['exactAmount'],
            'accountingStage':plan.accounting_stage,
            **({'sourceLayer':plan.source_layer,'icParentEntityId':plan.ic_parent,'periods':inspection['periods']} if plan.source_layer else {}),
            'accountingPolicyStatus':'Unreviewed',
            'previewToken':token}

    def _submit_translation(self, scope: ApplicationScope,
                            program: dict, *, preview_token: str,
                            idempotency_key: str,
                            depends_on_job_ids: tuple[str, ...]) -> dict:
        payload=self._unpack_preview(
            scope,_CURRENCY_TRANSLATION_PUBLISH,preview_token)
        if (set(payload)!={'scope','identity','function',
                           'programDigest','revisions','expiresAt',
                           'expectedPublicationRevision'}
                or type(payload['expectedPublicationRevision']) is not int
                or payload['expectedPublicationRevision']<0):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=compile_translation(program,
            expected_publication_revision=payload[
                'expectedPublicationRevision'])
        if payload['programDigest']!=_canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_CURRENCY_TRANSLATION_PUBLISH,
            normalized_program=plan.normalized_program,
            compiler_version=_CURRENCY_TRANSLATION_COMPILER,
            plan_digest=_CURRENCY_TRANSLATION_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            resource_class='medium',
            depends_on_job_ids=depends_on_job_ids)

    def _preview_full_contribution(self, scope: ApplicationScope,
                                   program: dict,*,typed=False) -> dict:
        function=(_TYPED_FULL_CONTRIBUTION_FUNCTION if typed else
                  _FULL_CONTRIBUTION_FUNCTION)
        compile_plan=(compile_typed_full_contribution if typed else
                      compile_full_contribution)
        validate_plan=(validate_typed_full_contribution if typed else
                       validate_full_contribution)
        syntax = compile_plan(
            program, expected_publication_revision=0)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,
                    'admin' if typed else 'write',function=function)
                state = db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer = db.execute('''SELECT committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     syntax.result_key)).fetchone()
                expected_pointer = (pointer['published_revision']
                                    if pointer else 0)
                plan = compile_plan(
                    program,
                    expected_publication_revision=expected_pointer)
                summary = validate_plan(db, scope, plan)
                revisions = {key: state[key] for key in (
                    'metadata_revision', 'data_revision',
                    'policy_revision')}
        token, digest = self._sign_preview(
            scope,function,
            plan.normalized_program, revisions,
            extra={'expectedPublicationRevision': expected_pointer})
        return {'languageVersion': 2,
                'function':function,
                'programDigest': digest, 'revisionVector': revisions,
                'expectedPublicationRevision': expected_pointer,
                'sourceAmount': format(summary['sourceAmount'], '.8f'),
                'targetMembers': dict(summary['target'].members),
                'pown': format(summary['pown'], '.8f'),
                'effectivePcon': '100.00000000',
                'pconFallback': summary['pconFallback'],
                'accountingStage':('pre_nci_untranslated_ic_adjusted'
                    if typed and summary.get('sourceLayer')==
                       'raw_plus_ic_elimination' else
                    'pre_nci_untranslated_uneliminated'),
                'accountingPolicyStatus': 'Unreviewed',
                'engine': 'postgres_exact_sql',
                **({'outputUnit':summary['outputUnit']} if typed else {}),
                **({'policy':summary['policy']} if typed else {}),
                **({'sourceLayer':summary['sourceLayer'],
                    'icResultStateToken':plan.ic_result_state_token,
                    'sourceLookupLineage':summary['sourceLookupLineage']}
                   if typed and summary.get('sourceLayer')!= 'raw' else {}),
                'previewToken': token}

    def _preview_certified_full_contribution(self,scope,program):
        if (not isinstance(program,dict)
                or set(program)!={'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion']!=2
                or program['function']!=_CERTIFIED_FULL_CONTRIBUTION
                or not isinstance(program['arguments'],dict)
                or set(program['arguments'])!={'certificate'}):
            raise ValueError('CERTIFIED_CONTRIBUTION_PROGRAM_INVALID')
        certificate=program['arguments']['certificate']
        inspected=PostgresContributionInputPrivate(
            self.dsn,identity=self.identity).inspect(scope,certificate)
        plan=inspected['plan'];revisions=inspected['revisionVector']
        token,digest=self._sign_preview(scope,_CERTIFIED_FULL_CONTRIBUTION,
            plan.document,revisions)
        return {'languageVersion':2,'function':_CERTIFIED_FULL_CONTRIBUTION,
            'programDigest':digest,'revisionVector':revisions,
            'commitRevision':inspected['commitRevision'],
            'sourceCoordinateId':inspected['sourceCoordinateId'],
            'sourceAmount':plan.document['sourceAmount'],
            'targetMembers':plan.document['targetMembers'],
            'coefficient':plan.document['coefficient'],
            'methodPreviewDigest':plan.document['methodPreviewDigest'],
            'policy':plan.document['policy'],'accountingPolicyStatus':'Unreviewed',
            'previewToken':token}

    def _submit_full_contribution(self, scope: ApplicationScope,
                                  program: dict, *, preview_token: str,
                                  idempotency_key: str,
                                  depends_on_job_ids: tuple[str, ...],
                                  typed=False) -> dict:
        function=(_TYPED_FULL_CONTRIBUTION_FUNCTION if typed else
                  _FULL_CONTRIBUTION_FUNCTION)
        compile_plan=(compile_typed_full_contribution if typed else
                      compile_full_contribution)
        payload = self._unpack_preview(
            scope,function,preview_token)
        if (set(payload) != {'scope', 'identity', 'function',
                             'programDigest', 'revisions', 'expiresAt',
                             'expectedPublicationRevision'}
                or type(payload['expectedPublicationRevision']) is not int
                or payload['expectedPublicationRevision'] < 0):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan = compile_plan(
            program, expected_publication_revision=
                payload['expectedPublicationRevision'])
        if payload['programDigest'] != _canonical_digest(
                plan.normalized_program):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions = payload['revisions']
        return PostgresJobQueue(self.dsn, identity=self.identity).submit(
            scope, idempotency_key=idempotency_key,
            function_name=function,
            normalized_program=plan.normalized_program,
            compiler_version=(plan.compiler_version if typed else
                              _FULL_CONTRIBUTION_COMPILER),
            plan_digest=(plan.plan_digest if typed else
                         _FULL_CONTRIBUTION_PLAN_DIGEST),
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _submit_certified_full_contribution(self,scope,program,*,preview_token,
                                            idempotency_key,
                                            depends_on_job_ids):
        if depends_on_job_ids:
            raise ValueError('CERTIFIED_CONTRIBUTION_DEPENDENCIES_UNSUPPORTED')
        if (not isinstance(program,dict) or not isinstance(program.get('arguments'),dict)
                or set(program['arguments'])!={'certificate'}):
            raise ValueError('CERTIFIED_CONTRIBUTION_PROGRAM_INVALID')
        plan=compile_full_contribution_input(program['arguments']['certificate'])
        payload=self._unpack_preview(scope,_CERTIFIED_FULL_CONTRIBUTION,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                or payload['programDigest']!=_canonical_digest(plan.document)):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        return PostgresContributionInputPrivate(self.dsn,identity=self.identity).admit(
            scope,plan.document,idempotency_key=idempotency_key)

    def _preview_acquisition_journal(self,scope,program):
        normalized=compile_acquisition_journal(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin', function=_ACQ_POST)
                state=db.execute('''SELECT s.*,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s FOR SHARE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if not state or state['application_status']!='Active' or state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                lines,manifest=validate_acquisition_journal(db,scope,normalized,state)
                revisions={key:state[key] for key in ('metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(scope,_ACQ_POST,normalized,revisions)
        return {'languageVersion':2,'function':_ACQ_POST,'programDigest':digest,
            'revisionVector':revisions,'previewToken':token,'accountingStage':'AcquisitionInvestmentOffset',
            'fullFinancialCloseSupported':False,'manifest':manifest,
            'lines':[{'members':dict(point.members),'signedAmount':format(amount,'.8f'),'role':role}
                for point,amount,role in lines]}

    def _submit_acquisition_journal(self,scope,program,*,preview_token,idempotency_key,depends_on_job_ids):
        normalized=compile_acquisition_journal(program)
        payload=self._unpack_preview(scope,_ACQ_POST,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
                or payload['programDigest']!=_canonical_digest(normalized)):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,
            idempotency_key=idempotency_key,function_name=_ACQ_POST,normalized_program=normalized,
            compiler_version=_ACQ_COMPILER,plan_digest=_ACQ_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)

    def _preview_expression_journal(self,scope,program):
        normalized=compile_expression_journal(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,15000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,
                    scope,'admin',function=_EXPRESSION_JOURNAL_PUBLISH)
                state=db.execute('''SELECT s.*,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',(scope.workspace_id,
                        scope.application_id)).fetchone()
                if (not state or state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                lines,lineage=validate_expression_journal(
                    db,scope,normalized,state)
                revisions={key:state[key] for key in (
                    'metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(scope,_EXPRESSION_JOURNAL_PUBLISH,
            normalized,revisions)
        return {'languageVersion':2,'function':_EXPRESSION_JOURNAL_PUBLISH,
            'programDigest':digest,'revisionVector':revisions,
            'previewToken':token,'lineCount':len(lines),
            'unit':normalized['arguments']['lines'][0]['source']['expectedUnit'],
            'sourceResults':[{'resultKey':item['resultKey'],
                'resultStateToken':item['resultStateToken'],
                'resultContentDigest':item['resultContentDigest']}
                for item in lineage],
            'accountingPolicyInferred':False}

    def _submit_expression_journal(self,scope,program,*,preview_token,
                                   idempotency_key,depends_on_job_ids):
        normalized=compile_expression_journal(program)
        payload=self._unpack_preview(
            scope,_EXPRESSION_JOURNAL_PUBLISH,preview_token)
        if (set(payload)!={'scope','identity','function','programDigest',
                'revisions','expiresAt'} or
                payload['programDigest']!=_canonical_digest(normalized)):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        revisions=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,
            function_name=_EXPRESSION_JOURNAL_PUBLISH,
            normalized_program=normalized,
            compiler_version=_EXPRESSION_JOURNAL_COMPILER,
            plan_digest=_EXPRESSION_JOURNAL_PLAN_DIGEST,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=depends_on_job_ids)


    def _preview_period_attribution(self,scope,program):
        syntax=compile_attribution(program,expected_publication_revision=0)
        from .postgres_period_nci_publication import (
            _pointer,evidence_digest,existing_typed_storage_contract,
            source_contract_for,enforce_period_attribution_dimensional_security)
        from .postgres_period_policy_cases import PostgresPeriodPolicyCases
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=PostgresPeriodPolicyCases(self.dsn,identity=self.identity)._open(db,scope,syntax.function,'write')
                if state['processing_mode']!='Active' or state['application_status']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
                pointer=_pointer(db,scope,syntax.result_key)
                expected=pointer['published_revision'] if pointer else 0
                plan=compile_attribution(program,
                    expected_publication_revision=expected,
                    source_contract=existing_typed_storage_contract(pointer))
                summary=validate_attribution(db,scope,plan,state)
                enforce_period_attribution_dimensional_security(
                    db,self.identity,scope,plan,summary)
                source_digest=evidence_digest(summary['sourceEvidence']) if summary['sourceEvidence'] is not None else None
                plan=compile_attribution(program,expected_publication_revision=expected,expected_source_digest=source_digest,
                    source_contract=source_contract_for(summary['sourceEvidence']) if summary['sourceEvidence'] is not None else None)
                revisions={key:state[key] for key in ('metadata_revision','data_revision','policy_revision')}
        token,digest=self._sign_preview(scope,plan.function,plan.normalized_program,revisions,
            extra={'expectedPublicationRevision':expected,'expectedSourceDigest':source_digest}
                | ({'sourceContract':plan.source_contract} if plan.source_contract is not None else {}))
        return {'languageVersion':2,'function':plan.function,'programDigest':digest,'revisionVector':revisions,
            'expectedPublicationRevision':expected,'rows':summary['rows'],'sourceEvidence':summary['sourceEvidence'],
            'accountingStage':plan.accounting_stage,'previewToken':token}

    def _submit_period_attribution(self,scope,program,*,preview_token,idempotency_key,depends_on_job_ids):
        function=program['function'];payload=self._unpack_preview(scope,function,preview_token)
        fields={'scope','identity','function','programDigest','revisions','expiresAt','expectedPublicationRevision','expectedSourceDigest'}
        if set(payload) not in (fields,fields|{'sourceContract'}):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan=compile_attribution(program,expected_publication_revision=payload['expectedPublicationRevision'],expected_source_digest=payload['expectedSourceDigest'],source_contract=payload.get('sourceContract'))
        if payload['programDigest']!=_canonical_digest(plan.normalized_program):raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        rev=payload['revisions']
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,idempotency_key=idempotency_key,
            function_name=function,normalized_program=plan.normalized_program,compiler_version=plan.compiler_version,
            plan_digest=plan.plan_digest,expected_metadata_revision=rev['metadata_revision'],
            expected_data_revision=rev['data_revision'],expected_policy_revision=rev['policy_revision'],
            resource_class='medium',depends_on_job_ids=depends_on_job_ids)
