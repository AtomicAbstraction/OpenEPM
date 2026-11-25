"""Explicit owner-qualified contract lookup, without a service or catalogue.

Only the named owner-qualified shapes enter structural diagnostic preflight.
Other discovered partial schemas do not enter this allowlist implicitly.
"""
from copy import deepcopy
from functools import lru_cache

from .cube_aggregate_public_contract import FUNCTIONS as AGGREGATE_FUNCTIONS
from .current_python_contract import PROGRAM_MUTATIONS, PROGRAM_READS
from .postgres_calculated_members import (MATERIALIZE as CALCULATED_MEMBER_MATERIALIZE,
    READ_FUNCTIONS as CALCULATED_MEMBER_READS)
from .postgres_calendar import SET_FUNCTION as CALENDAR_SET
from .postgres_populated_layout_activation import (
    CANCEL as LAYOUT_ACTIVATION_CANCEL, REQUEST as LAYOUT_ACTIVATION_REQUEST)
from .postgres_populated_layout_replacement import (
    CANCEL as LAYOUT_REPLACEMENT_CANCEL, REQUEST as LAYOUT_REPLACEMENT_REQUEST)
from .postgres_adjusted_scan import PUBLIC_READS as ADJUSTED_READS
from .postgres_applicability_relations import WRITE_FUNCTIONS as APPLICABILITY_RELATION_EFFECTS
from .postgres_attribute_catalog import WRITE_FUNCTIONS as ATTRIBUTE_EFFECTS
from .postgres_calculation_inspection import (
    FUNCTIONS as CALCULATION_INSPECTION, RECALCULATE as CALCULATION_RECALCULATE)
from .postgres_calculation_scan import PUBLIC_READS as CALCULATION_READS
from .postgres_cell_editability import FUNCTION as CELL_EDITABILITY
from .postgres_line_detail_job import FUNCTION as LINE_DETAIL_REPLACE
from .postgres_cube_query import FUNCTION as RAW_CUBE_SCAN
from .postgres_cube_layer_report import FUNCTION as LAYER_REPORT
from .postgres_fact_export import FUNCTION as FACT_EXPORT_PAGE
from .postgres_generic_facts import READ_FUNCTIONS as GENERIC_FACT_READS
from .postgres_scenario_comparison import FUNCTION as SCENARIO_COMPARE
from .postgres_hierarchies import MUTATIONS as NAMED_HIERARCHY_MUTATIONS
from .postgres_metadata import (HIERARCHY_BUILD, MODEL_STATE_EDIT_FUNCTIONS,
                                SECURITY_TAG_EDIT_FUNCTIONS,
                                STRUCTURE_EDIT_FUNCTIONS as METADATA_STRUCTURE_EFFECTS,
                                VALUE_EDIT_FUNCTIONS as METADATA_VALUE_EFFECTS)
from .postgres_metadata_hierarchy_patch import APPLY as HIERARCHY_PATCH_APPLY
from .postgres_application_workflow_occurrences import MUTATIONS as WORKFLOW_OCCURRENCE_EFFECTS
from .postgres_member_lists import WRITE_FUNCTIONS as MEMBER_LIST_EFFECTS
from .postgres_source_evidence import (
    READ_FUNCTIONS as SOURCE_EVIDENCE_READS,
    WRITE_FUNCTIONS as SOURCE_EVIDENCE_WRITES,
)
from .postgres_identity_directory import (
    READ_FUNCTIONS as PLATFORM_DIRECTORY_READ_FUNCTIONS,
    WRITE_FUNCTIONS as PLATFORM_DIRECTORY_WRITE_FUNCTIONS,
)
from .postgres_python_schedules import (
    EFFECTS as PYTHON_SCHEDULE_EFFECTS, READS as PYTHON_SCHEDULE_READS)
from .postgres_python_environments import FUNCTIONS as PYTHON_ENVIRONMENT_FUNCTIONS
from .postgres_planning_workflow_policy import FUNCTIONS as CUBE_WRITE_POLICY_FUNCTIONS
from .postgres_planning_locks import FUNCTIONS as CUBE_WRITE_SCOPE_FUNCTIONS
from .postgres_application_decisions import FUNCTIONS as APPLICATION_DECISION_FUNCTIONS
from .postgres_scale import PUBLICATION_LIST, SCALE


READ_FUNCTIONS = frozenset(('application.state.read', 'security.identity.current.read',
    'application.workflow.activity.evidence.read', 'application.workflow.activity.evidence.list',
    'application.operation.receipt.read',
    'application.rule.list', 'application.rule.read', 'application.rule.run.read',
    'rules.expression.list', 'rules.expression.read', 'rules.expression.sequence.read',
    'metadata.dimension.list', 'metadata.dimension.resolve',
    'metadata.member.list', 'metadata.member.resolve', 'cube.selection.preview',
    'facts.slice.copy.status.read', RAW_CUBE_SCAN, SCENARIO_COMPARE, PUBLICATION_LIST,
    CELL_EDITABILITY, LAYER_REPORT, FACT_EXPORT_PAGE,
)) | (ADJUSTED_READS | CALCULATION_INSPECTION | CALCULATION_READS | PYTHON_SCHEDULE_READS
      | GENERIC_FACT_READS | CALCULATED_MEMBER_READS)
from .python_execution_contract import FUNCTIONS as EXECUTION_FUNCTIONS
from .postgres_saved_grids import FUNCTIONS as SAVED_GRID_FUNCTIONS

OPERATION_FUNCTIONS = frozenset(('facts.cube.select', 'facts.slice.copy.prepare',
    'facts.numeric.sequence', 'facts.numeric.iterate',
    'facts.projections.rebuild', 'facts.projections.cleanup',
    'facts.numeric.batch', 'facts.text.batch', 'facts.numeric.transform'))

WORKFLOW_NAVIGATION_FUNCTIONS = frozenset((
    'application.workflow.worklist', 'application.workflow.occurrence.read',
))

RULE_WORKFLOW_EFFECTS = frozenset((
    'application.rule.run', 'application.rule.run.cancel', 'application.rule.run.reconcile',
))

SELECTION_ARTIFACT_FUNCTIONS = frozenset(('cube.selection.seal', 'cube.selection.read'))

RESOLVED_READ_FUNCTIONS = frozenset('facts.cube.resolved.' + suffix
    for suffix in ('read', 'request', 'result.read', 'cancel', 'binding.list'))

IMPORT_EXECUTION_FUNCTIONS = frozenset('facts.transfer.import.' + suffix
    for suffix in ('request', 'read', 'cancel'))
IMPORT_DIAGNOSTIC_FUNCTIONS = frozenset('facts.transfer.import.diagnostics.' + suffix
    for suffix in ('read', 'list'))
SOURCE_STAGING_STATUS = 'facts.source.staging.read'
SOURCE_BATCH_STAGING_FUNCTIONS = frozenset((
    'facts.source.begin', 'facts.source.append', 'facts.source.csv.append', 'facts.source.seal',
))
SOURCE_LIFECYCLE_FUNCTIONS = frozenset((
    'facts.source.cancel', 'facts.source.publish', 'facts.source.diagnostics.compile',
))
SOURCE_MANIFEST_FUNCTIONS = frozenset(('facts.source.manifest.attach', 'facts.source.manifest.read'))
SOURCE_PREVIEW = 'facts.source.preview'
EXPORT_ORCHESTRATION_FUNCTIONS = frozenset('facts.transfer.export.' + suffix
    for suffix in ('request', 'read', 'cancel'))
EXPORT_MANIFEST_FUNCTIONS = frozenset('facts.transfer.export.manifest.' + suffix
    for suffix in ('read', 'list'))
EXPORT_PAYLOAD_PAGE = 'facts.transfer.export.payload.page'

ASSIGNMENT_FUNCTIONS = frozenset('application.assignment.' + suffix
    for suffix in ('save', 'activate', 'deactivate', 'read', 'list'))

WORKFLOW_DEFINITION_FUNCTIONS = frozenset('application.workflow.' + suffix
    for suffix in ('save', 'activate', 'deactivate', 'read', 'list'))

SCHEDULE_FUNCTIONS = frozenset('schedule.' + suffix
    for suffix in ('save', 'activate', 'deactivate', 'read', 'list'))

EXECUTION_DELEGATION_FUNCTIONS = frozenset('execution.delegation.' + suffix
    for suffix in ('create', 'revoke', 'read', 'list'))

APPLICATION_ACCESS_READ_FUNCTIONS = frozenset('security.application.' + suffix
    for suffix in ('access.list', 'group-access.list', 'subject.list', 'audit.list', 'receipt.read'))

APPLICATION_AUTHORIZATION_FUNCTIONS = frozenset('security.application.' + suffix for suffix in (
    'authorization.read', 'authorization.preview', 'authorization.apply',
    'access.explain', 'authorization.tags.list', 'authorization.objects.list',
    'effective-access.list', 'resource-access.list',
))

APPLICATION_GRANT_EFFECT_FUNCTIONS = frozenset((
    'security.application.access.set', 'security.application.group-access.set',
    'security.rule.access.set', 'security.rule.group-access.set'))

WORKSPACE_SECURITY_FUNCTIONS = frozenset((
    'security.workspace.access.set', 'security.workspace.group-access.set',
    'security.workspace.group-access.list','security.workspace.people.list',
    'security.workspace.person-applications.list','security.workspace.bootstrap-groups.list',
    'security.workspace.authorization-migration.review','security.workspace.authorization-migration.activate'))
WORKSPACE_PROVISIONING_FUNCTIONS = frozenset(('workspace.application.create',))
PLATFORM_PROVISIONING_FUNCTIONS = frozenset((
    'platform.workspace.create', 'platform.operation.receipt.read'))


def provisioning_field_schemas() -> tuple[dict, dict]:
    identifier = {'type': 'string', 'minLength': 1, 'maxLength': 200,
                  'pattern': r'^[A-Za-z0-9][A-Za-z0-9._-]{0,199}(?![\s\S])'}
    whitespace = r'\x09-\x0d\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000'
    edge = rf'[^\x00{whitespace}]'
    name = {'type': 'string', 'minLength': 1, 'maxLength': 200,
            'pattern': rf'^{edge}(?:[^\x00]*{edge})?(?![\s\S])'}
    return identifier, name

DIMENSIONAL_ACCESS_READ_FUNCTIONS = frozenset('security.application.' + suffix
    for suffix in ('dimension-access.read', 'group-dimension-access.read', 'dimension-tags.read',
        'member-tags.read', 'dimension-metadata-tags.read', 'relationship-tags.read',
        'dimension-policy.read'))

DIMENSIONAL_ACCESS_EFFECT_FUNCTIONS = frozenset('security.application.' + suffix
    for suffix in ('dimension-access.set', 'group-dimension-access.set',
        'dimension-policy.save', 'dimension-policy.activate', 'dimension-policy.deactivate'))

METADATA_DISCOVERY_FUNCTIONS = frozenset((
    'metadata.applicability_relation.list',
    'metadata.applicability_relation.read',
    'metadata.attribute-definition.list',
    'metadata.attribute-definition.usage.read',
    'metadata.attribute-value.read',
    'metadata.authoring.context',
    'metadata.calendar.period.read',
    'metadata.hierarchy.list',
    'metadata.hierarchy.members.list',
    'metadata.hierarchy.read',
    'metadata.hierarchy.relationships.preview',
    'metadata.layout.populated.activate.read',
    'metadata.layout.populated.preview',
    'metadata.layout.populated.review',
    'metadata.layout.populated.source.read',
    'metadata.layout.populated.replace.read',
    'metadata.member.select',
    'metadata.member_list.evaluate',
    'metadata.member_list.list',
    'metadata.member_list.read',
    'metadata.relationship.list',
    'metadata.security-tag.list',
))


HIERARCHY_EFFECTS = frozenset(NAMED_HIERARCHY_MUTATIONS) | {HIERARCHY_BUILD, HIERARCHY_PATCH_APPLY}


FUNCTIONS = (READ_FUNCTIONS | EXECUTION_FUNCTIONS | PROGRAM_MUTATIONS | PROGRAM_READS | PYTHON_ENVIRONMENT_FUNCTIONS
             | PYTHON_SCHEDULE_EFFECTS | OPERATION_FUNCTIONS | {SCALE, LINE_DETAIL_REPLACE}
             | {CALCULATION_RECALCULATE, CALCULATED_MEMBER_MATERIALIZE, CALENDAR_SET,
                LAYOUT_REPLACEMENT_REQUEST, LAYOUT_REPLACEMENT_CANCEL,
                LAYOUT_ACTIVATION_REQUEST, LAYOUT_ACTIVATION_CANCEL}
             | RULE_WORKFLOW_EFFECTS
             | SAVED_GRID_FUNCTIONS
             | METADATA_DISCOVERY_FUNCTIONS | MEMBER_LIST_EFFECTS | WORKFLOW_NAVIGATION_FUNCTIONS | WORKFLOW_OCCURRENCE_EFFECTS
             | IMPORT_EXECUTION_FUNCTIONS | IMPORT_DIAGNOSTIC_FUNCTIONS
             | SOURCE_BATCH_STAGING_FUNCTIONS | SOURCE_MANIFEST_FUNCTIONS | SOURCE_LIFECYCLE_FUNCTIONS
             | {SOURCE_STAGING_STATUS, SOURCE_PREVIEW} | SOURCE_EVIDENCE_READS | SOURCE_EVIDENCE_WRITES
             | ASSIGNMENT_FUNCTIONS | WORKFLOW_DEFINITION_FUNCTIONS
             | SCHEDULE_FUNCTIONS | EXECUTION_DELEGATION_FUNCTIONS | CUBE_WRITE_POLICY_FUNCTIONS | CUBE_WRITE_SCOPE_FUNCTIONS
             | APPLICATION_DECISION_FUNCTIONS
             | AGGREGATE_FUNCTIONS | SELECTION_ARTIFACT_FUNCTIONS
             | RESOLVED_READ_FUNCTIONS | EXPORT_ORCHESTRATION_FUNCTIONS | EXPORT_MANIFEST_FUNCTIONS
             | APPLICATION_ACCESS_READ_FUNCTIONS | APPLICATION_AUTHORIZATION_FUNCTIONS | DIMENSIONAL_ACCESS_READ_FUNCTIONS
             | APPLICATION_GRANT_EFFECT_FUNCTIONS
             | DIMENSIONAL_ACCESS_EFFECT_FUNCTIONS
             | APPLICABILITY_RELATION_EFFECTS
             | ATTRIBUTE_EFFECTS | METADATA_STRUCTURE_EFFECTS | METADATA_VALUE_EFFECTS | HIERARCHY_EFFECTS
             | MODEL_STATE_EDIT_FUNCTIONS | SECURITY_TAG_EDIT_FUNCTIONS
             | {EXPORT_PAYLOAD_PAGE})


def project_program_contract(specification: dict) -> dict:
    """Read owner schemas and bound examples from the existing discovery shapes."""
    program_contract = specification['programContract']
    schema_fields = ('programSchema', 'resultSchema', 'resultSchemaScope')
    schemas = {key: specification[key] if key in specification else program_contract[key]
               for key in schema_fields}
    return {
        'schemaCoverage': specification.get('schemaCoverage', 'program-and-result'),
        'schemaDialect': specification.get('schemaDialect', schemas['programSchema']['$schema']),
        **schemas,
        'programContract': {
            **{key: value for key, value in program_contract.items() if key not in schema_fields},
            'examples': [example if 'program' in example else {'program': example}
                         for example in program_contract['examples']],
        },
    }


@lru_cache(maxsize=len(FUNCTIONS))
def _owner_contract(function: str) -> dict:
    if function in (LAYOUT_ACTIVATION_REQUEST, LAYOUT_ACTIVATION_CANCEL):
        from .postgres_populated_layout_activation import effect_program_contract
        return effect_program_contract(function)
    if function in (LAYOUT_REPLACEMENT_REQUEST, LAYOUT_REPLACEMENT_CANCEL):
        from .postgres_populated_layout_replacement import effect_program_contract
        return effect_program_contract(function)
    if function == CALENDAR_SET:
        from .postgres_calendar import set_program_contract
        return set_program_contract()
    if function == CALCULATED_MEMBER_MATERIALIZE:
        from .postgres_calculated_members import materialization_program_contract
        return materialization_program_contract()
    if function in CALCULATED_MEMBER_READS:
        from .postgres_calculated_members import read_program_contract
        return read_program_contract(function)
    if function in ADJUSTED_READS:
        from .postgres_adjusted_scan import read_program_contract
        return read_program_contract(function)
    if function == CELL_EDITABILITY:
        from .postgres_cell_editability import editability_program_contract
        return editability_program_contract()
    if function == LINE_DETAIL_REPLACE:
        from .postgres_line_detail_job import line_detail_program_contract
        return line_detail_program_contract()
    if function == LAYER_REPORT:
        from .postgres_cube_layer_report import layer_report_program_contract
        return layer_report_program_contract()
    if function == FACT_EXPORT_PAGE:
        from .postgres_fact_export import export_page_program_contract
        return export_page_program_contract()
    if function in GENERIC_FACT_READS:
        from .postgres_generic_facts import generic_read_program_contract
        return generic_read_program_contract(function)
    if function in SOURCE_EVIDENCE_READS:
        from .postgres_source_evidence import read_program_contract
        return read_program_contract(function)
    if function in SOURCE_EVIDENCE_WRITES:
        from .postgres_source_evidence import write_program_contract
        return write_program_contract(function)
    if function in MEMBER_LIST_EFFECTS:
        from .postgres_member_lists import write_program_contract
        return write_program_contract(function)
    if function in APPLICATION_DECISION_FUNCTIONS:
        from .postgres_application_decisions import decision_program_contract
        return decision_program_contract(function)
    if function in CUBE_WRITE_SCOPE_FUNCTIONS:
        from .postgres_planning_locks import scope_program_contract
        return scope_program_contract(function)
    if function in CUBE_WRITE_POLICY_FUNCTIONS:
        from .postgres_planning_workflow_policy import policy_program_contract
        return policy_program_contract(function)
    if function in PYTHON_ENVIRONMENT_FUNCTIONS:
        from .postgres_python_environments import environment_program_contract
        return environment_program_contract(function)
    if function in CALCULATION_INSPECTION or function == CALCULATION_RECALCULATE:
        from .postgres_calculation_inspection import inspection_program_contract
        return inspection_program_contract(function)
    if function in CALCULATION_READS:
        from .postgres_calculation_scan import read_program_contract
        return read_program_contract(function)
    if function == SCALE:
        from .postgres_scale import scale_program_contract
        return scale_program_contract()
    if function == PUBLICATION_LIST:
        from .postgres_scale import publication_list_program_contract
        return publication_list_program_contract()
    if function == RAW_CUBE_SCAN:
        from .postgres_cube_query import scan_program_contract
        return scan_program_contract()
    if function == SCENARIO_COMPARE:
        from .postgres_scenario_comparison import comparison_program_contract
        return comparison_program_contract()
    if function in SAVED_GRID_FUNCTIONS:
        from .postgres_saved_grids import saved_grid_program_contract
        return saved_grid_program_contract(function)
    if function in AGGREGATE_FUNCTIONS:
        from .cube_aggregate_public_contract import aggregate_program_contract
        return aggregate_program_contract(function)
    if function in RESOLVED_READ_FUNCTIONS:
        from .postgres_resolved_cube_read_public import resolved_read_program_contract
        return resolved_read_program_contract(function)
    if function in SELECTION_ARTIFACT_FUNCTIONS:
        from .postgres_sealed_selections import selection_artifact_contract
        return selection_artifact_contract(function)
    if function == 'cube.selection.preview':
        from .postgres_selection_preview import read_program_contract
        return read_program_contract()
    if function in ASSIGNMENT_FUNCTIONS:
        from .postgres_application_assignments import assignment_program_contract
        return assignment_program_contract(function)
    if function in WORKFLOW_DEFINITION_FUNCTIONS:
        from .postgres_application_workflows import workflow_program_contract
        return workflow_program_contract(function)
    if function in SCHEDULE_FUNCTIONS:
        from .postgres_application_schedules import schedule_program_contract
        return schedule_program_contract(function)
    if function in EXECUTION_DELEGATION_FUNCTIONS:
        from .postgres_execution_delegations import delegation_program_contract
        return delegation_program_contract(function)
    if function in APPLICATION_AUTHORIZATION_FUNCTIONS:
        from .postgres_security_language import PostgresSecurityLanguage
        return project_program_contract(PostgresSecurityLanguage.catalog()['functions'][function])
    if function in APPLICATION_ACCESS_READ_FUNCTIONS:
        from .postgres_security_language import application_access_read_contract
        return application_access_read_contract(function)
    if function in APPLICATION_GRANT_EFFECT_FUNCTIONS:
        from .postgres_security_language import application_grant_effect_contract
        return application_grant_effect_contract(function)
    if function in DIMENSIONAL_ACCESS_READ_FUNCTIONS:
        from .postgres_security_language import dimensional_access_read_contract
        return dimensional_access_read_contract(function)
    if function in DIMENSIONAL_ACCESS_EFFECT_FUNCTIONS:
        from .postgres_security_language import dimensional_access_effect_contract
        return dimensional_access_effect_contract(function)
    if function in APPLICABILITY_RELATION_EFFECTS:
        from .postgres_applicability_relations import write_program_contract
        return write_program_contract(function)
    if function in ATTRIBUTE_EFFECTS:
        from .postgres_attribute_catalog import write_program_contract
        return write_program_contract(function)
    if function in METADATA_VALUE_EFFECTS:
        from .postgres_metadata import value_edit_program_contract
        return value_edit_program_contract(function)
    if function in METADATA_STRUCTURE_EFFECTS:
        from .postgres_metadata import structure_edit_program_contract
        return structure_edit_program_contract(function)
    if function in MODEL_STATE_EDIT_FUNCTIONS:
        from .postgres_metadata import model_state_edit_program_contract
        return model_state_edit_program_contract(function)
    if function in SECURITY_TAG_EDIT_FUNCTIONS:
        from .postgres_metadata import security_tag_edit_program_contract
        return security_tag_edit_program_contract(function)
    if function in NAMED_HIERARCHY_MUTATIONS:
        from .postgres_hierarchies import write_program_contract
        return write_program_contract(function)
    if function == HIERARCHY_BUILD:
        from .postgres_metadata import hierarchy_build_program_contract
        return hierarchy_build_program_contract()
    if function == HIERARCHY_PATCH_APPLY:
        from .postgres_metadata_hierarchy_patch import program_contract
        return program_contract(function)
    if function == 'application.rule.run.read':
        from .postgres_application_rule_workflow import lineage_program_contract
        return lineage_program_contract()
    if function in RULE_WORKFLOW_EFFECTS:
        from .postgres_application_rule_workflow import workflow_effect_program_contract
        return workflow_effect_program_contract(function)
    if function in ('application.rule.list', 'application.rule.read'):
        from .postgres_application_rules import read_program_contract
        return read_program_contract(function)
    if function in ('rules.expression.list', 'rules.expression.read'):
        from .postgres_expression_rules import read_program_contract
        return read_program_contract(function)
    if function == 'rules.expression.sequence.read':
        from .postgres_expression_sequence import read_program_contract
        return read_program_contract()
    if function == 'application.workflow.activity.evidence.read':
        from .postgres_application_workflow_occurrences import evidence_assessment_program_contract
        return evidence_assessment_program_contract()
    if function == 'application.workflow.activity.evidence.list':
        from .postgres_application_workflow_occurrences import evidence_options_program_contract
        return evidence_options_program_contract()
    if function == 'application.operation.receipt.read':
        from .postgres_operation_receipts import read_program_contract
        return read_program_contract()
    if function in WORKFLOW_NAVIGATION_FUNCTIONS:
        from .postgres_application_workflow_occurrences import navigation_read_contract
        return navigation_read_contract(function)
    if function in WORKFLOW_OCCURRENCE_EFFECTS:
        from .postgres_application_workflow_occurrences import transition_program_contract
        return transition_program_contract(function)
    if function == SOURCE_STAGING_STATUS:
        from .source_staging_status import read_contract
        return read_contract()
    if function in SOURCE_BATCH_STAGING_FUNCTIONS:
        from .source_staging_status import batch_staging_program_contract
        return batch_staging_program_contract(function)
    if function in SOURCE_LIFECYCLE_FUNCTIONS:
        from .postgres_source_batch import source_lifecycle_program_contract
        return source_lifecycle_program_contract(function)
    if function in SOURCE_MANIFEST_FUNCTIONS:
        from .postgres_source_upload_manifest import manifest_program_contract
        return manifest_program_contract(function)
    if function == SOURCE_PREVIEW:
        from .postgres_source_batch import preview_program_contract
        return preview_program_contract()
    if function in IMPORT_EXECUTION_FUNCTIONS:
        from .postgres_import_execution import import_program_contract
        return import_program_contract(function)
    if function in EXPORT_ORCHESTRATION_FUNCTIONS:
        from .postgres_transfer_orchestration import export_program_contract
        return export_program_contract(function)
    if function in (EXPORT_MANIFEST_FUNCTIONS | IMPORT_DIAGNOSTIC_FUNCTIONS):
        from .postgres_transfer_artifacts import transfer_artifact_program_contract
        return transfer_artifact_program_contract(function)
    if function == EXPORT_PAYLOAD_PAGE:
        from .postgres_export_payload import payload_page_program_contract
        return payload_page_program_contract()
    if function in METADATA_DISCOVERY_FUNCTIONS:
        if function in ('metadata.relationship.list', 'metadata.security-tag.list'):
            from .metadata_read_contract import additional_metadata_read_program_contract
            return additional_metadata_read_program_contract(function)
        if function in ('metadata.hierarchy.list', 'metadata.hierarchy.read', 'metadata.hierarchy.members.list'):
            from .postgres_hierarchies import read_program_contract
        elif function == 'metadata.hierarchy.relationships.preview':
            from .postgres_metadata_hierarchy_patch import program_contract
            return program_contract(function)
        elif function.startswith('metadata.attribute'):
            from .postgres_attribute_catalog import read_program_contract
        elif function.startswith('metadata.member_list.'):
            from .postgres_member_lists import read_program_contract
        elif function.startswith('metadata.applicability_relation.'):
            from .postgres_applicability_relations import read_program_contract
        elif function == 'metadata.member.select':
            from .postgres_member_selection import read_program_contract
        elif function == 'metadata.authoring.context':
            from .postgres_authoring_context import read_program_contract
        elif function == 'metadata.calendar.period.read':
            from .postgres_calendar import read_program_contract
        elif function in ('metadata.layout.populated.preview', 'metadata.layout.populated.review',
                         'metadata.layout.populated.source.read'):
            from .postgres_populated_layout_preview import read_program_contract
        elif function == 'metadata.layout.populated.replace.read':
            from .postgres_populated_layout_replacement import read_program_contract
        else:
            from .postgres_populated_layout_activation import read_program_contract
        return read_program_contract(function)
    if function in ('facts.numeric.batch', 'facts.text.batch'):
        from .postgres_language_v2 import batch_program_contract
        return batch_program_contract(function)
    if function == 'facts.numeric.transform':
        from .postgres_numeric_transform import program_contract
        return project_program_contract({'programContract': program_contract()})
    if function in PROGRAM_MUTATIONS:
        from .current_python_contract import mutation_program_contract
        return mutation_program_contract(function)
    if function in PROGRAM_READS:
        from .current_python_contract import source_read_program_contract
        return source_read_program_contract(function)
    if function in EXECUTION_FUNCTIONS:
        from .python_execution_contract import execution_program_contract
        return execution_program_contract(function)
    if function in PYTHON_SCHEDULE_EFFECTS:
        from .postgres_python_schedules import effect_contract
        return effect_contract(function)
    if function in PYTHON_SCHEDULE_READS:
        from .postgres_python_schedules import schedule_read_contract
        return schedule_read_contract(function)
    if function in ('facts.numeric.sequence', 'facts.numeric.iterate'):
        from .postgres_numeric_catalog import direct_program_contract, examples
        return project_program_contract({'programContract': direct_program_contract(function, examples())})
    if function == 'facts.cube.select':
        from .postgres_cube_select import catalog
        return project_program_contract(catalog()[function])
    if function == 'facts.slice.copy.prepare':
        from .slice_copy_contract import catalog
        return project_program_contract(catalog()[function])
    if function == 'facts.slice.copy.status.read':
        from .slice_copy_contract import status_read_contract
        return status_read_contract()
    if function == 'facts.projections.rebuild':
        from .postgres_fact_reconstruction_job import catalog
        return project_program_contract(catalog()[function])
    if function == 'facts.projections.cleanup':
        from .postgres_projection_cleanup import catalog
        return project_program_contract(catalog()[function])
    if function in ('application.state.read', 'security.identity.current.read'):
        from .postgres_application_capabilities import state_program_contract, identity_program_contract
        return state_program_contract() if function == 'application.state.read' else identity_program_contract()
    from .metadata_read_contract import metadata_read_program_contract
    return metadata_read_program_contract(function)


def public_program_contract(function: str) -> dict | None:
    if type(function) is not str:
        return None
    if function in ('security.workspace.authorization-migration.review','security.workspace.authorization-migration.activate'):
        from .application_authorization_migration import catalog
        return project_program_contract(catalog()[function])
    if function in ('security.workspace.people.list','security.workspace.person-applications.list','security.workspace.bootstrap-groups.list'):
        from .postgres_workspace_access_review import catalog
        return project_program_contract(catalog()[function])
    if function in WORKSPACE_SECURITY_FUNCTIONS:
        from .postgres_security_language import workspace_security_contract
        return workspace_security_contract(function)
    if function in WORKSPACE_PROVISIONING_FUNCTIONS:
        from .postgres_workspace_lifecycle import application_creation_contract
        return application_creation_contract()
    if function in PLATFORM_PROVISIONING_FUNCTIONS:
        from .postgres_platform_provision import platform_provisioning_contract
        return platform_provisioning_contract(function)
    if function in PLATFORM_DIRECTORY_READ_FUNCTIONS:
        from .postgres_identity_directory import directory_read_contract
        return directory_read_contract(function)
    if function in PLATFORM_DIRECTORY_WRITE_FUNCTIONS:
        from .postgres_identity_directory import directory_write_contract
        return directory_write_contract(function)
    if function not in FUNCTIONS:
        return None
    return deepcopy(_owner_contract(function))


def public_program_contract_scope(function: str) -> str:
    if function in (PLATFORM_PROVISIONING_FUNCTIONS | PLATFORM_DIRECTORY_READ_FUNCTIONS
                    | PLATFORM_DIRECTORY_WRITE_FUNCTIONS):
        return 'platform'
    if function in WORKSPACE_SECURITY_FUNCTIONS or function in WORKSPACE_PROVISIONING_FUNCTIONS:
        return 'workspace'
    return 'application'
