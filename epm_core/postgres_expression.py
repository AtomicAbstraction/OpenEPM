"""Bounded typed numeric and conditional expressions lowered to exact SQL.

The compiler accepts data, never client SQL. A present numeric source anchors
each output coordinate; published inputs may look up declared alternate members.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from itertools import product
import math
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_calculation_status import published_input_status
from .postgres_scale import _member_predicates
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .temporal_expression_contract import compile_temporal_expression
from .current_object_contract import require_state_token


FUNCTION = 'facts.expression.calculate'


def _domain_coordinates(plan: 'ExpressionPlan') -> list[dict[str,str]]:
    if not plan.source_domain:return []
    axes=[axis for axis,_ in plan.source_domain]
    return [dict(zip(axes,values)) for values in product(*(
        members for _,members in plan.source_domain))]


def _target_member_combinations(plan: 'ExpressionPlan') -> list[dict[str,str]]:
    """Return bounded Cartesian output overrides in canonical axis order."""
    if not plan.target_member_sets:return []
    selections=tuple(sorted(plan.target_member_sets))
    axes=[axis for axis,_ in selections]
    return [dict(zip(axes,values)) for values in product(*(
        members for _,members in selections))]


def _plain_multi_axis_expression(node: dict) -> bool:
    """v30 deliberately excludes prior typed, conditional and driver profiles."""
    operation=node.get('op')
    if operation in ('SourceAmount','AmountLiteral','RatioLiteral'):
        return True
    if operation=='PublishedAmount':
        return True
    if operation in ('Add','Subtract','Multiply'):
        return (_plain_multi_axis_expression(node['left'])
                and _plain_multi_axis_expression(node['right']))
    if operation=='Divide':
        return (_plain_multi_axis_expression(node['left'])
                and node['right'].get('op')=='RatioLiteral')
    return False


@dataclass(frozen=True)
class _MultiReductionSql:
    """One canonical v31 coordinate/filter lowering shared by every stage."""
    base_sql: str
    base_params: tuple
    filter_sql: str
    filter_params: tuple
    target: Jsonb

    @property
    def target_sql(self) -> str:
        return f'({self.base_sql})||%s::jsonb'

    @property
    def target_params(self) -> tuple:
        return (*self.base_params, self.target)


def _multi_reduction_sql(plan: 'ExpressionPlan') -> _MultiReductionSql:
    selections=plan.reduce_member_sets[0]
    if len(selections) not in (3,4):
        raise ValueError('EXPRESSION_MULTI_AXIS_REDUCTION_PROFILE_UNSUPPORTED')
    base='c.members';base_params=[];filters=[];filter_params=[];targets={}
    for axis,members,target in selections:
        base=f'({base}-%s::text)';base_params.append(axis)
        filters.append('c.members->>%s=ANY(%s::text[])')
        filter_params.extend((axis,list(members)))
        targets[axis]=target
    return _MultiReductionSql(base,tuple(base_params),' AND '.join(filters),
                              tuple(filter_params),Jsonb(targets))


def _multi_reduction_publish_sql(plan: 'ExpressionPlan', expression_sql: str,
                                 joins: str, predicate: str, *,
                                 target: str = 'epm.calculation_result_staging') -> str:
    if target not in ('epm.calculation_result_staging',
                      'pg_temp.calculation_result_stage'):
        raise ValueError('CALCULATION_RESULT_TARGET_INVALID')
    reduction=_multi_reduction_sql(plan)
    return f'''INSERT INTO {target}
        (workspace_id,application_id,generation_id,coordinate_id,
         source_amount,source_change_id,amount,source_lookup_lineage)
        SELECT c.workspace_id,c.application_id,%s,t.coordinate_id,
         sum(n.amount),string_agg(n.change_id,',' ORDER BY c.series_key),
         epm.round_half_even(sum({expression_sql}),8),
         jsonb_agg(jsonb_build_object('sourceMembers',c.members,
          'sourceSeriesKey',c.series_key,'sourceAmount',n.amount::text,
          'sourceChangeId',n.change_id) ORDER BY c.series_key)
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
         USING(workspace_id,application_id,coordinate_id) {joins}
        JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
         AND t.application_id=c.application_id
         AND t.members={reduction.target_sql}
        WHERE c.workspace_id=%s AND c.application_id=%s
         AND n.present AND {reduction.filter_sql} {predicate}
        GROUP BY c.workspace_id,c.application_id,t.coordinate_id'''


COMPILER = 'typed-numeric-expression-v1'
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_full_coordinate',
    'nodes': ['SourceAmount', 'AmountLiteral', 'RatioLiteral',
              'Add', 'Subtract', 'Multiply', 'Divide'],
    'division': 'nonzero_literal_ratio_only',
})
COMPOSED_COMPILER = 'typed-numeric-expression-v2'
COMPOSED_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 2,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_full_coordinate',
    'nodes': ['SourceAmount', 'PublishedAmount', 'AmountLiteral',
              'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide'],
    'publishedInput': 'current_result_same_coordinate_required',
    'division': 'nonzero_literal_ratio_only',
})
MAPPED_COMPILER = 'typed-numeric-expression-v3'
MAPPED_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 3,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_full_coordinate',
    'nodes': ['SourceAmount', 'PublishedAmount', 'AmountLiteral',
              'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide'],
    'publishedInput': 'current_result_declared_member_overrides_required',
    'division': 'nonzero_literal_ratio_only',
})
CONDITIONAL_COMPILER = 'typed-numeric-expression-v4'
CONDITIONAL_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 4,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_full_coordinate',
    'nodes': ['SourceAmount', 'PublishedAmount', 'AmountLiteral',
              'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide',
              'Compare', 'If'],
    'publishedInput': 'current_result_declared_member_overrides_required',
    'comparison': 'same_numeric_unit_exact',
    'conditional': 'typed_case_expression',
    'division': 'nonzero_literal_ratio_only',
})
TRANSFORM_COMPILER = 'typed-numeric-expression-v5'
TRANSFORM_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 5,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'declared_target_member_overrides',
    'nodes': ['SourceAmount', 'PublishedAmount', 'AmountLiteral',
              'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide',
              'Compare', 'If'],
    'publishedInput': 'current_result_declared_member_overrides_required',
    'targetMapping': 'fixed_source_axis_member_to_active_target_member',
    'comparison': 'same_numeric_unit_exact',
    'conditional': 'typed_case_expression',
    'division': 'nonzero_literal_ratio_only',
})
DYNAMIC_DIVISION_COMPILER = 'typed-numeric-expression-v6'
DYNAMIC_DIVISION_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 6,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_or_declared_target_member_overrides',
    'nodes': ['SourceAmount', 'PublishedAmount', 'AmountLiteral',
              'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide',
              'Compare', 'If'],
    'publishedInput': 'current_result_declared_member_overrides_required',
    'targetMapping': 'fixed_source_axis_member_to_active_target_member',
    'division': 'dynamic_nonzero_denominator_checked_per_coordinate',
})
SAVED_RULE_COMPILER = 'typed-numeric-expression-v7'
SAVED_RULE_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 7,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_or_declared_target_member_overrides',
    'savedRule': 'immutable_version_and_current_publication_pinned',
    'authorization': 'current_write_and_rule_run_grant',
    'division': 'dynamic_nonzero_denominator_checked_per_coordinate',
})
PARAMETERIZED_RULE_COMPILER = 'typed-numeric-expression-v8'
PARAMETERIZED_RULE_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 8,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_or_declared_target_member_overrides',
    'savedRule': 'immutable_template_version_publication_and_exact_bindings_pinned',
    'authorization': 'current_write_and_rule_run_grant',
    'division': 'dynamic_nonzero_denominator_checked_per_coordinate',
})
MEMBER_PARAMETER_RULE_COMPILER = 'typed-numeric-expression-v9'
MEMBER_PARAMETER_RULE_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 9,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_or_declared_target_member_overrides',
    'savedRule': 'immutable_template_version_publication_and_typed_member_bindings_pinned',
    'authorization': 'current_write_and_rule_run_grant',
    'memberValidation': 'active_stable_id_at_preview_admission_and_publication',
    'division': 'dynamic_nonzero_denominator_checked_per_coordinate',
})
RAW_DRIVER_COMPILER = 'typed-numeric-expression-v10'
RAW_DRIVER_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 10,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'same_or_declared_target_member_overrides',
    'sourceLookup': 'active_declared_member_overrides_present_numeric_required',
    'sourceValueType': 'author_declared_amount_or_ratio',
    'savedRule': 'immutable_template_version_and_typed_bindings_when_present',
    'division': 'dynamic_nonzero_denominator_checked_per_coordinate',
})
TYPED_DRIVER_COMPILER = 'typed-numeric-expression-v11'
TYPED_DRIVER_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 11,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'sourceLookup': 'metadata_bound_measure_numeric_kind',
    'sourceLineage': 'per_result_row_immutable_source_change',
})
POLICY_DRIVER_COMPILER = 'typed-numeric-expression-v12'
POLICY_DRIVER_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 12,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'sourceLookup': 'metadata_bound_measure_numeric_kind',
    'sourceLineage': 'per_result_row_immutable_source_change',
    'policyPin': 'immutable_policy_identity_version_digest_and_revisions',
    'targetMapping': 'declared_output_member_overrides',
})
PUBLISHED_POLICY_DRIVER_COMPILER = 'typed-numeric-expression-v13'
PUBLISHED_POLICY_DRIVER_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 13,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'sourceLookup': 'metadata_bound_measure_numeric_kind',
    'policyPin': 'published_immutable_policy_and_current_revision',
    'activePointer': 'policy_version_digest_pointer_and_state_revision',
    'targetMapping': 'declared_output_member_overrides',
})
PUBLISHED_DEPENDENCY_DRIVER_COMPILER = 'typed-numeric-expression-v25'
PUBLISHED_DEPENDENCY_DRIVER_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 25,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'rawRatio': 'metadata_bound_measure_numeric_kind',
    'publishedAmount': 'generation_and_publication_pinned_recursive_freshness',
    'jobDependency': 'published_source_job',
    'policyPin': 'published_immutable_v2_policy_and_current_revision',
    'targetMapping': 'declared_output_member_overrides',
    'maxCells': 500,
    'upstreamLineage':
        'final-source-lookup-array-postgres-jsonb-text-65536-bytes-depth-8',
})
MEMBER_SET_TRANSFORM_COMPILER = 'typed-numeric-expression-v14'
MEMBER_SET_TRANSFORM_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 14,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-final-8',
    'inputGrain': 'present_full_coordinate',
    'outputGrain': 'one_axis_explicit_member_set',
    'lineage': 'source_coordinate_and_change_per_output',
    'missing': 'absent_source_produces_no_output',
})
MEMBER_SET_REDUCTION_COMPILER = 'typed-numeric-expression-v15'
MEMBER_SET_REDUCTION_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':15,'engine':'postgres_exact_sql',
    'inputGrain':'explicit_one_axis_member_set',
    'outputGrain':'same_dimensions_one_target_member',
    'measures':['SumAmount','CountPresent'],
    'missing':'exclude_absent_sources_empty_group_absent',
    'lineage':'all_present_source_coordinates_and_change_ids',
})
MEMBER_SET_AVERAGE_COMPILER = 'typed-numeric-expression-v18'
MEMBER_SET_AVERAGE_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':18,'engine':'postgres_exact_sql',
    'inputGrain':'explicit_one_axis_member_set',
    'outputGrain':'same_dimensions_one_target_member',
    'measures':['AverageAmount','CountPresent'],
    'resultUnit':'Amount','denominatorUnit':'CountPresent',
    'missing':'exclude_absent_sources_empty_group_absent',
    'presentZero':'included_in_sum_and_count',
    'rounding':'half_even_final_8',
    'lineage':'all_present_source_coordinates_and_change_ids',
})
UNIT_BOUND_REDUCTION_COMPILER = 'typed-numeric-expression-v19'
UNIT_BOUND_REDUCTION_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':19,'engine':'postgres_exact_sql',
    'inputGrain':'explicit_one_axis_member_set',
    'outputGrain':'same_dimensions_one_target_member',
    'measures':['SumAmount','CountPresent','AverageAmount'],
    'resultUnit':'explicit_active_currency_member',
    'unitBinding':'every_source_and_target_entity_default_currency_matches',
    'conversion':'unsupported_no_exchange_rate_inference',
    'missing':'exclude_absent_sources_empty_group_absent',
    'presentZero':'included', 'rounding':'half_even_final_8',
    'lineage':'all_present_source_coordinates_and_change_ids',
})
WEIGHTED_AVERAGE_COMPILER = 'typed-numeric-expression-v20'
WEIGHTED_AVERAGE_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':20,'engine':'postgres_exact_sql',
    'inputGrain':'explicit_one_axis_member_set',
    'outputGrain':'same_dimensions_one_target_member',
    'measure':'WeightedAverageAmount',
    'valueSource':'present_SourceAmount',
    'weightSource':'one_metadata_bound_Ratio_SourceValue_same_coordinate',
    'weightConstraint':'present_non_negative',
    'zeroWeightPolicy':'error',
    'rounding':'half_even_final_8',
    'lineage':'exact_amount_weight_numerator_and_change_ids',
})
CURRENCY_CONVERSION_COMPILER='typed-numeric-expression-v21'
CURRENCY_CONVERSION_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':21,'engine':'postgres_exact_sql',
    'node':'CurrencyConvert','source':'SourceAmount',
    'sourceUnit':'EntityDefaultCurrency','outputUnit':'explicit_Currency_member',
    'rate':'currency.rate.resolve_pinned_direct_inverse_or_triangulated',
    'arithmetic':'exact_rational','rounding':'half_even_final_8',
    'outputGrain':'unchanged_coordinate_typed_unit_schema_0143',
    'backend':'fixed_core_selected','statutorySemantics':'none'})
UNIT_ALIGNED_COMPILER='typed-numeric-expression-v22'
UNIT_ALIGNED_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':22,'engine':'postgres_exact_sql',
    'node':'PublishedUnitAmount','input':'schema_0143_typed_unit_generation',
    'unitRule':'all_published_inputs_one_explicit_Currency_member',
    'arithmetic':'exact_same_unit_only','rounding':'half_even_final_8',
    'output':'schema_0143_typed_unit_generation',
    'lineage':'recursive_published_generation_and_rate_lineage',
    'backend':'fixed_core_selected','statutorySemantics':'none'})
RAW_UNIT_EXPRESSION_COMPILER='typed-numeric-expression-v29'
RAW_UNIT_EXPRESSION_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':29,'engine':'postgres_exact_sql',
    'inputGrain':'present_full_coordinate_raw_driver',
    'rawInputUnit':'every_raw_input_entity_default_currency_matches',
    'publishedInput':'PublishedUnitAmount_same_explicit_currency_only',
    'outputUnit':'one_explicit_active_Currency_member',
    'sourcePresence':'optional_exact_required_count_1_to_500_present_zero_counts',
    'storage':'calculation_unit_result',
    'arithmetic':'exact_same_unit_amount_and_ratio_only',
    'rounding':'half_even_final_8',
    'lineage':'raw_changes_and_pinned_typed_published_generations',
    'backend':'fixed_core_selected','statutorySemantics':'none'})
CONTEXT_EXPRESSION_COMPILER='typed-numeric-expression-v32'
CONTEXT_EXPRESSION_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':32,'engine':'postgres_exact_sql',
    'contextDependencies':['OwnershipValue','CalendarPeriod'],
    'contextAssertions':'CallerDeclaredUnverified_audit_only',
    'publication':'exact_sealed_context_rechecked_under_application_fence',
    'lineage':'normalized_program_and_recursive_read_status',
    'accountingPolicyInference':'none'})
RATIO_RESULT_COMPILER='typed-numeric-expression-v24'
RATIO_RESULT_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':24,'engine':'postgres_exact_sql',
    'resultUnit':{'type':'Ratio','scale':12},
    'outputGrain':'existing_declared_full_coordinate',
    'storage':'calculation_ratio_result',
    'arithmetic':'exact_numeric','rounding':'half_even_final_12',
    'lineage':'raw_and_published_generation_pins',
    'backend':'fixed_core_selected','statutorySemantics':'none'})
TWO_AXIS_MEMBER_SET_COMPILER = 'typed-numeric-expression-v16'
TWO_AXIS_MEMBER_SET_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':16,'engine':'postgres_exact_sql',
    'inputGrain':'same_full_coordinate',
    'outputGrain':'explicit_two_axis_cartesian_member_sets',
    'bounds':'two_unique_axes_product_within_500_results',
    'lineage':'one_source_coordinate_and_change_per_output',
    'missing':'absent_source_produces_no_output',
})
MULTI_AXIS_MEMBER_SET_COMPILER = 'typed-numeric-expression-v30'
MULTI_AXIS_MEMBER_SET_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':30,'engine':'postgres_exact_sql',
    'inputGrain':'same_full_coordinate',
    'outputGrain':'explicit_three_or_four_axis_cartesian_member_sets',
    'bounds':{'uniqueAxes':[3,4],'cartesianResultsPerSource':500,
              'totalResults':500},
    'lineage':'one_source_coordinate_and_change_per_output',
    'nodes':['SourceAmount','PublishedAmount','AmountLiteral','RatioLiteral',
             'Add','Subtract','Multiply','DivideByLiteralRatio'],
    'publishedInput':'pinned_untyped_generation_only',
    'missing':'absent_source_produces_no_output',
    'rounding':'half_even_final_8',
    'authorization':'every_materialized_target_checked_by_planning_policy',
})
EXPLICIT_MISSING_DEFAULT_COMPILER = 'typed-numeric-expression-v17'
EXPLICIT_MISSING_DEFAULT_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':17,'engine':'postgres_exact_sql',
    'inputGrain':'complete_explicit_bounded_domain',
    'outputGrain':'same_full_coordinate','domainLimit':500,
    'missing':'explicit_exact_amount_default_only_for_absent_numeric_source',
    'lineage':'Actual_or_DefaultedAbsent_without_synthetic_change_id',
})
HIERARCHY_REDUCTION_COMPILER = 'typed-numeric-expression-v26'
HIERARCHY_REDUCTION_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 26,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'server_resolved_one_axis_unique_member_set',
    'outputGrain': 'same_dimensions_one_target_member',
    'selection': 'sealed_current_hierarchy_state_children_descendants_leaves',
    'measures': ['SumAmount', 'AverageAmount', 'CountPresent'],
    'bounds': {'resolvedMembers': 100, 'presentSources': 100,
               'outputIntersections': 1},
    'lineage': 'resolved_membership_digest_and_present_source_changes',
})
TWO_AXIS_HIERARCHY_REDUCTION_COMPILER = 'typed-numeric-expression-v27'
TWO_AXIS_HIERARCHY_REDUCTION_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 27,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'server_resolved_two_axis_unique_member_sets',
    'outputGrain': 'same_dimensions_two_target_members',
    'selection': 'sealed_current_hierarchy_states_children_descendants_leaves',
    'measures': ['SumAmount', 'AverageAmount', 'CountPresent'],
    'bounds': {'resolvedMembersPerAxis': 100, 'presentSources': 500,
               'outputIntersections': 1},
    'lineage': 'ordered_membership_digests_and_present_source_changes',
})
MULTI_AXIS_MEMBER_SET_REDUCTION_COMPILER = 'typed-numeric-expression-v31'
MULTI_AXIS_MEMBER_SET_REDUCTION_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':31,'engine':'postgres_exact_sql',
    'inputGrain':'explicit_three_or_four_axis_member_sets',
    'outputGrain':'same_dimensions_three_or_four_target_members',
    'measures':['SumAmount','CountPresent'],
    'bounds':{'axes':[3,4],'selectionProduct':500,
              'presentSources':500,'outputIntersections':500},
    'expressionProfile':'plain_untyped_amount_no_external_lookups',
    'missing':'exclude_absent_sources_empty_group_absent',
    'presentZero':'included_in_sum_and_count',
    'rounding':'half_even_final_8',
    'lineage':'all_present_source_coordinates_amounts_and_change_ids',
    'hierarchy':'unsupported','weights':'unsupported',
})
TWO_AXIS_MEMBER_SET_REDUCTION_COMPILER = 'typed-numeric-expression-v33'
TWO_AXIS_MEMBER_SET_REDUCTION_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':33,'engine':'postgres_exact_sql',
    'inputGrain':'explicit_two_axis_member_sets',
    'outputGrain':'same_dimensions_two_target_members',
    'measures':['SumAmount','CountPresent'],
    'bounds':{'axes':2,'selectionProduct':500,
              'presentSources':500,'outputIntersections':500},
    'expressionProfile':'plain_untyped_amount_no_external_lookups',
    'missing':'exclude_absent_sources_empty_group_absent',
    'presentZero':'included_in_sum_and_count',
    'rounding':'half_even_final_8',
    'lineage':'all_present_source_coordinates_amounts_and_change_ids',
    'hierarchy':'unsupported','weights':'unsupported',
})
TEXT_PREDICATE_COMPILER = 'typed-numeric-expression-v28'
TEXT_PREDICATE_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 28,
    'engine': 'postgres_exact_sql',
    'predicate': 'present_raw_text_exact_eq_ne',
    'missing': 'error_never_coerce_to_empty_or_false',
    'bounds': {'combinedRawLookups': 8, 'textLength': 32768},
    'lineage': 'text_members_value_and_change_id',
})
SOURCE_MEMBER_SETS_COMPILER = 'typed-numeric-expression-v34'
SOURCE_MEMBER_SETS_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 34,
    'engine': 'postgres_exact_sql',
    'rounding': 'existing_typed_expression_result_profile',
    'inputGrain': 'present_coordinates_in_explicit_member_sets',
    'selection': 'bounded_stable_member_ids_per_dimension',
    'outputGrain': 'same_or_declared_target_member_overrides',
    'lineage': 'source_coordinate_and_change_per_output',
    'missing': 'absent_source_produces_no_output',
})
CALCULATED_MEMBER_COMPILER = 'typed-numeric-expression-v35'
CALCULATED_MEMBER_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 35,
    'engine': 'postgres_exact_sql',
    'definition': 'exact_current_immutable_publication_pin',
    'selection': 'metadata_and_policy_pinned_resolved_member_sets',
    'publication': 'definition_and_lowered_plan_rechecked_before_commit',
    'lineage': 'definition_selection_and_source_coordinates',
})
SELECTED_DOMAIN_COMPILER = 'typed-numeric-expression-v37'
SELECTED_DOMAIN_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 37,
    'engine': 'postgres_exact_sql',
    'definition': 'exact_current_immutable_publication_pin',
    'selection': 'compact_server_resolved_selected_domain_v1',
    'membership': 'transaction_local_relational_semijoin',
    'anchorGrain': 'existing_present_cells',
    'executionPartition': {
        'maxPresentSources': 500,
        'largerDomains': 'partitioned_generation_required',
    },
    'missing': {'primary': 'exclude_absent', 'relative': 'error'},
    'publication': 'definition_resolution_and_lowered_plan_rechecked_before_commit',
    'lineage': 'definition_selection_resolution_and_source_coordinates',
})
TEMPORAL_SELECTED_DOMAIN_COMPILER = 'typed-numeric-expression-v38'
TEMPORAL_SELECTED_DOMAIN_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 38,
    'engine': 'postgres_exact_sql',
    'definition': 'exact_current_immutable_publication_pin',
    'selection': 'compact_server_resolved_selected_domain_v1',
    'temporal': {
        'contract': 'openepm-temporal-expression-v1',
        'calendar': 'current_application_calendar_exact_version',
        'reset': 'explicit_year_role_dimension',
        'order': 'calendar_ordinal',
        'operators': ['period_end', 'predecessor_delta', 'prefix_sum'],
        'boundary': 'explicit_error_or_opening_amount',
        'missing': 'operator_specific_never_silent_zero',
    },
    'anchorGrain': 'existing_present_cells',
    'publication': 'shared_dynamic_and_materialized_window_lowering',
    'lineage': 'ordered_window_source_coordinates_and_calendar_changes',
})
APPLICABILITY_DOMAIN_COMPILER = 'typed-numeric-expression-v39'
APPLICABILITY_DOMAIN_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 39,
    'engine': 'postgres_exact_sql',
    'selection': 'current_sparse_applicability_relation_v1',
    'membership': 'complete_anchor_relational_join',
    'targetMapping': 'explicit_overrides_inherit_anchor',
    'operands': 'named_coordinate_overrides_with_explicit_missingness',
    'values': 'typed_relation_columns',
    'publication': 'exclusive_target_current_result_replacement',
    'lineage': 'relation_state_digest_row_and_source_changes',
})
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB_ID = re.compile(r'[0-9a-f]{32}\Z')


def _decimal(value: object, *, amount: bool) -> str:
    if not isinstance(value, str):
        raise ValueError('EXPRESSION_DECIMAL_STRING_REQUIRED')
    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError) as error:
        raise ValueError('EXPRESSION_DECIMAL_INVALID') from error
    if not number.is_finite():
        raise ValueError('EXPRESSION_DECIMAL_INVALID')
    digits = len(number.as_tuple().digits)
    exponent = number.as_tuple().exponent
    if (max(0, digits + exponent) > (20 if amount else 8)
            or -exponent > (8 if amount else 12)):
        raise ValueError('EXPRESSION_DECIMAL_OUT_OF_RANGE')
    if amount:
        NumericCell(True, number, '')
    return format(number, 'f')


def _expression(node: object, *, depth: int = 0,
                budget: list[int] | None = None,
                leaf_parser=None) -> tuple[dict, str]:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 12 or budget[0] > 64 or not isinstance(node, dict):
        raise ValueError('EXPRESSION_COMPLEXITY_OR_SHAPE_INVALID')
    if leaf_parser is not None:
        parsed = leaf_parser(node)
        if parsed is not None:
            return parsed
    def child(value):
        return _expression(value, depth=depth + 1, budget=budget, leaf_parser=leaf_parser)
    name = node.get('op')
    if name == 'SourceAmount' and set(node) == {'op'}:
        return {'op': name}, 'amount'
    if name == 'RelationOperand' and set(node) == {
            'op', 'operandId', 'valueType'}:
        operand_id = node['operandId']; value_type = node['valueType']
        if (not isinstance(operand_id,str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}',
                                    operand_id)
                or value_type not in ('amount','ratio')):
            raise ValueError('EXPRESSION_RELATION_OPERAND_INVALID')
        return {'op':name,'operandId':operand_id,
                'valueType':value_type},value_type
    if name == 'RelationValue' and set(node) == {
            'op', 'valueId', 'valueType'}:
        value_id = node['valueId']; value_type = node['valueType']
        if (not isinstance(value_id,str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}',
                                    value_id)
                or value_type not in ('amount','ratio')):
            raise ValueError('EXPRESSION_RELATION_VALUE_INVALID')
        return {'op':name,'valueId':value_id,
                'valueType':value_type},value_type
    if name == 'TemporalWindow':
        fields = {'op', 'source', 'resetGroupDimensionId', 'definition'}
        definition = node.get('definition')
        boundary = (definition.get('boundaryPolicy')
                    if isinstance(definition, dict) else None)
        if boundary == 'use_opening_value':
            fields.add('openingAmount')
        if (set(node) != fields or node.get('source') != {'op': 'SourceAmount'}
                or not isinstance(node.get('resetGroupDimensionId'), str)
                or not 1 <= len(node['resetGroupDimensionId']) <= 200):
            raise ValueError('EXPRESSION_TEMPORAL_WINDOW_INVALID')
        try:
            temporal = compile_temporal_expression(definition)
        except ValueError as error:
            raise ValueError('EXPRESSION_TEMPORAL_WINDOW_INVALID') from error
        normalized_definition = temporal.normalized
        if (normalized_definition['sourceUnit'] != 'amount'
                or normalized_definition['resultUnit'] != 'amount'
                or normalized_definition['periodDimensionId'] ==
                    node['resetGroupDimensionId']):
            raise ValueError('EXPRESSION_TEMPORAL_WINDOW_INVALID')
        normalized = {'op': name, 'source': {'op': 'SourceAmount'},
            'resetGroupDimensionId': node['resetGroupDimensionId'],
            'definition': normalized_definition}
        if boundary == 'use_opening_value':
            normalized['openingAmount'] = _decimal(
                node.get('openingAmount'), amount=True)
        return normalized, 'amount'
    if name=='CurrencyConvert':
        fields={'op','source','fromCurrencyMemberId','toCurrencyMemberId',
            'outputUnitCurrencyMemberId','rateKind','expectedRate',
            'expectedDataRevision','rounding'}
        rate=node.get('expectedRate')
        if (set(node)!=fields or node.get('source')!={'op':'SourceAmount'}
                or node.get('outputUnitCurrencyMemberId')!=node.get(
                    'toCurrencyMemberId')
                or node.get('rateKind') not in ('balance','flow')
                or node.get('rounding')!='half-even-final-8'
                or type(node.get('expectedDataRevision')) is not int
                or node['expectedDataRevision']<0
                or any(type(node.get(key)) is not str
                    or not 1<=len(node[key])<=200 for key in (
                        'fromCurrencyMemberId','toCurrencyMemberId'))
                or node['fromCurrencyMemberId']==node['toCurrencyMemberId']
                or type(rate) is not dict
                or set(rate)!={'strategy','exactFactor','sourceChangeIds'}
                or type(rate.get('strategy')) is not str
                or not 1<=len(rate['strategy'])<=100
                or type(rate.get('exactFactor')) is not dict
                or set(rate['exactFactor'])!={'numerator','denominator'}
                or any(type(rate['exactFactor'].get(key)) is not str
                    or not re.fullmatch(r'[0-9]+',rate['exactFactor'][key])
                    or int(rate['exactFactor'][key])<=0
                    for key in ('numerator','denominator'))
                or type(rate.get('sourceChangeIds')) is not list
                or not 1<=len(rate['sourceChangeIds'])<=2
                or len(set(rate['sourceChangeIds']))!=len(
                    rate['sourceChangeIds'])
                or any(type(item) is not str or not 1<=len(item)<=200
                    for item in rate['sourceChangeIds'])):
            raise ValueError('EXPRESSION_CURRENCY_CONVERSION_INVALID')
        return {'op':name,'source':{'op':'SourceAmount'},
            'fromCurrencyMemberId':node['fromCurrencyMemberId'],
            'toCurrencyMemberId':node['toCurrencyMemberId'],
            'outputUnitCurrencyMemberId':node['outputUnitCurrencyMemberId'],
            'rateKind':node['rateKind'],
            'expectedRate':{'strategy':rate['strategy'],
                'exactFactor':dict(rate['exactFactor']),
                'sourceChangeIds':list(rate['sourceChangeIds'])},
            'expectedDataRevision':node['expectedDataRevision'],
            'rounding':node['rounding']},'amount'
    if name == 'SourceValue' and set(node) in (
            {'op', 'memberOverrides', 'valueType'},
            {'op', 'memberOverrides', 'valueType', 'measureDimensionId'}):
        overrides = node['memberOverrides']
        if (not isinstance(overrides, dict)
                or not 1 <= len(overrides) <= 128
                or any(not isinstance(axis, str)
                       or not 1 <= len(axis) <= 200
                       or not isinstance(member, str)
                       or not 1 <= len(member) <= 200
                       for axis, member in overrides.items())
                or node['valueType'] not in ('amount', 'ratio')):
            raise ValueError('EXPRESSION_SOURCE_LOOKUP_INVALID')
        measure_axis = node.get('measureDimensionId')
        if ('measureDimensionId' in node and
                (not isinstance(measure_axis, str)
                 or measure_axis not in overrides)):
            raise ValueError('EXPRESSION_MEASURE_BINDING_INVALID')
        normalized = {'op': name,
                'memberOverrides': dict(sorted(overrides.items())),
                'valueType': node['valueType']}
        if measure_axis is not None:
            normalized['measureDimensionId'] = measure_axis
        return normalized, node['valueType']
    if name == 'SourceTextPredicate':
        fields={'op','memberOverrides','operator','text','missingPolicy'}
        overrides=node.get('memberOverrides'); text=node.get('text')
        if (set(node)!=fields or not isinstance(overrides,dict)
                or not 1<=len(overrides)<=128
                or any(not isinstance(axis,str) or not 1<=len(axis)<=200
                    or not isinstance(member,str) or not 1<=len(member)<=200
                    for axis,member in overrides.items())
                or node.get('operator') not in ('eq','ne')
                or type(text) is not str or len(text)>32768
                or node.get('missingPolicy')!='error'):
            raise ValueError('EXPRESSION_SOURCE_TEXT_PREDICATE_INVALID')
        return {'op':name,'memberOverrides':dict(sorted(overrides.items())),
            'operator':node['operator'],'text':text,
            'missingPolicy':'error'},'boolean'
    if name == 'PublishedAmount' and set(node) in (
            {'op', 'resultKey'}, {'op', 'resultKey', 'memberOverrides'}):
        key = node['resultKey']
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise ValueError('EXPRESSION_RESULT_KEY_INVALID')
        result = {'op': name, 'resultKey': key}
        if 'memberOverrides' in node:
            overrides = node['memberOverrides']
            if (not isinstance(overrides, dict)
                    or not 1 <= len(overrides) <= 128
                    or any(not isinstance(axis, str)
                           or not 1 <= len(axis) <= 200
                           or not isinstance(member, str)
                           or not 1 <= len(member) <= 200
                           for axis, member in overrides.items())):
                raise ValueError('EXPRESSION_MEMBER_OVERRIDES_INVALID')
            result['memberOverrides'] = dict(sorted(overrides.items()))
        return result, 'amount'
    if name == 'PublishedUnitAmount' and set(node) == {
            'op', 'resultKey', 'memberOverrides',
            'outputUnitCurrencyMemberId'}:
        key = node['resultKey']; overrides = node['memberOverrides']
        unit = node['outputUnitCurrencyMemberId']
        if (not isinstance(key, str) or not _KEY.fullmatch(key)
                or not isinstance(overrides, dict)
                or not 0 <= len(overrides) <= 128
                or any(not isinstance(axis, str)
                       or not 1 <= len(axis) <= 200
                       or not isinstance(member, str)
                       or not 1 <= len(member) <= 200
                       for axis, member in overrides.items())
                or not isinstance(unit, str) or not 1 <= len(unit) <= 200):
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_INVALID')
        return {'op': name, 'resultKey': key,
          'memberOverrides': dict(sorted(overrides.items())),
          'outputUnitCurrencyMemberId': unit}, 'amount'
    if name == 'PublishedRatio' and set(node) in (
            {'op', 'resultKey'}, {'op', 'resultKey', 'memberOverrides'}):
        key = node['resultKey']
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise ValueError('EXPRESSION_RESULT_KEY_INVALID')
        result = {'op': name, 'resultKey': key}
        if 'memberOverrides' in node:
            overrides = node['memberOverrides']
            if (not isinstance(overrides, dict)
                    or not 1 <= len(overrides) <= 128
                    or any(not isinstance(axis, str)
                           or not 1 <= len(axis) <= 200
                           or not isinstance(member, str)
                           or not 1 <= len(member) <= 200
                           for axis, member in overrides.items())):
                raise ValueError('EXPRESSION_MEMBER_OVERRIDES_INVALID')
            result['memberOverrides'] = dict(sorted(overrides.items()))
        return result, 'ratio'
    if name in ('AmountLiteral', 'RatioLiteral') and set(node) == {'op', 'decimal'}:
        return {'op': name, 'decimal': _decimal(
            node['decimal'], amount=name == 'AmountLiteral')}, (
            'amount' if name == 'AmountLiteral' else 'ratio')
    if name == 'Compare' and set(node) == {
            'op', 'operator', 'left', 'right'}:
        if node['operator'] not in ('eq', 'ne', 'lt', 'le', 'gt', 'ge'):
            raise ValueError('EXPRESSION_COMPARISON_OPERATOR_INVALID')
        left, left_type = child(node['left'])
        right, right_type = child(node['right'])
        if left_type != right_type or left_type not in ('amount', 'ratio'):
            raise ValueError('EXPRESSION_TYPE_MISMATCH')
        return {'op': name, 'operator': node['operator'],
                'left': left, 'right': right}, 'boolean'
    if name == 'If' and set(node) == {'op', 'test', 'then', 'else'}:
        test, test_type = child(node['test'])
        then, then_type = child(node['then'])
        otherwise, else_type = child(node['else'])
        if (test_type != 'boolean' or then_type != else_type
                or then_type not in ('amount', 'ratio')):
            raise ValueError('EXPRESSION_TYPE_MISMATCH')
        return {'op': name, 'test': test, 'then': then,
                'else': otherwise}, then_type
    if name not in ('Add', 'Subtract', 'Multiply', 'Divide') or set(node) != {
            'op', 'left', 'right'}:
        raise ValueError('EXPRESSION_OPERATOR_UNSUPPORTED')
    left, left_type = child(node['left'])
    right, right_type = child(node['right'])
    if left_type not in ('amount', 'ratio') or right_type not in (
            'amount', 'ratio'):
        raise ValueError('EXPRESSION_TYPE_MISMATCH')
    if name in ('Add', 'Subtract'):
        if left_type != right_type:
            raise ValueError('EXPRESSION_TYPE_MISMATCH')
        result_type = left_type
    elif name == 'Multiply':
        if left_type == right_type == 'amount':
            raise ValueError('EXPRESSION_TYPE_MISMATCH')
        result_type = ('amount' if 'amount' in (left_type, right_type)
                       else 'ratio')
    else:
        if right['op'] == 'RatioLiteral' and Decimal(right['decimal']) == 0:
            raise ValueError('EXPRESSION_DIVISOR_UNSUPPORTED_OR_ZERO')
        if right_type == 'amount':
            if left_type != 'amount':
                raise ValueError('EXPRESSION_TYPE_MISMATCH')
            result_type = 'ratio'
        else:
            result_type = left_type
    return {'op': name, 'left': left, 'right': right}, result_type


def expression_references(node: dict) -> tuple[str, ...]:
    found: set[str] = set()
    def visit(current: dict) -> None:
        if current['op'] in ('PublishedAmount', 'PublishedUnitAmount',
                             'PublishedRatio'):
            found.add(current['resultKey'])
        elif current['op'] in ('CurrencyConvert', 'TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add', 'Subtract', 'Multiply', 'Divide',
                               'Compare'):
            visit(current['left'])
            visit(current['right'])
        elif current['op'] == 'If':
            visit(current['test'])
            visit(current['then'])
            visit(current['else'])
    visit(node)
    if len(found) > 8:
        raise ValueError('EXPRESSION_PUBLISHED_INPUT_LIMIT')
    return tuple(sorted(found))


def applicability_references(node: dict) -> dict[str, dict[str,str]]:
    found={'operands':{},'values':{}}
    def visit(current):
        operation=current['op']
        if operation=='RelationOperand':
            prior=found['operands'].get(current['operandId'])
            if prior is not None and prior!=current['valueType']:
                raise ValueError('EXPRESSION_RELATION_REFERENCE_TYPE_CONFLICT')
            found['operands'][current['operandId']]=current['valueType']
        elif operation=='RelationValue':
            prior=found['values'].get(current['valueId'])
            if prior is not None and prior!=current['valueType']:
                raise ValueError('EXPRESSION_RELATION_REFERENCE_TYPE_CONFLICT')
            found['values'][current['valueId']]=current['valueType']
        elif operation in ('Add','Subtract','Multiply','Divide','Compare'):
            visit(current['left']);visit(current['right'])
        elif operation=='If':
            visit(current['test']);visit(current['then']);visit(current['else'])
        elif operation in ('CurrencyConvert','TemporalWindow'):
            visit(current['source'])
    visit(node)
    return {kind:dict(sorted(items.items())) for kind,items in found.items()}


def currency_conversion(node:dict)->dict|None:
    """Return the one supported top-level typed conversion, if present."""
    if node.get('op')=='CurrencyConvert':return node
    children=[]
    if node.get('op') in ('Add','Subtract','Multiply','Divide','Compare'):
        children=[node['left'],node['right']]
    elif node.get('op')=='If':children=[node['test'],node['then'],node['else']]
    if any(currency_conversion(child) is not None for child in children):
        raise ValueError('EXPRESSION_CURRENCY_CONVERSION_MUST_BE_TOP_LEVEL')
    return None


def temporal_window(node: dict) -> dict | None:
    """Return the one supported top-level temporal expression, if present."""
    if node.get('op') == 'TemporalWindow':
        return node
    children = []
    if node.get('op') in ('Add', 'Subtract', 'Multiply', 'Divide', 'Compare'):
        children = [node['left'], node['right']]
    elif node.get('op') == 'If':
        children = [node['test'], node['then'], node['else']]
    elif node.get('op') == 'CurrencyConvert':
        children = [node['source']]
    if any(temporal_window(child) is not None for child in children):
        raise ValueError('EXPRESSION_TEMPORAL_WINDOW_MUST_BE_TOP_LEVEL')
    return None


def published_lookups(node: dict) -> tuple[tuple[str, tuple], ...]:
    found: set[tuple[str, tuple]] = set()
    def visit(current: dict) -> None:
        if current['op'] == 'PublishedAmount':
            found.add((current['resultKey'], tuple(sorted(
                current.get('memberOverrides', {}).items()))))
        elif current['op'] in ('CurrencyConvert', 'TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add', 'Subtract', 'Multiply', 'Divide',
                               'Compare'):
            visit(current['left'])
            visit(current['right'])
        elif current['op'] == 'If':
            visit(current['test'])
            visit(current['then'])
            visit(current['else'])
    visit(node)
    if len(found) > 8:
        raise ValueError('EXPRESSION_PUBLISHED_LOOKUP_LIMIT')
    return tuple(sorted(found))


def published_unit_lookups(node: dict) -> tuple[tuple[str, tuple, str], ...]:
    found: set[tuple[str, tuple, str]] = set()
    def visit(current: dict) -> None:
        if current['op'] == 'PublishedUnitAmount':
            found.add((current['resultKey'], tuple(sorted(
                current['memberOverrides'].items())),
                current['outputUnitCurrencyMemberId']))
        elif current['op'] in ('CurrencyConvert', 'TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add','Subtract','Multiply','Divide','Compare'):
            visit(current['left']); visit(current['right'])
        elif current['op']=='If':
            for part in ('test','then','else'): visit(current[part])
    visit(node)
    if len(found)>8:raise ValueError('EXPRESSION_PUBLISHED_LOOKUP_LIMIT')
    return tuple(sorted(found))


def published_ratio_lookups(node: dict) -> tuple[tuple[str, tuple], ...]:
    found: set[tuple[str, tuple]] = set()
    def visit(current: dict) -> None:
        if current['op'] == 'PublishedRatio':
            found.add((current['resultKey'], tuple(sorted(
                current.get('memberOverrides', {}).items()))))
        elif current['op'] in ('CurrencyConvert', 'TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add','Subtract','Multiply','Divide','Compare'):
            visit(current['left']); visit(current['right'])
        elif current['op']=='If':
            for part in ('test','then','else'): visit(current[part])
    visit(node)
    if len(found)>8:raise ValueError('EXPRESSION_PUBLISHED_LOOKUP_LIMIT')
    return tuple(sorted(found))


def aligned_output_unit(node: dict) -> str | None:
    lookups=published_unit_lookups(node)
    if not lookups:return None
    units={unit for _,_,unit in lookups}
    if len(units)!=1 or published_lookups(node) or source_lookups(node):
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
    def valid(current:dict)->bool:
        if current['op']=='PublishedUnitAmount':return True
        if current['op']=='RatioLiteral':return True
        if current['op'] in ('Add','Subtract','Multiply','Divide'):
            return valid(current['left']) and valid(current['right'])
        return False
    if not valid(node):
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
    return next(iter(units))


def source_lookups(node: dict) -> tuple[tuple[tuple[str, str], ...], ...]:
    found: set[tuple[tuple[str, str], ...]] = set()
    def visit(current: dict) -> None:
        if current['op'] == 'SourceValue':
            found.add(tuple(sorted(current['memberOverrides'].items())))
        elif current['op'] in ('CurrencyConvert', 'TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add', 'Subtract', 'Multiply', 'Divide',
                               'Compare'):
            visit(current['left'])
            visit(current['right'])
        elif current['op'] == 'If':
            visit(current['test'])
            visit(current['then'])
            visit(current['else'])
    visit(node)
    if len(found) > 8:
        raise ValueError('EXPRESSION_SOURCE_LOOKUP_LIMIT')
    return tuple(sorted(found))


def source_text_lookups(node: dict) -> tuple[tuple[tuple[str,str],...],...]:
    found:set[tuple[tuple[str,str],...]]=set()
    def visit(current:dict)->None:
        if current['op']=='SourceTextPredicate':
            found.add(tuple(sorted(current['memberOverrides'].items())))
        elif current['op'] in ('CurrencyConvert','TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add','Subtract','Multiply','Divide','Compare'):
            visit(current['left']);visit(current['right'])
        elif current['op']=='If':
            for part in ('test','then','else'):visit(current[part])
    visit(node)
    if len(found)>8:raise ValueError('EXPRESSION_SOURCE_LOOKUP_LIMIT')
    return tuple(sorted(found))


def source_measure_bindings(node: dict) -> tuple[tuple[str, str, str], ...]:
    found: set[tuple[str, str, str]] = set()
    def visit(current: dict) -> None:
        if current['op'] == 'SourceValue':
            axis = current.get('measureDimensionId')
            if axis is not None:
                found.add((axis, current['memberOverrides'][axis],
                           current['valueType']))
        elif current['op'] in ('CurrencyConvert', 'TemporalWindow'):
            visit(current['source'])
        elif current['op'] in ('Add', 'Subtract', 'Multiply', 'Divide',
                               'Compare'):
            visit(current['left'])
            visit(current['right'])
        elif current['op'] == 'If':
            visit(current['test'])
            visit(current['then'])
            visit(current['else'])
    visit(node)
    return tuple(sorted(found))


def _published_operand_lineage_sql(index:int,coordinate:str)->str:
    return f'''jsonb_build_object(
        'inputKind','PublishedAmount','resultKey',%s::text,
        'resultStateToken',%s::text,
        'memberOverrides',%s::jsonb,
        'sourceCoordinateId',{coordinate}.coordinate_id,
        'sourceMembers',{coordinate}.members,
        'sourceSeriesKey',{coordinate}.series_key,
        'sourceAmount',p{index}.amount::text,
        'upstreamSourceAmount',p{index}.source_amount::text,
        'upstreamSourceChangeId',p{index}.source_change_id,
        'upstreamSourcePresent',p{index}.source_present,
        'upstreamRowLineage',p{index}.source_lookup_lineage)'''


def _source_lineage_sql(plan: ExpressionPlan) -> tuple[str, tuple[object,...]]:
    """Exact per-output raw and PublishedAmount operand evidence."""
    temporal = temporal_window(plan.expression)
    if temporal is not None:
        definition = temporal['definition']
        item = '''jsonb_build_object(
            'inputKind','RawAmount','sourceCoordinateId',c.coordinate_id,
            'sourceMembers',c.members,'sourceSeriesKey',c.series_key,
            'sourceAmount',n.amount::text,'sourceChangeId',n.change_id,
            'calendarChangeId',temporal_calendar.change_id,
            'calendarOrdinal',temporal_calendar.ordinal)'''
        if definition['operator'] == 'prefix_sum':
            sql = f'''jsonb_agg({item}) OVER (
                PARTITION BY c.members-%s::text
                ORDER BY temporal_calendar.ordinal
                ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)'''
            return sql, (definition['periodDimensionId'],)
        if definition['operator'] == 'period_end':
            return f'jsonb_build_array({item})', ()
        prior = f'''lag({item}) OVER (
            PARTITION BY c.members-%s::text
            ORDER BY temporal_calendar.ordinal)'''
        if definition['boundaryPolicy'] == 'use_opening_value':
            prior = f'''CASE WHEN row_number() OVER (
                PARTITION BY c.members-%s::text
                ORDER BY temporal_calendar.ordinal)=1
                THEN jsonb_build_object('inputKind','OpeningAmount',
                    'amount',%s::text,
                    'resetGroupId',c.members->>%s::text)
                ELSE {prior} END'''
            return (f'jsonb_build_array({prior},{item})',
                    (definition['periodDimensionId'],
                     temporal['openingAmount'],
                     temporal['resetGroupDimensionId'],
                     definition['periodDimensionId']))
        return f'jsonb_build_array({prior},{item})', (
            definition['periodDimensionId'],)
    lookups=source_lookups(plan.expression)
    driver_v2=(plan.driver_policy and plan.driver_policy.get('policyFormat')==
        'openepm-planning-operation-policy-v2')
    raw_kind=("'inputKind','Raw'," if driver_v2
              else "'inputKind','RawAmount',")
    items=[f'''jsonb_build_object(
        {raw_kind}'memberOverrides',%s::jsonb,
        'sourceMembers',rawq{index}.members,
        'sourceSeriesKey',rawq{index}.series_key,
        'sourceAmount',rawv{index}.amount::text,
        'sourceChangeId',rawv{index}.change_id)'''
        for index,_ in enumerate(lookups)]
    params:list[object]=[Jsonb(dict(item)) for item in lookups]
    text_lookups=source_text_lookups(plan.expression)
    def uses_base_amount(node:dict)->bool:
        if node['op']=='SourceAmount':return True
        if node['op'] in ('CurrencyConvert','TemporalWindow'):
            return uses_base_amount(node['source'])
        if node['op'] in ('Add','Subtract','Multiply','Divide','Compare'):
            return uses_base_amount(node['left']) or uses_base_amount(node['right'])
        if node['op']=='If':
            return any(uses_base_amount(node[part])
                       for part in ('test','then','else'))
        return False
    # SourceAmount uses the row-driving coordinate rather than a joined
    # override.  It still belongs in the same complete operand lineage as
    # SourceValue and SourceTextPredicate inputs.
    if text_lookups and uses_base_amount(plan.expression):
        items.append('''jsonb_build_object(
            'inputKind','RawAmount','memberOverrides','{}'::jsonb,
            'sourceMembers',c.members,'sourceSeriesKey',c.series_key,
            'sourceAmount',n.amount::text,'sourceChangeId',n.change_id)''')
    items.extend(f'''jsonb_build_object(
        'inputKind','RawText','memberOverrides',%s::jsonb,
        'sourceMembers',rawtq{index}.members,
        'sourceSeriesKey',rawtq{index}.series_key,
        'sourceText',rawtv{index}.text_value,
        'sourceChangeId',rawtv{index}.change_id)'''
        for index,_ in enumerate(text_lookups))
    params.extend(Jsonb(dict(item)) for item in text_lookups)
    pins={item['resultKey']:item for item in plan.published_inputs or ()}
    published=(published_lookups(plan.expression) if driver_v2 else ())
    for index,(key,overrides) in enumerate(published):
        coordinate=f'q{index}' if overrides else 'c';pin=pins[key]
        items.append(_published_operand_lineage_sql(index,coordinate))
        params.extend((key,pin['resultStateToken'],
                       Jsonb(dict(overrides))))
    return (('jsonb_build_array('+','.join(items)+')') if items
            else "'[]'::jsonb",tuple(params))


def _lineage_depth(value: object) -> int:
    if isinstance(value,dict):
        return 1+max((_lineage_depth(item) for item in value.values()),
                     default=0)
    if isinstance(value,list):
        return 1+max((_lineage_depth(item) for item in value),default=0)
    return 0


def _validate_stored_lineage(value: object, *, canonical_bytes: int,
                             max_canonical_bytes: int,max_depth: int) -> None:
    if (type(canonical_bytes) is not int or canonical_bytes<0
            or canonical_bytes>max_canonical_bytes
            or _lineage_depth(value)>max_depth):
        raise ValueError('DRIVER_POLICY_UPSTREAM_LINEAGE_LIMIT')


def compiler_for(plan: ExpressionPlan) -> tuple[str, str]:
    def conditional(node: dict) -> bool:
        if node['op'] in ('Compare', 'If'):
            return True
        if node['op'] in ('Add', 'Subtract', 'Multiply', 'Divide'):
            return conditional(node['left']) or conditional(node['right'])
        return False
    if plan.context_dependencies:
        return CONTEXT_EXPRESSION_COMPILER,CONTEXT_EXPRESSION_PLAN_DIGEST
    if plan.applicability_domain:
        return APPLICABILITY_DOMAIN_COMPILER,APPLICABILITY_DOMAIN_PLAN_DIGEST
    if plan.selected_domain and temporal_window(plan.expression) is not None:
        return (TEMPORAL_SELECTED_DOMAIN_COMPILER,
                TEMPORAL_SELECTED_DOMAIN_PLAN_DIGEST)
    if plan.selected_domain:
        return SELECTED_DOMAIN_COMPILER,SELECTED_DOMAIN_PLAN_DIGEST
    if plan.calculated_member:
        return CALCULATED_MEMBER_COMPILER,CALCULATED_MEMBER_PLAN_DIGEST
    if plan.source_member_sets:
        return SOURCE_MEMBER_SETS_COMPILER,SOURCE_MEMBER_SETS_PLAN_DIGEST
    if source_text_lookups(plan.expression):
        return TEXT_PREDICATE_COMPILER,TEXT_PREDICATE_PLAN_DIGEST
    if plan.two_axis_reduction_context is not None:
        return (TWO_AXIS_HIERARCHY_REDUCTION_COMPILER,
                TWO_AXIS_HIERARCHY_REDUCTION_PLAN_DIGEST)
    if plan.reduction_context is not None:
        return HIERARCHY_REDUCTION_COMPILER,HIERARCHY_REDUCTION_PLAN_DIGEST
    if plan.expression.get('op')=='CurrencyConvert':
        return CURRENCY_CONVERSION_COMPILER,CURRENCY_CONVERSION_PLAN_DIGEST
    if plan.result_unit == ('Ratio', 12):
        return RATIO_RESULT_COMPILER,RATIO_RESULT_PLAN_DIGEST
    if plan.amount_unit and not plan.reduce_member_set:
        return (RAW_UNIT_EXPRESSION_COMPILER,
                RAW_UNIT_EXPRESSION_PLAN_DIGEST)
    if aligned_output_unit(plan.expression) is not None:
        return UNIT_ALIGNED_COMPILER,UNIT_ALIGNED_PLAN_DIGEST
    if plan.reduce_member_set:
        if plan.weight_expression:
            return WEIGHTED_AVERAGE_COMPILER,WEIGHTED_AVERAGE_PLAN_DIGEST
        if plan.amount_unit:
            return (UNIT_BOUND_REDUCTION_COMPILER,
                    UNIT_BOUND_REDUCTION_PLAN_DIGEST)
        if plan.reduce_member_set[3] == ('AverageAmount','CountPresent'):
            return MEMBER_SET_AVERAGE_COMPILER, MEMBER_SET_AVERAGE_PLAN_DIGEST
        return MEMBER_SET_REDUCTION_COMPILER, MEMBER_SET_REDUCTION_PLAN_DIGEST
    if plan.reduce_member_sets:
        if len(plan.reduce_member_sets[0])>2:
            return (MULTI_AXIS_MEMBER_SET_REDUCTION_COMPILER,
                    MULTI_AXIS_MEMBER_SET_REDUCTION_PLAN_DIGEST)
        return (TWO_AXIS_MEMBER_SET_REDUCTION_COMPILER,
                TWO_AXIS_MEMBER_SET_REDUCTION_PLAN_DIGEST)
    if plan.source_domain:
        return (EXPLICIT_MISSING_DEFAULT_COMPILER,
                EXPLICIT_MISSING_DEFAULT_PLAN_DIGEST)
    if plan.target_member_sets:
        if len(plan.target_member_sets)>2:
            return MULTI_AXIS_MEMBER_SET_COMPILER,MULTI_AXIS_MEMBER_SET_PLAN_DIGEST
        return TWO_AXIS_MEMBER_SET_COMPILER, TWO_AXIS_MEMBER_SET_PLAN_DIGEST
    if plan.target_member_set:
        return MEMBER_SET_TRANSFORM_COMPILER, MEMBER_SET_TRANSFORM_PLAN_DIGEST
    if plan.driver_policy:
        if not source_measure_bindings(plan.expression):
            raise ValueError('EXPRESSION_POLICY_DRIVER_MEASURE_BINDING_REQUIRED')
        if plan.driver_policy.get('policyFormat')==(
                'openepm-planning-operation-policy-v2'):
            return (PUBLISHED_DEPENDENCY_DRIVER_COMPILER,
                    PUBLISHED_DEPENDENCY_DRIVER_PLAN_DIGEST)
        if 'stateToken' in plan.driver_policy:
            return (PUBLISHED_POLICY_DRIVER_COMPILER,
                    PUBLISHED_POLICY_DRIVER_PLAN_DIGEST)
        return POLICY_DRIVER_COMPILER, POLICY_DRIVER_PLAN_DIGEST
    if source_lookups(plan.expression):
        if source_measure_bindings(plan.expression):
            return TYPED_DRIVER_COMPILER, TYPED_DRIVER_PLAN_DIGEST
        return RAW_DRIVER_COMPILER, RAW_DRIVER_PLAN_DIGEST
    if plan.saved_rule:
        if 'memberParameters' in plan.saved_rule:
            return MEMBER_PARAMETER_RULE_COMPILER, MEMBER_PARAMETER_RULE_PLAN_DIGEST
        if 'bindings' in plan.saved_rule:
            return PARAMETERIZED_RULE_COMPILER, PARAMETERIZED_RULE_PLAN_DIGEST
        return SAVED_RULE_COMPILER, SAVED_RULE_PLAN_DIGEST
    if _has_dynamic_divisor(plan.expression):
        return DYNAMIC_DIVISION_COMPILER, DYNAMIC_DIVISION_PLAN_DIGEST
    if plan.target_members:
        return TRANSFORM_COMPILER, TRANSFORM_PLAN_DIGEST
    if conditional(plan.expression):
        return CONDITIONAL_COMPILER, CONDITIONAL_PLAN_DIGEST
    lookups = published_lookups(plan.expression)
    if any(overrides for _, overrides in lookups):
        return MAPPED_COMPILER, MAPPED_PLAN_DIGEST
    if lookups:
        return COMPOSED_COMPILER, COMPOSED_PLAN_DIGEST
    return COMPILER, PLAN_DIGEST


def supported_compiler_for(plan: ExpressionPlan, compiler: str,
                           plan_digest: str) -> bool:
    """Accept the current identity or a precise pre-v33 admitted identity."""
    if (compiler, plan_digest) == compiler_for(plan):
        return True
    if not plan.reduce_member_sets or len(plan.reduce_member_sets[0]) != 2:
        return False
    if plan.saved_rule:
        legacy = ((MEMBER_PARAMETER_RULE_COMPILER,
                   MEMBER_PARAMETER_RULE_PLAN_DIGEST)
                  if 'memberParameters' in plan.saved_rule else
                  (PARAMETERIZED_RULE_COMPILER,
                   PARAMETERIZED_RULE_PLAN_DIGEST)
                  if 'bindings' in plan.saved_rule else
                  (SAVED_RULE_COMPILER, SAVED_RULE_PLAN_DIGEST))
    else:
        legacy = (COMPILER, PLAN_DIGEST)
    return (compiler, plan_digest) == legacy


def _has_dynamic_divisor(node: dict) -> bool:
    name = node['op']
    if name == 'Divide' and node['right']['op'] != 'RatioLiteral':
        return True
    if name in ('Add', 'Subtract', 'Multiply', 'Divide', 'Compare'):
        return (_has_dynamic_divisor(node['left'])
                or _has_dynamic_divisor(node['right']))
    if name == 'If':
        return any(_has_dynamic_divisor(node[part])
                   for part in ('test', 'then', 'else'))
    if name in ('CurrencyConvert','TemporalWindow'):
        return False
    return False


def _sql(node: dict, aliases: dict[tuple, str] | None = None,
         source_sql: str = 'n.amount'
         ) -> tuple[str, list[object]]:
    name = node['op']
    if name == 'SourceAmount':
        return source_sql, []
    if name == 'RelationOperand':
        lookup=('relation_operand',node['operandId'])
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_RELATION_OPERAND_UNRESOLVED')
        return aliases[lookup]+'.amount',[]
    if name == 'RelationValue':
        lookup=('relation_value',node['valueId'])
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_RELATION_VALUE_UNRESOLVED')
        resolved=aliases[lookup]
        if (not isinstance(resolved,tuple) or len(resolved)!=2
                or not isinstance(resolved[0],str)
                or not isinstance(resolved[1],tuple)):
            raise ValueError('EXPRESSION_RELATION_VALUE_UNRESOLVED')
        return resolved[0],list(resolved[1])
    if name == 'TemporalWindow':
        definition = node['definition']
        period_axis = definition['periodDimensionId']
        window = (f'PARTITION BY c.members-%s::text '
                  f'ORDER BY temporal_calendar.ordinal '
                  f'ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW')
        if definition['operator'] == 'prefix_sum':
            return f'sum({source_sql}) OVER ({window})', [period_axis]
        if definition['operator'] == 'period_end':
            return source_sql, []
        predecessor_window = (f'PARTITION BY c.members-%s::text '
                              f'ORDER BY temporal_calendar.ordinal')
        prior = f'lag({source_sql}) OVER ({predecessor_window})'
        if definition['boundaryPolicy'] == 'use_opening_value':
            prior = (f'CASE WHEN row_number() OVER ({predecessor_window})=1 '
                     f'THEN %s::numeric ELSE {prior} END')
            return (f'({source_sql}-({prior}))',
                    [period_axis, Decimal(node['openingAmount']), period_axis])
        return f'({source_sql}-({prior}))', [period_axis]
    if name=='CurrencyConvert':
        factor=node['expectedRate']['exactFactor']
        return (f'({source_sql} * %s::numeric / %s::numeric)',[
            Decimal(factor['numerator']),Decimal(factor['denominator'])])
    if name == 'SourceValue':
        lookup = ('raw', tuple(sorted(
            node['memberOverrides'].items())))
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_SOURCE_LOOKUP_UNRESOLVED')
        return aliases[lookup] + '.amount', []
    if name=='SourceTextPredicate':
        lookup=('raw_text',tuple(sorted(node['memberOverrides'].items())))
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_SOURCE_TEXT_LOOKUP_UNRESOLVED')
        operator='=' if node['operator']=='eq' else '<>'
        return f'{aliases[lookup]}.text_value {operator} %s::text',[node['text']]
    if name == 'PublishedAmount':
        lookup = ('published', node['resultKey'], tuple(sorted(
            node.get('memberOverrides', {}).items())))
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
        return aliases[lookup] + '.amount', []
    if name == 'PublishedUnitAmount':
        lookup = ('published_unit', node['resultKey'], tuple(sorted(
            node['memberOverrides'].items())),
            node['outputUnitCurrencyMemberId'])
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNRESOLVED')
        return aliases[lookup] + '.amount', []
    if name == 'PublishedRatio':
        lookup = ('published_ratio', node['resultKey'], tuple(sorted(
            node.get('memberOverrides', {}).items())))
        if aliases is None or lookup not in aliases:
            raise ValueError('EXPRESSION_PUBLISHED_RATIO_INPUT_UNRESOLVED')
        return aliases[lookup] + '.ratio', []
    if name in ('AmountLiteral', 'RatioLiteral'):
        return '%s::numeric', [Decimal(node['decimal'])]
    if name == 'If':
        test_sql, test_params = _sql(node['test'], aliases,source_sql)
        then_sql, then_params = _sql(node['then'], aliases,source_sql)
        else_sql, else_params = _sql(node['else'], aliases,source_sql)
        return (f'(CASE WHEN {test_sql} THEN {then_sql} '
                f'ELSE {else_sql} END)',
                test_params + then_params + else_params)
    left_sql, left_params = _sql(node['left'], aliases,source_sql)
    right_sql, right_params = _sql(node['right'], aliases,source_sql)
    operator = ({'eq': '=', 'ne': '<>', 'lt': '<', 'le': '<=',
                 'gt': '>', 'ge': '>='}[node['operator']]
                if name == 'Compare' else
                {'Add': '+', 'Subtract': '-', 'Multiply': '*',
                 'Divide': '/'}[name])
    if name == 'Divide' and node['right']['op'] != 'RatioLiteral':
        right_sql = f'NULLIF({right_sql},0)'
    return f'({left_sql} {operator} {right_sql})', left_params + right_params


def _dynamic_division_failure_sql(
        node: dict, aliases: dict[tuple, str] | None = None,
        source_sql: str = 'n.amount') -> tuple[str, list[object]]:
    """Return a predicate for an evaluated missing/zero dynamic divisor."""
    name = node['op']
    if name == 'If':
        test_sql, test_params = _sql(node['test'], aliases, source_sql)
        test_failure, test_failure_params = _dynamic_division_failure_sql(
            node['test'], aliases, source_sql)
        then_failure, then_params = _dynamic_division_failure_sql(
            node['then'], aliases, source_sql)
        else_failure, else_params = _dynamic_division_failure_sql(
            node['else'], aliases, source_sql)
        return (
            f'(({test_failure}) OR ({test_sql}) IS NULL OR '
            f'(CASE WHEN {test_sql} THEN ({then_failure}) '
            f'ELSE ({else_failure}) END))',
            test_failure_params + test_params + test_params
            + then_params + else_params)
    if name in ('Add', 'Subtract', 'Multiply', 'Divide', 'Compare'):
        left_failure, left_params = _dynamic_division_failure_sql(
            node['left'], aliases, source_sql)
        right_failure, right_params = _dynamic_division_failure_sql(
            node['right'], aliases, source_sql)
        predicate = f'(({left_failure}) OR ({right_failure})'
        params = left_params + right_params
        if name == 'Divide' and node['right']['op'] != 'RatioLiteral':
            divisor_sql, divisor_params = _sql(
                node['right'], aliases, source_sql)
            predicate += (f' OR ({divisor_sql}) IS NULL '
                          f'OR ({divisor_sql}) = 0')
            params += divisor_params + divisor_params
        return predicate + ')', params
    return 'FALSE', []


@dataclass(frozen=True, slots=True)
class ExpressionPlan:
    source_members: tuple[tuple[str, str], ...]
    expression: dict
    result_key: str
    expected_target_state_token: str | None
    published_inputs: tuple[dict, ...] | None = ()
    target_members: tuple[tuple[str, str], ...] = ()
    saved_rule: dict | None = None
    driver_policy: dict | None = None
    target_member_set: tuple[str, tuple[str, ...]] | None = None
    reduce_member_set: tuple[str, tuple[str, ...], str,
                             tuple[str, ...]] | None = None
    target_member_sets: tuple[tuple[str, tuple[str, ...]], ...] | None = None
    source_domain: tuple[tuple[str, tuple[str, ...]], ...] | None = None
    missing_default: str | None = None
    amount_unit: tuple[str, str, str] | None = None
    weight_expression: dict | None = None
    result_unit: tuple[str, int] | None = None
    reduction_context: dict | None = None
    reduce_member_sets: tuple[tuple[tuple[str, tuple[str, ...], str], ...],
                              tuple[str, ...]] | None = None
    two_axis_reduction_context: dict | None = None
    required_source_count: int | None = None
    context_dependencies: tuple[dict, ...] = ()
    context_assertions: tuple[dict, ...] = ()
    source_member_sets: tuple[tuple[str, tuple[str, ...]], ...] = ()
    calculated_member: dict | None = None
    selected_domain: dict | None = None
    applicability_domain: dict | None = None

    @property
    def normalized_program(self) -> dict:
        if self.published_inputs is None:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
        normalized = {'version': 2, 'function': FUNCTION,
                'sourceMembers': dict(self.source_members),
                'expression': self.expression,
                'resultKey': self.result_key,
                'expectedTargetStateToken':
                    self.expected_target_state_token,
                'rounding': ('half-even-final-12'
                             if self.result_unit == ('Ratio', 12)
                             else 'half-even-final-8'),
                'inputGrain': 'present_full_coordinate',
                'outputGrain': ('declared_target_member_overrides'
                                if self.target_members else
                                'same_full_coordinate')}
        if self.result_unit is not None:
            normalized['resultUnit'] = {
                'type': self.result_unit[0], 'scale': self.result_unit[1]}
        if self.target_members:
            normalized['targetMembers'] = dict(self.target_members)
        if self.source_member_sets:
            normalized['sourceMemberSets'] = [
                {'dimensionId': axis, 'memberIds': list(members)}
                for axis, members in self.source_member_sets]
        if self.calculated_member:
            normalized['calculatedMember']=self.calculated_member
        if self.selected_domain:
            normalized.pop('sourceMembers')
            normalized.pop('targetMembers',None)
            normalized['selectedDomain']=self.selected_domain
        if self.applicability_domain:
            normalized.pop('sourceMembers')
            normalized.pop('targetMembers',None)
            normalized['inputGrain']='current_sparse_relation_anchors'
            normalized['outputGrain']='relation_target_overrides'
            normalized['applicabilityDomain']=self.applicability_domain
        if self.target_member_set:
            normalized['outputGrain'] = 'one_axis_explicit_member_set'
            normalized['targetMemberSet'] = {
                'dimensionId': self.target_member_set[0],
                'memberIds': list(self.target_member_set[1])}
        if self.reduce_member_set:
            axis,members,target,measures=self.reduce_member_set
            normalized['outputGrain']='one_axis_member_set_reduction'
            normalized['reduceMemberSet']={'dimensionId':axis,
                'sourceMemberIds':list(members),'targetMemberId':target,
                'measures':list(measures)}
            if self.weight_expression:
                normalized['reduceMemberSet']['weightExpression']=(
                    self.weight_expression)
                normalized['reduceMemberSet']['zeroWeightPolicy']='error'
        if self.reduction_context:
            normalized['hierarchyReductionContext'] = self.reduction_context
        if self.reduce_member_sets:
            selections,measures=self.reduce_member_sets
            normalized['outputGrain']=(
                'two_axis_member_set_reduction' if len(selections)==2 else
                'bounded_multi_axis_member_set_reduction')
            normalized['reduceMemberSets']={
                'selections':[{'dimensionId':axis,
                    'sourceMemberIds':list(member_ids),
                    'targetMemberId':target}
                    for axis,member_ids,target in selections],
                'measures':list(measures)}
        if self.two_axis_reduction_context:
            normalized['hierarchyTwoAxisReductionContext']=(
                self.two_axis_reduction_context)
        if self.amount_unit:
            normalized['amountUnit'] = {
                'dimensionId': self.amount_unit[0],
                'memberId': self.amount_unit[1],
                'binding': self.amount_unit[2]}
        if self.required_source_count is not None:
            normalized['requiredSourceCount'] = self.required_source_count
        if self.context_dependencies:
            normalized['contextDependencies'] = [dict(item)
                for item in self.context_dependencies]
            normalized['contextAssertions'] = [dict(item)
                for item in self.context_assertions]
        if self.target_member_sets:
            normalized['outputGrain']=(
                'two_axis_explicit_member_sets'
                if len(self.target_member_sets)==2 else
                'bounded_multi_axis_explicit_member_sets')
            normalized['targetMemberSets']=[{'dimensionId':axis,
                'memberIds':list(member_ids)}
                for axis,member_ids in self.target_member_sets]
        if self.source_domain:
            normalized.pop('sourceMembers')
            normalized['inputGrain']='complete_explicit_bounded_domain'
            normalized['sourceDomain']=[{'dimensionId':axis,
                'memberIds':list(member_ids)} for axis,member_ids in self.source_domain]
            normalized['missingDefault']={'type':'AmountLiteral',
                                          'decimal':self.missing_default}
        if self.saved_rule:
            normalized['savedRule'] = self.saved_rule
        if self.driver_policy:
            normalized['driverPolicy'] = self.driver_policy
        if self.published_inputs:
            normalized['publishedInputs'] = list(self.published_inputs)
        return normalized


def _saved_rule_binding_valid(value: object) -> bool:
    if isinstance(value, str):
        return 1 <= len(value) <= 200
    if not isinstance(value, dict):
        return False
    try:
        normalized, kind = _expression({'op': 'CurrencyConvert',
            'source': {'op': 'SourceAmount'}, **value,
            'rounding': 'half-even-final-8'})
    except ValueError:
        return False
    return kind == 'amount' and set(normalized) == {
        'op', 'source', 'fromCurrencyMemberId', 'toCurrencyMemberId',
        'outputUnitCurrencyMemberId', 'rateKind', 'expectedRate',
        'expectedDataRevision', 'rounding'}


def compile_expression_program(program: object, *,
                               expected_target_state_token: str | None,
                               published_inputs: tuple[dict, ...] | None = None,
                               saved_rule: dict | None = None,
                               driver_policy: dict | None = None,
                               reduction_context: dict | None = None,
                               two_axis_reduction_context: dict | None = None,
                               allow_legacy_source_value: bool = False,
                               sealed_context_dependencies: tuple[dict, ...] | None = None,
                               calculated_member: dict | None = None,
                               ) -> ExpressionPlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)
            or (set(program['arguments']) - {
                'amountUnit', 'resultUnit', 'requiredSourceCount',
                'contextDependencies','contextAssertions',
                'sourceMemberSets'}) not in (
                {'sourceMembers', 'expression', 'resultKey'},
                {'sourceMembers', 'expression', 'resultKey',
                 'targetMembers'},
                {'sourceMembers', 'expression', 'resultKey',
                 'targetMemberSet'},
                {'sourceMembers', 'expression', 'resultKey',
                 'reduceMemberSet'},
                {'sourceMembers', 'expression', 'resultKey',
                 'reduceMemberSets'},
                {'sourceMembers', 'expression', 'resultKey',
                 'targetMemberSets'},
                {'sourceDomain','missingDefault','expression','resultKey'},
                {'selectedDomain','expression','resultKey'},
                {'applicabilityDomain','expression','resultKey'})):
        raise ValueError('V2_EXPRESSION_ARGUMENTS_INVALID')
    args = program['arguments']
    selected_domain=args.get('selectedDomain')
    normalized_selected_domain=None
    if selected_domain is not None:
        from .selected_domain_contract import canonical_selected_domain
        selection=(selected_domain.get('sourceSelection')
                   if isinstance(selected_domain,dict) else None)
        raw_dimensions=(selection.get('dimensions')
                        if isinstance(selection,dict) else None)
        if not isinstance(raw_dimensions,list):
            raise ValueError('SELECTED_DOMAIN_INVALID')
        active_dimensions=tuple(sorted(
            item.get('dimensionId') for item in raw_dimensions
            if isinstance(item,dict) and isinstance(item.get('dimensionId'),str)))
        normalized_selected_domain=canonical_selected_domain(
            selected_domain,active_dimensions=active_dimensions)
    applicability_domain=args.get('applicabilityDomain')
    normalized_applicability_domain=None
    if applicability_domain is not None:
        from .applicability_domain_contract import normalize_applicability_domain
        normalized_applicability_domain=normalize_applicability_domain(
            applicability_domain)
    context_dependencies=();context_assertions=()
    if ('contextDependencies' in args) != ('contextAssertions' in args):
        raise ValueError('EXPRESSION_CONTEXT_PAIR_REQUIRED')
    if 'contextDependencies' in args:
        from .expression_context_dependencies import (
            normalize_assertions,normalize_requests,normalize_sealed,
            requests_from_sealed)
        context_assertions=normalize_assertions(args['contextAssertions'])
        requested=normalize_requests(args['contextDependencies'])
        if sealed_context_dependencies is not None:
            context_dependencies=normalize_sealed(
                list(sealed_context_dependencies))
            if requests_from_sealed(context_dependencies)!=requested:
                raise ValueError('EXPRESSION_CONTEXT_SEALED_MISMATCH')
        else:
            context_dependencies=requested
    result_unit=args.get('resultUnit');normalized_result_unit=None
    if result_unit is not None:
        if (type(result_unit) is not dict
                or result_unit != {'type':'Ratio','scale':12}):
            raise ValueError('EXPRESSION_RESULT_UNIT_INVALID')
        normalized_result_unit=('Ratio',12)
    amount_unit=args.get('amountUnit');normalized_amount_unit=None
    if amount_unit is not None:
        if (type(amount_unit) is not dict
                or set(amount_unit)!={'dimensionId','memberId','binding'}
                or type(amount_unit.get('dimensionId')) is not str
                or not 1<=len(amount_unit['dimensionId'])<=200
                or type(amount_unit.get('memberId')) is not str
                or not 1<=len(amount_unit['memberId'])<=200
                or amount_unit.get('binding')!='EntityDefaultCurrency'):
            raise ValueError('EXPRESSION_AMOUNT_UNIT_INVALID')
        normalized_amount_unit=(amount_unit['dimensionId'],
                                amount_unit['memberId'],
                                amount_unit['binding'])
    if context_dependencies and normalized_amount_unit is None:
        raise ValueError('EXPRESSION_CONTEXT_TYPED_AMOUNT_REQUIRED')
    required_source_count=args.get('requiredSourceCount')
    if (required_source_count is not None
            and (type(required_source_count) is not int
                 or not 1 <= required_source_count <= 500)):
        raise ValueError('EXPRESSION_REQUIRED_SOURCE_COUNT_INVALID')
    members, key = args.get('sourceMembers',{}), args['resultKey']
    if (not isinstance(members, dict) or len(members) > 32
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in members.items())
            or not isinstance(key, str) or not _KEY.fullmatch(key)):
        raise ValueError('V2_EXPRESSION_ARGUMENTS_INVALID')
    if expected_target_state_token is not None:
        require_state_token(expected_target_state_token,
            error='EXPRESSION_TARGET_STATE_TOKEN_INVALID')
    targets = (args.get('targetMembers', {}) if normalized_selected_domain is None
        and normalized_applicability_domain is None
        else {normalized_selected_domain['targetMapping']['dimensionId']:
              normalized_selected_domain['targetMapping']['memberId']}
        if normalized_selected_domain is not None else {})
    if (not isinstance(targets, dict)
            or ('targetMembers' in args and not 1 <= len(targets) <= 128)
            or any(not isinstance(axis, str)
                   or not isinstance(member, str)
                   or not 1 <= len(member) <= 200
                   for axis, member in targets.items())):
        raise ValueError('EXPRESSION_TARGET_MEMBERS_INVALID')
    source_sets=args.get('sourceMemberSets',[]);normalized_source_sets=()
    if source_sets:
        if (type(source_sets) is not list or not 1<=len(source_sets)<=32
                or any(type(item) is not dict
                    or set(item)!={'dimensionId','memberIds'}
                    or type(item.get('dimensionId')) is not str
                    or not 1<=len(item['dimensionId'])<=200
                    or item['dimensionId'] in members
                    or type(item.get('memberIds')) is not list
                    or not 1<=len(item['memberIds'])<=100
                    or item['memberIds']!=sorted(set(item['memberIds']))
                    or any(type(member) is not str
                           or not 1<=len(member)<=200
                           for member in item['memberIds'])
                    for item in source_sets)
                or len({item['dimensionId'] for item in source_sets})!=
                   len(source_sets)):
            raise ValueError('EXPRESSION_SOURCE_MEMBER_SETS_INVALID')
        normalized_source_sets=tuple(sorted((item['dimensionId'],
            tuple(item['memberIds'])) for item in source_sets))
    source_set_map=dict(normalized_source_sets)
    if (normalized_selected_domain is None and any(
            axis not in members and axis not in source_set_map
            or members.get(axis)==member
            or member in source_set_map.get(axis,())
            for axis,member in targets.items())):
        raise ValueError('EXPRESSION_TARGET_MEMBERS_INVALID')
    target_set=args.get('targetMemberSet')
    normalized_target_set=None
    if target_set is not None:
        if (type(target_set) is not dict
                or set(target_set)!={'dimensionId','memberIds'}
                or type(target_set['dimensionId']) is not str
                or target_set['dimensionId'] not in members
                or type(target_set['memberIds']) is not list
                or not 1<=len(target_set['memberIds'])<=100
                or any(type(member) is not str or not 1<=len(member)<=200
                       for member in target_set['memberIds'])
                or len(set(target_set['memberIds']))!=len(target_set['memberIds'])
                or members[target_set['dimensionId']] in target_set['memberIds']):
            raise ValueError('EXPRESSION_TARGET_MEMBER_SET_INVALID')
        normalized_target_set=(target_set['dimensionId'],
                               tuple(target_set['memberIds']))
    reduction=args.get('reduceMemberSet');normalized_reduction=None
    normalized_weight=None
    if reduction is not None:
        ordinary={'dimensionId','sourceMemberIds','targetMemberId','measures'}
        weighted=ordinary|{'weightExpression','zeroWeightPolicy'}
        weighted_shape=(type(reduction) is dict and set(reduction)==weighted)
        if (type(reduction) is not dict or set(reduction) not in (
                ordinary,weighted)
                or reduction.get('measures') not in (
                    ['SumAmount','CountPresent'],
                    ['AverageAmount','CountPresent'],
                    ['WeightedAverageAmount','SumWeight','CountPresent'])
                or (weighted_shape != (reduction.get('measures')==
                    ['WeightedAverageAmount','SumWeight','CountPresent']))
                or (weighted_shape and reduction.get('zeroWeightPolicy')!=
                    'error')
                or type(reduction.get('dimensionId')) is not str
                or reduction['dimensionId'] in members
                or type(reduction.get('sourceMemberIds')) is not list
                or not 1<=len(reduction['sourceMemberIds'])<=100
                or any(type(item) is not str or not 1<=len(item)<=200
                       for item in reduction['sourceMemberIds'])
                or len(set(reduction['sourceMemberIds']))!=len(
                    reduction['sourceMemberIds'])
                or type(reduction.get('targetMemberId')) is not str
                or not 1<=len(reduction['targetMemberId'])<=200
                or reduction['targetMemberId'] in reduction['sourceMemberIds']):
            raise ValueError('EXPRESSION_REDUCE_MEMBER_SET_INVALID')
        normalized_reduction=(reduction['dimensionId'],
            tuple(reduction['sourceMemberIds']),reduction['targetMemberId'],
            tuple(reduction['measures']))
        if weighted_shape:
            normalized_weight,weight_type=_expression(
                reduction['weightExpression'])
            if (weight_type!='ratio' or normalized_weight.get('op')!='SourceValue'
                    or normalized_weight.get('valueType')!='ratio'
                    or 'measureDimensionId' not in normalized_weight
                    or set(normalized_weight['memberOverrides'])!={
                        normalized_weight['measureDimensionId']}):
                raise ValueError('EXPRESSION_WEIGHT_SOURCE_INVALID')
    reductions=args.get('reduceMemberSets'); normalized_reductions=None
    if reductions is not None:
        if (type(reductions) is not dict
                or set(reductions)!={'selections','measures'}
                or reductions.get('measures') not in (
                    ['SumAmount','CountPresent'],
                    ['AverageAmount','CountPresent'])
                or type(reductions.get('selections')) is not list
                or not 2<=len(reductions['selections'])<=4
                or (len(reductions['selections'])>2 and
                    reductions.get('measures')!=
                        ['SumAmount','CountPresent'])):
            raise ValueError('EXPRESSION_REDUCE_MEMBER_SETS_INVALID')
        normalized=[]
        for item in reductions['selections']:
            if (type(item) is not dict
                    or set(item)!={'dimensionId','sourceMemberIds',
                                   'targetMemberId'}
                    or type(item.get('dimensionId')) is not str
                    or item['dimensionId'] in members
                    or type(item.get('sourceMemberIds')) is not list
                    or not 1<=len(item['sourceMemberIds'])<=100
                    or item['sourceMemberIds']!=sorted(set(
                        item['sourceMemberIds']))
                    or any(type(value) is not str or not 1<=len(value)<=200
                        for value in item['sourceMemberIds'])
                    or type(item.get('targetMemberId')) is not str
                    or not 1<=len(item['targetMemberId'])<=200
                    or item['targetMemberId'] in item['sourceMemberIds']):
                raise ValueError('EXPRESSION_REDUCE_MEMBER_SETS_INVALID')
            normalized.append((item['dimensionId'],
                tuple(item['sourceMemberIds']),item['targetMemberId']))
        axes=[item[0] for item in normalized]
        if (axes!=sorted(set(axes))
                or math.prod(len(item[1]) for item in normalized)>500):
            raise ValueError('EXPRESSION_REDUCE_MEMBER_SETS_INVALID')
        normalized_reductions=(tuple(normalized),
            tuple(reductions['measures']))
    target_sets=args.get('targetMemberSets');normalized_target_sets=None
    if target_sets is not None:
        if (type(target_sets) is not list or not 2<=len(target_sets)<=4
                or any(type(item) is not dict
                       or set(item)!={'dimensionId','memberIds'}
                       or type(item.get('dimensionId')) is not str
                       or item['dimensionId'] not in members
                       or type(item.get('memberIds')) is not list
                       or not 1<=len(item['memberIds'])<=100
                       or any(type(member) is not str or not 1<=len(member)<=200
                              for member in item['memberIds'])
                       or len(set(item['memberIds']))!=len(item['memberIds'])
                       or members.get(item['dimensionId']) in item['memberIds']
                       for item in target_sets)
                or len({item['dimensionId'] for item in target_sets})!=len(
                    target_sets)):
            raise ValueError('EXPRESSION_TARGET_MEMBER_SETS_INVALID')
        cardinality=1
        for item in target_sets:cardinality*=len(item['memberIds'])
        if cardinality>500:
            raise ValueError('EXPRESSION_TARGET_MEMBER_SETS_INVALID')
        normalized_items=tuple((item['dimensionId'],tuple(item['memberIds']))
            for item in target_sets)
        normalized_target_sets=(normalized_items if len(normalized_items)==2
            else tuple(sorted((axis,tuple(sorted(member_ids)))
                              for axis,member_ids in normalized_items)))
    source_domain=args.get('sourceDomain');normalized_source_domain=None
    missing_default=args.get('missingDefault');normalized_default=None
    if source_domain is not None:
        product=1
        if (type(source_domain) is not list or not 1<=len(source_domain)<=32
                or type(missing_default) is not dict
                or set(missing_default)!={'type','decimal'}
                or missing_default.get('type')!='AmountLiteral'):
            raise ValueError('EXPRESSION_SOURCE_DOMAIN_INVALID')
        axes=[];normalized=[]
        for item in source_domain:
            if (type(item) is not dict
                    or set(item)!={'dimensionId','memberIds'}
                    or type(item.get('dimensionId')) is not str
                    or not 1<=len(item['dimensionId'])<=200
                    or type(item.get('memberIds')) is not list
                    or not 1<=len(item['memberIds'])<=100
                    or any(type(member) is not str or not 1<=len(member)<=200
                           for member in item['memberIds'])
                    or len(set(item['memberIds']))!=len(item['memberIds'])):
                raise ValueError('EXPRESSION_SOURCE_DOMAIN_INVALID')
            axes.append(item['dimensionId']);product*=len(item['memberIds'])
            normalized.append((item['dimensionId'],tuple(item['memberIds'])))
        if len(set(axes))!=len(axes) or product>500:
            raise ValueError('EXPRESSION_SOURCE_DOMAIN_INVALID')
        try: normalized_default=_decimal(missing_default['decimal'],amount=True)
        except (ValueError,InvalidOperation):
            raise ValueError('EXPRESSION_MISSING_DEFAULT_INVALID') from None
        normalized_source_domain=tuple(sorted((axis,tuple(sorted(member_ids)))
            for axis,member_ids in normalized))
    normalized, result_type = _expression(args['expression'])
    relation_references=applicability_references(normalized)
    if any(relation_references.values()) and normalized_applicability_domain is None:
        raise ValueError('EXPRESSION_APPLICABILITY_DOMAIN_REQUIRED')
    if normalized_applicability_domain is not None:
        operands={item['operandId']:item['numericKind'].lower()
            for item in normalized_applicability_domain['operands']}
        values={item['valueId']:item['type'].lower()
            for item in normalized_applicability_domain['values']}
        if (any(operands.get(name)!=value_type for name,value_type
                in relation_references['operands'].items())
                or any(values.get(name)!=value_type for name,value_type
                in relation_references['values'].items())):
            raise ValueError('EXPRESSION_APPLICABILITY_REFERENCE_INVALID')
    text_lookups=source_text_lookups(normalized)
    if len(source_lookups(normalized))+len(text_lookups)>8:
        raise ValueError('EXPRESSION_SOURCE_LOOKUP_LIMIT')
    if text_lookups and (normalized_reduction is not None
            or normalized_reductions is not None
            or normalized_source_domain is not None
            or normalized_weight is not None):
        raise ValueError('EXPRESSION_SOURCE_TEXT_SHAPE_UNSUPPORTED')
    conversion=currency_conversion(normalized)
    temporal=temporal_window(normalized)
    multi_axis=(normalized_target_sets is not None
                and len(normalized_target_sets)>2)
    multi_axis_reduction=(normalized_reductions is not None
                          and len(normalized_reductions[0])>2)
    if multi_axis and (
            not _plain_multi_axis_expression(normalized)
            or text_lookups
            or published_unit_lookups(normalized)
            or published_ratio_lookups(normalized)
            or source_lookups(normalized)
            or normalized_amount_unit is not None
            or normalized_result_unit is not None
            or conversion is not None
            or normalized_reduction is not None
            or normalized_reductions is not None
            or normalized_source_domain is not None
            or normalized_target_set is not None
            or normalized_weight is not None
            or reduction_context is not None
            or two_axis_reduction_context is not None
            or driver_policy is not None):
        raise ValueError('EXPRESSION_MULTI_AXIS_PROFILE_UNSUPPORTED')
    if multi_axis_reduction and (
            not _plain_multi_axis_expression(normalized)
            or text_lookups
            or published_lookups(normalized)
            or published_unit_lookups(normalized)
            or published_ratio_lookups(normalized)
            or source_lookups(normalized)
            or normalized_amount_unit is not None
            or normalized_result_unit is not None
            or conversion is not None
            or normalized_reduction is not None
            or normalized_target_sets is not None
            or normalized_source_domain is not None
            or normalized_target_set is not None
            or normalized_weight is not None
            or reduction_context is not None
            or two_axis_reduction_context is not None
            or driver_policy is not None):
        raise ValueError('EXPRESSION_MULTI_AXIS_REDUCTION_PROFILE_UNSUPPORTED')
    if conversion is not None and (set(args)!=
            {'sourceMembers','expression','resultKey'}
            or len(members)==0):
        raise ValueError('EXPRESSION_CURRENCY_CONVERSION_SHAPE_INVALID')
    if temporal is not None and normalized_selected_domain is None:
        raise ValueError('EXPRESSION_TEMPORAL_WINDOW_SHAPE_UNSUPPORTED')
    if (normalized_reduction or normalized_reductions) and (
            source_lookups(normalized) or published_lookups(normalized)):
        raise ValueError('EXPRESSION_REDUCTION_LOOKUP_UNSUPPORTED')
    if normalized_weight is not None and normalized!={'op':'SourceAmount'}:
        raise ValueError('EXPRESSION_WEIGHTED_VALUE_SOURCE_INVALID')
    if (normalized_weight is not None
            and normalized_amount_unit is not None):
        # Weighted reductions have their own ratio-basis compiler and do not
        # yet publish a typed-unit generation. Reject the otherwise ignored
        # unit declaration rather than returning an untyped result under a
        # typed receipt.
        raise ValueError('EXPRESSION_WEIGHTED_AMOUNT_UNIT_UNSUPPORTED')
    aligned_unit = aligned_output_unit(normalized)
    if aligned_unit is not None and (normalized_reduction is not None
            or normalized_reductions is not None
            or normalized_source_domain is not None):
        # The aligned-unit publisher operates one-for-one over current source
        # coordinates.  A reduction/default-domain needs a distinct compiler
        # that carries the exact selected inputs into grouped output lineage;
        # accepting those shapes here would validate and publish different
        # source sets.
        raise ValueError('EXPRESSION_ALIGNED_SOURCE_SHAPE_UNSUPPORTED')
    if (normalized_amount_unit is not None and normalized_reduction is None
            and published_lookups(normalized)):
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
    if (normalized_amount_unit is not None and normalized_reduction is None
            and (conversion is not None
                 or normalized_reductions is not None
                 or normalized_source_domain is not None
                 or normalized_target_set is not None
                 or normalized_target_sets is not None
                 or (aligned_unit is not None
                     and aligned_unit != normalized_amount_unit[1]))):
        raise ValueError('EXPRESSION_AMOUNT_UNIT_DIRECT_SHAPE_INVALID')
    if context_dependencies and (
            text_lookups
            or conversion is not None
            or normalized_reduction is not None
            or normalized_reductions is not None
            or normalized_source_domain is not None
            or normalized_target_set is not None
            or normalized_target_sets is not None
            or normalized_weight is not None
            or reduction_context is not None
            or two_axis_reduction_context is not None
            or driver_policy is not None):
        # v32 adds sealed non-fact publication fences to the ordinary
        # unit-bound Amount path.  It is not a generic wrapper around every
        # specialized expression compiler: accepting one of those profiles
        # here would replace that profile's compiler identity and could skip
        # its profile-specific admission/currentness contract.
        raise ValueError('EXPRESSION_CONTEXT_PROFILE_UNSUPPORTED')
    if normalized_source_sets and (
            normalized_reduction is not None
            or normalized_reductions is not None
            or normalized_source_domain is not None
            or normalized_target_set is not None
            or normalized_target_sets is not None
            or normalized_weight is not None
            or normalized_amount_unit is not None
            or normalized_result_unit is not None
            or context_dependencies
            or text_lookups
            or conversion is not None
            or aligned_output_unit(normalized) is not None
            or reduction_context is not None
            or two_axis_reduction_context is not None):
        raise ValueError('EXPRESSION_SOURCE_MEMBER_SETS_SHAPE_UNSUPPORTED')
    if normalized_selected_domain is not None and (
            members or normalized_source_sets or normalized_source_domain is not None
            or normalized_reduction is not None or normalized_reductions is not None
            or normalized_target_set is not None or normalized_target_sets is not None
            or normalized_weight is not None or normalized_amount_unit is not None
            or context_dependencies or text_lookups or conversion is not None
            or aligned_output_unit(normalized) is not None
            or reduction_context is not None
            or two_axis_reduction_context is not None
            or driver_policy is not None):
        raise ValueError('SELECTED_DOMAIN_EXPRESSION_SHAPE_UNSUPPORTED')
    if normalized_applicability_domain is not None and (
            members or normalized_source_sets or normalized_source_domain is not None
            or normalized_reduction is not None or normalized_reductions is not None
            or normalized_target_set is not None or normalized_target_sets is not None
            or normalized_weight is not None or normalized_amount_unit is not None
            or normalized_result_unit is not None or context_dependencies
            or text_lookups or conversion is not None or temporal is not None
            or published_lookups(normalized) or source_lookups(normalized)
            or aligned_output_unit(normalized) is not None
            or reduction_context is not None
            or two_axis_reduction_context is not None
            or driver_policy is not None
            or calculated_member is not None):
        raise ValueError('APPLICABILITY_DOMAIN_EXPRESSION_SHAPE_UNSUPPORTED')
    if (required_source_count is not None
            and (normalized_amount_unit is None
                 or normalized_reduction is not None)):
        raise ValueError('EXPRESSION_REQUIRED_SOURCE_COUNT_SHAPE_INVALID')
    if normalized_reductions is not None and normalized_amount_unit is not None:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_UNIT_UNSUPPORTED')
    if normalized_source_domain and (source_lookups(normalized)
            or published_lookups(normalized)):
        raise ValueError('EXPRESSION_DEFAULT_DOMAIN_LOOKUP_UNSUPPORTED')
    legacy_source_value_allowed=(allow_legacy_source_value
        or normalized_selected_domain is not None and calculated_member is not None)
    if (source_lookups(normalized)
            and len(source_measure_bindings(normalized)) == 0
            and not legacy_source_value_allowed):
        raise ValueError('EXPRESSION_MEASURE_BINDING_REQUIRED')
    if not legacy_source_value_allowed:
        def all_bound(node: dict) -> bool:
            if node['op'] == 'SourceValue':
                return 'measureDimensionId' in node
            if node['op'] in ('Add', 'Subtract', 'Multiply', 'Divide', 'Compare'):
                return all_bound(node['left']) and all_bound(node['right'])
            if node['op'] == 'If':
                return all(all_bound(node[part]) for part in
                           ('test', 'then', 'else'))
            return True
        if not all_bound(normalized):
            raise ValueError('EXPRESSION_MEASURE_BINDING_REQUIRED')
    if result_type == 'ratio':
        if normalized_result_unit != ('Ratio',12):
            raise ValueError('EXPRESSION_RATIO_RESULT_UNIT_REQUIRED')
        if (conversion is not None or normalized_amount_unit is not None
                or normalized_reduction is not None
                or normalized_reductions is not None
                or normalized_source_domain is not None
                or normalized_target_set is not None
                or normalized_target_sets is not None
                or published_unit_lookups(normalized)):
            raise ValueError('EXPRESSION_RATIO_RESULT_SHAPE_INVALID')
    elif result_type != 'amount' or normalized_result_unit is not None:
        raise ValueError('EXPRESSION_RESULT_MUST_BE_AMOUNT')
    references = expression_references(normalized)
    published_lookups(normalized)
    published_unit_lookups(normalized)
    published_ratio_lookups(normalized)
    aligned_output_unit(normalized)
    source_lookups(normalized)
    if key in references:
        raise ValueError('EXPRESSION_SELF_PUBLICATION_REFERENCE')
    if references:
        if published_inputs is not None:
            if (not isinstance(published_inputs, tuple)
                    or any(not isinstance(item, dict)
                           for item in published_inputs)
                    or [item.get('resultKey') for item in published_inputs]
                    != list(references)
                    or any(set(item) != {'resultKey', 'resultStateToken'}
                           or not isinstance(item['resultStateToken'], str)
                           or not re.fullmatch(r'[0-9a-f]{64}',
                                               item['resultStateToken'])
                           for item in published_inputs)):
                raise ValueError('EXPRESSION_PUBLISHED_INPUT_INVALID')
    elif published_inputs not in (None, ()):
        raise ValueError('EXPRESSION_PUBLISHED_INPUT_INVALID')
    if saved_rule is not None:
        if (not isinstance(saved_rule, dict)
                or set(saved_rule) not in (
                    {'ruleId', 'stateToken', 'programDigest'},
                    {'ruleId', 'stateToken', 'programDigest', 'bindings'},
                    {'ruleId', 'stateToken', 'programDigest',
                     'bindings', 'memberParameters'})
                or not isinstance(saved_rule['ruleId'], str)
                or not re.fullmatch(r'[A-Za-z0-9._-]{1,100}',
                                    saved_rule['ruleId'])
                or not isinstance(saved_rule['stateToken'],str)
                or re.fullmatch(r'[0-9a-f]{64}',
                                saved_rule['stateToken']) is None
                or not isinstance(saved_rule['programDigest'], str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                                    saved_rule['programDigest'])):
            raise ValueError('EXPRESSION_SAVED_RULE_PIN_INVALID')
        if 'bindings' in saved_rule:
            bindings = saved_rule['bindings']
            if (not isinstance(bindings, dict)
                    or not 1 <= len(bindings) <= 8
                    or any(not isinstance(name, str)
                           or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}', name)
                           or not _saved_rule_binding_valid(value)
                           for name, value in bindings.items())):
                raise ValueError('EXPRESSION_SAVED_RULE_PIN_INVALID')
        if 'memberParameters' in saved_rule:
            names = saved_rule['memberParameters']
            if (not isinstance(names, list) or not 1 <= len(names) <= 8
                    or any(not isinstance(name, str)
                           or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}',
                                               name)
                           or name not in saved_rule['bindings']
                           for name in names)
                    or names != sorted(set(names))):
                raise ValueError('EXPRESSION_SAVED_RULE_PIN_INVALID')
    if calculated_member is not None:
        compact={'definitionId','stateToken','programDigest',
            'definitionDigest','policyRevision','sourceSelectionDigest',
            'selectedDomainDigest','resolutionDigest'}
        if (not isinstance(calculated_member,dict)
                or set(calculated_member) != compact
                or not isinstance(calculated_member['definitionId'],str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}',
                                    calculated_member['definitionId'])
                or not isinstance(calculated_member['stateToken'],str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                                    calculated_member['stateToken'])
                or type(calculated_member['policyRevision']) is not int
                or calculated_member['policyRevision']<0
                or any(not isinstance(calculated_member[name],str)
                    or not re.fullmatch(r'[0-9a-f]{64}',
                                        calculated_member[name])
                    for name in ('programDigest','definitionDigest',
                        'sourceSelectionDigest','selectedDomainDigest',
                        'resolutionDigest'))):
            raise ValueError('CALCULATED_MEMBER_PIN_INVALID')
        if normalized_selected_domain is None:
            raise ValueError('CALCULATED_MEMBER_SELECTED_DOMAIN_PIN_REQUIRED')
    if driver_policy is not None:
        base = {'policyId', 'policyDigest', 'metadataRevision',
                'policyRevision'}
        published = base | {'authoredMetadataRevision',
                            'authoredPolicyRevision', 'stateToken'}
        published_v2=published|{'policyFormat','publishedDependency',
                                'maxCells','upstreamLineageBudget'}
        if (not isinstance(driver_policy, dict)
                or set(driver_policy) not in (base, published, published_v2)
                or not isinstance(driver_policy['policyId'], str)
                or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}',
                                    driver_policy['policyId'])
                or not isinstance(driver_policy['policyDigest'], str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                                    driver_policy['policyDigest'])
                or type(driver_policy['metadataRevision']) is not int
                or driver_policy['metadataRevision'] < 0
                or type(driver_policy['policyRevision']) is not int
                or driver_policy['policyRevision'] < 0):
            raise ValueError('EXPRESSION_DRIVER_POLICY_PIN_INVALID')
        if (set(driver_policy) in (published,published_v2)
                and (not isinstance(driver_policy['stateToken'],str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                                    driver_policy['stateToken'])
                or any(type(driver_policy[name]) is not int
                or driver_policy[name] < 0 for name in (
                    'authoredMetadataRevision', 'authoredPolicyRevision')))):
            raise ValueError('EXPRESSION_DRIVER_POLICY_PIN_INVALID')
        if set(driver_policy)==published_v2:
            dependency=driver_policy['publishedDependency']
            if (driver_policy['policyFormat']!=
                    'openepm-planning-operation-policy-v2'
                    or driver_policy['maxCells']!=500
                    or driver_policy['upstreamLineageBudget']!={
                        'maxCanonicalBytes':65536,'maxDepth':8}
                    or not isinstance(dependency,dict)
                    or set(dependency)!={'inputName','resultKey',
                                         'resultStateToken'}
                    or any(not isinstance(dependency[name],str)
                           or not dependency[name] for name in (
                               'inputName','resultKey','resultStateToken'))
                    or re.fullmatch(r'[0-9a-f]{64}',
                                    dependency['resultStateToken']) is None):
                raise ValueError('EXPRESSION_DRIVER_POLICY_PIN_INVALID')
    normalized_context = None
    if reduction_context is not None:
        required = {'format','dimensionId','kind','rootMemberId',
            'hierarchyId','hierarchyStateToken','membershipSemantics','resolvedMemberIds',
            'membershipDigest','layoutDigest','metadataRevision'}
        if (not isinstance(reduction_context, dict)
                or set(reduction_context) != required
                or (
                    not isinstance(reduction_context['hierarchyId'],str)
                    or not 1<=len(reduction_context['hierarchyId'])<=200
                    or reduction_context['hierarchyId']!=reduction_context['hierarchyId'].strip()
                    or any(ord(c)<32 for c in reduction_context['hierarchyId']))
                or reduction_context.get('format') != 'hierarchy-reduction-v1'
                or reduction_context.get('kind') not in (
                    'Children','Descendants','Leaves')
                or reduction_context.get('membershipSemantics') != 'UniqueMember'
                or not isinstance(reduction_context.get('hierarchyStateToken'),str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                    reduction_context['hierarchyStateToken'])
                or type(reduction_context.get('metadataRevision')) is not int
                or reduction_context['metadataRevision'] < 0
                or any(not isinstance(reduction_context.get(name), str)
                    or not 1 <= len(reduction_context[name]) <= 200
                    for name in ('dimensionId','rootMemberId'))
                or not isinstance(reduction_context.get('resolvedMemberIds'), list)
                or not 1 <= len(reduction_context['resolvedMemberIds']) <= 100
                or any(not isinstance(item,str) or not 1<=len(item)<=200
                    for item in reduction_context['resolvedMemberIds'])
                or reduction_context['resolvedMemberIds'] != sorted(set(
                    reduction_context['resolvedMemberIds']))
                or any(not isinstance(reduction_context.get(name),str)
                    or not re.fullmatch(r'[0-9a-f]{64}',reduction_context[name])
                    for name in ('membershipDigest','layoutDigest'))
                or normalized_reduction is None
                or normalized_reduction[0] != reduction_context['dimensionId']
                or list(normalized_reduction[1]) !=
                    reduction_context['resolvedMemberIds']
                or normalized_weight is not None):
            raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_CONTEXT_INVALID')
        expected_digest = _canonical_digest(
            reduction_context['resolvedMemberIds'])
        if reduction_context['membershipDigest'] != expected_digest:
            raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_CONTEXT_INVALID')
        normalized_context = dict(reduction_context)
    normalized_two_axis_context=None
    if two_axis_reduction_context is not None:
        required={'format','selections','layoutDigest','metadataRevision'}
        selections=(two_axis_reduction_context.get('selections')
            if isinstance(two_axis_reduction_context,dict) else None)
        if (not isinstance(two_axis_reduction_context,dict)
                or set(two_axis_reduction_context)!=required
                or two_axis_reduction_context.get('format')!=
                    'hierarchy-two-axis-reduction-v1'
                or type(two_axis_reduction_context.get('metadataRevision'))
                    is not int
                or two_axis_reduction_context['metadataRevision']<0
                or not isinstance(two_axis_reduction_context.get(
                    'layoutDigest'),str)
                or not re.fullmatch(r'[0-9a-f]{64}',
                    two_axis_reduction_context['layoutDigest'])
                or not isinstance(selections,list) or len(selections)!=2
                or normalized_reductions is None):
            raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_CONTEXT_INVALID')
        for index,item in enumerate(selections):
            expected={'dimensionId','kind','rootMemberId','hierarchyId',
                'hierarchyStateToken',
                'membershipSemantics','targetMemberId','resolvedMemberIds',
                'membershipDigest'}
            sealed=normalized_reductions[0][index]
            if (not isinstance(item,dict) or set(item)!=expected
                    or (
                        not isinstance(item['hierarchyId'],str)
                        or not 1<=len(item['hierarchyId'])<=200
                        or item['hierarchyId']!=item['hierarchyId'].strip()
                        or any(ord(c)<32 for c in item['hierarchyId']))
                    or item.get('kind') not in ('Children','Descendants','Leaves')
                    or item.get('membershipSemantics')!='UniqueMember'
                    or not isinstance(item.get('hierarchyStateToken'),str)
                    or not re.fullmatch(r'[0-9a-f]{64}',
                        item['hierarchyStateToken'])
                    or any(type(item.get(name)) is not str
                        or not 1<=len(item[name])<=200 for name in (
                            'dimensionId','rootMemberId'))
                    or not isinstance(item.get('resolvedMemberIds'),list)
                    or not 1<=len(item['resolvedMemberIds'])<=100
                    or item['resolvedMemberIds']!=sorted(set(
                        item['resolvedMemberIds']))
                    or any(type(value) is not str or not 1<=len(value)<=200
                        for value in item['resolvedMemberIds'])
                    or not isinstance(item.get('membershipDigest'),str)
                    or not re.fullmatch(r'[0-9a-f]{64}',
                        item['membershipDigest'])
                    or item.get('dimensionId')!=sealed[0]
                    or item.get('targetMemberId')!=sealed[2]
                    or item.get('resolvedMemberIds')!=list(sealed[1])
                    or item.get('membershipDigest')!=_canonical_digest(
                        item['resolvedMemberIds'])):
                raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_CONTEXT_INVALID')
        normalized_two_axis_context=dict(two_axis_reduction_context)
    result=ExpressionPlan(tuple(sorted(members.items())), normalized, key,
                          expected_target_state_token,
                          published_inputs if references else (),
                          tuple(sorted(targets.items())), saved_rule,
                          driver_policy, normalized_target_set,
                          normalized_reduction,normalized_target_sets,
                          normalized_source_domain,normalized_default,
                          normalized_amount_unit,normalized_weight,
                          normalized_result_unit, normalized_context,
                          normalized_reductions,normalized_two_axis_context,
                          required_source_count,context_dependencies,
                          context_assertions,normalized_source_sets,
                          calculated_member,normalized_selected_domain,
                          normalized_applicability_domain)
    if multi_axis and compiler_for(result)[0]!=MULTI_AXIS_MEMBER_SET_COMPILER:
        raise ValueError('EXPRESSION_MULTI_AXIS_PROFILE_UNSUPPORTED')
    if (multi_axis_reduction and compiler_for(result)[0]!=
            MULTI_AXIS_MEMBER_SET_REDUCTION_COMPILER):
        raise ValueError('EXPRESSION_MULTI_AXIS_REDUCTION_PROFILE_UNSUPPORTED')
    return result


def decode_expression_program(program: object) -> ExpressionPlan:
    fields = {'version', 'function', 'expression',
              'resultKey', 'expectedTargetStateToken', 'rounding',
              'inputGrain', 'outputGrain'}
    if (not isinstance(program, dict)
            or not fields <= set(program)
            or set(program) - fields - ({'sourceMembers','publishedInputs', 'targetMembers',
                                        'targetMemberSet','reduceMemberSet','targetMemberSets',
                                        'sourceDomain','missingDefault','amountUnit',
                                        'savedRule', 'driverPolicy','resultUnit',
                                        'hierarchyReductionContext',
                                        'reduceMemberSets',
                                        'hierarchyTwoAxisReductionContext',
                                        'requiredSourceCount',
                                        'contextDependencies',
                                        'contextAssertions',
                                        'sourceMemberSets','calculatedMember',
                                        'selectedDomain','applicabilityDomain'})
            or program.get('version') != 2
            or program.get('function') != FUNCTION
            or program.get('rounding') not in (
                'half-even-final-8','half-even-final-12')
            or sum(name in program for name in (
                'sourceMembers','sourceDomain','selectedDomain',
                'applicabilityDomain')) != 1
            or program.get('inputGrain') not in (
                'present_full_coordinate','complete_explicit_bounded_domain',
                'current_sparse_relation_anchors')
            or program.get('outputGrain') not in (
                'same_full_coordinate',
                'declared_target_member_overrides',
                'one_axis_explicit_member_set',
                'one_axis_member_set_reduction',
                'two_axis_explicit_member_sets',
                'bounded_multi_axis_explicit_member_sets',
                'two_axis_member_set_reduction',
                'bounded_multi_axis_member_set_reduction',
                'relation_target_overrides')):
        raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
    args = {'expression': program['expression'],'resultKey': program['resultKey']}
    if 'resultUnit' in program:
        args['resultUnit']=program['resultUnit']
    if 'sourceDomain' in program:
        args['sourceDomain']=program['sourceDomain']
        args['missingDefault']=program['missingDefault']
    elif 'sourceMembers' in program:
        args['sourceMembers']=program['sourceMembers']
    elif 'selectedDomain' in program:
        args['selectedDomain']=program['selectedDomain']
    else:
        args['applicabilityDomain']=program['applicabilityDomain']
    if 'sourceMemberSets' in program:
        args['sourceMemberSets']=program['sourceMemberSets']
    if 'targetMembers' in program:
        args['targetMembers'] = program['targetMembers']
    if 'targetMemberSet' in program:
        args['targetMemberSet'] = program['targetMemberSet']
    if 'reduceMemberSet' in program:
        args['reduceMemberSet'] = program['reduceMemberSet']
    if 'reduceMemberSets' in program:
        args['reduceMemberSets'] = program['reduceMemberSets']
    if 'amountUnit' in program:
        args['amountUnit'] = program['amountUnit']
    if 'requiredSourceCount' in program:
        args['requiredSourceCount'] = program['requiredSourceCount']
    if 'contextDependencies' in program:
        from .expression_context_dependencies import (
            normalize_sealed,requests_from_sealed)
        args['contextDependencies'] = list(requests_from_sealed(
            normalize_sealed(program['contextDependencies'])))
        args['contextAssertions'] = program['contextAssertions']
    if 'targetMemberSets' in program:
        args['targetMemberSets'] = program['targetMemberSets']
    plan = compile_expression_program({
        'languageVersion': 2, 'function': FUNCTION,
        'arguments': args},
        expected_target_state_token=program['expectedTargetStateToken'],
        published_inputs=tuple(program.get('publishedInputs', ())),
        saved_rule=program.get('savedRule'),
        driver_policy=program.get('driverPolicy'),
        reduction_context=program.get('hierarchyReductionContext'),
        two_axis_reduction_context=program.get(
            'hierarchyTwoAxisReductionContext'),
        allow_legacy_source_value=True,
        sealed_context_dependencies=tuple(program.get(
            'contextDependencies',())),
        calculated_member=program.get('calculatedMember'))
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_EXPRESSION_JOB_PROGRAM')
    return plan


def resolve_published_inputs(db, scope: ApplicationScope,
                             expression: dict) -> tuple[dict, ...]:
    keys = expression_references(expression)
    if not keys:
        return ()
    rows = db.execute('''SELECT result_key,state_token
        FROM epm.calculation_result_state WHERE workspace_id=%s
        AND application_id=%s AND result_key=ANY(%s::text[])
        ORDER BY result_key''',
        (scope.workspace_id, scope.application_id, list(keys))).fetchall()
    if [row['result_key'] for row in rows] != list(keys):
        raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNAVAILABLE')
    return tuple({'resultKey': row['result_key'],
                  'resultStateToken': row['state_token']}
                 for row in rows)


def verify_published_inputs(db, scope: ApplicationScope,
                            plan: ExpressionPlan) -> None:
    if plan.published_inputs is None:
        raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
    if (plan.published_inputs and resolve_published_inputs(
            db, scope, plan.expression) != plan.published_inputs):
        raise ValueError('STALE_PUBLISHED_INPUT')
    if plan.published_inputs:
        status = published_input_status(db, scope,
                                        plan.normalized_program)
        if status is None or not status['matchesAtRead']:
            raise ValueError('STALE_PUBLISHED_INPUT')


def _resolved_applicability_sql(db, scope: ApplicationScope,
                                plan: ExpressionPlan):
    """Resolve and lower one current relation without copying authored rows."""
    if plan.applicability_domain is None:
        return None
    from .postgres_applicability_relations import resolve_applicability_domain
    from .applicability_domain_sql import compile_applicability_domain_sql
    dimensions = db.execute('''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        ORDER BY dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()
    resolved = resolve_applicability_domain(
        db, scope, plan.applicability_domain,
        active_dimensions=tuple(row['dimension_id'] for row in dimensions))
    return resolved, compile_applicability_domain_sql(resolved['domain'])


def _applicability_row_windows(db,scope:ApplicationScope,
        plan:ExpressionPlan,*,window_size:int=500,heartbeat=None):
    """Yield deterministic server-owned relation work windows.

    These are execution details derived from the pinned business relation.
    They never enter the authored program, MCP request or saved rule identity.
    """
    if type(window_size) is not int or not 1<=window_size<=500:
        raise ValueError('APPLICABILITY_WORK_WINDOW_INVALID')
    resolved,lowering=_resolved_applicability_sql(db,scope,plan)
    after=''
    while True:
        candidates=db.execute('''SELECT row_id
            FROM epm.applicability_relation_row
            WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
              AND row_id>%s ORDER BY row_id LIMIT %s''',(
            scope.workspace_id,scope.application_id,resolved['relationId'],
            after,window_size)).fetchall()
        if not candidates:return
        candidate_ids=tuple(row['row_id'] for row in candidates)
        if lowering.required_predicate=='TRUE':
            members=[];member_parameters=[]
            for item in resolved['domain']['anchorMemberColumns']:
                members.extend(('%s::text',
                    'applicability_row.values->>%s::text'))
                member_parameters.extend((item['dimensionId'],
                                          item['columnId']))
            source_members='jsonb_build_object('+','.join(members)+')'
            rows=db.execute(f'''SELECT applicability_row.row_id
                FROM epm.applicability_relation_row applicability_row
                JOIN epm.coordinate c
                  ON c.workspace_id=applicability_row.workspace_id
                 AND c.application_id=applicability_row.application_id
                 AND c.series_key=epm.coordinate_series_key({source_members})
                 AND c.members={source_members}
                JOIN epm.numeric_cell_current n
                  ON n.workspace_id=c.workspace_id
                 AND n.application_id=c.application_id
                 AND n.coordinate_id=c.coordinate_id
                WHERE applicability_row.workspace_id=%s
                  AND applicability_row.application_id=%s
                  AND applicability_row.relation_id=%s
                  AND applicability_row.row_id=ANY(%s::text[]) AND n.present
                ORDER BY applicability_row.row_id''',(
                *member_parameters,*member_parameters,scope.workspace_id,
                scope.application_id,resolved['relationId'],
                list(candidate_ids))).fetchall()
        else:
            rows=db.execute(f'''SELECT applicability_row.row_id
                FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
                  (workspace_id,application_id,coordinate_id)
                {lowering.joins}
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                  AND ({lowering.required_predicate})
                  AND applicability_row.row_id=ANY(%s::text[])
                ORDER BY applicability_row.row_id''',(
                *lowering.join_parameters,scope.workspace_id,
                scope.application_id,list(candidate_ids))).fetchall()
        if rows:
            if heartbeat is not None:
                heartbeat()
            yield tuple(row['row_id'] for row in rows)
        after=candidate_ids[-1]
        if len(candidates)<window_size:return


def _published_joins(plan: ExpressionPlan) -> tuple[
        str, list[object], dict[tuple, str], str, str]:
    joins = []
    join_params: list[object] = []
    aliases = {}
    missing_published = []
    missing_source = []
    pins = {item['resultKey'] for item in plan.published_inputs or ()}
    lookup_expression=plan.weight_expression or plan.expression
    temporal = temporal_window(lookup_expression)
    if temporal is not None:
        definition = temporal['definition']
        joins.append('''JOIN epm.calendar_period_current temporal_calendar
            ON temporal_calendar.workspace_id=c.workspace_id
            AND temporal_calendar.application_id=c.application_id
            AND temporal_calendar.year_member_id=
                c.members->>%s::text
            AND temporal_calendar.period_member_id=
                c.members->>%s::text''')
        join_params.extend((temporal['resetGroupDimensionId'],
                            definition['periodDimensionId']))
    for index, lookup in enumerate(published_lookups(lookup_expression)):
        key, overrides = lookup
        alias = f'p{index}'
        aliases[('published', key, overrides)] = alias
        coordinate_id = 'c.coordinate_id'
        if overrides:
            coordinate_alias = f'q{index}'
            joins.append(f'''LEFT JOIN epm.coordinate {coordinate_alias}
                ON {coordinate_alias}.workspace_id=c.workspace_id
                AND {coordinate_alias}.application_id=c.application_id
                AND {coordinate_alias}.members=
                    (c.members || %s::jsonb)''')
            join_params.append(Jsonb(dict(overrides)))
            coordinate_id = f'{coordinate_alias}.coordinate_id'
        joins.append(f'''LEFT JOIN epm.calculation_result_current {alias}
            ON {alias}.workspace_id=c.workspace_id
            AND {alias}.application_id=c.application_id
            AND {alias}.coordinate_id={coordinate_id}
            AND {alias}.result_key=%s''')
        if key not in pins:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
        join_params.append(key)
        missing_published.append(f'{alias}.coordinate_id IS NULL')
    for index, lookup in enumerate(published_unit_lookups(lookup_expression)):
        key,overrides,unit=lookup; alias=f'pu{index}'
        aliases[('published_unit',key,overrides,unit)]=alias
        coordinate_alias=f'qu{index}'
        joins.append(f'''LEFT JOIN epm.coordinate {coordinate_alias}
            ON {coordinate_alias}.workspace_id=c.workspace_id
            AND {coordinate_alias}.application_id=c.application_id
            AND {coordinate_alias}.members=(c.members || %s::jsonb)''')
        join_params.append(Jsonb(dict(overrides)))
        joins.append(f'''LEFT JOIN epm.calculation_unit_result_current {alias}
            ON {alias}.workspace_id=c.workspace_id
            AND {alias}.application_id=c.application_id
            AND {alias}.coordinate_id={coordinate_alias}.coordinate_id
            AND {alias}.result_key=%s
            AND {alias}.output_unit_currency_member_id=%s''')
        if key not in pins:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
        join_params.extend((key,unit))
        missing_published.append(f'{alias}.coordinate_id IS NULL')
    for index, lookup in enumerate(published_ratio_lookups(lookup_expression)):
        key,overrides=lookup; alias=f'pr{index}'
        aliases[('published_ratio',key,overrides)]=alias
        coordinate_id='c.coordinate_id'
        if overrides:
            coordinate_alias=f'qr{index}'
            joins.append(f'''LEFT JOIN epm.coordinate {coordinate_alias}
                ON {coordinate_alias}.workspace_id=c.workspace_id
                AND {coordinate_alias}.application_id=c.application_id
                AND {coordinate_alias}.members=(c.members || %s::jsonb)''')
            join_params.append(Jsonb(dict(overrides)))
            coordinate_id=f'{coordinate_alias}.coordinate_id'
        joins.append(f'''LEFT JOIN epm.calculation_ratio_result_current {alias}
            ON {alias}.workspace_id=c.workspace_id
            AND {alias}.application_id=c.application_id
            AND {alias}.coordinate_id={coordinate_id}
            AND {alias}.result_key=%s''')
        if key not in pins:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
        join_params.append(key)
        missing_published.append(f'{alias}.coordinate_id IS NULL')
    raw_lookups = source_lookups(lookup_expression)
    raw_source = 'c'
    if raw_lookups and not plan.source_domain:
        # The canonical source predicate must precede input lookups. A
        # materialized single-row relational stage prevents the planner from
        # resolving every input for unrelated surrounding coordinates first.
        # Keep the outer predicates too: this changes work order, not grain,
        # protected membership semantics, or the existing source-count bound.
        source_predicate, source_parameters = _plan_member_predicates(plan)
        joins.append(f'''JOIN LATERAL (
            WITH selected_source AS MATERIALIZED (
                SELECT c.workspace_id,c.application_id,c.coordinate_id,c.members
                WHERE n.present {source_predicate})
            SELECT * FROM selected_source
        ) raw_source ON true''')
        join_params.extend(source_parameters)
        raw_source = 'raw_source'
    for index, overrides in enumerate(raw_lookups):
        coordinate_alias = f'rawq{index}'
        value_alias = f'rawv{index}'
        aliases[('raw', overrides)] = value_alias
        # Each override denotes one exact scoped coordinate. Keep both the
        # indexed identity and full members check, and bound the protected
        # projection view to that point before composing multiple inputs.
        # Otherwise cold estimates can repeatedly scan whole app projections.
        joins.append(f'''LEFT JOIN LATERAL (
            SELECT q.workspace_id,q.application_id,q.coordinate_id,
                   q.members,q.series_key
            FROM epm.coordinate q
            WHERE q.workspace_id={raw_source}.workspace_id
              AND q.application_id={raw_source}.application_id
              AND q.series_key=epm.coordinate_series_key({raw_source}.members || %s::jsonb)
              AND q.members=({raw_source}.members || %s::jsonb)
            LIMIT 1) {coordinate_alias} ON true''')
        join_params.extend((Jsonb(dict(overrides)), Jsonb(dict(overrides))))
        joins.append(f'''LEFT JOIN LATERAL (
            SELECT v.coordinate_id,v.amount,v.change_id
            FROM epm.numeric_cell_current v
            WHERE v.workspace_id={coordinate_alias}.workspace_id
              AND v.application_id={coordinate_alias}.application_id
              AND v.coordinate_id={coordinate_alias}.coordinate_id
              AND v.present
            LIMIT 1) {value_alias} ON true''')
        missing_source.append(f'{value_alias}.coordinate_id IS NULL')
    for index,overrides in enumerate(source_text_lookups(lookup_expression)):
        coordinate_alias=f'rawtq{index}';value_alias=f'rawtv{index}'
        aliases[('raw_text',overrides)]=value_alias
        joins.append(f'''LEFT JOIN epm.coordinate {coordinate_alias}
            ON {coordinate_alias}.workspace_id=c.workspace_id
            AND {coordinate_alias}.application_id=c.application_id
            AND {coordinate_alias}.members=(c.members || %s::jsonb)''')
        join_params.append(Jsonb(dict(overrides)))
        joins.append(f'''LEFT JOIN epm.text_cell_current {value_alias}
            ON {value_alias}.workspace_id=c.workspace_id
            AND {value_alias}.application_id=c.application_id
            AND {value_alias}.coordinate_id={coordinate_alias}.coordinate_id
            AND {value_alias}.present''')
        missing_source.append(f'{value_alias}.coordinate_id IS NULL')
    return ('\n'.join(joins), join_params, aliases,
            ' OR '.join(missing_published),
            ' OR '.join(missing_source))


def _plan_member_predicates(plan: ExpressionPlan) -> tuple[str, list[object]]:
    """Lower equality and explicit-set source filters through one boundary."""
    predicate,params=_member_predicates(plan.source_members)
    for axis,members in plan.source_member_sets:
        predicate+=' AND c.members->>%s=ANY(%s::text[])'
        params.extend((axis,list(members)))
    if plan.selected_domain:
        # Required axes come from the canonical domain, never its nonempty
        # membership rows. An empty axis must make the domain empty rather
        # than disappear from this intersection and broaden the calculation.
        for dimension in plan.selected_domain['sourceSelection']['dimensions']:
            axis = dimension['dimensionId']
            predicate += (' AND EXISTS (SELECT 1 FROM '
                'pg_temp.epm_selected_domain_member membership '
                'WHERE membership.dimension_id=%s '
                'AND membership.member_id=c.members->>%s)')
            params.extend((axis, axis))
    return predicate,params


def validate_currency_conversion(db,scope:ApplicationScope,
        identity:VerifiedIdentity|None,plan:ExpressionPlan)->dict|None:
    conversion=currency_conversion(plan.expression)
    if conversion is None:return None
    if identity is None:
        raise ValueError('EXPRESSION_CURRENCY_IDENTITY_REQUIRED')
    predicate,params=_plan_member_predicates(plan)
    rows=db.execute(f'''SELECT c.members,n.amount,n.change_id
        FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
        (workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
        {predicate} ORDER BY c.series_key LIMIT 2''',(
        scope.workspace_id,scope.application_id,*params)).fetchall()
    if len(rows)!=1:
        raise ValueError('EXPRESSION_CURRENCY_SOURCE_GRAIN_INVALID')
    row=rows[0]
    from .postgres_currency_amount_preview import evaluate_in_transaction
    args={'coordinate':Coordinate.from_mapping(row['members']),
        'sourceAmount':row['amount'],'sourceChangeId':row['change_id'],
        **{key:conversion[key] for key in ('fromCurrencyMemberId',
            'toCurrencyMemberId','rateKind','expectedRate',
            'expectedDataRevision','rounding')}}
    return evaluate_in_transaction(db,scope,identity,args,permission='write',
        function=FUNCTION)


def validate_aligned_unit_inputs(db, scope: ApplicationScope,
        plan: ExpressionPlan, expected_count: int) -> dict | None:
    """Resolve exact schema-0143 typed inputs without inferring translation."""
    unit = aligned_output_unit(plan.expression)
    if unit is None:
        return None
    if expected_count < 1:
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
    pins = {item['resultKey']: item for item in plan.published_inputs or ()}
    dependencies = []
    dimension_id = None
    selected_source_ids: set[int] | None = None
    predicate, filter_params = _plan_member_predicates(plan)
    predicate = (predicate.replace('c.workspace_id', 'source.workspace_id')
                 .replace('c.application_id', 'source.application_id')
                 .replace('c.coordinate_id', 'source.coordinate_id'))
    for result_key, overrides, expected_unit in published_unit_lookups(
            plan.expression):
        pin = pins.get(result_key)
        if pin is None:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNRESOLVED')
        override_members = dict(overrides)
        override_json = Jsonb(override_members)
        rows = db.execute(f'''SELECT source.coordinate_id AS source_coordinate_id,
            source.series_key AS source_series_key,
            target.members,r.source_amount,
            r.source_change_id,r.amount,
            r.output_unit_currency_dimension_id,
            r.output_unit_currency_member_id,r.rate_strategy,
            r.rate_numerator::text AS rate_numerator,
            r.rate_denominator::text AS rate_denominator,r.rate_sources
            FROM epm.coordinate source
            JOIN epm.numeric_cell_current n ON
              n.workspace_id=source.workspace_id
              AND n.application_id=source.application_id
              AND n.coordinate_id=source.coordinate_id AND n.present
            JOIN epm.coordinate target ON
              target.workspace_id=source.workspace_id
              AND target.application_id=source.application_id
              AND target.series_key=epm.coordinate_series_key(
                source.members||%s::jsonb)
              AND target.members=source.members||%s::jsonb
            JOIN epm.calculation_unit_result_current r ON
              r.workspace_id=target.workspace_id
              AND r.application_id=target.application_id
              AND r.coordinate_id=target.coordinate_id
              AND r.result_key=%s
              AND r.output_unit_currency_member_id=%s
            WHERE source.workspace_id=%s AND source.application_id=%s
              {predicate}
            ORDER BY source.series_key,r.output_unit_currency_dimension_id''',(
            override_json,override_json,result_key,expected_unit,
            scope.workspace_id,scope.application_id,*filter_params)).fetchall()
        lookup_source_ids = {row['source_coordinate_id'] for row in rows}
        if (not rows or len(lookup_source_ids) != len(rows)
                or (selected_source_ids is not None
                    and lookup_source_ids != selected_source_ids)):
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
        selected_source_ids = lookup_source_ids
        for row in rows:
            if row['output_unit_currency_member_id'] != unit:
                raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
            if dimension_id is None:
                dimension_id = row['output_unit_currency_dimension_id']
            elif dimension_id != row['output_unit_currency_dimension_id']:
                raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
            dependencies.append({'sourceCoordinateId':row['source_coordinate_id'],
              'resultKey': result_key,
              'resultStateToken': pin['resultStateToken'],
              'members': row['members'], 'amount': format(row['amount'], '.8f'),
              'outputUnit': {'dimensionId': dimension_id, 'memberId': unit},
              'inputLineage': {'sourceAmount': format(row['source_amount'], '.8f'),
                'sourceChangeId': row['source_change_id'],
                'rateStrategy': row['rate_strategy'],
                'rateNumerator': row['rate_numerator'],
                'rateDenominator': row['rate_denominator'],
                'rateSources': row['rate_sources']}})
    by_source=[]
    for source_coordinate_id in sorted({item['sourceCoordinateId']
                                        for item in dependencies}):
        source_dependencies=[{key:value for key,value in item.items()
                              if key!='sourceCoordinateId'}
            for item in dependencies
            if item['sourceCoordinateId']==source_coordinate_id]
        dependency_lineage=[{'inputKind':'PublishedUnitDependency',**item}
                            for item in source_dependencies]
        rate_sources=[{'kind':'alignedPublishedInputs',
                       'dependencies':source_dependencies}]
        by_source.append({'source_coordinate_id':source_coordinate_id,
            'dependencies':source_dependencies,
            'dependency_lineage':dependency_lineage,
            'rate_sources':rate_sources,
            'source_change_id':'aligned:'+_canonical_digest(rate_sources)})
    target_multiplier=(len(plan.target_member_set[1])
        if plan.target_member_set else
        (len(_target_member_combinations(plan))
         if plan.target_member_sets else 1))
    if (len(by_source)*target_multiplier)!=expected_count:
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
    return {'dimensionId': dimension_id, 'memberId': unit,
            'dependencies':[{key:value for key,value in item.items()
                             if key!='sourceCoordinateId'}
                            for item in dependencies],
            'dependenciesBySource':by_source}


def _validate_temporal_metadata(db, scope: ApplicationScope,
                                plan: ExpressionPlan) -> None:
    temporal = temporal_window(plan.expression)
    if temporal is None:
        return
    definition = temporal['definition']
    state = db.execute('''SELECT metadata_revision FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    roles = db.execute('''SELECT model_role,dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role IN ('Year','Period') ORDER BY model_role,dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()
    expected = [('Period', definition['periodDimensionId']),
                ('Year', temporal['resetGroupDimensionId'])]
    if (state is None or state['metadata_revision'] !=
            definition['calendarVersion']
            or [(row['model_role'], row['dimension_id'])
                for row in roles] != expected):
        raise ValueError('EXPRESSION_TEMPORAL_CALENDAR_STALE')
    predicate, params = _plan_member_predicates(plan)
    missing = db.execute(f'''SELECT 1 FROM epm.coordinate c
        JOIN epm.numeric_cell_current n USING
          (workspace_id,application_id,coordinate_id)
        LEFT JOIN epm.calendar_period_current cp
          ON cp.workspace_id=c.workspace_id
         AND cp.application_id=c.application_id
         AND cp.year_member_id=c.members->>%s::text
         AND cp.period_member_id=c.members->>%s::text
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
          {predicate} AND cp.change_id IS NULL LIMIT 1''',
        (temporal['resetGroupDimensionId'],
         definition['periodDimensionId'], scope.workspace_id,
         scope.application_id, *params)).fetchone()
    if missing is not None:
        raise ValueError('EXPRESSION_TEMPORAL_CALENDAR_INCOMPLETE')
    account_rows = db.execute(f'''SELECT DISTINCT m.numeric_value_kind,
            m.aggregation_operator
        FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
          (workspace_id,application_id,coordinate_id)
        JOIN epm.dimension d ON d.workspace_id=c.workspace_id
         AND d.application_id=c.application_id AND d.model_role='Account'
         AND d.status='Active'
        JOIN epm.member m ON m.workspace_id=d.workspace_id
         AND m.application_id=d.application_id
         AND m.dimension_id=d.dimension_id
         AND m.member_id=c.members->>d.dimension_id AND m.status='Active'
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
          {predicate}''',
        (scope.workspace_id, scope.application_id, *params)).fetchall()
    allowed = ({'Add', 'Subtract'} if definition['operator'] == 'prefix_sum'
               else {'Add', 'Subtract', 'NeverAggregate'})
    if not account_rows:
        selected_driver = db.execute(f'''SELECT 1 FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              {predicate} LIMIT 1''',
            (scope.workspace_id, scope.application_id, *params)).fetchone()
        if selected_driver is None:
            # The calendar and declared metadata still had to validate above.
            # No driver means no arithmetic or first-period boundary to check.
            return
        raise ValueError('EXPRESSION_TEMPORAL_MEASURE_UNSUPPORTED')
    if any(row['numeric_value_kind'] != 'amount'
            or row['aggregation_operator'] not in allowed
            for row in account_rows):
        raise ValueError('EXPRESSION_TEMPORAL_MEASURE_UNSUPPORTED')
    if (definition['operator'] == 'predecessor_delta'
            and definition['boundaryPolicy'] == 'error'):
        # A selected-domain expression emits every selected source row. Its
        # first row has no predecessor by definition; callers needing a first
        # result must bind an explicit opening amount rather than infer zero.
        raise ValueError('TEMPORAL_EXPRESSION_PREDECESSOR_MISSING')


def validate_expression_metadata(db, scope: ApplicationScope, plan: ExpressionPlan) -> None:
    """Validate fixed expression metadata independently of its trusted fact source."""
    _validate_temporal_metadata(db, scope, plan)
    bindings = source_measure_bindings(
        plan.weight_expression or plan.expression)
    if bindings:
        found = db.execute('''SELECT input.dimension_id,input.member_id,
            input.value_type,m.numeric_value_kind,d.status AS dimension_status,
            m.status AS member_status FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text,value_type text)
            LEFT JOIN epm.dimension d ON d.workspace_id=%s
            AND d.application_id=%s AND d.dimension_id=input.dimension_id
            LEFT JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id''',
            (Jsonb([{'dimension_id': axis, 'member_id': member,
                     'value_type': value_type}
                    for axis, member, value_type in bindings]),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        if len(found) != len(bindings) or any(
                row['dimension_status'] != 'Active' or
                row['member_status'] != 'Active' or
                row['numeric_value_kind'] != row['value_type']
                for row in found):
            raise ValueError('EXPRESSION_MEASURE_NUMERIC_KIND_MISMATCH')
    if plan.target_members:
        found = db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AND d.dimension_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            LEFT JOIN epm.dimension d ON d.workspace_id=%s
            AND d.application_id=%s AND d.dimension_id=input.dimension_id
            AND d.status='Active'
            LEFT JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb([{'dimension_id': axis, 'member_id': member}
                    for axis, member in plan.target_members]),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        if len(found) != len(plan.target_members) or any(
                not row['active'] for row in found):
            raise ValueError('EXPRESSION_TARGET_MEMBER_UNAVAILABLE')
    if plan.target_member_set:
        axis,members=plan.target_member_set
        found=db.execute('''SELECT m.member_id FROM unnest(%s::text[]) input(member_id)
            JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
            AND m.dimension_id=%s AND m.member_id=input.member_id
            AND m.status='Active' JOIN epm.dimension d ON d.workspace_id=m.workspace_id
            AND d.application_id=m.application_id AND d.dimension_id=m.dimension_id
            AND d.status='Active' ORDER BY input.member_id''',
            (list(members),scope.workspace_id,scope.application_id,axis)).fetchall()
        if sorted(row['member_id'] for row in found)!=sorted(members):
            raise ValueError('EXPRESSION_TARGET_MEMBER_UNAVAILABLE')
    if plan.reduce_member_set:
        axis,members,target,_=plan.reduce_member_set
        requested=sorted((*members,target))
        found=db.execute('''SELECT m.member_id FROM unnest(%s::text[]) input(member_id)
            JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
            AND m.dimension_id=%s AND m.member_id=input.member_id
            AND m.status='Active' JOIN epm.dimension d ON d.workspace_id=m.workspace_id
            AND d.application_id=m.application_id AND d.dimension_id=m.dimension_id
            AND d.status='Active' ORDER BY m.member_id''',(requested,
            scope.workspace_id,scope.application_id,axis)).fetchall()
        if sorted(row['member_id'] for row in found)!=requested:
            raise ValueError('EXPRESSION_TARGET_MEMBER_UNAVAILABLE')
    if plan.reduce_member_sets:
        for axis,members,target in plan.reduce_member_sets[0]:
            requested=sorted((*members,target))
            found=db.execute('''SELECT m.member_id FROM unnest(%s::text[]) i(member_id)
                JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
                AND m.dimension_id=%s AND m.member_id=i.member_id AND m.status='Active'
                JOIN epm.dimension d ON d.workspace_id=m.workspace_id
                AND d.application_id=m.application_id
                AND d.dimension_id=m.dimension_id AND d.status='Active'
                ORDER BY m.member_id''',(requested,scope.workspace_id,
                scope.application_id,axis)).fetchall()
            if sorted(row['member_id'] for row in found)!=requested:
                raise ValueError('EXPRESSION_TARGET_MEMBER_UNAVAILABLE')
    if plan.target_member_sets:
        for axis,members in plan.target_member_sets:
            found=db.execute('''SELECT m.member_id FROM unnest(%s::text[]) input(member_id)
                JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
                AND m.dimension_id=%s AND m.member_id=input.member_id
                AND m.status='Active' JOIN epm.dimension d ON d.workspace_id=m.workspace_id
                AND d.application_id=m.application_id AND d.dimension_id=m.dimension_id
                AND d.status='Active' ORDER BY m.member_id''',(list(members),
                scope.workspace_id,scope.application_id,axis)).fetchall()
            if sorted(row['member_id'] for row in found)!=sorted(members):
                raise ValueError('EXPRESSION_TARGET_MEMBER_UNAVAILABLE')
    overrides = sorted({pair for _, members in published_lookups(
        plan.expression) for pair in members} | {
        pair for _, members, _ in published_unit_lookups(plan.expression)
        for pair in members} | {
        pair for _, members in published_ratio_lookups(plan.expression)
        for pair in members} | {
        pair for members in source_lookups(plan.expression)
        for pair in members} | {pair for members in source_text_lookups(
            plan.expression) for pair in members})
    if overrides:
        found = db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AND d.dimension_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            LEFT JOIN epm.dimension d ON d.workspace_id=%s
            AND d.application_id=%s AND d.dimension_id=input.dimension_id
            AND d.status='Active'
            LEFT JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb([{'dimension_id': axis, 'member_id': member}
                    for axis, member in overrides]),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        if any(not row['active'] for row in found):
            raise ValueError('EXPRESSION_OVERRIDE_MEMBER_UNAVAILABLE')
    if plan.source_members:
        found = db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active FROM
            jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s
            AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb([{'dimension_id': axis, 'member_id': member}
                    for axis, member in plan.source_members]),
             scope.workspace_id, scope.application_id)).fetchall()
        if any(not row['active'] for row in found):
            raise ValueError('CALCULATION_SOURCE_MEMBER_UNAVAILABLE')
    if plan.source_member_sets:
        requested=[{'dimension_id':axis,'member_id':member}
            for axis,members in plan.source_member_sets for member in members]
        found=db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AND d.dimension_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
              AS input(dimension_id text,member_id text)
            LEFT JOIN epm.dimension d ON d.workspace_id=%s
             AND d.application_id=%s AND d.dimension_id=input.dimension_id
             AND d.status='Active'
            LEFT JOIN epm.member m ON m.workspace_id=%s
             AND m.application_id=%s AND m.dimension_id=input.dimension_id
             AND m.member_id=input.member_id AND m.status='Active' ''',(
            Jsonb(requested),scope.workspace_id,scope.application_id,
            scope.workspace_id,scope.application_id)).fetchall()
        if len(found)!=len(requested) or any(not row['active'] for row in found):
            raise ValueError('CALCULATION_SOURCE_MEMBER_UNAVAILABLE')
    if plan.result_unit == ('Ratio', 12):
        measures=db.execute('''SELECT d.dimension_id,m.member_id,
            m.numeric_value_kind FROM epm.dimension d
            JOIN epm.member m ON m.workspace_id=d.workspace_id
             AND m.application_id=d.application_id
             AND m.dimension_id=d.dimension_id
            WHERE d.workspace_id=%s AND d.application_id=%s
             AND d.model_role='Account' AND d.status='Active'
             AND m.member_id=COALESCE(%s::jsonb->>d.dimension_id,
                                     %s::jsonb->>d.dimension_id)
             AND m.status='Active' ORDER BY d.dimension_id''',(
            scope.workspace_id,scope.application_id,
            Jsonb(dict(plan.target_members)),Jsonb(dict(plan.source_members))
            )).fetchall()
        if len(measures)!=1 or measures[0]['numeric_value_kind']!='ratio':
            raise ValueError('EXPRESSION_RESULT_MEASURE_MUST_BE_RATIO')


def validate_amount_unit_coordinates(db, scope: ApplicationScope,
        plan: ExpressionPlan, source_members: list[dict] | None = None) -> None:
    """Check the one authoritative EntityDefaultCurrency binding.

    Publishers select their current source coordinates through the plan. The
    private evaluator supplies its already authorized snapshot/overlay drivers;
    neither path infers a conversion or drops the declared currency unit.
    """
    predicate, params = _plan_member_predicates(plan)
    reduction_filter='';reduction_params=()
    if plan.reduce_member_set:
        reduction_filter=' AND c.members->>%s=ANY(%s::text[])'
        reduction_params=(plan.reduce_member_set[0],
                          list(plan.reduce_member_set[1]))
    elif plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2:
        multi_reduction=_multi_reduction_sql(plan)
        reduction_filter=' AND '+multi_reduction.filter_sql
        reduction_params=multi_reduction.filter_params
    elif plan.reduce_member_sets:
        (a,am,_),(b,bm,_)=plan.reduce_member_sets[0]
        reduction_filter=(' AND c.members->>%s=ANY(%s::text[])'
                          ' AND c.members->>%s=ANY(%s::text[])')
        reduction_params=(a,list(am),b,list(bm))
    if plan.amount_unit:
        currency_axis,currency_member,_=plan.amount_unit
        unit=db.execute('''SELECT d.dimension_id,m.member_id FROM epm.dimension d
            JOIN epm.member m ON m.workspace_id=d.workspace_id
             AND m.application_id=d.application_id
             AND m.dimension_id=d.dimension_id
            WHERE d.workspace_id=%s AND d.application_id=%s
             AND d.dimension_id=%s AND d.model_role='Currency'
             AND d.status='Active' AND m.member_id=%s AND m.status='Active' ''',
            (scope.workspace_id,scope.application_id,currency_axis,
             currency_member)).fetchone()
        entity_axes=db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s
             AND model_role='Entity' AND status='Active' ORDER BY dimension_id''',
            (scope.workspace_id,scope.application_id)).fetchall()
        if unit is None:
            raise ValueError('EXPRESSION_AMOUNT_UNIT_UNAVAILABLE')
        if len(entity_axes)!=1:
            raise ValueError('EXPRESSION_ENTITY_UNIT_BINDING_UNAVAILABLE')
        entity_axis=entity_axes[0]['dimension_id']
        if source_members is None:
            mismatch=db.execute(f'''SELECT 1 FROM epm.coordinate c
                JOIN epm.numeric_cell_current n USING
                 (workspace_id,application_id,coordinate_id)
                LEFT JOIN epm.member e ON e.workspace_id=c.workspace_id
                 AND e.application_id=c.application_id
                 AND e.dimension_id=%s AND e.member_id=c.members->>%s
                 AND e.status='Active'
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                 {predicate} {reduction_filter}
                 AND (e.member_id IS NULL OR
                      e.entity_default_currency_member_id IS DISTINCT FROM %s)
                LIMIT 1''',(entity_axis,entity_axis,scope.workspace_id,
                scope.application_id,*params,*reduction_params,
                currency_member)).fetchone()
        else:
            mismatch=db.execute('''SELECT 1 FROM jsonb_array_elements(%s::jsonb) input(members)
                LEFT JOIN epm.member e ON e.workspace_id=%s AND e.application_id=%s
                 AND e.dimension_id=%s AND e.member_id=input.members->>%s
                 AND e.status='Active'
                WHERE e.member_id IS NULL OR
                  e.entity_default_currency_member_id IS DISTINCT FROM %s LIMIT 1''',
                (Jsonb(source_members),scope.workspace_id,scope.application_id,
                 entity_axis,entity_axis,currency_member)).fetchone()
        if mismatch is not None:
            raise ValueError('EXPRESSION_AMOUNT_UNIT_MISMATCH')
        if (plan.reduce_member_set is not None
                and plan.reduce_member_set[0]==entity_axis):
            target=plan.reduce_member_set[2]
            target_unit=db.execute('''SELECT 1 FROM epm.member WHERE
                workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND member_id=%s AND status='Active'
                AND entity_default_currency_member_id=%s''',(
                scope.workspace_id,scope.application_id,entity_axis,target,
                currency_member)).fetchone()
            if target_unit is None:
                raise ValueError('EXPRESSION_AMOUNT_UNIT_MISMATCH')
        for overrides in source_lookups(plan.expression):
            effective_entity = dict(overrides).get(entity_axis)
            if effective_entity is None:
                continue
            lookup_unit=db.execute('''SELECT 1 FROM epm.member WHERE
                workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND member_id=%s AND status='Active'
                AND entity_default_currency_member_id=%s''',(
                scope.workspace_id,scope.application_id,entity_axis,
                effective_entity,currency_member)).fetchone()
            if lookup_unit is None:
                raise ValueError('EXPRESSION_AMOUNT_UNIT_MISMATCH')


def source_count(db, scope: ApplicationScope, plan: ExpressionPlan,
                 identity:VerifiedIdentity|None=None) -> int:
    verify_published_inputs(db, scope, plan)
    if plan.applicability_domain:
        validate_expression_metadata(db, scope, plan)
        resolved, lowering = _resolved_applicability_sql(db, scope, plan)
        # Drive bounded windows from the pinned sparse relation. A monolithic
        # count/missing scan is planner-sensitive on a newly reconstructed
        # relation with cold statistics and can exceed the fixed statement
        # budget even though every exact coordinate lookup is indexed.
        total=0
        for row_ids in _applicability_row_windows(db,scope,plan):
            total+=len(row_ids)
            if (lowering.missing_error_predicate != 'FALSE'
                    and _applicability_has_missing_required_operand(
                        db,scope,plan,row_ids)):
                raise ValueError('APPLICABILITY_DOMAIN_OPERAND_MISSING')
            if total>resolved['domain']['maxRows']:
                raise ValueError('APPLICABILITY_DOMAIN_ROW_BUDGET_EXCEEDED')
        if total > resolved['domain']['maxRows']:
            raise ValueError('APPLICABILITY_DOMAIN_ROW_BUDGET_EXCEEDED')
        return total
    if plan.source_domain:
        dimensions=db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            ORDER BY dimension_id''',(scope.workspace_id,
            scope.application_id)).fetchall()
        if [row['dimension_id'] for row in dimensions]!=sorted(
                axis for axis,_ in plan.source_domain):
            raise ValueError('EXPRESSION_SOURCE_DOMAIN_INCOMPLETE')
        for axis,members in plan.source_domain:
            found=db.execute('''SELECT member_id FROM epm.member WHERE
                workspace_id=%s AND application_id=%s AND dimension_id=%s
                AND status='Active' AND member_id=ANY(%s::text[])
                ORDER BY member_id''',(scope.workspace_id,scope.application_id,
                axis,list(members))).fetchall()
            if sorted(row['member_id'] for row in found)!=sorted(members):
                raise ValueError('CALCULATION_SOURCE_MEMBER_UNAVAILABLE')
        return len(_domain_coordinates(plan))
    validate_expression_metadata(db, scope, plan)
    predicate, params = _plan_member_predicates(plan)
    reduction_filter='';reduction_params=()
    if plan.reduce_member_set:
        reduction_filter=' AND c.members->>%s=ANY(%s::text[])'
        reduction_params=(plan.reduce_member_set[0],
                          list(plan.reduce_member_set[1]))
    elif plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2:
        multi_reduction=_multi_reduction_sql(plan)
        reduction_filter=' AND '+multi_reduction.filter_sql
        reduction_params=multi_reduction.filter_params
    elif plan.reduce_member_sets:
        (a,am,_),(b,bm,_)=plan.reduce_member_sets[0]
        reduction_filter=(' AND c.members->>%s=ANY(%s::text[])'
                          ' AND c.members->>%s=ANY(%s::text[])')
        reduction_params=(a,list(am),b,list(bm))
    validate_amount_unit_coordinates(db, scope, plan)
    joins, join_params, aliases, missing_published, missing_source = (
        _published_joins(plan))
    if plan.weight_expression:
        weight_sql,weight_params=_sql(plan.weight_expression,aliases)
        if weight_params:
            raise ValueError('EXPRESSION_WEIGHT_SOURCE_INVALID')
        invalid_weight=db.execute(f'''SELECT 1 FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING
             (workspace_id,application_id,coordinate_id)
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             {predicate} {reduction_filter}
             AND ({weight_sql}<0) LIMIT 1''',(*join_params,
            scope.workspace_id,scope.application_id,*params,*reduction_params
            )).fetchone()
        if invalid_weight is not None:
            raise ValueError('EXPRESSION_WEIGHT_NEGATIVE')
        zero_weight=db.execute(f'''SELECT 1 FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING
             (workspace_id,application_id,coordinate_id)
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             {predicate} {reduction_filter}
            GROUP BY c.members-%s::text HAVING sum({weight_sql})=0
            LIMIT 1''',(*join_params,scope.workspace_id,
            scope.application_id,*params,*reduction_params,
            plan.reduce_member_set[0])).fetchone()
        if zero_weight is not None:
            raise ValueError('EXPRESSION_WEIGHT_DENOMINATOR_ZERO')
    selected_limit=(min(plan.selected_domain['maxSourceCells'],
                        plan.selected_domain['maxOutputCells'],500)
                    if plan.selected_domain else 500)
    count = db.execute(f'''SELECT count(*) AS total FROM (
        SELECT 1 FROM epm.coordinate c JOIN epm.numeric_cell_current n
          ON n.workspace_id=c.workspace_id
         AND n.application_id=c.application_id
         AND n.coordinate_id=c.coordinate_id
        {joins}
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND n.present {predicate} {reduction_filter} LIMIT %s) bounded''',
        (*join_params, scope.workspace_id,
         scope.application_id, *params,*reduction_params,
         selected_limit+1)).fetchone()['total']
    if plan.selected_domain and count>selected_limit:
        if count>plan.selected_domain['maxSourceCells']:
            raise ValueError('SELECTED_DOMAIN_SOURCE_BUDGET_EXCEEDED')
        if count>plan.selected_domain['maxOutputCells']:
            raise ValueError('SELECTED_DOMAIN_OUTPUT_BUDGET_EXCEEDED')
        raise ValueError('SELECTED_DOMAIN_PARTITION_REQUIRED')
    if (plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2
            and count>500):
        raise ValueError('EXPRESSION_MULTI_AXIS_REDUCTION_SOURCE_LIMIT')
    if plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2:
        multi_reduction=_multi_reduction_sql(plan)
        output_count=db.execute(f'''SELECT count(*) total FROM (
            SELECT {multi_reduction.base_sql} FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
            AND {multi_reduction.filter_sql} {predicate}
            GROUP BY 1 LIMIT 501) grouped''',(
            *multi_reduction.base_params,scope.workspace_id,
            scope.application_id,*multi_reduction.filter_params,
            *params)).fetchone()['total']
    elif plan.reduce_member_sets:
        (a,am,_),(b,bm,_)=plan.reduce_member_sets[0]
        output_count=db.execute(f'''SELECT count(*) total FROM (
            SELECT (c.members-%s::text)-%s::text FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
            AND c.members->>%s=ANY(%s::text[]) AND c.members->>%s=ANY(%s::text[])
            {predicate} GROUP BY 1 LIMIT 2) grouped''',(a,b,scope.workspace_id,
            scope.application_id,a,list(am),b,list(bm),*params)).fetchone()['total']
    elif plan.reduce_member_set:
        axis,members,_,_=plan.reduce_member_set
        reduction_groups=db.execute(f'''SELECT count(*) total FROM (
            SELECT c.members-%s::text FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
            AND c.members->>%s=ANY(%s::text[]) {predicate}
            GROUP BY 1 LIMIT 501) grouped''',(axis,
            scope.workspace_id,scope.application_id,axis,list(members),*params
            )).fetchone()['total']
        output_count=reduction_groups
    else:
        multiplier=(len(plan.target_member_set[1]) if plan.target_member_set else
            (len(_target_member_combinations(plan))
             if plan.target_member_sets else 1))
        output_count=count*multiplier
    if output_count > (plan.selected_domain['maxOutputCells']
                       if plan.selected_domain else 500):
        raise ValueError('SELECTED_DOMAIN_OUTPUT_BUDGET_EXCEEDED'
                         if plan.selected_domain else
                         'CALCULATION_RESULT_LIMIT')
    if (plan.required_source_count is not None
            and count != plan.required_source_count):
        raise ValueError('EXPRESSION_REQUIRED_SOURCE_COUNT_MISMATCH')
    if currency_conversion(plan.expression) is not None:
        if output_count!=1:
            raise ValueError('EXPRESSION_CURRENCY_SOURCE_GRAIN_INVALID')
        validate_currency_conversion(db,scope,identity,plan)
    missing_text=' OR '.join(f'rawtv{index}.coordinate_id IS NULL'
        for index,_ in enumerate(source_text_lookups(plan.expression)))
    if missing_text and db.execute(f'''SELECT 1 FROM epm.coordinate c
        JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
        {joins} WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
        {predicate} {reduction_filter} AND ({missing_text}) LIMIT 1''',(
        *join_params,scope.workspace_id,scope.application_id,*params,
        *reduction_params)).fetchone():
        raise ValueError('EXPRESSION_TEXT_LOOKUP_CELL_MISSING')
    for missing, error in ((missing_source,
                           'EXPRESSION_SOURCE_LOOKUP_CELL_MISSING'),
                           (missing_published,
                           'EXPRESSION_PUBLISHED_CELL_MISSING')):
        if missing and db.execute(f'''SELECT 1 FROM epm.coordinate c
            JOIN epm.numeric_cell_current n
              ON n.workspace_id=c.workspace_id
             AND n.application_id=c.application_id
             AND n.coordinate_id=c.coordinate_id
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s
            AND n.present {predicate} {reduction_filter}
            AND ({missing}) LIMIT 1''',
            (*join_params, scope.workspace_id,
             scope.application_id, *params,*reduction_params)).fetchone():
            raise ValueError(error)
    if (plan.driver_policy and plan.driver_policy.get('policyFormat') ==
            'openepm-planning-operation-policy-v2'):
        budget=plan.driver_policy['upstreamLineageBudget']
        for index,_ in enumerate(published_lookups(plan.expression)):
            oversized=db.execute(f'''SELECT 1
                FROM epm.coordinate c JOIN epm.numeric_cell_current n
                  ON n.workspace_id=c.workspace_id
                 AND n.application_id=c.application_id
                 AND n.coordinate_id=c.coordinate_id
                {joins}
                WHERE c.workspace_id=%s AND c.application_id=%s
                  AND n.present {predicate} {reduction_filter}
                  AND octet_length(p{index}.source_lookup_lineage::text)>
                      %s LIMIT 1''',(*join_params,
                scope.workspace_id,scope.application_id,*params,
                *reduction_params,budget['maxCanonicalBytes'])).fetchone()
            if oversized:
                raise ValueError('DRIVER_POLICY_UPSTREAM_LINEAGE_LIMIT')
        lineage_sql,lineage_params=_source_lineage_sql(plan)
        rows=db.execute(f'''SELECT {lineage_sql} AS lineage,
                octet_length(({lineage_sql})::text) AS canonical_bytes
            FROM epm.coordinate c JOIN epm.numeric_cell_current n
              ON n.workspace_id=c.workspace_id
             AND n.application_id=c.application_id
             AND n.coordinate_id=c.coordinate_id
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND n.present {predicate} {reduction_filter}
            ORDER BY c.series_key LIMIT 501''',(
            *lineage_params,*lineage_params,*join_params,
            scope.workspace_id,scope.application_id,*params,
            *reduction_params)).fetchall()
        if len(rows)>500:
            raise ValueError('DRIVER_POLICY_UPSTREAM_LINEAGE_LIMIT')
        for row in rows:
            _validate_stored_lineage(row['lineage'],
                canonical_bytes=row['canonical_bytes'],
                max_canonical_bytes=budget['maxCanonicalBytes'],
                max_depth=budget['maxDepth'])
    if _has_dynamic_divisor(plan.expression):
        expression_sql, expression_params = _sql(plan.expression, aliases)
        failure_sql, failure_params = _dynamic_division_failure_sql(
            plan.expression, aliases)
        if db.execute(f'''SELECT 1 FROM epm.coordinate c
            JOIN epm.numeric_cell_current n
              ON n.workspace_id=c.workspace_id
             AND n.application_id=c.application_id
             AND n.coordinate_id=c.coordinate_id
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND n.present {predicate} {reduction_filter}
              AND (({failure_sql}) OR ({expression_sql}) IS NULL) LIMIT 1''',
            (*join_params, scope.workspace_id, scope.application_id,
             *params,*reduction_params, *failure_params,
             *expression_params)).fetchone():
            raise ValueError('EXPRESSION_DIVISOR_ZERO_OR_MISSING')
    if plan.result_unit == ('Ratio', 12):
        expression_sql, expression_params = _sql(plan.expression, aliases)
        if db.execute(f'''SELECT 1 FROM epm.coordinate c
            JOIN epm.numeric_cell_current n
              ON n.workspace_id=c.workspace_id
             AND n.application_id=c.application_id
             AND n.coordinate_id=c.coordinate_id
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND n.present {predicate}
              AND abs(epm.round_half_even({expression_sql},12))
                    >= 100000000::numeric
            LIMIT 1''',(*join_params,scope.workspace_id,
            scope.application_id,*params,*expression_params)).fetchone():
            raise ValueError('EXPRESSION_RATIO_RESULT_OUT_OF_RANGE')
    return output_count


def materialize_targets(db, scope: ApplicationScope, plan: ExpressionPlan,
                        count: int, *, heartbeat=None) -> None:
    """Create complete target coordinates; numeric effects remain set-based."""
    if plan.applicability_domain:
        _, lowering = _resolved_applicability_sql(db, scope, plan)
        selected = f'''SELECT DISTINCT c.workspace_id,c.application_id,
              {lowering.target_members_sql} AS members
            FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            {lowering.joins}
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              AND ({lowering.required_predicate})
              AND applicability_row.row_id=ANY(%s::text[])'''
        matched=0
        for row_ids in _applicability_row_windows(
                db,scope,plan,heartbeat=heartbeat):
            selected_params = (*lowering.target_parameters,
                *lowering.join_parameters,scope.workspace_id,
                scope.application_id,list(row_ids))
            db.execute(f'''INSERT INTO epm.coordinate(
                workspace_id,application_id,series_key,members)
                SELECT workspace_id,application_id,
                epm.coordinate_series_key(members),members
                FROM ({selected}) target
                ON CONFLICT(workspace_id,application_id,series_key)
                DO NOTHING''',selected_params)
            matched += db.execute(f'''SELECT count(*) total
                FROM ({selected}) target JOIN epm.coordinate t
                  ON t.workspace_id=target.workspace_id
                 AND t.application_id=target.application_id
                 AND t.members=target.members''',
                selected_params).fetchone()['total']
            db.execute(f'''INSERT INTO epm.coordinate_member_projection(
                workspace_id,application_id,coordinate_id,dimension_id,
                member_id,projection_generation)
                SELECT t.workspace_id,t.application_id,t.coordinate_id,
                  x.key,x.value,(SELECT epm.active_projection_generation())
                FROM ({selected}) target JOIN epm.coordinate t
                  ON t.workspace_id=target.workspace_id
                 AND t.application_id=target.application_id
                 AND t.members=target.members
                CROSS JOIN LATERAL jsonb_each_text(t.members)x
                ON CONFLICT(workspace_id,application_id,
                    projection_generation,coordinate_id,dimension_id)
                DO NOTHING''',selected_params)
        if matched != count:
            raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        return
    if plan.source_domain:
        coordinates=_domain_coordinates(plan)
        db.execute('''INSERT INTO epm.coordinate(workspace_id,application_id,
            series_key,members) SELECT %s,%s,epm.coordinate_series_key(i.members),
            i.members FROM jsonb_to_recordset(%s::jsonb)i(members jsonb)
            ON CONFLICT(workspace_id,application_id,series_key) DO NOTHING''',(
            scope.workspace_id,scope.application_id,
            Jsonb([{'members':item} for item in coordinates])))
        matched=db.execute('''SELECT count(*) total FROM
            jsonb_to_recordset(%s::jsonb)i(members jsonb) JOIN epm.coordinate c
            ON c.workspace_id=%s AND c.application_id=%s AND c.members=i.members''',(
            Jsonb([{'members':item} for item in coordinates]),
            scope.workspace_id,scope.application_id)).fetchone()['total']
        if matched!=count:raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        db.execute('''INSERT INTO epm.coordinate_member_projection(workspace_id,
            application_id,coordinate_id,dimension_id,member_id,projection_generation)
            SELECT c.workspace_id,c.application_id,c.coordinate_id,x.key,x.value,
              (SELECT epm.active_projection_generation()) FROM epm.coordinate c
            JOIN jsonb_to_recordset(%s::jsonb)i(members jsonb) ON i.members=c.members
            CROSS JOIN LATERAL jsonb_each_text(c.members)x
            WHERE c.workspace_id=%s AND c.application_id=%s
            ON CONFLICT(workspace_id,application_id,projection_generation,
                        coordinate_id,dimension_id) DO NOTHING''',(
            Jsonb([{'members':item} for item in coordinates]),
            scope.workspace_id,scope.application_id))
        return
    if plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2:
        reduction=_multi_reduction_sql(plan)
        predicate,params=_plan_member_predicates(plan)
        grouped=f'''SELECT c.workspace_id,c.application_id,
             {reduction.target_sql} members FROM epm.coordinate c
             JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
             WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             AND {reduction.filter_sql} {predicate} GROUP BY 1,2,3'''
        grouped_params=(*reduction.target_params,scope.workspace_id,
            scope.application_id,*reduction.filter_params,*params)
        db.execute(f'''INSERT INTO epm.coordinate(workspace_id,application_id,
            series_key,members) SELECT workspace_id,application_id,
            epm.coordinate_series_key(members),members FROM ({grouped}) grouped
            ON CONFLICT(workspace_id,application_id,series_key) DO NOTHING''',
            grouped_params)
        matched=db.execute(f'''SELECT count(*) total FROM ({grouped}) grouped
            JOIN epm.coordinate t ON t.workspace_id=grouped.workspace_id
             AND t.application_id=grouped.application_id
             AND t.members=grouped.members''',grouped_params).fetchone()['total']
        if matched!=count:raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        db.execute(f'''INSERT INTO epm.coordinate_member_projection(workspace_id,
            application_id,coordinate_id,dimension_id,member_id,
            projection_generation) SELECT t.workspace_id,t.application_id,
            t.coordinate_id,x.key,x.value,(SELECT epm.active_projection_generation())
            FROM ({grouped}) grouped JOIN epm.coordinate t
             ON t.workspace_id=grouped.workspace_id
             AND t.application_id=grouped.application_id
             AND t.members=grouped.members
            CROSS JOIN LATERAL jsonb_each_text(t.members)x
            ON CONFLICT(workspace_id,application_id,projection_generation,
                coordinate_id,dimension_id) DO NOTHING''',grouped_params)
        return
    if plan.reduce_member_sets:
        (a,am,at),(b,bm,bt)=plan.reduce_member_sets[0]
        predicate,params=_plan_member_predicates(plan)
        db.execute(f'''INSERT INTO epm.coordinate(workspace_id,application_id,
            series_key,members) SELECT workspace_id,application_id,
            epm.coordinate_series_key(base||jsonb_build_object(
                %s::text,%s::text,%s::text,%s::text)),
            base||jsonb_build_object(%s::text,%s::text,%s::text,%s::text)
            FROM (SELECT c.workspace_id,c.application_id,
              (c.members-%s::text)-%s::text base FROM epm.coordinate c
              JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
              WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              AND c.members->>%s=ANY(%s::text[]) AND c.members->>%s=ANY(%s::text[])
              {predicate} GROUP BY 1,2,3) grouped
            ON CONFLICT(workspace_id,application_id,series_key) DO NOTHING''',(
            a,at,b,bt,a,at,b,bt,a,b,scope.workspace_id,scope.application_id,
            a,list(am),b,list(bm),*params))
        db.execute('''INSERT INTO epm.coordinate_member_projection(workspace_id,
            application_id,coordinate_id,dimension_id,member_id,
            projection_generation) SELECT c.workspace_id,c.application_id,
            c.coordinate_id,x.key,x.value,(SELECT epm.active_projection_generation())
            FROM epm.coordinate c CROSS JOIN LATERAL jsonb_each_text(c.members)x
            WHERE c.workspace_id=%s AND c.application_id=%s
            AND c.members->>%s=%s AND c.members->>%s=%s
            ON CONFLICT(workspace_id,application_id,projection_generation,
                coordinate_id,dimension_id) DO NOTHING''',(
            scope.workspace_id,scope.application_id,a,at,b,bt))
        return
    if plan.target_member_sets:
        combinations=_target_member_combinations(plan)
        encoded=Jsonb([{'members':item} for item in combinations])
        predicate,params=_plan_member_predicates(plan)
        db.execute(f'''INSERT INTO epm.coordinate(workspace_id,application_id,
            series_key,members) SELECT c.workspace_id,c.application_id,
            epm.coordinate_series_key(c.members||target.members),
            c.members||target.members
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            CROSS JOIN jsonb_to_recordset(%s::jsonb) target(members jsonb)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             {predicate}
            ON CONFLICT(workspace_id,application_id,series_key) DO NOTHING''',(
            encoded,scope.workspace_id,scope.application_id,*params))
        matched=db.execute(f'''SELECT count(*) total FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
            CROSS JOIN jsonb_to_recordset(%s::jsonb) target(members jsonb)
            JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
             AND t.application_id=c.application_id
             AND t.members=c.members||target.members
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             {predicate}''',(encoded,scope.workspace_id,
             scope.application_id,*params)).fetchone()['total']
        if matched!=count:raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        db.execute(f'''INSERT INTO epm.coordinate_member_projection(workspace_id,
            application_id,coordinate_id,dimension_id,member_id,projection_generation)
            SELECT t.workspace_id,t.application_id,t.coordinate_id,x.key,x.value,
              (SELECT epm.active_projection_generation())
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
             (workspace_id,application_id,coordinate_id)
            CROSS JOIN jsonb_to_recordset(%s::jsonb) target(members jsonb)
            JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
             AND t.application_id=c.application_id
             AND t.members=c.members||target.members
            CROSS JOIN LATERAL jsonb_each_text(t.members)x
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             {predicate}
            ON CONFLICT(workspace_id,application_id,projection_generation,
                        coordinate_id,dimension_id) DO NOTHING''',(
            encoded,scope.workspace_id,scope.application_id,*params))
        return
    if plan.reduce_member_set:
        axis,members,target,_=plan.reduce_member_set
        predicate,params=_plan_member_predicates(plan)
        db.execute(f'''INSERT INTO epm.coordinate(workspace_id,application_id,
            series_key,members) SELECT workspace_id,application_id,
            epm.coordinate_series_key(base||jsonb_build_object(%s::text,%s::text)),
            base||jsonb_build_object(%s::text,%s::text) FROM (
            SELECT c.workspace_id,c.application_id,c.members-%s::text base
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             AND c.members->>%s=ANY(%s::text[]) {predicate}
            GROUP BY c.workspace_id,c.application_id,3) grouped
            ON CONFLICT(workspace_id,application_id,series_key) DO NOTHING''',
            (axis,target,axis,target,axis,scope.workspace_id,
             scope.application_id,axis,list(members),*params))
        matched=db.execute(f'''SELECT count(*) total FROM (
            SELECT c.members-%s::text base FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             AND c.members->>%s=ANY(%s::text[]) {predicate}
            GROUP BY 1) g JOIN epm.coordinate t
              ON t.workspace_id=%s AND t.application_id=%s
             AND t.members=g.base||jsonb_build_object(%s::text,%s::text)''',
            (axis,scope.workspace_id,scope.application_id,axis,list(members),
             *params,scope.workspace_id,scope.application_id,axis,target)
            ).fetchone()['total']
        if matched!=count:raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        db.execute('''INSERT INTO epm.coordinate_member_projection(workspace_id,
            application_id,coordinate_id,dimension_id,member_id,projection_generation)
            SELECT t.workspace_id,t.application_id,t.coordinate_id,x.key,x.value,
              (SELECT epm.active_projection_generation()) FROM epm.coordinate t
            CROSS JOIN LATERAL jsonb_each_text(t.members)x
            WHERE t.workspace_id=%s AND t.application_id=%s
             AND t.members->>%s=%s
            ON CONFLICT(workspace_id,application_id,projection_generation,
                        coordinate_id,dimension_id) DO NOTHING''',
            (scope.workspace_id,scope.application_id,axis,target))
        return
    if plan.target_member_set:
        axis,members=plan.target_member_set
        predicate,params=_plan_member_predicates(plan)
        db.execute(f'''INSERT INTO epm.coordinate
            (workspace_id,application_id,series_key,members)
            SELECT c.workspace_id,c.application_id,
              epm.coordinate_series_key(c.members || jsonb_build_object(%s::text,m.member_id)),
              c.members || jsonb_build_object(%s::text,m.member_id)
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            CROSS JOIN unnest(%s::text[]) m(member_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present {predicate}
            ON CONFLICT(workspace_id,application_id,series_key) DO NOTHING''',
            (axis,axis,list(members),scope.workspace_id,scope.application_id,*params))
        matched=db.execute(f'''SELECT count(*) total FROM epm.coordinate c
            JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
            CROSS JOIN unnest(%s::text[]) m(member_id)
            JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
             AND t.application_id=c.application_id
             AND t.members=c.members||jsonb_build_object(%s::text,m.member_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present {predicate}''',
            (list(members),axis,scope.workspace_id,scope.application_id,*params)
            ).fetchone()['total']
        if matched!=count:raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        db.execute(f'''INSERT INTO epm.coordinate_member_projection
            (workspace_id,application_id,coordinate_id,dimension_id,member_id,
             projection_generation)
            SELECT DISTINCT t.workspace_id,t.application_id,t.coordinate_id,x.key,x.value,
              (SELECT epm.active_projection_generation())
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            CROSS JOIN unnest(%s::text[]) m(member_id)
            JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
             AND t.application_id=c.application_id
             AND t.members=c.members||jsonb_build_object(%s::text,m.member_id)
            CROSS JOIN LATERAL jsonb_each_text(t.members) x
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present {predicate}
            ON CONFLICT(workspace_id,application_id,projection_generation,
                        coordinate_id,dimension_id) DO NOTHING''',
            (list(members),axis,scope.workspace_id,scope.application_id,*params))
        return
    if not plan.target_members:
        return
    target = Jsonb(dict(plan.target_members))
    predicate, params = _plan_member_predicates(plan)
    db.execute(f'''INSERT INTO epm.coordinate
        (workspace_id,application_id,series_key,members)
        SELECT c.workspace_id,c.application_id,
            epm.coordinate_series_key(c.members || %s::jsonb),
            c.members || %s::jsonb
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
          ON n.workspace_id=c.workspace_id
         AND n.application_id=c.application_id
         AND n.coordinate_id=c.coordinate_id
        WHERE c.workspace_id=%s AND c.application_id=%s
          AND n.present {predicate}
        ON CONFLICT (workspace_id,application_id,series_key) DO NOTHING''',
        (target, target, scope.workspace_id, scope.application_id, *params))
    matched = db.execute(f'''SELECT count(*) AS total
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
          ON n.workspace_id=c.workspace_id
         AND n.application_id=c.application_id
         AND n.coordinate_id=c.coordinate_id
        JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
          AND t.application_id=c.application_id
          AND t.series_key=epm.coordinate_series_key(
              c.members || %s::jsonb)
          AND t.members=c.members || %s::jsonb
        WHERE c.workspace_id=%s AND c.application_id=%s
          AND n.present {predicate}''',
        (target, target, scope.workspace_id, scope.application_id,
         *params)).fetchone()['total']
    if matched != count:
        raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
    db.execute(f'''INSERT INTO epm.coordinate_member_projection
        (workspace_id,application_id,coordinate_id,dimension_id,member_id,projection_generation)
        SELECT DISTINCT t.workspace_id,t.application_id,t.coordinate_id,
            target_member.dimension_id,target_member.member_id,(SELECT epm.active_projection_generation())
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
          ON n.workspace_id=c.workspace_id
         AND n.application_id=c.application_id
         AND n.coordinate_id=c.coordinate_id
        JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
          AND t.application_id=c.application_id
          AND t.members=c.members || %s::jsonb
        CROSS JOIN LATERAL jsonb_each_text(t.members)
          AS target_member(dimension_id,member_id)
        WHERE c.workspace_id=%s AND c.application_id=%s
          AND n.present {predicate}
        ON CONFLICT (workspace_id,application_id,projection_generation,coordinate_id,dimension_id)
          DO NOTHING''',
        (target, scope.workspace_id, scope.application_id, *params))


def expression_driver_coordinates(db, scope: ApplicationScope,
                                  plan: ExpressionPlan, *,
                                  max_coordinates: int | None = None) -> tuple[Coordinate, ...]:
    """Bounded primary grain, without reading operand values or result heads."""
    if max_coordinates is not None and (type(max_coordinates) is not int or max_coordinates < 1):
        raise ValueError('EXPRESSION_DRIVER_COORDINATE_LIMIT_INVALID')
    if plan.applicability_domain:
        raise ValueError('EXPRESSION_DRIVER_COORDINATE_PROFILE_UNSUPPORTED')
    if plan.source_domain:
        primary=_domain_coordinates(plan)
    else:
        predicate,params=_plan_member_predicates(plan)
        reduction_filter='';reduction_params=()
        if plan.reduce_member_set:
            reduction_filter=' AND c.members->>%s=ANY(%s::text[])'
            reduction_params=(plan.reduce_member_set[0],
                              list(plan.reduce_member_set[1]))
        elif plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2:
            reduction=_multi_reduction_sql(plan)
            reduction_filter=' AND '+reduction.filter_sql
            reduction_params=reduction.filter_params
        elif plan.reduce_member_sets:
            (a,am,_),(b,bm,_)=plan.reduce_member_sets[0]
            reduction_filter=(' AND c.members->>%s=ANY(%s::text[])'
                              ' AND c.members->>%s=ANY(%s::text[])')
            reduction_params=(a,list(am),b,list(bm))
        source_limit = 501 if max_coordinates is None else max_coordinates + 1
        primary=[row['members'] for row in db.execute(f'''SELECT c.members
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
             (workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
             {predicate} {reduction_filter} ORDER BY c.series_key LIMIT %s''',(
            scope.workspace_id,scope.application_id,*params,
            *reduction_params,source_limit)).fetchall()]
    if max_coordinates is not None and len(primary) > max_coordinates:
        raise ValueError('CALCULATION_SOURCE_LIMIT_EXCEEDED')
    return tuple(Coordinate.from_mapping(members) for members in primary)


def expression_source_coordinates(db,scope:ApplicationScope,
                                  plan:ExpressionPlan, *,
                                  driver_coordinates: tuple[Coordinate, ...] | None = None)->tuple[Coordinate,...]:
    """Resolve every raw or published coordinate read by a sealed expression."""
    if plan.applicability_domain:
        _, lowering = _resolved_applicability_sql(db,scope,plan)
        operand_members = [
            f'relation_operand_coordinate_{index}.coordinate_id'
            for index,_ in enumerate(plan.applicability_domain['operands'])]
        columns = ['c.members AS members'] + [
            f'operand_{index}.members AS operand_{index}_members'
            for index,_ in enumerate(operand_members)]
        operand_joins = '\n'.join(
            f'''LEFT JOIN epm.coordinate operand_{index}
              ON operand_{index}.workspace_id=c.workspace_id
             AND operand_{index}.application_id=c.application_id
             AND operand_{index}.coordinate_id={coordinate_id}'''
            for index,coordinate_id in enumerate(operand_members))
        rows=db.execute(f'''SELECT {','.join(columns)}
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            {lowering.joins}
            {operand_joins}
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              AND ({lowering.required_predicate})
            ORDER BY c.series_key,applicability_row.row_id LIMIT 501''',(
            *lowering.join_parameters,scope.workspace_id,
            scope.application_id)).fetchall()
        if len(rows)>500:
            raise ValueError('CALCULATION_SOURCE_LIMIT_EXCEEDED')
        coordinates=set()
        for row in rows:
            coordinates.add(Coordinate.from_mapping(row['members']))
            for index,_ in enumerate(operand_members):
                members=row[f'operand_{index}_members']
                if members is not None:
                    coordinates.add(Coordinate.from_mapping(members))
        return tuple(sorted(coordinates,key=lambda item:item.series_key))
    primary = [dict(coordinate.members) for coordinate in
               (expression_driver_coordinates(db, scope, plan)
                if driver_coordinates is None else driver_coordinates)]
    lookup_nodes=(plan.expression,)+(
        (plan.weight_expression,) if plan.weight_expression else ())
    overrides=set()
    for node in lookup_nodes:
        overrides.update(members for _,members in published_lookups(node))
        overrides.update(members for _,members,_ in published_unit_lookups(node))
        overrides.update(members for _,members in published_ratio_lookups(node))
        overrides.update(source_lookups(node))
        overrides.update(source_text_lookups(node))
    coordinates={Coordinate.from_mapping(members) for members in primary}
    for members in primary:
        for override in overrides:
            coordinates.add(Coordinate.from_mapping({**members,**dict(override)}))
    return tuple(sorted(coordinates,key=lambda item:item.series_key))


def _applicability_source_coordinates_for_rows(db,scope,plan,row_ids):
    resolved,_=_resolved_applicability_sql(db,scope,plan)
    domain=resolved['domain']
    rows=db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
          AND row_id=ANY(%s::text[]) ORDER BY row_id''',(
        scope.workspace_id,scope.application_id,resolved['relationId'],
        list(row_ids))).fetchall()
    coordinates=set()
    for row in rows:
        source={item['dimensionId']:row['values'][item['columnId']]
                for item in domain['anchorMemberColumns']}
        coordinates.add(Coordinate.from_mapping(source))
        for operand in domain['operands']:
            members={**source,**{item['dimensionId']:
                row['values'][item['columnId']]
                for item in operand['memberColumns']}}
            coordinates.add(Coordinate.from_mapping(members))
    return tuple(sorted(coordinates,key=lambda item:item.series_key))


def _applicability_target_coordinates_for_rows(db,scope,plan,row_ids):
    resolved,_=_resolved_applicability_sql(db,scope,plan)
    domain=resolved['domain']
    rows=db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
          AND row_id=ANY(%s::text[]) ORDER BY row_id''',(
        scope.workspace_id,scope.application_id,resolved['relationId'],
        list(row_ids))).fetchall()
    return tuple(Coordinate.from_mapping({
        **{item['dimensionId']:row['values'][item['columnId']]
           for item in domain['anchorMemberColumns']},
        **{item['dimensionId']:row['values'][item['columnId']]
           for item in domain['targetMemberColumns']}}) for row in rows)


def _applicability_has_missing_required_operand(db,scope,plan,row_ids):
    """Check one bounded relation page through exact coordinate identities."""
    resolved,_=_resolved_applicability_sql(db,scope,plan)
    domain=resolved['domain']
    required=[item for item in domain['operands']
              if item['missing']=='error']
    if not required:return False
    rows=db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
          AND row_id=ANY(%s::text[]) ORDER BY row_id''',(
        scope.workspace_id,scope.application_id,resolved['relationId'],
        list(row_ids))).fetchall()
    coordinates={}
    for row in rows:
        source={item['dimensionId']:row['values'][item['columnId']]
                for item in domain['anchorMemberColumns']}
        for operand in required:
            coordinate=Coordinate.from_mapping({**source,**{
                item['dimensionId']:row['values'][item['columnId']]
                for item in operand['memberColumns']}})
            coordinates[coordinate.series_key]=dict(coordinate.members)
    if not coordinates:return False
    # jsonb_to_recordset binds JSON object keys to the declared SQL column
    # names exactly.  Keep the wire key in snake_case; a camelCase key here
    # becomes NULL and falsely reports every required operand as missing.
    declared=[{'series_key':series,'members':members}
              for series,members in sorted(coordinates.items())]
    return db.execute('''SELECT 1
        FROM jsonb_to_recordset(%s::jsonb)
          required(series_key text,members jsonb)
        LEFT JOIN epm.coordinate c ON c.workspace_id=%s
          AND c.application_id=%s AND c.series_key=required.series_key
          AND c.members=required.members
        LEFT JOIN epm.numeric_cell_current n ON
          n.workspace_id=c.workspace_id AND n.application_id=c.application_id
          AND n.coordinate_id=c.coordinate_id AND n.present
        WHERE n.coordinate_id IS NULL LIMIT 1''',(
        Jsonb(declared),scope.workspace_id,
        scope.application_id)).fetchone() is not None


def _applicability_result_stage_statement(db,scope,plan,operation_id,
        row_ids,*,durable:bool):
    """Build one exact private staging quantum for a pinned relation."""
    joins,join_params,aliases,_,_=_published_joins(plan)
    _,lowering=_resolved_applicability_sql(db,scope,plan)
    joins='\n'.join((joins,lowering.joins))
    join_params.extend(lowering.join_parameters)
    aliases.update(lowering.aliases)
    aliases.update({key:(lowering.aliases[key],params)
        for key,params in lowering.value_parameters.items()})
    expression_sql,expression_params=_sql(plan.expression,aliases)
    lineage_sql,lineage_params=_source_lineage_sql(plan)
    lineage_sql=(f'''({lineage_sql})||jsonb_build_array(
        {lowering.lineage_sql})''')
    lineage_params=(*lineage_params,*lowering.lineage_parameters)
    predicate,filter_params=_plan_member_predicates(plan)
    predicate+=f' AND ({lowering.required_predicate})'
    target_join=f'''JOIN epm.coordinate t
        ON t.workspace_id=c.workspace_id
       AND t.application_id=c.application_id
       AND t.series_key=epm.coordinate_series_key(
           {lowering.target_members_sql})
       AND t.members={lowering.target_members_sql}'''
    target_params=(*lowering.target_parameters,*lowering.target_parameters)
    if durable:
        target='epm.expression_result_staging_row'
        columns='''workspace_id,application_id,operation_id,relation_row_id,
          coordinate_id,source_amount,source_change_id,amount,
          source_lookup_lineage'''
        select_identity='%s,applicability_row.row_id,'
    else:
        target='pg_temp.calculation_result_stage'
        columns='''workspace_id,application_id,generation_id,coordinate_id,
          source_amount,source_change_id,amount,source_lookup_lineage'''
        select_identity='%s,'
    sql=f'''INSERT INTO {target} ({columns})
        SELECT c.workspace_id,c.application_id,{select_identity}
          t.coordinate_id,n.amount,n.change_id,
          epm.round_half_even({expression_sql},8),{lineage_sql}
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
          ON n.workspace_id=c.workspace_id
         AND n.application_id=c.application_id
         AND n.coordinate_id=c.coordinate_id
        {joins}
        {target_join}
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
          {predicate}
          AND applicability_row.row_id=ANY(%s::text[])'''
    parameters=(operation_id,*expression_params,*lineage_params,
        *join_params,*target_params,scope.workspace_id,scope.application_id,
        *filter_params,list(row_ids))
    return sql,parameters


def expression_target_coordinates(db,scope:ApplicationScope,
                                  plan:ExpressionPlan,count:int
                                  )->tuple[Coordinate,...]:
    """Resolve every output coordinate from the same bounded plan as SQL."""
    if count == 0:return ()
    if plan.applicability_domain:
        _,lowering=_resolved_applicability_sql(db,scope,plan)
        rows=db.execute(f'''SELECT {lowering.target_members_sql} members
            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            {lowering.joins}
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              AND ({lowering.required_predicate})
            ORDER BY c.series_key,applicability_row.row_id''',(
            *lowering.target_parameters,*lowering.join_parameters,
            scope.workspace_id,scope.application_id)).fetchall()
    elif plan.source_domain:
        rows=[{'members':item} for item in _domain_coordinates(plan)]
    else:
        predicate,params=_plan_member_predicates(plan)
        if plan.target_member_sets:
            encoded=Jsonb([{'members':item}
                           for item in _target_member_combinations(plan)])
            rows=db.execute(f'''SELECT c.members||target.members members
                FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
                 (workspace_id,application_id,coordinate_id)
                CROSS JOIN jsonb_to_recordset(%s::jsonb) target(members jsonb)
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                 {predicate} ORDER BY c.members,target.members''',(
                encoded,scope.workspace_id,scope.application_id,
                *params)).fetchall()
        elif plan.reduce_member_sets and len(plan.reduce_member_sets[0])>2:
            reduction=_multi_reduction_sql(plan)
            rows=db.execute(f'''SELECT {reduction.target_sql} members
                FROM epm.coordinate c JOIN epm.numeric_cell_current n
                USING(workspace_id,application_id,coordinate_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                AND {reduction.filter_sql} {predicate}
                GROUP BY 1 ORDER BY 1''',(*reduction.target_params,
                scope.workspace_id,scope.application_id,
                *reduction.filter_params,*params)).fetchall()
        elif plan.reduce_member_sets:
            (a,am,at),(b,bm,bt)=plan.reduce_member_sets[0]
            rows=db.execute(f'''SELECT ((c.members-%s::text)-%s::text)||
                jsonb_build_object(%s::text,%s::text,%s::text,%s::text) members
                FROM epm.coordinate c JOIN epm.numeric_cell_current n
                USING(workspace_id,application_id,coordinate_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                AND c.members->>%s=ANY(%s::text[]) AND
                    c.members->>%s=ANY(%s::text[]) {predicate}
                GROUP BY 1 ORDER BY 1''',(a,b,a,at,b,bt,
                scope.workspace_id,scope.application_id,a,list(am),b,list(bm),
                *params)).fetchall()
        elif plan.reduce_member_set:
            axis,members,target,_=plan.reduce_member_set
            rows=db.execute(f'''SELECT (c.members-%s::text)||
                jsonb_build_object(%s::text,%s::text) members
                FROM epm.coordinate c JOIN epm.numeric_cell_current n
                USING(workspace_id,application_id,coordinate_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                 AND c.members->>%s=ANY(%s::text[]) {predicate}
                GROUP BY 1 ORDER BY 1''',(axis,axis,target,
                scope.workspace_id,scope.application_id,axis,list(members),
                *params)).fetchall()
        elif plan.target_member_set:
            axis,members=plan.target_member_set
            rows=db.execute(f'''SELECT c.members||
                jsonb_build_object(%s::text,m.member_id) members
                FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
                 (workspace_id,application_id,coordinate_id)
                CROSS JOIN unnest(%s::text[]) m(member_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                 {predicate} ORDER BY c.series_key,m.member_id''',(
                axis,list(members),scope.workspace_id,scope.application_id,
                *params)).fetchall()
        else:
            overlay=Jsonb(dict(plan.target_members))
            rows=db.execute(f'''SELECT c.members || %s::jsonb members
                FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
                 (workspace_id,application_id,coordinate_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                 {predicate} ORDER BY c.series_key''',(overlay,
                scope.workspace_id,scope.application_id,*params)).fetchall()
    if len(rows)!=count:raise ValueError('CALCULATION_SOURCE_CHANGED')
    return tuple(Coordinate.from_mapping(row['members']) for row in rows)


def enforce_expression_dimensional_security(db,identity:VerifiedIdentity,
        scope:ApplicationScope,plan:ExpressionPlan,count:int,*,heartbeat=None)->None:
    if getattr(plan,'applicability_domain',None):
        observed=0
        for row_ids in _applicability_row_windows(
                db,scope,plan,heartbeat=heartbeat):
            sources=_applicability_source_coordinates_for_rows(
                db,scope,plan,row_ids)
            targets=_applicability_target_coordinates_for_rows(
                db,scope,plan,row_ids)
            authorize_coordinates(db,identity,scope,sources,kind=AccessKind.READ)
            authorize_coordinates(db,identity,scope,targets,kind=AccessKind.WRITE)
            observed+=len(targets)
        if observed!=count:
            raise ValueError('CALCULATION_SOURCE_CHANGED')
        return
    sources=expression_source_coordinates(db,scope,plan)
    targets=expression_target_coordinates(db,scope,plan,count)
    authorize_coordinates(db,identity,scope,sources,kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,targets,kind=AccessKind.WRITE)


def evaluate_dynamic_expression(db,scope:ApplicationScope,
        identity:VerifiedIdentity,plan:ExpressionPlan,*,authorization_db=None,
        definition_test=False,max_rows=500)->list[dict]:
    """Evaluate one bounded calculated member without persisting results."""
    if type(max_rows) is not int or not 1 <= max_rows <= 100_000:
        raise ValueError('CALCULATED_MEMBER_DYNAMIC_LIMIT_INVALID')
    if ((not plan.calculated_member and not definition_test) or plan.saved_rule or plan.driver_policy
            or plan.source_domain or plan.applicability_domain
            or plan.target_member_set
            or plan.target_member_sets or plan.reduce_member_set
            or plan.reduce_member_sets or plan.reduction_context
            or plan.two_axis_reduction_context or plan.amount_unit
            or plan.context_dependencies):
        raise ValueError('CALCULATED_MEMBER_DYNAMIC_PROFILE_UNSUPPORTED')
    if authorization_db is not None and currency_conversion(plan.expression) is not None:
        raise ValueError('CALCULATED_MEMBER_PRIVATE_CURRENCY_PROFILE_UNSUPPORTED')
    count=source_count(db,scope,plan,identity=identity)
    sources=expression_source_coordinates(db,scope,plan)
    targets=expression_target_coordinates(db,scope,plan,count)
    authority = db if authorization_db is None else authorization_db
    authorize_coordinates(authority,identity,scope,sources,kind=AccessKind.READ)
    authorize_coordinates(authority,identity,scope,targets,kind=AccessKind.READ)
    joins,join_params,aliases,_,_=_published_joins(plan)
    expression_sql,expression_params=_sql(plan.expression,aliases)
    lineage_sql,lineage_params=_source_lineage_sql(plan)
    predicate,filter_params=_plan_member_predicates(plan)
    target=Jsonb(dict(plan.target_members))
    scale=12 if plan.result_unit==('Ratio',12) else 8
    rows=db.execute(f'''SELECT c.members||%s::jsonb AS members,
            c.members AS source_members,n.amount AS source_amount,
            n.change_id AS source_change_id,
            epm.round_half_even({expression_sql},{scale}) AS value,
            {lineage_sql} AS source_lineage
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
          ON n.workspace_id=c.workspace_id
         AND n.application_id=c.application_id
         AND n.coordinate_id=c.coordinate_id
        {joins}
        WHERE c.workspace_id=%s AND c.application_id=%s
          AND n.present {predicate}
        ORDER BY members LIMIT %s''',(
        target,*expression_params,*lineage_params,*join_params,
        scope.workspace_id,scope.application_id,*filter_params,
        max_rows+1)).fetchall()
    if len(rows)!=count or len(rows)>max_rows:
        raise ValueError('CALCULATION_SOURCE_CHANGED')
    value_type='RatioLiteral' if scale==12 else 'AmountLiteral'
    return [{'members':row['members'],
        'value':{'type':value_type,'decimal':format(row['value'],f'.{scale}f')},
        'sourceMembers':row['source_members'],
        'sourceAmount':format(row['source_amount'],'.8f'),
        'sourceChangeId':row['source_change_id'],
        'sourceLineage':row['source_lineage']} for row in rows]


def enforce_expression_target_policy(db,scope:ApplicationScope,
                                     plan:ExpressionPlan,count:int,
                                     workflow_role:str,*,heartbeat=None)->dict|None:
    """Guard exact expression outputs through planning editability policy."""
    if plan.applicability_domain:
        from .postgres_planning_write_guard import enforce_active_planning_policy
        pages=[];observed=0
        for row_ids in _applicability_row_windows(
                db,scope,plan,heartbeat=heartbeat):
            targets=_applicability_target_coordinates_for_rows(
                db,scope,plan,row_ids)
            evidence=enforce_active_planning_policy(db,scope,
                writes=tuple((target,'Set') for target in targets),
                workflow_role=workflow_role)
            pages.append(evidence);observed+=len(targets)
        if observed!=count:
            raise ValueError('CALCULATION_SOURCE_CHANGED')
        if not pages:return None
        first=pages[0]
        stable=('configured','allowed','reasonCode','policyId','policyDigest',
                'policyStateToken')
        if any(any(item.get(key)!=first.get(key) for key in stable)
               for item in pages[1:]):
            raise ValueError('PLANNING_WRITE_POLICY_CHANGED')
        return {key:first.get(key) for key in stable}|{
            'writeCount':observed,
            'decisionDigest':_canonical_digest({
                'pageDecisionDigests':[item['decisionDigest'] for item in pages],
                'writeCount':observed}),
            'matchedRuleIds':sorted({rule for item in pages
                for rule in item.get('matchedRuleIds',())}),
            **({'levelResolutions':first['levelResolutions']}
               if 'levelResolutions' in first else {})}
    targets=expression_target_coordinates(db,scope,plan,count)
    if not targets:return None
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=tuple((target,'Set') for target in targets),
        workflow_role=workflow_role)


class PostgresExpressionPublisher:
    _DURABLE_WINDOW_SIZE=500

    def __init__(self, dsn: str, *, identity: VerifiedIdentity, worker=None):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity, self.worker = dsn, identity, worker

    def _after_durable_window(self,claim,row_ids):
        """Internal fault-injection seam; production execution is a no-op."""
        return None

    def _prepare_durable_applicability(self,claim,scope):
        if claim.get('resource_class')!='medium':
            return False
        plan=decode_expression_program(claim['normalized_program'])
        if not plan.applicability_domain:
            return False
        from .postgres_expression_staging import (
            ensure_stage,require_complete_stage)
        heartbeat=(lambda:self.worker.heartbeat(claim,lease_seconds=300)
                   if self.worker is not None else None)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                state=db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,processing_mode FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',(
                    scope.workspace_id,scope.application_id)).fetchone()
                job=db.execute('''SELECT status,claim_generation,claimant,
                    lease_until,program_digest,normalized_program,
                    expected_metadata_revision,expected_data_revision,
                    expected_policy_revision FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',(
                    scope.workspace_id,scope.application_id,
                    claim['job_id'])).fetchone()
                valid=(job is not None and db.execute(
                    '''SELECT %s::timestamptz>clock_timestamp() valid''',(
                    job['lease_until'],)).fetchone()['valid'])
                if (state is None or state['processing_mode']!='Active'
                        or job is None or job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant'] or not valid):
                    raise ValueError('STALE_WORKER_FENCE')
                if ((state['metadata_revision'],state['data_revision'],
                     state['policy_revision'])!=(
                     job['expected_metadata_revision'],
                     job['expected_data_revision'],
                     job['expected_policy_revision'])):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                count=source_count(db,scope,plan,identity=self.identity)
                materialize_targets(db,scope,plan,count,heartbeat=heartbeat)
                enforce_expression_dimensional_security(db,self.identity,
                    scope,plan,count,heartbeat=heartbeat)
                enforce_expression_target_policy(db,scope,plan,count,
                    access.role,heartbeat=heartbeat)
                window_size=self._DURABLE_WINDOW_SIZE
                if type(window_size) is not int or not 1<=window_size<=500:
                    raise ValueError('APPLICABILITY_WORK_WINDOW_INVALID')
                stage=ensure_stage(db,scope,operation_id=claim['job_id'],
                    program_digest=job['program_digest'],revisions=(
                        job['expected_metadata_revision'],
                        job['expected_data_revision'],
                        job['expected_policy_revision']),
                    expected_target_state_token=
                        plan.expected_target_state_token,
                    domain=plan.applicability_domain,
                    expected_row_count=count,window_size=window_size)
                windows=list(_applicability_row_windows(
                    db,scope,plan,heartbeat=heartbeat,
                    window_size=window_size))
        if stage['complete']:
            return True
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            for row_ids in windows:
                heartbeat();wrote=False
                try:
                    with db.transaction():
                        configure_statement_timeout(db,5000)
                        PostgresNumericFactStore._set_scope(db,scope)
                        state=db.execute('''SELECT metadata_revision,data_revision,
                            policy_revision,processing_mode FROM epm.application_state
                            WHERE workspace_id=%s AND application_id=%s''',(
                            scope.workspace_id,scope.application_id)).fetchone()
                        job=db.execute('''SELECT status,claim_generation,claimant,
                            lease_until FROM epm.job WHERE workspace_id=%s
                            AND application_id=%s AND job_id=%s''',(
                            scope.workspace_id,scope.application_id,
                            claim['job_id'])).fetchone()
                        valid=(job is not None and db.execute(
                            '''SELECT %s::timestamptz>clock_timestamp() valid''',(
                            job['lease_until'],)).fetchone()['valid'])
                        if (state is None or state['processing_mode']!='Active'
                                or job is None or job['status']!='running'
                                or job['claim_generation']!=claim['claim_generation']
                                or job['claimant']!=claim['claimant'] or not valid):
                            raise ValueError('STALE_WORKER_FENCE')
                        if ((state['metadata_revision'],state['data_revision'],
                             state['policy_revision'])!=(
                             claim['expected_metadata_revision'],
                             claim['expected_data_revision'],
                             claim['expected_policy_revision'])):
                            raise ValueError('STALE_JOB_INPUT_REVISION')
                        existing=db.execute('''SELECT relation_row_id FROM
                            epm.expression_result_staging_row
                            WHERE workspace_id=%s AND application_id=%s
                              AND operation_id=%s
                              AND relation_row_id=ANY(%s::text[])''',(
                            scope.workspace_id,scope.application_id,
                            claim['job_id'],list(row_ids))).fetchall()
                        present={row['relation_row_id'] for row in existing}
                        missing=tuple(row_id for row_id in row_ids
                                      if row_id not in present)
                        if missing:
                            sql,parameters=_applicability_result_stage_statement(
                                db,scope,plan,claim['job_id'],missing,durable=True)
                            if db.execute(sql,parameters).rowcount!=len(missing):
                                raise ValueError('CALCULATION_SOURCE_CHANGED')
                            wrote=True
                except Exception:
                    # The connection remains reusable only after psycopg has
                    # unwound the failed transaction context.
                    raise
                if wrote:
                    self._after_durable_window(claim,row_ids)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            PostgresNumericFactStore._set_scope(db,scope)
            require_complete_stage(db,scope,operation_id=claim['job_id'],
                                   expected_row_count=count)
        return True

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim, dict)
                or not isinstance(claim.get('workspace_id'), str)
                or not isinstance(claim.get('application_id'), str)
                or not isinstance(claim.get('job_id'), str)
                or not _JOB_ID.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'), str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        durable_applicability=self._prepare_durable_applicability(claim,scope)
        heartbeat=(lambda:self.worker.heartbeat(claim,lease_seconds=300)
                   if self.worker is not None else None)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.schema_epoch,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    ''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                job = db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision,idempotency_key,
                    python_workflow_id,execution_delegation_id,execution_delegation_state_token,
                    execution_schedule_id,execution_schedule_state_token
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                valid_lease = db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS valid''',
                    (job['lease_until'],)).fetchone()['valid']
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']
                        or not valid_lease):
                    raise ValueError('STALE_WORKER_FENCE')
                from .postgres_jobs import _require_python_job_authority
                _require_python_job_authority(db, scope, job)
                if (job['function_name'] != FUNCTION
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
                plan = decode_expression_program(job['normalized_program'])
                if (plan.driver_policy and (
                        plan.driver_policy['metadataRevision'] !=
                            job['expected_metadata_revision']
                        or plan.driver_policy['policyRevision'] !=
                            job['expected_policy_revision'])):
                    raise ValueError('STALE_DRIVER_POLICY_PIN')
                if not supported_compiler_for(
                        plan, job['compiler_version'], job['plan_digest']):
                    raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] != job['expected_metadata_revision']
                        or state['data_revision'] != job['expected_data_revision']
                        or state['policy_revision'] != job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                if plan.context_dependencies:
                    from .expression_context_dependencies import require_current
                    require_current(db,scope,plan.context_dependencies)
                if plan.saved_rule:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'rule_run')
                    from .postgres_expression_rules import verify_published_rule
                    verify_published_rule(
                        db, scope, plan.saved_rule, plan.normalized_program)
                if plan.calculated_member:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'rule_run')
                    from .postgres_calculated_members import (
                        verify_materialization_pin)
                    verify_materialization_pin(
                        db, scope, plan.calculated_member, plan)
                    from .postgres_calculated_members import (
                        prepare_materialization_dependency_state)
                    dependency_artifact = (
                        prepare_materialization_dependency_state(
                            db, scope, plan.calculated_member, plan,
                            job_id=claim['job_id'], state=state))
                elif plan.applicability_domain:
                    from .postgres_expression_dependencies import (
                        prepare_applicability_dependency_state)
                    dependency_artifact = prepare_applicability_dependency_state(
                        db, scope, plan, job_id=claim['job_id'], state=state)
                else:
                    dependency_artifact = None
                if plan.reduction_context is not None:
                    from .expression_hierarchy_member_set import (
                        validate_publication)
                    validate_publication(db, scope, plan)
                if plan.two_axis_reduction_context is not None:
                    from .expression_hierarchy_two_axis import validate_publication
                    validate_publication(db,scope,plan)
                pointer = db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['state_token'] if pointer else None) != (
                        plan.expected_target_state_token):
                    raise ValueError('STALE_RESULT_STATE')
                count = source_count(db, scope, plan,identity=self.identity)
                enforce_expression_dimensional_security(
                    db, self.identity, scope, plan, count,
                    heartbeat=heartbeat if plan.applicability_domain else None)
                if plan.reduction_context is not None:
                    from .expression_hierarchy_member_set import cardinality
                    counts = cardinality(db, scope, plan)
                    if counts['groupedOutputCount'] != count:
                        raise ValueError(
                            'EXPRESSION_HIERARCHY_REDUCTION_CARDINALITY_MISMATCH')
                if plan.two_axis_reduction_context is not None:
                    from .expression_hierarchy_two_axis import cardinality
                    counts=cardinality(db,scope,plan)
                    if counts['groupedOutputCount']!=count:
                        raise ValueError(
                            'EXPRESSION_HIERARCHY_TWO_AXIS_CARDINALITY_MISMATCH')
                if (plan.driver_policy
                        and plan.driver_policy.get('policyFormat')==
                            'openepm-planning-operation-policy-v2'
                        and not 1<=count<=plan.driver_policy['maxCells']):
                    raise ValueError('DRIVER_POLICY_CELL_LIMIT')
                currency_result=(validate_currency_conversion(
                    db,scope,self.identity,plan)
                    if currency_conversion(plan.expression) is not None
                    else None)
                aligned_result = validate_aligned_unit_inputs(
                    db, scope, plan, count)
                materialize_targets(db, scope, plan, count,
                    heartbeat=heartbeat if plan.applicability_domain else None)
                policy_evidence=enforce_expression_target_policy(
                    db,scope,plan,count,access.role,
                    heartbeat=heartbeat if plan.applicability_domain else None)
                # Result SQL can be the dominant part of a calculation.  Keep
                # it private and transaction-local while the application row
                # remains free; the generation and public pointer are created
                # only after the final dependency/authority fence below.
                db.execute('''CREATE TEMP TABLE calculation_result_stage
                    (LIKE epm.calculation_result_staging INCLUDING DEFAULTS)
                    ON COMMIT DROP''')
                db.execute('''CREATE TEMP TABLE calculation_unit_result_stage
                    (LIKE epm.calculation_unit_result_staging INCLUDING DEFAULTS)
                    ON COMMIT DROP''')
                db.execute('''CREATE TEMP TABLE calculation_ratio_result_stage
                    (LIKE epm.calculation_ratio_result_staging INCLUDING DEFAULTS)
                    ON COMMIT DROP''')
                joins, join_params, aliases, _, _ = _published_joins(plan)
                applicability = None
                if plan.applicability_domain:
                    _, applicability = _resolved_applicability_sql(
                        db,scope,plan)
                    joins = '\n'.join((joins,applicability.joins))
                    join_params.extend(applicability.join_parameters)
                    aliases.update(applicability.aliases)
                    aliases.update({key:(applicability.aliases[key],params)
                        for key,params in applicability.value_parameters.items()})
                aligned_join='';aligned_params=()
                if aligned_result is not None:
                    aligned_join='''JOIN jsonb_to_recordset(%s::jsonb) aligned(
                      source_coordinate_id bigint,rate_sources jsonb,
                      dependency_lineage jsonb,source_change_id text)
                      ON aligned.source_coordinate_id=c.coordinate_id'''
                    aligned_params=(Jsonb(aligned_result[
                        'dependenciesBySource']),)
                expression_sql, expression_params = _sql(plan.expression,
                                                          aliases)
                if currency_result is not None:
                    conversion=plan.expression
                    dimensions=db.execute('''SELECT dimension_id FROM epm.dimension
                        WHERE workspace_id=%s AND application_id=%s
                        AND model_role='Currency' AND status='Active'
                        ORDER BY dimension_id''',(scope.workspace_id,
                        scope.application_id)).fetchall()
                    if len(dimensions)!=1:
                        raise ValueError('EXPRESSION_CURRENCY_ROLE_AMBIGUOUS')
                    factor=conversion['expectedRate']['exactFactor']
                    inserted=db.execute('''INSERT INTO pg_temp.calculation_unit_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         output_unit_currency_dimension_id,
                         output_unit_currency_member_id,source_amount,
                         source_change_id,amount,rate_strategy,rate_numerator,
                         rate_denominator,rate_sources)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(
                        scope.workspace_id,scope.application_id,claim['job_id'],
                        currency_result['lineage']['source']['coordinateId'],
                        dimensions[0]['dimension_id'],
                        conversion['outputUnitCurrencyMemberId'],
                        currency_result['sourceAmount'],
                        currency_result['lineage']['source']['changeId'],
                        currency_result['translatedAmount'],
                        conversion['expectedRate']['strategy'],
                        factor['numerator'],factor['denominator'],
                        Jsonb(currency_result['lineage']['rate']['sources']))).rowcount
                elif plan.source_domain:
                    expression_sql,expression_params=_sql(plan.expression,
                        aliases,'COALESCE(n.amount,d.default_amount)')
                lineage_sql,lineage_params=_source_lineage_sql(plan)
                if applicability is not None:
                    lineage_sql=(f'''({lineage_sql})||jsonb_build_array(
                        {applicability.lineage_sql})''')
                    lineage_params=(*lineage_params,
                        *applicability.lineage_parameters)
                predicate, filter_params = _plan_member_predicates(plan)
                target_join = ''
                target_coordinate = 'c.coordinate_id'
                target_params: tuple[object, ...] = ()
                if applicability is not None:
                    target_join=f'''JOIN epm.coordinate t
                        ON t.workspace_id=c.workspace_id
                       AND t.application_id=c.application_id
                       AND t.series_key=epm.coordinate_series_key(
                           {applicability.target_members_sql})
                       AND t.members={applicability.target_members_sql}'''
                    target_coordinate='t.coordinate_id'
                    target_params=(*applicability.target_parameters,
                                   *applicability.target_parameters)
                    predicate+=(f' AND ({applicability.required_predicate})')
                elif plan.target_member_sets:
                    combinations=_target_member_combinations(plan)
                    target_join='''CROSS JOIN jsonb_to_recordset(%s::jsonb)
                          target_set(members jsonb)
                        JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
                         AND t.application_id=c.application_id
                         AND t.members=c.members||target_set.members'''
                    target_coordinate='t.coordinate_id'
                    target_params=(Jsonb([{'members':item}
                        for item in combinations]),)
                elif plan.target_member_set:
                    axis,members=plan.target_member_set
                    target_join='''CROSS JOIN unnest(%s::text[]) target_member(member_id)
                        JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
                         AND t.application_id=c.application_id
                         AND t.members=c.members||jsonb_build_object(%s::text,target_member.member_id)'''
                    target_coordinate='t.coordinate_id'
                    target_params=(list(members),axis)
                elif plan.target_members:
                    target = Jsonb(dict(plan.target_members))
                    target_join = '''JOIN epm.coordinate t
                        ON t.workspace_id=c.workspace_id
                       AND t.application_id=c.application_id
                       AND t.series_key=epm.coordinate_series_key(
                           c.members || %s::jsonb)
                       AND t.members=c.members || %s::jsonb'''
                    target_coordinate = 't.coordinate_id'
                    target_params = (target, target)
                # A currency conversion has already produced its single typed
                # result above.  Do not also lower the same expression through
                # the ordinary amount/untyped branches: that would create two
                # physical result rows for one logical output coordinate.
                if currency_result is not None:
                    pass
                elif plan.amount_unit and plan.reduce_member_set is None:
                    unit_dimension,unit_member,_=plan.amount_unit
                    raw_driver_sql='''jsonb_build_object(
                        'inputKind','RawDriver','sourcePresent',true,
                        'sourceCoordinateId',c.coordinate_id,
                        'sourceMembers',c.members,
                        'sourceSeriesKey',c.series_key,
                        'sourceAmount',n.amount::text,
                        'sourceChangeId',n.change_id)'''
                    if aligned_result is not None:
                        rate_strategy='aligned-published-inputs'
                        result_rate_sources=[{
                            'kind':'alignedPublishedInputs',
                            'sourceCoordinateId':item['source_coordinate_id'],
                            'dependencies':item['dependencies']}
                            for item in aligned_result['dependenciesBySource']]
                        rate_sources_sql='aligned.rate_sources'
                        dependency_lineage_sql='aligned.dependency_lineage'
                        rate_sources_params=()
                        dependency_lineage_params=()
                    else:
                        rate_strategy='identity-same-currency'
                        rate_sources=[{'kind':'Identity','currency':{
                            'dimensionId':unit_dimension,
                            'memberId':unit_member}}]
                        rate_sources_sql='%s'
                        dependency_lineage_sql='%s::jsonb'
                        rate_sources_params=(Jsonb(rate_sources),)
                        dependency_lineage_params=(Jsonb([]),)
                    inserted = db.execute(f'''INSERT INTO
                        pg_temp.calculation_unit_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         output_unit_currency_dimension_id,
                         output_unit_currency_member_id,source_amount,
                         source_change_id,amount,rate_strategy,rate_numerator,
                         rate_denominator,rate_sources,source_lookup_lineage)
                        SELECT c.workspace_id,c.application_id,%s,
                          {target_coordinate},%s,%s,n.amount,n.change_id,
                          epm.round_half_even({expression_sql},8),%s,1,1,
                          {rate_sources_sql},
                          jsonb_build_array({raw_driver_sql})||
                            {lineage_sql}||{dependency_lineage_sql}
                        FROM epm.coordinate c JOIN epm.numeric_cell_current n
                          ON n.workspace_id=c.workspace_id
                         AND n.application_id=c.application_id
                         AND n.coordinate_id=c.coordinate_id
                        {joins}
                        {aligned_join}
                        {target_join}
                        WHERE c.workspace_id=%s AND c.application_id=%s
                          AND n.present {predicate}''',(
                        claim['job_id'],unit_dimension,unit_member,
                        *expression_params,rate_strategy,*rate_sources_params,
                        *lineage_params,*dependency_lineage_params,
                        *join_params,*aligned_params,*target_params,
                        scope.workspace_id,scope.application_id,
                        *filter_params)).rowcount
                elif aligned_result is not None:
                    inserted = db.execute(f'''INSERT INTO
                        pg_temp.calculation_unit_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         output_unit_currency_dimension_id,
                         output_unit_currency_member_id,source_amount,
                         source_change_id,amount,rate_strategy,rate_numerator,
                         rate_denominator,rate_sources)
                        SELECT c.workspace_id,c.application_id,%s,
                          {target_coordinate},
                          %s,%s,epm.round_half_even({expression_sql},8),
                          aligned.source_change_id,
                          epm.round_half_even({expression_sql},8),
                          'aligned-published-inputs',1,1,aligned.rate_sources
                        FROM epm.coordinate c JOIN epm.numeric_cell_current n
                          ON n.workspace_id=c.workspace_id
                         AND n.application_id=c.application_id
                         AND n.coordinate_id=c.coordinate_id
                        {joins}
                        {aligned_join}
                        {target_join}
                        WHERE c.workspace_id=%s AND c.application_id=%s
                          AND n.present {predicate}''',(
                        claim['job_id'], aligned_result['dimensionId'],
                        aligned_result['memberId'], *expression_params,
                        *expression_params,
                        *join_params,*aligned_params,*target_params,
                        scope.workspace_id, scope.application_id,
                        *filter_params)).rowcount
                elif plan.result_unit == ('Ratio', 12):
                    inserted=db.execute(f'''INSERT INTO
                        pg_temp.calculation_ratio_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         source_amount,source_change_id,source_present,ratio,
                         source_lookup_lineage)
                        SELECT c.workspace_id,c.application_id,%s,
                          {target_coordinate},n.amount,n.change_id,true,
                          epm.round_half_even({expression_sql},12),
                          {lineage_sql}
                        FROM epm.coordinate c JOIN epm.numeric_cell_current n
                          ON n.workspace_id=c.workspace_id
                         AND n.application_id=c.application_id
                         AND n.coordinate_id=c.coordinate_id
                        {joins}
                        {target_join}
                        WHERE c.workspace_id=%s AND c.application_id=%s
                         AND n.present {predicate}''',(
                        claim['job_id'],*expression_params,*lineage_params,
                        *join_params,*target_params,scope.workspace_id,
                        scope.application_id,*filter_params)).rowcount
                elif plan.source_domain:
                    coordinates=_domain_coordinates(plan)
                    inserted=db.execute(f'''INSERT INTO pg_temp.calculation_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         source_amount,source_change_id,amount,source_lookup_lineage,
                         source_present)
                        SELECT c.workspace_id,c.application_id,%s,c.coordinate_id,
                         CASE WHEN n.present THEN n.amount END,
                         CASE WHEN n.present THEN n.change_id END,
                         epm.round_half_even({expression_sql},8),
                         jsonb_build_array(CASE WHEN n.present THEN
                          jsonb_build_object('sourceKind','Actual','sourceMembers',c.members,
                           'sourceSeriesKey',c.series_key,'sourceAmount',n.amount::text,
                           'sourceChangeId',n.change_id)
                          ELSE jsonb_build_object('sourceKind','DefaultedAbsent',
                           'sourceMembers',c.members,'sourceSeriesKey',c.series_key,
                           'defaultAmount',d.default_amount::text) END),
                         COALESCE(n.present,false)
                        FROM jsonb_to_recordset(%s::jsonb)i(members jsonb)
                        JOIN epm.coordinate c ON c.workspace_id=%s
                         AND c.application_id=%s AND c.members=i.members
                        LEFT JOIN epm.numeric_cell_current n USING
                         (workspace_id,application_id,coordinate_id)
                        CROSS JOIN (SELECT %s::numeric default_amount)d''',(
                        claim['job_id'],*expression_params,
                        Jsonb([{'members':item} for item in coordinates]),
                        scope.workspace_id,scope.application_id,
                        Decimal(plan.missing_default))).rowcount
                elif (plan.reduce_member_sets and
                      len(plan.reduce_member_sets[0])>2):
                    reduction=_multi_reduction_sql(plan)
                    inserted=db.execute(_multi_reduction_publish_sql(
                        plan,expression_sql,joins,predicate,
                        target='pg_temp.calculation_result_stage'),(
                        claim['job_id'],*expression_params,*join_params,
                        *reduction.target_params,scope.workspace_id,
                        scope.application_id,*reduction.filter_params,
                        *filter_params)).rowcount
                elif plan.reduce_member_sets:
                    (a,am,at),(b,bm,bt)=plan.reduce_member_sets[0]
                    measures=plan.reduce_member_sets[1]
                    average=measures==('AverageAmount','CountPresent')
                    source_aggregate=('epm.round_half_even(sum(n.amount)/count(*),8)'
                        if average else 'sum(n.amount)')
                    expression_aggregate=(f'sum({expression_sql})/count(*)'
                        if average else f'sum({expression_sql})')
                    inserted=db.execute(f'''INSERT INTO pg_temp.calculation_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         source_amount,source_change_id,amount,source_lookup_lineage)
                        SELECT c.workspace_id,c.application_id,%s,t.coordinate_id,
                         {source_aggregate},string_agg(n.change_id,',' ORDER BY c.series_key),
                         epm.round_half_even({expression_aggregate},8),
                         jsonb_agg(jsonb_build_object('sourceMembers',c.members,
                          'sourceSeriesKey',c.series_key,'sourceAmount',n.amount::text,
                          'sourceChangeId',n.change_id) ORDER BY c.series_key)
                        FROM epm.coordinate c JOIN epm.numeric_cell_current n
                         USING(workspace_id,application_id,coordinate_id) {joins}
                        JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
                         AND t.application_id=c.application_id AND t.members=
                          ((c.members-%s::text)-%s::text)||jsonb_build_object(
                            %s::text,%s::text,%s::text,%s::text)
                        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                         AND c.members->>%s=ANY(%s::text[])
                         AND c.members->>%s=ANY(%s::text[]) {predicate}
                        GROUP BY c.workspace_id,c.application_id,t.coordinate_id''',(
                        claim['job_id'],*expression_params,*join_params,a,b,a,at,b,bt,
                        scope.workspace_id,scope.application_id,a,list(am),b,list(bm),
                        *filter_params)).rowcount
                elif plan.reduce_member_set:
                    axis,members,target,measures=plan.reduce_member_set
                    average = measures == ('AverageAmount','CountPresent')
                    weighted=plan.weight_expression is not None
                    if weighted:
                        weight_sql,weight_params=_sql(
                            plan.weight_expression,aliases)
                        source_aggregate=(f'''epm.round_half_even(
                            sum(n.amount*({weight_sql}))/
                            NULLIF(sum({weight_sql}),0),8)''')
                        expression_aggregate=source_aggregate
                        reduction_lineage=f'''jsonb_agg(jsonb_build_object(
                            'sourceMembers',c.members,
                            'sourceSeriesKey',c.series_key,
                            'sourceAmount',n.amount::text,
                            'sourceChangeId',n.change_id,
                            'weightMembers',rawq0.members,
                            'weightAmount',rawv0.amount::text,
                            'weightChangeId',rawv0.change_id,
                            'weightedNumerator',(n.amount*rawv0.amount)::text)
                            ORDER BY c.series_key)'''
                    else:
                        weight_params=[]
                        source_aggregate = ('epm.round_half_even(sum(n.amount)/count(*),8)'
                                            if average else 'sum(n.amount)')
                        expression_aggregate = (f'sum({expression_sql})/count(*)'
                                                if average
                                                else f'sum({expression_sql})')
                        reduction_lineage='''jsonb_agg(jsonb_build_object(
                            'sourceMembers',c.members,
                            'sourceSeriesKey',c.series_key,
                            'sourceAmount',n.amount::text,
                            'sourceChangeId',n.change_id) ORDER BY c.series_key)'''
                    if plan.amount_unit and not weighted:
                        unit_dimension,unit_member,_=plan.amount_unit
                        rate_strategy='identity-same-currency'
                        rate_sources=[{'kind':'Identity','currency':{
                            'dimensionId':unit_dimension,
                            'memberId':unit_member}}]
                        inserted=db.execute(f'''INSERT INTO
                            pg_temp.calculation_unit_result_stage
                            (workspace_id,application_id,generation_id,
                             coordinate_id,
                             output_unit_currency_dimension_id,
                             output_unit_currency_member_id,source_amount,
                             source_change_id,amount,rate_strategy,
                             rate_numerator,rate_denominator,rate_sources,
                             source_lookup_lineage)
                            SELECT c.workspace_id,c.application_id,%s,
                             t.coordinate_id,%s,%s,{source_aggregate},
                             string_agg(n.change_id,',' ORDER BY c.series_key),
                             epm.round_half_even({expression_aggregate},8),
                             %s,1,1,%s,
                             {reduction_lineage}
                            FROM epm.coordinate c
                            JOIN epm.numeric_cell_current n USING
                             (workspace_id,application_id,coordinate_id)
                            {joins}
                            JOIN epm.coordinate t
                             ON t.workspace_id=c.workspace_id
                             AND t.application_id=c.application_id
                             AND t.members=(c.members-%s::text)||
                              jsonb_build_object(%s::text,%s::text)
                            WHERE c.workspace_id=%s
                             AND c.application_id=%s AND n.present
                             AND c.members->>%s=ANY(%s::text[]) {predicate}
                            GROUP BY c.workspace_id,c.application_id,
                             t.coordinate_id''',(
                            claim['job_id'],unit_dimension,unit_member,
                            *expression_params,rate_strategy,
                            Jsonb(rate_sources),
                            *join_params,axis,axis,target,
                            scope.workspace_id,scope.application_id,axis,
                            list(members),*filter_params)).rowcount
                    else:
                        inserted=db.execute(f'''INSERT INTO pg_temp.calculation_result_stage
                            (workspace_id,application_id,generation_id,coordinate_id,
                             source_amount,source_change_id,amount,source_lookup_lineage)
                            SELECT c.workspace_id,c.application_id,%s,t.coordinate_id,
                             {source_aggregate},string_agg(n.change_id,',' ORDER BY c.series_key),
                             epm.round_half_even({expression_aggregate},8),
                             {reduction_lineage}
                            FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
                             (workspace_id,application_id,coordinate_id)
                            {joins}
                            JOIN epm.coordinate t ON t.workspace_id=c.workspace_id
                             AND t.application_id=c.application_id AND t.members=
                              (c.members-%s::text)||jsonb_build_object(%s::text,%s::text)
                            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
                             AND c.members->>%s=ANY(%s::text[]) {predicate}
                            GROUP BY c.workspace_id,c.application_id,t.coordinate_id''',(
                            claim['job_id'],
                            *expression_params,*weight_params,*join_params,
                            axis,axis,target,scope.workspace_id,
                            scope.application_id,axis,list(members),*filter_params
                            )).rowcount
                else:
                    if durable_applicability:
                        from .postgres_expression_staging import (
                            require_complete_stage)
                        require_complete_stage(db,scope,
                            operation_id=claim['job_id'],
                            expected_row_count=count)
                        inserted=db.execute('''INSERT INTO
                            pg_temp.calculation_result_stage(
                              workspace_id,application_id,generation_id,
                              coordinate_id,source_amount,source_change_id,
                              amount,source_lookup_lineage)
                            SELECT workspace_id,application_id,operation_id,
                              coordinate_id,source_amount,source_change_id,
                              amount,source_lookup_lineage
                            FROM epm.expression_result_staging_row
                            WHERE workspace_id=%s AND application_id=%s
                              AND operation_id=%s
                            ORDER BY relation_row_id''',(
                            scope.workspace_id,scope.application_id,
                            claim['job_id'])).rowcount
                    elif applicability is not None:
                        inserted=0
                        for row_ids in _applicability_row_windows(
                                db,scope,plan,heartbeat=heartbeat):
                            stage_sql,stage_params=(
                                _applicability_result_stage_statement(
                                    db,scope,plan,claim['job_id'],row_ids,
                                    durable=False))
                            inserted+=db.execute(
                                stage_sql,stage_params).rowcount
                    else:
                        stage_sql=f'''INSERT INTO pg_temp.calculation_result_stage
                        (workspace_id,application_id,generation_id,coordinate_id,
                         source_amount,source_change_id,amount,
                         source_lookup_lineage)
                        SELECT c.workspace_id,c.application_id,%s,
                            {target_coordinate},n.amount,n.change_id,
                            epm.round_half_even({expression_sql},8),
                            {lineage_sql}
                        FROM epm.coordinate c JOIN epm.numeric_cell_current n
                          ON n.workspace_id=c.workspace_id
                         AND n.application_id=c.application_id
                         AND n.coordinate_id=c.coordinate_id
                        {joins}
                        {target_join}
                        WHERE c.workspace_id=%s AND c.application_id=%s
                        AND n.present {predicate}'''
                        stage_params=(claim['job_id'],*expression_params,
                            *lineage_params,*join_params,*target_params,
                            scope.workspace_id,scope.application_id,
                            *filter_params)
                        inserted=db.execute(stage_sql,stage_params).rowcount
                if inserted != count:
                    raise ValueError('CALCULATION_SOURCE_CHANGED')

                if plan.applicability_domain and self.worker is not None:
                    # Bound the final atomic fence with a fresh maximum lease.
                    # No heartbeat is attempted after the job row is locked.
                    heartbeat()

                # The private result tables are complete.  Fence publication
                # only now, then repeat every mutable input and authority
                # check.  Unrelated calculation publications may have moved
                # commit_revision; raw data, metadata and policy revisions,
                # pinned published inputs, context dependencies and this
                # result pointer must still match exactly.
                final_state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if final_state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                final_job = db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision,idempotency_key,
                    python_workflow_id,execution_delegation_id,execution_delegation_state_token,
                    execution_schedule_id,execution_schedule_state_token
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'])).fetchone()
                valid_lease = (final_job is not None and db.execute(
                    '''SELECT %s::timestamptz > clock_timestamp() AS valid''',
                    (final_job['lease_until'],)).fetchone()['valid'])
                immutable_job_fields = (
                    'issuer', 'subject_id', 'function_name',
                    'normalized_program', 'program_digest', 'plan_digest',
                    'compiler_version', 'expected_metadata_revision',
                    'expected_data_revision', 'expected_policy_revision', 'idempotency_key',
                    'python_workflow_id', 'execution_delegation_id',
                    'execution_delegation_state_token', 'execution_schedule_id',
                    'execution_schedule_state_token')
                if (final_job is None
                        or any(final_job[key] != job[key]
                               for key in immutable_job_fields)
                        or final_job['status'] != 'running'
                        or final_job['claim_generation'] !=
                           claim['claim_generation']
                        or final_job['claimant'] != claim['claimant']
                        or not valid_lease):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db, scope, final_job)
                final_access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                if (final_state['application_status'] != 'Active'
                        or final_state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (final_state['metadata_revision'] !=
                        job['expected_metadata_revision']
                        or final_state['data_revision'] !=
                        job['expected_data_revision']
                        or final_state['policy_revision'] !=
                        job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                if plan.context_dependencies:
                    from .expression_context_dependencies import require_current
                    require_current(db, scope, plan.context_dependencies)
                if plan.saved_rule:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'rule_run')
                    from .postgres_expression_rules import verify_published_rule
                    verify_published_rule(
                        db, scope, plan.saved_rule, plan.normalized_program)
                if plan.calculated_member:
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'rule_run')
                    from .postgres_calculated_members import (
                        verify_materialization_pin)
                    verify_materialization_pin(
                        db, scope, plan.calculated_member, plan)
                if plan.reduction_context is not None:
                    from .expression_hierarchy_member_set import (
                        validate_publication)
                    validate_publication(db, scope, plan)
                if plan.two_axis_reduction_context is not None:
                    from .expression_hierarchy_two_axis import validate_publication
                    validate_publication(db, scope, plan)
                pointer = db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['state_token'] if pointer else None) != (
                        plan.expected_target_state_token):
                    raise ValueError('STALE_RESULT_STATE')
                final_count = source_count(
                    db, scope, plan, identity=self.identity)
                if final_count != count:
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                enforce_expression_dimensional_security(
                    db, self.identity, scope, plan, final_count)
                final_currency = (validate_currency_conversion(
                    db, scope, self.identity, plan)
                    if currency_conversion(plan.expression) is not None
                    else None)
                if final_currency != currency_result:
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                final_aligned = validate_aligned_unit_inputs(
                    db, scope, plan, count)
                if final_aligned != aligned_result:
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                materialize_targets(db, scope, plan, count)
                policy_evidence = enforce_expression_target_policy(
                    db, scope, plan, count, final_access.role)
                revision = final_state['commit_revision'] + 1
                db.execute('''INSERT INTO epm.calculation_operation_staging
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision,
                     generation_kind)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], claim['job_id'], plan.result_key,
                     state['commit_revision'], state['metadata_revision'],
                     state['policy_revision'], FUNCTION, count, revision,
                     ('partition_manifest' if dependency_artifact is not None
                      else 'flat')))
                durable_rows = 0
                for durable_table,temp_table in (
                        ('calculation_result_staging','calculation_result_stage'),
                        ('calculation_unit_result_staging',
                         'calculation_unit_result_stage'),
                        ('calculation_ratio_result_staging',
                         'calculation_ratio_result_stage')):
                    durable_rows += db.execute(
                        f'''INSERT INTO epm.{durable_table}
                        SELECT * FROM pg_temp.{temp_table}''').rowcount
                if durable_rows != inserted:
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                if durable_applicability:
                    from .postgres_expression_staging import delete_stage
                    if delete_stage(db,scope,
                            operation_id=claim['job_id'])!=1:
                        raise ValueError('EXPRESSION_STAGE_INCOMPLETE')
                partition_manifest = None
                if dependency_artifact is not None:
                    from .postgres_calculated_members import (
                        stage_dependency_partition_manifest)
                    partition_manifest = stage_dependency_partition_manifest(
                        db, scope, dependency_artifact,
                        generation_id=claim['job_id'], row_count=inserted)
                from .postgres_current_result_publication import advance_result_head_during_conversion
                current_result = advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                dependency_result = None
                if dependency_artifact is not None:
                    from .postgres_calculated_members import (
                        publish_materialization_dependency_state)
                    dependency_result = publish_materialization_dependency_state(
                        db, scope, dependency_artifact,
                        result_state_token=current_result['state_token'],
                        partition_manifest=partition_manifest)
                result = {'resultKey': plan.result_key,
                          'resultStateToken':current_result['state_token'],
                          'resultContentDigest':current_result['content_digest'],
                          'rowCount': inserted,
                          'sourceCommitRevision': state['commit_revision'],
                          'engine': 'postgres_exact_sql'}
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=plan.result_key,existed=pointer is not None)
                result['impactDigest']=impact.digest
                if dependency_result is not None:
                    result['dependencyState'] = dependency_result
                if currency_result is not None:
                    result['outputUnit']=currency_result['lineage']['targetUnit']
                    result['rateLineage']=currency_result['lineage']['rate']
                    result['consolidationTranslation']=False
                elif plan.amount_unit:
                    result['outputUnit'] = {
                      'dimensionId': plan.amount_unit[0],
                      'memberId': plan.amount_unit[1]}
                    result['rateLineage'] = {
                      'strategy': rate_strategy,
                      'sources': result_rate_sources if aligned_result is not None
                          else rate_sources}
                    result['consolidationTranslation'] = False
                elif aligned_result is not None:
                    result['outputUnit'] = {
                      'dimensionId': aligned_result['dimensionId'],
                      'memberId': aligned_result['memberId']}
                    result['rateLineage'] = {
                      'strategy': 'aligned-published-inputs',
                      'sources': aligned_result['dependencies']}
                    result['consolidationTranslation'] = False
                elif plan.result_unit == ('Ratio', 12):
                    result['resultUnit']={'type':'Ratio','scale':12}
                if plan.published_inputs:
                    result['publishedInputs'] = list(plan.published_inputs)
                if source_lookups(plan.expression):
                    result['sourceLookups'] = [dict(item)
                        for item in source_lookups(plan.expression)]
                if source_text_lookups(plan.expression):
                    result['sourceTextLookups']=[dict(item)
                        for item in source_text_lookups(plan.expression)]
                if plan.target_members:
                    result['targetMembers'] = dict(plan.target_members)
                if plan.target_member_set:
                    result['targetMemberSet']={'dimensionId':plan.target_member_set[0],
                        'memberIds':list(plan.target_member_set[1])}
                if plan.target_member_sets:
                    result['targetMemberSets']=[{'dimensionId':axis,
                        'memberIds':list(member_ids)}
                        for axis,member_ids in plan.target_member_sets]
                if plan.source_domain:
                    result['sourceDomain']=[{'dimensionId':axis,
                        'memberIds':list(member_ids)}
                        for axis,member_ids in plan.source_domain]
                    result['missingDefault']={'type':'AmountLiteral',
                        'decimal':plan.missing_default}
                if plan.reduce_member_set:
                    result['reduceMemberSet']={'dimensionId':plan.reduce_member_set[0],
                        'sourceMemberIds':list(plan.reduce_member_set[1]),
                        'targetMemberId':plan.reduce_member_set[2],
                        'measures':list(plan.reduce_member_set[3])}
                if plan.reduction_context:
                    result['hierarchyReductionContext'] = (
                        plan.reduction_context)
                if plan.reduce_member_sets:
                    result['reduceMemberSets']={
                        'selections':[{'dimensionId':axis,
                            'sourceMemberIds':list(members),
                            'targetMemberId':target}
                            for axis,members,target in plan.reduce_member_sets[0]],
                        'measures':list(plan.reduce_member_sets[1])}
                if plan.two_axis_reduction_context:
                    result['hierarchyTwoAxisReductionContext']=(
                        plan.two_axis_reduction_context)
                if plan.saved_rule:
                    result['savedRule'] = plan.saved_rule
                if plan.calculated_member:
                    result['calculatedMember'] = plan.calculated_member
                if plan.driver_policy:
                    result['driverPolicy'] = plan.driver_policy
                if policy_evidence is not None:
                    result['planningPolicy'] = policy_evidence
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',
                    (revision, scope.workspace_id, scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], job['program_digest'],
                     job['subject_id'], revision, Jsonb(result)))
                from .postgres_calculation_impact import (
                    record_calculation_impact)
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                changed = db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s
                    AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision, Jsonb(result), scope.workspace_id,
                     scope.application_id, claim['job_id'],
                     claim['claim_generation'], claim['claimant'])).rowcount
                if changed != 1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
