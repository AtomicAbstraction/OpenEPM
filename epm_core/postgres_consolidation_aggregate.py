"""Bounded exact aggregation of every direct Full child at one parent point.

This publishes an unreviewed local Full result. Explicit source modes may
consume previously posted acquisition/manual journals and IC offsets. It does
not translate, derive acquisition measurements or certify a whole financial close.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .postgres_version_compare import _identifier
from .postgres_calculation_status import published_child_status
from .postgres_acquisition_contribution import (
    ACQUISITION_LAYERS, ACQUISITION_STAGES, acquisition_contributions)
from .postgres_consolidation_full import enforce_consolidation_target_policy


FUNCTION = 'consolidation.full.aggregate'
LEGACY_COMPILER = 'consolidation-full-aggregate-v2'
LEGACY_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 2,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_full_coordinates',
    'outputGrain': 'one_parent_full_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'coverage': 'all_active_direct_placements',
    'sourceLayers': ['raw', 'raw_plus_manual_journal'],
    'accountingStage': 'pre_nci_untranslated_uneliminated',
})
PREVIOUS_COMPILER = 'consolidation-full-aggregate-v3'
PREVIOUS_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 3,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_full_coordinates',
    'outputGrain': 'one_parent_full_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'coverage': 'all_active_direct_placements',
    'sourceLayers': ['raw', 'raw_plus_manual_journal'],
    'publishedChildren': 'explicit_pinned_full_aggregate_generation',
    'accountingStage': 'pre_nci_untranslated_uneliminated',
})
IC_DIRECT_COMPILER = 'consolidation-full-aggregate-v4'
IC_DIRECT_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 4,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_full_coordinates',
    'outputGrain': 'one_parent_full_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'coverage': 'all_active_direct_placements',
    'sourceLayers': ['raw', 'raw_plus_manual_journal',
                     'raw_plus_ic_elimination'],
    'publishedChildren': 'explicit_pinned_full_aggregate_generation_without_ic',
    'icLayer': 'current_parent_pair_generation_with_both_source_ids',
    'accountingStage': 'explicit_unreviewed_source_layer',
})
NESTED_COMPILER = 'consolidation-full-aggregate-v5'
NESTED_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 5,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_full_coordinates',
    'outputGrain': 'one_parent_full_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'coverage': 'all_active_direct_placements',
    'sourceLayers': ['raw', 'raw_plus_manual_journal',
                     'raw_plus_ic_elimination'],
    'publishedChildren': 'pinned_same_stage_full_aggregate_generation',
    'icLayer': 'current_parent_pair_generation_on_raw_children_only',
    'nestedFreshness': 'pointer_and_input_revisions_at_each_level',
    'accountingStage': 'explicit_unreviewed_source_layer',
})
JOURNAL_IC_COMPILER = 'consolidation-full-aggregate-v6'
JOURNAL_IC_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 6,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_full_coordinates',
    'outputGrain': 'one_parent_full_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'coverage': 'all_active_direct_placements',
    'sourceLayers': ['raw', 'raw_plus_manual_journal',
                     'raw_plus_ic_elimination',
                     'raw_plus_manual_journal_plus_ic_elimination'],
    'publishedChildren': 'pinned_same_stage_full_aggregate_generation',
    'icLayer': 'current_parent_pair_generation_on_raw_children_only',
    'journalLayer': 'posted_manual_journal_lines_at_same_coordinate',
    'nestedFreshness': 'pointer_and_input_revisions_at_each_level',
    'accountingStage': 'explicit_unreviewed_source_layer',
})
BASE_SOURCE_LAYERS=frozenset(('raw','raw_plus_manual_journal',
    'raw_plus_ic_elimination','raw_plus_manual_journal_plus_ic_elimination'))
SOURCE_LAYERS=BASE_SOURCE_LAYERS | ACQUISITION_LAYERS
COMPILER='consolidation-full-aggregate-v7'
PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':7,'engine':'postgres_exact_sql',
    'sourceLayers':sorted(SOURCE_LAYERS),'acquisitionLayer':'sealed_posted_effects_with_operational_pins',
    'sparseAcquisitionSources':'preserve_missing_and_present_zero',
    'nestedChildren':'pinned_same_stage_without_reapplying_adjustments',
    'currency':'current_aligned_functional_currency_with_exact_historical_corrections',
    'accountPolicy':'current_type_matches_unreversed_posting_role'})
# Freeze v7 authority before registering the prospective functional-unit contract.
V7_SOURCE_LAYERS = SOURCE_LAYERS
FUNCTIONAL_SOURCE_LAYERS = frozenset(('raw_functional',))
SOURCE_LAYERS = V7_SOURCE_LAYERS | FUNCTIONAL_SOURCE_LAYERS
FUNCTIONAL_COMPILER = 'consolidation-full-aggregate-v8'
FUNCTIONAL_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 8, 'engine': 'postgres_exact_sql',
    'sourceLayers': sorted(FUNCTIONAL_SOURCE_LAYERS),
    'currency': 'active_parent_and_child_functional_currency_exact_alignment',
    'factAxes': 'all_active_dimensions_except_currency',
    'adjustments': 'none',
    'nestedChildren': 'pinned_same_stage_without_reapplying_adjustments',
    'valueStage': 'entity_currency_ytd_when_present'})


def full_compiler_for(plan):
    if plan.source_layer in FUNCTIONAL_SOURCE_LAYERS:
        return FUNCTIONAL_COMPILER, FUNCTIONAL_PLAN_DIGEST
    return COMPILER, PLAN_DIGEST


_IC_LAYERS = {'raw_plus_ic_elimination','raw_plus_manual_journal_plus_ic_elimination',
    'raw_plus_ic_elimination_plus_acquisition_journal',
    'raw_plus_manual_journal_plus_ic_elimination_plus_acquisition_journal'}
_JOURNAL_LAYERS = {'raw_plus_manual_journal','raw_plus_manual_journal_plus_ic_elimination',
    'raw_plus_manual_journal_plus_acquisition_journal',
    'raw_plus_manual_journal_plus_ic_elimination_plus_acquisition_journal'}
_CURRENCY_LAYERS=_IC_LAYERS | ACQUISITION_LAYERS | FUNCTIONAL_SOURCE_LAYERS
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')
_ROLES = {'Scenario', 'Year', 'Period', 'Entity', 'Account'}


@dataclass(frozen=True, slots=True)
class FullAggregatePlan:
    parent_members: tuple[tuple[str, str], ...]
    relationship_ids: tuple[str, ...]
    scenario_id: str
    year_id: str
    period_id: str
    include_parent_source: bool
    source_layer: str
    result_key: str
    expected_publication_revision: int
    published_children: tuple[tuple[str, str, str, int], ...] = ()

    @property
    def parent(self) -> Coordinate:
        return Coordinate.from_mapping(dict(self.parent_members))

    @property
    def normalized_program(self) -> dict:
        program = {'version': 2, 'function': FUNCTION,
                'parentMembers': dict(self.parent_members),
                'decisions': [{'relationshipId': relationship_id,
                               'method': 'Full',
                               'controlConfirmed': True}
                              for relationship_id in self.relationship_ids],
                'scenarioId': self.scenario_id,
                'yearId': self.year_id,
                'periodId': self.period_id,
                'includeParentSource': self.include_parent_source,
                'sourceLayer': self.source_layer,
                'currencyAlignedConfirmed': True,
                'resultKey': self.result_key,
                'expectedPublicationRevision':
                    self.expected_publication_revision,
                'inputGrain': 'all_direct_child_full_coordinates',
                'outputGrain': 'one_parent_full_coordinate',
                'accountingStage': (ACQUISITION_STAGES[self.source_layer]
                    if self.source_layer in ACQUISITION_LAYERS else
                    'pre_nci_untranslated_journal_ic_adjusted'
                    if self.source_layer ==
                    'raw_plus_manual_journal_plus_ic_elimination' else
                    'pre_nci_untranslated_ic_adjusted'
                    if self.source_layer == 'raw_plus_ic_elimination' else
                    'pre_nci_untranslated_currency_aligned'
                    if self.source_layer in FUNCTIONAL_SOURCE_LAYERS else
                    'pre_nci_untranslated_uneliminated')}
        if self.published_children:
            program['publishedChildren'] = [
                {'relationshipId': relationship_id,
                 'resultKey': result_key,
                 'generationId': generation_id,
                 'publishedRevision': revision}
                for relationship_id, result_key, generation_id, revision
                in self.published_children]
        return program


def compile_full_aggregate(program: object, *,
                           expected_publication_revision: int
                           ) -> FullAggregatePlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)):
        raise ValueError('FULL_AGGREGATE_PROGRAM_INVALID')
    args = program['arguments']
    required = {'parentMembers', 'decisions', 'scenarioId',
                     'yearId', 'periodId', 'includeParentSource',
                     'sourceLayer',
                     'currencyAlignedConfirmed',
                     'resultKey'}
    if (set(args) not in (required, required | {'publishedChildren'})
            or not isinstance(args['parentMembers'], dict)
            or not 1 <= len(args['parentMembers']) <= 32
            or not isinstance(args['decisions'], list)
            or not 1 <= len(args['decisions']) <= 200
            or args['currencyAlignedConfirmed'] is not True
            or type(args['includeParentSource']) is not bool
            or not isinstance(args['sourceLayer'],str)
            or args['sourceLayer'] not in SOURCE_LAYERS
            or not isinstance(args['resultKey'], str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0):
        raise ValueError('FULL_AGGREGATE_ARGUMENTS_INVALID')
    if any(not isinstance(item, dict)
           or set(item) != {'relationshipId', 'method', 'controlConfirmed'}
           or item['method'] != 'Full'
           or item['controlConfirmed'] is not True
           for item in args['decisions']):
        raise ValueError('FULL_AGGREGATE_DECISION_INVALID')
    relationships = tuple(sorted(_identifier(item['relationshipId'],
                                            'Relationship ID')
                                 for item in args['decisions']))
    if len(set(relationships)) != len(relationships):
        raise ValueError('FULL_AGGREGATE_DUPLICATE_RELATIONSHIP')
    published = args.get('publishedChildren', [])
    if not isinstance(published, list) or len(published) > len(relationships):
        raise ValueError('FULL_AGGREGATE_PUBLISHED_CHILDREN_INVALID')
    pinned = []
    for item in published:
        if (not isinstance(item, dict) or set(item) != {
                'relationshipId','resultKey','generationId',
                'publishedRevision'} or
                not isinstance(item['resultKey'], str) or
                not _KEY.fullmatch(item['resultKey']) or
                item['resultKey'] == args['resultKey'] or
                not isinstance(item['generationId'], str) or
                not _JOB.fullmatch(item['generationId']) or
                type(item['publishedRevision']) is not int or
                item['publishedRevision'] <= 0):
            raise ValueError('FULL_AGGREGATE_PUBLISHED_CHILDREN_INVALID')
        pinned.append((_identifier(item['relationshipId'],
                                   'Relationship ID'),
                       item['resultKey'],item['generationId'],
                       item['publishedRevision']))
    pinned.sort()
    if (len({item[0] for item in pinned}) != len(pinned) or
            any(item[0] not in relationships for item in pinned)):
        raise ValueError('FULL_AGGREGATE_PUBLISHED_CHILDREN_INVALID')
    members = {_identifier(axis, 'Dimension ID'):
               _identifier(member, 'Member ID')
               for axis, member in args['parentMembers'].items()}
    return FullAggregatePlan(
        tuple(sorted(members.items())), relationships,
        _identifier(args['scenarioId'], 'Scenario ID'),
        _identifier(args['yearId'], 'Year ID'),
        _identifier(args['periodId'], 'Period ID'),
        args['includeParentSource'], args['sourceLayer'],
        args['resultKey'],
        expected_publication_revision, tuple(pinned))


def decode_full_aggregate(program: object) -> FullAggregatePlan:
    if (not isinstance(program, dict)
            or set(program) not in ({'version', 'function', 'parentMembers',
                                'decisions', 'scenarioId', 'yearId',
                                'periodId', 'includeParentSource',
                                'sourceLayer',
                                'currencyAlignedConfirmed',
                                'resultKey', 'expectedPublicationRevision',
                                'inputGrain', 'outputGrain',
                                'accountingStage'},
                                {'version', 'function', 'parentMembers',
                                'decisions', 'scenarioId', 'yearId',
                                'periodId', 'includeParentSource',
                                'sourceLayer',
                                'currencyAlignedConfirmed',
                                'resultKey', 'expectedPublicationRevision',
                                'inputGrain', 'outputGrain',
                                'accountingStage', 'publishedChildren'})
            or program['version'] != 2 or program['function'] != FUNCTION
            or program['inputGrain'] !=
                    'all_direct_child_full_coordinates'
            or program['outputGrain'] != 'one_parent_full_coordinate'
            or program['accountingStage'] not in (
                    'pre_nci_untranslated_currency_aligned',
                    'pre_nci_untranslated_uneliminated',
                    'pre_nci_untranslated_ic_adjusted',
                    'pre_nci_untranslated_journal_ic_adjusted',
                    *ACQUISITION_STAGES.values())):
        raise ValueError('UNSUPPORTED_FULL_AGGREGATE_JOB_PROGRAM')
    plan = compile_full_aggregate({
        'languageVersion': 2, 'function': FUNCTION,
        'arguments': {key: program[key] for key in (
            'parentMembers', 'decisions', 'scenarioId', 'yearId',
            'periodId', 'includeParentSource', 'sourceLayer',
            'currencyAlignedConfirmed', 'resultKey')}
            | ({'publishedChildren': program['publishedChildren']}
               if 'publishedChildren' in program else {})},
        expected_publication_revision=
            program['expectedPublicationRevision'])
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_FULL_AGGREGATE_JOB_PROGRAM')
    return plan


def authorize_full_aggregate(db, identity: VerifiedIdentity,
                             scope: ApplicationScope,
                             plan: FullAggregatePlan) -> None:
    """Authorize the complete bounded input/output grain before fact reads."""
    entity_axes=db.execute('''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role='Entity' ''',(
        scope.workspace_id,scope.application_id)).fetchall()
    if len(entity_axes)!=1:
        raise ValueError('FULL_AGGREGATE_FINANCIAL_MODEL_REQUIRED')
    entity_axis=entity_axes[0]['dimension_id']
    parent=dict(plan.parent_members)
    rows=db.execute('''SELECT relationship_id,child_member_id
        FROM epm.relationship WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND parent_member_id=%s AND status='Active'
        ORDER BY relationship_id LIMIT 201''',(
        scope.workspace_id,scope.application_id,entity_axis,
        parent.get(entity_axis))).fetchall()
    if (not 1<=len(rows)<=200
            or tuple(row['relationship_id'] for row in rows)!=
                plan.relationship_ids):
        raise ValueError('FULL_AGGREGATE_RELATIONSHIP_COVERAGE_MISMATCH')
    sources=[Coordinate.from_mapping(
        {**parent,entity_axis:row['child_member_id']}) for row in rows]
    if plan.include_parent_source:
        sources.append(plan.parent)
    authorize_coordinates(db,identity,scope,tuple(sources),
                          kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,(plan.parent,),
                          kind=AccessKind.WRITE)


def validate_full_aggregate(db, scope: ApplicationScope,
                            plan: FullAggregatePlan) -> dict:
    roles = {}
    axes = set()
    for row in db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        (scope.workspace_id, scope.application_id)).fetchall():
        if row['model_role']=='Method' and plan.source_layer in ACQUISITION_LAYERS:
            raise ValueError('FULL_AGGREGATE_ACQUISITION_METHOD_AXIS_UNSUPPORTED')
        if (plan.source_layer not in _CURRENCY_LAYERS
                or row['model_role'] != 'Currency'):
            axes.add(row['dimension_id'])
        if row['model_role'] in _ROLES | {'Currency', 'Value', 'View', 'ICP'}:
            if row['model_role'] in roles:
                raise ValueError('FULL_AGGREGATE_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']] = row['dimension_id']
    if not _ROLES <= set(roles):
        raise ValueError('FULL_AGGREGATE_FINANCIAL_MODEL_REQUIRED')
    if (('Value' in roles and plan.source_layer not in _CURRENCY_LAYERS)
            or (plan.source_layer not in _CURRENCY_LAYERS
                and 'Currency' in roles)):
        raise ValueError('FULL_AGGREGATE_FX_POLICY_REQUIRED')
    if (plan.source_layer in _IC_LAYERS
            and ('Currency' not in roles or 'ICP' not in roles)):
        raise ValueError('FULL_AGGREGATE_IC_MODEL_REQUIRED')
    if plan.source_layer in ACQUISITION_LAYERS and 'Currency' not in roles:
        raise ValueError('FULL_AGGREGATE_ACQUISITION_CURRENCY_REQUIRED')
    if plan.source_layer in FUNCTIONAL_SOURCE_LAYERS and 'Currency' not in roles:
        raise ValueError('FULL_AGGREGATE_FUNCTIONAL_CURRENCY_REQUIRED')
    parent_members = dict(plan.parent_members)
    if set(parent_members) != axes:
        raise ValueError('FULL_AGGREGATE_COORDINATE_GRAIN_MISMATCH')
    for role, value in (('Scenario', plan.scenario_id),
                        ('Year', plan.year_id),
                        ('Period', plan.period_id)):
        if parent_members[roles[role]] != value:
            raise ValueError('FULL_AGGREGATE_CONTEXT_MISMATCH')
    PostgresSourceBatch._check_scope_members(db, scope, parent_members)
    if 'Value' in roles:
        state = db.execute('''SELECT currency_settings,metadata_revision
            FROM epm.application_state WHERE workspace_id=%s
            AND application_id=%s''',
            (scope.workspace_id,scope.application_id)).fetchone()
        settings = state['currency_settings'] if state else None
        if (plan.source_layer not in _CURRENCY_LAYERS
                or 'View' not in roles
                or settings is None
                or settings.get('validatedMetadataRevision') !=
                    state['metadata_revision']
                or parent_members[roles['Value']] !=
                    settings.get('entityCurrencyValueMemberId')
                or parent_members[roles['View']] !=
                    settings.get('ytdViewMemberId')):
            raise ValueError('FULL_AGGREGATE_ACQUISITION_VALUE_STAGE_REQUIRED'
                if plan.source_layer in ACQUISITION_LAYERS else
                'FULL_AGGREGATE_FUNCTIONAL_VALUE_STAGE_REQUIRED'
                if plan.source_layer in FUNCTIONAL_SOURCE_LAYERS else 'FULL_AGGREGATE_IC_VALUE_STAGE_REQUIRED')
    account_id = parent_members[roles['Account']]
    if db.execute('''SELECT 1 FROM epm.relationship WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s
        AND parent_member_id=%s AND status='Active' LIMIT 1''',
        (scope.workspace_id, scope.application_id,
         roles['Account'], account_id)).fetchone():
        raise ValueError('FULL_AGGREGATE_ACCOUNT_LEAF_REQUIRED')
    parent_id = parent_members[roles['Entity']]
    parent_currency = None
    if plan.source_layer in _CURRENCY_LAYERS:
        parent_row = db.execute('''SELECT
            entity_default_currency_member_id AS currency_id
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND member_id=%s AND status='Active' ''',
            (scope.workspace_id,scope.application_id,
             roles['Entity'],parent_id)).fetchone()
        parent_currency = parent_row['currency_id'] if parent_row else None
        if (parent_currency is None or not db.execute('''SELECT 1 FROM
                epm.member WHERE workspace_id=%s AND application_id=%s
                AND dimension_id=%s AND member_id=%s AND status='Active' ''',
                (scope.workspace_id,scope.application_id,
                 roles['Currency'],parent_currency)).fetchone()):
            raise ValueError('FULL_AGGREGATE_ACQUISITION_PARENT_CURRENCY_REQUIRED'
                if plan.source_layer in ACQUISITION_LAYERS else
                'FULL_AGGREGATE_FUNCTIONAL_PARENT_CURRENCY_REQUIRED'
                if plan.source_layer in FUNCTIONAL_SOURCE_LAYERS else 'FULL_AGGREGATE_IC_PARENT_CURRENCY_REQUIRED')
    # One bounded relational read resolves every active direct placement,
    # period-sensitive ownership input and numeric child coordinate.
    rows = db.execute('''SELECT r.relationship_id,r.child_member_id,
        child.status AS child_status,
        child.entity_default_currency_member_id AS child_currency_id,
        (SELECT count(*) FROM epm.relationship other
            WHERE other.workspace_id=r.workspace_id
            AND other.application_id=r.application_id
            AND other.dimension_id=r.dimension_id
            AND other.child_member_id=r.child_member_id
            AND other.status='Active') AS parent_count,
        pown.amount AS pown,pcon.amount AS pcon,
        active.amount AS active_value,method.amount AS method_value,
        c.coordinate_id,n.amount,n.change_id,
        t.present AS text_present
        FROM epm.relationship r
        JOIN epm.member child ON child.workspace_id=r.workspace_id
            AND child.application_id=r.application_id
            AND child.dimension_id=r.dimension_id
            AND child.member_id=r.child_member_id
        LEFT JOIN epm.ownership_value_current pown ON
            pown.workspace_id=r.workspace_id
            AND pown.application_id=r.application_id
            AND pown.relationship_id=r.relationship_id
            AND pown.scenario_member_id=%s AND pown.year_member_id=%s
            AND pown.period_member_id=%s AND pown.account_name='POWN'
            AND pown.present
        LEFT JOIN epm.ownership_value_current pcon ON
            pcon.workspace_id=r.workspace_id
            AND pcon.application_id=r.application_id
            AND pcon.relationship_id=r.relationship_id
            AND pcon.scenario_member_id=%s AND pcon.year_member_id=%s
            AND pcon.period_member_id=%s AND pcon.account_name='PCON'
            AND pcon.present
        LEFT JOIN epm.ownership_value_current active ON
            active.workspace_id=r.workspace_id
            AND active.application_id=r.application_id
            AND active.relationship_id=r.relationship_id
            AND active.scenario_member_id=%s AND active.year_member_id=%s
            AND active.period_member_id=%s AND active.account_name='Active'
            AND active.present
        LEFT JOIN epm.ownership_value_current method ON
            method.workspace_id=r.workspace_id
            AND method.application_id=r.application_id
            AND method.relationship_id=r.relationship_id
            AND method.scenario_member_id=%s AND method.year_member_id=%s
            AND method.period_member_id=%s AND method.account_name='Method'
            AND method.present
        LEFT JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
            AND c.application_id=r.application_id
            AND c.members=(%s::jsonb || jsonb_build_object(%s::text,
                                                       r.child_member_id))
        LEFT JOIN epm.numeric_cell_current n ON
            n.workspace_id=c.workspace_id
            AND n.application_id=c.application_id
            AND n.coordinate_id=c.coordinate_id AND n.present
        LEFT JOIN epm.text_cell_current t ON
            t.workspace_id=c.workspace_id
            AND t.application_id=c.application_id
            AND t.coordinate_id=c.coordinate_id AND t.present
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.dimension_id=%s AND r.parent_member_id=%s
          AND r.status='Active'
        ORDER BY r.relationship_id LIMIT 201''',
        (plan.scenario_id, plan.year_id, plan.period_id) * 4 +
        (Jsonb(parent_members), roles['Entity'],
         scope.workspace_id, scope.application_id,
         roles['Entity'], parent_id)).fetchall()
    if not 1 <= len(rows) <= 200:
        raise ValueError('FULL_AGGREGATE_PLACEMENT_LIMIT')
    if tuple(row['relationship_id'] for row in rows) != plan.relationship_ids:
        raise ValueError('FULL_AGGREGATE_RELATIONSHIP_COVERAGE_MISMATCH')
    if len({row['child_member_id'] for row in rows}) != len(rows):
        raise ValueError('FULL_AGGREGATE_DUPLICATE_CHILD')
    published_by_relationship = {item[0]: item for item in
                                 plan.published_children}
    points = []
    for row in rows:
        if row['child_status'] != 'Active':
            raise ValueError('FULL_AGGREGATE_CHILD_INACTIVE')
        if (plan.source_layer in _CURRENCY_LAYERS
                and row['child_currency_id'] != parent_currency):
            raise ValueError('FULL_AGGREGATE_ACQUISITION_CURRENCY_ALIGNMENT_REQUIRED'
                if plan.source_layer in ACQUISITION_LAYERS else
                'FULL_AGGREGATE_FUNCTIONAL_CURRENCY_ALIGNMENT_REQUIRED'
                if plan.source_layer in FUNCTIONAL_SOURCE_LAYERS else 'FULL_AGGREGATE_IC_CURRENCY_ALIGNMENT_REQUIRED')
        if row['parent_count'] != 1:
            raise ValueError('FULL_AGGREGATE_AMBIGUOUS_PLACEMENT')
        if row['method_value'] is not None:
            raise ValueError('FULL_AGGREGATE_METHOD_CODE_UNMAPPED')
        if row['active_value'] == 0:
            raise ValueError('FULL_AGGREGATE_PERIOD_INACTIVE')
        if row['pown'] is None:
            raise ValueError('FULL_AGGREGATE_POWN_REQUIRED')
        if row['pcon'] is not None and row['pcon'] != 100:
            raise ValueError('FULL_AGGREGATE_FULL_PCON_REQUIRED')
        if row['text_present'] and row['relationship_id'] not in (
                published_by_relationship):
            raise ValueError('FULL_AGGREGATE_CHILD_TEXT_UNSUPPORTED')
        if row['coordinate_id'] is None and plan.source_layer not in ACQUISITION_LAYERS:
            raise ValueError('FULL_AGGREGATE_SOURCE_NUMERIC_REQUIRED')
        points.append((row['coordinate_id'], row['amount'],
                       row['change_id'], {
                           'relationshipId': row['relationship_id'],
                           'childEntityId': row['child_member_id'],
                           'pown': format(row['pown'], '.8f'),
                           'effectivePcon': '100.00000000',
                           'pconFallback': row['pcon'] is None}))
    parent_cell = db.execute('''SELECT c.coordinate_id,c.members,
        n.amount,n.change_id,t.present AS text_present
        FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n
        ON n.workspace_id=c.workspace_id
        AND n.application_id=c.application_id
        AND n.coordinate_id=c.coordinate_id AND n.present
        LEFT JOIN epm.text_cell_current t
        ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id AND t.present
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s''',
        (scope.workspace_id, scope.application_id,
         plan.parent.series_key)).fetchone()
    if parent_cell is not None and parent_cell['members'] != parent_members:
        raise ValueError('COORDINATE_HASH_COLLISION')
    if parent_cell is not None and parent_cell['text_present']:
        raise ValueError('FULL_AGGREGATE_PARENT_TEXT_UNSUPPORTED')
    published_inputs = []
    for point_id, raw_amount, change_id, context in points:
        pin = published_by_relationship.get(context['relationshipId'])
        if pin:
            published_inputs.append({'relationship_id': pin[0],
                'result_key': pin[1], 'generation_id': pin[2],
                'published_revision': pin[3], 'coordinate_id': point_id})
    published_sources = {}
    if published_inputs:
        matches = db.execute('''SELECT input.relationship_id,
            input.result_key,input.generation_id,
            input.published_revision,
            p.generation_id AS current_generation_id,
            p.published_revision AS current_published_revision,
            g.function_name,g.result_key AS generation_result_key,
            g.source_commit_revision,g.source_metadata_revision,
            g.source_policy_revision,
            r.amount,r.source_change_id,
            j.status AS job_status,
            j.expected_metadata_revision,j.expected_data_revision,
            j.expected_policy_revision,j.result AS job_result,
            s.metadata_revision AS observed_metadata_revision,
            s.data_revision AS observed_data_revision,
            s.policy_revision AS observed_policy_revision
            FROM jsonb_to_recordset(%s::jsonb) AS input(
                relationship_id text,result_key text,generation_id text,
                published_revision bigint,coordinate_id bigint)
            LEFT JOIN epm.calculation_publication p ON
                p.workspace_id=%s AND p.application_id=%s
                AND p.result_key=input.result_key
            LEFT JOIN epm.calculation_generation g ON
                g.workspace_id=%s AND g.application_id=%s
                AND g.generation_id=input.generation_id
            LEFT JOIN epm.calculation_result r ON
                r.workspace_id=%s AND r.application_id=%s
                AND r.generation_id=input.generation_id
                AND r.coordinate_id=input.coordinate_id
            LEFT JOIN epm.job j ON j.workspace_id=g.workspace_id
                AND j.application_id=g.application_id AND j.job_id=g.job_id
            JOIN epm.application_state s ON s.workspace_id=%s
                AND s.application_id=%s
            ORDER BY input.relationship_id''',
            (Jsonb(published_inputs),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        if len(matches) != len(published_inputs):
            raise ValueError('FULL_AGGREGATE_PUBLISHED_SOURCE_UNAVAILABLE')
        for match in matches:
            if (match['current_generation_id'] != match['generation_id']
                    or match['current_published_revision'] !=
                    match['published_revision']):
                raise ValueError('STALE_PUBLISHED_INPUT')
            receipt = match['job_result']
            expected_stage = plan.normalized_program['accountingStage']
            if (match['function_name'] != FUNCTION
                    or match['generation_result_key'] != match['result_key']
                    or match['amount'] is None
                    or match['job_status'] != 'published'
                    or not isinstance(receipt, dict)
                    or receipt.get('accountingStage') != expected_stage
                    or receipt.get('accountingPolicyStatus') != 'Unreviewed'):
                raise ValueError('FULL_AGGREGATE_PUBLISHED_SOURCE_UNSUPPORTED')
            if (match['expected_metadata_revision'] !=
                    match['observed_metadata_revision'] or
                    match['expected_data_revision'] !=
                    match['observed_data_revision'] or
                    match['expected_policy_revision'] !=
                    match['observed_policy_revision']):
                raise ValueError('FULL_AGGREGATE_PUBLISHED_SOURCE_STALE')
            published_sources[match['relationship_id']] = match
        dependency_status = published_child_status(
            db, scope, plan.normalized_program)
        if dependency_status is None or not dependency_status['matchesAtRead']:
            raise ValueError('STALE_PUBLISHED_INPUT')
    ic_by_coordinate = {}
    if plan.source_layer in _IC_LAYERS:
        selected_ids = [point[0] for point in points if point[0] is not None and
            point[3]['relationshipId'] not in published_by_relationship]
        from .postgres_ic_contribution import ic_contributions
        ic_by_coordinate=ic_contributions(db,scope,selected_ids,parent_id)
    ic_amounts = {}
    if plan.source_layer in _IC_LAYERS:
        selected = [{'coordinate_id': point[0],
                     'adjustment': format(ic_by_coordinate[point[0]]
                         ['signedAmount'],'.8f')
                         if point[0] in ic_by_coordinate else '0.00000000'}
                    for point in points if point[3]['relationshipId'] not in
                    published_by_relationship and (point[1] is not None
                        or plan.source_layer not in ACQUISITION_LAYERS)]
        computed = db.execute('''SELECT input.coordinate_id,
            (n.amount + input.adjustment)::numeric(28,8) AS amount
            FROM jsonb_to_recordset(%s::jsonb) AS input(
                coordinate_id bigint,adjustment numeric)
            JOIN epm.numeric_cell_current n ON
                n.workspace_id=%s AND n.application_id=%s
                AND n.coordinate_id=input.coordinate_id AND n.present''',
            (Jsonb(selected),scope.workspace_id,
             scope.application_id)).fetchall()
        if len(computed) != len(selected):
            raise ValueError('FULL_AGGREGATE_SOURCE_NUMERIC_REQUIRED')
        ic_amounts = {row['coordinate_id']: row['amount']
                      for row in computed}
        if len(ic_amounts) != len(selected):
            raise ValueError('FULL_AGGREGATE_SOURCE_NUMERIC_REQUIRED')
    journal_ids = [point[0] for point in points if point[0] is not None and
                   point[3]['relationshipId'] not in
                   published_by_relationship]
    if parent_cell is not None:
        journal_ids.append(parent_cell['coordinate_id'])
    journal_lines = []
    if plan.source_layer in _JOURNAL_LAYERS:
        journal_lines = db.execute('''SELECT l.coordinate_id,l.journal_id,
            l.line_ordinal,l.signed_amount,h.committed_revision
            FROM epm.manual_journal_line l JOIN epm.manual_journal h
            USING (workspace_id,application_id,journal_id)
            WHERE l.workspace_id=%s AND l.application_id=%s
            AND l.coordinate_id=ANY(%s::bigint[])
            ORDER BY l.coordinate_id,h.committed_revision,
                     l.journal_id,l.line_ordinal LIMIT 501''',
            (scope.workspace_id, scope.application_id,
             journal_ids)).fetchall()
        if len(journal_lines) > 500:
            raise ValueError('FULL_AGGREGATE_JOURNAL_LINE_LIMIT')
    by_coordinate = {point_id: [] for point_id in journal_ids}
    for line in journal_lines:
        by_coordinate[line['coordinate_id']].append({
            'journalId': line['journal_id'],
            'lineOrdinal': line['line_ordinal'],
            'signedAmount': format(line['signed_amount'], '.8f'),
            'committedRevision': line['committed_revision']})

    account_type=(db.execute('''SELECT financial_account_type FROM epm.member WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s AND member_id=%s''',
        (scope.workspace_id,scope.application_id,roles['Account'],account_id)).fetchone()['financial_account_type']
        if plan.source_layer in ACQUISITION_LAYERS else None)
    acquisition_by_coordinate=(acquisition_contributions(db,scope,journal_ids,
        roles['Currency'],parent_currency,account_type) if plan.source_layer in ACQUISITION_LAYERS else {})

    def resolved_amount(point_id, raw_amount, raw_change_id, context):
        lines = by_coordinate.get(point_id, [])
        ic = ic_by_coordinate.get(point_id)
        acquisition=acquisition_by_coordinate.get(point_id,[])
        with localcontext() as decimal_context:
            decimal_context.prec = 64
            adjustment = sum((Decimal(item['signedAmount'])
                              for item in lines), Decimal(0))
            acquisition_adjustment=sum((Decimal(line['signedAmount']) for line in acquisition),Decimal(0))
            ic_adjustment = (ic['signedAmount'] if ic else Decimal(0))
            amount = ((ic_amounts[point_id] + adjustment)
                      if point_id in ic_amounts else
                      (raw_amount if raw_amount is not None
                       else Decimal(0)) + adjustment) + acquisition_adjustment
        if plan.source_layer in ACQUISITION_LAYERS:
            if raw_amount is None and not lines and not acquisition: return None
        elif (raw_amount is None and
                (plan.source_layer == 'raw' or adjustment == 0)):
            return None
        NumericCell(True, amount, '')
        source = {**context,
                'rawAmount': (format(raw_amount, '.8f')
                              if raw_amount is not None else None),
                'changeId': raw_change_id or '',
                'journalAdjustment': format(adjustment, '.8f'),
                'journalLines': lines,
                'amount': format(amount, '.8f')}
        if plan.source_layer in ACQUISITION_LAYERS:
            source['acquisitionAdjustment']=format(acquisition_adjustment,'.8f')
            source['acquisitionLines']=acquisition
            source['present']=True
        if plan.source_layer in _IC_LAYERS:
            source['icEliminationAdjustment'] = format(ic_adjustment,'.8f')
            source['icEliminationGenerationId'] = (
                ic['generationId'] if ic else None)
            source['icEliminationPublishedRevision'] = (
                ic['publishedRevision'] if ic else None)
            source['icEliminationLineOrdinal'] = (
                ic['lineOrdinal'] if ic else None)
        return source

    sources = []
    source_ids = []
    for point_id, raw_amount, change_id, context in points:
        published = published_sources.get(context['relationshipId'])
        if published:
            sources.append({**context,
                'selectedLayer': 'published_full_aggregate',
                'rawAmount': (format(raw_amount, '.8f')
                              if raw_amount is not None else None),
                'rawUsed': False, 'changeId': change_id or '',
                'journalAdjustment': '0.00000000', 'journalLines': [],
                'resultKey': published['result_key'],
                'generationId': published['generation_id'],
                'publishedRevision': published['published_revision'],
                'sourceCommitRevision': published['source_commit_revision'],
                'sourceMetadataRevision':
                    published['source_metadata_revision'],
                'sourcePolicyRevision': published['source_policy_revision'],
                'sourceChangeId': published['source_change_id'],
                'amount': format(published['amount'], '.8f')})
            if plan.source_layer in ACQUISITION_LAYERS:
                sources[-1].update({'present':True,'acquisitionAdjustment':'0.00000000',
                    'acquisitionLines':[],'acquisitionIncludedInPublishedChild':True})
            continue
        resolved = resolved_amount(point_id, raw_amount,
                                   change_id, context)
        if resolved is None:
            if plan.source_layer in ACQUISITION_LAYERS:
                sources.append({**context,'present':False,'amount':None,'rawAmount':None,
                    'changeId':'','journalAdjustment':'0.00000000','journalLines':[],
                    'acquisitionAdjustment':'0.00000000','acquisitionLines':[]})
                continue
            raise ValueError('FULL_AGGREGATE_SOURCE_NUMERIC_REQUIRED')
        source_ids.append(point_id)
        sources.append(resolved)
    parent_resolved = None
    if parent_cell is not None:
        parent_resolved = resolved_amount(
            parent_cell['coordinate_id'], parent_cell['amount'],
            parent_cell['change_id'],
            {'relationshipId': None, 'childEntityId': None,
             'pown': None, 'effectivePcon': None,
             'pconFallback': False})
    if plan.include_parent_source and parent_resolved is None:
        raise ValueError('FULL_AGGREGATE_PARENT_SOURCE_REQUIRED')
    if not plan.include_parent_source and (
            parent_resolved is not None or
            (parent_cell is not None and
             by_coordinate.get(parent_cell['coordinate_id']))):
        raise ValueError('FULL_AGGREGATE_PARENT_SOURCE_NOT_DECLARED')
    if parent_resolved is not None:
        source_ids.append(parent_cell['coordinate_id'])
        sources.append(parent_resolved)
    if published_sources or plan.source_layer in _IC_LAYERS | ACQUISITION_LAYERS:
        total = db.execute('''SELECT sum(value)::numeric(28,8) AS amount
            FROM unnest(%s::numeric[]) AS selected(value)''',
            ([Decimal(source['amount']) for source in sources if source['amount'] is not None],)
            ).fetchone()['amount']
    elif plan.source_layer in {'raw', 'raw_functional'}:
        total = db.execute('''SELECT sum(n.amount)::numeric(28,8) AS amount
            FROM epm.numeric_cell_current n
            WHERE n.workspace_id=%s AND n.application_id=%s
            AND n.coordinate_id=ANY(%s::bigint[]) AND n.present''',
            (scope.workspace_id, scope.application_id,
             source_ids)).fetchone()['amount']
    else:
        total = db.execute('''SELECT sum(coalesce(n.amount,0)+
                coalesce(j.adjustment,0))::numeric(28,8) AS amount
            FROM unnest(%s::bigint[]) AS selected(coordinate_id)
            LEFT JOIN epm.numeric_cell_current n
                ON n.workspace_id=%s AND n.application_id=%s
                AND n.coordinate_id=selected.coordinate_id AND n.present
            LEFT JOIN LATERAL (
                SELECT sum(l.signed_amount) AS adjustment
                FROM epm.manual_journal_line l
                WHERE l.workspace_id=%s AND l.application_id=%s
                AND l.coordinate_id=selected.coordinate_id
            ) j ON true''',
            (source_ids, scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchone()['amount']
    if total is None:
        raise ValueError('FULL_AGGREGATE_SOURCE_NUMERIC_REQUIRED')
    with localcontext() as decimal_context:
        decimal_context.prec = 64
        if total != sum((Decimal(source['amount']) for source in sources if source['amount'] is not None),
                        Decimal(0)):
            raise ValueError('FULL_AGGREGATE_SOURCE_SUM_CHANGED')
    return {'target': plan.parent, 'amount': total,
            'sources': sources, 'sourceChangeId': _canonical_digest({
                'sourceLayer': plan.source_layer, 'sources': sources}),
            'parentEntityId': parent_id,
            'includeParentSource': plan.include_parent_source,
            'sourceLayer': plan.source_layer}


def supported_full_compiler(version,digest,program):
    if not isinstance(program,dict) or not isinstance(program.get('sourceLayer'),str): return False
    layer=program['sourceLayer']
    if layer not in SOURCE_LAYERS: return False
    base3=BASE_SOURCE_LAYERS-{'raw_plus_manual_journal_plus_ic_elimination'}
    base2={'raw','raw_plus_manual_journal'}
    return (
        (version==FUNCTIONAL_COMPILER and digest==FUNCTIONAL_PLAN_DIGEST
            and layer in FUNCTIONAL_SOURCE_LAYERS) or
        (version==COMPILER and digest==PLAN_DIGEST and layer in V7_SOURCE_LAYERS) or
        (version==JOURNAL_IC_COMPILER and digest==JOURNAL_IC_PLAN_DIGEST and layer in BASE_SOURCE_LAYERS) or
        (version==NESTED_COMPILER and digest==NESTED_PLAN_DIGEST and layer in base3) or
        (version==IC_DIRECT_COMPILER and digest==IC_DIRECT_PLAN_DIGEST and layer in base3
            and not program.get('publishedChildren')) or
        (version==PREVIOUS_COMPILER and digest==PREVIOUS_PLAN_DIGEST and layer in base2) or
        (version==LEGACY_COMPILER and digest==LEGACY_PLAN_DIGEST and layer in base2
            and 'publishedChildren' not in program))


class PostgresFullAggregatePublisher:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim, dict)
                or not isinstance(claim.get('workspace_id'), str)
                or not isinstance(claim.get('application_id'), str)
                or not isinstance(claim.get('job_id'), str)
                or not _JOB.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'), str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                job = db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                unexpired = db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']
                        or not unexpired):
                    raise ValueError('STALE_WORKER_FENCE')
                supported_compiler=supported_full_compiler(job['compiler_version'],
                    job['plan_digest'],job['normalized_program'])
                if (job['function_name'] != FUNCTION
                        or not supported_compiler
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_FULL_AGGREGATE_JOB_PROGRAM')
                plan = decode_full_aggregate(job['normalized_program'])
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] !=
                        job['expected_metadata_revision']
                        or state['data_revision'] !=
                        job['expected_data_revision']
                        or state['policy_revision'] !=
                        job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer = db.execute('''SELECT published_revision
                    FROM epm.calculation_publication
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0) != (
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                authorize_full_aggregate(db,self.identity,scope,plan)
                summary = validate_full_aggregate(db, scope, plan)
                target = summary['target']
                final_state=db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                final_job=db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'])).fetchone()
                final_live=(final_job is not None and db.execute(
                    '''SELECT %s::timestamptz > clock_timestamp()
                       AS unexpired''',
                    (final_job['lease_until'],)).fetchone()['unexpired'])
                immutable_job_fields=('issuer','subject_id','function_name',
                    'normalized_program','program_digest','plan_digest',
                    'compiler_version','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision')
                if (final_state is None or final_job is None
                        or any(final_job[key]!=job[key]
                               for key in immutable_job_fields)
                        or final_job['status']!='running'
                        or final_job['claim_generation']!=
                           claim['claim_generation']
                        or final_job['claimant']!=claim['claimant']
                        or not final_live):
                    raise ValueError('STALE_WORKER_FENCE')
                final_access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=FUNCTION)
                if (final_state['application_status']!='Active'
                        or final_state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (final_state['metadata_revision']!=
                        job['expected_metadata_revision']
                        or final_state['data_revision']!=
                        job['expected_data_revision']
                        or final_state['policy_revision']!=
                        job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                final_pointer=db.execute('''SELECT published_revision
                    FROM epm.calculation_publication
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (final_pointer['published_revision']
                        if final_pointer else 0)!=(
                            plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                authorize_full_aggregate(db,self.identity,scope,plan)
                if validate_full_aggregate(db,scope,plan)!=summary:
                    raise ValueError('FULL_AGGREGATE_SOURCE_CHANGED')
                policy_evidence=enforce_consolidation_target_policy(
                    db,scope,target,final_access.role)
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (scope.workspace_id, scope.application_id,
                     target.series_key, Jsonb(dict(target.members))))
                point = db.execute('''SELECT coordinate_id,members
                    FROM epm.coordinate WHERE workspace_id=%s
                    AND application_id=%s AND series_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     target.series_key)).fetchone()
                if point['members'] != dict(target.members):
                    raise ValueError('COORDINATE_HASH_COLLISION')
                db.execute('''INSERT INTO epm.coordinate_member_projection
                    (workspace_id,application_id,coordinate_id,
                     dimension_id,member_id,projection_generation)
                    SELECT %s,%s,%s,item.key,item.value,(SELECT epm.active_projection_generation())
                    FROM jsonb_each_text(%s::jsonb) item
                    ON CONFLICT DO NOTHING''',
                    (scope.workspace_id, scope.application_id,
                     point['coordinate_id'], Jsonb(dict(target.members))))
                revision = final_state['commit_revision'] + 1
                db.execute('''INSERT INTO epm.calculation_generation
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], claim['job_id'], plan.result_key,
                     state['commit_revision'], state['metadata_revision'],
                     state['policy_revision'], FUNCTION, revision))
                db.execute('''INSERT INTO epm.calculation_result
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_amount,source_change_id,amount)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], point['coordinate_id'],
                     summary['amount'], summary['sourceChangeId'],
                     summary['amount']))
                db.execute('''INSERT INTO epm.calculation_publication
                    (workspace_id,application_id,result_key,generation_id,
                     published_revision) VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,result_key)
                    DO UPDATE SET generation_id=EXCLUDED.generation_id,
                    published_revision=EXCLUDED.published_revision,
                    updated_at=transaction_timestamp()''',
                    (scope.workspace_id, scope.application_id,
                     plan.result_key, claim['job_id'], revision))
                result = {'generationId': claim['job_id'],
                          'resultKey': plan.result_key,
                          'function': FUNCTION, 'rowCount': 1,
                          'parentMembers': dict(plan.parent_members),
                          'parentEntityId': summary['parentEntityId'],
                          'relationshipIds': list(plan.relationship_ids),
                          'includeParentSource':
                              summary['includeParentSource'],
                          'sourceLayer': summary['sourceLayer'],
                          'sources': summary['sources'],
                          'sourceChangeId': summary['sourceChangeId'],
                          'amount': format(summary['amount'], '.8f'),
                          'accountingStage': plan.normalized_program[
                              'accountingStage'],
                          'accountingPolicyStatus': 'Unreviewed',
                          'sourceCommitRevision': state['commit_revision'],
                          'committedRevision': revision,
                          'engine': 'postgres_exact_sql',
                          'planningPolicy':policy_evidence}
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
                finalized = db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s AND claimant=%s
                    AND lease_until>clock_timestamp()''',
                    (revision, Jsonb(result), scope.workspace_id,
                     scope.application_id, claim['job_id'],
                     claim['claim_generation'], claim['claimant']))
                if finalized.rowcount != 1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
