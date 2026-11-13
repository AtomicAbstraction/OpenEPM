"""Full-method parent sum of pinned translated source generations.

This bounded stage takes every active direct child and, where present, the
parent's own identity-translated source at one parent, period and account. It
never mixes raw local-currency facts with translated results and does not
claim NCI, eliminations, CTA or an accounting-policy-certified close.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
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
from .postgres_source_batch import PostgresSourceBatch
from .postgres_consolidation_stages import (
    BASE_TRANSLATED_STAGES, TRANSLATED_STAGES, ACQUISITION_LAYERS, ACQUISITION_OWN_STAGES)
from .postgres_consolidation_full import enforce_consolidation_target_policy
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION = 'consolidation.full.translated.aggregate'
PREVIOUS_COMPILER = 'consolidation-full-translated-v4'
PREVIOUS_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 4,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_translated_generations',
    'outputGrain': 'one_parent_translated_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'parentSource': 'explicit_pinned_identity_translation_or_absent',
    'nestedSource': 'pinned_full_or_calculation_fx_for_nonleaf_child',
    'accountingStage': 'pre_nci_translated_uneliminated'})
LAYERED_COMPILER = 'consolidation-full-translated-v5'
LAYERED_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 5,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'all_direct_child_translated_generations',
    'outputGrain': 'one_parent_translated_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'parentSource': 'explicit_pinned_identity_translation_or_absent',
    'nestedSource': 'pinned_stage_matched_full_or_calculation_fx',
    'accountingStage': 'source_layer_specific_pre_nci_translated'})
ACQUISITION_COMPILER = 'consolidation-full-translated-v6'
ACQUISITION_PLAN_DIGEST = _canonical_digest({
    'function':FUNCTION,'loweringVersion':6,
    'engine':'postgres_exact_sql',
    'inputGrain':'all_direct_child_translated_generations',
    'outputGrain':'one_parent_translated_coordinate',
    'sourceStages':TRANSLATED_STAGES,
    'nestedSource':'pinned_stage_matched_full_or_calculation_fx',
    'parentSource':'layered_parent_effects_rejected'})
COMPILER = 'consolidation-full-translated-v7'
PLAN_DIGEST = _canonical_digest({'function':FUNCTION,'loweringVersion':7,
    'engine':'postgres_exact_sql','sourceStages':TRANSLATED_STAGES,
    'ownSourcePolicy':'explicit_layered_fx_v1','ownStages':ACQUISITION_OWN_STAGES})
_SOURCE_STAGES = TRANSLATED_STAGES
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')
_ROLES = {'Scenario','Year','Period','Entity','Account','Value','Currency'}


def _id(value: object) -> str:
    if (not isinstance(value,str) or not 1 <= len(value) <= 200
            or value != value.strip() or '\x00' in value):
        raise ValueError('TRANSLATED_AGGREGATE_ID_INVALID')
    return value


@dataclass(frozen=True,slots=True)
class TranslatedFullPlan:
    parent_members: tuple[tuple[str,str], ...]
    target_currency_member_id: str
    scenario_id: str
    year_id: str
    period_id: str
    pins: tuple[tuple[str,str,str,int], ...]
    parent_translation: tuple[str,str,int] | None
    result_key: str
    expected_publication_revision: int
    source_layer: str = 'translated_full'
    legacy: bool = False
    layered_own: bool = False

    @property
    def accounting_stage(self) -> str:
        return _SOURCE_STAGES[self.source_layer]

    @property
    def parent(self) -> Coordinate:
        return Coordinate.from_mapping(dict(self.parent_members))

    @property
    def normalized_program(self) -> dict:
        program = {'version':2,'function':FUNCTION,
            'parentMembers':dict(self.parent_members),
            'targetCurrencyMemberId':self.target_currency_member_id,
            'scenarioId':self.scenario_id,'yearId':self.year_id,
            'periodId':self.period_id,
            'decisions':[{'relationshipId':relationship_id,
                'method':'Full','controlConfirmed':True,
                'resultKey':result_key,'generationId':generation_id,
                'publishedRevision':revision}
                for relationship_id,result_key,generation_id,revision
                in self.pins],
            'parentTranslation': ({'resultKey':
                self.parent_translation[0],
                'generationId':self.parent_translation[1],
                'publishedRevision':self.parent_translation[2]}
                if self.parent_translation else None),
            'resultKey':self.result_key,
            'expectedPublicationRevision':self.expected_publication_revision,
            'inputGrain':'all_direct_child_translated_generations',
            'outputGrain':'one_parent_translated_coordinate',
            'accountingStage':self.accounting_stage}
        if not self.legacy:
            program['sourceLayer'] = self.source_layer
        if self.layered_own: program['ownSourcePolicy']='explicit_layered_fx_v1'
        return program


def compile_translated_full(raw: object, *,
                            expected_publication_revision: int
                            ) -> TranslatedFullPlan:
    if (not isinstance(raw,dict)
            or set(raw) != {'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != FUNCTION
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('TRANSLATED_AGGREGATE_PROGRAM_INVALID')
    args=raw['arguments']
    required = {'parentMembers','targetCurrencyMemberId',
                     'scenarioId','yearId','periodId','decisions',
                     'parentTranslation',
                     'resultKey'}
    if (set(args) not in (required, required | {'sourceLayer'},required|{'sourceLayer','ownSourcePolicy'})
            or ('ownSourcePolicy' in args and (args['ownSourcePolicy']!='explicit_layered_fx_v1' or not isinstance(args.get('sourceLayer'),str) or args.get('sourceLayer') not in ACQUISITION_LAYERS))
            or not isinstance(args.get('sourceLayer','translated_full'),str)
            or args.get('sourceLayer','translated_full') not in _SOURCE_STAGES
            or not isinstance(args['parentMembers'],dict)
            or not 1 <= len(args['parentMembers']) <= 32
            or not isinstance(args['decisions'],list)
            or not 1 <= len(args['decisions']) <= 200
            or not isinstance(args['resultKey'],str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0):
        raise ValueError('TRANSLATED_AGGREGATE_ARGUMENTS_INVALID')
    parent=Coordinate.from_mapping(args['parentMembers'])
    pins=[]
    for item in args['decisions']:
        if (not isinstance(item,dict)
                or set(item) != {'relationshipId','method',
                    'controlConfirmed','resultKey','generationId',
                    'publishedRevision'}
                or item['method'] != 'Full'
                or item['controlConfirmed'] is not True
                or not isinstance(item['resultKey'],str)
                or not _KEY.fullmatch(item['resultKey'])
                or not isinstance(item['generationId'],str)
                or not _JOB.fullmatch(item['generationId'])
                or type(item['publishedRevision']) is not int
                or item['publishedRevision'] <= 0):
            raise ValueError('TRANSLATED_AGGREGATE_DECISION_INVALID')
        pins.append((_id(item['relationshipId']),item['resultKey'],
                     item['generationId'],item['publishedRevision']))
    pins.sort()
    if (len({item[0] for item in pins}) != len(pins)
            or any(item[1] == args['resultKey'] for item in pins)):
        raise ValueError('TRANSLATED_AGGREGATE_DUPLICATE_OR_CYCLIC_PIN')
    parent_pin=args['parentTranslation']
    if parent_pin is not None:
        if (not isinstance(parent_pin,dict)
                or set(parent_pin) != {'resultKey','generationId',
                                       'publishedRevision'}
                or not isinstance(parent_pin['resultKey'],str)
                or not _KEY.fullmatch(parent_pin['resultKey'])
                or parent_pin['resultKey'] == args['resultKey']
                or not isinstance(parent_pin['generationId'],str)
                or not _JOB.fullmatch(parent_pin['generationId'])
                or type(parent_pin['publishedRevision']) is not int
                or parent_pin['publishedRevision'] <= 0):
            raise ValueError('TRANSLATED_AGGREGATE_PARENT_PIN_INVALID')
        parent_pin=(parent_pin['resultKey'],parent_pin['generationId'],
                    parent_pin['publishedRevision'])
    return TranslatedFullPlan(tuple(parent.members),
        _id(args['targetCurrencyMemberId']),
        _id(args['scenarioId']),_id(args['yearId']),
        _id(args['periodId']),tuple(pins),parent_pin,args['resultKey'],
        expected_publication_revision,
        args.get('sourceLayer','translated_full'),False,'ownSourcePolicy' in args)


def decode_translated_full(raw: object) -> TranslatedFullPlan:
    required = {'version','function','parentMembers',
                'targetCurrencyMemberId','scenarioId','yearId','periodId',
                'decisions','parentTranslation','resultKey',
                'expectedPublicationRevision',
                'inputGrain','outputGrain','accountingStage'}
    if (not isinstance(raw,dict)
            or set(raw) not in (required,required | {'sourceLayer'},required|{'sourceLayer','ownSourcePolicy'})
            or raw['version'] != 2 or raw['function'] != FUNCTION
            or raw['inputGrain'] !=
                'all_direct_child_translated_generations'
            or raw['outputGrain'] != 'one_parent_translated_coordinate'
            or raw['accountingStage'] not in _SOURCE_STAGES.values()):
        raise ValueError('UNSUPPORTED_TRANSLATED_AGGREGATE_JOB_PROGRAM')
    legacy = 'sourceLayer' not in raw
    plan=compile_translated_full({'languageVersion':2,'function':FUNCTION,
        'arguments':{key:raw[key] for key in (
            'parentMembers','targetCurrencyMemberId','scenarioId',
            'yearId','periodId','decisions','parentTranslation',
            'resultKey')} | ({'sourceLayer':raw['sourceLayer']}
                           if not legacy else {}) | ({'ownSourcePolicy':raw['ownSourcePolicy']} if 'ownSourcePolicy' in raw else {})},
        expected_publication_revision=raw['expectedPublicationRevision'])
    if legacy:
        plan = replace(plan,legacy=True)
    if plan.normalized_program != raw:
        raise ValueError('NONCANONICAL_TRANSLATED_AGGREGATE_JOB_PROGRAM')
    return plan


def validate_translated_full(db, scope: ApplicationScope,
                             plan: TranslatedFullPlan) -> dict:
    keys=(scope.workspace_id,scope.application_id)
    dimensions=db.execute('''SELECT dimension_id,model_role
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND status='Active' ''',keys).fetchall()
    roles={}
    fact_axes=set()
    for row in dimensions:
        if row['model_role'] != 'Currency':
            fact_axes.add(row['dimension_id'])
        if row['model_role'] in _ROLES:
            if row['model_role'] in roles:
                raise ValueError('TRANSLATED_AGGREGATE_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']]=row['dimension_id']
    if set(roles) != _ROLES:
        raise ValueError('TRANSLATED_AGGREGATE_FINANCIAL_MODEL_REQUIRED')
    parent=dict(plan.parent_members)
    if set(parent) != fact_axes:
        raise ValueError('TRANSLATED_AGGREGATE_COORDINATE_GRAIN_INVALID')
    for role,expected in (('Scenario',plan.scenario_id),
                          ('Year',plan.year_id),('Period',plan.period_id)):
        if parent[roles[role]] != expected:
            raise ValueError('TRANSLATED_AGGREGATE_CONTEXT_MISMATCH')
    PostgresSourceBatch._check_scope_members(db,scope,parent)
    account=parent[roles['Account']]
    if db.execute('''SELECT 1 FROM epm.relationship
        WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND parent_member_id=%s
        AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
        (*keys,roles['Account'],account)).fetchone():
        raise ValueError('TRANSLATED_AGGREGATE_ACCOUNT_LEAF_REQUIRED')
    currency=db.execute('''SELECT name FROM epm.member
        WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND member_id=%s AND status='Active' ''',
        (*keys,roles['Currency'],plan.target_currency_member_id)).fetchone()
    parent_entity=db.execute('''SELECT entity_default_currency_member_id
        FROM epm.member WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND member_id=%s AND status='Active' ''',
        (*keys,roles['Entity'],parent[roles['Entity']])).fetchone()
    value=db.execute('''SELECT name FROM epm.member
        WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND member_id=%s AND status='Active' ''',
        (*keys,roles['Value'],parent[roles['Value']])).fetchone()
    if (currency is None or parent_entity is None or value is None
            or parent_entity['entity_default_currency_member_id'] !=
                plan.target_currency_member_id
            or value['name'].lower() not in (
                currency['name'].lower(),
                '['+currency['name'].lower()+']')):
        raise ValueError('TRANSLATED_AGGREGATE_PARENT_CURRENCY_INVALID')
    if db.execute('''SELECT 1 FROM epm.numeric_cell_current n
        JOIN epm.coordinate c USING (
            workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s AND n.present''',
        (*keys,plan.parent.series_key)).fetchone():
        raise ValueError('TRANSLATED_AGGREGATE_PARENT_RAW_NOT_DECLARED')
    if db.execute('''SELECT 1 FROM epm.text_cell_current t
        JOIN epm.coordinate c USING (
            workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s AND t.present''',
        (*keys,plan.parent.series_key)).fetchone():
        raise ValueError('TRANSLATED_AGGREGATE_PARENT_TEXT_UNSUPPORTED')
    state=db.execute('''SELECT currency_settings,metadata_revision
        FROM epm.application_state WHERE workspace_id=%s
        AND application_id=%s''',keys).fetchone()
    settings=state['currency_settings'] if state else None
    if (settings is None or settings.get('validatedMetadataRevision') !=
            state['metadata_revision']):
        raise ValueError('CURRENCY_SETTINGS_METADATA_STALE')
    parent_local={**parent,
        roles['Value']:settings['entityCurrencyValueMemberId']}
    local_coordinate=Coordinate.from_mapping(parent_local)
    local=db.execute('''SELECT c.members,n.present AS numeric_present,
        t.present AS text_present FROM epm.coordinate c
        LEFT JOIN epm.numeric_cell_current n USING (
            workspace_id,application_id,coordinate_id)
        LEFT JOIN epm.text_cell_current t USING (
            workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s''',
        (*keys,local_coordinate.series_key)).fetchone()
    if local is not None and local['members'] != parent_local:
        raise ValueError('COORDINATE_HASH_COLLISION')
    if local is not None and local['text_present']:
        raise ValueError('TRANSLATED_AGGREGATE_PARENT_TEXT_UNSUPPORTED')
    has_parent_source=bool(local and local['numeric_present'])
    if plan.layered_own:
        from .postgres_own_source import resolve_own_source
        local_fact=db.execute("""SELECT c.coordinate_id,n.amount,n.present AS numeric_present,n.change_id
            FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n
            USING(workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s""",
            (*keys,local_coordinate.series_key)).fetchone()
        account_type=db.execute("""SELECT financial_account_type FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND member_id=%s""",(*keys,roles['Account'],parent[roles['Account']])).fetchone()['financial_account_type']
        try:
            resolve_own_source(db,scope,parent_local,local_fact,plan.source_layer,
                plan.target_currency_member_id,account_type,parent[roles['Entity']] if 'ic_elimination' in plan.source_layer else None)
            has_parent_source=True
        except ValueError as error:
            if str(error)!='CURRENCY_TRANSLATION_SOURCE_MISSING': raise
            has_parent_source=False
    else:
        if plan.source_layer in ACQUISITION_LAYERS:
            tables=['acquisition_journal_line']
            if 'manual_journal' in plan.source_layer:
                tables.append('manual_journal_line')
            for table in tables:
                if db.execute(f"""SELECT 1 FROM epm.{table} l
                    JOIN epm.coordinate c USING (workspace_id,application_id,coordinate_id)
                    WHERE c.workspace_id=%s AND c.application_id=%s
                    AND c.series_key=%s LIMIT 1""",
                    (*keys,local_coordinate.series_key)).fetchone():
                    raise ValueError('TRANSLATED_AGGREGATE_LAYERED_PARENT_UNSUPPORTED')
        if plan.source_layer != 'translated_full' and has_parent_source:
            raise ValueError('TRANSLATED_AGGREGATE_LAYERED_PARENT_UNSUPPORTED')
    if has_parent_source and plan.parent_translation is None:
        raise ValueError('TRANSLATED_AGGREGATE_PARENT_SOURCE_REQUIRED')
    if not has_parent_source and plan.parent_translation is not None:
        raise ValueError('TRANSLATED_AGGREGATE_PARENT_SOURCE_UNAVAILABLE')
    # One relational read resolves every active direct placement and its
    # period-specific Full-method ownership inputs.
    rows=db.execute('''SELECT r.relationship_id,r.child_member_id,
        child.status AS child_status,
        child.entity_default_currency_member_id,
        EXISTS (SELECT 1 FROM epm.relationship descendant
          WHERE descendant.workspace_id=r.workspace_id
          AND descendant.application_id=r.application_id
          AND descendant.dimension_id=r.dimension_id
          AND descendant.parent_member_id=r.child_member_id
          AND descendant.hierarchy_id=r.hierarchy_id AND descendant.status='Active') AS child_has_descendants,
        (SELECT count(*) FROM epm.relationship other
          WHERE other.workspace_id=r.workspace_id
          AND other.application_id=r.application_id
          AND other.dimension_id=r.dimension_id
          AND other.child_member_id=r.child_member_id
          AND other.hierarchy_id=r.hierarchy_id AND other.status='Active') AS parent_count,
        pown.amount AS pown,pcon.amount AS pcon,
        active.amount AS active_value,method.amount AS method_value
        FROM epm.relationship r JOIN epm.member child
          ON child.workspace_id=r.workspace_id
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
        WHERE r.workspace_id=%s AND r.application_id=%s
        AND r.dimension_id=%s AND r.parent_member_id=%s
        AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active' ORDER BY r.relationship_id LIMIT 201''',
        (plan.scenario_id,plan.year_id,plan.period_id)*4+
        (*keys,roles['Entity'],parent[roles['Entity']])).fetchall()
    if not 1 <= len(rows) <= 200:
        raise ValueError('TRANSLATED_AGGREGATE_PLACEMENT_LIMIT')
    if tuple(row['relationship_id'] for row in rows) != (
            tuple(item[0] for item in plan.pins)):
        raise ValueError('TRANSLATED_AGGREGATE_RELATIONSHIP_COVERAGE')
    if len({row['child_member_id'] for row in rows}) != len(rows):
        raise ValueError('TRANSLATED_AGGREGATE_DUPLICATE_CHILD')
    by_relationship={row['relationship_id']:row for row in rows}
    for row in rows:
        if row['child_status'] != 'Active' or row[
                'entity_default_currency_member_id'] is None:
            raise ValueError('TRANSLATED_AGGREGATE_CHILD_CURRENCY_REQUIRED')
        if row['parent_count'] != 1:
            raise ValueError('TRANSLATED_AGGREGATE_AMBIGUOUS_PLACEMENT')
        if row['method_value'] is not None:
            raise ValueError('TRANSLATED_AGGREGATE_METHOD_CODE_UNMAPPED')
        if row['active_value'] == 0:
            raise ValueError('TRANSLATED_AGGREGATE_PERIOD_INACTIVE')
        if row['pown'] is None:
            raise ValueError('TRANSLATED_AGGREGATE_POWN_REQUIRED')
        if row['pcon'] is not None and row['pcon'] != 100:
            raise ValueError('TRANSLATED_AGGREGATE_FULL_PCON_REQUIRED')
    requested=[{'relationship_id':rel,'result_key':key,
        'generation_id':generation,'published_revision':revision}
        for rel,key,generation,revision in plan.pins]
    if plan.parent_translation is not None:
        key,generation,revision=plan.parent_translation
        requested.append({'relationship_id':'__parent__',
            'result_key':key,'generation_id':generation,
            'published_revision':revision})
    pins=db.execute('''SELECT input.relationship_id,input.result_key,
        input.generation_id,input.published_revision,
        p.source_operation_id AS current_generation_id,
        p.committed_revision AS current_published_revision,
        p.source_function AS function_name,
        p.result_key AS generation_result_key,
        p.row_count,p.source_commit_revision,
        r.amount,r.source_change_id,c.members,
        j.status AS job_status,j.result AS job_result,
        j.expected_metadata_revision,j.expected_data_revision,
        j.expected_policy_revision,
        s.metadata_revision AS current_metadata_revision,
        s.data_revision AS current_data_revision,
        s.policy_revision AS current_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
          relationship_id text,result_key text,generation_id text,
          published_revision bigint)
        LEFT JOIN epm.calculation_result_state p ON
          p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=input.result_key
        LEFT JOIN epm.calculation_result_current r ON
          r.workspace_id=p.workspace_id
          AND r.application_id=p.application_id
          AND r.result_key=p.result_key
        LEFT JOIN epm.coordinate c ON
          c.workspace_id=r.workspace_id
          AND c.application_id=r.application_id
          AND c.coordinate_id=r.coordinate_id
        LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
          AND j.application_id=p.application_id
          AND j.job_id=p.source_operation_id
        JOIN epm.application_state s ON s.workspace_id=%s
          AND s.application_id=%s
        ORDER BY input.relationship_id''',
        (Jsonb(requested),*keys,*keys)).fetchall()
    if len(pins) != len(requested):
        raise ValueError('TRANSLATED_AGGREGATE_SOURCE_UNAVAILABLE')
    sources=[]
    for pin in pins:
        if pin['relationship_id'] == '__parent__':
            receipt=pin['job_result']
            if (pin['current_generation_id'] != pin['generation_id']
                    or pin['current_published_revision'] !=
                        pin['published_revision']):
                raise ValueError('STALE_PUBLISHED_INPUT')
            if (pin['function_name'] != 'currency.translation.publish'
                    or pin['generation_result_key'] != pin['result_key']
                    or pin['row_count'] != 1 or pin['amount'] is None
                    or pin['source_change_id'] is None
                    or pin['members'] != parent
                    or pin['job_status'] != 'published'
                    or not isinstance(receipt,dict)
                    or receipt.get('accountingStage') !=
                        (ACQUISITION_OWN_STAGES[plan.source_layer] if plan.layered_own else 'translated_unreviewed')
                    or (plan.layered_own and (receipt.get('sourceLayer')!=plan.source_layer or
                        receipt.get('icParentEntityId')!=(parent[roles['Entity']] if 'ic_elimination' in plan.source_layer else None)))
                    or receipt.get('accountingPolicyStatus') != 'Unreviewed'
                    or receipt.get('sourceMembers') != parent_local
                    or receipt.get('targetMembers') != parent
                    or receipt.get('fromCurrencyMemberId') !=
                        plan.target_currency_member_id
                    or receipt.get('toCurrencyMemberId') !=
                        plan.target_currency_member_id):
                raise ValueError('TRANSLATED_AGGREGATE_PARENT_SOURCE_UNSUPPORTED')
            if any(pin['expected_'+kind+'_revision'] !=
                   pin['current_'+kind+'_revision']
                   for kind in ('metadata','data','policy')):
                raise ValueError('TRANSLATED_AGGREGATE_SOURCE_STALE')
            sources.append({'relationshipId':None,'parentSource':True,
                'parentEntityId':parent[roles['Entity']],
                'resultKey':pin['result_key'],
                'generationId':pin['generation_id'],
                'publishedRevision':pin['published_revision'],
                'sourceCommitRevision':pin['source_commit_revision'],
                'sourceChangeId':pin['source_change_id'],
                'amount':format(pin['amount'],'.8f')})
            continue
        relationship=by_relationship[pin['relationship_id']]
        expected={**parent,
                  roles['Entity']:relationship['child_member_id']}
        expected_source={**expected,
            roles['Value']:settings['entityCurrencyValueMemberId']}
        receipt=pin['job_result']
        if (pin['current_generation_id'] != pin['generation_id']
                or pin['current_published_revision'] !=
                    pin['published_revision']):
            raise ValueError('STALE_PUBLISHED_INPUT')
        nested=relationship['child_has_descendants']
        if plan.source_layer != 'translated_full' and not nested and not plan.layered_own:
            raise ValueError('TRANSLATED_AGGREGATE_LAYERED_LEAF_UNSUPPORTED')
        cross_currency=(relationship[
            'entity_default_currency_member_id']!=
            plan.target_currency_member_id)
        expected_function=(
            'currency.calculation.translation.publish'
            if nested and cross_currency else
            FUNCTION if nested else 'currency.translation.publish')
        expected_stage=(plan.accounting_stage if nested else
                        ACQUISITION_OWN_STAGES[plan.source_layer] if plan.layered_own else 'translated_unreviewed')
        if (pin['function_name'] != expected_function
                or pin['generation_result_key'] != pin['result_key']
                or pin['row_count'] != 1 or pin['amount'] is None
                or pin['source_change_id'] is None
                or pin['members'] != expected
                or pin['job_status'] != 'published'
                or not isinstance(receipt,dict)
                or receipt.get('accountingStage') != expected_stage
                or (plan.layered_own and not nested and (receipt.get('sourceLayer')!=plan.source_layer or
                    receipt.get('icParentEntityId')!=(parent[roles['Entity']] if 'ic_elimination' in plan.source_layer else None)))
                or (nested and receipt.get('sourceLayer',
                    'translated_full') != plan.source_layer)
                or receipt.get('accountingPolicyStatus') != 'Unreviewed'
                or (receipt.get('parentMembers') != expected
                    if nested and not cross_currency else
                    (receipt.get('targetMembers') != expected or
                     receipt.get('fromCurrencyMemberId') !=
                        relationship['entity_default_currency_member_id'] or
                     receipt.get('toCurrencyMemberId') !=
                        plan.target_currency_member_id or
                     (receipt.get('sourceMembers') != expected_source
                      if not nested else
                      not isinstance(receipt.get('sourceMembers'),dict) or
                      {axis:member for axis,member in receipt[
                          'sourceMembers'].items() if axis!=roles['Value']}
                          != {axis:member for axis,member in expected.items()
                              if axis!=roles['Value']})))):
            raise ValueError('TRANSLATED_AGGREGATE_SOURCE_UNSUPPORTED')
        if any(pin['expected_'+kind+'_revision'] !=
               pin['current_'+kind+'_revision']
               for kind in ('metadata','data','policy')):
            raise ValueError('TRANSLATED_AGGREGATE_SOURCE_STALE')
        sources.append({'relationshipId':pin['relationship_id'],
            'childEntityId':relationship['child_member_id'],
            'pown':format(relationship['pown'],'.8f'),
            'effectivePcon':'100.00000000',
            'pconFallback':relationship['pcon'] is None,
            'resultKey':pin['result_key'],
            'generationId':pin['generation_id'],
            'publishedRevision':pin['published_revision'],
            'sourceCommitRevision':pin['source_commit_revision'],
            'sourceChangeId':pin['source_change_id'],
            'sourceFunction':expected_function,
            'amount':format(pin['amount'],'.8f')})
    if any(row['child_has_descendants'] for row in rows):
        from .postgres_calculation_status import published_translation_status
        status=published_translation_status(db,scope,plan.normalized_program)
        if not status['matchesAtRead']:
            raise ValueError('STALE_PUBLISHED_INPUT')
    total=db.execute('''SELECT sum(value)::numeric(28,8) AS amount
        FROM unnest(%s::numeric[]) AS selected(value)''',
        ([Decimal(source['amount']) for source in sources],)
        ).fetchone()['amount']
    NumericCell(True,total,'')
    if total != sum((Decimal(source['amount']) for source in sources),
                    Decimal(0)):
        raise ValueError('TRANSLATED_AGGREGATE_SOURCE_SUM_CHANGED')
    return {'target':plan.parent,'amount':total,'sources':sources,
        'sourceChangeId':_canonical_digest({'sources':sources}),
        'parentEntityId':parent[roles['Entity']]}


def supported_translated_full_compiler(version,digest,program):
    if not isinstance(program,dict): return False
    layer=program.get('sourceLayer','translated_full')
    if not isinstance(layer,str) or layer not in _SOURCE_STAGES: return False
    legacy='sourceLayer' not in program
    return ((version==COMPILER and digest==PLAN_DIGEST and not legacy) or
        (version==ACQUISITION_COMPILER and digest==ACQUISITION_PLAN_DIGEST
            and not legacy and 'ownSourcePolicy' not in program) or
        (version==LAYERED_COMPILER and digest==LAYERED_PLAN_DIGEST
            and not legacy and layer in BASE_TRANSLATED_STAGES and 'ownSourcePolicy' not in program) or
        (version==PREVIOUS_COMPILER and digest==PREVIOUS_PLAN_DIGEST
            and legacy and layer=='translated_full'))


def enforce_translated_full_dimensional_security(
        db, identity, scope, plan, summary):
    """Authorize every pinned translated input and the exact parent output."""
    target = summary.get('target') if isinstance(summary, dict) else None
    sources = summary.get('sources') if isinstance(summary, dict) else None
    if (not isinstance(target, Coordinate) or not isinstance(sources, list)
            or not sources or target != plan.parent):
        raise ValueError(
            'TRANSLATED_AGGREGATE_SECURITY_COORDINATES_INVALID')
    rows = db.execute('''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role='Entity' ORDER BY dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()
    if len(rows) != 1:
        raise ValueError(
            'TRANSLATED_AGGREGATE_SECURITY_COORDINATES_INVALID')
    entity_axis = rows[0]['dimension_id']
    parent = dict(plan.parent_members)
    reads = {}
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError(
                'TRANSLATED_AGGREGATE_SECURITY_COORDINATES_INVALID')
        if source.get('parentSource') is True:
            members = parent
        else:
            child = source.get('childEntityId')
            if not isinstance(child, str) or not child:
                raise ValueError(
                    'TRANSLATED_AGGREGATE_SECURITY_COORDINATES_INVALID')
            members = {**parent, entity_axis: child}
        coordinate = Coordinate.from_mapping(members)
        reads[coordinate.series_key] = coordinate
    authorize_coordinates(
        db, identity, scope, reads.values(), kind=AccessKind.READ)
    authorize_coordinates(
        db, identity, scope, (target,), kind=AccessKind.WRITE)


class PostgresTranslatedFullPublisher:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim,dict)
                or not isinstance(claim.get('workspace_id'),str)
                or not isinstance(claim.get('application_id'),str)
                or not isinstance(claim.get('job_id'),str)
                or not _JOB.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'),str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT a.status AS application_status,
                    s.processing_mode,s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                job=db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                unexpired=db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']
                        or not unexpired):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['function_name']!=FUNCTION
                        or not supported_translated_full_compiler(job['compiler_version'],
                            job['plan_digest'],job['normalized_program'])
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_TRANSLATED_AGGREGATE_JOB')
                plan=decode_translated_full(job['normalized_program'])
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(state[k]!=job['expected_'+k]
                       for k in ('metadata_revision','data_revision',
                                 'policy_revision')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer=db.execute('''SELECT committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (*keys,plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0) != (
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                summary=validate_translated_full(db,scope,plan)
                enforce_translated_full_dimensional_security(
                    db, self.identity, scope, plan, summary)
                target=summary['target']
                final_state=db.execute('''SELECT a.status AS application_status,
                    s.processing_mode,s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',keys).fetchone()
                final_job=db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (*keys,claim['job_id'])).fetchone()
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
                        or final_job['claim_generation']!=claim['claim_generation']
                        or final_job['claimant']!=claim['claimant']
                        or not final_live):
                    raise ValueError('STALE_WORKER_FENCE')
                final_access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=FUNCTION)
                if (final_state['application_status']!='Active'
                        or final_state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(final_state[k]!=job['expected_'+k]
                       for k in ('metadata_revision','data_revision',
                                 'policy_revision')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                final_pointer=db.execute('''SELECT committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',(*keys,plan.result_key)).fetchone()
                if (final_pointer['published_revision']
                        if final_pointer else 0)!=(
                            plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                final_summary = validate_translated_full(db,scope,plan)
                enforce_translated_full_dimensional_security(
                    db, self.identity, scope, plan, final_summary)
                if final_summary!=summary:
                    raise ValueError('TRANSLATED_AGGREGATE_SOURCE_CHANGED')
                policy_evidence=enforce_consolidation_target_policy(
                    db,scope,target,final_access.role)
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (*keys,target.series_key,Jsonb(dict(target.members))))
                point=db.execute('''SELECT coordinate_id,members
                    FROM epm.coordinate WHERE workspace_id=%s
                    AND application_id=%s AND series_key=%s''',
                    (*keys,target.series_key)).fetchone()
                if point['members'] != dict(target.members):
                    raise ValueError('COORDINATE_HASH_COLLISION')
                db.execute('''INSERT INTO epm.coordinate_member_projection
                    (workspace_id,application_id,coordinate_id,
                     dimension_id,member_id,projection_generation)
                    SELECT %s,%s,%s,item.key,item.value,(SELECT epm.active_projection_generation())
                    FROM jsonb_each_text(%s::jsonb) item
                    ON CONFLICT DO NOTHING''',
                    (*keys,point['coordinate_id'],
                     Jsonb(dict(target.members))))
                revision=final_state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_operation_staging
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',
                    (*keys,claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],FUNCTION,revision))
                db.execute('''INSERT INTO epm.calculation_result_staging
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_amount,source_change_id,amount)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],point['coordinate_id'],
                     summary['amount'],summary['sourceChangeId'],
                     summary['amount']))
                from .postgres_current_result_publication import advance_result_head_during_conversion
                advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                result={'generationId':claim['job_id'],
                    'resultKey':plan.result_key,'function':FUNCTION,
                    'rowCount':1,'parentMembers':dict(plan.parent_members),
                    'parentEntityId':summary['parentEntityId'],
                    'targetCurrencyMemberId':plan.target_currency_member_id,
                    **({'sourceLayer':plan.source_layer}
                       if not plan.legacy else {}),
                    'sources':summary['sources'],
                    'sourceChangeId':summary['sourceChangeId'],
                    'amount':format(summary['amount'],'.8f'),
                    'accountingStage':plan.accounting_stage,
                    'accountingPolicyStatus':'Unreviewed',
                    'sourceCommitRevision':state['commit_revision'],
                    'committedRevision':revision,
                    'engine':'postgres_exact_sql',
                    'planningPolicy':policy_evidence}
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=plan.result_key,
                    existed=final_pointer is not None)
                result['impactDigest']=impact.digest
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',(revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],job['program_digest'],
                     job['subject_id'],revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                finalized=db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s
                    AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision,Jsonb(result),*keys,claim['job_id'],
                     claim['claim_generation'],claim['claimant'])).rowcount
                if finalized!=1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
