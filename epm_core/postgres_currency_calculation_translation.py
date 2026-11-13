"""Translate pinned lower Full generations into a parent's Value currency.

PVA consumes every fiscal-period cumulative lower Full result. VAL consumes
the current period only. This is an Unreviewed pre-NCI calculation stage.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from decimal import Decimal
from fractions import Fraction
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_calculation_status import (published_translation_status,
    published_child_status)
from .postgres_currency_rates import PostgresCurrencyRates, FUNCTION as RATE
from .postgres_currency_translation import _fixed8, _rational
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_currency_publication import enforce_currency_target_policy
from .postgres_source_batch import PostgresSourceBatch
from .postgres_consolidation_stages import (
    BASE_TRANSLATED_STAGES, TRANSLATED_STAGES, ACQUISITION_LOCAL_STAGES)
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION='currency.calculation.translation.publish'
PREVIOUS_COMPILER='currency-calculation-translation-v1'
PREVIOUS_PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'loweringVersion':1,
    'engine':'postgres_exact_rational',
    'source':'pinned_full_generations_by_fiscal_period',
    'outputGrain':'one_translated_calculation_coordinate',
    'accountingStage':'pre_nci_translated_uneliminated'})
SECOND_COMPILER='currency-calculation-translation-v2'
SECOND_PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'loweringVersion':2,
    'engine':'postgres_exact_rational',
    'sources':['translated_full','raw_plus_ic_elimination',
               'raw_plus_manual_journal_plus_ic_elimination'],
    'outputGrain':'one_translated_calculation_coordinate',
    'accountingStage':'source_layer_specific_pre_nci_translated'})
THIRD_COMPILER='currency-calculation-translation-v3'
THIRD_PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'loweringVersion':3,
    'engine':'postgres_exact_rational',
    'sourceLayer':'source_layer_specific_pre_nci_translated',
    'sourceBasis':['local_full','translated_full'],
    'outputGrain':'one_translated_calculation_coordinate'})
COMPILER='currency-calculation-translation-v4'
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'loweringVersion':4,
    'engine':'postgres_exact_rational','sourceStages':TRANSLATED_STAGES,
    'sourceBasis':['local_full','translated_full'],
    'outputGrain':'one_translated_calculation_coordinate'})
_SOURCE_STAGES=TRANSLATED_STAGES
_LOCAL_STAGES={
    'raw_plus_ic_elimination':'pre_nci_untranslated_ic_adjusted',
    'raw_plus_manual_journal_plus_ic_elimination':'pre_nci_untranslated_journal_ic_adjusted',
    **ACQUISITION_LOCAL_STAGES}
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB=re.compile(r'[0-9a-f]{32}\Z')
_ROLES={'Currency','Value','Entity','Account','View','Year','Period'}


def _id(value: object) -> str:
    if (not isinstance(value,str) or not 1<=len(value)<=200
            or value!=value.strip() or '\x00' in value):
        raise ValueError('CALCULATION_TRANSLATION_ID_INVALID')
    return value


@dataclass(frozen=True,slots=True)
class CalculationTranslationPlan:
    source_members: tuple[tuple[str,str],...]
    from_currency: str
    to_currency: str
    rate_kind: str
    method: str
    target_value_member_id: str
    pins: tuple[tuple[str,str,str,int],...]
    result_key: str
    expected_publication_revision: int
    source_layer: str = 'translated_full'
    source_basis: str = 'translated_full'
    translation_format_level: int = 3

    @property
    def accounting_stage(self) -> str:
        return _SOURCE_STAGES[self.source_layer]

    @property
    def normalized_program(self) -> dict:
        program={'version':2,'function':FUNCTION,
            'sourceMembers':dict(self.source_members),
            'fromCurrencyMemberId':self.from_currency,
            'toCurrencyMemberId':self.to_currency,
            'rateKind':self.rate_kind,'method':self.method,
            'targetValueMemberId':self.target_value_member_id,
            'periodPins':[{'periodId':period,'resultKey':key,
                'generationId':generation,'publishedRevision':revision}
                for period,key,generation,revision in self.pins],
            'resultKey':self.result_key,
            'expectedPublicationRevision':self.expected_publication_revision,
            'accountingStage':self.accounting_stage}
        if self.translation_format_level >= 2:
            program['sourceLayer']=self.source_layer
        if self.translation_format_level >= 3:
            program['sourceBasis']=self.source_basis
        return program


def compile_calculation_translation(raw: object, *,
                                    expected_publication_revision: int
                                    ) -> CalculationTranslationPlan:
    if (not isinstance(raw,dict)
            or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion']!=2 or raw['function']!=FUNCTION
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('CALCULATION_TRANSLATION_PROGRAM_INVALID')
    args=raw['arguments']
    required={'sourceMembers','fromCurrencyMemberId',
                    'toCurrencyMemberId','rateKind','method',
                    'targetValueMemberId','periodPins','resultKey'}
    if (not required <= set(args)
            or set(args)-required not in (
                set(),{'sourceLayer'},{'sourceBasis'},
                {'sourceLayer','sourceBasis'})
            or not isinstance(args['sourceMembers'],dict)
            or not isinstance(args['periodPins'],list)
            or not 1<=len(args['periodPins'])<=120
            or args['rateKind'] not in ('balance','flow')
            or args['method'] not in ('PVA','VAL')
            or not isinstance(args.get('sourceLayer','translated_full'),str)
            or args.get('sourceLayer','translated_full') not in _SOURCE_STAGES
            or args.get('sourceBasis',
                'translated_full' if args.get('sourceLayer',
                    'translated_full')=='translated_full' else
                'local_full') not in ('local_full','translated_full')
            or (args.get('sourceLayer','translated_full')==
                'translated_full' and args.get('sourceBasis',
                    'translated_full')!='translated_full')
            or not isinstance(args['resultKey'],str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision<0):
        raise ValueError('CALCULATION_TRANSLATION_ARGUMENTS_INVALID')
    source=Coordinate.from_mapping(args['sourceMembers'])
    pins=[]
    for item in args['periodPins']:
        if (not isinstance(item,dict)
                or set(item)!={'periodId','resultKey','generationId',
                                'publishedRevision'}
                or not isinstance(item['resultKey'],str)
                or not _KEY.fullmatch(item['resultKey'])
                or item['resultKey']==args['resultKey']
                or not isinstance(item['generationId'],str)
                or not _JOB.fullmatch(item['generationId'])
                or type(item['publishedRevision']) is not int
                or item['publishedRevision']<=0):
            raise ValueError('CALCULATION_TRANSLATION_PIN_INVALID')
        pins.append((_id(item['periodId']),item['resultKey'],
                     item['generationId'],item['publishedRevision']))
    pins.sort()
    if len({item[0] for item in pins})!=len(pins):
        raise ValueError('CALCULATION_TRANSLATION_PIN_DUPLICATE')
    return CalculationTranslationPlan(tuple(source.members),
        _id(args['fromCurrencyMemberId']),
        _id(args['toCurrencyMemberId']),args['rateKind'],args['method'],
        _id(args['targetValueMemberId']),tuple(pins),args['resultKey'],
        expected_publication_revision,args.get('sourceLayer',
            'translated_full'),args.get('sourceBasis',
            'translated_full' if args.get('sourceLayer',
                'translated_full')=='translated_full' else 'local_full'))


def decode_calculation_translation(raw: object) -> CalculationTranslationPlan:
    required={'version','function','sourceMembers',
                'fromCurrencyMemberId','toCurrencyMemberId','rateKind',
                'method','targetValueMemberId','periodPins','resultKey',
                'expectedPublicationRevision','accountingStage'}
    if (not isinstance(raw,dict)
            or set(raw) not in (required,required|{'sourceLayer'},
                                required|{'sourceLayer','sourceBasis'})
            or raw['version']!=2 or raw['function']!=FUNCTION
            or raw['accountingStage'] not in _SOURCE_STAGES.values()):
        raise ValueError('UNSUPPORTED_CALCULATION_TRANSLATION_JOB_PROGRAM')
    translation_format_level=(3 if 'sourceBasis' in raw else
                     2 if 'sourceLayer' in raw else 1)
    plan=compile_calculation_translation({'languageVersion':2,
        'function':FUNCTION,'arguments':{key:raw[key] for key in (
            'sourceMembers','fromCurrencyMemberId','toCurrencyMemberId',
            'rateKind','method','targetValueMemberId','periodPins',
            'resultKey')} | ({'sourceLayer':raw['sourceLayer']}
                          if translation_format_level>=2 else {}) | (
                          {'sourceBasis':raw['sourceBasis']}
                          if translation_format_level>=3 else {})},
        expected_publication_revision=raw['expectedPublicationRevision'])
    plan=replace(plan,translation_format_level=translation_format_level)
    if plan.normalized_program!=raw:
        raise ValueError('NONCANONICAL_CALCULATION_TRANSLATION_JOB_PROGRAM')
    return plan


def validate_calculation_translation(db,scope:ApplicationScope,
                                     plan:CalculationTranslationPlan,
                                     identity:VerifiedIdentity,
                                     dsn:str) -> dict:
    keys=(scope.workspace_id,scope.application_id)
    state=db.execute('''SELECT currency_settings,metadata_revision,
        data_revision,policy_revision,commit_revision
        FROM epm.application_state WHERE workspace_id=%s
        AND application_id=%s''',keys).fetchone()
    settings=state['currency_settings'] if state else None
    if settings is None:
        raise ValueError('CURRENCY_SETTINGS_UNCONFIGURED')
    if settings.get('validatedMetadataRevision')!=state['metadata_revision']:
        raise ValueError('CURRENCY_SETTINGS_METADATA_STALE')
    if plan.method!=settings[
            'balanceMethod' if plan.rate_kind=='balance' else 'flowMethod']:
        raise ValueError('CALCULATION_TRANSLATION_METHOD_CONFLICT')
    dimensions=db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        keys).fetchall()
    roles={}
    fact_axes=set()
    for row in dimensions:
        if row['model_role']!='Currency':
            fact_axes.add(row['dimension_id'])
        if row['model_role'] in _ROLES:
            if row['model_role'] in roles:
                raise ValueError('CURRENCY_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']]=row['dimension_id']
    source=dict(plan.source_members)
    if set(roles)!=_ROLES or set(source)!=fact_axes:
        raise ValueError('CALCULATION_TRANSLATION_COORDINATE_GRAIN_INVALID')
    PostgresSourceBatch._check_scope_members(db,scope,source)
    if source[roles['View']]!=settings['ytdViewMemberId']:
        raise ValueError('CALCULATION_TRANSLATION_VIEW_INVALID')
    metadata=db.execute('''SELECT dimension_id,member_id,name,
        financial_account_type,entity_default_currency_member_id
        FROM epm.member WHERE workspace_id=%s AND application_id=%s
        AND ((dimension_id=%s AND member_id=ANY(%s::text[]))
          OR (dimension_id=%s AND member_id=ANY(%s::text[]))
          OR (dimension_id=%s AND member_id=%s)
          OR (dimension_id=%s AND member_id=%s)) AND status='Active' ''',
        (*keys,roles['Currency'],[plan.from_currency,plan.to_currency],
         roles['Value'],[source[roles['Value']],
                         plan.target_value_member_id],
         roles['Entity'],source[roles['Entity']],
         roles['Account'],source[roles['Account']])).fetchall()
    members={(row['dimension_id'],row['member_id']):row for row in metadata}
    from_row=members.get((roles['Currency'],plan.from_currency))
    to_row=members.get((roles['Currency'],plan.to_currency))
    source_value=members.get((roles['Value'],source[roles['Value']]))
    target_value=members.get((roles['Value'],plan.target_value_member_id))
    entity=members.get((roles['Entity'],source[roles['Entity']]))
    account=members.get((roles['Account'],source[roles['Account']]))
    if any(row is None for row in (from_row,to_row,source_value,
                                   target_value,entity,account)):
        raise ValueError('CALCULATION_TRANSLATION_MEMBER_UNAVAILABLE')
    source_stage_valid=(
        source_value['name'].lower() in (
            from_row['name'].lower(),
            '['+from_row['name'].lower()+']')
        if plan.source_basis=='translated_full' else
        source[roles['Value']]==settings['entityCurrencyValueMemberId'])
    if (plan.from_currency==plan.to_currency
            or not source_stage_valid
            or target_value['name'].lower() not in (
                to_row['name'].lower(),
                '['+to_row['name'].lower()+']')
            or source[roles['Value']]==plan.target_value_member_id
            or entity['entity_default_currency_member_id']!=
                plan.from_currency):
        raise ValueError('CALCULATION_TRANSLATION_CURRENCY_STAGE_INVALID')
    if db.execute('''SELECT 1 FROM epm.relationship WHERE
        workspace_id=%s AND application_id=%s AND dimension_id=%s
        AND parent_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
        (*keys,roles['Value'],plan.target_value_member_id)).fetchone():
        raise ValueError('CALCULATION_TRANSLATION_TARGET_VALUE_MUST_BE_LEAF')
    kind=('balance' if account['financial_account_type'] in (
        'ASSET','LIABILITY','BALANCE','BALANCERECURRING') else
        'flow' if account['financial_account_type'] in (
            'REVENUE','EXPENSE','FLOW') else None)
    if kind!=plan.rate_kind:
        raise ValueError('CALCULATION_TRANSLATION_RATE_KIND_CONFLICT')
    if not db.execute('''SELECT 1 FROM epm.relationship WHERE
        workspace_id=%s AND application_id=%s AND dimension_id=%s
        AND parent_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
        (*keys,roles['Entity'],source[roles['Entity']])).fetchone():
        raise ValueError('CALCULATION_TRANSLATION_FULL_SOURCE_REQUIRED')
    periods=db.execute('''SELECT period_member_id,ordinal,change_id,
        last_revision FROM epm.calendar_period_current
        WHERE workspace_id=%s AND application_id=%s
        AND year_member_id=%s ORDER BY ordinal''',
        (*keys,source[roles['Year']])).fetchall()
    current=next((row for row in periods if row['period_member_id']==
                  source[roles['Period']]),None)
    if current is None:
        raise ValueError('CALCULATION_TRANSLATION_PERIOD_UNCONFIGURED')
    selected=[row for row in periods if row['ordinal']<=current['ordinal']]
    if [row['ordinal'] for row in selected]!=list(
            range(1,current['ordinal']+1)):
        raise ValueError('CALCULATION_TRANSLATION_PERIOD_GAP')
    if plan.method=='VAL':
        selected=[current]
    if not 1<=len(selected)<=120 or {row['period_member_id'] for row in
            selected}!={pin[0] for pin in plan.pins}:
        raise ValueError('CALCULATION_TRANSLATION_PERIOD_COVERAGE')
    requested=[{'period_id':period,'result_key':key,
        'generation_id':generation,'published_revision':revision}
        for period,key,generation,revision in plan.pins]
    pins=db.execute('''SELECT input.period_id,input.result_key,
        input.generation_id,input.published_revision,
        p.source_operation_id AS current_generation_id,
        p.committed_revision AS current_published_revision,
        p.source_function AS function_name,
        p.result_key AS generation_result_key,
        p.row_count,p.source_commit_revision,r.amount,r.source_change_id,
        c.members,j.status AS job_status,j.result AS job_result,
        j.normalized_program,j.expected_metadata_revision,
        j.expected_data_revision,j.expected_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
          period_id text,result_key text,generation_id text,
          published_revision bigint)
        LEFT JOIN epm.calculation_result_state p ON
          p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=input.result_key
        LEFT JOIN epm.calculation_result_current r ON
          r.workspace_id=p.workspace_id AND r.application_id=p.application_id
          AND r.result_key=p.result_key
        LEFT JOIN epm.coordinate c ON
          c.workspace_id=r.workspace_id AND c.application_id=r.application_id
          AND c.coordinate_id=r.coordinate_id
        LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
          AND j.application_id=p.application_id
          AND j.job_id=p.source_operation_id
        ORDER BY input.period_id''',
        (Jsonb(requested),*keys)).fetchall()
    if len(pins)!=len(requested):
        raise ValueError('CALCULATION_TRANSLATION_SOURCE_UNAVAILABLE')
    by_period={row['period_id']:row for row in pins}
    rate_resolver=PostgresCurrencyRates(dsn,identity=identity)
    previous=Fraction(0)
    total=Fraction(0)
    lineage=[]
    budget=[1000]
    for period in selected:
        period_id=period['period_member_id']
        pin=by_period[period_id]
        expected={**source,roles['Period']:period_id}
        receipt=pin['job_result']
        if (pin['current_generation_id']!=pin['generation_id']
                or pin['current_published_revision']!=
                    pin['published_revision']):
            raise ValueError('STALE_PUBLISHED_INPUT')
        translated_source=plan.source_basis=='translated_full'
        expected_function=('consolidation.full.translated.aggregate'
                           if translated_source else
                           'consolidation.full.aggregate')
        expected_stage=(plan.accounting_stage
                        if translated_source else
                        _LOCAL_STAGES[plan.source_layer])
        if (pin['function_name']!=expected_function
                or pin['generation_result_key']!=pin['result_key']
                or pin['row_count']!=1 or pin['amount'] is None
                or pin['source_change_id'] is None
                or pin['members']!=expected
                or pin['job_status']!='published'
                or not isinstance(receipt,dict)
                or receipt.get('parentMembers')!=expected
                or (translated_source and
                    receipt.get('targetCurrencyMemberId')!=
                    plan.from_currency)
                or receipt.get('sourceLayer', 'translated_full')!=
                    plan.source_layer
                or receipt.get('accountingStage')!=expected_stage
                or receipt.get('accountingPolicyStatus')!='Unreviewed'):
            raise ValueError('CALCULATION_TRANSLATION_SOURCE_UNSUPPORTED')
        if any(pin['expected_'+kind+'_revision']!=state[kind+'_revision']
               for kind in ('metadata','data','policy')):
            raise ValueError('CALCULATION_TRANSLATION_SOURCE_STALE')
        if translated_source:
            status=published_translation_status(db,scope,
                pin['normalized_program'],_budget=budget)
            if not status['matchesAtRead']:
                raise ValueError('STALE_PUBLISHED_INPUT')
        else:
            status=published_child_status(db,scope,
                pin['normalized_program'])
            if status is not None and not status['matchesAtRead']:
                raise ValueError('STALE_PUBLISHED_INPUT')
        cumulative=Fraction(pin['amount'])
        delta=cumulative-previous if plan.method=='PVA' else cumulative
        rate=rate_resolver.resolve_in_transaction(db,scope,{
            'languageVersion':2,'function':RATE,
            'arguments':{'coordinate':expected,
                'fromCurrencyMemberId':plan.from_currency,
                'toCurrencyMemberId':plan.to_currency,
                'rateKind':plan.rate_kind}},lock_state=False)
        factor=Fraction(int(rate['exactFactor']['numerator']),
                        int(rate['exactFactor']['denominator']))
        contribution=delta*factor
        total+=contribution
        lineage.append({'periodMemberId':period_id,
            'ordinal':period['ordinal'],
            'calendarChangeId':period['change_id'],
            'calendarRevision':period['last_revision'],
            'resultKey':pin['result_key'],
            'generationId':pin['generation_id'],
            'publishedRevision':pin['published_revision'],
            'sourceCommitRevision':pin['source_commit_revision'],
            'sourceChangeId':pin['source_change_id'],
            'sourceAmount':format(pin['amount'],'.8f'),
            'exactPeriodChange':_rational(delta),
            'exactContribution':_rational(contribution),
            'rate':rate})
        previous=cumulative
    amount=Decimal(_fixed8(total))
    NumericCell(True,amount,'')
    target=Coordinate.from_mapping({**source,
        roles['Value']:plan.target_value_member_id})
    digest_periods=[]
    for period in lineage:
        rate=dict(period['rate'])
        rate.pop('commitRevision',None)
        digest_periods.append({**period,'rate':rate})
    return {'target':target,'amount':amount,
        'sourceAmount':lineage[-1]['sourceAmount'],
        'exactAmount':_rational(total),'periods':lineage,
        'sourceChangeId':_canonical_digest({'periods':digest_periods}),
        'revisionVector':{kind:state[kind+'_revision'] for kind in (
            'metadata','data','policy')},
        'sourceCommitRevision':state['commit_revision'],
        'sourceLayer':plan.source_layer}


def supported_calculation_translation_compiler(version,digest,program):
    if not isinstance(program,dict): return False
    layer=program.get('sourceLayer','translated_full')
    if not isinstance(layer,str) or layer not in _SOURCE_STAGES: return False
    form=3 if 'sourceBasis' in program else 2 if 'sourceLayer' in program else 1
    return ((version==COMPILER and digest==PLAN_DIGEST and form==3) or
        (version==THIRD_COMPILER and digest==THIRD_PLAN_DIGEST and form==3
            and layer in BASE_TRANSLATED_STAGES) or
        (version==SECOND_COMPILER and digest==SECOND_PLAN_DIGEST and form==2
            and layer in BASE_TRANSLATED_STAGES) or
        (version==PREVIOUS_COMPILER and digest==PREVIOUS_PLAN_DIGEST and form==1
            and layer=='translated_full'))


def enforce_calculation_translation_dimensional_security(
        db, identity, scope, plan, summary):
    """Authorize pinned Full/rate inputs separately from translated output."""
    periods = summary.get('periods') if isinstance(summary, dict) else None
    target = summary.get('target') if isinstance(summary, dict) else None
    if (not isinstance(periods, list) or not periods
            or not isinstance(target, Coordinate)):
        raise ValueError(
            'CALCULATION_TRANSLATION_SECURITY_COORDINATES_INVALID')
    rows = db.execute('''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role='Period' ORDER BY dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()
    if len(rows) != 1:
        raise ValueError(
            'CALCULATION_TRANSLATION_SECURITY_COORDINATES_INVALID')
    period_axis = rows[0]['dimension_id']
    reads = {}
    base = dict(plan.source_members)
    for period in periods:
        period_id = (period.get('periodMemberId')
                     if isinstance(period, dict) else None)
        rate = period.get('rate') if isinstance(period, dict) else None
        rate_sources = rate.get('sources') if isinstance(rate, dict) else None
        if (not isinstance(period_id, str) or not period_id
                or not isinstance(rate_sources, list)):
            raise ValueError(
                'CALCULATION_TRANSLATION_SECURITY_COORDINATES_INVALID')
        source = Coordinate.from_mapping({**base, period_axis: period_id})
        reads[source.series_key] = source
        for item in rate_sources:
            members = item.get('coordinate') if isinstance(item, dict) else None
            if not isinstance(members, dict):
                raise ValueError(
                    'CALCULATION_TRANSLATION_SECURITY_COORDINATES_INVALID')
            coordinate = Coordinate.from_mapping(members)
            reads[coordinate.series_key] = coordinate
    authorize_coordinates(
        db, identity, scope, reads.values(), kind=AccessKind.READ)
    authorize_coordinates(
        db, identity, scope, (target,), kind=AccessKind.WRITE)


def _comparable_summary(summary:dict) -> dict:
    """Exclude only observation-time commit counters from source equality."""
    comparable={key:value for key,value in summary.items()
                if key!='sourceCommitRevision'}
    comparable['periods']=[]
    for period in summary['periods']:
        rate=dict(period['rate'])
        rate.pop('commitRevision',None)
        comparable['periods'].append({**period,'rate':rate})
    return comparable


class PostgresCalculationTranslationPublisher:
    def __init__(self,dsn:str,*,identity:VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def publish(self,claim:dict) -> dict:
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
                PostgresAccessChecker.check_in_transaction(
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
                        or not supported_calculation_translation_compiler(job['compiler_version'],
                            job['plan_digest'],job['normalized_program'])
                        or job['program_digest']!=_canonical_digest(job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_CALCULATION_TRANSLATION_JOB')
                plan=decode_calculation_translation(job['normalized_program'])
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
                summary=validate_calculation_translation(
                    db,scope,plan,self.identity,self.dsn)
                enforce_calculation_translation_dimensional_security(
                    db, self.identity, scope, plan, summary)
                if any(state[k]!=summary['revisionVector'][kind]
                       for kind,k in (('metadata','metadata_revision'),
                                      ('data','data_revision'),
                                      ('policy','policy_revision'))):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
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
                final_summary=validate_calculation_translation(
                    db,scope,plan,self.identity,self.dsn)
                enforce_calculation_translation_dimensional_security(
                    db, self.identity, scope, plan, final_summary)
                if _comparable_summary(final_summary)!=(
                        _comparable_summary(summary)):
                    raise ValueError('CALCULATION_TRANSLATION_SOURCE_CHANGED')
                policy_evidence=enforce_currency_target_policy(
                    db,scope,target,final_access.role)
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (*keys,target.series_key,Jsonb(dict(target.members))))
                point=db.execute('''SELECT coordinate_id,members
                    FROM epm.coordinate WHERE workspace_id=%s
                    AND application_id=%s AND series_key=%s''',
                    (*keys,target.series_key)).fetchone()
                if point['members']!=dict(target.members):
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
                     Decimal(summary['sourceAmount']),
                     summary['sourceChangeId'],summary['amount']))
                from .postgres_current_result_publication import advance_result_head_during_conversion
                advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                result={'generationId':claim['job_id'],
                    'resultKey':plan.result_key,'function':FUNCTION,
                    'sourceMembers':dict(plan.source_members),
                    'targetMembers':dict(target.members),
                    'fromCurrencyMemberId':plan.from_currency,
                    'toCurrencyMemberId':plan.to_currency,
                    'rateKind':plan.rate_kind,'method':plan.method,
                    'sourceLayer':plan.source_layer,
                    **({'sourceBasis':plan.source_basis}
                       if plan.translation_format_level>=3 else {}),
                    'periodPins':plan.normalized_program['periodPins'],
                    'periods':summary['periods'],
                    'sourceChangeId':summary['sourceChangeId'],
                    'sourceAmount':summary['sourceAmount'],
                    'amount':format(summary['amount'],'.8f'),
                    'exactAmount':summary['exactAmount'],
                    'rowCount':1,
                    'accountingStage':plan.accounting_stage,
                    'accountingPolicyStatus':'Unreviewed',
                    'sourceCommitRevision':state['commit_revision'],
                    'committedRevision':revision,
                    'engine':'postgres_exact_rational',
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
