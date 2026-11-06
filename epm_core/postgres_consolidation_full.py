"""One exact direct-child Full contribution before NCI, FX or eliminations.

This is a bounded calculation stage, not a finished consolidated balance or a
reviewed IFRS/US GAAP policy. It publishes only through the fixed job runner.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_job_final_fence import finish_published_job
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .postgres_version_compare import _identifier


FUNCTION = 'consolidation.full.contribute'
TYPED_FUNCTION = 'consolidation.full.typed.contribute'
COMPILER = 'consolidation-full-contribution-v1'
TYPED_COMPILER = 'consolidation-full-typed-contribution-v1'
TYPED_IC_COMPILER = 'consolidation-full-typed-contribution-v2-ic-adjusted'
TYPED_JOURNAL_IC_COMPILER = (
    'consolidation-full-typed-contribution-v3-journal-ic-adjusted')
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'child_full_coordinate',
    'outputGrain': 'parent_full_coordinate',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'accountingStage': 'pre_nci_untranslated_uneliminated',
})
TYPED_PLAN_DIGEST = _canonical_digest({
    'function': TYPED_FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'child_coordinate_currency_as_typed_unit',
    'outputGrain': 'parent_coordinate_currency_as_typed_unit',
    'method': 'Full', 'pcon': '100_percent_or_labeled_fallback',
    'accountingStage': 'pre_nci_untranslated_uneliminated',
    'effects': 'calculated-unit-generation-only',
})
TYPED_IC_PLAN_DIGEST = _canonical_digest({
    'function': TYPED_FUNCTION, 'loweringVersion': 2,
    'engine': 'postgres_exact_sql','sourceLayer':'raw_plus_ic_elimination',
    'inputGrain':'child_coordinate_currency_as_typed_unit',
    'outputGrain':'parent_coordinate_currency_as_typed_unit',
    'method':'Full','accountingPolicyStatus':'Unreviewed'})
TYPED_JOURNAL_IC_PLAN_DIGEST = _canonical_digest({
    'function': TYPED_FUNCTION, 'loweringVersion': 3,
    'engine': 'postgres_exact_sql',
    'sourceLayer': 'raw_plus_manual_journal_plus_ic_elimination',
    'inputGrain': 'child_coordinate_currency_as_typed_unit',
    'outputGrain': 'parent_coordinate_currency_as_typed_unit',
    'method': 'Full', 'journalLayer': 'immutable_posted_lines_at_source',
    'icLayer': 'current_parent_pair_generation',
    'accountingPolicyStatus': 'Unreviewed'})
_TYPED_IC_LAYERS = frozenset((
    'raw_plus_ic_elimination',
    'raw_plus_manual_journal_plus_ic_elimination'))
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')

def _typed_result_evidence(plan,summary):
    if plan.source_layer=='raw':
        return summary['sourceChangeId'],None,[]
    lineage=summary['sourceLookupLineage']
    encoded=json.dumps(lineage,sort_keys=True,ensure_ascii=True).encode('ascii')
    if not lineage or len(lineage)>64 or len(encoded)>65536:
        raise ValueError('TYPED_CONTRIBUTION_LINEAGE_LIMIT')
    return None,_canonical_digest(lineage),lineage


def enforce_consolidation_target_policy(db,scope:ApplicationScope,
                                        target:Coordinate,
                                        workflow_role:str)->dict:
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=((target,'Set'),),workflow_role=workflow_role)
_REQUIRED_ROLES = {'Scenario', 'Year', 'Period', 'Entity', 'Account'}


@dataclass(frozen=True, slots=True)
class FullContributionPlan:
    relationship_id: str
    scenario_id: str
    year_id: str
    period_id: str
    source_members: tuple[tuple[str, str], ...]
    result_key: str
    expected_publication_revision: int

    @property
    def source(self) -> Coordinate:
        return Coordinate.from_mapping(dict(self.source_members))

    def target(self, entity_dimension: str, parent_id: str) -> Coordinate:
        return Coordinate.from_mapping({**dict(self.source_members),
                                        entity_dimension: parent_id})

    @property
    def normalized_program(self) -> dict:
        return {'version': 2, 'function': FUNCTION,
                'relationshipId': self.relationship_id,
                'scenarioId': self.scenario_id,
                'yearId': self.year_id,
                'periodId': self.period_id,
                'sourceMembers': dict(self.source_members),
                'resultKey': self.result_key,
                'controlConfirmed': True,
                'currencyAlignedConfirmed': True,
                'expectedPublicationRevision':
                    self.expected_publication_revision,
                'inputGrain': 'child_full_coordinate',
                'outputGrain': 'parent_full_coordinate',
                'accountingStage':
                    'pre_nci_untranslated_uneliminated'}


@dataclass(frozen=True, slots=True)
class TypedFullContributionPlan(FullContributionPlan):
    currency_dimension_id: str
    currency_member_id: str
    policy_id: str
    policy_version: int
    policy_digest: str
    effective_on: date
    source_layer: str = 'raw'
    ic_generation_id: str | None = None

    @property
    def normalized_program(self) -> dict:
        result={**FullContributionPlan.normalized_program.fget(self), 'version': 3,
                'function': TYPED_FUNCTION,
                'currencyDimensionId': self.currency_dimension_id,
                'currencyMemberId': self.currency_member_id,
                'policy':{'policyId':self.policy_id,
                          'version':self.policy_version,
                          'digest':self.policy_digest,
                          'effectiveOn':self.effective_on.isoformat()},
                'inputGrain': 'child_coordinate_currency_as_typed_unit',
                'outputGrain': 'parent_coordinate_currency_as_typed_unit'}
        if self.source_layer!='raw':
            result.update(version=(5 if self.source_layer ==
                          'raw_plus_manual_journal_plus_ic_elimination' else 4),
                          sourceLayer=self.source_layer,
                          icGenerationId=self.ic_generation_id,
                          accountingStage=(
                            'pre_nci_untranslated_journal_ic_adjusted'
                            if self.source_layer ==
                              'raw_plus_manual_journal_plus_ic_elimination'
                            else 'pre_nci_untranslated_ic_adjusted'))
        return result

    @property
    def compiler_version(self):
        return (TYPED_COMPILER if self.source_layer == 'raw' else
                TYPED_JOURNAL_IC_COMPILER if self.source_layer ==
                    'raw_plus_manual_journal_plus_ic_elimination' else
                TYPED_IC_COMPILER)

    @property
    def plan_digest(self):
        return (TYPED_PLAN_DIGEST if self.source_layer == 'raw' else
                TYPED_JOURNAL_IC_PLAN_DIGEST if self.source_layer ==
                    'raw_plus_manual_journal_plus_ic_elimination' else
                TYPED_IC_PLAN_DIGEST)


def compile_typed_full_contribution(program: object, *,
                                    expected_publication_revision: int
                                    ) -> TypedFullContributionPlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != TYPED_FUNCTION
            or not isinstance(program.get('arguments'), dict)):
        raise ValueError('TYPED_CONTRIBUTION_PROGRAM_INVALID')
    args = program['arguments']
    required = {'relationshipId', 'scenarioId', 'yearId', 'periodId',
                'sourceMembers', 'currencyDimensionId', 'currencyMemberId',
                'policyId','policyVersion','policyDigest','effectiveOn',
                'resultKey', 'controlConfirmed', 'currencyAlignedConfirmed'}
    ic=set(args)==required|{'sourceLayer','icGenerationId'}
    try:effective_on=date.fromisoformat(args.get('effectiveOn'))
    except (TypeError,ValueError):
        raise ValueError('TYPED_CONTRIBUTION_POLICY_INVALID') from None
    if (set(args) not in (required,required|{'sourceLayer','icGenerationId'})
            or ic and (args.get('sourceLayer') not in _TYPED_IC_LAYERS
                or not isinstance(args.get('icGenerationId'),str)
                or not re.fullmatch(r'[A-Za-z0-9._-]{8,128}',args['icGenerationId']))
            or args['controlConfirmed'] is not True
            or args['currencyAlignedConfirmed'] is not True
            or not isinstance(args['sourceMembers'], dict)
            or not 1 <= len(args['sourceMembers']) <= 31
            or any(not isinstance(args.get(key), str) or not args[key]
                   for key in ('currencyDimensionId','currencyMemberId',
                               'policyId'))
            or type(args['policyVersion']) is not int
            or args['policyVersion']<1
            or not isinstance(args['policyDigest'],str)
            or not re.fullmatch(r'[0-9a-f]{64}',args['policyDigest'])
            or effective_on.isoformat()!=args['effectiveOn']
            or args['currencyDimensionId'] in args['sourceMembers']
            or not isinstance(args['resultKey'], str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0):
        raise ValueError('TYPED_CONTRIBUTION_ARGUMENTS_INVALID')
    members = {_identifier(axis, 'Dimension ID'):
               _identifier(member, 'Member ID')
               for axis, member in args['sourceMembers'].items()}
    return TypedFullContributionPlan(
        _identifier(args['relationshipId'], 'Relationship ID'),
        _identifier(args['scenarioId'], 'Scenario ID'),
        _identifier(args['yearId'], 'Year ID'),
        _identifier(args['periodId'], 'Period ID'),
        tuple(sorted(members.items())), args['resultKey'],
        expected_publication_revision,
        _identifier(args['currencyDimensionId'], 'Dimension ID'),
        _identifier(args['currencyMemberId'], 'Member ID'),
        _identifier(args['policyId'],'Policy ID'),args['policyVersion'],
        args['policyDigest'],effective_on,
        args.get('sourceLayer','raw'),args.get('icGenerationId'))


def decode_typed_full_contribution(program: object) -> TypedFullContributionPlan:
    if (not isinstance(program,dict) or program.get('version') not in (3,4,5)
            or program.get('function') != TYPED_FUNCTION):
        raise ValueError('UNSUPPORTED_TYPED_CONTRIBUTION_JOB_PROGRAM')
    keys=('relationshipId','scenarioId','yearId','periodId','sourceMembers',
          'currencyDimensionId','currencyMemberId','resultKey',
          'controlConfirmed','currencyAlignedConfirmed')
    policy=program.get('policy') if isinstance(program.get('policy'),dict) else {}
    extra=({'sourceLayer':program.get('sourceLayer'),
            'icGenerationId':program.get('icGenerationId')}
           if program.get('version') in (4,5) else {})
    plan=compile_typed_full_contribution({'languageVersion':2,
        'function':TYPED_FUNCTION,
        'arguments':{**{key:program.get(key) for key in keys},
          'policyId':policy.get('policyId'),
          'policyVersion':policy.get('version'),
          'policyDigest':policy.get('digest'),
          'effectiveOn':policy.get('effectiveOn'),**extra}},
        expected_publication_revision=program.get('expectedPublicationRevision'))
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_TYPED_CONTRIBUTION_JOB_PROGRAM')
    return plan


def compile_full_contribution(program: object, *,
                              expected_publication_revision: int) -> FullContributionPlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)):
        raise ValueError('CONTRIBUTION_PROGRAM_INVALID')
    args = program['arguments']
    required = {'relationshipId', 'scenarioId', 'yearId', 'periodId',
                'sourceMembers', 'resultKey', 'controlConfirmed',
                'currencyAlignedConfirmed'}
    if (set(args) != required or args['controlConfirmed'] is not True
            or args['currencyAlignedConfirmed'] is not True
            or not isinstance(args['sourceMembers'], dict)
            or not 1 <= len(args['sourceMembers']) <= 32
            or not isinstance(args['resultKey'], str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0):
        raise ValueError('CONTRIBUTION_ARGUMENTS_INVALID')
    members = {_identifier(axis, 'Dimension ID'):
               _identifier(member, 'Member ID')
               for axis, member in args['sourceMembers'].items()}
    return FullContributionPlan(
        _identifier(args['relationshipId'], 'Relationship ID'),
        _identifier(args['scenarioId'], 'Scenario ID'),
        _identifier(args['yearId'], 'Year ID'),
        _identifier(args['periodId'], 'Period ID'),
        tuple(sorted(members.items())), args['resultKey'],
        expected_publication_revision)


def decode_full_contribution(program: object) -> FullContributionPlan:
    if (not isinstance(program, dict)
            or set(program) != {'version', 'function', 'relationshipId',
                                'scenarioId', 'yearId', 'periodId',
                                'sourceMembers', 'resultKey',
                                'controlConfirmed',
                                'currencyAlignedConfirmed',
                                'expectedPublicationRevision',
                                'inputGrain', 'outputGrain',
                                'accountingStage'}
            or program['version'] != 2 or program['function'] != FUNCTION
            or program['inputGrain'] != 'child_full_coordinate'
            or program['outputGrain'] != 'parent_full_coordinate'
            or program['accountingStage'] !=
                    'pre_nci_untranslated_uneliminated'):
        raise ValueError('UNSUPPORTED_CONTRIBUTION_JOB_PROGRAM')
    plan = compile_full_contribution({
        'languageVersion': 2, 'function': FUNCTION,
        'arguments': {key: program[key] for key in (
            'relationshipId', 'scenarioId', 'yearId', 'periodId',
            'sourceMembers', 'resultKey', 'controlConfirmed',
            'currencyAlignedConfirmed')}},
        expected_publication_revision=
            program['expectedPublicationRevision'])
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_CONTRIBUTION_JOB_PROGRAM')
    return plan


def validate_full_contribution(db, scope: ApplicationScope,
                               plan: FullContributionPlan) -> dict:
    roles = {}
    axes = set()
    for row in db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        (scope.workspace_id, scope.application_id)).fetchall():
        axes.add(row['dimension_id'])
        if row['model_role'] in _REQUIRED_ROLES | {'Currency', 'Value'}:
            if row['model_role'] in roles:
                raise ValueError('CONTRIBUTION_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']] = row['dimension_id']
    if not _REQUIRED_ROLES <= set(roles):
        raise ValueError('CONTRIBUTION_FINANCIAL_MODEL_REQUIRED')
    if 'Currency' in roles or 'Value' in roles:
        raise ValueError('CONTRIBUTION_FX_POLICY_REQUIRED')
    members = dict(plan.source_members)
    if set(members) != axes:
        raise ValueError('CONTRIBUTION_COORDINATE_GRAIN_MISMATCH')
    for role, expected in (('Scenario', plan.scenario_id),
                           ('Year', plan.year_id),
                           ('Period', plan.period_id)):
        if members[roles[role]] != expected:
            raise ValueError('CONTRIBUTION_CONTEXT_MISMATCH')
    PostgresSourceBatch._check_scope_members(db, scope, members)
    account_id = members[roles['Account']]
    if db.execute('''SELECT 1 FROM epm.relationship WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s
        AND parent_member_id=%s AND status='Active' LIMIT 1''',
        (scope.workspace_id, scope.application_id,
         roles['Account'], account_id)).fetchone():
        raise ValueError('CONTRIBUTION_ACCOUNT_LEAF_REQUIRED')
    placement = db.execute('''SELECT r.parent_member_id,r.child_member_id
        FROM epm.relationship r
        JOIN epm.member parent ON parent.workspace_id=r.workspace_id
        AND parent.application_id=r.application_id
        AND parent.dimension_id=r.dimension_id
        AND parent.member_id=r.parent_member_id AND parent.status='Active'
        JOIN epm.member child ON child.workspace_id=r.workspace_id
        AND child.application_id=r.application_id
        AND child.dimension_id=r.dimension_id
        AND child.member_id=r.child_member_id AND child.status='Active'
        WHERE r.workspace_id=%s AND r.application_id=%s
        AND r.relationship_id=%s AND r.dimension_id=%s
        AND r.status='Active' ''',
        (scope.workspace_id, scope.application_id,
         plan.relationship_id, roles['Entity'])).fetchone()
    if placement is None or members[roles['Entity']] != placement['child_member_id']:
        raise ValueError('CONTRIBUTION_ENTITY_PLACEMENT_UNAVAILABLE')
    parents = db.execute('''SELECT count(*) AS total FROM epm.relationship
        WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
        AND child_member_id=%s AND status='Active' ''',
        (scope.workspace_id, scope.application_id,
         roles['Entity'], placement['child_member_id'])).fetchone()['total']
    if parents != 1:
        raise ValueError('CONTRIBUTION_AMBIGUOUS_ENTITY_PLACEMENT')
    values = {row['account_name']: row['amount'] for row in db.execute('''
        SELECT account_name,amount FROM epm.ownership_value_current
        WHERE workspace_id=%s AND application_id=%s
        AND relationship_id=%s AND scenario_member_id=%s
        AND year_member_id=%s AND period_member_id=%s AND present
        AND account_name IN ('POWN','PCON','Active','Method')''',
        (scope.workspace_id, scope.application_id,
         plan.relationship_id, plan.scenario_id, plan.year_id,
         plan.period_id)).fetchall()}
    if 'Method' in values:
        raise ValueError('CONTRIBUTION_METHOD_CODE_UNMAPPED')
    if values.get('Active') == 0:
        raise ValueError('CONTRIBUTION_PERIOD_INACTIVE')
    if 'POWN' not in values:
        raise ValueError('CONTRIBUTION_POWN_REQUIRED')
    pcon_fallback = 'PCON' not in values
    if values.get('PCON', 100) != 100:
        raise ValueError('CONTRIBUTION_FULL_PCON_REQUIRED')
    source = db.execute('''SELECT c.coordinate_id,c.members,
        n.amount,n.change_id FROM epm.coordinate c
        JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id
        AND n.application_id=c.application_id
        AND n.coordinate_id=c.coordinate_id AND n.present
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s''',
        (scope.workspace_id, scope.application_id,
         plan.source.series_key)).fetchone()
    if source is None:
        raise ValueError('CONTRIBUTION_SOURCE_NUMERIC_REQUIRED')
    if source['members'] != members:
        raise ValueError('COORDINATE_HASH_COLLISION')
    target = plan.target(roles['Entity'], placement['parent_member_id'])
    return {'sourceCoordinateId': source['coordinate_id'],
            'sourceAmount': source['amount'],
            'sourceChangeId': source['change_id'],
            'pown': values['POWN'],
            'effectivePcon': 100,
            'pconFallback': pcon_fallback,
            'target': target,
            'parentEntityId': placement['parent_member_id'],
            'childEntityId': placement['child_member_id']}


def validate_typed_full_contribution(db,scope:ApplicationScope,
                                     plan:TypedFullContributionPlan)->dict:
    roles={};axes=set()
    for row in db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        (scope.workspace_id,scope.application_id)).fetchall():
        if row['model_role']!='Currency':axes.add(row['dimension_id'])
        if row['model_role'] in _REQUIRED_ROLES|{'Currency','Value','View'}:
            if row['model_role'] in roles:raise ValueError('TYPED_CONTRIBUTION_MODEL_ROLE_AMBIGUOUS')
            roles[row['model_role']]=row['dimension_id']
    if set(roles)&(_REQUIRED_ROLES|{'Currency'}) != _REQUIRED_ROLES|{'Currency'}:
        raise ValueError('TYPED_CONTRIBUTION_FINANCIAL_MODEL_REQUIRED')
    if roles['Currency']!=plan.currency_dimension_id:
        raise ValueError('TYPED_CONTRIBUTION_GRAIN_INVALID')
    members=dict(plan.source_members)
    if set(members)!=axes:raise ValueError('TYPED_CONTRIBUTION_GRAIN_INVALID')
    for role,expected in (('Scenario',plan.scenario_id),('Year',plan.year_id),
                          ('Period',plan.period_id)):
        if members[roles[role]]!=expected:raise ValueError('TYPED_CONTRIBUTION_CONTEXT_MISMATCH')
    PostgresSourceBatch._check_scope_members(db,scope,members)
    if 'Value' in roles or 'View' in roles:
        state=db.execute('''SELECT currency_settings,metadata_revision
          FROM epm.application_state WHERE workspace_id=%s
          AND application_id=%s''',
          (scope.workspace_id,scope.application_id)).fetchone()
        settings=state['currency_settings'] if state else None
        if (not {'Value','View'}<=set(roles) or settings is None
                or settings.get('validatedMetadataRevision')!=
                   state['metadata_revision']
                or members[roles['Value']]!=
                   settings.get('entityCurrencyValueMemberId')
                or members[roles['View']]!=
                   settings.get('ytdViewMemberId')):
            raise ValueError(
                'TYPED_CONTRIBUTION_FUNCTIONAL_VALUE_STAGE_REQUIRED')
    drafts=db.execute('''SELECT version,family,effective_from,effective_before,
        required_elections,source_refs,created_revision
        FROM epm.policy_pack_draft WHERE workspace_id=%s
        AND application_id=%s AND policy_id=%s AND version=%s
        AND effective_from<=%s AND effective_before>%s''',(
        scope.workspace_id,scope.application_id,plan.policy_id,
        plan.policy_version,plan.effective_on,plan.effective_on)).fetchall()
    if len(drafts)!=1:
        raise ValueError('TYPED_CONTRIBUTION_POLICY_UNAVAILABLE')
    draft=drafts[0]
    if draft['family']!='CUSTOM' or draft['required_elections']!=[]:
        raise ValueError('TYPED_CONTRIBUTION_POLICY_UNSUPPORTED')
    policy_digest=_canonical_digest({'policyId':plan.policy_id,
      'version':draft['version'],'family':draft['family'],
      'effectiveFrom':draft['effective_from'].isoformat(),
      'effectiveBefore':draft['effective_before'].isoformat(),
      'requiredElections':draft['required_elections'],
      'sourceRefs':draft['source_refs'],
      'createdRevision':draft['created_revision']})
    if policy_digest!=plan.policy_digest:
        raise ValueError('STALE_TYPED_CONTRIBUTION_POLICY')
    currency=db.execute('''SELECT 1 FROM epm.member WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s AND member_id=%s
        AND status='Active' ''',(scope.workspace_id,scope.application_id,
        plan.currency_dimension_id,plan.currency_member_id)).fetchone()
    child=members[roles['Entity']]
    placement=db.execute('''SELECT r.parent_member_id,r.child_member_id,
        child.entity_default_currency_member_id AS child_currency,
        parent.entity_default_currency_member_id AS parent_currency
        FROM epm.relationship r JOIN epm.member parent
          ON parent.workspace_id=r.workspace_id AND parent.application_id=r.application_id
         AND parent.dimension_id=r.dimension_id AND parent.member_id=r.parent_member_id
         AND parent.status='Active'
        JOIN epm.member child ON child.workspace_id=r.workspace_id
         AND child.application_id=r.application_id AND child.dimension_id=r.dimension_id
         AND child.member_id=r.child_member_id AND child.status='Active'
        WHERE r.workspace_id=%s AND r.application_id=%s
         AND r.relationship_id=%s AND r.dimension_id=%s AND r.status='Active' ''',
        (scope.workspace_id,scope.application_id,plan.relationship_id,
         roles['Entity'])).fetchone()
    if (not currency or not placement or child!=placement['child_member_id']
            or placement['child_currency']!=plan.currency_member_id
            or placement['parent_currency']!=plan.currency_member_id):
        raise ValueError('TYPED_CONTRIBUTION_CURRENCY_ALIGNMENT_REQUIRED')
    parents=db.execute('''SELECT count(*) total FROM epm.relationship WHERE
        workspace_id=%s AND application_id=%s AND dimension_id=%s
        AND child_member_id=%s AND status='Active' ''',(scope.workspace_id,
        scope.application_id,roles['Entity'],child)).fetchone()['total']
    if parents!=1:raise ValueError('TYPED_CONTRIBUTION_AMBIGUOUS_ENTITY_PLACEMENT')
    if db.execute('''SELECT 1 FROM epm.relationship WHERE workspace_id=%s
        AND application_id=%s AND dimension_id=%s AND parent_member_id=%s
        AND status='Active' LIMIT 1''',(scope.workspace_id,scope.application_id,
        roles['Account'],members[roles['Account']])).fetchone():
        raise ValueError('TYPED_CONTRIBUTION_ACCOUNT_LEAF_REQUIRED')
    values={row['account_name']:{'amount':row['amount'],
      'changeId':row['change_id']} for row in db.execute('''SELECT
        account_name,amount,change_id FROM epm.ownership_value_current WHERE workspace_id=%s
        AND application_id=%s AND relationship_id=%s AND scenario_member_id=%s
        AND year_member_id=%s AND period_member_id=%s AND present
        AND account_name IN ('POWN','PCON','Active','Method')''',(scope.workspace_id,
        scope.application_id,plan.relationship_id,plan.scenario_id,plan.year_id,
        plan.period_id)).fetchall()}
    if (values.get('Method',{'amount':1})['amount']!=1
            or values.get('Active',{'amount':1})['amount']==0
            or 'POWN' not in values
            or values.get('PCON',{'amount':100})['amount']!=100):
        raise ValueError('TYPED_CONTRIBUTION_METHOD_UNAVAILABLE')
    source=db.execute('''SELECT c.coordinate_id,c.members,n.amount,n.change_id
        FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
          (workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s
          AND n.present''',(scope.workspace_id,scope.application_id,
        plan.source.series_key)).fetchone()
    if not source:raise ValueError('TYPED_CONTRIBUTION_SOURCE_NUMERIC_REQUIRED')
    if source['members']!=members:raise ValueError('COORDINATE_HASH_COLLISION')
    source_amount=source['amount'];source_change_id=source['change_id']
    source_lineage=[]
    if plan.source_layer in _TYPED_IC_LAYERS:
        from .postgres_ic_adjusted_balance import resolve_ic_adjusted_source
        current=db.execute('''SELECT metadata_revision,policy_revision,
          commit_revision FROM epm.application_state WHERE workspace_id=%s
          AND application_id=%s''',(scope.workspace_id,
          scope.application_id)).fetchone()
        resolved=resolve_ic_adjusted_source(db,scope,
          parent=placement['parent_member_id'],members=members,state=current,
          expected_generation_id=plan.ic_generation_id,
          allow_manual_journals=(plan.source_layer ==
            'raw_plus_manual_journal_plus_ic_elimination'),
          include_journal_lineage=(plan.source_layer ==
            'raw_plus_manual_journal_plus_ic_elimination'))
        source_amount=(resolved['layeredAmount'] if plan.source_layer ==
          'raw_plus_manual_journal_plus_ic_elimination'
          else resolved['adjustedAmount'])
        source_change_id=None
        source_lineage=[{'kind':(
          'RawPlusManualJournalPlusIcElimination'
          if plan.source_layer ==
             'raw_plus_manual_journal_plus_ic_elimination'
          else 'RawPlusIcElimination'),
          'rawAmount':format(resolved['raw']['amount'],'.8f'),
          'rawChangeId':resolved['raw']['change_id'],
          'icGenerationId':resolved['generationId'],
          'pairKey':resolved['pairKey'],
          'sourceMetadataRevision':resolved['lines'][0]['source_metadata_revision'],
          'sourcePolicyRevision':resolved['lines'][0]['source_policy_revision'],
          'matchedMagnitude':format(resolved['matchedMagnitude'],'.8f'),
          'signedResidual':format(resolved['signedResidual'],'.8f'),
          'eliminationOffset':format(resolved['offset'],'.8f'),
          'adjustedAmount':format(resolved['adjustedAmount'],'.8f'),
          'sources':[{'members':row['members'],
            'sourceChangeId':row['source_change_id'],
            'signedAmount':format(row['signed_amount'],'.8f')}
            for row in resolved['lines']]}]
        if plan.source_layer == 'raw_plus_manual_journal_plus_ic_elimination':
            source_lineage[0].update(
              journalAdjustment=format(
                resolved['journals']['signed_amount'],'.8f'),
              journalLines=resolved['journalLines'],
              layeredAmount=format(resolved['layeredAmount'],'.8f'))
    return {'sourceCoordinateId':source['coordinate_id'],
      'sourceChangeId':source_change_id,'pown':values['POWN']['amount'],
      'effectivePcon':100,'pconFallback':'PCON' not in values,
      'target':plan.target(roles['Entity'],placement['parent_member_id']),
      'parentEntityId':placement['parent_member_id'],'childEntityId':child,
      'policy':{'policyId':plan.policy_id,'version':plan.policy_version,
                'digest':plan.policy_digest,
                'effectiveOn':plan.effective_on.isoformat()},
      'ownership':{key:{'amount':format(value['amount'],'.8f'),
                        'changeId':value['changeId']}
                   for key,value in sorted(values.items())},
      'outputUnit':{'dimensionId':plan.currency_dimension_id,
                    'memberId':plan.currency_member_id},
      'sourceLayer':plan.source_layer,'sourceLookupLineage':source_lineage,
      'sourceAmount':source_amount}


def typed_full_context_status(db,scope:ApplicationScope,normalized:dict,
                              receipt:dict)->dict:
    """Recheck the exact policy, placement, unit and ownership certificate."""
    try:
        plan=decode_typed_full_contribution(normalized)
        expected_policy={'policyId':plan.policy_id,
                         'version':plan.policy_version,
                         'digest':plan.policy_digest,
                         'effectiveOn':plan.effective_on.isoformat()}
        expected_unit={'dimensionId':plan.currency_dimension_id,
                       'memberId':plan.currency_member_id}
        if (not isinstance(receipt,dict)
                or receipt.get('function')!=TYPED_FUNCTION
                or receipt.get('policy')!=expected_policy
                or receipt.get('outputUnit')!=expected_unit
                or not isinstance(receipt.get('ownership'),dict)):
            return {'matchesAtRead':False,'reason':'RECEIPT_INVALID'}
    except (KeyError,TypeError,ValueError):
        return {'matchesAtRead':False,'reason':'PROGRAM_INVALID'}
    keys=(scope.workspace_id,scope.application_id)
    drafts=db.execute('''SELECT version,family,effective_from,effective_before,
        required_elections,source_refs,created_revision
        FROM epm.policy_pack_draft WHERE workspace_id=%s
        AND application_id=%s AND policy_id=%s AND version=%s
        AND effective_from<=%s AND effective_before>%s''',(*keys,
        plan.policy_id,plan.policy_version,plan.effective_on,
        plan.effective_on)).fetchall()
    policy_current=False
    if len(drafts)==1:
        draft=drafts[0]
        digest=_canonical_digest({'policyId':plan.policy_id,
          'version':draft['version'],'family':draft['family'],
          'effectiveFrom':draft['effective_from'].isoformat(),
          'effectiveBefore':draft['effective_before'].isoformat(),
          'requiredElections':draft['required_elections'],
          'sourceRefs':draft['source_refs'],
          'createdRevision':draft['created_revision']})
        policy_current=(draft['family']=='CUSTOM'
            and draft['required_elections']==[] and digest==plan.policy_digest)
    placement=db.execute('''SELECT r.parent_member_id,r.child_member_id,
        child.entity_default_currency_member_id AS child_currency,
        parent.entity_default_currency_member_id AS parent_currency,
        EXISTS(SELECT 1 FROM epm.member currency
          WHERE currency.workspace_id=r.workspace_id
          AND currency.application_id=r.application_id
          AND currency.dimension_id=%s AND currency.member_id=%s
          AND currency.status='Active') AS unit_active
        FROM epm.relationship r JOIN epm.dimension entity
          ON entity.workspace_id=r.workspace_id
         AND entity.application_id=r.application_id
         AND entity.dimension_id=r.dimension_id
         AND entity.model_role='Entity' AND entity.status='Active'
        JOIN epm.member parent
          ON parent.workspace_id=r.workspace_id
         AND parent.application_id=r.application_id
         AND parent.dimension_id=r.dimension_id
         AND parent.member_id=r.parent_member_id AND parent.status='Active'
        JOIN epm.member child ON child.workspace_id=r.workspace_id
         AND child.application_id=r.application_id
         AND child.dimension_id=r.dimension_id
         AND child.member_id=r.child_member_id AND child.status='Active'
        WHERE r.workspace_id=%s AND r.application_id=%s
         AND r.relationship_id=%s AND r.status='Active' ''',
        (plan.currency_dimension_id,plan.currency_member_id,*keys,
         plan.relationship_id)).fetchone()
    placement_current=bool(placement
        and placement['parent_member_id']==receipt.get('parentEntityId')
        and placement['child_member_id']==receipt.get('childEntityId')
        and placement['child_currency']==plan.currency_member_id
        and placement['parent_currency']==plan.currency_member_id
        and placement['unit_active'])
    rows=db.execute('''SELECT account_name,amount,change_id
        FROM epm.ownership_value_current WHERE workspace_id=%s
        AND application_id=%s AND relationship_id=%s
        AND scenario_member_id=%s AND year_member_id=%s
        AND period_member_id=%s AND present
        AND account_name IN ('POWN','PCON','Active','Method')''',(*keys,
        plan.relationship_id,plan.scenario_id,plan.year_id,
        plan.period_id)).fetchall()
    ownership={row['account_name']:{'amount':format(row['amount'],'.8f'),
      'changeId':row['change_id']} for row in rows}
    ownership_current=(ownership==receipt['ownership']
        and ownership.get('Method',{'amount':'1.00000000'})['amount']==
            '1.00000000'
        and ownership.get('Active',{'amount':'1.00000000'})['amount']!=
            '0.00000000'
        and 'POWN' in ownership
        and ownership.get('PCON',{'amount':'100.00000000'})['amount']==
            '100.00000000')
    source_current=True;source_detail=None
    if plan.source_layer in _TYPED_IC_LAYERS:
        try:
            candidate=validate_typed_full_contribution(db,scope,plan)
            source_current=(receipt.get('sourceLayer')==plan.source_layer
                and receipt.get('icGenerationId')==plan.ic_generation_id
                and receipt.get('amount')==format(candidate['sourceAmount'],'.8f')
                and receipt.get('sourceLookupLineage')==
                    candidate['sourceLookupLineage']
                and receipt.get('sourceEvidenceDigest')==
                    _canonical_digest(candidate['sourceLookupLineage']))
            source_detail={'matchesAtRead':source_current,
              'icGenerationId':plan.ic_generation_id}
        except ValueError as error:
            source_current=False;source_detail={'matchesAtRead':False,
              'reason':str(error),'icGenerationId':plan.ic_generation_id}
    return {'matchesAtRead':policy_current and placement_current
                           and ownership_current and source_current,
            'policyCurrent':policy_current,
            'placementCurrent':placement_current,
            'ownershipCurrent':ownership_current,
            'sourceStatus':source_detail,
            'policy':expected_policy,'outputUnit':expected_unit}


class PostgresFullContributionPublisher:
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
                # The claimed fixed function selects a versioned producer;
                # caller input never chooses the storage path.
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
                typed=job['function_name']==TYPED_FUNCTION
                if job['function_name'] not in (FUNCTION,TYPED_FUNCTION):
                    raise ValueError('UNSUPPORTED_CONTRIBUTION_JOB_PROGRAM')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin' if typed else 'write')
                unexpired = db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant']
                        or not unexpired):
                    raise ValueError('STALE_WORKER_FENCE')
                plan=(decode_typed_full_contribution(job['normalized_program'])
                      if typed else decode_full_contribution(job['normalized_program']))
                if (job['compiler_version'] !=
                        (plan.compiler_version if typed else COMPILER)
                        or job['plan_digest'] !=
                        (plan.plan_digest if typed else PLAN_DIGEST)
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_CONTRIBUTION_JOB_PROGRAM')
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
                summary=(validate_typed_full_contribution(db,scope,plan)
                         if typed else validate_full_contribution(db, scope, plan))
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
                    db,self.identity,scope,'admin' if typed else 'write',
                    function=job['function_name'])
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
                final_summary=(validate_typed_full_contribution(db,scope,plan)
                    if typed else validate_full_contribution(db,scope,plan))
                if final_summary!=summary:
                    raise ValueError('CONTRIBUTION_SOURCE_CHANGED')
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
                     point['coordinate_id'],
                     Jsonb(dict(target.members))))
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
                     state['policy_revision'],
                     TYPED_FUNCTION if typed else FUNCTION, revision))
                if typed:
                 unit=summary['outputUnit']
                 if plan.source_layer!='raw':
                  _,evidence_digest,lineage=_typed_result_evidence(plan,summary)
                  db.execute('''INSERT INTO epm.calculation_unit_result
                    (workspace_id,application_id,generation_id,coordinate_id,
                     output_unit_currency_dimension_id,
                     output_unit_currency_member_id,source_amount,
                     source_change_id,source_evidence_digest,amount,rate_strategy,
                     rate_numerator,rate_denominator,rate_sources,
                     source_lookup_lineage)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,
                     'identity-same-currency',1,1,%s,%s)''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     point['coordinate_id'],unit['dimensionId'],unit['memberId'],
                     summary['sourceAmount'],evidence_digest,
                     summary['sourceAmount'],Jsonb([{'kind':'Identity',
                      'currency':unit}]),Jsonb(lineage)))
                 else: db.execute('''INSERT INTO epm.calculation_unit_result
                    (workspace_id,application_id,generation_id,coordinate_id,
                     output_unit_currency_dimension_id,
                     output_unit_currency_member_id,source_amount,
                     source_change_id,amount,rate_strategy,rate_numerator,
                     rate_denominator,rate_sources,source_lookup_lineage)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,
                     'identity-same-currency',1,1,%s,'[]'::jsonb)''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     point['coordinate_id'],unit['dimensionId'],unit['memberId'],
                     summary['sourceAmount'],summary['sourceChangeId'],
                     summary['sourceAmount'],Jsonb([{'kind':'Identity',
                      'currency':unit}])))
                else:
                 db.execute('''INSERT INTO epm.calculation_result
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_amount,source_change_id,amount)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], point['coordinate_id'],
                     summary['sourceAmount'], summary['sourceChangeId'],
                     summary['sourceAmount']))
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
                          'function': TYPED_FUNCTION if typed else FUNCTION,
                          'rowCount': 1,
                          'sourceMembers': dict(plan.source_members),
                          'targetMembers': dict(target.members),
                          'sourceChangeId': summary['sourceChangeId'],
                          'relationshipId': plan.relationship_id,
                          'parentEntityId': summary['parentEntityId'],
                          'childEntityId': summary['childEntityId'],
                          'pown': format(summary['pown'], '.8f'),
                          'effectivePcon': '100.00000000',
                          'pconFallback': summary['pconFallback'],
                          'amount': format(summary['sourceAmount'], '.8f'),
                          'accountingStage':
                              'pre_nci_untranslated_uneliminated',
                          'accountingPolicyStatus': 'Unreviewed',
                          'sourceCommitRevision': state['commit_revision'],
                          'committedRevision': revision,
                          'engine': 'postgres_exact_sql',
                          'planningPolicy':policy_evidence}
                if typed:result['outputUnit']=summary['outputUnit']
                if typed:result['policy']=summary['policy']
                if typed:result['ownership']=summary['ownership']
                if typed and plan.source_layer!='raw':result.update(
                    sourceLayer=plan.source_layer,
                    icGenerationId=plan.ic_generation_id,
                    sourceLookupLineage=summary['sourceLookupLineage'],
                    sourceEvidenceDigest=evidence_digest,
                    accountingStage=(
                      'pre_nci_untranslated_journal_ic_adjusted'
                      if plan.source_layer ==
                        'raw_plus_manual_journal_plus_ic_elimination'
                      else 'pre_nci_untranslated_ic_adjusted'))
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
                finish_published_job(db,scope,claim,revision=revision,
                                     result=result)
                return result
