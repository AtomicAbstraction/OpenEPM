"""Durable one-coordinate FX translation into a named calculation generation.

This publishes an Unreviewed translated Value-stage result. Accounting policy,
CTA, close and whole-unit translation remain outside this bounded stage.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_currency_translation import (
    PostgresCurrencyTranslation, FUNCTION as INSPECT)
from .postgres_jobs import _canonical_digest, _require_python_job_authority
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_consolidation_stages import ACQUISITION_OWN_STAGES
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION = 'currency.translation.publish'
PREVIOUS_COMPILER = 'currency-translation-v1'
PREVIOUS_PLAN_DIGEST = _canonical_digest({'function':FUNCTION,
    'loweringVersion':1,'engine':'postgres_exact_rational',
    'outputGrain':'single-translated-value-coordinate',
    'stage':'translated_unreviewed'})
COMPILER = 'currency-translation-v2'
PLAN_DIGEST = _canonical_digest({'function':FUNCTION,'loweringVersion':2,
    'engine':'postgres_exact_rational','source':'own_entity_only',
    'sourceStages':ACQUISITION_OWN_STAGES,'icContext':'explicit_parent',
    'outputGrain':'single-translated-value-coordinate'})
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')


@dataclass(frozen=True, slots=True)
class TranslationPlan:
    source_members: tuple[tuple[str,str], ...]
    from_currency: str
    to_currency: str
    rate_kind: str
    method: str
    target_value_member_id: str
    result_key: str
    expected_publication_revision: int
    source_layer: str | None = None
    ic_parent: str | None = None

    @property
    def accounting_stage(self):
        return ACQUISITION_OWN_STAGES[self.source_layer] if self.source_layer else 'translated_unreviewed'

    @property
    def inspect_program(self) -> dict:
        return {'languageVersion':2,'function':INSPECT,'arguments':{
            'coordinate':dict(self.source_members),
            'fromCurrencyMemberId':self.from_currency,
            'toCurrencyMemberId':self.to_currency,
            'rateKind':self.rate_kind,'method':self.method}}

    @property
    def normalized_program(self) -> dict:
        return {**({'sourceLayer':self.source_layer,'icParentEntityId':self.ic_parent} if self.source_layer else {}),
            'version':2,'function':FUNCTION,
            'sourceMembers':dict(self.source_members),
            'fromCurrencyMemberId':self.from_currency,
            'toCurrencyMemberId':self.to_currency,
            'rateKind':self.rate_kind,'method':self.method,
            'targetValueMemberId':self.target_value_member_id,
            'resultKey':self.result_key,
            'expectedPublicationRevision':self.expected_publication_revision,
            'accountingStage':self.accounting_stage}


def compile_translation(raw: object, *,
                        expected_publication_revision: int) -> TranslationPlan:
    if (not isinstance(raw,dict)
            or set(raw) != {'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != FUNCTION
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('V2_TRANSLATION_PUBLICATION_PROGRAM_INVALID')
    args=raw['arguments']
    required={'coordinate','fromCurrencyMemberId','toCurrencyMemberId','rateKind','method','targetValueMemberId','resultKey'}
    layer=args.get('sourceLayer')
    ic_parent=args.get('icParentEntityId')
    if (set(args) not in (required,required|{'sourceLayer'},required|{'sourceLayer','icParentEntityId'})
            or ('sourceLayer' in args and (not isinstance(layer,str) or layer not in ACQUISITION_OWN_STAGES))
            or (layer is not None and 'ic_elimination' in layer and
                (not isinstance(ic_parent,str) or not 1<=len(ic_parent)<=200 or ic_parent!=ic_parent.strip()))
            or (layer is not None and 'ic_elimination' not in layer and 'icParentEntityId' in args)
            or not isinstance(args['resultKey'],str) or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int or expected_publication_revision<0):
        raise ValueError('V2_TRANSLATION_PUBLICATION_ARGUMENTS_INVALID')
    # Reuse the exact inspection program's strict syntax validation.
    inspect = {key:args[key] for key in (
        'coordinate','fromCurrencyMemberId','toCurrencyMemberId',
        'rateKind','method')}
    from .postgres_currency_translation import _program
    source, from_id, to_id, kind, method = _program({
        'languageVersion':2,'function':INSPECT,'arguments':inspect})
    target=args['targetValueMemberId']
    if (not isinstance(target,str) or not 1 <= len(target) <= 200
            or target != target.strip() or '\x00' in target):
        raise ValueError('TRANSLATION_TARGET_VALUE_INVALID')
    return TranslationPlan(tuple(sorted(source.items())),from_id,to_id,
        kind,method,target,args['resultKey'],
        expected_publication_revision,layer,ic_parent)


def decode_translation(raw: object) -> TranslationPlan:
    if (not isinstance(raw,dict)
            or set(raw)-{'sourceLayer','icParentEntityId'} != {'version','function','sourceMembers',
                'fromCurrencyMemberId','toCurrencyMemberId','rateKind',
                'method','targetValueMemberId','resultKey',
                'expectedPublicationRevision','accountingStage'}
            or raw['version'] != 2 or raw['function'] != FUNCTION
            or raw['accountingStage'] not in {'translated_unreviewed',*ACQUISITION_OWN_STAGES.values()}):
        raise ValueError('UNSUPPORTED_TRANSLATION_JOB_PROGRAM')
    plan=compile_translation({'languageVersion':2,'function':FUNCTION,
        'arguments':{'coordinate':raw['sourceMembers'],
            **({'sourceLayer':raw['sourceLayer']} if 'sourceLayer' in raw else {}),
            **({'icParentEntityId':raw['icParentEntityId']} if raw.get('icParentEntityId') is not None else {}),
            **{key:raw[key] for key in (
                'fromCurrencyMemberId','toCurrencyMemberId','rateKind',
                'method','targetValueMemberId','resultKey')}}},
        expected_publication_revision=raw['expectedPublicationRevision'])
    if plan.normalized_program != raw:
        raise ValueError('NONCANONICAL_TRANSLATION_JOB_PROGRAM')
    return plan


def target_coordinate(db, scope: ApplicationScope,
                      plan: TranslationPlan) -> Coordinate:
    keys=(scope.workspace_id,scope.application_id)
    rows=db.execute('''SELECT dimension_id,model_role
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND model_role IN ('Value','Currency') AND status='Active' ''',
        keys).fetchall()
    roles={}
    for row in rows:
        if row['model_role'] in roles:
            raise ValueError('CURRENCY_MODEL_ROLE_AMBIGUOUS')
        roles[row['model_role']]=row['dimension_id']
    if set(roles)!={'Value','Currency'}:
        raise ValueError('CURRENCY_MODEL_ROLES_REQUIRED')
    names=db.execute('''SELECT dimension_id,member_id,name FROM epm.member
        WHERE workspace_id=%s AND application_id=%s
        AND ((dimension_id=%s AND member_id=%s)
          OR (dimension_id=%s AND member_id=%s))
        AND status='Active' ''',
        (*keys,roles['Currency'],plan.to_currency,
         roles['Value'],plan.target_value_member_id)).fetchall()
    found={(row['dimension_id'],row['member_id']):row['name']
           for row in names}
    currency_name=found.get((roles['Currency'],plan.to_currency))
    target_name=found.get((roles['Value'],plan.target_value_member_id))
    if currency_name is None or target_name is None:
        raise ValueError('TRANSLATION_TARGET_VALUE_UNAVAILABLE')
    if target_name.lower() not in (currency_name.lower(),
                                  '['+currency_name.lower()+']'):
        raise ValueError('TRANSLATION_TARGET_VALUE_CURRENCY_MISMATCH')
    if db.execute('''SELECT 1 FROM epm.relationship
        WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND parent_member_id=%s
        AND status='Active' LIMIT 1''',
        (*keys,roles['Value'],plan.target_value_member_id)).fetchone():
        raise ValueError('TRANSLATION_TARGET_VALUE_MUST_BE_LEAF')
    source=dict(plan.source_members)
    if roles['Value'] not in source or source[roles['Value']] == (
            plan.target_value_member_id):
        raise ValueError('TRANSLATION_TARGET_STAGE_INVALID')
    return Coordinate.from_mapping({**source,
                                    roles['Value']:plan.target_value_member_id})


def supported_translation_compiler(version,digest,program):
    if not isinstance(program,dict): return False
    return ((version==COMPILER and digest==PLAN_DIGEST) or
        (version==PREVIOUS_COMPILER and digest==PREVIOUS_PLAN_DIGEST and 'sourceLayer' not in program))


def enforce_currency_target_policy(db,scope:ApplicationScope,
                                   target:Coordinate,
                                   workflow_role:str)->dict:
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=((target,'Set'),),workflow_role=workflow_role)


def enforce_translation_dimensional_security(
        db, identity, scope, inspection, target):
    """Authorize each raw/adjusted/rate input and the translated output."""
    periods = inspection.get('periods') if isinstance(inspection, dict) else None
    if (not isinstance(periods, list) or not periods
            or not isinstance(target, Coordinate)):
        raise ValueError('TRANSLATION_SECURITY_COORDINATES_INVALID')
    reads = {}
    for period in periods:
        members = (period.get('sourceCoordinate')
                   if isinstance(period, dict) else None)
        rate = period.get('rate') if isinstance(period, dict) else None
        rate_sources = rate.get('sources') if isinstance(rate, dict) else None
        if not isinstance(members, dict) or not isinstance(rate_sources, list):
            raise ValueError('TRANSLATION_SECURITY_COORDINATES_INVALID')
        source = Coordinate.from_mapping(members)
        reads[source.series_key] = source
        own = period.get('ownSource')
        if own is not None and (not isinstance(own, dict)
                or own.get('members') != members):
            raise ValueError('TRANSLATION_SECURITY_COORDINATES_INVALID')
        for item in rate_sources:
            rate_members = (item.get('coordinate')
                            if isinstance(item, dict) else None)
            if not isinstance(rate_members, dict):
                raise ValueError('TRANSLATION_SECURITY_COORDINATES_INVALID')
            coordinate = Coordinate.from_mapping(rate_members)
            reads[coordinate.series_key] = coordinate
    authorize_coordinates(
        db, identity, scope, reads.values(), kind=AccessKind.READ)
    authorize_coordinates(
        db, identity, scope, (target,), kind=AccessKind.WRITE)


def _seal_candidate(plan: TranslationPlan, inspection: dict,
                    target: Coordinate) -> dict:
    """Detach the privately calculated result from its read transactions."""
    sealed_inspection=deepcopy(inspection)
    target_members=dict(target.members)
    digest=_canonical_digest({'plan':plan.normalized_program,
        'inspection':sealed_inspection,'targetMembers':target_members})
    return {'digest':digest,'inspection':sealed_inspection,
        'targetMembers':target_members}


class PostgresTranslationPublisher:
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
        # Validate the accepted job and live worker before doing potentially
        # expensive period/rate/source resolution.  This transaction takes no
        # application mutation fence.
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before,10000)
                PostgresNumericFactStore._set_scope(before,scope)
                job=before.execute('''SELECT *,
                    lease_until>clock_timestamp() AS unexpired
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',(*keys,claim['job_id'])).fetchone()
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                receipt=before.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                if receipt:
                    if (receipt['command_digest']!=job['program_digest']
                            or receipt['actor_id']!=job['subject_id']):
                        raise ValueError('TRANSLATION_RECEIPT_CONFLICT')
                    return receipt['result']
                if (job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']
                        or not job['unexpired']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(before,scope,job)
                plan=decode_translation(job['normalized_program'])
                access=PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'write',function=FUNCTION,
                    arguments={'sourceLayer':plan.source_layer})
                if (job['function_name']!=FUNCTION
                        or not supported_translation_compiler(
                            job['compiler_version'],job['plan_digest'],
                            job['normalized_program'])
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_TRANSLATION_JOB_PROGRAM')
                state=before.execute('''SELECT a.status AS application_status,
                    s.processing_mode,s.metadata_revision,s.data_revision,
                    s.policy_revision FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    keys).fetchone()
                if (state is None or state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(state[key]!=job['expected_'+key] for key in
                        ('metadata_revision','data_revision','policy_revision')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
        inspection=PostgresCurrencyTranslation(
            self.dsn,identity=self.identity).inspect(scope,
            plan.inspect_program,source_layer=plan.source_layer,ic_parent=plan.ic_parent)
        # Validate and seal the exact calculated candidate without the writer
        # fence.  Final publication repeats every mutable dependency.
        with connect_postgres(self.dsn,row_factory=dict_row) as prepared:
            with prepared.transaction():
                configure_statement_timeout(prepared,10000)
                PostgresNumericFactStore._set_scope(prepared,scope)
                state=prepared.execute('''SELECT a.status AS application_status,
                    s.processing_mode,s.metadata_revision,s.data_revision,
                    s.policy_revision FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    keys).fetchone()
                if (state is None or state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                revisions={'metadataRevision':'metadata_revision',
                    'dataRevision':'data_revision',
                    'policyRevision':'policy_revision'}
                if any(state[database]!=job['expected_'+database]
                        or state[database]!=inspection[result]
                        for result,database in revisions.items()):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer=prepared.execute('''SELECT published_revision
                    FROM epm.calculation_publication
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',(*keys,plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0)!=(
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                target=target_coordinate(prepared,scope,plan)
                enforce_translation_dimensional_security(
                    prepared, self.identity, scope, inspection, target)
                enforce_currency_target_policy(
                    prepared,scope,target,access.role)
        initial_job=job
        candidate=_seal_candidate(plan,inspection,target)
        inspection=candidate['inspection']
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
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write', function=FUNCTION, arguments={'sourceLayer':plan.source_layer})
                job=db.execute('''SELECT *
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (*keys,claim['job_id'])).fetchone()
                receipt=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                if receipt:
                    if (job is None
                            or receipt['command_digest']!=job['program_digest']
                            or receipt['actor_id']!=job['subject_id']):
                        raise ValueError('TRANSLATION_RECEIPT_CONFLICT')
                    return receipt['result']
                immutable=('issuer','subject_id','function_name',
                    'normalized_program','program_digest','compiler_version',
                    'plan_digest','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision')
                if (job is None or any(job[key]!=initial_job[key]
                        for key in immutable)):
                    raise ValueError('STALE_WORKER_FENCE')
                unexpired=db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']
                        or not unexpired):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,job)
                if (job['function_name']!=FUNCTION
                        or not supported_translation_compiler(job['compiler_version'],job['plan_digest'],job['normalized_program'])
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])
                        or job['normalized_program']!=plan.normalized_program):
                    raise ValueError('UNSUPPORTED_TRANSLATION_JOB_PROGRAM')
                if _canonical_digest({'plan':plan.normalized_program,
                        'inspection':inspection,
                        'targetMembers':candidate['targetMembers']})!=(
                            candidate['digest']):
                    raise ValueError('TRANSLATION_CANDIDATE_CHANGED')
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                revisions={'metadataRevision':'metadata_revision',
                    'dataRevision':'data_revision',
                    'policyRevision':'policy_revision'}
                if any(state[database] != job['expected_'+database]
                       or state[database] != inspection[result]
                       for result,database in revisions.items()):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer=db.execute('''SELECT published_revision
                    FROM epm.calculation_publication
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (*keys,plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0) != (
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                target=target_coordinate(db,scope,plan)
                if dict(target.members)!=candidate['targetMembers']:
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                enforce_translation_dimensional_security(
                    db, self.identity, scope, inspection, target)
                policy_evidence=enforce_currency_target_policy(
                    db,scope,target,access.role)
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
                revision=state['commit_revision']+1
                source=inspection['periods'][-1]
                db.execute('''INSERT INTO epm.calculation_generation
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',
                    (*keys,claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],FUNCTION,revision))
                db.execute('''INSERT INTO epm.calculation_result
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_amount,source_change_id,amount)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],point['coordinate_id'],
                     source['sourceAmount'],source['sourceChangeId'],
                     inspection['roundedAmount']))
                db.execute('''INSERT INTO epm.calculation_publication
                    (workspace_id,application_id,result_key,generation_id,
                     published_revision) VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,result_key)
                    DO UPDATE SET generation_id=EXCLUDED.generation_id,
                    published_revision=EXCLUDED.published_revision,
                    updated_at=transaction_timestamp()''',
                    (*keys,plan.result_key,claim['job_id'],revision))
                result={'generationId':claim['job_id'],
                    'resultKey':plan.result_key,'function':FUNCTION,
                    'sourceMembers':dict(plan.source_members),
                    'targetMembers':dict(target.members),
                    'method':plan.method,'rateKind':plan.rate_kind,
                    'fromCurrencyMemberId':plan.from_currency,
                    'toCurrencyMemberId':plan.to_currency,
                    'amount':inspection['roundedAmount'],
                    'exactAmount':inspection['exactAmount'],
                    'periods':inspection['periods'],
                    'rowCount':1,'accountingStage':plan.accounting_stage,
                    **({'sourceLayer':plan.source_layer,'icParentEntityId':plan.ic_parent,'sourceBasis':'own_local'} if plan.source_layer else {}),
                    'accountingPolicyStatus':'Unreviewed',
                    'sourceCommitRevision':state['commit_revision'],
                    'committedRevision':revision,
                    'engine':'postgres_exact_rational',
                    'planningPolicy':policy_evidence}
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',
                    (revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],job['program_digest'],
                     job['subject_id'],revision,Jsonb(result)))
                changed=db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s AND claimant=%s
                    AND lease_until>clock_timestamp()''',
                    (revision,Jsonb(result),*keys,claim['job_id'],claim['claim_generation'],claim['claimant'])).rowcount
                if changed!=1: raise ValueError('STALE_WORKER_FENCE')
                return result
