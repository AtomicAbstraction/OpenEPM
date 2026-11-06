"""Exact equal top-down spread into an immutable planning result generation.

This is a generic-cube planning function: no finance-only axis is assumed.
It does not perform source-data writeback or planning workflow transitions.
The bounded target metadata loop constructs canonical coordinate keys; all
target result arithmetic and persistence are one relational SQL stage.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope,Coordinate
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION='facts.planning.spread.equal'
COMPILER='planning-spread-equal-v1'
PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':1,
    'engine':'postgres_exact_sql','inputGrain':'full_coordinate',
    'outputGrain':'rebound_full_coordinate',
    'unitScale':8,'residualOrder':'stable_member_id'})
POLICY_COMPILER='planning-spread-equal-policy-v1'
POLICY_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':1,
    'engine':'postgres_exact_sql','inputGrain':'full_coordinate',
    'outputGrain':'rebound_full_coordinate','unitScale':8,
    'residualOrder':'stable_member_id',
    'policyContract':'openepm-planning-operation-policy-v1',
    'calendarPolicy':'selection_order','totalPreservation':'exact'})
CALENDAR_FUNCTION='facts.planning.spread.calendar.equal'
CALENDAR_COMPILER='planning-spread-calendar-equal-v1'
CALENDAR_PLAN_DIGEST=_canonical_digest({
    'function':CALENDAR_FUNCTION,'loweringVersion':1,
    'engine':'postgres_exact_sql','inputGrain':'full_coordinate',
    'outputGrain':'rebound_full_coordinate',
    'unitScale':8,'residualOrder':'fiscal_period_ordinal'})
POLICY_CALENDAR_COMPILER='planning-spread-calendar-policy-v2'
POLICY_CALENDAR_PLAN_DIGEST=_canonical_digest({
    'function':CALENDAR_FUNCTION,'loweringVersion':2,
    'engine':'postgres_exact_sql','inputGrain':'full_coordinate',
    'outputGrain':'rebound_full_coordinate','unitScale':8,
    'residualOrder':'fiscal_period_ordinal',
    'policyContract':'openepm-planning-operation-policy-v2',
    'calendarPolicy':'fiscal_ordinal','totalPreservation':'exact',
    'roundingPolicy':'largestRemainderFiscalOrdinal'})
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB_ID=re.compile(r'[0-9a-f]{32}\Z')


@dataclass(frozen=True,slots=True)
class SpreadPlan:
    source: Coordinate
    target_dimension: str
    target_members: tuple[str,...]
    result_key: str
    expected_publication_revision: int
    function: str=FUNCTION
    calendar_selection: tuple[str,int,int] | None=None

    @property
    def normalized_program(self) -> dict:
        program={'version':2,'function':self.function,
                'source':dict(self.source.members),
                'targetDimension':self.target_dimension,
                'targetMembers':list(self.target_members),
                'resultKey':self.result_key,
                'expectedPublicationRevision':
                    self.expected_publication_revision,
                'inputGrain':'full_coordinate',
                'outputGrain':'rebound_full_coordinate',
                'rounding':('minor-unit-residual-calendar-order'
                            if self.calendar_selection else
                            'minor-unit-residual-stable-member')}
        if self.calendar_selection:
            year,first,last=self.calendar_selection
            program.update({'yearId':year,'firstOrdinal':first,
                            'lastOrdinal':last})
        return program

    @property
    def outputs(self) -> list[dict]:
        source=dict(self.source.members)
        result=[]
        for ordinal,member in enumerate(self.target_members,1):
            members={**source,self.target_dimension:member}
            coordinate=Coordinate.from_mapping(members)
            row={'member_id':member,'series_key':coordinate.series_key,
                 'members':members}
            if self.calendar_selection:
                row['target_ordinal']=ordinal
            result.append(row)
        return result


def _calendar_roles(db,scope: ApplicationScope) -> dict:
    roles={}
    for row in db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role IN ('Year','Period')''',
        (scope.workspace_id,scope.application_id)).fetchall():
        if row['model_role'] in roles:
            raise ValueError('CALENDAR_SPREAD_MODEL_ROLE_AMBIGUOUS')
        roles[row['model_role']]=row['dimension_id']
    if set(roles)!={'Year','Period'}:
        raise ValueError('CALENDAR_SPREAD_MODEL_ROLES_REQUIRED')
    return roles


def _calendar_targets(db,scope: ApplicationScope,source: Coordinate,
                      year_id: str,first: int,last: int) -> tuple[str,...]:
    roles=_calendar_roles(db,scope)
    if dict(source.members).get(roles['Year'])!=year_id:
        raise ValueError('CALENDAR_SPREAD_SOURCE_YEAR_MISMATCH')
    rows=db.execute('''SELECT ordinal,period_member_id
        FROM epm.calendar_period_current WHERE workspace_id=%s
        AND application_id=%s AND year_member_id=%s
        AND ordinal BETWEEN %s AND %s ORDER BY ordinal''',
        (scope.workspace_id,scope.application_id,year_id,first,last)
        ).fetchall()
    if ([row['ordinal'] for row in rows]!=list(range(first,last+1))
            or dict(source.members).get(roles['Period']) in
                {row['period_member_id'] for row in rows}):
        raise ValueError('CALENDAR_SPREAD_RANGE_INCOMPLETE_OR_SOURCE_TARGET')
    return tuple(row['period_member_id'] for row in rows)


def compile_calendar_spread_program(db,scope: ApplicationScope,
                                    program: object,*,
                                    expected_publication_revision: int
                                    ) -> SpreadPlan:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2
            or program['function']!=CALENDAR_FUNCTION
            or not isinstance(program['arguments'],dict)
            or set(program['arguments'])!={'source','yearId',
                                           'firstOrdinal','lastOrdinal',
                                           'resultKey'}):
        raise ValueError('V2_CALENDAR_SPREAD_ARGUMENTS_INVALID')
    args=program['arguments']
    try:
        source=Coordinate.from_mapping(args['source'])
    except (TypeError,ValueError) as error:
        raise ValueError('V2_CALENDAR_SPREAD_SOURCE_INVALID') from error
    first,last=args['firstOrdinal'],args['lastOrdinal']
    if (not isinstance(args['yearId'],str)
            or not 1<=len(args['yearId'])<=200
            or type(first) is not int or type(last) is not int
            or not 1<=first<=last<=366 or last-first>=500
            or not isinstance(args['resultKey'],str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision<0):
        raise ValueError('V2_CALENDAR_SPREAD_ARGUMENTS_INVALID')
    roles=_calendar_roles(db,scope)
    targets=_calendar_targets(db,scope,source,args['yearId'],first,last)
    if not targets:
        raise ValueError('CALENDAR_SPREAD_RANGE_INCOMPLETE_OR_SOURCE_TARGET')
    return SpreadPlan(source,roles['Period'],targets,args['resultKey'],
                      expected_publication_revision,CALENDAR_FUNCTION,
                      (args['yearId'],first,last))


def compile_spread_program(program: object,*,
                           expected_publication_revision: int) -> SpreadPlan:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2
            or program['function']!=FUNCTION
            or not isinstance(program['arguments'],dict)
            or set(program['arguments'])!={'source','targetDimension',
                                           'targetMembers','resultKey'}):
        raise ValueError('V2_SPREAD_FUNCTION_OR_ARGUMENTS_INVALID')
    args=program['arguments']
    try:
        source=Coordinate.from_mapping(args['source'])
    except (TypeError,ValueError) as error:
        raise ValueError('V2_SPREAD_SOURCE_INVALID') from error
    dimension=args['targetDimension']
    members=args['targetMembers']
    key=args['resultKey']
    if (not isinstance(dimension,str) or not 1<=len(dimension)<=200
            or dimension not in dict(source.members)
            or not isinstance(members,list) or not 1<=len(members)<=500
            or any(not isinstance(member,str) or not 1<=len(member)<=200
                   for member in members)
            or len(set(members))!=len(members)
            or dict(source.members)[dimension] in members
            or not isinstance(key,str) or not _KEY.fullmatch(key)
            or type(expected_publication_revision) is not int
            or expected_publication_revision<0):
        raise ValueError('V2_SPREAD_ARGUMENTS_INVALID')
    return SpreadPlan(source,dimension,tuple(sorted(members)),key,
                      expected_publication_revision)


def decode_spread_program(program: object) -> SpreadPlan:
    if isinstance(program,dict) and program.get('function')==CALENDAR_FUNCTION:
        if (set(program)!={'version','function','source',
                            'targetDimension','targetMembers','resultKey',
                            'expectedPublicationRevision','inputGrain',
                            'outputGrain','rounding','yearId',
                            'firstOrdinal','lastOrdinal'}
                or type(program['version']) is not int
                or program['version']!=2
                or program['inputGrain']!='full_coordinate'
                or program['outputGrain']!='rebound_full_coordinate'
                or program['rounding']!=
                    'minor-unit-residual-calendar-order'
                or not isinstance(program['targetDimension'],str)
                or not 1<=len(program['targetDimension'])<=200
                or not isinstance(program['targetMembers'],list)
                or not 1<=len(program['targetMembers'])<=500
                or any(not isinstance(member,str) or not 1<=len(member)<=200
                       for member in program['targetMembers'])
                or len(set(program['targetMembers']))!=len(
                    program['targetMembers'])
                or not isinstance(program['yearId'],str)
                or not 1<=len(program['yearId'])<=200
                or type(program['firstOrdinal']) is not int
                or type(program['lastOrdinal']) is not int
                or not 1<=program['firstOrdinal']<=
                    program['lastOrdinal']<=366
                or program['lastOrdinal']-program['firstOrdinal']+1!=len(
                    program['targetMembers'])
                or not isinstance(program['resultKey'],str)
                or not _KEY.fullmatch(program['resultKey'])
                or type(program['expectedPublicationRevision']) is not int
                or program['expectedPublicationRevision']<0):
            raise ValueError('UNSUPPORTED_CALENDAR_SPREAD_JOB_PROGRAM')
        try:
            source=Coordinate.from_mapping(program['source'])
        except (TypeError,ValueError) as error:
            raise ValueError('UNSUPPORTED_CALENDAR_SPREAD_JOB_PROGRAM') from error
        plan=SpreadPlan(source,program['targetDimension'],
                        tuple(program['targetMembers']),program['resultKey'],
                        program['expectedPublicationRevision'],
                        CALENDAR_FUNCTION,
                        (program['yearId'],program['firstOrdinal'],
                         program['lastOrdinal']))
        if plan.normalized_program!=program:
            raise ValueError('NONCANONICAL_CALENDAR_SPREAD_JOB_PROGRAM')
        return plan
    if (not isinstance(program,dict)
            or set(program)!={'version','function','source','targetDimension',
                               'targetMembers','resultKey',
                               'expectedPublicationRevision','inputGrain',
                               'outputGrain','rounding'}
            or type(program['version']) is not int
            or program['version']!=2 or program['function']!=FUNCTION
            or program['inputGrain']!='full_coordinate'
            or program['outputGrain']!='rebound_full_coordinate'
            or program['rounding']!='minor-unit-residual-stable-member'):
        raise ValueError('UNSUPPORTED_SPREAD_JOB_PROGRAM')
    plan=compile_spread_program({'languageVersion':2,
        'function':FUNCTION,'arguments':{
            'source':program['source'],
            'targetDimension':program['targetDimension'],
            'targetMembers':program['targetMembers'],
            'resultKey':program['resultKey']}},
        expected_publication_revision=program['expectedPublicationRevision'])
    if plan.normalized_program!=program:
        raise ValueError('NONCANONICAL_SPREAD_JOB_PROGRAM')
    return plan


def encode_policy_spread_program(plan: SpreadPlan, policy: dict) -> dict:
    required={'policyId','version','policyDigest','metadataRevision',
              'policyRevision','authoredMetadataRevision',
              'authoredPolicyRevision','pointerVersion','stateRevision'}
    if not isinstance(policy,dict) or set(policy)!=required:
        raise ValueError('SPREAD_POLICY_PIN_INVALID')
    if ((plan.function==FUNCTION) != (plan.calendar_selection is None)
            or plan.function not in (FUNCTION,CALENDAR_FUNCTION)):
        raise ValueError('SPREAD_POLICY_PLAN_INVALID')
    return {**plan.normalized_program,'reusablePolicy':dict(policy)}


def decode_policy_spread_program(program: object) -> tuple[SpreadPlan,dict]:
    if not isinstance(program,dict) or 'reusablePolicy' not in program:
        raise ValueError('UNSUPPORTED_SPREAD_POLICY_JOB_PROGRAM')
    policy=program['reusablePolicy'];base=dict(program);base.pop('reusablePolicy')
    plan=decode_spread_program(base)
    if encode_policy_spread_program(plan,policy)!=program:
        raise ValueError('NONCANONICAL_SPREAD_POLICY_JOB_PROGRAM')
    return plan,policy


def _current_policy_pointer_matches(db,scope: ApplicationScope,
                                    policy: dict)->bool:
    row=db.execute('''SELECT p.version,p.canonical_digest,
        s.pointer_version,s.state_revision,a.metadata_revision,
        a.policy_revision FROM epm.planning_operation_policy_state s
        JOIN epm.planning_operation_policy_version p
          ON p.workspace_id=s.workspace_id
         AND p.application_id=s.application_id
         AND p.policy_id=s.policy_id AND p.version=s.active_version
        JOIN epm.application_state a ON a.workspace_id=s.workspace_id
         AND a.application_id=s.application_id
        WHERE s.workspace_id=%s AND s.application_id=%s
          AND s.policy_id=%s''',(scope.workspace_id,scope.application_id,
                                policy.get('policyId'))).fetchone()
    return row is not None and all((
        row['version']==policy.get('version'),
        row['canonical_digest']==policy.get('policyDigest'),
        row['pointer_version']==policy.get('pointerVersion'),
        row['state_revision']==policy.get('stateRevision'),
        row['metadata_revision']==policy.get('metadataRevision'),
        row['policy_revision']==policy.get('policyRevision')))


def validate_spread_inputs(db,scope: ApplicationScope,plan: SpreadPlan) -> dict:
    if plan.calendar_selection:
        year,first,last=plan.calendar_selection
        roles=_calendar_roles(db,scope)
        if plan.target_dimension!=roles['Period']:
            raise ValueError('CALENDAR_SPREAD_TARGET_AXIS_CHANGED')
        if _calendar_targets(db,scope,plan.source,year,first,last)!=(
                plan.target_members):
            raise ValueError('CALENDAR_SPREAD_MAPPING_CHANGED')
    axes={row['dimension_id'] for row in db.execute('''SELECT dimension_id
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
        (scope.workspace_id,scope.application_id)).fetchall()}
    if set(dict(plan.source.members))!=axes:
        raise ValueError('SPREAD_SOURCE_GRAIN_MISMATCH')
    inputs=[{'dimension_id':axis,'member_id':member}
            for axis,member in plan.source.members]
    inputs += [{'dimension_id':plan.target_dimension,'member_id':member}
               for member in plan.target_members]
    found=db.execute('''SELECT input.dimension_id,input.member_id,
        m.member_id IS NOT NULL AS active
        FROM jsonb_to_recordset(%s::jsonb)
        AS input(dimension_id text,member_id text)
        LEFT JOIN epm.member m ON m.workspace_id=%s
        AND m.application_id=%s
        AND m.dimension_id=input.dimension_id
        AND m.member_id=input.member_id AND m.status='Active' ''',
        (Jsonb(inputs),scope.workspace_id,scope.application_id)).fetchall()
    if len(found)!=len(inputs) or any(not row['active'] for row in found):
        raise ValueError('SPREAD_MEMBER_UNAVAILABLE')
    source=db.execute('''SELECT c.members,n.amount,n.change_id
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
        ON n.workspace_id=c.workspace_id
        AND n.application_id=c.application_id
        AND n.coordinate_id=c.coordinate_id
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s AND n.present''',
        (scope.workspace_id,scope.application_id,
         plan.source.series_key)).fetchone()
    if source is None or source['members']!=dict(plan.source.members):
        raise ValueError('SPREAD_SOURCE_MISSING')
    conflict=db.execute('''SELECT 1 FROM
        jsonb_to_recordset(%s::jsonb)
        AS input(series_key text,members jsonb)
        JOIN epm.coordinate c ON c.workspace_id=%s
        AND c.application_id=%s AND c.series_key=input.series_key
        LEFT JOIN epm.text_cell_current t ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id
        LEFT JOIN epm.line_detail_current d ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id
        WHERE c.members<>input.members OR COALESCE(t.present,false)
        OR d.coordinate_id IS NOT NULL LIMIT 1''',
        (Jsonb(plan.outputs),scope.workspace_id,
         scope.application_id)).fetchone()
    if conflict:
        raise ValueError('SPREAD_TARGET_CONFLICT')
    return source


def enforce_spread_target_policy(db,scope: ApplicationScope,
                                 plan: SpreadPlan,workflow_role: str) -> dict:
    """Guard final output Set operations; the source remains read-only."""
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=tuple((
            Coordinate.from_mapping(target['members']),'Set')
            for target in plan.outputs),workflow_role=workflow_role)


def enforce_spread_dimensional_security(db,identity: VerifiedIdentity,
        scope: ApplicationScope,plan: SpreadPlan) -> None:
    """Authorize the exact source and every deterministic spread output."""
    authorize_coordinates(
        db,identity,scope,(plan.source,),kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,tuple(
        Coordinate.from_mapping(target['members']) for target in plan.outputs),
        kind=AccessKind.WRITE)


class PostgresSpreadPublisher:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn=dsn
        self.identity=identity

    def publish(self,claim: dict) -> dict:
        if (not isinstance(claim,dict)
                or not isinstance(claim.get('workspace_id'),str)
                or not isinstance(claim.get('application_id'),str)
                or not isinstance(claim.get('job_id'),str)
                or not _JOB_ID.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'),str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                state=db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    ''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                job=db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                valid=db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant'] or not valid):
                    raise ValueError('STALE_WORKER_FENCE')
                expected_contract={
                    FUNCTION:(COMPILER,PLAN_DIGEST),
                    'policy:' + FUNCTION:(POLICY_COMPILER,POLICY_PLAN_DIGEST),
                    CALENDAR_FUNCTION:(CALENDAR_COMPILER,
                                       CALENDAR_PLAN_DIGEST),
                    'policy:' + CALENDAR_FUNCTION:(
                        POLICY_CALENDAR_COMPILER,
                        POLICY_CALENDAR_PLAN_DIGEST)}
                policy_job=((job['function_name']==FUNCTION
                              and job['compiler_version']==POLICY_COMPILER)
                    or (job['function_name']==CALENDAR_FUNCTION
                        and job['compiler_version']==
                            POLICY_CALENDAR_COMPILER))
                expected=expected_contract.get(
                    'policy:'+job['function_name'] if policy_job
                    else job['function_name'])
                if (expected is None
                        or (job['compiler_version'],job['plan_digest'])!=
                            expected
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_SPREAD_JOB_PROGRAM')
                if policy_job:
                    plan,reusable_policy=decode_policy_spread_program(
                        job['normalized_program'])
                    if not _current_policy_pointer_matches(
                            db,scope,reusable_policy):
                        raise ValueError('PLANNING_POLICY_POINTER_STALE')
                else:
                    plan=decode_spread_program(job['normalized_program'])
                if plan.function!=job['function_name']:
                    raise ValueError('SPREAD_JOB_FUNCTION_MISMATCH')
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=job['expected_metadata_revision']
                        or state['data_revision']!=job['expected_data_revision']
                        or state['policy_revision']!=job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer=db.execute('''SELECT published_revision
                    FROM epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0)!=(
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                source=validate_spread_inputs(db,scope,plan)
                enforce_spread_dimensional_security(
                    db,self.identity,scope,plan)
                targets=plan.outputs
                policy_evidence=enforce_spread_target_policy(
                    db,scope,plan,access.role)
                # Equal-share arithmetic may be large.  Build the complete
                # candidate privately before taking the application
                # publication row; target coordinates are materialized only
                # after that fence because their database trigger correctly
                # takes the same application row.
                db.execute('''CREATE TEMP TABLE spread_result_stage
                    (series_key text PRIMARY KEY,
                     source_amount numeric NOT NULL,
                     source_change_id text NOT NULL,
                     amount numeric NOT NULL)
                    ON COMMIT DROP''')
                order_by=('input.target_ordinal'
                          if plan.calendar_selection else 'input.member_id')
                inserted=db.execute(f'''WITH ranked AS (
                    SELECT input.series_key,input.member_id,
                        row_number() OVER (ORDER BY {order_by}) AS ordinal,
                        count(*) OVER () AS target_count
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS input(series_key text,member_id text,
                             target_ordinal integer)
                ), shares AS (
                    SELECT series_key,ordinal,
                        div((%s::numeric * 100000000::numeric),
                            target_count) AS base_units,
                        (%s::numeric * 100000000::numeric)
                          - div((%s::numeric * 100000000::numeric),
                                target_count) * target_count
                          AS residual_units
                    FROM ranked
                ) INSERT INTO pg_temp.spread_result_stage
                    (series_key,source_amount,source_change_id,amount)
                    SELECT series_key,%s,%s,
                        (base_units + CASE WHEN ordinal<=abs(residual_units)
                            THEN sign(residual_units) ELSE 0 END)
                          * 0.00000001::numeric
                    FROM shares''',
                    (Jsonb(targets),
                     source['amount'],source['amount'],source['amount'],
                     source['amount'],source['change_id'])).rowcount
                if inserted!=len(targets):
                    raise ValueError('SPREAD_TARGET_COUNT_CHANGED')
                conserved=db.execute('''SELECT sum(amount) AS total
                    FROM pg_temp.spread_result_stage''').fetchone()['total']
                if conserved!=source['amount']:
                    raise ValueError('SPREAD_CONSERVATION_FAILED')

                # Fence only final publication, then repeat every mutable
                # input, permission, plan pointer and policy dependency.
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
                final_valid=(final_job is not None and db.execute(
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
                        or not final_valid):
                    raise ValueError('STALE_WORKER_FENCE')
                final_access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
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
                if (policy_job and not _current_policy_pointer_matches(
                        db,scope,reusable_policy)):
                    raise ValueError('PLANNING_POLICY_POINTER_STALE')
                final_pointer=db.execute('''SELECT published_revision
                    FROM epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (final_pointer['published_revision']
                        if final_pointer else 0)!=(
                            plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                if validate_spread_inputs(db,scope,plan)!=source:
                    raise ValueError('SPREAD_SOURCE_CHANGED')
                enforce_spread_dimensional_security(
                    db,self.identity,scope,plan)
                policy_evidence=enforce_spread_target_policy(
                    db,scope,plan,final_access.role)
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    SELECT %s,%s,input.series_key,input.members
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS input(series_key text,members jsonb)
                    ON CONFLICT DO NOTHING''',
                    (scope.workspace_id,scope.application_id,Jsonb(targets)))
                db.execute('''INSERT INTO epm.coordinate_member_projection
                    (workspace_id,application_id,coordinate_id,
                     dimension_id,member_id,projection_generation)
                    SELECT c.workspace_id,c.application_id,c.coordinate_id,
                           item.key,item.value,(SELECT epm.active_projection_generation())
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS input(series_key text,members jsonb)
                    JOIN epm.coordinate c ON c.workspace_id=%s
                    AND c.application_id=%s AND c.series_key=input.series_key
                    CROSS JOIN LATERAL jsonb_each_text(input.members) item
                    ON CONFLICT DO NOTHING''',
                    (Jsonb(targets),scope.workspace_id,
                     scope.application_id))
                revision=final_state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_generation
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],plan.function,len(targets),revision))
                durable_rows=db.execute('''INSERT INTO epm.calculation_result
                    (workspace_id,application_id,generation_id,coordinate_id,
                     source_amount,source_change_id,amount)
                    SELECT %s,%s,%s,c.coordinate_id,s.source_amount,
                           s.source_change_id,s.amount
                    FROM pg_temp.spread_result_stage s
                    JOIN epm.coordinate c ON c.workspace_id=%s
                     AND c.application_id=%s AND c.series_key=s.series_key''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     scope.workspace_id,scope.application_id)).rowcount
                if durable_rows!=inserted:
                    raise ValueError('SPREAD_TARGET_COUNT_CHANGED')
                db.execute('''INSERT INTO epm.calculation_publication
                    (workspace_id,application_id,result_key,generation_id,
                     published_revision) VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,result_key)
                    DO UPDATE SET generation_id=EXCLUDED.generation_id,
                    published_revision=EXCLUDED.published_revision,
                    updated_at=transaction_timestamp()''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key,claim['job_id'],revision))
                result={'generationId':claim['job_id'],
                        'resultKey':plan.result_key,
                        'function':plan.function,
                        'rowCount':inserted,
                        'sourceAmount':format(source['amount'],'f'),
                        'sourceCommitRevision':state['commit_revision'],
                        'committedRevision':revision,
                        'engine':'postgres_exact_sql',
                        'planningPolicy':policy_evidence}
                if policy_job:
                    result['reusablePolicy']=reusable_policy
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'],job['program_digest'],
                     job['subject_id'],revision,Jsonb(result)))
                changed=db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s
                    AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision,Jsonb(result),scope.workspace_id,
                     scope.application_id,claim['job_id'],
                     claim['claim_generation'],claim['claimant'])).rowcount
                if changed!=1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
