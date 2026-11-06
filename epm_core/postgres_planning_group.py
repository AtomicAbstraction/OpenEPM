"""Bounded many-to-one exact sum over explicitly selected cube members.

Every declared full source coordinate must contain a present numeric cell.
The separate calculated target is one full coordinate; raw facts are intact.
"""
from __future__ import annotations

from dataclasses import dataclass
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
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION = 'facts.planning.group.sum'
COMPILER = 'planning-explicit-group-sum-v1'
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'declared_full_coordinates',
    'outputGrain': 'one_declared_full_coordinate',
    'missing': 'reject', 'sourceType': 'numeric',
    'rounding': 'exact_sum_8',
})
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')


@dataclass(frozen=True, slots=True)
class GroupPlan:
    dimension: str
    source_members: tuple[str, ...]
    target_member: str
    other_members: tuple[tuple[str, str], ...]
    result_key: str
    expected_publication_revision: int

    @property
    def target(self) -> Coordinate:
        return Coordinate.from_mapping({**dict(self.other_members),
                                        self.dimension: self.target_member})

    @property
    def sources(self) -> tuple[Coordinate, ...]:
        return tuple(Coordinate.from_mapping({
            **dict(self.other_members),self.dimension: member})
            for member in self.source_members)

    @property
    def source_rows(self) -> list[dict]:
        return [{'series_key':coordinate.series_key,
                 'members':dict(coordinate.members)}
                for coordinate in self.sources]

    @property
    def normalized_program(self) -> dict:
        return {'version':2,'function':FUNCTION,
                'dimension':self.dimension,
                'sourceMembers':list(self.source_members),
                'targetMember':self.target_member,
                'otherMembers':dict(self.other_members),
                'resultKey':self.result_key,
                'expectedPublicationRevision':
                    self.expected_publication_revision,
                'inputGrain':'declared_full_coordinates',
                'outputGrain':'one_declared_full_coordinate',
                'rounding':'exact_sum_8'}

    def source_params(self, scope: ApplicationScope) -> tuple:
        return (Jsonb(self.source_rows),scope.workspace_id,
                scope.application_id)


def compile_group_program(program: object, *,
                          expected_publication_revision: int) -> GroupPlan:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2 or program['function']!=FUNCTION
            or not isinstance(program['arguments'],dict)
            or set(program['arguments'])!={'dimension','sourceMembers',
                'targetMember','otherMembers','resultKey'}):
        raise ValueError('V2_GROUP_FUNCTION_OR_ARGUMENTS_INVALID')
    args=program['arguments']
    sources=args['sourceMembers']
    others=args['otherMembers']
    if (not isinstance(args['dimension'],str)
            or not 1<=len(args['dimension'])<=200
            or not isinstance(sources,list) or not 2<=len(sources)<=500
            or any(not isinstance(member,str) or not 1<=len(member)<=200
                   for member in sources)
            or len(set(sources))!=len(sources)
            or not isinstance(args['targetMember'],str)
            or not 1<=len(args['targetMember'])<=200
            or args['targetMember'] in sources
            or not isinstance(others,dict) or len(others)>31
            or args['dimension'] in others
            or any(not isinstance(axis,str) or not 1<=len(axis)<=200
                   or not isinstance(member,str) or not 1<=len(member)<=200
                   for axis,member in others.items())
            or not isinstance(args['resultKey'],str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision<0):
        raise ValueError('V2_GROUP_ARGUMENTS_INVALID')
    return GroupPlan(args['dimension'],tuple(sorted(sources)),
                     args['targetMember'],tuple(sorted(others.items())),
                     args['resultKey'],expected_publication_revision)


def decode_group_program(program: object) -> GroupPlan:
    if (not isinstance(program,dict)
            or set(program)!={'version','function','dimension',
                'sourceMembers','targetMember','otherMembers','resultKey',
                'expectedPublicationRevision','inputGrain','outputGrain',
                'rounding'}
            or program['version']!=2 or program['function']!=FUNCTION
            or program['inputGrain']!='declared_full_coordinates'
            or program['outputGrain']!='one_declared_full_coordinate'
            or program['rounding']!='exact_sum_8'):
        raise ValueError('UNSUPPORTED_GROUP_JOB_PROGRAM')
    plan=compile_group_program({'languageVersion':2,'function':FUNCTION,
        'arguments':{key:program[key] for key in ('dimension',
            'sourceMembers','targetMember','otherMembers','resultKey')}},
        expected_publication_revision=program[
            'expectedPublicationRevision'])
    if plan.normalized_program!=program:
        raise ValueError('NONCANONICAL_GROUP_JOB_PROGRAM')
    return plan


_SOURCE = '''FROM jsonb_to_recordset(%s::jsonb)
        AS input(series_key text,members jsonb)
    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
        AND c.application_id=%s AND c.series_key=input.series_key
        AND c.members=input.members
    LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id
        AND n.application_id=c.application_id
        AND n.coordinate_id=c.coordinate_id AND n.present
    LEFT JOIN epm.text_cell_current t ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id AND t.present
    LEFT JOIN epm.line_detail_current d ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id'''


def validate_group_inputs(db,scope:ApplicationScope,plan:GroupPlan)->dict:
    axes={row['dimension_id'] for row in db.execute('''SELECT dimension_id
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
        (scope.workspace_id,scope.application_id)).fetchall()}
    if axes!=set(dict(plan.other_members))|{plan.dimension}:
        raise ValueError('GROUP_COORDINATE_GRAIN_MISMATCH')
    PostgresSourceBatch._check_scope_members(
        db,scope,dict(plan.other_members))
    PostgresSourceBatch._check_scope_members(
        db,scope,{plan.dimension:plan.target_member})
    active=db.execute('''SELECT count(*) AS total FROM epm.member
        WHERE workspace_id=%s AND application_id=%s
        AND dimension_id=%s AND member_id=ANY(%s) AND status='Active' ''',
        (scope.workspace_id,scope.application_id,plan.dimension,
         list(plan.source_members))).fetchone()['total']
    if active!=len(plan.source_members):
        raise ValueError('GROUP_SOURCE_MEMBER_UNAVAILABLE')
    target=plan.target
    conflict=db.execute('''SELECT 1 FROM epm.coordinate c
        LEFT JOIN epm.text_cell_current t ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id
        LEFT JOIN epm.line_detail_current d ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s AND (c.members<>%s::jsonb
            OR COALESCE(t.present,false) OR d.coordinate_id IS NOT NULL)
        LIMIT 1''',(scope.workspace_id,scope.application_id,
            target.series_key,Jsonb(dict(target.members)))).fetchone()
    if conflict:
        raise ValueError('GROUP_TARGET_CONFLICT')
    summary=db.execute(f'''SELECT count(n.coordinate_id) AS source_count,
        count(c.coordinate_id) AS coordinate_count,
        sum(n.amount) AS amount,
        bool_or(t.coordinate_id IS NOT NULL OR
                d.coordinate_id IS NOT NULL) AS type_conflict
        {_SOURCE}''',plan.source_params(scope)).fetchone()
    if summary['type_conflict']:
        raise ValueError('GROUP_SOURCE_TYPE_UNSUPPORTED')
    if (summary['coordinate_count']!=len(plan.source_members)
            or summary['source_count']!=len(plan.source_members)):
        raise ValueError('GROUP_SOURCE_MISSING')
    NumericCell(True,summary['amount'],'')
    return {'sourceCount':summary['source_count'],
            'amount':summary['amount'],'target':dict(target.members)}


def enforce_group_target_policy(db,scope:ApplicationScope,plan:GroupPlan,
                                workflow_role:str)->dict:
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=((plan.target,'Set'),),
        workflow_role=workflow_role)


def enforce_group_dimensional_security(db,identity:VerifiedIdentity,
        scope:ApplicationScope,plan:GroupPlan)->None:
    authorize_coordinates(
        db,identity,scope,plan.sources,kind=AccessKind.READ)
    authorize_coordinates(
        db,identity,scope,(plan.target,),kind=AccessKind.WRITE)


class PostgresGroupPublisher:
    def __init__(self,dsn:str,*,identity:VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def publish(self,claim:dict)->dict:
        if (not isinstance(claim,dict)
                or not isinstance(claim.get('workspace_id'),str)
                or not isinstance(claim.get('application_id'),str)
                or not isinstance(claim.get('job_id'),str)
                or not _JOB.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'),str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                state=db.execute('''SELECT s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
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
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                live=db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant'] or not live):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['function_name']!=FUNCTION
                        or job['compiler_version']!=COMPILER
                        or job['plan_digest']!=PLAN_DIGEST
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_GROUP_JOB_PROGRAM')
                plan=decode_group_program(job['normalized_program'])
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=job[
                        'expected_metadata_revision']
                        or state['data_revision']!=job[
                        'expected_data_revision']
                        or state['policy_revision']!=job[
                        'expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer=db.execute('''SELECT published_revision FROM
                    epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0)!=(
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                summary=validate_group_inputs(db,scope,plan)
                enforce_group_dimensional_security(
                    db,self.identity,scope,plan)
                target=plan.target
                policy_evidence=enforce_group_target_policy(
                    db,scope,plan,access.role)
                db.execute('''CREATE TEMP TABLE group_source_stage
                    (series_key text NOT NULL,
                     source_coordinate_id bigint NOT NULL,
                     source_amount numeric NOT NULL,
                     source_change_id text NOT NULL) ON COMMIT DROP''')
                staged=db.execute(f'''INSERT INTO pg_temp.group_source_stage
                    (series_key,source_coordinate_id,source_amount,
                     source_change_id)
                    SELECT c.series_key,c.coordinate_id,n.amount,n.change_id
                    {_SOURCE}''',plan.source_params(scope)).rowcount
                if staged!=summary['sourceCount']:
                    raise ValueError('GROUP_SOURCE_COUNT_CHANGED')
                db.execute('''CREATE TEMP TABLE group_result_stage
                    (source_amount numeric NOT NULL,
                     source_change_id text NOT NULL,
                     amount numeric NOT NULL) ON COMMIT DROP''')
                inserted=db.execute('''INSERT INTO pg_temp.group_result_stage
                    (source_amount,source_change_id,amount)
                    SELECT sum(source_amount),
                      'group:' || encode(sha256(convert_to(
                        string_agg(source_coordinate_id::text || ':' ||
                          source_change_id,E'\\n' ORDER BY series_key),
                        'UTF8')),'hex'),sum(source_amount)
                    FROM pg_temp.group_source_stage''').rowcount
                if inserted!=1:
                    raise ValueError('GROUP_RESULT_COUNT_CHANGED')
                private_amount=db.execute('''SELECT amount FROM
                    pg_temp.group_result_stage''').fetchone()['amount']
                if private_amount!=summary['amount']:
                    raise ValueError('GROUP_RESULT_CHANGED')

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
                final_pointer=db.execute('''SELECT published_revision FROM
                    epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (final_pointer['published_revision']
                        if final_pointer else 0)!=(
                            plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                if validate_group_inputs(db,scope,plan)!=summary:
                    raise ValueError('GROUP_SOURCE_CHANGED')
                enforce_group_dimensional_security(
                    db,self.identity,scope,plan)
                policy_evidence=enforce_group_target_policy(
                    db,scope,plan,final_access.role)
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (scope.workspace_id,scope.application_id,
                     target.series_key,Jsonb(dict(target.members))))
                coordinate=db.execute('''SELECT coordinate_id,members FROM
                    epm.coordinate WHERE workspace_id=%s AND application_id=%s
                    AND series_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     target.series_key)).fetchone()
                if coordinate['members']!=dict(target.members):
                    raise ValueError('COORDINATE_HASH_COLLISION')
                db.execute('''INSERT INTO epm.coordinate_member_projection
                    (workspace_id,application_id,coordinate_id,
                     dimension_id,member_id,projection_generation)
                    SELECT %s,%s,%s,item.key,item.value,(SELECT epm.active_projection_generation())
                    FROM jsonb_each_text(%s::jsonb) item
                    ON CONFLICT DO NOTHING''',
                    (scope.workspace_id,scope.application_id,
                     coordinate['coordinate_id'],
                     Jsonb(dict(target.members))))
                revision=final_state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_generation
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],FUNCTION,revision))
                durable_result=db.execute('''INSERT INTO epm.calculation_result
                    (workspace_id,application_id,generation_id,coordinate_id,
                     source_amount,source_change_id,amount)
                    SELECT %s,%s,%s,%s,source_amount,source_change_id,amount
                    FROM pg_temp.group_result_stage''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     coordinate['coordinate_id'])).rowcount
                if durable_result!=1:
                    raise ValueError('GROUP_RESULT_COUNT_CHANGED')
                lineage=db.execute('''INSERT INTO epm.rollup_source_lineage
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_coordinate_id,source_amount,
                     source_change_id,source_selection)
                    SELECT %s,%s,%s,%s,source_coordinate_id,source_amount,
                        source_change_id,'explicit'
                    FROM pg_temp.group_source_stage''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     coordinate['coordinate_id'])).rowcount
                if lineage!=summary['sourceCount']:
                    raise ValueError('GROUP_SOURCE_COUNT_CHANGED')
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
                    'resultKey':plan.result_key,'function':FUNCTION,
                    'rowCount':1,'sourceCount':lineage,
                    'amount':format(summary['amount'],'f'),
                    'target':dict(target.members),
                    'sourceCommitRevision':state['commit_revision'],
                    'committedRevision':revision,
                    'engine':'postgres_exact_sql',
                    'planningPolicy':policy_evidence}
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
