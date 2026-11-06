"""Exact set-based many-to-one sums for several declared cube coordinates.

Each target differs only on the declared aggregation axis. The caller names
complete coordinates on all remaining axes; the fixed core requires every
selected numeric source and publishes one immutable multi-row generation.
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
from .postgres_jobs import _canonical_digest, _require_python_job_authority
from .postgres_numeric_store import PostgresNumericFactStore
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION = 'facts.planning.group.sum.bulk'
COMPILER = 'planning-explicit-group-bulk-v1'
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql',
    'inputGrain': 'declared_full_coordinate_sets',
    'outputGrain': 'declared_target_coordinate_set',
    'missing': 'reject', 'sourceType': 'numeric',
    'rounding': 'exact_sum_8',
})
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')


@dataclass(frozen=True, slots=True)
class BulkGroupPlan:
    dimension: str
    source_members: tuple[str, ...]
    target_member: str
    other_member_sets: tuple[tuple[tuple[str, str], ...], ...]
    result_key: str
    expected_publication_revision: int

    @property
    def targets(self) -> tuple[Coordinate, ...]:
        return tuple(Coordinate.from_mapping({**dict(others),
            self.dimension: self.target_member})
            for others in self.other_member_sets)

    @property
    def target_rows(self) -> list[dict]:
        return [{'series_key': target.series_key,
                 'members': dict(target.members)}
                for target in self.targets]

    @property
    def source_rows(self) -> list[dict]:
        rows = []
        for target, others in zip(self.targets, self.other_member_sets,
                                  strict=True):
            for member in self.source_members:
                source = Coordinate.from_mapping({**dict(others),
                    self.dimension: member})
                rows.append({'target_series_key': target.series_key,
                             'source_series_key': source.series_key,
                             'source_members': dict(source.members)})
        return rows

    @property
    def normalized_program(self) -> dict:
        return {'version': 2, 'function': FUNCTION,
                'dimension': self.dimension,
                'sourceMembers': list(self.source_members),
                'targetMember': self.target_member,
                'otherMemberSets': [dict(items)
                                    for items in self.other_member_sets],
                'resultKey': self.result_key,
                'expectedPublicationRevision':
                    self.expected_publication_revision,
                'inputGrain': 'declared_full_coordinate_sets',
                'outputGrain': 'declared_target_coordinate_set',
                'rounding': 'exact_sum_8'}


def compile_bulk_group(program: object, *,
                       expected_publication_revision: int) -> BulkGroupPlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'dimension', 'sourceMembers',
                'targetMember', 'otherMemberSets', 'resultKey'}):
        raise ValueError('V2_BULK_GROUP_FUNCTION_OR_ARGUMENTS_INVALID')
    args = program['arguments']
    sources, groups = args['sourceMembers'], args['otherMemberSets']
    if (not isinstance(args['dimension'], str)
            or not 1 <= len(args['dimension']) <= 200
            or not isinstance(sources, list) or not 2 <= len(sources) <= 500
            or any(not isinstance(member, str)
                   or not 1 <= len(member) <= 200 for member in sources)
            or len(set(sources)) != len(sources)
            or not isinstance(args['targetMember'], str)
            or not 1 <= len(args['targetMember']) <= 200
            or args['targetMember'] in sources
            or not isinstance(groups, list) or not 2 <= len(groups) <= 100
            or len(groups) * len(sources) > 10000
            or any(not isinstance(group, dict) or len(group) > 31
                   or args['dimension'] in group
                   or any(not isinstance(axis, str)
                          or not 1 <= len(axis) <= 200
                          or not isinstance(member, str)
                          or not 1 <= len(member) <= 200
                          for axis, member in group.items())
                   for group in groups)
            or not isinstance(args['resultKey'], str)
            or not _KEY.fullmatch(args['resultKey'])
            or type(expected_publication_revision) is not int
            or expected_publication_revision < 0):
        raise ValueError('V2_BULK_GROUP_ARGUMENTS_INVALID')
    normalized_groups = tuple(sorted(tuple(sorted(group.items()))
                                     for group in groups))
    if len(set(normalized_groups)) != len(normalized_groups):
        raise ValueError('V2_BULK_GROUP_DUPLICATE_TARGET')
    plan = BulkGroupPlan(args['dimension'], tuple(sorted(sources)),
        args['targetMember'], normalized_groups, args['resultKey'],
        expected_publication_revision)
    if len({target.series_key for target in plan.targets}) != len(groups):
        raise ValueError('V2_BULK_GROUP_TARGET_COLLISION')
    return plan


def decode_bulk_group(program: object) -> BulkGroupPlan:
    required = {'version', 'function', 'dimension', 'sourceMembers',
        'targetMember', 'otherMemberSets', 'resultKey',
        'expectedPublicationRevision', 'inputGrain', 'outputGrain', 'rounding'}
    if (not isinstance(program, dict) or set(program) != required
            or program['version'] != 2 or program['function'] != FUNCTION
            or program['inputGrain'] != 'declared_full_coordinate_sets'
            or program['outputGrain'] != 'declared_target_coordinate_set'
            or program['rounding'] != 'exact_sum_8'):
        raise ValueError('UNSUPPORTED_BULK_GROUP_JOB_PROGRAM')
    plan = compile_bulk_group({'languageVersion': 2, 'function': FUNCTION,
        'arguments': {key: program[key] for key in ('dimension',
            'sourceMembers', 'targetMember', 'otherMemberSets', 'resultKey')}},
        expected_publication_revision=program[
            'expectedPublicationRevision'])
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_BULK_GROUP_JOB_PROGRAM')
    return plan


_SOURCE = '''FROM jsonb_to_recordset(%s::jsonb) AS input(
        target_series_key text,source_series_key text,source_members jsonb)
    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
        AND c.application_id=%s
        AND c.series_key=input.source_series_key
        AND c.members=input.source_members
    LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id
        AND n.application_id=c.application_id
        AND n.coordinate_id=c.coordinate_id AND n.present
    LEFT JOIN epm.text_cell_current t ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id AND t.present
    LEFT JOIN epm.line_detail_current d ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id'''


def validate_bulk_inputs(db, scope: ApplicationScope,
                         plan: BulkGroupPlan) -> dict:
    keys = (scope.workspace_id, scope.application_id)
    axes = {row['dimension_id'] for row in db.execute('''SELECT dimension_id
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
        keys).fetchall()}
    if any(axes != set(dict(group)) | {plan.dimension}
           for group in plan.other_member_sets):
        raise ValueError('BULK_GROUP_COORDINATE_GRAIN_MISMATCH')
    selected = {(plan.dimension, member)
                for member in (*plan.source_members, plan.target_member)}
    selected.update(pair for group in plan.other_member_sets
                    for pair in group)
    pairs = [{'dimension_id': axis, 'member_id': member}
             for axis, member in sorted(selected)]
    matched = db.execute('''SELECT count(*) AS total
        FROM jsonb_to_recordset(%s::jsonb)
            AS selected(dimension_id text,member_id text)
        JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
            AND m.dimension_id=selected.dimension_id
            AND m.member_id=selected.member_id AND m.status='Active' ''',
        (Jsonb(pairs), *keys)).fetchone()['total']
    if matched != len(pairs):
        raise ValueError('BULK_GROUP_MEMBER_UNAVAILABLE')
    target_rows = plan.target_rows
    conflict = db.execute('''SELECT 1 FROM
        jsonb_to_recordset(%s::jsonb) AS input(series_key text,members jsonb)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s
            AND c.series_key=input.series_key
        LEFT JOIN epm.text_cell_current t ON t.workspace_id=c.workspace_id
            AND t.application_id=c.application_id
            AND t.coordinate_id=c.coordinate_id
        LEFT JOIN epm.line_detail_current d ON d.workspace_id=c.workspace_id
            AND d.application_id=c.application_id
            AND d.coordinate_id=c.coordinate_id
        WHERE c.members<>input.members OR COALESCE(t.present,false)
            OR d.coordinate_id IS NOT NULL LIMIT 1''',
        (Jsonb(target_rows), *keys)).fetchone()
    if conflict:
        raise ValueError('BULK_GROUP_TARGET_CONFLICT')
    source_rows = plan.source_rows
    rows = db.execute(f'''SELECT input.target_series_key,
        count(c.coordinate_id) AS coordinate_count,
        count(n.coordinate_id) AS source_count,
        sum(n.amount) AS amount,
        bool_or(t.coordinate_id IS NOT NULL OR
                d.coordinate_id IS NOT NULL) AS type_conflict
        {_SOURCE} GROUP BY input.target_series_key
        ORDER BY input.target_series_key''',
        (Jsonb(source_rows), *keys)).fetchall()
    if len(rows) != len(target_rows):
        raise ValueError('BULK_GROUP_SOURCE_MISSING')
    targets_by_key = {row['series_key']: row['members']
                      for row in target_rows}
    output = []
    for row in rows:
        if row['type_conflict']:
            raise ValueError('BULK_GROUP_SOURCE_TYPE_UNSUPPORTED')
        if (row['coordinate_count'] != len(plan.source_members)
                or row['source_count'] != len(plan.source_members)):
            raise ValueError('BULK_GROUP_SOURCE_MISSING')
        NumericCell(True, row['amount'], '')
        output.append({'target': targets_by_key[row['target_series_key']],
                       'amount': row['amount'],
                       'sourceCount': row['source_count']})
    return {'rowCount': len(output),
            'sourceCount': len(source_rows), 'rows': output}


def enforce_bulk_group_target_policy(db,scope:ApplicationScope,
                                     plan:BulkGroupPlan,
                                     workflow_role:str)->dict:
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=tuple((target,'Set') for target in plan.targets),
        workflow_role=workflow_role)


def enforce_bulk_group_dimensional_security(db,identity:VerifiedIdentity,
        scope:ApplicationScope,plan:BulkGroupPlan)->None:
    sources=tuple(Coordinate.from_mapping(row['source_members'])
                  for row in plan.source_rows)
    authorize_coordinates(db,identity,scope,sources,kind=AccessKind.READ)
    authorize_coordinates(
        db,identity,scope,plan.targets,kind=AccessKind.WRITE)


def _bulk_group_replay(job, receipt):
    if receipt is None:
        return None
    if (job is None or job['status'] != 'published'
            or job['receipt_revision'] != receipt['committed_revision']
            or job['result'] != receipt['result']
            or job['subject_id'] != receipt['actor_id']):
        raise ValueError('BULK_GROUP_RECEIPT_CONFLICT')
    return receipt['result']


class PostgresBulkGroupPublisher:
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
        scope = ApplicationScope(claim['workspace_id'],claim['application_id'])
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 20000)
                PostgresNumericFactStore._set_scope(db,scope)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access = PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                job = db.execute('''SELECT * FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                receipt = db.execute('''SELECT committed_revision,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                replay = _bulk_group_replay(job, receipt)
                if replay is not None:
                    return replay
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                live = db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant'] or not live):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['function_name'] != FUNCTION
                        or job['compiler_version'] != COMPILER
                        or job['plan_digest'] != PLAN_DIGEST
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_BULK_GROUP_JOB_PROGRAM')
                _require_python_job_authority(db,scope,job)
                plan = decode_bulk_group(job['normalized_program'])
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(state[kind+'_revision'] !=
                       job['expected_'+kind+'_revision']
                       for kind in ('metadata','data','policy')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer = db.execute('''SELECT published_revision FROM
                    epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (*keys,plan.result_key)).fetchone()
                if (pointer['published_revision'] if pointer else 0) != (
                        plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                summary = validate_bulk_inputs(db,scope,plan)
                enforce_bulk_group_dimensional_security(
                    db,self.identity,scope,plan)
                policy_evidence = enforce_bulk_group_target_policy(
                    db,scope,plan,access.role)
                targets = Jsonb(plan.target_rows)
                sources = Jsonb(plan.source_rows)
                db.execute('''CREATE TEMP TABLE bulk_group_source_stage(
                    target_series_key text NOT NULL,
                    source_coordinate_id bigint NOT NULL,
                    source_series_key text NOT NULL,
                    source_amount numeric(28,8) NOT NULL,
                    source_change_id text NOT NULL,
                    PRIMARY KEY(target_series_key,source_coordinate_id))
                    ON COMMIT DROP''')
                staged = db.execute(f'''INSERT INTO
                    pg_temp.bulk_group_source_stage(target_series_key,
                    source_coordinate_id,source_series_key,source_amount,
                    source_change_id) SELECT input.target_series_key,
                    c.coordinate_id,c.series_key,n.amount,n.change_id
                    {_SOURCE}''',(sources,*keys)).rowcount
                if staged != summary['sourceCount']:
                    raise ValueError('BULK_GROUP_SOURCE_COUNT_CHANGED')
                db.execute('''CREATE TEMP TABLE bulk_group_result_stage(
                    target_series_key text PRIMARY KEY,
                    amount numeric(28,8) NOT NULL,
                    source_count integer NOT NULL,
                    source_change_id text NOT NULL) ON COMMIT DROP''')
                staged_results = db.execute('''INSERT INTO
                    pg_temp.bulk_group_result_stage(target_series_key,amount,
                    source_count,source_change_id)
                    SELECT target_series_key,sum(source_amount),count(*),
                    'group:' || encode(sha256(convert_to(string_agg(
                    source_coordinate_id::text || ':' || source_change_id,
                    E'\\n' ORDER BY source_series_key),'UTF8')),'hex')
                    FROM pg_temp.bulk_group_source_stage
                    GROUP BY target_series_key RETURNING target_series_key,
                    amount,source_count''').fetchall()
                expected = {
                    Coordinate.from_mapping(row['target']).series_key:
                        (format(row['amount'],'f'),row['sourceCount'])
                    for row in summary['rows']}
                if (len(staged_results) != summary['rowCount']
                        or any(expected.get(row['target_series_key']) !=
                            (format(row['amount'],'f'),row['source_count'])
                            for row in staged_results)):
                    raise ValueError('BULK_GROUP_RESULT_COUNT_CHANGED')

                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                final_state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',keys).fetchone()
                final_job = db.execute('''SELECT * FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    FOR UPDATE''',(*keys,claim['job_id'])).fetchone()
                final_receipt = db.execute('''SELECT committed_revision,
                    actor_id,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',(*keys,claim['job_id'])).fetchone()
                replay = _bulk_group_replay(final_job,final_receipt)
                if replay is not None:
                    return replay
                final_live = (final_job is not None and db.execute(
                    '''SELECT %s::timestamptz > clock_timestamp()
                    AS unexpired''',(final_job['lease_until'],)).fetchone()[
                        'unexpired'])
                immutable = ('issuer','subject_id','function_name',
                    'normalized_program','program_digest','plan_digest',
                    'compiler_version','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision',
                    'idempotency_key','python_workflow_id',
                    'execution_delegation_id','execution_delegation_version',
                    'execution_schedule_id','execution_schedule_version')
                if (final_state is None or final_job is None
                        or any(final_job[key] != job[key] for key in immutable)
                        or final_job['status'] != 'running'
                        or final_job['claim_generation'] !=
                            claim['claim_generation']
                        or final_job['claimant'] != claim['claimant']
                        or not final_live):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,final_job)
                final_access = PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                if (final_state['application_status'] != 'Active'
                        or final_state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(final_state[kind+'_revision'] !=
                       final_job['expected_'+kind+'_revision']
                       for kind in ('metadata','data','policy')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                final_pointer = db.execute('''SELECT published_revision FROM
                    epm.calculation_publication WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (*keys,plan.result_key)).fetchone()
                if (final_pointer['published_revision']
                        if final_pointer else 0) != (
                            plan.expected_publication_revision):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                enforce_bulk_group_dimensional_security(
                    db,self.identity,scope,plan)
                policy_evidence = enforce_bulk_group_target_policy(
                    db,scope,plan,final_access.role)
                state,job = final_state,final_job
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    SELECT %s,%s,input.series_key,input.members
                    FROM jsonb_to_recordset(%s::jsonb)
                        AS input(series_key text,members jsonb)
                    ON CONFLICT DO NOTHING''',(*keys,targets))
                coordinates = db.execute('''SELECT c.coordinate_id,
                    c.series_key,c.members FROM jsonb_to_recordset(%s::jsonb)
                        AS input(series_key text,members jsonb)
                    JOIN epm.coordinate c ON c.workspace_id=%s
                        AND c.application_id=%s
                        AND c.series_key=input.series_key''',
                    (targets,*keys)).fetchall()
                targets_by_key = {item['series_key']: item['members']
                                  for item in plan.target_rows}
                if (len(coordinates) != summary['rowCount']
                        or any(row['members'] != targets_by_key.get(
                            row['series_key'])
                            for row in coordinates)):
                    raise ValueError('COORDINATE_HASH_COLLISION')
                db.execute('''INSERT INTO epm.coordinate_member_projection
                    (workspace_id,application_id,coordinate_id,
                     dimension_id,member_id,projection_generation)
                    SELECT %s,%s,c.coordinate_id,item.key,item.value,(SELECT epm.active_projection_generation())
                    FROM jsonb_to_recordset(%s::jsonb)
                        AS input(series_key text,members jsonb)
                    JOIN epm.coordinate c ON c.workspace_id=%s
                        AND c.application_id=%s
                        AND c.series_key=input.series_key,
                        LATERAL jsonb_each_text(input.members) item
                    ON CONFLICT DO NOTHING''',
                    (*keys,targets,*keys))
                revision = state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_generation
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s)''',
                    (*keys,claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],FUNCTION,
                     summary['rowCount'],revision))
                inserted = db.execute('''INSERT INTO epm.calculation_result
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_amount,source_change_id,amount)
                    SELECT %s,%s,%s,target.coordinate_id,
                        grouped.amount,grouped.source_change_id,grouped.amount
                    FROM pg_temp.bulk_group_result_stage grouped
                    JOIN epm.coordinate target ON
                        target.workspace_id=%s AND target.application_id=%s
                        AND target.series_key=grouped.target_series_key''',
                    (*keys,claim['job_id'],*keys)).rowcount
                if inserted != summary['rowCount']:
                    raise ValueError('BULK_GROUP_RESULT_COUNT_CHANGED')
                lineage = db.execute('''INSERT INTO epm.rollup_source_lineage
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_coordinate_id,source_amount,
                     source_change_id,source_selection)
                    SELECT %s,%s,%s,target.coordinate_id,
                        source.source_coordinate_id,source.source_amount,
                        source.source_change_id,'explicit'
                    FROM pg_temp.bulk_group_source_stage source
                    JOIN epm.coordinate target ON target.workspace_id=%s
                        AND target.application_id=%s
                        AND target.series_key=source.target_series_key''',
                    (*keys,claim['job_id'],*keys)).rowcount
                if lineage != summary['sourceCount']:
                    raise ValueError('BULK_GROUP_SOURCE_COUNT_CHANGED')
                db.execute('''INSERT INTO epm.calculation_publication
                    (workspace_id,application_id,result_key,generation_id,
                     published_revision) VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (workspace_id,application_id,result_key)
                    DO UPDATE SET generation_id=EXCLUDED.generation_id,
                    published_revision=EXCLUDED.published_revision,
                    updated_at=transaction_timestamp()''',
                    (*keys,plan.result_key,claim['job_id'],revision))
                result = {'generationId':claim['job_id'],
                    'resultKey':plan.result_key,'function':FUNCTION,
                    'rowCount':summary['rowCount'],
                    'sourceCount':lineage,
                    'rows':[{'target':row['target'],
                             'amount':format(row['amount'],'.8f')}
                            for row in summary['rows']],
                    'sourceCommitRevision':state['commit_revision'],
                    'committedRevision':revision,
                    'engine':'postgres_exact_sql',
                    'planningPolicy':policy_evidence}
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',(revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],job['program_digest'],
                     job['subject_id'],revision,Jsonb(result)))
                changed = db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s AND status='running'
                    AND claim_generation=%s AND claimant=%s
                    AND lease_until>clock_timestamp()''',
                    (revision,Jsonb(result),*keys,claim['job_id'],
                     claim['claim_generation'],claim['claimant'])).rowcount
                if changed != 1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
