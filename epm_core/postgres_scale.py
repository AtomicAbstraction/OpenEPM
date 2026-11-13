"""Typed exact scale stage over the generic cube, lowered to PostgreSQL SQL.

The first relational calculation stage is deliberately a separate published
result layer. It does not rewrite source facts. General expression trees,
multi-stage plans and large asynchronous staging still require P10 work.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .current_object_contract import require_state_token
from .postgres_capability_contract import producer_capability_status
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest, _require_python_job_authority
from .postgres_numeric_store import PostgresNumericFactStore
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import (
    authorize_coordinates, filter_read_rows)
from .postgres_calculation_visibility import (
    redact_calculation_lineage, redact_expression_lineage,
    redact_expression_result_metadata)
from .postgres_calculation_status import published_result_status


_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_FUNCTION = 'facts.numeric.scale'
_COMPILER = 'numeric-relational-v1'
_PLAN_DIGEST = _canonical_digest({
    'function': _FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql', 'rounding': 'half-even-8',
    'inputGrain': 'full_coordinate', 'outputGrain': 'full_coordinate',
})


@dataclass(frozen=True, slots=True)
class ScalePlan:
    source_members: tuple[tuple[str, str], ...]
    factor: Decimal
    result_key: str
    expected_target_state_token: str | None

    @property
    def normalized_program(self) -> dict:
        return {'function': _FUNCTION,
                'sourceMembers': dict(self.source_members),
                'factor': format(self.factor, 'f'),
                'resultKey': self.result_key,
                'expectedTargetStateToken': self.expected_target_state_token,
                'rounding': 'half-even-8',
                'inputGrain': 'full_coordinate',
                'outputGrain': 'full_coordinate'}


def _ratio(value: object) -> Decimal:
    if not isinstance(value, str):
        raise ValueError('SCALE_FACTOR_DECIMAL_STRING_REQUIRED')
    try:
        ratio = Decimal(value)
    except (InvalidOperation, ValueError) as error:
        raise ValueError('SCALE_FACTOR_INVALID') from error
    if not ratio.is_finite():
        raise ValueError('SCALE_FACTOR_INVALID')
    digits = len(ratio.as_tuple().digits)
    exponent = ratio.as_tuple().exponent
    if max(0, digits + exponent) > 8 or -exponent > 12:
        raise ValueError('SCALE_FACTOR_OUT_OF_RANGE')
    return ratio


def compile_scale_program(program: object,
                          *, expected_target_state_token: str | None) -> ScalePlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != _FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) != {'sourceMembers', 'factor',
                                             'resultKey'}):
        raise ValueError('V2_SCALE_FUNCTION_OR_ARGUMENTS_INVALID')
    args = program['arguments']
    members = args['sourceMembers']
    factor = args['factor']
    key = args['resultKey']
    if (not isinstance(members, dict) or len(members) > 32
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in members.items())
            or not isinstance(factor, dict)
            or set(factor) != {'type', 'decimal'}
            or factor['type'] != 'RatioLiteral'
            or not isinstance(key, str) or not _RESULT_KEY.fullmatch(key)):
        raise ValueError('V2_SCALE_ARGUMENTS_INVALID')
    if expected_target_state_token is not None:
        require_state_token(expected_target_state_token,
                            error='V2_SCALE_ARGUMENTS_INVALID')
    return ScalePlan(tuple(sorted(members.items())),
                     _ratio(factor['decimal']), key,
                     expected_target_state_token)


def decode_scale_program(program: object) -> ScalePlan:
    if (not isinstance(program, dict)
            or set(program) != {'function', 'sourceMembers',
                                'factor', 'resultKey',
                                'expectedTargetStateToken', 'rounding',
                                'inputGrain', 'outputGrain'}
            or program['function'] != _FUNCTION
            or program['rounding'] != 'half-even-8'
            or program['inputGrain'] != 'full_coordinate'
            or program['outputGrain'] != 'full_coordinate'):
        raise ValueError('UNSUPPORTED_SCALE_JOB_PROGRAM')
    source = {'languageVersion': 2, 'function': _FUNCTION,
              'arguments': {'sourceMembers': program['sourceMembers'],
                            'factor': {'type': 'RatioLiteral',
                                       'decimal': program['factor']},
                            'resultKey': program['resultKey']}}
    plan = compile_scale_program(
        source,
        expected_target_state_token=program['expectedTargetStateToken'])
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_SCALE_JOB_PROGRAM')
    return plan


def _member_predicates(members: tuple[tuple[str, str], ...]) -> tuple[str, list[str]]:
    predicates = []
    parameters = []
    for axis, member in members:
        predicates.append('''AND EXISTS (SELECT 1 FROM epm.coordinate_member cm
            WHERE cm.workspace_id=c.workspace_id
            AND cm.application_id=c.application_id
            AND cm.coordinate_id=c.coordinate_id
            AND cm.dimension_id=%s AND cm.member_id=%s)''')
        parameters.extend((axis, member))
    return '\n'.join(predicates), parameters


def enforce_scale_target_policy(db,scope:ApplicationScope,targets,
                                workflow_role:str)->dict|None:
    if not targets:
        return None
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=tuple((Coordinate.from_mapping(row['members']),'Set')
                              for row in targets),
        workflow_role=workflow_role)


def _scale_state(db,scope:ApplicationScope,*,lock:bool=False)->dict:
    row=db.execute('''SELECT s.metadata_revision,s.data_revision,
        s.policy_revision,s.commit_revision,s.processing_mode,
        a.status AS application_status
        FROM epm.application_state s JOIN epm.application a
        USING (workspace_id,application_id)
        WHERE s.workspace_id=%s AND s.application_id=%s''' +
        (' FOR UPDATE OF s' if lock else ''),
        (scope.workspace_id,scope.application_id)).fetchone()
    if row is None:
        raise ValueError('APPLICATION_UNAVAILABLE')
    if (row['application_status']!='Active'
            or row['processing_mode']!='Active'):
        raise ValueError('APPLICATION_NOT_WRITABLE')
    return dict(row)


def _scale_candidate(db,scope:ApplicationScope,plan:ScalePlan)->tuple[dict,...]:
    """Resolve the bounded exact SQL result without creating durable effects."""
    if plan.source_members:
        found=db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
              AS input(dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s
              AND m.application_id=%s
              AND m.dimension_id=input.dimension_id
              AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb([{'dimension_id':axis,'member_id':member}
                    for axis,member in plan.source_members]),
             scope.workspace_id,scope.application_id)).fetchall()
        if (len(found)!=len(plan.source_members)
                or any(not row['active'] for row in found)):
            raise ValueError('CALCULATION_SOURCE_MEMBER_UNAVAILABLE')
    predicate,params=_member_predicates(plan.source_members)
    try:
        rows=db.execute(f'''SELECT c.series_key,c.coordinate_id,c.members,
            n.amount AS source_amount,n.change_id AS source_change_id,
            epm.round_half_even(n.amount * %s::numeric,8)::numeric(28,8) AS amount
            FROM epm.coordinate c JOIN epm.numeric_cell_current n
              ON n.workspace_id=c.workspace_id
              AND n.application_id=c.application_id
              AND n.coordinate_id=c.coordinate_id
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND n.present {predicate}
            ORDER BY c.series_key LIMIT 501''',
            (plan.factor,scope.workspace_id,scope.application_id,
             *params)).fetchall()
    except psycopg.errors.NumericValueOutOfRange as error:
        raise ValueError('NUMERIC_OVERFLOW') from error
    if len(rows)>500:
        raise ValueError('CALCULATION_RESULT_LIMIT')
    candidate=[]
    for row in rows:
        NumericCell(True,row['source_amount'],'')
        NumericCell(True,row['amount'],'')
        candidate.append({'seriesKey':row['series_key'],
            'coordinateId':row['coordinate_id'],'members':row['members'],
            'sourceAmount':row['source_amount'],
            'sourceChangeId':row['source_change_id'],'amount':row['amount']})
    return tuple(candidate)


def enforce_scale_dimensional_security(db,identity:VerifiedIdentity,
                                       scope:ApplicationScope,candidate)->None:
    """Authorize every raw source and same-coordinate calculated target."""
    coordinates=tuple(Coordinate.from_mapping(row['members'])
                      for row in candidate)
    authorize_coordinates(db,identity,scope,coordinates,kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,coordinates,kind=AccessKind.WRITE)


def _scale_replay(job,receipt):
    if receipt is None:
        return None
    if (job is None or job['status']!='published'
            or job['receipt_revision']!=receipt['committed_revision']
            or job['result']!=receipt['result']
            or job['subject_id']!=receipt['actor_id']):
        raise ValueError('SCALE_RECEIPT_CONFLICT')
    return receipt['result']


class PostgresScalePublisher:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim, dict)
                or not isinstance(claim.get('workspace_id'), str)
                or not isinstance(claim.get('application_id'), str)
                or not isinstance(claim.get('job_id'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', claim['job_id'])
                or not isinstance(claim.get('claimant'), str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                configure_statement_timeout(before,5000)
                PostgresNumericFactStore._set_scope(before,scope)
                state=_scale_state(before,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'write',function=_FUNCTION)
                job=before.execute('''SELECT *,lease_until>clock_timestamp()
                    AS unexpired FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                receipt=before.execute('''SELECT committed_revision,actor_id,
                    result FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                replay=_scale_replay(job,receipt)
                if replay is not None:
                    return replay
                if (job is None or job['issuer']!=self.identity.issuer
                        or job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                if (job['status']!='running' or not job['unexpired']
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(before,scope,job)
                if (job['function_name']!=_FUNCTION
                        or job['compiler_version']!=_COMPILER
                        or job['plan_digest']!=_PLAN_DIGEST
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_SCALE_JOB_PROGRAM')
                if any(state[name+'_revision']!=job[
                        'expected_'+name+'_revision']
                        for name in ('metadata','data','policy')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                plan=decode_scale_program(job['normalized_program'])
                pointer=before.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (*keys,plan.result_key)).fetchone()
                if (pointer['state_token'] if pointer else None)!=(
                        plan.expected_target_state_token):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                candidate=_scale_candidate(before,scope,plan)
                enforce_scale_dimensional_security(
                    before,self.identity,scope,candidate)
                enforce_scale_target_policy(before,scope,
                    tuple({'members':item['members']} for item in candidate),
                    access.role)
                initial_job=dict(job)

        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                final_state=_scale_state(db,scope,lock=True)
                final_access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=_FUNCTION)
                final_job=db.execute('''SELECT *,lease_until>clock_timestamp()
                    AS unexpired FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s FOR UPDATE''',
                    (*keys,claim['job_id'])).fetchone()
                receipt=db.execute('''SELECT committed_revision,actor_id,
                    result FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                replay=_scale_replay(final_job,receipt)
                if replay is not None:
                    return replay
                immutable=('issuer','subject_id','function_name',
                    'normalized_program','program_digest','plan_digest',
                    'compiler_version','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision')
                if (final_job is None or any(final_job[name]!=initial_job[name]
                        for name in immutable)
                        or final_job['status']!='running'
                        or not final_job['unexpired']
                        or final_job['claim_generation']!=claim['claim_generation']
                        or final_job['claimant']!=claim['claimant']):
                    raise ValueError('STALE_WORKER_FENCE')
                _require_python_job_authority(db,scope,final_job)
                if (final_job['function_name']!=_FUNCTION
                        or final_job['compiler_version']!=_COMPILER
                        or final_job['plan_digest']!=_PLAN_DIGEST
                        or final_job['program_digest']!=_canonical_digest(
                            final_job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_SCALE_JOB_PROGRAM')
                if any(final_state[name+'_revision']!=final_job[
                        'expected_'+name+'_revision']
                        for name in ('metadata','data','policy')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                final_pointer=db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (*keys,plan.result_key)).fetchone()
                if (final_pointer['state_token']
                        if final_pointer else None)!=(
                            plan.expected_target_state_token):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                final_candidate=_scale_candidate(db,scope,plan)
                if final_candidate!=candidate:
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                enforce_scale_dimensional_security(
                    db,self.identity,scope,final_candidate)
                policy_evidence=enforce_scale_target_policy(db,scope,
                    tuple({'members':item['members']}
                          for item in final_candidate),final_access.role)
                revision=final_state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_operation_staging
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],plan.factor,
                     len(final_candidate),revision))
                db.cursor().executemany('''INSERT INTO epm.calculation_result_staging
                    (workspace_id,application_id,generation_id,coordinate_id,
                     source_amount,source_change_id,amount)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',[
                    (*keys,claim['job_id'],item['coordinateId'],
                     item['sourceAmount'],item['sourceChangeId'],item['amount'])
                    for item in final_candidate])
                inserted=len(final_candidate)
                if inserted != len(candidate):
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                from .postgres_current_result_publication import advance_result_head_during_conversion
                head=advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                result = {'resultKey': plan.result_key,
                          'resultStateToken':head['state_token'],
                          'resultContentDigest':head['content_digest'],
                          'rowCount': inserted,
                          'sourceCommitRevision': state['commit_revision'],
                          'engine': 'postgres_exact_sql'}
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=plan.result_key,
                    existed=final_pointer is not None)
                result['impactDigest']=impact.digest
                if policy_evidence is not None:
                    result['planningPolicy']=policy_evidence
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',
                    (revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,claim['job_id'],final_job['program_digest'],
                     final_job['subject_id'],revision,Jsonb(result)))
                from .postgres_calculation_impact import (
                    record_calculation_impact)
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (revision,Jsonb(result),*keys,claim['job_id']))
                return result


class PostgresScaleReader:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def list_published(self, scope: ApplicationScope, *, limit: int = 100,
                       after_result_key: str | None = None) -> dict:
        if (type(limit) is not int or not 1 <= limit <= 100
                or after_result_key is not None
                and (not isinstance(after_result_key,str)
                     or not _RESULT_KEY.fullmatch(after_result_key))):
            raise ValueError('PUBLICATION_LIST_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                rows=db.execute('''SELECT current_result.result_key,
                    current_result.state_token,current_result.updated_at,
                    current_result.source_function AS function_name
                    FROM epm.calculation_result_state current_result
                    WHERE current_result.workspace_id=%s
                      AND current_result.application_id=%s
                    AND (%s::text IS NULL OR current_result.result_key>%s::text)
                    ORDER BY current_result.result_key LIMIT %s''',(
                    scope.workspace_id,scope.application_id,
                    after_result_key,after_result_key,limit+1)).fetchall()
        page=rows[:limit]
        return {'items':[{'resultKey':row['result_key'],
                          'resultStateToken':row['state_token'],
                          'function':row['function_name'],
                          'updatedAt':row['updated_at'].isoformat()}
                         for row in page],
                'hasMore':len(rows)>limit,
                'nextAfterResultKey':(page[-1]['result_key']
                                      if len(rows)>limit else None)}

    def read_published(self, scope: ApplicationScope,
                       result_key: str) -> dict:
        if not isinstance(result_key, str) or not _RESULT_KEY.fullmatch(result_key):
            raise ValueError('RESULT_KEY_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                pointer = db.execute('''SELECT
                    current_result.state_token,
                    current_result.source_operation_id AS generation_id,
                    current_result.committed_revision AS published_revision,
                    current_result.source_function AS function_name,
                    current_result.source_commit_revision,
                    current_result.source_metadata_revision,
                    j.normalized_program,j.result AS job_result,
                    j.compiler_version,
                    j.expected_metadata_revision,
                    j.expected_data_revision,j.expected_policy_revision,
                    s.metadata_revision AS current_metadata_revision,
                    s.data_revision AS current_data_revision,
                    s.policy_revision AS current_policy_revision,
                    s.security_revision AS current_security_revision,
                    s.commit_revision AS observed_commit_revision,
                    s.enabled_capabilities,s.capability_revision
                    FROM epm.calculation_result_state current_result
                    JOIN epm.job j ON j.workspace_id=current_result.workspace_id
                    AND j.application_id=current_result.application_id
                    AND j.job_id=current_result.source_operation_id
                    JOIN epm.application_state s
                    ON s.workspace_id=current_result.workspace_id
                    AND s.application_id=current_result.application_id
                    WHERE current_result.workspace_id=%s
                      AND current_result.application_id=%s
                      AND current_result.result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     result_key)).fetchone()
                if pointer is None:
                    raise ValueError('PUBLICATION_UNAVAILABLE')
                currentness = published_result_status(db, scope, result_key, pointer['state_token'])
                profiles = currentness['profileStatuses']
                normalized=pointer['normalized_program']
                typed_unit=(isinstance(normalized,dict) and (
                    (pointer['function_name']=='currency.amount.translate.publish'
                     and normalized.get('version')==3)
                    or pointer['function_name']==
                        'consolidation.equity.contribution.publish'
                    or pointer['function_name']==
                        'consolidation.proportional.contribution.publish'
                    or pointer['function_name']==
                        'consolidation.full.typed.contribute'
                    or pointer['function_name']==
                        'consolidation.method.total.publish'
                    or pointer['function_name']==
                        'consolidation.inventory.unrealized_profit.request'
                    or (pointer['function_name']==
                        'consolidation.nci.period.publish' and
                        pointer.get('compiler_version') in (
                        'period-nci-attribution-v7-typed-unit',
                        'period-nci-attribution-v8-ic-adjusted-typed-unit'))
                    or (pointer['function_name']=='facts.expression.calculate'
                        and ((isinstance(normalized.get('expression'),dict)
                          and normalized['expression'].get('op')=='CurrencyConvert')
                         or pointer['compiler_version'] in (
                            'typed-numeric-expression-v19',
                            'typed-numeric-expression-v22',
                            'typed-numeric-expression-v23',
                            'typed-numeric-expression-v29',
                            'typed-numeric-expression-v32')))))
                typed_ratio=(pointer['function_name']=='facts.expression.calculate'
                    and pointer.get('compiler_version')==
                        'typed-numeric-expression-v24')
                if typed_ratio:
                    rows=db.execute('''SELECT c.series_key,c.members,
                        r.source_amount,r.source_change_id,r.source_present,
                        r.ratio,r.source_lookup_lineage
                        FROM epm.calculation_ratio_result_current r
                        JOIN epm.coordinate c
                        USING(workspace_id,application_id,coordinate_id)
                        WHERE r.workspace_id=%s AND r.application_id=%s
                        AND r.result_key=%s ORDER BY c.series_key
                        LIMIT 501''',(scope.workspace_id,
                        scope.application_id,result_key
                        )).fetchall()
                elif typed_unit:
                    rows=db.execute('''SELECT c.series_key,c.members,
                        r.source_amount,r.source_change_id,
                        r.source_evidence_digest,r.amount,
                        r.output_unit_currency_dimension_id,
                        r.output_unit_currency_member_id,r.rate_strategy,
                        r.rate_numerator::text AS rate_numerator,
                        r.rate_denominator::text AS rate_denominator,
                        r.rate_sources,r.source_lookup_lineage
                        FROM epm.calculation_unit_result_current r JOIN epm.coordinate c
                        USING(workspace_id,application_id,coordinate_id)
                        WHERE r.workspace_id=%s AND r.application_id=%s
                        AND r.result_key=%s ORDER BY c.series_key,
                        r.output_unit_currency_dimension_id,
                        r.output_unit_currency_member_id LIMIT 501''',
                        (scope.workspace_id,scope.application_id,
                         result_key)).fetchall()
                else:
                    rows = db.execute('''SELECT c.series_key,c.members,
                    r.source_amount,r.source_change_id,r.amount,
                    r.source_lookup_lineage,
                    b.basis_coordinate_id,bc.members AS basis_members,
                    b.basis_amount,b.basis_change_id,b.total_basis,
                    b.base_units,b.remainder_numerator,b.extra_unit,
                    rollup.sources AS rollup_sources
                    FROM epm.calculation_result_current r JOIN epm.coordinate c
                    ON c.workspace_id=r.workspace_id
                    AND c.application_id=r.application_id
                    AND c.coordinate_id=r.coordinate_id
                    LEFT JOIN epm.allocation_basis_lineage_current b
                    ON b.workspace_id=r.workspace_id
                    AND b.application_id=r.application_id
                    AND b.result_key=r.result_key
                    AND b.coordinate_id=r.coordinate_id
                    LEFT JOIN epm.coordinate bc
                    ON bc.workspace_id=b.workspace_id
                    AND bc.application_id=b.application_id
                    AND bc.coordinate_id=b.basis_coordinate_id
                    LEFT JOIN LATERAL (
                        SELECT jsonb_agg(jsonb_build_object(
                            'members',sc.members,
                            'amount',l.source_amount::text,
                            'changeId',l.source_change_id,
                            'sourceSelection',l.source_selection,
                            'hierarchyDimension',l.hierarchy_dimension_id,
                            'hierarchyStateToken',l.hierarchy_state_token)
                            ORDER BY sc.series_key) AS sources
                        FROM epm.rollup_source_lineage_current l
                        JOIN epm.coordinate sc
                        ON sc.workspace_id=l.workspace_id
                        AND sc.application_id=l.application_id
                        AND sc.coordinate_id=l.source_coordinate_id
                        WHERE l.workspace_id=r.workspace_id
                        AND l.application_id=r.application_id
                        AND l.result_key=r.result_key
                        AND l.coordinate_id=r.coordinate_id
                    ) rollup ON true
                    WHERE r.workspace_id=%s AND r.application_id=%s
                    AND r.result_key=%s ORDER BY c.series_key LIMIT 501''',
                    (scope.workspace_id,scope.application_id,result_key)).fetchall()
                rows = filter_read_rows(
                    db, self.identity, scope, rows)
                result={'resultStateToken': pointer['state_token'],
                        'resultKey': result_key,
                        'function': pointer['function_name'],
                        'sourceCommitRevision':
                            pointer['source_commit_revision'],
                        'sourceMetadataRevision':
                            pointer['source_metadata_revision'],
                        'securityRevision':
                            pointer['current_security_revision'],
                        'inputRevisionStatus': currentness['inputRevisionStatus'],
                        'resultCurrentness': {key: currentness[key] for key in (
                            'basis', 'freshness', 'matchesAtRead', 'impactBarrier', 'definitionStatus')},
                        'producerCapabilities':producer_capability_status(pointer['function_name'],
                            pointer['normalized_program'],pointer['enabled_capabilities'],pointer['capability_revision']),
                        'rows': ([self._ratio_result_row(row) for row in rows]
                            if typed_ratio else
                            [self._typed_unit_result_row(row) for row in rows]
                            if typed_unit else
                            [self._result_row(row) for row in rows])}
                if pointer['function_name']==(
                        'facts.planning.allocate.weighted'):
                    ratio_pin=pointer['normalized_program'].get(
                        'publishedRatioBasis')
                    if ratio_pin is not None:
                        dependency_status=profiles.get('publishedRatioBasisStatus')
                        if dependency_status is None:
                            dependency_status={'matchesAtRead':False,
                                'truncated':True,'dependencies':[]}
                        result['publishedRatioBasisStatus']=dependency_status
                        result['inputRevisionStatus']['matchesAtRead'] &= (
                            dependency_status['matchesAtRead'])
                if pointer['function_name'] in ('consolidation.nci.period.publish','consolidation.nci.period.withdraw'):
                    result['periodNciContext']=pointer['job_result']
                    result['periodNciSourceStatus']=profiles['periodNciSourceStatus']
                    result['inputRevisionStatus']['matchesAtRead'] &= result['periodNciSourceStatus']['matchesAtRead']
                if pointer['function_name']=='consolidation.equity.contribution.publish':
                    result['equitySourceStatus']=profiles['equitySourceStatus']
                    result['equityContextStatus']=profiles['equityContextStatus']
                    result['inputRevisionStatus']['matchesAtRead'] &= (result['equitySourceStatus']['matchesAtRead'] and result['equityContextStatus']['matchesAtRead'])
                if pointer['function_name']=='consolidation.proportional.contribution.publish':
                    result['proportionalSourceStatus']=profiles['proportionalSourceStatus']
                    result['proportionalContextStatus']=profiles['proportionalContextStatus']
                    result['inputRevisionStatus']['matchesAtRead'] &= (result['proportionalSourceStatus']['matchesAtRead'] and result['proportionalContextStatus']['matchesAtRead'])
                if pointer['function_name']=='consolidation.method.total.publish':
                    result['methodTotalSourceStatus']=profiles['methodTotalSourceStatus']
                    result['inputRevisionStatus']['matchesAtRead'] &= result['methodTotalSourceStatus']['matchesAtRead']
                if pointer['function_name']=='consolidation.inventory.unrealized_profit.request':
                    result['inventoryUnrealizedSourceStatus']=profiles['inventoryUnrealizedSourceStatus']
                    result['inputRevisionStatus']['matchesAtRead'] &= result['inventoryUnrealizedSourceStatus']['matchesAtRead']
                if pointer['function_name'] in (
                        'facts.planning.group.sum',
                        'facts.planning.group.sum.bulk'):
                    for row in result['rows']:
                        if 'rollupSources' in row:
                            row['groupSources']=row.pop('rollupSources')
                if pointer['function_name']==(
                        'facts.planning.spread.calendar.equal'):
                    program=pointer['normalized_program']
                    calendar_selection={
                        'yearId':program['yearId'],
                        'firstOrdinal':program['firstOrdinal'],
                        'lastOrdinal':program['lastOrdinal'],
                        'targetMembers':program['targetMembers']}
                    if program.get('reusablePolicy'):
                        calendar_selection['roundingPolicy']=(
                            'largestRemainderFiscalOrdinal')
                        result['reusablePolicy']=program['reusablePolicy']
                    result['calendarSelection']=calendar_selection
                if (pointer['function_name']=='facts.planning.rollup.sum'
                        and pointer['normalized_program'].get('version')==3):
                    result['rollupSliceContext']={key:
                        pointer['normalized_program'][key] for key in (
                            'dimension','parent','fixedMembers',
                            'sliceSelection','placementIds','reusablePolicy')}
                if pointer['function_name'] == 'facts.expression.calculate':
                    program = pointer['normalized_program']
                    result['publishedInputs'] = program.get(
                        'publishedInputs', [])
                    if isinstance(pointer['job_result'],dict) and (
                            'sourceLookups' in pointer['job_result']):
                        result['sourceLookups'] = pointer['job_result'][
                            'sourceLookups']
                    if isinstance(pointer['job_result'],dict) and (
                            'sourceTextLookups' in pointer['job_result']):
                        result['sourceTextLookups']=pointer['job_result'][
                            'sourceTextLookups']
                    if program.get('savedRule'):
                        result['savedRule'] = program['savedRule']
                    if program.get('driverPolicy'):
                        result['driverPolicy'] = program['driverPolicy']
                    if program.get('targetMembers'):
                        result['outputMapping'] = {
                            'sourceMembers': program['sourceMembers'],
                            'targetMembers': program['targetMembers']}
                        if program.get('sourceMemberSets'):
                            result['outputMapping']['sourceMemberSets']=(
                                program['sourceMemberSets'])
                            result['sourceMemberSets']=program[
                                'sourceMemberSets']
                        for row in result['rows']:
                            row['sourceMembers'] = {
                                **row['members'], **program['sourceMembers']}
                    if program.get('reduceMemberSet'):
                        result['outputMapping'] = {
                            'sourceMembers': program['sourceMembers'],
                            'reduceMemberSet': program['reduceMemberSet']}
                        if program.get('hierarchyReductionContext'):
                            result['outputMapping']['hierarchySelection'] = (
                                program['hierarchyReductionContext'])
                        for row in result['rows']:
                            row['countPresent'] = len(
                                row.get('sourceLookupLineage', []))
                    if program.get('reduceMemberSets'):
                        result['outputMapping']={
                            'sourceMembers':program['sourceMembers'],
                            'reduceMemberSets':program['reduceMemberSets']}
                    if program.get('hierarchyTwoAxisReductionContext'):
                        result['outputMapping']['hierarchySelections']=(
                            program['hierarchyTwoAxisReductionContext'])
                        for row in result['rows']:
                            row['countPresent'] = len(
                                row.get('sourceLookupLineage', []))
                    dependency_status = profiles.get('publishedInputStatus')
                    if dependency_status is not None:
                        result['publishedInputStatus'] = dependency_status
                        result['inputRevisionStatus']['matchesAtRead'] &= (
                            dependency_status['matchesAtRead'])
                    raw_driver_status=profiles.get('rawDriverStatus')
                    if raw_driver_status is not None:
                        result['rawDriverStatus']=raw_driver_status
                        result['inputRevisionStatus']['matchesAtRead'] &= (
                            raw_driver_status['matchesAtRead'])
                    context_dependency_status=profiles.get('contextDependencyStatus')
                    if context_dependency_status is not None:
                        result['contextDependencyStatus']=(
                            context_dependency_status)
                        result['contextAssertions']=program.get(
                            'contextAssertions',[])
                        result['inputRevisionStatus']['matchesAtRead'] &= (
                            context_dependency_status['matchesAtRead'])
                    redact_expression_lineage(
                        db,self.identity,scope,program,result['rows'])
                    redact_expression_result_metadata(result)
                if pointer['function_name'] in (
                        'consolidation.full.contribute',
                        'consolidation.full.typed.contribute'):
                    receipt = pointer['job_result']
                    if not isinstance(receipt, dict):
                        raise ValueError('CONTRIBUTION_RECEIPT_UNAVAILABLE')
                    result['contributionContext'] = {key: receipt[key]
                        for key in ('relationshipId', 'parentEntityId',
                                    'childEntityId', 'sourceMembers',
                                    'targetMembers', 'sourceChangeId',
                                    'pown', 'effectivePcon', 'pconFallback',
                                    'accountingStage',
                                    'accountingPolicyStatus')}
                    if 'outputUnit' in receipt:
                        result['contributionContext']['outputUnit']=receipt['outputUnit']
                    if 'policy' in receipt:
                        result['contributionContext']['policy']=receipt['policy']
                    if 'ownership' in receipt:
                        result['contributionContext']['ownership']=receipt['ownership']
                    if pointer['function_name']==(
                            'consolidation.full.typed.contribute'):
                        result['typedFullContextStatus']=profiles['typedFullContextStatus']
                        result['inputRevisionStatus']['matchesAtRead'] &= (
                            result['typedFullContextStatus']['matchesAtRead'])
                if (pointer['function_name']=='consolidation.nci.period.publish'
                        and pointer.get('compiler_version') in (
                            'period-nci-attribution-v7-typed-unit',
                            'period-nci-attribution-v8-ic-adjusted-typed-unit')):
                    result['periodNciSourceStatus']=profiles['periodNciSourceStatus']
                    result['inputRevisionStatus']['matchesAtRead'] &= (
                        result['periodNciSourceStatus']['matchesAtRead'])
                if pointer['function_name'] == 'currency.translation.publish':
                    receipt = pointer['job_result']
                    if not isinstance(receipt, dict):
                        raise ValueError('TRANSLATION_RECEIPT_UNAVAILABLE')
                    result['translationContext'] = {key: receipt[key]
                        for key in ('sourceMembers','targetMembers','method',
                                    'rateKind','fromCurrencyMemberId',
                                    'toCurrencyMemberId','exactAmount',
                                    'periods','accountingStage',
                                    'accountingPolicyStatus')}
                    result['translationContext'].update({key:receipt[key] for key in ('sourceLayer','icParentEntityId','sourceBasis') if key in receipt})
                if pointer['function_name'] == (
                        'currency.calculation.translation.publish'):
                    receipt=pointer['job_result']
                    if not isinstance(receipt,dict):
                        raise ValueError(
                            'CALCULATION_TRANSLATION_RECEIPT_UNAVAILABLE')
                    dependency_status=profiles['publishedCalculationTranslationStatus']
                    result['publishedCalculationTranslationStatus']=\
                        dependency_status
                    result['inputRevisionStatus']['matchesAtRead'] &= (
                        dependency_status['matchesAtRead'])
                    result['calculationTranslationContext']={key:receipt[key]
                        for key in ('sourceMembers','targetMembers','method',
                            'rateKind','fromCurrencyMemberId',
                            'toCurrencyMemberId','exactAmount','periodPins',
                            'periods','accountingStage',
                            'accountingPolicyStatus')} | (
                            {'sourceLayer':receipt['sourceLayer']}
                            if 'sourceLayer' in receipt else {}) | (
                            {'sourceBasis':receipt['sourceBasis']}
                            if 'sourceBasis' in receipt else {})
                if pointer['function_name'] == (
                        'consolidation.full.translated.aggregate'):
                    receipt = pointer['job_result']
                    if not isinstance(receipt, dict):
                        raise ValueError('TRANSLATED_AGGREGATE_RECEIPT_UNAVAILABLE')
                    dependency_status=profiles['publishedTranslationStatus']
                    result['publishedTranslationStatus']=dependency_status
                    result['inputRevisionStatus']['matchesAtRead'] &= (
                        dependency_status['matchesAtRead'])
                    result['translatedAggregateContext'] = {
                        key: receipt[key] for key in (
                            'parentMembers','parentEntityId',
                            'targetCurrencyMemberId','sources',
                            'sourceChangeId','accountingStage',
                            'accountingPolicyStatus')} | (
                            {'sourceLayer':receipt['sourceLayer']}
                            if 'sourceLayer' in receipt else {})
                if pointer['function_name'] == 'consolidation.full.aggregate':
                    receipt = pointer['job_result']
                    if not isinstance(receipt, dict):
                        raise ValueError('FULL_AGGREGATE_RECEIPT_UNAVAILABLE')
                    dependency_status = profiles.get('publishedChildStatus')
                    if dependency_status is not None:
                        result['publishedChildStatus'] = dependency_status
                        result['inputRevisionStatus']['matchesAtRead'] &= (
                            dependency_status['matchesAtRead'])
                    result['aggregateContext'] = {key: receipt[key]
                        for key in ('parentMembers', 'parentEntityId',
                                    'relationshipIds', 'includeParentSource',
                                    'sourceLayer', 'sources', 'sourceChangeId',
                                    'accountingStage',
                                    'accountingPolicyStatus')}
                redact_calculation_lineage(
                    db,self.identity,scope,result['rows'])
                redact_expression_result_metadata(result)
                final_security=db.execute('''SELECT security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',(scope.workspace_id,
                    scope.application_id)).fetchone()
                if (final_security is None or final_security[
                        'security_revision']!=pointer[
                            'current_security_revision']):
                    raise ValueError('STALE_SECURITY_REVISION')
                final_result=db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                      AND application_id=%s AND result_key=%s''',(
                    scope.workspace_id,scope.application_id,
                    result_key)).fetchone()
                if (final_result is None or final_result['state_token'] !=
                        pointer['state_token']):
                    raise ValueError(
                        'CALCULATION_RESULT_STATE_CHANGED_RESTART')
                return result

    @staticmethod
    def _typed_unit_result_row(row):
        result={'series_key':row['series_key'],'members':row['members'],
            'source_amount':format(row['source_amount'],'f'),
            'amount':format(row['amount'],'f'),
            'outputUnit':{'type':'Currency',
                'dimensionId':row['output_unit_currency_dimension_id'],
                'memberId':row['output_unit_currency_member_id']},
            'rateLineage':{'strategy':row['rate_strategy'],
                'exactFactor':{'numerator':row['rate_numerator'],
                    'denominator':row['rate_denominator']},
                'sources':row['rate_sources']}}
        if row['source_change_id'] is not None:
            result['source_change_id']=row['source_change_id']
        if row['source_evidence_digest'] is not None:
            result['sourceEvidenceDigest']=row['source_evidence_digest']
        if row['source_lookup_lineage']:
            result['sourceLookupLineage']=row['source_lookup_lineage']
        return result

    @staticmethod
    def _ratio_result_row(row):
        result={'series_key':row['series_key'],'members':row['members'],
            'source_present':row['source_present'],
            'value':{'type':'Ratio','decimal':format(row['ratio'],'.12f')},
            'resultUnit':{'type':'Ratio','scale':12}}
        if row['source_present']:
            result['source_amount']=format(row['source_amount'],'.8f')
            result['source_change_id']=row['source_change_id']
        if row['source_lookup_lineage']:
            result['sourceLookupLineage']=row['source_lookup_lineage']
        return result

    @staticmethod
    def _result_row(row):
        result={'series_key':row['series_key'],
                'members':row['members'],
                'source_amount':format(row['source_amount'],'f'),
                'source_change_id':row['source_change_id'],
                'amount':format(row['amount'],'f')}
        if row['source_lookup_lineage']:
            result['sourceLookupLineage']=row['source_lookup_lineage']
        if row['basis_coordinate_id'] is not None:
            result['basis']={
                'members':row['basis_members'],
                'amount':format(row['basis_amount'],'f'),
                'changeId':row['basis_change_id'],
                'totalBasis':format(row['total_basis'],'f'),
                'baseUnits':format(row['base_units'],'f'),
                'remainderNumerator':format(
                    row['remainder_numerator'],'f'),
                'extraUnit':row['extra_unit']}
        if row['rollup_sources'] is not None:
            result['rollupSources'] = row['rollup_sources']
        return result
