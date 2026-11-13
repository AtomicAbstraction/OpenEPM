"""Exact weighted allocation into one atomically replaced current result."""
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
from .current_object_contract import require_state_token


FUNCTION='facts.planning.allocate.weighted'
COMPILER='planning-allocation-weighted-v1'
PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':1,
    'engine':'postgres_exact_sql','inputGrain':'full_coordinate',
    'outputGrain':'rebound_full_coordinate','unitScale':8,
    'basisPolicy':'strictly_positive_present_numeric',
    'rounding':'largest_remainder_stable_member'})
POLICY_COMPILER='planning-allocation-weighted-policy-v1'
POLICY_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':1,'engine':'postgres_exact_sql',
    'inputGrain':'full_coordinate','outputGrain':'rebound_full_coordinate',
    'unitScale':8,'basisPolicy':'strictly_positive_present_numeric',
    'rounding':'largest_remainder_stable_member',
    'policyContract':'openepm-planning-operation-policy-v1',
    'lockedTargetPolicy':'reject','conservationScope':'sourceCoordinate'})
POLICY_V2_COMPILER='planning-allocation-published-ratio-policy-v2'
POLICY_V2_PLAN_DIGEST=_canonical_digest({
    'function':FUNCTION,'loweringVersion':2,'engine':'postgres_exact_sql',
    'sourceUnit':'Amount','basisUnit':'Ratio','outputUnit':'Amount',
    'inputGrain':'full_coordinate','outputGrain':'rebound_full_coordinate',
    'unitScale':8,'basisPolicy':'one_pinned_positive_published_ratio_per_target',
    'rounding':'largest_remainder_stable_member','maxTargets':500,
    'policyContract':'openepm-planning-operation-policy-v2',
    'lockedTargetPolicy':'reject','conservationScope':'sourceCoordinate'})
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB_ID=re.compile(r'[0-9a-f]{32}\Z')

def _lineage_depth(value):
    if isinstance(value,dict): return 1+max((_lineage_depth(v) for v in value.values()),default=0)
    if isinstance(value,list): return 1+max((_lineage_depth(v) for v in value),default=0)
    return 0


@dataclass(frozen=True,slots=True)
class AllocationPlan:
    source: Coordinate
    basis_template: Coordinate
    target_dimension: str
    target_members: tuple[str,...]
    result_key: str
    expected_target_state_token: str | None
    published_ratio_basis: dict | None = None

    @property
    def normalized_program(self) -> dict:
        result={'version':2,'function':FUNCTION,
                'source':dict(self.source.members),
                'basisTemplate':dict(self.basis_template.members),
                'targetDimension':self.target_dimension,
                'targetMembers':list(self.target_members),
                'resultKey':self.result_key,
                'conservationScope':'sourceCoordinate',
                'roundingPolicy':'largestRemainderStableMember',
                'expectedTargetStateToken':
                    self.expected_target_state_token,
                'inputGrain':'full_coordinate',
                'outputGrain':'rebound_full_coordinate'}
        if self.published_ratio_basis is not None:
            result['publishedRatioBasis']=dict(self.published_ratio_basis)
        return result

    @property
    def outputs(self) -> list[dict]:
        source=dict(self.source.members)
        basis=dict(self.basis_template.members)
        rows=[]
        for member in self.target_members:
            target_members={**source,self.target_dimension:member}
            basis_members={**basis,self.target_dimension:member}
            rows.append({'member_id':member,
                         'series_key':Coordinate.from_mapping(
                             target_members).series_key,
                         'members':target_members,
                         'basis_key':Coordinate.from_mapping(
                             basis_members).series_key,
                         'basis_members':basis_members})
        return rows


def compile_allocation_program(program: object,*,
                               expected_target_state_token: str | None
                               ) -> AllocationPlan:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2
            or program['function']!=FUNCTION
            or not isinstance(program['arguments'],dict)
            or set(program['arguments']) not in ({'source','basisTemplate',
                'targetDimension','targetMembers','resultKey',
                'conservationScope','roundingPolicy'}, {'source','basisTemplate',
                'targetDimension','targetMembers','resultKey',
                'conservationScope','roundingPolicy','publishedRatioBasis'})):
        raise ValueError('V2_ALLOCATION_FUNCTION_OR_ARGUMENTS_INVALID')
    args=program['arguments']
    try:
        source=Coordinate.from_mapping(args['source'])
        basis=Coordinate.from_mapping(args['basisTemplate'])
    except (TypeError,ValueError) as error:
        raise ValueError('V2_ALLOCATION_COORDINATE_INVALID') from error
    dimension=args['targetDimension']
    members=args['targetMembers']
    key=args['resultKey']
    if (not isinstance(dimension,str) or not 1<=len(dimension)<=200
            or dimension not in dict(source.members)
            or dimension not in dict(basis.members)
            or set(dict(source.members))!=set(dict(basis.members))
            or not isinstance(members,list) or not 1<=len(members)<=500
            or any(not isinstance(member,str) or not 1<=len(member)<=200
                   for member in members)
            or len(set(members))!=len(members)
            or dict(source.members)[dimension] in members
            or not isinstance(key,str) or not _KEY.fullmatch(key)
            or args['conservationScope']!='sourceCoordinate'
            or args['roundingPolicy']!='largestRemainderStableMember'):
        raise ValueError('V2_ALLOCATION_ARGUMENTS_INVALID')
    if expected_target_state_token is not None:
        require_state_token(expected_target_state_token,
            error='V2_ALLOCATION_TARGET_STATE_TOKEN_INVALID')
    ratio=args.get('publishedRatioBasis')
    if ratio is not None and (not isinstance(ratio,dict)
            or set(ratio)!={'resultKey','resultStateToken'}
            or not isinstance(ratio['resultKey'],str) or not _KEY.fullmatch(ratio['resultKey'])
            or not isinstance(ratio['resultStateToken'],str)
            or re.fullmatch(r'[0-9a-f]{64}',ratio['resultStateToken']) is None
            or ratio['resultKey']==key):
        raise ValueError('V2_ALLOCATION_PUBLISHED_RATIO_INVALID')
    return AllocationPlan(source,basis,dimension,tuple(sorted(members)),
                          key,expected_target_state_token,ratio)


def decode_allocation_program(program: object) -> AllocationPlan:
    if (not isinstance(program,dict)
            or set(program) not in ({'version','function','source','basisTemplate',
                'targetDimension','targetMembers','resultKey',
                'conservationScope','roundingPolicy',
                'expectedTargetStateToken','inputGrain','outputGrain'},
                {'version','function','source','basisTemplate',
                'targetDimension','targetMembers','resultKey',
                'conservationScope','roundingPolicy','publishedRatioBasis',
                'expectedTargetStateToken','inputGrain','outputGrain'})
            or type(program['version']) is not int or program['version']!=2
            or program['function']!=FUNCTION
            or program['inputGrain']!='full_coordinate'
            or program['outputGrain']!='rebound_full_coordinate'):
        raise ValueError('UNSUPPORTED_ALLOCATION_JOB_PROGRAM')
    plan=compile_allocation_program({'languageVersion':2,
        'function':FUNCTION,'arguments':{
            'source':program['source'],
            'basisTemplate':program['basisTemplate'],
            'targetDimension':program['targetDimension'],
            'targetMembers':program['targetMembers'],
            'resultKey':program['resultKey'],
            'conservationScope':program['conservationScope'],
            'roundingPolicy':program['roundingPolicy'],
            **({'publishedRatioBasis':program['publishedRatioBasis']}
               if 'publishedRatioBasis' in program else {})}},
        expected_target_state_token=
            program['expectedTargetStateToken'])
    if plan.normalized_program!=program:
        raise ValueError('NONCANONICAL_ALLOCATION_JOB_PROGRAM')
    return plan

def encode_policy_allocation_program(plan:AllocationPlan,policy:dict)->dict:
    required={'policyId','policyDigest','metadataRevision',
        'policyRevision','authoredMetadataRevision','authoredPolicyRevision',
        'stateToken'}
    v2=plan.published_ratio_basis is not None
    if v2: required|={'policyFormat','publishedDependency','lineageBudget'}
    if not isinstance(policy,dict) or set(policy)!=required:
        raise ValueError('ALLOCATION_POLICY_PIN_INVALID')
    if v2 and (policy['policyFormat']!='openepm-planning-operation-policy-v2'
            or policy['lineageBudget']!={'maxCanonicalBytes':65536,'maxDepth':8}
            or not isinstance(policy['publishedDependency'],dict)
            or policy['publishedDependency']!=plan.published_ratio_basis):
        raise ValueError('ALLOCATION_POLICY_PIN_INVALID')
    return {**plan.normalized_program,'reusablePolicy':dict(policy)}

def decode_policy_allocation_program(program:object)->tuple[AllocationPlan,dict]:
    if not isinstance(program,dict) or 'reusablePolicy' not in program:
        raise ValueError('UNSUPPORTED_ALLOCATION_POLICY_JOB_PROGRAM')
    policy=program['reusablePolicy'];base=dict(program);base.pop('reusablePolicy')
    plan=decode_allocation_program(base)
    if encode_policy_allocation_program(plan,policy)!=program:
        raise ValueError('NONCANONICAL_ALLOCATION_POLICY_JOB_PROGRAM')
    return plan,policy

def _current_policy_pointer_matches(db,scope,policy):
    row=db.execute('''SELECT p.state_token,p.canonical_digest,
        a.metadata_revision,a.policy_revision
        FROM epm.planning_operation_policy p
        JOIN epm.application_state a ON a.workspace_id=p.workspace_id
         AND a.application_id=p.application_id WHERE p.workspace_id=%s
         AND p.application_id=%s AND p.policy_id=%s AND p.status='Active' ''',
        (scope.workspace_id,scope.application_id,policy.get('policyId'))).fetchone()
    return row is not None and all((
        row['canonical_digest']==policy.get('policyDigest'),
        row['state_token']==policy.get('stateToken'),
        row['metadata_revision']==policy.get('metadataRevision'),
        row['policy_revision']==policy.get('policyRevision')))


def validate_allocation_inputs(db,scope: ApplicationScope,
                               plan: AllocationPlan,*,
                               check_locks: bool=True) -> tuple[dict,object]:
    axes={row['dimension_id'] for row in db.execute('''SELECT dimension_id
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
        (scope.workspace_id,scope.application_id)).fetchall()}
    if (set(dict(plan.source.members))!=axes
            or set(dict(plan.basis_template.members))!=axes):
        raise ValueError('ALLOCATION_GRAIN_MISMATCH')
    pairs={(axis,member) for coordinate in
           (plan.source,plan.basis_template)
           for axis,member in coordinate.members}
    pairs.update((plan.target_dimension,member)
                 for member in plan.target_members)
    found=db.execute('''SELECT input.dimension_id,input.member_id,
        m.member_id IS NOT NULL AS active
        FROM jsonb_to_recordset(%s::jsonb)
        AS input(dimension_id text,member_id text)
        LEFT JOIN epm.member m ON m.workspace_id=%s
        AND m.application_id=%s
        AND m.dimension_id=input.dimension_id
        AND m.member_id=input.member_id AND m.status='Active' ''',
        (Jsonb([{'dimension_id':axis,'member_id':member}
                for axis,member in sorted(pairs)]),
         scope.workspace_id,scope.application_id)).fetchall()
    if len(found)!=len(pairs) or any(not row['active'] for row in found):
        raise ValueError('ALLOCATION_MEMBER_UNAVAILABLE')
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
        raise ValueError('ALLOCATION_SOURCE_MISSING')
    outputs=plan.outputs
    if plan.published_ratio_basis is None:
      basis_rows=db.execute('''SELECT input.member_id,
        c.members AS actual_members,n.amount,n.change_id,
        COALESCE(t.present,false) AS text_present,
        d.coordinate_id IS NOT NULL AS has_detail
        FROM jsonb_to_recordset(%s::jsonb)
        AS input(member_id text,basis_key text,basis_members jsonb)
        LEFT JOIN epm.coordinate c ON c.workspace_id=%s
        AND c.application_id=%s AND c.series_key=input.basis_key
        LEFT JOIN epm.numeric_cell_current n
        ON n.workspace_id=c.workspace_id
        AND n.application_id=c.application_id
        AND n.coordinate_id=c.coordinate_id AND n.present
        LEFT JOIN epm.text_cell_current t
        ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id
        LEFT JOIN epm.line_detail_current d
        ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id''',
        (Jsonb(outputs),scope.workspace_id,
         scope.application_id)).fetchall()
    else:
      pin=plan.published_ratio_basis
      pointer=db.execute('''SELECT p.state_token,
        p.source_function AS function_name,
        j.status,j.compiler_version,j.plan_digest
        FROM epm.calculation_result_state p
        JOIN epm.job j ON (j.workspace_id,j.application_id,j.job_id)=
             (p.workspace_id,p.application_id,p.source_operation_id)
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s''',
        (scope.workspace_id,scope.application_id,pin['resultKey'])).fetchone()
      if (pointer is None or pointer['state_token']!=pin['resultStateToken']
              or pointer['status']!='published'
              or pointer['function_name']!='facts.expression.calculate'):
          raise ValueError('ALLOCATION_PUBLISHED_RATIO_STALE')
      from .postgres_expression import (RATIO_RESULT_COMPILER,
          RATIO_RESULT_PLAN_DIGEST)
      if (pointer['compiler_version']!=RATIO_RESULT_COMPILER
              or pointer['plan_digest']!=RATIO_RESULT_PLAN_DIGEST):
          raise ValueError('ALLOCATION_PUBLISHED_RATIO_PRODUCER_INVALID')
      from .postgres_expression import published_input_status
      status=published_input_status(db,scope,{'publishedInputs':[pin]})
      if status is None or not status['matchesAtRead']:
          raise ValueError('ALLOCATION_PUBLISHED_RATIO_STALE')
      basis_rows=db.execute('''WITH ratio_rows AS (SELECT input.member_id,
        c.members AS actual_members,r.ratio AS amount,
        (%s::text||':'||c.coordinate_id::text) AS change_id,
        false AS text_present,false AS has_detail,
        r.source_lookup_lineage AS upstream_lineage
        FROM jsonb_to_recordset(%s::jsonb)
        AS input(member_id text,basis_key text,basis_members jsonb)
        LEFT JOIN epm.coordinate c ON c.workspace_id=%s
        AND c.application_id=%s AND c.series_key=input.basis_key
        LEFT JOIN epm.calculation_ratio_result_current r ON
        r.workspace_id=c.workspace_id AND r.application_id=c.application_id
        AND r.coordinate_id=c.coordinate_id AND r.result_key=%s)
        SELECT ratio_rows.*,lineage.stored_lineage,
          octet_length(lineage.stored_lineage::text) AS stored_lineage_bytes
        FROM ratio_rows CROSS JOIN LATERAL (SELECT jsonb_build_array(
          jsonb_build_object('inputKind','PublishedRatio','resultKey',%s::text,
            'resultStateToken',%s::text,
            'memberId',ratio_rows.member_id,'ratio',ratio_rows.amount::text,
            'upstreamRowLineage',ratio_rows.upstream_lineage)) AS stored_lineage
        ) lineage''',(
        pin['resultStateToken'],Jsonb(outputs),scope.workspace_id,
        scope.application_id,pin['resultKey'],pin['resultKey'],
        pin['resultStateToken'])).fetchall()
    by_member={row['member_id']:row for row in basis_rows}
    if (len(by_member)!=len(outputs)
            or any(by_member[output['member_id']]['actual_members']!=
                       output['basis_members']
                   or by_member[output['member_id']]['amount'] is None
                   or by_member[output['member_id']]['text_present']
                   or by_member[output['member_id']]['has_detail']
                   for output in outputs)):
        raise ValueError('ALLOCATION_BASIS_MISSING_OR_AMBIGUOUS')
    if any(row['amount']<=0 for row in basis_rows):
        raise ValueError('ALLOCATION_BASIS_NONPOSITIVE')
    if plan.published_ratio_basis is not None:
        for row in basis_rows:
            if row['stored_lineage_bytes']>65536 or _lineage_depth(
                    row['stored_lineage'])>8:
                raise ValueError('ALLOCATION_PUBLISHED_RATIO_LINEAGE_LIMIT')
    conflicts=db.execute('''SELECT 1 FROM
        jsonb_to_recordset(%s::jsonb)
        AS input(series_key text,members jsonb)
        LEFT JOIN epm.coordinate c ON c.workspace_id=%s
        AND c.application_id=%s AND c.series_key=input.series_key
        LEFT JOIN epm.text_cell_current t
        ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id
        LEFT JOIN epm.line_detail_current d
        ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id
        WHERE (c.coordinate_id IS NOT NULL AND c.members<>input.members)
        OR COALESCE(t.present,false) OR d.coordinate_id IS NOT NULL
        LIMIT 1''',
        (Jsonb(outputs),scope.workspace_id,
         scope.application_id)).fetchone()
    if conflicts:
        raise ValueError('ALLOCATION_TARGET_CONFLICT')
    if check_locks:
        locked=db.execute('''SELECT 1 FROM
            jsonb_to_recordset(%s::jsonb) AS input(members jsonb)
            JOIN epm.cube_write_scope_lock l
            ON l.workspace_id=%s AND l.application_id=%s
            AND l.status='Locked'
            AND (l.scope_all OR input.members @> l.scope_members)
            LIMIT 1''',
            (Jsonb(outputs),scope.workspace_id,
             scope.application_id)).fetchone()
        if locked:
            raise ValueError('PLANNING_SLICE_LOCKED')
    return source,sum((row['amount'] for row in basis_rows),start=0)


def enforce_allocation_target_policy(db,scope: ApplicationScope,
                                     plan: AllocationPlan,
                                     workflow_role: str) -> dict:
    """Guard final allocated Set outputs, never source or basis reads."""
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=tuple((
            Coordinate.from_mapping(target['members']),'Set')
            for target in plan.outputs),workflow_role=workflow_role)


def enforce_allocation_dimensional_security(db,identity: VerifiedIdentity,
        scope: ApplicationScope,plan: AllocationPlan) -> None:
    """Authorize the amount, every allocation basis, and every output."""
    authorize_coordinates(
        db,identity,scope,(plan.source,),kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,tuple(
        Coordinate.from_mapping(target['basis_members'])
        for target in plan.outputs),kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,tuple(
        Coordinate.from_mapping(target['members'])
        for target in plan.outputs),kind=AccessKind.WRITE)


_SHARES_CTE='''WITH weights AS (
    SELECT input.series_key,
        basis.coordinate_id AS basis_coordinate_id,
        input.member_id,bn.amount AS basis_amount,
        bn.change_id AS basis_change_id,
        '[]'::jsonb AS upstream_lineage,
        abs(%s::numeric * 100000000::numeric) AS source_units,
        sum(bn.amount) OVER () AS total_basis
    FROM jsonb_to_recordset(%s::jsonb)
    AS input(series_key text,basis_key text,member_id text)
    JOIN epm.coordinate basis ON basis.workspace_id=%s
    AND basis.application_id=%s AND basis.series_key=input.basis_key
    JOIN epm.numeric_cell_current bn
    ON bn.workspace_id=basis.workspace_id
    AND bn.application_id=basis.application_id
    AND bn.coordinate_id=basis.coordinate_id
    AND bn.present AND bn.amount>0
), pieces AS (
    SELECT *,div(source_units*basis_amount,total_basis) AS base_units,
        mod(source_units*basis_amount,total_basis) AS remainder_numerator
    FROM weights
), ranked AS (
    SELECT *,row_number() OVER (
        ORDER BY remainder_numerator DESC,member_id COLLATE "C")
        AS remainder_rank,
        source_units-sum(base_units) OVER () AS residual_units
    FROM pieces
)'''

_PUBLISHED_RATIO_SHARES_CTE='''WITH weights AS (
    SELECT input.series_key,basis.coordinate_id AS basis_coordinate_id,
        input.member_id,bn.ratio AS basis_amount,
        (%s::text||':'||basis.coordinate_id::text) AS basis_change_id,
        bn.source_lookup_lineage AS upstream_lineage,
        abs(%s::numeric * 100000000::numeric) AS source_units,
        sum(bn.ratio) OVER () AS total_basis
    FROM jsonb_to_recordset(%s::jsonb)
    AS input(series_key text,basis_key text,member_id text)
    JOIN epm.coordinate basis ON basis.workspace_id=%s
      AND basis.application_id=%s AND basis.series_key=input.basis_key
    JOIN epm.calculation_ratio_result_current bn ON bn.workspace_id=basis.workspace_id
      AND bn.application_id=basis.application_id AND bn.coordinate_id=basis.coordinate_id
      AND bn.result_key=%s AND bn.ratio>0
), pieces AS (
    SELECT *,div(source_units*basis_amount,total_basis) AS base_units,
      mod(source_units*basis_amount,total_basis) AS remainder_numerator FROM weights
), ranked AS (
    SELECT *,row_number() OVER (ORDER BY remainder_numerator DESC,
      member_id COLLATE "C") AS remainder_rank,
      source_units-sum(base_units) OVER () AS residual_units FROM pieces
)'''


class PostgresAllocationPublisher:
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
                unexpired=db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS valid''',
                    (job['lease_until'],)).fetchone()['valid']
                if (job['status']!='running'
                        or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant']
                        or not unexpired):
                    raise ValueError('STALE_WORKER_FENCE')
                policy_job=job['compiler_version'] in (POLICY_COMPILER,POLICY_V2_COMPILER)
                if (job['function_name']!=FUNCTION
                        or job['compiler_version'] not in (COMPILER,POLICY_COMPILER,POLICY_V2_COMPILER)
                        or job['plan_digest']!=(POLICY_V2_PLAN_DIGEST if
                            job['compiler_version']==POLICY_V2_COMPILER else
                            POLICY_PLAN_DIGEST if policy_job else PLAN_DIGEST)
                        or job['program_digest']!=_canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_ALLOCATION_JOB_PROGRAM')
                if policy_job:
                    plan,reusable_policy=decode_policy_allocation_program(
                        job['normalized_program'])
                    if not _current_policy_pointer_matches(db,scope,reusable_policy):
                        raise ValueError('PLANNING_POLICY_POINTER_STALE')
                else:plan=decode_allocation_program(job['normalized_program'])
                if (state['application_status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=job['expected_metadata_revision']
                        or state['data_revision']!=job['expected_data_revision']
                        or state['policy_revision']!=job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer=db.execute('''SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['state_token'] if pointer else None)!=(
                        plan.expected_target_state_token):
                    raise ValueError('STALE_RESULT_STATE')
                source,total_basis=validate_allocation_inputs(
                    db,scope,plan,check_locks=False)
                enforce_allocation_dimensional_security(
                    db,self.identity,scope,plan)
                targets=plan.outputs
                policy_evidence=enforce_allocation_target_policy(
                    db,scope,plan,access.role)
                db.execute('''CREATE TEMP TABLE allocation_result_stage
                    (series_key text PRIMARY KEY,source_amount numeric NOT NULL,
                     source_change_id text NOT NULL,amount numeric NOT NULL,
                     source_lookup_lineage jsonb NOT NULL)
                    ON COMMIT DROP''')
                db.execute('''CREATE TEMP TABLE allocation_basis_stage
                    (series_key text PRIMARY KEY,basis_coordinate_id bigint,
                     basis_amount numeric,basis_change_id text,
                     total_basis numeric,base_units numeric,
                     remainder_numerator numeric,extra_unit integer)
                    ON COMMIT DROP''')
                if plan.published_ratio_basis is None:
                    shares_sql=_SHARES_CTE
                    share_args=(source['amount'],Jsonb(targets),
                        scope.workspace_id,scope.application_id)
                else:
                    shares_sql=_PUBLISHED_RATIO_SHARES_CTE
                    share_args=(plan.published_ratio_basis['resultStateToken'],
                        source['amount'],Jsonb(targets),scope.workspace_id,
                        scope.application_id,plan.published_ratio_basis['resultKey'])
                inserted=db.execute(shares_sql+'''
                    INSERT INTO pg_temp.allocation_result_stage
                    (series_key,source_amount,source_change_id,amount,
                     source_lookup_lineage)
                    SELECT series_key,%s,%s,
                        sign(%s::numeric) *
                        (base_units+CASE WHEN remainder_rank<=residual_units
                            THEN 1 ELSE 0 END) * 0.00000001::numeric,
                        CASE WHEN %s::boolean THEN jsonb_build_array(
                          jsonb_build_object('inputKind','PublishedRatio',
                            'resultKey',%s::text,'resultStateToken',%s::text,
                            'memberId',member_id,
                            'ratio',basis_amount::text,'upstreamRowLineage',
                            upstream_lineage)) ELSE '[]'::jsonb END
                    FROM ranked''',
                    (*share_args,source['amount'],source['change_id'],
                     source['amount'],plan.published_ratio_basis is not None,
                     plan.published_ratio_basis['resultKey'] if plan.published_ratio_basis else '',
                     plan.published_ratio_basis['resultStateToken'] if plan.published_ratio_basis else '')).rowcount
                if inserted!=len(targets):
                    raise ValueError('ALLOCATION_TARGET_COUNT_CHANGED')
                lineage=(db.execute(_SHARES_CTE+'''
                    INSERT INTO pg_temp.allocation_basis_stage
                    (series_key,basis_coordinate_id,basis_amount,
                     basis_change_id,total_basis,base_units,
                     remainder_numerator,extra_unit)
                    SELECT series_key,basis_coordinate_id,
                        basis_amount,basis_change_id,total_basis,
                        base_units,remainder_numerator,
                        CASE WHEN remainder_rank<=residual_units
                            THEN 1 ELSE 0 END
                    FROM ranked''',
                    share_args).rowcount if plan.published_ratio_basis is None
                     else inserted)
                if lineage!=len(targets):
                    raise ValueError('ALLOCATION_LINEAGE_COUNT_CHANGED')
                conserved=db.execute('''SELECT sum(amount) AS total
                    FROM pg_temp.allocation_result_stage''').fetchone()['total']
                if conserved!=source['amount']:
                    raise ValueError('ALLOCATION_CONSERVATION_FAILED')
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
                    '''SELECT %s::timestamptz > clock_timestamp() AS valid''',
                    (final_job['lease_until'],)).fetchone()['valid'])
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
                final_pointer=db.execute('''SELECT state_token
                    FROM epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (final_pointer['state_token']
                        if final_pointer else None)!=(
                            plan.expected_target_state_token):
                    raise ValueError('STALE_RESULT_STATE')
                final_source,final_total_basis=validate_allocation_inputs(
                    db,scope,plan,check_locks=False)
                if (final_source!=source
                        or final_total_basis!=total_basis):
                    raise ValueError('ALLOCATION_SOURCE_CHANGED')
                enforce_allocation_dimensional_security(
                    db,self.identity,scope,plan)
                policy_evidence=enforce_allocation_target_policy(
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
                db.execute('''INSERT INTO epm.calculation_operation_staging
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],FUNCTION,len(targets),revision))
                durable_results=db.execute('''INSERT INTO epm.calculation_result_staging
                    (workspace_id,application_id,generation_id,coordinate_id,
                     source_amount,source_change_id,amount,
                     source_lookup_lineage)
                    SELECT %s,%s,%s,c.coordinate_id,s.source_amount,
                     s.source_change_id,s.amount,s.source_lookup_lineage
                    FROM pg_temp.allocation_result_stage s
                    JOIN epm.coordinate c ON c.workspace_id=%s
                     AND c.application_id=%s AND c.series_key=s.series_key''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     scope.workspace_id,scope.application_id)).rowcount
                if durable_results!=inserted:
                    raise ValueError('ALLOCATION_TARGET_COUNT_CHANGED')
                if plan.published_ratio_basis is None:
                    durable_lineage=db.execute('''INSERT INTO
                        epm.allocation_basis_lineage_staging
                        (workspace_id,application_id,generation_id,
                         coordinate_id,basis_coordinate_id,basis_amount,
                         basis_change_id,total_basis,base_units,
                         remainder_numerator,extra_unit)
                        SELECT %s,%s,%s,c.coordinate_id,s.basis_coordinate_id,
                         s.basis_amount,s.basis_change_id,s.total_basis,
                         s.base_units,s.remainder_numerator,s.extra_unit
                        FROM pg_temp.allocation_basis_stage s
                        JOIN epm.coordinate c ON c.workspace_id=%s
                         AND c.application_id=%s
                         AND c.series_key=s.series_key''',
                        (scope.workspace_id,scope.application_id,
                         claim['job_id'],scope.workspace_id,
                         scope.application_id)).rowcount
                    if durable_lineage!=lineage:
                        raise ValueError('ALLOCATION_LINEAGE_COUNT_CHANGED')
                from .postgres_current_result_publication import advance_result_head_during_conversion
                current_result=advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                result={'resultKey':plan.result_key,
                        'resultStateToken':current_result['state_token'],
                        'resultContentDigest':current_result['content_digest'],
                        'function':FUNCTION,
                        'rowCount':inserted,
                        'sourceAmount':format(source['amount'],'f'),
                        'totalBasis':format(total_basis,'f'),
                        'sourceCommitRevision':state['commit_revision'],
                        'engine':'postgres_exact_sql',
                        'planningPolicy':policy_evidence}
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=plan.result_key,
                    existed=final_pointer is not None)
                result['impactDigest']=impact.digest
                if policy_job:result['reusablePolicy']=reusable_policy
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
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                completed=db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s
                    AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision,Jsonb(result),scope.workspace_id,
                     scope.application_id,claim['job_id'],
                     claim['claim_generation'],claim['claimant'])).rowcount
                if completed!=1:
                    raise ValueError('STALE_WORKER_FINAL_FENCE')
                return result
