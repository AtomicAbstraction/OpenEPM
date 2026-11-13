"""Exact mechanical CTA bridge posting over the immutable journal layer.

This stage does not select rates or assert an accounting policy. It posts only
an explicitly pinned opening + movements = closing bridge supplied by an
upstream qualified translation stage.
"""
from copy import deepcopy
from decimal import Decimal, localcontext
from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_cta_bridge_v2 import CtaBridgeV2
from .consolidation_cta_bridge_v3 import CtaBridgeV3
from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_manual_journal import POST_FUNCTION, PostgresManualJournal
from .postgres_manual_journal import valid_idempotency_key
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy
from .postgres_consolidation_layout import resolve_active_layout
from .postgres_calculation_status import (
    input_revision_status, published_calculation_translation_status,
    published_input_status,typed_expression_raw_driver_status)

PREVIEW='consolidation.cta.bridge.preview'
FUNCTION='consolidation.cta.bridge.post'
READ='consolidation.cta.bridge.read'


def _public_current_evidence(value):
    """Remove server operation/version locators from CTA public evidence."""
    if isinstance(value,dict):
        return {key:_public_current_evidence(item) for key,item in value.items()
                if key not in ('generationId','publishedRevision',
                               'sourceOperationId','sourceCommittedRevision')}
    if isinstance(value,list):
        return [_public_current_evidence(item) for item in value]
    return value


def _authorize_plan_coordinates(db, identity, scope, plan, *,
                                sources=False, targets=None):
    """Authorize the explicit CTA grain before reading or publishing it.

    Translation generations are technical containers, not an authorization
    boundary.  Their selected coordinates remain business data and therefore
    require current dimensional READ authority.  CTA/offset effects require
    current dimensional authority independently of the broader function grant.
    """
    if sources:
        authorize_coordinates(
            db, identity, scope,
            tuple(Coordinate.from_mapping(dict(pin.members))
                  for pin in plan.sources),
            kind=AccessKind.READ)
    if targets is not None:
        authorize_coordinates(
            db, identity, scope,
            (Coordinate.from_mapping(dict(plan.cta_members)),
             Coordinate.from_mapping(dict(plan.offset_members))),
            kind=targets)


def expected_current_data_revision(compiler_version: str,
                                   pinned_source_data_revision: int) -> int:
    """Raw revision expected after publishing a bridge of this profile."""
    return (pinned_source_data_revision if
            compiler_version == 'cta-bridge-v3-typed-unit' else
            pinned_source_data_revision + 1)


def _dependency_pins(status):
    """Flatten the bounded dependency certificate persisted at publication."""
    found=[]
    def visit(node):
        if isinstance(node,dict):
            if {'resultKey','generationId','publishedRevision'} <= set(node):
                found.append((node['resultKey'],node['generationId'],
                              node['publishedRevision']))
            for value in node.values():visit(value)
        elif isinstance(node,list):
            for value in node:visit(value)
    visit(status)
    return tuple(sorted(set(found)))


def _dependency_pointers_current(db,scope,status):
    pins=_dependency_pins(status)
    if not pins:return True
    rows=db.execute('''SELECT input.result_key,input.generation_id,
        input.published_revision,p.source_operation_id AS observed_generation_id,
        p.committed_revision AS observed_published_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(result_key text,
          generation_id text,published_revision bigint)
        LEFT JOIN epm.calculation_result_state p ON p.workspace_id=%s
          AND p.application_id=%s AND p.result_key=input.result_key
        ORDER BY input.result_key,input.generation_id''',(Jsonb([{
          'result_key':key,'generation_id':generation,
          'published_revision':revision} for key,generation,revision in pins]),
          scope.workspace_id,scope.application_id)).fetchall()
    return len(rows)==len(pins) and all(
      row['generation_id']==row['observed_generation_id'] and
      row['published_revision']==row['observed_published_revision']
      for row in rows)


def _seal_v3_candidate(plan:CtaBridgeV3,roles:dict,sources:list,
                       movement:Decimal)->dict:
    payload={'plan':plan.normalized(),'roles':deepcopy(roles),
      'sources':deepcopy(sources),'movement':format(movement,'.8f')}
    return {**payload,'digest':_canonical_digest(payload)}


def cta_bridge_sources_current(db, scope, bridge_id: str) -> bool:
    """Deep currentness check reusable inside an existing transaction."""
    bridge=db.execute('''SELECT compiler_version,data_revision,
      metadata_revision,policy_revision,layout_state_token,layout_digest
      FROM epm.cta_bridge WHERE workspace_id=%s AND application_id=%s
      AND bridge_id=%s AND status='Posted' ''',(
      scope.workspace_id,scope.application_id,bridge_id)).fetchone()
    if bridge is None:return False
    try:
        resolve_active_layout(db,scope,expected_state_token=bridge['layout_state_token'],
                              expected_digest=bridge['layout_digest'])
    except ValueError:
        return False
    rows=db.execute('''SELECT s.result_state_token,s.result_content_digest,
      s.source_operation_id,s.source_committed_revision,
      s.source_function,s.compiler_version AS source_compiler_version,
      s.dependency_status,
      p.state_token AS observed_state_token,
      p.source_function AS function_name,
      p.source_metadata_revision,p.source_policy_revision,
      j.compiler_version AS job_compiler_version,j.status,
      j.expected_metadata_revision,j.expected_data_revision,
      j.expected_policy_revision,st.metadata_revision,st.data_revision,
      st.policy_revision FROM epm.cta_bridge_source s
      LEFT JOIN epm.calculation_result_state p ON
        p.workspace_id=s.workspace_id AND p.application_id=s.application_id
        AND p.result_key=s.result_key
      LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
        AND j.application_id=p.application_id
        AND j.job_id=p.source_operation_id
      JOIN epm.application_state st ON st.workspace_id=s.workspace_id
        AND st.application_id=s.application_id
      WHERE s.workspace_id=%s AND s.application_id=%s AND s.bridge_id=%s
      ORDER BY s.source_ordinal''',(
      scope.workspace_id,scope.application_id,bridge_id)).fetchall()
    expected_data=expected_current_data_revision(
      bridge['compiler_version'],bridge['data_revision'])
    return bool(rows) and all(
      row['result_state_token']==row['observed_state_token']
      and row['source_function']==row['function_name']
      and row['source_compiler_version']==row['job_compiler_version']
      and row['status']=='published'
      and row['source_metadata_revision']==row['expected_metadata_revision']
      and row['source_policy_revision']==row['expected_policy_revision']
      and row['expected_metadata_revision']==bridge['metadata_revision']
      and row['expected_metadata_revision']==row['metadata_revision']
      and row['expected_policy_revision']==bridge['policy_revision']
      and row['expected_policy_revision']==row['policy_revision']
      and row['expected_data_revision']==bridge['data_revision']
      and row['data_revision']==expected_data
      and _dependency_pointers_current(db,scope,row['dependency_status'])
      for row in rows)

def _amount(value):
    if type(value) is not str: raise ValueError('CTA_AMOUNT_INVALID')
    return NumericCell.from_wire(present=True,amount=value).amount

def compile_cta_bridge(arguments):
    required={'openingCta','closingCta','movements','ctaMembers','offsetMembers',
        'sourceResults','expectedMetadataRevision','expectedPolicyRevision',
        'expectedDataRevision','policyStateToken','policyDigest','effectivePeriod','reason'}
    if type(arguments) is not dict or set(arguments)!=required:
        raise ValueError('CTA_ARGUMENTS_INVALID')
    revisions=('expectedMetadataRevision','expectedPolicyRevision','expectedDataRevision')
    if any(type(arguments[name]) is not int or arguments[name]<0 for name in revisions):
        raise ValueError('CTA_PINS_INVALID')
    if (not isinstance(arguments['policyStateToken'],str)
            or not re.fullmatch(r'[0-9a-f]{64}',arguments['policyStateToken'])):
        raise ValueError('CTA_PINS_INVALID')
    digest=arguments['policyDigest']
    if type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('CTA_POLICY_DIGEST_INVALID')
    if (type(arguments['movements']) is not list or not 1<=len(arguments['movements'])<=100
            or type(arguments['sourceResults']) is not list
            or not 1<=len(arguments['sourceResults'])<=100):
        raise ValueError('CTA_BOUNDS_INVALID')
    movements=[]
    for row in arguments['movements']:
        if (type(row) is not dict or set(row)!={'movementId','amount'}
                or type(row['movementId']) is not str or not 1<=len(row['movementId'])<=100):
            raise ValueError('CTA_MOVEMENT_INVALID')
        movements.append((row['movementId'],_amount(row['amount'])))
    if len({v[0] for v in movements})!=len(movements):
        raise ValueError('CTA_MOVEMENT_DUPLICATE')
    results=arguments['sourceResults']
    if any(type(v) is not dict or set(v)!={'resultKey','resultStateToken'}
            or type(v['resultKey']) is not str or not v['resultKey']
            or type(v['resultStateToken']) is not str
            or not re.fullmatch(r'[0-9a-f]{64}',v['resultStateToken'])
            for v in results): raise ValueError('CTA_LINEAGE_INVALID')
    opening,closing=_amount(arguments['openingCta']),_amount(arguments['closingCta'])
    with localcontext() as context:
        context.prec=64;movement=sum((v for _,v in movements),Decimal(0))
        if opening+movement!=closing: raise ValueError('CTA_BRIDGE_NOT_RECONCILED')
    for name in ('ctaMembers','offsetMembers'):
        value=arguments[name]
        if type(value) is not dict or not 1<=len(value)<=32 or any(
                type(k) is not str or type(v) is not str or not k or not v
                for k,v in value.items()): raise ValueError('CTA_COORDINATE_INVALID')
    if arguments['ctaMembers']==arguments['offsetMembers']:
        raise ValueError('CTA_COORDINATES_MUST_DIFFER')
    period=arguments['effectivePeriod']
    if (type(period) is not dict or set(period)!={'scenarioDimension','scenarioId',
            'yearDimension','yearId','periodDimension','periodId'}
            or any(type(v) is not str or not v for v in period.values())):
        raise ValueError('CTA_EFFECTIVE_PERIOD_INVALID')
    for members in (arguments['ctaMembers'],arguments['offsetMembers']):
        if any(members.get(period[axis])!=period[value] for axis,value in (
                ('scenarioDimension','scenarioId'),('yearDimension','yearId'),
                ('periodDimension','periodId'))):
            raise ValueError('CTA_EFFECTIVE_PERIOD_MISMATCH')
    canonical={'openingCta':format(opening,'f'),'closingCta':format(closing,'f'),
        'movements':[{'movementId':k,'amount':format(v,'f')} for k,v in movements],
        'ctaMembers':dict(sorted(arguments['ctaMembers'].items())),
        'offsetMembers':dict(sorted(arguments['offsetMembers'].items())),
        'sourceResults':results,'effectivePeriod':period,
        'policyStateToken':arguments['policyStateToken'],
        'policyDigest':digest,'pins':{name:arguments[name] for name in revisions[:3]}}
    bridge_digest=sha256(json.dumps(canonical,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return canonical,movement,bridge_digest

class PostgresCtaBridge:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity): raise ValueError('Verified identity is required')
        self.dsn,self.identity=dsn,identity
    def _validate_current(self,scope,canonical):
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=FUNCTION)
                state=db.execute('''SELECT metadata_revision,data_revision,policy_revision
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',(
                    scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or any(state[column]!=canonical['pins'][argument]
                        for argument,column in (
                            ('expectedMetadataRevision','metadata_revision'),
                            ('expectedDataRevision','data_revision'),
                            ('expectedPolicyRevision','policy_revision')))):
                    raise ValueError('CTA_STALE_CONTEXT')
                source_rows=[{'result_key':row['resultKey'],
                    'result_state_token':row['resultStateToken']}
                    for row in canonical['sourceResults']]
                sources=db.execute('''SELECT input.result_key,
                    input.result_state_token,p.source_function AS function_name,
                    p.state_token=input.result_state_token AS current
                    FROM jsonb_to_recordset(%s::jsonb) AS input(
                        result_key text,result_state_token text)
                    LEFT JOIN epm.calculation_result_state p ON p.workspace_id=%s
                     AND p.application_id=%s AND p.result_key=input.result_key''',(
                    Jsonb(source_rows),scope.workspace_id,
                    scope.application_id)).fetchall()
                if (len(sources)!=len(canonical['sourceResults'])
                        or any(not row['current']
                            or row['function_name']!='currency.translation.publish'
                            for row in sources)):
                    raise ValueError('CTA_TRANSLATION_SOURCE_STALE')

    @staticmethod
    def _v2_replay(db,scope,bridge_id,operation_id,bridge_digest,identity):
        existing=db.execute('''SELECT bridge_digest,issuer,subject_id,result
            FROM epm.cta_bridge WHERE workspace_id=%s
            AND application_id=%s AND bridge_id=%s''',(
            scope.workspace_id,scope.application_id,bridge_id)).fetchone()
        if existing:
            if (existing['bridge_digest']!=bridge_digest
                    or existing['issuer']!=identity.issuer
                    or existing['subject_id']!=identity.subject_id):
                raise ValueError('CTA_V2_IDEMPOTENCY_CONFLICT')
            return existing['result']
        receipt=db.execute('''SELECT command_digest,actor_id FROM
            epm.operation_receipt WHERE workspace_id=%s
            AND application_id=%s AND operation_id=%s''',(
            scope.workspace_id,scope.application_id,operation_id)).fetchone()
        if receipt is not None:
            raise ValueError('CTA_V2_IDEMPOTENCY_CONFLICT')
        return None

    @staticmethod
    def _validate_v2_layout(db,scope,plan:CtaBridgeV2)->dict:
        layout=resolve_active_layout(db,scope,
            expected_state_token=plan.layout_state_token,
            expected_digest=plan.layout_digest)
        roles={'Entity':layout['entity_dimension_id'],
          'Currency':layout['currency_dimension_id'],
          'Account':layout['account_dimension_id']}
        stage=layout['stage_dimension_id'];movement=layout[
            'movement_dimension_id']
        points=[dict(item.members) for item in plan.sources]+[
            dict(plan.cta_members),dict(plan.offset_members)]
        axes=set(points[0])
        required=set(roles.values())|{stage,movement}
        if not required<=axes or any(set(point)!=axes for point in points):
            raise ValueError('CTA_V2_SOURCE_GRAIN_MISMATCH')
        varying={roles['Account'],movement}
        baseline={axis:member for axis,member in points[0].items()
                  if axis not in varying}
        if any({axis:member for axis,member in point.items()
                if axis not in varying}!=baseline for point in points[1:]):
            raise ValueError('CTA_V2_NON_FINANCIAL_GRAIN_MISMATCH')
        currency=plan.sources[0].output_currency_member_id
        if any(point[roles['Currency']]!=currency for point in points):
            raise ValueError('CTA_V2_CURRENCY_TARGET_MISMATCH')
        pairs=sorted({(axis,member) for point in points
                      for axis,member in point.items()})
        active=db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active FROM
            jsonb_to_recordset(%s::jsonb) AS input(
              dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s
              AND m.application_id=%s
              AND m.dimension_id=input.dimension_id
              AND m.member_id=input.member_id AND m.status='Active' ''',(
            Jsonb([{'dimension_id':axis,'member_id':member}
                   for axis,member in pairs]),scope.workspace_id,
            scope.application_id)).fetchall()
        if len(active)!=len(pairs) or any(not row['active'] for row in active):
            raise ValueError('CTA_V2_MEMBER_UNAVAILABLE')
        return {**roles,'Stage':stage,'Movement':movement,
          'layoutStateToken':layout['state_token'],
          'layoutDigest':layout['layout_digest']}

    @staticmethod
    def _v2_state(db, scope, plan: CtaBridgeV2, *, lock=False):
        if lock:
            PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        state = db.execute('''SELECT s.metadata_revision,s.data_revision,
            s.policy_revision,s.commit_revision,s.processing_mode,
            a.status AS application_status FROM epm.application_state s
            JOIN epm.application a USING(workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s ''' +
            ('FOR UPDATE OF s' if lock else ''),
            (scope.workspace_id, scope.application_id)).fetchone()
        if (state is None or state['application_status'] != 'Active'
                or state['processing_mode'] != 'Active'):
            raise ValueError('APPLICATION_NOT_WRITABLE')
        if (state['metadata_revision'] != plan.expected_metadata_revision
                or state['data_revision'] != plan.expected_data_revision
                or state['policy_revision'] != plan.expected_policy_revision):
            raise ValueError('CTA_V2_STALE_CONTEXT')
        return state

    @staticmethod
    def _lock_application_state(db,scope)->None:
        """Take the mutation row before capability authorization reads it.

        Authorization takes a shared row lock for capability currentness.  Two
        publishers must not both take that shared lock and then try to upgrade
        it to ``FOR UPDATE``.  The workspace fence is always acquired first;
        this short row lock then serializes only final publication.
        """
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        row=db.execute('''SELECT 1 FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',(
            scope.workspace_id,scope.application_id)).fetchone()
        if row is None:raise ValueError('APPLICATION_NOT_WRITABLE')

    @staticmethod
    def _validate_v3_layout(db,scope,plan:CtaBridgeV3)->dict:
        layout=resolve_active_layout(db,scope,
            expected_state_token=plan.layout_state_token,
            expected_digest=plan.layout_digest)
        roles={'Entity':layout['entity_dimension_id'],
          'Currency':layout['currency_dimension_id'],
          'Account':layout['account_dimension_id']}
        if plan.currency_dimension_id!=roles['Currency']:
            raise ValueError('CTA_V3_CURRENCY_DIMENSION_MISMATCH')
        stage=layout['stage_dimension_id'];movement=layout[
            'movement_dimension_id']
        points=[dict(item.members) for item in plan.sources]+[
            dict(plan.cta_members),dict(plan.offset_members)]
        axes=set(points[0]);required={roles['Entity'],roles['Account'],
                                     stage,movement}
        active_axes={row['dimension_id'] for row in db.execute('''SELECT
            dimension_id FROM epm.dimension WHERE workspace_id=%s
            AND application_id=%s AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency' ''',(
            scope.workspace_id,scope.application_id)).fetchall()}
        if (roles['Currency'] in axes or not required<=axes
                or axes!=active_axes
                or any(set(point)!=axes for point in points)):
            raise ValueError('CTA_V3_SOURCE_GRAIN_MISMATCH')
        varying={roles['Account'],movement}
        baseline={axis:member for axis,member in points[0].items()
                  if axis not in varying}
        if any({axis:member for axis,member in point.items()
                if axis not in varying}!=baseline for point in points[1:]):
            raise ValueError('CTA_V3_NON_FINANCIAL_GRAIN_MISMATCH')
        pairs=sorted({(axis,member) for point in points
                      for axis,member in point.items()}|{
                      (roles['Currency'],plan.currency_member_id)})
        active=db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active FROM
            jsonb_to_recordset(%s::jsonb) AS input(
              dimension_id text,member_id text)
            LEFT JOIN epm.member m ON m.workspace_id=%s
              AND m.application_id=%s
              AND m.dimension_id=input.dimension_id
              AND m.member_id=input.member_id AND m.status='Active' ''',(
            Jsonb([{'dimension_id':axis,'member_id':member}
                   for axis,member in pairs]),scope.workspace_id,
            scope.application_id)).fetchall()
        if len(active)!=len(pairs) or any(not row['active'] for row in active):
            raise ValueError('CTA_V3_MEMBER_UNAVAILABLE')
        return {**roles,'Stage':stage,'Movement':movement,
          'layoutStateToken':layout['state_token'],
          'layoutDigest':layout['layout_digest']}

    @staticmethod
    def _resolve_v3_sources(db,scope,plan:CtaBridgeV3,roles:dict):
        from .postgres_consolidation_full import (
            TYPED_COMPILER,TYPED_FUNCTION,typed_full_context_status)
        resolved=[];opening=closing=None;movement=Decimal(0)
        for ordinal,pin in enumerate(plan.sources,1):
            coordinate=Coordinate.from_mapping(dict(pin.members))
            generation=db.execute('''SELECT
                p.state_token AS current_result_state_token,
                p.content_digest AS current_result_content_digest,
                p.source_operation_id AS current_generation_id,
                p.committed_revision AS current_published_revision,
                p.source_function AS function_name,
                j.compiler_version,j.status AS job_status,
                j.normalized_program,j.result AS job_result,
                j.expected_metadata_revision,j.expected_data_revision,
                j.expected_policy_revision,p.source_metadata_revision,
                p.source_policy_revision,s.metadata_revision AS current_metadata_revision,
                s.data_revision AS current_data_revision,
                s.policy_revision AS current_policy_revision,
                s.commit_revision AS observed_commit_revision
                FROM epm.calculation_result_state p
                JOIN epm.job j ON j.workspace_id=p.workspace_id
                  AND j.application_id=p.application_id
                  AND j.job_id=p.source_operation_id
                JOIN epm.application_state s ON s.workspace_id=p.workspace_id
                  AND s.application_id=p.application_id
                WHERE p.workspace_id=%s AND p.application_id=%s
                  AND p.result_key=%s''',(scope.workspace_id,
                 scope.application_id,pin.result_key)).fetchone()
            if generation is None:
                raise ValueError('CTA_V3_SOURCE_UNAVAILABLE')
            expression=(generation['function_name']=='facts.expression.calculate'
                and PostgresCtaBridge._certified_v3_expression(
                    generation['compiler_version'],
                    generation['normalized_program'],plan.currency_member_id))
            typed_full=(generation['function_name']==TYPED_FUNCTION
                        and generation['compiler_version']==TYPED_COMPILER)
            if not (expression or typed_full):
                raise ValueError('CTA_V3_SOURCE_STALE_OR_UNSUPPORTED')
            rows=db.execute('''SELECT c.members,ur.amount,
                ur.output_unit_currency_dimension_id,
                ur.output_unit_currency_member_id,ur.rate_strategy,
                ur.rate_numerator::text AS rate_numerator,
                ur.rate_denominator::text AS rate_denominator,
                ur.rate_sources,ur.source_lookup_lineage
                FROM epm.calculation_unit_result_current ur JOIN epm.coordinate c
                USING(workspace_id,application_id,coordinate_id)
                WHERE ur.workspace_id=%s AND ur.application_id=%s
                AND ur.result_key=%s AND c.series_key=%s
                AND ur.output_unit_currency_dimension_id=%s
                AND ur.output_unit_currency_member_id=%s
                ORDER BY ur.coordinate_id LIMIT 2''',(scope.workspace_id,
                scope.application_id,pin.result_key,coordinate.series_key,
                plan.currency_dimension_id,plan.currency_member_id)).fetchall()
            direct=input_revision_status(generation)
            raw_status=(typed_expression_raw_driver_status(
                db,scope,pin.result_key,generation['normalized_program'])
                if generation.get('compiler_version')==
                    'typed-numeric-expression-v29' else None)
            # A raw-driver change also advances the broad data revision. Check
            # the more exact v29 certificate first so this dedicated safety
            # boundary is observable instead of being shadowed forever by the
            # generic revision error.
            if raw_status is not None and not raw_status['matchesAtRead']:
                raise ValueError('CTA_V3_SOURCE_RAW_DRIVER_STALE')
            if (len(rows)!=1
                    or generation['current_result_state_token']!=
                        pin.result_state_token
                    or generation['job_status']!='published'
                    or rows[0]['members']!=dict(pin.members)
                    or plan.currency_dimension_id in rows[0]['members']
                    or rows[0]['amount'] is None or not direct['matchesAtRead']):
                raise ValueError('CTA_V3_SOURCE_STALE_OR_UNSUPPORTED')
            row=rows[0]
            status=(published_input_status(db,scope,generation['normalized_program'])
                    if expression else typed_full_context_status(db,scope,
                        generation['normalized_program'],generation['job_result']))
            if status is not None and not status['matchesAtRead']:
                raise ValueError('CTA_V3_SOURCE_DEPENDENCY_STALE')
            amount=row['amount'];lineage={'unit':{
              'dimensionId':plan.currency_dimension_id,
              'memberId':plan.currency_member_id},
              'rateStrategy':row['rate_strategy'],
              'rateNumerator':row['rate_numerator'],
              'rateDenominator':row['rate_denominator'],
              'rateSources':row['rate_sources'],
              'sourceLookupLineage':row['source_lookup_lineage']}
            item={**pin.normalized(),'ordinal':ordinal,
              'amount':format(amount,'.8f'),'function':generation['function_name'],
              'compilerVersion':generation['compiler_version'],
              'resultContentDigest':generation['current_result_content_digest'],
              'sourceOperationId':generation['current_generation_id'],
              'sourceCommittedRevision':generation['current_published_revision'],
              'outputCurrencyDimensionId':plan.currency_dimension_id,
              'outputCurrencyMemberId':plan.currency_member_id,
              'lineage':lineage,'inputRevisionStatus':direct,
              'dependencyStatus':status}
            if raw_status is not None:item['rawDriverStatus']=raw_status
            resolved.append(item)
            if pin.role=='Opening':opening=amount
            elif pin.role=='Closing':closing=amount
            else:movement+=amount*pin.sign
        if opening is None or closing is None or opening+movement!=closing:
            raise ValueError('CTA_V3_BRIDGE_NOT_RECONCILED')
        return resolved,movement

    @staticmethod
    def _verify_v3_candidate(db,scope,plan:CtaBridgeV3,
                             candidate:dict)->None:
        """Bulk-check one sealed source certificate under the final fence."""
        from .postgres_consolidation_full import TYPED_COMPILER,TYPED_FUNCTION
        inputs=[]
        for ordinal,(pin,item) in enumerate(
                zip(plan.sources,candidate['sources']),1):
            if (item.get('ordinal')!=ordinal
                    or item.get('resultKey')!=pin.result_key
                    or item.get('resultStateToken')!=pin.result_state_token
                    or item.get('members')!=dict(pin.members)):
                raise ValueError('CTA_V3_CANDIDATE_CHANGED')
            inputs.append({'ordinal':ordinal,'result_key':pin.result_key,
              'result_state_token':pin.result_state_token,
              'generation_id':item['sourceOperationId'],
              'published_revision':item['sourceCommittedRevision'],
              'series_key':Coordinate.from_mapping(
                  dict(pin.members)).series_key})
        rows=db.execute('''SELECT input.ordinal,input.result_key,
            input.result_state_token,input.generation_id,input.published_revision,
            p.state_token AS current_result_state_token,
            p.source_operation_id AS current_generation_id,
            p.committed_revision AS current_published_revision,
            p.source_function AS function_name,p.source_metadata_revision,
            p.source_policy_revision,j.compiler_version,j.status AS job_status,
            j.normalized_program,j.result AS job_result,
            j.expected_metadata_revision,j.expected_data_revision,
            j.expected_policy_revision,c.members,ur.amount,
            ur.output_unit_currency_dimension_id,
            ur.output_unit_currency_member_id,ur.rate_strategy,
            ur.rate_numerator::text AS rate_numerator,
            ur.rate_denominator::text AS rate_denominator,
            ur.rate_sources,ur.source_lookup_lineage
            FROM jsonb_to_recordset(%s::jsonb) AS input(
              ordinal integer,result_key text,result_state_token text,generation_id text,
              published_revision bigint,series_key text)
            LEFT JOIN epm.calculation_result_state p ON
              p.workspace_id=%s AND p.application_id=%s
              AND p.result_key=input.result_key
            LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
              AND j.application_id=p.application_id
              AND j.job_id=p.source_operation_id
            LEFT JOIN epm.coordinate c ON c.workspace_id=%s
              AND c.application_id=%s AND c.series_key=input.series_key
            LEFT JOIN epm.calculation_unit_result_current ur ON
              ur.workspace_id=p.workspace_id
              AND ur.application_id=p.application_id
              AND ur.result_key=p.result_key
              AND ur.coordinate_id=c.coordinate_id
              AND ur.output_unit_currency_dimension_id=%s
              AND ur.output_unit_currency_member_id=%s
            ORDER BY input.ordinal''',(Jsonb(inputs),
            scope.workspace_id,scope.application_id,
            scope.workspace_id,scope.application_id,
            plan.currency_dimension_id,plan.currency_member_id)).fetchall()
        if len(rows)!=len(candidate['sources']):
            raise ValueError('CTA_V3_SOURCE_STALE_OR_UNSUPPORTED')
        for row,item in zip(rows,candidate['sources']):
            expression=(row['function_name']=='facts.expression.calculate'
              and PostgresCtaBridge._certified_v3_expression(
                row['compiler_version'],row['normalized_program'],
                plan.currency_member_id))
            typed_full=(row['function_name']==TYPED_FUNCTION
                        and row['compiler_version']==TYPED_COMPILER)
            lineage={'unit':{'dimensionId':plan.currency_dimension_id,
              'memberId':plan.currency_member_id},
              'rateStrategy':row['rate_strategy'],
              'rateNumerator':row['rate_numerator'],
              'rateDenominator':row['rate_denominator'],
              'rateSources':row['rate_sources'],
              'sourceLookupLineage':row['source_lookup_lineage']}
            if (not (expression or typed_full)
                    or row['current_result_state_token']!=
                        row['result_state_token']
                    or row['job_status']!='published'
                    or row['members']!=item['members']
                    or plan.currency_dimension_id in row['members']
                    or row['amount'] is None
                    or format(row['amount'],'.8f')!=item['amount']
                    or row['output_unit_currency_dimension_id']!=
                        plan.currency_dimension_id
                    or row['output_unit_currency_member_id']!=
                        plan.currency_member_id
                    or row['function_name']!=item['function']
                    or row['compiler_version']!=item['compilerVersion']
                    or lineage!=item['lineage']
                    or row['expected_metadata_revision']!=
                        plan.expected_metadata_revision
                    or row['expected_data_revision']!=
                        plan.expected_data_revision
                    or row['expected_policy_revision']!=
                        plan.expected_policy_revision
                    or row['source_metadata_revision']!=
                        row['expected_metadata_revision']
                    or row['source_policy_revision']!=
                        row['expected_policy_revision']
                    or not item['inputRevisionStatus']['matchesAtRead']
                    or (item.get('rawDriverStatus') is not None and
                        not item['rawDriverStatus']['matchesAtRead'])
                    or (item.get('dependencyStatus') is not None and
                        (not item['dependencyStatus']['matchesAtRead'] or
                         not _dependency_pointers_current(
                             db,scope,item['dependencyStatus'])))):
                raise ValueError('CTA_V3_SOURCE_STALE_OR_UNSUPPORTED')

    @staticmethod
    def _certified_v3_expression(compiler,program,currency_member):
        """Certify a stored Amount-with-Currency profile, never by version alone."""
        from .postgres_expression import (aligned_output_unit,compiler_for,
          currency_conversion,decode_expression_program)
        qualified=frozenset(('typed-numeric-expression-v21',
          'typed-numeric-expression-v22','typed-numeric-expression-v23',
          'typed-numeric-expression-v26','typed-numeric-expression-v27',
          'typed-numeric-expression-v28','typed-numeric-expression-v29'))
        if compiler not in qualified or not isinstance(program,dict):return False
        try:
            plan=decode_expression_program(program)
            effective_compiler,_=compiler_for(plan)
            if effective_compiler!=compiler:return False
            conversion=currency_conversion(plan.expression)
            if conversion is not None:
                return (conversion.get('outputUnitCurrencyMemberId')==
                        currency_member)
            if getattr(plan,'amount_unit',None) is not None:
                return plan.amount_unit[1] == currency_member
            return aligned_output_unit(plan.expression)==currency_member
        except (TypeError,ValueError,KeyError):return False

    def preview_v3(self,scope:ApplicationScope,arguments:dict)->dict:
        plan=CtaBridgeV3.parse(arguments)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=PREVIEW)
                self._v2_state(db,scope,plan)
                roles=self._validate_v3_layout(db,scope,plan)
                _authorize_plan_coordinates(
                    db,self.identity,scope,plan,sources=True)
                sources,movement=self._resolve_v3_sources(db,scope,plan,roles)
        opening=next(item['amount'] for item in sources if item['role']=='Opening')
        closing=next(item['amount'] for item in sources if item['role']=='Closing')
        return {'status':'Previewed','bridgeVersion':3,
          'bridgeDigest':plan.digest,'openingCta':opening,
          'movementCta':format(movement,'.8f'),'closingCta':closing,
          'outputCurrencyDimensionId':plan.currency_dimension_id,
          'outputCurrencyMemberId':plan.currency_member_id,
          'layoutStateToken':plan.layout_state_token,'layoutDigest':plan.layout_digest,
          'sources':_public_current_evidence(sources),
          'accountingPolicyStatus':'Unreviewed',
          'mechanicalOnly':True,'effects':'None'}

    @staticmethod
    def _resolve_v2_sources(db, scope, plan: CtaBridgeV2,
                            roles:dict) -> tuple[list, Decimal]:
        resolved = []
        opening = closing = None
        movement = Decimal(0)
        for ordinal, pin in enumerate(plan.sources, 1):
            coordinate = Coordinate.from_mapping(dict(pin.members))
            generation = db.execute('''SELECT
                p.state_token AS current_result_state_token,
                p.content_digest AS current_result_content_digest,
                p.source_operation_id AS current_generation_id,
                p.committed_revision AS current_published_revision,
                p.source_function AS function_name,
                j.compiler_version,j.status AS job_status,
                j.normalized_program,j.result AS job_result,
                j.expected_metadata_revision,j.expected_data_revision,
                j.expected_policy_revision,p.source_metadata_revision,
                p.source_policy_revision,s.metadata_revision AS current_metadata_revision,
                s.data_revision AS current_data_revision,
                s.policy_revision AS current_policy_revision,
                s.commit_revision AS observed_commit_revision
                FROM epm.calculation_result_state p
                JOIN epm.job j ON j.workspace_id=p.workspace_id
                  AND j.application_id=p.application_id
                  AND j.job_id=p.source_operation_id
                JOIN epm.application_state s ON s.workspace_id=p.workspace_id
                  AND s.application_id=p.application_id
                WHERE p.workspace_id=%s AND p.application_id=%s
                  AND p.result_key=%s''', (scope.workspace_id,
                 scope.application_id, pin.result_key)).fetchone()
            if generation is None:
                raise ValueError('CTA_V2_SOURCE_UNAVAILABLE')
            typed_expression = (generation['function_name'] ==
                'facts.expression.calculate' and generation['compiler_version'] in (
                    'typed-numeric-expression-v21',
                    'typed-numeric-expression-v22',
                    'typed-numeric-expression-v23',
                    'typed-numeric-expression-v29'))
            calculation_translation = (generation['function_name'] ==
                'currency.calculation.translation.publish')
            if not (typed_expression or calculation_translation):
                raise ValueError('CTA_V2_SOURCE_STALE_OR_UNSUPPORTED')
            if typed_expression:
                rows = db.execute('''SELECT c.members,ur.amount,
                    ur.output_unit_currency_dimension_id,
                    ur.output_unit_currency_member_id,ur.rate_strategy,
                    ur.rate_numerator::text AS rate_numerator,
                    ur.rate_denominator::text AS rate_denominator,
                    ur.rate_sources FROM epm.calculation_unit_result_current ur
                    JOIN epm.coordinate c USING(
                      workspace_id,application_id,coordinate_id)
                    WHERE ur.workspace_id=%s AND ur.application_id=%s
                    AND ur.result_key=%s AND c.series_key=%s
                    AND ur.output_unit_currency_member_id=%s
                    ORDER BY ur.output_unit_currency_dimension_id LIMIT 2''',
                    (scope.workspace_id,scope.application_id,
                     pin.result_key,coordinate.series_key,
                     pin.output_currency_member_id)).fetchall()
            else:
                rows = db.execute('''SELECT c.members,r.amount,
                    NULL::text AS output_unit_currency_dimension_id,
                    NULL::text AS output_unit_currency_member_id,
                    NULL::text AS rate_strategy,NULL::text AS rate_numerator,
                    NULL::text AS rate_denominator,NULL::jsonb AS rate_sources
                    FROM epm.calculation_result_current r JOIN epm.coordinate c
                    USING(workspace_id,application_id,coordinate_id)
                    WHERE r.workspace_id=%s AND r.application_id=%s
                    AND r.result_key=%s AND c.series_key=%s
                    ORDER BY c.coordinate_id LIMIT 2''',(scope.workspace_id,
                    scope.application_id,pin.result_key,
                    coordinate.series_key)).fetchall()
            if len(rows) != 1:
                raise ValueError('CTA_V2_SOURCE_UNAVAILABLE')
            row = rows[0]
            currency_dimension = roles['Currency']
            output_unit = (row['output_unit_currency_member_id'] if
                typed_expression else (generation['job_result'] or {}).get(
                    'toCurrencyMemberId'))
            direct_status = input_revision_status(generation)
            raw_status=(typed_expression_raw_driver_status(
                db,scope,pin.result_key,generation['normalized_program'])
                if generation.get('compiler_version')==
                    'typed-numeric-expression-v29' else None)
            if raw_status is not None and not raw_status['matchesAtRead']:
                raise ValueError('CTA_V2_SOURCE_RAW_DRIVER_STALE')
            if (generation['current_result_state_token'] != pin.result_state_token
                    or generation['job_status'] != 'published'
                    or row['members'] != dict(pin.members)
                    or row['amount'] is None
                    or output_unit != pin.output_currency_member_id
                    or (typed_expression and
                        row['output_unit_currency_dimension_id'] !=
                            currency_dimension)
                    or generation['expected_metadata_revision'] !=
                        generation['source_metadata_revision']
                    or generation['expected_policy_revision'] !=
                        generation['source_policy_revision']
                    or not direct_status['matchesAtRead']):
                raise ValueError('CTA_V2_SOURCE_STALE_OR_UNSUPPORTED')
            if typed_expression:
                status = published_input_status(
                    db, scope, generation['normalized_program'])
                lineage = {'rateStrategy': row['rate_strategy'],
                  'rateNumerator': row['rate_numerator'],
                  'rateDenominator': row['rate_denominator'],
                  'rateSources': row['rate_sources']}
            else:
                status = published_calculation_translation_status(
                    db, scope, generation['normalized_program'])
                lineage = {'translation': generation['job_result']}
            if status is not None and not status['matchesAtRead']:
                raise ValueError('CTA_V2_SOURCE_DEPENDENCY_STALE')
            amount = row['amount']
            item = {**pin.normalized(), 'ordinal': ordinal,
              'amount': format(amount, '.8f'),
              'function': generation['function_name'],
              'compilerVersion': generation['compiler_version'],
              'resultContentDigest':generation['current_result_content_digest'],
              'sourceOperationId':generation['current_generation_id'],
              'sourceCommittedRevision':generation['current_published_revision'],
              'outputCurrencyDimensionId':currency_dimension,
              'lineage': lineage, 'inputRevisionStatus': direct_status,
              'dependencyStatus': status}
            if raw_status is not None:item['rawDriverStatus']=raw_status
            resolved.append(item)
            if pin.role == 'Opening':
                opening = amount
            elif pin.role == 'Closing':
                closing = amount
            else:
                movement += amount * pin.sign
        if opening is None or closing is None or opening + movement != closing:
            raise ValueError('CTA_V2_BRIDGE_NOT_RECONCILED')
        return resolved, movement

    def preview_v2(self, scope: ApplicationScope, arguments: dict) -> dict:
        plan = CtaBridgeV2.parse(arguments)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=PREVIEW)
                self._v2_state(db, scope, plan)
                roles=self._validate_v2_layout(db,scope,plan)
                _authorize_plan_coordinates(
                    db,self.identity,scope,plan,sources=True)
                sources, movement = self._resolve_v2_sources(
                    db, scope, plan,roles)
        opening = next(item['amount'] for item in sources
                       if item['role'] == 'Opening')
        closing = next(item['amount'] for item in sources
                       if item['role'] == 'Closing')
        return {'status': 'Previewed', 'bridgeVersion': 2,
          'bridgeDigest': plan.digest, 'openingCta': opening,
          'movementCta': format(movement, '.8f'), 'closingCta': closing,
          'outputCurrencyMemberId':
              plan.sources[0].output_currency_member_id,
          'outputCurrencyDimensionId':roles['Currency'],
          'layoutStateToken':plan.layout_state_token,'layoutDigest':plan.layout_digest,
          'sources': _public_current_evidence(sources),
          'accountingPolicyStatus': 'Unreviewed',
          'mechanicalOnly': True, 'effects': 'None'}

    def post_v2(self, scope: ApplicationScope, arguments: dict, *,
                idempotency_key: str, expected_bridge_digest: str) -> dict:
        plan = CtaBridgeV2.parse(arguments)
        if not valid_idempotency_key(idempotency_key):
            raise ValueError('CTA_V2_IDEMPOTENCY_KEY_INVALID')
        if expected_bridge_digest != plan.digest:
            raise ValueError('CTA_PREVIEW_STALE_OR_MISMATCHED')
        bridge_id = sha256((scope.workspace_id + '\0' + scope.application_id +
            '\0' + self.identity.issuer + '\0' + self.identity.subject_id +
            '\0' + idempotency_key).encode()).hexdigest()[:32]
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                self._lock_application_state(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=FUNCTION)
                replay=self._v2_replay(db,scope,bridge_id,idempotency_key,plan.digest,
                                       self.identity)
                if replay is not None:return replay
                state = self._v2_state(db, scope, plan)
                roles=self._validate_v2_layout(db,scope,plan)
                _authorize_plan_coordinates(
                    db,self.identity,scope,plan,sources=True,
                    targets=AccessKind.WRITE)
                sources, movement = self._resolve_v2_sources(
                    db, scope, plan,roles)
                if movement == 0:
                    raise ValueError('CTA_V2_NO_MOVEMENT_POST_UNNECESSARY')
                opening = next(item['amount'] for item in sources
                               if item['role'] == 'Opening')
                closing = next(item['amount'] for item in sources
                               if item['role'] == 'Closing')
                reference = 'cta-v2:' + plan.digest[:40]
                journal = {'languageVersion': 2, 'function': POST_FUNCTION,
                  'arguments': {'reason': plan.reason, 'lines': [
                    {'members': dict(plan.cta_members), 'amount': {
                      'type': 'AmountLiteral',
                      'decimal': format(movement, '.8f')},
                     'sourceRef': reference + ':cta'},
                    {'members': dict(plan.offset_members), 'amount': {
                      'type': 'AmountLiteral',
                      'decimal': format(-movement, '.8f')},
                     'sourceRef': reference + ':offset'}],
                    'expectedMetadataRevision':
                        plan.expected_metadata_revision,
                    'expectedDataRevision': plan.expected_data_revision,
                    'expectedPolicyRevision': plan.expected_policy_revision}}
                result = {'bridgeId': bridge_id, 'bridgeVersion': 2,
                  'status': 'Posted', 'bridgeDigest': plan.digest,
                  'openingCta': opening,
                  'movementCta': format(movement, '.8f'),
                  'closingCta': closing,
                  'outputCurrencyMemberId':
                      plan.sources[0].output_currency_member_id,
                  'outputCurrencyDimensionId':roles['Currency'],
                  'layoutStateToken':plan.layout_state_token,
                  'layoutDigest':plan.layout_digest,
                  'accountingPolicyStatus': 'Unreviewed',
                  'mechanicalOnly': True}
                journal_result = PostgresManualJournal(
                    self.dsn, identity=self.identity).post_in_transaction(
                        db, scope, journal, idempotency_key=idempotency_key,
                        state=state, result_extension={'ctaBridge': result})
                result['journal'] = journal_result
                db.execute('''INSERT INTO epm.cta_bridge
                    (workspace_id,application_id,bridge_id,journal_id,
                     bridge_digest,compiler_version,status,
                     currency_dimension_id,currency_member_id,
                     effective_period,opening_amount,movement_amount,
                     closing_amount,layout_state_token,layout_digest,
                     metadata_revision,data_revision,policy_revision,
                     committed_revision,issuer,subject_id,reason,result)
                    VALUES(%s,%s,%s,%s,%s,'cta-bridge-v2','Posted',%s,%s,%s,
                      %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(
                    scope.workspace_id, scope.application_id, bridge_id,
                    idempotency_key, plan.digest,
                    roles['Currency'],plan.sources[0].output_currency_member_id,
                    Jsonb(dict(plan.effective_period)), opening, movement,
                    closing,plan.layout_state_token,plan.layout_digest,
                    plan.expected_metadata_revision,
                    plan.expected_data_revision,
                    plan.expected_policy_revision,
                    journal_result['committedRevision'], self.identity.issuer,
                    self.identity.subject_id, plan.reason, Jsonb(result)))
                db.cursor().executemany('''INSERT INTO epm.cta_bridge_source
                    (workspace_id,application_id,bridge_id,source_ordinal,
                     role,movement_id,result_key,result_state_token,
                     result_content_digest,source_operation_id,
                     source_committed_revision,members,amount,sign,
                     currency_dimension_id,currency_member_id,
                     source_function,compiler_version,
                     lineage,dependency_status)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                      %s,%s,%s,%s,%s)''', [(scope.workspace_id, scope.application_id,
                    bridge_id, item['ordinal'], item['role'],
                    item['movementId'], item['resultKey'],
                    item['resultStateToken'],item['resultContentDigest'],
                    item['sourceOperationId'],item['sourceCommittedRevision'],
                    Jsonb(item['members']), item['amount'], item['sign'],
                    item['outputCurrencyDimensionId'],
                    item['outputCurrencyMemberId'], item['function'],
                    item['compilerVersion'], Jsonb(item['lineage']),
                    Jsonb(item['dependencyStatus'])) for item in sources])
                return result

    def post_v3(self,scope:ApplicationScope,arguments:dict,*,
                idempotency_key:str,expected_bridge_digest:str)->dict:
        plan=CtaBridgeV3.parse(arguments)
        if not valid_idempotency_key(idempotency_key):
            raise ValueError('CTA_V3_IDEMPOTENCY_KEY_INVALID')
        if expected_bridge_digest!=plan.digest:
            raise ValueError('CTA_PREVIEW_STALE_OR_MISMATCHED')
        bridge_id=sha256((scope.workspace_id+'\0'+scope.application_id+
            '\0'+self.identity.issuer+'\0'+self.identity.subject_id+
            '\0'+idempotency_key).encode()).hexdigest()[:32]
        # Resolve and reconcile the bounded source set without holding the
        # application mutation fence.  Final publication verifies the exact
        # sealed source certificate in one bulk query.
        with connect_postgres(self.dsn,row_factory=dict_row) as prepared:
            with prepared.transaction():
                PostgresNumericFactStore._set_scope(prepared,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    prepared,self.identity,scope,'admin',function=FUNCTION)
                replay=self._v2_replay(prepared,scope,bridge_id,
                    idempotency_key,plan.digest,self.identity)
                if replay is not None:return replay
                self._v2_state(prepared,scope,plan)
                roles=self._validate_v3_layout(prepared,scope,plan)
                _authorize_plan_coordinates(
                    prepared,self.identity,scope,plan,sources=True,
                    targets=AccessKind.WRITE)
                sources,movement=self._resolve_v3_sources(
                    prepared,scope,plan,roles)
                if movement==0:
                    raise ValueError('CTA_V3_NO_MOVEMENT_POST_UNNECESSARY')
                points=(Coordinate.from_mapping(dict(plan.cta_members)),
                        Coordinate.from_mapping(dict(plan.offset_members)))
                enforce_active_planning_policy(prepared,scope,
                    writes=tuple((point,'Add') for point in points),
                    workflow_role=access.role,ordered_actions=True)
        candidate=_seal_v3_candidate(plan,roles,sources,movement)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                self._lock_application_state(db,scope)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=FUNCTION)
                replay=self._v2_replay(db,scope,bridge_id,idempotency_key,
                                       plan.digest,self.identity)
                if replay is not None:return replay
                state=self._v2_state(db,scope,plan)
                roles=self._validate_v3_layout(db,scope,plan)
                _authorize_plan_coordinates(
                    db,self.identity,scope,plan,sources=True,
                    targets=AccessKind.WRITE)
                if (roles!=candidate['roles']
                        or _canonical_digest({key:candidate[key] for key in
                            ('plan','roles','sources','movement')})!=
                                candidate['digest']):
                    raise ValueError('CTA_V3_CANDIDATE_CHANGED')
                self._verify_v3_candidate(db,scope,plan,candidate)
                sources=candidate['sources']
                movement=Decimal(candidate['movement'])
                opening=next(item['amount'] for item in sources
                             if item['role']=='Opening')
                closing=next(item['amount'] for item in sources
                             if item['role']=='Closing')
                reference='cta-v3:'+plan.digest[:40]
                coordinate_ids=tuple(PostgresNumericFactStore._coordinate_id(
                    db,scope,point) for point in points)
                policy=enforce_active_planning_policy(db,scope,
                    writes=tuple((point,'Add') for point in points),
                    workflow_role=access.role,ordered_actions=True)
                revision=state['commit_revision']+1
                result={'bridgeId':bridge_id,'bridgeVersion':3,
                  'status':'Posted','bridgeDigest':plan.digest,
                  'openingCta':opening,'movementCta':format(movement,'.8f'),
                  'closingCta':closing,
                  'outputCurrencyDimensionId':plan.currency_dimension_id,
                  'outputCurrencyMemberId':plan.currency_member_id,
                  'layoutStateToken':plan.layout_state_token,
                  'layoutDigest':plan.layout_digest,
                  'accountingPolicyStatus':'Unreviewed','mechanicalOnly':True,
                  'typedEffects':{'effectCount':2,
                    'currencyDimensionId':plan.currency_dimension_id,
                    'currencyMemberId':plan.currency_member_id},
                  'planningPolicy':policy,
                  'sourceDataRevision':plan.expected_data_revision,
                  'currentRawDataRevision':state['data_revision'],
                  'dataRevision':state['data_revision'],
                  'committedRevision':revision}
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',(
                    revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
                    scope.workspace_id,scope.application_id,idempotency_key,
                    plan.digest,self.identity.subject_id,revision,Jsonb(result)))
                db.execute('''INSERT INTO epm.cta_bridge
                    (workspace_id,application_id,bridge_id,journal_id,
                     bridge_digest,compiler_version,status,
                     currency_dimension_id,currency_member_id,
                     effective_period,opening_amount,movement_amount,
                     closing_amount,layout_state_token,layout_digest,
                     metadata_revision,data_revision,policy_revision,
                     committed_revision,issuer,subject_id,reason,result)
                    VALUES(%s,%s,%s,%s,%s,'cta-bridge-v3-typed-unit',
                      'Posted',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                      %s,%s,%s)''',(scope.workspace_id,scope.application_id,
                    bridge_id,None,plan.digest,
                    plan.currency_dimension_id,plan.currency_member_id,
                    Jsonb(dict(plan.effective_period)),opening,movement,closing,
                    plan.layout_state_token,plan.layout_digest,
                    plan.expected_metadata_revision,plan.expected_data_revision,
                    plan.expected_policy_revision,
                    revision,self.identity.issuer,
                    self.identity.subject_id,plan.reason,Jsonb(result)))
                db.cursor().executemany('''INSERT INTO epm.cta_bridge_unit_effect
                    (workspace_id,application_id,bridge_id,effect_ordinal,
                     effect_role,coordinate_id,currency_dimension_id,
                     currency_member_id,amount,source_ref)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',[
                    (scope.workspace_id,scope.application_id,bridge_id,1,'CTA',
                     coordinate_ids[0],plan.currency_dimension_id,
                     plan.currency_member_id,movement,reference+':cta'),
                    (scope.workspace_id,scope.application_id,bridge_id,2,'Offset',
                     coordinate_ids[1],plan.currency_dimension_id,
                     plan.currency_member_id,-movement,reference+':offset')])
                db.cursor().executemany('''INSERT INTO epm.cta_bridge_source
                    (workspace_id,application_id,bridge_id,source_ordinal,
                     role,movement_id,result_key,result_state_token,
                     result_content_digest,source_operation_id,
                     source_committed_revision,members,amount,sign,
                     currency_dimension_id,currency_member_id,
                     source_function,compiler_version,lineage,dependency_status)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                      %s,%s,%s,%s,%s)''',[(scope.workspace_id,scope.application_id,
                    bridge_id,item['ordinal'],item['role'],item['movementId'],
                    item['resultKey'],item['resultStateToken'],
                    item['resultContentDigest'],item['sourceOperationId'],
                    item['sourceCommittedRevision'],Jsonb(item['members']),
                    item['amount'],item['sign'],
                    item['outputCurrencyDimensionId'],
                    item['outputCurrencyMemberId'],item['function'],
                    item['compilerVersion'],Jsonb(item['lineage']),
                    Jsonb(item['dependencyStatus'])) for item in sources])
                return result

    def read(self, scope: ApplicationScope, bridge_id: str) -> dict:
        if not isinstance(bridge_id, str) or not re.fullmatch(
                r'[0-9a-f]{32}', bridge_id):
            raise ValueError('CTA_V2_BRIDGE_ID_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=READ)
                bridge = db.execute('''SELECT result,data_revision,compiler_version,
                    journal_id
                    FROM epm.cta_bridge
                    WHERE workspace_id=%s AND application_id=%s
                    AND bridge_id=%s''', (scope.workspace_id,
                    scope.application_id, bridge_id)).fetchone()
                if bridge is None:
                    raise ValueError('CTA_V2_BRIDGE_UNAVAILABLE')
                sources = db.execute('''SELECT source_ordinal,role,movement_id,
                    result_key,result_state_token,result_content_digest,members,
                    amount,sign,currency_dimension_id,currency_member_id,source_function,
                    compiler_version,lineage,dependency_status
                    FROM epm.cta_bridge_source WHERE workspace_id=%s
                    AND application_id=%s AND bridge_id=%s
                    ORDER BY source_ordinal''', (scope.workspace_id,
                    scope.application_id, bridge_id)).fetchall()
                authorize_coordinates(db,self.identity,scope,tuple(
                    Coordinate.from_mapping(row['members']) for row in sources),
                    kind=AccessKind.READ)
                current = db.execute('''SELECT s.result_key,s.result_state_token,
                    s.source_operation_id,s.source_committed_revision,
                    p.state_token AS observed_state_token,
                    p.source_function AS function_name,
                    j.normalized_program,j.expected_metadata_revision,
                    j.expected_data_revision,j.expected_policy_revision,
                    st.metadata_revision AS current_metadata_revision,
                    st.data_revision AS current_data_revision,
                    st.policy_revision AS current_policy_revision,
                    st.commit_revision AS observed_commit_revision,
                    j.status AS job_status
                    FROM epm.cta_bridge_source s LEFT JOIN
                    epm.calculation_result_state p ON
                      p.workspace_id=s.workspace_id
                      AND p.application_id=s.application_id
                      AND p.result_key=s.result_key
                    LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
                      AND j.application_id=p.application_id
                      AND j.job_id=p.source_operation_id
                    JOIN epm.application_state st ON
                      st.workspace_id=s.workspace_id
                      AND st.application_id=s.application_id
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    AND s.bridge_id=%s ORDER BY s.source_ordinal''',(
                    scope.workspace_id, scope.application_id,
                    bridge_id)).fetchall()
                effects=(db.execute('''SELECT e.effect_ordinal,e.effect_role,
                    c.members,e.currency_dimension_id,e.currency_member_id,
                    e.amount,e.source_ref FROM epm.cta_bridge_unit_effect e
                    JOIN epm.coordinate c USING(workspace_id,application_id,
                      coordinate_id) WHERE e.workspace_id=%s
                    AND e.application_id=%s AND e.bridge_id=%s
                    ORDER BY e.effect_ordinal''',(scope.workspace_id,
                    scope.application_id,bridge_id)).fetchall()
                    if bridge['compiler_version']=='cta-bridge-v3-typed-unit'
                    else [])
                effect_points=[Coordinate.from_mapping(row['members'])
                               for row in effects]
                if bridge['journal_id'] is not None:
                    journal_points=db.execute('''SELECT c.members FROM
                        epm.manual_journal_line l JOIN epm.coordinate c USING
                          (workspace_id,application_id,coordinate_id)
                        WHERE l.workspace_id=%s AND l.application_id=%s
                        AND l.journal_id=%s ORDER BY l.line_ordinal''',(
                        scope.workspace_id,scope.application_id,
                        bridge['journal_id'])).fetchall()
                    effect_points.extend(Coordinate.from_mapping(row['members'])
                                         for row in journal_points)
                authorize_coordinates(db,self.identity,scope,
                    tuple(effect_points),kind=AccessKind.READ)
                statuses=[]
                for row in current:
                    expected_current_data=expected_current_data_revision(
                      bridge['compiler_version'],bridge['data_revision'])
                    direct=(row['result_state_token']==row['observed_state_token']
                      and row['job_status']=='published'
                      and row['expected_metadata_revision']==
                          row['current_metadata_revision']
                      and row['expected_policy_revision']==
                          row['current_policy_revision']
                      and row['expected_data_revision']==bridge['data_revision']
                      and row['current_data_revision']==expected_current_data)
                    source_certificate=sources[len(statuses)][
                        'dependency_status']
                    nested={'matchesAtRead':_dependency_pointers_current(
                        db,scope,source_certificate),
                        'certificate':source_certificate}
                    statuses.append({'matchesAtRead':direct and (
                        nested is None or nested['matchesAtRead']),
                        'dependencyStatus':nested})
                deep_current=cta_bridge_sources_current(db,scope,bridge_id)
        stale = (not deep_current or len(statuses)!=len(sources) or any(
            not item['matchesAtRead'] for item in statuses)
            )
        observed_commit_revision=(current[0]['observed_commit_revision']
          if current else None)
        result={**_public_current_evidence(bridge['result']),
          'sources': _public_current_evidence([dict(row) for row in sources]),
          'stale': stale,
          'staleReasons': ['SOURCE_OR_DEPENDENCY_STALE'] if stale else [],
          'observedCommitRevision': observed_commit_revision,
          'currentSourceStatus': _public_current_evidence(statuses)}
        if effects:result['typedEffects']=[dict(row) for row in effects]
        return result
    def preview(self,scope:ApplicationScope,arguments):
        canonical,movement,digest=compile_cta_bridge(arguments)
        self._validate_current(scope,canonical)
        return {'status':'Previewed','bridgeDigest':digest,
            'openingCta':canonical['openingCta'],'movementCta':format(movement,'f'),
            'closingCta':canonical['closingCta'],'balancedLineCount':0 if movement==0 else 2,
            'sourceResults':canonical['sourceResults'],
            'policyStateToken':canonical['policyStateToken'],
            'policyDigest':canonical['policyDigest'],
            'effectivePeriod':canonical['effectivePeriod'],'policyReviewStatus':'Unreviewed'}
    def post(self,scope:ApplicationScope,arguments,*,idempotency_key,
             expected_bridge_digest=None):
        canonical,movement,digest=compile_cta_bridge(arguments)
        if expected_bridge_digest is not None and expected_bridge_digest!=digest:
            raise ValueError('CTA_PREVIEW_STALE_OR_MISMATCHED')
        if movement==0:
            self._validate_current(scope,canonical)
            return {'status':'NoMovement','bridgeDigest':digest,'journal':None,
                'openingCta':canonical['openingCta'],'movementCta':format(movement,'f'),
                'closingCta':canonical['closingCta']}
        reference='cta:'+digest[:48]
        program={'languageVersion':2,'function':POST_FUNCTION,'arguments':{
            'reason':arguments['reason'],'lines':[
                {'members':arguments['ctaMembers'],'amount':{'type':'AmountLiteral','decimal':format(movement,'f')},'sourceRef':reference+':cta'},
                {'members':arguments['offsetMembers'],'amount':{'type':'AmountLiteral','decimal':format(-movement,'f')},'sourceRef':reference+':offset'}],
            'expectedMetadataRevision':arguments['expectedMetadataRevision'],
            'expectedPolicyRevision':arguments['expectedPolicyRevision'],
            'expectedDataRevision':arguments['expectedDataRevision']}}
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',function=FUNCTION)
                prior=db.execute('''SELECT 1 FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(
                    scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
        if prior is None:
            self._validate_current(scope,canonical)
        posted=PostgresManualJournal(self.dsn,identity=self.identity).execute(
            scope,program,idempotency_key=idempotency_key)
        return {'status':'Posted','bridgeDigest':digest,'journal':posted,
            'openingCta':canonical['openingCta'],'movementCta':format(movement,'f'),
            'closingCta':canonical['closingCta'],'sourceResults':canonical['sourceResults']}
