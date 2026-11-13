"""Sealed public execution of one published reusable Spread policy."""
from __future__ import annotations
from hashlib import sha256
import json
from psycopg.rows import dict_row
from .persistence_contract import ApplicationScope,Coordinate
from .planning_operation_policy_lowering import lower_bound_policy_to_legacy_v2
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import (PostgresJobQueue,_canonical_digest,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_policy_resolution import resolve_published_planning_policy
from .postgres_planning_spread import (FUNCTION,CALENDAR_FUNCTION,
    POLICY_COMPILER,POLICY_PLAN_DIGEST,POLICY_CALENDAR_COMPILER,
    POLICY_CALENDAR_PLAN_DIGEST,compile_spread_program,
    compile_calendar_spread_program,decode_policy_spread_program,
    encode_policy_spread_program,validate_spread_inputs,_calendar_roles)
from .postgres_processing_limits import configure_statement_timeout

PREVIEW='planning.operation.policy.spread.preview'
RUN='planning.operation.policy.spread.run'
FUNCTIONS=frozenset((PREVIEW,RUN))

def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def _fiscal_selection(definition,source,roles,rows):
    """Validate and seal one persisted fiscal-calendar member selection."""
    declared=definition['targetMembers']['memberIds']
    if (definition['targetDimension']!=roles['Period']
            or set(dict(source.members).values())!=set(
                definition['sourceMembers']['memberIds'])
            or not 1<=len(declared)<=500):
        raise ValueError('PLANNING_SPREAD_POLICY_CALENDAR_INVALID')
    year=dict(source.members).get(roles['Year'])
    ordinals=[row['ordinal'] for row in rows]
    if (len(rows)!=len(declared) or not rows
            or any(row['year_member_id']!=year
                   or row['period_dimension_id']!=roles['Period']
                   for row in rows)
            or {row['period_member_id'] for row in rows}!=set(declared)
            or ordinals!=list(range(ordinals[0],ordinals[-1]+1))):
        raise ValueError('PLANNING_SPREAD_POLICY_CALENDAR_INVALID')
    return (year,ordinals[0],ordinals[-1],
            tuple(row['period_member_id'] for row in rows))

def catalog():
    args={'policyId':'currently published reusable Spread policy ID',
          'effectiveOn':'ISO date within immutable policy range',
          'bindings':'all and only typed policy parameters',
          'source':'complete source coordinate','resultKey':'stable current result key'}
    return {PREVIEW:{'mode':'calculation_preview','permission':'write',
        'requiredCapabilities':[],'arguments':args,
        'result':'sealed policy, source, fiscal/selection target order and current-state pins',
        'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
        RUN:{'mode':'durable_calculation','permission':'write',
        'requiredCapabilities':[],'arguments':{**args,
            'previewToken':'unexpired server-signed exact preview'},
        'result':'durable exact spread job','previewRequired':True,
        'idempotencyRequired':True,'workClass':'short'}}

class PostgresPublishedPlanningSpread:
    def __init__(self,dsn:str,*,identity:VerifiedIdentity,preview_secret:bytes):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity
        from .postgres_language_v2 import PostgresLanguageV2
        self.language=PostgresLanguageV2(
            dsn,identity=identity,preview_secret=preview_secret)

    @staticmethod
    def _arguments(program,function,*,token):
        required={'policyId','effectiveOn','bindings','source','resultKey'}
        if token:required.add('previewToken')
        if (not isinstance(program,dict)
                or set(program)!={'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion']!=2
                or program['function']!=function
                or not isinstance(program['arguments'],dict)
                or set(program['arguments'])!=required):
            raise ValueError('PLANNING_SPREAD_POLICY_PROGRAM_INVALID')
        return dict(program['arguments'])

    def _resolve(self,scope,args):
        bound,pointer=resolve_published_planning_policy(
            self.dsn,self.identity,scope,{k:args[k] for k in
                ('policyId','effectiveOn','bindings')},expected_kind='Spread',
            function=RUN)
        policy={k:bound[k] for k in ('policyId','policyDigest',
            'metadataRevision','policyRevision')};policy.update(pointer)
        return bound,policy

    def _compile_current(self,scope,args):
        bound,policy=self._resolve(scope,args)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=RUN,arguments=args)
                state=db.execute('''SELECT a.status,s.processing_mode,
                    s.metadata_revision,s.data_revision,s.policy_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (state is None or state['status']!='Active'
                        or state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision']!=policy['metadataRevision']
                        or state['policy_revision']!=policy['policyRevision']):
                    raise ValueError('PLANNING_SPREAD_POLICY_STALE')
                pointer=db.execute('''SELECT state_token FROM
                    epm.calculation_result_state WHERE workspace_id=%s
                    AND application_id=%s AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     args['resultKey'])).fetchone()
                target_token=pointer['state_token'] if pointer else None
                definition=bound['definition']
                if definition['calendarPolicy']=='selection_order':
                    lowered=lower_bound_policy_to_legacy_v2(bound,{
                        'source':args['source'],'resultKey':args['resultKey'],
                        'expectedTargetStateToken':target_token})
                    plan=compile_spread_program(lowered.program,
                        expected_target_state_token=target_token)
                elif bound.get('policyFormat')==(
                        'openepm-planning-operation-policy-v2'):
                    plan=self._compile_fiscal(db,scope,definition,args,
                                              target_token)
                else:
                    raise ValueError('PLANNING_SPREAD_POLICY_CALENDAR_V2_REQUIRED')
                source=validate_spread_inputs(db,scope,plan)
                revisions={k:state[k] for k in (
                    'metadata_revision','data_revision','policy_revision')}
        return plan,policy,source,revisions

    @staticmethod
    def _compile_fiscal(db,scope,definition,args,target_token):
        try:source=Coordinate.from_mapping(args['source'])
        except (TypeError,ValueError) as error:
            raise ValueError('PLANNING_SPREAD_POLICY_SOURCE_INVALID') from error
        roles=_calendar_roles(db,scope)
        declared=definition['targetMembers']['memberIds']
        year=dict(source.members).get(roles['Year'])
        if year is None:
            raise ValueError('PLANNING_SPREAD_POLICY_CALENDAR_INVALID')
        rows=db.execute('''SELECT year_member_id,period_dimension_id,
                period_member_id,ordinal,change_id,last_revision
            FROM epm.calendar_period_current WHERE workspace_id=%s
            AND application_id=%s AND year_member_id=%s
            AND period_member_id=ANY(%s::text[])
            ORDER BY ordinal''',(scope.workspace_id,
            scope.application_id,year,list(declared))).fetchall()
        selected_year,first,last,ordered=_fiscal_selection(
            definition,source,roles,rows)
        request={'languageVersion':2,'function':CALENDAR_FUNCTION,
            'arguments':{'source':args['source'],'yearId':selected_year,
                'firstOrdinal':first,'lastOrdinal':last,
                'resultKey':args['resultKey']}}
        plan=compile_calendar_spread_program(db,scope,request,
            expected_target_state_token=target_token)
        if plan.target_members!=ordered:
            raise ValueError('PLANNING_SPREAD_POLICY_CALENDAR_INVALID')
        return plan

    def preview(self,scope,program):
        args=self._arguments(program,PREVIEW,token=False)
        plan,policy,source,revisions=self._compile_current(scope,args)
        normalized=encode_policy_spread_program(plan,policy)
        token,digest=self.language._sign_preview(scope,RUN,normalized,revisions,
            extra={'requestDigest':_digest(args),
                   'expectedTargetStateToken':plan.expected_target_state_token})
        compiler,plan_digest=((POLICY_CALENDAR_COMPILER,
            POLICY_CALENDAR_PLAN_DIGEST) if plan.calendar_selection else
            (POLICY_COMPILER,POLICY_PLAN_DIGEST))
        return {'languageVersion':2,'function':RUN,'programDigest':digest,
            'revisionVector':revisions,'sourceAmount':format(source['amount'],'f'),
            'targetCount':len(plan.target_members),'conservesSourceTotal':True,
            'remainderOrder':('fiscal_period_ordinal'
                if plan.calendar_selection else 'stable_member_id'),
            **({'calendarSelection':{'yearId':plan.calendar_selection[0],
                'firstOrdinal':plan.calendar_selection[1],
                'lastOrdinal':plan.calendar_selection[2],
                'orderedMembers':list(plan.target_members),
                'roundingPolicy':'largestRemainderFiscalOrdinal'}}
               if plan.calendar_selection else {}),
            'reusablePolicy':policy,'compilerVersion':compiler,
            'planDigest':plan_digest,
            'engine':'postgres_exact_sql','previewToken':token}

    def _replay(self,scope,key,args,payload):
        if payload.get('requestDigest')!=_digest(args):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=RUN,arguments=args)
                prior=db.execute('''SELECT job_id,status,function_name,
                    normalized_program,compiler_version,program_digest,
                    request_digest,plan_digest,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision,
                    resource_class,verified_groups,authorization_scope_digest
                    FROM epm.job WHERE workspace_id=%s
                    AND application_id=%s AND issuer=%s AND subject_id=%s
                    AND idempotency_key=%s''',(scope.workspace_id,
                    scope.application_id,self.identity.issuer,
                    self.identity.subject_id,key)).fetchone()
                if prior is None:return None
                deps=db.execute('''SELECT depends_on_job_id FROM
                    epm.job_dependency WHERE workspace_id=%s
                    AND application_id=%s AND job_id=%s
                    ORDER BY depends_on_job_id''',(scope.workspace_id,
                    scope.application_id,prior['job_id'])).fetchall()
                auth_scope=_verify_job_replay_authorization(db,scope,
                    self.identity,prior,access=access,
                    function_name=prior['function_name'])
        try:plan,policy=decode_policy_spread_program(prior['normalized_program'])
        except ValueError as error:
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT') from error
        revisions=payload.get('revisions')
        compiler,plan_digest=((POLICY_CALENDAR_COMPILER,
            POLICY_CALENDAR_PLAN_DIGEST) if plan.calendar_selection else
            (POLICY_COMPILER,POLICY_PLAN_DIGEST))
        if (prior['function_name']!=plan.function
                or prior['compiler_version']!=compiler
                or prior['plan_digest']!=plan_digest
                or prior['program_digest']!=_canonical_digest(prior['normalized_program'])
                or prior['program_digest']!=payload.get('programDigest')
                or policy.get('policyId')!=args['policyId']
                or not isinstance(revisions,dict)
                or [prior['expected_metadata_revision'],prior['expected_data_revision'],
                    prior['expected_policy_revision']]!=[revisions.get(
                    'metadata_revision'),revisions.get('data_revision'),
                    revisions.get('policy_revision')]):
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        dep_ids=tuple(x['depends_on_job_id'] for x in deps)
        descriptor=_job_request_descriptor(scope,self.identity,
            function_name=plan.function,program_digest=prior['program_digest'],
            compiler_version=compiler,plan_digest=plan_digest,
            revisions=(prior['expected_metadata_revision'],
                prior['expected_data_revision'],prior['expected_policy_revision']),
            resource_class=prior['resource_class'],dependencies=dep_ids,
            authorization_scope_digest=auth_scope,
            verified_groups=access.groups)
        if dep_ids or _canonical_digest(descriptor)!=prior['request_digest']:
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        return {'jobId':prior['job_id'],'status':prior['status'],'duplicate':True}

    def run(self,scope,program,*,idempotency_key):
        args=self._arguments(program,RUN,token=True);token=args.pop('previewToken')
        payload=self.language._unpack_preview(scope,RUN,token)
        replay=self._replay(scope,idempotency_key,args,payload)
        if replay is not None:return replay
        required={'scope','identity','function','programDigest','revisions',
            'expiresAt','requestDigest','expectedTargetStateToken'}
        if set(payload)!=required:
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan,policy,_,revisions=self._compile_current(scope,args)
        normalized=encode_policy_spread_program(plan,policy)
        if (payload['programDigest']!=_canonical_digest(normalized)
                or payload['requestDigest']!=_digest(args)
                or payload['revisions']!=revisions
                or payload['expectedTargetStateToken']!=
                    plan.expected_target_state_token):
            raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        compiler,plan_digest=((POLICY_CALENDAR_COMPILER,
            POLICY_CALENDAR_PLAN_DIGEST) if plan.calendar_selection else
            (POLICY_COMPILER,POLICY_PLAN_DIGEST))
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(
            scope,idempotency_key=idempotency_key,function_name=plan.function,
            normalized_program=normalized,compiler_version=compiler,
            plan_digest=plan_digest,
            expected_metadata_revision=revisions['metadata_revision'],
            expected_data_revision=revisions['data_revision'],
            expected_policy_revision=revisions['policy_revision'],
            depends_on_job_ids=())
