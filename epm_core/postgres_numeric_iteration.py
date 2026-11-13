"""Bounded fixed-point iteration over exact ordered PostgreSQL vector stages."""
from contextlib import contextmanager
import json
import time

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from . import postgres_numeric_sequence as sequence
from .postgres_numeric_sequence_expression import instructions,COMPILER as BASE_COMPILER,PLAN_DIGEST as BASE_PLAN
from .postgres_jobs import (_canonical_digest,PostgresJobQueue,_KEY,_JOB_ID,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_connection import connect_postgres
from .postgres_access import PostgresAccessChecker
from .postgres_numeric_store import PostgresNumericFactStore
from .persistence_contract import NumericCell
from .postgres_processing_limits import configure_statement_timeout
from .postgres_execution_scope import current_deadline,tool_execution_scope,remaining_milliseconds,ToolDeadlineExpired

FUNCTION='facts.numeric.iterate'
COMPILER='bounded-numeric-iteration-v1'
MAX_ITERATIONS=128
MAX_EFFECTS=8192
MAX_INSTRUCTIONS=32768
MAX_EXPANDED_BYTES=16_000_000
EXECUTION_SECONDS=20
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'compiler':COMPILER,'base':(BASE_COMPILER,BASE_PLAN),
    'rounding':'half_even_8_each_statement','state':'previous_final_vector_next_initial',
    'history':'prior_statement_indices_reset_each_iteration','criterion':'all_final_targets_presence_and_absolute_delta',
    'iterations':MAX_ITERATIONS,'effects':MAX_EFFECTS,'instructions':MAX_INSTRUCTIONS,
    'expandedBytes':MAX_EXPANDED_BYTES,'executionSeconds':EXECUTION_SECONDS,
    'publication':'all_iteration_statement_events_one_commit_on_convergence_only'})


def compile_program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2 or raw['function']!=FUNCTION
            or not isinstance(raw['arguments'],dict) or set(raw['arguments'])!={'statements','rounding','convergence'}):
        raise ValueError('NUMERIC_ITERATION_PROGRAM_INVALID')
    args=raw['arguments'];stop=args['convergence']
    if (not isinstance(stop,dict) or set(stop)!={'mode','tolerance','maxIterations','onNonConvergence'}
            or stop['mode']!='absolute_delta' or stop['onNonConvergence']!='fail'
            or type(stop['maxIterations']) is not int or not 1<=stop['maxIterations']<=MAX_ITERATIONS
            or not isinstance(stop['tolerance'],dict) or set(stop['tolerance'])!={'type','decimal'}
            or stop['tolerance']['type']!='AmountLiteral'):
        raise ValueError('NUMERIC_ITERATION_CONVERGENCE_INVALID')
    tolerance=NumericCell.from_wire(present=True,amount=stop['tolerance']['decimal']).amount
    if tolerance<0:raise ValueError('NUMERIC_ITERATION_TOLERANCE_NEGATIVE')
    base=sequence.compile_program({'languageVersion':2,'function':sequence.FUNCTION,
        'arguments':{'statements':args['statements'],'rounding':args['rounding']}})
    count=stop['maxIterations']
    if (count*len(base['statements'])>MAX_EFFECTS or count*len(instructions(base['statements']))>MAX_INSTRUCTIONS
            or count*len(json.dumps(base,ensure_ascii=False,allow_nan=False).encode())>MAX_EXPANDED_BYTES):
        raise ValueError('NUMERIC_ITERATION_WORK_BUDGET')
    return {'version':1,'function':FUNCTION,'sequence':base,'convergence':{
        'mode':'absolute_delta','tolerance':format(tolerance,'.8f'),'maxIterations':count,'onNonConvergence':'fail'}}


def decode_program(value):
    try:
        if not isinstance(value,dict) or set(value)!={'version','function','sequence','convergence'} or type(value['version']) is not int or value['version']!=1:
            raise ValueError('version')
        base=sequence.decode_program(value['sequence']);stop=value['convergence']
        raw={'languageVersion':2,'function':value['function'],'arguments':{
            **sequence.to_program(base)['arguments'],'convergence':{**stop,
                'tolerance':{'type':'AmountLiteral','decimal':stop['tolerance']}}}}
        checked=compile_program(raw)
        if checked!=value:raise ValueError('noncanonical')
        return checked
    except (KeyError,TypeError,ValueError) as error:
        raise ValueError('NUMERIC_ITERATION_NORMALIZED_INVALID') from error


@contextmanager
def execution_budget(db,job=None):
    seconds=EXECUTION_SECONDS
    if job is not None:
        seconds=min(seconds,float(db.execute('SELECT extract(epoch FROM (%s::timestamptz-clock_timestamp())) remaining',
            (job['lease_until'],)).fetchone()['remaining']))
    deadline=time.monotonic()+max(0,seconds)
    if current_deadline() is not None:deadline=min(deadline,current_deadline())
    try:
        with tool_execution_scope(deadline):yield
    except (ToolDeadlineExpired,psycopg.errors.QueryCanceled):
        raise ValueError('NUMERIC_ITERATION_EXECUTION_BUDGET') from None


def check_fence(db,scope,job,job_id):
    return sequence.check_publication_fence(db,scope,job,job_id,lock=False)


def evaluate(db,scope,normalized,*,job=None,job_id=None,initial=None):
    base=normalized['sequence'];rows=base['statements']
    if initial is None:initial=sequence.initial_state(db,scope,base)
    diagnostics=[];effects=[];trace_all=[]
    for number in range(1,normalized['convergence']['maxIterations']+1):
        remaining_milliseconds();configure_statement_timeout(db,5000)
        if job is not None:check_fence(db,scope,job,job_id)
        trace=sequence.evaluate_from_initial(db,base,initial)
        final=dict(initial)
        offset=len(effects)
        for row,output in zip(rows,trace):
            final[row['series_key']]={'present':output['amount'] is not None,
                'amount':format(output['amount'],'f') if output['amount'] is not None else None}
            effects.append({**row,'ordinal':offset+row['ordinal']})
            trace_all.append({**output,'ordinal':offset+output['ordinal']})
        # Compare the complete vector in exact PostgreSQL arithmetic; missing
        # and present zero never become equal through a numeric coalesce.
        pairs=[{'before':initial[key],'after':final[key]} for key in sorted(initial)]
        configure_statement_timeout(db,5000)
        delta=db.execute('''SELECT count(*) FILTER(WHERE (i.before->>'present')::boolean IS DISTINCT FROM
            (i.after->>'present')::boolean)::integer presence_changes,
            coalesce(max(abs((i.after->>'amount')::numeric-(i.before->>'amount')::numeric))
                FILTER(WHERE (i.before->>'present')::boolean AND (i.after->>'present')::boolean),0) max_delta,
            bool_and((i.before->>'present')::boolean=(i.after->>'present')::boolean AND
                (NOT (i.after->>'present')::boolean OR
                 abs((i.after->>'amount')::numeric-(i.before->>'amount')::numeric)<=%s::numeric)) converged
            FROM jsonb_to_recordset(%s::jsonb) i(before jsonb,after jsonb)''',
            (normalized['convergence']['tolerance'],Jsonb(pairs))).fetchone()
        item={'iteration':number,'presenceChanges':delta['presence_changes'],'maxAbsoluteDelta':format(delta['max_delta'],'.8f')}
        diagnostics.append(item)
        if delta['converged']:
            return {'converged':True,'iterations':number,'diagnostics':diagnostics,
                'rows':effects,'trace':trace_all,'final':final}
        initial=final
    return {'converged':False,'iterations':number,'diagnostics':diagnostics,
        'rows':effects,'trace':trace_all,'final':final}


def report(outcome):
    return {'converged':outcome['converged'],'iterations':outcome['iterations'],
        'diagnostics':outcome['diagnostics'],'executedStatementCount':len(outcome['rows']),
        'finalValues':[{'seriesKey':key,'present':value['present'],
            'amount':format(NumericCell.from_wire(present=True,amount=value['amount']).amount,'.8f') if value['present'] else None}
            for key,value in sorted(outcome['final'].items())]}


def preview(language,scope,raw):
    normalized=compile_program(raw)
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,language.identity,scope,'write',function=FUNCTION)
            state=db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,s.data_revision,s.policy_revision
                FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
                WHERE workspace_id=%s AND application_id=%s FOR SHARE OF s''',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None or state['status']!='Active' or state['processing_mode']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
            sequence.enforce_sequence_dimensional_security(
                db,language.identity,scope,normalized['sequence'])
            with execution_budget(db):outcome=evaluate(db,scope,normalized)
            revisions={k:state[k] for k in ('metadata_revision','data_revision','policy_revision')}
    result={'languageVersion':2,'function':FUNCTION,'admissionAllowed':outcome['converged'],
        'revisionVector':revisions,**report(outcome)}
    if outcome['converged']:
        token,digest=language._sign_preview(scope,FUNCTION,normalized,revisions)
        result.update(previewToken=token,programDigest=digest)
    else:result['errorCode']='NUMERIC_ITERATION_NOT_CONVERGED'
    return result


def submit(language,scope,raw,token,key,dependencies,*,execution_authority=None):
    normalized=compile_program(raw)
    if (not isinstance(key,str) or not _KEY.fullmatch(key) or not isinstance(dependencies,tuple) or len(dependencies)>16
            or any(not isinstance(d,str) or not _JOB_ID.fullmatch(d) for d in dependencies)
            or len(set(dependencies))!=len(dependencies)):
        raise ValueError('NUMERIC_ITERATION_REQUEST_INVALID')
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(
                db,language.identity,scope,'write',function=FUNCTION)
            prior=db.execute('''SELECT job_id,status,request_digest,expected_metadata_revision,
                expected_data_revision,expected_policy_revision,verified_groups,
                authorization_scope_digest FROM epm.job WHERE workspace_id=%s AND application_id=%s
                AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                (scope.workspace_id,scope.application_id,language.identity.issuer,language.identity.subject_id,key)).fetchone()
            if prior:
                auth_scope=_verify_job_replay_authorization(db,scope,
                    language.identity,prior,access=access,function_name=FUNCTION)
                descriptor=_job_request_descriptor(scope,language.identity,
                    function_name=FUNCTION,program_digest=_canonical_digest(normalized),
                    compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],prior['expected_policy_revision']),
                    resource_class='short',dependencies=dependencies,
                    authorization_scope_digest=auth_scope,
                    verified_groups=access.groups,execution_authority=execution_authority)
                if _canonical_digest(descriptor)!=prior['request_digest']:raise ValueError('NUMERIC_ITERATION_IDEMPOTENCY_CONFLICT')
                return {'jobId':prior['job_id'],'status':prior['status'],'duplicate':True}
    payload=language._unpack_preview(scope,FUNCTION,token)
    if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt'}
            or payload['programDigest']!=_canonical_digest(normalized)):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    revisions=payload['revisions']
    return PostgresJobQueue(language.dsn,identity=language.identity).submit(scope,
        function_name=FUNCTION,idempotency_key=key,normalized_program=normalized,compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
        expected_metadata_revision=revisions['metadata_revision'],expected_data_revision=revisions['data_revision'],
        expected_policy_revision=revisions['policy_revision'],depends_on_job_ids=dependencies,
        execution_authority=execution_authority)


def apply(db,scope,job,job_id,*,identity,workflow_role):
    normalized=decode_program(job['normalized_program'])
    sequence.enforce_sequence_dimensional_security(
        db,identity,scope,normalized['sequence'])
    with execution_budget(db,job):
        outcome=evaluate(db,scope,normalized,job=job,job_id=job_id)
        if not outcome['converged']:raise ValueError('NUMERIC_ITERATION_NOT_CONVERGED')
        check_fence(db,scope,job,job_id)
        return sequence.publish_trace(db,scope,job,job_id,{'statements':outcome['rows']},outcome['trace'],
            identity=identity,
            result_fields={'convergence':report(outcome),'iterationStatementCount':len(normalized['sequence']['statements'])},
            workflow_role=workflow_role)


def catalog():
    return {FUNCTION:{'mode':'durable_write','permission':'write','arguments':{
        'statements':'1–500 ordered set/add/clear at full coordinates, first touch has expectedChangeId',
        'rounding':'half_even_8','convergence':{'mode':'absolute_delta','tolerance':{'type':'AmountLiteral','decimal':'nonnegative exact amount'},
            'maxIterations':'1–128','onNonConvergence':'fail'}},
        'workBound':'8192 executed statements,32768 instructions,16MB expanded program;20s compute/native SQL budget,shorter inherited limits preserved',
        'semantics':'each prior final vector seeds next iteration; earlier statement indices reset; all target presence and final deltas must match criterion',
        'result':'diagnostics and admissionAllowed; non-convergence has no previewToken; success admits one atomic job and retains all iteration statement events',
        'previewRequired':True,'idempotencyRequired':True,'workClass':'short'}}
