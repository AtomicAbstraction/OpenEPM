"""Bounded fixed-point iteration over exact ordered PostgreSQL vector stages."""
from contextlib import contextmanager
import json
import time

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from . import postgres_numeric_sequence as sequence
from .postgres_numeric_sequence_expression import instructions,COMPILER as BASE_COMPILER,PLAN_DIGEST as BASE_PLAN
from .postgres_jobs import _canonical_digest,PostgresJobQueue
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


def report_schema(*, converged=None):
    """Wire report from report(); deltas may be wider than either endpoint."""
    from .postgres_numeric_catalog import obj
    convergence = {'type': 'boolean'}
    if converged is not None:
        convergence['const'] = converged
    return obj({
        'converged': convergence,
        'iterations': {'type': 'integer', 'minimum': 1, 'maximum': MAX_ITERATIONS},
        'diagnostics': {'type': 'array', 'minItems': 1, 'maxItems': MAX_ITERATIONS,
            'items': obj({
                'iteration': {'type': 'integer', 'minimum': 1, 'maximum': MAX_ITERATIONS},
                'presenceChanges': {'type': 'integer', 'minimum': 0, 'maximum': 500},
                'maxAbsoluteDelta': {'type': 'string',
                    'pattern': r'^(?:0|[1-9][0-9]{0,20})\.[0-9]{8}(?![\s\S])'}})},
        'executedStatementCount': {'type': 'integer', 'minimum': 1, 'maximum': MAX_EFFECTS},
        'finalValues': {'type': 'array', 'minItems': 1, 'maxItems': 500,
            'items': sequence.numeric_result_cell_schema({
                'seriesKey': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}})}})


def preview_result_schema():
    from .postgres_numeric_catalog import obj
    variants = []
    for converged in (True, False):
        fields = {
            'languageVersion': {'type': 'integer', 'const': 2}, 'function': {'const': FUNCTION},
            'admissionAllowed': {'type': 'boolean', 'const': converged},
            'revisionVector': obj({key: {'type': 'integer', 'minimum': 0} for key in
                ('metadata_revision', 'data_revision', 'policy_revision')}),
            **report_schema(converged=converged)['properties']}
        if converged:
            fields.update(previewToken={'type': 'string', 'minLength': 1},
                programDigest={'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'})
        else:
            fields['errorCode'] = {'const': 'NUMERIC_ITERATION_NOT_CONVERGED'}
        variants.append(obj(fields))
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', 'oneOf': variants}


def published_result_schema():
    from .postgres_numeric_catalog import obj
    base = sequence.published_result_schema(maximum_statements=MAX_EFFECTS)
    return {'$schema': base['$schema'], **obj({**base['properties'],
        'convergence': report_schema(converged=True),
        'iterationStatementCount': {'type': 'integer', 'minimum': 1, 'maximum': 500}})}


def output_contract():
    from .postgres_jobs import job_submission_schema
    submission = job_submission_schema()
    return {'resultSchema': submission, 'resultSchemaScope': 'envelope',
        'outputSchemas': {
            'preview': {'schema': preview_result_schema(), 'scope': 'envelope',
                'surface': 'preview_v2_program or browser /api/preview; convergence or nonconvergence is a returned preview, not a published effect'},
            'submission': {'schema': submission, 'scope': 'envelope',
                'surface': 'submit_v2_program or browser /api/submit; accepted durable job or matching original job'},
            'publishedResult': {'schema': published_result_schema(), 'scope': 'result',
                'surface': 'read_v2_job result when published, also operation receipt result; not the worker wrapper'}},
        'outputRules': [
            'Nonconvergent preview has converged=false, admissionAllowed=false and NUMERIC_ITERATION_NOT_CONVERGED, with no previewToken or programDigest. It is inspectable but cannot admit work. Converged preview has both signed-preview fields and no errorCode; publication requires convergence.',
            'diagnostics has one ordered entry per executed iteration. presenceChanges counts changed presence across distinct final targets; maxAbsoluteDelta compares only targets present before and after. Two valid NUMERIC(28,8) endpoints can have a 21-integer-digit delta; it is not a cell amount.',
            'Final values are sorted by seriesKey. Missing remains distinct from present zero. executedStatementCount and published statementCount count all iteration effects; iterationStatementCount counts the original program statements. Iteration count times original statement count equals executed count.',
            'changedCount counts distinct final target coordinates, not changed-value comparisons. Every intermediate event and final projection publishes in one commit; failed or nonconvergent work has no publishedResult.',
            'Signed previewToken binds the current compiler and execution plan. Old or mismatched plan previews cannot admit new work; accepted old-plan jobs fail before evaluation. Original job/receipt recovery preserves the accepted identity and completed outcome without rerunning convergence.',
            'Current direct iteration results contain no savedProgram. Existing authorized historical job/receipt inspection preserves the originally stored result without applying these schemas as a decoder.']}


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
        token,digest=language._sign_preview(scope,FUNCTION,normalized,revisions,
            extra={'compilerVersion':COMPILER,'planDigest':PLAN_DIGEST})
        result.update(previewToken=token,programDigest=digest)
    else:result['errorCode']='NUMERIC_ITERATION_NOT_CONVERGED'
    return result


def replay(language,scope,raw,key,dependencies,*,execution_authority=None):
    normalized=compile_program(raw)
    sequence._validate_replay_key(key,dependencies,'NUMERIC_ITERATION_REQUEST_INVALID')
    return sequence._replay_request(language,scope,normalized,FUNCTION,'short',key,dependencies,
        execution_authority=execution_authority,conflict='NUMERIC_ITERATION_IDEMPOTENCY_CONFLICT')


def submit(language,scope,raw,token,key,dependencies,*,execution_authority=None):
    normalized=compile_program(raw)
    sequence._validate_replay_key(key,dependencies,'NUMERIC_ITERATION_REQUEST_INVALID')
    prior=sequence._replay_request(language,scope,normalized,FUNCTION,'short',key,dependencies,
        execution_authority=execution_authority,conflict='NUMERIC_ITERATION_IDEMPOTENCY_CONFLICT')
    if prior is not None:return prior
    payload=language._unpack_preview(scope,FUNCTION,token)
    if (set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt','compilerVersion','planDigest'}
            or payload['programDigest']!=_canonical_digest(normalized)
            or payload['compilerVersion']!=COMPILER or payload['planDigest']!=PLAN_DIGEST):
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
