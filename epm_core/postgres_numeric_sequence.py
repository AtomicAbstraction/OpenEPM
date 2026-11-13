"""Ordered numeric statements, evaluated by exact relational PostgreSQL stages.

All statements share one accepted snapshot and one commit. Earlier statement
outputs can be referenced explicitly; no client code, SQL or per-cell DB loop.
"""
from __future__ import annotations

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope,Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_jobs import (_canonical_digest,_require_python_job_authority,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_execution_scope import current_deadline
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates

FUNCTION = 'facts.numeric.sequence'
COMPILER = 'ordered-numeric-statements-v1'
PLAN_DIGEST = _canonical_digest({'function': FUNCTION, 'version': 1,
    'engine': 'postgres_exact_recursive_sql', 'bound': 500,
    'order': 'explicit_statement_order', 'references': 'prior_present_output',
    'arithmetic': 'exact_numeric_28_8_each_statement',
    'events': 'all_statements_one_commit', 'projection': 'last_per_coordinate'})


def compiler_for(normalized):
    version = normalized.get('version') if isinstance(normalized, dict) else None
    if type(version) is not int:
        raise ValueError('NUMERIC_SEQUENCE_NORMALIZED_PROGRAM_INVALID')
    if version == 1:
        return COMPILER, PLAN_DIGEST
    if version == 2:
        from .postgres_numeric_sequence_expression import COMPILER as compiler, PLAN_DIGEST as digest
        return compiler, digest
    raise ValueError('NUMERIC_SEQUENCE_NORMALIZED_PROGRAM_INVALID')


def compile_program(raw):
    if (not isinstance(raw, dict) or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion'] != 2
            or raw['function'] != FUNCTION or not isinstance(raw['arguments'], dict)
            or set(raw['arguments']) not in ({'statements'}, {'statements', 'rounding'})):
        raise ValueError('NUMERIC_SEQUENCE_PROGRAM_INVALID')
    expressions = 'rounding' in raw['arguments']
    if expressions and raw['arguments']['rounding'] != 'half_even_8':
        raise ValueError('NUMERIC_SEQUENCE_ROUNDING_INVALID')
    statements = raw['arguments']['statements']
    if not isinstance(statements, list) or not 1 <= len(statements) <= 500:
        raise ValueError('NUMERIC_SEQUENCE_STATEMENT_BOUNDS')
    seen = set(); rows = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict) or statement.get('op') not in ('set', 'add', 'clear'):
            raise ValueError('NUMERIC_SEQUENCE_STATEMENT_INVALID')
        point = Coordinate.from_mapping(statement.get('coordinate'))
        first = point.series_key not in seen
        fields = {'coordinate', 'op'} | ({'expectedChangeId'} if first else set())
        if statement['op'] != 'clear': fields.add('value')
        if set(statement) != fields:
            raise ValueError('NUMERIC_SEQUENCE_STATEMENT_FIELDS')
        expected = statement.get('expectedChangeId')
        if first and (not isinstance(expected, str) or len(expected) > 200):
            raise ValueError('NUMERIC_SEQUENCE_CHANGE_ID_INVALID')
        literal = reference = expression = None
        if statement['op'] != 'clear':
            value = statement['value']
            if isinstance(value, dict) and set(value) == {'type', 'decimal'} and value['type'] == 'AmountLiteral':
                literal = format(NumericCell.from_wire(present=True, amount=value['decimal']).amount, 'f')
            elif (isinstance(value, dict) and set(value) == {'type', 'statementIndex'}
                    and value['type'] == 'StatementValue'
                    and type(value['statementIndex']) is int
                    and 0 <= value['statementIndex'] < index):
                reference = value['statementIndex']
            elif isinstance(value, dict) and set(value) == {'type', 'expression'} and value['type'] == 'NumericExpression':
                if not expressions:
                    raise ValueError('NUMERIC_SEQUENCE_EXPRESSION_ROUNDING_REQUIRED')
                from .postgres_numeric_sequence_expression import compile_expression
                expression = compile_expression(value['expression'], index)
            else:
                raise ValueError('NUMERIC_SEQUENCE_VALUE_INVALID')
        rows.append({'ordinal': index + 1, 'series_key': point.series_key,
            'members': dict(point.members), 'op': statement['op'],
            'literal': literal, 'reference': reference, 'expected_change_id': expected,
            **({'expression': expression} if expression is not None else {})})
        seen.add(point.series_key)
    normalized = {'version': 2 if expressions else 1, 'function': FUNCTION, 'statements': rows,
                  **({'rounding': 'half_even_8'} if expressions else {})}
    if expressions:
        from .postgres_numeric_sequence_expression import instructions
        instructions(rows)  # Enforce the aggregate work budget before admission.
    return normalized


def to_program(normalized):
    compiler_for(normalized)
    statements = []
    for row in normalized['statements']:
        statement = {'coordinate': row['members'], 'op': row['op']}
        if row['expected_change_id'] is not None:
            statement['expectedChangeId'] = row['expected_change_id']
        if row['op'] != 'clear':
            statement['value'] = ({'type': 'NumericExpression', 'expression': row['expression']}
                if 'expression' in row else {'type': 'StatementValue', 'statementIndex': row['reference']}
                if row['reference'] is not None else {'type': 'AmountLiteral', 'decimal': row['literal']})
        statements.append(statement)
    return {'languageVersion':2,'function':FUNCTION,'arguments':{'statements':statements,
        **({'rounding':normalized.get('rounding')} if normalized['version']==2 else {})}}


def decode_program(normalized):
    try:
        checked=compile_program(to_program(normalized))
        if _canonical_digest(checked)!=_canonical_digest(normalized):raise ValueError('noncanonical')
        return checked
    except (KeyError,TypeError,ValueError) as error:
        raise ValueError('NUMERIC_SEQUENCE_NORMALIZED_PROGRAM_INVALID') from error


def validate_coordinates(db,scope,normalized):
    rows=normalized['statements']
    unique = {row['series_key']: row for row in reversed(rows)}
    from .postgres_fact_batch import validate_coordinates as validate_batch
    validate_batch(db,scope,list(unique.values()))
    return unique


def initial_state(db, scope, normalized, *, fact_state=None):
    configure_statement_timeout(db, 5000)
    rows = normalized['statements']
    unique=validate_coordinates(db,scope,normalized)
    from .postgres_fact_batch import numeric_inputs
    current=(numeric_inputs(db,scope,list(unique.values())) if fact_state is None
             else fact_state.numeric_inputs(db,scope,list(unique.values())))
    initial = {}
    numeric_targets = {r['series_key'] for r in rows if r['op'] != 'clear'}
    for row in current:
        declared = unique[row['series_key']]
        if row['members'] is not None and row['members'] != declared['members']:
            raise ValueError('COORDINATE_HASH_COLLISION')
        if row['change_id'] != declared['expected_change_id']: raise ValueError('STALE_CELL_CHANGE_ID')
        if row['has_detail']: raise ValueError('COORDINATE_HAS_LINE_DETAIL')
        if row['text_present'] and row['series_key'] in numeric_targets: raise ValueError('COORDINATE_HAS_TEXT_VALUE')
        initial[row['series_key']] = {'present': row['present'],
            'amount': format(row['amount'], 'f') if row['amount'] is not None else None}
    if db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb) i(members jsonb)
        JOIN epm.cube_write_scope_lock l ON l.workspace_id=%s AND l.application_id=%s
        AND l.status='Locked' AND (l.scope_all OR i.members @> l.scope_members) LIMIT 1''',
        (Jsonb(list(unique.values())), scope.workspace_id, scope.application_id)).fetchone():
        raise ValueError('PLANNING_SLICE_LOCKED')
    return initial


def evaluate(db,scope,normalized):
    return evaluate_from_initial(db,normalized,initial_state(db,scope,normalized))


def evaluate_from_initial(db,normalized,initial):
    configure_statement_timeout(db,5000)
    rows=normalized['statements']
    if normalized['version'] == 2:
        from .postgres_numeric_sequence_expression import evaluate_trace
        return evaluate_trace(db, rows, initial)
    try:
        trace = db.execute('''WITH RECURSIVE inputs AS (
            SELECT * FROM jsonb_to_recordset(%s::jsonb) AS i(ordinal int,series_key text,
                op text,literal numeric,reference int)),
        execution(ordinal,states,history,amount,before_amount,reference_present) AS (
            SELECT 0,%s::jsonb,'[]'::jsonb,NULL::numeric,0::numeric,true
            UNION ALL
            SELECT i.ordinal,jsonb_set(e.states,ARRAY[i.series_key],v.cell),
                e.history || jsonb_build_array(v.cell),a.amount,b.amount,
                i.reference IS NULL OR coalesce((e.history->i.reference->>'present')::boolean,false)
            FROM execution e JOIN inputs i ON i.ordinal=e.ordinal+1
            CROSS JOIN LATERAL (SELECT coalesce((e.states->i.series_key->>'amount')::numeric,0) amount) b
            CROSS JOIN LATERAL (SELECT CASE WHEN i.reference IS NULL THEN i.literal
                ELSE (e.history->i.reference->>'amount')::numeric END amount) operand
            CROSS JOIN LATERAL (SELECT (CASE WHEN i.op='clear' THEN NULL
                WHEN i.op='set' THEN operand.amount ELSE b.amount+operand.amount END)::numeric(28,8) amount) a
            CROSS JOIN LATERAL (SELECT jsonb_build_object('present',i.op<>'clear','amount',a.amount) cell) v)
        SELECT ordinal,amount,before_amount,reference_present FROM execution
        WHERE ordinal>0 ORDER BY ordinal''', (Jsonb(rows), Jsonb(initial))).fetchall()
    except psycopg.errors.NumericValueOutOfRange as error:
        raise ValueError('NUMERIC_SEQUENCE_AMOUNT_OUT_OF_RANGE') from error
    if any(not row['reference_present'] for row in trace):
        raise ValueError('NUMERIC_SEQUENCE_REFERENCED_VALUE_MISSING')
    return trace


def enforce_sequence_dimensional_security(db, identity, scope, normalized):
    """Authorize every current-value source and ordered write target.

    Ordered statements read the current value/presence of every distinct
    coordinate before evaluating Set/Add/Clear, even when a literal Set does
    not expose that value to the caller.  The same coordinates are then write
    targets.  Resolve both sides from the canonical normalized program so no
    caller can supply a narrower authorization set.
    """
    if normalized.get('function') == 'facts.numeric.transform':
        from .postgres_numeric_transform import authorize_rows
        return authorize_rows(db, scope, identity, normalized['statements'])
    unique = {row['series_key']: Coordinate.from_mapping(row['members'])
              for row in normalized['statements']}
    coordinates = tuple(unique[key] for key in sorted(unique))
    authorize_coordinates(
        db, identity, scope, coordinates, kind=AccessKind.READ)
    authorize_coordinates(
        db, identity, scope, coordinates, kind=AccessKind.WRITE)


def preview(language, scope, raw):
    normalized = compile_program(raw)
    with connect_postgres(language.dsn, row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db, language.identity, scope, 'write', function=FUNCTION)
            state = db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,
                s.data_revision,s.policy_revision FROM epm.application_state s JOIN epm.application a
                USING(workspace_id,application_id) WHERE workspace_id=%s AND application_id=%s FOR SHARE OF s''',
                (scope.workspace_id, scope.application_id)).fetchone()
            if state is None or state['status'] != 'Active' or state['processing_mode'] != 'Active':
                raise ValueError('APPLICATION_NOT_WRITABLE')
            enforce_sequence_dimensional_security(
                db, language.identity, scope, normalized)
            trace = evaluate(db, scope, normalized)
            revisions = {k: state[k] for k in ('metadata_revision','data_revision','policy_revision')}
    token, digest = language._sign_preview(scope, FUNCTION, normalized, revisions)
    return {'languageVersion': 2, 'function': FUNCTION, 'previewToken': token,
        'programDigest': digest, 'revisionVector': revisions,
        'statementCount': len(trace), 'targetCount': len({r['series_key'] for r in normalized['statements']}),
        'statementResults': [{'statementIndex': r['ordinal']-1, 'present': r['amount'] is not None,
            'amount': format(r['amount'], '.8f') if r['amount'] is not None else None} for r in trace],
        'engine': 'postgres_exact_recursive_sql',
        **({'compilerVersion': compiler_for(normalized)[0], 'rounding': normalized['rounding']}
           if normalized['version'] == 2 else {})}


def submit(language, scope, raw, token, key, dependencies, *, execution_authority=None):
    from .postgres_jobs import PostgresJobQueue, _KEY, _JOB_ID
    function = raw.get('function') if isinstance(raw, dict) else None
    resource = 'short'
    if function == 'facts.numeric.transform':
        from .postgres_numeric_transform import compile_program as compile_transform, COMPILER, PLAN_DIGEST
        normalized = compile_transform(raw)
        compiler, digest, resource = COMPILER, PLAN_DIGEST, 'medium'
    else:
        function = FUNCTION
        normalized = compile_program(raw)
        compiler, digest = compiler_for(normalized)
    if (not isinstance(key, str) or not _KEY.fullmatch(key)
            or not isinstance(dependencies, tuple) or len(dependencies)>16
            or any(not isinstance(value, str) or not _JOB_ID.fullmatch(value) for value in dependencies)
            or len(set(dependencies)) != len(dependencies)):
        raise ValueError('NUMERIC_SEQUENCE_IDEMPOTENCY_OR_DEPENDENCY_INVALID')
    # A retry after restart is a receipt lookup, not another admission. It must
    # survive preview expiry and changed cells, while preserving current grants
    # and the complete original request identity (including dependency order).
    with connect_postgres(language.dsn, row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(
                db,language.identity,scope,'write',function=function)
            prior = db.execute('''SELECT job_id,status,request_digest,expected_metadata_revision,
                expected_data_revision,expected_policy_revision,verified_groups,
                authorization_scope_digest FROM epm.job WHERE workspace_id=%s
                AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                (scope.workspace_id,scope.application_id,language.identity.issuer,language.identity.subject_id,key)).fetchone()
            if prior:
                auth_scope=_verify_job_replay_authorization(db,scope,
                    language.identity,prior,access=access,function_name=function)
                descriptor=_job_request_descriptor(scope,language.identity,
                    function_name=function,program_digest=_canonical_digest(normalized),
                    compiler_version=compiler,plan_digest=digest,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],prior['expected_policy_revision']),
                    resource_class=resource,dependencies=dependencies,
                    authorization_scope_digest=auth_scope,
                    verified_groups=access.groups,
                    execution_authority=execution_authority)
                if _canonical_digest(descriptor) != prior['request_digest']:
                    raise ValueError('IDEMPOTENCY_KEY_REUSED')
                return {'jobId':prior['job_id'],'status':prior['status'],'duplicate':True}
    payload = language._unpack_preview(scope, function, token)
    if (set(payload) != {'scope','identity','function','programDigest','revisions','expiresAt'}
            or payload['programDigest'] != _canonical_digest(normalized)):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    revisions = payload['revisions']
    return PostgresJobQueue(language.dsn, identity=language.identity).submit(scope,
        idempotency_key=key, function_name=function, normalized_program=normalized,
        compiler_version=compiler, plan_digest=digest,
        resource_class=resource, expected_metadata_revision=revisions['metadata_revision'],
        expected_data_revision=revisions['data_revision'],
        expected_policy_revision=revisions['policy_revision'], depends_on_job_ids=dependencies,
        execution_authority=execution_authority)


def apply_in_transaction(db, scope, job, job_id, *, identity,
                         provenance=None, workflow_role):
    normalized = decode_program(job['normalized_program'])
    enforce_sequence_dimensional_security(db, identity, scope, normalized)
    trace = evaluate(db, scope, normalized)
    return publish_trace(db,scope,job,job_id,normalized,trace,
        identity=identity,provenance=provenance,workflow_role=workflow_role)


def enforce_sequence_target_policy(db,scope,normalized,workflow_role):
    from .postgres_planning_write_guard import enforce_active_planning_policy
    actions={'set':'Set','add':'Add','clear':'Clear'}
    return enforce_active_planning_policy(
        db,scope,writes=tuple((Coordinate.from_mapping(row['members']),
                               actions[row['op']])
                              for row in normalized['statements']),
        workflow_role=workflow_role,ordered_actions=True)


def _sequence_replay(db,scope,job,receipt):
    if receipt is None:return None
    if (job is None or job['status']!='published'
            or job['receipt_revision']!=receipt['committed_revision']
            or job['result']!=receipt['result']
            or job['subject_id']!=receipt['actor_id']):
        raise ValueError('NUMERIC_SEQUENCE_RECEIPT_CONFLICT')
    PostgresNumericFactStore._require_replay_impact(
        db,scope,job['job_id'],receipt)
    return receipt['result']


def _prepare_sequence(db,scope,normalized):
    initial=initial_state(db,scope,normalized)
    trace=evaluate_from_initial(db,normalized,initial)
    return initial,trace


def _ordered_job_authority(program,function):
    if function=='facts.numeric.transform':
        from .postgres_numeric_transform import COMPILER, PLAN_DIGEST, decode_program
        decode_program(program)
        return COMPILER, PLAN_DIGEST
    if function==FUNCTION:
        return compiler_for(program)
    if function=='facts.numeric.iterate':
        from .postgres_numeric_iteration import COMPILER,PLAN_DIGEST
        return COMPILER,PLAN_DIGEST
    from .postgres_saved_numeric_sequence import (
        RUN,COMPILER as saved_compiler,PLAN_DIGEST as saved_digest)
    if function!=RUN:raise ValueError('UNSUPPORTED_NUMERIC_JOB_PROGRAM')
    return saved_compiler,saved_digest


def _prepare_ordered_job(db,scope,job,function,identity):
    if function=='facts.numeric.transform':
        from .postgres_numeric_transform import prepared_job
        return prepared_job(db,scope,job,identity)
    if function==FUNCTION:
        normalized=decode_program(job['normalized_program']);provenance=None
        enforce_sequence_dimensional_security(
            db,identity,scope,normalized)
        initial,trace=_prepare_sequence(db,scope,normalized)
        return normalized,initial,trace,provenance,None
    if function=='facts.numeric.iterate':
        from . import postgres_numeric_iteration as iteration
        definition=iteration.decode_program(job['normalized_program'])
        enforce_sequence_dimensional_security(
            db,identity,scope,definition['sequence'])
        initial=initial_state(db,scope,definition['sequence'])
        with iteration.execution_budget(db,job):
            outcome=iteration.evaluate(db,scope,definition,job=job,
                job_id=job['job_id'],initial=initial)
        if not outcome['converged']:
            raise ValueError('NUMERIC_ITERATION_NOT_CONVERGED')
        normalized={'statements':outcome['rows']}
        result_fields={'convergence':iteration.report(outcome),
            'iterationStatementCount':len(definition['sequence']['statements'])}
        return normalized,{'definition':definition,'initial':initial},(
            outcome['trace']),None,result_fields
    else:
        from .postgres_saved_numeric_sequence import validate_run
        normalized=validate_run(db,scope,job['normalized_program'])
        provenance=job['normalized_program']['pin']
    enforce_sequence_dimensional_security(db,identity,scope,normalized)
    initial,trace=_prepare_sequence(db,scope,normalized)
    return normalized,initial,trace,provenance,None


class PostgresNumericSequencePublisher:
    """Prepare a direct or saved exact ordered trace before publication."""
    def __init__(self,dsn,*,identity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def publish(self,claim):
        import re
        if (not isinstance(claim,dict)
                or not isinstance(claim.get('workspace_id'),str)
                or not isinstance(claim.get('application_id'),str)
                or not isinstance(claim.get('job_id'),str)
                or not re.fullmatch(r'[0-9a-f]{32}',claim['job_id'])
                or not isinstance(claim.get('claimant'),str)
                or type(claim.get('claim_generation')) is not int
                or claim.get('function_name') not in (
                    None,FUNCTION,'rules.numeric_sequence.run',
                    'facts.numeric.iterate','facts.numeric.transform')):
            raise ValueError('Invalid worker claim')
        function=claim.get('function_name') or FUNCTION
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        if function=='facts.numeric.transform':
            from .postgres_numeric_transform import stage
            stage(self.dsn,scope,claim,self.identity)
        keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            state=db.execute('''SELECT a.status application_status,
              s.processing_mode,s.metadata_revision,s.data_revision,
              s.policy_revision,s.commit_revision FROM epm.application_state s
              JOIN epm.application a USING(workspace_id,application_id)
              WHERE s.workspace_id=%s AND s.application_id=%s''',keys).fetchone()
            if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
            access=PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,'write',function=function)
            if function=='rules.numeric_sequence.run':
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'rule_run')
            job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
              AND application_id=%s AND job_id=%s''',(*keys,claim['job_id'])).fetchone()
            receipt=db.execute('''SELECT committed_revision,actor_id,result
              FROM epm.operation_receipt WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s''',
              (*keys,claim['job_id'])).fetchone()
            replay=_sequence_replay(db,scope,job,receipt)
            if replay is not None:return replay
            live=(job is not None and db.execute('''SELECT %s::timestamptz>
              clock_timestamp() valid''',(job['lease_until'],)).fetchone()['valid'])
            if (job is None or job['issuer']!=self.identity.issuer
                    or job['subject_id']!=self.identity.subject_id
                    or job['status']!='running'
                    or job['claim_generation']!=claim['claim_generation']
                    or job['claimant']!=claim['claimant'] or not live):
                raise ValueError('STALE_WORKER_FENCE')
            _require_python_job_authority(db,scope,job)
            authority=_ordered_job_authority(job['normalized_program'],function)
            if (job['function_name']!=function
                    or (job['compiler_version'],job['plan_digest'])!=authority
                    or job['program_digest']!=_canonical_digest(
                        job['normalized_program'])):
                raise ValueError('UNSUPPORTED_NUMERIC_JOB_PROGRAM')
            normalized,initial,trace,provenance,result_fields=(
                _prepare_ordered_job(db,scope,job,function,self.identity))
            # An unrelated cell publication may advance the application-wide
            # data revision after admission.  The exact ordered targets are
            # fenced by their declared change IDs below, so only metadata and
            # policy remain application-wide admission pins here.
            if ((state['metadata_revision'],state['policy_revision'])!=(
                    job['expected_metadata_revision'],
                    job['expected_policy_revision'])):
                raise ValueError('STALE_JOB_INPUT_REVISION')
            enforce_sequence_target_policy(db,scope,normalized,access.role)

            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            final_state=db.execute('''SELECT a.status application_status,
              s.processing_mode,s.metadata_revision,s.data_revision,
              s.policy_revision,s.commit_revision FROM epm.application_state s
              JOIN epm.application a USING(workspace_id,application_id)
              WHERE s.workspace_id=%s AND s.application_id=%s
              FOR UPDATE OF s''',keys).fetchone()
            final_job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
              AND application_id=%s AND job_id=%s FOR UPDATE''',
              (*keys,claim['job_id'])).fetchone()
            final_receipt=db.execute('''SELECT committed_revision,actor_id,result
              FROM epm.operation_receipt WHERE workspace_id=%s
              AND application_id=%s AND operation_id=%s''',
              (*keys,claim['job_id'])).fetchone()
            replay=_sequence_replay(db,scope,final_job,final_receipt)
            if replay is not None:return replay
            final_live=(final_job is not None and db.execute('''SELECT
              %s::timestamptz>clock_timestamp() valid''',(
              final_job['lease_until'],)).fetchone()['valid'])
            immutable=('issuer','subject_id','function_name','normalized_program',
              'program_digest','compiler_version','plan_digest',
              'expected_metadata_revision','expected_data_revision',
              'expected_policy_revision','idempotency_key','python_workflow_id',
              'execution_delegation_id','execution_delegation_state_token',
              'execution_schedule_id','execution_schedule_state_token')
            if (final_state is None or final_job is None
                    or any(final_job[key]!=job[key] for key in immutable)
                    or final_job['status']!='running'
                    or final_job['claim_generation']!=claim['claim_generation']
                    or final_job['claimant']!=claim['claimant'] or not final_live):
                raise ValueError('STALE_WORKER_FENCE')
            _require_python_job_authority(db,scope,final_job)
            final_access=PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,'write',function=function)
            if function=='rules.numeric_sequence.run':
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'rule_run')
            if (final_state['application_status']!='Active'
                    or final_state['processing_mode']!='Active'):
                raise ValueError('APPLICATION_NOT_WRITABLE')
            if (final_state['metadata_revision']!=
                    final_job['expected_metadata_revision']
                    or final_state['policy_revision']!=
                    final_job['expected_policy_revision']):
                raise ValueError('STALE_JOB_INPUT_REVISION')
            if function=='facts.numeric.iterate':
                from .postgres_numeric_iteration import decode_program
                final_definition=decode_program(final_job['normalized_program'])
                final_initial=initial_state(
                    db,scope,final_definition['sequence'])
                if ({'definition':final_definition,'initial':final_initial}
                        !=initial):
                    raise ValueError('NUMERIC_SEQUENCE_SOURCE_CHANGED')
            else:
                (final_normalized,final_initial,final_trace,
                 final_provenance,final_result_fields)=_prepare_ordered_job(
                    db,scope,final_job,function,self.identity)
                if (final_normalized!=normalized or final_initial!=initial
                        or final_trace!=trace
                        or final_provenance!=provenance
                        or final_result_fields!=result_fields):
                    raise ValueError('NUMERIC_SEQUENCE_SOURCE_CHANGED')
            enforce_sequence_target_policy(
                db,scope,normalized,final_access.role)
            job=final_job
            result=publish_trace(db,scope,job,claim['job_id'],normalized,trace,
                identity=self.identity,provenance=provenance,
                result_fields=result_fields,
                workflow_role=final_access.role)
            changed=db.execute('''UPDATE epm.job SET status='published',
              receipt_revision=%s,result=%s,claimant=NULL,lease_until=NULL,
              updated_at=transaction_timestamp() WHERE workspace_id=%s
              AND application_id=%s AND job_id=%s AND status='running'
              AND claim_generation=%s AND claimant=%s
              AND lease_until>clock_timestamp()''',(result['committedRevision'],
              Jsonb(result),*keys,claim['job_id'],claim['claim_generation'],
              claim['claimant'])).rowcount
            if changed!=1:raise ValueError('STALE_WORKER_FENCE')
            return result


def publish_trace(db,scope,job,job_id,normalized,trace,*,identity,
                  provenance=None,result_fields=None,workflow_role):
    configure_statement_timeout(db,5000)
    def execute(query,arguments):
        if current_deadline() is not None:configure_statement_timeout(db,5000)
        return db.execute(query,arguments)
    state = execute('''SELECT a.status,s.processing_mode,s.commit_revision FROM epm.application_state s
        JOIN epm.application a USING(workspace_id,application_id)
        WHERE workspace_id=%s AND application_id=%s FOR UPDATE OF s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if state['status'] != 'Active' or state['processing_mode'] != 'Active': raise ValueError('APPLICATION_NOT_WRITABLE')
    revision = state['commit_revision'] + 1
    rows = normalized['statements']; unique = {r['series_key']: r for r in rows}
    # This is the final current-authority fence for every direct, saved and
    # iterative ordered publisher, including legacy fixed-runner entry points.
    enforce_sequence_dimensional_security(db,identity,scope,normalized)
    policy_evidence=enforce_sequence_target_policy(
        db,scope,normalized,workflow_role)
    from .postgres_fact_batch import ensure_coordinates
    unique_rows=[{**row,'ordinal':index}
                 for index,row in enumerate(unique.values(),1)]
    ensure_coordinates(db,scope,unique_rows)
    from .postgres_fact_batch import numeric_inputs
    before={row['series_key']:row for row in
            numeric_inputs(db,scope,unique_rows)}
    from .calculation_impact_contract import (
        compile_calculation_impact,fact_effect)
    impact=compile_calculation_impact({
        'format':'openepm-calculation-impact-v1',
        'sourceKind':'numeric_transform','sourceId':job_id,
        'causalRevision':revision,
        'effects':[fact_effect(domain='numeric_fact',change=row['op'],
            object_id=series,members=row['members'],
            old_present=before[series]['present'],
            new_present=row['op']!='clear')
            for series,row in sorted(unique.items())]})
    result = {'changedCount': len(unique), 'statementCount': len(rows),
        'committedRevision': revision,'planningPolicy':policy_evidence,
        'impactDigest':impact.digest}
    if provenance is not None:result['savedProgram']=provenance
    if result_fields is not None:result.update(result_fields)
    execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
        command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
        (scope.workspace_id, scope.application_id, job_id, job['program_digest'], job['subject_id'], revision, Jsonb(result)))
    effects = [{**row, 'amount': format(value['amount'], 'f') if value['amount'] is not None else None,
        'before_amount': format(value['before_amount'], 'f')} for row, value in zip(rows, trace)]
    execute('''INSERT INTO epm.numeric_fact_event(workspace_id,application_id,coordinate_id,
        operation_id,line_ordinal,kind,delta,present,resulting_amount,change_id,committed_revision)
        SELECT %s,%s,c.coordinate_id,%s,i.ordinal,i.op,coalesce(i.amount,0)-i.before_amount,
        i.op<>'clear',i.amount,%s::text || ':' || i.ordinal,%s FROM jsonb_to_recordset(%s::jsonb)
        i(series_key text,ordinal int,op text,amount numeric,before_amount numeric)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key''',
        (scope.workspace_id, scope.application_id, job_id, revision, revision, Jsonb(effects), scope.workspace_id, scope.application_id))
    execute('''INSERT INTO epm.numeric_cell_projection(workspace_id,application_id,coordinate_id,
        present,amount,change_id,last_revision,projection_generation)
        SELECT DISTINCT ON(i.series_key) %s,%s,c.coordinate_id,i.op<>'clear',i.amount,
        %s::text || ':' || i.ordinal,%s,(SELECT epm.active_projection_generation()) FROM jsonb_to_recordset(%s::jsonb)
        i(series_key text,ordinal int,op text,amount numeric)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key
        ORDER BY i.series_key,i.ordinal DESC ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id)
        DO UPDATE SET present=EXCLUDED.present,amount=EXCLUDED.amount,change_id=EXCLUDED.change_id,last_revision=EXCLUDED.last_revision''',
        (scope.workspace_id, scope.application_id, revision, revision, Jsonb(effects), scope.workspace_id, scope.application_id))
    execute('''UPDATE epm.application_state SET data_revision=data_revision+1,commit_revision=%s
        WHERE workspace_id=%s AND application_id=%s''', (revision, scope.workspace_id, scope.application_id))
    from .postgres_calculation_impact import record_calculation_impact
    record_calculation_impact(db,scope,operation_id=job_id,impact=impact)
    check_publication_fence(db,scope,job,job_id)
    return result


def check_publication_fence(db,scope,job,job_id,*,lock=True):
    if current_deadline() is not None:configure_statement_timeout(db,5000)
    valid=db.execute("""SELECT status='running' AND claim_generation=%s AND claimant=%s
        AND lease_until>clock_timestamp() valid FROM epm.job
        WHERE workspace_id=%s AND application_id=%s AND job_id=%s"""+(' FOR UPDATE' if lock else ''),
        (job['claim_generation'],job['claimant'],scope.workspace_id,scope.application_id,job_id)).fetchone()
    if valid is None or not valid['valid']:raise ValueError('STALE_WORKER_FENCE')
