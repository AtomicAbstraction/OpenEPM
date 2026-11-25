"""Strict V2 admission for atomic supporting detail and its numeric total."""
from __future__ import annotations

from psycopg.rows import dict_row

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate, LineItem, NumericCell
from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_cube_query import _FILTER_ID
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_jobs import PostgresJobQueue, _DETAIL_FUNCTION, _detail_program, job_submission_schema
from .postgres_line_detail import PostgresLineDetailStore, prepare_detail_items
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy
from .postgres_processing_limits import configure_statement_timeout


FUNCTION = _DETAIL_FUNCTION


def compile_program(program: object):
    if (type(program) is not dict
            or set(program) != {'languageVersion','function','arguments'}
            or type(program.get('languageVersion')) is not int
            or program['languageVersion'] != 2
            or program.get('function') != FUNCTION
            or type(program.get('arguments')) is not dict
            or set(program['arguments']) != {'coordinate','items',
                'expectedCellChangeId','expectedDetailChangeId'}):
        raise ValueError('V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED')
    args=program['arguments']
    if (type(args['items']) is not list or len(args['items'])>500
            or type(args['expectedCellChangeId']) is not str
            or len(args['expectedCellChangeId'])>200
            or type(args['expectedDetailChangeId']) is not str
            or len(args['expectedDetailChangeId'])>200):
        raise ValueError('V2_LINE_DETAIL_INVALID')
    try:
        coordinate=Coordinate.from_mapping(args['coordinate'])
        items=tuple(LineItem(row['description'],NumericCell.from_wire(
            present=True,amount=row['amount']).amount) for row in args['items']
            if type(row) is dict and set(row)=={'description','amount'}
            and isinstance(row['description'],str) and _FILTER_ID.fullmatch(row['description']))
    except (TypeError,ValueError,KeyError) as error:
        raise ValueError('V2_LINE_DETAIL_INVALID') from error
    if (len(items)!=len(args['items'])
            or any(not _FILTER_ID.fullmatch(identifier)
                   for pair in coordinate.members for identifier in pair)):
        raise ValueError('V2_LINE_DETAIL_INVALID')
    # The publication owner also validates the exact sum before any preview.
    prepare_detail_items(items)
    _detail_program(coordinate,items,args['expectedCellChangeId'],
                    args['expectedDetailChangeId'])
    return coordinate,items,args['expectedCellChangeId'],args['expectedDetailChangeId']


def normalized_v2(values) -> dict:
    coordinate,items,cell_change,detail_change=values
    return {'languageVersion':2,'function':FUNCTION,'arguments':{
        'coordinate':dict(coordinate.members),
        'items':[{'description':item.description,
                  'amount':format(item.amount,'f')} for item in items],
        'expectedCellChangeId':cell_change,
        'expectedDetailChangeId':detail_change}}


def detail_preview_evidence(values) -> dict:
    """Project the existing native total kernel; never infer a parent result."""
    coordinate, items, _, _ = values
    total, _ = prepare_detail_items(items)
    return {'coordinate': dict(coordinate.members), 'replacement': 'complete_set',
            'itemCount': len(items), 'present': True,
            'total': {'type': 'AmountLiteral', 'decimal': format(total, 'f')}}


def line_detail_program_contract() -> dict:
    from .metadata_read_contract import DIALECT, obj, read_example
    from .postgres_numeric_catalog import program_schema
    from .persistence_contract import AMOUNT_INTEGER_DIGITS, AMOUNT_SCALE

    identifier = {'type': 'string', 'minLength': 1,
                  'pattern': '^' + _FILTER_ID.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
    coordinate = {'type': 'object', 'minProperties': 1,
                  'propertyNames': identifier, 'additionalProperties': identifier}
    change_id = {'type': 'string', 'maxLength': 200}
    amount = {'type': 'string', 'minLength': 1,
              'description': 'Finite exact NUMERIC(28,8) decimal string. The fixed compiler validates syntax, precision and the complete-set sum.'}
    arguments = obj({
        'coordinate': coordinate, 'expectedCellChangeId': change_id, 'expectedDetailChangeId': change_id,
        'items': {'type': 'array', 'maxItems': 500, 'items': obj({
            'description': {**identifier, 'maxLength': 80}, 'amount': amount})},
    })
    decimal = {'type': 'string', 'pattern':
               rf'^-?[0-9]{{1,{AMOUNT_INTEGER_DIGITS}}}(?:\.[0-9]{{1,{AMOUNT_SCALE}}})?(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    detail = obj({'coordinate': coordinate, 'replacement': {'const': 'complete_set'},
                  'itemCount': {**revision, 'maximum': 500}, 'present': {'const': True},
                  'total': obj({'type': {'const': 'AmountLiteral'}, 'decimal': decimal})})
    preview_shape = {'$schema': DIALECT, **obj({
        'languageVersion': {'type': 'integer', 'const': 2}, 'function': {'const': FUNCTION},
        'programDigest': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'},
        'revisionVector': obj(dict.fromkeys(('metadata_revision', 'data_revision', 'policy_revision'), revision)),
        'previewToken': {'type': 'string', 'minLength': 1}, 'changedCount': {'const': 1},
        'detail': detail,
    })}
    submission = job_submission_schema()
    published = {'$schema': DIALECT, **obj({
        'changedCount': {'const': 1}, 'committedRevision': {'type': 'integer', 'minimum': 1},
    })}
    fresh = {'coordinate': {'Metric': 'Input'}, 'expectedCellChangeId': '', 'expectedDetailChangeId': '',
             'items': [{'description': 'Forecast base', 'amount': '1.25000000'},
                       {'description': 'Forecast correction', 'amount': '-0.25000000'}]}
    return {
        'schemaCoverage': 'program-and-result', 'schemaDialect': DIALECT,
        'programSchema': program_schema(FUNCTION, arguments),
        'resultSchema': submission, 'resultSchemaScope': 'envelope',
        'programContract': {
            'owner': 'PostgresLineDetailStore and compile_program',
            'examples': [
                read_example(FUNCTION, fresh, name='Replace all supporting lines with an exact total',
                    binding='Use a permitted full coordinate in a disposable application with no prior numeric event or supporting detail. The reviewed total is 1.00000000.'),
                read_example(FUNCTION, {**fresh, 'items': [], 'expectedCellChangeId': '17:1',
                    'expectedDetailChangeId': '17:1'}, name='Replace the current detail with an empty set',
                    binding='Read a current numeric change ID and confirm a LineDetailLiteral at the same authorized snapshot. Replace both sample IDs with that shared current change ID. The empty set leaves a present zero.'),
            ],
            'outputSchemas': {
                'preview': {'schema': preview_shape, 'scope': 'envelope',
                            'surface': 'preview_v2_program or browser /api/preview'},
                'submission': {'schema': submission, 'scope': 'envelope',
                               'surface': 'submit_v2_program or browser /api/submit'},
                'publishedResult': {'schema': published, 'scope': 'result',
                                    'surface': 'result from read_v2_job after publication'},
            },
            'semanticRules': [
                'Provide the complete ordered set for one full coordinate. The fixed owner sums the signed decimals and commits detail and numeric total at one change identity.',
                'Use facts.cube.scan with includeMissing to obtain the current numeric change ID. Use facts.export.page at the same authorized snapshot to confirm whether the value is a LineDetailLiteral. Existing detail shares the numeric change ID.',
                'The two expected change IDs independently assert current versions. An empty ID means no corresponding current version. An inaccessible coordinate requires fresh authorized selection before review.',
                'Preview and publication use current dimensional write authority and the same planning ReplaceDetail decision. Review the exact total before submitting the unchanged request and preserve its operation key.',
            ],
            'recovery': ('After an uncertain submit, use the original admission operation_id with read_v2_job, '
                         'or operationId with browser /api/job. Use the returned jobId to read its committed receipt. '
                         'Refresh supporting lines and both change IDs before a new preview after a conflict.'),
        },
    }


def preview(language,scope:ApplicationScope,program:dict)->dict:
    values=compile_program(program);coordinate,_,cell_change,detail_change=values
    normalized=normalized_v2(values)
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            db.execute('SET TRANSACTION READ ONLY')
            configure_statement_timeout(db,5000)
            PostgresNumericFactStore._set_scope(db,scope)
            access=PostgresAccessChecker.check_in_transaction(db,language.identity,scope,
                'write',function=FUNCTION,arguments=normalized['arguments'])
            state=db.execute('''SELECT a.status,s.processing_mode,
                s.metadata_revision,s.data_revision,s.policy_revision,s.security_revision
                FROM epm.application_state s JOIN epm.application a
                USING(workspace_id,application_id) WHERE s.workspace_id=%s
                AND s.application_id=%s''',(scope.workspace_id,
                scope.application_id)).fetchone()
            if (state is None or state['status']!='Active'
                    or state['processing_mode']!='Active'):
                raise ValueError('APPLICATION_NOT_WRITABLE')
            authorize_coordinates(db,language.identity,scope,(coordinate,),
                                  kind=AccessKind.WRITE,expected_access=access)
            current=PostgresLineDetailStore._current_inputs(db,scope,coordinate,False)
            PostgresLineDetailStore._validate_inputs(current,cell_change,detail_change)
            enforce_active_planning_policy(db,scope,writes=((coordinate,'ReplaceDetail'),),
                                          workflow_role=access.role)
            after=db.execute('''SELECT metadata_revision,policy_revision,security_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                (scope.workspace_id,scope.application_id)).fetchone()
            if after is None:
                raise ValueError('APPLICATION_UNAVAILABLE')
            for revision in ('metadata','policy','security'):
                if after[f'{revision}_revision']!=state[f'{revision}_revision']:
                    raise ValueError(f'STALE_{revision.upper()}_REVISION')
            if PostgresAccessChecker.check_in_transaction(db,language.identity,scope,
                    'write',function=FUNCTION,arguments=normalized['arguments'])!=access:
                raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
            revisions={key:state[key] for key in ('metadata_revision',
                'data_revision','policy_revision')}
    token,digest=language._sign_preview(scope,FUNCTION,normalized,revisions)
    return {'languageVersion':2,'function':FUNCTION,'programDigest':digest,
            'revisionVector':revisions,'previewToken':token,'changedCount':1,
            'detail': detail_preview_evidence(values)}


def submit(language,scope,program,*,preview_token,idempotency_key,
           depends_on_job_ids=(),execution_authority=None):
    values=compile_program(program);normalized=normalized_v2(values)
    queue=PostgresJobQueue(language.dsn,identity=language.identity)
    previous=queue.replay_batch(scope,idempotency_key=idempotency_key,
        function_name=FUNCTION,mutations=values,
        depends_on_job_ids=depends_on_job_ids,
        execution_authority=execution_authority)
    if previous is not None:return previous
    payload=language._unpack_preview(scope,FUNCTION,preview_token)
    from .postgres_language_v2 import _canonical_digest
    if (set(payload)!={'scope','identity','function','programDigest','revisions',
                       'expiresAt'}
            or payload['programDigest']!=_canonical_digest(normalized)):
        raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    revisions=payload['revisions']
    return queue.submit_detail(scope,idempotency_key=idempotency_key,
        coordinate=values[0],items=values[1],
        expected_cell_change_id=values[2],expected_detail_change_id=values[3],
        expected_metadata_revision=revisions['metadata_revision'],
        expected_data_revision=revisions['data_revision'],
        expected_policy_revision=revisions['policy_revision'],
        depends_on_job_ids=depends_on_job_ids,
        execution_authority=execution_authority)
