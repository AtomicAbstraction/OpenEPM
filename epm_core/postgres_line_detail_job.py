"""Strict V2 admission for atomic supporting detail and its numeric total."""
from __future__ import annotations

from .persistence_contract import ApplicationScope, Coordinate, LineItem, NumericCell
from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_jobs import (PostgresJobQueue, _DETAIL_FUNCTION,
                            _detail_program)
from .postgres_numeric_store import PostgresNumericFactStore
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


FUNCTION = _DETAIL_FUNCTION


def compile_program(program: object):
    if (type(program) is not dict
            or set(program) != {'languageVersion','function','arguments'}
            or program.get('languageVersion') != 2
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
            if type(row) is dict and set(row)=={'description','amount'})
    except (TypeError,ValueError,KeyError) as error:
        raise ValueError('V2_LINE_DETAIL_INVALID') from error
    if len(items)!=len(args['items']):
        raise ValueError('V2_LINE_DETAIL_INVALID')
    # This also proves the exact total fits the authoritative numeric type.
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


def preview(language,scope:ApplicationScope,program:dict)->dict:
    values=compile_program(program);coordinate,_,cell_change,detail_change=values
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,language.identity,scope,
                'write',function=FUNCTION,arguments=normalized_v2(values))
            state=db.execute('''SELECT a.status,s.processing_mode,
                s.metadata_revision,s.data_revision,s.policy_revision
                FROM epm.application_state s JOIN epm.application a
                USING(workspace_id,application_id) WHERE s.workspace_id=%s
                AND s.application_id=%s''',(scope.workspace_id,
                scope.application_id)).fetchone()
            if (state is None or state['status']!='Active'
                    or state['processing_mode']!='Active'):
                raise ValueError('APPLICATION_NOT_WRITABLE')
            axes={row['dimension_id'] for row in db.execute('''SELECT dimension_id
                FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
                AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
                (scope.workspace_id,scope.application_id)).fetchall()}
            if set(dict(coordinate.members))!=axes:
                raise ValueError('COORDINATE_DIMENSIONS_MISMATCH')
            found=db.execute('''SELECT count(*) AS n FROM jsonb_to_recordset(%s::jsonb)
                AS x(dimension_id text,member_id text) JOIN epm.member m ON
                (m.workspace_id,m.application_id,m.dimension_id,m.member_id)=
                (%s,%s,x.dimension_id,x.member_id) AND m.status='Active' ''',
                (Jsonb([{'dimension_id':d,'member_id':m}
                    for d,m in coordinate.members]),scope.workspace_id,
                 scope.application_id)).fetchone()
            if found['n']!=len(coordinate.members):
                raise ValueError('COORDINATE_MEMBER_UNAVAILABLE')
            current=db.execute('''SELECT c.members,COALESCE(n.change_id,'') cell_change,
                COALESCE(d.change_id,'') detail_change,COALESCE(t.present,false) text_present
                FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n USING
                (workspace_id,application_id,coordinate_id)
                LEFT JOIN epm.line_detail_current d USING
                (workspace_id,application_id,coordinate_id)
                LEFT JOIN epm.text_cell_current t USING
                (workspace_id,application_id,coordinate_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s''',
                (scope.workspace_id,scope.application_id,
                 coordinate.series_key)).fetchone()
            if current is not None and current['members']!=dict(coordinate.members):
                raise ValueError('COORDINATE_HASH_COLLISION')
            if cell_change!=(current['cell_change'] if current else ''):
                raise ValueError('STALE_CELL_CHANGE_ID')
            if detail_change!=(current['detail_change'] if current else ''):
                raise ValueError('STALE_DETAIL_CHANGE_ID')
            if current and current['text_present']:
                raise ValueError('COORDINATE_HAS_TEXT_VALUE')
            locked=db.execute('''SELECT 1 FROM epm.cube_write_scope_lock WHERE
                workspace_id=%s AND application_id=%s AND status='Locked'
                AND (scope_all OR %s::jsonb @> scope_members) LIMIT 1''',
                (scope.workspace_id,scope.application_id,
                 Jsonb(dict(coordinate.members)))).fetchone()
            if locked:raise ValueError('PLANNING_SLICE_LOCKED')
            revisions={key:state[key] for key in ('metadata_revision',
                'data_revision','policy_revision')}
    normalized=normalized_v2(values)
    token,digest=language._sign_preview(scope,FUNCTION,normalized,revisions)
    return {'languageVersion':2,'function':FUNCTION,'programDigest':digest,
            'revisionVector':revisions,'previewToken':token,'changedCount':1}


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
