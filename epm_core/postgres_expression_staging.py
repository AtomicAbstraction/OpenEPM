"""Private durable staging for restartable large expression execution.

The tables are keyed only by the admitted operation. They are not application
objects and expose no client-authored work controls.
"""
from __future__ import annotations

import re

from .persistence_contract import ApplicationScope


_JOB=re.compile(r"^[0-9a-f]{32}$")
_DIGEST=re.compile(r"^[0-9a-f]{64}$")


def ensure_stage(db,scope:ApplicationScope,*,operation_id:str,
        program_digest:str,revisions:tuple[int,int,int],
        expected_target_state_token:str|None,domain:dict,
        expected_row_count:int,window_size:int=500)->dict:
    if (not isinstance(scope,ApplicationScope)
            or not isinstance(operation_id,str) or not _JOB.fullmatch(operation_id)
            or not isinstance(program_digest,str) or not _DIGEST.fullmatch(program_digest)
            or not isinstance(revisions,tuple) or len(revisions)!=3
            or any(type(item) is not int or item<0 for item in revisions)
            or (expected_target_state_token is not None and
                (not isinstance(expected_target_state_token,str) or
                 not _DIGEST.fullmatch(expected_target_state_token)))
            or not isinstance(domain,dict)
            or not isinstance(domain.get('relationId'),str)
            or not isinstance(domain.get('relationStateToken'),str)
            or not _DIGEST.fullmatch(domain['relationStateToken'])
            or not isinstance(domain.get('relationDigest'),str)
            or not _DIGEST.fullmatch(domain['relationDigest'])
            or type(expected_row_count) is not int
            or not 0<=expected_row_count<=100_000
            or type(window_size) is not int or not 1<=window_size<=500):
        raise ValueError('EXPRESSION_STAGE_ARGUMENT_INVALID')
    values=(scope.workspace_id,scope.application_id,operation_id,
        program_digest,*revisions,expected_target_state_token,
        domain['relationId'],domain['relationStateToken'],
        domain['relationDigest'],expected_row_count,window_size)
    db.execute('''INSERT INTO epm.expression_result_staging(
        workspace_id,application_id,operation_id,program_digest,
        expected_metadata_revision,expected_data_revision,
        expected_policy_revision,expected_target_state_token,relation_id,
        relation_state_token,relation_digest,expected_row_count,window_size)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,application_id,operation_id) DO NOTHING''',values)
    row=db.execute('''SELECT program_digest,expected_metadata_revision,
        expected_data_revision,expected_policy_revision,
        expected_target_state_token,relation_id,relation_state_token,
        relation_digest,expected_row_count,window_size,
        (SELECT count(*) FROM epm.expression_result_staging_row staged_row
          WHERE staged_row.workspace_id=stage.workspace_id
            AND staged_row.application_id=stage.application_id
            AND staged_row.operation_id=stage.operation_id) AS staged_row_count
        FROM epm.expression_result_staging stage
        WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
        (scope.workspace_id,scope.application_id,operation_id)).fetchone()
    expected=(program_digest,*revisions,expected_target_state_token,
        domain['relationId'],domain['relationStateToken'],
        domain['relationDigest'],expected_row_count,window_size)
    observed=tuple(row[key] for key in ('program_digest',
        'expected_metadata_revision','expected_data_revision',
        'expected_policy_revision','expected_target_state_token','relation_id',
        'relation_state_token','relation_digest','expected_row_count',
        'window_size')) if row is not None else None
    if observed!=expected:
        raise ValueError('EXPRESSION_STAGE_PIN_CONFLICT')
    return {'expectedRowCount':expected_row_count,
            'stagedRowCount':row['staged_row_count'],
            'complete':row['staged_row_count']==expected_row_count,
            'windowSize':window_size}


def require_complete_stage(db,scope:ApplicationScope,*,operation_id:str,
                           expected_row_count:int)->dict:
    row=db.execute('''SELECT stage.expected_row_count,
        count(staged.relation_row_id) AS total
        FROM epm.expression_result_staging stage
        LEFT JOIN epm.expression_result_staging_row staged
          ON staged.workspace_id=stage.workspace_id
         AND staged.application_id=stage.application_id
         AND staged.operation_id=stage.operation_id
        WHERE stage.workspace_id=%s AND stage.application_id=%s
          AND stage.operation_id=%s GROUP BY stage.expected_row_count''',(
        scope.workspace_id,scope.application_id,operation_id)).fetchone()
    if (row is None or row['expected_row_count']!=expected_row_count
            or row['total']!=expected_row_count):
        raise ValueError('EXPRESSION_STAGE_INCOMPLETE')
    return {'rowCount':row['total']}


def delete_stage(db,scope:ApplicationScope,*,operation_id:str)->int:
    return db.execute('''DELETE FROM epm.expression_result_staging
        WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(
        scope.workspace_id,scope.application_id,operation_id)).rowcount
