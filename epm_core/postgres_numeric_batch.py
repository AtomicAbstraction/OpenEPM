"""Ordinary numeric batch: exact preparation and atomic set publication.

Preparation is read-only and may run concurrently for disjoint coordinates.
The caller must still acquire the short application publication fence, recheck
the prepared inputs and current authority, and only then publish the rows.
"""
from psycopg.types.json import Jsonb
from .persistence_contract import NumericCell,MutationReceipt
from .postgres_fact_batch import execute,validate_coordinates,numeric_inputs,ensure_coordinates


def prepare(db,scope,mutations,*,ordinal_offset=0):
    rows=[{'ordinal':n+ordinal_offset,'series_key':m.coordinate.series_key,'members':dict(m.coordinate.members),
        'op':m.kind.value,'amount':str(m.amount) if m.amount is not None else None,
        'expected_change_id':m.expected_change_id} for n,m in enumerate(mutations,1)]
    validate_coordinates(db,scope,rows)
    for declared,current in zip(rows,numeric_inputs(db,scope,rows)):
        if current['members'] is not None and current['members']!=declared['members']:
            raise ValueError('COORDINATE_HASH_COLLISION')
        if current['has_detail']:raise ValueError('COORDINATE_HAS_LINE_DETAIL')
        if declared['op']!='clear' and current['text_present']:raise ValueError('COORDINATE_HAS_TEXT_VALUE')
        if current['change_id']!=declared['expected_change_id']:raise ValueError('STALE_CELL_CHANGE_ID')
        declared['before_present']=current['present']
        declared['before_amount']=format(current['amount'],'f') if current['present'] else '0'
    calculated=execute(db,'''WITH effects AS(
        SELECT i.*,CASE i.op WHEN 'set' THEN i.amount WHEN 'add' THEN i.before_amount+i.amount
            ELSE NULL END AS after_amount
        FROM jsonb_to_recordset(%s::jsonb) i(ordinal int,series_key text,op text,amount numeric,before_amount numeric))
        SELECT ordinal,after_amount,coalesce(after_amount,0)-before_amount AS delta
        FROM effects ORDER BY ordinal''',(Jsonb(rows),)).fetchall()
    # Validation/serialization is local; arithmetic is PostgreSQL exact NUMERIC.
    for row,effect in zip(rows,calculated):
        cell=NumericCell(effect['after_amount'] is not None,effect['after_amount'],'prepared')
        row['amount']=cell.wire_amount();row['delta']=format(effect['delta'],'f')
    return rows


def recheck_prepared_inputs(db,scope,rows):
    """Fence changes to every target after read-only preparation.

    Other application coordinates may have committed while preparation ran;
    that is safe.  A target coordinate, type, detail or expected-change drift
    is not safe and must fail rather than silently recompute a prepared write.
    """
    validate_coordinates(db,scope,rows)
    for declared,current in zip(rows,numeric_inputs(db,scope,rows)):
        if current['members'] is not None and current['members']!=declared['members']:
            raise ValueError('COORDINATE_HASH_COLLISION')
        if current['has_detail']:raise ValueError('COORDINATE_HAS_LINE_DETAIL')
        if declared['op']!='clear' and current['text_present']:
            raise ValueError('COORDINATE_HAS_TEXT_VALUE')
        if current['change_id']!=declared['expected_change_id']:
            raise ValueError('STALE_CELL_CHANGE_ID')
        current_amount=(format(current['amount'],'f') if current['present'] else '0')
        if (current['present']!=declared['before_present']
                or current_amount!=declared['before_amount']):
            raise ValueError('STALE_CELL_CHANGE_ID')


def publish_prepared(db,scope,rows,*,revision,operation_id,command_digest,
                     actor_id,payload_digest,write_control=True):
    ensure_coordinates(db,scope,rows)
    if write_control:
        execute(db,'''UPDATE epm.application_state SET data_revision=data_revision+1,commit_revision=%s
        WHERE workspace_id=%s AND application_id=%s''',(revision,scope.workspace_id,scope.application_id))
        execute(db,'''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
        command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
        (scope.workspace_id,scope.application_id,operation_id,command_digest,actor_id,revision,
         Jsonb({'changedCount':len(rows),'payloadDigest':payload_digest})))
    execute(db,'''INSERT INTO epm.numeric_fact_event(workspace_id,application_id,coordinate_id,
        operation_id,line_ordinal,kind,delta,present,resulting_amount,change_id,committed_revision)
        SELECT %s,%s,c.coordinate_id,%s,i.ordinal,i.op,i.delta,i.op<>'clear',i.amount,
            %s::text||':'||i.ordinal,%s FROM jsonb_to_recordset(%s::jsonb)
            i(series_key text,ordinal int,op text,amount numeric,delta numeric)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key''',
        (scope.workspace_id,scope.application_id,operation_id,revision,revision,Jsonb(rows),scope.workspace_id,scope.application_id))
    execute(db,'''INSERT INTO epm.numeric_cell_projection(workspace_id,application_id,coordinate_id,
        present,amount,change_id,last_revision,projection_generation)
        SELECT %s,%s,c.coordinate_id,i.op<>'clear',i.amount,%s::text||':'||i.ordinal,%s,(SELECT epm.active_projection_generation())
        FROM jsonb_to_recordset(%s::jsonb) i(series_key text,ordinal int,op text,amount numeric)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key
        ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id) DO UPDATE SET
        present=EXCLUDED.present,amount=EXCLUDED.amount,change_id=EXCLUDED.change_id,last_revision=EXCLUDED.last_revision''',
        (scope.workspace_id,scope.application_id,revision,revision,Jsonb(rows),scope.workspace_id,scope.application_id))
    return MutationReceipt(operation_id,revision,len(rows))


def apply(db,scope,mutations,*,revision,operation_id,command_digest,actor_id,
          payload_digest,write_control=True,ordinal_offset=0):
    rows=prepare(db,scope,mutations,ordinal_offset=ordinal_offset)
    return publish_prepared(db,scope,rows,revision=revision,
        operation_id=operation_id,command_digest=command_digest,
        actor_id=actor_id,payload_digest=payload_digest,
        write_control=write_control)
