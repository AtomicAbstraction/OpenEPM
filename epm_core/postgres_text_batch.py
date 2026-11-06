"""Ordinary text batch: read-only preparation and atomic publication.

Preparation may overlap for disjoint coordinates.  The caller owns the short
application publication fence and must recheck prepared inputs before publish.
"""
from psycopg.types.json import Jsonb
from .persistence_contract import MutationReceipt
from .postgres_fact_batch import execute,validate_coordinates,numeric_inputs,ensure_coordinates


def prepare(db,scope,mutations,*,ordinal_offset=0):
    rows=[{'ordinal':n+ordinal_offset,'series_key':m.coordinate.series_key,'members':dict(m.coordinate.members),
        'op':m.kind.value,'value':m.value,'expected_change_id':m.expected_change_id} for n,m in enumerate(mutations,1)]
    validate_coordinates(db,scope,rows)
    for declared,current in zip(rows,numeric_inputs(db,scope,rows)):
        if current['members'] is not None and current['members']!=declared['members']:raise ValueError('COORDINATE_HASH_COLLISION')
        if current['has_detail']:raise ValueError('COORDINATE_HAS_LINE_DETAIL')
        if declared['op']=='set' and current['present']:raise ValueError('COORDINATE_HAS_NUMERIC_VALUE')
        if current['text_change_id']!=declared['expected_change_id']:raise ValueError('STALE_CELL_CHANGE_ID')
        declared['before_value']=current['text_value'] if current['text_present'] else None
        declared['prior_present']=current['text_present']
        declared['numeric_present']=current['present']
    return rows


def recheck_prepared_inputs(db,scope,rows):
    """Reject target/type drift after preparation rather than rebasing it."""
    validate_coordinates(db,scope,rows)
    for declared,current in zip(rows,numeric_inputs(db,scope,rows)):
        if current['members'] is not None and current['members']!=declared['members']:raise ValueError('COORDINATE_HASH_COLLISION')
        if current['has_detail']:raise ValueError('COORDINATE_HAS_LINE_DETAIL')
        if declared['op']=='set' and current['present']:raise ValueError('COORDINATE_HAS_NUMERIC_VALUE')
        if current['text_change_id']!=declared['expected_change_id']:raise ValueError('STALE_CELL_CHANGE_ID')
        current_value=current['text_value'] if current['text_present'] else None
        if (current['text_present']!=declared['prior_present']
                or current_value!=declared['before_value']
                or current['present']!=declared['numeric_present']):
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
    execute(db,'''INSERT INTO epm.text_fact_event(workspace_id,application_id,coordinate_id,
        operation_id,line_ordinal,kind,prior_present,prior_value,present,resulting_value,change_id,committed_revision)
        SELECT %s,%s,c.coordinate_id,%s,i.ordinal,i.op,i.prior_present,i.before_value,i.op='set',i.value,
            %s::text||':'||i.ordinal,%s FROM jsonb_to_recordset(%s::jsonb)
            i(series_key text,ordinal int,op text,value text,prior_present bool,before_value text)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key''',
        (scope.workspace_id,scope.application_id,operation_id,revision,revision,Jsonb(rows),scope.workspace_id,scope.application_id))
    execute(db,'''INSERT INTO epm.text_cell_projection(workspace_id,application_id,coordinate_id,
        present,text_value,change_id,last_revision,projection_generation)
        SELECT %s,%s,c.coordinate_id,i.op='set',i.value,%s::text||':'||i.ordinal,%s,(SELECT epm.active_projection_generation())
        FROM jsonb_to_recordset(%s::jsonb) i(series_key text,ordinal int,op text,value text)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key
        ON CONFLICT(workspace_id,application_id,projection_generation,coordinate_id) DO UPDATE SET
        present=EXCLUDED.present,text_value=EXCLUDED.text_value,change_id=EXCLUDED.change_id,last_revision=EXCLUDED.last_revision''',
        (scope.workspace_id,scope.application_id,revision,revision,Jsonb(rows),scope.workspace_id,scope.application_id))
    return MutationReceipt(operation_id,revision,len(rows))


def apply(db,scope,mutations,*,revision,operation_id,command_digest,actor_id,
          payload_digest,write_control=True,ordinal_offset=0):
    rows=prepare(db,scope,mutations,ordinal_offset=ordinal_offset)
    return publish_prepared(db,scope,rows,revision=revision,
        operation_id=operation_id,command_digest=command_digest,
        actor_id=actor_id,payload_digest=payload_digest,
        write_control=write_control)
