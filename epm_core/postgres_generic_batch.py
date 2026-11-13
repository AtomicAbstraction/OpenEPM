"""Opaque JSON value preparation and atomic publication.

Disjoint series may prepare concurrently.  Callers must recheck the prepared
native JSONB text/change identities under their short publication fence.
"""
from uuid import uuid4
from psycopg.types.json import Jsonb
from .postgres_fact_batch import execute


def prepare(db,scope,table_id,changes):
    rows=[{**c,'ordinal':n,'new_id':uuid4().hex,'event_id':uuid4().hex} for n,c in enumerate(changes,1)]
    current=execute(db,'''SELECT i.ordinal,c.series_key IS NOT NULL AS found,
        coalesce(c.change_id,'') change_id,c.value::text value_text
        FROM jsonb_to_recordset(%s::jsonb) i(ordinal int,"seriesKey" text)
        LEFT JOIN epm.generic_fact_current c ON c.workspace_id=%s AND c.application_id=%s
          AND c.table_id=%s AND c.series_key=i."seriesKey" ORDER BY i.ordinal''',
        (Jsonb(rows),scope.workspace_id,scope.application_id,table_id)).fetchall()
    for row,prior in zip(rows,current):
        if row['expectedChangeId']!=prior['change_id']:raise ValueError('STALE_CELL_CHANGE_ID')
        if row['action']=='Delete' and not prior['found']:raise ValueError('GENERIC_FACT_NOT_PRESENT')
        row['before_found']=prior['found'];row['before_value_text']=prior['value_text']
    return rows


def recheck_prepared_inputs(db,scope,table_id,rows):
    current=execute(db,'''SELECT i.ordinal,c.series_key IS NOT NULL AS found,
        coalesce(c.change_id,'') change_id,c.value::text value_text
        FROM jsonb_to_recordset(%s::jsonb) i(ordinal int,"seriesKey" text)
        LEFT JOIN epm.generic_fact_current c ON c.workspace_id=%s AND c.application_id=%s
          AND c.table_id=%s AND c.series_key=i."seriesKey" ORDER BY i.ordinal''',
        (Jsonb(rows),scope.workspace_id,scope.application_id,table_id)).fetchall()
    for row,prior in zip(rows,current):
        if (row['expectedChangeId']!=prior['change_id']
                or row['before_found']!=prior['found']
                or row['before_value_text']!=prior['value_text']):
            raise ValueError('STALE_CELL_CHANGE_ID')


def publish_prepared(db,scope,table_id,rows,*,revision,operation_id,actor_id):
    # Events precede current mutation so before_value is copied natively, without
    # decoding/re-encoding JSON numbers or losing values removed by DELETE.
    execute(db,'''INSERT INTO epm.generic_fact_event(workspace_id,application_id,event_id,table_id,series_key,
        operation_id,action,before_value,after_value,before_change_id,resulting_change_id,actor_id,committed_revision)
        SELECT %s,%s,i.event_id,%s,i."seriesKey",%s,
          CASE WHEN i.action='Delete' THEN 'Delete' WHEN c.series_key IS NULL THEN 'Create' ELSE 'Update' END,
          c.value,CASE WHEN i.action='Delete' THEN NULL ELSE i.value END,
          coalesce(c.change_id,''),i.new_id,%s,%s
        FROM jsonb_to_recordset(%s::jsonb) i("seriesKey" text,action text,value jsonb,new_id text,event_id text)
        LEFT JOIN epm.generic_fact_current c ON c.workspace_id=%s AND c.application_id=%s
          AND c.table_id=%s AND c.series_key=i."seriesKey"''',
        (scope.workspace_id,scope.application_id,table_id,operation_id,actor_id,revision,Jsonb(rows),
         scope.workspace_id,scope.application_id,table_id))
    execute(db,'''INSERT INTO epm.generic_fact_projection(workspace_id,application_id,table_id,series_key,value,change_id,last_revision,projection_generation)
        SELECT %s,%s,%s,i."seriesKey",i.value,i.new_id,%s,(SELECT epm.active_projection_generation())
        FROM jsonb_to_recordset(%s::jsonb) i("seriesKey" text,action text,value jsonb,new_id text) WHERE i.action='Set'
        ON CONFLICT(workspace_id,application_id,projection_generation,table_id,series_key) DO UPDATE SET
          value=EXCLUDED.value,change_id=EXCLUDED.change_id,last_revision=EXCLUDED.last_revision,
          updated_at=transaction_timestamp()''',(scope.workspace_id,scope.application_id,table_id,revision,Jsonb(rows)))
    execute(db,'''DELETE FROM epm.generic_fact_projection c USING jsonb_to_recordset(%s::jsonb) i("seriesKey" text,action text)
        WHERE c.projection_generation=(SELECT epm.active_projection_generation()) AND c.workspace_id=%s AND c.application_id=%s AND c.table_id=%s
          AND c.series_key=i."seriesKey" AND i.action='Delete' ''',
        (Jsonb(rows),scope.workspace_id,scope.application_id,table_id))
    return [{'seriesKey':r['seriesKey'],'changeId':'' if r['action']=='Delete' else r['new_id'],
        'deleted':r['action']=='Delete'} for r in rows]


def apply(db,scope,table_id,changes,*,revision,operation_id,actor_id):
    rows=prepare(db,scope,table_id,changes)
    return publish_prepared(db,scope,table_id,rows,revision=revision,
        operation_id=operation_id,actor_id=actor_id)
