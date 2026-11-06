"""Shared fixed relational coordinate/input stages; no per-cell SQL calls."""
from psycopg.types.json import Jsonb
from .postgres_processing_limits import configure_statement_timeout


def execute(db,query,arguments):
    configure_statement_timeout(db,5000)
    return db.execute(query,arguments)


def validate_coordinates(db,scope,rows):
    axes={r['dimension_id'] for r in execute(db,'''SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role IS DISTINCT FROM 'Currency' ''',(scope.workspace_id,scope.application_id))}
    if any(set(row['members'])!=axes for row in rows):
        raise ValueError('COORDINATE_DIMENSIONS_MISMATCH')
    if execute(db,'''SELECT 1 FROM jsonb_to_recordset(%s::jsonb) i(members jsonb)
        CROSS JOIN LATERAL jsonb_each_text(i.members) pair
        LEFT JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
        AND m.dimension_id=pair.key AND m.member_id=pair.value AND m.status='Active'
        WHERE m.member_id IS NULL LIMIT 1''',(Jsonb(rows),scope.workspace_id,scope.application_id)).fetchone():
        raise ValueError('COORDINATE_MEMBER_UNAVAILABLE')


def numeric_inputs(db,scope,rows):
    # Keep each input bounded to its unique scoped point. The LIMIT barriers
    # prevent stale statistics from joining all coordinates to broad secured
    # generation views before applying the small authored input set.
    return execute(db,'''SELECT i.series_key,c.members,c.coordinate_id,
        coalesce(n.change_id,'') change_id,coalesce(n.present,false) present,n.amount,
        coalesce(t.present,false) text_present,coalesce(t.change_id,'') text_change_id,t.text_value,
        d.coordinate_id IS NOT NULL has_detail
        FROM jsonb_to_recordset(%s::jsonb) i(series_key text,ordinal int)
        LEFT JOIN LATERAL (
            SELECT c.workspace_id,c.application_id,c.members,c.coordinate_id
            FROM epm.coordinate c WHERE c.workspace_id=%s AND c.application_id=%s
              AND c.series_key=i.series_key LIMIT 1) c ON true
        LEFT JOIN LATERAL (
            SELECT n.change_id,n.present,n.amount FROM epm.numeric_cell_current n
            WHERE n.workspace_id=c.workspace_id AND n.application_id=c.application_id
              AND n.coordinate_id=c.coordinate_id LIMIT 1) n ON true
        LEFT JOIN LATERAL (
            SELECT t.present,t.change_id,t.text_value FROM epm.text_cell_current t
            WHERE t.workspace_id=c.workspace_id AND t.application_id=c.application_id
              AND t.coordinate_id=c.coordinate_id LIMIT 1) t ON true
        LEFT JOIN LATERAL (
            SELECT d.coordinate_id FROM epm.line_detail_current d
            WHERE d.workspace_id=c.workspace_id AND d.application_id=c.application_id
              AND d.coordinate_id=c.coordinate_id LIMIT 1) d ON true
        ORDER BY i.ordinal''',(Jsonb(rows),scope.workspace_id,scope.application_id)).fetchall()


def ensure_coordinates(db,scope,rows):
    execute(db,'''INSERT INTO epm.coordinate(workspace_id,application_id,series_key,members)
        SELECT %s,%s,i.series_key,i.members FROM jsonb_to_recordset(%s::jsonb) i(series_key text,members jsonb)
        ON CONFLICT DO NOTHING''',(scope.workspace_id,scope.application_id,Jsonb(rows)))
    if execute(db,'''SELECT 1 FROM jsonb_to_recordset(%s::jsonb) i(series_key text,members jsonb)
        LEFT JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key
        WHERE c.coordinate_id IS NULL OR c.members IS DISTINCT FROM i.members LIMIT 1''',
        (Jsonb(rows),scope.workspace_id,scope.application_id)).fetchone():
        raise ValueError('COORDINATE_HASH_COLLISION')
    execute(db,'''INSERT INTO epm.coordinate_member_projection(workspace_id,application_id,coordinate_id,dimension_id,member_id,projection_generation)
        SELECT c.workspace_id,c.application_id,c.coordinate_id,pair.key,pair.value,(SELECT epm.active_projection_generation())
        FROM jsonb_to_recordset(%s::jsonb) i(series_key text,members jsonb)
        JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s AND c.series_key=i.series_key
        CROSS JOIN LATERAL jsonb_each_text(i.members) pair ON CONFLICT DO NOTHING''',
        (Jsonb(rows),scope.workspace_id,scope.application_id))
