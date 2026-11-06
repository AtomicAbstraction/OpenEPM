"""Current parent-scoped IC contributions, shared by Full and own-source FX."""
from decimal import Decimal


def ic_contributions(db,scope,coordinate_ids,parent_id):
    ic_by_coordinate={}
    ic_rows = db.execute('''SELECT target.coordinate_id AS selected_id,
        p.generation_id,p.published_revision,g.signed_residual,
        g.matched_magnitude,g.source_metadata_revision,
        g.source_policy_revision,l.line_ordinal,l.coordinate_id,
        l.signed_amount,l.source_change_id,
        current.change_id AS current_change_id
        FROM epm.ic_elimination_publication p
        JOIN epm.ic_elimination_generation g ON
            g.workspace_id=p.workspace_id
            AND g.application_id=p.application_id
            AND g.generation_id=p.generation_id
            AND g.parent_entity_member_id=p.parent_entity_member_id
            AND g.pair_key=p.pair_key
        JOIN epm.ic_elimination_line target ON
            target.workspace_id=p.workspace_id
            AND target.application_id=p.application_id
            AND target.generation_id=p.generation_id
            AND target.coordinate_id=ANY(%s::bigint[])
        JOIN epm.ic_elimination_line l ON
            l.workspace_id=p.workspace_id
            AND l.application_id=p.application_id
            AND l.generation_id=p.generation_id
        LEFT JOIN epm.numeric_cell_current current ON
            current.workspace_id=l.workspace_id
            AND current.application_id=l.application_id
            AND current.coordinate_id=l.coordinate_id AND current.present
        WHERE p.workspace_id=%s AND p.application_id=%s
        AND p.parent_entity_member_id=%s
        ORDER BY target.coordinate_id,p.generation_id,l.line_ordinal
        LIMIT 401''',
        (coordinate_ids,scope.workspace_id,scope.application_id,
         parent_id)).fetchall()
    if len(ic_rows) > 400:
        raise ValueError('FULL_AGGREGATE_IC_LINE_LIMIT')
    state = db.execute('''SELECT metadata_revision,policy_revision
        FROM epm.application_state WHERE workspace_id=%s
        AND application_id=%s''',
        (scope.workspace_id,scope.application_id)).fetchone()
    grouped = {}
    for row in ic_rows:
        grouped.setdefault(row['selected_id'], []).append(row)
    for point_id, lines in grouped.items():
        if (len(lines) != 2
                or len({line['generation_id'] for line in lines}) != 1
                or {line['line_ordinal'] for line in lines} != {1,2}
                or sum((line['signed_amount'] for line in lines),
                       Decimal(0)) != 0):
            raise ValueError('FULL_AGGREGATE_IC_LINEAGE_INVALID')
        if (lines[0]['source_metadata_revision'] !=
                state['metadata_revision']
                or lines[0]['source_policy_revision'] !=
                state['policy_revision']
                or any(line['source_change_id'] !=
                       line['current_change_id'] for line in lines)):
            raise ValueError('FULL_AGGREGATE_IC_SOURCE_STALE')
        selected = [line for line in lines
                    if line['coordinate_id'] == point_id]
        if len(selected) != 1:
            raise ValueError('FULL_AGGREGATE_IC_LINEAGE_INVALID')
        ic_by_coordinate[point_id] = {
            'generationId': lines[0]['generation_id'],
            'publishedRevision': lines[0]['published_revision'],
            'lineOrdinal': selected[0]['line_ordinal'],
            'signedAmount': selected[0]['signed_amount'],
            'matchedMagnitude': lines[0]['matched_magnitude'],
            'signedResidual': lines[0]['signed_residual']}
    return ic_by_coordinate
