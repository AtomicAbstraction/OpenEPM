"""Current parent-scoped IC contributions, shared by Full and own-source FX."""
from decimal import Decimal


def ic_contributions(db,scope,coordinate_ids,parent_id):
    ic_by_coordinate={}
    ic_rows = db.execute('''SELECT target.coordinate_id AS selected_id,
        s.state_token,s.signed_residual,
        s.matched_magnitude,s.source_metadata_revision,
        s.source_policy_revision,l.line_ordinal,l.coordinate_id,
        l.signed_amount,l.source_change_id,
        current.change_id AS current_change_id
        FROM epm.ic_elimination_state s
        JOIN epm.ic_elimination_current_line target ON
            target.workspace_id=s.workspace_id
            AND target.application_id=s.application_id
            AND target.parent_entity_member_id=s.parent_entity_member_id
            AND target.pair_key=s.pair_key
            AND target.coordinate_id=ANY(%s::bigint[])
        JOIN epm.ic_elimination_current_line l ON
            l.workspace_id=s.workspace_id
            AND l.application_id=s.application_id
            AND l.parent_entity_member_id=s.parent_entity_member_id
            AND l.pair_key=s.pair_key
        LEFT JOIN epm.numeric_cell_current current ON
            current.workspace_id=l.workspace_id
            AND current.application_id=l.application_id
            AND current.coordinate_id=l.coordinate_id AND current.present
        WHERE s.workspace_id=%s AND s.application_id=%s
        AND s.parent_entity_member_id=%s
        AND s.status='PublishedUnreviewed'
        ORDER BY target.coordinate_id,s.pair_key,l.line_ordinal
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
                or len({line['state_token'] for line in lines}) != 1
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
            'resultStateToken': lines[0]['state_token'],
            'lineOrdinal': selected[0]['line_ordinal'],
            'signedAmount': selected[0]['signed_amount'],
            'matchedMagnitude': lines[0]['matched_magnitude'],
            'signedResidual': lines[0]['signed_residual']}
    return ic_by_coordinate
