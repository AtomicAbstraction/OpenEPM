"""Sealed hierarchy selection for generic typed-expression reductions."""
from __future__ import annotations

import json
import re
from hashlib import sha256

from psycopg.types.json import Jsonb
from .postgres_hierarchies import identifier as hierarchy_identifier

from .postgres_expression import (FUNCTION, HIERARCHY_REDUCTION_COMPILER,
    HIERARCHY_REDUCTION_PLAN_DIGEST, compile_expression_program,
    decode_expression_program)


COMPILER = HIERARCHY_REDUCTION_COMPILER
PLAN_DIGEST = HIERARCHY_REDUCTION_PLAN_DIGEST
MAX_MEMBERS = 100
MAX_PRESENT_SOURCES = 100
MAX_OUTPUT_GROUPS = 1
_ID = re.compile(r'[^\x00]{1,200}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value) or value != value.strip():
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_ID_INVALID')
    return value


def normalize_request(program):
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != FUNCTION
            or not isinstance(program.get('arguments'), dict)):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_PROGRAM_INVALID')
    args = program['arguments']
    if set(args) != {'sourceMembers', 'expression', 'reduceSelection', 'resultKey'}:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_ARGUMENTS_INVALID')
    source = args['sourceMembers']; selection = args['reduceSelection']
    if (not isinstance(source, dict) or len(source) > 127
            or any(_id(axis) != axis or _id(member) != member
                   for axis, member in source.items())
            or not isinstance(selection, dict)
            or set(selection) - {'hierarchyId'} != {'dimensionId', 'kind', 'rootMemberId',
                'membershipSemantics', 'targetMemberId',
                'measures'}
            or selection.get('kind') not in ('Children', 'Descendants', 'Leaves')
            or selection.get('membershipSemantics') != 'UniqueMember'
            or selection.get('measures') not in (
                ['SumAmount', 'CountPresent'],
                ['AverageAmount', 'CountPresent'])):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_SELECTION_INVALID')
    axis = _id(selection['dimensionId'])
    if axis in source:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_GRAIN_INVALID')
    if not isinstance(args['resultKey'],str) or not _KEY.fullmatch(
            args['resultKey']):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_ARGUMENTS_INVALID')
    return {'sourceMembers': dict(sorted((_id(k), _id(v))
        for k, v in source.items())), 'expression': args['expression'],
        'reduceSelection': {'dimensionId': axis, 'kind': selection['kind'],
            'rootMemberId': _id(selection['rootMemberId']),
            **({'hierarchyId': hierarchy_identifier(selection['hierarchyId'])}
               if 'hierarchyId' in selection else {}),
            'membershipSemantics': 'UniqueMember',
            'targetMemberId': _id(selection['targetMemberId']),
            'measures': list(selection['measures'])},
        'resultKey': args['resultKey']}


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False).encode()).hexdigest()


def _current_hierarchy(db, scope, dimension, hierarchy_id=None):
    """Resolve the one current chosen tree, defaulting only when omitted."""
    return db.execute('''SELECT s.state_token,s.hierarchy_id,s.metadata_revision,
          s.membership_semantics
        FROM epm.hierarchy_state s JOIN epm.hierarchy_definition d
        USING(workspace_id,application_id,dimension_id,hierarchy_id)
        WHERE s.workspace_id=%s AND s.application_id=%s AND s.dimension_id=%s
        AND d.status='Active' AND s.hierarchy_id=COALESCE(%s,
          epm.default_hierarchy_id(s.workspace_id,s.application_id,s.dimension_id))''',
        (scope.workspace_id, scope.application_id, dimension, hierarchy_id)).fetchone()


def resolve(db, scope, program, state, *, expected_target_state_token):
    request = normalize_request(program); selection = request['reduceSelection']
    axes = db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        ORDER BY dimension_id''', (scope.workspace_id,
        scope.application_id)).fetchall()
    fact_axes = [row['dimension_id'] for row in axes
                 if row['model_role'] != 'Currency']
    currency_axes = {row['dimension_id'] for row in axes
                     if row['model_role'] == 'Currency'}
    axis = selection['dimensionId']
    if (axis in currency_axes or axis not in fact_axes
            or set(request['sourceMembers']) != set(fact_axes) - {axis}):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_GRAIN_INVALID')
    lookups = [{'dimension_id': key, 'member_id': value}
               for key, value in request['sourceMembers'].items()]
    lookups.extend(({'dimension_id': axis, 'member_id': member}
                    for member in (selection['rootMemberId'],
                                   selection['targetMemberId'])))
    unavailable = db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
        i(dimension_id text,member_id text) LEFT JOIN epm.member m
        ON m.workspace_id=%s AND m.application_id=%s
        AND m.dimension_id=i.dimension_id AND m.member_id=i.member_id
        AND m.status='Active' WHERE m.member_id IS NULL LIMIT 1''',
        (Jsonb(lookups), scope.workspace_id, scope.application_id)).fetchone()
    if unavailable:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_MEMBER_UNAVAILABLE')
    hierarchy = _current_hierarchy(db, scope, axis, selection.get('hierarchyId'))
    if (hierarchy is None
            or hierarchy['membership_semantics'] != 'unique_member'
            or hierarchy['metadata_revision'] != state['metadata_revision']):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_HIERARCHY_STALE')
    rows = db.execute('''SELECT DISTINCT h.descendant_member_id member_id
        FROM epm.hierarchy_closure h JOIN epm.member m
        ON m.workspace_id=h.workspace_id AND m.application_id=h.application_id
        AND m.dimension_id=h.dimension_id
        AND m.member_id=h.descendant_member_id AND m.status='Active'
        WHERE h.workspace_id=%s
        AND h.application_id=%s AND h.dimension_id=%s AND h.hierarchy_id=%s
        AND h.state_token=%s
        AND h.ancestor_member_id=%s AND h.min_depth>0
        AND (%s<>'Children' OR h.min_depth=1)
        AND (%s<>'Leaves' OR NOT EXISTS (SELECT 1 FROM epm.hierarchy_closure c
          WHERE c.workspace_id=h.workspace_id AND c.application_id=h.application_id
          AND c.dimension_id=h.dimension_id AND c.hierarchy_id=h.hierarchy_id
          AND c.state_token=h.state_token
          AND c.ancestor_member_id=h.descendant_member_id AND c.min_depth>0))
        ORDER BY h.descendant_member_id LIMIT %s''', (scope.workspace_id,
        scope.application_id, axis, hierarchy['hierarchy_id'], hierarchy['state_token'],
        selection['rootMemberId'], selection['kind'], selection['kind'],
        MAX_MEMBERS + 1)).fetchall()
    members = sorted(row['member_id'] for row in rows)
    if not 1 <= len(members) <= MAX_MEMBERS:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_EXPANSION_LIMIT')
    if selection['targetMemberId'] in members:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_TARGET_OVERLAP')
    layout = _digest({'factAxes': fact_axes})
    context = {'format': 'hierarchy-reduction-v1', 'dimensionId': axis,
        'kind': selection['kind'], 'rootMemberId': selection['rootMemberId'],
        'hierarchyStateToken': hierarchy['state_token'],
        'hierarchyId': hierarchy['hierarchy_id'],
        'membershipSemantics': 'UniqueMember',
        'resolvedMemberIds': members, 'membershipDigest': _digest(members),
        'layoutDigest': layout, 'metadataRevision': state['metadata_revision']}
    explicit = {'languageVersion': 2, 'function': FUNCTION, 'arguments': {
        'sourceMembers': request['sourceMembers'],
        'expression': request['expression'], 'resultKey': request['resultKey'],
        'reduceMemberSet': {'dimensionId': axis, 'sourceMemberIds': members,
            'targetMemberId': selection['targetMemberId'],
            'measures': selection['measures']}}}
    return compile_expression_program(explicit,
        expected_target_state_token=expected_target_state_token,
        published_inputs=(), reduction_context=context)


def validate_admission(program, digest):
    if _digest(program) != digest:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_DIGEST_MISMATCH')
    plan = decode_expression_program(program)
    if plan.reduction_context is None:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_PROGRAM_INVALID')
    return plan


def validate_publication(db, scope, plan):
    context = plan.reduction_context
    if context is None:
        return
    axis = context['dimensionId']; members = list(context['resolvedMemberIds'])
    current = _current_hierarchy(db, scope, axis, context.get('hierarchyId'))
    if current is None:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_CONTEXT_STALE')
    axes = db.execute('''SELECT dimension_id FROM epm.dimension WHERE
        workspace_id=%s AND application_id=%s AND status='Active'
        AND model_role IS DISTINCT FROM 'Currency' ORDER BY dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()
    selected = db.execute('''SELECT DISTINCT h.descendant_member_id member_id
        FROM epm.hierarchy_closure h JOIN epm.member m
        ON m.workspace_id=h.workspace_id AND m.application_id=h.application_id
        AND m.dimension_id=h.dimension_id
        AND m.member_id=h.descendant_member_id AND m.status='Active'
        WHERE h.workspace_id=%s AND h.application_id=%s
        AND h.dimension_id=%s AND h.hierarchy_id=%s AND h.state_token=%s
        AND h.ancestor_member_id=%s AND h.min_depth>0
        AND (%s<>'Children' OR h.min_depth=1)
        AND (%s<>'Leaves' OR NOT EXISTS (SELECT 1 FROM epm.hierarchy_closure c
          WHERE c.workspace_id=h.workspace_id AND c.application_id=h.application_id
          AND c.dimension_id=h.dimension_id AND c.hierarchy_id=h.hierarchy_id
          AND c.state_token=h.state_token
          AND c.ancestor_member_id=h.descendant_member_id AND c.min_depth>0))
        ORDER BY h.descendant_member_id LIMIT %s''', (scope.workspace_id,
        scope.application_id, axis, context['hierarchyId'],
        context['hierarchyStateToken'],
        context['rootMemberId'], context['kind'], context['kind'],
        MAX_MEMBERS + 1)).fetchall()
    current_members = sorted(row['member_id'] for row in selected)
    if (current is None
            or current['state_token'] != context['hierarchyStateToken']
            or current['metadata_revision'] != context['metadataRevision']
            or _digest({'factAxes': [row['dimension_id'] for row in axes]}) !=
                context['layoutDigest']
            or current_members != members
            or _digest(members) != context['membershipDigest']):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_CONTEXT_STALE')


def cardinality(db, scope, plan):
    """Count present source coordinates separately from output groups."""
    if plan.reduction_context is None or plan.reduce_member_set is None:
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_CONTEXT_INVALID')
    axis, members, _, _ = plan.reduce_member_set
    row = db.execute('''SELECT count(*)::bigint AS present_source_count,
        count(DISTINCT (c.members-%s::text))::bigint AS grouped_output_count
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
        USING(workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
        AND c.members @> %s::jsonb AND c.members->>%s=ANY(%s::text[])''',
        (axis, scope.workspace_id, scope.application_id,
         Jsonb(dict(plan.source_members)), axis, list(members))).fetchone()
    sources = row['present_source_count']; outputs = row['grouped_output_count']
    if (type(sources) is not int or type(outputs) is not int
            or not 0 <= sources <= MAX_PRESENT_SOURCES
            or not 0 <= outputs <= MAX_OUTPUT_GROUPS
            or (sources == 0) != (outputs == 0)):
        raise ValueError('EXPRESSION_HIERARCHY_REDUCTION_CARDINALITY_LIMIT')
    return {'presentSourceCount': sources, 'groupedOutputCount': outputs}

