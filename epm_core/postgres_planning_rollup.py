"""Bounded exact hierarchy rollup over generic current numeric facts.

Only present leaf cells contribute. One fixed full-coordinate parent result is
atomically replaced with every source change ID recorded.
This generic sum does not apply consolidation signs, ownership, FX or policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .current_object_contract import require_state_token
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION = 'facts.planning.rollup.sum'
COMPILER = 'planning-rollup-sum-v1'
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql', 'inputGrain': 'leaf_full_coordinate',
    'outputGrain': 'parent_full_coordinate', 'hierarchyPaths': 'unique',
    'sourceType': 'numeric', 'rounding': 'exact_sum_8',
})
POLICY_COMPILER = 'planning-rollup-sum-policy-v1'
POLICY_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'engine': 'postgres_exact_sql', 'inputGrain': 'leaf_full_coordinate',
    'outputGrain': 'parent_full_coordinate', 'hierarchyPaths': 'unique',
    'sourceType': 'numeric', 'rounding': 'exact_sum_8',
    'policyContract': 'openepm-planning-operation-policy-v1',
    'sharedMemberPolicy': 'unique_member',
})
PLACEMENT_COMPILER = 'planning-rollup-explicit-placement-v2'
PLACEMENT_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 2,
    'engine': 'postgres_exact_sql', 'inputGrain': 'explicit_direct_leaf_placements',
    'outputGrain': 'parent_full_coordinate',
    'placementIdentity': 'active_relationship_id_with_parent_child_snapshot',
    'sharedMemberPolicy': 'placement_explicit',
    'recursion': 'unsupported', 'sourceType': 'numeric',
    'rounding': 'exact_sum_8',
})
POLICY_PLACEMENT_COMPILER = 'planning-rollup-explicit-placement-policy-v2'
POLICY_PLACEMENT_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 2,
    'engine': 'postgres_exact_sql', 'inputGrain': 'explicit_direct_leaf_placements',
    'outputGrain': 'parent_full_coordinate',
    'placementIdentity': 'active_relationship_id_with_parent_child_snapshot',
    'sharedMemberPolicy': 'placement_explicit',
    'policyContract': 'openepm-planning-operation-policy-v1',
    'recursion': 'unsupported', 'sourceType': 'numeric',
    'rounding': 'exact_sum_8',
})
RECURSIVE_PLACEMENT_COMPILER = 'planning-rollup-recursive-placement-v3'
RECURSIVE_PLACEMENT_PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 3,
    'engine': 'postgres_exact_sql', 'inputGrain': 'explicit_recursive_leaf_placement_paths',
    'outputGrain': 'parent_full_coordinate',
    'placementIdentity': 'ordered_active_relationship_path_with_edge_snapshots',
    'sharedMemberPolicy': 'placement_explicit',
    'repeatedPlacement': 'one_contribution_per_explicit_path',
    'bounds': {'paths':100,'depth':32,'sourceContributions':500},
    'sourceType': 'numeric', 'rounding': 'exact_sum_8',
})
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')

_SOURCE = '''FROM epm.hierarchy_closure h
    JOIN epm.coordinate_member cm
    ON cm.workspace_id=h.workspace_id
    AND cm.application_id=h.application_id
    AND cm.dimension_id=h.dimension_id
    AND cm.member_id=h.descendant_member_id
    JOIN epm.coordinate c ON c.workspace_id=cm.workspace_id
    AND c.application_id=cm.application_id
    AND c.coordinate_id=cm.coordinate_id
    JOIN epm.numeric_cell_current n
    ON n.workspace_id=c.workspace_id
    AND n.application_id=c.application_id
    AND n.coordinate_id=c.coordinate_id AND n.present
    WHERE h.workspace_id=%s AND h.application_id=%s
    AND h.dimension_id=%s AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id)
    AND h.state_token=%s
    AND h.ancestor_member_id=%s AND h.min_depth>0
    AND h.path_count=1 AND c.members @> %s::jsonb
    AND NOT EXISTS (SELECT 1 FROM epm.relationship edge
        WHERE edge.workspace_id=h.workspace_id
        AND edge.application_id=h.application_id
        AND edge.dimension_id=h.dimension_id
        AND edge.parent_member_id=h.descendant_member_id
        AND edge.hierarchy_id=epm.default_hierarchy_id(edge.workspace_id,edge.application_id,edge.dimension_id) AND edge.status='Active')'''

_PLACEMENT_SOURCE = '''FROM epm.relationship placement
    JOIN epm.coordinate_member cm
    ON cm.workspace_id=placement.workspace_id
    AND cm.application_id=placement.application_id
    AND cm.dimension_id=placement.dimension_id
    AND cm.member_id=placement.child_member_id
    JOIN epm.coordinate c ON c.workspace_id=cm.workspace_id
    AND c.application_id=cm.application_id
    AND c.coordinate_id=cm.coordinate_id
    JOIN epm.numeric_cell_current n
    ON n.workspace_id=c.workspace_id
    AND n.application_id=c.application_id
    AND n.coordinate_id=c.coordinate_id AND n.present
    WHERE placement.workspace_id=%s AND placement.application_id=%s
    AND placement.dimension_id=%s AND placement.parent_member_id=%s
    AND placement.relationship_id=ANY(%s::text[])
    AND placement.hierarchy_id=epm.default_hierarchy_id(placement.workspace_id,placement.application_id,placement.dimension_id) AND placement.status='Active' AND c.members @> %s::jsonb
    AND NOT EXISTS (SELECT 1 FROM epm.relationship edge
        WHERE edge.workspace_id=placement.workspace_id
        AND edge.application_id=placement.application_id
        AND edge.dimension_id=placement.dimension_id
        AND edge.parent_member_id=placement.child_member_id
        AND edge.hierarchy_id=placement.hierarchy_id AND edge.status='Active')'''

_RECURSIVE_PLACEMENT_SOURCE = '''FROM jsonb_to_recordset(%s::jsonb)
    path(path_id text,path_ordinal integer,terminal_relationship_id text)
    JOIN epm.relationship placement ON placement.workspace_id=%s
    AND placement.application_id=%s AND placement.dimension_id=%s
    AND placement.relationship_id=path.terminal_relationship_id
    AND placement.hierarchy_id=epm.default_hierarchy_id(placement.workspace_id,placement.application_id,placement.dimension_id) AND placement.status='Active'
    JOIN epm.coordinate_member cm ON cm.workspace_id=placement.workspace_id
    AND cm.application_id=placement.application_id
    AND cm.dimension_id=placement.dimension_id
    AND cm.member_id=placement.child_member_id
    JOIN epm.coordinate c ON c.workspace_id=cm.workspace_id
    AND c.application_id=cm.application_id AND c.coordinate_id=cm.coordinate_id
    JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id
    AND n.application_id=c.application_id AND n.coordinate_id=c.coordinate_id
    AND n.present WHERE c.members @> %s::jsonb
    AND NOT EXISTS (SELECT 1 FROM epm.relationship edge
      WHERE edge.workspace_id=placement.workspace_id
      AND edge.application_id=placement.application_id
      AND edge.dimension_id=placement.dimension_id
      AND edge.parent_member_id=placement.child_member_id
      AND edge.hierarchy_id=placement.hierarchy_id AND edge.status='Active')'''


@dataclass(frozen=True, slots=True)
class RollupPlan:
    dimension: str
    parent: str
    other_members: tuple[tuple[str, str], ...]
    result_key: str
    hierarchy_state_token: str
    expected_target_state_token: str | None
    placement_ids: tuple[str, ...] = ()
    placement_paths: tuple[tuple[str, ...], ...] = ()

    @property
    def target(self) -> Coordinate:
        return Coordinate.from_mapping({**dict(self.other_members),
                                        self.dimension: self.parent})

    @property
    def normalized_program(self) -> dict:
        return {'function': FUNCTION,
                'dimension': self.dimension, 'parent': self.parent,
                'otherMembers': dict(self.other_members),
                'resultKey': self.result_key,
                'hierarchyStateToken': self.hierarchy_state_token,
                'expectedTargetStateToken':
                    self.expected_target_state_token,
                'inputGrain': ('explicit_recursive_leaf_placement_paths'
                    if self.placement_paths else 'leaf_full_coordinate'),
                'outputGrain': 'parent_full_coordinate',
                'rounding': 'exact_sum_8',
                **({'placementIds':list(self.placement_ids)}
                   if self.placement_ids else {}),
                **({'placementPaths':[list(path) for path in self.placement_paths]}
                   if self.placement_paths else {})}

    def source_params(self, scope: ApplicationScope) -> tuple:
        if self.placement_paths:
            return (Jsonb(_path_payload(self)),scope.workspace_id,
                    scope.application_id,self.dimension,
                    Jsonb(dict(self.other_members)))
        if self.placement_ids:
            return (scope.workspace_id, scope.application_id,
                    self.dimension, self.parent, list(self.placement_ids),
                    Jsonb(dict(self.other_members)))
        return (scope.workspace_id, scope.application_id,
                self.dimension, self.hierarchy_state_token, self.parent,
                Jsonb(dict(self.other_members)))


def _path_id(path: tuple[str,...]) -> str:
    return _canonical_digest(list(path))


def _path_payload(plan: RollupPlan) -> list[dict]:
    return [{'path_id':_path_id(path),'path_ordinal':ordinal,
             'terminal_relationship_id':path[-1]}
            for ordinal,path in enumerate(plan.placement_paths,1)]


def _validate_path_snapshots(plan: RollupPlan, edges: dict,
                             non_leaf_members: set[str]) -> list[dict]:
    details=[]
    for ordinal,path in enumerate(plan.placement_paths,1):
        if any(item not in edges for item in path):
            raise ValueError('ROLLUP_PLACEMENT_PATH_UNAVAILABLE')
        snapshots=[edges[item] for item in path]
        if snapshots[0]['parent_member_id']!=plan.parent or any(
                left['child_member_id']!=right['parent_member_id']
                for left,right in zip(snapshots,snapshots[1:])):
            raise ValueError('ROLLUP_PLACEMENT_PATH_DISCONTIGUOUS')
        members=[snapshots[0]['parent_member_id']]+[
            edge['child_member_id'] for edge in snapshots]
        if len(members)!=len(set(members)):
            raise ValueError('ROLLUP_PLACEMENT_PATH_CYCLE')
        terminal=snapshots[-1]
        if terminal['child_member_id'] in non_leaf_members:
            raise ValueError('ROLLUP_PLACEMENT_PATH_NOT_LEAF')
        details.append({'pathId':_path_id(path),'pathOrdinal':ordinal,
            'rootMemberId':plan.parent,'leafMemberId':terminal['child_member_id'],
            'relationshipIds':list(path),'edges':[{
                'edgeOrdinal':index,'relationshipId':edge['relationship_id'],
                'parentMemberId':edge['parent_member_id'],
                'childMemberId':edge['child_member_id']}
                for index,edge in enumerate(snapshots,1)]})
    return details


def enforce_rollup_target_policy(db,scope:ApplicationScope,plan:RollupPlan,
                                 workflow_role:str)->dict:
    from .postgres_planning_write_guard import enforce_active_planning_policy
    return enforce_active_planning_policy(
        db,scope,writes=((plan.target,'Set'),),
        workflow_role=workflow_role)


def compile_rollup_program(program: object, *, hierarchy_state_token: str,
                           expected_target_state_token: str | None) -> RollupPlan:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)
            or set(program['arguments']) not in (
                {'dimension', 'parent', 'otherMembers', 'resultKey'},
                {'dimension', 'parent', 'otherMembers', 'resultKey','placementIds'},
                {'dimension', 'parent', 'otherMembers', 'resultKey','placementPaths'})):
        raise ValueError('V2_ROLLUP_FUNCTION_OR_ARGUMENTS_INVALID')
    args = program['arguments']
    others = args['otherMembers']
    if (not isinstance(args['dimension'], str)
            or not 1 <= len(args['dimension']) <= 200
            or not isinstance(args['parent'], str)
            or not 1 <= len(args['parent']) <= 200
            or not isinstance(others, dict) or len(others) > 31
            or args['dimension'] in others
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in others.items())
            or not isinstance(args['resultKey'], str)
            or not _KEY.fullmatch(args['resultKey'])
            or not isinstance(hierarchy_state_token,str)
            or not re.fullmatch(r'[0-9a-f]{64}',hierarchy_state_token)):
        raise ValueError('V2_ROLLUP_ARGUMENTS_INVALID')
    if expected_target_state_token is not None:
        require_state_token(expected_target_state_token,
                            error='V2_ROLLUP_ARGUMENTS_INVALID')
    placements=args.get('placementIds',[])
    paths=args.get('placementPaths',[])
    if (not isinstance(placements,list)
            or any(not isinstance(item,str) or not 1<=len(item)<=200
                   for item in placements)
            or len(placements)!=len(set(placements))
            or ('placementIds' in args and not placements)
            or len(placements)>100):
        raise ValueError('ROLLUP_PLACEMENT_IDS_INVALID')
    if (not isinstance(paths,list) or len(paths)>100
            or ('placementPaths' in args and not paths)
            or any(not isinstance(path,list) or not 1<=len(path)<=32
                   or any(not isinstance(item,str) or not 1<=len(item)<=200
                          for item in path)
                   or len(path)!=len(set(path)) for path in paths)):
        raise ValueError('ROLLUP_PLACEMENT_PATHS_INVALID')
    normalized_paths=tuple(sorted(tuple(path) for path in paths))
    if len(normalized_paths)!=len(set(normalized_paths)):
        raise ValueError('ROLLUP_PLACEMENT_PATHS_INVALID')
    return RollupPlan(args['dimension'], args['parent'],
                      tuple(sorted(others.items())), args['resultKey'],
                      hierarchy_state_token, expected_target_state_token,
                      tuple(sorted(placements)),normalized_paths)


def decode_rollup_program(program: object) -> RollupPlan:
    if (not isinstance(program, dict)
            or set(program) not in ({'function', 'dimension', 'parent',
                                'otherMembers', 'resultKey',
                                'hierarchyStateToken',
                                'expectedTargetStateToken', 'inputGrain',
                                'outputGrain', 'rounding'},
                {'function', 'dimension', 'parent',
                 'otherMembers', 'resultKey', 'hierarchyStateToken',
                 'expectedTargetStateToken', 'inputGrain','outputGrain',
                 'rounding','placementIds'},
                {'function', 'dimension', 'parent',
                 'otherMembers', 'resultKey', 'hierarchyStateToken',
                 'expectedTargetStateToken', 'inputGrain','outputGrain',
                 'rounding','placementPaths'})
            or program['function'] != FUNCTION
            or program['inputGrain'] != ('explicit_recursive_leaf_placement_paths'
                    if 'placementPaths' in program else 'leaf_full_coordinate')
            or program['outputGrain'] != 'parent_full_coordinate'
            or program['rounding'] != 'exact_sum_8'):
        raise ValueError('UNSUPPORTED_ROLLUP_JOB_PROGRAM')
    plan = compile_rollup_program({
        'languageVersion': 2, 'function': FUNCTION,
        'arguments': {'dimension': program['dimension'],
                      'parent': program['parent'],
                      'otherMembers': program['otherMembers'],
                      'resultKey': program['resultKey'],
                      **({'placementIds':program['placementIds']}
                         if 'placementIds' in program else {}),
                      **({'placementPaths':program['placementPaths']}
                         if 'placementPaths' in program else {})}},
        hierarchy_state_token=program['hierarchyStateToken'],
        expected_target_state_token=
            program['expectedTargetStateToken'])
    if plan.normalized_program != program:
        raise ValueError('NONCANONICAL_ROLLUP_JOB_PROGRAM')
    return plan


def encode_policy_rollup_program(plan: RollupPlan, reusable_policy: dict) -> dict:
    required = {'policyId', 'policyDigest', 'metadataRevision',
                'policyRevision', 'authoredMetadataRevision',
                'authoredPolicyRevision', 'stateToken'}
    if not isinstance(reusable_policy, dict) or set(reusable_policy) != required:
        raise ValueError('ROLLUP_POLICY_PIN_INVALID')
    return {**plan.normalized_program, 'reusablePolicy': dict(reusable_policy)}


def decode_policy_rollup_program(program: object) -> tuple[RollupPlan, dict]:
    if not isinstance(program, dict) or 'reusablePolicy' not in program:
        raise ValueError('UNSUPPORTED_ROLLUP_POLICY_JOB_PROGRAM')
    policy = program['reusablePolicy']
    base = dict(program); base.pop('reusablePolicy')
    plan = decode_rollup_program(base)
    if encode_policy_rollup_program(plan, policy) != program:
        raise ValueError('NONCANONICAL_ROLLUP_POLICY_JOB_PROGRAM')
    return plan, policy


def _current_policy_pointer_matches(db, scope: ApplicationScope,
                                    policy: dict) -> bool:
    row = db.execute('''SELECT p.state_token,p.canonical_digest,
        a.metadata_revision,a.policy_revision
        FROM epm.planning_operation_policy p
        JOIN epm.application_state a ON a.workspace_id=p.workspace_id
         AND a.application_id=p.application_id
        WHERE p.workspace_id=%s AND p.application_id=%s
          AND p.policy_id=%s AND p.status='Active' ''',
        (scope.workspace_id, scope.application_id,
         policy.get('policyId'))).fetchone()
    return row is not None and all((
        row['canonical_digest'] == policy.get('policyDigest'),
        row['state_token'] == policy.get('stateToken'),
        row['metadata_revision'] == policy.get('metadataRevision'),
        row['policy_revision'] == policy.get('policyRevision')))


def current_hierarchy_state_token(db, scope: ApplicationScope,
                                  dimension: str) -> str:
    row = db.execute('''SELECT h.state_token FROM epm.hierarchy_state h
        JOIN epm.application_state s ON s.workspace_id=h.workspace_id
        AND s.application_id=h.application_id
        WHERE h.workspace_id=%s AND h.application_id=%s
        AND h.dimension_id=%s AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id) AND h.metadata_revision=s.metadata_revision''',
        (scope.workspace_id, scope.application_id, dimension)).fetchone()
    if row is None:
        raise ValueError('ROLLUP_HIERARCHY_NOT_CURRENT')
    return row['state_token']


def _source_sql(plan: RollupPlan) -> str:
    if plan.placement_paths:return _RECURSIVE_PLACEMENT_SOURCE
    return _PLACEMENT_SOURCE if plan.placement_ids else _SOURCE


def _source_coordinate_sql(plan: RollupPlan) -> str:
    """Return the eligible leaf-coordinate query before numeric filtering.

    Type validation must see text/detail-only leaves too.  Reusing the numeric
    source query directly would hide precisely those conflicts behind its
    inner join to ``numeric_cell_current``.
    """
    source = _source_sql(plan)
    standard_numeric_join = '''    JOIN epm.numeric_cell_current n
    ON n.workspace_id=c.workspace_id
    AND n.application_id=c.application_id
    AND n.coordinate_id=c.coordinate_id AND n.present
'''
    recursive_numeric_join = '''    JOIN epm.numeric_cell_current n ON n.workspace_id=c.workspace_id
    AND n.application_id=c.application_id AND n.coordinate_id=c.coordinate_id
    AND n.present WHERE'''
    if plan.placement_paths:
        coordinates = source.replace(recursive_numeric_join, '    WHERE', 1)
    else:
        coordinates = source.replace(standard_numeric_join, '', 1)
    if coordinates == source:
        raise RuntimeError('Rollup coordinate-source lowering is inconsistent')
    return coordinates


def validate_rollup_inputs(db, scope: ApplicationScope,
                           plan: RollupPlan) -> dict:
    axes = {row['dimension_id'] for row in db.execute('''SELECT dimension_id
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND status='Active' AND model_role IS DISTINCT FROM 'Currency' ''',
        (scope.workspace_id, scope.application_id)).fetchall()}
    if axes != set(dict(plan.other_members)) | {plan.dimension}:
        raise ValueError('ROLLUP_COORDINATE_GRAIN_MISMATCH')
    PostgresSourceBatch._check_scope_members(
        db, scope, dict(plan.other_members))
    PostgresSourceBatch._check_scope_members(
        db, scope, {plan.dimension: plan.parent})
    if current_hierarchy_state_token(db, scope, plan.dimension) != (
            plan.hierarchy_state_token):
        raise ValueError('ROLLUP_HIERARCHY_CHANGED')
    path_details=[]
    if plan.placement_paths:
        requested=sorted({edge for path in plan.placement_paths for edge in path})
        rows=db.execute('''SELECT r.relationship_id,r.parent_member_id,
            r.child_member_id FROM epm.relationship r WHERE r.workspace_id=%s
            AND r.application_id=%s AND r.dimension_id=%s
            AND r.relationship_id=ANY(%s::text[]) AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active'
            ORDER BY r.relationship_id''',(scope.workspace_id,
            scope.application_id,plan.dimension,requested)).fetchall()
        edges={row['relationship_id']:row for row in rows}
        if sorted(edges)!=requested:
            raise ValueError('ROLLUP_PLACEMENT_PATH_UNAVAILABLE')
        terminals={edges[path[-1]]['child_member_id'] for path in plan.placement_paths}
        non_leaf={row['parent_member_id'] for row in db.execute('''SELECT DISTINCT
            parent_member_id FROM epm.relationship WHERE workspace_id=%s
            AND application_id=%s AND dimension_id=%s
            AND parent_member_id=ANY(%s::text[]) AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' ''',(
            scope.workspace_id,scope.application_id,plan.dimension,
            sorted(terminals))).fetchall()}
        path_details=_validate_path_snapshots(plan,edges,non_leaf)
    if plan.placement_ids:
        placements=db.execute('''SELECT r.relationship_id,r.parent_member_id,
            r.child_member_id,NOT EXISTS(SELECT 1 FROM epm.relationship child
              WHERE child.workspace_id=r.workspace_id
               AND child.application_id=r.application_id
               AND child.dimension_id=r.dimension_id
               AND child.parent_member_id=r.child_member_id
               AND child.hierarchy_id=r.hierarchy_id AND child.status='Active') AS is_leaf
            FROM epm.relationship r WHERE r.workspace_id=%s
             AND r.application_id=%s AND r.dimension_id=%s
             AND r.parent_member_id=%s AND r.relationship_id=ANY(%s::text[])
             AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active' ORDER BY r.relationship_id''',(
            scope.workspace_id,scope.application_id,plan.dimension,
            plan.parent,list(plan.placement_ids))).fetchall()
        if tuple(row['relationship_id'] for row in placements)!=(
                plan.placement_ids):
            raise ValueError('ROLLUP_PLACEMENT_UNAVAILABLE')
        if any(not row['is_leaf'] for row in placements):
            raise ValueError('ROLLUP_PLACEMENT_RECURSION_UNSUPPORTED')
    ambiguous = None if (plan.placement_ids or plan.placement_paths) else db.execute('''SELECT 1 FROM epm.hierarchy_closure h
        WHERE h.workspace_id=%s AND h.application_id=%s
        AND h.dimension_id=%s AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id)
        AND h.state_token=%s
        AND h.ancestor_member_id=%s AND h.min_depth>0
        AND h.path_count<>1 LIMIT 1''',
        (scope.workspace_id, scope.application_id, plan.dimension,
         plan.hierarchy_state_token, plan.parent)).fetchone()
    if ambiguous:
        raise ValueError('ROLLUP_AMBIGUOUS_HIERARCHY_PATH')
    descendants = (len(path_details) if plan.placement_paths else
        len(placements) if plan.placement_ids else db.execute('''SELECT count(*) AS total
        FROM epm.hierarchy_closure h
        WHERE h.workspace_id=%s AND h.application_id=%s
        AND h.dimension_id=%s AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id)
        AND h.state_token=%s
        AND h.ancestor_member_id=%s AND h.min_depth>0
        AND NOT EXISTS (SELECT 1 FROM epm.relationship edge
            WHERE edge.workspace_id=h.workspace_id
            AND edge.application_id=h.application_id
            AND edge.dimension_id=h.dimension_id
            AND edge.parent_member_id=h.descendant_member_id
            AND edge.hierarchy_id=epm.default_hierarchy_id(edge.workspace_id,edge.application_id,edge.dimension_id) AND edge.status='Active')''',
        (scope.workspace_id, scope.application_id, plan.dimension,
         plan.hierarchy_state_token, plan.parent)).fetchone()['total'])
    if descendants == 0:
        raise ValueError('ROLLUP_PARENT_HAS_NO_LEAF_DESCENDANTS')
    conflicts = db.execute(f'''SELECT 1 FROM (
        SELECT c.workspace_id,c.application_id,c.coordinate_id
        {_source_coordinate_sql(plan)}) source
        LEFT JOIN epm.text_cell_current t
        ON t.workspace_id=source.workspace_id
        AND t.application_id=source.application_id
        AND t.coordinate_id=source.coordinate_id
        LEFT JOIN epm.line_detail_current d
        ON d.workspace_id=source.workspace_id
        AND d.application_id=source.application_id
        AND d.coordinate_id=source.coordinate_id
        WHERE (COALESCE(t.present,false) OR d.coordinate_id IS NOT NULL)
        LIMIT 1''',
        plan.source_params(scope)).fetchone()
    if conflicts:
        raise ValueError('ROLLUP_SOURCE_TYPE_UNSUPPORTED')
    target = plan.target
    target_conflict = db.execute('''SELECT 1 FROM epm.coordinate c
        LEFT JOIN epm.text_cell_current t
        ON t.workspace_id=c.workspace_id
        AND t.application_id=c.application_id
        AND t.coordinate_id=c.coordinate_id
        LEFT JOIN epm.line_detail_current d
        ON d.workspace_id=c.workspace_id
        AND d.application_id=c.application_id
        AND d.coordinate_id=c.coordinate_id
        WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s
        AND (c.members<>%s::jsonb OR COALESCE(t.present,false)
             OR d.coordinate_id IS NOT NULL) LIMIT 1''',
        (scope.workspace_id, scope.application_id, target.series_key,
         Jsonb(dict(target.members)))).fetchone()
    if target_conflict:
        raise ValueError('ROLLUP_TARGET_CONFLICT')
    summary = db.execute(f'''SELECT count(*) AS total,sum(n.amount) AS amount
        {_source_sql(plan)}''', plan.source_params(scope)).fetchone()
    if summary['total'] == 0:
        raise ValueError('ROLLUP_SOURCE_MISSING')
    if summary['total'] > 500:
        raise ValueError('ROLLUP_SOURCE_LIMIT')
    return {'sourceCount': summary['total'],
            'amount': summary['amount'],
            'hierarchyStateToken': plan.hierarchy_state_token,
            'target': dict(target.members),
            **({'placementPaths':path_details} if path_details else {})}


def enforce_rollup_dimensional_security(db,identity: VerifiedIdentity,
        scope: ApplicationScope,plan: RollupPlan) -> None:
    """Authorize every resolved numeric leaf and the exact parent output."""
    rows=db.execute(f'''SELECT DISTINCT c.members
        {_source_sql(plan)}''',
        plan.source_params(scope)).fetchall()
    sources=tuple(Coordinate.from_mapping(row['members']) for row in rows)
    if not sources or len(sources)>500:
        raise ValueError('ROLLUP_SOURCE_LIMIT')
    authorize_coordinates(db,identity,scope,sources,kind=AccessKind.READ)
    authorize_coordinates(
        db,identity,scope,(plan.target,),kind=AccessKind.WRITE)


class PostgresRollupPublisher:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def publish(self, claim: dict) -> dict:
        if (not isinstance(claim, dict)
                or not isinstance(claim.get('workspace_id'), str)
                or not isinstance(claim.get('application_id'), str)
                or not isinstance(claim.get('job_id'), str)
                or not _JOB.fullmatch(claim['job_id'])
                or not isinstance(claim.get('claimant'), str)
                or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    ''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                job = db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'])).fetchone()
                if (job is None or job['issuer'] != self.identity.issuer
                        or job['subject_id'] != self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                valid = db.execute('''SELECT %s::timestamptz >
                    clock_timestamp() AS unexpired''',
                    (job['lease_until'],)).fetchone()['unexpired']
                if (job['status'] != 'running'
                        or job['claim_generation'] != claim['claim_generation']
                        or job['claimant'] != claim['claimant'] or not valid):
                    raise ValueError('STALE_WORKER_FENCE')
                policy_job = job['compiler_version'] in (
                    POLICY_COMPILER, POLICY_PLACEMENT_COMPILER)
                placement_job = job['compiler_version'] == PLACEMENT_COMPILER
                recursive_job = job['compiler_version'] == RECURSIVE_PLACEMENT_COMPILER
                if (job['function_name'] != FUNCTION
                        or job['compiler_version'] not in (
                            COMPILER, POLICY_COMPILER, PLACEMENT_COMPILER,
                            POLICY_PLACEMENT_COMPILER,RECURSIVE_PLACEMENT_COMPILER)
                        or job['plan_digest'] != (POLICY_PLACEMENT_PLAN_DIGEST
                            if job['compiler_version']==POLICY_PLACEMENT_COMPILER
                            else POLICY_PLAN_DIGEST if policy_job
                            else RECURSIVE_PLACEMENT_PLAN_DIGEST if recursive_job
                            else PLACEMENT_PLAN_DIGEST
                            if placement_job else PLAN_DIGEST)
                        or job['program_digest'] != _canonical_digest(
                            job['normalized_program'])):
                    raise ValueError('UNSUPPORTED_ROLLUP_JOB_PROGRAM')
                if policy_job:
                    plan, reusable_policy = decode_policy_rollup_program(
                        job['normalized_program'])
                    if not _current_policy_pointer_matches(
                            db, scope, reusable_policy):
                        raise ValueError('PLANNING_POLICY_POINTER_STALE')
                else:
                    plan = decode_rollup_program(job['normalized_program'])
                if ((placement_job or job['compiler_version']==
                     POLICY_PLACEMENT_COMPILER) != bool(plan.placement_ids)):
                    raise ValueError('UNSUPPORTED_ROLLUP_JOB_PROGRAM')
                if recursive_job != bool(plan.placement_paths):
                    raise ValueError('UNSUPPORTED_ROLLUP_JOB_PROGRAM')
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] != job['expected_metadata_revision']
                        or state['data_revision'] != job['expected_data_revision']
                        or state['policy_revision'] != job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                pointer = db.execute('''SELECT state_token
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     plan.result_key)).fetchone()
                if (pointer['state_token'] if pointer else None) != (
                        plan.expected_target_state_token):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                summary = validate_rollup_inputs(db, scope, plan)
                enforce_rollup_dimensional_security(
                    db,self.identity,scope,plan)
                target = plan.target
                policy_evidence = enforce_rollup_target_policy(
                    db,scope,plan,access.role)
                # Materialize the full source set and lineage privately.  This
                # is the potentially dominant hierarchy scan; target
                # coordinate creation remains behind the final application
                # fence because its database trigger owns that lock contract.
                db.execute('''CREATE TEMP TABLE rollup_source_stage
                    (source_coordinate_id bigint NOT NULL,
                     source_amount numeric NOT NULL,
                     source_change_id text NOT NULL,
                     placement_relationship_id text,
                     placement_parent_member_id text,
                     placement_child_member_id text,
                     placement_path_id text,
                     placement_path_ordinal integer)
                    ON COMMIT DROP''')
                placement_select=(',placement.relationship_id,'
                    'placement.parent_member_id,placement.child_member_id'
                    if (plan.placement_ids or plan.placement_paths)
                    else ',NULL::text,NULL::text,NULL::text')
                path_select=(',path.path_id,path.path_ordinal'
                    if plan.placement_paths
                    else ',NULL::text,NULL::integer')
                staged_sources=db.execute(f'''INSERT INTO
                    pg_temp.rollup_source_stage
                    (source_coordinate_id,source_amount,source_change_id,
                     placement_relationship_id,
                     placement_parent_member_id,
                     placement_child_member_id,placement_path_id,
                     placement_path_ordinal)
                    SELECT c.coordinate_id,n.amount,n.change_id
                     {placement_select}{path_select}
                    {_source_sql(plan)}''',
                    plan.source_params(scope)).rowcount
                if staged_sources!=summary['sourceCount']:
                    raise ValueError('ROLLUP_SOURCE_COUNT_CHANGED')
                db.execute('''CREATE TEMP TABLE rollup_result_stage
                    (source_amount numeric NOT NULL,
                     source_change_id text NOT NULL,
                     amount numeric NOT NULL) ON COMMIT DROP''')
                digest_item=("placement_path_id || ':' || "
                    "source_coordinate_id::text || ':' || source_change_id"
                    if plan.placement_paths else
                    "source_coordinate_id::text || ':' || source_change_id")
                inserted=db.execute(f'''INSERT INTO
                    pg_temp.rollup_result_stage
                    (source_amount,source_change_id,amount)
                    SELECT sum(source_amount),
                      'rollup:' || encode(sha256(convert_to(
                        string_agg({digest_item},E'\\n' ORDER BY
                          {digest_item}),'UTF8')),'hex'),
                      sum(source_amount)
                    FROM pg_temp.rollup_source_stage''').rowcount
                if inserted != 1:
                    raise ValueError('ROLLUP_RESULT_COUNT_CHANGED')
                private_amount=db.execute('''SELECT amount FROM
                    pg_temp.rollup_result_stage''').fetchone()['amount']
                if private_amount!=summary['amount']:
                    raise ValueError('ROLLUP_RESULT_CHANGED')

                final_state=db.execute('''SELECT s.metadata_revision,
                    s.data_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                final_job=db.execute('''SELECT issuer,subject_id,status,
                    claim_generation,claimant,lease_until,function_name,
                    normalized_program,program_digest,plan_digest,
                    compiler_version,expected_metadata_revision,
                    expected_data_revision,expected_policy_revision
                    FROM epm.job WHERE workspace_id=%s AND application_id=%s
                    AND job_id=%s FOR UPDATE''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'])).fetchone()
                final_valid=(final_job is not None and db.execute(
                    '''SELECT %s::timestamptz > clock_timestamp()
                       AS unexpired''',
                    (final_job['lease_until'],)).fetchone()['unexpired'])
                immutable_job_fields=('issuer','subject_id','function_name',
                    'normalized_program','program_digest','plan_digest',
                    'compiler_version','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision')
                if (final_state is None or final_job is None
                        or any(final_job[key]!=job[key]
                               for key in immutable_job_fields)
                        or final_job['status']!='running'
                        or final_job['claim_generation']!=
                           claim['claim_generation']
                        or final_job['claimant']!=claim['claimant']
                        or not final_valid):
                    raise ValueError('STALE_WORKER_FENCE')
                final_access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write')
                if (final_state['application_status']!='Active'
                        or final_state['processing_mode']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (final_state['metadata_revision']!=
                        job['expected_metadata_revision']
                        or final_state['data_revision']!=
                        job['expected_data_revision']
                        or final_state['policy_revision']!=
                        job['expected_policy_revision']):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                if (policy_job and not _current_policy_pointer_matches(
                        db,scope,reusable_policy)):
                    raise ValueError('PLANNING_POLICY_POINTER_STALE')
                final_pointer=db.execute('''SELECT state_token
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                    AND result_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     plan.result_key)).fetchone()
                if (final_pointer['state_token']
                        if final_pointer else None)!=(
                            plan.expected_target_state_token):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                if validate_rollup_inputs(db,scope,plan)!=summary:
                    raise ValueError('ROLLUP_SOURCE_CHANGED')
                enforce_rollup_dimensional_security(
                    db,self.identity,scope,plan)
                policy_evidence=enforce_rollup_target_policy(
                    db,scope,plan,final_access.role)
                db.execute('''INSERT INTO epm.coordinate
                    (workspace_id,application_id,series_key,members)
                    VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING''',
                    (scope.workspace_id,scope.application_id,
                     target.series_key,Jsonb(dict(target.members))))
                coordinate=db.execute('''SELECT coordinate_id,members
                    FROM epm.coordinate WHERE workspace_id=%s
                    AND application_id=%s AND series_key=%s''',
                    (scope.workspace_id,scope.application_id,
                     target.series_key)).fetchone()
                if coordinate['members']!=dict(target.members):
                    raise ValueError('COORDINATE_HASH_COLLISION')
                db.execute('''INSERT INTO epm.coordinate_member_projection
                    (workspace_id,application_id,coordinate_id,
                     dimension_id,member_id,projection_generation)
                    SELECT %s,%s,%s,item.key,item.value,
                           (SELECT epm.active_projection_generation())
                    FROM jsonb_each_text(%s::jsonb) item
                    ON CONFLICT DO NOTHING''',
                    (scope.workspace_id,scope.application_id,
                     coordinate['coordinate_id'],
                     Jsonb(dict(target.members))))
                revision=final_state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_operation_staging
                    (workspace_id,application_id,generation_id,job_id,
                     result_key,source_commit_revision,
                     source_metadata_revision,source_policy_revision,
                     function_name,factor,row_count,published_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,1,%s)''',
                    (scope.workspace_id,scope.application_id,
                     claim['job_id'],claim['job_id'],plan.result_key,
                     state['commit_revision'],state['metadata_revision'],
                     state['policy_revision'],FUNCTION,revision))
                durable_result=db.execute('''INSERT INTO epm.calculation_result_staging
                    (workspace_id,application_id,generation_id,coordinate_id,
                     source_amount,source_change_id,amount)
                    SELECT %s,%s,%s,%s,source_amount,source_change_id,amount
                    FROM pg_temp.rollup_result_stage''',
                    (scope.workspace_id,scope.application_id,claim['job_id'],
                     coordinate['coordinate_id'])).rowcount
                if durable_result!=1:
                    raise ValueError('ROLLUP_RESULT_COUNT_CHANGED')
                if plan.placement_paths:
                    paths=summary['placementPaths']
                    headers=[{'path_id':item['pathId'],'path_ordinal':item['pathOrdinal'],
                        'root_member_id':item['rootMemberId'],
                        'leaf_member_id':item['leafMemberId'],
                        'relationship_count':len(item['relationshipIds'])} for item in paths]
                    inserted_paths=db.execute('''INSERT INTO epm.rollup_placement_path_staging
                        (workspace_id,application_id,generation_id,coordinate_id,
                         placement_path_id,path_ordinal,hierarchy_dimension_id,
                         hierarchy_state_token,root_member_id,leaf_member_id,relationship_count)
                        SELECT %s,%s,%s,%s,p.path_id,p.path_ordinal,%s,%s,
                         p.root_member_id,p.leaf_member_id,p.relationship_count
                        FROM jsonb_to_recordset(%s::jsonb)p(path_id text,
                         path_ordinal integer,root_member_id text,leaf_member_id text,
                         relationship_count integer)''',(scope.workspace_id,
                        scope.application_id,claim['job_id'],coordinate['coordinate_id'],
                        plan.dimension,plan.hierarchy_state_token,Jsonb(headers))).rowcount
                    if inserted_paths!=len(headers):raise ValueError('ROLLUP_PATH_COUNT_CHANGED')
                    edges=[{'path_id':item['pathId'],'edge_ordinal':edge['edgeOrdinal'],
                        'relationship_id':edge['relationshipId'],
                        'hierarchy_dimension_id':plan.dimension,
                        'parent_member_id':edge['parentMemberId'],
                        'child_member_id':edge['childMemberId']}
                        for item in paths for edge in item['edges']]
                    inserted_edges=db.execute('''INSERT INTO epm.rollup_placement_path_edge_staging
                        (workspace_id,application_id,generation_id,coordinate_id,
                         placement_path_id,edge_ordinal,relationship_id,
                         hierarchy_dimension_id,parent_member_id,child_member_id)
                         SELECT %s,%s,%s,%s,e.path_id,e.edge_ordinal,e.relationship_id,
                         e.hierarchy_dimension_id,
                         e.parent_member_id,e.child_member_id FROM jsonb_to_recordset(
                         %s::jsonb)e(path_id text,edge_ordinal integer,
                         relationship_id text,hierarchy_dimension_id text,
                         parent_member_id text,child_member_id text)''',(
                        scope.workspace_id,scope.application_id,claim['job_id'],
                        coordinate['coordinate_id'],Jsonb(edges))).rowcount
                    if inserted_edges!=len(edges):raise ValueError('ROLLUP_PATH_EDGE_COUNT_CHANGED')
                placement_columns = (',placement_relationship_id,'
                    'placement_parent_member_id,placement_child_member_id'
                    if (plan.placement_ids or plan.placement_paths) else '')
                path_columns=(',placement_path_id,placement_path_ordinal'
                    if plan.placement_paths else '')
                placement_values = (',s.placement_relationship_id,'
                    's.placement_parent_member_id,'
                    's.placement_child_member_id'
                    if (plan.placement_ids or plan.placement_paths) else '')
                path_values=(',s.placement_path_id,'
                    's.placement_path_ordinal'
                    if plan.placement_paths else '')
                lineage = db.execute(f'''INSERT INTO epm.rollup_source_lineage_staging
                    (workspace_id,application_id,generation_id,
                     coordinate_id,source_coordinate_id,source_amount,
                     source_change_id,hierarchy_dimension_id,
                     hierarchy_state_token{placement_columns}{path_columns})
                    SELECT %s,%s,%s,%s,s.source_coordinate_id,
                        s.source_amount,s.source_change_id,
                        %s,%s{placement_values}{path_values}
                    FROM pg_temp.rollup_source_stage s''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], coordinate['coordinate_id'],
                     plan.dimension, plan.hierarchy_state_token)).rowcount
                if lineage != summary['sourceCount']:
                    raise ValueError('ROLLUP_SOURCE_COUNT_CHANGED')
                from .postgres_current_result_publication import advance_result_head_during_conversion
                head=advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                result = {'resultKey': plan.result_key,
                          'resultStateToken':head['state_token'],
                          'resultContentDigest':head['content_digest'],
                          'function': FUNCTION,
                          'rowCount': 1,
                          'sourceCount': lineage,
                          'amount': format(summary['amount'], 'f'),
                          'hierarchyStateToken': plan.hierarchy_state_token,
                          'sourceCommitRevision': state['commit_revision'],
                          'engine': 'postgres_exact_sql',
                          'planningPolicy':policy_evidence}
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=plan.result_key,
                    existed=final_pointer is not None)
                result['impactDigest']=impact.digest
                if policy_job:
                    result['reusablePolicy'] = reusable_policy
                if plan.placement_ids:
                    result['placementContext'] = {
                        'dimensionId':plan.dimension,
                        'parentMemberId':plan.parent,
                        'relationshipIds':list(plan.placement_ids),
                        'semantics':'explicit_direct_leaf_placements'}
                if plan.placement_paths:
                    result['placementPathContext']={
                        'dimensionId':plan.dimension,'parentMemberId':plan.parent,
                        'paths':[{'pathId':item['pathId'],'pathOrdinal':item['pathOrdinal'],
                          'relationshipIds':item['relationshipIds'],
                          'leafMemberId':item['leafMemberId']}
                          for item in summary['placementPaths']],
                        'semantics':'explicit_recursive_placement_paths'}
                db.execute('''UPDATE epm.application_state SET
                    commit_revision=%s WHERE workspace_id=%s
                    AND application_id=%s''',
                    (revision, scope.workspace_id, scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     claim['job_id'], job['program_digest'],
                     job['subject_id'], revision, Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                changed=db.execute('''UPDATE epm.job SET status='published',
                    receipt_revision=%s,result=%s,claimant=NULL,
                    lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s
                    AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision, Jsonb(result), scope.workspace_id,
                     scope.application_id, claim['job_id'],
                     claim['claim_generation'],claim['claimant'])).rowcount
                if changed!=1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
