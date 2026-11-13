"""Derive a bounded explicit Full sequence from an active Entity tree.

This returns application language, never posts accounting entries. The caller
still makes every control and parent-source decision and must preview/submit
the generated sequence through the ordinary fixed Full workflow.
"""
from __future__ import annotations

from collections import defaultdict

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_consolidation_aggregate import FUNCTION as AGGREGATE, SOURCE_LAYERS
from .postgres_full_sequence import FUNCTION as SEQUENCE, _program as sequence_program
from .postgres_numeric_store import PostgresNumericFactStore
from .current_object_contract import require_stable_identifier as _identifier


FUNCTION = 'consolidation.full.tree.plan'
_LAYERS = SOURCE_LAYERS


def _request(program: object) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != FUNCTION
            or not isinstance(program['arguments'], dict)):
        raise ValueError('FULL_TREE_PLAN_PROGRAM_INVALID')
    args = program['arguments']
    required = {'rootMembers', 'scenarioId', 'yearId', 'periodId',
                'sourceLayer', 'currencyAlignedConfirmed', 'decisions',
                'parentSourceChoices', 'resultKeys',
                'expectedMetadataRevision'}
    if (set(args) != required
            or not isinstance(args['rootMembers'], dict)
            or not 1 <= len(args['rootMembers']) <= 32
            or any(not isinstance(axis, str) or not isinstance(member, str)
                   for axis, member in args['rootMembers'].items())
            or not isinstance(args['sourceLayer'], str)
            or args['sourceLayer'] not in _LAYERS
            or args['currencyAlignedConfirmed'] is not True
            or type(args['expectedMetadataRevision']) is not int
            or args['expectedMetadataRevision'] < 0
            or not isinstance(args['decisions'], list)
            or not 2 <= len(args['decisions']) <= 200
            or not isinstance(args['parentSourceChoices'], dict)
            or not isinstance(args['resultKeys'], dict)):
        raise ValueError('FULL_TREE_PLAN_ARGUMENTS_INVALID')
    for axis, member in args['rootMembers'].items():
        _identifier(axis, 'Dimension ID')
        _identifier(member, 'Member ID')
    for part in ('scenarioId', 'yearId', 'periodId'):
        _identifier(args[part], 'Member ID')
    for decision in args['decisions']:
        if (not isinstance(decision, dict)
                or set(decision) != {'relationshipId', 'method',
                                     'controlConfirmed'}
                or decision['method'] != 'Full'
                or decision['controlConfirmed'] is not True):
            raise ValueError('FULL_TREE_PLAN_DECISION_INVALID')
        _identifier(decision['relationshipId'], 'Relationship ID')
    return args


class PostgresFullTreePlanner:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def plan(self, scope: ApplicationScope, program: dict) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('APPLICATION_SCOPE_INVALID')
        args = _request(program)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                if (state['metadata_revision'] !=
                        args['expectedMetadataRevision']):
                    raise ValueError('FULL_TREE_PLAN_METADATA_STALE')
                roles = db.execute('''SELECT model_role,dimension_id FROM
                    epm.dimension WHERE workspace_id=%s AND application_id=%s
                    AND status='Active' AND model_role IN
                    ('Scenario','Year','Period','Entity')''', keys).fetchall()
                role_map = {row['model_role']: row['dimension_id']
                            for row in roles}
                if (len(roles) != 4 or len(role_map) != 4
                        or any(args['rootMembers'].get(role_map[role]) !=
                               args[f'{role.lower()}Id']
                               for role in ('Scenario', 'Year', 'Period'))
                        or role_map['Entity'] not in args['rootMembers']):
                    raise ValueError('FULL_TREE_PLAN_MODEL_ROLES_INVALID')
                entity_axis = role_map['Entity']
                root = args['rootMembers'][entity_axis]
                rows = db.execute('''WITH RECURSIVE walk AS (
                    SELECT r.relationship_id,r.parent_member_id,
                        r.child_member_id,1 AS depth
                    FROM epm.relationship r WHERE r.workspace_id=%s
                    AND r.application_id=%s AND r.dimension_id=%s
                    AND r.parent_member_id=%s AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active'
                    UNION ALL
                    SELECT r.relationship_id,r.parent_member_id,
                        r.child_member_id,w.depth+1 FROM walk w
                    JOIN epm.relationship r ON r.workspace_id=%s
                    AND r.application_id=%s AND r.dimension_id=%s
                    AND r.parent_member_id=w.child_member_id
                    AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active' WHERE w.depth<32)
                    SELECT relationship_id,parent_member_id,
                        child_member_id,depth FROM walk LIMIT 201''',
                    (*keys, entity_axis, root,
                     *keys, entity_axis)).fetchall()
                if (not rows or len(rows) > 200
                        or any(row['depth'] >= 32 for row in rows)):
                    raise ValueError('FULL_TREE_PLAN_SIZE_UNSUPPORTED')
                edge_ids = [row['relationship_id'] for row in rows]
                if len(set(edge_ids)) != len(edge_ids):
                    raise ValueError('FULL_TREE_SHARED_CHILD_UNSUPPORTED')
                declared = [item['relationshipId']
                            for item in args['decisions']]
                if (len(set(declared)) != len(declared)
                        or set(declared) != set(edge_ids)):
                    raise ValueError('FULL_TREE_PLAN_DECISION_COVERAGE')
                parents_by_child = defaultdict(set)
                children = defaultdict(list)
                for row in rows:
                    parents_by_child[row['child_member_id']].add(
                        row['parent_member_id'])
                    children[row['parent_member_id']].append((
                        row['relationship_id'], row['child_member_id']))
                if any(len(parents) != 1 for parents in
                       parents_by_child.values()):
                    raise ValueError('FULL_TREE_SHARED_CHILD_UNSUPPORTED')
                internal = set(children)
                if (not 2 <= len(internal) <= 8
                        or set(args['parentSourceChoices']) != internal
                        or set(args['resultKeys']) != internal
                        or any(type(value) is not bool for value in
                               args['parentSourceChoices'].values())):
                    raise ValueError('FULL_TREE_PLAN_PARENT_CHOICES_INVALID')
                order = []
                visiting = set()
                def visit(node: str) -> None:
                    if node in visiting:
                        raise ValueError('FULL_TREE_CYCLE_UNSUPPORTED')
                    visiting.add(node)
                    for _, child in sorted(children[node]):
                        if child in internal:
                            visit(child)
                    visiting.remove(node)
                    order.append(node)
                visit(root)
                if len(order) != len(internal) or len(set(order)) != len(order):
                    raise ValueError('FULL_TREE_SHARED_CHILD_UNSUPPORTED')
                indices = {node: index for index, node in enumerate(order)}
                steps = []
                for node in order:
                    relationships = sorted(children[node])
                    parent_members = {**args['rootMembers'],
                                      entity_axis: node}
                    step = {'program': {'languageVersion': 2,
                        'function': AGGREGATE,
                        'arguments': {
                            'parentMembers': parent_members,
                            'decisions': [{'relationshipId': edge,
                                'method': 'Full', 'controlConfirmed': True}
                                for edge, _ in relationships],
                            'scenarioId': args['scenarioId'],
                            'yearId': args['yearId'],
                            'periodId': args['periodId'],
                            'includeParentSource':
                                args['parentSourceChoices'][node],
                            'sourceLayer': args['sourceLayer'],
                            'currencyAlignedConfirmed': True,
                            'resultKey': args['resultKeys'][node]}},
                        'publishedChildrenFromSteps': [
                            {'relationshipId': edge,
                             'stepIndex': indices[child]}
                            for edge, child in relationships
                            if child in internal]}
                    steps.append(step)
                generated = {'languageVersion': 2,
                    'function': SEQUENCE, 'arguments': {'steps': steps}}
                sequence_program(generated, SEQUENCE)
                return {'sequenceProgram': generated,
                    'internalEntityOrder': order,
                    'relationshipCount': len(rows),
                    'observedMetadataRevision': state['metadata_revision'],
                    'accountingPolicyStatus': 'Unreviewed'}
