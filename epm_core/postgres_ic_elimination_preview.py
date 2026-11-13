"""Unreviewed, group-scoped intercompany balance-offset candidate.

This is a bounded preflight. A candidate line is a proposed offset to one
source coordinate, not a posted journal, elimination or certified close.
"""
from __future__ import annotations

from decimal import Decimal

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_consolidation_assess import PostgresConsolidationAssessment
from .postgres_ic_pair_inspect import PostgresIntercompanyPairInspector
from .postgres_numeric_store import PostgresNumericFactStore
from .current_object_contract import require_stable_identifier as _identifier


FUNCTION = 'consolidation.ic.elimination.preview'


class PostgresIntercompanyEliminationPreview:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def preview(self, scope: ApplicationScope, program: object) -> dict:
        required = {'leftMembers', 'rightMembers', 'parentEntityId',
                    'leftRelationshipId', 'rightRelationshipId',
                    'scenarioId', 'yearId', 'periodId', 'decisions'}
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != required):
            raise ValueError('IC_ELIMINATION_PREVIEW_PROGRAM_INVALID')
        args = program['arguments']
        ids = {name: _identifier(args[name], name) for name in
               ('parentEntityId', 'leftRelationshipId',
                'rightRelationshipId', 'scenarioId', 'yearId', 'periodId')}
        if ids['leftRelationshipId'] == ids['rightRelationshipId']:
            raise ValueError('IC_ELIMINATION_DISTINCT_RELATIONSHIPS_REQUIRED')
        pair_program = {'languageVersion': 2,
                        'function': 'consolidation.ic.pair.inspect',
                        'arguments': {'leftMembers': args['leftMembers'],
                                      'rightMembers': args['rightMembers']}}
        pair = PostgresIntercompanyPairInspector(
            self.dsn, identity=self.identity).inspect(scope, pair_program)
        assessment = PostgresConsolidationAssessment(
            self.dsn, identity=self.identity).assess(scope, {
                'languageVersion': 2, 'function': 'consolidation.scope.assess',
                'arguments': {'parentEntityId': ids['parentEntityId'],
                              'scenarioId': ids['scenarioId'],
                              'yearId': ids['yearId'],
                              'periodId': ids['periodId'],
                              'decisions': args['decisions']}})
        if (pair['commitRevision'] != assessment['commitRevision']
                or pair['metadataRevision'] != assessment['metadataRevision']
                or pair['policyRevision'] != assessment['policyRevision']):
            raise ValueError('IC_ELIMINATION_PREVIEW_STALE')
        if not assessment['structurallyEligible']:
            raise ValueError('IC_ELIMINATION_FULL_SCOPE_REQUIRED')
        placements = {row['relationshipId']: row
                      for row in assessment['placements']}
        for side, relationship in (('left', ids['leftRelationshipId']),
                                   ('right', ids['rightRelationshipId'])):
            row = placements.get(relationship)
            if (row is None or row['method'] != 'Full'
                    or not row['controlConfirmed'] or row['issues']):
                raise ValueError('IC_ELIMINATION_PAIR_FULL_METHOD_REQUIRED')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                state = db.execute('''SELECT commit_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or
                        state['commit_revision'] != pair['commitRevision']):
                    raise ValueError('IC_ELIMINATION_PREVIEW_STALE')
                roles = {row['model_role']: row['dimension_id'] for row in
                    db.execute('''SELECT dimension_id,model_role FROM
                        epm.dimension WHERE workspace_id=%s
                        AND application_id=%s AND status='Active'
                        AND model_role IN ('Scenario','Year','Period',
                                           'Entity','Currency')''',
                        (scope.workspace_id, scope.application_id)).fetchall()}
                if set(roles) != {'Scenario','Year','Period','Entity','Currency'}:
                    raise ValueError('IC_ELIMINATION_FINANCIAL_MODEL_REQUIRED')
                for side in ('left', 'right'):
                    members = pair[side]['members']
                    for role, argument in (('Scenario','scenarioId'),
                                           ('Year','yearId'),
                                           ('Period','periodId')):
                        if members[roles[role]] != ids[argument]:
                            raise ValueError('IC_ELIMINATION_CONTEXT_MISMATCH')
                    relationship = ids[side+'RelationshipId']
                    if placements[relationship]['childEntityId'] != (
                            members[roles['Entity']]):
                        raise ValueError('IC_ELIMINATION_CHILD_SCOPE_MISMATCH')
                    count = db.execute('''SELECT count(*) AS total FROM
                        epm.relationship WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s
                        AND child_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' ''',
                        (scope.workspace_id, scope.application_id,
                         roles['Entity'], members[roles['Entity']]
                         )).fetchone()['total']
                    if count != 1:
                        raise ValueError('IC_ELIMINATION_SHARED_PLACEMENT_UNSUPPORTED')
                parent = db.execute('''SELECT m.entity_default_currency_member_id
                    AS currency_id FROM epm.member m
                    WHERE m.workspace_id=%s AND m.application_id=%s
                    AND m.dimension_id=%s AND m.member_id=%s
                    AND m.status='Active' ''',
                    (scope.workspace_id, scope.application_id,
                     roles['Entity'], ids['parentEntityId'])).fetchone()
                if not parent:
                    raise ValueError('IC_ELIMINATION_PARENT_UNAVAILABLE')
                parent_currency = parent['currency_id']
        issues = list(pair['issues'])
        if (parent_currency is None
                or parent_currency != pair['left']['entityCurrencyMemberId']
                or parent_currency != pair['right']['entityCurrencyMemberId']):
            issues.append('IC_ELIMINATION_PARENT_CURRENCY_ALIGNMENT_REQUIRED')
        matched = (Decimal(pair['matchedMagnitude'])
                   if pair['matchedMagnitude'] is not None else None)
        candidate_lines = []
        if not issues and matched is not None and matched > 0:
            for side in ('left', 'right'):
                source = pair[side]
                source_amount = Decimal(source['amount'])
                adjustment = -matched if source_amount > 0 else matched
                candidate_lines.append({
                    'sourceMembers': source['members'],
                    'sourceChangeId': source['changeId'],
                    'sourceAmount': source['amount'],
                    'signedCandidateOffset': format(adjustment, '.8f'),
                    'relationshipId': ids[side+'RelationshipId']})
        if pair['signedResidual'] not in (None, '0.00000000'):
            issues.append('IC_ELIMINATION_UNMATCHED_RESIDUAL')
        if matched == 0:
            issues.append('IC_ELIMINATION_ZERO_MATCH')
        return {
            'parentEntityId': ids['parentEntityId'],
            'parentCurrencyMemberId': parent_currency,
            'sourcePair': pair,
            'placements': [placements[ids['leftRelationshipId']],
                           placements[ids['rightRelationshipId']]],
            'candidateLines': candidate_lines,
            'matchedMagnitude': pair['matchedMagnitude'],
            'signedResidual': pair['signedResidual'],
            'issues': issues,
            'candidateAvailable': len(candidate_lines) == 2,
            'metadataRevision': pair['metadataRevision'],
            'dataRevision': pair['dataRevision'],
            'policyRevision': pair['policyRevision'],
            'commitRevision': pair['commitRevision'],
            'accountingPolicyStatus': 'Unreviewed',
            'targetAccountPolicyStatus': 'NotConfigured',
            'eliminationPublished': False,
            'publishSupported': len(candidate_lines) == 2,
            'publishFunction': 'consolidation.ic.elimination.publish',
        }
