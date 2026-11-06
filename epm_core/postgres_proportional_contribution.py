"""Unreviewed, no-effect proportional contribution preview.

This service computes one exact candidate Amount × period PCON.  It neither
publishes a calculation generation nor implies that a proportional accounting
policy has passed P15 review.
"""
from __future__ import annotations

from decimal import Decimal
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_consolidation_assess import (
    METHOD_PREVIEW_FUNCTION, PostgresConsolidationAssessment)
from .postgres_jobs import _canonical_digest
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_version_compare import _identifier


FUNCTION = 'consolidation.proportional.contribution.preview'
_HEX = re.compile(r'[0-9a-f]{64}\Z')


def _arguments(program: object) -> dict:
    required = {'relationshipId', 'methodPreviewProgram',
                'expectedMethodPreviewDigest', 'sourceMembers',
                'targetMembers', 'sourceAmount', 'sourceChangeId',
                'currencyDimensionId', 'currencyMemberId',
                'expectedDataRevision', 'rounding'}
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != FUNCTION
            or type(program.get('arguments')) is not dict
            or set(program['arguments']) != required):
        raise ValueError('PROPORTIONAL_PREVIEW_INVALID')
    args = program['arguments']
    for key in ('relationshipId', 'currencyDimensionId', 'currencyMemberId'):
        _identifier(args[key], key)
    if (type(args['methodPreviewProgram']) is not dict
            or args['methodPreviewProgram'].get('function') !=
               METHOD_PREVIEW_FUNCTION
            or type(args['expectedMethodPreviewDigest']) is not str
            or _HEX.fullmatch(args['expectedMethodPreviewDigest']) is None
            or type(args['sourceChangeId']) is not str
            or not 1 <= len(args['sourceChangeId']) <= 200
            or type(args['expectedDataRevision']) is not int
            or args['expectedDataRevision'] < 0
            or args['rounding'] != 'half-even-final-8'):
        raise ValueError('PROPORTIONAL_PREVIEW_PINS_INVALID')
    source = Coordinate.from_mapping(args['sourceMembers'])
    target = Coordinate.from_mapping(args['targetMembers'])
    amount = NumericCell.from_wire(
        present=True, amount=args['sourceAmount']).amount
    if (args['currencyDimensionId'] in dict(source.members)
            or args['currencyDimensionId'] in dict(target.members)
            or source == target
            or set(dict(source.members)) != set(dict(target.members))):
        raise ValueError('PROPORTIONAL_PREVIEW_GRAIN_INVALID')
    return {**args, 'source': source, 'target': target,
            'sourceAmount': amount}


class PostgresProportionalContributionPreview:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def preview(self, scope: ApplicationScope, program: dict) -> dict:
        args = _arguments(program)
        method = PostgresConsolidationAssessment(
            self.dsn, identity=self.identity).preview_method(
                scope, args['methodPreviewProgram'])
        if method['previewDigest'] != args['expectedMethodPreviewDigest']:
            raise ValueError('STALE_PROPORTIONAL_METHOD_PREVIEW')
        selected = [row for row in method['placements']
                    if row['relationshipId'] == args['relationshipId']]
        if len(selected) != 1:
            raise ValueError('PROPORTIONAL_RELATIONSHIP_UNAVAILABLE')
        placement = selected[0]
        if placement['method'] != 'Proportional':
            raise ValueError('PROPORTIONAL_METHOD_REQUIRED')
        if placement['controlConfirmed'] is not False:
            raise ValueError('PROPORTIONAL_CONTROL_CONFLICT')
        if placement['issues']:
            raise ValueError('PROPORTIONAL_METHOD_INPUT_UNSUPPORTED')
        ownership = placement['ownership']
        if set(ownership) != {'Active', 'Method', 'PCON', 'PCTRL', 'POWN'}:
            raise ValueError('PROPORTIONAL_OWNERSHIP_INCOMPLETE')
        pcon = Decimal(ownership['PCON']['amount'])
        if not Decimal(0) < pcon <= Decimal(100):
            raise ValueError('PROPORTIONAL_PCON_INVALID')

        preview_args = args['methodPreviewProgram']['arguments']
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=FUNCTION)
                state = db.execute('''SELECT a.status AS application_status,
                    s.processing_mode,s.metadata_revision,s.data_revision,
                    s.policy_revision,s.commit_revision
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR SHARE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_READABLE')
                if (state['metadata_revision'] !=
                        preview_args['expectedMetadataRevision']
                        or state['policy_revision'] !=
                        preview_args['expectedPolicyRevision']
                        or state['commit_revision'] !=
                        preview_args['expectedCommitRevision']
                        or state['data_revision'] !=
                        args['expectedDataRevision']):
                    raise ValueError('STALE_PROPORTIONAL_PREVIEW')
                draft = db.execute('''SELECT family,required_elections
                    FROM epm.policy_pack_draft WHERE workspace_id=%s
                    AND application_id=%s AND policy_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     preview_args['policyId'],
                     preview_args['policyVersion'])).fetchone()
                if (draft is None or draft['family'] != 'CUSTOM'
                        or draft['required_elections']):
                    raise ValueError('PROPORTIONAL_POLICY_REVIEW_REQUIRED')
                dimensions = db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active' ''',
                    (scope.workspace_id, scope.application_id)).fetchall()
                roles = {}
                fact_axes = set()
                for row in dimensions:
                    if row['model_role'] != 'Currency':
                        fact_axes.add(row['dimension_id'])
                    if row['model_role'] in ('Entity', 'Account', 'Currency'):
                        if row['model_role'] in roles:
                            raise ValueError('PROPORTIONAL_MODEL_ROLE_AMBIGUOUS')
                        roles[row['model_role']] = row['dimension_id']
                if set(roles) != {'Entity', 'Account', 'Currency'}:
                    raise ValueError('PROPORTIONAL_MODEL_ROLES_REQUIRED')
                if (roles['Currency'] != args['currencyDimensionId']
                        or set(dict(args['source'].members)) != fact_axes
                        or set(dict(args['target'].members)) != fact_axes):
                    raise ValueError('PROPORTIONAL_PREVIEW_GRAIN_INVALID')
                source_members, target_members = (
                    dict(args['source'].members), dict(args['target'].members))
                changed = [axis for axis in fact_axes
                           if source_members[axis] != target_members[axis]]
                if (changed != [roles['Entity']]
                        or source_members[roles['Entity']] !=
                           placement['childEntityId']
                        or target_members[roles['Entity']] !=
                           method['parentEntityId']):
                    raise ValueError('PROPORTIONAL_PREVIEW_GRAIN_INVALID')
                active = db.execute('''SELECT count(*) AS n
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS x(dimension_id text,member_id text)
                    JOIN epm.member m ON m.workspace_id=%s
                    AND m.application_id=%s
                    AND m.dimension_id=x.dimension_id
                    AND m.member_id=x.member_id AND m.status='Active' ''',
                    (Jsonb([{'dimension_id': axis, 'member_id': member}
                      for axis, member in args['source'].members]),
                     scope.workspace_id, scope.application_id)).fetchone()['n']
                if active != len(fact_axes):
                    raise ValueError('PROPORTIONAL_SOURCE_MEMBER_UNAVAILABLE')
                account = source_members[roles['Account']]
                if db.execute('''SELECT 1 FROM epm.relationship
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND parent_member_id=%s
                    AND status='Active' LIMIT 1''',
                    (scope.workspace_id, scope.application_id,
                     roles['Account'], account)).fetchone():
                    raise ValueError('PROPORTIONAL_SOURCE_ACCOUNT_MUST_BE_LEAF')
                entities = db.execute('''SELECT member_id,
                    entity_default_currency_member_id AS currency_id
                    FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id IN (%s,%s) AND status='Active' ''',
                    (scope.workspace_id, scope.application_id, roles['Entity'],
                     placement['childEntityId'], method['parentEntityId'])).fetchall()
                if (len(entities) != 2
                        or {row['currency_id'] for row in entities} !=
                           {args['currencyMemberId']}
                        or db.execute('''SELECT 1 FROM epm.member
                            WHERE workspace_id=%s AND application_id=%s
                            AND dimension_id=%s AND member_id=%s
                            AND status='Active' ''',
                            (scope.workspace_id, scope.application_id,
                             roles['Currency'],
                             args['currencyMemberId'])).fetchone() is None):
                    raise ValueError('PROPORTIONAL_CURRENCY_ALIGNMENT_REQUIRED')
                source = db.execute('''SELECT c.coordinate_id,c.members,
                    n.amount,n.change_id FROM epm.coordinate c
                    JOIN epm.numeric_cell_current n USING
                    (workspace_id,application_id,coordinate_id)
                    WHERE c.workspace_id=%s AND c.application_id=%s
                    AND c.series_key=%s AND n.present''',
                    (scope.workspace_id, scope.application_id,
                     args['source'].series_key)).fetchone()
                if (source is None or source['members'] != source_members
                        or source['change_id'] != args['sourceChangeId']
                        or source['amount'] != args['sourceAmount']):
                    raise ValueError('STALE_PROPORTIONAL_SOURCE')
                authorize_coordinates(
                    db, self.identity, scope, (args['source'],),
                    kind=AccessKind.READ)
                authorize_coordinates(
                    db, self.identity, scope, (args['target'],),
                    kind=AccessKind.WRITE)
                amount = db.execute('''SELECT epm.round_half_even(
                    %s::numeric * %s::numeric / 100,8)::numeric(28,8)
                    AS amount''',
                    (args['sourceAmount'], pcon)).fetchone()['amount']
                NumericCell(True, amount, '')

        lineage = {
            'methodPreviewDigest': method['previewDigest'],
            'policy': {'policyId': method['policyId'],
                       'version': method['policyVersion'],
                       'digest': method['policyDigest'],
                       'family': method['policyFamily'],
                       'status': 'Unreviewed'},
            'ownership': ownership,
            'source': {'coordinateId': source['coordinate_id'],
                       'members': source_members,
                       'amount': format(args['sourceAmount'], '.8f'),
                       'changeId': args['sourceChangeId'],
                       'commitRevision': state['commit_revision']},
            'currency': {'dimensionId': args['currencyDimensionId'],
                         'memberId': args['currencyMemberId'],
                         'alignment': 'child_and_parent_functional_currency'},
            'revisions': {key: state[key] for key in
                          ('metadata_revision', 'data_revision',
                           'policy_revision', 'commit_revision')},
        }
        result = {
            'relationshipId': args['relationshipId'],
            'parentEntityId': method['parentEntityId'],
            'childEntityId': placement['childEntityId'],
            'scenarioId': method['scenarioId'], 'yearId': method['yearId'],
            'periodId': method['periodId'], 'method': 'Proportional',
            'sourceAmount': format(args['sourceAmount'], '.8f'),
            'pcon': format(pcon, '.8f'),
            'coefficient': format(pcon / Decimal(100), '.8f'),
            'candidateAmount': format(amount, '.8f'),
            'targetMembers': target_members,
            'rounding': 'half-even-final-8',
            'accountingPolicyStatus': 'Unreviewed',
            'publicationSupported': False, 'effects': 'None',
            'lineage': lineage,
        }
        return {**result, 'previewDigest': _canonical_digest(result)}
