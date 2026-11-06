"""Unreviewed, no-effect Equity-method contribution preview.

The service calculates the period ownership share of explicit post-acquisition
result and OCI sources, then reconciles those movements to an explicitly pinned
opening carrying value.  It does not infer dividends, impairment, acquisition
date allocation, policy elections, or a publishable journal.
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


FUNCTION = 'consolidation.equity.contribution.preview'
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_SOURCE_KEYS = ('openingCarryingValue', 'postAcquisitionResult',
                'postAcquisitionOci')


def _source(value: object, name: str) -> dict:
    if (type(value) is not dict
            or set(value) != {'members', 'amount', 'changeId'}
            or type(value['changeId']) is not str
            or not 1 <= len(value['changeId']) <= 200):
        raise ValueError('EQUITY_PREVIEW_SOURCE_INVALID:' + name)
    return {'coordinate': Coordinate.from_mapping(value['members']),
            'amount': NumericCell.from_wire(
                present=True, amount=value['amount']).amount,
            'changeId': value['changeId']}


def _arguments(program: object) -> dict:
    required = {'relationshipId', 'methodPreviewProgram',
                'expectedMethodPreviewDigest', *_SOURCE_KEYS,
                'targetMembers', 'currencyDimensionId', 'currencyMemberId',
                'expectedDataRevision', 'rounding'}
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != FUNCTION
            or type(program.get('arguments')) is not dict
            or set(program['arguments']) != required):
        raise ValueError('EQUITY_PREVIEW_INVALID')
    args = program['arguments']
    for key in ('relationshipId', 'currencyDimensionId', 'currencyMemberId'):
        _identifier(args[key], key)
    if (type(args['methodPreviewProgram']) is not dict
            or args['methodPreviewProgram'].get('function') !=
               METHOD_PREVIEW_FUNCTION
            or type(args['expectedMethodPreviewDigest']) is not str
            or _HEX.fullmatch(args['expectedMethodPreviewDigest']) is None
            or type(args['expectedDataRevision']) is not int
            or args['expectedDataRevision'] < 0
            or args['rounding'] != 'half-even-final-8'):
        raise ValueError('EQUITY_PREVIEW_PINS_INVALID')
    sources = {key: _source(args[key], key) for key in _SOURCE_KEYS}
    target = Coordinate.from_mapping(args['targetMembers'])
    if (args['currencyDimensionId'] in dict(target.members)
            or any(args['currencyDimensionId'] in
                   dict(item['coordinate'].members)
                   for item in sources.values())):
        raise ValueError('EQUITY_PREVIEW_GRAIN_INVALID')
    axes = {frozenset(dict(item['coordinate'].members))
            for item in sources.values()} | {frozenset(dict(target.members))}
    if len(axes) != 1:
        raise ValueError('EQUITY_PREVIEW_GRAIN_INVALID')
    return {**args, 'sources': sources, 'target': target}


class PostgresEquityMethodContributionPreview:
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
            raise ValueError('STALE_EQUITY_METHOD_PREVIEW')
        selected = [row for row in method['placements']
                    if row['relationshipId'] == args['relationshipId']]
        if len(selected) != 1:
            raise ValueError('EQUITY_RELATIONSHIP_UNAVAILABLE')
        placement = selected[0]
        if placement['method'] != 'Equity':
            raise ValueError('EQUITY_METHOD_REQUIRED')
        if placement['controlConfirmed'] is not False:
            raise ValueError('EQUITY_CONTROL_CONFLICT')
        if placement['issues']:
            raise ValueError('EQUITY_METHOD_INPUT_UNSUPPORTED')
        ownership = placement['ownership']
        if set(ownership) != {'Active', 'Method', 'PCON', 'PCTRL', 'POWN'}:
            raise ValueError('EQUITY_OWNERSHIP_INCOMPLETE')
        share = Decimal(ownership['POWN']['amount'])
        if not Decimal(0) < share <= Decimal(100):
            raise ValueError('EQUITY_POWN_INVALID')

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
                    raise ValueError('STALE_EQUITY_PREVIEW')
                draft = db.execute('''SELECT family,required_elections
                    FROM epm.policy_pack_draft WHERE workspace_id=%s
                    AND application_id=%s AND policy_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     preview_args['policyId'],
                     preview_args['policyVersion'])).fetchone()
                if (draft is None or draft['family'] != 'CUSTOM'
                        or draft['required_elections']):
                    raise ValueError('EQUITY_POLICY_REVIEW_REQUIRED')
                dimensions = db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active' ''',
                    (scope.workspace_id, scope.application_id)).fetchall()
                roles, fact_axes = {}, set()
                for row in dimensions:
                    if row['model_role'] != 'Currency':
                        fact_axes.add(row['dimension_id'])
                    if row['model_role'] in ('Entity', 'Account', 'Currency'):
                        if row['model_role'] in roles:
                            raise ValueError('EQUITY_MODEL_ROLE_AMBIGUOUS')
                        roles[row['model_role']] = row['dimension_id']
                if set(roles) != {'Entity', 'Account', 'Currency'}:
                    raise ValueError('EQUITY_MODEL_ROLES_REQUIRED')
                if (roles['Currency'] != args['currencyDimensionId']
                        or any(set(dict(item['coordinate'].members)) != fact_axes
                               for item in args['sources'].values())
                        or set(dict(args['target'].members)) != fact_axes):
                    raise ValueError('EQUITY_PREVIEW_GRAIN_INVALID')

                source_members = {key: dict(item['coordinate'].members)
                                  for key, item in args['sources'].items()}
                target_members = dict(args['target'].members)
                child, parent = placement['childEntityId'], method['parentEntityId']
                # Result and OCI are explicit child inputs.  Opening carrying
                # value and candidate target are explicit parent inputs.  All
                # other axes except Account must be identical.
                if (source_members['postAcquisitionResult'][roles['Entity']] != child
                        or source_members['postAcquisitionOci'][roles['Entity']] != child
                        or source_members['openingCarryingValue'][roles['Entity']] != parent
                        or target_members[roles['Entity']] != parent
                        or target_members != source_members['openingCarryingValue']):
                    raise ValueError('EQUITY_PREVIEW_GRAIN_INVALID')
                reference = source_members['postAcquisitionResult']
                for name, members in source_members.items():
                    for axis in fact_axes - {roles['Account'], roles['Entity']}:
                        if members[axis] != reference[axis]:
                            raise ValueError('EQUITY_PREVIEW_GRAIN_INVALID')
                for axis in fact_axes - {roles['Account'], roles['Entity']}:
                    if target_members[axis] != reference[axis]:
                        raise ValueError('EQUITY_PREVIEW_GRAIN_INVALID')
                if len({source_members[key][roles['Account']]
                        for key in _SOURCE_KEYS}) != 3:
                    raise ValueError('EQUITY_SOURCE_ACCOUNTS_MUST_BE_DISTINCT')

                all_members = {(axis, member) for members in
                    (*source_members.values(), target_members)
                    for axis, member in members.items()}
                active = db.execute('''SELECT count(*) AS n
                    FROM jsonb_to_recordset(%s::jsonb)
                    AS x(dimension_id text,member_id text)
                    JOIN epm.member m ON m.workspace_id=%s
                    AND m.application_id=%s
                    AND m.dimension_id=x.dimension_id
                    AND m.member_id=x.member_id AND m.status='Active' ''',
                    (Jsonb([{'dimension_id': axis, 'member_id': member}
                            for axis, member in sorted(all_members)]),
                     scope.workspace_id, scope.application_id)).fetchone()['n']
                if active != len(all_members):
                    raise ValueError('EQUITY_SOURCE_MEMBER_UNAVAILABLE')
                accounts = {members[roles['Account']]
                            for members in source_members.values()}
                if db.execute('''SELECT 1 FROM epm.relationship
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND parent_member_id=ANY(%s)
                    AND status='Active' LIMIT 1''',
                    (scope.workspace_id, scope.application_id,
                     roles['Account'], list(accounts))).fetchone():
                    raise ValueError('EQUITY_SOURCE_ACCOUNT_MUST_BE_LEAF')
                entities = db.execute('''SELECT member_id,
                    entity_default_currency_member_id AS currency_id
                    FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id IN (%s,%s) AND status='Active' ''',
                    (scope.workspace_id, scope.application_id, roles['Entity'],
                     child, parent)).fetchall()
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
                    raise ValueError('EQUITY_CURRENCY_ALIGNMENT_REQUIRED')

                rows = {}
                for name, pin in args['sources'].items():
                    row = db.execute('''SELECT c.coordinate_id,c.members,
                        n.amount,n.change_id FROM epm.coordinate c
                        JOIN epm.numeric_cell_current n USING
                        (workspace_id,application_id,coordinate_id)
                        WHERE c.workspace_id=%s AND c.application_id=%s
                        AND c.series_key=%s AND n.present''',
                        (scope.workspace_id, scope.application_id,
                         pin['coordinate'].series_key)).fetchone()
                    if (row is None or row['members'] != source_members[name]
                            or row['change_id'] != pin['changeId']
                            or row['amount'] != pin['amount']):
                        raise ValueError('STALE_EQUITY_SOURCE:' + name)
                    rows[name] = row
                authorize_coordinates(
                    db, self.identity, scope,
                    tuple(item['coordinate'] for item in args['sources'].values()),
                    kind=AccessKind.READ)
                authorize_coordinates(
                    db, self.identity, scope, (args['target'],),
                    kind=AccessKind.WRITE)
                calculated = db.execute('''SELECT
                    epm.round_half_even(%s::numeric * %s::numeric / 100,8)
                        ::numeric(28,8) AS result_share,
                    epm.round_half_even(%s::numeric * %s::numeric / 100,8)
                        ::numeric(28,8) AS oci_share''',
                    (args['sources']['postAcquisitionResult']['amount'], share,
                     args['sources']['postAcquisitionOci']['amount'], share)
                    ).fetchone()
                closing = db.execute('''SELECT epm.round_half_even(
                    %s::numeric + %s::numeric + %s::numeric,8)
                    ::numeric(28,8) AS amount''',
                    (args['sources']['openingCarryingValue']['amount'],
                     calculated['result_share'], calculated['oci_share'])
                    ).fetchone()['amount']
                NumericCell(True, calculated['result_share'], '')
                NumericCell(True, calculated['oci_share'], '')
                NumericCell(True, closing, '')

        source_lineage = {name: {
            'coordinateId': rows[name]['coordinate_id'],
            'members': source_members[name],
            'amount': format(args['sources'][name]['amount'], '.8f'),
            'changeId': args['sources'][name]['changeId']}
            for name in _SOURCE_KEYS}
        lineage = {
            'methodPreviewDigest': method['previewDigest'],
            'policy': {'policyId': method['policyId'],
                       'version': method['policyVersion'],
                       'digest': method['policyDigest'],
                       'family': method['policyFamily'],
                       'status': 'Unreviewed'},
            'ownership': ownership, 'sources': source_lineage,
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
            'periodId': method['periodId'], 'method': 'Equity',
            'ownershipShare': format(share, '.8f'),
            'postAcquisitionResultShare':
                format(calculated['result_share'], '.8f'),
            'postAcquisitionOciShare':
                format(calculated['oci_share'], '.8f'),
            'openingCarryingValue': format(
                args['sources']['openingCarryingValue']['amount'], '.8f'),
            'closingCarryingValueCandidate': format(closing, '.8f'),
            'targetMembers': target_members,
            'rounding': 'half-even-final-8',
            'accountingPolicyStatus': 'Unreviewed',
            'publicationSupported': False, 'effects': 'None',
            'lineage': lineage,
        }
        return {**result, 'previewDigest': _canonical_digest(result)}
