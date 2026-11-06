"""Structural preflight for an explicitly declared direct consolidation scope.

This does not execute or certify an accounting policy. In particular, an
ownership percentage is never interpreted as evidence of control.
"""
from __future__ import annotations

from decimal import Decimal
from datetime import date
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import _identifier
from .postgres_jobs import _canonical_digest


FUNCTION = 'consolidation.scope.assess'
METHOD_PREVIEW_FUNCTION = 'consolidation.ownership.method.preview'
_METHODS = {'Full', 'Equity', 'Proportional', 'None'}
_METHOD_CODES = {'None': Decimal('0'), 'Full': Decimal('1'),
                 'Equity': Decimal('2'), 'Proportional': Decimal('3')}
_ROLES = {'Scenario', 'Year', 'Period', 'Entity'}


def _method_preview_arguments(program: object) -> dict:
    if (not isinstance(program, dict)
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion'] != 2
            or program['function'] != METHOD_PREVIEW_FUNCTION
            or not isinstance(program['arguments'], dict)):
        raise ValueError('CONSOLIDATION_METHOD_PREVIEW_INVALID')
    args = program['arguments']
    required = {'parentEntityId', 'scenarioId', 'yearId', 'periodId',
                'effectiveOn', 'policyId', 'policyVersion', 'policyDigest',
                'expectedMetadataRevision', 'expectedPolicyRevision',
                'expectedCommitRevision', 'decisions'}
    if set(args) != required:
        raise ValueError('CONSOLIDATION_METHOD_PREVIEW_INVALID')
    result = {key: _identifier(args[key], key) for key in
              ('parentEntityId', 'scenarioId', 'yearId', 'periodId',
               'policyId')}
    try:
        effective_on = date.fromisoformat(args['effectiveOn'])
    except (TypeError, ValueError):
        raise ValueError('CONSOLIDATION_EFFECTIVE_DATE_INVALID') from None
    if effective_on.isoformat() != args['effectiveOn']:
        raise ValueError('CONSOLIDATION_EFFECTIVE_DATE_INVALID')
    if (type(args['policyVersion']) is not int or args['policyVersion'] < 1
            or not isinstance(args['policyDigest'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', args['policyDigest'])
            or any(type(args[key]) is not int or args[key] < 0 for key in
                   ('expectedMetadataRevision', 'expectedPolicyRevision',
                    'expectedCommitRevision'))):
        raise ValueError('CONSOLIDATION_METHOD_PINS_INVALID')
    decisions = args['decisions']
    if not isinstance(decisions, list) or not 1 <= len(decisions) <= 200:
        raise ValueError('CONSOLIDATION_ASSESS_BOUNDS_INVALID')
    parsed, seen = [], set()
    expected_changes = {'POWN', 'PCON', 'PCTRL', 'Active', 'Method'}
    for item in decisions:
        if (not isinstance(item, dict)
                or set(item) != {'relationshipId', 'method',
                                 'controlConfirmed', 'expectedChangeIds'}
                or item.get('method') not in _METHODS
                or type(item.get('controlConfirmed')) is not bool
                or not isinstance(item.get('expectedChangeIds'), dict)
                or set(item['expectedChangeIds']) != expected_changes
                or any(not isinstance(value, str) or len(value) > 200
                       for value in item['expectedChangeIds'].values())):
            raise ValueError('CONSOLIDATION_DECISION_INVALID')
        relationship = _identifier(item['relationshipId'], 'Relationship ID')
        if relationship in seen:
            raise ValueError('CONSOLIDATION_DUPLICATE_DECISION')
        seen.add(relationship)
        parsed.append({**item, 'relationshipId': relationship})
    return {**result, 'effectiveOn': effective_on,
            **{key: args[key] for key in ('policyVersion', 'policyDigest',
               'expectedMetadataRevision', 'expectedPolicyRevision',
               'expectedCommitRevision')}, 'decisions': parsed}


class PostgresConsolidationAssessment:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def preview_method(self, scope: ApplicationScope, program: dict) -> dict:
        """Resolve exact period ownership inputs without selecting a method.

        The caller supplies the explicit method decision.  Fixed core verifies
        that its code, ownership values, policy draft and revisions are the
        exact pinned inputs. Supported methods retain distinct structural
        requirements and are never silently lowered to Full.
        """
        query = _method_preview_arguments(program)
        by_relationship = {item['relationshipId']: item
                           for item in query['decisions']}
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin',
                    function=METHOD_PREVIEW_FUNCTION)
                state = db.execute('''SELECT metadata_revision,
                    policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if any(state[column] != query['expected' + label + 'Revision']
                       for column, label in (('metadata_revision', 'Metadata'),
                                             ('policy_revision', 'Policy'),
                                             ('commit_revision', 'Commit'))):
                    raise ValueError('STALE_CONSOLIDATION_METHOD_PREVIEW')
                draft = db.execute('''SELECT version,family,effective_from,
                    effective_before,required_elections,source_refs,
                    created_revision FROM epm.policy_pack_draft
                    WHERE workspace_id=%s AND application_id=%s
                    AND policy_id=%s AND effective_from<=%s
                    AND effective_before>%s''',
                    (scope.workspace_id, scope.application_id,
                     query['policyId'], query['effectiveOn'],
                     query['effectiveOn'])).fetchone()
                if draft is None or draft['version'] != query['policyVersion']:
                    raise ValueError('CONSOLIDATION_METHOD_POLICY_UNAVAILABLE')
                policy_digest = _canonical_digest({
                    'policyId': query['policyId'], 'version': draft['version'],
                    'family': draft['family'],
                    'effectiveFrom': draft['effective_from'].isoformat(),
                    'effectiveBefore': draft['effective_before'].isoformat(),
                    'requiredElections': draft['required_elections'],
                    'sourceRefs': draft['source_refs'],
                    'createdRevision': draft['created_revision']})
                if policy_digest != query['policyDigest']:
                    raise ValueError('STALE_CONSOLIDATION_METHOD_POLICY')
                roles = {}
                for row in db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active'
                    AND model_role IN ('Scenario','Year','Period','Entity')''',
                    (scope.workspace_id, scope.application_id)).fetchall():
                    if row['model_role'] in roles:
                        raise ValueError('OWNERSHIP_MODEL_ROLE_AMBIGUOUS')
                    roles[row['model_role']] = row['dimension_id']
                if set(roles) != _ROLES:
                    raise ValueError('OWNERSHIP_MODEL_ROLES_REQUIRED')
                for role, name in (('Scenario', 'scenarioId'),
                                   ('Year', 'yearId'),
                                   ('Period', 'periodId'),
                                   ('Entity', 'parentEntityId')):
                    if db.execute('''SELECT 1 FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (scope.workspace_id, scope.application_id, roles[role],
                         query[name])).fetchone() is None:
                        raise ValueError('CONSOLIDATION_CONTEXT_MEMBER_UNAVAILABLE')
                rows = db.execute('''SELECT r.relationship_id,
                    r.child_member_id,v.account_name,v.amount,v.change_id
                    FROM epm.relationship r
                    JOIN epm.member child ON child.workspace_id=r.workspace_id
                    AND child.application_id=r.application_id
                    AND child.dimension_id=r.dimension_id
                    AND child.member_id=r.child_member_id
                    LEFT JOIN epm.ownership_value_current v
                    ON v.workspace_id=r.workspace_id
                    AND v.application_id=r.application_id
                    AND v.relationship_id=r.relationship_id
                    AND v.scenario_member_id=%s AND v.year_member_id=%s
                    AND v.period_member_id=%s AND v.present
                    AND v.account_name IN ('POWN','PCON','PCTRL','Active','Method')
                    WHERE r.workspace_id=%s AND r.application_id=%s
                    AND r.dimension_id=%s AND r.parent_member_id=%s
                    AND r.status='Active' AND child.status='Active'
                    ORDER BY r.relationship_id,v.account_name LIMIT 1001''',
                    (query['scenarioId'], query['yearId'], query['periodId'],
                     scope.workspace_id, scope.application_id, roles['Entity'],
                     query['parentEntityId'])).fetchall()
        relationships = {}
        for row in rows:
            item = relationships.setdefault(row['relationship_id'], {
                'childEntityId': row['child_member_id'], 'values': {}})
            if row['account_name'] is not None:
                item['values'][row['account_name']] = (
                    row['amount'], row['change_id'])
        if len(relationships) > 200:
            raise ValueError('CONSOLIDATION_SCOPE_TOO_LARGE')
        if set(relationships) != set(by_relationship):
            raise ValueError('CONSOLIDATION_DECISIONS_SCOPE_MISMATCH')
        placements = []
        for relationship_id in sorted(relationships):
            source, decision = relationships[relationship_id], by_relationship[relationship_id]
            values, issues = source['values'], []
            missing = sorted(set(decision['expectedChangeIds']) - set(values))
            if missing:
                issues.append('OWNERSHIP_INPUTS_REQUIRED:' + ','.join(missing))
            for account, expected in sorted(decision['expectedChangeIds'].items()):
                if account in values and values[account][1] != expected:
                    issues.append('STALE_OWNERSHIP_INPUT:' + account)
            method = decision['method']
            if 'Method' in values and values['Method'][0] != _METHOD_CODES[method]:
                issues.append('METHOD_CODE_MISMATCH')
            if 'Active' in values and values['Active'][0] != 1:
                issues.append('PLACEMENT_INACTIVE_FOR_PERIOD')
            if method == 'Full':
                if not decision['controlConfirmed']:
                    issues.append('CONTROL_DECISION_REQUIRED')
                if 'PCON' in values and values['PCON'][0] != 100:
                    issues.append('FULL_PCON_MUST_BE_100')
            elif method == 'Equity':
                if decision['controlConfirmed']:
                    issues.append('EQUITY_CONTROL_CONFLICT')
                if ('POWN' in values and not
                        Decimal(0) < values['POWN'][0] <= Decimal(100)):
                    issues.append('EQUITY_POWN_INVALID')
            elif method == 'Proportional':
                if decision['controlConfirmed']:
                    issues.append('PROPORTIONAL_CONTROL_CONFLICT')
                if ('PCON' in values and not
                        Decimal(0) < values['PCON'][0] <= Decimal(100)):
                    issues.append('PROPORTIONAL_PCON_INVALID')
            elif decision['controlConfirmed']:
                issues.append('EXCLUDED_PLACEMENT_CONTROL_CONFLICT')
            placements.append({'relationshipId': relationship_id,
                'childEntityId': source['childEntityId'], 'method': method,
                'methodCode': format(_METHOD_CODES[method], '.8f'),
                'controlConfirmed': decision['controlConfirmed'],
                'ownership': {account: {'amount': format(values[account][0], '.8f'),
                                        'changeId': values[account][1]}
                              for account in sorted(values)},
                'issues': issues, 'executionSupported': True})
        digest = _canonical_digest({'scope': [scope.workspace_id, scope.application_id],
            'context': {key: query[key] for key in ('parentEntityId','scenarioId',
                       'yearId','periodId')}, 'effectiveOn': query['effectiveOn'].isoformat(),
            'policyId': query['policyId'], 'policyVersion': query['policyVersion'],
            'policyDigest': policy_digest, 'revisions': dict(state),
            'placements': placements})
        return {'parentEntityId': query['parentEntityId'],
                'scenarioId': query['scenarioId'], 'yearId': query['yearId'],
                'periodId': query['periodId'],
                'effectiveOn': query['effectiveOn'].isoformat(),
                'policyId': query['policyId'], 'policyVersion': draft['version'],
                'policyDigest': policy_digest, 'policyFamily': draft['family'],
                'metadataRevision': state['metadata_revision'],
                'policyRevision': state['policy_revision'],
                'commitRevision': state['commit_revision'],
                'placements': placements, 'previewDigest': digest,
                'structurallyEligible': all(not row['issues'] for row in placements),
                'accountingPolicyStatus': 'Unreviewed', 'executable': False}

    def assess(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)):
            raise ValueError('CONSOLIDATION_ASSESS_ARGUMENTS_INVALID')
        args = program['arguments']
        required = {'parentEntityId', 'scenarioId', 'yearId',
                    'periodId', 'decisions'}
        if set(args) != required:
            raise ValueError('CONSOLIDATION_ASSESS_ARGUMENTS_INVALID')
        context = {key: _identifier(args[key], key)
                   for key in required - {'decisions'}}
        decisions = args['decisions']
        if (not isinstance(decisions, list)
                or not 1 <= len(decisions) <= 200):
            raise ValueError('CONSOLIDATION_ASSESS_BOUNDS_INVALID')
        by_relationship = {}
        for item in decisions:
            if (not isinstance(item, dict)
                    or set(item) != {'relationshipId', 'method',
                                     'controlConfirmed'}
                    or not isinstance(item.get('method'), str)
                    or item.get('method') not in _METHODS
                    or type(item.get('controlConfirmed')) is not bool):
                raise ValueError('CONSOLIDATION_DECISION_INVALID')
            relationship = _identifier(item['relationshipId'],
                                       'Relationship ID')
            if relationship in by_relationship:
                raise ValueError('CONSOLIDATION_DUPLICATE_DECISION')
            by_relationship[relationship] = item
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                # Grant rechecks require READ COMMITTED. A shared state lock
                # pins metadata, ownership and policy writers for this read.
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                state = db.execute('''SELECT metadata_revision,
                    policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                roles = {}
                for row in db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active'
                    AND model_role IN ('Scenario','Year','Period','Entity')''',
                    (scope.workspace_id, scope.application_id)).fetchall():
                    if row['model_role'] in roles:
                        raise ValueError('OWNERSHIP_MODEL_ROLE_AMBIGUOUS')
                    roles[row['model_role']] = row['dimension_id']
                if set(roles) != _ROLES:
                    raise ValueError('OWNERSHIP_MODEL_ROLES_REQUIRED')
                for role, argument in (('Scenario', 'scenarioId'),
                                       ('Year', 'yearId'),
                                       ('Period', 'periodId'),
                                       ('Entity', 'parentEntityId')):
                    found = db.execute('''SELECT 1 FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND member_id=%s
                        AND status='Active' ''',
                        (scope.workspace_id, scope.application_id,
                         roles[role], context[argument])).fetchone()
                    if not found:
                        raise ValueError('CONSOLIDATION_CONTEXT_MEMBER_UNAVAILABLE')
                rows = db.execute('''SELECT r.relationship_id,
                    r.child_member_id,
                    max(v.amount) FILTER (WHERE v.account_name='POWN') AS pown,
                    max(v.amount) FILTER (WHERE v.account_name='PCON') AS pcon,
                    max(v.amount) FILTER (WHERE v.account_name='PCTRL') AS pctrl,
                    max(v.amount) FILTER (WHERE v.account_name='Active') AS active,
                    max(v.amount) FILTER (WHERE v.account_name='Method') AS method_code
                    FROM epm.relationship r
                    JOIN epm.member child ON child.workspace_id=r.workspace_id
                    AND child.application_id=r.application_id
                    AND child.dimension_id=r.dimension_id
                    AND child.member_id=r.child_member_id
                    AND child.status='Active'
                    LEFT JOIN epm.ownership_value_current v
                    ON v.workspace_id=r.workspace_id
                    AND v.application_id=r.application_id
                    AND v.relationship_id=r.relationship_id
                    AND v.scenario_member_id=%s AND v.year_member_id=%s
                    AND v.period_member_id=%s AND v.present
                    AND v.account_name IN ('POWN','PCON','PCTRL','Active','Method')
                    WHERE r.workspace_id=%s AND r.application_id=%s
                    AND r.dimension_id=%s AND r.parent_member_id=%s
                    AND r.status='Active'
                    GROUP BY r.relationship_id,r.child_member_id
                    ORDER BY r.relationship_id LIMIT 201''',
                    (context['scenarioId'], context['yearId'],
                     context['periodId'], scope.workspace_id,
                     scope.application_id, roles['Entity'],
                     context['parentEntityId'])).fetchall()
        if not rows:
            raise ValueError('CONSOLIDATION_SCOPE_EMPTY')
        if len(rows) > 200:
            raise ValueError('CONSOLIDATION_SCOPE_TOO_LARGE')
        actual = {row['relationship_id'] for row in rows}
        if actual != set(by_relationship):
            raise ValueError('CONSOLIDATION_DECISIONS_SCOPE_MISMATCH')
        assessed = []
        included_count = 0
        for row in rows:
            decision = by_relationship[row['relationship_id']]
            method = decision['method']
            issues = []
            pcon_fallback = row['pcon'] is None
            pcon = Decimal('100') if pcon_fallback else row['pcon']
            if (row['method_code'] is not None
                    and row['method_code'] != _METHOD_CODES[method]):
                issues.append('METHOD_CODE_MISMATCH')
            if row['active'] == 0 and method != 'None':
                issues.append('PLACEMENT_INACTIVE_FOR_PERIOD')
            if method == 'Full':
                included_count += 1
                if not decision['controlConfirmed']:
                    issues.append('CONTROL_DECISION_REQUIRED')
                if row['pown'] is None:
                    issues.append('POWN_REQUIRED')
                if pcon != 100:
                    issues.append('FULL_PCON_MUST_BE_100')
            elif method == 'Equity':
                included_count += 1
                if decision['controlConfirmed']:
                    issues.append('EQUITY_CONTROL_CONFLICT')
                if row['pown'] is None:
                    issues.append('POWN_REQUIRED')
                elif not Decimal(0) < row['pown'] <= Decimal(100):
                    issues.append('EQUITY_POWN_INVALID')
            elif method == 'Proportional':
                included_count += 1
                if decision['controlConfirmed']:
                    issues.append('PROPORTIONAL_CONTROL_CONFLICT')
                if pcon_fallback:
                    issues.append('PCON_REQUIRED')
                elif not Decimal(0) < pcon <= Decimal(100):
                    issues.append('PROPORTIONAL_PCON_INVALID')
            elif decision['controlConfirmed']:
                issues.append('EXCLUDED_PLACEMENT_CONTROL_CONFLICT')
            assessed.append({
                'relationshipId': row['relationship_id'],
                'childEntityId': row['child_member_id'],
                'method': method,
                'controlConfirmed': decision['controlConfirmed'],
                'pown': format(row['pown'], '.8f')
                    if row['pown'] is not None else None,
                'pctrl': format(row['pctrl'], '.8f')
                    if row['pctrl'] is not None else None,
                'effectivePcon': format(pcon, '.8f'),
                'pconFallback': pcon_fallback,
                'periodActive': row['active'] != 0,
                'periodActiveFallback': row['active'] is None,
                'issues': issues,
            })
        scope_issues = []
        if included_count == 0:
            scope_issues.append('NO_INCLUDED_PLACEMENTS')
        return {**context,
                'metadataRevision': state['metadata_revision'],
                'policyRevision': state['policy_revision'],
                'commitRevision': state['commit_revision'],
                'placements': assessed,
                'issues': scope_issues,
                'structurallyEligible': (not scope_issues and
                    all(not item['issues'] for item in assessed)),
                'accountingPolicyStatus': 'Unreviewed',
                'executable': False}
