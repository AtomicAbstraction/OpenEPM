"""Typed application currency settings over classified rate Accounts.

The configured account IDs point to authoritative fact sources, not a second
rate writer. Translation publication remains a later fixed-core stage.
"""
from __future__ import annotations

import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


SAVE = 'currency.settings.save'
READ = 'currency.settings.read'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_REFERENCE_FIELDS = {
    'applicationCurrencyMemberId': 'Currency',
    'balanceRateAccountMemberId': 'Account',
    'flowRateAccountMemberId': 'Account',
    'entityNoneMemberId': 'Entity',
    'entityCurrencyValueMemberId': 'Value',
    'ytdViewMemberId': 'View',
    'icpNoneMemberId': 'ICP',
}
_CUSTOM_FIELDS = ('fromCurrencyDimensionId', 'toCurrencyDimensionId')
_METHOD_FIELDS = ('balanceMethod', 'flowMethod')
_REQUIRED_ROLES = {
    'Scenario', 'Year', 'Period', 'View', 'Entity', 'Value',
    'Account', 'ICP', 'Currency',
}


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('V2_CURRENCY_SETTINGS_FUNCTION_INVALID')
    args = raw['arguments']
    if function == READ:
        if args:
            raise ValueError('V2_CURRENCY_SETTINGS_ARGUMENTS_INVALID')
        return args
    expected = (set(_REFERENCE_FIELDS) | set(_CUSTOM_FIELDS) |
                set(_METHOD_FIELDS) |
                {'expectedMetadataRevision', 'expectedPolicyRevision'})
    if set(args) != expected:
        raise ValueError('V2_CURRENCY_SETTINGS_ARGUMENTS_INVALID')
    for key in set(_REFERENCE_FIELDS) | set(_CUSTOM_FIELDS):
        value = args[key]
        if (not isinstance(value, str) or not 1 <= len(value) <= 200
                or value != value.strip() or '\x00' in value):
            raise ValueError('V2_CURRENCY_SETTINGS_REFERENCE_INVALID')
    for key in _METHOD_FIELDS:
        if args[key] not in ('PVA', 'VAL'):
            raise ValueError('V2_CURRENCY_SETTINGS_METHOD_INVALID')
    for key in ('expectedMetadataRevision', 'expectedPolicyRevision'):
        if type(args[key]) is not int or args[key] < 0:
            raise ValueError('V2_CURRENCY_SETTINGS_REVISION_INVALID')
    if args[_CUSTOM_FIELDS[0]] == args[_CUSTOM_FIELDS[1]]:
        raise ValueError('CURRENCY_RATE_AXES_MUST_DIFFER')
    return args


def _validated_settings(db, scope: ApplicationScope, args: dict) -> dict:
    keys = (scope.workspace_id, scope.application_id)
    dimensions = db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
          AND model_role IS NOT NULL''', keys).fetchall()
    roles: dict[str, str] = {}
    custom = set()
    for row in dimensions:
        if row['model_role'] == 'Custom':
            custom.add(row['dimension_id'])
        elif row['model_role'] in roles:
            raise ValueError('CURRENCY_MODEL_ROLE_AMBIGUOUS')
        else:
            roles[row['model_role']] = row['dimension_id']
    if not _REQUIRED_ROLES <= set(roles):
        raise ValueError('CURRENCY_MODEL_ROLES_REQUIRED')
    if any(args[field] not in custom for field in _CUSTOM_FIELDS):
        raise ValueError('CURRENCY_RATE_AXES_REQUIRED')
    for field, role in _REFERENCE_FIELDS.items():
        member = db.execute('''SELECT name,financial_account_type FROM epm.member
            WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=%s AND member_id=%s AND status='Active' ''',
            (*keys, roles[role], args[field])).fetchone()
        if member is None:
            raise ValueError('CURRENCY_SETTINGS_MEMBER_UNAVAILABLE')
        if field == 'applicationCurrencyMemberId':
            application_currency_name = member['name']
        if field in ('balanceRateAccountMemberId',
                     'flowRateAccountMemberId') and member[
                         'financial_account_type'] != 'CURRENCYRATE':
            raise ValueError('CURRENCY_RATE_ACCOUNT_TYPE_REQUIRED')
    for field in ('balanceRateAccountMemberId',
                  'flowRateAccountMemberId'):
        if db.execute('''SELECT 1 FROM epm.relationship
            WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=%s AND parent_member_id=%s
              AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
            (*keys, roles['Account'], args[field])).fetchone():
            raise ValueError('CURRENCY_RATE_ACCOUNT_MUST_BE_LEAF')
    for field in _CUSTOM_FIELDS:
        if not db.execute('''SELECT 1 FROM epm.member
            WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=%s AND lower(name)=lower(%s)
              AND status='Active' ''',
            (*keys, args[field], application_currency_name)).fetchone():
            raise ValueError('APPLICATION_CURRENCY_RATE_MEMBER_MISSING')
    return {key: args[key] for key in sorted(set(_REFERENCE_FIELDS) |
                                             set(_CUSTOM_FIELDS) |
                                             set(_METHOD_FIELDS))} | {
        'validatedMetadataRevision': args['expectedMetadataRevision']}


class PostgresCurrencySettings:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        _program(raw, READ)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT currency_settings,
                    metadata_revision,policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                      AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                settings = state['currency_settings']
                status = ('Unconfigured' if settings is None else
                          'Stale' if settings.get('validatedMetadataRevision')
                          != state['metadata_revision'] else 'Unreviewed')
                return {'configured': settings is not None,
                        'status': status,
                        'settings': settings,
                        'metadataRevision': state['metadata_revision'],
                        'policyRevision': state['policy_revision'],
                        'commitRevision': state['commit_revision']}

    def save(self, scope: ApplicationScope, raw: dict, *,
             idempotency_key: str) -> dict:
        args = _program(raw, SAVE)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('CURRENCY_SETTINGS_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': raw})
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT s.currency_settings,
                    s.metadata_revision,s.policy_revision,s.commit_revision,
                    s.processing_mode,a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                      USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin')
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                      AND application_id=%s AND operation_id=%s''',
                    (*keys, idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != digest or
                            prior['actor_id'] != self.identity.subject_id):
                        raise ValueError('CURRENCY_SETTINGS_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if (state['application_status'] != 'Active' or
                        state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['metadata_revision'] !=
                        args['expectedMetadataRevision'] or
                        state['policy_revision'] !=
                        args['expectedPolicyRevision']):
                    raise ValueError('STALE_CURRENCY_SETTINGS_REVISION')
                settings = _validated_settings(db, scope, args)
                if state['currency_settings'] == settings:
                    raise ValueError('CURRENCY_SETTINGS_UNCHANGED')
                policy_revision = state['policy_revision'] + 1
                revision = state['commit_revision'] + 1
                from .postgres_calculation_impact import object_impact
                impact = object_impact(source_kind='layout',
                    operation_id=idempotency_key,causal_revision=revision,
                    domain='layout',object_type='currency-settings',
                    object_id='active',change='replace',
                    reason='unit_policy_changed')
                result = {'operationId': idempotency_key,
                          'status': 'Unreviewed',
                          'policyRevision': policy_revision,
                          'committedRevision': revision,
                          'settings': settings,
                          'impactDigest': impact.digest}
                db.execute('''UPDATE epm.application_state SET
                    currency_settings=%s,policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (Jsonb(settings), policy_revision, revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key, digest,
                     self.identity.subject_id, revision, Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                return result
