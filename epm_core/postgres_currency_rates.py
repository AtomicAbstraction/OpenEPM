"""Bounded, read-only FX source resolution over authoritative numeric cells.

The result is an exact rational factor and source lineage. No rate table or
second writer exists; translation and accounting certification are separate.
"""
from __future__ import annotations

from decimal import Decimal
from fractions import Fraction

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'currency.rate.resolve'


def _program(raw: object) -> tuple[dict, str, str, str]:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != FUNCTION
            or not isinstance(raw['arguments'], dict)
            or set(raw['arguments']) != {
                'coordinate', 'fromCurrencyMemberId',
                'toCurrencyMemberId', 'rateKind'}):
        raise ValueError('V2_CURRENCY_RATE_ARGUMENTS_INVALID')
    args = raw['arguments']
    if (args['rateKind'] not in ('balance', 'flow')
            or any(not isinstance(args[key], str)
                   or not 1 <= len(args[key]) <= 200
                   or args[key] != args[key].strip()
                   for key in ('fromCurrencyMemberId',
                               'toCurrencyMemberId'))):
        raise ValueError('V2_CURRENCY_RATE_ARGUMENTS_INVALID')
    coordinate = Coordinate.from_mapping(args['coordinate'])
    return (dict(coordinate.members), args['fromCurrencyMemberId'],
            args['toCurrencyMemberId'], args['rateKind'])


class PostgresCurrencyRates:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def resolve(self, scope: ApplicationScope, raw: dict) -> dict:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                return self.resolve_in_transaction(db, scope, raw)

    def resolve_in_transaction(self, db, scope: ApplicationScope,
                               raw: dict, *, lock_state: bool = True) -> dict:
        """Resolve under the caller's scoped transaction.

        The caller must have set the application scope on this connection.
        This entry point lets period-aware translation read sources and rates
        without creating a second snapshot. Publishers that privately compute
        before a final revision fence may disable the shared state-row lock;
        they must then repeat exact revision and rate/source validation under
        their final exclusive publication fence.
        """
        source, from_id, to_id, kind = _program(raw)
        keys = (scope.workspace_id, scope.application_id)
        PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, 'read')
        state = db.execute('''SELECT currency_settings,
            metadata_revision,data_revision,policy_revision,
            commit_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s''' +
            (' FOR SHARE' if lock_state else ''),
            keys).fetchone()
        if state is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        settings = state['currency_settings']
        if settings is None:
            raise ValueError('CURRENCY_SETTINGS_UNCONFIGURED')
        if settings.get('validatedMetadataRevision') != (
                state['metadata_revision']):
            raise ValueError('CURRENCY_SETTINGS_METADATA_STALE')
        dimensions = db.execute('''SELECT dimension_id,model_role
            FROM epm.dimension WHERE workspace_id=%s
              AND application_id=%s AND status='Active' ''',
            keys).fetchall()
        axes = {row['dimension_id'] for row in dimensions
                if row['model_role'] != 'Currency'}
        if set(source) != axes:
            raise ValueError('CURRENCY_RATE_COORDINATE_GRAIN_INVALID')
        roles: dict[str, str] = {}
        custom = []
        for row in dimensions:
            if row['model_role'] == 'Custom':
                custom.append(row['dimension_id'])
            elif row['model_role'] is not None:
                if row['model_role'] in roles:
                    raise ValueError('CURRENCY_MODEL_ROLE_AMBIGUOUS')
                roles[row['model_role']] = row['dimension_id']
        for axis, member in source.items():
            if not db.execute('''SELECT 1 FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s AND member_id=%s
                  AND status='Active' ''',
                (*keys, axis, member)).fetchone():
                raise ValueError('CURRENCY_RATE_COORDINATE_MEMBER_UNAVAILABLE')
        names = db.execute('''SELECT member_id,name FROM epm.member
            WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=%s AND member_id=ANY(%s::text[])
              AND status='Active' ''',
            (*keys, roles['Currency'],
             sorted({from_id, to_id,
                     settings['applicationCurrencyMemberId']}))
            ).fetchall()
        currency_names = {row['member_id']: row['name'].lower()
                          for row in names}
        if set(currency_names) != {from_id, to_id,
                                   settings['applicationCurrencyMemberId']}:
            raise ValueError('CURRENCY_MEMBER_UNAVAILABLE')
        result = {'fromCurrencyMemberId': from_id,
                  'toCurrencyMemberId': to_id,
                  'rateKind': kind,
                  'rateAccountMemberId': settings[
                      'balanceRateAccountMemberId' if kind == 'balance'
                      else 'flowRateAccountMemberId'],
                  'metadataRevision': state['metadata_revision'],
                  'dataRevision': state['data_revision'],
                  'policyRevision': state['policy_revision'],
                  'commitRevision': state['commit_revision'],
                  'reviewStatus': 'Unreviewed'}
        if from_id == to_id:
            return {**result, 'strategy': 'identity',
                    'exactFactor': {'numerator': '1',
                                    'denominator': '1'},
                    'sources': []}
        rate_axes = (settings['fromCurrencyDimensionId'],
                     settings['toCurrencyDimensionId'])
        wanted_names = sorted(set(currency_names.values()))
        rows = db.execute('''SELECT dimension_id,member_id,
            lower(name) AS name FROM epm.member
            WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=ANY(%s::text[])
              AND lower(name)=ANY(%s::text[])
              AND status='Active' ''',
            (*keys, list(rate_axes), wanted_names)).fetchall()
        rate_members = {(row['dimension_id'],row['name']):
                        row['member_id'] for row in rows}
        if any((axis, name) not in rate_members
               for axis in rate_axes for name in wanted_names):
            raise ValueError('CURRENCY_RATE_MEMBER_UNAVAILABLE')
        other_custom = [axis for axis in custom
                        if axis not in rate_axes]
        other_none = {}
        if other_custom:
            rows = db.execute('''SELECT dimension_id,member_id
                FROM epm.member WHERE workspace_id=%s
                  AND application_id=%s
                  AND dimension_id=ANY(%s::text[])
                  AND lower(name)='none' AND status='Active' ''',
                (*keys, other_custom)).fetchall()
            other_none = {row['dimension_id']: row['member_id']
                          for row in rows}
            if set(other_none) != set(other_custom):
                raise ValueError('CURRENCY_RATE_DEFAULT_CUSTOM_MEMBER_MISSING')
        base = dict(source)
        base[roles['Value']] = settings['entityCurrencyValueMemberId']
        base[roles['View']] = settings['ytdViewMemberId']
        base[roles['Account']] = result['rateAccountMemberId']
        base[roles['ICP']] = settings['icpNoneMemberId']
        base.update(other_none)
        candidates = {}
        def candidate(label: str, entity: str,
                      start: str, end: str) -> None:
            members = dict(base)
            members[roles['Entity']] = entity
            members[rate_axes[0]] = rate_members[(
                rate_axes[0], currency_names[start])]
            members[rate_axes[1]] = rate_members[(
                rate_axes[1], currency_names[end])]
            coordinate = Coordinate.from_mapping(members)
            candidates[label] = (coordinate.series_key, members)
        entity = source[roles['Entity']]
        none = settings['entityNoneMemberId']
        candidate('entity-direct', entity, from_id, to_id)
        candidate('entity-inverse', entity, to_id, from_id)
        candidate('none-entity-direct', none, from_id, to_id)
        candidate('none-entity-inverse', none, to_id, from_id)
        app = settings['applicationCurrencyMemberId']
        if app not in (from_id, to_id):
            candidate('triangulation-first-direct', none, from_id, app)
            candidate('triangulation-first-inverse', none, app, from_id)
            candidate('triangulation-second-direct', none, app, to_id)
            candidate('triangulation-second-inverse', none, to_id, app)
        series = sorted({key for key, _ in candidates.values()})
        rows = db.execute('''SELECT c.series_key,c.members,
            n.present AS numeric_present,n.amount,n.change_id,
            n.last_revision,t.present AS text_present
            FROM epm.coordinate c
            LEFT JOIN epm.numeric_cell_current n
              USING (workspace_id,application_id,coordinate_id)
            LEFT JOIN epm.text_cell_current t
              USING (workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND c.series_key=ANY(%s::text[])''',
            (*keys, series)).fetchall()
        by_key = {row['series_key']: row for row in rows}
        def cell(label: str):
            series_key, members = candidates[label]
            row = by_key.get(series_key)
            if row is None:
                return None
            if row['members'] != members:
                raise ValueError('COORDINATE_HASH_COLLISION')
            if row['text_present']:
                raise ValueError('CURRENCY_RATE_NONNUMERIC')
            if not row['numeric_present']:
                return None
            amount: Decimal = row['amount']
            if amount <= 0:
                raise ValueError('CURRENCY_RATE_NONPOSITIVE')
            return (Fraction(amount),
                    {'coordinate': members,
                     'amount': format(amount, '.8f'),
                     'changeId': row['change_id'],
                     'lastRevision': row['last_revision']})
        def pair(direct: str, inverse: str):
            found = cell(direct)
            if found:
                return found[0], [found[1]], 'direct'
            found = cell(inverse)
            if found:
                return 1 / found[0], [found[1]], 'inverse'
            return None
        for prefix in ('entity', 'none-entity'):
            found = pair(prefix+'-direct', prefix+'-inverse')
            if found:
                factor, sources, direction = found
                return {**result,
                        'strategy': prefix+'-'+direction,
                        'exactFactor': {
                            'numerator': str(factor.numerator),
                            'denominator': str(factor.denominator)},
                        'sources': sources}
        if app not in (from_id, to_id):
            first = pair('triangulation-first-direct',
                         'triangulation-first-inverse')
            second = pair('triangulation-second-direct',
                          'triangulation-second-inverse')
            if first and second:
                factor = first[0] * second[0]
                return {**result,
                        'strategy': 'application-currency-triangulation',
                        'exactFactor': {
                            'numerator': str(factor.numerator),
                            'denominator': str(factor.denominator)},
                        'sources': first[1] + second[1]}
        raise ValueError('CURRENCY_RATE_UNAVAILABLE')
