"""Read-only, exact PVA/VAL translation inspection over current V2 facts.

This is an unreviewed calculation preview. Account classification and entity
default currency are checked; target Value selection and publication remain
separate policy steps. No translated fact is written here.
"""
from __future__ import annotations

from fractions import Fraction

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_currency_rates import PostgresCurrencyRates, FUNCTION as RATE
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'currency.translation.inspect'


def _fixed8(value: Fraction) -> str:
    """Round an exact rational to the numeric-cell scale, ties to even."""
    negative = value < 0
    quotient, remainder = divmod(abs(value.numerator) * 100_000_000,
                                  value.denominator)
    if 2 * remainder > value.denominator or (
            2 * remainder == value.denominator and quotient % 2):
        quotient += 1
    whole, decimal = divmod(quotient, 100_000_000)
    return f'{"-" if negative and quotient else ""}{whole}.{decimal:08d}'


def _rational(value: Fraction) -> dict[str, str]:
    return {'numerator': str(value.numerator),
            'denominator': str(value.denominator)}


def _program(raw: object) -> tuple[dict, str, str, str, str]:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != FUNCTION
            or not isinstance(raw['arguments'], dict)
            or set(raw['arguments']) != {'coordinate',
                'fromCurrencyMemberId', 'toCurrencyMemberId',
                'rateKind', 'method'}):
        raise ValueError('V2_CURRENCY_TRANSLATION_ARGUMENTS_INVALID')
    args = raw['arguments']
    if (args['rateKind'] not in ('balance', 'flow')
            or args['method'] not in ('PVA', 'VAL')
            or any(not isinstance(args[key], str)
                   or not 1 <= len(args[key]) <= 200
                   or args[key] != args[key].strip()
                   for key in ('fromCurrencyMemberId',
                               'toCurrencyMemberId'))):
        raise ValueError('V2_CURRENCY_TRANSLATION_ARGUMENTS_INVALID')
    coordinate = Coordinate.from_mapping(args['coordinate'])
    return (dict(coordinate.members), args['fromCurrencyMemberId'],
            args['toCurrencyMemberId'], args['rateKind'], args['method'])


class PostgresCurrencyTranslation:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, raw: dict, *, source_layer=None, ic_parent=None) -> dict:
        source, from_id, to_id, kind, method = _program(raw)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function='currency.translation.publish', arguments={'sourceLayer':source_layer})
                state = db.execute('''SELECT currency_settings,
                    metadata_revision,data_revision,policy_revision,
                    commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                settings = state['currency_settings']
                if settings is None:
                    raise ValueError('CURRENCY_SETTINGS_UNCONFIGURED')
                if settings.get('validatedMetadataRevision') != (
                        state['metadata_revision']):
                    raise ValueError('CURRENCY_SETTINGS_METADATA_STALE')
                configured = settings[
                    'balanceMethod' if kind == 'balance' else 'flowMethod']
                if method != configured:
                    raise ValueError('CURRENCY_TRANSLATION_METHOD_CONFLICT')
                roles = {}
                for row in db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active'
                    AND model_role IN (
                        'Year','Period','Account','Value','View','Entity')''',
                    keys).fetchall():
                    if row['model_role'] in roles:
                        raise ValueError('CURRENCY_MODEL_ROLE_AMBIGUOUS')
                    roles[row['model_role']] = row['dimension_id']
                if set(roles) != {
                        'Year','Period','Account','Value','View','Entity'}:
                    raise ValueError('CURRENCY_MODEL_ROLES_REQUIRED')
                if (source.get(roles['Value']) !=
                        settings['entityCurrencyValueMemberId'] or
                        source.get(roles['View']) !=
                        settings['ytdViewMemberId']):
                    raise ValueError('CURRENCY_TRANSLATION_SOURCE_STAGE_INVALID')
                if source.get(roles['Account']) in (
                        settings['balanceRateAccountMemberId'],
                        settings['flowRateAccountMemberId']):
                    raise ValueError('CURRENCY_TRANSLATION_RATE_ACCOUNT_SOURCE')
                account = db.execute('''SELECT financial_account_type
                    FROM epm.member WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND member_id=%s AND status='Active' ''',
                    (*keys,roles['Account'],source.get(roles['Account']))
                    ).fetchone()
                if account is None or account['financial_account_type'] is None:
                    raise ValueError('CURRENCY_TRANSLATION_ACCOUNT_TYPE_REQUIRED')
                account_type = account['financial_account_type']
                inferred_kind = (
                    'balance' if account_type in (
                        'ASSET','LIABILITY','BALANCE','BALANCERECURRING')
                    else 'flow' if account_type in (
                        'REVENUE','EXPENSE','FLOW') else None)
                if inferred_kind is None or inferred_kind != kind:
                    raise ValueError('CURRENCY_TRANSLATION_RATE_KIND_CONFLICT')
                entity = db.execute('''SELECT
                    entity_default_currency_member_id FROM epm.member
                    WHERE workspace_id=%s AND application_id=%s
                    AND dimension_id=%s AND member_id=%s AND status='Active' ''',
                    (*keys,roles['Entity'],source.get(roles['Entity']))
                    ).fetchone()
                if (entity is None or
                        entity['entity_default_currency_member_id'] is None):
                    raise ValueError('ENTITY_DEFAULT_CURRENCY_REQUIRED')
                if entity['entity_default_currency_member_id'] != from_id:
                    raise ValueError('CURRENCY_TRANSLATION_SOURCE_CURRENCY_CONFLICT')
                year = source.get(roles['Year'])
                current_period = source.get(roles['Period'])
                periods = db.execute('''SELECT period_member_id,ordinal,
                    change_id,last_revision FROM epm.calendar_period_current
                    WHERE workspace_id=%s AND application_id=%s
                    AND year_member_id=%s ORDER BY ordinal''',
                    (*keys, year)).fetchall()
                current = next((row for row in periods
                                if row['period_member_id'] == current_period),
                               None)
                if current is None:
                    raise ValueError('CURRENCY_TRANSLATION_PERIOD_UNCONFIGURED')
                periods = [row for row in periods
                           if row['ordinal'] <= current['ordinal']]
                if [row['ordinal'] for row in periods] != list(
                        range(1, current['ordinal'] + 1)):
                    raise ValueError('CURRENCY_TRANSLATION_PERIOD_GAP')
                selected = periods if method == 'PVA' else [current]
                coordinates = []
                for period in selected:
                    members = {**source,
                               roles['Period']: period['period_member_id']}
                    coordinate = Coordinate.from_mapping(members)
                    coordinates.append((period, members,
                                        coordinate.series_key))
                rows = db.execute('''SELECT c.coordinate_id,c.series_key,c.members,
                    n.present AS numeric_present,n.amount,n.change_id,
                    n.last_revision,t.present AS text_present
                    FROM epm.coordinate c
                    LEFT JOIN epm.numeric_cell_current n
                      USING (workspace_id,application_id,coordinate_id)
                    LEFT JOIN epm.text_cell_current t
                      USING (workspace_id,application_id,coordinate_id)
                    WHERE c.workspace_id=%s AND c.application_id=%s
                    AND c.series_key=ANY(%s::text[])''',
                    (*keys, [entry[2] for entry in coordinates])).fetchall()
                by_key = {row['series_key']: row for row in rows}
                rate_resolver = PostgresCurrencyRates(
                    self.dsn, identity=self.identity)
                previous = Fraction(0)
                translated = Fraction(0)
                lineage = []
                own_line_count=0
                for period, members, series_key in coordinates:
                    fact = by_key.get(series_key)
                    if fact is not None and fact['members'] != members:
                        raise ValueError('COORDINATE_HASH_COLLISION')
                    if fact is not None and fact['text_present']:
                        raise ValueError('CURRENCY_TRANSLATION_SOURCE_NONNUMERIC')
                    own_lineage=None
                    if source_layer is not None:
                        from .postgres_own_source import resolve_own_source
                        amount,source_change_id,own_lineage=resolve_own_source(db,scope,members,fact,
                            source_layer,from_id,account_type,ic_parent)
                    else:
                        if fact is None or not fact['numeric_present']:
                            raise ValueError('CURRENCY_TRANSLATION_SOURCE_MISSING')
                        amount,source_change_id=fact['amount'],fact['change_id']
                    if own_lineage is not None:
                        own_line_count+=len(own_lineage['journalLines'])+len(own_lineage['acquisitionLines'])+(2 if own_lineage['icElimination'] else 0)
                        if own_line_count>500: raise ValueError('OWN_SOURCE_TOTAL_LINE_LIMIT')
                    cumulative = Fraction(amount)
                    delta = cumulative - previous if method == 'PVA' else cumulative
                    rate = rate_resolver.resolve_in_transaction(db, scope, {
                        'languageVersion': 2, 'function': RATE,
                        'arguments': {'coordinate': members,
                            'fromCurrencyMemberId': from_id,
                            'toCurrencyMemberId': to_id,
                            'rateKind': kind}})
                    factor = Fraction(int(rate['exactFactor']['numerator']),
                                      int(rate['exactFactor']['denominator']))
                    contribution = delta * factor
                    translated += contribution
                    lineage.append({'periodMemberId': period['period_member_id'],
                        'ordinal': period['ordinal'],
                        'calendarChangeId': period['change_id'],
                        'calendarRevision': period['last_revision'],
                        'sourceCoordinate': members,
                        'sourceAmount': format(amount, '.8f'),
                        'sourceChangeId': source_change_id,
                        'sourceRevision': fact['last_revision'] if fact else None,
                        **({'ownSource':own_lineage} if own_lineage is not None else {}),
                        'exactPeriodChange': _rational(delta),
                        'exactContribution': _rational(contribution),
                        'rate': rate})
                    previous = cumulative
                return {'method': method, 'rateKind': kind,
                    'accountType': account_type,
                    'entityDefaultCurrencyMemberId': from_id,
                    'fromCurrencyMemberId': from_id,
                    'toCurrencyMemberId': to_id,
                    'sourceCoordinate': source,
                    'exactAmount': _rational(translated),
                    'roundedAmount': _fixed8(translated),
                    'periods': lineage,
                    'metadataRevision': state['metadata_revision'],
                    'dataRevision': state['data_revision'],
                    'policyRevision': state['policy_revision'],
                    'commitRevision': state['commit_revision'],
                    'reviewStatus': 'Unreviewed',
                    'publicationSupported': False}
