"""Exact, no-effect Amount × explicit resolved FX rate preview.

This generic FP&A primitive binds the source Amount to its Entity default
currency and re-resolves an established currency-rate contract in the same
scoped transaction.  It does not infer statutory translation stages, account
classification, CTA, PVA/VAL policy, or a publishable target coordinate.
"""
from __future__ import annotations

from decimal import Decimal
from fractions import Fraction
import re

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_currency_rates import PostgresCurrencyRates
from .postgres_currency_translation import _fixed8
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


FUNCTION = 'currency.amount.translate.preview'
_CHANGE = re.compile(r'.{1,200}\Z')


def _arguments(program: object) -> dict:
    required = {'coordinate', 'sourceAmount', 'sourceChangeId',
                'fromCurrencyMemberId', 'toCurrencyMemberId', 'rateKind',
                'expectedRate', 'expectedDataRevision', 'rounding'}
    if (type(program) is not dict
            or set(program) != {'languageVersion', 'function', 'arguments'}
            or program.get('languageVersion') != 2
            or program.get('function') != FUNCTION
            or type(program.get('arguments')) is not dict
            or set(program['arguments']) != required):
        raise ValueError('CURRENCY_AMOUNT_PREVIEW_INVALID')
    args = program['arguments']
    if (args['rateKind'] not in ('balance', 'flow')
            or args['rounding'] != 'half-even-final-8'
            or type(args['expectedDataRevision']) is not int
            or args['expectedDataRevision'] < 0
            or any(type(args[key]) is not str
                   or not 1 <= len(args[key]) <= 200
                   or args[key] != args[key].strip()
                   for key in ('fromCurrencyMemberId',
                               'toCurrencyMemberId'))
            or args['fromCurrencyMemberId'] == args['toCurrencyMemberId']
            or type(args['sourceChangeId']) is not str
            or _CHANGE.fullmatch(args['sourceChangeId']) is None):
        raise ValueError('CURRENCY_AMOUNT_PREVIEW_PINS_INVALID')
    amount = NumericCell.from_wire(
        present=True, amount=args['sourceAmount']).amount
    expected = args['expectedRate']
    if (type(expected) is not dict
            or set(expected) != {'strategy', 'exactFactor',
                                 'sourceChangeIds'}
            or type(expected['strategy']) is not str
            or not 1 <= len(expected['strategy']) <= 100
            or type(expected['exactFactor']) is not dict
            or set(expected['exactFactor']) != {'numerator', 'denominator'}
            or any(type(expected['exactFactor'][key]) is not str
                   or not re.fullmatch(r'-?[0-9]+',
                                       expected['exactFactor'][key])
                   for key in ('numerator', 'denominator'))
            or int(expected['exactFactor']['denominator']) <= 0
            or int(expected['exactFactor']['numerator']) <= 0
            or type(expected['sourceChangeIds']) is not list
            or not 1 <= len(expected['sourceChangeIds']) <= 2
            or any(type(value) is not str or _CHANGE.fullmatch(value) is None
                   for value in expected['sourceChangeIds'])
            or len(set(expected['sourceChangeIds'])) !=
               len(expected['sourceChangeIds'])):
        raise ValueError('CURRENCY_AMOUNT_PREVIEW_RATE_PIN_INVALID')
    return {**args, 'coordinate': Coordinate.from_mapping(args['coordinate']),
            'sourceAmount': amount}


def exact_translation(source_amount: Decimal, expected_rate: dict) -> str:
    """Apply an already validated resolver factor with one final scale-8 round."""
    factor = Fraction(int(expected_rate['exactFactor']['numerator']),
                      int(expected_rate['exactFactor']['denominator']))
    translated = _fixed8(Fraction(source_amount) * factor)
    NumericCell.from_wire(present=True, amount=translated)
    return translated


class PostgresCurrencyAmountPreview:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def preview(self, scope: ApplicationScope, program: dict) -> dict:
        args = _arguments(program)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                return evaluate_in_transaction(
                    db, scope, self.identity, args, permission='read',
                    function=FUNCTION)


def evaluate_in_transaction(db, scope: ApplicationScope,
                            identity: VerifiedIdentity, args: dict, *,
                            permission: str, function: str,
                            lock_state: bool = True) -> dict:
        """Revalidate one parsed Amount×Rate intent in the caller's transaction."""
        rate_program = {'languageVersion': 2,
            'function': 'currency.rate.resolve', 'arguments': {
                'coordinate': dict(args['coordinate'].members),
                'fromCurrencyMemberId': args['fromCurrencyMemberId'],
                'toCurrencyMemberId': args['toCurrencyMemberId'],
                'rateKind': args['rateKind']}}
        configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(
            db, identity, scope, permission,
            function=(function if lock_state else None))
        rate = PostgresCurrencyRates(
            'in-transaction', identity=identity).resolve_in_transaction(
                db, scope, rate_program, lock_state=lock_state)
        if rate['dataRevision'] != args['expectedDataRevision']:
                    raise ValueError('STALE_CURRENCY_AMOUNT_PREVIEW')
        observed_rate = {
                    'strategy': rate['strategy'],
                    'exactFactor': rate['exactFactor'],
                    'sourceChangeIds': [item['changeId']
                                        for item in rate['sources']]}
        if observed_rate != args['expectedRate']:
                    raise ValueError('STALE_CURRENCY_AMOUNT_RATE')
        keys = (scope.workspace_id, scope.application_id)
        roles = db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active'
                    AND model_role IN ('Entity','Account')
                    ORDER BY model_role,dimension_id''', keys).fetchall()
        by_role = {}
        for row in roles:
                    if row['model_role'] in by_role:
                        raise ValueError('CURRENCY_AMOUNT_MODEL_ROLE_AMBIGUOUS')
                    by_role[row['model_role']] = row['dimension_id']
        if set(by_role) != {'Entity', 'Account'}:
                    raise ValueError('CURRENCY_AMOUNT_MODEL_ROLES_REQUIRED')
        members = dict(args['coordinate'].members)
        entity = db.execute('''SELECT
                    entity_default_currency_member_id AS currency_id
                    FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id=%s AND status='Active' ''', (*keys,
                    by_role['Entity'], members.get(by_role['Entity']))).fetchone()
        if (entity is None or entity['currency_id'] !=
                        args['fromCurrencyMemberId']):
                    raise ValueError('CURRENCY_AMOUNT_SOURCE_UNIT_MISMATCH')
        if members.get(by_role['Account']) == rate['rateAccountMemberId']:
                    raise ValueError('CURRENCY_AMOUNT_RATE_ACCOUNT_SOURCE')
        source = db.execute('''SELECT c.coordinate_id,c.members,
                    n.amount,n.change_id,n.last_revision
                    FROM epm.coordinate c JOIN epm.numeric_cell_current n
                    USING(workspace_id,application_id,coordinate_id)
                    WHERE c.workspace_id=%s AND c.application_id=%s
                    AND c.series_key=%s AND n.present''', (*keys,
                    args['coordinate'].series_key)).fetchone()
        if (source is None or source['members'] != members
                        or source['amount'] != args['sourceAmount']
                        or source['change_id'] != args['sourceChangeId']):
                    raise ValueError('STALE_CURRENCY_AMOUNT_SOURCE')
        translated = exact_translation(args['sourceAmount'], observed_rate)

        lineage = {'source': {'coordinateId': source['coordinate_id'],
                    'members': members,
                    'amount': format(args['sourceAmount'], '.8f'),
                    'changeId': source['change_id'],
                    'lastRevision': source['last_revision'],
                    'unit': {'type': 'Currency',
                             'memberId': args['fromCurrencyMemberId'],
                             'binding': 'EntityDefaultCurrency'}},
            'rate': {**observed_rate, 'rateKind': args['rateKind'],
                     'rateAccountMemberId': rate['rateAccountMemberId'],
                     'sources': rate['sources']},
            'targetUnit': {'type': 'Currency',
                           'memberId': args['toCurrencyMemberId']},
            'revisions': {key: rate[key] for key in
                          ('metadataRevision', 'dataRevision',
                           'policyRevision', 'commitRevision')}}
        result = {'sourceAmount': format(args['sourceAmount'], '.8f'),
            'fromCurrencyMemberId': args['fromCurrencyMemberId'],
            'toCurrencyMemberId': args['toCurrencyMemberId'],
            'rateKind': args['rateKind'], 'rate': observed_rate,
            'translatedAmount': translated,
            'rounding': 'half-even-final-8',
            'effects': 'None', 'publicationSupported': False,
            'consolidationTranslation': False, 'lineage': lineage}
        return {**result, 'previewDigest': _canonical_digest(result)}
