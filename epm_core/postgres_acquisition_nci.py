"""Bounded acquisition-date NCI/goodwill candidate, never a posted close.

This supports a declared single-step acquisition of ordinary present ownership
interests. A current draft supplies an explicit measurement choice; fixed core
rules reject a choice outside the stated IFRS/US GAAP family. It neither
assesses control nor promotes the draft to reviewed accounting policy.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_EVEN, localcontext

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_ownership import PostgresOwnershipValues
from .postgres_policy_drafts import (
    ELECTIONS_FUNCTION, _program as _policy_program,
    validate_elections_in_transaction)


FUNCTION = 'consolidation.acquisition.nci.measure.inspect'
STEP_FUNCTION = 'consolidation.acquisition.step.measure.inspect'
_SCALE = Decimal('0.00000001')


def _amount(value: object, field: str) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f'{field}_DECIMAL_STRING_REQUIRED')
    try:
        amount = Decimal(value)
        NumericCell(True, amount, '')
    except (ArithmeticError, ValueError) as error:
        raise ValueError(f'{field}_AMOUNT_INVALID') from error
    return amount


def _program(raw: object) -> tuple[dict, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != FUNCTION
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('ACQUISITION_NCI_PROGRAM_INVALID')
    args = raw['arguments']
    if set(args) != {'policyId', 'effectiveOn', 'selections',
                     'expectedPolicyRevision', 'acquisitionType',
                     'nciInstrumentClass', 'controlConfirmed',
                     'relationshipId', 'scenarioId', 'yearId', 'periodId',
                     'ownershipPercent', 'considerationTransferred',
                     'identifiableNetAssets', 'nciFairValue'}:
        raise ValueError('ACQUISITION_NCI_ARGUMENTS_INVALID')
    if any(not isinstance(args[key], str) or not 1 <= len(args[key]) <= 200
           for key in ('relationshipId', 'scenarioId', 'yearId', 'periodId')):
        raise ValueError('ACQUISITION_OWNERSHIP_CONTEXT_INVALID')
    policy = _policy_program({'languageVersion': 2,
        'function': ELECTIONS_FUNCTION,
        'arguments': {key: args[key] for key in ('policyId',
            'effectiveOn', 'selections', 'expectedPolicyRevision')}},
        ELECTIONS_FUNCTION)
    if (args['acquisitionType'] != 'single_step'
            or args['nciInstrumentClass'] !=
                'present_ownership_proportionate_liquidation'
            or args['controlConfirmed'] is not True):
        raise ValueError('ACQUISITION_NCI_SCOPE_UNSUPPORTED')
    ownership = _amount(args['ownershipPercent'], 'OWNERSHIP_PERCENT')
    consideration = _amount(args['considerationTransferred'],
                            'CONSIDERATION')
    net_assets = _amount(args['identifiableNetAssets'], 'NET_ASSETS')
    fair = (None if args['nciFairValue'] is None else
            _amount(args['nciFairValue'], 'NCI_FAIR_VALUE'))
    if (not Decimal(0) < ownership <= Decimal(100)
            or consideration < 0 or net_assets < 0
            or fair is not None and fair < 0):
        raise ValueError('ACQUISITION_NCI_INPUT_RANGE_INVALID')
    return policy, {'relationshipId': args['relationshipId'],
                    'scenarioId': args['scenarioId'],
                    'yearId': args['yearId'],
                    'periodId': args['periodId'],
                    'ownershipPercent': ownership,
                    'considerationTransferred': consideration,
                    'identifiableNetAssets': net_assets,
                    'nciFairValue': fair}


def _evaluate_in_transaction(db, scope: ApplicationScope,
                             policy: dict, amounts: dict, state: dict) -> dict:
    """Evaluate one already parsed candidate under a checked caller transaction."""
    draft = validate_elections_in_transaction(
        db, scope, policy, state)
    ownership_query = {key: amounts[key] for key in
        ('relationshipId', 'scenarioId', 'yearId', 'periodId')}
    ownership_query['account'] = 'POWN'
    PostgresOwnershipValues._active_context(
        db, scope, ownership_query)
    recorded = db.execute('''SELECT present,amount,change_id,
        last_revision FROM epm.ownership_value_current
        WHERE workspace_id=%s AND application_id=%s
        AND relationship_id=%s AND scenario_member_id=%s
        AND year_member_id=%s AND period_member_id=%s
        AND account_name='POWN' ''',
        (scope.workspace_id, scope.application_id,
         amounts['relationshipId'], amounts['scenarioId'],
         amounts['yearId'], amounts['periodId'])).fetchone()
    if recorded is None or not recorded['present']:
        raise ValueError('ACQUISITION_POWN_UNAVAILABLE')
    if recorded['amount'] != amounts['ownershipPercent']:
        raise ValueError('ACQUISITION_POWN_MISMATCH')
    period = db.execute('''SELECT starts_on,ends_before,change_id,
        last_revision FROM epm.calendar_period_current
        WHERE workspace_id=%s AND application_id=%s
        AND year_member_id=%s AND period_member_id=%s''',
        (scope.workspace_id, scope.application_id,
         amounts['yearId'], amounts['periodId'])).fetchone()
    if period is None or not (
            period['starts_on'] <= policy['effectiveOn']
            < period['ends_before']):
        raise ValueError('ACQUISITION_PERIOD_DATE_MISMATCH')
    choice = draft['selections'].get('nciAcquisitionMeasurement')
    if choice not in ('fair_value', 'proportionate_share'):
        raise ValueError('NCI_MEASUREMENT_ELECTION_REQUIRED')
    if draft['family'] == 'US_GAAP' and choice != 'fair_value':
        raise ValueError('NCI_MEASUREMENT_FAMILY_CONFLICT')
    if draft['family'] not in ('IFRS', 'US_GAAP'):
        raise ValueError('NCI_MEASUREMENT_FAMILY_UNSUPPORTED')
    ownership = amounts['ownershipPercent']
    consideration = amounts['considerationTransferred']
    net_assets = amounts['identifiableNetAssets']
    fair = amounts['nciFairValue']
    with localcontext() as precision:
        precision.prec = 80
        exact_proportionate = (net_assets *
            (Decimal(100) - ownership) / Decimal(100))
        proportionate = exact_proportionate.quantize(
            _SCALE, rounding=ROUND_HALF_EVEN)
        if choice == 'fair_value':
            if fair is None:
                raise ValueError('NCI_FAIR_VALUE_REQUIRED')
            nci = fair
        else:
            if fair is not None:
                raise ValueError('NCI_FAIR_VALUE_NOT_APPLICABLE')
            nci = proportionate
        if ownership == Decimal(100) and nci != 0:
            raise ValueError('NCI_FULL_OWNERSHIP_CONFLICT')
        goodwill = consideration + nci - net_assets
    NumericCell(True, proportionate, '')
    NumericCell(True, nci, '')
    NumericCell(True, goodwill, '')
    if goodwill < 0:
        raise ValueError('BARGAIN_PURCHASE_REASSESSMENT_REQUIRED')
    return {'policyId': draft['policyId'],
        'policyVersion': draft['version'],
        'policyFamily': draft['family'],
        'policyRevision': draft['policyRevision'],
        'draftDigest': draft['draftDigest'],
        'selectionDigest': draft['selectionDigest'],
        'acquisitionDate': draft['effectiveOn'],
        'measurement': choice,
        'ownershipPercent': format(ownership, '.8f'),
        'ownershipSource': {
            **ownership_query,
            'changeId': recorded['change_id'],
            'lastRevision': recorded['last_revision']},
        'calendarSource': {
            'startsOn': period['starts_on'].isoformat(),
            'endsBefore': period['ends_before'].isoformat(),
            'changeId': period['change_id'],
            'lastRevision': period['last_revision']},
        'considerationTransferred': format(consideration, '.8f'),
        'identifiableNetAssets': format(net_assets, '.8f'),
        'proportionateNetAssetsNci': format(proportionate, '.8f'),
        'nciAtAcquisition': format(nci, '.8f'),
        'goodwillCandidate': format(goodwill, '.8f'),
        'observedCommitRevision': state['commit_revision'],
        'accountingPolicyStatus': 'DraftUnreviewed',
        'publicationSupported': False,
        'requiredBeforePosting': [
            'independently reviewed policy and acquisition fixture',
            'validated identifiable asset and liability values',
            'step acquisition and exception assessment',
            'journal target mapping and close approval']}


class PostgresAcquisitionNciInspector:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, raw: object) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        policy, amounts = _program(raw)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=raw['function'])
                return _evaluate_in_transaction(
                    db, scope, policy, amounts, state)


def _step_program(raw: object) -> tuple[dict, dict, dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != STEP_FUNCTION
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('ACQUISITION_STEP_PROGRAM_INVALID')
    args = raw['arguments']
    required = {'policyId', 'effectiveOn', 'selections',
        'expectedPolicyRevision', 'relationshipId', 'scenarioId',
        'yearId', 'periodId', 'priorControlConfirmed',
        'controlConfirmed', 'priorInterestPercent',
        'additionalInterestPercent', 'finalOwnershipPercent',
        'priorInterestCarryingAmount', 'priorInterestFairValue',
        'considerationTransferred', 'identifiableNetAssets'}
    if (set(args) != required
            or args['priorControlConfirmed'] is not False
            or args['controlConfirmed'] is not True
            or any(not isinstance(args[key], str)
                   or not 1 <= len(args[key]) <= 200
                   for key in ('relationshipId', 'scenarioId',
                               'yearId', 'periodId'))):
        raise ValueError('ACQUISITION_STEP_ARGUMENTS_INVALID')
    policy = _policy_program({'languageVersion': 2,
        'function': ELECTIONS_FUNCTION,
        'arguments': {key: args[key] for key in (
            'policyId', 'effectiveOn', 'selections',
            'expectedPolicyRevision')}}, ELECTIONS_FUNCTION)
    amounts = {key: _amount(args[key], key.upper()) for key in (
        'priorInterestPercent', 'additionalInterestPercent',
        'finalOwnershipPercent', 'priorInterestCarryingAmount',
        'priorInterestFairValue', 'considerationTransferred',
        'identifiableNetAssets')}
    if (not Decimal(0) < amounts['priorInterestPercent'] < Decimal(100)
            or not Decimal(0) < amounts['additionalInterestPercent']
            or amounts['finalOwnershipPercent'] != Decimal(100)
            or amounts['priorInterestPercent'] +
               amounts['additionalInterestPercent'] != Decimal(100)
            or any(amounts[key] < 0 for key in (
                'priorInterestCarryingAmount',
                'priorInterestFairValue', 'considerationTransferred',
                'identifiableNetAssets'))):
        raise ValueError('ACQUISITION_STEP_INPUT_RANGE_INVALID')
    return args, policy, amounts


def _evaluate_step_in_transaction(db, scope: ApplicationScope,
                                  args: dict, policy: dict,
                                  amounts: dict, state: dict) -> dict:
    keys = (scope.workspace_id, scope.application_id)
    draft = validate_elections_in_transaction(
        db, scope, policy, state)
    choice = draft['selections'].get(
        'nciAcquisitionMeasurement')
    if (choice not in ('fair_value', 'proportionate_share')
            or draft['family'] == 'US_GAAP'
            and choice != 'fair_value'
            or draft['family'] not in ('IFRS', 'US_GAAP')):
        raise ValueError('ACQUISITION_STEP_POLICY_UNSUPPORTED')
    context = {key: args[key] for key in (
        'relationshipId', 'scenarioId',
        'yearId', 'periodId')}
    context['account'] = 'POWN'
    PostgresOwnershipValues._active_context(
        db, scope, context)
    ownership = db.execute('''SELECT present,amount,change_id,
        last_revision FROM epm.ownership_value_current
        WHERE workspace_id=%s AND application_id=%s
        AND relationship_id=%s AND scenario_member_id=%s
        AND year_member_id=%s AND period_member_id=%s
        AND account_name='POWN' ''',
        (*keys, args['relationshipId'], args['scenarioId'],
         args['yearId'], args['periodId'])).fetchone()
    if (ownership is None or not ownership['present']
            or ownership['amount'] != Decimal(100)):
        raise ValueError('ACQUISITION_STEP_FINAL_POWN_MISMATCH')
    period = db.execute('''SELECT starts_on,ends_before,
        change_id,last_revision
        FROM epm.calendar_period_current
        WHERE workspace_id=%s AND application_id=%s
        AND year_member_id=%s AND period_member_id=%s''',
        (*keys, args['yearId'], args['periodId'])).fetchone()
    if (period is None or not (
            period['starts_on'] <= policy['effectiveOn']
            < period['ends_before'])):
        raise ValueError('ACQUISITION_PERIOD_DATE_MISMATCH')
    remeasurement = (amounts['priorInterestFairValue'] -
                     amounts['priorInterestCarryingAmount'])
    goodwill = (amounts['considerationTransferred'] +
                amounts['priorInterestFairValue'] -
                amounts['identifiableNetAssets'])
    NumericCell(True, remeasurement, '')
    NumericCell(True, goodwill, '')
    if goodwill < 0:
        raise ValueError(
            'BARGAIN_PURCHASE_REASSESSMENT_REQUIRED')
    return {'policyId': draft['policyId'],
        'policyVersion': draft['version'],
        'policyFamily': draft['family'],
        'policyRevision': draft['policyRevision'],
        'draftDigest': draft['draftDigest'],
        'selectionDigest': draft['selectionDigest'],
        'acquisitionDate': draft['effectiveOn'],
        'priorInterestPercent': format(
            amounts['priorInterestPercent'], '.8f'),
        'additionalInterestPercent': format(
            amounts['additionalInterestPercent'], '.8f'),
        'finalOwnershipPercent': '100.00000000',
        'priorInterestCarryingAmount': format(
            amounts['priorInterestCarryingAmount'], '.8f'),
        'priorInterestFairValue': format(
            amounts['priorInterestFairValue'], '.8f'),
        'considerationTransferred': format(
            amounts['considerationTransferred'], '.8f'),
        'identifiableNetAssets': format(
            amounts['identifiableNetAssets'], '.8f'),
        'remeasurementGainOrLossCandidate': format(
            remeasurement, '.8f'),
        'goodwillCandidate': format(goodwill, '.8f'),
        'ownershipSource': {**context,
            'changeId': ownership['change_id'],
            'lastRevision': ownership['last_revision']},
        'calendarSource': {
            'startsOn': period['starts_on'].isoformat(),
            'endsBefore': period['ends_before'].isoformat(),
            'changeId': period['change_id'],
            'lastRevision': period['last_revision']},
        'observedCommitRevision': state['commit_revision'],
        'priorOwnershipEvidenceStatus':
            'CallerDeclaredUnverified',
        'controlAssessmentStatus':
            'CallerDeclaredUnverified',
        'valuationEvidenceStatus':
            'CallerDeclaredUnverified',
        'accountingPolicyStatus': 'DraftUnreviewed',
        'publicationSupported': False}


class PostgresAcquisitionStepInspector:
    """Read-only 100%-ownership step-acquisition arithmetic candidate.

    Prior interest, control and valuations are explicit caller assertions.
    This does not assess those assertions or publish an accounting result.
    """

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, raw: object) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args, policy, amounts = _step_program(raw)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=raw['function'])
                return _evaluate_step_in_transaction(
                    db, scope, args, policy, amounts, state)
