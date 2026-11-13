"""Internal acquisition journal compiler and exact balanced-entry builder.

The V2 language routes preview/admission to this compiler; the effects module
resolves sources and publishes through the fixed worker.
No function in this module connects to a database or grants posting authority.
"""
from __future__ import annotations

from decimal import Decimal, localcontext
import json
import re

from .persistence_contract import Coordinate, NumericCell
from .postgres_policy_activation import _program as _activation_program, RESOLVE
from .postgres_acquisition_nci import FUNCTION as SINGLE, STEP_FUNCTION as STEP

FUNCTION = 'consolidation.acquisition.journal.publish'
COMPILER = 'acquisition-investment-offset-v1'
ACCOUNT_TYPES={
    'netAssetsOffset':frozenset(('BALANCE','LIABILITY','BALANCERECURRING')),
    'goodwill':frozenset(('ASSET',)),'investmentOffset':frozenset(('ASSET',)),
    'nonControllingInterest':frozenset(('BALANCE','LIABILITY')),
    'remeasurementGainOrLoss':frozenset(('REVENUE','EXPENSE'))}

_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_CHANGE=re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_STEP_FIELDS=('priorInterestPercent','additionalInterestPercent',
    'priorInterestCarryingAmount','priorInterestFairValue',
    'considerationTransferred','identifiableNetAssets','priorOciBalance')


def _id(value):
    return isinstance(value,str) and 1<=len(value)<=200 and value==value.strip() and '\0' not in value


def _coordinate(raw):
    if (not isinstance(raw,dict) or not 1<=len(raw)<=32
            or any(not _id(key) or not _id(value) for key,value in raw.items())):
        raise ValueError('ACQUISITION_JOURNAL_COORDINATE_INVALID')
    return Coordinate.from_mapping(raw)


def compile_program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or raw['function']!=FUNCTION or not isinstance(raw['arguments'],dict)):
        raise ValueError('ACQUISITION_JOURNAL_PROGRAM_INVALID')
    args=raw['arguments']
    expected={'acquisitionKey','policyId','policyStateToken','candidateFunction',
        'selections','effectiveOn','activationId','relationshipId','targetMembers',
        'currencyMemberId','sources','accounts','expectedInvestmentChangeId',
        'controlConfirmed','priorControlConfirmed','fairValueBasisConfirmed','reason'}
    if (set(args)!=expected or not isinstance(args['acquisitionKey'],str)
            or not _KEY.fullmatch(args['acquisitionKey'])
            or not isinstance(args['activationId'],str) or not _KEY.fullmatch(args['activationId'])
            or not _id(args['relationshipId']) or not _id(args['currencyMemberId'])
            or args['controlConfirmed'] is not True
            or args['priorControlConfirmed'] is not False
            or args['fairValueBasisConfirmed'] is not True
            or not isinstance(args['reason'],str) or not 1<=len(args['reason'])<=500
            or args['reason']!=args['reason'].strip() or '\0' in args['reason']
            or not isinstance(args['expectedInvestmentChangeId'],str)
            or not _CHANGE.fullmatch(args['expectedInvestmentChangeId'])):
        raise ValueError('ACQUISITION_JOURNAL_ARGUMENTS_INVALID')
    _activation_program({'languageVersion':2,'function':RESOLVE,'arguments':{
        key:args[key] for key in ('policyId','policyStateToken','candidateFunction',
                                  'selections','effectiveOn')}|{'expectedPolicyRevision':0}})
    _coordinate(args['targetMembers'])
    if args['candidateFunction']==SINGLE:
        fields={'considerationTransferred','identifiableNetAssets'}
        if args['selections'].get('nciAcquisitionMeasurement')=='fair_value':
            fields.add('nciFairValue')
        accounts={'netAssetsOffset','goodwill','investmentOffset','nonControllingInterest'}
    else:
        fields=set(_STEP_FIELDS)
        accounts={'netAssetsOffset','goodwill','investmentOffset','remeasurementGainOrLoss'}
    if (not isinstance(args['sources'],dict) or set(args['sources'])!=fields
            or not isinstance(args['accounts'],dict) or set(args['accounts'])!=accounts
            or any(not _id(value) for value in args['accounts'].values())
            or len(set(args['accounts'].values()))!=len(accounts)):
        raise ValueError('ACQUISITION_JOURNAL_SOURCE_OR_ACCOUNT_MAP_INVALID')
    for source in args['sources'].values():
        if (not isinstance(source,dict) or set(source)!={'members','expectedChangeId'}
                or not isinstance(source['expectedChangeId'],str)
                or not _CHANGE.fullmatch(source['expectedChangeId'])):
            raise ValueError('ACQUISITION_JOURNAL_SOURCE_INVALID')
        _coordinate(source['members'])
    return json.loads(json.dumps(raw,sort_keys=True,allow_nan=False))



def balanced_entries(candidate_function: str, source_amounts: dict,
                     measured: dict) -> tuple[tuple[str, Decimal], ...]:
    """Build a debit-positive investment offset from fixed-core measurement.

    Amounts are internal normalized Decimals, not an application-language
    argument. Net assets are positive here; the future source adapter must
    validate/normalize a signed credit balance before calling this builder.
    The caller must resolve current ownership/calendar/policy and source pins.
    This validates arithmetic consistency, not acquisition/control judgments.
    """
    if candidate_function == SINGLE:
        source_keys = {'considerationTransferred', 'identifiableNetAssets'}
        measurement_keys = {'nciAtAcquisition', 'goodwillCandidate'}
    elif candidate_function == STEP:
        source_keys = {'considerationTransferred', 'identifiableNetAssets',
            'priorInterestCarryingAmount', 'priorInterestFairValue', 'priorOciBalance'}
        measurement_keys = {'remeasurementGainOrLossCandidate', 'goodwillCandidate'}
    else:
        raise ValueError('ACQUISITION_CANDIDATE_UNSUPPORTED')
    if (not isinstance(source_amounts, dict) or set(source_amounts) != source_keys
            or not isinstance(measured, dict)
            or not measurement_keys <= measured.keys()):
        raise ValueError('ACQUISITION_MEASUREMENT_SHAPE_INVALID')
    values = dict(source_amounts)
    for value in values.values():
        NumericCell(True, value, '')
    for key in measurement_keys:
        raw = measured[key]
        if not isinstance(raw, str):
            raise ValueError('ACQUISITION_MEASUREMENT_DECIMAL_STRING_REQUIRED')
        try:
            values[key] = Decimal(raw)
            NumericCell(True, values[key], '')
        except (ArithmeticError, ValueError) as error:
            raise ValueError('ACQUISITION_MEASUREMENT_AMOUNT_INVALID') from error
    if any(values[key] < 0 for key in source_keys | {'goodwillCandidate'}):
        raise ValueError('ACQUISITION_NONNEGATIVE_AMOUNTS_REQUIRED')
    with localcontext() as precision:
        precision.prec = 80
        consideration = values['considerationTransferred']
        net_assets = values['identifiableNetAssets']
        goodwill = values['goodwillCandidate']
        if candidate_function == SINGLE:
            nci = values['nciAtAcquisition']
            if nci < 0 or goodwill != consideration + nci - net_assets:
                raise ValueError('ACQUISITION_MEASUREMENT_INCONSISTENT')
            entries = (('netAssetsOffset', net_assets), ('goodwill', goodwill),
                ('investmentOffset', -consideration), ('nonControllingInterest', -nci))
        else:
            if values['priorOciBalance'] != 0:
                raise ValueError('ACQUISITION_PRIOR_OCI_RECLASSIFICATION_UNSUPPORTED')
            carrying = values['priorInterestCarryingAmount']
            fair = values['priorInterestFairValue']
            gain = values['remeasurementGainOrLossCandidate']
            if (gain != fair - carrying
                    or goodwill != consideration + fair - net_assets):
                raise ValueError('ACQUISITION_MEASUREMENT_INCONSISTENT')
            entries = (('netAssetsOffset', net_assets), ('goodwill', goodwill),
                ('investmentOffset', -(consideration + carrying)),
                ('remeasurementGainOrLoss', -gain))
        result = tuple((role, amount) for role, amount in entries if amount != 0)
        if len(result) < 2 or sum((amount for _, amount in result), Decimal(0)) != 0:
            raise ValueError('ACQUISITION_JOURNAL_NOT_BALANCED')
        for _, amount in result:
            NumericCell(True, amount, '')
    return result
