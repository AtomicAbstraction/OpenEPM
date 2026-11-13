"""Sealed, policy-neutral input contract for one consolidation contribution.

This contract does not select an accounting method.  The first compiler only
accepts Full with an explicit coefficient of one.  Equity and Proportional
remain unavailable until independently reviewed source profiles exist.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
import re

from .postgres_jobs import _canonical_digest
from .current_object_contract import require_stable_identifier as _identifier
from .current_object_contract import require_state_token


FUNCTION = 'consolidation.method.contribute'
COMPILER = 'consolidation-contribution-input-v1'
PLAN_DIGEST = _canonical_digest({
    'function': FUNCTION, 'loweringVersion': 1,
    'supportedMethods': ['Full'], 'sourceProfile': 'raw_child_numeric_v1',
    'inputGrain': 'certified_child_full_coordinate',
    'outputGrain': 'parent_full_coordinate',
    'arithmetic': 'Amount*Ratio', 'rounding': 'half-even-final-8',
    'engine': 'postgres_exact_sql',
})
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_OWNERSHIP = ('Active', 'Method', 'PCON', 'PCTRL', 'POWN')


def _decimal(value: object, error: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'-?(0|[1-9][0-9]*)(\.[0-9]+)?', value):
        raise ValueError(error)
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(error) from exc
    if not parsed.is_finite() or parsed.as_tuple().exponent < -8:
        raise ValueError(error)
    return format(parsed, 'f')


@dataclass(frozen=True, slots=True)
class ContributionInputPlan:
    document: dict

    @property
    def digest(self) -> str:
        return _canonical_digest(self.document)


def compile_full_contribution_input(document: object) -> ContributionInputPlan:
    required = {'version','function','method','sourceProfile','relationshipId',
        'scenarioId','yearId','periodId','sourceMembers','targetMembers',
        'sourceChangeId','sourceAmount','methodPreviewDigest',
        'methodPreviewCommitRevision','policy','ownership','coefficient',
        'resultKey','expectedPublicationRevision','inputGrain','outputGrain',
        'rounding','accountingPolicyStatus'}
    if (not isinstance(document, dict) or set(document) != required
            or type(document.get('version')) is not int or document['version'] != 1
            or document.get('function') != FUNCTION
            or document.get('method') != 'Full'
            or document.get('sourceProfile') != 'raw_child_numeric_v1'
            or document.get('inputGrain') != 'certified_child_full_coordinate'
            or document.get('outputGrain') != 'parent_full_coordinate'
            or document.get('rounding') != 'half-even-final-8'
            or document.get('accountingPolicyStatus') != 'Unreviewed'):
        raise ValueError('CONTRIBUTION_INPUT_CONTRACT_INVALID')
    for name in ('relationshipId','scenarioId','yearId','periodId'):
        _identifier(document[name], name)
    if (not isinstance(document['resultKey'], str)
            or not _KEY.fullmatch(document['resultKey'])
            or not isinstance(document['sourceChangeId'], str)
            or not 1 <= len(document['sourceChangeId']) <= 200
            or not isinstance(document['methodPreviewDigest'], str)
            or not _HEX.fullmatch(document['methodPreviewDigest'])
            or type(document['methodPreviewCommitRevision']) is not int
            or document['methodPreviewCommitRevision'] < 0
            or type(document['expectedPublicationRevision']) is not int
            or document['expectedPublicationRevision'] < 0):
        raise ValueError('CONTRIBUTION_INPUT_PINS_INVALID')
    source, target = document['sourceMembers'], document['targetMembers']
    if (not isinstance(source, dict) or not isinstance(target, dict)
            or not 1 <= len(source) <= 32 or set(source) != set(target)
            or any(_identifier(k, 'Dimension ID') != k
                   or _identifier(v, 'Member ID') != v for k,v in source.items())
            or any(_identifier(k, 'Dimension ID') != k
                   or _identifier(v, 'Member ID') != v for k,v in target.items())
            or sum(source[k] != target[k] for k in source) != 1):
        raise ValueError('CONTRIBUTION_INPUT_GRAIN_INVALID')
    policy = document['policy']
    if (not isinstance(policy, dict)
            or set(policy) != {'policyId','stateToken','digest','family',
                               'effectiveOn','effectiveFrom','effectiveBefore'}
            or policy['family'] not in ('IFRS','US_GAAP','CUSTOM')
            or not isinstance(policy['digest'], str) or not _HEX.fullmatch(policy['digest'])
            or any(not isinstance(policy[k], str) for k in
                   ('policyId','effectiveOn','effectiveFrom','effectiveBefore'))):
        raise ValueError('CONTRIBUTION_INPUT_POLICY_INVALID')
    require_state_token(policy['stateToken'],
                        error='CONTRIBUTION_INPUT_POLICY_INVALID')
    _identifier(policy['policyId'], 'Policy ID')
    try:
        effective_on=date.fromisoformat(policy['effectiveOn'])
        effective_from=date.fromisoformat(policy['effectiveFrom'])
        effective_before=date.fromisoformat(policy['effectiveBefore'])
    except ValueError as exc:
        raise ValueError('CONTRIBUTION_INPUT_POLICY_INVALID') from exc
    if (effective_on.isoformat()!=policy['effectiveOn']
            or effective_from.isoformat()!=policy['effectiveFrom']
            or effective_before.isoformat()!=policy['effectiveBefore']
            or not effective_from<=effective_on<effective_before):
        raise ValueError('CONTRIBUTION_INPUT_POLICY_INVALID')
    ownership = document['ownership']
    if not isinstance(ownership, dict) or tuple(sorted(ownership)) != _OWNERSHIP:
        raise ValueError('CONTRIBUTION_INPUT_OWNERSHIP_INVALID')
    normalized_ownership = {}
    for account in _OWNERSHIP:
        value = ownership[account]
        if (not isinstance(value, dict) or set(value) != {'amount','changeId'}
                or not isinstance(value['changeId'], str)
                or not 1 <= len(value['changeId']) <= 200):
            raise ValueError('CONTRIBUTION_INPUT_OWNERSHIP_INVALID')
        normalized_ownership[account] = {
            'amount': _decimal(value['amount'], 'CONTRIBUTION_INPUT_OWNERSHIP_INVALID'),
            'changeId': value['changeId']}
    if (Decimal(normalized_ownership['Method']['amount']) != 1
            or Decimal(normalized_ownership['Active']['amount']) != 1
            or Decimal(normalized_ownership['PCON']['amount']) != 100):
        raise ValueError('CONTRIBUTION_INPUT_FULL_METHOD_REQUIRED')
    coefficient = document['coefficient']
    if (not isinstance(coefficient, dict)
            or set(coefficient) != {'type','decimal','source'}
            or coefficient.get('type') != 'RatioLiteral'
            or coefficient.get('source') != 'FullMethodFixedOne'
            or Decimal(_decimal(coefficient.get('decimal'),
                                'CONTRIBUTION_INPUT_COEFFICIENT_INVALID')) != 1):
        raise ValueError('CONTRIBUTION_INPUT_COEFFICIENT_INVALID')
    normalized = {**document,
        'sourceMembers': dict(sorted(source.items())),
        'targetMembers': dict(sorted(target.items())),
        'sourceAmount': _decimal(document['sourceAmount'],
                                 'CONTRIBUTION_INPUT_SOURCE_AMOUNT_INVALID'),
        'ownership': normalized_ownership,
        'coefficient': {'type':'RatioLiteral','decimal':'1',
                        'source':'FullMethodFixedOne'}}
    return ContributionInputPlan(normalized)
