"""Pure multi-period total-equity chain contract.

This module deliberately does not post facts or infer accounting mappings.  It
proves an explicitly configured, Unreviewed chain in which each period opens
from one certified prior TotalEquity calculated generation and applies pinned
current-period movements.  Corrections change the candidate digest and make
the corrected period plus every downstream period stale; accepted generations
are never silently rewritten.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, localcontext
from hashlib import sha256
import json
import re
from typing import Mapping

from .consolidation_equity_rollforward import EquityMovement, _amount


_ID = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_GENERATION = re.compile(r'[a-f0-9]{32,64}\Z')
_DIGEST = re.compile(r'[a-f0-9]{64}\Z')
_MAX_PERIODS = 120
_MAX_MOVEMENTS = 500
_MAX_AMOUNT = Decimal('99999999999999999999.99999999')


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'EQUITY_CHAIN_{code}_INVALID')
    return value


def _revision(value: object, code: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum:
        raise ValueError(f'EQUITY_CHAIN_{code}_INVALID')
    return value


def _state_token(value: object, code: str) -> str:
    if not isinstance(value,str) or not _DIGEST.fullmatch(value):
        raise ValueError(f'EQUITY_CHAIN_{code}_INVALID')
    return value


@dataclass(frozen=True)
class CertifiedPriorClose:
    result_key: str
    generation_id: str
    published_revision: int
    period_id: str

    @classmethod
    def parse(cls, raw: object) -> 'CertifiedPriorClose':
        if (not isinstance(raw, dict) or set(raw) != {
                'resultKey', 'generationId', 'publishedRevision', 'periodId'}
                or not isinstance(raw.get('generationId'), str)
                or not _GENERATION.fullmatch(raw['generationId'])):
            raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_INVALID')
        return cls(_id(raw['resultKey'], 'RESULT_KEY'), raw['generationId'],
                   _revision(raw['publishedRevision'], 'PUBLISHED_REVISION',
                             positive=True),
                   _id(raw['periodId'], 'PERIOD'))

    def normalized(self) -> dict:
        return {'resultKey': self.result_key,
                'generationId': self.generation_id,
                'publishedRevision': self.published_revision,
                'periodId': self.period_id}


@dataclass(frozen=True)
class EquityChainPeriod:
    period_id: str
    effective_on: date
    prior_close: CertifiedPriorClose
    movements: tuple[EquityMovement, ...]
    result_key: str

    @classmethod
    def parse(cls, raw: object) -> 'EquityChainPeriod':
        if (not isinstance(raw, dict) or set(raw) != {
                'periodId', 'effectiveOn', 'priorClose', 'movements',
                'resultKey'} or not isinstance(raw.get('effectiveOn'), str)
                or not isinstance(raw.get('movements'), list)
                or not 1 <= len(raw['movements']) <= _MAX_MOVEMENTS):
            raise ValueError('EQUITY_CHAIN_PERIOD_INVALID')
        try:
            effective_on = date.fromisoformat(raw['effectiveOn'])
        except ValueError as error:
            raise ValueError('EQUITY_CHAIN_EFFECTIVE_DATE_INVALID') from error
        movements = tuple(sorted(
            (EquityMovement.parse(item) for item in raw['movements']),
            key=lambda item: item.movement_id))
        if len({item.movement_id for item in movements}) != len(movements):
            raise ValueError('EQUITY_CHAIN_MOVEMENT_AMBIGUOUS')
        return cls(_id(raw['periodId'], 'PERIOD'), effective_on,
                   CertifiedPriorClose.parse(raw['priorClose']), movements,
                   _id(raw['resultKey'], 'RESULT_KEY'))

    def normalized(self) -> dict:
        return {'periodId': self.period_id,
                'effectiveOn': self.effective_on.isoformat(),
                'priorClose': self.prior_close.normalized(),
                'movements': [item.normalized() for item in self.movements],
                'resultKey': self.result_key}


@dataclass(frozen=True)
class EquityRollforwardChain:
    chain_id: str
    chain_version: int
    currency_dimension_id: str
    currency_member_id: str
    hierarchy_dimension_id: str
    total_equity_member_id: str
    hierarchy_state_token: str
    expected_metadata_revision: int
    expected_policy_revision: int
    expected_authorization_revision: int
    periods: tuple[EquityChainPeriod, ...]

    @classmethod
    def parse(cls, raw: object) -> 'EquityRollforwardChain':
        expected = {'chainId', 'chainVersion', 'accountingPolicyStatus',
            'currencyDimensionId', 'currencyMemberId', 'hierarchy',
            'expectedMetadataRevision', 'expectedPolicyRevision',
            'expectedAuthorizationRevision', 'periods'}
        if (not isinstance(raw, dict) or set(raw) != expected
                or raw.get('accountingPolicyStatus') != 'Unreviewed'
                or not isinstance(raw.get('hierarchy'), dict)
                or set(raw['hierarchy']) != {'dimensionId',
                    'totalEquityMemberId', 'stateToken'}
                or not isinstance(raw.get('periods'), list)
                or not 1 <= len(raw['periods']) <= _MAX_PERIODS):
            raise ValueError('EQUITY_CHAIN_INVALID')
        periods = tuple(EquityChainPeriod.parse(item) for item in raw['periods'])
        if (len({item.period_id for item in periods}) != len(periods)
                or len({item.result_key for item in periods}) != len(periods)
                or any(periods[index - 1].effective_on >= periods[index].effective_on
                       for index in range(1, len(periods)))):
            raise ValueError('EQUITY_CHAIN_PERIOD_ORDER_INVALID')
        for index in range(1, len(periods)):
            prior, current = periods[index - 1], periods[index]
            if (current.prior_close.result_key != prior.result_key
                    or current.prior_close.period_id != prior.period_id):
                raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_SEQUENCE_INVALID')
        pins = [movement.source for period in periods
                for movement in period.movements]
        if (len({pin.change_id for pin in pins}) != len(pins)
                or len({pin.members for pin in pins}) != len(pins)):
            raise ValueError('EQUITY_CHAIN_MOVEMENT_AMBIGUOUS')
        grain = {axis for axis, _ in pins[0].members}
        if any({axis for axis, _ in pin.members} != grain for pin in pins):
            raise ValueError('EQUITY_CHAIN_GRAIN_MISMATCH')
        if any(dict(movement.source.members).get('Period') != period.period_id
               for period in periods for movement in period.movements):
            raise ValueError('EQUITY_CHAIN_MOVEMENT_PERIOD_MISMATCH')
        currency_dimension = _id(raw['currencyDimensionId'],
                                 'CURRENCY_DIMENSION')
        if currency_dimension in grain:
            raise ValueError('EQUITY_CHAIN_CURRENCY_AXIS_FORBIDDEN')
        hierarchy = raw['hierarchy']
        hierarchy_dimension = _id(hierarchy['dimensionId'],
                                  'HIERARCHY_DIMENSION')
        if hierarchy_dimension not in grain or 'Period' not in grain:
            raise ValueError('EQUITY_CHAIN_GRAIN_MISMATCH')
        return cls(_id(raw['chainId'], 'ID'),
                   _revision(raw['chainVersion'], 'VERSION', positive=True),
                   currency_dimension,
                   _id(raw['currencyMemberId'], 'CURRENCY_MEMBER'),
                   hierarchy_dimension,
                   _id(hierarchy['totalEquityMemberId'],
                       'TOTAL_EQUITY_MEMBER'),
                   _state_token(hierarchy['stateToken'], 'HIERARCHY_STATE_TOKEN'),
                   _revision(raw['expectedMetadataRevision'],
                             'METADATA_REVISION'),
                   _revision(raw['expectedPolicyRevision'], 'POLICY_REVISION'),
                   _revision(raw['expectedAuthorizationRevision'],
                             'AUTHORIZATION_REVISION'), periods)

    def normalized(self) -> dict:
        return {'chainId': self.chain_id, 'chainVersion': self.chain_version,
          'accountingPolicyStatus': 'Unreviewed',
          'currencyDimensionId': self.currency_dimension_id,
          'currencyMemberId': self.currency_member_id,
          'hierarchy': {'dimensionId': self.hierarchy_dimension_id,
            'totalEquityMemberId': self.total_equity_member_id,
            'stateToken': self.hierarchy_state_token},
          'expectedMetadataRevision': self.expected_metadata_revision,
          'expectedPolicyRevision': self.expected_policy_revision,
          'expectedAuthorizationRevision': self.expected_authorization_revision,
          'periods': [period.normalized() for period in self.periods]}

    @property
    def digest(self) -> str:
        return sha256(json.dumps(self.normalized(), sort_keys=True,
            separators=(',', ':'), ensure_ascii=True,
            allow_nan=False).encode('ascii')).hexdigest()

    def evaluate(self, *, current_revisions: Mapping[str, int],
                 publications: Mapping[str, object],
                 movement_amounts: Mapping[str, str]) -> dict:
        expected_revisions = {'metadata': self.expected_metadata_revision,
            'policy': self.expected_policy_revision,
            'authorization': self.expected_authorization_revision,
            'hierarchy': self.hierarchy_state_token}
        if (not isinstance(current_revisions, Mapping)
                or dict(current_revisions) != expected_revisions):
            raise ValueError('EQUITY_CHAIN_REVISION_STALE')
        required_changes = {movement.source.change_id for period in self.periods
                            for movement in period.movements}
        if (not isinstance(movement_amounts, Mapping)
                or set(movement_amounts) != required_changes):
            raise ValueError('EQUITY_CHAIN_MOVEMENT_VALUES_INCOMPLETE')
        amounts = {key: _amount(value)
                   for key, value in movement_amounts.items()}
        if not isinstance(publications, Mapping):
            raise ValueError('EQUITY_CHAIN_PUBLICATIONS_INVALID')
        results, upstream_stale = [], False
        with localcontext() as precision:
            precision.prec = 80
            for period in self.periods:
                prior = publications.get(period.prior_close.result_key)
                if not isinstance(prior, dict):
                    raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_MISSING_OR_AMBIGUOUS')
                required = {'resultKey', 'generationId', 'publishedRevision',
                    'periodId', 'amount', 'currency', 'totalEquityMemberId',
                    'hierarchyStateToken', 'metadataRevision', 'policyRevision',
                    'authorizationRevision', 'chainPeriodDigest'}
                if set(prior) != required:
                    raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_INVALID')
                pin = period.prior_close
                if (prior['resultKey'] != pin.result_key
                        or prior['generationId'] != pin.generation_id
                        or prior['publishedRevision'] != pin.published_revision
                        or prior['periodId'] != pin.period_id
                        or prior['currency'] != self.currency_member_id
                        or prior['totalEquityMemberId'] != self.total_equity_member_id
                        or prior['hierarchyStateToken'] != self.hierarchy_state_token
                        or prior['metadataRevision'] != self.expected_metadata_revision
                        or prior['policyRevision'] != self.expected_policy_revision
                        or prior['authorizationRevision'] !=
                            self.expected_authorization_revision
                        or not isinstance(prior['chainPeriodDigest'], str)
                        or not _DIGEST.fullmatch(prior['chainPeriodDigest'])):
                    raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_STALE')
                opening = _amount(prior['amount'])
                movements_by_kind: dict[str, Decimal] = {}
                movement_lineage = []
                for movement in period.movements:
                    amount = amounts[movement.source.change_id]
                    signed = amount * movement.direction
                    movements_by_kind[movement.movement_kind] = (
                        movements_by_kind.get(movement.movement_kind, Decimal(0))
                        + signed)
                    movement_lineage.append({
                        'movementId': movement.movement_id,
                        'movementKind': movement.movement_kind,
                        'direction': movement.direction,
                        'source': movement.source.normalized(),
                        'sourceAmount': format(amount, '.8f'),
                        'signedAmount': format(signed, '.8f')})
                total = sum(movements_by_kind.values(), Decimal(0))
                closing = opening + total
                if any(abs(item) > _MAX_AMOUNT for item in
                       (opening, total, closing, *movements_by_kind.values())):
                    raise ValueError('EQUITY_CHAIN_NUMERIC_OVERFLOW')
                candidate = {'chainId': self.chain_id,
                    'chainVersion': self.chain_version,
                    'periodId': period.period_id,
                    'effectiveOn': period.effective_on.isoformat(),
                    'priorClose': pin.normalized(),
                    'movementLineage': movement_lineage,
                    'openingBalance': format(opening, '.8f'),
                    'movements': {key: format(value, '.8f') for key, value
                                  in sorted(movements_by_kind.items())},
                    'totalMovement': format(total, '.8f'),
                    'closingBalance': format(closing, '.8f'),
                    'resultKey': period.result_key,
                    'currency': self.currency_member_id,
                    'totalEquityMemberId': self.total_equity_member_id,
                    'hierarchyStateToken': self.hierarchy_state_token}
                candidate_digest = sha256(json.dumps(candidate,
                    sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                    allow_nan=False).encode('ascii')).hexdigest()
                published = publications.get(period.result_key)
                own_stale = published is not None and (
                    not isinstance(published, dict)
                    or published.get('chainPeriodDigest') != candidate_digest
                    or published.get('amount') != format(closing, '.8f'))
                stale = upstream_stale or own_stale
                results.append({**candidate,
                    'candidateDigest': candidate_digest,
                    'publicationStatus': ('Unpublished' if published is None
                                          else 'Stale' if stale else 'Current'),
                    'stale': stale,
                    'staleReason': ('UPSTREAM_PERIOD_STALE' if upstream_stale
                        else 'CURRENT_PERIOD_CORRECTED' if own_stale else None)})
                upstream_stale = stale
        return {'chainId': self.chain_id, 'chainVersion': self.chain_version,
          'chainDigest': self.digest, 'accountingPolicyStatus': 'Unreviewed',
          'currency': {'dimensionId': self.currency_dimension_id,
                       'memberId': self.currency_member_id},
          'hierarchy': {'dimensionId': self.hierarchy_dimension_id,
            'totalEquityMemberId': self.total_equity_member_id,
            'stateToken': self.hierarchy_state_token},
          'revisionPins': expected_revisions, 'periods': results,
          'stale': any(item['stale'] for item in results),
          'effects': {'published': False, 'authoritativeFactsChanged': False},
          'limitations': ['Unreviewed explicit mapping only',
            'No accounting-policy inference', 'No currency conversion',
            'Candidate calculated generations only']}
