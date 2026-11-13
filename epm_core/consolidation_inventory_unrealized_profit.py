"""Exact, bounded and unreviewed inventory unrealized-profit candidate.

The caller supplies positive-magnitude transfer revenue, transfer cost and a
previously deferred-profit source plus explicit inventory ratios.  The module
computes a structural creation/release schedule only.  It does not select
accounts, infer transfer-pricing or impairment policy, post eliminations, or
claim IFRS/US-GAAP compliance.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN, localcontext
from hashlib import sha256
import json
import re
from typing import Mapping


_ID = re.compile(r'[A-Za-z0-9._-]{1,200}\Z')
_CHANGE = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_MAX_AMOUNT = Decimal('99999999999999999999.99999999')
_QUANTUM = Decimal('0.00000001')


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'INVENTORY_UNREALIZED_{label}_INVALID')
    return value


def _revision(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'INVENTORY_UNREALIZED_{label}_INVALID')
    return value


def _coordinate(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 128:
        raise ValueError('INVENTORY_UNREALIZED_COORDINATE_INVALID')
    return tuple(sorted((_identifier(axis, 'DIMENSION'),
                         _identifier(member, 'MEMBER'))
                        for axis, member in value.items()))


def _decimal(value: object, label: str, *, ratio: bool = False) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f'INVENTORY_UNREALIZED_{label}_INVALID')
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f'INVENTORY_UNREALIZED_{label}_INVALID') from error
    limit = 18 if ratio else 8
    if (not result.is_finite() or result.as_tuple().exponent < -limit
            or (ratio and not Decimal(0) <= result <= Decimal(1))
            or (not ratio and (result < 0 or result > _MAX_AMOUNT))):
        raise ValueError(f'INVENTORY_UNREALIZED_{label}_INVALID')
    return result


@dataclass(frozen=True)
class InventoryProfitSourcePin:
    members: tuple[tuple[str, str], ...]
    change_id: str

    @classmethod
    def parse(cls, value: object) -> 'InventoryProfitSourcePin':
        if (not isinstance(value, dict) or set(value) != {'members', 'changeId'}
                or not isinstance(value['changeId'], str)
                or not _CHANGE.fullmatch(value['changeId'])):
            raise ValueError('INVENTORY_UNREALIZED_SOURCE_PIN_INVALID')
        return cls(_coordinate(value['members']), value['changeId'])

    def normalized(self) -> dict:
        return {'members': dict(self.members), 'changeId': self.change_id}


@dataclass(frozen=True)
class InventoryUnrealizedProfitSchedule:
    schedule_id: str
    effective_on: date
    currency_dimension_id: str
    currency_member_id: str
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    transfer_revenue: InventoryProfitSourcePin
    transfer_cost: InventoryProfitSourcePin
    prior_unrealized_profit: InventoryProfitSourcePin
    closing_inventory_ratio: Decimal
    prior_inventory_realized_ratio: Decimal

    @classmethod
    def parse(cls, value: object) -> 'InventoryUnrealizedProfitSchedule':
        expected = {'scheduleId', 'effectiveOn',
          'currencyDimensionId', 'currencyMemberId', 'accountingPolicyStatus',
          'signConvention', 'expectedMetadataRevision', 'expectedDataRevision',
          'expectedPolicyRevision', 'transferRevenue', 'transferCost',
          'priorUnrealizedProfit', 'closingInventoryRatio',
          'priorInventoryRealizedRatio'}
        if (not isinstance(value, dict) or set(value) != expected
                or value.get('accountingPolicyStatus') != 'Unreviewed'
                or value.get('signConvention') != 'positive_magnitudes'
                or not isinstance(value.get('effectiveOn'), str)):
            raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_INVALID')
        try:
            effective_on = date.fromisoformat(value['effectiveOn'])
        except ValueError as error:
            raise ValueError('INVENTORY_UNREALIZED_EFFECTIVE_DATE_INVALID') from error
        pins = (InventoryProfitSourcePin.parse(value['transferRevenue']),
                InventoryProfitSourcePin.parse(value['transferCost']),
                InventoryProfitSourcePin.parse(value['priorUnrealizedProfit']))
        if (len({pin.members for pin in pins}) != len(pins)
                or len({pin.change_id for pin in pins}) != len(pins)):
            raise ValueError('INVENTORY_UNREALIZED_MAPPING_AMBIGUOUS')
        grain = {axis for axis, _ in pins[0].members}
        if any({axis for axis, _ in pin.members} != grain for pin in pins):
            raise ValueError('INVENTORY_UNREALIZED_GRAIN_MISMATCH')
        currency_dimension = _identifier(
            value['currencyDimensionId'], 'CURRENCY_DIMENSION')
        if currency_dimension in grain:
            raise ValueError('INVENTORY_UNREALIZED_CURRENCY_AXIS_FORBIDDEN')
        return cls(_identifier(value['scheduleId'], 'SCHEDULE_ID'),
          effective_on, currency_dimension,
          _identifier(value['currencyMemberId'], 'CURRENCY_MEMBER'),
          _revision(value['expectedMetadataRevision'], 'METADATA_REVISION'),
          _revision(value['expectedDataRevision'], 'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'], 'POLICY_REVISION'),
          *pins,
          _decimal(value['closingInventoryRatio'], 'CLOSING_RATIO', ratio=True),
          _decimal(value['priorInventoryRealizedRatio'],
                   'REALIZED_RATIO', ratio=True))

    @property
    def pins(self) -> tuple[InventoryProfitSourcePin, ...]:
        return (self.transfer_revenue, self.transfer_cost,
                self.prior_unrealized_profit)

    def normalized(self) -> dict:
        return {'scheduleId': self.schedule_id,
          'effectiveOn': self.effective_on.isoformat(),
          'currencyDimensionId': self.currency_dimension_id,
          'currencyMemberId': self.currency_member_id,
          'accountingPolicyStatus': 'Unreviewed',
          'signConvention': 'positive_magnitudes',
          'expectedMetadataRevision': self.expected_metadata_revision,
          'expectedDataRevision': self.expected_data_revision,
          'expectedPolicyRevision': self.expected_policy_revision,
          'transferRevenue': self.transfer_revenue.normalized(),
          'transferCost': self.transfer_cost.normalized(),
          'priorUnrealizedProfit': self.prior_unrealized_profit.normalized(),
          'closingInventoryRatio': format(self.closing_inventory_ratio, 'f'),
          'priorInventoryRealizedRatio': format(
              self.prior_inventory_realized_ratio, 'f')}

    @property
    def digest(self) -> str:
        raw = json.dumps(self.normalized(), sort_keys=True,
          separators=(',', ':'), ensure_ascii=True,
          allow_nan=False).encode('ascii')
        return sha256(raw).hexdigest()

    def calculate(self, amounts_by_change_id: Mapping[str, str]) -> dict:
        expected = {pin.change_id for pin in self.pins}
        if not isinstance(amounts_by_change_id, Mapping) or set(amounts_by_change_id) != expected:
            raise ValueError('INVENTORY_UNREALIZED_SOURCE_VALUES_INCOMPLETE')
        amounts = {key: _decimal(value, 'SOURCE_AMOUNT')
                   for key, value in amounts_by_change_id.items()}
        revenue = amounts[self.transfer_revenue.change_id]
        cost = amounts[self.transfer_cost.change_id]
        prior = amounts[self.prior_unrealized_profit.change_id]
        margin = revenue - cost
        if margin < 0:
            raise ValueError('INVENTORY_UNREALIZED_NEGATIVE_MARGIN_UNSUPPORTED')
        with localcontext() as precision:
            precision.prec = 80
            creation_unrounded = margin * self.closing_inventory_ratio
            release_unrounded = prior * self.prior_inventory_realized_ratio
            creation = creation_unrounded.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN)
            release = release_unrounded.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN)
            closing_deferred = prior + creation - release
        if any(item < 0 or item > _MAX_AMOUNT for item in
               (margin, creation, release, closing_deferred)):
            raise ValueError('INVENTORY_UNREALIZED_NUMERIC_OVERFLOW')
        return {'scheduleId': self.schedule_id,
          'scheduleDigest': self.digest,
          'accountingPolicyStatus': 'Unreviewed',
          'signConvention': 'positive_magnitudes',
          'currency': {'dimensionId': self.currency_dimension_id,
                       'memberId': self.currency_member_id},
          'transferMargin': format(margin, '.8f'),
          'creationCandidate': format(creation, '.8f'),
          'releaseCandidate': format(release, '.8f'),
          'closingDeferredProfitCandidate': format(closing_deferred, '.8f'),
          'rounding': {'mode': 'half-even-final-8',
            'creationUnrounded': format(creation_unrounded, 'f'),
            'releaseUnrounded': format(release_unrounded, 'f')},
          'sourcePins': [pin.normalized() for pin in self.pins],
          'revisionPins': {'metadata': self.expected_metadata_revision,
            'data': self.expected_data_revision,
            'policy': self.expected_policy_revision}}
