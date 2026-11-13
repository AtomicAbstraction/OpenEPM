"""Exact, bounded, unreviewed fixed-asset unrealized-profit candidate.

The caller supplies positive-magnitude transfer proceeds, carrying amount and
prior deferred profit plus explicit depreciation/disposal ratios.  The fixed
core computes a deterministic creation, excess-depreciation adjustment and
disposal release schedule.  It does not infer useful life, impairment,
transfer-pricing or accounting policy and never posts the candidate.
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
        raise ValueError(f'FIXED_ASSET_UNREALIZED_{label}_INVALID')
    return value


def _revision(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'FIXED_ASSET_UNREALIZED_{label}_INVALID')
    return value


def _coordinate(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 128:
        raise ValueError('FIXED_ASSET_UNREALIZED_COORDINATE_INVALID')
    return tuple(sorted((_identifier(axis, 'DIMENSION'),
                         _identifier(member, 'MEMBER'))
                        for axis, member in value.items()))


def _decimal(value: object, label: str, *, ratio: bool = False) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f'FIXED_ASSET_UNREALIZED_{label}_INVALID')
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f'FIXED_ASSET_UNREALIZED_{label}_INVALID') from error
    scale = 18 if ratio else 8
    if (not result.is_finite() or result.as_tuple().exponent < -scale
            or (ratio and not Decimal(0) <= result <= Decimal(1))
            or (not ratio and (result < 0 or result > _MAX_AMOUNT))):
        raise ValueError(f'FIXED_ASSET_UNREALIZED_{label}_INVALID')
    return result


@dataclass(frozen=True)
class FixedAssetSourcePin:
    members: tuple[tuple[str, str], ...]
    change_id: str

    @classmethod
    def parse(cls, value: object) -> 'FixedAssetSourcePin':
        if (not isinstance(value, dict) or set(value) != {'members', 'changeId'}
                or not isinstance(value['changeId'], str)
                or not _CHANGE.fullmatch(value['changeId'])):
            raise ValueError('FIXED_ASSET_UNREALIZED_SOURCE_PIN_INVALID')
        return cls(_coordinate(value['members']), value['changeId'])

    def normalized(self) -> dict:
        return {'members': dict(self.members), 'changeId': self.change_id}


@dataclass(frozen=True)
class FixedAssetUnrealizedProfitSchedule:
    schedule_id: str
    effective_on: date
    currency_dimension_id: str
    currency_member_id: str
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    transfer_proceeds: FixedAssetSourcePin
    carrying_amount: FixedAssetSourcePin
    prior_deferred_profit: FixedAssetSourcePin
    excess_depreciation_ratio: Decimal
    disposal_release_ratio: Decimal

    @classmethod
    def parse(cls, value: object) -> 'FixedAssetUnrealizedProfitSchedule':
        expected = {'scheduleId', 'effectiveOn',
          'currencyDimensionId', 'currencyMemberId', 'accountingPolicyStatus',
          'signConvention', 'rounding', 'expectedMetadataRevision',
          'expectedDataRevision', 'expectedPolicyRevision', 'transferProceeds',
          'carryingAmount', 'priorDeferredProfit', 'excessDepreciationRatio',
          'disposalReleaseRatio'}
        if (not isinstance(value, dict) or set(value) != expected
                or value.get('accountingPolicyStatus') != 'Unreviewed'
                or value.get('signConvention') != 'positive_magnitudes'
                or value.get('rounding') != 'half-even-step-8'
                or not isinstance(value.get('effectiveOn'), str)):
            raise ValueError('FIXED_ASSET_UNREALIZED_SCHEDULE_INVALID')
        try:
            effective_on = date.fromisoformat(value['effectiveOn'])
        except ValueError as error:
            raise ValueError('FIXED_ASSET_UNREALIZED_EFFECTIVE_DATE_INVALID') from error
        pins = (FixedAssetSourcePin.parse(value['transferProceeds']),
                FixedAssetSourcePin.parse(value['carryingAmount']),
                FixedAssetSourcePin.parse(value['priorDeferredProfit']))
        if (len({pin.members for pin in pins}) != len(pins)
                or len({pin.change_id for pin in pins}) != len(pins)):
            raise ValueError('FIXED_ASSET_UNREALIZED_MAPPING_AMBIGUOUS')
        grain = {axis for axis, _ in pins[0].members}
        if any({axis for axis, _ in pin.members} != grain for pin in pins):
            raise ValueError('FIXED_ASSET_UNREALIZED_GRAIN_MISMATCH')
        currency_dimension = _identifier(
            value['currencyDimensionId'], 'CURRENCY_DIMENSION')
        if currency_dimension in grain:
            raise ValueError('FIXED_ASSET_UNREALIZED_CURRENCY_AXIS_FORBIDDEN')
        return cls(_identifier(value['scheduleId'], 'SCHEDULE_ID'),
          effective_on, currency_dimension,
          _identifier(value['currencyMemberId'], 'CURRENCY_MEMBER'),
          _revision(value['expectedMetadataRevision'], 'METADATA_REVISION'),
          _revision(value['expectedDataRevision'], 'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'], 'POLICY_REVISION'),
          *pins,
          _decimal(value['excessDepreciationRatio'], 'DEPRECIATION_RATIO', ratio=True),
          _decimal(value['disposalReleaseRatio'], 'DISPOSAL_RATIO', ratio=True))

    @property
    def pins(self) -> tuple[FixedAssetSourcePin, ...]:
        return (self.transfer_proceeds, self.carrying_amount,
                self.prior_deferred_profit)

    def normalized(self) -> dict:
        return {'scheduleId': self.schedule_id,
          'effectiveOn': self.effective_on.isoformat(),
          'currencyDimensionId': self.currency_dimension_id,
          'currencyMemberId': self.currency_member_id,
          'accountingPolicyStatus': 'Unreviewed',
          'signConvention': 'positive_magnitudes',
          'rounding': 'half-even-step-8',
          'expectedMetadataRevision': self.expected_metadata_revision,
          'expectedDataRevision': self.expected_data_revision,
          'expectedPolicyRevision': self.expected_policy_revision,
          'transferProceeds': self.transfer_proceeds.normalized(),
          'carryingAmount': self.carrying_amount.normalized(),
          'priorDeferredProfit': self.prior_deferred_profit.normalized(),
          'excessDepreciationRatio': format(self.excess_depreciation_ratio, 'f'),
          'disposalReleaseRatio': format(self.disposal_release_ratio, 'f')}

    @property
    def digest(self) -> str:
        return sha256(json.dumps(self.normalized(), sort_keys=True,
          separators=(',', ':'), ensure_ascii=True,
          allow_nan=False).encode('ascii')).hexdigest()

    def calculate(self, amounts_by_change_id: Mapping[str, str]) -> dict:
        expected = {pin.change_id for pin in self.pins}
        if not isinstance(amounts_by_change_id, Mapping) or set(amounts_by_change_id) != expected:
            raise ValueError('FIXED_ASSET_UNREALIZED_SOURCE_VALUES_INCOMPLETE')
        amounts = {key: _decimal(value, 'SOURCE_AMOUNT')
                   for key, value in amounts_by_change_id.items()}
        proceeds = amounts[self.transfer_proceeds.change_id]
        carrying = amounts[self.carrying_amount.change_id]
        prior = amounts[self.prior_deferred_profit.change_id]
        margin = proceeds - carrying
        if margin < 0:
            raise ValueError('FIXED_ASSET_UNREALIZED_NEGATIVE_MARGIN_UNSUPPORTED')
        with localcontext() as precision:
            precision.prec = 80
            creation = margin.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN)
            opening_pool = prior + creation
            depreciation_unrounded = opening_pool * self.excess_depreciation_ratio
            depreciation = depreciation_unrounded.quantize(
                _QUANTUM, rounding=ROUND_HALF_EVEN)
            after_depreciation = opening_pool - depreciation
            disposal_unrounded = after_depreciation * self.disposal_release_ratio
            disposal = disposal_unrounded.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN)
            closing = after_depreciation - disposal
        if any(item < 0 or item > _MAX_AMOUNT for item in
               (margin, creation, opening_pool, depreciation,
                after_depreciation, disposal, closing)):
            raise ValueError('FIXED_ASSET_UNREALIZED_NUMERIC_OVERFLOW')
        return {'scheduleId': self.schedule_id,
          'scheduleDigest': self.digest,
          'accountingPolicyStatus': 'Unreviewed',
          'signConvention': 'positive_magnitudes',
          'currency': {'dimensionId': self.currency_dimension_id,
                       'memberId': self.currency_member_id},
          'transferMargin': format(margin, '.8f'),
          'creationCandidate': format(creation, '.8f'),
          'openingDeferredPool': format(opening_pool, '.8f'),
          'excessDepreciationAdjustmentCandidate': format(depreciation, '.8f'),
          'disposalReleaseCandidate': format(disposal, '.8f'),
          'closingDeferredProfitCandidate': format(closing, '.8f'),
          'rounding': {'mode': 'half-even-step-8',
            'depreciationUnrounded': format(depreciation_unrounded, 'f'),
            'disposalUnrounded': format(disposal_unrounded, 'f')},
          'sourcePins': [pin.normalized() for pin in self.pins],
          'revisionPins': {'metadata': self.expected_metadata_revision,
            'data': self.expected_data_revision,
            'policy': self.expected_policy_revision}}
