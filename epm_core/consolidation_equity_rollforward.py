"""Pure, bounded and explicitly unreviewed equity-rollforward contract.

The caller supplies exact opening, closing and movement coordinates for each
equity component.  This contract proves only the structural equation
``opening + signed movements = closing`` per component.  It does not choose
accounts, infer IFRS/US-GAAP treatment, translate currency, eliminate
intercompany balances or publish a statement.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, localcontext
from hashlib import sha256
import json
import re
from typing import Mapping


_ID = re.compile(r'[A-Za-z0-9._-]{1,200}\Z')
_CHANGE = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_MOVEMENT_KINDS = frozenset((
    'ProfitOrLoss', 'OtherComprehensiveIncome', 'OwnerContribution',
    'Distribution', 'Transfer', 'AcquisitionDisposal', 'Other'))
_MAX_COMPONENTS = 100
_MAX_MOVEMENTS = 500
_MAX_AMOUNT = Decimal('99999999999999999999.99999999')


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'EQUITY_ROLLFORWARD_{label}_INVALID')
    return value


def _revision(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'EQUITY_ROLLFORWARD_{label}_INVALID')
    return value


def _coordinate(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 128:
        raise ValueError('EQUITY_ROLLFORWARD_COORDINATE_INVALID')
    return tuple(sorted((_identifier(axis, 'DIMENSION'),
                         _identifier(member, 'MEMBER'))
                        for axis, member in value.items()))


def _amount(value: object) -> Decimal:
    if not isinstance(value, str):
        raise ValueError('EQUITY_ROLLFORWARD_SOURCE_AMOUNT_INVALID')
    try:
        result = Decimal(value)
    except Exception as error:
        raise ValueError('EQUITY_ROLLFORWARD_SOURCE_AMOUNT_INVALID') from error
    if (not result.is_finite() or result.as_tuple().exponent < -8
            or abs(result) > _MAX_AMOUNT):
        raise ValueError('EQUITY_ROLLFORWARD_SOURCE_AMOUNT_INVALID')
    return result


@dataclass(frozen=True)
class EquitySourcePin:
    members: tuple[tuple[str, str], ...]
    change_id: str

    @classmethod
    def parse(cls, value: object) -> 'EquitySourcePin':
        if (not isinstance(value, dict) or set(value) != {'members', 'changeId'}
                or not isinstance(value['changeId'], str)
                or not _CHANGE.fullmatch(value['changeId'])):
            raise ValueError('EQUITY_ROLLFORWARD_SOURCE_PIN_INVALID')
        return cls(_coordinate(value['members']), value['changeId'])

    def normalized(self) -> dict:
        return {'members': dict(self.members), 'changeId': self.change_id}


@dataclass(frozen=True)
class EquityMovement:
    movement_id: str
    movement_kind: str
    direction: int
    source: EquitySourcePin

    @classmethod
    def parse(cls, value: object) -> 'EquityMovement':
        if (not isinstance(value, dict)
                or set(value) != {'movementId', 'movementKind', 'direction', 'source'}
                or value.get('movementKind') not in _MOVEMENT_KINDS
                or type(value.get('direction')) is not int
                or value['direction'] not in (-1, 1)):
            raise ValueError('EQUITY_ROLLFORWARD_MOVEMENT_INVALID')
        return cls(_identifier(value['movementId'], 'MOVEMENT_ID'),
                   value['movementKind'], value['direction'],
                   EquitySourcePin.parse(value['source']))

    def normalized(self) -> dict:
        return {'movementId': self.movement_id,
                'movementKind': self.movement_kind,
                'direction': self.direction, 'source': self.source.normalized()}


@dataclass(frozen=True)
class EquityComponent:
    component_id: str
    opening: EquitySourcePin
    closing: EquitySourcePin
    movements: tuple[EquityMovement, ...]

    @classmethod
    def parse(cls, value: object) -> 'EquityComponent':
        if (not isinstance(value, dict)
                or set(value) != {'componentId', 'opening', 'closing', 'movements'}
                or not isinstance(value.get('movements'), list)
                or not 1 <= len(value['movements']) <= _MAX_MOVEMENTS):
            raise ValueError('EQUITY_ROLLFORWARD_COMPONENT_INVALID')
        movements = tuple(sorted(
            (EquityMovement.parse(item) for item in value['movements']),
            key=lambda item: item.movement_id))
        if len({item.movement_id for item in movements}) != len(movements):
            raise ValueError('EQUITY_ROLLFORWARD_MAPPING_AMBIGUOUS')
        return cls(_identifier(value['componentId'], 'COMPONENT_ID'),
                   EquitySourcePin.parse(value['opening']),
                   EquitySourcePin.parse(value['closing']), movements)

    def normalized(self) -> dict:
        return {'componentId': self.component_id,
                'opening': self.opening.normalized(),
                'closing': self.closing.normalized(),
                'movements': [item.normalized() for item in self.movements]}


@dataclass(frozen=True)
class EquityRollforward:
    rollforward_id: str
    rollforward_version: int
    effective_on: date
    currency_dimension_id: str
    currency_member_id: str
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    components: tuple[EquityComponent, ...]

    @classmethod
    def parse(cls, value: object) -> 'EquityRollforward':
        expected = {'rollforwardId', 'rollforwardVersion', 'effectiveOn',
            'currencyDimensionId', 'currencyMemberId', 'accountingPolicyStatus',
            'expectedMetadataRevision', 'expectedDataRevision',
            'expectedPolicyRevision', 'components'}
        if (not isinstance(value, dict) or set(value) != expected
                or value.get('accountingPolicyStatus') != 'Unreviewed'
                or type(value.get('rollforwardVersion')) is not int
                or value['rollforwardVersion'] <= 0
                or not isinstance(value.get('effectiveOn'), str)
                or not isinstance(value.get('components'), list)
                or not 1 <= len(value['components']) <= _MAX_COMPONENTS):
            raise ValueError('EQUITY_ROLLFORWARD_INVALID')
        try:
            effective_on = date.fromisoformat(value['effectiveOn'])
        except ValueError as error:
            raise ValueError('EQUITY_ROLLFORWARD_EFFECTIVE_DATE_INVALID') from error
        components = tuple(sorted(
            (EquityComponent.parse(item) for item in value['components']),
            key=lambda item: item.component_id))
        if len({item.component_id for item in components}) != len(components):
            raise ValueError('EQUITY_ROLLFORWARD_MAPPING_AMBIGUOUS')
        pins = [pin for component in components
                for pin in (component.opening, component.closing,
                            *(item.source for item in component.movements))]
        if (len({pin.members for pin in pins}) != len(pins)
                or len({pin.change_id for pin in pins}) != len(pins)):
            raise ValueError('EQUITY_ROLLFORWARD_MAPPING_AMBIGUOUS')
        grain = {axis for axis, _ in pins[0].members}
        if any({axis for axis, _ in pin.members} != grain for pin in pins):
            raise ValueError('EQUITY_ROLLFORWARD_GRAIN_MISMATCH')
        currency_dimension = _identifier(
            value['currencyDimensionId'], 'CURRENCY_DIMENSION')
        if currency_dimension in grain:
            raise ValueError('EQUITY_ROLLFORWARD_CURRENCY_AXIS_FORBIDDEN')
        return cls(_identifier(value['rollforwardId'], 'ID'),
            value['rollforwardVersion'], effective_on, currency_dimension,
            _identifier(value['currencyMemberId'], 'CURRENCY_MEMBER'),
            _revision(value['expectedMetadataRevision'], 'METADATA_REVISION'),
            _revision(value['expectedDataRevision'], 'DATA_REVISION'),
            _revision(value['expectedPolicyRevision'], 'POLICY_REVISION'),
            components)

    @property
    def pins(self) -> tuple[EquitySourcePin, ...]:
        return tuple(pin for component in self.components
                     for pin in (component.opening, component.closing,
                                 *(item.source for item in component.movements)))

    def normalized(self) -> dict:
        return {'rollforwardId': self.rollforward_id,
          'rollforwardVersion': self.rollforward_version,
          'effectiveOn': self.effective_on.isoformat(),
          'currencyDimensionId': self.currency_dimension_id,
          'currencyMemberId': self.currency_member_id,
          'accountingPolicyStatus': 'Unreviewed',
          'expectedMetadataRevision': self.expected_metadata_revision,
          'expectedDataRevision': self.expected_data_revision,
          'expectedPolicyRevision': self.expected_policy_revision,
          'components': [item.normalized() for item in self.components]}

    @property
    def digest(self) -> str:
        raw = json.dumps(self.normalized(), sort_keys=True,
                         separators=(',', ':'), ensure_ascii=True,
                         allow_nan=False).encode('ascii')
        return sha256(raw).hexdigest()

    def reconcile(self, amounts_by_change_id: Mapping[str, str]) -> dict:
        if (not isinstance(amounts_by_change_id, Mapping)
                or set(amounts_by_change_id) !=
                    {pin.change_id for pin in self.pins}):
            raise ValueError('EQUITY_ROLLFORWARD_SOURCE_VALUES_INCOMPLETE')
        amounts = {key: _amount(value)
                   for key, value in amounts_by_change_id.items()}
        results = []
        total_opening = Decimal(0)
        total_closing = Decimal(0)
        total_movements = {kind: Decimal(0) for kind in sorted(_MOVEMENT_KINDS)}
        with localcontext() as precision:
            precision.prec = 80
            for component in self.components:
                movements = {kind: Decimal(0) for kind in sorted(_MOVEMENT_KINDS)}
                for movement in component.movements:
                    movements[movement.movement_kind] += (
                        amounts[movement.source.change_id] * movement.direction)
                total = sum(movements.values(), Decimal(0))
                opening = amounts[component.opening.change_id]
                closing = amounts[component.closing.change_id]
                expected = opening + total
                difference = closing - expected
                if any(abs(item) > _MAX_AMOUNT for item in
                       (*movements.values(), total, expected, difference)):
                    raise ValueError('EQUITY_ROLLFORWARD_NUMERIC_OVERFLOW')
                results.append({'componentId': component.component_id,
                  'openingBalance': format(opening, '.8f'),
                  'movements': {kind: format(amount, '.8f')
                                for kind, amount in movements.items()},
                  'totalMovement': format(total, '.8f'),
                  'expectedClosingBalance': format(expected, '.8f'),
                  'closingBalance': format(closing, '.8f'),
                  'difference': format(difference, '.8f'),
                  'reconciled': difference == 0})
                total_opening += opening
                total_closing += closing
                for kind, amount in movements.items():
                    total_movements[kind] += amount
            total_movement = sum(total_movements.values(), Decimal(0))
            total_expected = total_opening + total_movement
            total_difference = total_closing - total_expected
            if any(abs(item) > _MAX_AMOUNT for item in (
                    total_opening, total_closing, *total_movements.values(),
                    total_movement, total_expected, total_difference)):
                raise ValueError('EQUITY_ROLLFORWARD_NUMERIC_OVERFLOW')
            total_equity = {
              'openingBalance': format(total_opening, '.8f'),
              'movements': {kind: format(amount, '.8f')
                            for kind, amount in total_movements.items()},
              'totalMovement': format(total_movement, '.8f'),
              'expectedClosingBalance': format(total_expected, '.8f'),
              'closingBalance': format(total_closing, '.8f'),
              'difference': format(total_difference, '.8f'),
              'reconciled': total_difference == 0,
              'componentIds': [item.component_id for item in self.components]}
        return {'rollforwardId': self.rollforward_id,
          'rollforwardVersion': self.rollforward_version,
          'rollforwardDigest': self.digest,
          'accountingPolicyStatus': 'Unreviewed',
          'currency': {'dimensionId': self.currency_dimension_id,
                       'memberId': self.currency_member_id},
          'components': results,
          'totalEquity': total_equity,
          'reconciled': all(item['reconciled'] for item in results),
          'sourcePins': [pin.normalized() for pin in self.pins],
          'revisionPins': {'metadata': self.expected_metadata_revision,
            'data': self.expected_data_revision,
            'policy': self.expected_policy_revision}}
