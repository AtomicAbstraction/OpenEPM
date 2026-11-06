"""Bounded Unreviewed cash-flow mapping publication contract."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from hashlib import sha256
import json
import re


_ID = re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_CHANGE = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_SECTIONS = ('Operating', 'Investing', 'Financing')


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'CASH_FLOW_{label}_INVALID')
    return value


def _revision(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'CASH_FLOW_{label}_INVALID')
    return value


def _members(value: object) -> tuple[tuple[str, str], ...]:
    if (not isinstance(value, dict) or len(value) < 5
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not _ID.fullmatch(k) or not _ID.fullmatch(v)
                   for k, v in value.items())):
        raise ValueError('CASH_FLOW_MEMBERS_INVALID')
    required = {'Account', 'Movement', 'Period', 'View'}
    if not required <= set(value):
        raise ValueError('CASH_FLOW_REQUIRED_GRAIN_MISSING')
    if 'Currency' in value:
        raise ValueError('CASH_FLOW_CURRENCY_AXIS_FORBIDDEN')
    return tuple(sorted(value.items()))


@dataclass(frozen=True)
class GenerationPin:
    result_key: str
    generation_id: str
    published_revision: int
    members: tuple[tuple[str, str], ...]
    output_unit_currency_member_id: str

    @classmethod
    def parse(cls, value: object) -> 'GenerationPin':
        if (not isinstance(value, dict)
                or set(value) != {'resultKey', 'generationId',
                                  'publishedRevision', 'members',
                                  'outputUnitCurrencyMemberId'}
                or not isinstance(value.get('generationId'), str)
                or not re.fullmatch(r'[0-9a-f]{32}', value['generationId'])):
            raise ValueError('CASH_FLOW_GENERATION_PIN_INVALID')
        return cls(_identifier(value['resultKey'], 'RESULT_KEY'),
                   value['generationId'],
                   _revision(value['publishedRevision'],
                             'PUBLISHED_REVISION'),
                   _members(value['members']),
                   _identifier(value['outputUnitCurrencyMemberId'],
                               'CURRENCY_MEMBER'))

    def normalized(self) -> dict:
        return {'resultKey': self.result_key,
                'generationId': self.generation_id,
                'publishedRevision': self.published_revision,
                'members': dict(self.members),
                'outputUnitCurrencyMemberId':
                    self.output_unit_currency_member_id}


@dataclass(frozen=True)
class SourceLine:
    line_id: str
    section: str
    direction: int
    source: GenerationPin

    @classmethod
    def parse(cls, value: object) -> 'SourceLine':
        if (not isinstance(value, dict)
                or set(value) != {'lineId', 'section', 'direction',
                                  'source'}
                or value.get('section') not in _SECTIONS
                or type(value.get('direction')) is not int
                or value['direction'] not in (-1, 1)
                or not isinstance(value.get('source'), dict)):
            raise ValueError('CASH_FLOW_MAPPING_LINE_INVALID')
        return cls(_identifier(value['lineId'], 'LINE_ID'), value['section'],
                   value['direction'], GenerationPin.parse(value['source']))

    @property
    def members(self):
        return self.source.members

    def normalized(self) -> dict:
        return {'lineId': self.line_id, 'section': self.section,
                'direction': self.direction,
                'source': self.source.normalized()}


@dataclass(frozen=True)
class CashFlowPublication:
    mapping_id: str
    mapping_version: int
    effective_on: date
    currency_member_id: str
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    expected_authorization_revision: int
    hierarchy_pins: tuple[tuple[str, int], ...]
    opening: GenerationPin
    closing: GenerationPin
    lines: tuple[SourceLine, ...]
    targets: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]
    result_keys: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, value: object) -> 'CashFlowPublication':
        expected = {'mappingId', 'mappingVersion', 'effectiveOn',
          'accountingPolicyStatus', 'currencyMemberId',
          'expectedMetadataRevision', 'expectedDataRevision',
          'expectedPolicyRevision', 'expectedAuthorizationRevision',
          'hierarchyPins', 'opening', 'closing', 'lines', 'targets',
          'resultKeys'}
        if (not isinstance(value, dict) or set(value) != expected
                or value.get('accountingPolicyStatus') != 'Unreviewed'
                or type(value.get('mappingVersion')) is not int
                or value['mappingVersion'] <= 0
                or not isinstance(value.get('lines'), list)
                or not 3 <= len(value['lines']) <= 250
                or not isinstance(value.get('hierarchyPins'), list)
                or not 1 <= len(value['hierarchyPins']) <= 8
                or not isinstance(value.get('targets'), dict)
                or set(value['targets']) != {*_SECTIONS, 'Reconciliation'}
                or not isinstance(value.get('resultKeys'), dict)
                or set(value['resultKeys']) != {*_SECTIONS,
                                                'Reconciliation'}):
            raise ValueError('CASH_FLOW_PUBLICATION_INVALID')
        try:
            effective_on = date.fromisoformat(value['effectiveOn'])
        except (TypeError, ValueError) as error:
            raise ValueError('CASH_FLOW_EFFECTIVE_DATE_INVALID') from error
        lines = tuple(sorted((SourceLine.parse(item) for item in value['lines']),
                             key=lambda item: item.line_id))
        if (len({line.line_id for line in lines}) != len(lines)
                or {line.section for line in lines} != set(_SECTIONS)
                or len({(line.members, line.source.result_key,
                         line.source.generation_id) for line in lines}) !=
                    len(lines)):
            raise ValueError('CASH_FLOW_MAPPING_AMBIGUOUS')
        opening = GenerationPin.parse(value['opening'])
        closing = GenerationPin.parse(value['closing'])
        targets = tuple((name, _members(value['targets'][name]))
                        for name in (*_SECTIONS, 'Reconciliation'))
        result_keys = tuple((name, _identifier(value['resultKeys'][name],
                                                'RESULT_KEY'))
                            for name in (*_SECTIONS, 'Reconciliation'))
        if len({key for _, key in result_keys}) != 4:
            raise ValueError('CASH_FLOW_RESULT_KEY_REPEATED')
        all_members = [opening.members, closing.members,
                       *(line.members for line in lines),
                       *(members for _, members in targets)]
        axes = {axis for axis, _ in all_members[0]}
        if any({axis for axis, _ in members} != axes
               for members in all_members):
            raise ValueError('CASH_FLOW_GRAIN_MISMATCH')
        currency = _identifier(value['currencyMemberId'], 'CURRENCY_MEMBER')
        if any(pin.output_unit_currency_member_id != currency for pin in
               (opening, closing, *(line.source for line in lines))):
            raise ValueError('CASH_FLOW_CURRENCY_UNIT_MISMATCH')
        fixed_axes = axes - {'Account', 'Movement'}
        fixed = {axis: dict(all_members[0])[axis] for axis in fixed_axes}
        if any(any(dict(members)[axis] != member
                   for axis, member in fixed.items())
               for members in all_members[1:]):
            raise ValueError('CASH_FLOW_SLICE_MISMATCH')
        hierarchy_pins = []
        for pin in value['hierarchyPins']:
            if (not isinstance(pin, dict)
                    or set(pin) != {'dimensionId', 'version'}):
                raise ValueError('CASH_FLOW_HIERARCHY_PIN_INVALID')
            hierarchy_pins.append((_identifier(pin['dimensionId'],
                                                'HIERARCHY_DIMENSION'),
                                   _revision(pin['version'],
                                             'HIERARCHY_VERSION')))
        if len({item[0] for item in hierarchy_pins}) != len(hierarchy_pins):
            raise ValueError('CASH_FLOW_HIERARCHY_PIN_REPEATED')
        return cls(_identifier(value['mappingId'], 'MAPPING_ID'),
          value['mappingVersion'], effective_on, currency,
          _revision(value['expectedMetadataRevision'], 'METADATA_REVISION'),
          _revision(value['expectedDataRevision'], 'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'], 'POLICY_REVISION'),
          _revision(value['expectedAuthorizationRevision'],
                    'AUTHORIZATION_REVISION'),
          tuple(sorted(hierarchy_pins)), opening, closing, lines, targets,
          result_keys)

    def normalized(self) -> dict:
        return {'mappingId': self.mapping_id,
          'mappingVersion': self.mapping_version,
          'effectiveOn': self.effective_on.isoformat(),
          'accountingPolicyStatus': 'Unreviewed',
          'currencyMemberId': self.currency_member_id,
          'expectedMetadataRevision': self.expected_metadata_revision,
          'expectedDataRevision': self.expected_data_revision,
          'expectedPolicyRevision': self.expected_policy_revision,
          'expectedAuthorizationRevision': self.expected_authorization_revision,
          'hierarchyPins': [{'dimensionId': dimension, 'version': version}
                            for dimension, version in self.hierarchy_pins],
          'opening': self.opening.normalized(),
          'closing': self.closing.normalized(),
          'lines': [line.normalized() for line in self.lines],
          'targets': {name: dict(members) for name, members in self.targets},
          'resultKeys': dict(self.result_keys)}

    @property
    def digest(self) -> str:
        encoded = json.dumps(self.normalized(), sort_keys=True,
          separators=(',', ':'), ensure_ascii=True).encode('ascii')
        return sha256(encoded).hexdigest()
