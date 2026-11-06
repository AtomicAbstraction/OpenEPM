"""Strict source-bound contract for the mechanical Unreviewed CTA bridge v2."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .persistence_contract import Coordinate


_ID = re.compile(r'[A-Za-z0-9._-]{1,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_ROLES = ('Opening', 'Movement', 'Closing')


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'CTA_V2_{label}_INVALID')
    return value


def _revision(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f'CTA_V2_{label}_INVALID')
    return value


@dataclass(frozen=True)
class CtaSourcePin:
    role: str
    movement_id: str | None
    result_key: str
    generation_id: str
    published_revision: int
    members: tuple[tuple[str, str], ...]
    output_currency_member_id: str
    sign: int

    @classmethod
    def parse(cls, value: object) -> 'CtaSourcePin':
        fields = {'role', 'movementId', 'resultKey', 'generationId',
                  'publishedRevision', 'members',
                  'outputCurrencyMemberId', 'sign'}
        if (not isinstance(value, dict) or set(value) != fields
                or value.get('role') not in _ROLES
                or not isinstance(value.get('generationId'), str)
                or not _JOB.fullmatch(value['generationId'])
                or value.get('sign') not in (-1, 1)
                or isinstance(value.get('sign'), bool)):
            raise ValueError('CTA_V2_SOURCE_INVALID')
        movement = value['movementId']
        if ((value['role'] == 'Movement') != (movement is not None)
                or (movement is not None and
                    (not isinstance(movement, str) or
                     not _ID.fullmatch(movement)))):
            raise ValueError('CTA_V2_MOVEMENT_ID_INVALID')
        try:
            members = Coordinate.from_mapping(value['members']).members
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError('CTA_V2_SOURCE_MEMBERS_INVALID') from error
        return cls(value['role'], movement,
          _id(value['resultKey'], 'RESULT_KEY'), value['generationId'],
          _revision(value['publishedRevision'], 'PUBLISHED_REVISION', 1),
          members, _id(value['outputCurrencyMemberId'], 'CURRENCY_MEMBER'),
          value['sign'])

    def normalized(self) -> dict:
        return {'role': self.role, 'movementId': self.movement_id,
          'resultKey': self.result_key, 'generationId': self.generation_id,
          'publishedRevision': self.published_revision,
          'members': dict(self.members),
          'outputCurrencyMemberId': self.output_currency_member_id,
          'sign': self.sign}


@dataclass(frozen=True)
class CtaBridgeV2:
    sources: tuple[CtaSourcePin, ...]
    cta_members: tuple[tuple[str, str], ...]
    offset_members: tuple[tuple[str, str], ...]
    effective_period: tuple[tuple[str, str], ...]
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    layout_version: int
    layout_digest: str
    reason: str

    @classmethod
    def parse(cls, value: object) -> 'CtaBridgeV2':
        fields = {'bridgeVersion', 'accountingPolicyStatus', 'sources',
          'ctaMembers', 'offsetMembers', 'effectivePeriod',
          'expectedMetadataRevision', 'expectedDataRevision',
          'expectedPolicyRevision', 'layoutVersion','layoutDigest','reason'}
        if (not isinstance(value, dict) or set(value) != fields
                or value.get('bridgeVersion') != 2
                or value.get('accountingPolicyStatus') != 'Unreviewed'
                or not isinstance(value.get('sources'), list)
                or not 3 <= len(value['sources']) <= 102
                or not isinstance(value.get('reason'), str)
                or not 1 <= len(value['reason']) <= 500
                or value['reason'] != value['reason'].strip()
                or not isinstance(value.get('layoutDigest'),str)
                or not _DIGEST.fullmatch(value['layoutDigest'])):
            raise ValueError('CTA_V2_ARGUMENTS_INVALID')
        sources = tuple(CtaSourcePin.parse(item) for item in value['sources'])
        roles = [item.role for item in sources]
        if (roles.count('Opening') != 1 or roles.count('Closing') != 1
                or roles.count('Movement') < 1
                or len({(item.result_key, item.generation_id, item.members)
                        for item in sources}) != len(sources)
                or len({item.movement_id for item in sources
                        if item.role == 'Movement'}) != roles.count('Movement')):
            raise ValueError('CTA_V2_SOURCE_SET_INVALID')
        if (next(item for item in sources if item.role == 'Opening').sign != 1
                or next(item for item in sources
                        if item.role == 'Closing').sign != 1):
            raise ValueError('CTA_V2_BALANCE_SIGN_INVALID')
        units = {item.output_currency_member_id for item in sources}
        if len(units) != 1:
            raise ValueError('CTA_V2_CURRENCY_MIXED_OR_MISSING')
        axes = {axis for axis, _ in sources[0].members}
        if any({axis for axis, _ in item.members} != axes
               for item in sources[1:]):
            raise ValueError('CTA_V2_SOURCE_GRAIN_MISMATCH')
        try:
            cta = Coordinate.from_mapping(value['ctaMembers']).members
            offset = Coordinate.from_mapping(value['offsetMembers']).members
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError('CTA_V2_TARGET_INVALID') from error
        if cta == offset:
            raise ValueError('CTA_V2_TARGETS_MUST_DIFFER')
        period = value['effectivePeriod']
        if (not isinstance(period, dict)
                or set(period) != {'scenarioDimension', 'scenarioId',
                                   'yearDimension', 'yearId',
                                   'periodDimension', 'periodId'}
                or any(not isinstance(item, str) or not item
                       for item in period.values())):
            raise ValueError('CTA_V2_PERIOD_INVALID')
        for members in (cta, offset, *(item.members for item in sources)):
            point = dict(members)
            if any(point.get(period[axis]) != period[member] for axis, member in (
                    ('scenarioDimension', 'scenarioId'),
                    ('yearDimension', 'yearId'),
                    ('periodDimension', 'periodId'))):
                raise ValueError('CTA_V2_PERIOD_MISMATCH')
        target_points = [dict(cta), dict(offset)]
        if any(set(point) != axes for point in target_points):
            raise ValueError('CTA_V2_SOURCE_GRAIN_MISMATCH')
        return cls(sources, cta, offset, tuple(sorted(period.items())),
          _revision(value['expectedMetadataRevision'], 'METADATA_REVISION'),
          _revision(value['expectedDataRevision'], 'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'], 'POLICY_REVISION'),
          _revision(value['layoutVersion'],'LAYOUT_VERSION',1),
          value['layoutDigest'],
          value['reason'])

    def normalized(self) -> dict:
        return {'bridgeVersion': 2, 'accountingPolicyStatus': 'Unreviewed',
          'sources': [item.normalized() for item in self.sources],
          'ctaMembers': dict(self.cta_members),
          'offsetMembers': dict(self.offset_members),
          'effectivePeriod': dict(self.effective_period),
          'expectedMetadataRevision': self.expected_metadata_revision,
          'expectedDataRevision': self.expected_data_revision,
          'expectedPolicyRevision': self.expected_policy_revision,
          'layoutVersion':self.layout_version,'layoutDigest':self.layout_digest,
          'reason': self.reason}

    @property
    def digest(self) -> str:
        payload = json.dumps(self.normalized(), sort_keys=True,
          separators=(',', ':'), ensure_ascii=True).encode('ascii')
        return sha256(payload).hexdigest()
