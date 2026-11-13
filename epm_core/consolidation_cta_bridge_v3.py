"""Strict typed-unit CTA bridge contract with Currency outside cube grain."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from .consolidation_cta_bridge_v2 import (
    _DIGEST, _ID, _ROLES, _id, _revision)
from .persistence_contract import Coordinate


@dataclass(frozen=True)
class CtaUnitSourcePin:
    role: str
    movement_id: str | None
    result_key: str
    result_state_token: str
    members: tuple[tuple[str, str], ...]
    sign: int

    @classmethod
    def parse(cls, value: object) -> 'CtaUnitSourcePin':
        fields={'role','movementId','resultKey','resultStateToken',
                'members','sign'}
        if (not isinstance(value,dict) or set(value)!=fields
                or value.get('role') not in _ROLES
                or not isinstance(value.get('resultStateToken'),str)
                or not _DIGEST.fullmatch(value['resultStateToken'])
                or value.get('sign') not in (-1,1)
                or isinstance(value.get('sign'),bool)):
            raise ValueError('CTA_V3_SOURCE_INVALID')
        movement=value['movementId']
        if ((value['role']=='Movement')!=(movement is not None)
                or (movement is not None and (not isinstance(movement,str)
                    or not _ID.fullmatch(movement)))):
            raise ValueError('CTA_V3_MOVEMENT_ID_INVALID')
        try: members=Coordinate.from_mapping(value['members']).members
        except (TypeError,ValueError,AttributeError) as error:
            raise ValueError('CTA_V3_SOURCE_MEMBERS_INVALID') from error
        return cls(value['role'],movement,
          _id(value['resultKey'],'RESULT_KEY'),value['resultStateToken'],
          members,value['sign'])

    def normalized(self):
        return {'role':self.role,'movementId':self.movement_id,
          'resultKey':self.result_key,
          'resultStateToken':self.result_state_token,
          'members':dict(self.members),'sign':self.sign}


@dataclass(frozen=True)
class CtaBridgeV3:
    sources: tuple[CtaUnitSourcePin,...]
    cta_members: tuple[tuple[str,str],...]
    offset_members: tuple[tuple[str,str],...]
    currency_dimension_id: str
    currency_member_id: str
    effective_period: tuple[tuple[str,str],...]
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    layout_state_token: str
    layout_digest: str
    reason: str

    @classmethod
    def parse(cls,value:object)->'CtaBridgeV3':
        fields={'bridgeVersion','accountingPolicyStatus','sources','ctaMembers',
          'offsetMembers','outputCurrencyDimensionId','outputCurrencyMemberId',
          'effectivePeriod','expectedMetadataRevision','expectedDataRevision',
          'expectedPolicyRevision','layoutStateToken','layoutDigest','reason'}
        if (not isinstance(value,dict) or set(value)!=fields
                or value.get('bridgeVersion')!=3
                or value.get('accountingPolicyStatus')!='Unreviewed'
                or not isinstance(value.get('sources'),list)
                or not 3<=len(value['sources'])<=102
                or not isinstance(value.get('reason'),str)
                or not 1<=len(value['reason'])<=500
                or value['reason']!=value['reason'].strip()
                or not isinstance(value.get('layoutStateToken'),str)
                or not _DIGEST.fullmatch(value['layoutStateToken'])
                or not isinstance(value.get('layoutDigest'),str)
                or not _DIGEST.fullmatch(value['layoutDigest'])):
            raise ValueError('CTA_V3_ARGUMENTS_INVALID')
        sources=tuple(CtaUnitSourcePin.parse(item) for item in value['sources'])
        roles=[item.role for item in sources]
        if (roles.count('Opening')!=1 or roles.count('Closing')!=1
                or roles.count('Movement')<1
                or len({(item.result_key,item.result_state_token,item.members)
                        for item in sources})!=len(sources)
                or len({item.movement_id for item in sources
                        if item.role=='Movement'})!=roles.count('Movement')):
            raise ValueError('CTA_V3_SOURCE_SET_INVALID')
        if (next(item for item in sources if item.role=='Opening').sign!=1
                or next(item for item in sources
                        if item.role=='Closing').sign!=1):
            raise ValueError('CTA_V3_BALANCE_SIGN_INVALID')
        axes={axis for axis,_ in sources[0].members}
        if any({axis for axis,_ in item.members}!=axes for item in sources[1:]):
            raise ValueError('CTA_V3_SOURCE_GRAIN_MISMATCH')
        try:
            cta=Coordinate.from_mapping(value['ctaMembers']).members
            offset=Coordinate.from_mapping(value['offsetMembers']).members
        except (TypeError,ValueError,AttributeError) as error:
            raise ValueError('CTA_V3_TARGET_INVALID') from error
        if cta==offset or any({axis for axis,_ in point}!=axes
                              for point in (cta,offset)):
            raise ValueError('CTA_V3_TARGET_OR_GRAIN_INVALID')
        currency_dimension=_id(value.get('outputCurrencyDimensionId'),
                               'CURRENCY_DIMENSION')
        currency_member=_id(value.get('outputCurrencyMemberId'),
                            'CURRENCY_MEMBER')
        if currency_dimension in axes:
            raise ValueError('CTA_V3_CURRENCY_AXIS_FORBIDDEN')
        period=value['effectivePeriod']
        if (not isinstance(period,dict) or set(period)!={
                'scenarioDimension','scenarioId','yearDimension','yearId',
                'periodDimension','periodId'} or any(
                not isinstance(item,str) or not item for item in period.values())):
            raise ValueError('CTA_V3_PERIOD_INVALID')
        for members in (cta,offset,*(item.members for item in sources)):
            point=dict(members)
            if any(point.get(period[axis])!=period[member]
                   for axis,member in (('scenarioDimension','scenarioId'),
                    ('yearDimension','yearId'),('periodDimension','periodId'))):
                raise ValueError('CTA_V3_PERIOD_MISMATCH')
        return cls(sources,cta,offset,currency_dimension,currency_member,
          tuple(sorted(period.items())),
          _revision(value['expectedMetadataRevision'],'METADATA_REVISION'),
          _revision(value['expectedDataRevision'],'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'],'POLICY_REVISION'),
          value['layoutStateToken'],
          value['layoutDigest'],value['reason'])

    def normalized(self):
        return {'bridgeVersion':3,'accountingPolicyStatus':'Unreviewed',
          'sources':[item.normalized() for item in self.sources],
          'ctaMembers':dict(self.cta_members),
          'offsetMembers':dict(self.offset_members),
          'outputCurrencyDimensionId':self.currency_dimension_id,
          'outputCurrencyMemberId':self.currency_member_id,
          'effectivePeriod':dict(self.effective_period),
          'expectedMetadataRevision':self.expected_metadata_revision,
          'expectedDataRevision':self.expected_data_revision,
          'expectedPolicyRevision':self.expected_policy_revision,
          'layoutStateToken':self.layout_state_token,'layoutDigest':self.layout_digest,
          'reason':self.reason}

    @property
    def digest(self):
        payload=json.dumps(self.normalized(),sort_keys=True,
          separators=(',',':'),ensure_ascii=True).encode('ascii')
        return sha256(payload).hexdigest()
