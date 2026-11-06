"""Exact, bounded loss-of-control disposal candidate contract.

This contract validates caller-declared ownership/control assertions and exact
source pins, then computes a structural gain/loss candidate.  It does not
assess control, choose an accounting policy, validate a valuation, or post a
disposal.  Both full disposal and partial disposal with loss of control are
supported; a non-controlling-interest change without loss of control is
explicitly outside this profile.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, localcontext
from hashlib import sha256
import json
import re
from typing import Mapping


_ID = re.compile(r'[A-Za-z0-9._-]{1,200}\Z')
_CHANGE = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_MAX = Decimal('99999999999999999999.99999999')


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f'DISPOSAL_{label}_INVALID')
    return value


def _revision(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'DISPOSAL_{label}_INVALID')
    return value


def _decimal(value: object, label: str, *, nonnegative: bool) -> Decimal:
    if not isinstance(value, str):
        raise ValueError(f'DISPOSAL_{label}_INVALID')
    try: result = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f'DISPOSAL_{label}_INVALID') from error
    if (not result.is_finite() or result.as_tuple().exponent < -8
            or abs(result) > _MAX or nonnegative and result < 0):
        raise ValueError(f'DISPOSAL_{label}_INVALID')
    return result


def _coordinate(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict) or not 1 <= len(value) <= 128:
        raise ValueError('DISPOSAL_COORDINATE_INVALID')
    return tuple(sorted((_identifier(axis, 'DIMENSION'),
                         _identifier(member, 'MEMBER'))
                        for axis, member in value.items()))


@dataclass(frozen=True)
class DisposalSourcePin:
    members: tuple[tuple[str, str], ...]
    change_id: str

    @classmethod
    def parse(cls, value: object) -> 'DisposalSourcePin':
        if (not isinstance(value, dict) or set(value) != {'members', 'changeId'}
                or not isinstance(value['changeId'], str)
                or not _CHANGE.fullmatch(value['changeId'])):
            raise ValueError('DISPOSAL_SOURCE_PIN_INVALID')
        return cls(_coordinate(value['members']), value['changeId'])

    def normalized(self) -> dict:
        return {'members': dict(self.members), 'changeId': self.change_id}


@dataclass(frozen=True)
class DisposalCandidate:
    disposal_id: str
    disposal_version: int
    effective_on: date
    currency_dimension_id: str
    currency_member_id: str
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    relationship_id: str
    scenario_id: str
    year_id: str
    period_id: str
    prior_ownership_percent: Decimal
    disposed_ownership_percent: Decimal
    retained_ownership_percent: Decimal
    ownership_change_id: str
    calendar_change_id: str
    consideration_received: DisposalSourcePin
    retained_interest_fair_value: DisposalSourcePin
    net_assets_including_goodwill: DisposalSourcePin
    nci_carrying_amount: DisposalSourcePin
    oci_reclassification: DisposalSourcePin

    @classmethod
    def parse(cls, value: object) -> 'DisposalCandidate':
        expected = {'disposalId','disposalVersion','effectiveOn','disposalType',
          'priorControlConfirmed','controlAfterConfirmed','currencyDimensionId',
          'currencyMemberId','accountingPolicyStatus','expectedMetadataRevision',
          'expectedDataRevision','expectedPolicyRevision','relationshipId',
          'scenarioId','yearId','periodId','priorOwnershipPercent',
          'disposedOwnershipPercent','retainedOwnershipPercent',
          'ownershipChangeId','calendarChangeId','considerationReceived',
          'retainedInterestFairValue','netAssetsIncludingGoodwillCarryingAmount',
          'nciCarryingAmount','ociReclassification'}
        if (not isinstance(value, dict) or set(value) != expected
                or value.get('disposalType') != 'loss_of_control'
                or value.get('priorControlConfirmed') is not True
                or value.get('controlAfterConfirmed') is not False
                or value.get('accountingPolicyStatus') != 'Unreviewed'
                or type(value.get('disposalVersion')) is not int
                or value['disposalVersion'] <= 0
                or not isinstance(value.get('effectiveOn'), str)):
            raise ValueError('DISPOSAL_CANDIDATE_INVALID')
        try: effective = date.fromisoformat(value['effectiveOn'])
        except ValueError as error:
            raise ValueError('DISPOSAL_EFFECTIVE_DATE_INVALID') from error
        prior = _decimal(value['priorOwnershipPercent'], 'PRIOR_PERCENT', nonnegative=True)
        disposed = _decimal(value['disposedOwnershipPercent'], 'DISPOSED_PERCENT', nonnegative=True)
        retained = _decimal(value['retainedOwnershipPercent'], 'RETAINED_PERCENT', nonnegative=True)
        if (not Decimal(0) < prior <= Decimal(100) or disposed <= 0
                or retained >= prior or disposed + retained != prior):
            raise ValueError('DISPOSAL_OWNERSHIP_RANGE_INVALID')
        pins = tuple(DisposalSourcePin.parse(value[key]) for key in (
          'considerationReceived','retainedInterestFairValue',
          'netAssetsIncludingGoodwillCarryingAmount','nciCarryingAmount',
          'ociReclassification'))
        if (len({pin.members for pin in pins}) != len(pins)
                or len({pin.change_id for pin in pins}) != len(pins)):
            raise ValueError('DISPOSAL_MAPPING_AMBIGUOUS')
        grain = {axis for axis, _ in pins[0].members}
        if any({axis for axis, _ in pin.members} != grain for pin in pins):
            raise ValueError('DISPOSAL_GRAIN_MISMATCH')
        currency_dimension = _identifier(value['currencyDimensionId'],'CURRENCY_DIMENSION')
        if currency_dimension in grain:
            raise ValueError('DISPOSAL_CURRENCY_AXIS_FORBIDDEN')
        for key in ('ownershipChangeId','calendarChangeId'):
            if not isinstance(value[key], str) or not _CHANGE.fullmatch(value[key]):
                raise ValueError('DISPOSAL_CHANGE_ID_INVALID')
        return cls(_identifier(value['disposalId'],'ID'),value['disposalVersion'],effective,
          currency_dimension,_identifier(value['currencyMemberId'],'CURRENCY_MEMBER'),
          _revision(value['expectedMetadataRevision'],'METADATA_REVISION'),
          _revision(value['expectedDataRevision'],'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'],'POLICY_REVISION'),
          *(_identifier(value[key],key.upper()) for key in
            ('relationshipId','scenarioId','yearId','periodId')),
          prior,disposed,retained,value['ownershipChangeId'],value['calendarChangeId'],*pins)

    @property
    def pins(self) -> tuple[DisposalSourcePin, ...]:
        return (self.consideration_received,self.retained_interest_fair_value,
          self.net_assets_including_goodwill,self.nci_carrying_amount,
          self.oci_reclassification)

    def normalized(self) -> dict:
        result={'disposalId':self.disposal_id,'disposalVersion':self.disposal_version,
          'effectiveOn':self.effective_on.isoformat(),'disposalType':'loss_of_control',
          'priorControlConfirmed':True,'controlAfterConfirmed':False,
          'currencyDimensionId':self.currency_dimension_id,
          'currencyMemberId':self.currency_member_id,
          'accountingPolicyStatus':'Unreviewed',
          'expectedMetadataRevision':self.expected_metadata_revision,
          'expectedDataRevision':self.expected_data_revision,
          'expectedPolicyRevision':self.expected_policy_revision,
          'relationshipId':self.relationship_id,'scenarioId':self.scenario_id,
          'yearId':self.year_id,'periodId':self.period_id,
          'priorOwnershipPercent':format(self.prior_ownership_percent,'f'),
          'disposedOwnershipPercent':format(self.disposed_ownership_percent,'f'),
          'retainedOwnershipPercent':format(self.retained_ownership_percent,'f'),
          'ownershipChangeId':self.ownership_change_id,
          'calendarChangeId':self.calendar_change_id}
        for key,pin in zip(('considerationReceived','retainedInterestFairValue',
          'netAssetsIncludingGoodwillCarryingAmount','nciCarryingAmount',
          'ociReclassification'),self.pins):result[key]=pin.normalized()
        return result

    @property
    def digest(self) -> str:
        return sha256(json.dumps(self.normalized(),sort_keys=True,
          separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()

    def calculate(self, amounts_by_change_id: Mapping[str,str]) -> dict:
        if (not isinstance(amounts_by_change_id,Mapping)
                or set(amounts_by_change_id)!={pin.change_id for pin in self.pins}):
            raise ValueError('DISPOSAL_SOURCE_VALUES_INCOMPLETE')
        values={pin.change_id:_decimal(amounts_by_change_id[pin.change_id],
          'SOURCE_AMOUNT',nonnegative=pin is not self.oci_reclassification) for pin in self.pins}
        consideration=values[self.consideration_received.change_id]
        retained_fair=values[self.retained_interest_fair_value.change_id]
        net_assets=values[self.net_assets_including_goodwill.change_id]
        nci=values[self.nci_carrying_amount.change_id]
        oci=values[self.oci_reclassification.change_id]
        if self.retained_ownership_percent==0 and retained_fair!=0:
            raise ValueError('DISPOSAL_FULL_RETAINED_FAIR_VALUE_CONFLICT')
        if self.retained_ownership_percent>0 and retained_fair==0:
            raise ValueError('DISPOSAL_RETAINED_FAIR_VALUE_REQUIRED')
        with localcontext() as precision:
            precision.prec=80
            gain=consideration+retained_fair+nci+oci-net_assets
        if abs(gain)>_MAX:raise ValueError('DISPOSAL_NUMERIC_OVERFLOW')
        return {'disposalId':self.disposal_id,'disposalVersion':self.disposal_version,
          'disposalDigest':self.digest,'accountingPolicyStatus':'Unreviewed',
          'disposalScope':'full' if self.retained_ownership_percent==0 else 'partial_with_loss_of_control',
          'currency':{'dimensionId':self.currency_dimension_id,'memberId':self.currency_member_id},
          'considerationReceived':format(consideration,'.8f'),
          'retainedInterestFairValue':format(retained_fair,'.8f'),
          'nciCarryingAmount':format(nci,'.8f'),
          'ociReclassification':format(oci,'.8f'),
          'netAssetsIncludingGoodwillDerecognized':format(net_assets,'.8f'),
          'gainOrLossCandidate':format(gain,'.8f'),
          'sourcePins':[pin.normalized() for pin in self.pins],
          'revisionPins':{'metadata':self.expected_metadata_revision,
            'data':self.expected_data_revision,'policy':self.expected_policy_revision}}
