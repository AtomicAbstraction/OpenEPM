"""Exact, read-only parent-equity/NCI reattribution candidate.

The caller declares that control exists before and after a partial ownership
reduction.  This profile computes only the difference between exact
consideration and the caller-supplied NCI carrying-amount increase.  It does
not infer control, fair value, gain/loss, an accounting policy, or postings.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, localcontext
from hashlib import sha256
import json

from .consolidation_disposal_candidate import (
    DisposalSourcePin, _decimal, _identifier, _revision)


@dataclass(frozen=True)
class RetainedControlDisposal:
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
    nci_carrying_amount_increase: DisposalSourcePin

    @classmethod
    def parse(cls, value: object) -> 'RetainedControlDisposal':
        expected = {'disposalId','disposalVersion','effectiveOn','disposalType',
          'priorControlConfirmed','controlAfterConfirmed','currencyDimensionId',
          'currencyMemberId','accountingPolicyStatus','expectedMetadataRevision',
          'expectedDataRevision','expectedPolicyRevision','relationshipId',
          'scenarioId','yearId','periodId','priorOwnershipPercent',
          'disposedOwnershipPercent','retainedOwnershipPercent',
          'ownershipChangeId','calendarChangeId','considerationReceived',
          'nciCarryingAmountIncrease'}
        if (not isinstance(value,dict) or set(value)!=expected
          or value.get('disposalType')!='partial_retaining_control'
          or value.get('priorControlConfirmed') is not True
          or value.get('controlAfterConfirmed') is not True
          or value.get('accountingPolicyStatus')!='Unreviewed'
          or type(value.get('disposalVersion')) is not int
          or value['disposalVersion']<=0 or not isinstance(value.get('effectiveOn'),str)):
            raise ValueError('RETAINED_CONTROL_DISPOSAL_INVALID')
        try: effective=date.fromisoformat(value['effectiveOn'])
        except ValueError as error:
            raise ValueError('RETAINED_CONTROL_EFFECTIVE_DATE_INVALID') from error
        prior=_decimal(value['priorOwnershipPercent'],'PRIOR_PERCENT',nonnegative=True)
        disposed=_decimal(value['disposedOwnershipPercent'],'DISPOSED_PERCENT',nonnegative=True)
        retained=_decimal(value['retainedOwnershipPercent'],'RETAINED_PERCENT',nonnegative=True)
        if (not Decimal(0)<prior<=Decimal(100) or disposed<=0 or retained<=0
          or retained>=prior or disposed+retained!=prior):
            raise ValueError('RETAINED_CONTROL_OWNERSHIP_RANGE_INVALID')
        pins=(DisposalSourcePin.parse(value['considerationReceived']),
          DisposalSourcePin.parse(value['nciCarryingAmountIncrease']))
        if pins[0].members==pins[1].members or pins[0].change_id==pins[1].change_id:
            raise ValueError('RETAINED_CONTROL_MAPPING_AMBIGUOUS')
        grain={axis for axis,_ in pins[0].members}
        if {axis for axis,_ in pins[1].members}!=grain:
            raise ValueError('RETAINED_CONTROL_GRAIN_MISMATCH')
        currency_dimension=_identifier(value['currencyDimensionId'],'CURRENCY_DIMENSION')
        if currency_dimension in grain:
            raise ValueError('RETAINED_CONTROL_CURRENCY_AXIS_FORBIDDEN')
        for key in ('ownershipChangeId','calendarChangeId'):
            _identifier(value[key],key.upper())
        return cls(_identifier(value['disposalId'],'ID'),value['disposalVersion'],effective,
          currency_dimension,_identifier(value['currencyMemberId'],'CURRENCY_MEMBER'),
          _revision(value['expectedMetadataRevision'],'METADATA_REVISION'),
          _revision(value['expectedDataRevision'],'DATA_REVISION'),
          _revision(value['expectedPolicyRevision'],'POLICY_REVISION'),
          *(_identifier(value[key],key.upper()) for key in
            ('relationshipId','scenarioId','yearId','periodId')),
          prior,disposed,retained,value['ownershipChangeId'],value['calendarChangeId'],*pins)

    @property
    def pins(self) -> tuple[DisposalSourcePin,DisposalSourcePin]:
        return self.consideration_received,self.nci_carrying_amount_increase

    def normalized(self) -> dict:
        return {'disposalId':self.disposal_id,'disposalVersion':self.disposal_version,
          'effectiveOn':self.effective_on.isoformat(),'disposalType':'partial_retaining_control',
          'priorControlConfirmed':True,'controlAfterConfirmed':True,
          'currencyDimensionId':self.currency_dimension_id,
          'currencyMemberId':self.currency_member_id,'accountingPolicyStatus':'Unreviewed',
          'expectedMetadataRevision':self.expected_metadata_revision,
          'expectedDataRevision':self.expected_data_revision,
          'expectedPolicyRevision':self.expected_policy_revision,
          'relationshipId':self.relationship_id,'scenarioId':self.scenario_id,
          'yearId':self.year_id,'periodId':self.period_id,
          'priorOwnershipPercent':format(self.prior_ownership_percent,'f'),
          'disposedOwnershipPercent':format(self.disposed_ownership_percent,'f'),
          'retainedOwnershipPercent':format(self.retained_ownership_percent,'f'),
          'ownershipChangeId':self.ownership_change_id,'calendarChangeId':self.calendar_change_id,
          'considerationReceived':self.consideration_received.normalized(),
          'nciCarryingAmountIncrease':self.nci_carrying_amount_increase.normalized()}

    @property
    def digest(self) -> str:
        return sha256(json.dumps(self.normalized(),sort_keys=True,separators=(',',':'),
          ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()

    def calculate(self, amounts_by_change_id: dict[str,str]) -> dict:
        if set(amounts_by_change_id)!={pin.change_id for pin in self.pins}:
            raise ValueError('RETAINED_CONTROL_SOURCE_VALUES_INCOMPLETE')
        consideration=_decimal(amounts_by_change_id[self.consideration_received.change_id],
          'CONSIDERATION',nonnegative=True)
        nci=_decimal(amounts_by_change_id[self.nci_carrying_amount_increase.change_id],
          'NCI_INCREASE',nonnegative=True)
        with localcontext() as precision:
            precision.prec=80;adjustment=consideration-nci
        return {'disposalId':self.disposal_id,'disposalVersion':self.disposal_version,
          'disposalDigest':self.digest,'disposalScope':'partial_retaining_control',
          'accountingPolicyStatus':'Unreviewed',
          'currency':{'dimensionId':self.currency_dimension_id,'memberId':self.currency_member_id},
          'considerationReceived':format(consideration,'.8f'),
          'nciCarryingAmountIncrease':format(nci,'.8f'),
          'parentEquityAdjustmentCandidate':format(adjustment,'.8f'),
          'gainOrLossRecognized':False,'gainOrLossCandidate':None,
          'sourcePins':[pin.normalized() for pin in self.pins],
          'revisionPins':{'metadata':self.expected_metadata_revision,
            'data':self.expected_data_revision,'policy':self.expected_policy_revision}}
