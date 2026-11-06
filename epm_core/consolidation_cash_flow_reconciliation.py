"""Pure, unreviewed cash-flow mapping and reconciliation contract.

This module classifies caller-selected, exact currency amounts and proves the
arithmetic bridge opening cash + mapped movements = closing cash.  The initial
profile deliberately requires one unique coordinate per opening, closing, and
movement line, all at the identical complete non-Currency fact grain, plus one
explicit Currency registry member as their declared unit.
It does not select accounts, support one-to-many/many-to-one mapping, infer
accounting treatment, translate currency, or publish a financial statement. A
fixed PostgreSQL adapter may resolve the pinned source cells; professional
accounting review remains outside this contract.
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
_SECTIONS = frozenset(('Operating','Investing','Financing','ExchangeEffects'))
_MAX_LINES = 500
_MAX_AMOUNT = Decimal('99999999999999999999.99999999')


def _identifier(value: object, label: str) -> str:
    if not isinstance(value,str) or not _ID.fullmatch(value):
        raise ValueError(f'CASH_FLOW_{label}_INVALID')
    return value


def _strict_revision(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f'CASH_FLOW_{label}_INVALID')
    return value


def _coordinate(value: object) -> tuple[tuple[str,str],...]:
    if not isinstance(value,dict) or not 1 <= len(value) <= 128:
        raise ValueError('CASH_FLOW_COORDINATE_INVALID')
    return tuple(sorted((_identifier(axis,'DIMENSION'),
                         _identifier(member,'MEMBER'))
                        for axis,member in value.items()))


def _amount(value: object, label: str) -> Decimal:
    if not isinstance(value,str):
        raise ValueError(f'CASH_FLOW_{label}_INVALID')
    try: result=Decimal(value)
    except Exception as error:
        raise ValueError(f'CASH_FLOW_{label}_INVALID') from error
    if (not result.is_finite() or result.as_tuple().exponent < -8
            or abs(result)>_MAX_AMOUNT):
        raise ValueError(f'CASH_FLOW_{label}_INVALID')
    return result


@dataclass(frozen=True)
class CashFlowSourcePin:
    members: tuple[tuple[str,str],...]
    change_id: str

    @classmethod
    def parse(cls,value: object) -> 'CashFlowSourcePin':
        if (not isinstance(value,dict) or set(value)!= {'members','changeId'}
                or not isinstance(value['changeId'],str)
                or not _CHANGE.fullmatch(value['changeId'])):
            raise ValueError('CASH_FLOW_SOURCE_PIN_INVALID')
        return cls(_coordinate(value['members']),value['changeId'])

    def normalized(self) -> dict:
        return {'members':dict(self.members),'changeId':self.change_id}


@dataclass(frozen=True)
class CashFlowMappingLine:
    line_id: str
    section: str
    direction: int
    source: CashFlowSourcePin

    @classmethod
    def parse(cls,value: object) -> 'CashFlowMappingLine':
        if (not isinstance(value,dict)
                or set(value)!= {'lineId','section','direction','source'}
                or value.get('section') not in _SECTIONS
                or type(value.get('direction')) is not int
                or value['direction'] not in (-1,1)):
            raise ValueError('CASH_FLOW_MAPPING_LINE_INVALID')
        return cls(_identifier(value['lineId'],'LINE_ID'),value['section'],
                   value['direction'],CashFlowSourcePin.parse(value['source']))

    def normalized(self) -> dict:
        return {'lineId':self.line_id,'section':self.section,
                'direction':self.direction,'source':self.source.normalized()}


@dataclass(frozen=True)
class CashFlowReconciliation:
    mapping_id: str
    mapping_version: int
    effective_on: date
    currency_dimension_id: str
    currency_member_id: str
    expected_metadata_revision: int
    expected_data_revision: int
    expected_policy_revision: int
    opening: CashFlowSourcePin
    closing: CashFlowSourcePin
    lines: tuple[CashFlowMappingLine,...]

    @classmethod
    def parse(cls,value: object) -> 'CashFlowReconciliation':
        expected={'mappingId','mappingVersion','effectiveOn','currencyDimensionId',
          'currencyMemberId','accountingPolicyStatus','expectedMetadataRevision',
          'expectedDataRevision','expectedPolicyRevision','opening','closing','lines'}
        if (not isinstance(value,dict) or set(value)!=expected
                or value.get('accountingPolicyStatus')!='Unreviewed'
                or type(value.get('mappingVersion')) is not int
                or value['mappingVersion']<=0
                or not isinstance(value.get('effectiveOn'),str)
                or not isinstance(value.get('lines'),list)
                or not 1<=len(value['lines'])<=_MAX_LINES):
            raise ValueError('CASH_FLOW_RECONCILIATION_INVALID')
        try: effective=date.fromisoformat(value['effectiveOn'])
        except ValueError as error:
            raise ValueError('CASH_FLOW_EFFECTIVE_DATE_INVALID') from error
        currency_dimension=_identifier(value['currencyDimensionId'],'CURRENCY_DIMENSION')
        currency_member=_identifier(value['currencyMemberId'],'CURRENCY_MEMBER')
        opening=CashFlowSourcePin.parse(value['opening'])
        closing=CashFlowSourcePin.parse(value['closing'])
        lines=tuple(sorted((CashFlowMappingLine.parse(line)
                            for line in value['lines']),key=lambda line:line.line_id))
        ids=[line.line_id for line in lines]
        pins=[opening,closing,*(line.source for line in lines)]
        if len(ids)!=len(set(ids)) or len({pin.members for pin in pins})!=len(pins):
            raise ValueError('CASH_FLOW_MAPPING_AMBIGUOUS')
        grain={axis for axis,_ in opening.members}
        if any({axis for axis,_ in pin.members}!=grain for pin in pins):
            raise ValueError('CASH_FLOW_GRAIN_MISMATCH')
        if currency_dimension in grain:
            raise ValueError('CASH_FLOW_CURRENCY_AXIS_FORBIDDEN')
        return cls(_identifier(value['mappingId'],'MAPPING_ID'),
          value['mappingVersion'],effective,currency_dimension,currency_member,
          _strict_revision(value['expectedMetadataRevision'],'METADATA_REVISION'),
          _strict_revision(value['expectedDataRevision'],'DATA_REVISION'),
          _strict_revision(value['expectedPolicyRevision'],'POLICY_REVISION'),
          opening,closing,lines)

    def normalized(self) -> dict:
        return {'mappingId':self.mapping_id,'mappingVersion':self.mapping_version,
          'effectiveOn':self.effective_on.isoformat(),
          'currencyDimensionId':self.currency_dimension_id,
          'currencyMemberId':self.currency_member_id,
          'accountingPolicyStatus':'Unreviewed',
          'expectedMetadataRevision':self.expected_metadata_revision,
          'expectedDataRevision':self.expected_data_revision,
          'expectedPolicyRevision':self.expected_policy_revision,
          'opening':self.opening.normalized(),'closing':self.closing.normalized(),
          'lines':[line.normalized() for line in self.lines]}

    @property
    def digest(self) -> str:
        raw=json.dumps(self.normalized(),sort_keys=True,separators=(',',':'),
                       ensure_ascii=True,allow_nan=False).encode('ascii')
        return sha256(raw).hexdigest()

    def reconcile(self,amounts_by_change_id: Mapping[str,str]) -> dict:
        if not isinstance(amounts_by_change_id,Mapping):
            raise ValueError('CASH_FLOW_SOURCE_VALUES_INVALID')
        pins=(self.opening,self.closing,*(line.source for line in self.lines))
        expected={pin.change_id for pin in pins}
        if set(amounts_by_change_id)!=expected:
            raise ValueError('CASH_FLOW_SOURCE_VALUES_INCOMPLETE')
        amounts={change_id:_amount(value,'SOURCE_AMOUNT')
                 for change_id,value in amounts_by_change_id.items()}
        sections={section:Decimal(0) for section in sorted(_SECTIONS)}
        with localcontext() as precision:
            precision.prec=80
            for line in self.lines:
                sections[line.section]+=amounts[line.source.change_id]*line.direction
            net=sum(sections.values(),Decimal(0))
            expected_closing=amounts[self.opening.change_id]+net
            difference=amounts[self.closing.change_id]-expected_closing
        for value in (*sections.values(),net,expected_closing,difference):
            if abs(value)>_MAX_AMOUNT:
                raise ValueError('CASH_FLOW_NUMERIC_OVERFLOW')
        return {'mappingId':self.mapping_id,'mappingVersion':self.mapping_version,
          'mappingDigest':self.digest,'accountingPolicyStatus':'Unreviewed',
          'currency':{'dimensionId':self.currency_dimension_id,
                      'memberId':self.currency_member_id},
          'openingCash':format(amounts[self.opening.change_id],'.8f'),
          'sections':{key:format(value,'.8f') for key,value in sections.items()},
          'netCashChange':format(net,'.8f'),
          'expectedClosingCash':format(expected_closing,'.8f'),
          'closingCash':format(amounts[self.closing.change_id],'.8f'),
          'difference':format(difference,'.8f'),
          'reconciled':difference==0,
          'sourcePins':[pin.normalized() for pin in pins],
          'revisionPins':{'metadata':self.expected_metadata_revision,
            'data':self.expected_data_revision,'policy':self.expected_policy_revision}}
