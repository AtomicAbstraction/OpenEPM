"""Exact, caller-directed intercompany residual-resolution candidate."""
from __future__ import annotations
from dataclasses import dataclass
from decimal import Decimal,InvalidOperation
from hashlib import sha256
import json,re

_ID=re.compile(r'[A-Za-z0-9._-]{1,200}\Z')
_CHANGE=re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_MAX=Decimal('99999999999999999999.99999999')

def _id(value:object,label:str)->str:
    if not isinstance(value,str) or not _ID.fullmatch(value):raise ValueError(f'IC_RESIDUAL_{label}_INVALID')
    return value
def _revision(value:object,label:str)->int:
    if type(value) is not int or value<0:raise ValueError(f'IC_RESIDUAL_{label}_INVALID')
    return value
def _amount(value:object,label:str)->Decimal:
    if not isinstance(value,str):raise ValueError(f'IC_RESIDUAL_{label}_INVALID')
    try: result=Decimal(value)
    except InvalidOperation as error:raise ValueError(f'IC_RESIDUAL_{label}_INVALID') from error
    if not result.is_finite() or result.as_tuple().exponent < -8 or abs(result)>_MAX:
        raise ValueError(f'IC_RESIDUAL_{label}_INVALID')
    return result
def _members(value:object)->dict[str,str]:
    if not isinstance(value,dict) or not 1<=len(value)<=32:raise ValueError('IC_RESIDUAL_COORDINATE_INVALID')
    return {_id(k,'DIMENSION'):_id(v,'MEMBER') for k,v in value.items()}

@dataclass(frozen=True)
class IntercompanyResidualResolution:
    resolution_id:str;resolution_version:int;currency_dimension_id:str;currency_member_id:str
    left_members:dict[str,str];right_members:dict[str,str]
    expected_left_change_id:str;expected_right_change_id:str
    expected_metadata_revision:int;expected_data_revision:int;expected_policy_revision:int;expected_commit_revision:int
    adjustment_side:str;declared_signed_adjustment:Decimal
    @classmethod
    def parse(cls,value:object)->'IntercompanyResidualResolution':
        expected={'resolutionId','resolutionVersion','accountingPolicyStatus','resolutionAction',
          'currencyDimensionId','currencyMemberId','leftMembers','rightMembers',
          'expectedLeftChangeId','expectedRightChangeId','expectedMetadataRevision',
          'expectedDataRevision','expectedPolicyRevision','expectedCommitRevision',
          'adjustmentSide','declaredSignedAdjustment'}
        if (not isinstance(value,dict) or set(value)!=expected
          or value.get('accountingPolicyStatus')!='Unreviewed'
          or value.get('resolutionAction')!='candidate_adjustment'
          or type(value.get('resolutionVersion')) is not int or value['resolutionVersion']<=0
          or value.get('adjustmentSide') not in ('left','right')):
            raise ValueError('IC_RESIDUAL_DEFINITION_INVALID')
        left,right=_members(value['leftMembers']),_members(value['rightMembers'])
        if set(left)!=set(right):raise ValueError('IC_RESIDUAL_GRAIN_MISMATCH')
        changes=[]
        for key in ('expectedLeftChangeId','expectedRightChangeId'):
            if not isinstance(value[key],str) or not _CHANGE.fullmatch(value[key]):raise ValueError('IC_RESIDUAL_CHANGE_ID_INVALID')
            changes.append(value[key])
        if changes[0]==changes[1]:raise ValueError('IC_RESIDUAL_CHANGE_ID_AMBIGUOUS')
        return cls(_id(value['resolutionId'],'ID'),value['resolutionVersion'],
          _id(value['currencyDimensionId'],'CURRENCY_DIMENSION'),_id(value['currencyMemberId'],'CURRENCY_MEMBER'),
          left,right,*changes,_revision(value['expectedMetadataRevision'],'METADATA_REVISION'),
          _revision(value['expectedDataRevision'],'DATA_REVISION'),_revision(value['expectedPolicyRevision'],'POLICY_REVISION'),
          _revision(value['expectedCommitRevision'],'COMMIT_REVISION'),value['adjustmentSide'],
          _amount(value['declaredSignedAdjustment'],'DECLARED_ADJUSTMENT'))
    def normalized(self)->dict:
        return {'resolutionId':self.resolution_id,'resolutionVersion':self.resolution_version,
          'accountingPolicyStatus':'Unreviewed','resolutionAction':'candidate_adjustment',
          'currencyDimensionId':self.currency_dimension_id,'currencyMemberId':self.currency_member_id,
          'leftMembers':self.left_members,'rightMembers':self.right_members,
          'expectedLeftChangeId':self.expected_left_change_id,'expectedRightChangeId':self.expected_right_change_id,
          'expectedMetadataRevision':self.expected_metadata_revision,'expectedDataRevision':self.expected_data_revision,
          'expectedPolicyRevision':self.expected_policy_revision,'expectedCommitRevision':self.expected_commit_revision,
          'adjustmentSide':self.adjustment_side,'declaredSignedAdjustment':format(self.declared_signed_adjustment,'f')}
    @property
    def digest(self)->str:
        return sha256(json.dumps(self.normalized(),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    def calculate(self,pair:dict)->dict:
        for key,expected in (('metadataRevision',self.expected_metadata_revision),('dataRevision',self.expected_data_revision),
          ('policyRevision',self.expected_policy_revision),('commitRevision',self.expected_commit_revision)):
            if pair.get(key)!=expected:raise ValueError('IC_RESIDUAL_SOURCE_REVISION_STALE')
        if pair.get('issues'):raise ValueError('IC_RESIDUAL_PAIR_NOT_COMPARABLE')
        if pair.get('signedResidual') in (None,'0.00000000'):raise ValueError('IC_RESIDUAL_MISMATCH_REQUIRED')
        if (pair.get('left',{}).get('members')!=self.left_members
          or pair.get('right',{}).get('members')!=self.right_members):raise ValueError('IC_RESIDUAL_COORDINATE_STALE')
        if (pair['left'].get('changeId')!=self.expected_left_change_id
          or pair['right'].get('changeId')!=self.expected_right_change_id):raise ValueError('IC_RESIDUAL_SOURCE_CHANGE_STALE')
        if (pair['left'].get('entityCurrencyMemberId')!=self.currency_member_id
          or pair['right'].get('entityCurrencyMemberId')!=self.currency_member_id):raise ValueError('IC_RESIDUAL_CURRENCY_MISMATCH')
        residual=_amount(pair['signedResidual'],'SOURCE_RESIDUAL');required=-residual
        if self.declared_signed_adjustment!=required:raise ValueError('IC_RESIDUAL_DECLARED_ADJUSTMENT_MISMATCH')
        source=pair[self.adjustment_side]
        return {'resolutionId':self.resolution_id,'resolutionVersion':self.resolution_version,
          'resolutionDigest':self.digest,'accountingPolicyStatus':'Unreviewed',
          'currency':{'dimensionId':self.currency_dimension_id,'memberId':self.currency_member_id},
          'sourceSignedResidual':format(residual,'.8f'),'candidateAvailable':True,
          'candidateLine':{'side':self.adjustment_side,'sourceMembers':source['members'],
            'sourceChangeId':source['changeId'],'declaredSignedAdjustment':format(required,'.8f')},
          'gainOrLossInferred':False,'resolutionPolicyInferred':False}
