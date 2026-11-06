"""Sealed contract for one Unreviewed mixed-method parent total."""
from dataclasses import dataclass
import re

from .persistence_contract import Coordinate
from .postgres_jobs import _canonical_digest

FUNCTION='consolidation.method.total.publish'
PUBLIC_FUNCTION=FUNCTION
COMPILER_V2='mixed-method-total-v2'
PLAN_DIGEST_V2=_canonical_digest({'function':FUNCTION,'version':2,
 'arithmetic':'exact-sum-explicit-method-contributions',
 'rounding':'half-even-final-8','effects':'calculated-generation-only',
 'accountingPolicyStatus':'Unreviewed'})
COMPILER_V3='mixed-method-total-v3'
PLAN_DIGEST_V3=_canonical_digest({'function':FUNCTION,'version':3,
 'arithmetic':'exact-sum-explicit-method-contributions',
 'transformation':'explicit-account-axis-remap-no-hierarchy-traversal',
 'rounding':'half-even-final-8','effects':'calculated-generation-only',
 'accountingPolicyStatus':'Unreviewed'})
COMPILER='mixed-method-total-v4'
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'version':4,
 'arithmetic':'exact-sum-explicit-method-contributions',
 'transformation':'explicit-entity-account-axis-remap-no-hierarchy-traversal',
 'rounding':'half-even-final-8','effects':'calculated-generation-only',
 'accountingPolicyStatus':'Unreviewed'})
_HEX=re.compile(r'[0-9a-f]{64}\Z');_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')

@dataclass(frozen=True,slots=True)
class MethodTotalPlan:
 document:dict
 @property
 def digest(self):return _canonical_digest(self.document)

def _compile_total(program,version):
 if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
  or program.get('languageVersion')!=2 or program.get('function')!=PUBLIC_FUNCTION
  or not isinstance(program.get('arguments'),dict)):
  raise ValueError('METHOD_TOTAL_PROGRAM_INVALID')
 args=program['arguments'];required={'coverageProgram','expectedCoverageDigest',
  'targetMembers','currencyDimensionId','currencyMemberId','resultKey',
  'expectedPublicationRevision'}
 if version in (3,4):required.add('transformedAxes')
 if set(args)!=required:raise ValueError('METHOD_TOTAL_ARGUMENTS_INVALID')
 coverage=args['coverageProgram']
 if (not isinstance(coverage,dict)
  or coverage.get('function')!='consolidation.method.coverage.inspect'
  or not isinstance(args['expectedCoverageDigest'],str)
  or not _HEX.fullmatch(args['expectedCoverageDigest'])
  or not isinstance(args['currencyDimensionId'],str) or not args['currencyDimensionId']
  or not isinstance(args['currencyMemberId'],str) or not args['currencyMemberId']
  or not isinstance(args['resultKey'],str) or not _KEY.fullmatch(args['resultKey'])
  or type(args['expectedPublicationRevision']) is not int
  or args['expectedPublicationRevision']<0):raise ValueError('METHOD_TOTAL_PINS_INVALID')
 expected_axes=(['Account'] if version==3 else ['Entity','Account'])
 if version in (3,4) and (not isinstance(args['transformedAxes'],list)
  or args['transformedAxes']!=expected_axes):
  raise ValueError('METHOD_TOTAL_TRANSFORMED_AXES_INVALID')
 target=Coordinate.from_mapping(args['targetMembers'])
 if args['currencyDimensionId'] in dict(target.members):
  raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')
 document={'version':version,'function':FUNCTION,'coverageProgram':coverage,
  'expectedCoverageDigest':args['expectedCoverageDigest'],
  'targetMembers':dict(target.members),'currencyDimensionId':args['currencyDimensionId'],
  'currencyMemberId':args['currencyMemberId'],'resultKey':args['resultKey'],
  'expectedPublicationRevision':args['expectedPublicationRevision'],
  'accountingPolicyStatus':'Unreviewed','effects':'calculated-generation-only'}
 if version in (3,4):document['transformedAxes']=expected_axes
 return MethodTotalPlan(document)

def compile_total(program):return _compile_total(program,4)

def decode_total(document):
 if isinstance(document,dict) and document.get('version')==1:
  # V1 incorrectly encoded Currency as coordinate grain.  Never reinterpret
  # an accepted V1 job using corrected V2 semantics.
  raise ValueError('UNSUPPORTED_METHOD_TOTAL_PLAN_VERSION')
 if not isinstance(document,dict) or document.get('version') not in (2,3,4):
  raise ValueError('METHOD_TOTAL_DOCUMENT_INVALID')
 version=document['version'];keys=('coverageProgram','expectedCoverageDigest',
   'targetMembers','currencyDimensionId','currencyMemberId','resultKey',
   'expectedPublicationRevision')
 arguments={key:document.get(key) for key in keys}
 if version in (3,4):arguments['transformedAxes']=document.get('transformedAxes')
 return _compile_total({'languageVersion':2,'function':PUBLIC_FUNCTION,'arguments':arguments},version)
