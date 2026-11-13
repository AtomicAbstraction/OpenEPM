"""Sealed contract for one Unreviewed mixed-method parent total."""
from dataclasses import dataclass
import re

from .persistence_contract import Coordinate
from .postgres_jobs import _canonical_digest
from .current_object_contract import require_state_token

FUNCTION='consolidation.method.total.publish'
PUBLIC_FUNCTION=FUNCTION
COMPILER='mixed-method-total-current'
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,
 'arithmetic':'exact-sum-explicit-method-contributions',
 'transformation':'explicit-entity-account-axis-remap-no-hierarchy-traversal',
 'rounding':'half-even-final-8','effects':'current-result-replacement',
 'accountingPolicyStatus':'Unreviewed'})
_HEX=re.compile(r'[0-9a-f]{64}\Z');_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')

@dataclass(frozen=True,slots=True)
class MethodTotalPlan:
 document:dict
 @property
 def digest(self):return _canonical_digest(self.document)

def compile_total(program):
 if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
  or program.get('languageVersion')!=2 or program.get('function')!=PUBLIC_FUNCTION
  or not isinstance(program.get('arguments'),dict)):
  raise ValueError('METHOD_TOTAL_PROGRAM_INVALID')
 args=program['arguments'];required={'coverageProgram','expectedCoverageDigest',
  'targetMembers','currencyDimensionId','currencyMemberId','resultKey',
  'expectedTargetStateToken'}
 required.add('transformedAxes')
 if set(args)!=required:raise ValueError('METHOD_TOTAL_ARGUMENTS_INVALID')
 coverage=args['coverageProgram']
 if (not isinstance(coverage,dict)
  or coverage.get('function')!='consolidation.method.coverage.inspect'
  or not isinstance(args['expectedCoverageDigest'],str)
  or not _HEX.fullmatch(args['expectedCoverageDigest'])
  or not isinstance(args['currencyDimensionId'],str) or not args['currencyDimensionId']
  or not isinstance(args['currencyMemberId'],str) or not args['currencyMemberId']
  or not isinstance(args['resultKey'],str) or not _KEY.fullmatch(args['resultKey'])
  or args['expectedTargetStateToken'] is not None and
     not isinstance(args['expectedTargetStateToken'],str)):
  raise ValueError('METHOD_TOTAL_PINS_INVALID')
 if args['expectedTargetStateToken'] is not None:
  require_state_token(args['expectedTargetStateToken'],
                      error='METHOD_TOTAL_PINS_INVALID')
 expected_axes=['Entity','Account']
 if (not isinstance(args['transformedAxes'],list)
  or args['transformedAxes']!=expected_axes):
  raise ValueError('METHOD_TOTAL_TRANSFORMED_AXES_INVALID')
 target=Coordinate.from_mapping(args['targetMembers'])
 if args['currencyDimensionId'] in dict(target.members):
  raise ValueError('METHOD_TOTAL_CURRENCY_MISMATCH')
 document={'function':FUNCTION,'coverageProgram':coverage,
  'expectedCoverageDigest':args['expectedCoverageDigest'],
  'targetMembers':dict(target.members),'currencyDimensionId':args['currencyDimensionId'],
  'currencyMemberId':args['currencyMemberId'],'resultKey':args['resultKey'],
  'expectedTargetStateToken':args['expectedTargetStateToken'],
  'accountingPolicyStatus':'Unreviewed','effects':'current-result-replacement'}
 document['transformedAxes']=expected_axes
 return MethodTotalPlan(document)

def decode_total(document):
 expected={'function','coverageProgram','expectedCoverageDigest',
  'targetMembers','currencyDimensionId','currencyMemberId','resultKey',
  'expectedTargetStateToken','accountingPolicyStatus','effects',
  'transformedAxes'}
 if not isinstance(document,dict) or set(document)!=expected:
  raise ValueError('METHOD_TOTAL_DOCUMENT_INVALID')
 keys=('coverageProgram','expectedCoverageDigest',
   'targetMembers','currencyDimensionId','currencyMemberId','resultKey',
   'expectedTargetStateToken','transformedAxes')
 arguments={key:document.get(key) for key in keys}
 return compile_total({'languageVersion':2,'function':PUBLIC_FUNCTION,
                       'arguments':arguments})
