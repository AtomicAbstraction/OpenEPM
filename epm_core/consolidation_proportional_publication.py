"""Sealed contract for one Unreviewed calculated Proportional candidate."""
from dataclasses import dataclass
import re

from .postgres_jobs import _canonical_digest

FUNCTION='consolidation.proportional.contribution.publish'
PUBLIC_FUNCTION='consolidation.proportional.contribution.publish.certified'
COMPILER='proportional-contribution-v1'
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'version':1,
 'arithmetic':'source*PCON/100','rounding':'half-even-final-8',
 'effects':'calculated-generation-only','accountingPolicyStatus':'Unreviewed'})
_HEX=re.compile(r'[0-9a-f]{64}\Z');_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')

@dataclass(frozen=True,slots=True)
class ProportionalPublicationPlan:
 document:dict
 @property
 def digest(self):return _canonical_digest(self.document)

def compile_publication(program):
 if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
   or program.get('languageVersion')!=2 or program.get('function')!=PUBLIC_FUNCTION
   or not isinstance(program.get('arguments'),dict)):raise ValueError('PROPORTIONAL_PUBLICATION_PROGRAM_INVALID')
 args=program['arguments']
 if set(args)!={'previewProgram','expectedPreviewDigest','resultKey','expectedPublicationRevision'}:raise ValueError('PROPORTIONAL_PUBLICATION_ARGUMENTS_INVALID')
 preview=args['previewProgram']
 if (not isinstance(preview,dict) or preview.get('function')!='consolidation.proportional.contribution.preview'
   or not isinstance(args['expectedPreviewDigest'],str) or not _HEX.fullmatch(args['expectedPreviewDigest'])
   or not isinstance(args['resultKey'],str) or not _KEY.fullmatch(args['resultKey'])
   or type(args['expectedPublicationRevision']) is not int or args['expectedPublicationRevision']<0):raise ValueError('PROPORTIONAL_PUBLICATION_PINS_INVALID')
 from .postgres_proportional_contribution import _arguments
 _arguments(preview)
 return ProportionalPublicationPlan({'version':1,'function':FUNCTION,
  'previewProgram':preview,'expectedPreviewDigest':args['expectedPreviewDigest'],
  'resultKey':args['resultKey'],'expectedPublicationRevision':args['expectedPublicationRevision'],
  'accountingPolicyStatus':'Unreviewed','effects':'calculated-generation-only'})

def decode_publication(document):
 if not isinstance(document,dict) or document.get('version')!=1:return compile_publication({})
 return compile_publication({'languageVersion':2,'function':PUBLIC_FUNCTION,'arguments':{
  'previewProgram':document.get('previewProgram'),'expectedPreviewDigest':document.get('expectedPreviewDigest'),
  'resultKey':document.get('resultKey'),'expectedPublicationRevision':document.get('expectedPublicationRevision')}})
