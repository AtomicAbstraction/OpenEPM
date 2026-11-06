"""Strict multi-equation structural statement pack; no accounting inference."""
from decimal import Decimal,localcontext
import re
from .persistence_contract import Coordinate,NumericCell

_ID=re.compile(r'[A-Za-z0-9._-]{8,128}\Z');_JOB=re.compile(r'[0-9a-f]{32}\Z')
KINDS=('CalculationAmount','TypedUnitAmount','CtaBridge',
       'CalculationJournalLine','AcquisitionJournalLine')
MAX_EQUATIONS=32

def compile_pack(raw,function):
 if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'} or raw.get('languageVersion')!=2 or raw.get('function')!=function or not isinstance(raw.get('arguments'),dict)):raise ValueError('STATEMENT_PACK_PROGRAM_INVALID')
 a=raw['arguments'];required={'packId','sources','equations','expectedMetadataRevision','expectedDataRevision','expectedPolicyRevision','expectedCommitRevision'}
 if (set(a)!=required or not isinstance(a['packId'],str) or not _ID.fullmatch(a['packId']) or not isinstance(a['sources'],list) or not 2<=len(a['sources'])<=64 or not isinstance(a['equations'],list) or not 2<=len(a['equations'])<=MAX_EQUATIONS or any(type(a[k]) is not int or a[k]<0 for k in required if k.startswith('expected'))):raise ValueError('STATEMENT_PACK_ARGUMENTS_INVALID')
 sources=[];ids=set()
 for s in a['sources']:
  base={'sourceId','sourceKind','members'}
  if not isinstance(s,dict) or s.get('sourceKind') not in KINDS:raise ValueError('STATEMENT_PACK_SOURCE_INVALID')
  kind=s['sourceKind']
  if kind=='CtaBridge':expected=base|{'bridgeId'}
  elif kind in ('CalculationJournalLine','AcquisitionJournalLine'):expected=base|{
      'journalId','lineOrdinal','committedRevision',
      'currencyDimensionId','currencyMemberId'}|(
      {'lineRole'} if kind=='AcquisitionJournalLine' else set())
  else:expected=base|{'resultKey','generationId','publishedRevision'}|(
      {'currencyDimensionId','currencyMemberId'}
      if kind=='TypedUnitAmount' else set())
  if set(s)!=expected or not isinstance(s.get('sourceId'),str) or not _ID.fullmatch(s['sourceId']) or s['sourceId'] in ids:raise ValueError('STATEMENT_PACK_SOURCE_INVALID')
  ids.add(s['sourceId'])
  try:members=dict(Coordinate.from_mapping(s['members']).members)
  except Exception as e:raise ValueError('STATEMENT_PACK_SOURCE_INVALID') from e
  if kind=='CtaBridge':
   if not isinstance(s['bridgeId'],str) or not _JOB.fullmatch(s['bridgeId']):raise ValueError('STATEMENT_PACK_SOURCE_INVALID')
  elif kind in ('CalculationJournalLine','AcquisitionJournalLine'):
   if (not isinstance(s['journalId'],str) or not _ID.fullmatch(s['journalId'])
       or type(s['lineOrdinal']) is not int
       or not 1<=s['lineOrdinal']<=100
       or type(s['committedRevision']) is not int
       or s['committedRevision']<1
       or any(not isinstance(s[k],str) or not 1<=len(s[k])<=200
              for k in ('currencyDimensionId','currencyMemberId'))
       or (kind=='AcquisitionJournalLine' and (
           not isinstance(s['lineRole'],str)
           or s['lineRole'] not in ('netAssetsOffset','goodwill',
             'investmentOffset','nonControllingInterest',
             'remeasurementGainOrLoss')))):raise ValueError('STATEMENT_PACK_SOURCE_INVALID')
  else:
   if (not isinstance(s['resultKey'],str) or not _ID.fullmatch(s['resultKey']) or not isinstance(s['generationId'],str) or not _JOB.fullmatch(s['generationId']) or type(s['publishedRevision']) is not int or s['publishedRevision']<1):raise ValueError('STATEMENT_PACK_SOURCE_INVALID')
  if kind=='TypedUnitAmount' and any(not isinstance(s[k],str) or not s[k] for k in ('currencyDimensionId','currencyMemberId')):raise ValueError('STATEMENT_PACK_SOURCE_INVALID')
  sources.append({**s,'members':members})
 by_id={s['sourceId']:s for s in sources};equations=[];used=set()
 for e in a['equations']:
  if (not isinstance(e,dict) or set(e)!={'equationId','fixedMembers','currencyDimensionId','currencyMemberId','terms'} or not isinstance(e.get('equationId'),str) or not _ID.fullmatch(e['equationId']) or not isinstance(e.get('terms'),list) or not 2<=len(e['terms'])<=128):raise ValueError('STATEMENT_PACK_EQUATION_INVALID')
  fixed=dict(Coordinate.from_mapping(e['fixedMembers']).members)
  if (not isinstance(e['currencyDimensionId'],str) or not e['currencyDimensionId']
      or not isinstance(e['currencyMemberId'],str) or not e['currencyMemberId']
      or e['currencyDimensionId'] in fixed):raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
  terms=[];seen=set()
  for term in e['terms']:
   if not isinstance(term,dict) or set(term)!={'sourceId','sectionId','sign'} or term.get('sourceId') not in by_id or not isinstance(term.get('sectionId'),str) or not _ID.fullmatch(term['sectionId']) or term.get('sign') not in (-1,1) or isinstance(term.get('sign'),bool) or term['sourceId'] in seen:raise ValueError('STATEMENT_PACK_TERM_INVALID')
   source=by_id[term['sourceId']];seen.add(term['sourceId']);used.add(term['sourceId'])
   if (e['currencyDimensionId'] in source['members']
       or any(source['members'].get(k)!=v for k,v in fixed.items())):raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
   if source['sourceKind'] in ('TypedUnitAmount','CalculationJournalLine','AcquisitionJournalLine') and (source['currencyDimensionId']!=e['currencyDimensionId'] or source['currencyMemberId']!=e['currencyMemberId']):raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
   terms.append(dict(term))
  # Every explicit source occupies the same dimensional grain, while member
  # values outside ``fixedMembers`` may differ (for example Asset versus
  # Liability/Equity accounts).  This remains non-aggregating: every source is
  # one exact pinned coordinate.
  if len({tuple(sorted(by_id[t['sourceId']]['members']))
          for t in terms})!=1:
   raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
  equations.append({**e,'fixedMembers':fixed,'terms':terms})
 source_units={}
 for equation in equations:
  unit=(equation['currencyDimensionId'],equation['currencyMemberId'])
  for term in equation['terms']:
   previous=source_units.setdefault(term['sourceId'],unit)
   if previous!=unit:raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
 if used!=ids or len({e['equationId'] for e in equations})!=len(equations):raise ValueError('STATEMENT_PACK_SOURCE_UNUSED_OR_EQUATION_DUPLICATE')
 return {'version':2,'packId':a['packId'],'sources':sources,'equations':equations,'pins':{k:a[k] for k in required if k.startswith('expected')}}

def reconcile_pack(plan,amounts):
 out=[]
 with localcontext() as c:
  c.prec=80
  for equation in plan['equations']:
   total=Decimal(0);sections={};terms=[]
   for term in equation['terms']:
    amount=Decimal(amounts[term['sourceId']]);signed=amount*term['sign'];total+=signed;sections[term['sectionId']]=sections.get(term['sectionId'],Decimal(0))+signed;terms.append({**term,'amount':format(amount,'.8f'),'signedAmount':format(signed,'.8f')})
   NumericCell(True,total,'');out.append({'equationId':equation['equationId'],'reconciled':total==0,'signedTotal':format(total,'.8f'),'sections':{k:format(v,'.8f') for k,v in sorted(sections.items())},'terms':terms})
 return out
