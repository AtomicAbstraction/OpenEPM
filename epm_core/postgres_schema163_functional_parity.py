"""Exact two-database functional parity contract for schema-163 candidates.

Collectors must exercise disposable databases through public/fixed-core paths.
This module compares their normalized certificates; it never provisions data,
repairs migration history, constructs a baseline, or authorizes activation.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any,Callable


FORMAT='openepm-schema163-functional-parity-certificate-v1'
DOMAINS=('aggregateTechnicalJob','sourceImportExport','ctaTypedEffects',
 'forecastSchedule','pythonArtifactPaging','inventoryUnrealized',
 'recursiveRollup')
_HEX=re.compile(r'[0-9a-f]{64}')


def _fail(code:str)->None:raise ValueError(code)
def _digest(value:Any)->str:return hashlib.sha256(json.dumps(
 value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
def _exact(value:Any,expected:Any,code:str)->None:
 if value!=expected:_fail(code)
def _hex(value:Any,code:str)->None:
 if not isinstance(value,str) or not _HEX.fullmatch(value):_fail(code)


def validate_certificate(value:dict[str,Any])->dict[str,Any]:
 required={'format','activationAuthorized','databaseIdentity','sourceCommit',
  'schemaFingerprint','postgresProfile','extensionProfile','domains'}
 if not isinstance(value,dict) or set(value)!=required:
  _fail('SCHEMA163_FUNCTIONAL_CERTIFICATE_SHAPE_INVALID')
 if value['format']!=FORMAT or value['activationAuthorized'] is not False:
  _fail('SCHEMA163_FUNCTIONAL_CERTIFICATE_BOUNDARY_INVALID')
 for key in ('databaseIdentity','sourceCommit','postgresProfile','extensionProfile'):
  if not isinstance(value[key],str) or not value[key]:
   _fail('SCHEMA163_FUNCTIONAL_CERTIFICATE_IDENTITY_INVALID')
 _hex(value['databaseIdentity'],'SCHEMA163_FUNCTIONAL_DATABASE_IDENTITY_INVALID')
 if not re.fullmatch(r'[0-9a-f]{40,64}',value['sourceCommit']):
  _fail('SCHEMA163_FUNCTIONAL_SOURCE_IDENTITY_INVALID')
 try:extensions=json.loads(value['extensionProfile'])
 except json.JSONDecodeError:_fail('SCHEMA163_FUNCTIONAL_EXTENSION_PROFILE_INVALID')
 if not isinstance(extensions,list):_fail('SCHEMA163_FUNCTIONAL_EXTENSION_PROFILE_INVALID')
 _hex(value['schemaFingerprint'],'SCHEMA163_FUNCTIONAL_FINGERPRINT_INVALID')
 domains=value['domains']
 if not isinstance(domains,dict) or set(domains)!=set(DOMAINS):
  _fail('SCHEMA163_FUNCTIONAL_DOMAINS_INVALID')

 aggregate=domains['aggregateTechnicalJob']
 _exact(set(aggregate),{'sum','countPresent','zeroCounted','missingExcluded',
  'businessRevisionDelta','stablePageDigest','cancelledResultAbsent',
  'outsiderDenied'},'SCHEMA163_AGGREGATE_SHAPE_INVALID')
 _exact({k:aggregate[k] for k in ('sum','countPresent','zeroCounted',
  'missingExcluded','businessRevisionDelta','cancelledResultAbsent','outsiderDenied')},
  {'sum':'3.00000000','countPresent':'2','zeroCounted':True,
   'missingExcluded':True,'businessRevisionDelta':0,
   'cancelledResultAbsent':True,'outsiderDenied':True},
  'SCHEMA163_AGGREGATE_INVARIANT_FAILED')
 _hex(aggregate['stablePageDigest'],'SCHEMA163_AGGREGATE_DIGEST_INVALID')

 transfer=domains['sourceImportExport']
 _exact(set(transfer),{'numeric','text','detailTotal','zeroPresent','missingAbsent',
  'replaySameReceipt','snapshotStable','resumeNoDuplicate','finalFenceRejectsStale',
  'manifestDigest'},'SCHEMA163_TRANSFER_SHAPE_INVALID')
 _exact({k:transfer[k] for k in transfer if k!='manifestDigest'},
  {'numeric':'7.50000000','text':'','detailTotal':'7.50000000',
   'zeroPresent':True,'missingAbsent':True,'replaySameReceipt':True,
   'snapshotStable':True,'resumeNoDuplicate':True,'finalFenceRejectsStale':True},
  'SCHEMA163_TRANSFER_INVARIANT_FAILED')
 _hex(transfer['manifestDigest'],'SCHEMA163_TRANSFER_DIGEST_INVALID')

 cta=domains['ctaTypedEffects']
 _exact(cta,{'compilerVersion':'cta-bridge-v3-typed-unit',
  'typedEffectCount':2,'balance':'0.00000000','untypedJournalAbsent':True,
  'lineageComplete':True,'staleSourceRejected':True,'readerDenied':True},
  'SCHEMA163_CTA_INVARIANT_FAILED')

 forecast=domains['forecastSchedule']
 _exact(set(forecast),{'occurrenceCount','duplicateSuppressed','restartResumed',
  'delegationRevocationDenied','progressAdvancedOnce','occurrenceDigest'},
  'SCHEMA163_FORECAST_SHAPE_INVALID')
 _exact({k:forecast[k] for k in forecast if k!='occurrenceDigest'},
  {'occurrenceCount':1,'duplicateSuppressed':True,'restartResumed':True,
   'delegationRevocationDenied':True,'progressAdvancedOnce':True},
  'SCHEMA163_FORECAST_INVARIANT_FAILED')
 _hex(forecast['occurrenceDigest'],'SCHEMA163_FORECAST_DIGEST_INVALID')

 python=domains['pythonArtifactPaging']
 _exact(set(python),{'sections','pageReplayStable','sourceDigestBound',
  'restartIdentical','outsiderDenied','cancelledBuildNoArtifact','artifactDigest'},
  'SCHEMA163_PYTHON_ARTIFACT_SHAPE_INVALID')
 _exact({k:python[k] for k in python if k!='artifactDigest'},
  {'sections':['Plan','SourceMap','BuildLog'],'pageReplayStable':True,
   'sourceDigestBound':True,'restartIdentical':True,'outsiderDenied':True,
   'cancelledBuildNoArtifact':True},'SCHEMA163_PYTHON_ARTIFACT_INVARIANT_FAILED')
 _hex(python['artifactDigest'],'SCHEMA163_PYTHON_ARTIFACT_DIGEST_INVALID')

 inventory=domains['inventoryUnrealized']
 _exact(inventory,{'roles':['Opening','Creation','Release','Closing'],
  'rowCount':4,'balance':'0.00000000','legacyLineForbidden':True,
  'sourceLineageComplete':True,'scheduleVersionPinned':True,
  'stalePointerRejected':True},'SCHEMA163_INVENTORY_INVARIANT_FAILED')

 rollup=domains['recursiveRollup']
 _exact(set(rollup),{'sharedLeafContributionCount','pathCount','sum',
  'zeroCounted','missingExcluded','lineagePathDistinct','stalePathRejected',
  'lineageDigest'},'SCHEMA163_ROLLUP_SHAPE_INVALID')
 _exact({k:rollup[k] for k in rollup if k!='lineageDigest'},
  {'sharedLeafContributionCount':2,'pathCount':2,'sum':'6.00000000',
   'zeroCounted':True,'missingExcluded':True,'lineagePathDistinct':True,
   'stalePathRejected':True},'SCHEMA163_ROLLUP_INVARIANT_FAILED')
 _hex(rollup['lineageDigest'],'SCHEMA163_ROLLUP_DIGEST_INVALID')
 return value


def verify_pair(left:dict[str,Any],right:dict[str,Any])->dict[str,Any]:
 left=validate_certificate(left);right=validate_certificate(right)
 if left['databaseIdentity']==right['databaseIdentity']:
  _fail('SCHEMA163_FUNCTIONAL_DATABASES_NOT_INDEPENDENT')
 for key in ('sourceCommit','schemaFingerprint','postgresProfile','extensionProfile'):
  if left[key]!=right[key]:_fail('SCHEMA163_FUNCTIONAL_ENVIRONMENT_MISMATCH')
 if left['domains']!=right['domains']:
  _fail('SCHEMA163_FUNCTIONAL_PARITY_MISMATCH')
 digest=_digest(left['domains'])
 return {'format':'openepm-schema163-functional-parity-result-v1',
  'activationAuthorized':False,'equal':True,'sourceCommit':left['sourceCommit'],
  'schemaFingerprint':left['schemaFingerprint'],
  'postgresProfile':left['postgresProfile'],
  'extensionProfile':left['extensionProfile'],'domainDigest':digest,
  'domains':list(DOMAINS),'databaseCount':2}


def qualify_disposable_pair(left_dsn:str,right_dsn:str,
 collector:Callable[[str],dict[str,Any]])->dict[str,Any]:
 """Run one approved public/fixed-core collector against two owned DSNs."""
 if (not isinstance(left_dsn,str) or not left_dsn or not isinstance(right_dsn,str)
   or not right_dsn or left_dsn==right_dsn):
  _fail('SCHEMA163_FUNCTIONAL_DSN_PAIR_INVALID')
 return verify_pair(collector(left_dsn),collector(right_dsn))
