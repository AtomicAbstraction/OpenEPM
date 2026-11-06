#!/usr/bin/env python3
"""Publish producer-fence reopen authority only from a certified completion."""
from __future__ import annotations
import base64,json,os,stat,tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
try:from macos_pilot_secure_activation import canonical,digest,verify_journal
except ModuleNotFoundError:
 from scripts.macos_pilot_secure_activation import canonical,digest,verify_journal

class ProducerReopenPublishError(RuntimeError):pass

class ProducerReopenPublisher:
 def __init__(self,root:Path,key:Ed25519PrivateKey,*,key_id:str,key_version:int,
              _test_owner_uid=None,clock=None):
  self.root=Path(root);self.key=key;self.key_id=key_id;self.key_version=key_version
  self.owner=0 if _test_owner_uid is None else _test_owner_uid
  self.clock=clock or (lambda:datetime.now(timezone.utc))
  if not isinstance(key,Ed25519PrivateKey) or not key_id or key_version<1 \
     or not self.root.is_absolute() or self.root.is_symlink() \
     or not self.root.is_dir() or self.root.stat().st_uid!=self.owner \
     or stat.S_IMODE(self.root.stat().st_mode)!=0o700:
   raise ProducerReopenPublishError('producer reopen publisher is unsafe')

 def publish(self,*,kind:str,manifest:dict,contract:dict,journal:dict,
             pointer:dict,trust:dict)->dict:
  modern=contract.get('format')=='openepm-macos-pilot-activation-execution-contract-v3'
  slot,state,command,prior=((('blue','publishing-rollback','certify-rollback','rolled-back')
      if kind=='rollback' else ('green','publishing-active','publish-active','finalized')
      if kind=='finalize' else (None,None,None,None)) if modern else
      (('blue','rolled-back','certify-rollback','rolled-back') if kind=='rollback'
       else ('green','active','finalize','active') if kind=='finalize'
       else (None,None,None,None)))
  body_j={k:v for k,v in journal.items() if k!='snapshotSha256'}
  try:head=verify_journal(journal.get('records'),journal.get('planSha256'),
      journal.get('activationId'),journal.get('executionContractSha256'))
  except Exception as error:raise ProducerReopenPublishError(
      'certified journal is invalid') from error
  if slot is None or journal.get('snapshotSha256')!=digest(body_j) \
     or journal.get('activationId')!=contract.get('activationId') \
     or journal.get('executionContractSha256')!=contract.get('executionContractSha256') \
     or head is None or head.get('eventKind')!=('intent' if modern else 'completion') \
     or (head.get('command'),head.get('state'))!=(command,state):
   raise ProducerReopenPublishError('certified completion is absent')
  predecessor=journal.get('records',[])[-2] if len(journal.get('records',[]))>1 else None
  if modern and (not isinstance(predecessor,dict) or predecessor.get('eventKind')!='completion' \
     or predecessor.get('state')!=prior):
   raise ProducerReopenPublishError('certified completion is absent')
  pointer_body={k:v for k,v in pointer.items() if k!='pointerSha256'}
  pointer_state=('rolling-back' if modern and kind=='rollback' else state)
  pointer_event=(predecessor.get('previousSha256')
                 if modern and kind=='rollback' else head.get('recordSha256'))
  if pointer.get('pointerSha256')!=digest(pointer_body) \
     or pointer.get('activationEventSha256')!=pointer_event \
     or pointer.get('executionContractSha256')!=contract.get('executionContractSha256') \
     or (pointer.get('slot'),pointer.get('authorityState'),pointer.get('writesAdmitted')) \
        !=(slot,pointer_state,False if modern else True):
   raise ProducerReopenPublishError('certified pointer is absent')
  evidence=manifest.get('evidenceSha256')
  if not isinstance(evidence,str) or len(evidence)!=64:
   raise ProducerReopenPublishError('producer fence manifest is invalid')
  now=self.clock().astimezone(timezone.utc).replace(microsecond=0);expires=now+timedelta(seconds=60)
  body={'format':'openepm-macos-pilot-producer-reopen-authority-v1',
   'activationId':contract['activationId'],'executionContractSha256':contract['executionContractSha256'],
   'kind':kind,'slot':slot,'producerFenceEvidenceSha256':evidence,
   'journalHeadEventSha256':head['recordSha256'],'journalGeneration':head['ordinal'],
   'authorityState':state,'observedAtUtc':now.strftime('%Y-%m-%dT%H:%M:%SZ'),
   'expiresAtUtc':expires.strftime('%Y-%m-%dT%H:%M:%SZ'),
   'executorKeyId':self.key_id,'executorKeyVersion':self.key_version}
  if modern:body.update(priorCompletionEventSha256=predecessor['recordSha256'],
   operationKey=head['recordSha256'],stagedPointerSha256=pointer['pointerSha256'])
  signed={**body,'authoritySha256':digest(body)}
  authority={**signed,'signature':{'algorithm':'Ed25519','keyId':self.key_id,
   'valueBase64':base64.b64encode(self.key.sign(canonical(signed))).decode()}}
  # Trust, journal and pointer precede authority; readers never observe a new
  # authority with stale dependencies.
  for name,value in (('executor-trust-snapshot.json',trust),
                     ('activation-journal-snapshot.json',journal),
                     ('active-slot.json',pointer),
                     ('producer-reopen-authority.json',authority)):
   self._atomic(name,value)
  return authority

 def _atomic(self,name,value):
  payload=canonical(value);fd,path=tempfile.mkstemp(prefix='.'+name+'.',dir=self.root)
  temporary=Path(path)
  try:
   os.fchmod(fd,0o400);offset=0
   while offset<len(payload):
    written=os.write(fd,payload[offset:])
    if written<1:raise OSError('producer authority write made no progress')
    offset+=written
   os.fsync(fd);os.close(fd);fd=-1;os.replace(temporary,self.root/name)
   directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(directory)
   finally:os.close(directory)
  finally:
   if fd>=0:os.close(fd)
   try:temporary.unlink()
   except FileNotFoundError:pass
