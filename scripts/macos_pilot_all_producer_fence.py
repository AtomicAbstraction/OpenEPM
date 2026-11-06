#!/usr/bin/env python3
"""Two-phase, fail-closed producer quiescence for Mac-pilot activation.

Open EPM's existing ``processing_mode`` is a *whole application* execution
gate: worker claims as well as new producers require ``Active``.  It therefore
cannot be changed before accepted work drains.  This controller encodes the
only safe contract supported by the current schema:

1. public/root admission is already closed and workers drain to zero;
2. the privileged host controller stops every producer/worker service and
   proves their database sessions are gone;
3. application states are atomically moved from Active to Maintenance;
4. the canonical all-family observer takes the final zero snapshot.

The service stop is the producer-only fence during the transition; durable
``processing_mode`` is the restart fence.  Reopening requires signed rollback
or finalize authority and the exact captured mode manifest.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from typing import Callable,Protocol

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from psycopg.rows import dict_row

from epm_core.postgres_connection import connect_postgres
from scripts.macos_pilot_active_work import ActiveWorkObserver,FAMILIES,canonical


SOURCE_FAMILIES=(
 "job","cube_aggregate_query","python_program_build","python_program_workflow",
 "application_task_flow_activity","planning_forecast_occurrence",
 "source_import_execution","python_program_occurrence",
 "fact_export_producer_request","transfer_cleanup_request",
 "layout_replacement_request","layout_replacement_activation",
 "expression_rule_sequence","full_aggregate_sequence","source_batch",
 "planning_assignment_due_occurrence","application_task_flow_occurrence",
 "application_rule_workflow","application_schedule_occurrence")

class ProducerFenceError(RuntimeError):pass

class ProducerBoundary(Protocol):
 def public_admission_closed(self,operation_key:str,contract:dict)->bool:...
 def workers_running(self)->bool:...
 def stop_all_producers(self,operation_key:str,contract:dict)->str:...
 def producer_sessions_zero(self)->bool:...
 def producers_stopped(self)->bool:...
 def start_all_producers(self,operation_key:str,contract:dict)->str:...

def digest(value:object)->str:
 return hashlib.sha256(canonical(value)).hexdigest()

def verify_inventory(value:dict)->None:
 items=value.get("universalTaskSources") if isinstance(value,dict) else None
 if not isinstance(items,list) or tuple(x.get("table") for x in items
         if isinstance(x,dict))!=SOURCE_FAMILIES:
  raise ProducerFenceError("durable producer inventory differs")
 if len(set(SOURCE_FAMILIES))!=19:
  raise ProducerFenceError("durable producer inventory is not exact")

class AllProducerFence:
 def __init__(self,admin_dsn:str,observer:ActiveWorkObserver,
              boundary:ProducerBoundary,private_key:Ed25519PrivateKey,*,
              key_id:str,timeout_seconds:float=120,poll_seconds:float=.5,
              prestate_path:Path|None=None,
              monotonic:Callable[[],float]=time.monotonic,
              sleeper:Callable[[float],None]=time.sleep):
  if not admin_dsn or not isinstance(private_key,Ed25519PrivateKey) or not key_id \
     or timeout_seconds<=0 or poll_seconds<=0:
   raise ProducerFenceError("producer fence configuration is invalid")
  self.dsn,self.observer,self.boundary=admin_dsn,observer,boundary
  self.key,self.key_id=private_key,key_id
  self.prestate_path=Path(prestate_path) if prestate_path is not None else None
  self.timeout,self.poll=timeout_seconds,poll_seconds
  self.monotonic,self.sleep=monotonic,sleeper

 def _verified_prior(self,manifest:dict,contract:dict)->list[dict]:
  signature=manifest.get('signature') if isinstance(manifest,dict) else None
  signed={k:v for k,v in manifest.items() if k!='signature'} \
      if isinstance(manifest,dict) else {}
  body={k:v for k,v in signed.items() if k!='evidenceSha256'}
  try:
   if manifest.get('format')!='openepm-macos-pilot-all-producer-fence-v1' \
      or manifest.get('activationId')!=contract.get('activationId') \
      or manifest.get('executionContractSha256')!=contract.get('executionContractSha256') \
      or manifest.get('evidenceSha256')!=digest(body) \
      or not isinstance(signature,dict) or signature.get('algorithm')!='Ed25519' \
      or signature.get('keyId')!=self.key_id:
    raise ProducerFenceError('producer fence manifest is invalid')
   self.key.public_key().verify(base64.b64decode(signature.get(
    'valueBase64',''),validate=True),canonical(signed))
  except (InvalidSignature,ValueError,TypeError) as error:
   raise ProducerFenceError('producer fence manifest is invalid') from error
  prior=manifest.get('priorProcessingModes')
  if not isinstance(prior,list):raise ProducerFenceError('producer fence modes are invalid')
  return prior

 def verify_closed(self,manifest:dict,*,contract:dict)->str:
  """Freshly prove durable Maintenance and zero work after services restart."""
  prior=self._verified_prior(manifest,contract)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   current=[dict(x) for x in db.execute('''SELECT workspace_id,application_id,
    processing_mode FROM epm.application_state ORDER BY workspace_id,application_id''').fetchall()]
  expected=[{**x,'processing_mode':'Maintenance' if x.get('processing_mode')=='Active'
             else x.get('processing_mode')} for x in prior]
  active=self.observer.observe()
  if current!=expected or set(active)!=set(FAMILIES) or any(active.values()):
   raise ProducerFenceError('live producer fence is open or drifted')
  return digest({'manifest':manifest['evidenceSha256'],'modes':current,'activeWork':active})

 def verify_open(self,manifest:dict,*,contract:dict)->str:
  """Freshly prove the signed prior processing modes were restored."""
  prior=self._verified_prior(manifest,contract)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   current=[dict(x) for x in db.execute('''SELECT workspace_id,application_id,
    processing_mode FROM epm.application_state ORDER BY workspace_id,application_id''').fetchall()]
  if current!=prior:raise ProducerFenceError('live producer fence is closed or drifted')
  return digest({'manifest':manifest['evidenceSha256'],'modes':current})

 def _drain(self)->dict[str,int]:
  deadline=self.monotonic()+self.timeout
  while True:
   if self.boundary.workers_running() is not True:
    raise ProducerFenceError("workers stopped before accepted work drained")
   counts=self.observer.observe()
   if set(counts)!=set(FAMILIES):raise ProducerFenceError("observer inventory differs")
   if all(counts[x]==0 for x in FAMILIES):return counts
   if self.monotonic()>=deadline:raise ProducerFenceError("producer drain timed out")
   self.sleep(self.poll)

 def _validate_modes(self,value:object)->list[dict]:
  if not isinstance(value,list):raise ProducerFenceError('producer prestate modes are invalid')
  expected_keys={'workspace_id','application_id','processing_mode'};seen=set()
  for item in value:
   if not isinstance(item,dict) or set(item)!=expected_keys \
      or not all(isinstance(item[x],str) and item[x] for x in expected_keys):
    raise ProducerFenceError('producer prestate modes are invalid')
   identity=(item['workspace_id'],item['application_id'])
   if identity in seen:raise ProducerFenceError('producer prestate modes are duplicated')
   seen.add(identity)
  if value!=sorted(value,key=lambda x:(x['workspace_id'],x['application_id'])):
   raise ProducerFenceError('producer prestate modes are unordered')
  return value

 def _prestate(self,prior:list[dict],operation_key:str,contract:dict)->dict:
  body={'format':'openepm-macos-pilot-producer-fence-prestate-v1',
   'activationId':contract.get('activationId'),
   'executionContractSha256':contract.get('executionContractSha256'),
   'operationKey':operation_key,'keyId':self.key_id,
   'priorProcessingModes':self._validate_modes(prior)}
  sealed={**body,'prestateSha256':digest(body)}
  return {**sealed,'signature':{'algorithm':'Ed25519','keyId':self.key_id,
   'valueBase64':base64.b64encode(self.key.sign(canonical(sealed))).decode()}}

 def _verified_prestate(self,value:object,operation_key:str,contract:dict)->dict:
  signature=value.get('signature') if isinstance(value,dict) else None
  signed={k:v for k,v in value.items() if k!='signature'} if isinstance(value,dict) else {}
  body={k:v for k,v in signed.items() if k!='prestateSha256'}
  try:
   if value.get('format')!='openepm-macos-pilot-producer-fence-prestate-v1' \
      or value.get('activationId')!=contract.get('activationId') \
      or value.get('executionContractSha256')!=contract.get('executionContractSha256') \
      or value.get('operationKey')!=operation_key or value.get('keyId')!=self.key_id \
      or value.get('prestateSha256')!=digest(body) \
      or not isinstance(signature,dict) or signature.get('algorithm')!='Ed25519' \
      or signature.get('keyId')!=self.key_id:
    raise ProducerFenceError('producer prestate is invalid')
   self.key.public_key().verify(base64.b64decode(signature.get(
    'valueBase64',''),validate=True),canonical(signed))
  except (InvalidSignature,ValueError,TypeError,AttributeError) as error:
   raise ProducerFenceError('producer prestate is invalid') from error
  self._validate_modes(value.get('priorProcessingModes'))
  return value

 def _fsync_parent(self,path:Path)->None:
  directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(directory)
  finally:os.close(directory)

 def _read_prestate_file(self,path:Path,operation_key:str,contract:dict,*,
                         links:int=1)->dict:
  descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   metadata=os.fstat(descriptor)
   if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=links \
      or metadata.st_uid!=os.geteuid() \
      or stat.S_IMODE(metadata.st_mode)!=0o400 or not 1<=metadata.st_size<=4*1024*1024:
    raise ProducerFenceError('producer prestate storage is unsafe')
   raw=os.read(descriptor,4*1024*1024+1)
  finally:os.close(descriptor)
  try:value=json.loads(raw)
  except (json.JSONDecodeError,UnicodeDecodeError) as error:
   raise ProducerFenceError('producer prestate is invalid') from error
  return self._verified_prestate(value,operation_key,contract)

 def _read_prestate(self,operation_key:str,contract:dict)->dict|None:
  path=self.prestate_path
  if path is None:raise ProducerFenceError('producer prestate path is unavailable')
  parent=path.parent;metadata=os.lstat(parent)
  if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) \
     or metadata.st_uid!=os.geteuid() or metadata.st_mode&(stat.S_IWGRP|stat.S_IWOTH):
   raise ProducerFenceError('producer prestate storage is unsafe')
  staging=path.with_name('.'+path.name+'.staging')
  target_exists=path.exists();staging_exists=staging.exists()
  if staging_exists and not target_exists:
   # A crash after the durable staging fsync but before publication is safe to
   # finish: the signed payload is already bound to this operation.
   try:self._read_prestate_file(staging,operation_key,contract)
   except ProducerFenceError:
    # Target absence proves the database mutation could not have started.
    # Only a regular, single-link, effective-owner staging object may be
    # discarded; anything else may be an attempted path substitution.
    partial=os.lstat(staging)
    if not stat.S_ISREG(partial.st_mode) or partial.st_nlink!=1 \
       or partial.st_uid!=os.geteuid() or stat.S_IMODE(partial.st_mode)!=0o400:
     raise ProducerFenceError('producer prestate staging is unsafe')
    staging.unlink();self._fsync_parent(path);return None
   try:os.link(staging,path,follow_symlinks=False)
   except FileExistsError:pass
   self._fsync_parent(path);target_exists=True
  if staging.exists() and target_exists:
   left=os.lstat(staging);right=os.lstat(path)
   if not stat.S_ISREG(left.st_mode) or not stat.S_ISREG(right.st_mode) \
      or (left.st_dev,left.st_ino)!=(right.st_dev,right.st_ino) \
      or left.st_nlink!=2 or left.st_uid!=os.geteuid() \
      or stat.S_IMODE(left.st_mode)!=0o400:
    raise ProducerFenceError('producer prestate publication is inconsistent')
   # This is the exact crash-after-link state.  Removing only the fixed
   # staging name restores the target's required single-link invariant.
   staging.unlink();self._fsync_parent(path)
  if not path.exists():return None
  return self._read_prestate_file(path,operation_key,contract)

 def _persist_prestate(self,value:dict)->dict:
  path=self.prestate_path
  if path is None:raise ProducerFenceError('producer prestate path is unavailable')
  existing=self._read_prestate(value['operationKey'],value)
  if existing is not None:
   if existing!=value:raise ProducerFenceError('producer prestate replay differs')
   return existing
  staging=path.with_name('.'+path.name+'.staging');payload=canonical(value)
  descriptor=os.open(staging,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
  ready=False
  try:
   os.fchmod(descriptor,0o400);offset=0
   while offset<len(payload):
    written=os.write(descriptor,payload[offset:])
    if written<1:raise ProducerFenceError('producer prestate write made no progress')
    offset+=written
   os.fsync(descriptor);ready=True
  finally:
   os.close(descriptor)
   if not ready:
    try:staging.unlink()
    except FileNotFoundError:pass
  try:os.link(staging,path,follow_symlinks=False)
  except FileExistsError:pass
  self._fsync_parent(path)
  # Use the same recovery path for normal completion and host-crash replay.
  published=self._read_prestate(value['operationKey'],value)
  if published!=value:raise ProducerFenceError('producer prestate replay differs')
  return published

 def _maintenance(self,operation_key:str,contract:dict)->tuple[list[dict],str]:
  prestate=self._read_prestate(operation_key,contract)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    db.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
    db.execute("SELECT pg_advisory_xact_lock(%s)",(0x45504D5052464E,))
    current=self._validate_modes([dict(x) for x in db.execute('''SELECT
      workspace_id,application_id,processing_mode FROM epm.application_state
      ORDER BY workspace_id,application_id FOR UPDATE''').fetchall()])
    if prestate is None:
     prestate=self._persist_prestate(self._prestate(current,operation_key,contract))
    prior=prestate['priorProcessingModes']
    expected=[{**x,'processing_mode':'Maintenance' if x['processing_mode']=='Active'
               else x['processing_mode']} for x in prior]
    if current==prior:
     db.execute("UPDATE epm.application_state SET processing_mode='Maintenance' "
                "WHERE processing_mode='Active'")
    elif current!=expected:
     raise ProducerFenceError('durable producer fence state drifted from prestate')
  return prior,prestate['prestateSha256']

 def close(self,*,operation_key:str,contract:dict,journal_head:str,
           journal_generation:int,observed_at_utc:str)->dict:
  if self.boundary.public_admission_closed(operation_key,contract) is not True:
   raise ProducerFenceError("public admission must be closed first")
  drained=self._drain()
  stop=self.boundary.stop_all_producers(operation_key,contract)
  if not isinstance(stop,str) or len(stop)!=64 \
     or self.boundary.producers_stopped() is not True \
     or self.boundary.producer_sessions_zero() is not True:
   raise ProducerFenceError("producer service stop is not proven")
  prior,prestate_sha256=self._maintenance(operation_key,contract)
  if self.boundary.producers_stopped() is not True \
     or self.boundary.producer_sessions_zero() is not True:
   raise ProducerFenceError("producer stop changed during durable close")
  final=self.observer.observe()
  if any(final.values()):raise ProducerFenceError("work appeared after producer stop")
  body={"format":"openepm-macos-pilot-all-producer-fence-v1",
   "activationId":contract["activationId"],
   "executionContractSha256":contract["executionContractSha256"],
   "intentEventSha256":operation_key,"journalHeadEventSha256":journal_head,
   "journalGeneration":journal_generation,"observedAtUtc":observed_at_utc,
   "keyId":self.key_id,"sourceFamilies":list(SOURCE_FAMILIES),
   "serviceStopEvidenceSha256":stop,"drainedActiveWork":drained,
   "finalActiveWork":final,"priorProcessingModes":prior,
   "producerFencePrestateSha256":prestate_sha256,
   "producerServicesStopped":True,"producerSessionsZero":True}
  sealed={**body,"evidenceSha256":digest(body)}
  return {**sealed,"signature":{"algorithm":"Ed25519","keyId":self.key_id,
   "valueBase64":base64.b64encode(self.key.sign(canonical(sealed))).decode()}}

 def close_after_stopped(self,*,operation_key:str,contract:dict,journal_head:str,
                         journal_generation:int,observed_at_utc:str,
                         drained_active_work:dict)->dict:
  """Close durable producer admission after an independently certified drain/stop."""
  if self.boundary.public_admission_closed(operation_key,contract) is not True \
     or self.boundary.producers_stopped() is not True \
     or self.boundary.producer_sessions_zero() is not True \
     or set(drained_active_work)!=set(FAMILIES) or any(drained_active_work.values()):
   raise ProducerFenceError("drained stopped producer boundary is not proven")
  prior,prestate_sha256=self._maintenance(operation_key,contract)
  if self.boundary.producers_stopped() is not True \
     or self.boundary.producer_sessions_zero() is not True:
   raise ProducerFenceError("producer stop changed during durable close")
  final=self.observer.observe()
  if set(final)!=set(FAMILIES) or any(final.values()):
   raise ProducerFenceError("work appeared after producer stop")
  body={"format":"openepm-macos-pilot-all-producer-fence-v1",
   "activationId":contract["activationId"],
   "executionContractSha256":contract["executionContractSha256"],
   "intentEventSha256":operation_key,"journalHeadEventSha256":journal_head,
   "journalGeneration":journal_generation,"observedAtUtc":observed_at_utc,
   "keyId":self.key_id,"sourceFamilies":list(SOURCE_FAMILIES),
   "serviceStopEvidenceSha256":digest({"stopped":True,"operationKey":operation_key}),
   "drainedActiveWork":drained_active_work,"finalActiveWork":final,
   "priorProcessingModes":prior,"producerFencePrestateSha256":prestate_sha256,
   "producerServicesStopped":True,
   "producerSessionsZero":True}
  sealed={**body,"evidenceSha256":digest(body)}
  return {**sealed,"signature":{"algorithm":"Ed25519","keyId":self.key_id,
   "valueBase64":base64.b64encode(self.key.sign(canonical(sealed))).decode()}}

 def reopen_modes(self,manifest:dict,*,operation_key:str,contract:dict,
                  authority:dict)->str:
  """Restore only durable producer admission while services remain stopped.

  Activation publication must keep service start as a separately observed host
  effect.  Returning a digest of the restored mode projection lets the caller
  durably reconcile a lost acknowledgement without implicitly starting any
  producer process.
  """
  signature=authority.get("signature") if isinstance(authority,dict) else None
  body={key:value for key,value in authority.items() if key!="signature"} \
       if isinstance(authority,dict) else {}
  sealed={key:value for key,value in body.items() if key!="authoritySha256"}
  try:
   if not isinstance(signature,dict) or signature.get("algorithm")!="Ed25519" \
      or signature.get("keyId")!=self.key_id \
      or body.get("authoritySha256")!=digest(sealed):
    raise ProducerFenceError("signed reopen authority is invalid")
   self.key.public_key().verify(base64.b64decode(signature.get(
    "valueBase64",""),validate=True),canonical(body))
  except (InvalidSignature,ValueError,TypeError) as error:
   raise ProducerFenceError("signed reopen authority is invalid") from error
  if authority.get("kind") not in ("rollback","finalize") \
     or authority.get("activationId")!=contract.get("activationId") \
     or authority.get("executionContractSha256")!=contract.get(
      "executionContractSha256") \
     or authority.get("producerFenceEvidenceSha256")!=manifest.get(
      "evidenceSha256") \
     or authority.get("operationKey",operation_key)!=operation_key:
   raise ProducerFenceError("signed reopen authority differs")
  if self.boundary.producers_stopped() is not True \
     or self.boundary.producer_sessions_zero() is not True:
   raise ProducerFenceError("producer services must remain stopped for reopen")
  prior=manifest.get("priorProcessingModes")
  if not isinstance(prior,list):raise ProducerFenceError("mode manifest is invalid")
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    db.execute("SELECT pg_advisory_xact_lock(%s)",(0x45504D5052464E,))
    current=[dict(x) for x in db.execute('''SELECT workspace_id,application_id,
      processing_mode FROM epm.application_state ORDER BY workspace_id,
      application_id FOR UPDATE''').fetchall()]
    expected=[{**x,"processing_mode":"Maintenance" if x["processing_mode"]=="Active"
              else x["processing_mode"]} for x in prior]
    if current not in (expected,prior):
     raise ProducerFenceError("durable fence state drifted")
    if current==expected:
     for item in prior:
      db.execute('''UPDATE epm.application_state SET processing_mode=%s
        WHERE workspace_id=%s AND application_id=%s''',(
        item["processing_mode"],item["workspace_id"],item["application_id"]))
  restored=[]
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   restored=[dict(x) for x in db.execute('''SELECT workspace_id,application_id,
     processing_mode FROM epm.application_state ORDER BY workspace_id,
     application_id''').fetchall()]
  if restored!=prior:
   raise ProducerFenceError("durable producer modes were not restored")
  return digest({"operationKey":operation_key,"restoredModes":restored,
                 "authoritySha256":authority["authoritySha256"]})

 def reopen(self,manifest:dict,*,operation_key:str,contract:dict,
            authority:dict)->str:
  self.reopen_modes(manifest,operation_key=operation_key,contract=contract,
                    authority=authority)
  started=self.boundary.start_all_producers(operation_key,contract)
  if not isinstance(started,str) or len(started)!=64:
   raise ProducerFenceError("producer restart evidence is invalid")
  return started
