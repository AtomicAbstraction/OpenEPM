#!/usr/bin/env python3
"""Authenticated fixed-method IPC between non-root activation core and root authority."""
from __future__ import annotations
import base64,fcntl,hashlib,json,os,re,socket,stat,struct,sys,threading,uuid
from datetime import datetime,timezone
from pathlib import Path
from typing import Callable
if __package__:
 from .execute_macos_pilot_activation import PhaseResult
 from .macos_pilot_secure_activation import canonical
 from .macos_pilot_secure_activation import verify_journal
else:
 from execute_macos_pilot_activation import PhaseResult
 from macos_pilot_secure_activation import canonical
 from macos_pilot_secure_activation import verify_journal

MAX_MESSAGE=2*1024*1024
METHODS=frozenset({"execute-or-reconcile","publish-admission-open"})
class ActivationIpcError(RuntimeError):pass
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()

def _peer_uid(connection):
 getter=getattr(connection,"getpeereid",None)
 if getter is not None:return int(getter()[0])
 if hasattr(socket,"SO_PEERCRED"):
  return int(struct.unpack("3i",connection.getsockopt(socket.SOL_SOCKET,
   socket.SO_PEERCRED,12))[1])
 raise ActivationIpcError("peer credentials are unavailable")

def _send(connection,value):
 payload=canonical(value)
 if not payload or len(payload)>MAX_MESSAGE:raise ActivationIpcError(
  "activation IPC message is oversized")
 connection.sendall(struct.pack("!I",len(payload))+payload)

def _receive(connection):
 header=b""
 while len(header)<4:
  chunk=connection.recv(4-len(header))
  if not chunk:raise ActivationIpcError("activation IPC message ended early")
  header+=chunk
 size=struct.unpack("!I",header)[0]
 if size<2 or size>MAX_MESSAGE:raise ActivationIpcError(
  "activation IPC message size is invalid")
 chunks=[]
 while size:
  chunk=connection.recv(min(65536,size))
  if not chunk:raise ActivationIpcError("activation IPC message ended early")
  chunks.append(chunk);size-=len(chunk)
 raw=b"".join(chunks)
 try:value=json.loads(raw.decode())
 except (UnicodeError,json.JSONDecodeError) as error:raise ActivationIpcError(
  "activation IPC message is invalid") from error
 if not isinstance(value,dict) or canonical(value)!=raw:raise ActivationIpcError(
  "activation IPC message is not canonical")
 return value

def _validate_request(value,expected_parent):
 if not isinstance(value,dict) or set(value)!={"format","method","activationId",
  "planSha256","executionContractSha256","parentAssemblySha256","operationKey",
  "payload","requestSha256"}:
  raise ActivationIpcError("activation IPC request shape differs")
 body={k:v for k,v in value.items() if k!="requestSha256"}
 method=value.get("method");payload=value.get("payload")
 contract=payload.get("contract") if isinstance(payload,dict) else None
 prepare=method=="execute-or-reconcile" and isinstance(payload,dict) \
  and payload.get("command")=="prepare"
 if value.get("format")!="openepm-macos-pilot-authority-request-v1" or method not in METHODS \
    or value.get("requestSha256")!=digest(body) \
    or value.get("parentAssemblySha256")!=expected_parent \
    or value.get("operationKey")!=payload.get("operationKey"):
  raise ActivationIpcError("activation IPC request binding differs")
 if prepare:
  intent=payload.get("context",{}).get("intent")
  if contract!={} or not isinstance(intent,dict) \
     or value.get("activationId")!=intent.get("activationId") \
     or value.get("planSha256")!=intent.get("planSha256") \
     or value.get("executionContractSha256") is not None:
   raise ActivationIpcError("activation prepare bootstrap binding differs")
 elif not isinstance(contract,dict) \
    or value.get("activationId")!=contract.get("activationId") \
    or value.get("planSha256")!=contract.get("dryPlanSha256") \
    or value.get("executionContractSha256")!=contract.get("executionContractSha256"):
  raise ActivationIpcError("activation IPC contract binding differs")
 if method=="execute-or-reconcile":
  if set(payload)!={"command","context","contract","operationKey"} \
     or not isinstance(payload.get("context"),dict) \
     or payload["context"].get("operationKey")!=value["operationKey"] \
     or payload["context"].get("contract")!=contract:
   raise ActivationIpcError("activation execution request differs")
 else:
  modern=isinstance(contract,dict) and contract.get("format","").endswith("-v3")
  expected=({"phase","contract","operationKey","completion","executorEvidence"}
            if modern else {"phase","contract","operationKey"})
  if set(payload)!=expected or modern and (
      not isinstance(payload.get("completion"),dict) \
      or payload["completion"].get("recordSha256")!=value["operationKey"]):
   raise ActivationIpcError("activation publication request differs")
 return method,payload

class ActivationAuthorityServer:
 """Root endpoint with peer-UID admission and durable replay records."""
 def __init__(self,socket_path:Path,attempts_root:Path,*,service_uid:int,service_gid:int,adapter,
              admission_publisher,parent_assembly_sha256:str,
              trust_registry=None,executor_key_id=None,executor_key_version=None,
              executor_evidence_root:Path|None=None,
              producer_reopen_publisher=None,producer_manifest_provider=None,
              producer_trust_value=None,
              _qualification_fault_hook=None,
              _test_owner_uid=None,_test_effective_uid=None,_test_now_utc=None,
              peer_uid:Callable=_peer_uid):
  self.socket_path=Path(socket_path);self.root=Path(attempts_root)
  self.service_uid=service_uid;self.service_gid=service_gid
  self.adapter=adapter;self.publisher=admission_publisher;self.listener=None
  self.parent_assembly_sha256=parent_assembly_sha256
  self.trust=trust_registry;self.executor_key_id=executor_key_id
  self.executor_key_version=executor_key_version
  self.evidence_root=Path(executor_evidence_root) if executor_evidence_root else None
  self.producer_reopen_publisher=producer_reopen_publisher
  self.producer_manifest_provider=producer_manifest_provider
  self.producer_trust_value=producer_trust_value
  if (_test_now_utc is not None and (_test_owner_uid is None
          or not isinstance(_test_now_utc,str)
          or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                          _test_now_utc) is None)):
   raise ActivationIpcError("test clock is invalid")
  self._test_now_utc=_test_now_utc
  if _qualification_fault_hook is not None and not callable(
      _qualification_fault_hook):
   raise ActivationIpcError("qualification fault hook is invalid")
  self.qualification_fault_hook=_qualification_fault_hook
  self.peer_uid=peer_uid;owner=0 if _test_owner_uid is None else _test_owner_uid
  effective=os.geteuid() if _test_effective_uid is None else _test_effective_uid
  if effective!=0:raise ActivationIpcError(
   "activation authority requires root")
  if not isinstance(service_uid,int) or isinstance(service_uid,bool) or service_uid<1 \
     or not isinstance(service_gid,int) or isinstance(service_gid,bool) or service_gid<0 \
     or not isinstance(parent_assembly_sha256,str) \
     or len(parent_assembly_sha256)!=64 \
     or not hasattr(adapter,"execute_or_reconcile") or not hasattr(
      admission_publisher,"publish"):
   raise ActivationIpcError("activation authority dependency is invalid")
  for root,mode in ((self.root,0o700),(self.socket_path.parent,0o750)):
   if not root.is_absolute() or root.is_symlink() or not root.is_dir() \
      or root.stat().st_uid!=owner or stat.S_IMODE(root.stat().st_mode)!=mode:
    raise ActivationIpcError("activation authority directory is unsafe")
  self.owner=owner;self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  # flock provides the durable cross-process exclusion boundary.  On macOS its
  # ownership semantics must not be used as a same-process thread mutex, so
  # serialize local callers independently before acquiring the file lock.
  self._handle_lock=threading.Lock()
  self.evidence_fd=None
  if self.evidence_root is not None:
   if self.trust is None or not isinstance(executor_key_id,str) \
      or not isinstance(executor_key_version,int) or self.evidence_root.is_symlink() \
      or not self.evidence_root.is_dir() or self.evidence_root.stat().st_uid!=owner \
      or stat.S_IMODE(self.evidence_root.stat().st_mode)!=0o700:
    raise ActivationIpcError("executor evidence authority is invalid")
   self.evidence_fd=os.open(self.evidence_root,
    os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  producer_values=(producer_reopen_publisher,producer_manifest_provider,
                   producer_trust_value)
  if any(item is not None for item in producer_values) and not (
      hasattr(producer_reopen_publisher,"publish") and
      hasattr(producer_manifest_provider,"current") and
      isinstance(producer_trust_value,dict)):
   raise ActivationIpcError("producer reopen authority dependency is invalid")
 def _qualification_fault(self,seam):
  allowed={"publish-active-producer-authority-persisted",
   "publish-active-response-ready","certify-rollback-producer-authority-persisted",
   "certify-rollback-response-ready"}
  if seam not in allowed:raise ActivationIpcError(
   "qualification fault seam is invalid")
  if self.qualification_fault_hook is not None:self.qualification_fault_hook(seam)
 def _stage_executor_evidence(self,payload):
  if self.evidence_fd is None:return None
  value=payload.get("context",{}).get("executorEvidence",
                                     payload.get("executorEvidence"))
  signature=value.get("signature") if isinstance(value,dict) else None
  signed={k:v for k,v in value.items() if k!="signature"} if isinstance(value,dict) else {}
  journal=value.get("journal") if isinstance(value,dict) else None
  context=payload.get("context",{})
  intent=context.get("intent") or context.get("completion") \
   or payload.get("completion") or {}
  base_required={"format","parentAssemblySha256","activationId","planSha256",
   "executionContractSha256","operationKey","journal","executorKeyId",
   "executorKeyVersion","evidenceSha256","signature"}
  version=value.get("format") if isinstance(value,dict) else None
  pointer_evidence=version=="openepm-macos-pilot-executor-journal-evidence-v2"
  authority_pointer_evidence=version== \
   "openepm-macos-pilot-executor-journal-evidence-v3"
  required=(base_required|{"stagedPointer","stagedPointerSha256"}
            if pointer_evidence else base_required|{"authorityPointerPurpose",
             "authorityPointer","authorityPointerSha256"}
            if authority_pointer_evidence else base_required)
  if not isinstance(value,dict) or set(value)!=required \
     or version not in ("openepm-macos-pilot-executor-journal-evidence-v1",
                        "openepm-macos-pilot-executor-journal-evidence-v2",
                        "openepm-macos-pilot-executor-journal-evidence-v3") \
     or value.get("parentAssemblySha256")!=self.parent_assembly_sha256 \
     or value.get("activationId")!=intent.get("activationId") \
     or value.get("planSha256")!=intent.get("planSha256") \
     or value.get("operationKey")!=payload.get("operationKey") \
     or value.get("operationKey")!=intent.get("recordSha256") \
     or value.get("executorKeyId")!=self.executor_key_id \
     or value.get("executorKeyVersion")!=self.executor_key_version \
     or value.get("evidenceSha256")!=digest({k:v for k,v in signed.items()
      if k!="evidenceSha256"}) or not isinstance(signature,dict) \
     or signature.get("algorithm")!="Ed25519" \
     or signature.get("keyId")!=self.executor_key_id:
   raise ActivationIpcError("executor journal evidence binding differs")
  contract=payload.get("contract",{})
  expected_contract=contract.get("executionContractSha256") if contract else None
  if value.get("executionContractSha256")!=expected_contract \
     or not isinstance(journal,dict) or journal.get("snapshotSha256")!=digest({
      k:v for k,v in journal.items() if k!="snapshotSha256"}) \
     or journal.get("activationId")!=value["activationId"] \
     or journal.get("planSha256")!=value["planSha256"] \
     or journal.get("executionContractSha256")!=expected_contract:
   raise ActivationIpcError("executor journal snapshot differs")
  try:
   head=verify_journal(journal.get("records"),value["planSha256"],
    value["activationId"],expected_contract)
   if expected_contract is not None:self.trust.require_contract(expected_contract)
   now=self._test_now_utc or datetime.now(timezone.utc).strftime(
    "%Y-%m-%dT%H:%M:%SZ")
   key=self.trust.verifier_public_key_at(self.executor_key_id,role="executor",
    version=self.executor_key_version,now_utc=now)
   key.verify(base64.b64decode(signature.get("valueBase64"),validate=True),canonical(signed))
  except Exception as error:raise ActivationIpcError(
   "executor journal evidence signature is invalid") from error
  if not isinstance(head,dict) or head.get("recordSha256")!=value["operationKey"]:
   raise ActivationIpcError("executor journal evidence is stale")
  if pointer_evidence:
   self._validate_staged_pointer(value,contract,journal,head)
  if authority_pointer_evidence:
   self._validate_authority_pointer(value,contract,journal,head)
  staged=dict(journal)
  if expected_contract is None:
   staged["prepareBootstrap"]={"parentAssemblySha256":self.parent_assembly_sha256,
    "activationId":value["activationId"],"planSha256":value["planSha256"],
    "operationKey":value["operationKey"],
    "executorEvidenceSha256":value["evidenceSha256"]}
   staged["snapshotSha256"]=digest({k:v for k,v in staged.items()
    if k!="snapshotSha256"})
  raw=canonical(staged);temporary=f".journal.{uuid.uuid4().hex}.tmp"
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,
   dir_fd=self.evidence_fd)
  try:os.write(fd,raw);os.fchmod(fd,0o400);os.fsync(fd)
  finally:os.close(fd)
  os.rename(temporary,"activation-journal-snapshot.json",src_dir_fd=self.evidence_fd,
   dst_dir_fd=self.evidence_fd);os.fsync(self.evidence_fd)
  if pointer_evidence:self._persist_staged_pointer(value["stagedPointer"])
  if authority_pointer_evidence:self._persist_authority_pointer(
   value["authorityPointer"])
  return {"version":version,"journal":staged,
   "authorityPointer":value.get("authorityPointer"),
   "authorityPointerPurpose":value.get("authorityPointerPurpose")}
 def _validate_staged_pointer(self,value,contract,journal,head):
  pointer=value.get("stagedPointer");records=journal.get("records")
  required={"format","activationId","generation","slot","authorityState",
   "authorityPredecessorSha256","project","applicationImage","databaseImage",
   "databaseVolume","databaseVolumeId","schema","services","networks",
   "businessDataDumpFingerprintSha256","bindingSha256",
   "executionContractSha256","activationEventSha256","writesAdmitted",
   "publicIngressPermitted","pointerSha256"}
  candidate=contract.get("candidate") if isinstance(contract,dict) else None
  prior=records[-2] if isinstance(records,list) and len(records)>=2 else None
  if not isinstance(pointer,dict) or set(pointer)!=required \
     or head.get("command")!="commit" or head.get("state")!="committing" \
     or not isinstance(prior,dict) or prior.get("eventKind")!="completion" \
     or prior.get("command")!="activate-read-only" \
     or prior.get("state")!="read-only" \
     or head.get("previousSha256")!=prior.get("recordSha256") \
     or pointer.get("format")!="openepm-macos-pilot-active-slot-v3" \
     or pointer.get("activationId")!=value.get("activationId") \
     or pointer.get("generation")!=prior.get("ordinal") \
     or pointer.get("slot")!="green" or pointer.get("authorityState")!="read-only" \
     or pointer.get("authorityPredecessorSha256")!=prior.get("previousSha256") \
     or pointer.get("activationEventSha256")!=prior.get("recordSha256") \
     or pointer.get("executionContractSha256")!=value.get(
      "executionContractSha256") or pointer.get("writesAdmitted") is not False \
     or pointer.get("publicIngressPermitted") is not False \
     or not isinstance(candidate,dict) or pointer.get("bindingSha256")!=digest(candidate) \
     or any(pointer.get(field)!=candidate.get(field) for field in (
      "project","applicationImage","databaseImage","databaseVolume",
      "databaseVolumeId","schema","services","networks",
      "businessDataDumpFingerprintSha256")) \
     or pointer.get("pointerSha256")!=digest({k:v for k,v in pointer.items()
      if k!="pointerSha256"}) \
     or value.get("stagedPointerSha256")!=pointer.get("pointerSha256"):
   raise ActivationIpcError("executor staged pointer evidence differs")
 def _persist_staged_pointer(self,pointer):
  raw=canonical(pointer);name="staged-green-slot.json"
  try:
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.evidence_fd)
  except FileNotFoundError:fd=None
  if fd is not None:
   try:
    meta=os.fstat(fd);existing=os.read(fd,MAX_MESSAGE+1)
   finally:os.close(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 \
      or meta.st_uid!=self.owner or stat.S_IMODE(meta.st_mode)!=0o400 \
      or existing!=raw:
    raise ActivationIpcError("staged pointer authority already differs")
   return
  temporary=f".staged-pointer.{uuid.uuid4().hex}.tmp"
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,
   dir_fd=self.evidence_fd)
  try:
   offset=0
   while offset<len(raw):offset+=os.write(fd,raw[offset:])
   os.fchmod(fd,0o400);os.fsync(fd)
  finally:os.close(fd)
  try:os.link(temporary,name,src_dir_fd=self.evidence_fd,dst_dir_fd=self.evidence_fd,
              follow_symlinks=False)
  except FileExistsError:
   os.unlink(temporary,dir_fd=self.evidence_fd)
   return self._persist_staged_pointer(pointer)
  os.unlink(temporary,dir_fd=self.evidence_fd);os.fsync(self.evidence_fd)
 def _validate_authority_pointer(self,value,contract,journal,head):
  pointer=value.get("authorityPointer");purpose=value.get("authorityPointerPurpose")
  records=journal.get("records");candidate=contract.get("candidate") \
   if isinstance(contract,dict) else None
  if purpose=="finalize-committed":
   event=records[-2] if isinstance(records,list) and len(records)>=2 else None
   valid_head=head.get("command")=="finalize" and head.get("state")=="finalizing" \
    and isinstance(event,dict) and event.get("eventKind")=="completion" \
    and event.get("command")=="commit" and event.get("state")=="committed" \
    and head.get("previousSha256")==event.get("recordSha256")
  elif purpose=="publish-active":
   event=head;valid_head=head.get("command")=="publish-active" \
    and head.get("state")=="publishing-active"
  elif purpose=="certify-active":
   event=head;valid_head=head.get("eventKind")=="completion" \
    and head.get("command")=="publish-active" and head.get("state")=="active"
  elif purpose=="certify-rollback":
   event=head;valid_head=head.get("eventKind")=="completion" \
    and head.get("command")=="certify-rollback" \
    and head.get("state")=="rolled-back"
  elif purpose=="certify-rollback-preopen":
   completion=(records[-2] if isinstance(records,list) and len(records)>=3 else None)
   event=(records[-3] if isinstance(records,list) and len(records)>=3 else None)
   valid_head=head.get("eventKind")=="intent" \
    and head.get("command")=="certify-rollback" \
    and head.get("state")=="publishing-rollback" \
    and isinstance(completion,dict) and completion.get("eventKind")=="completion" \
    and completion.get("command")=="rollback" \
    and completion.get("state")=="rolled-back" \
    and head.get("previousSha256")==completion.get("recordSha256") \
    and isinstance(event,dict) and event.get("eventKind")=="intent" \
    and event.get("command")=="rollback" and event.get("state")=="rolling-back" \
    and completion.get("previousSha256")==event.get("recordSha256")
  else:event=None;valid_head=False
  common={"format","activationId","generation","slot","authorityState",
   "authorityPredecessorSha256","project","applicationImage","databaseImage",
   "databaseVolume","databaseVolumeId","schema","services","networks",
   "businessDataDumpFingerprintSha256","bindingSha256",
   "executionContractSha256","activationEventSha256","writesAdmitted",
   "publicIngressPermitted","pointerSha256"}
  expected_state={"finalize-committed":"committed",
                  "publish-active":"publishing-active",
                  "certify-active":"active",
                  "certify-rollback":"rolled-back",
                  "certify-rollback-preopen":"rolling-back"}.get(purpose)
  slot="blue" if purpose in ("certify-rollback",
                              "certify-rollback-preopen") else "green"
  selected=contract.get("source" if slot=="blue" else "candidate") \
   if isinstance(contract,dict) else None
  public=purpose in ("certify-active","certify-rollback")
  if not valid_head or not isinstance(pointer,dict) or set(pointer)!=common \
     or pointer.get("format")!="openepm-macos-pilot-active-slot-v3" \
     or pointer.get("activationId")!=value.get("activationId") \
     or pointer.get("generation")!=event.get("ordinal") \
     or pointer.get("slot")!=slot \
     or pointer.get("authorityState")!=expected_state \
     or pointer.get("authorityPredecessorSha256")!=event.get("previousSha256") \
     or pointer.get("activationEventSha256")!=event.get("recordSha256") \
     or pointer.get("executionContractSha256")!=value.get(
      "executionContractSha256") or pointer.get("writesAdmitted") is not public \
     or pointer.get("publicIngressPermitted") is not public \
     or not isinstance(selected,dict) or pointer.get("bindingSha256")!=digest(selected) \
     or any(pointer.get(field)!=selected.get(field) for field in (
      "project","applicationImage","databaseImage","databaseVolume",
      "databaseVolumeId","schema","services","networks",
      "businessDataDumpFingerprintSha256")) \
     or pointer.get("pointerSha256")!=digest({k:v for k,v in pointer.items()
      if k!="pointerSha256"}) \
     or value.get("authorityPointerSha256")!=pointer.get("pointerSha256"):
   raise ActivationIpcError("executor authority pointer evidence differs")
 def _persist_authority_pointer(self,pointer):
  raw=canonical(pointer);name="active-slot.json";prior=None
  try:
   fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.evidence_fd)
  except FileNotFoundError:fd=None
  if fd is not None:
   try:
    meta=os.fstat(fd);existing=os.read(fd,MAX_MESSAGE+1)
   finally:os.close(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 \
      or meta.st_uid!=self.owner or stat.S_IMODE(meta.st_mode)!=0o400:
    raise ActivationIpcError("active pointer authority is unsafe")
   try:prior=json.loads(existing.decode())
   except Exception as error:raise ActivationIpcError(
    "active pointer authority is invalid") from error
   if existing==raw:return
   allowed=(prior.get("activationId")==pointer.get("activationId")
    and prior.get("executionContractSha256")==pointer.get("executionContractSha256")
    and isinstance(prior.get("generation"),int)
    and pointer.get("generation")>prior.get("generation")
    and ((prior.get("slot")==pointer.get("slot")=="green"
          and prior.get("authorityState")=="committed"
          and pointer.get("authorityState")=="publishing-active")
         or (pointer.get("authorityState") in ("active","rolled-back")
             and pointer.get("writesAdmitted") is True
             and pointer.get("publicIngressPermitted") is True)
         or (pointer.get("slot")=="blue"
             and pointer.get("authorityState")=="rolling-back"
             and pointer.get("writesAdmitted") is False
             and pointer.get("publicIngressPermitted") is False)))
   if not allowed:raise ActivationIpcError("active pointer authority regresses")
  temporary=f".active-pointer.{uuid.uuid4().hex}.tmp"
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400,
   dir_fd=self.evidence_fd)
  try:
   offset=0
   while offset<len(raw):offset+=os.write(fd,raw[offset:])
   os.fchmod(fd,0o400);os.fsync(fd)
  finally:os.close(fd)
  os.rename(temporary,name,src_dir_fd=self.evidence_fd,
   dst_dir_fd=self.evidence_fd);os.fsync(self.evidence_fd)
 def _attempt(self,sha):
  try:fd=os.open(sha+".json",os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
  except FileNotFoundError:return None
  try:
   meta=os.fstat(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=self.owner \
      or stat.S_IMODE(meta.st_mode)!=0o600 or not 1<=meta.st_size<=MAX_MESSAGE:
    raise ActivationIpcError("activation IPC replay record is unsafe")
   raw=os.read(fd,MAX_MESSAGE+1)
  finally:os.close(fd)
  value=json.loads(raw.decode())
  if not isinstance(value,dict) or canonical(value)!=raw:raise ActivationIpcError(
   "activation IPC replay record is invalid")
  return value
 def _persist(self,sha,value):
  payload=canonical(value);temporary=f".{sha}.{uuid.uuid4().hex}.tmp"
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,
             dir_fd=self.fd)
  try:
   offset=0
   while offset<len(payload):offset+=os.write(fd,payload[offset:])
   os.fchmod(fd,0o600);os.fsync(fd)
  finally:os.close(fd)
  os.rename(temporary,sha+".json",src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)
 def handle(self,request,*,peer_uid):
  if peer_uid!=self.service_uid:raise ActivationIpcError(
   "activation IPC peer is unauthorized")
  method,payload=_validate_request(request,self.parent_assembly_sha256);sha=request["requestSha256"]
  with self._handle_lock:
   lock=os.open("authority.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,
                dir_fd=self.fd)
   try:
    fcntl.flock(lock,fcntl.LOCK_EX);meta=os.fstat(lock)
    if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=self.owner \
       or stat.S_IMODE(meta.st_mode)!=0o600:raise ActivationIpcError(
        "activation IPC lock is unsafe")
    prior=self._attempt(sha)
    if prior is not None:
     if prior.get("requestSha256")!=sha:raise ActivationIpcError(
      "activation IPC replay differs")
     return prior["response"]
    if method=="execute-or-reconcile":
     staged=self._stage_executor_evidence(payload)
     if payload["command"]=="publish-active":
      if not isinstance(staged,dict) or staged.get("authorityPointerPurpose") \
         !="publish-active" or self.producer_reopen_publisher is None:
       raise ActivationIpcError("producer reopen authority evidence is absent")
      self.producer_reopen_publisher.publish(kind="finalize",
       manifest=self.producer_manifest_provider.current("green"),
       contract=payload["contract"],journal=staged["journal"],
       pointer=staged["authorityPointer"],trust=self.producer_trust_value)
      self._qualification_fault("publish-active-producer-authority-persisted")
     if payload["command"]=="certify-rollback":
      if not isinstance(staged,dict) or staged.get("authorityPointerPurpose") \
         !="certify-rollback-preopen" or self.producer_reopen_publisher is None:
       raise ActivationIpcError("rollback producer reopen authority evidence is absent")
      self.producer_reopen_publisher.publish(kind="rollback",
       manifest=self.producer_manifest_provider.current("blue"),
       contract=payload["contract"],journal=staged["journal"],
       pointer=staged["authorityPointer"],trust=self.producer_trust_value)
      self._qualification_fault("certify-rollback-producer-authority-persisted")
     result=self.adapter.execute_or_reconcile(payload["command"],payload["context"])
     if payload["command"] in ("publish-active","certify-rollback"):
      self._qualification_fault(payload["command"]+"-response-ready")
     if not isinstance(result,PhaseResult):raise ActivationIpcError(
      "activation authority result is invalid")
     body={"kind":"phase","operationKey":result.operation_key,
      "observations":result.observations,"executionContract":result.execution_contract,
      "authority":result.authority}
    else:
     if payload.get("contract",{}).get("format","").endswith("-v3"):
      self._stage_executor_evidence(payload)
     body={"kind":"authority","authority":self.publisher.publish(phase=payload["phase"],
      operation_key=payload["operationKey"],contract=payload["contract"])}
    response={"format":"openepm-macos-pilot-authority-response-v1",
     "requestSha256":sha,"result":body};response["responseSha256"]=digest(response)
    self._persist(sha,{"requestSha256":sha,"response":response});return response
   finally:
    fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
 def serve_once(self,listener):
  connection,_=listener.accept()
  with connection:
   try:_send(connection,{"ok":True,"response":self.handle(_receive(connection),
    peer_uid=self.peer_uid(connection))})
   except Exception as error:_send(connection,{"ok":False,"error":type(error).__name__,
    "message":str(error)})
 def open_listener(self):
  if self.listener is not None:raise ActivationIpcError(
   "activation authority listener already exists")
  try:
   meta=os.lstat(self.socket_path)
   if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid!=self.owner \
      or stat.S_IMODE(meta.st_mode)!=0o660:
    raise ActivationIpcError("existing activation socket is unsafe")
   os.unlink(self.socket_path)
  except FileNotFoundError:pass
  listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  try:
   listener.bind(str(self.socket_path));os.chmod(self.socket_path,0o660)
   os.chown(self.socket_path,self.owner,self.service_gid);listener.listen(16)
   meta=os.lstat(self.socket_path)
   if meta.st_uid!=self.owner or meta.st_gid!=self.service_gid \
      or stat.S_IMODE(meta.st_mode)!=0o660:
    raise ActivationIpcError("activation socket identity differs")
  except Exception:
   listener.close()
   try:os.unlink(self.socket_path)
   except FileNotFoundError:pass
   raise
  self.listener=listener;return listener
 def serve_forever(self):
  listener=self.listener or self.open_listener()
  while self.listener is listener:self.serve_once(listener)
 def close(self):
  if self.listener is not None:
   self.listener.close();self.listener=None
   try:
    meta=os.lstat(self.socket_path)
    if stat.S_ISSOCK(meta.st_mode) and meta.st_uid==self.owner:os.unlink(self.socket_path)
   except FileNotFoundError:pass
  if self.fd is not None:os.close(self.fd);self.fd=None
  if self.evidence_fd is not None:os.close(self.evidence_fd);self.evidence_fd=None

class ActivationAuthorityClient:
 """Non-root fixed-method client implementing executor adapter and publisher."""
 def __init__(self,socket_path:Path,*,timeout_seconds=30,expected_server_uid=0,
              parent_assembly_sha256:str,_test_effective_uid=None,
              connector=None,peer_uid:Callable=_peer_uid):
  effective=os.geteuid() if _test_effective_uid is None else _test_effective_uid
  if effective==0:raise ActivationIpcError(
   "activation executor IPC client must be non-root")
  self.path=Path(socket_path);self.timeout=timeout_seconds;self.server_uid=expected_server_uid
  self.connector=connector or self._connect;self.peer_uid=peer_uid
  self.parent_assembly_sha256=parent_assembly_sha256
  if not self.path.is_absolute() or timeout_seconds<=0 \
     or not isinstance(parent_assembly_sha256,str) or len(parent_assembly_sha256)!=64:
   raise ActivationIpcError(
   "activation IPC client configuration is invalid")
 def _connect(self):
  connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(
   self.timeout);connection.connect(str(self.path));return connection
 def _call(self,method,payload):
  contract=payload["contract"]
  prepare=method=="execute-or-reconcile" and payload.get("command")=="prepare"
  identity=payload.get("context",{}).get("intent",{}) if prepare else contract
  body={"format":"openepm-macos-pilot-authority-request-v1","method":method,
   "activationId":identity.get("activationId"),
   "planSha256":identity.get("planSha256") if prepare else contract.get("dryPlanSha256"),
   "executionContractSha256":None if prepare else contract.get(
    "executionContractSha256"),"parentAssemblySha256":self.parent_assembly_sha256,
   "operationKey":payload["operationKey"],"payload":payload}
  request={**body,"requestSha256":digest(body)}
  with self.connector() as connection:
   if self.peer_uid(connection)!=self.server_uid:raise ActivationIpcError(
    "activation IPC server identity differs")
   _send(connection,request);envelope=_receive(connection)
  if envelope.get("ok") is not True:raise ActivationIpcError(
   "activation authority rejected request: "+str(envelope.get("message","unknown")))
  response=envelope.get("response");claimed=response.get("responseSha256") \
   if isinstance(response,dict) else None
  if not isinstance(response,dict) or response.get("requestSha256")!=request["requestSha256"] \
     or claimed!=digest({k:v for k,v in response.items() if k!="responseSha256"}):
   raise ActivationIpcError("activation IPC response binding differs")
  return response["result"]
 def execute_or_reconcile(self,command,context):
  if not isinstance(context,dict) or not isinstance(context.get("contract"),dict):
   raise ActivationIpcError("activation execution context is invalid")
  result=self._call("execute-or-reconcile",{"command":command,"context":context,
   "contract":context["contract"],"operationKey":context.get("operationKey")})
  if result.get("kind")!="phase":raise ActivationIpcError(
   "activation phase response differs")
  if command=="prepare":
   contract=result.get("executionContract")
   intent=context.get("intent",{})
   verifier=contract.get("authorityVerifier") if isinstance(contract,dict) else None
   if not isinstance(contract,dict) or contract.get("activationId")!=intent.get(
      "activationId") or contract.get("dryPlanSha256")!=intent.get("planSha256") \
      or contract.get("executionContractSha256")!=digest({k:v for k,v in
       contract.items() if k!="executionContractSha256"}) \
      or contract.get("format","").endswith("-v3") and (not isinstance(verifier,dict)
       or set(verifier)!={"algorithm","keyId","version"} \
       or verifier.get("algorithm")!="Ed25519"):
    raise ActivationIpcError("activation prepare contract response differs")
  return PhaseResult(result["operationKey"],result["observations"],
   result.get("executionContract"),result.get("authority"))
 def publish(self,*,phase,operation_key,contract,completion=None,executor_evidence=None):
  payload={"phase":phase,"operationKey":operation_key,"contract":contract}
  if contract.get("format","").endswith("-v3"):
   payload.update(completion=completion,executorEvidence=executor_evidence)
  result=self._call("publish-admission-open",payload)
  if result.get("kind")!="authority" or not isinstance(result.get("authority"),dict):
   raise ActivationIpcError("activation publication response differs")
  return result["authority"]


class ProtectedAdmissionOpenEvidenceSource:
 """Fresh root-owned evidence source for public-admission publication.

 Static signed artifacts are reread for every call; database and producer
 fences are verified live and converted into operation-bound evidence.  This
 keeps the publisher independent of caller-supplied evidence.
 """
 def __init__(self,root:Path,db_fence,producer_fences:dict,*,trust_registry_path:Path,
              authority_gate_root:Path,
              _test_owner_uid=None,_test_now_utc=None):
  self.root=Path(root);self.db=db_fence;self.producers=producer_fences
  self.trust_path=Path(trust_registry_path)
  self.gate_root=Path(authority_gate_root)
  self.owner=0 if _test_owner_uid is None else _test_owner_uid
  if (_test_now_utc is not None and (_test_owner_uid is None
          or not isinstance(_test_now_utc,str)
          or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                          _test_now_utc) is None)):
   raise ActivationIpcError("test clock is invalid")
  self._test_now_utc=_test_now_utc
  if not self.root.is_absolute() or self.root.is_symlink() or not self.root.is_dir() \
     or self.root.stat().st_uid!=self.owner \
     or stat.S_IMODE(self.root.stat().st_mode) not in (0o500,0o700) \
     or set(producer_fences)!={"blue","green"} \
     or any(not hasattr(item,"verify_closed") or not hasattr(item,"verify_open")
            for item in producer_fences.values()) \
     or not hasattr(db_fence,"verify_closed") or not hasattr(db_fence,"verify_open") \
     or not self.trust_path.is_absolute() or self.trust_path.is_symlink() \
     or not self.trust_path.is_file() or self.trust_path.stat().st_uid!=self.owner \
     or self.trust_path.stat().st_nlink!=1 \
     or stat.S_IMODE(self.trust_path.stat().st_mode)!=0o400:
   raise ActivationIpcError("admission evidence source is unsafe")
  if not self.gate_root.is_absolute() or self.gate_root.is_symlink() \
     or not self.gate_root.is_dir() or self.gate_root.stat().st_uid!=self.owner \
     or stat.S_IMODE(self.gate_root.stat().st_mode)!=0o555:
   raise ActivationIpcError("admission gate authority is unsafe")
  self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  self.gate_fd=os.open(self.gate_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 def _read(self,name):
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
  try:
   meta=os.fstat(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=self.owner \
      or stat.S_IMODE(meta.st_mode)!=0o400 or not 1<=meta.st_size<=MAX_MESSAGE:
    raise ActivationIpcError("admission evidence artifact is unsafe")
   raw=os.read(fd,MAX_MESSAGE+1)
  finally:os.close(fd)
  try:value=json.loads(raw.decode())
  except Exception as error:raise ActivationIpcError(
   "admission evidence artifact is invalid") from error
  if not isinstance(value,dict) or canonical(value)!=raw:raise ActivationIpcError(
   "admission evidence artifact is not canonical")
  return value
 def _read_gate(self,name):
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.gate_fd)
  try:
   meta=os.fstat(fd);raw=os.read(fd,MAX_MESSAGE+1)
  finally:os.close(fd)
  try:value=json.loads(raw.decode())
  except Exception as error:raise ActivationIpcError(
   "admission gate authority is invalid") from error
  if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 \
     or meta.st_uid!=self.owner or stat.S_IMODE(meta.st_mode)!=0o444 \
     or not isinstance(value,dict) or canonical(value)!=raw:
   raise ActivationIpcError("admission gate authority differs")
  return value
 def _trust(self,contract):
  fd=os.open(self.trust_path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   meta=os.fstat(fd);raw=os.read(fd,MAX_MESSAGE+1)
  finally:os.close(fd)
  try:value=json.loads(raw.decode())
  except Exception as error:raise ActivationIpcError(
   "admission immutable trust is invalid") from error
  if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 \
     or meta.st_uid!=self.owner or stat.S_IMODE(meta.st_mode)!=0o400 \
     or canonical(value)!=raw or not isinstance(value,dict) \
     or set(value)!={"format","keys","approvedContracts"} \
     or value.get("format")!="openepm-macos-pilot-runtime-trust-v1" \
     or contract.get("executionContractSha256") not in value.get(
      "approvedContracts",[]):
   raise ActivationIpcError("admission immutable trust differs")
  try:
   if __package__:
    from .validate_macos_pilot_activation_receipt import trust_registry_from_runtime_value
   else:
    from validate_macos_pilot_activation_receipt import trust_registry_from_runtime_value
   registry=trust_registry_from_runtime_value(value)
   registry.require_contract(contract["executionContractSha256"])
   modern=contract.get("format","").endswith("-v3")
   verifier=contract["authorityVerifier" if modern else "executorVerifier"]
   registry.verifier_public_key_at(verifier["keyId"],
    role="authority" if modern else "executor",version=verifier["version"],
    now_utc=self._test_now_utc or datetime.now(timezone.utc).strftime(
     "%Y-%m-%dT%H:%M:%SZ"))
  except Exception as error:raise ActivationIpcError(
   "admission immutable trust is not currently authorized") from error
  return value
 @staticmethod
 def _evidence(kind,slot,state,operation,contract,live):
  body={"format":f"openepm-macos-pilot-{kind}-fence-v1","slot":slot,
   "state":state,"activationId":contract["activationId"],
   "executionContractSha256":contract["executionContractSha256"],
   "authorityEventSha256":operation,"liveVerificationSha256":live}
  return {**body,"evidenceSha256":digest(body)}
 def current(self,phase,operation_key,contract):
  selected={"certify-active":"green","certify-rollback":"blue"}.get(phase)
  if selected is None:raise ActivationIpcError("admission evidence phase differs")
  other="blue" if selected=="green" else "green"
  # One all-producer manifest is the canonical close/reopen state. Per-slot
  # shadow files are deliberately neither required nor consulted.
  manifest=self._read("all-producer-fence.json")
  selected_db=self.db.verify_open(selected,operation_key,contract)
  other_db=self.db.verify_closed(other,operation_key,contract)
  selected_producer=self.producers[selected].verify_open(manifest,
                                                         contract=contract)
  other_producer=self.producers[other].verify_closed(manifest,
                                                     contract=contract)
  gate="green-write-gate.json" if selected=="green" else "rollback-write-gate.json"
  gate_value=self._read_gate(gate)
  health_field=("greenServiceHealthSha256" if selected=="green" else
                "blueServiceHealthSha256")
  service_health={"format":"openepm-macos-pilot-gate-health-evidence-v1",
   "slot":selected,"activationId":contract["activationId"],
   "executionContractSha256":contract["executionContractSha256"],
   "authorityEventSha256":operation_key,
   "evidenceSha256":gate_value.get(health_field)}
  return {"journal":self._read("activation-journal-snapshot.json"),
   "pointer":self._read("active-slot.json"),
   "trust":self._trust(contract),
   "writeGate":gate_value,
   "selectedDbFence":self._evidence("database",selected,"open",operation_key,
                                    contract,selected_db),
   "selectedProducerFence":self._evidence("producer",selected,"open",operation_key,
                                          contract,selected_producer),
   "otherDbFence":self._evidence("database",other,"closed",operation_key,
                                 contract,other_db),
   "otherProducerFence":self._evidence("producer",other,"closed",operation_key,
                                       contract,other_producer),
   "serviceHealth":service_health}
 def close(self):
  if self.fd is not None:os.close(self.fd);self.fd=None
  if self.gate_fd is not None:os.close(self.gate_fd);self.gate_fd=None
