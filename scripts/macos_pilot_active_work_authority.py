#!/usr/bin/env python3
"""Protected providers wiring admission closure to the canonical active-work drain."""
from __future__ import annotations

from datetime import datetime,timezone
import json
import os
from pathlib import Path
import re
import stat

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

try:
    from macos_pilot_active_work import ActiveWorkObserver,ActiveWorkDrain,canonical,digest
    from macos_pilot_public_admission import PublicAdmissionBoundary
    from macos_pilot_secure_activation import verify_journal
except ModuleNotFoundError:  # package import in source tests
    from scripts.macos_pilot_active_work import (ActiveWorkObserver,ActiveWorkDrain,
                                                  canonical,digest)
    from scripts.macos_pilot_public_admission import PublicAdmissionBoundary
    from scripts.macos_pilot_secure_activation import verify_journal

SHA=re.compile(r"^[0-9a-f]{64}$")

class ActiveWorkAuthorityError(RuntimeError):pass

def protected_json(path:Path,owner:int,maximum:int=2*1024*1024)->dict:
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=owner \
                or stat.S_IMODE(meta.st_mode) not in (0o400,0o444) \
                or not 1<=meta.st_size<=maximum:
            raise ActiveWorkAuthorityError("protected authority file is unsafe")
        raw=os.read(fd,maximum+1)
    finally:os.close(fd)
    try:value=json.loads(raw.decode())
    except (UnicodeError,json.JSONDecodeError) as error:
        raise ActiveWorkAuthorityError("protected authority file is invalid") from error
    if not isinstance(value,dict) or raw!=canonical(value):
        raise ActiveWorkAuthorityError("protected authority file is not canonical")
    return value

def validate_current_journal_snapshot(snapshot:dict,contract:dict,operation_key:str,
                                      parent_assembly_sha256:str|None)->dict:
    body={key:item for key,item in snapshot.items() if key!="snapshotSha256"} \
        if isinstance(snapshot,dict) else {}
    if not isinstance(snapshot,dict) \
            or snapshot.get("format")!="openepm-macos-pilot-secure-journal-snapshot-v1" \
            or snapshot.get("snapshotSha256")!=digest(body) \
            or snapshot.get("activationId")!=contract.get("activationId"):
        raise ActiveWorkAuthorityError("secure journal authority differs")
    bootstrap=snapshot.get("executionContractSha256") is None
    if not bootstrap and snapshot.get("executionContractSha256")!=contract.get(
            "executionContractSha256"):
        raise ActiveWorkAuthorityError("secure journal authority differs")
    try:head=verify_journal(snapshot.get("records"),snapshot.get("planSha256"),
        snapshot.get("activationId"),snapshot.get("executionContractSha256"))
    except Exception as error:
        raise ActiveWorkAuthorityError("secure journal is invalid") from error
    prepare=snapshot.get("prepareBootstrap")
    if bootstrap and (parent_assembly_sha256 is None or not isinstance(prepare,dict) \
            or set(prepare)!={"parentAssemblySha256","activationId","planSha256",
                "operationKey","executorEvidenceSha256"} \
            or prepare.get("parentAssemblySha256")!=parent_assembly_sha256 \
            or prepare.get("activationId")!=contract.get("activationId") \
            or prepare.get("planSha256")!=contract.get("dryPlanSha256") \
            or prepare.get("planSha256")!=snapshot.get("planSha256") \
            or prepare.get("operationKey")!=operation_key \
            or SHA.fullmatch(str(prepare.get("executorEvidenceSha256"))) is None \
            or head is None or head.get("command")!="prepare" \
            or head.get("ordinal")!=1 or head.get("state")!="preparing"):
        raise ActiveWorkAuthorityError("prepare bootstrap journal authority differs")
    if head is None or head.get("recordSha256")!=operation_key \
            or head.get("eventKind")!="intent":
        raise ActiveWorkAuthorityError("operation is not current journal intent")
    return head

def validate_terminal_journal_snapshot(snapshot:dict,contract:dict,
                                       operation_key:str,phase:str)->dict:
    """Validate the exact completed authority head used only for public resume."""
    expected={"certify-active":("publish-active","active"),
              "certify-rollback":("certify-rollback","rolled-back")}.get(phase)
    body={key:item for key,item in snapshot.items() if key!="snapshotSha256"} \
        if isinstance(snapshot,dict) else {}
    if expected is None or not isinstance(snapshot,dict) \
            or set(snapshot)!={"format","planSha256","activationId",
                "executionContractSha256","records","snapshotSha256"} \
            or snapshot.get("format")!= \
                "openepm-macos-pilot-secure-journal-snapshot-v1" \
            or snapshot.get("snapshotSha256")!=digest(body) \
            or snapshot.get("activationId")!=contract.get("activationId") \
            or snapshot.get("planSha256")!=contract.get("dryPlanSha256") \
            or snapshot.get("executionContractSha256")!=contract.get(
                "executionContractSha256"):
        raise ActiveWorkAuthorityError("terminal journal authority differs")
    try:head=verify_journal(snapshot.get("records"),snapshot["planSha256"],
        snapshot["activationId"],snapshot["executionContractSha256"])
    except Exception as error:raise ActiveWorkAuthorityError(
        "terminal journal authority differs") from error
    if head is None or head.get("recordSha256")!=operation_key \
            or head.get("eventKind")!="completion" \
            or (head.get("command"),head.get("state"))!=expected:
        raise ActiveWorkAuthorityError("operation is not current terminal completion")
    return head

def validate_continuous_closure_lineage(records:list[dict],current_generation:int,
                                        closure_generation:int)->str:
    """Validate the complete closed-admission phase table after prepare."""
    if not isinstance(records,list) or not isinstance(current_generation,int) \
            or not isinstance(closure_generation,int) \
            or closure_generation<1 or current_generation<=closure_generation \
            or len(records)<current_generation:
        raise ActiveWorkAuthorityError("admission closure lineage differs")
    head=records[current_generation-1]
    prior=records[current_generation-2] if current_generation>=2 else None
    table={
      ("rollback","rolling-back","intent"):{
       ("prepare","prepared","completion"),
       ("activate-read-only","read-only","completion")},
      ("finalize","finalizing","intent"):{("commit","committed","completion")},
      ("publish-active","publishing-active","intent"):{
       ("finalize","finalized","completion")},
      ("certify-rollback","publishing-rollback","intent"):{
       ("rollback","rolled-back","completion")}}
    allowed=table.get((head.get("command"),head.get("state"),head.get("eventKind")))
    predecessor=(prior.get("command"),prior.get("state"),prior.get("eventKind")) \
        if isinstance(prior,dict) else None
    if allowed is None or predecessor not in allowed \
            or head.get("previousSha256")!=prior.get("recordSha256"):
        raise ActiveWorkAuthorityError("admission closure lineage differs")
    forbidden=records[closure_generation:current_generation-2]
    if any(item.get("command") in ("certify-rollback","publish-active")
           or item.get("state") in ("rolled-back","publishing-rollback",
                                    "publishing-active","active")
           for item in forbidden):
        raise ActiveWorkAuthorityError("admission closure lineage differs")
    return head["command"]

class ProtectedJournalCurrent:
    def __init__(self,path:Path,*,parent_assembly_sha256:str|None=None,
                 _test_owner_uid:int|None=None,now=None):
        self.path=Path(path);self.owner=0 if _test_owner_uid is None else _test_owner_uid
        self.parent_assembly_sha256=parent_assembly_sha256
        self.now=now or (lambda:datetime.now(timezone.utc))
    def current(self,contract:dict,operation_key:str)->dict:
        snapshot=protected_json(self.path,self.owner)
        head=validate_current_journal_snapshot(snapshot,contract,operation_key,
            self.parent_assembly_sha256)
        now=self.now()
        if not isinstance(now,datetime) or now.tzinfo is None:
            raise ActiveWorkAuthorityError("operation is not current journal intent")
        return {"head":operation_key,"generation":head["ordinal"],
            "observedAtUtc":now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}

class ProtectedActiveWorkRuntime:
    def __init__(self,path:Path,process,*,_test_owner_uid:int|None=None):
        self.path=Path(path);self.owner=0 if _test_owner_uid is None else _test_owner_uid
        self.process=process;self.config=self._load()
    def _load(self):
        value=protected_json(self.path,self.owner,65536)
        body={key:item for key,item in value.items() if key!="configSha256"}
        if set(value)!={"format","adminDsnFile","dockerPath","composeFile","envFile",
                "project","workerServices","configSha256"} \
                or value.get("format")!="openepm-active-work-runtime-v1" \
                or value.get("configSha256")!=digest(body) \
                or value.get("workerServices")!=["worker","python-build-broker"]:
            raise ActiveWorkAuthorityError("active-work runtime config differs")
        for key in ("adminDsnFile","dockerPath","composeFile","envFile"):
            target=Path(value[key])
            if not target.is_absolute() or target.is_symlink() or not target.is_file() \
                    or target.stat().st_uid!=self.owner or target.stat().st_nlink!=1 \
                    or stat.S_IMODE(target.stat().st_mode) not in (
                        (0o500,0o555) if key=="dockerPath" else (0o400,0o444)):
                raise ActiveWorkAuthorityError("active-work runtime resource is unsafe")
        return value
    def dsn(self)->str:
        if self._load()!=self.config:
            raise ActiveWorkAuthorityError("active-work runtime changed")
        path=Path(self.config["adminDsnFile"]);data=path.read_text().strip()
        if not data or "\n" in data or "\r" in data:return ""
        return data
    def workers_running(self)->bool:
        if self._load()!=self.config:
            raise ActiveWorkAuthorityError("active-work runtime changed")
        c=self.config;base=(c["dockerPath"],"compose","--project-name",c["project"],
            "--env-file",c["envFile"],"-f",c["composeFile"])
        for service in c["workerServices"]:
            result=self.process.run((*base,"ps","--status","running","--services",service),30)
            if result.returncode!=0 or result.stdout.decode().strip()!=service:return False
        return True

class AdmissionDrainBoundary:
    def __init__(self,admission:PublicAdmissionBoundary,journal:ProtectedJournalCurrent,
                 contract:dict,operation_key:str):
        self.admission,self.journal,self.contract,self.operation=admission,journal,contract,operation_key
        self.runtime=None
    def close_new_public_admission(self,operation_key:str,contract:dict)->str:
        if operation_key!=self.operation or contract!=self.contract:
            raise ActiveWorkAuthorityError("drain admission request differs")
        current=self.journal.current(contract,operation_key)
        value=self.admission.close(operation_key=operation_key,contract=contract,
            journal_head=current["head"],journal_generation=current["generation"],
            observed_at_utc=current["observedAtUtc"])
        return value["evidenceSha256"]
    def workers_running(self)->bool:return self.runtime.workers_running()

def build_drain(*,runtime:ProtectedActiveWorkRuntime,
                admission:PublicAdmissionBoundary,journal:ProtectedJournalCurrent,
                contract:dict,operation_key:str,private_key,key_id:str,
                timeout_seconds:float=120,poll_seconds:float=.5)->tuple[ActiveWorkDrain,dict]:
    current=journal.current(contract,operation_key)
    boundary=AdmissionDrainBoundary(admission,journal,contract,operation_key)
    boundary.runtime=runtime
    drain=ActiveWorkDrain(ActiveWorkObserver(runtime.dsn()),boundary,private_key,
        key_id=key_id,timeout_seconds=timeout_seconds,poll_seconds=poll_seconds)
    return drain,current
