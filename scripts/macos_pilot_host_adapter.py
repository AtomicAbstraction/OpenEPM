#!/usr/bin/env python3
"""Non-live production HostAdapter for bounded Mac-pilot activation.

This owns sequencing, durable attempts and the allowlist.  The injected runner
is a narrow privileged boundary; callers can never supply commands, paths,
environment variables or action names.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Protocol

from execute_macos_pilot_activation import PhaseResult
from macos_pilot_secure_activation import canonical,digest
from validate_macos_pilot_activation_receipt import OBSERVATIONS
from macos_pilot_rollback_gate_publisher import DurableRollbackGatePublisher


SHA=re.compile(r"^[0-9a-f]{64}$")


class MacPilotHostAdapterError(RuntimeError): pass


class FixedMacPilotRunner(Protocol):
    """Privileged implementation of fixed actions; no generic shell method."""
    def perform(self,action: str,operation_key: str,contract: dict) -> str: ...
    def seal_execution_contract(self,operation_key: str) -> dict: ...


class MacPilotController(Protocol):
    def compose(self,action: str,operation_key: str,contract: dict) -> str: ...
    def tunnel(self,action: str,operation_key: str,contract: dict) -> str: ...
    def observe(self,action: str,operation_key: str,contract: dict) -> str: ...
    def seal_execution_contract(self,operation_key: str) -> dict: ...


class PostgresWriteFence(Protocol):
    def close_blue(self,operation_key: str,contract: dict) -> str: ...
    def close_green(self,operation_key: str,contract: dict) -> str: ...
    def restore_blue(self,operation_key: str,contract: dict) -> str: ...
    def restore_green(self,operation_key: str,contract: dict) -> str: ...
    def restore(self,operation_key: str,contract: dict) -> str: ...
    def verify_closed(self,slot: str,operation_key: str,contract: dict) -> str: ...
    def verify_open(self,slot: str,operation_key: str,contract: dict) -> str: ...


class BoundedMacPilotRunner:
    """Fixed dispatch to qualified controller and PostgreSQL fence components."""
    def __init__(self,controller: MacPilotController,fence: PostgresWriteFence):
        required=("compose","tunnel","observe","seal_execution_contract")
        if any(not hasattr(controller,name) for name in required) \
                or any(not hasattr(fence,name) for name in
                       ("close_blue","close_green","restore_blue","restore_green",
                        "verify_closed","verify_open")):
            raise MacPilotHostAdapterError("bounded runner dependency is incomplete")
        self.controller=controller; self.fence=fence

    def perform(self,action: str,operation_key: str,contract: dict) -> str:
        if action not in ALLOWED_ACTIONS:
            raise MacPilotHostAdapterError("bounded runner action is not allowlisted")
        if action=="close-blue-postgres-write-fence":
            return self.fence.close_blue(operation_key,contract)
        if action=="close-green-postgres-write-fence":
            return self.fence.close_green(operation_key,contract)
        if action=="restore-blue-postgres-write-fence":
            return self.fence.restore_blue(operation_key,contract)
        if action=="restore-green-postgres-fence":
            return self.fence.restore_green(operation_key,contract)
        if action=="verify-postgres-fence-closed":
            return self.fence.verify_closed("blue",operation_key,contract)
        if action=="verify-blue-fence-closed":
            return self.fence.verify_closed("blue",operation_key,contract)
        if action=="verify-blue-fence-open":
            return self.fence.verify_open("blue",operation_key,contract)
        if action=="verify-green-fence-open":
            return self.fence.verify_open("green",operation_key,contract)
        if action=="verify-green-fence-closed":
            return self.fence.verify_closed("green",operation_key,contract)
        if action.startswith("compose-") or action == "stop-app-and-broker-services":
            return self.controller.compose(action,operation_key,contract)
        if action in ("verify-tunnel-stopped","resume-public-tunnel"):
            return self.controller.tunnel(action,operation_key,contract)
        return self.controller.observe(action,operation_key,contract)

    def seal_execution_contract(self,operation_key: str) -> dict:
        return self.controller.seal_execution_contract(operation_key)


ACTION_BY_OBSERVATION={
    "prepare":{
        "quiescence":"verify-source-quiescent","drainedWork":"verify-work-drained",
        "finalBackup":"verify-protected-backup","sourceEquality":"fingerprint-source",
        "candidatePrepared":"verify-green-prepared","restoreMigration":"verify-green-migrated",
        "dataIdentity":"verify-green-data","sandboxNetwork":"verify-private-network"},
    "activate-read-only":{
        "tunnelStopped":"verify-tunnel-stopped",
        "writeDenial":"verify-green-fence-closed",
        "candidateServices":"compose-start-green",
        "launcherNetwork":"verify-launcher-network","health":"verify-green-health",
        "unsignedDenial":"verify-unsigned-denial","authenticatedRead":"verify-green-read",
        "sourcePreserved":"verify-blue-preserved"},
    "rollback":{
        "candidateStopped":"verify-green-stopped","sourceNetworkRestored":"restore-blue-network",
        "sourceServices":"compose-start-blue-readonly","sourceData":"verify-blue-data",
        "authenticatedRead":"verify-blue-read",
        "unsignedDenial":"verify-blue-unsigned-denial",
        "writesControlled":"verify-blue-write-job-denial",
        "candidateRetained":"verify-green-retained"},
    "commit":{
        "candidateRevalidated":"verify-green-current","greenPointerPrepared":"verify-green-authority-prepared",
        "ownerAuthorized":"verify-owner-authorization","writeGateStillClosed":"verify-green-gate-closed",
        "tunnelStillStopped":"verify-tunnel-stopped"},
    "finalize":{
        "committedDecisionCurrent":"verify-commit-current","greenPointerSelected":"verify-green-authority-selected",
        "writeGateOpened":"verify-green-fence-open","tunnelResumed":"resume-public-tunnel",
        "publicForwardVerified":"verify-public-green"},
    "publish-active":{"signedGreenGateReadBack":"publish-green-write-gate",
        "producerFenceOpened":"reopen-green-producer-fence"},
}
FINALIZE_V3_ACTIONS={"committedDecisionCurrent":"verify-commit-current",
    "greenPointerSelected":"verify-green-authority-selected",
    "greenDatabaseAclReady":"verify-green-fence-open",
    "candidateServices":"compose-start-green-finalize","health":"verify-green-finalize-health",
    "producerFenceClosed":"verify-producer-fence-closed",
    "tunnelStillStopped":"verify-tunnel-stopped"}
PRECONDITION_ACTIONS={
    "prepare":("close-public-admission","drain-durable-work",
        "stop-app-and-broker-services","close-all-producer-fence",
        "create-signed-stopped-proof",
        "close-blue-postgres-write-fence","capture-quiescent-source",
        "create-protected-backup","compose-prepare-green",
        "close-green-postgres-write-fence"),
    "activate-read-only":("verify-green-fence-closed",),
    "rollback":("verify-public-admission-closed","compose-stop-green",
        "verify-blue-fence-closed","verify-green-fence-closed",
        "verify-producer-fence-closed"),
    "commit":(),
    "finalize":("compose-stop-green","verify-green-services-stopped",
        "create-signed-restore-stopped-proof",
        "restore-green-postgres-fence","compose-start-green-finalize",
        "verify-green-finalize-health"),
    "publish-active":("verify-green-publishing-pointer","compose-stop-green","verify-green-services-stopped",
        "create-signed-restore-stopped-proof","verify-blue-fence-closed",
        "verify-green-fence-open","reopen-green-producer-fence",
        "compose-start-green-active","verify-green-active-health"),
}
CERTIFY_ROLLBACK_ACTIONS=("verify-public-admission-closed",
    "compose-stop-blue","compose-stop-green","verify-green-services-stopped",
    "create-signed-restore-stopped-proof",
    "restore-blue-postgres-write-fence","verify-blue-fence-open",
    "verify-green-fence-closed","reopen-blue-producer-fence",
    "compose-start-blue","verify-blue-health")
ALLOWED_ACTIONS=frozenset(action for values in ACTION_BY_OBSERVATION.values()
                          for action in values.values()) | frozenset(
    action for values in PRECONDITION_ACTIONS.values() for action in values) \
    | frozenset(CERTIFY_ROLLBACK_ACTIONS) | frozenset(FINALIZE_V3_ACTIONS.values()) \
    | frozenset({"verify-postgres-fence-closed"})
FRESH_BEFORE_DEPENDENT_EFFECT=frozenset({
    "verify-public-admission-closed","verify-green-services-stopped",
    "create-signed-stopped-proof","create-signed-restore-stopped-proof",
    "verify-postgres-fence-closed","verify-blue-fence-closed",
    "verify-green-fence-closed","verify-green-fence-open",
    "verify-producer-fence-closed","verify-green-publishing-pointer"})
FRESH_OBSERVATION_ACTIONS=frozenset({"verify-tunnel-stopped",
    "verify-green-fence-closed","verify-blue-fence-closed",
    "verify-producer-fence-closed","verify-green-gate-closed",
    "verify-green-authority-prepared","verify-green-authority-selected",
    "verify-green-publishing-pointer"})
FIXED_CORE_ACTIONS=frozenset({"verify-owner-authorization",
                              "publish-green-write-gate"})


class MacPilotHostAdapter:
    """Crash-reconciling adapter over fixed host actions and gate publisher."""
    def __init__(self,attempts_root: Path,runner: FixedMacPilotRunner,
                 rollback_publisher: DurableRollbackGatePublisher,*,
                 active_gate_publisher: DurableRollbackGatePublisher|None=None,
                 _test_owner_uid: int | None=None,
                 _qualification_fault_hook=None):
        self.root=Path(attempts_root); self.runner=runner
        self.rollback_publisher=rollback_publisher
        self.active_gate_publisher=active_gate_publisher or rollback_publisher
        if _qualification_fault_hook is not None and not callable(
                _qualification_fault_hook):
            raise MacPilotHostAdapterError("qualification fault hook is invalid")
        self.qualification_fault_hook=_qualification_fault_hook
        owner=0 if _test_owner_uid is None else _test_owner_uid
        if _test_owner_uid is None and os.geteuid()!=0:
            raise MacPilotHostAdapterError("host adapter requires root")
        current=self.root.parent
        while True:
            metadata=os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid not in (0,owner) \
                    or metadata.st_mode&(stat.S_IWGRP|stat.S_IWOTH) \
                    and not metadata.st_mode&stat.S_ISVTX:
                raise MacPilotHostAdapterError("host-adapter ancestry is unsafe")
            if current.parent==current: break
            current=current.parent
        if not hasattr(runner,"perform") or not hasattr(runner,"seal_execution_contract") \
                or not self.root.is_absolute() \
                or self.root.is_symlink() or not self.root.is_dir() \
                or self.root.resolve(strict=True)!=self.root \
                or self.root.stat().st_uid!=owner \
                or stat.S_IMODE(self.root.stat().st_mode)!=0o700:
            raise MacPilotHostAdapterError("host-adapter attempt root is unsafe")
        self.owner=owner
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        opened=os.fstat(self.fd)
        if not stat.S_ISDIR(opened.st_mode) or opened.st_uid!=owner \
                or stat.S_IMODE(opened.st_mode)!=0o700:
            os.close(self.fd); raise MacPilotHostAdapterError(
                "opened host-adapter attempt root is unsafe")

    def _qualification_fault(self,seam):
        allowed={"publish-active-producer-effect-persisted",
                 "publish-active-gate-persisted",
                 "certify-rollback-producer-effect-persisted",
                 "certify-rollback-gate-persisted"}
        if seam not in allowed:raise MacPilotHostAdapterError(
            "qualification fault seam is invalid")
        if self.qualification_fault_hook is not None:self.qualification_fault_hook(seam)

    def _read(self,name: str) -> dict | None:
        if self.fd is None: raise MacPilotHostAdapterError("host adapter is closed")
        try: descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
        except FileNotFoundError: return None
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode)!=0o600 \
                    or not 1<=metadata.st_size<=1024*1024:
                raise MacPilotHostAdapterError("host-adapter attempt is unsafe")
            chunks=[]; remaining=1024*1024+1
            while remaining:
                chunk=os.read(descriptor,min(65536,remaining))
                if not chunk: break
                chunks.append(chunk); remaining-=len(chunk)
            if remaining==0: raise MacPilotHostAdapterError(
                "host-adapter attempt is oversized")
            raw=b"".join(chunks)
        finally: os.close(descriptor)
        value=json.loads(raw.decode())
        if not isinstance(value,dict) or raw!=canonical(value):
            raise MacPilotHostAdapterError("host-adapter attempt is invalid")
        return value

    def _write(self,name: str,value: dict) -> None:
        if self.fd is None: raise MacPilotHostAdapterError("host adapter is closed")
        temporary=f".{name}.{uuid.uuid4().hex}.tmp"; payload=canonical(value)
        descriptor=None
        try:
            descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                               0o600,dir_fd=self.fd)
            offset=0
            while offset<len(payload):
                written=os.write(descriptor,payload[offset:])
                if written<1: raise OSError("host-adapter write made no progress")
                offset+=written
            os.fsync(descriptor); os.close(descriptor); descriptor=None
            os.rename(temporary,name,src_dir_fd=self.fd,dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            if descriptor is not None: os.close(descriptor)
            try: os.unlink(temporary,dir_fd=self.fd)
            except FileNotFoundError: pass

    def close(self):
        if self.fd is not None: os.close(self.fd); self.fd=None

    def execute_or_reconcile(self,command: str,context: dict) -> PhaseResult:
        if self.fd is None: raise MacPilotHostAdapterError("host adapter is closed")
        if command=="certify-rollback":
            operation=context.get("operationKey"); contract=context.get("contract")
            if not isinstance(operation,str) or SHA.fullmatch(operation) is None \
                    or not isinstance(contract,dict):
                raise MacPilotHostAdapterError("rollback certification context is invalid")
            protected=self._read("sealed-execution-contract.json")
            if protected!=contract or digest({key:value for key,value in contract.items()
                if key!="executionContractSha256"}) \
                    != contract.get("executionContractSha256"):
                raise MacPilotHostAdapterError("protected execution contract differs")
            lock=os.open("adapter.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,
                         dir_fd=self.fd)
            try:
                fcntl.flock(lock,fcntl.LOCK_EX)
                name=f"certify-{operation}.json"
                attempt=self._read(name) or {"format":"openepm-macos-certify-attempt-v1",
                    "operationKey":operation,"preconditions":{}}
                for index,action in enumerate(CERTIFY_ROLLBACK_ACTIONS):
                    remaining=any(item not in attempt["preconditions"]
                                  for item in CERTIFY_ROLLBACK_ACTIONS[index+1:])
                    if action in attempt["preconditions"] and not (
                            remaining and action in FRESH_BEFORE_DEPENDENT_EFFECT):continue
                    evidence=self.runner.perform(action,operation,contract)
                    if not isinstance(evidence,str) or SHA.fullmatch(evidence) is None:
                        raise MacPilotHostAdapterError(
                            "rollback certification evidence is invalid")
                    attempt["preconditions"][action]=evidence; self._write(name,attempt)
                    if action=="reopen-blue-producer-fence":
                        self._qualification_fault(
                            "certify-rollback-producer-effect-persisted")
                gate_evidence={
                    "blueDatabaseOpenSha256":attempt["preconditions"].get(
                        "verify-blue-fence-open"),
                    "greenDatabaseClosedSha256":attempt["preconditions"].get(
                        "verify-green-fence-closed"),
                    "blueProducerOpenSha256":attempt["preconditions"].get(
                        "reopen-blue-producer-fence"),
                    "blueServiceHealthSha256":attempt["preconditions"].get(
                        "verify-blue-health")}
                published=self.rollback_publisher.execute_or_reconcile(command,
                    {**context,"gateEvidence":gate_evidence})
                self._qualification_fault("certify-rollback-gate-persisted")
                producer_open=attempt["preconditions"].get(
                    "reopen-blue-producer-fence")
                if not isinstance(published,PhaseResult) \
                        or published.operation_key!=operation \
                        or not isinstance(published.observations,dict) \
                        or SHA.fullmatch(str(producer_open)) is None:
                    raise MacPilotHostAdapterError(
                        "rollback certification publication is invalid")
                return PhaseResult(published.operation_key,
                    {**published.observations,
                     "producerFenceOpened":producer_open},
                    published.execution_contract,published.authority)
            finally:
                fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
        if command=="resume-public":
            operation=context.get("operationKey");contract=context.get("contract")
            completion=context.get("completion");slot=context.get("slot")
            pointer=context.get("pointer")
            if SHA.fullmatch(str(operation)) is None or not isinstance(contract,dict) \
                    or not isinstance(completion,dict) \
                    or completion.get("recordSha256")!=operation \
                    or (slot,completion.get("state")) not in (("blue","rolled-back"),
                                                              ("green","active")):
                raise MacPilotHostAdapterError("public resume context is invalid")
            if contract.get("format")=="openepm-macos-pilot-activation-execution-contract-v3":
                expected_state="rolled-back" if slot=="blue" else "active"
                if not isinstance(pointer,dict) or pointer.get("format") \
                        !="openepm-macos-pilot-active-slot-v3" \
                        or pointer.get("slot")!=slot \
                        or pointer.get("authorityState")!=expected_state \
                        or pointer.get("activationEventSha256")!=operation \
                        or pointer.get("executionContractSha256")!=contract.get(
                            "executionContractSha256") \
                        or pointer.get("writesAdmitted") is not True \
                        or pointer.get("publicIngressPermitted") is not True \
                        or pointer.get("pointerSha256")!=digest({key:value for key,value
                            in pointer.items() if key!="pointerSha256"}):
                    raise MacPilotHostAdapterError("active pointer is not certified")
            protected=self._read("sealed-execution-contract.json")
            if protected!=contract:raise MacPilotHostAdapterError(
                "protected execution contract differs")
            request=digest({"command":"resume-public","operationKey":operation,
                "executionContractSha256":contract.get("executionContractSha256"),
                "slot":slot,"pointerSha256":pointer.get("pointerSha256")
                    if isinstance(pointer,dict) else None})
            lock=os.open("adapter.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,
                         dir_fd=self.fd)
            try:
                fcntl.flock(lock,fcntl.LOCK_EX);name=f"resume-{operation}.json"
                attempt=self._read(name) or {
                    "format":"openepm-macos-resume-public-attempt-v1",
                    "operationKey":operation,"requestSha256":request,
                    "observations":{}}
                if attempt.get("requestSha256")!=request \
                        or attempt.get("operationKey")!=operation:
                    raise MacPilotHostAdapterError("public resume replay differs")
                for observation,action in (("publicResumed","resume-public-tunnel"),
                        ("publicVerified","verify-public-green" if slot=="green"
                         else "verify-blue-health")):
                    if observation not in attempt["observations"]:
                        evidence=self.runner.perform(action,operation,contract)
                        if SHA.fullmatch(str(evidence)) is None:
                            raise MacPilotHostAdapterError(
                                "public resume evidence is invalid")
                        attempt["observations"][observation]=evidence
                        self._write(name,attempt)
                return PhaseResult(operation,dict(attempt["observations"]))
            finally:
                fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
        if command not in ACTION_BY_OBSERVATION or not isinstance(context,dict):
            raise MacPilotHostAdapterError("host-adapter command is not allowlisted")
        operation=context.get("operationKey"); intent=context.get("intent")
        contract=context.get("contract")
        if not isinstance(operation,str) or SHA.fullmatch(operation) is None \
                or not isinstance(intent,dict) or intent.get("recordSha256")!=operation \
                or not isinstance(contract,dict):
            raise MacPilotHostAdapterError("host-adapter context is invalid")
        if command=="prepare":
            # The bootstrap authority is read before the first host effect.  The
            # empty fixed-core placeholder is not allowed to select a different
            # contract after the host has already been mutated.
            sealed=self.runner.seal_execution_contract(operation)
            claimed=sealed.get("executionContractSha256") \
                if isinstance(sealed,dict) else None
            if not isinstance(claimed,str) or SHA.fullmatch(claimed) is None \
                    or digest({key:value for key,value in sealed.items()
                               if key!="executionContractSha256"})!=claimed:
                raise MacPilotHostAdapterError("bootstrap contract digest is invalid")
            if contract and contract!=sealed:
                raise MacPilotHostAdapterError("bootstrap contract differs from request")
            contract=sealed
        else:
            protected=self._read("sealed-execution-contract.json")
            claimed=contract.get("executionContractSha256")
            if protected is None or protected!=contract \
                    or not isinstance(claimed,str) or SHA.fullmatch(claimed) is None \
                    or digest({key:value for key,value in contract.items()
                               if key!="executionContractSha256"})!=claimed:
                raise MacPilotHostAdapterError("protected execution contract differs")
        request=digest({"command":command,"operationKey":operation,
            "activationId":contract.get("activationId"),
            "contractSha256":digest(contract),
            "ownerAuthorizationSha256":context.get("ownerAuthorizationSha256")})
        name=f"{operation}.json"; lock=os.open("adapter.lock",os.O_RDWR|os.O_CREAT
            |os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        try:
            lock_metadata=os.fstat(lock)
            if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_nlink!=1 \
                    or lock_metadata.st_uid!=self.owner \
                    or stat.S_IMODE(lock_metadata.st_mode)!=0o600:
                raise MacPilotHostAdapterError("host-adapter lock is unsafe")
            fcntl.flock(lock,fcntl.LOCK_EX); attempt=self._read(name)
            if attempt is None:
                attempt={"format":"openepm-macos-host-attempt-v1",
                    "operationKey":operation,"requestSha256":request,"command":command,
                    "preconditions":{},"observations":{},
                    "executionContract":contract if command=="prepare" else None}
            if attempt.get("requestSha256")!=request or attempt.get("command")!=command:
                raise MacPilotHostAdapterError("host-adapter operation replay differs")
            preconditions=attempt["preconditions"]
            ordered=PRECONDITION_ACTIONS[command]
            for index,action in enumerate(ordered):
                remaining=any(item not in preconditions for item in ordered[index+1:])
                if action in preconditions and not (
                        remaining and action in FRESH_BEFORE_DEPENDENT_EFFECT): continue
                evidence=self.runner.perform(action,operation,contract)
                if not isinstance(evidence,str) or SHA.fullmatch(evidence) is None:
                    raise MacPilotHostAdapterError("host precondition evidence is invalid")
                preconditions[action]=evidence; self._write(name,attempt)
                if command=="publish-active" \
                        and action=="reopen-green-producer-fence":
                    self._qualification_fault(
                        "publish-active-producer-effect-persisted")
            observations=attempt["observations"]
            action_map=(FINALIZE_V3_ACTIONS if command=="finalize" and
                contract.get("format")=="openepm-macos-pilot-activation-execution-contract-v3"
                else ACTION_BY_OBSERVATION[command])
            ordered_observations=list(action_map.items())
            for index,(observation,action) in enumerate(ordered_observations):
                if action not in ALLOWED_ACTIONS:
                    raise MacPilotHostAdapterError("host-adapter action is not allowlisted")
                later_unfinished=any(name not in observations for name,_
                                     in ordered_observations[index+1:])
                if observation in observations and not (
                        later_unfinished and action in FRESH_OBSERVATION_ACTIONS):continue
                if command=="commit" and observation=="ownerAuthorized":
                    evidence=context.get("ownerAuthorizationSha256")
                elif command=="publish-active" and observation=="signedGreenGateReadBack":
                    published=self.active_gate_publisher.execute_or_reconcile(
                        "publish-active",{**context,"gateEvidence":{
                            "blueDatabaseClosedSha256":preconditions.get(
                                "verify-blue-fence-closed"),
                            "greenDatabaseOpenSha256":preconditions.get(
                                "verify-green-fence-open"),
                            "greenProducerOpenSha256":preconditions.get(
                                "reopen-green-producer-fence"),
                            "greenServiceHealthSha256":preconditions.get(
                                "verify-green-active-health")}})
                    self._qualification_fault("publish-active-gate-persisted")
                    evidence=published.observations.get("signedGreenGateReadBack")
                else:
                    evidence=self.runner.perform(action,operation,contract)
                if not isinstance(evidence,str) or SHA.fullmatch(evidence) is None:
                    raise MacPilotHostAdapterError("host action evidence is invalid")
                observations[observation]=evidence; self._write(name,attempt)
            if command=="prepare":
                if attempt.get("executionContract")!=contract:
                    raise MacPilotHostAdapterError("prepared contract changed during execution")
                protected=self._read("sealed-execution-contract.json")
                if protected is None:self._write("sealed-execution-contract.json",contract)
                elif protected!=contract:
                    raise MacPilotHostAdapterError("protected execution contract differs")
            prepared_contract=attempt["executionContract"] if command=="prepare" else None
            if command=="prepare" and not isinstance(prepared_contract,dict):
                raise MacPilotHostAdapterError("prepared contract is invalid")
            return PhaseResult(operation,dict(observations),prepared_contract)
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
