#!/usr/bin/env python3
"""Fixed host-side orchestration boundary for Mac-pilot activation.

This module deliberately has no subprocess, Docker, launchctl, Cloudflare,
network or database implementation.  A separately qualified host adapter must
implement the exact ``execute_or_reconcile`` interface.  The orchestrator
durably records intent before invoking that adapter and accepts effects only
through authenticated receipts and the secure activation state service.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

if __package__:
    from .macos_pilot_secure_activation import (
        SecureActivationError, SecureActivationService, canonical, digest)
    from .validate_macos_pilot_activation_receipt import (OBSERVATIONS,
        observations_for,_runtime_bindings)
else:
    from macos_pilot_secure_activation import (
        SecureActivationError, SecureActivationService, canonical, digest)
    from validate_macos_pilot_activation_receipt import (OBSERVATIONS,
        observations_for,_runtime_bindings)


class ActivationExecutionError(RuntimeError):
    pass


@dataclass(frozen=True)
class PhaseResult:
    operation_key: str
    observations: dict[str, str]
    execution_contract: dict | None = None
    authority: dict | None = None


class HostAdapter(Protocol):
    """Intent-keyed durable effect adapter with no generic shell surface.

    ``context['operationKey']`` is the immutable intent-event digest for a
    mutation phase, or ``rollback-publication:<completion digest>`` for the
    bounded post-certification blue-gate transition.
    Before mutating, an implementation must look up that key in its protected
    attempt journal. A completed attempt returns its original evidence; an
    incomplete attempt observes and reconciles reality before retrying. The
    same key must never apply an external effect twice.
    """

    def execute_or_reconcile(self, command: str, context: dict) -> PhaseResult:
        ...


class RollbackGateReader(Protocol):
    """Read-only capability; deliberately exposes no publication operation."""
    def read(self) -> dict:
        ...


class PublicAdmissionAuthorityPublisher(Protocol):
    def publish(self,*,phase:str,operation_key:str,contract:dict,
                completion:dict|None=None,executor_evidence:dict|None=None)->dict: ...


class ProtectedRollbackGateReader:
    """Open one durable signed gate artifact through a pinned read-only fd."""
    FILENAME="rollback-write-gate.json"

    def __init__(self, authority_root: Path, *,
                 _test_authority_owner_uid: int | None=None,
                 _test_runtime_uid: int | None=None):
        root=Path(authority_root)
        runtime_uid=os.geteuid() if _test_runtime_uid is None else _test_runtime_uid
        authority_owner_uid=0 if _test_authority_owner_uid is None \
            else _test_authority_owner_uid
        if _test_runtime_uid is None and runtime_uid==0:
            raise ActivationExecutionError("rollback gate reader runtime must be non-root")
        if not root.is_absolute() or root.is_symlink() \
                or not root.is_dir() or root.resolve(strict=True)!=root \
                or root.stat().st_uid!=authority_owner_uid \
                or stat.S_IMODE(root.stat().st_mode) not in (0o500,0o555):
            raise ActivationExecutionError("rollback gate authority directory is unsafe")
        flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0) \
            | getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
        descriptor=None
        try:
            descriptor=os.open(root,flags)
            metadata=os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=authority_owner_uid \
                    or stat.S_IMODE(metadata.st_mode) not in (0o500,0o555):
                raise ActivationExecutionError(
                    "rollback gate opened authority directory is unsafe")
            self._directory_fd=descriptor; descriptor=None
        finally:
            if descriptor is not None: os.close(descriptor)
        self._owner_uid=authority_owner_uid

    def read(self) -> dict:
        if self._directory_fd is None:
            raise ActivationExecutionError("rollback gate reader is closed")
        directory=os.fstat(self._directory_fd)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=self._owner_uid \
                or stat.S_IMODE(directory.st_mode) not in (0o500,0o555):
            raise ActivationExecutionError("rollback gate authority changed")
        flags=os.O_RDONLY|getattr(os,"O_CLOEXEC",0)|getattr(os,"O_NOFOLLOW",0)
        descriptor=os.open(self.FILENAME,flags,dir_fd=self._directory_fd)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self._owner_uid \
                    or stat.S_IMODE(metadata.st_mode) not in (0o400,0o444) \
                    or not 1<=metadata.st_size<=65536:
                raise ActivationExecutionError("rollback gate artifact is unsafe")
            raw=os.read(descriptor,65537)
        finally:
            os.close(descriptor)
        try: value=json.loads(raw.decode("utf-8"))
        except (UnicodeError,json.JSONDecodeError) as error:
            raise ActivationExecutionError("rollback gate artifact is invalid") from error
        if not isinstance(value,dict) or raw!=canonical(value):
            raise ActivationExecutionError("rollback gate artifact is not canonical")
        return value

    def close(self) -> None:
        if self._directory_fd is not None:
            os.close(self._directory_fd); self._directory_fd=None

class ProtectedActiveGateReader(ProtectedRollbackGateReader):
    """Independent read-only green gate capability."""
    FILENAME="green-write-gate.json"


class OwnerAuthorizer(Protocol):
    """Owner signing remains a separate boundary from executor signing."""

    def authorize(self, contract: dict, commit_intent: dict,
                  read_only_completion: dict) -> dict:
        ...


class ExecutorSigner:
    """In-memory signing boundary; production key loading is intentionally absent."""

    def __init__(self, key_id: str, version: int, private_key: Ed25519PrivateKey,
                 parent_assembly_sha256: str | None = None):
        if not isinstance(key_id, str) or not key_id \
                or not isinstance(version, int) or isinstance(version, bool) \
                or version < 1 or not isinstance(private_key, Ed25519PrivateKey):
            raise ActivationExecutionError("executor signer identity is invalid")
        self._key_id=key_id; self._version=version; self._private_key=private_key
        self._parent_assembly_sha256=parent_assembly_sha256

    def journal_evidence(self,records:list[dict],intent:dict,contract:dict,
                         staged_pointer:dict|None=None,
                         authority_pointer:tuple[str,dict]|None=None)->dict|None:
        if self._parent_assembly_sha256 is None:return None
        activation=intent.get("activationId");plan=intent.get("planSha256")
        contract_sha=contract.get("executionContractSha256") if contract else None
        snapshot={"format":"openepm-macos-pilot-secure-journal-snapshot-v1",
            "planSha256":plan,"activationId":activation,
            "executionContractSha256":contract_sha,"records":records}
        snapshot["snapshotSha256"]=digest(snapshot)
        body={"format":("openepm-macos-pilot-executor-journal-evidence-v3"
                        if authority_pointer is not None else
                        "openepm-macos-pilot-executor-journal-evidence-v2"
                        if staged_pointer is not None else
                        "openepm-macos-pilot-executor-journal-evidence-v1"),
            "parentAssemblySha256":self._parent_assembly_sha256,
            "activationId":activation,"planSha256":plan,
            "executionContractSha256":contract_sha,
            "operationKey":intent.get("recordSha256"),"journal":snapshot,
            "executorKeyId":self._key_id,"executorKeyVersion":self._version}
        if staged_pointer is not None:
            body["stagedPointer"]=staged_pointer
            body["stagedPointerSha256"]=staged_pointer.get("pointerSha256") \
                if isinstance(staged_pointer,dict) else None
        if authority_pointer is not None:
            purpose,pointer=authority_pointer
            body["authorityPointerPurpose"]=purpose
            body["authorityPointer"]=pointer
            body["authorityPointerSha256"]=pointer.get("pointerSha256") \
                if isinstance(pointer,dict) else None
        sealed={**body,"evidenceSha256":digest(body)}
        return {**sealed,"signature":{"algorithm":"Ed25519",
            "keyId":self._key_id,"valueBase64":base64.b64encode(
             self._private_key.sign(canonical(sealed))).decode("ascii")}}

    def receipt(self, contract: dict, intent: dict,
                observations: dict[str, str]) -> dict:
        command=intent.get("command")
        verifier=contract.get("executorVerifier")
        expected=set(observations_for(contract,command))
        if not isinstance(verifier,dict) \
                or verifier.get("algorithm") != "Ed25519" \
                or verifier.get("keyId") != self._key_id \
                or verifier.get("version") != self._version:
            raise ActivationExecutionError("executor signer differs from sealed contract")
        if set(observations) != expected \
                or any(not isinstance(value,str) or len(value)!=64
                       or any(character not in "0123456789abcdef" for character in value)
                       for value in observations.values()):
            raise ActivationExecutionError("phase observations are incomplete or invalid")
        body={"format":"openepm-macos-pilot-executor-receipt-v1",
            "activationId":contract["activationId"],"command":command,
            "intentEventSha256":intent["recordSha256"],
            "dryPlanSha256":contract["dryPlanSha256"],
            "executionContractSha256":contract["executionContractSha256"],
            "executorKeyId":self._key_id,
            "runtimeBindings":_runtime_bindings(contract,command),
            "observations":{name:{"passed":True,"evidenceSha256":observations[name]}
                            for name in observations_for(contract,command)},
            "outcome":"passed"}
        receipt_sha=digest(body)
        signed={**body,"receiptSha256":receipt_sha}
        signed["signature"]={"algorithm":"Ed25519","keyId":self._key_id,
            "valueBase64":base64.b64encode(
                self._private_key.sign(canonical(signed))).decode("ascii")}
        return signed


class ActivationExecutor:
    """Sequence durable state around one fixed, independently qualified adapter."""

    QUALIFICATION_FAULT_SEAMS=frozenset({
        "certify-rollback-root-response","publish-active-root-response",
        "certify-rollback-admission-response","publish-active-admission-response",
        "certify-rollback-resume-response","publish-active-resume-response"})

    def __init__(self, service: SecureActivationService,
                 adapter: HostAdapter, signer: ExecutorSigner,
                 rollback_gate_reader: RollbackGateReader,
                 admission_open_publisher:PublicAdmissionAuthorityPublisher|None=None,
                 active_gate_reader:RollbackGateReader|None=None,
                 _qualification_fault_hook=None):
        if not isinstance(service,SecureActivationService) \
                or not hasattr(adapter,"execute_or_reconcile") \
                or not isinstance(signer,ExecutorSigner) \
                or not hasattr(rollback_gate_reader,"read") \
                or (admission_open_publisher is not None and not hasattr(
                    admission_open_publisher,"publish")) \
                or (active_gate_reader is not None and not hasattr(active_gate_reader,"read")):
            raise ActivationExecutionError("activation executor dependency is invalid")
        if _qualification_fault_hook is not None and not callable(
                _qualification_fault_hook):
            raise ActivationExecutionError("qualification fault hook is invalid")
        self._service=service; self._adapter=adapter; self._signer=signer
        self._rollback_gate_reader=rollback_gate_reader
        self._admission_open_publisher=admission_open_publisher
        self._active_gate_reader=active_gate_reader
        self._qualification_fault_hook=_qualification_fault_hook

    def _qualification_fault(self,seam:str)->None:
        if seam not in self.QUALIFICATION_FAULT_SEAMS:
            raise ActivationExecutionError("qualification fault seam is invalid")
        if self._qualification_fault_hook is not None:
            self._qualification_fault_hook(seam)

    def _records(self) -> list[dict]:
        with self._service._store._lock():
            return self._service._store.load()

    def _contract(self) -> dict:
        with self._service._store._lock():
            return self._service._contract()

    @staticmethod
    def _completion(records: list[dict], request_key: str,
                    command: str, state: str) -> dict | None:
        matches=[record for record in records if record.get("requestKey")==request_key]
        if not matches:
            return None
        if len(matches)!=1 or matches[0].get("eventKind")!="completion" \
                or matches[0].get("command")!=command \
                or matches[0].get("state")!=state:
            raise ActivationExecutionError("completion request key is already occupied")
        return matches[0]

    def _recover(self, command: str, intent: dict, error: BaseException) -> None:
        # Before finalization every external action is keyed by the durable
        # intent and remains safely reconcilable. Leaving that intent current
        # permits an exact retry after process loss or transient host failure.
        # Finalization is different: its effects may cross the point of no
        # return, so ambiguity is recorded and may only reconcile forward.
        if command != "finalize":
            return
        observation=digest({"command":command,
            "intentEventSha256":intent["recordSha256"],
            "failureClass":type(error).__name__})
        try:
            self._service.recovery_required(
                request_key=f"recovery:{intent['recordSha256']}",
                observation_sha256=observation)
        except Exception as recovery_error:
            raise ActivationExecutionError(
                "phase failed and durable recovery recording also failed") from recovery_error

    def _execute(self, command: str, intent: dict, contract: dict,
                 extra_context: dict | None = None) -> PhaseResult:
        try:
            staged_pointer=(self._service.staged_green_pointer_for_commit(intent)
                            if command=="commit" else None)
            authority_pointer=(self._service.authority_pointer_for_intent(intent)
                               if command in ("finalize","publish-active") else None)
            evidence=self._signer.journal_evidence(self._records(),intent,contract,
                                                    staged_pointer,authority_pointer)
            result=self._adapter.execute_or_reconcile(command,{
                "operationKey":intent["recordSha256"],
                "intent":intent,"contract":contract,
                **({"executorEvidence":evidence} if evidence is not None else {}),
                **(extra_context or {})})
            if not isinstance(result,PhaseResult) \
                    or result.operation_key != intent["recordSha256"]:
                raise ActivationExecutionError("host adapter returned an invalid result")
            return result
        except Exception as error:
            self._recover(command,intent,error)
            raise ActivationExecutionError(
                f"{command} did not produce a certifiable result") from error

    def _certify_rollback_publication(self, completion: dict,
                                      contract: dict, now_utc: str) -> dict:
        """Open the blue gate only after the rollback receipt is certified."""
        intent=self._service.begin(command="certify-rollback",
            request_key="rollback-publication:intent:"+completion["recordSha256"],
            evidence_sha256=completion["recordSha256"])
        completion_key="rollback-publication:complete:"+completion["recordSha256"]
        completed=self._completion(self._records(),completion_key,
                                   "certify-rollback","rolled-back")
        if completed is None:
            try:
                context={
                    "operationKey":intent["recordSha256"],"intent":intent,
                    "completion":completion,
                    "contract":contract}
                evidence=self._signer.journal_evidence(self._records(),intent,contract,
                    None,self._service.authority_pointer_for_intent(intent))
                if evidence is not None:context["executorEvidence"]=evidence
                result=self._adapter.execute_or_reconcile("certify-rollback",context)
                self._qualification_fault("certify-rollback-root-response")
            except Exception as error:
                raise ActivationExecutionError(
                    "certified rollback gate publication did not complete") from error
            if not isinstance(result,PhaseResult) \
                    or result.operation_key!=intent["recordSha256"]:
                raise ActivationExecutionError(
                    "certified rollback gate publication result is invalid")
        try:
            if completed is None:
                durable_authority=self._rollback_gate_reader.read()
                attestation_sha=self._service.validate_rollback_gate_attestation(
                    durable_authority,intent=intent,
                    rollback_completion=completion,now_utc=now_utc)
                if result.observations.get("signedBlueGateReadBack") \
                        != attestation_sha:
                    raise ActivationExecutionError(
                        "rollback gate readback evidence differs")
                receipt=self._signer.receipt(contract,intent,result.observations)
                completed=self._service.complete(
                    request_key=completion_key,receipt=receipt,now_utc=now_utc)
            active_pointer=self._service.publish_pointer()
            if contract.get("format").endswith("-v3"):
                if self._admission_open_publisher is None:
                    raise ActivationExecutionError(
                        "public-admission authority publisher is unavailable")
                self._admission_open_publisher.publish(
                    phase="certify-rollback",
                    operation_key=completed["recordSha256"],contract=contract,
                    completion=completed,executor_evidence=self._signer.journal_evidence(
                        self._records(),completed,contract,None,
                        self._service.public_pointer_for_completion(completed)))
                self._qualification_fault("certify-rollback-admission-response")
                resume_context={
                    "operationKey":completed["recordSha256"],"completion":completed,
                    "contract":contract,"slot":"blue","pointer":active_pointer}
                evidence=self._signer.journal_evidence(self._records(),completed,contract)
                if evidence is not None:resume_context["executorEvidence"]=evidence
                self._adapter.execute_or_reconcile("resume-public",resume_context)
                self._qualification_fault("certify-rollback-resume-response")
            return completed
        except Exception as error:
            raise ActivationExecutionError(
                "rollback gate publication did not pass certification") from error

    def _publish_active(self,finalized:dict,contract:dict,now_utc:str)->dict:
        self._service.publish_pointer()
        intent=self._service.begin(command="publish-active",
            request_key="active-publication:intent:"+finalized["recordSha256"],
            evidence_sha256=finalized["recordSha256"])
        completion_key="active-publication:complete:"+finalized["recordSha256"]
        active=self._completion(self._records(),completion_key,
                                "publish-active","active")
        if active is None:
            self._service.publish_pointer()
            result=self._execute("publish-active",intent,contract,
                {"finalizeCompletion":finalized})
            self._qualification_fault("publish-active-root-response")
            if self._active_gate_reader is not None:
                authority=self._active_gate_reader.read()
                evidence=self._service.validate_active_gate_attestation(authority,
                    intent=intent,finalized_completion=finalized,
                    now_utc=now_utc)
                if result.observations.get("signedGreenGateReadBack")!=evidence:
                    raise ActivationExecutionError("active gate readback evidence differs")
            receipt=self._signer.receipt(contract,intent,result.observations)
            active=self._service.complete(request_key=completion_key,
                receipt=receipt,now_utc=now_utc)
        active_pointer=self._service.publish_pointer()
        if self._admission_open_publisher is None:
            raise ActivationExecutionError(
                "public-admission authority publisher is unavailable")
        self._admission_open_publisher.publish(phase="certify-active",
            operation_key=active["recordSha256"],contract=contract,
            completion=active,executor_evidence=self._signer.journal_evidence(
                self._records(),active,contract,None,
                self._service.public_pointer_for_completion(active)))
        self._qualification_fault("publish-active-admission-response")
        resume_context={
            "operationKey":active["recordSha256"],"completion":active,
            "contract":contract,"slot":"green","pointer":active_pointer}
        evidence=self._signer.journal_evidence(self._records(),active,contract)
        if evidence is not None:resume_context["executorEvidence"]=evidence
        self._adapter.execute_or_reconcile("resume-public",resume_context)
        self._qualification_fault("publish-active-resume-response")
        return active

    def prepare(self, plan: dict, *, activation_id: str,
                intent_request_key: str, completion_request_key: str,
                intent_evidence_sha256: str, now_utc: str) -> dict:
        intent=self._service.begin_prepare(plan,activation_id=activation_id,
            request_key=intent_request_key,evidence_sha256=intent_evidence_sha256)
        records=self._records()
        existing=self._completion(records,completion_request_key,"prepare","prepared")
        if existing is not None:
            if records[-1].get("state")=="prepared":
                self._service.publish_pointer()
            return existing
        result=self._execute("prepare",intent,{})
        if result.execution_contract is None:
            self._recover("prepare",intent,
                          ActivationExecutionError("adapter omitted execution contract"))
            raise ActivationExecutionError("prepare did not produce a sealed contract")
        try:
            receipt=self._signer.receipt(
                result.execution_contract,intent,result.observations)
            completed=self._service.complete_prepare(result.execution_contract,
                request_key=completion_request_key,receipt=receipt,now_utc=now_utc)
        except Exception as error:
            self._recover("prepare",intent,error)
            raise ActivationExecutionError(
                "prepare result did not pass fixed-core certification") from error
        self._service.publish_pointer()
        return completed

    def phase(self, command: str, *, intent_request_key: str,
              completion_request_key: str, intent_evidence_sha256: str,
              now_utc: str,
              owner_authorizer: OwnerAuthorizer | None = None) -> dict:
        if command not in ("activate-read-only","rollback","commit","finalize"):
            raise ActivationExecutionError("unsupported activation phase")
        if command != "commit" and owner_authorizer is not None:
            raise ActivationExecutionError("owner authorizer is valid only for commit")
        current=self._records()
        if command=="commit" and current and current[-1].get("state")=="read-only" \
                and (owner_authorizer is None
                     or not hasattr(owner_authorizer,"authorize")):
            raise ActivationExecutionError("commit requires owner authorizer")
        if command=="activate-read-only" and current \
                and current[-1].get("state")=="prepared":
            self._service.publish_pointer()
        if command=="finalize" and current \
                and current[-1].get("state")=="committed":
            self._service.publish_pointer()
        intent=self._service.begin(command=command,request_key=intent_request_key,
            evidence_sha256=intent_evidence_sha256)
        if command in ("rollback","finalize") \
                and self._records()[-1]==intent:
            # Publish route selection from the durable intent before host
            # effects. Public ingress is still controlled by the tunnel and
            # the separately signed write-admission authority.
            self._service.publish_pointer()
        target={"activate-read-only":"read-only","rollback":"rolled-back",
                "commit":"committed","finalize":("finalized" if command=="finalize"
                and self._contract().get("format").endswith("-v3") else "active")}[command]
        existing=self._completion(self._records(),completion_request_key,command,target)
        if existing is not None:
            if command=="rollback":
                existing=self._certify_rollback_publication(
                    existing,self._contract(),now_utc)
            if command=="finalize" and self._contract().get(
                    "format","").endswith("-v3"):
                existing=self._publish_active(existing,self._contract(),now_utc)
            if command in ("rollback","commit","finalize"):
                self._service.publish_pointer()
            return existing
        contract=self._contract(); owner_authorization=None; read_only_completion=None
        accepted_owner_authorization=None
        extra_context={}
        if command == "commit":
            read_only_completion=next((record for record in reversed(self._records())
                if record.get("state")=="read-only"
                and record.get("eventKind")=="completion"),None)
            if read_only_completion is None:
                self._recover(command,intent,
                              ActivationExecutionError("read-only completion is absent"))
                raise ActivationExecutionError("commit requires read-only completion")
            accepted_owner_authorization=self._service.owner_authorization(
                intent["recordSha256"])
            if accepted_owner_authorization is None:
                if owner_authorizer is None or not hasattr(owner_authorizer,"authorize"):
                    raise ActivationExecutionError("commit requires owner authorizer")
                try:
                    owner_authorization=owner_authorizer.authorize(
                        contract,intent,read_only_completion)
                except Exception as error:
                    raise ActivationExecutionError("owner authorization failed") from error
                if not isinstance(owner_authorization,dict) \
                        or not isinstance(owner_authorization.get(
                            "authorizationSha256"),str):
                    raise ActivationExecutionError("owner authorization is invalid")
                try:
                    accepted_owner_authorization=\
                        self._service.accept_owner_authorization(
                        intent=intent,read_only_completion=read_only_completion,
                        authorization=owner_authorization,now_utc=now_utc)
                except SecureActivationError as error:
                    raise ActivationExecutionError(
                        "owner authorization did not pass fixed-core validation") from error
            owner_authorization=accepted_owner_authorization["authorization"]
            extra_context={"ownerAuthorizationSha256":
                           owner_authorization["authorizationSha256"]}
        result=self._execute(command,intent,contract,extra_context)
        try:
            receipt=self._signer.receipt(contract,intent,result.observations)
            completed=self._service.complete(request_key=completion_request_key,
                receipt=receipt,now_utc=now_utc,
                owner_authorization=owner_authorization,
                read_only_completion=read_only_completion,
                accepted_owner_authorization=accepted_owner_authorization)
        except Exception as error:
            self._recover(command,intent,error)
            raise ActivationExecutionError(
                f"{command} result did not pass fixed-core certification") from error
        if command=="rollback":
            completed=self._certify_rollback_publication(
                completed,contract,now_utc)
        if command=="finalize" and contract.get("format").endswith("-v3"):
            completed=self._publish_active(completed,contract,now_utc)
        if command in ("rollback","commit","finalize"):
            self._service.publish_pointer()
        return completed

    def reconcile_finalize(self, *, request_key: str, now_utc: str) -> dict:
        records=self._records()
        existing=self._completion(records,request_key,"finalize","active")
        if existing is not None:
            return existing
        recovery=records[-1] if records else None
        if not isinstance(recovery,dict) or recovery.get("state")!="recovery-required":
            raise ActivationExecutionError("finalize reconciliation requires recovery head")
        intent=next((record for record in records
                     if record.get("recordSha256")==recovery.get("intentSha256")),None)
        if intent is None:
            raise ActivationExecutionError("finalize recovery intent is unavailable")
        try:
            self._service.require_staged_green_pointer()
        except SecureActivationError as error:
            raise ActivationExecutionError(
                "finalize recovery requires exact staged green authority") from error
        contract=self._contract()
        result=self._adapter.execute_or_reconcile("finalize",{
            "operationKey":intent["recordSha256"],
            "intent":intent,"contract":contract,"recovery":recovery})
        if not isinstance(result,PhaseResult) \
                or result.operation_key != intent["recordSha256"]:
            raise ActivationExecutionError("host adapter returned an invalid result")
        receipt=self._signer.receipt(contract,intent,result.observations)
        completed=self._service.reconcile_finalize(request_key=request_key,
            receipt=receipt,now_utc=now_utc)
        self._service.publish_pointer()
        return completed
