#!/usr/bin/env python3
"""Bounded production publisher for certified Mac-pilot blue rollback gates."""
from __future__ import annotations

import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
 from execute_macos_pilot_activation import PhaseResult
 from macos_pilot_secure_activation import canonical,digest
except ModuleNotFoundError:
 from scripts.execute_macos_pilot_activation import PhaseResult
 from scripts.macos_pilot_secure_activation import canonical,digest


SHA=re.compile(r"^[0-9a-f]{64}$")


class RollbackGatePublisherError(RuntimeError): pass


class DurableRollbackGatePublisher:
    """Publish/reconcile one signed artifact per immutable operation key."""
    FILENAME="rollback-write-gate.json"
    ACTIVE_FILENAME="green-write-gate.json"

    def __init__(self, authority_root: Path, attempts_root: Path, *,
                 private_key: Ed25519PrivateKey, key_id: str, key_version: int,
                 _test_owner_uid: int | None=None,
                 _test_effective_uid: int | None=None):
        self.authority_root=Path(authority_root)
        self.attempts_root=Path(attempts_root)
        if not isinstance(private_key,Ed25519PrivateKey) or not key_id \
                or not isinstance(key_version,int) or isinstance(key_version,bool) \
                or key_version<1:
            raise RollbackGatePublisherError("rollback publisher signer is invalid")
        self.private_key=private_key; self.key_id=key_id; self.key_version=key_version
        effective_uid=os.geteuid() if _test_effective_uid is None \
            else _test_effective_uid
        owner_uid=0 if _test_owner_uid is None else _test_owner_uid
        if _test_effective_uid is None and effective_uid!=0:
            raise RollbackGatePublisherError("rollback publisher requires root")
        self._owner_uid=owner_uid
        self._directory_fds={}
        for root,label in ((self.authority_root,"authority"),
                           (self.attempts_root,"attempts")):
            current=root.parent
            while True:
                metadata=os.lstat(current)
                if stat.S_ISLNK(metadata.st_mode) \
                        or metadata.st_uid not in (0,owner_uid) \
                        or metadata.st_mode&(stat.S_IWGRP|stat.S_IWOTH) \
                        and not metadata.st_mode&stat.S_ISVTX:
                    raise RollbackGatePublisherError(
                        f"rollback publisher {label} ancestry is unsafe")
                if current.parent==current: break
                current=current.parent
            if not root.is_absolute() or root.is_symlink() or not root.is_dir() \
                    or root.resolve(strict=True)!=root or root.stat().st_uid!=owner_uid \
                    or stat.S_IMODE(root.stat().st_mode) not in (
                        (0o500,0o555,0o700) if label=="authority" else (0o700,)):
                raise RollbackGatePublisherError(
                    f"rollback publisher {label} directory is unsafe")
            flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0)
            descriptor=os.open(root,flags); metadata=os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=owner_uid:
                os.close(descriptor)
                raise RollbackGatePublisherError(
                    f"rollback publisher opened {label} directory is unsafe")
            self._directory_fds[label]=descriptor

    def _directory_fd(self,label: str) -> int:
        descriptor=self._directory_fds[label]; metadata=os.fstat(descriptor)
        expected=(0o500,0o555,0o700) if label=="authority" else (0o700,)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=self._owner_uid \
                or stat.S_IMODE(metadata.st_mode) not in expected:
            raise RollbackGatePublisherError(
                f"rollback publisher {label} directory changed")
        return descriptor

    def _atomic(self,root: Path,name: str,value: dict,mode: int) -> None:
        label="authority" if root==self.authority_root else "attempts"
        directory_fd=self._directory_fd(label)
        original_mode=stat.S_IMODE(os.fstat(directory_fd).st_mode)
        if label=="authority": os.fchmod(directory_fd,0o700)
        payload=canonical(value); temporary=f".{name}.{uuid.uuid4().hex}.tmp"
        descriptor=None
        try:
            descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL
                |os.O_NOFOLLOW,mode,dir_fd=directory_fd)
            offset=0
            while offset<len(payload): offset+=os.write(descriptor,payload[offset:])
            os.fchmod(descriptor,mode); os.fsync(descriptor); os.close(descriptor)
            descriptor=None
            os.rename(temporary,name,src_dir_fd=directory_fd,dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            if descriptor is not None: os.close(descriptor)
            try: os.unlink(temporary,dir_fd=directory_fd)
            except FileNotFoundError: pass
            if label=="authority": os.fchmod(directory_fd,original_mode)

    def _read(self,label: str,name: str,expected_mode: int) -> dict | None:
        directory_fd=self._directory_fd(label)
        try: descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,
                                 dir_fd=directory_fd)
        except FileNotFoundError: return None
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self._owner_uid \
                    or stat.S_IMODE(metadata.st_mode)!=expected_mode \
                    or metadata.st_size>65536:
                raise RollbackGatePublisherError("rollback publisher artifact is unsafe")
            raw=os.read(descriptor,65537)
        finally: os.close(descriptor)
        value=json.loads(raw.decode())
        if not isinstance(value,dict) or raw!=canonical(value):
            raise RollbackGatePublisherError("rollback publisher artifact is invalid")
        return value

    def _authority(self,command: str,context: dict) -> dict:
        contract=context["contract"]; intent=context["intent"]
        if command=="certify-rollback":
            completion=context["completion"]
            body={"format":"openepm-macos-pilot-rollback-gate-attestation-v1",
            "activationId":contract["activationId"],
            "executionContractSha256":contract["executionContractSha256"],
            "slot":"blue","state":"open","authorityState":"rolled-back",
            "rollbackCompletionSha256":completion["recordSha256"],
            "publicationIntentSha256":intent["recordSha256"],
            "keyId":self.key_id,"keyVersion":self.key_version}
            if contract.get("format","").endswith("-v3"):
                body.update(context["gateEvidence"])
        else:
            completion=context["finalizeCompletion"]
            evidence=context["gateEvidence"]
            body={"format":"openepm-macos-pilot-active-gate-attestation-v1",
             "activationId":contract["activationId"],
             "executionContractSha256":contract["executionContractSha256"],
             "slot":"green","state":"open","authorityState":"active",
             "finalizedCompletionSha256":completion["recordSha256"],
             "publicationIntentSha256":intent["recordSha256"],
             **evidence,
             "keyId":self.key_id,"keyVersion":self.key_version}
        signed={**body,"attestationSha256":digest(body)}
        return {**signed,"signature":{"algorithm":"Ed25519","keyId":self.key_id,
            "valueBase64":base64.b64encode(
                self.private_key.sign(canonical(signed))).decode("ascii")}}

    def _after_artifact_published(self) -> None: pass
    def _after_attempt_persisted(self) -> None: pass

    def execute_or_reconcile(self,command: str,context: dict) -> PhaseResult:
        if command not in ("certify-rollback","publish-active") or not isinstance(context,dict):
            raise RollbackGatePublisherError("rollback publisher command is unsupported")
        operation=context.get("operationKey")
        contract=context.get("contract",{})
        completion=(context.get("completion") if command=="certify-rollback"
                    else context.get("finalizeCompletion"))
        expected_intent="publishing-rollback" if command=="certify-rollback" else "publishing-active"
        expected_completion="rolled-back" if command=="certify-rollback" else "finalized"
        evidence=context.get("gateEvidence")
        evidence_fields=({"blueDatabaseOpenSha256","greenDatabaseClosedSha256",
            "blueProducerOpenSha256","blueServiceHealthSha256"}
            if command=="certify-rollback" else
            {"blueDatabaseClosedSha256","greenDatabaseOpenSha256",
             "greenProducerOpenSha256","greenServiceHealthSha256"})
        if not isinstance(operation,str) or SHA.fullmatch(operation) is None \
                or context.get("intent",{}).get("recordSha256")!=operation \
                or context.get("intent",{}).get("state")!=expected_intent \
                or not isinstance(completion,dict) \
                or completion.get("state")!=expected_completion \
                or contract.get("format","").endswith("-v3") and (
                    not isinstance(evidence,dict) or set(evidence)!=evidence_fields \
                    or any(SHA.fullmatch(str(value)) is None
                           for value in evidence.values())):
            raise RollbackGatePublisherError("rollback publisher context is invalid")
        lock=os.open("publisher.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,
                     dir_fd=self._directory_fd("attempts"))
        try:
            metadata=os.fstat(lock)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self._owner_uid \
                    or stat.S_IMODE(metadata.st_mode)!=0o600:
                raise RollbackGatePublisherError("rollback publisher lock is unsafe")
            fcntl.flock(lock,fcntl.LOCK_EX)
            expected=self._authority(command,context)
            attempt=self._read("attempts",f"{command}-{operation}.json",0o600)
            filename=self.FILENAME if command=="certify-rollback" else self.ACTIVE_FILENAME
            shared=stat.S_IMODE(os.fstat(
                self._directory_fd("authority")).st_mode)==0o555
            artifact=self._read("authority",filename,0o444 if shared else 0o400)
            if attempt is not None:
                if attempt.get("operationKey")!=operation \
                        or attempt.get("authority")!=expected or artifact!=expected:
                    raise RollbackGatePublisherError("rollback attempt replay differs")
            else:
                if artifact is not None and artifact!=expected:
                    raise RollbackGatePublisherError("rollback gate already differs")
                if artifact is None:
                    self._atomic(self.authority_root,filename,expected,
                                 0o444 if shared else 0o400)
                    self._after_artifact_published()
                attempt={"format":"openepm-slot-gate-attempt-v1",
                    "command":command,"operationKey":operation,"authority":expected}
                self._atomic(self.attempts_root,f"{command}-{operation}.json",attempt,0o600)
                self._after_attempt_persisted()
            observation="signedBlueGateReadBack" if command=="certify-rollback" \
                else "signedGreenGateReadBack"
            return PhaseResult(operation,{observation:digest(expected)},
                               None,expected)
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)
