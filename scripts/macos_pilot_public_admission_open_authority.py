#!/usr/bin/env python3
"""Publish and read short-lived authority for reopening public admission.

The publisher accepts no evidence from its caller.  A fixed evidence source
must freshly return the secure journal, active pointer, trust registry, both
slot fences, selected-slot health and the signed write-gate artifact.
"""
from __future__ import annotations

import base64
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import stat
from typing import Protocol
import uuid

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,Ed25519PublicKey)

from scripts.macos_pilot_secure_activation import canonical,digest,verify_journal


class AdmissionOpenAuthorityError(RuntimeError):pass


class AdmissionOpenEvidenceSource(Protocol):
    def current(self,phase:str,operation_key:str,contract:dict)->dict:...


def _sealed(value:dict,field:str)->bool:
    claimed=value.get(field)
    return isinstance(claimed,str) and len(claimed)==64 and claimed==digest(
        {key:item for key,item in value.items() if key!=field})


def _trust_key(trust:dict,key_id:str,key_version:int,now:datetime,
               role:str="authority",contract_sha256:str|None=None)->Ed25519PublicKey:
    modern=trust.get("format")=="openepm-macos-pilot-runtime-trust-v1"
    if modern:
        if set(trust)!={"format","keys","approvedContracts"} \
                or contract_sha256 not in trust.get("approvedContracts",[]):
            raise AdmissionOpenAuthorityError("executor trust differs")
    elif not _sealed(trust,"trustRegistrySha256"):
        raise AdmissionOpenAuthorityError("executor trust differs")
    matches=[item for item in trust.get("keys",[]) if item.get("keyId")==key_id
        and item.get("version")==key_version and item.get("role")==role
        and item.get("revoked") is False]
    if len(matches)!=1:raise AdmissionOpenAuthorityError("executor trust differs")
    try:
        start=datetime.strptime(matches[0]["notBeforeUtc"],
            "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        end=datetime.strptime(matches[0]["expiresAtUtc"],
            "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if not start<=now<end:raise ValueError("trust time")
        return Ed25519PublicKey.from_public_bytes(base64.b64decode(
            matches[0]["publicKeyBase64"],validate=True))
    except Exception as error:raise AdmissionOpenAuthorityError(
        "executor trust differs") from error


class PublicAdmissionOpenAuthorityPublisher:
    def __init__(self,root:Path,source:AdmissionOpenEvidenceSource,
                 key:Ed25519PrivateKey,*,key_id:str,key_version:int,clock=None,
                 _test_owner_uid:int|None=None):
        self.root=Path(root);self.source=source;self.key=key
        self.key_id=key_id;self.key_version=key_version
        self.owner=0 if _test_owner_uid is None else _test_owner_uid
        self.clock=clock or (lambda:datetime.now(timezone.utc))
        if not isinstance(key,Ed25519PrivateKey) or not hasattr(source,"current") \
                or not key_id or not isinstance(key_version,int) \
                or isinstance(key_version,bool) or key_version<1 \
                or not self.root.is_absolute() or self.root.is_symlink() \
                or not self.root.is_dir() or self.root.stat().st_uid!=self.owner \
                or stat.S_IMODE(self.root.stat().st_mode)!=0o700:
            raise AdmissionOpenAuthorityError("admission authority publisher is unsafe")
        current=self.root.parent
        while True:
            metadata=os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode) \
                    or metadata.st_mode&(stat.S_IWGRP|stat.S_IWOTH) \
                    and not metadata.st_mode&stat.S_ISVTX:
                raise AdmissionOpenAuthorityError(
                    "admission authority ancestry is unsafe")
            if current.parent==current:break
            current=current.parent
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|getattr(os,"O_CLOEXEC",0)
        self.fd=os.open(self.root,flags)
        metadata=os.fstat(self.fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=self.owner \
                or stat.S_IMODE(metadata.st_mode)!=0o700:
            os.close(self.fd);self.fd=-1
            raise AdmissionOpenAuthorityError("admission authority publisher is unsafe")

    def publish(self,*,phase:str,operation_key:str,contract:dict,**_ignored)->dict:
        if contract.get("format")!= \
                "openepm-macos-pilot-activation-execution-contract-v3":
            raise AdmissionOpenAuthorityError("v3 execution contract is required")
        expected={"certify-active":("green","publish-active","active"),
            "certify-rollback":("blue","certify-rollback","rolled-back")}.get(phase)
        if expected is None:raise AdmissionOpenAuthorityError(
            "admission-open phase differs")
        slot,command,state=expected
        snapshot=self.source.current(phase,operation_key,contract)
        if not isinstance(snapshot,dict):raise AdmissionOpenAuthorityError(
            "admission-open evidence is unavailable")
        journal=snapshot.get("journal",{});pointer=snapshot.get("pointer",{})
        trust=snapshot.get("trust",{});gate=snapshot.get("writeGate",{})
        try:head=verify_journal(journal.get("records"),journal.get("planSha256"),
            journal.get("activationId"),journal.get("executionContractSha256"))
        except Exception as error:raise AdmissionOpenAuthorityError(
            "secure journal differs") from error
        if not _sealed(journal,"snapshotSha256") \
                or journal.get("activationId")!=contract.get("activationId") \
                or journal.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") or head is None \
                or head.get("eventKind")!="completion" \
                or (head.get("command"),head.get("state"))!=(command,state) \
                or head.get("recordSha256")!=operation_key:
            raise AdmissionOpenAuthorityError("secure completion differs")
        if not _sealed(pointer,"pointerSha256") \
                or pointer.get("format")!="openepm-macos-pilot-active-slot-v3" \
                or pointer.get("activationId")!=contract.get("activationId") \
                or pointer.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or (pointer.get("slot"),pointer.get("authorityState"),
                    pointer.get("writesAdmitted"),pointer.get(
                    "publicIngressPermitted"))!=(slot,state,True,True) \
                or pointer.get("activationEventSha256")!=operation_key:
            raise AdmissionOpenAuthorityError("active pointer differs")
        now=self.clock().astimezone(timezone.utc).replace(microsecond=0)
        verifier=contract.get("authorityVerifier",{})
        if (verifier.get("keyId"),verifier.get("version"))!=(self.key_id,
                self.key_version):
            raise AdmissionOpenAuthorityError("authority verifier differs")
        key=_trust_key(trust,self.key_id,self.key_version,now,"authority",
                       contract.get("executionContractSha256"))
        if key.public_bytes_raw()!=self.key.public_key().public_bytes_raw():
            raise AdmissionOpenAuthorityError("publisher key differs from trust")
        records=journal.get("records",[])
        gate_intent=records[-2] if len(records)>=2 else None
        gate_prior=records[-3] if len(records)>=3 else None
        if not isinstance(gate_intent,dict) \
                or head.get("previousSha256")!=gate_intent.get("recordSha256"):
            raise AdmissionOpenAuthorityError("signed write gate lineage differs")
        gate_digest,gate_health=self._verify_gate(
            gate,key,slot,state,operation_key,contract,trust,
            gate_intent=gate_intent,gate_prior=gate_prior)
        selected=self._fence(snapshot.get("selectedDbFence"),slot,"open",
            operation_key,contract,"database")
        selected_producer=self._fence(snapshot.get("selectedProducerFence"),slot,
            "open",operation_key,contract,"producer")
        other="blue" if slot=="green" else "green"
        other_db=self._fence(snapshot.get("otherDbFence"),other,"closed",
            operation_key,contract,"database")
        other_producer=self._fence(snapshot.get("otherProducerFence"),other,
            "closed",operation_key,contract,"producer")
        health=snapshot.get("serviceHealth",{})
        gate_bound=health.get("format")== \
            "openepm-macos-pilot-gate-health-evidence-v1"
        if (not gate_bound and not _sealed(health,"evidenceSha256")) \
                or health.get("format") not in (
                    "openepm-macos-pilot-service-health-v1",
                    "openepm-macos-pilot-gate-health-evidence-v1") \
                or health.get("slot")!=slot \
                or health.get("activationId")!=contract.get("activationId") \
                or health.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or health.get("authorityEventSha256")!=operation_key \
                or (gate_bound and health.get("evidenceSha256")!=gate_health) \
                or (not gate_bound and (not isinstance(health.get("services"),dict) \
                    or not health["services"] or any(value!="healthy-exact"
                    for value in health["services"].values()))):
            raise AdmissionOpenAuthorityError("selected service health differs")
        body={"format":"openepm-macos-public-admission-open-authority-v2",
            "phase":phase,"selectedSlot":slot,"authorityState":state,
            "activationId":contract["activationId"],
            "executionContractSha256":contract["executionContractSha256"],
            "intentEventSha256":operation_key,"journalHeadEventSha256":operation_key,
            "journalGeneration":head["ordinal"],"journalCommand":command,
            "journalEventKind":"completion","selectedFenceState":"open",
            "otherFenceState":"closed","selectedFenceOpenSha256":digest(
                [selected,selected_producer]),"otherFenceClosedSha256":digest(
                [other_db,other_producer]),"serviceHealthSha256":health["evidenceSha256"],
            "serviceHealthy":True,"authorityPointerSha256":pointer["pointerSha256"],
            "pointerStable":True,"gateArtifactSha256":gate_digest,
            "gateStable":True,"pointerFormat":pointer["format"],
            "pointerSlot":slot,"pointerAuthorityState":state,
            "pointerWritesAdmitted":True,"pointerPublicIngressPermitted":True,
            "pointerActivationEventSha256":operation_key,
            "observedAtUtc":now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expiresAtUtc":(now+timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "authorityKeyId":self.key_id,"authorityKeyVersion":self.key_version}
        sealed={**body,"evidenceSha256":digest(body)}
        authority={**sealed,"signature":{"algorithm":"Ed25519","keyId":self.key_id,
            "valueBase64":base64.b64encode(self.key.sign(canonical(sealed))).decode()}}
        self._before_publish()
        for name,value in (("executor-trust-snapshot.json",trust),
                ("activation-journal-snapshot.json",journal),
                ("active-slot.json",pointer),
                ("public-admission-open-authority.json",authority)):
            self._atomic(name,value)
        self._after_publish()
        return authority
    def _before_publish(self):pass
    def _after_publish(self):pass

    def _fence(self,value,slot,state,operation,contract,kind):
        if not isinstance(value,dict) or not _sealed(value,"evidenceSha256") \
                or value.get("format")!=f"openepm-macos-pilot-{kind}-fence-v1" \
                or value.get("slot")!=slot or value.get("state")!=state \
                or value.get("activationId")!=contract.get("activationId") \
                or value.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or value.get("authorityEventSha256")!=operation:
            raise AdmissionOpenAuthorityError(f"{kind} fence differs")
        return value["evidenceSha256"]

    def _verify_gate(self,gate,key,slot,state,operation,contract,trust,
                     *,gate_intent=None,gate_prior=None):
        if gate.get("format") in (
                "openepm-macos-pilot-active-gate-attestation-v1",
                "openepm-macos-pilot-rollback-gate-attestation-v1"):
            signature=gate.get("signature");signed={k:v for k,v in gate.items()
                                                   if k!="signature"}
            digest_field="attestationSha256"
            body={k:v for k,v in signed.items() if k!=digest_field}
            try:key.verify(base64.b64decode(signature.get("valueBase64"),
                validate=True),canonical(signed))
            except Exception as error:raise AdmissionOpenAuthorityError(
                "signed write gate differs") from error
            active=slot=="green"
            health=(gate.get("greenServiceHealthSha256") if active else
                    gate.get("blueServiceHealthSha256"))
            expected_command="publish-active" if active else "certify-rollback"
            expected_prior=("finalize","finalized") if active else (
                            "rollback","rolled-back")
            completion_field=("finalizedCompletionSha256" if active else
                              "rollbackCompletionSha256")
            if gate.get(digest_field)!=digest(body) \
                    or signature.get("algorithm")!="Ed25519" \
                    or signature.get("keyId")!=self.key_id \
                    or gate.get("activationId")!=contract.get("activationId") \
                    or gate.get("executionContractSha256")!=contract.get(
                        "executionContractSha256") \
                    or gate.get("slot")!=slot or gate.get("state")!="open" \
                    or gate.get("authorityState")!=state \
                    or not isinstance(gate_intent,dict) \
                    or gate_intent.get("eventKind")!="intent" \
                    or gate_intent.get("command")!=expected_command \
                    or gate_intent.get("recordSha256")!=gate.get(
                        "publicationIntentSha256") \
                    or not isinstance(gate_prior,dict) \
                    or (gate_prior.get("command"),gate_prior.get("state")) \
                        !=expected_prior \
                    or gate_prior.get("eventKind")!="completion" \
                    or gate.get(completion_field)!=gate_prior.get("recordSha256") \
                    or gate.get("keyId")!=self.key_id \
                    or gate.get("keyVersion")!=self.key_version \
                    or not isinstance(health,str) or len(health)!=64:
                raise AdmissionOpenAuthorityError("signed write gate differs")
            return gate[digest_field],health
        signed={k:v for k,v in gate.items() if k!="signature"}
        unsigned={k:v for k,v in signed.items() if k!="gateSha256"}
        try:key.verify(bytes.fromhex(gate.get("signature","")),canonical(signed))
        except (InvalidSignature,ValueError,TypeError) as error:
            raise AdmissionOpenAuthorityError("signed write gate differs") from error
        if gate.get("format")!="openepm-macos-pilot-write-gate-v1" \
                or gate.get("gateSha256")!=digest(unsigned) \
                or gate.get("state")!="open" or gate.get("slot")!=slot \
                or gate.get("authorityState")!=state \
                or gate.get("activationId")!=contract.get("activationId") \
                or gate.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or gate.get("authorityEventSha256")!=operation \
                or gate.get("trustRegistrySha256")!=trust.get("trustRegistrySha256") \
                or (gate.get("keyId"),gate.get("keyVersion"))!=(self.key_id,
                    self.key_version):
            raise AdmissionOpenAuthorityError("signed write gate differs")
        return gate["gateSha256"],None

    def _atomic(self,name,value):
        metadata=os.fstat(self.fd)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid!=self.owner \
                or stat.S_IMODE(metadata.st_mode)!=0o700:
            raise AdmissionOpenAuthorityError("admission authority root changed")
        payload=canonical(value);temporary=f".{name}.{uuid.uuid4().hex}.tmp"
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
            0o400,dir_fd=self.fd)
        try:
            os.fchmod(fd,0o400);offset=0
            while offset<len(payload):
                written=os.write(fd,payload[offset:])
                if written<1:raise OSError("admission authority write made no progress")
                offset+=written
            os.fsync(fd);os.close(fd);fd=-1
            os.rename(temporary,name,src_dir_fd=self.fd,dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            if fd>=0:os.close(fd)
            try:os.unlink(temporary,dir_fd=self.fd)
            except FileNotFoundError:pass

    def close(self):
        if self.fd>=0:os.close(self.fd);self.fd=-1


class ProtectedAdmissionOpenAuthority:
    """Read back the publisher's current protected dependency set."""
    def __init__(self,root:Path,*,clock=None,_test_owner_uid:int|None=None):
        self.root=Path(root);self.owner=0 if _test_owner_uid is None else _test_owner_uid
        self.clock=clock or (lambda:datetime.now(timezone.utc))
        if not self.root.is_absolute() or self.root.is_symlink() \
                or not self.root.is_dir() or self.root.stat().st_uid!=self.owner \
                or stat.S_IMODE(self.root.stat().st_mode) not in (0o500,0o700):
            raise AdmissionOpenAuthorityError("admission authority root is unsafe")

    def _read(self,name):
        path=self.root/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            metadata=os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode)!=0o400 \
                    or metadata.st_size<1 or metadata.st_size>2*1024*1024:
                raise AdmissionOpenAuthorityError("admission authority artifact is unsafe")
            raw=os.read(fd,2*1024*1024+1)
        finally:os.close(fd)
        try:value=json.loads(raw.decode())
        except Exception as error:raise AdmissionOpenAuthorityError(
            "admission authority artifact is invalid") from error
        if not isinstance(value,dict) or raw!=canonical(value):
            raise AdmissionOpenAuthorityError("admission authority artifact is invalid")
        return value

    def current(self,phase:str,operation_key:str,contract:dict)->dict:
        trust=self._read("executor-trust-snapshot.json")
        journal=self._read("activation-journal-snapshot.json")
        pointer=self._read("active-slot.json")
        authority=self._read("public-admission-open-authority.json")
        expected={"certify-active":("green","publish-active","active"),
            "certify-rollback":("blue","certify-rollback","rolled-back")}.get(phase)
        if expected is None:raise AdmissionOpenAuthorityError(
            "admission-open phase differs")
        slot,command,state=expected
        try:head=verify_journal(journal.get("records"),journal.get("planSha256"),
            journal.get("activationId"),journal.get("executionContractSha256"))
        except Exception as error:raise AdmissionOpenAuthorityError(
            "protected journal differs") from error
        if not _sealed(journal,"snapshotSha256") or not _sealed(pointer,"pointerSha256") \
                or head is None or head.get("recordSha256")!=operation_key \
                or (head.get("eventKind"),head.get("command"),head.get("state"))!= \
                    ("completion",command,state) \
                or pointer.get("pointerSha256")!=authority.get("authorityPointerSha256") \
                or pointer.get("activationEventSha256")!=operation_key \
                or (pointer.get("slot"),pointer.get("authorityState"),
                    pointer.get("writesAdmitted"),pointer.get(
                    "publicIngressPermitted"))!=(slot,state,True,True) \
                or authority.get("phase")!=phase \
                or authority.get("activationId")!=contract.get("activationId") \
                or authority.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or authority.get("journalHeadEventSha256")!=operation_key \
                or authority.get("journalGeneration")!=head.get("ordinal"):
            raise AdmissionOpenAuthorityError("protected admission authority differs")
        signed={k:v for k,v in authority.items() if k!="signature"}
        body={k:v for k,v in signed.items() if k!="evidenceSha256"}
        now=self.clock()
        verifier=contract.get("authorityVerifier",{})
        key_id=authority.get("authorityKeyId",authority.get("executorKeyId"))
        key_version=authority.get("authorityKeyVersion",authority.get("executorKeyVersion"))
        if (key_id,key_version)!= \
                (verifier.get("keyId"),verifier.get("version")):
            raise AdmissionOpenAuthorityError("protected authority verifier differs")
        key=_trust_key(trust,key_id,key_version,now,"authority")
        signature=authority.get("signature",{})
        try:
            key.verify(base64.b64decode(signature.get("valueBase64",""),validate=True),
                canonical(signed))
            observed=datetime.strptime(authority["observedAtUtc"],
                "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            expires=datetime.strptime(authority["expiresAtUtc"],
                "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except Exception as error:raise AdmissionOpenAuthorityError(
            "protected admission signature differs") from error
        if authority.get("evidenceSha256")!=digest(body) \
                or signature.get("algorithm")!="Ed25519" \
                or signature.get("keyId")!=key_id \
                or not (observed<=now<expires) or (expires-observed).total_seconds()>60:
            raise AdmissionOpenAuthorityError("protected admission authority expired")
        return authority
