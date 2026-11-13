#!/usr/bin/env python3
"""Publish the exact signed stopped-service authority consumed by the PG fence."""
from __future__ import annotations

import base64
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from macos_pilot_active_work_authority import (ProtectedJournalCurrent,protected_json,
 validate_continuous_closure_lineage)
from macos_pilot_public_admission import canonical,digest,PublicAdmissionBoundary
from capture_macos_pilot_stopped_source import canonical_observer_binding

SERVICE_STATES=("platform","workspace","router","web","worker",
                "python-coordinator","build-broker")

class StoppedProofPublishError(RuntimeError):pass

class StoppedProofPublisher:
    def __init__(self,authority_root:Path,host_observer,admission:PublicAdmissionBoundary,
                 journal:ProtectedJournalCurrent,trust_path:Path,
                 journal_path:Path,private_key:Ed25519PrivateKey,*,
                 key_id:str,key_version:int,_test_owner_uid:int|None=None,
                 _clock=None,candidate_host_observer=None):
        self.root=Path(authority_root);self.host=host_observer;self.admission=admission
        self.journal=journal;self.trust_path=Path(trust_path);self.journal_path=Path(journal_path)
        self.key=private_key;self.key_id=key_id;self.key_version=key_version
        self.clock=_clock or (lambda:datetime.now(timezone.utc))
        self.owner=0 if _test_owner_uid is None else _test_owner_uid
        self.candidate_host=candidate_host_observer
        if not self.root.is_absolute() or self.root.is_symlink() or not self.root.is_dir() \
                or self.root.stat().st_uid!=self.owner \
                or stat.S_IMODE(self.root.stat().st_mode)!=0o700:
            raise StoppedProofPublishError("stopped-proof authority root is unsafe")

    def _validate_admission_closure(self,admission:dict,current:dict,
                                    operation_key:str,contract:dict,phase:str)->None:
        signature=admission.get("signature") if isinstance(admission,dict) else None
        signed={key:item for key,item in admission.items() if key!="signature"} \
            if isinstance(admission,dict) else {}
        try:self.admission.key.public_key().verify(base64.b64decode(
            signature["valueBase64"],validate=True),canonical(signed))
        except Exception as error:raise StoppedProofPublishError(
            "admission closure signature is invalid") from error
        modern=admission.get("format")=="openepm-macos-public-admission-closure-v2"
        if not modern:
            if phase not in ("close","restore") \
                    or admission.get("intentEventSha256")!=operation_key \
                    or admission.get("journalHeadEventSha256")!=current["head"] \
                    or admission.get("journalGeneration")!=current["generation"]:
                raise StoppedProofPublishError("admission closure is stale")
            return
        body={key:item for key,item in signed.items() if key!="evidenceSha256"}
        key_id=self.admission.config.get("authorityKeyId")
        key_version=self.admission.config.get("authorityKeyVersion")
        if admission.get("publicAdmissionStopped") is not True \
                or admission.get("activationId")!=contract.get("activationId") \
                or admission.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or admission.get("authorityKeyId")!=key_id \
                or admission.get("authorityKeyVersion")!=key_version \
                or not isinstance(signature,dict) \
                or signature.get("algorithm")!="Ed25519" \
                or signature.get("keyId")!=key_id \
                or admission.get("evidenceSha256")!=digest(body):
            raise StoppedProofPublishError("admission closure binding differs")
        closure_operation=admission.get("intentEventSha256")
        closure_generation=admission.get("journalGeneration")
        if admission.get("journalHeadEventSha256")!=closure_operation:
            raise StoppedProofPublishError("admission closure lineage differs")
        if phase=="close":
            if closure_operation!=operation_key \
                    or closure_generation!=current["generation"] \
                    or current["head"]!=operation_key:
                raise StoppedProofPublishError("admission closure is stale")
            return
        if phase!="restore" or not isinstance(closure_generation,int) \
                or isinstance(closure_generation,bool) or closure_generation<1 \
                or closure_generation>=current.get("generation",0):
            raise StoppedProofPublishError("admission closure lineage differs")
        snapshot=protected_json(self.journal_path,self.owner)
        records=snapshot.get("records") if isinstance(snapshot,dict) else None
        generation=current["generation"]
        if not isinstance(records,list) or len(records)<generation:
            raise StoppedProofPublishError("admission closure lineage differs")
        closure=records[closure_generation-1];head=records[generation-1]
        try:phase_command=validate_continuous_closure_lineage(
            records,generation,closure_generation)
        except Exception as error:raise StoppedProofPublishError(
            "admission closure lineage differs") from error
        if closure.get("ordinal")!=closure_generation \
                or closure.get("recordSha256")!=closure_operation \
                or closure.get("activationId")!=contract.get("activationId") \
                or closure.get("command")!="prepare" \
                or closure.get("eventKind")!="intent" \
                or head.get("recordSha256")!=current["head"] \
                or head.get("recordSha256")!=operation_key \
                or phase_command not in ("finalize","publish-active",
                                         "certify-rollback"):
            raise StoppedProofPublishError("admission closure lineage differs")

    def publish(self,*,operation_key:str,contract:dict,phase:str="close")->dict:
        current=self.journal.current(contract,operation_key)
        admission_path=Path(self.admission.config["artifactPath"])
        admission=protected_json(admission_path,self.owner)
        self._validate_admission_closure(admission,current,operation_key,contract,phase)
        self.admission.verify_closed()
        source_binding=canonical_observer_binding(contract,"source")
        host=self.host.observe_host(source_binding)
        states=host.get("serviceStates",{})
        if states.get("db")!="running" or any(states.get(name)!="stopped" for name in (
                "platform","workspace","router","web","worker","python-build-broker")):
            raise StoppedProofPublishError("application services are not stopped")
        candidate=None
        if phase=="restore":
            if self.candidate_host is None or not isinstance(contract.get("candidate"),dict):
                raise StoppedProofPublishError("candidate stopped observer is unavailable")
            candidate=self.candidate_host.observe_host(canonical_observer_binding(
                contract,"candidate"))
            candidate_states=candidate.get("serviceStates",{})
            if candidate_states.get("db")!="running" or any(
                    candidate_states.get(name)!="stopped" for name in (
                        "platform","workspace","router","web","worker",
                        "python-build-broker")):
                raise StoppedProofPublishError("candidate services are not stopped")
        service_states={name:"stopped" for name in SERVICE_STATES}
        # Validity starts at the fresh host observation, never at the older
        # journal intent timestamp.
        observed=self.clock().astimezone(timezone.utc).replace(microsecond=0)
        expires=observed+timedelta(seconds=60)
        observation=digest({"admissionEvidenceSha256":admission["evidenceSha256"],
            "serviceStates":states,"services":host.get("services"),
            "databaseVolumeId":host.get("databaseVolumeId"),
            "candidateServiceStates":None if candidate is None else candidate.get(
                "serviceStates"),"candidateDatabaseVolumeId":None if candidate is None
                else candidate.get("databaseVolumeId")})
        body={"format":"openepm-macos-pilot-service-stopped-proof-v2",
            "phase":phase,"activationId":contract["activationId"],
            "executionContractSha256":contract["executionContractSha256"],
            "intentEventSha256":operation_key,"journalHeadEventSha256":current["head"],
            "journalGeneration":current["generation"],"serviceStates":service_states,
            "publicAdmissionStopped":True,"observedAtUtc":observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expiresAtUtc":expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "observationSha256":observation,"executorKeyId":self.key_id,
            "executorKeyVersion":self.key_version}
        sealed={**body,"proofSha256":digest(body)}
        proof={**sealed,"signature":self.key.sign(canonical(sealed)).hex()}
        trust=protected_json(self.trust_path,self.owner)
        journal=protected_json(self.journal_path,self.owner)
        self._atomic("executor-trust-snapshot.json",trust)
        self._atomic("activation-journal-snapshot.json",journal)
        self._atomic("service-stopped-proof.json",proof)
        return proof

    def observe(self,operation_key:str,contract:dict)->dict|None:
        path=self.root/"service-stopped-proof.json"
        try:value=protected_json(path,self.owner)
        except FileNotFoundError:return None
        if value.get("intentEventSha256")!=operation_key or value.get(
                "executionContractSha256")!=contract.get("executionContractSha256"):
            raise StoppedProofPublishError("stopped proof differs")
        current=self.journal.current(contract,operation_key)
        now=self.clock().astimezone(timezone.utc)
        try:expires=datetime.strptime(value["expiresAtUtc"],"%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
        except (KeyError,TypeError,ValueError) as error:
            raise StoppedProofPublishError("stopped proof validity is invalid") from error
        if value.get("journalHeadEventSha256")!=current["head"] \
                or value.get("journalGeneration")!=current["generation"] \
                or now>=expires:
            return None
        self.admission.verify_closed();host=self.host.observe_host(
            canonical_observer_binding(contract,"source"))
        if host.get("serviceStates",{}).get("db")!="running" or any(
                host.get("serviceStates",{}).get(name)!="stopped" for name in (
                    "platform","workspace","router","web","worker","python-build-broker")):
            return None
        if value.get("phase")=="restore":
            if self.candidate_host is None:return None
            candidate=self.candidate_host.observe_host(canonical_observer_binding(
                contract,"candidate"))
            if candidate.get("serviceStates",{}).get("db")!="running" or any(
                    candidate.get("serviceStates",{}).get(name)!="stopped" for name in (
                        "platform","workspace","router","web","worker",
                        "python-build-broker")):return None
        return value

    def _atomic(self,name:str,value:dict)->None:
        payload=canonical(value);fd,path=tempfile.mkstemp(prefix="."+name+".",dir=self.root)
        temporary=Path(path)
        try:
            os.fchmod(fd,0o400);offset=0
            while offset<len(payload):
                written=os.write(fd,payload[offset:])
                if written<1:raise OSError("stopped-proof write made no progress")
                offset+=written
            os.fsync(fd);os.close(fd);fd=-1;os.replace(temporary,self.root/name)
            directory=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:
            if fd>=0:os.close(fd)
            try:temporary.unlink()
            except FileNotFoundError:pass
