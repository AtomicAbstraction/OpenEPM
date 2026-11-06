#!/usr/bin/env python3
"""Privileged, fixed launchd public-admission closure authority."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import stat
import subprocess
import tempfile
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SHA=re.compile(r"^[0-9a-f]{64}$")
DOMAIN=re.compile(r"^(system|gui/[0-9]+)$")
LABEL=re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")

class PublicAdmissionError(RuntimeError): pass

def canonical(value: object)->bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True).encode()
def digest(value: object)->str:return hashlib.sha256(canonical(value)).hexdigest()

class Result:
    def __init__(self,returncode:int,stdout:bytes=b"",stderr:bytes=b""):
        self.returncode,self.stdout,self.stderr=returncode,stdout,stderr

class LaunchctlBackend(Protocol):
    def run(self,argv:tuple[str,...],timeout_seconds:int)->Result: ...

class AdmissionOpenAuthority(Protocol):
    def current(self,phase:str,operation_key:str,contract:dict)->dict: ...

class FixedLaunchctlBackend:
    def run(self,argv:tuple[str,...],timeout_seconds:int)->Result:
        completed=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,check=False,timeout=timeout_seconds,
            env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},cwd="/",close_fds=True)
        return Result(completed.returncode,completed.stdout,completed.stderr)

class PublicAdmissionBoundary:
    def __init__(self,config_path:Path,backend:LaunchctlBackend,
                 signing_key:Ed25519PrivateKey,*,_test_owner_uid:int|None=None,
                 _port_probe=None,open_authority:AdmissionOpenAuthority|None=None,
                 open_verifier_key:Ed25519PublicKey|None=None,
                 open_verifier_key_id:str|None=None,
                 open_verifier_key_version:int|None=None):
        self.path=Path(config_path);self.owner=0 if _test_owner_uid is None else _test_owner_uid
        if not hasattr(backend,"run") or not isinstance(signing_key,Ed25519PrivateKey):
            raise PublicAdmissionError("admission dependency is invalid")
        self.backend=backend;self.key=signing_key
        self.open_authority=open_authority
        self.config=self._load()
        self.open_verifier_key=open_verifier_key or signing_key.public_key()
        self.open_verifier_key_id=open_verifier_key_id or self._key_id()
        self.open_verifier_key_version=(open_verifier_key_version
            if open_verifier_key_version is not None else self._key_version())
        if not isinstance(self.open_verifier_key,Ed25519PublicKey) \
                or not isinstance(self.open_verifier_key_id,str) \
                or not isinstance(self.open_verifier_key_version,int):
            raise PublicAdmissionError("admission-open verifier is invalid")
        self.port_probe=_port_probe or self._port_probe

    @staticmethod
    def _port_probe(port:int)->bool:
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.25):return True
        except OSError:return False

    def _load(self)->dict:
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            meta=os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 \
                    or meta.st_uid!=self.owner or stat.S_IMODE(meta.st_mode) not in (0o400,0o444) \
                    or not 1<=meta.st_size<=131072:
                raise PublicAdmissionError("admission config is unsafe")
            raw=os.read(fd,131073)
        finally:os.close(fd)
        try:value=json.loads(raw.decode())
        except (UnicodeError,json.JSONDecodeError) as error:
            raise PublicAdmissionError("admission config is invalid") from error
        body={key:item for key,item in value.items() if key!="configSha256"} \
            if isinstance(value,dict) else {}
        modern=value.get("format")=="openepm-macos-public-admission-v2" \
            if isinstance(value,dict) else False
        key_fields={"authorityKeyId","authorityKeyVersion"} if modern else {
            "executorKeyId","executorKeyVersion"}
        if not isinstance(value,dict) or set(value)!={"format","launchctlPath",
                "domain","ownerUid","entries","artifactPath","configSha256",*key_fields} \
                or raw!=canonical(value) or value.get("format") not in (
                    "openepm-macos-public-admission-v1",
                    "openepm-macos-public-admission-v2") \
                or value.get("configSha256")!=digest(body) \
                or DOMAIN.fullmatch(str(value.get("domain"))) is None \
                or not isinstance(value.get("ownerUid"),int) \
                or (value["domain"].startswith("gui/") and value["domain"]!=
                    f'gui/{value["ownerUid"]}') \
                or not isinstance(value.get("entries"),list) or not value["entries"]:
            raise PublicAdmissionError("admission config differs")
        launchctl=Path(value["launchctlPath"])
        if not self._protected(launchctl,executable=True):
            raise PublicAdmissionError("launchctl executable is unsafe")
        labels=set();ports=set()
        for item in value["entries"]:
            if not isinstance(item,dict) or set(item)!={"label","plistPath",
                    "plistSha256","programArguments","ports"} \
                    or LABEL.fullmatch(str(item.get("label"))) is None \
                    or item["label"] in labels or not isinstance(item.get("ports"),list) \
                    or any(not isinstance(p,int) or p<1 or p>65535 or p in ports
                           for p in item["ports"]):
                raise PublicAdmissionError("admission entry differs")
            labels.add(item["label"]);ports.update(item["ports"])
            plist=Path(item["plistPath"])
            if not self._protected(plist) or self._sha(plist)!=item["plistSha256"]:
                raise PublicAdmissionError("admission plist differs")
            parsed=plistlib.loads(plist.read_bytes())
            if parsed.get("Label")!=item["label"] or parsed.get(
                    "ProgramArguments")!=item["programArguments"]:
                raise PublicAdmissionError("admission plist program differs")
        artifact=Path(value["artifactPath"])
        if not artifact.is_absolute() or artifact.parent.is_symlink() \
                or artifact.parent.stat().st_uid!=self.owner:
            raise PublicAdmissionError("admission artifact path is unsafe")
        return value

    def _key_id(self):
        return self.config.get("authorityKeyId",self.config.get("executorKeyId"))
    def _key_version(self):
        return self.config.get("authorityKeyVersion",self.config.get("executorKeyVersion"))
    def _key_body(self):
        return ({"authorityKeyId":self._key_id(),"authorityKeyVersion":self._key_version()}
            if self.config["format"].endswith("-v2") else
            {"executorKeyId":self._key_id(),"executorKeyVersion":self._key_version()})

    def _protected(self,path:Path,executable:bool=False)->bool:
        if not path.is_absolute() or path.is_symlink() or not path.is_file():return False
        meta=path.stat();modes=(0o500,0o555) if executable else (0o400,0o444)
        return meta.st_uid==self.owner and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode) in modes
    @staticmethod
    def _sha(path:Path)->str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _observe(self)->dict:
        launchctl=self.config["launchctlPath"];domain=self.config["domain"]
        states={};listeners={}
        for item in self.config["entries"]:
            result=self.backend.run((launchctl,"print",f'{domain}/{item["label"]}'),15)
            if result.returncode==0: states[item["label"]]="loaded"
            elif result.returncode==3 and (b"not found" in result.stderr.lower()
                    or b"could not find" in result.stderr.lower()):
                states[item["label"]]="absent"
            else:
                raise PublicAdmissionError("launchd admission observation failed")
            for port in item["ports"]:listeners[str(port)]=self.port_probe(port)
        return {"launchdStates":states,"listeners":listeners}

    def verify_closed(self)->dict:
        observed=self._observe()
        if any(value!="absent" for value in observed["launchdStates"].values()) \
                or any(observed["listeners"].values()):
            raise PublicAdmissionError("public admission remains active")
        return observed

    def verify_open(self)->dict:
        observed=self._observe()
        launchctl=self.config["launchctlPath"];domain=self.config["domain"]
        for item in self.config["entries"]:
            if observed["launchdStates"].get(item["label"])!="loaded" \
                    or any(observed["listeners"].get(str(port)) is not True
                           for port in item["ports"]):
                raise PublicAdmissionError("public admission is not ready")
            result=self.backend.run((launchctl,"print",f'{domain}/{item["label"]}'),15)
            if result.returncode!=0 or not self._program_matches(
                    result.stdout,item["programArguments"]):
                raise PublicAdmissionError("launchd admission program differs")
        return observed

    @staticmethod
    def _program_matches(output:bytes,arguments:list[str])->bool:
        try:lines={line.strip() for line in output.decode("utf-8").splitlines()}
        except UnicodeDecodeError:return False
        return all(argument in lines for argument in arguments)

    def _open_authority(self,phase:str,operation_key:str,contract:dict)->dict:
        if self.open_authority is None or not hasattr(self.open_authority,"current"):
            raise PublicAdmissionError("admission-open authority is unavailable")
        value=self.open_authority.current(phase,operation_key,contract)
        if not isinstance(value,dict):
            raise PublicAdmissionError("admission-open authority differs")
        signature=value.get("signature")
        signed={key:item for key,item in value.items() if key!="signature"}
        body={key:item for key,item in signed.items() if key!="evidenceSha256"}
        modern=contract.get("format")== \
            "openepm-macos-pilot-activation-execution-contract-v3"
        if modern:
            phases={"certify-active":("green","publish-active","active"),
                "certify-rollback":("blue","certify-rollback","rolled-back")}
            authority_format="openepm-macos-public-admission-open-authority-v2"
        else:
            phases={"finalize":("green","finalize","active-finalization"),
                "certified-rollback":("blue","certify-rollback","certified-rollback")}
            authority_format="openepm-macos-public-admission-open-authority-v1"
        expected=phases.get(phase)
        if expected is None:
            raise PublicAdmissionError("admission-open authority differs")
        expected_slot,expected_command,expected_state=expected
        required_sha=("executionContractSha256","intentEventSha256",
            "journalHeadEventSha256","selectedFenceOpenSha256",
            "otherFenceClosedSha256","serviceHealthSha256",
            "authorityPointerSha256","gateArtifactSha256")
        if value.get("format")!=authority_format \
                or value.get("phase")!=phase or value.get("selectedSlot")!=expected_slot \
                or value.get("authorityState")!=expected_state \
                or value.get("activationId")!=contract.get("activationId") \
                or value.get("executionContractSha256")!=contract.get(
                    "executionContractSha256") \
                or value.get("intentEventSha256")!=operation_key \
                or value.get("journalHeadEventSha256")!=operation_key \
                or not isinstance(value.get("journalGeneration"),int) \
                or isinstance(value.get("journalGeneration"),bool) \
                or value["journalGeneration"]<1 \
                or value.get("serviceHealthy") is not True \
                or value.get("selectedFenceState")!="open" \
                or value.get("otherFenceState")!="closed" \
                or value.get("pointerStable") is not True \
                or value.get("gateStable") is not True \
                or any(SHA.fullmatch(str(value.get(field))) is None
                       for field in required_sha) \
                or value.get("executorKeyId",value.get("authorityKeyId")) \
                    != self.open_verifier_key_id \
                or value.get("executorKeyVersion",value.get("authorityKeyVersion")) \
                    != self.open_verifier_key_version \
                or (modern and (value.get("journalCommand")!=expected_command \
                    or value.get("journalEventKind")!="completion" \
                    or value.get("pointerFormat")!= \
                        "openepm-macos-pilot-active-slot-v3" \
                    or value.get("pointerSlot")!=expected_slot \
                    or value.get("pointerAuthorityState")!=expected_state \
                    or value.get("pointerWritesAdmitted") is not True \
                    or value.get("pointerPublicIngressPermitted") is not True \
                    or value.get("pointerActivationEventSha256")!=operation_key)) \
                or value.get("evidenceSha256")!=digest(body) \
                or not isinstance(signature,dict) \
                or signature.get("algorithm")!="Ed25519" \
                or signature.get("keyId")!=self.open_verifier_key_id:
            raise PublicAdmissionError("admission-open authority differs")
        try:self.open_verifier_key.verify(base64.b64decode(
            signature.get("valueBase64"),validate=True),canonical(signed))
        except Exception as error:raise PublicAdmissionError(
            "admission-open authority signature is invalid") from error
        return value

    def reopen(self,*,phase:str,operation_key:str,contract:dict)->dict:
        """Enable only the fixed public surfaces after signed final authority."""
        if self._load()!=self.config or SHA.fullmatch(operation_key or "") is None \
                or not isinstance(contract,dict) \
                or LABEL.fullmatch(str(contract.get("activationId"))) is None \
                or SHA.fullmatch(str(contract.get("executionContractSha256"))) is None:
            raise PublicAdmissionError("admission reopen request differs")
        authority=self._open_authority(phase,operation_key,contract)
        try:observed=self.verify_open()
        except PublicAdmissionError:
            launchctl=self.config["launchctlPath"];domain=self.config["domain"]
            for item in self.config["entries"]:
                target=f'{domain}/{item["label"]}'
                current=self.backend.run((launchctl,"print",target),15)
                if current.returncode==0:
                    if not self._program_matches(current.stdout,item["programArguments"]) \
                            or any(not self.port_probe(port) for port in item["ports"]):
                        raise PublicAdmissionError("loaded admission service differs")
                    continue
                if current.returncode!=3 or not (b"not found" in current.stderr.lower()
                        or b"could not find" in current.stderr.lower()):
                    raise PublicAdmissionError("launchd admission observation failed")
                enabled=self.backend.run((launchctl,"enable",target),15)
                if enabled.returncode not in (0,3):
                    raise PublicAdmissionError("launchd admission enable failed")
                result=self.backend.run((launchctl,"bootstrap",domain,item["plistPath"]),30)
                if result.returncode not in (0,3):
                    raise PublicAdmissionError("launchd admission bootstrap failed")
            observed=self.verify_open()
        modern=contract.get("format")== \
            "openepm-macos-pilot-activation-execution-contract-v3"
        body={"format":"openepm-macos-public-admission-open-v2" if modern else
                "openepm-macos-public-admission-open-v1",
            "phase":phase,"selectedSlot":authority["selectedSlot"],
            "activationId":contract["activationId"],
            "executionContractSha256":contract["executionContractSha256"],
            "intentEventSha256":operation_key,
            "journalHeadEventSha256":authority["journalHeadEventSha256"],
            "journalGeneration":authority["journalGeneration"],
            "openAuthorityEvidenceSha256":authority["evidenceSha256"],
            "domain":self.config["domain"],"ownerUid":self.config["ownerUid"],
            **observed,**self._key_body()}
        sealed={**body,"evidenceSha256":digest(body)}
        value={**sealed,"signature":{"algorithm":"Ed25519",
            "keyId":self._key_id(),"valueBase64":base64.b64encode(
                self.key.sign(canonical(sealed))).decode()}}
        self._publish(value);return value

    def close(self,*,operation_key:str,contract:dict,journal_head:str,
              journal_generation:int,observed_at_utc:str)->dict:
        if self._load()!=self.config:
            raise PublicAdmissionError("admission config changed")
        if SHA.fullmatch(operation_key or "") is None or operation_key!=journal_head \
                or not isinstance(journal_generation,int) or journal_generation<1:
            raise PublicAdmissionError("admission authority differs")
        try:observed=self.verify_closed()
        except PublicAdmissionError:
            launchctl=self.config["launchctlPath"];domain=self.config["domain"]
            for item in self.config["entries"]:
                target=f'{domain}/{item["label"]}'
                disabled=self.backend.run((launchctl,"disable",target),15)
                if disabled.returncode not in (0,3):
                    raise PublicAdmissionError("launchd admission disable failed")
                result=self.backend.run((launchctl,"bootout",domain,item["plistPath"]),30)
                if result.returncode not in (0,3):
                    raise PublicAdmissionError("launchd admission close failed")
            observed=self.verify_closed()
        body={"format":"openepm-macos-public-admission-closure-v2",
            "publicAdmissionStopped":True,
            "activationId":contract["activationId"],
            "executionContractSha256":contract["executionContractSha256"],
            "intentEventSha256":operation_key,"journalHeadEventSha256":journal_head,
            "journalGeneration":journal_generation,"domain":self.config["domain"],
            "ownerUid":self.config["ownerUid"],**observed,
            "observedAtUtc":observed_at_utc,**self._key_body()}
        sealed={**body,"evidenceSha256":digest(body)}
        value={**sealed,"signature":{"algorithm":"Ed25519",
            "keyId":self._key_id(),"valueBase64":base64.b64encode(
                self.key.sign(canonical(sealed))).decode()}}
        self._publish(value);return value

    def _publish(self,value:dict)->None:
        output=Path(self.config["artifactPath"]);payload=canonical(value)
        fd,name=tempfile.mkstemp(prefix=".admission.",dir=output.parent);temporary=Path(name)
        try:
            os.fchmod(fd,0o400);offset=0
            while offset<len(payload):
                written=os.write(fd,payload[offset:])
                if written<1:raise OSError("admission write made no progress")
                offset+=written
            os.fsync(fd);os.close(fd);fd=-1
            os.replace(temporary,output);directory=os.open(output.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
        finally:
            if fd>=0:os.close(fd)
            try:temporary.unlink()
            except FileNotFoundError:pass
