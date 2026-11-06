#!/usr/bin/env python3
"""Authoritative stopped-application source capture for Mac-pilot activation."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg import connect
from psycopg.rows import dict_row


SHA=re.compile(r"^[0-9a-f]{64}$")
IMAGE=re.compile(r"^sha256:[0-9a-f]{64}$")
APP_SERVICES=("platform","workspace","router","web","worker",
              "python-build-broker")


class StoppedSourceCaptureError(RuntimeError): pass


def canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True).encode()


def digest(value: object) -> str: return hashlib.sha256(canonical(value)).hexdigest()

def canonical_observer_binding(contract:dict,slot:str="source")->dict:
    """Derive the only host-observer binding without changing sealed contract data."""
    selected=contract.get(slot) if isinstance(contract,dict) else None
    body={"format":"openepm-macos-pilot-host-observer-binding-v2","slot":slot,
        "activationId":contract.get("activationId") if isinstance(contract,dict) else None,
        "executionContractSha256":contract.get("executionContractSha256")
            if isinstance(contract,dict) else None,
        "project":selected.get("project") if isinstance(selected,dict) else None,
        "databaseVolume":selected.get("databaseVolume") if isinstance(selected,dict) else None,
        "applicationImage":selected.get("applicationImage") if isinstance(selected,dict) else None,
        "databaseImage":selected.get("databaseImage") if isinstance(selected,dict) else None}
    if slot not in ("source","candidate") or not isinstance(selected,dict) \
            or any(not isinstance(body[key],str) or not body[key] for key in (
                "activationId","project","databaseVolume")) \
            or SHA.fullmatch(str(body["executionContractSha256"])) is None \
            or any(IMAGE.fullmatch(str(body[key])) is None for key in (
                "applicationImage","databaseImage")):
        raise StoppedSourceCaptureError("sealed observer binding differs")
    return {**body,"configSha256":digest(body)}


class FixedStoppedSourceProvider(Protocol):
    def observe_host(self,binding: dict) -> dict: ...
    def capture_database_snapshot(self,binding: dict) -> dict: ...


class ConcreteStoppedSourceProvider:
    """Fixed Docker/PostgreSQL observer loaded only from protected configuration."""
    def __init__(self,config_path: Path,*,_test_owner_uid: int | None=None,
                 _run=None,_connect=None,_port_probe=None):
        self.path=Path(config_path); self.owner=0 if _test_owner_uid is None \
            else _test_owner_uid
        self.run=_run or self._run
        self.connect=_connect or connect
        self.port_probe=_port_probe or self._port_probe
        self.config=self._load()

    @staticmethod
    def _run(argv: tuple[str,...]) -> bytes:
        result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,check=False,timeout=120,env={
                "PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},cwd="/",close_fds=True)
        if result.returncode:
            raise StoppedSourceCaptureError("fixed Docker observation failed")
        return result.stdout

    @staticmethod
    def _port_probe(port: int) -> bool:
        import socket
        try:
            with socket.create_connection(("127.0.0.1",port),timeout=.25): return True
        except OSError: return False

    def _load(self) -> dict:
        descriptor=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode) not in (0o400,0o444) \
                    or not 1<=metadata.st_size<=131072:
                raise StoppedSourceCaptureError("provider config is unsafe")
            raw=os.read(descriptor,131073)
        finally: os.close(descriptor)
        try: value=json.loads(raw.decode())
        except (UnicodeError,json.JSONDecodeError) as error:
            raise StoppedSourceCaptureError("provider config is invalid") from error
        expected={"format","bindingSha256","dockerPath","composeFile","envFile",
            "project","dsnFile","databaseService","applicationServices",
            "publicAdmissionStateFile","ports","quiescenceEvidenceSha256",
            "configSha256"}
        body={key:item for key,item in value.items() if key!="configSha256"} \
            if isinstance(value,dict) else {}
        modern=isinstance(value,dict) and value.get("format")== \
            "openepm-stopped-source-provider-v2"
        if modern:expected|={"admissionAuthorityKeyId","admissionAuthorityPublicKeyBase64",
            "observerBindingSha256"}
        if not isinstance(value,dict) or set(value)!=expected or raw!=canonical(value) \
                or value.get("format") not in ("openepm-stopped-source-provider-v1",
                    "openepm-stopped-source-provider-v2") \
                or value.get("configSha256")!=digest(body) \
                or value.get("databaseService")!="db" \
                or tuple(value.get("applicationServices",()))!=APP_SERVICES \
                or (value.get("ports")!=[5192,5193,5194,5195]
                    if value.get("format").endswith("-v1") else
                    not isinstance(value.get("ports"),list) or len(value["ports"])!=4
                    or len(set(value["ports"]))!=4 or any(not isinstance(port,int)
                    or port<1024 or port>65535 for port in value["ports"])) \
                or SHA.fullmatch(value.get("quiescenceEvidenceSha256","")) is None \
                or modern and SHA.fullmatch(value.get("observerBindingSha256","")) is None:
            raise StoppedSourceCaptureError("provider config differs")
        if modern:
            try:Ed25519PublicKey.from_public_bytes(base64.b64decode(
                value["admissionAuthorityPublicKeyBase64"],validate=True))
            except Exception as error:raise StoppedSourceCaptureError(
                "provider admission authority differs") from error
        for key in ("dockerPath","composeFile","envFile","dsnFile"):
            target=Path(value[key])
            if not target.is_absolute() or target.is_symlink() or not target.is_file() \
                    or target.stat().st_uid!=self.owner or target.stat().st_nlink!=1 \
                    or stat.S_IMODE(target.stat().st_mode) not in (0o400,0o444,0o500):
                raise StoppedSourceCaptureError("provider resource is unsafe")
        admission=Path(value["publicAdmissionStateFile"])
        if not admission.is_absolute() or admission.parent.is_symlink() \
                or not admission.parent.is_dir() \
                or admission.parent.stat().st_uid!=self.owner:
            raise StoppedSourceCaptureError("provider admission path is unsafe")
        return value

    def _base(self) -> tuple[str,...]:
        c=self.config
        return (c["dockerPath"],"compose","--project-name",c["project"],
            "--env-file",c["envFile"],"-f",c["composeFile"])

    def _json(self,argv: tuple[str,...]):
        try: return json.loads(self.run(argv).decode())
        except (UnicodeError,json.JSONDecodeError) as error:
            raise StoppedSourceCaptureError("Docker observation is invalid") from error

    def observe_host(self,binding: dict) -> dict:
        expected=(binding.get("configSha256") if binding.get("format")==
            "openepm-macos-pilot-host-observer-binding-v2" else
            binding.get("executionContractSha256") if self.config["format"].endswith(
            "-v2") else binding.get("configSha256"))
        configured=(self.config.get("observerBindingSha256") if binding.get("format")==
            "openepm-macos-pilot-host-observer-binding-v2" else self.config["bindingSha256"])
        if expected!=configured:
            raise StoppedSourceCaptureError("provider binding differs")
        base=self._base(); services={}; states={}; networks={}
        for name in ("db",*APP_SERVICES):
            identifier=self.run((*base,"ps","-aq",name)).decode().strip()
            values=self._json((self.config["dockerPath"],"inspect",identifier))
            if not isinstance(values,list) or len(values)!=1:
                raise StoppedSourceCaptureError("container identity is invalid")
            item=values[0]; state=item.get("State",{}); config=item.get("Config",{})
            attached=item.get("NetworkSettings",{}).get("Networks",{})
            running=state.get("Running") is True; expected=name=="db"
            if running is not expected or config.get("Labels",{}).get(
                    "com.docker.compose.project")!=binding["project"] \
                    or config.get("Labels",{}).get(
                        "com.docker.compose.service")!=name:
                raise StoppedSourceCaptureError("container state differs")
            image=item.get("Image"); expected_image=(binding["databaseImage"]
                if name=="db" else binding["applicationImage"])
            if image!=expected_image:
                raise StoppedSourceCaptureError("container image differs")
            mapped={network:details.get("NetworkID")
                    for network,details in sorted(attached.items())}
            services[name]={"running":running,"imageId":image,
                "healthConfigured":name!="python-build-broker",
                "healthStatus":"healthy" if name=="db" else "stopped",
                "networks":mapped}; states[name]="running" if running else "stopped"
            for network,network_id in mapped.items():
                observed=self._json((self.config["dockerPath"],"network","inspect",network))[0]
                networks[network]={"networkId":network_id,"driver":observed.get("Driver"),
                    "scope":observed.get("Scope"),"internal":observed.get("Internal"),
                    "attachable":observed.get("Attachable"),"composeProject":
                    observed.get("Labels",{}).get("com.docker.compose.project",""),
                    "composeNetwork":observed.get("Labels",{}).get(
                        "com.docker.compose.network","")}
        admission_path=Path(self.config["publicAdmissionStateFile"])
        admission=admission_path.read_text().strip()
        admission_closed=admission=="closed"
        if self.config["format"].endswith("-v2"):
            try:value=json.loads(admission);signature=value["signature"]
            except Exception as error:raise StoppedSourceCaptureError(
                "signed admission closure is invalid") from error
            signed={key:item for key,item in value.items() if key!="signature"}
            body={key:item for key,item in signed.items() if key!="evidenceSha256"}
            if value.get("format")!="openepm-macos-public-admission-closure-v2" \
                    or value.get("publicAdmissionStopped") is not True \
                    or value.get("evidenceSha256")!=digest(body) \
                    or signature.get("algorithm")!="Ed25519" \
                    or signature.get("keyId")!=self.config["admissionAuthorityKeyId"]:
                raise StoppedSourceCaptureError("signed admission closure differs")
            try:Ed25519PublicKey.from_public_bytes(base64.b64decode(
                self.config["admissionAuthorityPublicKeyBase64"],validate=True)).verify(
                base64.b64decode(signature["valueBase64"],validate=True),canonical(signed))
            except Exception as error:raise StoppedSourceCaptureError(
                "signed admission closure signature is invalid") from error
            admission_closed=True
        volume=self._json((self.config["dockerPath"],"volume","inspect",
            binding["databaseVolume"]))[0]
        return {"bindingSha256":binding["configSha256"],"project":binding["project"],
            "publicAdmissionClosed":admission_closed,"serviceStates":states,
            "services":services,"networks":networks,
            "databaseImage":binding["databaseImage"],
            "applicationImage":binding["applicationImage"],
            "databaseVolume":binding["databaseVolume"],
            "databaseVolumeId":volume.get("Name") and digest({"name":volume.get("Name"),
                "mountpoint":volume.get("Mountpoint"),"driver":volume.get("Driver")}),
            "ports":{str(port):"listening" if self.port_probe(port) else "closed"
                     for port in self.config["ports"]},"unsignedDenials":{}}

    def capture_database_snapshot(self,binding: dict) -> dict:
        expected=(binding.get("executionContractSha256") if self.config["format"].endswith(
            "-v2") else binding.get("configSha256"))
        if expected!=self.config["bindingSha256"]:
            raise StoppedSourceCaptureError("provider binding differs")
        dsn=Path(self.config["dsnFile"]).read_text().strip()
        with self.connect(dsn,row_factory=dict_row,autocommit=False) as db:
            db.execute("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            snapshot=db.execute("SELECT pg_export_snapshot() snapshot").fetchone()["snapshot"]
            sessions=db.execute("SELECT count(*) count FROM pg_stat_activity WHERE "
                "datname=current_database() AND pid<>pg_backend_pid()").fetchone()["count"]
            schema=db.execute("SELECT count(*) rows,min(version) minimum,max(version) maximum,"
                "md5(string_agg(version::text||':'||checksum,',' ORDER BY version)) "
                "ordered_digest_md5 FROM epm.schema_migration").fetchone()
            applications=db.execute("SELECT count(*) count FROM epm.application").fetchone()["count"]
            def dump(exclude: bool) -> str:
                argv=(*self._base(),"exec","-T","db","pg_dump","-U","postgres",
                    "-d","postgres","--data-only","--column-inserts","--rows-per-insert=1",
                    "--no-owner","--no-acl","--restrict-key=openepmstoppedsourcev1",
                    "--snapshot",snapshot)
                if exclude: argv=(*argv,"--exclude-table-data=epm.schema_migration")
                return hashlib.sha256(self.run(argv)).hexdigest()
            whole=dump(False); business=dump(True); db.rollback()
        profile={"kind":"pg_dump-data-only-column-inserts-v1",
            "pgDumpVersion":"pg_dump (PostgreSQL) protected-snapshot",
            "excludedTables":[]}
        return {"bindingSha256":binding["configSha256"],
            "transaction":"repeatable-read-read-only","singleSnapshot":True,
            "serviceSessions":sessions,"allowedAdminCaptureSessions":1,
            "applicationCount":applications,"schema":{"rows":schema["rows"],
                "minimum":schema["minimum"],"maximum":schema["maximum"],
                "orderedDigestMd5":schema["ordered_digest_md5"]},
            "dataDumpFingerprintSha256":whole,
            "businessDataDumpFingerprintSha256":business,
            "dataDumpFingerprintProfile":profile,
            "businessDataDumpFingerprintProfile":{**profile,
                "excludedTables":["epm.schema_migration"]},
            "databaseSnapshotId":digest({"snapshot":snapshot,"whole":whole,
                "business":business}),
            "quiescenceEvidenceSha256":self.config["quiescenceEvidenceSha256"]}


class StoppedSourceCapturer:
    """Validate one protected binding and sign one stopped-app source fact."""
    def __init__(self,config_path: Path,provider: FixedStoppedSourceProvider,
                 signing_key: Ed25519PrivateKey,*,
                 _test_owner_uid: int | None=None):
        self.path=Path(config_path); self.owner=0 if _test_owner_uid is None \
            else _test_owner_uid
        if not hasattr(provider,"observe_host") or not hasattr(
                provider,"capture_database_snapshot") \
                or not isinstance(signing_key,Ed25519PrivateKey):
            raise StoppedSourceCaptureError("stopped-source dependency is invalid")
        self.provider=provider; self.key=signing_key; self.config=self._config()

    def _config(self) -> dict:
        descriptor=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode) not in (0o400,0o444) \
                    or not 1<=metadata.st_size<=65536:
                raise StoppedSourceCaptureError("stopped-source config is unsafe")
            raw=os.read(descriptor,65537)
        finally: os.close(descriptor)
        try: value=json.loads(raw.decode())
        except (UnicodeError,json.JSONDecodeError) as error:
            raise StoppedSourceCaptureError("stopped-source config is invalid") from error
        expected={"format","activationId","executionContractSha256",
            "intentEventSha256","journalHeadEventSha256","project",
            "databaseVolume","databaseVolumeId","applicationImage",
            "databaseImage","capturedAtUtc","configSha256"}
        body={key:item for key,item in value.items() if key!="configSha256"} \
            if isinstance(value,dict) else {}
        modern=isinstance(value,dict) and value.get("format")== \
            "openepm-stopped-source-binding-v2"
        expected.add("authorityKeyId" if modern else "executorKeyId")
        if not isinstance(value,dict) or set(value)!=expected \
                or raw!=canonical(value) \
                or value.get("format") not in ("openepm-stopped-source-binding-v1",
                    "openepm-stopped-source-binding-v2") \
                or value.get("configSha256")!=digest(body) \
                or any(SHA.fullmatch(value.get(key,"")) is None for key in (
                    "executionContractSha256","intentEventSha256",
                    "journalHeadEventSha256","databaseVolumeId")) \
                or any(IMAGE.fullmatch(value.get(key,"")) is None for key in (
                    "applicationImage","databaseImage")) \
                or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
                    r"[0-9]{2}:[0-9]{2}Z",value.get("capturedAtUtc","")) is None:
            raise StoppedSourceCaptureError("stopped-source config differs")
        return value

    def capture(self,captured_at_utc: str) -> dict:
        if self._config()!=self.config:
            raise StoppedSourceCaptureError("stopped-source binding changed")
        binding=self.config
        host=self.provider.observe_host(dict(binding))
        snapshot=self.provider.capture_database_snapshot(dict(binding))
        binding_sha=binding["configSha256"]
        states=host.get("serviceStates") if isinstance(host,dict) else None
        if host.get("publicAdmissionClosed") is not True \
                or not isinstance(states,dict) or set(states)!={"db",*APP_SERVICES} \
                or states.get("db")!="running" \
                or any(states[name]!="stopped" for name in APP_SERVICES) \
                or host.get("databaseImage")!=binding["databaseImage"] \
                or host.get("applicationImage")!=binding["applicationImage"] \
                or host.get("databaseVolume")!=binding["databaseVolume"] \
                or host.get("databaseVolumeId")!=binding["databaseVolumeId"] \
                or host.get("project")!=binding["project"] \
                or host.get("bindingSha256")!=binding_sha:
            raise StoppedSourceCaptureError("host is not exact and stopped")
        if snapshot.get("transaction")!="repeatable-read-read-only" \
                or snapshot.get("singleSnapshot") is not True \
                or snapshot.get("serviceSessions")!=0 \
                or snapshot.get("allowedAdminCaptureSessions")!=1 \
                or snapshot.get("applicationCount") not in (5,6) \
                or snapshot.get("bindingSha256")!=binding_sha \
                or SHA.fullmatch(snapshot.get("dataDumpFingerprintSha256", "")) is None \
                or SHA.fullmatch(snapshot.get(
                    "businessDataDumpFingerprintSha256", "")) is None \
                or not isinstance(snapshot.get("schema"),dict):
            raise StoppedSourceCaptureError("database snapshot is not quiescent")
        modern=binding["format"].endswith("-v2")
        key_field="authorityKeyId" if modern else "executorKeyId"
        key_id=binding[key_field]
        body={"format":("openepm-macos-pilot-stopped-source-v2" if modern else
                "openepm-macos-pilot-stopped-source-v1"),
            "activationId":binding["activationId"],
            "executionContractSha256":binding["executionContractSha256"],
            "intentEventSha256":binding["intentEventSha256"],
            "journalHeadEventSha256":binding["journalHeadEventSha256"],
            "project":binding["project"],"capturedAtUtc":captured_at_utc,
            "databaseVolume":binding["databaseVolume"],
            "databaseVolumeId":binding["databaseVolumeId"],
            "applicationImage":binding["applicationImage"],
            "databaseImage":binding["databaseImage"],
            "services":host["services"],"networks":host["networks"],
            "serviceStates":states,"publicAdmissionClosed":True,
            "ports":host["ports"],"unsignedDenials":host["unsignedDenials"],
            "schema":snapshot["schema"],"applicationCount":snapshot["applicationCount"],
            "dataDumpFingerprintSha256":snapshot["dataDumpFingerprintSha256"],
            "businessDataDumpFingerprintSha256":snapshot[
                "businessDataDumpFingerprintSha256"],
            "dataDumpFingerprintProfile":snapshot["dataDumpFingerprintProfile"],
            "businessDataDumpFingerprintProfile":snapshot[
                "businessDataDumpFingerprintProfile"],
            "databaseSnapshotId":snapshot["databaseSnapshotId"],
            "bindingSha256":binding_sha,
            "databaseSnapshotIsolation":"repeatable-read-read-only",
            "serviceSessions":0,"allowedAdminCaptureSessions":1,
            "captureConsistency":"single-repeatable-read-stopped-app-v1",
            "quiescenceEvidenceSha256":snapshot["quiescenceEvidenceSha256"],
            "readOnlyCapture":True,key_field:key_id}
        claimed=digest(body); signed={**body,"evidenceSha256":claimed}
        return {**signed,"signature":{"algorithm":"Ed25519",
            "keyId":key_id,"valueBase64":base64.b64encode(
                self.key.sign(canonical(signed))).decode()}}
