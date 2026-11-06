#!/usr/bin/env python3
"""Concrete, non-live privileged controller for fixed Mac-pilot host actions."""
from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from typing import Protocol


SHA=re.compile(r"^[0-9a-f]{64}$")
FIXED_SERVICES=("platform","workspace","router","web","worker",
                "python-build-broker")
CONFIG_KEYS={"format","blueProject","greenProject","blueComposeFile",
    "greenComposeFile","blueEnvFile","greenEnvFile","applicationImage",
    "databaseImage","blueVolume","greenVolume","blueNetwork","greenNetwork",
    "privatePorts","forwarderLabels","tunnelLabel","dockerPath","dockerSha256",
    "helperPath","helperSha256","runtimeStateRoot","deploymentConfigSha256"}
CONFIG_KEYS.update({"blueComposeSha256","greenComposeSha256",
                    "blueEnvSha256","greenEnvSha256"})
PORT_KEYS={"web","platform","workspace","application"}
LABEL_KEYS={"web","platform","workspace","application"}
CONTROLLER_ACTIONS=frozenset({
    "close-public-admission","verify-public-admission-closed",
    "drain-durable-work","stop-app-and-broker-services",
    "close-all-producer-fence",
    "create-signed-stopped-proof","capture-quiescent-source",
    "create-signed-restore-stopped-proof",
    "create-protected-backup","compose-prepare-green",
    "compose-start-green","compose-start-green-finalize","compose-start-green-active",
    "compose-stop-green","compose-stop-blue",
    "compose-start-blue","compose-start-blue-readonly","verify-source-quiescent",
    "verify-work-drained","verify-protected-backup","fingerprint-source",
    "verify-green-prepared","verify-green-migrated","verify-green-data",
    "verify-private-network","verify-tunnel-stopped","verify-launcher-network",
    "verify-green-health","verify-unsigned-denial","verify-green-read",
    "verify-blue-preserved","restore-blue-network","verify-blue-data",
    "verify-blue-read","verify-blue-unsigned-denial",
    "verify-blue-write-job-denial","verify-green-retained","verify-green-current",
    "verify-green-authority-prepared",
    "verify-green-gate-closed","verify-commit-current",
    "verify-green-authority-selected",
    "resume-public-tunnel","verify-public-green","verify-green-stopped",
    "verify-green-services-stopped",
    "verify-blue-health",
    "verify-producer-fence-closed","reopen-blue-producer-fence",
    "reopen-green-producer-fence","verify-green-finalize-health",
    "verify-green-active-health","verify-green-publishing-pointer"})
VOLATILE_ACTIONS=frozenset({"verify-public-admission-closed",
    "verify-green-services-stopped","create-signed-stopped-proof",
    "create-signed-restore-stopped-proof","verify-postgres-fence-closed",
    "verify-green-fence-closed","verify-blue-fence-open","verify-green-fence-open"})


class PrivilegedControllerError(RuntimeError): pass


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class FixedProcessBackend(Protocol):
    def run(self,argv: tuple[str,...],environment: dict[str,str],
            timeout_seconds: int) -> ProcessResult: ...


class SubprocessBackend:
    """Production backend with no shell, inherited input, cwd, or environment."""
    def run(self,argv: tuple[str,...],environment: dict[str,str],
            timeout_seconds: int) -> ProcessResult:
        if not isinstance(argv,tuple) or not argv or any(
                not isinstance(item,str) or not item for item in argv):
            raise PrivilegedControllerError("process argv is invalid")
        completed=subprocess.run(argv,stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,
            env=dict(environment),cwd="/",timeout=timeout_seconds,close_fds=True)
        return ProcessResult(completed.returncode,completed.stdout,completed.stderr)


class ProtectedBootstrapProvider:
    """Read an operation-bound, canonical contract envelope from protected storage."""
    def __init__(self,path: Path,*,_test_owner_uid: int | None=None):
        self.path=Path(path); self.owner=0 if _test_owner_uid is None else _test_owner_uid

    def seal(self,operation_key: str) -> dict:
        descriptor=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode) not in (0o400,0o444) \
                    or not 1<=metadata.st_size<=1024*1024:
                raise PrivilegedControllerError("bootstrap contract is unsafe")
            raw=os.read(descriptor,1024*1024+1)
        finally: os.close(descriptor)
        try: envelope=json.loads(raw.decode())
        except (UnicodeError,json.JSONDecodeError) as error:
            raise PrivilegedControllerError("bootstrap contract is invalid") from error
        body={key:value for key,value in envelope.items() if key!="envelopeSha256"} \
            if isinstance(envelope,dict) else {}
        contract=envelope.get("executionContract") if isinstance(envelope,dict) else None
        if raw!=canonical(envelope) or envelope.get("format")!= \
                "openepm-macos-pilot-bootstrap-contract-v1" \
                or envelope.get("prepareOperationKey")!=operation_key \
                or envelope.get("envelopeSha256")!=digest(body) \
                or not isinstance(contract,dict) \
                or contract.get("executionContractSha256")!=digest({key:value
                    for key,value in contract.items() if key!="executionContractSha256"}):
            raise PrivilegedControllerError("bootstrap contract differs")
        return contract


def canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True).encode()


def digest(value: object) -> str: return hashlib.sha256(canonical(value)).hexdigest()


class PrivilegedMacPilotController:
    """Translate fixed actions into exact argv with durable reconciliation."""
    def __init__(self,config_path: Path,attempts_root: Path,
                 backend: FixedProcessBackend,bootstrap_provider=None,*,
                 _test_owner_uid: int | None=None,
                 _test_effective_uid: int | None=None):
        owner=0 if _test_owner_uid is None else _test_owner_uid
        effective=os.geteuid() if _test_effective_uid is None else _test_effective_uid
        if _test_effective_uid is None and effective!=0:
            raise PrivilegedControllerError("privileged controller requires root")
        self.config_path=Path(config_path); self.root=Path(attempts_root)
        if not hasattr(backend,"run"): raise PrivilegedControllerError(
            "fixed process backend is unavailable")
        self.backend=backend; self.owner=owner; self.bootstrap_provider=bootstrap_provider
        self.config=self._protected_config(owner)
        current=self.root.parent
        while True:
            metadata=os.lstat(current)
            writable=metadata.st_mode&(stat.S_IWGRP|stat.S_IWOTH)
            if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid not in (0,owner) \
                    or writable and not metadata.st_mode&stat.S_ISVTX:
                raise PrivilegedControllerError("controller ancestry is unsafe")
            if current.parent==current: break
            current=current.parent
        if not self.root.is_absolute() or self.root.is_symlink() \
                or not self.root.is_dir() or self.root.resolve(strict=True)!=self.root \
                or self.root.stat().st_uid!=owner \
                or stat.S_IMODE(self.root.stat().st_mode)!=0o700:
            raise PrivilegedControllerError("controller attempt root is unsafe")
        self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        opened=os.fstat(self.fd)
        if not stat.S_ISDIR(opened.st_mode) or opened.st_uid!=owner \
                or stat.S_IMODE(opened.st_mode)!=0o700:
            os.close(self.fd)
            raise PrivilegedControllerError("opened controller root is unsafe")
        self.closed=False

    def _protected_config(self,owner: int) -> dict:
        path=self.config_path
        if not path.is_absolute() or path.is_symlink() or not path.is_file() \
                or path.resolve(strict=True)!=path:
            raise PrivilegedControllerError("deployment config is unsafe")
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=owner \
                    or stat.S_IMODE(metadata.st_mode) not in (0o400,0o444) \
                    or not 1<=metadata.st_size<=65536:
                raise PrivilegedControllerError("deployment config is unsafe")
            raw=os.read(descriptor,65537)
        finally: os.close(descriptor)
        value=json.loads(raw.decode())
        if not isinstance(value,dict) or set(value)!=CONFIG_KEYS or raw!=canonical(value) \
                or value.get("format")!="openepm-macos-pilot-deployment-v1" \
                or value.get("deploymentConfigSha256")!=digest({key:item for key,item
                    in value.items() if key!="deploymentConfigSha256"}) \
                or set(value.get("privatePorts",{}))!=PORT_KEYS \
                or set(value.get("forwarderLabels",{}))!=LABEL_KEYS:
            raise PrivilegedControllerError("deployment config is invalid")
        resources={}
        state_root=Path(value["runtimeStateRoot"])
        if not state_root.is_absolute() or state_root.is_symlink() \
                or not state_root.is_dir() or state_root.resolve(strict=True)!=state_root \
                or state_root.stat().st_uid!=owner \
                or stat.S_IMODE(state_root.stat().st_mode)!=0o700:
            raise PrivilegedControllerError("runtime state root is unsafe")
        for key,digest_key in (("blueComposeFile","blueComposeSha256"),
                ("greenComposeFile","greenComposeSha256"),
                ("blueEnvFile","blueEnvSha256"),("greenEnvFile","greenEnvSha256")):
            target=Path(value[key])
            if not target.is_absolute() or target.is_symlink() or not target.is_file() \
                    or target.stat().st_uid!=owner or target.stat().st_nlink!=1 \
                    or stat.S_IMODE(target.stat().st_mode) not in (0o400,0o444) \
                    or self._file_sha256(target)!=value[digest_key]:
                raise PrivilegedControllerError("deployment path is invalid")
            resources[key]=(target.stat().st_dev,target.stat().st_ino,
                            value[digest_key])
        for path_key,digest_key in (("dockerPath","dockerSha256"),
                                    ("helperPath","helperSha256")):
            target=Path(value[path_key])
            if not target.is_absolute() or target.is_symlink() or not target.is_file() \
                    or target.stat().st_uid!=owner or target.stat().st_nlink!=1 \
                    or target.stat().st_mode&(stat.S_IWGRP|stat.S_IWOTH) \
                    or self._file_sha256(target)!=value[digest_key]:
                raise PrivilegedControllerError("deployment executable is invalid")
            resources[path_key]=(target.stat().st_dev,target.stat().st_ino,
                                 value[digest_key])
        self._resource_identities=resources
        return value

    @staticmethod
    def _file_sha256(path: Path) -> str:
        value=hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda:stream.read(65536),b""): value.update(chunk)
        return value.hexdigest()

    def _revalidate_executables(self) -> None:
        pairs=(("blueComposeFile","blueComposeSha256"),
            ("greenComposeFile","greenComposeSha256"),
            ("blueEnvFile","blueEnvSha256"),("greenEnvFile","greenEnvSha256"),
            ("dockerPath","dockerSha256"),("helperPath","helperSha256"))
        for path_key,digest_key in pairs:
            target=Path(self.config[path_key]); metadata=os.lstat(target)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) \
                    or metadata.st_uid!=self.owner or metadata.st_nlink!=1 \
                    or (path_key.endswith("Path") and metadata.st_mode&(
                        stat.S_IWGRP|stat.S_IWOTH)) \
                    or (path_key.endswith("File") and stat.S_IMODE(
                        metadata.st_mode) not in (0o400,0o444)) \
                    or (metadata.st_dev,metadata.st_ino,self.config[digest_key]) \
                        != self._resource_identities[path_key] \
                    or self._file_sha256(target)!=self.config[digest_key]:
                raise PrivilegedControllerError("protected deployment resource changed")

    def _compose(self,slot: str,*arguments: str) -> tuple[str,...]:
        config=self.config; prefix="blue" if slot=="blue" else "green"
        return (config["dockerPath"],"compose","--project-name",config[f"{prefix}Project"],
            "--env-file",config[f"{prefix}EnvFile"],"-f",
            config[f"{prefix}ComposeFile"],*arguments)

    def _helper(self,action: str,operation: str) -> tuple[str,...]:
        return (self.config["helperPath"],action,"--operation-key",operation,"--config",
                str(self.config_path))

    def _argv(self,action: str,operation: str) -> tuple[tuple[str,...],tuple[str,...]]:
        compose={
            "compose-stop-green":self._compose("green","stop",*FIXED_SERVICES),
            "compose-stop-blue":self._compose("blue","stop",*FIXED_SERVICES),
            "compose-start-green":self._compose("green","up","-d",*FIXED_SERVICES),
            "compose-start-green-finalize":self._compose("green","up","-d",*FIXED_SERVICES),
            "compose-start-green-active":self._compose("green","up","-d",*FIXED_SERVICES),
            "compose-start-blue":self._compose("blue","up","-d",*FIXED_SERVICES),
            "compose-start-blue-readonly":self._compose("blue","up","-d",*FIXED_SERVICES),
            "stop-app-and-broker-services":self._compose("blue","stop",*FIXED_SERVICES),
        }
        helper_action={"restore-blue-network":"verify-blue-network"}.get(action,action)
        apply=compose.get(action,self._helper("apply-"+helper_action,operation))
        observation={"compose-start-blue-readonly":"verify-blue-services-readonly",
            "compose-start-blue":"verify-blue-health",
            "compose-start-green-finalize":"verify-green-finalize-health",
            "compose-start-green-active":"verify-green-active-health",
            "restore-blue-network":"verify-blue-network"}.get(action,action)
        observe=self._helper("observe-"+observation,operation)
        return apply,observe

    def _attempt(self,name: str) -> dict | None:
        if self.closed: raise PrivilegedControllerError("controller is closed")
        try: descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
        except FileNotFoundError: return None
        try:
            metadata=os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode)!=0o600 \
                    or not 1<=metadata.st_size<=262144:
                raise PrivilegedControllerError("controller attempt is unsafe")
            chunks=[]; remaining=262145
            while remaining:
                chunk=os.read(descriptor,min(65536,remaining))
                if not chunk: break
                chunks.append(chunk); remaining-=len(chunk)
            if remaining==0:
                raise PrivilegedControllerError("controller attempt is oversized")
            raw=b"".join(chunks)
        finally: os.close(descriptor)
        value=json.loads(raw.decode())
        if not isinstance(value,dict) or raw!=canonical(value):
            raise PrivilegedControllerError("controller attempt is invalid")
        return value

    def _write(self,name: str,value: dict) -> None:
        if self.closed: raise PrivilegedControllerError("controller is closed")
        temporary=f".{name}.{uuid.uuid4().hex}.tmp"; payload=canonical(value)
        descriptor=None
        try:
            descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                               0o600,dir_fd=self.fd)
            offset=0
            while offset<len(payload):
                written=os.write(descriptor,payload[offset:])
                if written<1: raise OSError("controller write made no progress")
                offset+=written
            os.fsync(descriptor)
            os.close(descriptor); descriptor=None
            os.rename(temporary,name,src_dir_fd=self.fd,dst_dir_fd=self.fd)
            os.fsync(self.fd)
        finally:
            if descriptor is not None: os.close(descriptor)
            try: os.unlink(temporary,dir_fd=self.fd)
            except FileNotFoundError: pass

    def perform(self,action: str,operation_key: str,contract: dict) -> str:
        if self.closed: raise PrivilegedControllerError("controller is closed")
        if action not in CONTROLLER_ACTIONS \
                or not isinstance(operation_key,str) or SHA.fullmatch(operation_key) is None:
            raise PrivilegedControllerError("controller action identity is invalid")
        apply,observe=self._argv(action,operation_key)
        request=digest({"action":action,"operationKey":operation_key,
            "config":self.config["deploymentConfigSha256"],
            "contract":contract.get("executionContractSha256")})
        name=f"{operation_key}-{digest(action)[:16]}.json"
        lock=os.open("controller.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,
                     dir_fd=self.fd)
        try:
            metadata=os.fstat(lock)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 \
                    or metadata.st_uid!=self.owner \
                    or stat.S_IMODE(metadata.st_mode)!=0o600:
                raise PrivilegedControllerError("controller lock is unsafe")
            fcntl.flock(lock,fcntl.LOCK_EX)
            self._revalidate_executables()
            attempt=self._attempt(name)
            if attempt is None:
                attempt={"format":"openepm-controller-attempt-v1","requestSha256":request,
                    "state":"intent","evidenceSha256":None}; self._write(name,attempt)
                attempt["state"]="invoking"; self._write(name,attempt)
                applied=self.backend.run(apply,
                    {"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},120)
                if not isinstance(applied,ProcessResult) or applied.returncode!=0:
                    raise PrivilegedControllerError("controller action failed")
                result=self.backend.run(observe,{"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},30)
            else:
                if attempt.get("requestSha256")!=request:
                    raise PrivilegedControllerError("controller replay differs")
                if attempt.get("state")=="complete" and action not in VOLATILE_ACTIONS:
                    return attempt["evidenceSha256"]
                result=self.backend.run(observe,{"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},30)
                if isinstance(result,ProcessResult) and result.returncode==3:
                    applied=self.backend.run(apply,
                        {"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},120)
                    if not isinstance(applied,ProcessResult) or applied.returncode!=0:
                        raise PrivilegedControllerError("controller action failed")
                    result=self.backend.run(observe,
                        {"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"},30)
            if not isinstance(result,ProcessResult) or result.returncode!=0 \
                    or len(result.stdout)>1024*1024 or len(result.stderr)>1024*1024:
                raise PrivilegedControllerError("controller action did not reconcile")
            evidence=hashlib.sha256(result.stdout).hexdigest()
            attempt["state"]="complete"; attempt["evidenceSha256"]=evidence
            self._write(name,attempt); return evidence
        finally:
            fcntl.flock(lock,fcntl.LOCK_UN); os.close(lock)

    def close_public_admission(self,operation_key: str,contract: dict) -> str:
        return self.perform("close-public-admission",operation_key,contract)

    def compose(self,action: str,operation_key: str,contract: dict) -> str:
        if not action.startswith("compose-") and action != \
                "stop-app-and-broker-services":
            raise PrivilegedControllerError("controller compose action is invalid")
        return self.perform(action,operation_key,contract)

    def tunnel(self,action: str,operation_key: str,contract: dict) -> str:
        if action not in ("verify-tunnel-stopped","resume-public-tunnel"):
            raise PrivilegedControllerError("controller tunnel action is invalid")
        return self.perform(action,operation_key,contract)

    def observe(self,action: str,operation_key: str,contract: dict) -> str:
        if action.startswith("compose-") or action in (
                "stop-app-and-broker-services","verify-tunnel-stopped",
                "resume-public-tunnel"):
            raise PrivilegedControllerError("controller observation action is invalid")
        return self.perform(action,operation_key,contract)

    def seal_execution_contract(self,operation_key: str) -> dict:
        if self.bootstrap_provider is None or not hasattr(self.bootstrap_provider,"seal"):
            raise PrivilegedControllerError("protected bootstrap provider is unavailable")
        return self.bootstrap_provider.seal(operation_key)

    def close(self) -> None:
        if self.closed: return
        os.close(self.fd); self.closed=True
