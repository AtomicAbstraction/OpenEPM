#!/usr/bin/env python3
"""Durable fixed green database prepare/restore/migrate boundary."""
from __future__ import annotations
import fcntl,hashlib,json,os
from pathlib import Path
import re,stat,uuid
import subprocess

SHA=re.compile(r"^[0-9a-f]{64}$")
STAGES=("network","volume","database","restore","migrate","bootstrap-roles",
        "bootstrap-operator","fence","verify")
class GreenPrepareError(RuntimeError):pass
class Result:
    def __init__(self,returncode,stdout=b"",stderr=b""):
        self.returncode,self.stdout,self.stderr=returncode,stdout,stderr
class GreenSubprocessProcess:
    def run(self,argv,timeout,stdin_fd=None):
        input_value=subprocess.DEVNULL if stdin_fd is None else stdin_fd
        completed=subprocess.run(tuple(argv),stdin=input_value,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,check=False,timeout=timeout,cwd="/",close_fds=True,
            env={"PATH":"/usr/bin:/bin:/usr/sbin:/sbin"})
        return Result(completed.returncode,completed.stdout,completed.stderr)
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()

class GreenPrepareBoundary:
    def __init__(self,config_path:Path,attempt_root:Path,process,backup,fence,*,
                 _test_owner_uid:int|None=None):
        self.path=Path(config_path).resolve(strict=True);self.root=Path(attempt_root).resolve(strict=True)
        self.owner=0 if _test_owner_uid is None else _test_owner_uid
        self.process,self.backup,self.fence=process,backup,fence
        self.config=self._load();self.fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    def _load(self):
        if not self.path.is_absolute() or self.path.is_symlink():
            raise GreenPrepareError("green prepare config is unsafe")
        current=self.path.parent
        while True:
            meta=os.lstat(current)
            if stat.S_ISLNK(meta.st_mode) or meta.st_uid not in (0,self.owner) \
                    or (meta.st_mode&(stat.S_IWGRP|stat.S_IWOTH)
                        and not meta.st_mode&stat.S_ISVTX):
                raise GreenPrepareError("green prepare config ancestry is unsafe")
            if current.parent==current:break
            current=current.parent
        fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            meta=os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 \
                    or meta.st_uid!=self.owner or stat.S_IMODE(meta.st_mode) not in (0o400,0o444) \
                    or not 1<=meta.st_size<=131072:
                raise GreenPrepareError("green prepare config is unsafe")
            raw=os.read(fd,131073)
        finally:os.close(fd)
        value=json.loads(raw)
        body={k:v for k,v in value.items() if k!="configSha256"}
        expected={"format","dockerPath","composeFile","envFile","project","dbService",
            "dbContainer","databaseImage","operationsImage","databaseVolume","network",
            "expectedNetworkId",
            "dbConfigHash","networkDriver","networkInternal","networkAttachable",
            "volumeDriver","volumeScope","volumeMountpoint",
            "expectedSystemIdentifier","expectedSchemaVersion","expectedApplicationCount","expectedBusinessSha256",
            "dockerSha256","composeSha256","envSha256","configSha256"}
        if set(value)!=expected or raw!=canonical(value) or value["format"]!= \
                "openepm-green-prepare-v1" or value["configSha256"]!=digest(body) \
                or value["dbService"]!="db" or not self.root.is_dir() \
                or self.root.stat().st_uid!=self.owner or stat.S_IMODE(
                    self.root.stat().st_mode)!=0o700:
            raise GreenPrepareError("green prepare config differs")
        for key,sha_key in (("dockerPath","dockerSha256"),("composeFile","composeSha256"),
                            ("envFile","envSha256")):
            p=Path(value[key])
            if not p.is_absolute() or p.is_symlink() or not p.is_file() \
                    or p.stat().st_uid!=self.owner or p.stat().st_nlink!=1 \
                    or hashlib.sha256(p.read_bytes()).hexdigest()!=value[sha_key]:
                raise GreenPrepareError("green prepare resource is unsafe")
        return value
    def _bind_contract(self,contract):
        c=self.config;candidate=contract.get("candidate")
        if not isinstance(candidate,dict):raise GreenPrepareError("candidate contract is missing")
        networks=candidate.get("networks");services=candidate.get("services")
        network=networks.get(c["network"]) if isinstance(networks,dict) else None
        schema=candidate.get("schema")
        operations=(candidate.get("applicationImage") if contract.get("format")==
                    "openepm-macos-pilot-activation-execution-contract-v2"
                    else candidate.get("operationsImage"))
        if candidate.get("project")!=c["project"] \
                or candidate.get("databaseImage")!=c["databaseImage"] \
                or operations!=c["operationsImage"] \
                or candidate.get("databaseVolume")!=c["databaseVolume"] \
                or candidate.get("applicationCount")!=c["expectedApplicationCount"] \
                or candidate.get("businessDataDumpFingerprintSha256")!=c["expectedBusinessSha256"] \
                or not isinstance(schema,dict) or schema.get("maximum")!=c["expectedSchemaVersion"] \
                or not isinstance(network,dict) \
                or network.get("networkId")!=c["expectedNetworkId"] \
                or network.get("driver")!=c["networkDriver"] \
                or network.get("internal") is not c["networkInternal"] \
                or network.get("attachable") is not c["networkAttachable"] \
                or not isinstance(services,dict) or "db" not in services:
            raise GreenPrepareError("green config differs from sealed candidate contract")
    def _base(self):
        c=self.config;return (c["dockerPath"],"compose","--project-name",c["project"],
            "--env-file",c["envFile"],"-f",c["composeFile"])
    def _run(self,argv,timeout=300,stdin_fd=None,allowed=(0,)):
        result=self.process.run(tuple(argv),timeout,stdin_fd=stdin_fd)
        if result.returncode not in allowed:raise GreenPrepareError("green stage command failed")
        return result
    def _inspect(self,kind,name):
        result=self._run((self.config["dockerPath"],kind,"inspect",name),30,allowed=(0,1))
        if result.returncode:return None
        try:value=json.loads(result.stdout.decode())[0]
        except Exception as error:raise GreenPrepareError("green observation invalid") from error
        return value
    def _stage_observed(self,stage,contract,operation):
        c=self.config
        if stage=="network":
            v=self._inspect("network",c["network"]);labels=v.get("Labels",{}) if v else {}
            return bool(v and v.get("Name")==c["network"] and
                labels.get("com.docker.compose.project")==c["project"] and
                labels.get("org.openepm.activation.slot")=="green" and
                v.get("Driver")==c["networkDriver"] and
                v.get("Internal") is c["networkInternal"] and
                v.get("Attachable") is c["networkAttachable"])
        if stage=="volume":
            v=self._inspect("volume",c["databaseVolume"]);labels=v.get("Labels",{}) if v else {}
            return bool(v and v.get("Name")==c["databaseVolume"] and
                labels.get("com.docker.compose.project")==c["project"] and
                labels.get("org.openepm.activation.slot")=="green" and
                v.get("Driver")==c["volumeDriver"] and v.get("Scope")==c["volumeScope"] and
                v.get("Mountpoint")==c["volumeMountpoint"])
        if stage=="database":
            v=self._inspect("container",c["dbContainer"])
            labels=v.get("Config",{}).get("Labels",{}) if v else {}
            return bool(v and v.get("State",{}).get("Running") is True and v.get("Image")==c["databaseImage"]
                and labels.get("com.docker.compose.project")==c["project"]
                and labels.get("com.docker.compose.service")=="db"
                and labels.get("com.docker.compose.config-hash")==c["dbConfigHash"]
                and any(m.get("Name")==c["databaseVolume"] for m in v.get("Mounts",[])))
        if stage in ("restore","migrate","bootstrap-roles","bootstrap-operator","verify"):
            if stage=="verify":
                identity=self._run((c["dockerPath"],"exec",c["dbContainer"],"psql","-X","-A","-t",
                    "-U","postgres","-d","postgres","-c",
                    "SELECT (pg_control_system()).system_identifier::text"),30,allowed=(0,1))
                if identity.returncode or identity.stdout.decode().strip()!=c["expectedSystemIdentifier"]:return False
                dumped=self._run((c["dockerPath"],"exec",c["dbContainer"],"pg_dump","-U","postgres",
                    "-d","postgres","--data-only","--column-inserts","--rows-per-insert=1",
                    "--no-owner","--no-acl","--exclude-table-data=epm.schema_migration",
                    "--restrict-key=openepmpilotbusinessv1"),3600,allowed=(0,1))
                if dumped.returncode or hashlib.sha256(dumped.stdout).hexdigest()!=c["expectedBusinessSha256"]:return False
            sql={"restore":"SELECT count(*) FROM epm.application",
                "migrate":f"SELECT count(*) FROM epm.schema_migration WHERE version={c['expectedSchemaVersion']}",
                "bootstrap-roles":"SELECT count(*) FROM pg_roles WHERE rolname='epm_runtime_login'",
                "bootstrap-operator":"SELECT count(*) FROM epm.platform_operator",
                "verify":"SELECT count(*) FROM epm.application"}[stage]
            r=self._run((c["dockerPath"],"exec",c["dbContainer"],"psql","-X","-A","-t",
                "-U","postgres","-d","postgres","-c",sql),30,allowed=(0,1))
            return r.returncode==0 and r.stdout.decode().strip()==str(c["expectedApplicationCount"] if stage in ("restore","verify") else 1)
        if stage=="fence":
            if hasattr(self.fence,"closed_if_present"):
                return self.fence.closed_if_present("green",operation,contract) is True
            return bool(self.fence.verify_closed("green",operation,contract))
        return False
    def _apply(self,stage,contract,operation):
        c=self.config
        if stage=="network":
            flags=("--driver",c["networkDriver"],* (("--internal",) if c["networkInternal"] else ()),
                *(("--attachable",) if c["networkAttachable"] else ()))
            self._run((c["dockerPath"],"network","create",*flags,"--label",
                f'com.docker.compose.project={c["project"]}',"--label",
                "org.openepm.activation.slot=green",c["network"]),60);return
        if stage=="volume":self._run((c["dockerPath"],"volume","create","--driver",
            c["volumeDriver"],"--label",
            f'com.docker.compose.project={c["project"]}',"--label",
            "org.openepm.activation.slot=green",c["databaseVolume"]),60);return
        if stage=="database":self._run((*self._base(),"up","-d","db"),300);return
        if stage=="restore":
            archive=self.backup.open_verified_archive(operation,contract,"blue")
            try:
                os.lseek(archive.fileno(),0,os.SEEK_SET)
                self._run((c["dockerPath"],"exec","-i",c["dbContainer"],"pg_restore",
                    "-U","postgres","-d","postgres","--clean","--if-exists",
                    "--exit-on-error","--no-owner","-"),3600,stdin_fd=archive.fileno())
            finally:archive.close()
            return
        if stage in ("migrate","bootstrap-roles","bootstrap-operator"):
            service={"migrate":"migrate","bootstrap-roles":"bootstrap-roles",
                     "bootstrap-operator":"bootstrap-operator"}[stage]
            self._run((*self._base(),"--profile","setup","run","--rm",service),1800);return
        if stage=="fence":self.fence.close_green(operation,contract);return
        if stage=="verify":return
    def execute(self,operation,contract):
        if SHA.fullmatch(operation or "") is None:raise GreenPrepareError("operation invalid")
        self._bind_contract(contract)
        lock=os.open("green.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX)
            running=self._run((*self._base(),"ps","--status","running","--services"),30).stdout.decode().splitlines()
            if any(service.strip() not in ("","db") for service in running):
                raise GreenPrepareError("green application service started during preparation")
            images=set(self._run((*self._base(),"config","--images"),30).stdout.decode().splitlines())
            if not {self.config["databaseImage"],self.config["operationsImage"]}.issubset(images):
                raise GreenPrepareError("green compose images differ")
            for image in (self.config["databaseImage"],self.config["operationsImage"]):
                inspected=self._inspect("image",image)
                if not inspected or inspected.get("Id")!=image:
                    raise GreenPrepareError("green image identity differs")
            name=operation+".json";record=self._read(name) or {
                "format":"openepm-green-prepare-attempt-v1","operationKey":operation,
                "contractSha256":contract["executionContractSha256"],
                "configSha256":self.config["configSha256"],"stages":{}}
            if set(record)!={"format","operationKey","contractSha256","configSha256","stages"} \
                    and set(record)!={"format","operationKey","contractSha256","configSha256","stages","evidenceSha256"} \
                    or record.get("format")!="openepm-green-prepare-attempt-v1" \
                    or record.get("operationKey")!=operation \
                    or not isinstance(record.get("stages"),dict) \
                    or any(stage not in STAGES or SHA.fullmatch(str(value)) is None
                           for stage,value in record.get("stages",{}).items()) \
                    or record["contractSha256"]!=contract["executionContractSha256"] \
                    or record.get("configSha256")!=self.config["configSha256"]:
                raise GreenPrepareError("replay differs")
            for stage in STAGES:
                if stage in record["stages"]:
                    if stage in ("network","volume","database","fence") and not self._stage_observed(
                            stage,contract,operation):
                        raise GreenPrepareError("completed green resource identity changed")
                    continue
                if not self._stage_observed(stage,contract,operation):self._apply(stage,contract,operation)
                if not self._stage_observed(stage,contract,operation):raise GreenPrepareError("stage did not reconcile")
                record["stages"][stage]=digest({"stage":stage,"operation":operation});self._write(name,record)
            record["evidenceSha256"]=digest({key:value for key,value in record.items()
                                             if key!="evidenceSha256"})
            self._write(name,record)
            return record
        finally:fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
    def observe_complete(self,operation,contract):
        self._bind_contract(contract)
        record=self._read(operation+".json")
        if record is None or set(record.get("stages",{}))!=set(STAGES) \
                or record.get("contractSha256")!=contract.get("executionContractSha256"):
            return None
        if record.get("evidenceSha256")!=digest({key:value for key,value in record.items()
                                                 if key!="evidenceSha256"}):return None
        for stage in ("database","migrate","bootstrap-roles","bootstrap-operator",
                      "fence","verify"):
            if not self._stage_observed(stage,contract,operation):return None
        return record
    def _read(self,name):
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=self.fd)
        except FileNotFoundError:return None
        try:
            meta=os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=self.owner \
                    or stat.S_IMODE(meta.st_mode)!=0o600 or not 1<=meta.st_size<=1024*1024:
                raise GreenPrepareError("green attempt is unsafe")
            raw=os.read(fd,1024*1024+1);value=json.loads(raw.decode())
            if raw!=canonical(value) or not isinstance(value,dict):
                raise GreenPrepareError("green attempt is invalid")
            return value
        finally:os.close(fd)
    def _write(self,name,value):
        temp="."+name+"."+uuid.uuid4().hex;fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.fd)
        try:
            payload=canonical(value);offset=0
            while offset<len(payload):
                written=os.write(fd,payload[offset:])
                if written<1:raise OSError("green attempt write made no progress")
                offset+=written
            os.fsync(fd)
        except Exception:
            try:os.unlink(temp,dir_fd=self.fd)
            except FileNotFoundError:pass
            raise
        finally:os.close(fd)
        os.rename(temp,name,src_dir_fd=self.fd,dst_dir_fd=self.fd);os.fsync(self.fd)
