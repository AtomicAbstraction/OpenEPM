#!/usr/bin/env python3
"""Protected exact probes for blue read-only rollback before certification."""
from __future__ import annotations
import hashlib,json,os,stat
from pathlib import Path

try:from macos_pilot_readonly_probe import ReadOnlyProbeError,canonical,digest
except ModuleNotFoundError:
 from scripts.macos_pilot_readonly_probe import ReadOnlyProbeError,canonical,digest
try:from capture_macos_pilot_stopped_source import canonical_observer_binding
except ModuleNotFoundError:
 from scripts.capture_macos_pilot_stopped_source import canonical_observer_binding

class RollbackProbeError(ReadOnlyProbeError):pass

class ProtectedRollbackProbe:
 ACTIONS={"verify-blue-data","verify-blue-read","verify-blue-unsigned-denial",
          "verify-blue-write-job-denial","verify-green-retained",
          "verify-blue-network","verify-blue-health","verify-blue-services-readonly"}
 SERVICES=("platform","workspace","router","web","worker","python-build-broker")
 def __init__(self,path:Path,docker,http,db_fence,producer_fence,producer_manifest,
              source_provider,operation_key,contract,*,_test_owner_uid=None):
  self.path=Path(path);self.owner=0 if _test_owner_uid is None else _test_owner_uid
  self.docker,self.http=docker,http;self.db_fence=db_fence
  self.producer_fence,self.manifest=producer_fence,producer_manifest
  self.source_provider=source_provider;self.operation=operation_key;self.contract=contract
  self.config=self._load()
 def _producer_manifest(self):
  value=self.manifest
  if hasattr(value,'current'):value=value.current('blue')
  if not isinstance(value,dict):raise RollbackProbeError('producer fence manifest is unavailable')
  return value
 def _protected(self,path,maximum=1024*1024):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   meta=os.fstat(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=self.owner \
      or stat.S_IMODE(meta.st_mode) not in (0o400,0o444,0o500) \
      or not 1<=meta.st_size<=maximum:raise RollbackProbeError("probe resource is unsafe")
   raw=os.read(fd,maximum+1)
   if len(raw)!=meta.st_size:raise RollbackProbeError("probe resource changed")
   return raw
  finally:os.close(fd)
 def _load(self):
  raw=self._protected(self.path,131072);value=json.loads(raw)
  body={k:v for k,v in value.items() if k!="configSha256"}
  required={"format","dockerPath","composeFile","envFile","blueProject",
   "blueServices","applicationImage","databaseImage","blueNetwork","blueNetworkId",
   "greenVolume","greenVolumeId","admissionArtifact","tokenFile","caFile",
   "unsignedUrls","readUrl","readResultSha256","writeDenialUrl","writeDenialStatus",
   "jobDenialUrl","jobDenialStatus","configSha256"}
  if set(value)!=required or raw!=canonical(value) or value.get("format") \
     !="openepm-macos-pilot-rollback-probe-v1" or value.get("configSha256")!=digest(body) \
     or tuple(value.get("blueServices",()))!=self.SERVICES:
   raise RollbackProbeError("rollback probe config differs")
  for key in ("dockerPath","composeFile","envFile","tokenFile","caFile"):
   self._protected(Path(value[key]))
  admission=Path(value["admissionArtifact"])
  if not admission.is_absolute() or admission.parent.is_symlink() \
     or not admission.parent.is_dir() or admission.parent.stat().st_uid!=self.owner:
   raise RollbackProbeError("admission artifact path is unsafe")
  return value
 def _base(self):
  c=self.config;return (c["dockerPath"],"compose","--project-name",c["blueProject"],
   "--env-file",c["envFile"],"-f",c["composeFile"])
 def _json(self,argv):
  code,out=self.docker.run(argv,30)
  if code:raise RollbackProbeError("Docker observation failed")
  try:return json.loads(out)
  except Exception as error:raise RollbackProbeError("Docker observation is invalid") from error
 def _verify_fences(self):
  try:
   self.db_fence.verify_closed("blue",self.operation,self.contract)
   self.db_fence.verify_closed("green",self.operation,self.contract)
   self.producer_fence.verify_closed(self._producer_manifest(),contract=self.contract)
  except Exception as error:raise RollbackProbeError("live rollback fence is open") from error
 def _services(self,*,certified=False):
  if certified:
   try:
    self.db_fence.verify_open("blue",self.operation,self.contract)
    self.db_fence.verify_closed("green",self.operation,self.contract)
    self.producer_fence.verify_open(self._producer_manifest(),contract=self.contract)
   except Exception as error:raise RollbackProbeError("certified blue fence differs") from error
  else:self._verify_fences()
  c=self.config
  code,out=self.docker.run((*self._base(),"ps","--status","running","--services"),30)
  if code or set(out.decode().split())!=set(("db",*self.SERVICES)):
   raise RollbackProbeError("blue service inventory differs")
  for service in ("db",*self.SERVICES):
   code,raw=self.docker.run((*self._base(),"ps","-q",service),30)
   identifier=raw.decode().strip() if code==0 else ""
   inspected=self._json((c["dockerPath"],"inspect",identifier)) if identifier else None
   if not isinstance(inspected,list) or len(inspected)!=1:
    raise RollbackProbeError("blue container identity differs")
   item=inspected[0];labels=item.get("Config",{}).get("Labels",{})
   expected=c["databaseImage"] if service=="db" else c["applicationImage"]
   network=item.get("NetworkSettings",{}).get("Networks",{}).get(c["blueNetwork"],{})
   if item.get("Image")!=expected or item.get("State",{}).get("Running") is not True \
      or labels.get("com.docker.compose.project")!=c["blueProject"] \
      or labels.get("com.docker.compose.service")!=service \
      or network.get("NetworkID")!=c["blueNetworkId"]:
    raise RollbackProbeError("blue container identity differs")
  if certified:
   self.db_fence.verify_open("blue",self.operation,self.contract)
   self.db_fence.verify_closed("green",self.operation,self.contract)
   self.producer_fence.verify_open(self._producer_manifest(),contract=self.contract)
  else:self._verify_fences()
 def _data(self):
  snapshot=self.source_provider.capture_database_snapshot(
   canonical_observer_binding(self.contract,"source"))
  source=self.contract["source"]
  for key in ("applicationCount","schema","dataDumpFingerprintSha256",
              "businessDataDumpFingerprintSha256"):
   if snapshot.get(key)!=source.get(key):raise RollbackProbeError("blue source data differs")
  return digest({key:snapshot[key] for key in ("applicationCount","schema",
   "dataDumpFingerprintSha256","businessDataDumpFingerprintSha256")})
 def observe(self,action):
  if action not in self.ACTIONS:raise RollbackProbeError("rollback probe action is not allowlisted")
  c=self.config
  if action=="verify-blue-network":
   network=self._json((c["dockerPath"],"network","inspect",c["blueNetwork"]))
   if not isinstance(network,list) or len(network)!=1 or network[0].get("Id")!=c["blueNetworkId"]:
    raise RollbackProbeError("blue network identity differs")
   return digest({"blueNetworkId":c["blueNetworkId"]})
  self._services(certified=action=="verify-blue-health")
  if action=="verify-blue-services-readonly":
   return digest({"services":list(self.SERVICES),"mode":"read-only"})
  if action=="verify-blue-health":
   token=self._protected(Path(c["tokenFile"]),65536).decode().strip()
   status,body=self.http.request(c["readUrl"],token,c["caFile"],10)
   if status!=200 or hashlib.sha256(body).hexdigest()!=c["readResultSha256"]:
    raise RollbackProbeError("certified blue health differs")
   return digest({"read":c["readResultSha256"],"certified":True})
  if action=="verify-blue-data":return self._data()
  if action=="verify-green-retained":
   volume=self._json((c["dockerPath"],"volume","inspect",c["greenVolume"]))
   if not isinstance(volume,list) or len(volume)!=1:raise RollbackProbeError("green volume is absent")
   item=volume[0];identity=digest({"name":item.get("Name"),"mountpoint":item.get("Mountpoint"),
                                  "driver":item.get("Driver")})
   if identity!=c["greenVolumeId"] or identity!=self.contract["candidate"]["databaseVolumeId"]:
    raise RollbackProbeError("green candidate identity differs")
   return identity
  token=self._protected(Path(c["tokenFile"]),65536).decode().strip()
  if action=="verify-blue-unsigned-denial":
   results={url:self.http.request(url,None,c["caFile"],10)[0] for url in c["unsignedUrls"]}
   if any(status!=401 for status in results.values()):raise RollbackProbeError("unsigned request admitted")
   return digest(results)
  if action=="verify-blue-read":
   status,body=self.http.request(c["readUrl"],token,c["caFile"],10)
   if status!=200 or hashlib.sha256(body).hexdigest()!=c["readResultSha256"]:
    raise RollbackProbeError("authenticated blue read differs")
   return digest({"read":c["readResultSha256"]})
  results={"write":self.http.request(c["writeDenialUrl"],token,c["caFile"],10)[0],
           "job":self.http.request(c["jobDenialUrl"],token,c["caFile"],10)[0]}
  if results!={"write":c["writeDenialStatus"],"job":c["jobDenialStatus"]}:
   raise RollbackProbeError("read-only capability admitted mutation")
  self._verify_fences();return digest(results)
