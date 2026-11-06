#!/usr/bin/env python3
"""Protected fixed probes for the candidate read-only activation phase."""
from __future__ import annotations
import hashlib,json,os,ssl,stat,subprocess,urllib.error,urllib.request
from pathlib import Path

class ReadOnlyProbeError(RuntimeError):pass
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()

class SubprocessDocker:
 def run(self,argv,timeout):
  result=subprocess.run(tuple(argv),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
   stderr=subprocess.PIPE,check=False,timeout=timeout,cwd='/',close_fds=True,
   env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
  return result.returncode,result.stdout

class FixedHttps:
 def request(self,url,token,ca_file,timeout):
  request=urllib.request.Request(url,headers={} if token is None else
   {'Authorization':'Bearer '+token,'Accept':'application/json'})
  try:
   with urllib.request.urlopen(request,context=ssl.create_default_context(cafile=ca_file),
       timeout=timeout) as response:return response.status,response.read(1024*1024+1)
  except urllib.error.HTTPError as error:return error.code,error.read(1024*1024+1)

class ProtectedReadOnlyProbe:
 ACTIONS={'verify-tunnel-stopped','compose-start-green','verify-launcher-network',
  'verify-green-health','verify-unsigned-denial','verify-green-read',
  'verify-blue-preserved'}
 def __init__(self,path:Path,docker,http,db_fence,producer_fence,producer_manifest,
              operation_key,contract,*,_test_owner_uid=None):
  self.path=Path(path);self.owner=0 if _test_owner_uid is None else _test_owner_uid
  self.docker,self.http=docker,http;self.db_fence=db_fence
  self.producer_fence=producer_fence;self.producer_manifest=producer_manifest
  self.operation=operation_key;self.contract=contract;self.config=self._load()
 def _producer_manifest(self):
  value=self.producer_manifest
  if hasattr(value,'current'):value=value.current('green')
  if not isinstance(value,dict):raise ReadOnlyProbeError('producer fence manifest is unavailable')
  return value
 def _protected(self,path,maximum=1024*1024):
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   meta=os.fstat(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=self.owner \
      or stat.S_IMODE(meta.st_mode) not in (0o400,0o444,0o500) \
      or not 1<=meta.st_size<=maximum:raise ReadOnlyProbeError('probe resource is unsafe')
   return os.read(fd,maximum+1)
  finally:os.close(fd)
 def _load(self):
  raw=self._protected(self.path,131072);value=json.loads(raw)
  body={k:v for k,v in value.items() if k!='configSha256'}
  required={'format','dockerPath','composeFile','envFile','greenProject','greenServices',
   'applicationImage','databaseImage','greenNetwork','greenNetworkId','blueVolumeId',
   'admissionArtifact','tokenFile','caFile',
   'unsignedUrls','readUrl','readResultSha256','writeDenialUrl','writeDenialStatus',
   'jobDenialUrl','jobDenialStatus','configSha256'}
  if set(value)!=required or raw!=canonical(value) or value.get('format') \
     !='openepm-macos-pilot-readonly-probe-v1' or value.get('configSha256')!=digest(body) \
     or value.get('greenServices')!=['platform','workspace','router','web','worker','python-build-broker']:
   raise ReadOnlyProbeError('probe config differs')
  for key in ('dockerPath','composeFile','envFile','tokenFile','caFile'):
   self._protected(Path(value[key]))
  admission=Path(value['admissionArtifact'])
  if not admission.is_absolute() or admission.parent.is_symlink() \
     or not admission.parent.is_dir() or admission.parent.stat().st_uid!=self.owner:
   raise ReadOnlyProbeError('admission artifact path is unsafe')
  return value
 def _base(self):
  c=self.config;return (c['dockerPath'],'compose','--project-name',c['greenProject'],
   '--env-file',c['envFile'],'-f',c['composeFile'])
 def _json(self,argv):
  code,out=self.docker.run(argv,30)
  if code:return None
  try:return json.loads(out)
  except Exception as error:raise ReadOnlyProbeError('docker observation is invalid') from error
 def _closed(self,path,kind):
  value=json.loads(self._protected(Path(path)).decode())
  if kind=='admission':return value.get('format') in (
   'openepm-macos-public-admission-closure-v1',
   'openepm-macos-public-admission-closure-v2') \
   and value.get('publicAdmissionStopped') is True
  if kind=='fence':return value.get('state')=='closed' or value.get('closed') is True
  return value.get('producerServicesStopped') is True and value.get('producerSessionsZero') is True
 def _services(self,contract,*,database_state='closed',producer_state='closed'):
  c=self.config
  try:
   getattr(self.db_fence,'verify_'+database_state)('green',self.operation,contract)
   getattr(self.producer_fence,'verify_'+producer_state)(self._producer_manifest(),
                                                        contract=contract)
  except Exception as error:raise ReadOnlyProbeError('live write/job fence is open') from error
  code,out=self.docker.run((*self._base(),'ps','--status','running','--services'),30)
  if code or set(out.decode().split())!=set(('db',*c['greenServices'])):
   raise ReadOnlyProbeError('green service inventory differs')
  for service in ('db',*c['greenServices']):
   code,raw=self.docker.run((*self._base(),'ps','-q',service),30)
   identifier=raw.decode().strip() if code==0 else ''
   if not identifier:raise ReadOnlyProbeError('green container identity differs')
   inspected=self._json((c['dockerPath'],'inspect',identifier))
   if not isinstance(inspected,list) or len(inspected)!=1:raise ReadOnlyProbeError(
    'green container identity differs')
   item=inspected[0];labels=item.get('Config',{}).get('Labels',{})
   expected=c['databaseImage'] if service=='db' else c['applicationImage']
   networks=item.get('NetworkSettings',{}).get('Networks',{})
   if item.get('Image')!=expected or item.get('State',{}).get('Running') is not True \
      or labels.get('com.docker.compose.project')!=c['greenProject'] \
      or labels.get('com.docker.compose.service')!=service \
      or networks.get(c['greenNetwork'],{}).get('NetworkID')!=c['greenNetworkId']:
    raise ReadOnlyProbeError('green container identity differs')
  # Recheck after observing every started service; startup must not have
  # reopened database roles or application processing modes.
  try:
   getattr(self.db_fence,'verify_'+database_state)('green',self.operation,contract)
   getattr(self.producer_fence,'verify_'+producer_state)(self._producer_manifest(),
                                                        contract=contract)
  except Exception as error:raise ReadOnlyProbeError('live fence drifted after start') from error
  return digest({'services':c['greenServices'],'networkId':c['greenNetworkId']})
 def observe(self,action,contract):
  if action not in self.ACTIONS:raise ReadOnlyProbeError('probe action is not allowlisted')
  c=self.config
  if action=='verify-tunnel-stopped':
   if not self._closed(c['admissionArtifact'],'admission'):raise ReadOnlyProbeError('admission is open')
   return digest({'admission':'closed'})
  if action in ('compose-start-green','verify-launcher-network','verify-green-health'):
   return self._services(contract)
  if action=='verify-blue-preserved':
   if contract.get('source',{}).get('databaseVolumeId')!=c['blueVolumeId']:
    raise ReadOnlyProbeError('blue source identity differs')
   return digest({'blueVolumeId':c['blueVolumeId']})
  token=self._protected(Path(c['tokenFile']),65536).decode().strip()
  if action=='verify-unsigned-denial':
   results={url:self.http.request(url,None,c['caFile'],10)[0] for url in c['unsignedUrls']}
   if any(status!=401 for status in results.values()):raise ReadOnlyProbeError('unsigned request admitted')
   return digest(results)
  if action=='verify-green-read':
   status,body=self.http.request(c['readUrl'],token,c['caFile'],10)
   if status!=200 or hashlib.sha256(body).hexdigest()!=c['readResultSha256']:
    raise ReadOnlyProbeError('authenticated read differs')
   # The same scoped identity must have neither write nor job admission.
   for url,expected in ((c['writeDenialUrl'],c['writeDenialStatus']),
                        (c['jobDenialUrl'],c['jobDenialStatus'])):
    observed,_=self.http.request(url,token,c['caFile'],10)
    if observed!=expected:raise ReadOnlyProbeError('read-only capability admitted mutation')
   return digest({'read':c['readResultSha256'],'writeDenied':True,'jobDenied':True})
