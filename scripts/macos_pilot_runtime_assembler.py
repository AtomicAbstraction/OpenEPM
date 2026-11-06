#!/usr/bin/env python3
"""Atomic offline assembler for the protected Mac-pilot activation runtime.

The input is one reviewed canonical manifest.  It is data, not an executable
recipe: paths are relative, object kinds and modes are allowlisted, and every
file payload is digest-bound.  The assembler performs no Docker, launchctl,
network, database, or activation action.
"""
from __future__ import annotations
import base64,hashlib,json,os,re,stat,sys,tempfile
from dataclasses import dataclass
from pathlib import Path,PurePosixPath

_PROJECT_ROOT=Path(__file__).resolve().parents[1]
for _module_root in (Path(__file__).resolve().parent,
                     _PROJECT_ROOT/'deploy'/'macos-pilot'):
 if str(_module_root) not in sys.path:sys.path.insert(0,str(_module_root))

SHA=re.compile(r'^[0-9a-f]{64}$')
REQUIRED_COMPONENTS=frozenset({'privilegedController','hostAdapter',
 'publicAdmission','activeWork','phaseAStoppedProvider','greenStoppedProvider',
 'slotPostgresFence','protectedBackup','greenPrepare','readonlyProbe',
 'rollbackProbe','producerFence','producerReopen','stagedSlot',
 'bootstrapContract','rollbackGate','activeGate'})
PRIVILEGED_COMPONENTS=REQUIRED_COMPONENTS-{
 'hostAdapter','producerReopen','rollbackGate','activeGate',
 'producerFence'}
EXECUTOR_COMPONENTS=frozenset({'stagedSlot'})

class RuntimeAssemblyError(RuntimeError):pass
def canonical(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def digest(v):return hashlib.sha256(canonical(v)).hexdigest()

@dataclass(frozen=True)
class ActivationRuntimeLayout:
 root:Path
 manifest_sha256:str
 components:dict[str,Path]
 role:str|None=None
 parent_assembly_sha256:str|None=None

ActivationRuntime=ActivationRuntimeLayout

@dataclass(frozen=True)
class PrivilegedActivationRuntime:
 layout:ActivationRuntimeLayout
 controller:object
 postgres_fence:object
 protected_backup:object
 green_prepare:object
 producer_fences:dict
 readonly_probe:object
 rollback_probe:object
 candidate_stopped_source:object
 host_adapter:object
 admission_publisher:object
 producer_reopen_publisher:object
 authority_server:object

@dataclass(frozen=True)
class ExecutorActivationRuntime:
 layout:ActivationRuntimeLayout
 authority_client:object
 secure_service:object
 signer:object
 rollback_gate_reader:object
 active_gate_reader:object
 executor:object

def _relative(value):
 if not isinstance(value,str):raise RuntimeAssemblyError('assembly path is invalid')
 p=PurePosixPath(value)
 if p.is_absolute() or not p.parts or any(x in ('','.', '..') for x in p.parts):
  raise RuntimeAssemblyError('assembly path is invalid')
 return p

def _validate(manifest):
 if not isinstance(manifest,dict):raise RuntimeAssemblyError('reviewed assembly manifest is invalid')
 modern=manifest.get('format')=='openepm-macos-pilot-role-runtime-assembly-v2'
 expected=({'format','generation','entries','components','manifestSha256','role',
            'parentAssemblySha256','ownerUid','ownerGid'} if modern else
           {'format','generation','entries','components','manifestSha256'})
 if set(manifest)!=expected \
    or (not modern and manifest.get('format')!='openepm-macos-pilot-runtime-assembly-v1') \
    or not isinstance(manifest.get('generation'),int) or manifest['generation']<1 \
    or manifest.get('manifestSha256')!=digest({k:v for k,v in manifest.items() if k!='manifestSha256'}):
  raise RuntimeAssemblyError('reviewed assembly manifest is invalid')
 if modern and (manifest.get('role') not in ('privileged','executor') \
    or not isinstance(manifest.get('parentAssemblySha256'),str) \
    or SHA.fullmatch(manifest['parentAssemblySha256']) is None \
    or not isinstance(manifest.get('ownerUid'),int) \
    or isinstance(manifest.get('ownerUid'),bool) or manifest['ownerUid']<0 \
    or not isinstance(manifest.get('ownerGid'),int) \
    or isinstance(manifest.get('ownerGid'),bool) or manifest['ownerGid']<0):
  raise RuntimeAssemblyError('role assembly binding is invalid')
 entries=manifest['entries'];components=manifest['components']
 required=(REQUIRED_COMPONENTS if not modern else PRIVILEGED_COMPONENTS
           if manifest['role']=='privileged' else EXECUTOR_COMPONENTS)
 if not isinstance(entries,list) or not isinstance(components,dict) \
    or set(components)!=required:
  raise RuntimeAssemblyError('assembly inventory is incomplete')
 seen=set()
 for item in entries:
  if not isinstance(item,dict) or set(item)!={'path','kind','mode','payloadBase64','sha256'}:
   raise RuntimeAssemblyError('assembly entry is invalid')
  p=str(_relative(item['path']))
  if p in seen:raise RuntimeAssemblyError('assembly path is duplicated')
  seen.add(p);kind=item['kind'];mode=item['mode']
  if (kind,mode) not in (('directory',448),('protected',256),('resource',256),
                         ('secret',256),('executable',320)):
   raise RuntimeAssemblyError('assembly object mode is invalid')
  payload=item['payloadBase64']
  if kind=='directory':
   if payload is not None or item['sha256'] is not None:raise RuntimeAssemblyError('directory payload is invalid')
  else:
   try:raw=base64.b64decode(payload,validate=True)
   except (ValueError,TypeError) as error:raise RuntimeAssemblyError('assembly payload is invalid') from error
   if not raw or len(raw)>4*1024*1024 or hashlib.sha256(raw).hexdigest()!=item['sha256']:
    raise RuntimeAssemblyError('assembly payload digest differs')
 for name,path in components.items():
  if str(_relative(path)) not in seen:raise RuntimeAssemblyError(f'component {name} is absent')
 return manifest

def _verify(root,manifest):
 expected={item['path']:item for item in manifest['entries']}
 actual=[]
 for path in root.rglob('*'):
  relative=str(path.relative_to(root));
  if relative=='.assembly.json':continue
  actual.append(relative);item=expected.get(relative)
  if item is None or path.is_symlink() or (path.is_file()
      and path.stat().st_nlink!=1):
   raise RuntimeAssemblyError('assembled runtime contains an unknown object')
  if stat.S_IMODE(path.stat().st_mode)!=item['mode']:
   raise RuntimeAssemblyError('assembled runtime mode differs')
  if item['kind']=='directory':
   if not path.is_dir():raise RuntimeAssemblyError('assembled directory differs')
  elif not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
   raise RuntimeAssemblyError('assembled file differs')
 if set(actual)!=set(expected):raise RuntimeAssemblyError('assembled runtime is incomplete')
 attestation=root/'.assembly.json'
 if not attestation.is_file() or stat.S_IMODE(attestation.stat().st_mode)!=0o400 \
    or json.loads(attestation.read_bytes())!={'manifestSha256':manifest['manifestSha256']}:
  raise RuntimeAssemblyError('assembly attestation differs')

def assemble_activation_runtime(manifest:dict,destination:Path,*,_test_owner_uid=None,
                                _production_owner=None)->ActivationRuntimeLayout:
 manifest=_validate(manifest);destination=Path(destination)
 if _production_owner is not None:
  if os.geteuid()!=0 or _test_owner_uid is not None \
     or not isinstance(_production_owner,tuple) or len(_production_owner)!=2:
   raise RuntimeAssemblyError('production role ownership is invalid')
  owner,group=_production_owner
 else:owner=0 if _test_owner_uid is None else _test_owner_uid;group=None
 if not destination.is_absolute() or destination.is_symlink():raise RuntimeAssemblyError('destination is unsafe')
 parent=destination.parent;meta=os.lstat(parent)
 if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0,owner) \
    or meta.st_mode&(stat.S_IWGRP|stat.S_IWOTH) and not meta.st_mode&stat.S_ISVTX:
  raise RuntimeAssemblyError('destination ancestry is unsafe')
 if destination.exists():
  _verify(destination,manifest);return _layout(destination,manifest,owner)
 staging=Path(tempfile.mkdtemp(prefix='.'+destination.name+'.',dir=parent));staging.chmod(0o700)
 try:
  # Parent directories must be declared; ordering is deterministic.
  for item in sorted(manifest['entries'],key=lambda x:(len(PurePosixPath(x['path']).parts),x['path'])):
   path=staging/item['path'];path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   if item['kind']=='directory':path.mkdir(mode=item['mode'],exist_ok=True)
   else:
    raw=base64.b64decode(item['payloadBase64'],validate=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,item['mode'])
    try:os.write(fd,raw);os.fchmod(fd,item['mode']);os.fsync(fd)
    finally:os.close(fd)
  att=staging/'.assembly.json';att.write_bytes(canonical({'manifestSha256':manifest['manifestSha256']}));att.chmod(0o400)
  if group is not None:
   for path in sorted(staging.rglob('*'),key=lambda item:len(item.parts),reverse=True):
    os.chown(path,owner,group,follow_symlinks=False)
   os.chown(staging,owner,group,follow_symlinks=False)
  os.rename(staging,destination)
 except Exception:
  # Staging contains only newly generated immutable configuration.  Leave it
  # for operator inspection rather than recursively deleting an uncertain path.
  raise
 return _layout(destination,manifest,owner)

def install_role_runtime(manifest:dict,destination:Path)->ActivationRuntimeLayout:
 """Root-only atomic role install; ownership comes only from signed manifest."""
 manifest=_validate(manifest)
 if manifest.get('format')!='openepm-macos-pilot-role-runtime-assembly-v2' \
    or os.geteuid()!=0 or (manifest['role']=='privileged' and manifest['ownerUid']!=0) \
    or (manifest['role']=='executor' and manifest['ownerUid']==0):
  raise RuntimeAssemblyError('production role installation policy differs')
 destination=Path(destination);owner=manifest['ownerUid'];group=manifest['ownerGid']
 if destination.exists():return _layout(destination,manifest,owner)
 layout=assemble_activation_runtime(manifest,destination,
  _production_owner=(owner,group))
 parent_fd=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(parent_fd)
 finally:os.close(parent_fd)
 return _layout(destination,manifest,owner)

def _layout(root:Path,manifest:dict,owner:int)->ActivationRuntimeLayout:
 manifest=_validate(manifest);root=Path(root)
 if not root.is_absolute() or root.is_symlink() or not root.is_dir() \
    or root.stat().st_uid!=owner or stat.S_IMODE(root.stat().st_mode)!=0o700:
  raise RuntimeAssemblyError('runtime root is unsafe')
 _verify(root,manifest)
 return ActivationRuntimeLayout(root,manifest['manifestSha256'],
  {name:root/path for name,path in manifest['components'].items()},
  manifest.get('role'),manifest.get('parentAssemblySha256'))

def verify_activation_runtime_layout(root:Path,manifest:dict,*,
                                     _test_owner_uid=None)->ActivationRuntimeLayout:
 return _layout(Path(root),manifest,0 if _test_owner_uid is None else _test_owner_uid)

def verify_role_assembly_pair(privileged:ActivationRuntimeLayout,
                              executor:ActivationRuntimeLayout):
 try:
  executor.root.relative_to(privileged.root);nested=True
 except ValueError:
  try:privileged.root.relative_to(executor.root);nested=True
  except ValueError:nested=False
 if privileged.role!='privileged' or executor.role!='executor' \
    or nested \
    or privileged.parent_assembly_sha256 is None \
    or privileged.parent_assembly_sha256!=executor.parent_assembly_sha256:
  raise RuntimeAssemblyError('activation role assemblies are incompatible')
 return privileged.parent_assembly_sha256

def _protected_json(path:Path,owner:int,maximum=2*1024*1024):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  meta=os.fstat(fd)
  if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=owner \
     or stat.S_IMODE(meta.st_mode)!=0o400 or not 1<=meta.st_size<=maximum:
   raise RuntimeAssemblyError('runtime binding is unsafe')
  raw=os.read(fd,maximum+1)
 finally:os.close(fd)
 try:value=json.loads(raw.decode())
 except Exception as error:raise RuntimeAssemblyError('runtime binding is invalid') from error
 if not isinstance(value,dict) or raw!=canonical(value):raise RuntimeAssemblyError(
  'runtime binding is not canonical')
 return value

RUNTIME_COMMON_KEYS=frozenset({'format','role','parentAssemblySha256',
 'serviceUid','serviceGid','socketPath',
 'executorKeyId','executorKeyVersion','authorityKeyId','authorityKeyVersion',
 'evidenceKeyId','evidenceKeyVersion',
 'authorityGateRoot','socketDirectory','runtimeStateRoot',
 'trustRegistryFile','controllerAttemptsRoot','gateAttemptsRoot',
 'authorityAttemptsRoot','stoppedProofAuthorityRoot','backupEvidenceRoot',
 'greenAttemptsRoot','activationStateRoot','admissionEvidenceRoot',
 'hostAdapterAttemptsRoot','producerReopenRoot','slotFenceStateRoot',
 'protectedBackupStateRoot','prepareOperationKey'})
RUNTIME_KEYS_BY_ROLE={
 'privileged':RUNTIME_COMMON_KEYS|{'authorityPrivateKeyFile','evidencePrivateKeyFile','blueAdminDsnFile',
                                   'greenAdminDsnFile'},
 'executor':RUNTIME_COMMON_KEYS|{'executorPrivateKeyFile'},
}
MUTABLE_ROOT_KEYS=frozenset({'controllerAttemptsRoot','gateAttemptsRoot',
 'authorityAttemptsRoot','stoppedProofAuthorityRoot','backupEvidenceRoot',
 'greenAttemptsRoot','activationStateRoot','admissionEvidenceRoot',
 'hostAdapterAttemptsRoot','producerReopenRoot','slotFenceStateRoot',
 'protectedBackupStateRoot'})
RUNTIME_STATE_POLICY={
 'controllerAttemptsRoot':{'backup':True,'reset':'retain-for-replay','retention':'release'},
 'gateAttemptsRoot':{'backup':True,'reset':'retain-for-replay','retention':'release'},
 'authorityAttemptsRoot':{'backup':True,'reset':'retain-for-replay','retention':'release'},
 'stoppedProofAuthorityRoot':{'backup':True,'reset':'retain-latest','retention':'activation'},
 'backupEvidenceRoot':{'backup':True,'reset':'retain-recovery','retention':'operator'},
 'greenAttemptsRoot':{'backup':True,'reset':'retain-for-replay','retention':'release'},
 'activationStateRoot':{'backup':True,'reset':'retain-until-cutover','retention':'release'},
 'admissionEvidenceRoot':{'backup':True,'reset':'retain-latest','retention':'activation'},
 'hostAdapterAttemptsRoot':{'backup':True,'reset':'retain-for-replay','retention':'release'},
 'producerReopenRoot':{'backup':True,'reset':'retain-latest','retention':'activation'},
 'slotFenceStateRoot':{'backup':True,'reset':'retain-recovery','retention':'release'},
 'protectedBackupStateRoot':{'backup':True,'reset':'retain-recovery','retention':'operator'},
}
if set(RUNTIME_STATE_POLICY)!=MUTABLE_ROOT_KEYS:raise RuntimeError(
 'runtime state policy inventory differs')

def _binding(layout:ActivationRuntimeLayout,owner:int,authority_owner:int=0):
 value=_protected_json(layout.components['stagedSlot'],owner)
 role=layout.role
 if role not in RUNTIME_KEYS_BY_ROLE or set(value)!=RUNTIME_KEYS_BY_ROLE[role] \
    or value.get('format')!='openepm-macos-pilot-role-runtime-binding-v2' \
    or value.get('role')!=role or value.get('parentAssemblySha256')!= \
    layout.parent_assembly_sha256 or not isinstance(
     value.get('serviceUid'),int) or isinstance(value.get('serviceUid'),bool) \
    or value['serviceUid']<1 or not isinstance(value.get('serviceGid'),int) \
    or isinstance(value.get('serviceGid'),bool) or value['serviceGid']<0 \
    or not isinstance(value.get('socketPath'),str) \
    or not Path(value['socketPath']).is_absolute():
  raise RuntimeAssemblyError('runtime binding differs')
 for name,mode,expected in (('authorityGateRoot',0o555,authority_owner),
                   ('socketDirectory',0o750,authority_owner),
                   ('runtimeStateRoot',0o700,owner)):
  path=Path(value[name]) if isinstance(value.get(name),str) else Path('.')
  if not path.is_absolute() or path.is_symlink() or not path.is_dir() \
     or path.stat().st_uid!=expected or stat.S_IMODE(path.stat().st_mode)!=mode:
   raise RuntimeAssemblyError(f'runtime shared {name} is unsafe')
 if Path(value['socketPath']).parent!=Path(value['socketDirectory']):
  raise RuntimeAssemblyError('runtime socket binding differs')
 for signing_role in ('executor','authority','evidence'):
  if not isinstance(value.get(signing_role+'KeyId'),str) or not value[signing_role+'KeyId'] \
     or not isinstance(value.get(signing_role+'KeyVersion'),int) \
     or isinstance(value.get(signing_role+'KeyVersion'),bool) \
     or value[signing_role+'KeyVersion']<1:
   raise RuntimeAssemblyError(f'runtime {signing_role} signing identity differs')
 if len({value['executorKeyId'],value['authorityKeyId'],value['evidenceKeyId']})!=3:
  raise RuntimeAssemblyError('runtime signing roles are not distinct')
 paths={}
 excluded={'format','role','parentAssemblySha256',
                           'serviceUid','serviceGid','socketPath',
                           'authorityGateRoot','socketDirectory',
                           'runtimeStateRoot',
                           'prepareOperationKey','executorKeyId','executorKeyVersion',
                           'authorityKeyId','authorityKeyVersion'}
 excluded.update({'evidenceKeyId','evidenceKeyVersion'})
 state_root=Path(value['runtimeStateRoot'])
 for name in MUTABLE_ROOT_KEYS:
  relative=_relative(value[name]);path=state_root/relative
  try:path.relative_to(state_root)
  except ValueError as error:raise RuntimeAssemblyError(
   'runtime mutable binding escapes state root') from error
  if not path.is_dir() or path.is_symlink() or path.stat().st_uid!=owner \
     or stat.S_IMODE(path.stat().st_mode)!=0o700:
   raise RuntimeAssemblyError(f'runtime mutable binding {name} is unsafe')
  paths[name]=path
 for name in RUNTIME_KEYS_BY_ROLE[role]-excluded-MUTABLE_ROOT_KEYS:
  relative=_relative(value[name]);path=layout.root/relative
  try:path.relative_to(layout.root)
  except ValueError as error:raise RuntimeAssemblyError(
   'runtime binding escapes assembly') from error
  if not path.exists() or path.is_symlink():raise RuntimeAssemblyError(
   f'runtime binding {name} is unavailable')
  paths[name]=path
 if not isinstance(value.get('prepareOperationKey'),str) or len(
     value['prepareOperationKey'])!=64:
  raise RuntimeAssemblyError('runtime prepare operation is invalid')
 if role=='privileged':
  helper_root=layout.components['privilegedController'].parent
  helper_config=_protected_json(layout.components['privilegedController'],owner)
  if paths['authorityPrivateKeyFile']!=helper_root/'authority-ed25519.key' \
     or paths['trustRegistryFile']!=helper_root/'executor-trust-snapshot.json' \
     or helper_config.get('runtimeStateRoot')!=value['runtimeStateRoot']:
   raise RuntimeAssemblyError('privileged helper authority binding differs')
 return value,paths

def _private_key(path,owner):
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  meta=os.fstat(fd);raw=os.read(fd,33)
  if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=owner \
     or stat.S_IMODE(meta.st_mode)!=0o400 or len(raw)!=32:
   raise RuntimeAssemblyError('executor private key is unsafe')
 finally:os.close(fd)
 return Ed25519PrivateKey.from_private_bytes(raw)

def _trust(path,owner):
 from validate_macos_pilot_activation_receipt import trust_registry_from_runtime_value
 value=_protected_json(path,owner)
 try:
  return trust_registry_from_runtime_value(value)
 except Exception as error:raise RuntimeAssemblyError(
  'runtime trust registry is invalid') from error

def _bind_signing_key(private_key,trust,key_id,version,role):
 from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
 try:trusted=trust.verifier_public_key(key_id,role=role,version=version)
 except Exception as error:raise RuntimeAssemblyError(
  f'runtime {role} signing identity is not trusted') from error
 actual=private_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
 expected=trusted.public_bytes(Encoding.Raw,PublicFormat.Raw)
 if actual!=expected:raise RuntimeAssemblyError(
  f'runtime {role} private key differs from trust registry')

def _text(path,owner):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  meta=os.fstat(fd);raw=os.read(fd,16385)
  if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=owner \
     or stat.S_IMODE(meta.st_mode)!=0o400 or not 1<=len(raw)<=16384:
   raise RuntimeAssemblyError('protected runtime text is unsafe')
 finally:os.close(fd)
 try:value=raw.decode().rstrip('\n')
 except UnicodeError as error:raise RuntimeAssemblyError(
  'protected runtime text is invalid') from error
 if not value or '\n' in value or '\r' in value:raise RuntimeAssemblyError(
  'protected runtime text is invalid')
 return value

class _ProducerBoundary:
 """Concrete root boundary; service start remains a separate phase effect."""
 def __init__(self,admission,runtime,controller,dsn):
  self.admission,self.runtime,self.controller,self.dsn=admission,runtime,controller,dsn
 def public_admission_closed(self,*_):
  try:self.admission.verify_closed();return True
  except Exception:return False
 def workers_running(self):return self.runtime.workers_running()
 def stop_all_producers(self,operation,contract):
  return self.controller.compose('stop-app-and-broker-services',operation,contract)
 def producer_sessions_zero(self):
  from epm_core.postgres_connection import connect_postgres
  with connect_postgres(self.dsn,autocommit=True) as db:
   return db.execute("SELECT count(*) FROM pg_stat_activity WHERE "
    "datname=current_database() AND pid<>pg_backend_pid()").fetchone()[0]==0
 def producers_stopped(self):return self.runtime.workers_running() is False
 def start_all_producers(self,*_):raise RuntimeAssemblyError(
  'producer service start is a separate authority effect')

class _ProtectedProducerManifestProvider:
 """Read the current root-owned producer manifest only when a phase needs it."""
 def __init__(self,root:Path,owner:int):
  self.root=Path(root);self.owner=owner
 def current(self,slot:str)->dict:
  if slot not in ('blue','green'):raise RuntimeAssemblyError(
   'producer manifest slot differs')
  return _protected_json(self.root/f'{slot}-producer-fence.json',self.owner)

class _RuntimeProducerManifestProvider:
 def __init__(self,root:Path,owner:int):self.root=Path(root);self.owner=owner
 def current(self,slot:str)->dict:
  if slot not in ('blue','green'):raise RuntimeAssemblyError(
   'producer manifest slot differs')
  value=_protected_json(self.root/'all-producer-fence.json',self.owner)
  if value.get('slot') not in (None,slot):raise RuntimeAssemblyError(
   'producer manifest selected slot differs')
  return value

def build_privileged_activation_runtime(root:Path,manifest:dict,*,
        _test_owner_uid=None,_test_effective_uid=None)->PrivilegedActivationRuntime:
 """Construct the root-only authority graph from one verified assembly."""
 owner=0 if _test_owner_uid is None else _test_owner_uid
 layout=_layout(Path(root),manifest,owner)
 if layout.role!='privileged' or layout.parent_assembly_sha256 is None:
  raise RuntimeAssemblyError('privileged role assembly is required')
 binding,paths=_binding(layout,owner,owner)
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 from macos_pilot_privileged_controller import (PrivilegedMacPilotController,
  ProtectedBootstrapProvider,SubprocessBackend)
 from protected_stopped_proof_provider import ProtectedStoppedProofProvider
 from slot_postgres_write_fence import FixedSlotPostgresWriteFence
 from macos_pilot_public_admission import PublicAdmissionBoundary,FixedLaunchctlBackend
 from macos_pilot_public_admission_open_authority import (
  ProtectedAdmissionOpenAuthority,PublicAdmissionOpenAuthorityPublisher)
 from macos_pilot_active_work_authority import ProtectedActiveWorkRuntime
 from macos_pilot_active_work import ActiveWorkObserver
 from macos_pilot_all_producer_fence import AllProducerFence
 from protected_backup_evidence_provider import ProtectedBackupEvidenceProvider
 from macos_pilot_slot_protected_backup import (FixedSlotProtectedBackup,
  FixedContainerPgDumpBackend,SubprocessBackupProcessBackend)
 from macos_pilot_green_prepare import GreenPrepareBoundary,GreenSubprocessProcess
 from macos_pilot_readonly_probe import ProtectedReadOnlyProbe,SubprocessDocker,FixedHttps
 from macos_pilot_rollback_probe import ProtectedRollbackProbe
 from capture_macos_pilot_stopped_source import (ConcreteStoppedSourceProvider,
  canonical_observer_binding)
 from macos_pilot_rollback_gate_publisher import DurableRollbackGatePublisher
 from macos_pilot_host_adapter import BoundedMacPilotRunner,MacPilotHostAdapter
 from macos_pilot_activation_ipc import (ActivationAuthorityServer,
  ProtectedAdmissionOpenEvidenceSource)
 from macos_pilot_producer_reopen_publisher import ProducerReopenPublisher
 key=_private_key(paths['authorityPrivateKeyFile'],owner)
 evidence_key=_private_key(paths['evidencePrivateKeyFile'],owner)
 trust=_trust(paths['trustRegistryFile'],owner)
 _bind_signing_key(key,trust,binding['authorityKeyId'],
  binding['authorityKeyVersion'],'authority')
 _bind_signing_key(evidence_key,trust,binding['evidenceKeyId'],
  binding['evidenceKeyVersion'],'evidence')
 bootstrap=ProtectedBootstrapProvider(layout.components['bootstrapContract'],
  _test_owner_uid=owner)
 controller=PrivilegedMacPilotController(layout.components['privilegedController'],
  paths['controllerAttemptsRoot'],SubprocessBackend(),bootstrap,
  _test_owner_uid=owner,_test_effective_uid=_test_effective_uid)
 open_authority=ProtectedAdmissionOpenAuthority(paths['producerReopenRoot'],
  _test_owner_uid=owner)
 admission=PublicAdmissionBoundary(layout.components['publicAdmission'],
  FixedLaunchctlBackend(),evidence_key,_test_owner_uid=owner,
  open_authority=open_authority,open_verifier_key=key.public_key(),
  open_verifier_key_id=binding['authorityKeyId'],
  open_verifier_key_version=binding['authorityKeyVersion'])
 active=ProtectedActiveWorkRuntime(layout.components['activeWork'],
  FixedLaunchctlBackend(),_test_owner_uid=owner)
 stopped=ProtectedStoppedProofProvider(paths['stoppedProofAuthorityRoot'],
  parent_assembly_sha256=layout.parent_assembly_sha256,
  _test_owner_uid=owner,_test_effective_uid=_test_effective_uid)
 fence=FixedSlotPostgresWriteFence(layout.components['slotPostgresFence'],stopped,
  paths['slotFenceStateRoot'],
  _test_owner_uid=owner,_test_effective_uid=_test_effective_uid)
 blue_dsn=_text(paths['blueAdminDsnFile'],owner);green_dsn=_text(
  paths['greenAdminDsnFile'],owner)
 producer_fences={}
 for slot,dsn in (('blue',blue_dsn),('green',green_dsn)):
  boundary=_ProducerBoundary(admission,active,controller,dsn)
  producer_fences[slot]=AllProducerFence(dsn,ActiveWorkObserver(dsn),boundary,key,
   key_id=binding['authorityKeyId'])
 evidence=ProtectedBackupEvidenceProvider(paths['backupEvidenceRoot'],stopped,fence,
  _test_owner_uid=owner,_test_effective_uid=_test_effective_uid)
 backup=FixedSlotProtectedBackup(layout.components['protectedBackup'],evidence,
  FixedContainerPgDumpBackend(SubprocessBackupProcessBackend()),
  paths['protectedBackupStateRoot'],
  _test_owner_uid=owner,_test_effective_uid=_test_effective_uid)
 green=GreenPrepareBoundary(layout.components['greenPrepare'],paths['greenAttemptsRoot'],
  GreenSubprocessProcess(),backup,fence,_test_owner_uid=owner)
 contract=bootstrap.seal(binding['prepareOperationKey'])
 manifests=_ProtectedProducerManifestProvider(paths['admissionEvidenceRoot'],owner)
 readonly=ProtectedReadOnlyProbe(layout.components['readonlyProbe'],SubprocessDocker(),
  FixedHttps(),fence,producer_fences['green'],manifests,
  binding['prepareOperationKey'],contract,_test_owner_uid=owner)
 source=ConcreteStoppedSourceProvider(layout.components['phaseAStoppedProvider'],
  _test_owner_uid=owner)
 candidate_source=ConcreteStoppedSourceProvider(
  layout.components['greenStoppedProvider'],_test_owner_uid=owner)
 for provider,slot in ((source,'source'),(candidate_source,'candidate')):
  selected=contract[slot];observer=canonical_observer_binding(contract,slot)
  if provider.config.get('bindingSha256')!=contract['executionContractSha256'] \
     or provider.config.get('observerBindingSha256')!=observer['configSha256'] \
     or provider.config.get('project')!=selected['project']:
   raise RuntimeAssemblyError(slot+' stopped provider binding differs')
 rollback=ProtectedRollbackProbe(layout.components['rollbackProbe'],SubprocessDocker(),
  FixedHttps(),fence,producer_fences['blue'],manifests,source,
  binding['prepareOperationKey'],contract,_test_owner_uid=owner)
 gate=DurableRollbackGatePublisher(Path(binding['authorityGateRoot']),
  paths['gateAttemptsRoot'],private_key=key,key_id=binding['authorityKeyId'],
  key_version=binding['authorityKeyVersion'],_test_owner_uid=owner,
  _test_effective_uid=_test_effective_uid)
 runner=BoundedMacPilotRunner(controller,fence)
 adapter=MacPilotHostAdapter(paths['hostAdapterAttemptsRoot'],runner,gate,
  active_gate_publisher=gate,_test_owner_uid=owner)
 public_source=ProtectedAdmissionOpenEvidenceSource(Path(binding['runtimeStateRoot']),fence,
  producer_fences,trust_registry_path=paths['trustRegistryFile'],
  authority_gate_root=Path(binding['authorityGateRoot']),
  _test_owner_uid=owner)
 public_publisher=PublicAdmissionOpenAuthorityPublisher(
  paths['producerReopenRoot'],public_source,key,
  key_id=binding['authorityKeyId'],
  key_version=binding['authorityKeyVersion'],_test_owner_uid=owner)
 producer_publisher=ProducerReopenPublisher(paths['producerReopenRoot'],key,
  key_id=binding['authorityKeyId'],key_version=binding['authorityKeyVersion'],
  _test_owner_uid=owner)
 runtime_manifests=_RuntimeProducerManifestProvider(
  Path(binding['runtimeStateRoot']),owner)
 trust_value=_protected_json(paths['trustRegistryFile'],owner)
 authority=ActivationAuthorityServer(Path(binding['socketPath']),
  paths['authorityAttemptsRoot'],service_uid=binding['serviceUid'],
  service_gid=binding['serviceGid'],adapter=adapter,
  admission_publisher=public_publisher,
  parent_assembly_sha256=layout.parent_assembly_sha256,_test_owner_uid=owner,
  trust_registry=trust,executor_key_id=binding['executorKeyId'],
  executor_key_version=binding['executorKeyVersion'],
  executor_evidence_root=Path(binding['runtimeStateRoot']),
  producer_reopen_publisher=producer_publisher,
  producer_manifest_provider=runtime_manifests,
  producer_trust_value=trust_value,
  _test_effective_uid=_test_effective_uid)
 return PrivilegedActivationRuntime(layout,controller,fence,backup,green,
  producer_fences,readonly,rollback,candidate_source,adapter,public_publisher,
  producer_publisher,authority)

def build_executor_activation_runtime(root:Path,manifest:dict,*,
        _test_owner_uid=None,_test_effective_uid=None,
        _test_authority_owner_uid=None)->ExecutorActivationRuntime:
 """Construct the non-root journal/executor graph with no host privileges."""
 owner=os.geteuid() if _test_owner_uid is None else _test_owner_uid
 layout=_layout(Path(root),manifest,owner)
 if layout.role!='executor' or layout.parent_assembly_sha256 is None:
  raise RuntimeAssemblyError('executor role assembly is required')
 authority_owner=0 if _test_authority_owner_uid is None else _test_authority_owner_uid
 binding,paths=_binding(layout,owner,authority_owner)
 if __package__:
  from .execute_macos_pilot_activation import (ActivationExecutor,ExecutorSigner,
   ProtectedRollbackGateReader,ProtectedActiveGateReader)
  from .macos_pilot_secure_activation import SecureActivationService
  from .macos_pilot_activation_ipc import ActivationAuthorityClient
 else:
  from execute_macos_pilot_activation import (ActivationExecutor,ExecutorSigner,
   ProtectedRollbackGateReader,ProtectedActiveGateReader)
  from macos_pilot_secure_activation import SecureActivationService
  from macos_pilot_activation_ipc import ActivationAuthorityClient
 key=_private_key(paths['executorPrivateKeyFile'],owner)
 trust=_trust(paths['trustRegistryFile'],owner)
 _bind_signing_key(key,trust,binding['executorKeyId'],
  binding['executorKeyVersion'],'executor')
 service=SecureActivationService(paths['activationStateRoot'],trust)
 client=ActivationAuthorityClient(Path(binding['socketPath']),
  expected_server_uid=0,parent_assembly_sha256=layout.parent_assembly_sha256,
  _test_effective_uid=_test_effective_uid)
 signer=ExecutorSigner(binding['executorKeyId'],binding['executorKeyVersion'],key,
  layout.parent_assembly_sha256)
 runtime_uid=os.geteuid() if _test_effective_uid is None else _test_effective_uid
 rollback=ProtectedRollbackGateReader(Path(binding['authorityGateRoot']),
  _test_authority_owner_uid=authority_owner,_test_runtime_uid=runtime_uid)
 active=ProtectedActiveGateReader(Path(binding['authorityGateRoot']),
  _test_authority_owner_uid=authority_owner,_test_runtime_uid=runtime_uid)
 executor=ActivationExecutor(service,client,signer,rollback,
  admission_open_publisher=client,active_gate_reader=active)
 return ExecutorActivationRuntime(layout,client,service,signer,rollback,active,executor)

def build_activation_runtime(root:Path,manifest:dict,*,role:str,
        _test_owner_uid=None,_test_effective_uid=None,
        _test_authority_owner_uid=None):
 if role=='privileged':return build_privileged_activation_runtime(root,manifest,
  _test_owner_uid=_test_owner_uid,_test_effective_uid=_test_effective_uid)
 if role=='executor':return build_executor_activation_runtime(root,manifest,
  _test_owner_uid=_test_owner_uid,_test_effective_uid=_test_effective_uid,
  _test_authority_owner_uid=_test_authority_owner_uid)
 raise RuntimeAssemblyError('runtime process role must be privileged or executor')
