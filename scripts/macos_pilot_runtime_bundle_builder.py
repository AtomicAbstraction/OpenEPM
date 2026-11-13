#!/usr/bin/env python3
"""Authoritative reviewed-input builder for split-role Mac-pilot bundles."""
from __future__ import annotations
import argparse,ast,base64,hashlib,json,os,plistlib,stat
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from macos_pilot_runtime_assembler import (EXECUTOR_COMPONENTS,PRIVILEGED_COMPONENTS,
 MUTABLE_ROOT_KEYS,RuntimeAssemblyError,canonical,digest,install_role_runtime)
from macos_pilot_activation import validate_plan as validate_activation_plan

class BundleBuildError(RuntimeError):pass
INPUT_KEYS={'format','generation','identities','serviceUid','serviceGid','paths',
 'keys','approvedContracts','privilegedComponents','executorComponents','roleFiles'}
IDENTITY_KEYS={'sourceSha256','schemaSha256','applicationImage','databaseImage'}
PATH_KEYS={'privilegedRoot','executorRoot','privilegedStateRoot','executorStateRoot',
 'authorityGateRoot','socketDirectory'}
KEY_ROLES=('executor','owner','authority','evidence')
PRODUCTION_PROFILE_KEYS={'format','generation','identities','serviceUid','serviceGid',
 'paths','keys','plan','contract','prepareOperationKey','namespace','runtime','artifacts'}
PRODUCTION_ARTIFACTS={'docker','helper','launchctl','blueCompose','greenCompose',
 'blueEnv','greenEnv','token','ca','blueReceiptKey','greenReceiptKey'}
PRODUCTION_RUNTIME_KEYS={'blueAdminDsn','greenAdminDsn','blueDatabase','greenDatabase',
 'blueSystemIdentifier','greenSystemIdentifier','blueDbContainer','greenDbContainer',
 'blueNetwork','greenNetwork','blueNetworkId','greenNetworkId','blueVolumeId',
 'greenVolumeId','operationsImage','dbConfigHash','volumeMountpoint','baseHttpsUrl',
 'privatePorts','admissionPorts','launchdOwnerUid','launchdDomain','readResultSha256'}
HELPER_MODULES=(
 'scripts/capture_macos_pilot_stopped_source.py','scripts/macos_pilot_activation.py',
 'scripts/macos_pilot_active_work.py','scripts/macos_pilot_active_work_authority.py',
 'scripts/macos_pilot_all_producer_fence.py','scripts/macos_pilot_green_prepare.py',
 'scripts/macos_pilot_producer_fence_actions.py','scripts/macos_pilot_public_admission.py',
 'scripts/macos_pilot_readonly_probe.py','scripts/macos_pilot_rollback_probe.py',
 'scripts/macos_pilot_secure_activation.py','scripts/macos_pilot_slot_protected_backup.py',
 'scripts/macos_pilot_stopped_proof_publisher.py',
 'scripts/validate_macos_pilot_activation_receipt.py',
 'deploy/macos-pilot/postgres_write_fence.py',
 'deploy/macos-pilot/protected_backup_evidence_provider.py',
 'deploy/macos-pilot/protected_producer_reopen_authority.py',
 'deploy/macos-pilot/protected_stopped_proof_provider.py',
 'deploy/macos-pilot/slot_postgres_write_fence.py','epm_core/__init__.py',
 'epm_core/postgres_connection.py','epm_core/postgres_execution_scope.py',
 'epm_core/postgres_pilot_write_gate.py')

def _helper_package():
 root=Path(__file__).resolve().parent.parent
 helper=root/'deploy/macos-pilot/openepm-pilot-host-action'
 try:helper_raw=helper.read_bytes()
 except OSError as error:raise BundleBuildError('helper package source is unavailable') from error
 module_paths={}
 for source in (root/'scripts').glob('*.py'):
  module_paths[source.stem]=source;module_paths['scripts.'+source.stem]=source
 for source in (root/'deploy/macos-pilot').glob('*.py'):module_paths[source.stem]=source
 for source in (root/'epm_core').glob('*.py'):
  module_paths['epm_core.'+source.stem]=source
 queue=[]
 def imports(source,current=None):
  try:tree=ast.parse(source.read_text())
  except (OSError,SyntaxError) as error:raise BundleBuildError(
   'helper module closure cannot be audited') from error
  found=[]
  for node in ast.walk(tree):
   if isinstance(node,ast.Import):found.extend(alias.name for alias in node.names)
   elif isinstance(node,ast.ImportFrom) and node.module:
    name=node.module
    if node.level and current and '.' in current:
     package=current.rsplit('.',node.level)[0];name=package+'.'+name
    found.append(name)
  return found
 queue.extend(imports(helper));selected={}
 while queue:
  name=queue.pop()
  source=module_paths.get(name)
  if source is None or source in selected:continue
  selected[source]=name;queue.extend(imports(source,name))
 for required in HELPER_MODULES:
  if root/required not in selected and not required.endswith('__init__.py'):
   raise BundleBuildError('helper module closure is incomplete')
 selected[root/'epm_core/__init__.py']='epm_core.__init__'
 files=[]
 for source in sorted(selected,key=lambda item:str(item.relative_to(root))):
  relative=str(source.relative_to(root))
  try:raw=source.read_bytes()
  except OSError as error:raise BundleBuildError('helper module closure is unavailable') from error
  destination=('lib/'+relative if relative.startswith(('epm_core/','scripts/')) else
   'lib/'+source.name)
  files.append(_descriptor(destination,raw,'resource'))
 return helper_raw,files

def _sha(value,label):
 if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
  raise BundleBuildError(label+' differs')
 return value
def _payload(value,label):
 if not isinstance(value,dict) or set(value)!={'path','kind','mode','payloadBase64'}:
  raise BundleBuildError(label+' descriptor differs')
 if value['kind']=='directory':
  if value['mode']!=0o700 or value['payloadBase64'] is not None:
   raise BundleBuildError(label+' policy differs')
  return None
 try:raw=base64.b64decode(value['payloadBase64'],validate=True)
 except Exception as error:raise BundleBuildError(label+' payload differs') from error
 if not raw or value['kind'] not in ('protected','resource','secret','executable') \
    or (value['kind'],value['mode']) not in (('protected',0o400),('secret',0o400),
      ('resource',0o400),('executable',0o500)):
  raise BundleBuildError(label+' policy differs')
 if value['kind']=='protected':
  try:parsed=json.loads(raw)
  except Exception as error:raise BundleBuildError(label+' JSON differs') from error
  if raw!=canonical(parsed):raise BundleBuildError(label+' is not canonical')
 return raw
def _entry(value,label):
 raw=_payload(value,label)
 if raw is None:return {'path':value['path'],'kind':'directory','mode':0o700,
  'payloadBase64':None,'sha256':None}
 return {'path':value['path'],'kind':value['kind'],'mode':value['mode'],
  'payloadBase64':value['payloadBase64'],'sha256':hashlib.sha256(raw).hexdigest()}

def _component_identity(name,item):
 """Digest a child component without hashing its embedded parent digest."""
 raw=_payload(item,name)
 if raw is None:return 'directory'
 if name!='stagedSlot':return hashlib.sha256(raw).hexdigest()
 try:value=json.loads(raw)
 except Exception as error:raise BundleBuildError('stagedSlot JSON differs') from error
 if value.get('format')!='openepm-macos-pilot-role-runtime-binding-v2':
  return hashlib.sha256(raw).hexdigest()
 if not isinstance(value.get('parentAssemblySha256'),str):
  raise BundleBuildError('stagedSlot parent binding differs')
 value=dict(value);value['parentAssemblySha256']='<parent-assembly-sha256>'
 return hashlib.sha256(canonical(value)).hexdigest()
def build_bundle(value):
 if not isinstance(value,dict) or set(value)!=INPUT_KEYS \
    or value.get('format')!='openepm-macos-pilot-reviewed-installation-v1' \
    or not isinstance(value.get('generation'),int) or value['generation']<1:
  raise BundleBuildError('reviewed installation input differs')
 identities=value['identities']
 if not isinstance(identities,dict) or set(identities)!=IDENTITY_KEYS:raise BundleBuildError(
  'release identity differs')
 for name,item in identities.items():
  if name.endswith('Image'):
   if not isinstance(item,str) or not item.startswith('sha256:'):_sha('',name)
   _sha(item[7:],name)
  else:_sha(item,name)
 paths=value['paths']
 if not isinstance(paths,dict) or set(paths)!=PATH_KEYS \
    or any(not Path(item).is_absolute() for item in paths.values()):
  raise BundleBuildError('installation paths differ')
 if not isinstance(value['serviceUid'],int) or value['serviceUid']<1 \
    or not isinstance(value['serviceGid'],int) or value['serviceGid']<0:
  raise BundleBuildError('service identity differs')
 keys=value['keys'];materials={};trust=[]
 if not isinstance(keys,dict) or set(keys)!=set(KEY_ROLES):raise BundleBuildError(
  'signing key inventory differs')
 for role in KEY_ROLES:
  item=keys[role]
  if not isinstance(item,dict) or set(item)!={'keyId','version','privateKeyBase64',
    'notBeforeUtc','expiresAtUtc'}:raise BundleBuildError(role+' key differs')
  try:private=base64.b64decode(item['privateKeyBase64'],validate=True);key=Ed25519PrivateKey.from_private_bytes(private)
  except Exception as error:raise BundleBuildError(role+' key differs') from error
  if len(private)!=32:raise BundleBuildError(role+' key differs')
  materials[role]=(private,key.public_key().public_bytes_raw())
  trust.append({'keyId':item['keyId'],'publicKeyBase64':base64.b64encode(
   materials[role][1]).decode(),'role':role,'version':item['version'],
   'notBeforeUtc':item['notBeforeUtc'],'expiresAtUtc':item['expiresAtUtc'],
   'revoked':False})
 if len({item[1] for item in materials.values()})!=4:raise BundleBuildError(
  'signing role key material is not distinct')
 contracts=value['approvedContracts']
 if not isinstance(contracts,list) or not contracts or any(_sha(x,'approved contract')!=x for x in contracts):
  raise BundleBuildError('approved contracts differ')
 trust_value={'format':'openepm-macos-pilot-runtime-trust-v1','keys':trust,
  'approvedContracts':sorted(set(contracts))}
 trust_raw=canonical(trust_value)
 parent_descriptor={'format':'openepm-macos-pilot-parent-assembly-v2',
  'generation':value['generation'],'identities':identities,
  'serviceUid':value['serviceUid'],'serviceGid':value['serviceGid'],
  'paths':paths,'approvedContracts':sorted(set(contracts)),
  'signingIdentities':{role:{'keyId':value['keys'][role]['keyId'],
    'version':value['keys'][role]['version'],'publicKeySha256':hashlib.sha256(
      materials[role][1]).hexdigest()} for role in KEY_ROLES},
  'componentProfileDigests':{role:{name:_component_identity(name,item)
   for name,item in sorted(value[role+'Components'].items())}
   for role in ('privileged','executor')}}
 parent=digest(parent_descriptor)
 manifests={}
 for role,names,uid,gid in (('privileged',PRIVILEGED_COMPONENTS,0,0),
    ('executor',EXECUTOR_COMPONENTS,value['serviceUid'],value['serviceGid'])):
  supplied=value[role+'Components']
  if not isinstance(supplied,dict) or set(supplied)!=names:raise BundleBuildError(
   role+' component inventory differs')
  entries=[_entry(item,role+' '+name) for name,item in sorted(supplied.items())]
  components={name:item['path'] for name,item in supplied.items()}
  files=value['roleFiles'].get(role) if isinstance(value['roleFiles'],dict) else None
  if not isinstance(files,list):raise BundleBuildError(role+' file inventory differs')
  entries.extend(_entry(item,role+' file') for item in files)
  key_role='authority' if role=='privileged' else 'executor'
  key_material=[('config/'+key_role+'-ed25519.key','secret',materials[key_role][0])]
  if role=='privileged':
   key_material.append(('config/evidence-ed25519.key','secret',materials['evidence'][0]))
  trust_path='config/executor-trust-snapshot.json'
  for path,kind,raw in (*key_material,(trust_path,'protected',trust_raw)):
   entries.append({'path':path,'kind':kind,'mode':0o400,
    'payloadBase64':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest()})
  directories=sorted({str(Path(item['path']).parent) for item in entries if str(
   Path(item['path']).parent)!='.'},key=lambda x:(x.count('/'),x))
  existing={item['path'] for item in entries}
  for directory in directories:
   if directory not in existing:entries.append({'path':directory,'kind':'directory',
    'mode':0o700,'payloadBase64':None,'sha256':None})
  body={'format':'openepm-macos-pilot-role-runtime-assembly-v2',
   'generation':value['generation'],'role':role,'parentAssemblySha256':parent,
   'ownerUid':uid,'ownerGid':gid,'entries':entries,'components':components}
  manifests[role]={**body,'manifestSha256':digest(body)}
 bundle_body={'format':'openepm-macos-pilot-runtime-bundle-v2',
  'parentAssemblySha256':parent,'parentDescriptor':parent_descriptor,
  'identities':identities,'paths':paths,'manifests':manifests,
  'secretFieldsRedacted':['keys.*.privateKeyBase64']}
 return {**bundle_body,'bundleSha256':digest(bundle_body)}

def _descriptor(path,raw,kind='protected'):
 mode={'protected':0o400,'resource':0o400,'secret':0o400,'executable':0o500}[kind]
 return {'path':path,'kind':kind,'mode':mode,
  'payloadBase64':base64.b64encode(raw).decode()}

def _json_descriptor(path,value):return _descriptor(path,canonical(value))
def _sealed(format_name,body,field='configSha256'):
 return {'format':format_name,**body,field:digest({'format':format_name,**body})}

def build_production_reviewed_installation(profile:dict)->dict:
 """Generate every real immutable config consumed by the split constructors.

 The caller supplies reviewed release identities, keys, sealed v3 contract and
 exact external endpoint bindings.  No component JSON is caller-authored.
 """
 if not isinstance(profile,dict) or set(profile)!=PRODUCTION_PROFILE_KEYS \
    or profile.get('format')!='openepm-macos-pilot-production-profile-v1':
  raise BundleBuildError('production profile differs')
 runtime=profile['runtime'];artifacts=profile['artifacts'];contract=profile['contract']
 try:plan_sha=validate_activation_plan(profile['plan'])
 except Exception as error:raise BundleBuildError(
  'production activation plan differs') from error
 if not isinstance(runtime,dict) or set(runtime)!=PRODUCTION_RUNTIME_KEYS \
    or not isinstance(artifacts,dict) or set(artifacts)!=PRODUCTION_ARTIFACTS \
    or not isinstance(contract,dict) or contract.get('format')!= \
      'openepm-macos-pilot-activation-execution-contract-v3' \
    or contract.get('executionContractSha256')!=digest({k:v for k,v in contract.items()
      if k!='executionContractSha256'}) \
    or not isinstance(contract.get('activationId'),str) or not contract['activationId'] \
    or contract.get('dryPlanSha256')!=plan_sha \
    or not isinstance(profile['plan'].get('privatePorts'),dict) \
    or profile['plan'].get('privatePorts')!=dict(zip(
      ('web','platform','workspace','application'),runtime.get('privatePorts',()))) \
    or contract.get('authorityVerifier',{}).get('keyId')!=profile['keys'].get(
      'authority',{}).get('keyId') \
    or contract.get('executorVerifier',{}).get('keyId')!=profile['keys'].get(
      'executor',{}).get('keyId') \
    or contract.get('ownerAuthorizationVerifier',{}).get('keyId')!=profile['keys'].get(
      'owner',{}).get('keyId') \
    or contract.get('evidenceVerifier',{}).get('keyId')!=profile['keys'].get(
      'evidence',{}).get('keyId') \
    or len({contract.get(field,{}).get('keyId') for field in (
      'executorVerifier','ownerAuthorizationVerifier','authorityVerifier',
      'evidenceVerifier')})!=4:
  raise BundleBuildError('production contract/profile binding differs')
 namespace=profile['namespace']
 if not isinstance(namespace,str) or not namespace.startswith('openepm-qual-'):
  raise BundleBuildError('production namespace differs')
 for name in PRODUCTION_ARTIFACTS:
  try:raw=base64.b64decode(artifacts[name],validate=True)
  except Exception as error:raise BundleBuildError(name+' artifact differs') from error
  if not raw:raise BundleBuildError(name+' artifact differs')
 paths=profile['paths'];p=Path(paths['privilegedRoot']);e=Path(paths['executorRoot'])
 ps=Path(paths['privilegedStateRoot']);es=Path(paths['executorStateRoot'])
 gate=Path(paths['authorityGateRoot']);sockdir=Path(paths['socketDirectory'])
 def P(rel):return str(p/rel)
 def S(rel):return str(ps/rel)
 raw={name:base64.b64decode(value,validate=True) for name,value in artifacts.items()}
 helper_raw,helper_modules=_helper_package()
 if raw['helper']!=helper_raw:
  raise BundleBuildError('reviewed helper artifact differs from production source')
 file_paths={
  'docker':P('bin/docker'),'helper':P('config/openepm-pilot-host-action'),
  'launchctl':P('bin/launchctl'),'blueCompose':P('config/blue-compose.yaml'),
  'greenCompose':P('config/green-compose.yaml'),'blueEnv':P('config/blue.env'),
  'greenEnv':P('config/green.env'),'token':P('config/token.txt'),'ca':P('config/ca.pem')}
 source,candidate=contract['source'],contract['candidate']
 if source.get('project') is None or candidate.get('project') is None \
    or source.get('databaseVolume') is None or candidate.get('databaseVolume') is None:
  raise BundleBuildError('production slot binding differs')
 if _sha(source.get('databaseVolumeId'),'source database volume identity')!=runtime[
     'blueVolumeId']:
  raise BundleBuildError('source database volume identity differs')
 prepare=profile['prepareOperationKey'];_sha(prepare,'prepare operation')
 observer_body={'format':'openepm-macos-pilot-host-observer-binding-v2','slot':'source',
  'activationId':contract.get('activationId'),
  'executionContractSha256':contract['executionContractSha256'],
  'project':source['project'],'databaseVolume':source['databaseVolume'],
  'applicationImage':source['applicationImage'],'databaseImage':source['databaseImage']}
 observer_binding={**observer_body,'configSha256':digest(observer_body)}
 candidate_observer_body={'format':'openepm-macos-pilot-host-observer-binding-v2',
  'slot':'candidate','activationId':contract.get('activationId'),
  'executionContractSha256':contract['executionContractSha256'],
  'project':candidate['project'],'databaseVolume':candidate['databaseVolume'],
  'applicationImage':candidate['applicationImage'],
  'databaseImage':candidate['databaseImage']}
 candidate_observer_binding={**candidate_observer_body,
  'configSha256':digest(candidate_observer_body)}
 # Fixed host controller and helper share one immutable config directory.
 deployment_body={'format':'openepm-macos-pilot-deployment-v1',
  'blueProject':source['project'],'greenProject':candidate['project'],
  'blueComposeFile':file_paths['blueCompose'],'greenComposeFile':file_paths['greenCompose'],
  'blueEnvFile':file_paths['blueEnv'],'greenEnvFile':file_paths['greenEnv'],
  'applicationImage':candidate['applicationImage'],'databaseImage':candidate['databaseImage'],
  'blueVolume':source['databaseVolume'],'greenVolume':candidate['databaseVolume'],
  'blueNetwork':runtime['blueNetwork'],'greenNetwork':runtime['greenNetwork'],
  'privatePorts':dict(zip(('web','platform','workspace','application'),runtime['privatePorts'])),
  'forwarderLabels':{name:namespace+'.forwarder.'+name for name in
    ('web','platform','workspace','application')},'tunnelLabel':namespace+'.tunnel',
  'runtimeStateRoot':str(ps)}
 for prefix,name in (('blueCompose','blueCompose'),('greenCompose','greenCompose'),
                     ('blueEnv','blueEnv'),('greenEnv','greenEnv')):
  deployment_body[prefix+'Sha256']=hashlib.sha256(raw[name]).hexdigest()
 deployment_body.update({'dockerPath':file_paths['docker'],
  'dockerSha256':hashlib.sha256(raw['docker']).hexdigest(),'helperPath':file_paths['helper'],
  'helperSha256':hashlib.sha256(raw['helper']).hexdigest()})
 deployment={**deployment_body,'deploymentConfigSha256':digest(deployment_body)}
 bootstrap_body={'format':'openepm-macos-pilot-bootstrap-contract-v1',
  'prepareOperationKey':prepare,'executionContract':contract}
 bootstrap={**bootstrap_body,'envelopeSha256':digest(bootstrap_body)}
 # Public listener artifacts are immutable plists; closure output is mutable state.
 entries=[];plist_files=[]
 for index,(label,port) in enumerate(zip((namespace+'.forwarder',namespace+'.tunnel'),
                                        runtime['admissionPorts'])):
  args=[P('bin/launchctl'),'managed',str(index)]
  plist=plistlib.dumps({'Label':label,'ProgramArguments':args},sort_keys=True)
  rel=f'config/admission-{index}.plist';plist_files.append(_descriptor(rel,plist,'resource'))
  entries.append({'label':label,'plistPath':P(rel),'plistSha256':hashlib.sha256(plist).hexdigest(),
   'programArguments':args,'ports':[port]})
 admission_body={'format':'openepm-macos-public-admission-v2',
  'launchctlPath':file_paths['launchctl'],'domain':runtime['launchdDomain'],
  'ownerUid':runtime['launchdOwnerUid'],'entries':entries,
  'artifactPath':S('public-admission-closed.json'),
  'authorityKeyId':profile['keys']['evidence']['keyId'],
  'authorityKeyVersion':profile['keys']['evidence']['version']}
 admission={**admission_body,'configSha256':digest(admission_body)}
 active_body={'format':'openepm-active-work-runtime-v1','adminDsnFile':P('config/blue.dsn'),
  'dockerPath':file_paths['docker'],'composeFile':file_paths['blueCompose'],
  'envFile':file_paths['blueEnv'],'project':source['project'],
  'workerServices':['worker','python-build-broker']}
 active={**active_body,'configSha256':digest(active_body)}
 provider_body={'format':'openepm-stopped-source-provider-v2',
  'bindingSha256':contract['executionContractSha256'],'dockerPath':file_paths['docker'],
  'composeFile':file_paths['blueCompose'],'envFile':file_paths['blueEnv'],
  'project':source['project'],'dsnFile':P('config/blue.dsn'),'databaseService':'db',
  'applicationServices':['platform','workspace','router','web','worker','python-build-broker'],
  'publicAdmissionStateFile':S('public-admission-closed.json'),
  'admissionAuthorityKeyId':profile['keys']['evidence']['keyId'],
  'admissionAuthorityPublicKeyBase64':base64.b64encode(
    Ed25519PrivateKey.from_private_bytes(base64.b64decode(
      profile['keys']['evidence']['privateKeyBase64'],validate=True)).public_key(
      ).public_bytes_raw()).decode(),
  'observerBindingSha256':observer_binding['configSha256'],
  'ports':runtime['privatePorts'],'quiescenceEvidenceSha256':source.get(
    'quiescenceEvidenceSha256')}
 provider={**provider_body,'configSha256':digest(provider_body)}
 candidate_provider_body={**provider_body,
  'composeFile':file_paths['greenCompose'],'envFile':file_paths['greenEnv'],
  'project':candidate['project'],'dsnFile':P('config/green.dsn'),
  'observerBindingSha256':candidate_observer_binding['configSha256'],
  'quiescenceEvidenceSha256':candidate.get('candidateEvidenceSha256',
                                           digest(candidate))}
 candidate_provider={**candidate_provider_body,
  'configSha256':digest(candidate_provider_body)}
 slot_fence={'format':'openepm-macos-pilot-slot-postgres-fence-v2',
  'serviceRoles':['epm_runtime','epm_access','epm_worker','epm_lifecycle',
   'epm_provision','epm_security','epm_python_coordinator'],
  'serviceLogins':['epm_runtime_login','epm_access_login','epm_worker_login',
   'epm_lifecycle_login','epm_provision_login','epm_security_login',
   'epm_python_coordinator_login'],
  'attemptsDirectory':'attempts','slots':{
   'blue':{'database':runtime['blueDatabase'],'databaseVolume':source['databaseVolume'],
    'systemIdentifier':runtime['blueSystemIdentifier'],'dsnFile':'blue.dsn',
    'stateDirectory':'blue-state'},
   'green':{'database':runtime['greenDatabase'],'databaseVolume':candidate['databaseVolume'],
    'systemIdentifier':runtime['greenSystemIdentifier'],'dsnFile':'green.dsn',
    'stateDirectory':'green-state'}}}
 docker_identity={'path':file_paths['docker'],'sha256':hashlib.sha256(raw['docker']).hexdigest(),
  'ownerUid':0,'mode':0o500}
 backup={'format':'openepm-macos-pilot-slot-backup-v2','attemptsDirectory':'attempts',
  'slots':{
   'blue':{'database':runtime['blueDatabase'],'systemIdentifier':runtime['blueSystemIdentifier'],
    'databaseVolume':source['databaseVolume'],'sourceIdentity':runtime['blueDbContainer'],
    'backupDirectory':'blue-backups','receiptKeyFile':'blue.key',
    'manifestFile':'blue-manifest.json','containerImage':source['databaseImage'],
    'dockerExecutable':docker_identity},
   'green':{'database':runtime['greenDatabase'],'systemIdentifier':runtime['greenSystemIdentifier'],
    'databaseVolume':candidate['databaseVolume'],'sourceIdentity':runtime['greenDbContainer'],
    'backupDirectory':'green-backups','receiptKeyFile':'green.key',
    'manifestFile':'green-manifest.json','containerImage':candidate['databaseImage'],
    'dockerExecutable':docker_identity}}}
 green_network=candidate.get('networks',{}).get(runtime['greenNetwork'])
 if not isinstance(green_network,dict) or green_network.get('networkId') \
    !=runtime['greenNetworkId']:
  raise BundleBuildError('green network binding differs')
 green_body={'format':'openepm-green-prepare-v1','dockerPath':file_paths['docker'],
  'composeFile':file_paths['greenCompose'],'envFile':file_paths['greenEnv'],
  'project':candidate['project'],'dbService':'db','dbContainer':runtime['greenDbContainer'],
  'databaseImage':candidate['databaseImage'],'operationsImage':runtime['operationsImage'],
  'databaseVolume':candidate['databaseVolume'],'network':runtime['greenNetwork'],
  'expectedNetworkId':runtime['greenNetworkId'],
  'dbConfigHash':runtime['dbConfigHash'],'networkDriver':green_network.get('driver'),
  'networkInternal':green_network.get('internal'),
  'networkAttachable':green_network.get('attachable'),
  'volumeDriver':'local','volumeScope':'local',
  'volumeMountpoint':runtime['volumeMountpoint'],
  'expectedSystemIdentifier':runtime['greenSystemIdentifier'],
  'expectedSchemaVersion':candidate['schema']['maximum'],
  'expectedApplicationCount':candidate['applicationCount'],
  'expectedBusinessSha256':candidate['businessDataDumpFingerprintSha256'],
  'dockerSha256':hashlib.sha256(raw['docker']).hexdigest(),
  'composeSha256':hashlib.sha256(raw['greenCompose']).hexdigest(),
  'envSha256':hashlib.sha256(raw['greenEnv']).hexdigest()}
 green={**green_body,'configSha256':digest(green_body)}
 services=['platform','workspace','router','web','worker','python-build-broker']
 base=runtime['baseHttpsUrl'].rstrip('/')
 readonly_body={'format':'openepm-macos-pilot-readonly-probe-v1',
  'dockerPath':file_paths['docker'],'composeFile':file_paths['greenCompose'],
  'envFile':file_paths['greenEnv'],'greenProject':candidate['project'],
  'greenServices':services,'applicationImage':candidate['applicationImage'],
  'databaseImage':candidate['databaseImage'],'greenNetwork':runtime['greenNetwork'],
  'greenNetworkId':runtime['greenNetworkId'],'blueVolumeId':runtime['blueVolumeId'],
  'admissionArtifact':S('public-admission-closed.json'),'tokenFile':file_paths['token'],
  'caFile':file_paths['ca'],'unsignedUrls':[base+'/web',base+'/mcp'],
  'readUrl':base+'/read','readResultSha256':runtime['readResultSha256'],
  'writeDenialUrl':base+'/write','writeDenialStatus':423,
  'jobDenialUrl':base+'/job','jobDenialStatus':409}
 readonly={**readonly_body,'configSha256':digest(readonly_body)}
 rollback_body={'format':'openepm-macos-pilot-rollback-probe-v1',
  'dockerPath':file_paths['docker'],'composeFile':file_paths['blueCompose'],
  'envFile':file_paths['blueEnv'],'blueProject':source['project'],'blueServices':services,
  'applicationImage':source['applicationImage'],'databaseImage':source['databaseImage'],
  'blueNetwork':runtime['blueNetwork'],'blueNetworkId':runtime['blueNetworkId'],
  'greenVolume':candidate['databaseVolume'],'greenVolumeId':runtime['greenVolumeId'],
  'admissionArtifact':S('public-admission-closed.json'),'tokenFile':file_paths['token'],
  'caFile':file_paths['ca'],'unsignedUrls':[base+'/web',base+'/mcp'],
  'readUrl':base+'/read','readResultSha256':runtime['readResultSha256'],
  'writeDenialUrl':base+'/write','writeDenialStatus':423,
  'jobDenialUrl':base+'/job','jobDenialStatus':409}
 rollback={**rollback_body,'configSha256':digest(rollback_body)}
 mutable={name:name.replace('Root','').replace('State','-state').lower()
  for name in MUTABLE_ROOT_KEYS}
 # Stable explicit names are easier to audit than generated host paths.
 mutable.update({'controllerAttemptsRoot':'controller-attempts','gateAttemptsRoot':'gate-attempts',
  'authorityAttemptsRoot':'authority-attempts','stoppedProofAuthorityRoot':'stopped-proofs',
  'backupEvidenceRoot':'backup-evidence','greenAttemptsRoot':'green-attempts',
  'activationStateRoot':'activation-state','admissionEvidenceRoot':'admission-evidence',
  'hostAdapterAttemptsRoot':'host-adapter-attempts','producerReopenRoot':'producer-reopen',
  'slotFenceStateRoot':'slot-fence','protectedBackupStateRoot':'protected-backup'})
 def binding(role):
  body={'format':'openepm-macos-pilot-role-runtime-binding-v2','role':role,
   'parentAssemblySha256':'0'*64,'serviceUid':profile['serviceUid'],
   'serviceGid':profile['serviceGid'],'socketPath':str(sockdir/'authority.sock'),
   'executorKeyId':profile['keys']['executor']['keyId'],
   'executorKeyVersion':profile['keys']['executor']['version'],
   'authorityKeyId':profile['keys']['authority']['keyId'],
   'authorityKeyVersion':profile['keys']['authority']['version'],
   'evidenceKeyId':profile['keys']['evidence']['keyId'],
   'evidenceKeyVersion':profile['keys']['evidence']['version'],
   'authorityGateRoot':str(gate),'socketDirectory':str(sockdir),
   'runtimeStateRoot':str(ps if role=='privileged' else es),
   'trustRegistryFile':'config/executor-trust-snapshot.json',
   'prepareOperationKey':prepare,**mutable}
  if role=='privileged':body.update({'blueAdminDsnFile':'config/blue.dsn',
    'greenAdminDsnFile':'config/green.dsn',
    'evidencePrivateKeyFile':'config/evidence-ed25519.key'})
  body[('authorityPrivateKeyFile' if role=='privileged' else
        'executorPrivateKeyFile')]=('config/authority-ed25519.key' if role=='privileged'
                                    else 'config/executor-ed25519.key')
  return body
 privileged_components={
  'privilegedController':_json_descriptor('config/deployment.json',deployment),
  'publicAdmission':_json_descriptor('config/public-admission.json',admission),
  'activeWork':_json_descriptor('config/active-work-runtime.json',active),
  'phaseAStoppedProvider':_json_descriptor('config/phase-a-provider.json',provider),
  'greenStoppedProvider':_json_descriptor('config/green-stopped-provider.json',
                                          candidate_provider),
  'slotPostgresFence':{'path':'config/slot-fence','kind':'directory','mode':0o700,
    'payloadBase64':None},
  'protectedBackup':{'path':'config/backup','kind':'directory','mode':0o700,
    'payloadBase64':None},
  'greenPrepare':_json_descriptor('config/green-prepare.json',green),
  'readonlyProbe':_json_descriptor('config/readonly-probe.json',readonly),
  'rollbackProbe':_json_descriptor('config/rollback-probe.json',rollback),
  'stagedSlot':_json_descriptor('config/runtime-binding.json',binding('privileged')),
  'bootstrapContract':_json_descriptor('config/bootstrap-contract.json',bootstrap)}
 executor_components={'stagedSlot':_json_descriptor('config/runtime-binding.json',
  binding('executor'))}
 privileged_files=[_descriptor('bin/docker',raw['docker'],'executable'),
  _descriptor('bin/launchctl',raw['launchctl'],'executable'),
  _descriptor('config/openepm-pilot-host-action',raw['helper'],'executable'),
  _descriptor('config/blue-compose.yaml',raw['blueCompose'],'resource'),
  _descriptor('config/green-compose.yaml',raw['greenCompose'],'resource'),
  _descriptor('config/blue.env',raw['blueEnv'],'resource'),
  _descriptor('config/green.env',raw['greenEnv'],'resource'),
  _descriptor('config/token.txt',raw['token'],'secret'),
  _descriptor('config/ca.pem',raw['ca'],'resource'),
  _descriptor('config/blue.dsn',runtime['blueAdminDsn'].encode(),'secret'),
  _descriptor('config/green.dsn',runtime['greenAdminDsn'].encode(),'secret'),
  *plist_files,
  _json_descriptor('config/slot-fence/slots.json',slot_fence),
  _descriptor('config/slot-fence/blue.dsn',runtime['blueAdminDsn'].encode(),'secret'),
  _descriptor('config/slot-fence/green.dsn',runtime['greenAdminDsn'].encode(),'secret'),
  _json_descriptor('config/backup/backup-slots.json',backup),
  _descriptor('config/backup/blue.key',raw['blueReceiptKey'],'secret'),
  _descriptor('config/backup/green.key',raw['greenReceiptKey'],'secret'),
  *helper_modules]
 reviewed={'format':'openepm-macos-pilot-reviewed-installation-v1',
  'generation':profile['generation'],'identities':profile['identities'],
  'serviceUid':profile['serviceUid'],'serviceGid':profile['serviceGid'],'paths':paths,
  'keys':profile['keys'],'approvedContracts':[contract['executionContractSha256']],
  'privilegedComponents':privileged_components,'executorComponents':executor_components,
  'roleFiles':{'privileged':privileged_files,'executor':[]}}
 return reviewed

def build_production_bundle(profile:dict)->dict:
 reviewed=build_production_reviewed_installation(profile)
 # The parent descriptor normalizes the one embedded parent field.  Child role
 # manifests then bind that parent and the bundle digest binds both children.
 first=build_bundle(reviewed);parent=first['parentAssemblySha256']
 for role in ('privileged','executor'):
  item=reviewed[role+'Components']['stagedSlot'];value=json.loads(base64.b64decode(
   item['payloadBase64'],validate=True));value['parentAssemblySha256']=parent
  item['payloadBase64']=base64.b64encode(canonical(value)).decode()
 final=build_bundle(reviewed)
 if final['parentAssemblySha256']!=parent:
  raise BundleBuildError('production parent binding is not stable')
 return final

def install_bundle(bundle):
 if os.geteuid()!=0:raise BundleBuildError('bundle installation requires root')
 if not isinstance(bundle,dict) or bundle.get('format') not in (
    'openepm-macos-pilot-runtime-bundle-v1','openepm-macos-pilot-runtime-bundle-v2'):
  raise BundleBuildError('runtime bundle differs')
 if bundle['format'].endswith('-v2'):
  body={key:value for key,value in bundle.items() if key!='bundleSha256'}
  if bundle.get('bundleSha256')!=digest(body) or not isinstance(
     bundle.get('parentDescriptor'),dict) or bundle.get(
      'parentAssemblySha256')!=digest(bundle['parentDescriptor']):
   raise BundleBuildError('runtime bundle binding differs')
 if any(manifest.get('parentAssemblySha256')!=bundle.get('parentAssemblySha256')
        for manifest in bundle.get('manifests',{}).values()):
  raise BundleBuildError('runtime role parent binding differs')
 paths=bundle['paths']
 for name,mode,uid,gid in (('privilegedStateRoot',0o700,0,0),
   ('executorStateRoot',0o700,bundle['manifests']['executor']['ownerUid'],
    bundle['manifests']['executor']['ownerGid']),('authorityGateRoot',0o555,0,0),
   ('socketDirectory',0o750,0,bundle['manifests']['executor']['ownerGid'])):
  path=Path(paths[name])
  if path.exists():
   meta=os.lstat(path)
   if not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode)!=mode \
      or meta.st_uid!=uid or meta.st_gid!=gid:raise BundleBuildError(name+' differs')
  else:path.mkdir(mode=mode);os.chown(path,uid,gid);os.chmod(path,mode)
 for role,state_name in (('privileged','privilegedStateRoot'),
                         ('executor','executorStateRoot')):
  manifest=bundle['manifests'][role];component=manifest['components']['stagedSlot']
  entry=next((item for item in manifest['entries'] if item['path']==component),None)
  try:binding=json.loads(base64.b64decode(entry['payloadBase64'],validate=True))
  except Exception as error:raise BundleBuildError(role+' runtime binding differs') from error
  state=Path(paths[state_name])
  if binding.get('runtimeStateRoot')!=str(state):raise BundleBuildError(
   role+' runtime state binding differs')
  for name in MUTABLE_ROOT_KEYS:
   relative=Path(binding.get(name,''))
   if relative.is_absolute() or '..' in relative.parts or not relative.parts:
    raise BundleBuildError(role+' mutable root binding differs')
   target=state/relative
   if target.exists():
    meta=os.lstat(target)
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=manifest['ownerUid'] \
       or meta.st_gid!=manifest['ownerGid'] or stat.S_IMODE(meta.st_mode)!=0o700:
     raise BundleBuildError(role+' mutable root differs')
   else:
    target.mkdir(mode=0o700,parents=True);os.chown(target,manifest['ownerUid'],
     manifest['ownerGid']);os.chmod(target,0o700)
  # These roots contain fixed subdirectories named by their immutable v2
  # configs.  Create them at installation so constructors never need to mutate
  # root-owned structure as a side effect of loading the graph.
  if role=='privileged':
   nested={'slotFenceStateRoot':('attempts','blue-state','green-state'),
           'protectedBackupStateRoot':('attempts','blue-backups','green-backups')}
   for key,names in nested.items():
    parent=state/Path(binding[key])
    for name in names:
     child=parent/name
     if child.exists():
      meta=os.lstat(child)
      if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=manifest['ownerUid'] \
         or meta.st_gid!=manifest['ownerGid'] or stat.S_IMODE(meta.st_mode)!=0o700:
       raise BundleBuildError(role+' nested mutable root differs')
     else:
      child.mkdir(mode=0o700);os.chown(child,manifest['ownerUid'],manifest['ownerGid'])
      os.chmod(child,0o700)
 for role in ('privileged','executor'):
  install_role_runtime(bundle['manifests'][role],Path(paths[role+'Root']))

def redacted_plan(bundle):
 return {'format':'openepm-macos-pilot-runtime-install-plan-v1',
  'parentAssemblySha256':bundle['parentAssemblySha256'],
  'identities':bundle['identities'],'paths':bundle['paths'],
  'roles':{role:{'manifestSha256':item['manifestSha256'],
   'ownerUid':item['ownerUid'],'ownerGid':item['ownerGid'],
   'components':sorted(item['components'])} for role,item in bundle['manifests'].items()},
  'secretFieldsRedacted':bundle['secretFieldsRedacted']}

def main():
 parser=argparse.ArgumentParser();parser.add_argument('input',type=Path)
 parser.add_argument('--output',type=Path,required=True);parser.add_argument('--install',action='store_true')
 parser.add_argument('--plan',action='store_true')
 args=parser.parse_args();value=json.loads(args.input.read_text())
 bundle=(build_production_bundle(value) if value.get('format')==
  'openepm-macos-pilot-production-profile-v1' else build_bundle(value))
 args.output.write_bytes(canonical(redacted_plan(bundle) if args.plan else bundle));args.output.chmod(0o400)
 if args.plan and args.install:raise BundleBuildError('plan cannot install')
 if args.install:install_bundle(bundle)
if __name__=='__main__':main()
