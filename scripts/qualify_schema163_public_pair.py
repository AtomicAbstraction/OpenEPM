"""Run all seven signed public parity domains on both schema-169 paths."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import AsyncExitStack,asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import time
from mcp.shared.exceptions import MCPError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_access import VerifiedIdentity
from epm_core.persistence_contract import ApplicationScope
from epm_core.postgres_fresh_baseline import schema_fingerprint
from epm_core.postgres_schema163_functional_collector import DisposableCollectorContext,collect_certificate
from epm_core.postgres_schema163_functional_parity import verify_pair
from epm_core.postgres_schema163_public_compose import DockerComposePublicParityFactory
from epm_core.postgres_schema163_public_domain_adapters import (
 aggregate_adapter,cta_adapter,forecast_adapter,inventory_adapter,
 python_artifact_adapter,recursive_rollup_adapter,transfer_adapter)
from tests import qualify_postgres_compose_signed as signed
from tests import recursive_placement_signed_mcp_fixture as recursive
from tests import transfer_orchestration_signed_mcp_fixture as transfer
from tests import real_keycloak_mixed_method_close_fixture as cta
from tests import real_keycloak_p20_scheduled_forecast_fixture as forecast
from tests import real_keycloak_python_run_fixture as python_run
from tests import real_keycloak_inventory_unrealized_fixture as inventory
from tests.qualify_export_publish_complete_pg18_0167 import (
 _wrong_family_no_effect)
from tests.capability_revocation_concurrency_fixture import (
 qualify as qualify_revocation_concurrency)


def _run(command,cwd:Path,environment=None)->str:
 result=subprocess.run(command,cwd=cwd,text=True,capture_output=True,
  env=environment)
 if result.returncode:
  raise RuntimeError('SCHEMA163_PARITY_COMMAND_FAILED:'+repr(command)+':'
                     +(result.stderr or result.stdout)[-4000:])
 return result.stdout.strip()


def _collect(root:Path,factory:DockerComposePublicParityFactory,mode:str,
             issuer:str,private,workspace:str)->dict:
 with factory.lifecycle(mode) as runtime:
  ports={5193:runtime['servicePorts']['platform'],5192:runtime['servicePorts']['workspace'],
         5194:runtime['servicePorts']['router'],5195:runtime['servicePorts']['web']}
  restart_observations=[]
  @asynccontextmanager
  async def client(port,token):
   for attempt in range(1,31):
    stack=AsyncExitStack()
    try:
     session=await stack.enter_async_context(signed._client(ports[port],token))
    except MCPError as error:
     await stack.aclose()
     if error.code!=-32603 or attempt==30:raise
     await asyncio.sleep(.2)
     continue
    if port==5194 and restart_observations:
     observation=restart_observations[-1]
     if observation['service']=='router' and 'mcpReady' not in observation:
      observation.update({'mcpReady':True,
                          'mcpInitializationAttempts':attempt})
    try:yield session
    finally:await stack.aclose()
    return
  def compose(*arguments):
   result=_run([*runtime['baseCommand'],'--profile','v2','--profile','workspace',
                *arguments],root,factory.subprocess_environment())
   if len(arguments)>=2 and arguments[0]=='restart':
    for service in arguments[1:]:
     container=_run([*runtime['baseCommand'],'--profile','v2','--profile','workspace',
                     'ps','-q',service],root,factory.subprocess_environment())
     if not container:
      raise RuntimeError('SCHEMA163_PARITY_RESTART_SERVICE_MISSING:'+service)
     for _ in range(100):
      health=_run(['docker','inspect','-f','{{.State.Health.Status}}',container],
                  root,factory.subprocess_environment())
      if health=='healthy':break
      if health=='unhealthy':
       raise RuntimeError('SCHEMA163_PARITY_RESTART_UNHEALTHY:'+service)
      time.sleep(.2)
     else:
      raise RuntimeError('SCHEMA163_PARITY_RESTART_HEALTH_TIMEOUT:'+service)
     internal={'platform':5193,'workspace':5192,'router':5194,'web':5195}.get(service)
     if internal is not None:
      previous_port=ports[internal]
      address=_run([*runtime['baseCommand'],'port',service,str(internal)],root,
                   factory.subprocess_environment())
      ports[internal]=int(address.rsplit(':',1)[1])
      for _ in range(100):
       try:
        with socket.create_connection(('127.0.0.1',ports[internal]),timeout=.2):break
       except OSError:
        time.sleep(.2)
      else:
       raise RuntimeError('SCHEMA163_PARITY_RESTART_PORT_TIMEOUT:'+service)
      restart_observations.append({'service':service,'oldHostPort':previous_port,
        'newHostPort':ports[internal],'dockerHealth':'healthy','tcpReady':True})
   return result
  subjects={'operator':'operator','planner':'parity-planner','author':'parity-author',
            'reader':'parity-reader','outsider':'parity-outsider'}
  def fresh_tokens():return {name:signed._token(private,issuer,'epm-disposable-mcp',subject)
                              for name,subject in subjects.items()}
  tokens=fresh_tokens()
  def restart():
   compose('restart','router');time.sleep(4);return fresh_tokens()
  def stop_worker():compose('stop','worker')
  def start_worker():compose('start','worker');time.sleep(2)
  raw={}
  def recursive_result():
   if 'recursive' not in raw:
    raw['recursive']=asyncio.run(recursive.qualify(issuer,private,workspace,
      client=client,call=signed._call,token=signed._token,program=signed._program,
      compose=compose,certificate_mode=True))
    # Shared generic application used by the inventory negative visibility check.
    async def generic():
     async with client(5192,tokens['operator']) as session:
      await signed._call(session,'execute_v2_workspace_program',{'program':signed._program(
       'workspace.application.create',{'applicationId':'oidc-plan','name':'Generic plan','kind':'blank'}),
       'idempotency_key':'parity-generic-app'})
    asyncio.run(generic())
   return raw['recursive']
  def transfer_result():
   if 'transfer' not in raw:
    recursive_result()
    raw['transfer']=asyncio.run(transfer.qualify(issuer,private,workspace,
      client=client,call=signed._call,token=signed._token,program=signed._program,
      compose=compose,tokens={'operator':tokens['operator'],'planner':tokens['planner'],
       'reader':tokens['reader']},subjects={'operator':subjects['operator'],
       'planner':subjects['planner'],'reader':subjects['reader']},workspace_created=True))
   return raw['transfer']
  def cta_result():
   if 'cta' not in raw:
    recursive_result();raw['cta']=asyncio.run(cta.qualify(tokens=tokens,subjects=subjects,
      workspace=workspace,client=client,call=signed._call,restart=restart,
      stop_worker=stop_worker,start_worker=start_worker,certificate_mode=True))
   return raw['cta']
  def forecast_result():
   if 'forecast' not in raw:
    recursive_result();raw['forecast']=asyncio.run(forecast.qualify(tokens=tokens,
      subjects=subjects,workspace=workspace,issuer=issuer,client=client,
      call=signed._call,restart=restart,stop_worker=stop_worker,start_worker=start_worker))
   return raw['forecast']
  def python_result():
   if 'python' not in raw:
    recursive_result();secrets_=factory.environment
    raw['python']=asyncio.run(python_run.qualify(tokens=tokens,subjects=subjects,
      workspace=workspace,issuer=issuer,client=client,call=signed._call,compose=compose,
      database_passwords={'admin':secrets_['EPM_POSTGRES_PASSWORD'],
       'runtime':secrets_['EPM_PG_RUNTIME_PASSWORD']},
      preview_secret=secrets_['EPM_PG_PREVIEW_SECRET_HEX'],restart=restart,
      database_name=runtime['database']))
   return raw['python']
  def inventory_result():
   if 'inventory' not in raw:
    recursive_result();raw['inventory']=asyncio.run(inventory.qualify(tokens=tokens,
      subjects=subjects,workspace=workspace,client=client,call=signed._call,
      certificate_mode=True))
   return raw['inventory']
  adapters=(aggregate_adapter(lambda _:recursive_result()),
    transfer_adapter(lambda _:transfer_result()),cta_adapter(lambda _:cta_result()),
    forecast_adapter(lambda _:forecast_result()),python_artifact_adapter(lambda _:python_result()),
    inventory_adapter(lambda _:inventory_result()),recursive_rollup_adapter(lambda _:recursive_result()))
  password=factory.environment['EPM_POSTGRES_PASSWORD']
  dsn=runtime['adminDsn'].replace(' user=postgres ',f' user=postgres password={password} ')
  runtime_dsn=runtime['adminDsn'].replace(' user=postgres ',
    ' user=epm_runtime_login password='+factory.environment['EPM_PG_RUNTIME_PASSWORD']+' ')
  worker_dsn=runtime['adminDsn'].replace(' user=postgres ',
    ' user=epm_worker_login password='+factory.environment['EPM_PG_WORKER_PASSWORD']+' ')
  security_dsn=runtime['adminDsn'].replace(' user=postgres ',
    ' user=epm_security_login password='+factory.environment['EPM_PG_SECURITY_PASSWORD']+' ')
  with connect_postgres(dsn) as db:fingerprint=schema_fingerprint(db)
  noop=lambda *args,**kwargs:None
  context=DisposableCollectorContext(dsn=dsn,source_commit=factory.environment[
    'EPM_TEST_SOURCE_COMMIT'],expected_schema_fingerprint=fingerprint,
    workspace_id=workspace,resource_owner_token=tokens['operator'],disposable=True,
    shared_data=False,service_context={'mcpClient':noop,'call':noop,'program':noop,
      'compose':compose,'restart':restart,'workerControl':noop,'identities':tokens,
      'applicationFactory':noop})
  try:
   certificate=collect_certificate(context,adapters)
  except BaseException as error:
   try:
    logs=compose('logs','--no-color','--tail','200','router','workspace','worker')
   except Exception as log_error:
    logs='SCHEMA170_PARITY_FAILURE_LOG_CAPTURE_FAILED:'+repr(log_error)
   raise RuntimeError('SCHEMA170_PARITY_DOMAIN_FAILED:'+repr(error)+'\n'+logs) from error
  stop_worker()
  try:
   wrong_family_no_effect=_wrong_family_no_effect(dsn,runtime_dsn,worker_dsn,
    ApplicationScope(workspace,raw['cta']['applicationId']),
    VerifiedIdentity(issuer,subjects['operator']))
  finally:
   start_worker()
  revocation_concurrency=qualify_revocation_concurrency(
    admin_dsn=dsn,runtime_dsn=runtime_dsn,security_dsn=security_dsn,
    scope=ApplicationScope(workspace,'oidc-plan'),
    administrator=VerifiedIdentity(issuer,subjects['operator']),
    preview_secret=bytes.fromhex(factory.environment['EPM_PG_PREVIEW_SECRET_HEX']),
    reader_subject='parity-revocation-reader')
  result={'certificate':certificate,'serviceIdentities':runtime['serviceIdentities'],
          'databaseName':runtime['database'],'restartObservations':restart_observations,
          'methodCoveragePlacements':raw['cta']['methodCoveragePlacements'],
          'methodTotalV4Evidence':raw['cta']['methodTotalV4Evidence'],
          'methodTotalFinalFenceEvidence':raw['cta'][
            'methodTotalFinalFenceEvidence'],
          'wrongFamilyRejectedWithoutEffects':wrong_family_no_effect}
  result['revocationConcurrency']=revocation_concurrency
 # Reaching this line proves the lifecycle context completed its verified cleanup.
 return {**result,'cleanupVerifiedAfterExit':True}


def _collect_pair(collector):
 results=[collector('fresh-baseline-164','fresh'),
          collector('semantic-reference-164','semantic')]
 try:
  equality=verify_pair(results[0]['certificate'],results[1]['certificate'])
 except ValueError as error:
  if str(error)!='SCHEMA163_FUNCTIONAL_PARITY_MISMATCH':raise
  paths=_difference_paths(results[0]['certificate']['domains'],
                          results[1]['certificate']['domains'])
  raise ValueError('SCHEMA163_FUNCTIONAL_PARITY_MISMATCH:'+','.join(paths)) from error
 return results,equality


def _difference_paths(left, right, path='domains', limit=32):
 """Return bounded structural paths only; never retain certificate values."""
 if left==right:return []
 if limit<=0:return [path+'.$more']
 if isinstance(left,dict) and isinstance(right,dict):
  paths=[]
  for key in sorted(set(left)|set(right)):
   if len(paths)>=limit:return paths[:-1]+[path+'.$more']
   if key not in left or key not in right:paths.append(path+'.'+key);continue
   paths.extend(_difference_paths(left[key],right[key],path+'.'+key,
                                  limit-len(paths)))
  return paths
 if isinstance(left,list) and isinstance(right,list):
  paths=[]
  for index in range(max(len(left),len(right))):
   if len(paths)>=limit:return paths[:-1]+[path+'.$more']
   if index>=len(left) or index>=len(right):paths.append(f'{path}[{index}]');continue
   paths.extend(_difference_paths(left[index],right[index],f'{path}[{index}]',
                                  limit-len(paths)))
  return paths
 return [path]


def main()->None:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True)
 p.add_argument('--qualification-image',required=True);p.add_argument('--database-image',required=True)
 p.add_argument('--source-commit',required=True);p.add_argument('--source-tree',required=True)
 p.add_argument('--output',type=Path,required=True);a=p.parse_args();root=a.root.resolve()
 common_value=Path(_run(['git','rev-parse','--git-common-dir'],root))
 common=(common_value if common_value.is_absolute() else root/common_value).resolve().parent
 output=a.output.resolve()
 if root not in output.parents or not output.parent.is_dir() or output.exists():
  raise ValueError('SCHEMA170_PARITY_OUTPUT_TARGET_INVALID')
 with tempfile.TemporaryDirectory(prefix='.epm-parity-oidc-',dir=common) as temporary:
  private,ca,cert,key,jwks=signed._keys(Path(temporary));server=signed._serve_keys(cert,key,jwks)
  try:
   issuer=f'https://host.docker.internal:{server.server_port}'
   environment={'EPM_TEST_SOURCE_COMMIT':a.source_commit,'EPM_TEST_SOURCE_TREE':a.source_tree,
    'EPM_TEST_QUALIFICATION_IMAGE':a.qualification_image,
    'EPM_TEST_COMPOSE_DATABASE_IMAGE':a.database_image,'EPM_TEST_OIDC_CA_PATH':str(ca),
    'EPM_PG_PREVIEW_SECRET_HEX':os.urandom(32).hex(),'EPM_AUTH_MODE':'oidc',
    'EPM_OIDC_ISSUER':issuer,'EPM_OIDC_JWKS_URL':issuer+'/jwks.json',
    'EPM_OIDC_AUD_MCP':'epm-disposable-mcp','EPM_OIDC_AUD_WEB':'epm-disposable-web',
    'EPM_PUBLIC_WEB_ORIGIN':'https://openepm.invalid','EPM_PLATFORM_OPERATOR_ISSUER':issuer,
    'EPM_PLATFORM_OPERATOR_SUBJECT':'operator','EPM_PG_WORKSPACE_ID':'epm-disposable-parity'}
   def collector(mode,suffix):
    workspace='epm-disposable-seven-'+suffix
    configured={**environment,'EPM_PG_WORKSPACE_ID':workspace}
    factory=DockerComposePublicParityFactory(root=root,project_prefix='parity7-'+suffix,
      environment=configured)
    return _collect(root,factory,mode,issuer,private,workspace)
   results,equality=_collect_pair(collector)
   evidence={'format':'openepm-schema170-seven-domain-pair-v1','passed':True,
    'activationAuthorized':False,'source':{'commit':a.source_commit,'tree':a.source_tree},
    'images':{'qualification':a.qualification_image,'database':a.database_image},
    'results':results,'equality':equality,'secretsRetained':False,
    'oidcArtifactsRetained':False}
   output.write_text(json.dumps(evidence,sort_keys=True,separators=(',',':'))+'\n')
   print(json.dumps({'passed':True,'evidenceSha256':hashlib.sha256(
    output.read_bytes()).hexdigest(),'output':str(output)},sort_keys=True))
  finally:
   server.shutdown();server.server_close()

if __name__=='__main__':main()
