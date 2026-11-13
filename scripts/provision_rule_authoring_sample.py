#!/usr/bin/env python3
"""Create one fresh eight-axis sample through authorized public MCP contracts.

Dry-run is the default. The native OAuth session uses authorized public MCP
only. --development-reset purges the exact controller-provided application
incarnations, waits for its empty-runtime gate, then creates the sample;
--execute creates the sample after separately completed development cleanup.
"""
from __future__ import annotations

import argparse
import ast
import asyncio
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
import json
import sys
from urllib.parse import urlsplit
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != 'scripts':raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts.bootstrap_macos_pilot_application import IDENTIFIER
from openepm import ApplicationPurge, HttpsMcpTransport, McpTransportError, OidcDeviceTokenProvider
from scripts.programmable_source_authoring import active_environment,state_pins,wait_build,read_artifact
from scripts.provision_programmable_uat_sample_contents import _exact_replay,_wait_job

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST=ROOT/'deploy/macos-pilot/rule-authoring-sample.json'
ROLES=frozenset(('Account','Entity','Year','Period','View','Value','Scenario','DataType'))


def program(function,arguments):return {'languageVersion':2,'function':function,'arguments':arguments}
def key(members):return json.dumps(members,sort_keys=True,separators=(',',':'))


def prepare(manifest_path,workspace_id,output,*,authentication=None):
    if not IDENTIFIER.fullmatch(workspace_id) or not output.is_absolute():
        raise ValueError('SAMPLE_SCOPE_INVALID')
    manifest=json.loads(manifest_path.read_text())
    if (manifest.get('format')!='openepm-rule-authoring-sample-v1'
            or not IDENTIFIER.fullmatch(manifest.get('applicationId',''))
            or Path(manifest.get('sourceFile','')).name!=manifest.get('sourceFile')):
        raise ValueError('SAMPLE_DESCRIPTOR_INVALID')
    source=(manifest_path.parent/manifest['sourceFile']).read_text()
    ast.parse(source)
    if {m['dimensionId'] for m in manifest['members']}!=ROLES:
        raise ValueError('SAMPLE_EIGHT_ROLES_REQUIRED')
    points=[row['members'] for row in manifest['numeric']]+[manifest['text']['members']]
    if (len(manifest['numeric'])!=6 or any(set(p)!=ROLES for p in [*points,manifest['absent']])
            or len({key(p) for p in points})!=7 or key(manifest['absent']) in {key(p) for p in points}):
        raise ValueError('SAMPLE_COORDINATES_INVALID')
    if manifest['expected']!={'selectedNumericCount':3,'changedNumericCount':2,
            'beforeSelectedTotal':'150','afterSelectedTotal':'300'}:
        raise ValueError('SAMPLE_EXPECTATION_INVALID')
    return {'format':'openepm-rule-authoring-sample-provision-v1','workspaceId':workspace_id,
        'applicationId':manifest['applicationId'],'name':manifest['name'],
        'sourceDigest':sha256(source.encode()).hexdigest(),
        'descriptorDigest':sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'publicMcpOnly':True,'databaseAccess':False,'businessMutationPerformed':False,
        'output':str(output),'manifest':manifest,'source':source,
        **({'authentication':auth_configuration(**authentication)} if authentication is not None else {})}


async def apply_sample(plan,call):
    """Populate a newly created application, inspect private effects and run once."""
    manifest=plan['manifest'];scope={'workspace_id':plan['workspaceId'],'application_id':plan['applicationId']}
    prefix='rule-authoring-sample-v1';program_id=manifest['programId']
    async def read(function,args=None):return (await call('read_v2_program',{
        **scope,'program':program(function,args or {})}))['result']
    async def write(tool,function,args,label):return (await _exact_replay(call,tool,{
        **scope,'program':program(function,args),'idempotency_key':prefix+'-'+label},label))['result']
    state=await read('application.state.read')
    dimensions=await read('metadata.dimension.list',{'limit':100})
    if (state['metadataRevision']!=1 or state['dataRevision']!=0 or state['policyRevision']!=0
            or state['capabilityRevision']!=0 or state['status']!='Active' or dimensions['hasMore']
            or len(dimensions['rows'])!=8 or {r['model_role'] for r in dimensions['rows']}!=ROLES
            or any(not r['short_description'] or not r['detailed_description'] for r in dimensions['rows'])):
        raise RuntimeError('SAMPLE_REQUIRES_FRESH_EIGHT_AXIS_APPLICATION')
    revision=1
    for index,(function,args) in enumerate([
            *(('metadata.member.create',item) for item in manifest['members']),
            *(('metadata.relationship.create',item) for item in manifest['relationships'])]):
        await write('execute_v2_metadata_program',function,
            {**args,'expectedMetadataRevision':revision},'metadata-'+str(index))
        revision+=1
    for dimension in ('Account','Entity'):
        await write('execute_v2_metadata_program','metadata.hierarchy.build',{
            'dimensionId':dimension,'membershipSemantics':'unique_member',
            'expectedMetadataRevision':revision},'hierarchy-'+dimension)
    for kind,rows in (('numeric',manifest['numeric']),('text',[manifest['text']])):
        mutations=[{'coordinate':row['members'],'op':'set','expectedChangeId':'',
            'value':({'type':'AmountLiteral','decimal':row['before']} if kind=='numeric'
                     else {'type':'TextLiteral','text':row['value']})} for row in rows]
        request=program('facts.'+kind+'.batch',{'mutations':mutations})
        preview=await call('preview_v2_program',{**scope,'program':request})
        accepted=await _exact_replay(call,'submit_v2_program',{
            **scope,'program':request,'preview_token':preview['previewToken'],
            'idempotency_key':prefix+'-seed-'+kind},'seed-'+kind)
        await _wait_job(call,scope,accepted['jobId'])
    decision=await _exact_replay(call,'execute_v2_application_decision',{
        **scope,'program':program('application.decision.create',manifest['decision']),
        'idempotency_key':prefix+'-decision'},'decision')
    shared=await read('application.decision.read',{'decisionId':manifest['decision']['decisionId']})
    if shared['text']!=manifest['decision']['text']:
        raise RuntimeError('SAMPLE_DECISION_READBACK_MISMATCH')

    async def cells():
        result=await read('facts.cube.select',{'grain':{'mode':'full_coordinate','dimensions':sorted(ROLES)},
            'selectors':{'Year':{'kind':'Members','memberIds':['FY26']}},'limit':100})
        if result['hasMore']:raise RuntimeError('SAMPLE_UNEXPECTED_FACTS')
        return {key(row['members']):row for row in result['rows']}
    def verify(rows,phase):
        if len(rows)!=7 or key(manifest['absent']) in rows:raise RuntimeError('SAMPLE_PRESENCE_MISMATCH')
        for item in manifest['numeric']:
            row=rows[key(item['members'])]
            if row['kind']!='numeric' or not row['present'] or Decimal(row['amount'])!=Decimal(item[phase]):
                raise RuntimeError('SAMPLE_NUMERIC_READBACK_MISMATCH')
        text=rows[key(manifest['text']['members'])]
        if text['kind']!='text' or not text['present'] or text['text']!=manifest['text']['value']:
            raise RuntimeError('SAMPLE_COMMENTARY_CHANGED')
    before=await cells();verify(before,'before')
    environment=await active_environment(call,scope,key_prefix=prefix)
    saved=await write('execute_v2_python_program_registry','python.program.save',{
        'definition':{'format':'openepm-current-python-source-v1',
            'programId':program_id,'sourceText':plan['source'],'entryPoint':'build',
            'parameterSchema':{},**environment},**await state_pins(call,scope)},'source-save')
    await wait_build(call,scope,saved['validation']['buildId'])
    tested=await write('execute_v2_python_program_build','python.program.test',{
        'programId':program_id,'programSourceToken':saved['sourceToken'],'parameters':{},
        **await state_pins(call,scope)},'test')
    await wait_build(call,scope,tested['buildId'])
    impact=await read_artifact(call,scope,tested['buildId'],'Impact')
    if (impact['status']!='complete' or impact['businessDataChanged'] is not False
            or impact['sourceDigest']!=plan['sourceDigest']
            or impact['counts']!={'selected':3,'changed':2,'created':0,'cleared':0}
            or len(impact['rows'])!=3):raise RuntimeError('SAMPLE_IMPACT_MISMATCH')
    expected_selected={key(r['members']):r for r in manifest['numeric'][:3]}
    if {key(r['members']) for r in impact['rows']}!=set(expected_selected):
        raise RuntimeError('SAMPLE_IMPACT_SCOPE_MISMATCH')
    for row in impact['rows']:
        expected=expected_selected[key(row['members'])]
        if (not row['before']['present'] or not row['after']['present']
                or Decimal(row['before']['amount'])!=Decimal(expected['before'])
                or Decimal(row['after']['amount'])!=Decimal(expected['after'])):
            raise RuntimeError('SAMPLE_IMPACT_VALUE_MISMATCH')
    totals={phase:sum((Decimal(row[phase]['amount']) for row in impact['rows']),Decimal(0))
            for phase in ('before','after')}
    if totals!={'before':Decimal('150'),'after':Decimal('300')}:
        raise RuntimeError('SAMPLE_IMPACT_TOTAL_MISMATCH')
    if await cells()!=before:raise RuntimeError('PRIVATE_TEST_CHANGED_BUSINESS_DATA')
    active=await write('execute_v2_python_program_registry','python.program.activate',{
        'programId':program_id,'expectedStateToken':saved['stateToken'],
        'validationBuildId':saved['validation']['buildId'],
        **await state_pins(call,scope)},'activate')
    identity=await read('security.identity.current.read')
    now=datetime.now(timezone.utc).replace(microsecond=0)
    binding={'delegationId':'sample-run-authority','scheduleId':None}
    delegated=await write('execute_v2_execution_delegation','execution.delegation.create',{
        **binding,'issuer':identity['issuer'],'subjectId':identity['subjectId'],
        'operationScope':['python.program.build','python.program.run'],
        'validFrom':(now-timedelta(minutes=1)).isoformat(),'validUntil':(now+timedelta(minutes=30)).isoformat(),
        **await state_pins(call,scope)},'run-authority')
    built=await write('execute_v2_python_program_build','python.program.build',{
        **binding,'delegationStateToken':delegated['stateToken'],'programId':program_id,
        'programSourceToken':saved['sourceToken'],'scheduleStateToken':None,'parameters':{},
        **await state_pins(call,scope)},'plan')
    sealed=await wait_build(call,scope,built['buildId'])
    run_args={**scope,'program':program('python.program.run',{'buildId':built['buildId']}),
        'idempotency_key':prefix+'-run'}
    try:running=(await call('execute_v2_python_program_run',run_args))['result']
    except (ConnectionError,TimeoutError):
        running=(await call('execute_v2_python_program_run',run_args))['result']
    for _ in range(480):
        completed=await call('read_v2_python_program_workflow',{**scope,'workflow_id':running['workflowId']})
        if completed['status']=='published':break
        if completed['status'] in ('failed','cancelled','partially_published','needs_inspection'):
            raise RuntimeError('SAMPLE_RULE_FAILED:'+completed['status'])
        await asyncio.sleep(.25)
    else:raise RuntimeError('SAMPLE_RULE_TIMEOUT')
    after=await cells();verify(after,'after')
    before_retry=await read('application.state.read')
    replay=(await call('execute_v2_python_program_run',run_args))['result']
    if replay['workflowId']!=completed['workflowId'] or replay['buildId']!=built['buildId']:
        raise RuntimeError('SAMPLE_RUN_REPLAY_IDENTITY_MISMATCH')
    if await cells()!=after or (await read('application.state.read'))['dataRevision']!=before_retry['dataRevision']:
        raise RuntimeError('SAMPLE_RUN_REPLAY_CHANGED_DATA')
    reopened=await read('python.program.read',{'programId':program_id})
    if (reopened['sourceText']!=plan['source'] or reopened['sourceDigest']!=plan['sourceDigest']
            or reopened['status']!='Active' or reopened['sourceToken']!=saved['sourceToken']):
        raise RuntimeError('SAMPLE_SOURCE_REOPEN_MISMATCH')
    return {'applicationId':plan['applicationId'],'programId':program_id,
        'programSourceToken':saved['sourceToken'],
        'sourceDigest':plan['sourceDigest'],'validationBuildId':saved['validation']['buildId'],
        'impactBuildId':tested['buildId'],'planBuildId':built['buildId'],'planDigest':sealed['planDigest'],
        'workflowId':completed['workflowId'],'activationOperationId':active['operationId'],
        'decisionId':manifest['decision']['decisionId'],'decisionStateToken':decision['stateToken'],
        'selectedNumericCount':3,'changedNumericCount':2,'beforeSelectedTotal':'150','afterSelectedTotal':'300',
        'presentZeroPreserved':True,'absencePreserved':True,'commentaryPreserved':True,
        'outsideScopePreserved':True,'privateTestDidNotPublish':True,'runReplayDidNotRedouble':True,
        'finalDataRevision':before_retry['dataRevision'],'businessMutationPerformed':True,
        'publicMcpOnly':True,'databaseAccess':False}


def auth_configuration(*,issuer,client_id,workspace_endpoint,application_endpoint):
    for value in (issuer,workspace_endpoint,application_endpoint):
        parsed=urlsplit(value)
        if (parsed.scheme!='https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or not parsed.path.startswith('/') or any(c in value for c in ('\r','\n','\x00'))):
            raise ValueError('SAMPLE_AUTH_URL_INVALID')
        _=parsed.port
    if issuer.endswith('/') or not IDENTIFIER.fullmatch(client_id):
        raise ValueError('SAMPLE_AUTH_CONFIGURATION_INVALID')
    return {'issuer':issuer,'client_id':client_id,'workspace_endpoint':workspace_endpoint,
            'application_endpoint':application_endpoint}


async def native_call(transport,tool,arguments):
    try:
        return await asyncio.to_thread(transport.call,tool,arguments)
    except McpTransportError as error:
        # Only an uncertain network acknowledgement is retried, with exactly
        # the same request key. Server authorization/validation denials remain
        # visible and never become a new operation.
        if str(error)!='MCP HTTPS request failed' or not (
                arguments.get('idempotency_key') or tool.startswith(('read_','list_'))):
            raise
        return await asyncio.to_thread(transport.call,tool,arguments)


async def verify_workspace_authority(plan,workspace):
    catalogue=await native_call(workspace,'list_v2_workspace_functions',{})
    if (catalogue.get('listener')!={'scope':'workspace','workspaceId':plan['workspaceId']}
            or 'workspace.application.create' not in catalogue.get('functions',{})):
        raise RuntimeError('SAMPLE_WORKSPACE_AUTHORITY_MISMATCH')
    return catalogue


async def verify_native_authority(plan,workspace,application):
    catalogue=await verify_workspace_authority(plan,workspace)
    identity=await native_call(application,'read_v2_session_identity',{})
    if (identity.get('issuer')!=plan['authentication']['issuer']
            or not isinstance(identity.get('subject'),str) or not identity['subject']):
        raise RuntimeError('SAMPLE_MCP_IDENTITY_MISMATCH')
    return catalogue


def _instant(value):
    if not isinstance(value,str) or len(value)>80:raise ValueError('SAMPLE_PURGE_INVENTORY_INVALID')
    parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None:raise ValueError('SAMPLE_PURGE_INVENTORY_INVALID')
    return parsed


def validate_controller_barrier(value,event,workspace_id):
    expected={'event','workspaceId'}|({'applicationPurgeTargets'} if event=='purge-ready' else set())
    if (type(value) is not dict or set(value)!=expected or value['event']!=event
            or value['workspaceId']!=workspace_id):
        raise ValueError('SAMPLE_CONTROLLER_BARRIER_INVALID')
    if event!='purge-ready':return value
    targets=value['applicationPurgeTargets']
    if type(targets) is not list or len(targets)>1000:raise ValueError('SAMPLE_PURGE_INVENTORY_INVALID')
    seen=set()
    for target in targets:
        if (type(target) is not dict or set(target)!={'workspaceId','applicationId','createdAt','status'}
                or target['workspaceId']!=workspace_id or not isinstance(target['applicationId'],str)
                or not IDENTIFIER.fullmatch(target['applicationId']) or target['applicationId'] in seen
                or target['status'] not in ('Active','Inactive','Deleting')):
            raise ValueError('SAMPLE_PURGE_INVENTORY_INVALID')
        _instant(target['createdAt']);seen.add(target['applicationId'])
    return value


async def controller_barrier(event,workspace_id):
    print(json.dumps({'event':'waiting-for-controller','requiredEvent':event,
                      'workspaceId':workspace_id}),flush=True)
    raw=await asyncio.to_thread(sys.stdin.buffer.readline,1024*1024+1)
    if len(raw)>1024*1024 or not raw.endswith(b'\n'):
        raise ValueError('SAMPLE_CONTROLLER_BARRIER_INVALID')
    return validate_controller_barrier(json.loads(raw),event,workspace_id)


async def visible_workspace_applications(application,workspace_id):
    found=set();after=None;seen=set()
    for _ in range(256):
        page=await native_call(application,'list_v2_applications',
            {'limit':100,**({'after':after} if after is not None else {})})
        if type(page.get('applications')) is not list:raise RuntimeError('SAMPLE_APPLICATION_LIST_INVALID')
        for row in page['applications']:
            if row.get('workspaceId')==workspace_id:
                app=row.get('applicationId')
                if not isinstance(app,str) or not IDENTIFIER.fullmatch(app) or app in found:
                    raise RuntimeError('SAMPLE_APPLICATION_LIST_INVALID')
                found.add(app)
        after=page.get('nextAfter')
        if after is None:return found
        token=json.dumps(after,sort_keys=True)
        if token in seen:raise RuntimeError('SAMPLE_APPLICATION_LIST_INVALID')
        seen.add(token)
    raise RuntimeError('SAMPLE_APPLICATION_LIST_LIMIT')


async def development_reset(plan,workspace,application):
    ready=await controller_barrier('purge-ready',plan['workspaceId'])
    catalogue=await verify_workspace_authority(plan,workspace)
    required={'workspace.application.purge.'+name for name in ('prepare','quiesce','apply')}
    if not required<=set(catalogue['functions']):raise RuntimeError('SAMPLE_PURGE_INTERFACE_UNAVAILABLE')
    targets=ready['applicationPurgeTargets']
    purge=ApplicationPurge(workspace)
    for target in targets:
        app=target['applicationId']
        prepared=await asyncio.to_thread(purge.prepare,app)
        manifest=prepared['manifest']
        if (manifest.get('workspaceId')!=plan['workspaceId'] or manifest.get('applicationId')!=app
                or _instant(manifest.get('createdAt'))!=_instant(target['createdAt'])):
            raise RuntimeError('SAMPLE_PURGE_INCARNATION_CHANGED')
        created=manifest['createdAt']
        prefix='sample-reset-'+sha256(json.dumps([plan['workspaceId'],app,created],
            separators=(',',':')).encode()).hexdigest()[:40]
        if manifest['status']!='Deleting':
            await asyncio.to_thread(purge.quiesce,app,created_at=created,
                manifest_digest=prepared['manifestDigest'],request_key=prefix+'-quiesce')
        for _ in range(1200):
            current=(await asyncio.to_thread(purge.prepare,app))['manifest']
            if (_instant(current.get('createdAt'))!=_instant(created)
                    or current.get('workspaceId')!=plan['workspaceId'] or current.get('applicationId')!=app):
                raise RuntimeError('SAMPLE_PURGE_INCARNATION_CHANGED')
            if current.get('activeLeases')=={}:break
            await asyncio.sleep(.25)
        else:raise RuntimeError('SAMPLE_PURGE_WORKERS_NOT_DRAINED')
        args={'program':program('workspace.application.purge.apply',{
            'applicationId':app,'createdAt':created}),'idempotency_key':prefix+'-apply'}
        async def call(tool,arguments):return await native_call(workspace,tool,arguments)
        deleted=await _exact_replay(call,'execute_v2_application_purge',args,'purge-apply')
        if (deleted.get('status')!='Deleted' or deleted.get('workspaceId')!=plan['workspaceId']
                or deleted.get('applicationId')!=app or _instant(deleted.get('createdAt'))!=_instant(created)):
            raise RuntimeError('SAMPLE_PURGE_RESULT_MISMATCH')
    # The router is stopped during purge-ready. Only the workspace listener
    # may be called until the controller proves empty storage and starts it.
    print(json.dumps({'event':'workspace-purge-complete','workspaceId':plan['workspaceId'],
        'purgedApplicationCount':len(targets),
        'authoritativeControllerEmptyProofRequired':True}),flush=True)
    await controller_barrier('activate-empty',plan['workspaceId'])
    await verify_native_authority(plan,workspace,application)
    # This additional check cannot replace the controller's authoritative
    # empty gate: normal router discovery intentionally omits Deleting apps.
    if await visible_workspace_applications(application,plan['workspaceId']):
        raise RuntimeError('SAMPLE_VISIBLE_APPLICATIONS_REMAIN')
    return {'purgedApplicationCount':len(targets),'controllerEmptyBarrierReceived':True}


async def execute(plan,*,check_auth=False,reset_development=False):
    if check_auth and reset_development:raise ValueError('SAMPLE_ACTION_INVALID')
    config=plan.get('authentication')
    if config is None:raise ValueError('SAMPLE_AUTH_CONFIGURATION_REQUIRED')
    provider=OidcDeviceTokenProvider(config['issuer'],client_id=config['client_id'])
    result=None
    try:
        prompt=await asyncio.to_thread(provider.begin)
        print(json.dumps({'event':'device-login-required','verificationUri':prompt.verification_uri,
            'verificationUriComplete':prompt.verification_uri_complete,'userCode':prompt.user_code,
            'expiresIn':prompt.expires_in}),flush=True)
        await asyncio.to_thread(provider.await_token)
        workspace=HttpsMcpTransport(config['workspace_endpoint'],provider,timeout_seconds=300)
        application=HttpsMcpTransport(config['application_endpoint'],provider,timeout_seconds=300)
        await verify_native_authority(plan,workspace,application)
        reset_result=None
        if reset_development:reset_result=await development_reset(plan,workspace,application)
        if check_auth:
            result={'format':'openepm-rule-authoring-sample-auth-check-v1','status':'passed',
                'workspaceId':plan['workspaceId'],'workspaceAdministratorVerified':True,
                'mcpIdentityVerified':True,'businessMutationPerformed':False}
        else:
            async def workspace_call(tool,args):return await native_call(workspace,tool,args)
            created=await _exact_replay(workspace_call,'execute_v2_workspace_program',{
                'program':program('workspace.application.create',{'applicationId':plan['applicationId'],
                    'name':plan['name'],'kind':'multidimensional'}),
                'idempotency_key':'rule-authoring-sample-create-v1'},'create')
            if (created['workspaceId']!=plan['workspaceId'] or created['applicationId']!=plan['applicationId']
                    or created['enabledCapabilities']!=[]):raise RuntimeError('SAMPLE_CREATE_MISMATCH')
            async def call(tool,args):return await native_call(application,tool,args)
            populated=await apply_sample(plan,call)
            result={'format':'openepm-rule-authoring-sample-provision-result-v1',
                'generatedAt':datetime.now(timezone.utc).isoformat(),'workspaceId':plan['workspaceId'],
                'descriptorDigest':plan['descriptorDigest'],'status':'passed',**populated,
                **({'developmentReset':reset_result} if reset_result is not None else {})}
    finally:
        try:await asyncio.to_thread(provider.revoke)
        finally:provider.close()
    return {**result,'oauthTokenRetained':False,'oauthSessionRevoked':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest',type=Path,default=DEFAULT_MANIFEST)
    parser.add_argument('--workspace-id',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--issuer',required=True)
    parser.add_argument('--client-id',default='openepm-mcp')
    parser.add_argument('--workspace-endpoint',required=True)
    parser.add_argument('--application-endpoint',required=True)
    actions=parser.add_mutually_exclusive_group()
    actions.add_argument('--execute',action='store_true')
    actions.add_argument('--check-auth',action='store_true')
    actions.add_argument('--development-reset',action='store_true')
    args=parser.parse_args()
    try:
        plan=prepare(args.manifest,args.workspace_id,args.output,authentication={
            'issuer':args.issuer,'client_id':args.client_id,'workspace_endpoint':args.workspace_endpoint,
            'application_endpoint':args.application_endpoint})
        if not (args.execute or args.check_auth or args.development_reset):
            print(json.dumps({k:v for k,v in plan.items() if k not in ('manifest','source')},sort_keys=True));return 0
        result=asyncio.run(execute(plan,check_auth=args.check_auth,reset_development=args.development_reset))
    except (OSError,ValueError,RuntimeError) as error:parser.error(str(error))
    args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'status':'passed','workspaceId':plan['workspaceId'],'output':str(args.output)}));return 0


if __name__=='__main__':raise SystemExit(main())
