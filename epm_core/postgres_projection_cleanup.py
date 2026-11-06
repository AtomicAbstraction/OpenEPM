"""Administrator-authored, fixed-target cleanup of hidden derived generations."""
from contextlib import contextmanager
import time

import psycopg
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity,assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_execution_scope import current_deadline,tool_execution_scope,ToolDeadlineExpired
from .postgres_jobs import (PostgresJobQueue,_canonical_digest,_JOB_ID,_KEY,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout,lock_busy_boundary
from .postgres_fact_reconstruction_job import _heartbeat

FUNCTION='facts.projections.cleanup'
COMPILER='projection-generations-cleanup-v1'
EXECUTION_SECONDS=20
PLAN_DIGEST=_canonical_digest({'function':FUNCTION,'compiler':COMPILER,
    'source':'native-recovery-manifest','effect':'bounded-inactive-generation-deletion',
    'publication':'technical-receipt-no-active-pointer-change','checkpoint':'durable-ready-yield',
    'retryAccounting':'successful-quantum-does-not-consume-failure-attempt',
    'preserve':['active-generation','canonical-events','source-history','change-ids',
                'data-revision','metadata-revision','policy-revision','schema-epoch'],
    'executionSeconds':EXECUTION_SECONDS})
_PINS=('targetGeneration','recoveryProgramDigest','schemaEpoch')
_NATIVE_CODES=frozenset(('STALE_WORKER_FENCE','APPLICATION_NOT_WRITABLE','APPLICATION_GRANT_REQUIRED',
    'PROJECTION_CLEANUP_SCOPE_INVALID','PROJECTION_CLEANUP_JOB_INVALID','PROJECTION_CLEANUP_TARGET_INVALID',
    'PROJECTION_CLEANUP_TARGET_ACTIVE','PROJECTION_CLEANUP_SCHEMA_CHANGED','PROJECTION_CLEANUP_DELETE_FORBIDDEN'))


@contextmanager
def _native_boundary():
    try:yield
    except (psycopg.errors.CheckViolation,psycopg.errors.RaiseException) as error:
        code=error.diag.message_primary
        if code in _NATIVE_CODES:raise ValueError(code) from error
        raise


def intent(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or raw['function']!=FUNCTION or not isinstance(raw['arguments'],dict)
            or set(raw['arguments'])!={'rebuildJobId','generationKind','reason'}):
        raise ValueError('CLEANUP_PROGRAM_INVALID')
    args=raw['arguments'];reason=args['reason']
    if (not isinstance(args['rebuildJobId'],str) or not _JOB_ID.fullmatch(args['rebuildJobId'])
            or args['generationKind'] not in ('abandoned','retired')
            or not isinstance(reason,str) or not 1<=len(reason.strip())<=500 or '\0' in reason):
        raise ValueError('CLEANUP_ARGUMENTS_INVALID')
    return {'rebuildJobId':args['rebuildJobId'],'generationKind':args['generationKind'],'reason':reason.strip()}


def compile_program(raw,target):
    args=intent(raw)
    if (not isinstance(target,dict)
            or type(target.get('targetGeneration')) is not int or target['targetGeneration']<0
            or type(target.get('schemaEpoch')) is not int or target['schemaEpoch']<0
            or not isinstance(target.get('recoveryProgramDigest'),str)
            or len(target['recoveryProgramDigest'])!=64
            or any(c not in '0123456789abcdef' for c in target['recoveryProgramDigest'])):
        raise ValueError('CLEANUP_TARGET_INVALID')
    return {'version':1,'function':FUNCTION,**args,**{key:target[key] for key in _PINS}}


def decode_program(value):
    try:
        if (not isinstance(value,dict) or set(value)!={'version','function','reason','rebuildJobId',
                'generationKind',*_PINS} or type(value['version']) is not int or value['version']!=1):
            raise ValueError('shape')
        checked=compile_program({'languageVersion':2,'function':value['function'],'arguments':{
            key:value[key] for key in ('rebuildJobId','generationKind','reason')}},value)
        if checked!=value:raise ValueError('noncanonical')
        return checked
    except (KeyError,TypeError,ValueError) as error:
        raise ValueError('CLEANUP_NORMALIZED_INVALID') from error


def resolve_target(db,scope,args):
    with _native_boundary():
        return db.execute('SELECT epm.projection_cleanup_target(%s,%s,%s,%s) AS target',
            (scope.workspace_id,scope.application_id,args['rebuildJobId'],args['generationKind'])).fetchone()['target']


def preview(language,scope,raw):
    args=intent(raw)
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            configure_statement_timeout(db,5000)
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(
                db,language.identity,scope,'admin',function=FUNCTION)
            state=db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,s.data_revision,
                s.policy_revision,s.schema_epoch,s.commit_open FROM epm.application_state s
                JOIN epm.application a USING(workspace_id,application_id)
                WHERE workspace_id=%s AND application_id=%s FOR SHARE OF s''',
                (scope.workspace_id,scope.application_id)).fetchone()
            if not state or state['status']!='Active' or state['processing_mode']!='Active':
                raise ValueError('APPLICATION_NOT_WRITABLE')
            if state['commit_open']:raise ValueError('CLEANUP_SCHEMA_CHANGED')
            normalized=compile_program(raw,resolve_target(db,scope,args))
            if normalized['schemaEpoch']!=state['schema_epoch']:raise ValueError('CLEANUP_SCHEMA_CHANGED')
            revisions={key:state[key] for key in ('metadata_revision','data_revision','policy_revision')}
    pins={key:normalized[key] for key in _PINS}
    token,digest=language._sign_preview(scope,FUNCTION,normalized,revisions,extra=pins)
    return {'languageVersion':2,'function':FUNCTION,'previewToken':token,'programDigest':digest,
            'revisionVector':revisions,'workClass':'long',**pins}


def submit(language,scope,raw,token,key,dependencies):
    args=intent(raw)
    if (not isinstance(key,str) or not _KEY.fullmatch(key)
            or not isinstance(dependencies,tuple) or len(dependencies)>16
            or any(not isinstance(dep,str) or not _JOB_ID.fullmatch(dep) for dep in dependencies)
            or len(set(dependencies))!=len(dependencies)):
        raise ValueError('CLEANUP_REQUEST_INVALID')
    keys={'scope','identity','function','programDigest','revisions','expiresAt',*_PINS}
    with connect_postgres(language.dsn,row_factory=dict_row) as db:
        with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(db,language.identity,scope,'admin',function=FUNCTION)
            prior=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s AND application_id=%s
                AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
                (scope.workspace_id,scope.application_id,language.identity.issuer,language.identity.subject_id,key)).fetchone()
            if prior:
                normalized=decode_program(prior['normalized_program'])
                signed=language._unpack_preview(scope,FUNCTION,token,allow_expired=True)
                revisions={k:prior['expected_'+k] for k in ('metadata_revision','data_revision','policy_revision')}
                if (set(signed)!=keys or signed['programDigest']!=_canonical_digest(normalized)
                        or any(signed[k]!=normalized[k] for k in _PINS) or signed['revisions']!=revisions):
                    raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
                auth_scope=_verify_job_replay_authorization(db,scope,
                    language.identity,prior,access=access,function_name=FUNCTION)
                descriptor=_job_request_descriptor(scope,language.identity,
                    function_name=FUNCTION,
                    program_digest=_canonical_digest(normalized),
                    compiler_version=COMPILER,plan_digest=PLAN_DIGEST,
                    revisions=(prior['expected_metadata_revision'],
                        prior['expected_data_revision'],prior['expected_policy_revision']),
                    resource_class='long',dependencies=dependencies,
                    authorization_scope_digest=auth_scope)
                if (any(normalized[k]!=args[k] for k in args) or prior['function_name']!=FUNCTION
                        or prior['compiler_version']!=COMPILER or prior['plan_digest']!=PLAN_DIGEST
                        or prior['program_digest']!=descriptor['programDigest'] or prior['resource_class']!='long'
                        or prior['request_digest']!=_canonical_digest(descriptor)):
                    raise ValueError('CLEANUP_IDEMPOTENCY_CONFLICT')
                return {'jobId':prior['job_id'],'status':prior['status'],'duplicate':True}
    payload=language._unpack_preview(scope,FUNCTION,token)
    if set(payload)!=keys:raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    normalized=compile_program(raw,payload)
    if payload['programDigest']!=_canonical_digest(normalized):raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
    revisions=payload['revisions']
    return PostgresJobQueue(language.dsn,identity=language.identity).submit(scope,
        idempotency_key=key,function_name=FUNCTION,normalized_program=normalized,compiler_version=COMPILER,
        plan_digest=PLAN_DIGEST,resource_class='long',expected_metadata_revision=revisions['metadata_revision'],
        expected_data_revision=revisions['data_revision'],expected_policy_revision=revisions['policy_revision'],
        depends_on_job_ids=dependencies)


@contextmanager
def _execution_budget(deadline):
    try:
        with tool_execution_scope(deadline):yield
    except (ToolDeadlineExpired,psycopg.errors.QueryCanceled):
        raise ValueError('CLEANUP_EXECUTION_BUDGET') from None


class PostgresProjectionCleanupPublisher:
    def __init__(self,dsn,*,identity,worker=None):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn,'epm_runtime',('application_state','operation_receipt','projection_cleanup_manifest'))
        self.dsn,self.identity,self.worker=dsn,identity,worker

    @lock_busy_boundary
    def publish(self,claim):
        if (not isinstance(claim,dict) or any(not isinstance(claim.get(k),str) or not claim[k]
                for k in ('workspace_id','application_id','job_id','claimant'))
                or not _JOB_ID.fullmatch(claim['job_id']) or type(claim.get('claim_generation')) is not int
                or claim['claim_generation']<1):raise ValueError('STALE_WORKER_FENCE')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id'])
        deadline=time.monotonic()+EXECUTION_SECONDS
        if current_deadline() is not None:deadline=min(deadline,current_deadline())
        with _execution_budget(deadline),_heartbeat(self.worker,claim) as failures:
            with connect_postgres(self.dsn,row_factory=dict_row) as db:
                with db.transaction():
                    PostgresNumericFactStore._set_scope(db,scope)
                    PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                    PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=FUNCTION)
                    configure_statement_timeout(db,20000)
                    job=db.execute('''SELECT *,lease_until>clock_timestamp() AS lease_live FROM epm.job
                        WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                        (scope.workspace_id,scope.application_id,claim['job_id'])).fetchone()
                    if (not job or job['status']!='running' or not job['lease_live']
                            or job['claimant']!=claim['claimant'] or job['claim_generation']!=claim['claim_generation']
                            or job['issuer']!=self.identity.issuer or job['subject_id']!=self.identity.subject_id):
                        raise ValueError('STALE_WORKER_FENCE')
                    normalized=decode_program(job['normalized_program'])
                    if (job['function_name']!=FUNCTION or job['compiler_version']!=COMPILER
                            or job['plan_digest']!=PLAN_DIGEST or job['program_digest']!=_canonical_digest(normalized)
                            or job['resource_class']!='long'):raise ValueError('CLEANUP_JOB_INVALID')
                    state=db.execute('''SELECT processing_mode,schema_epoch,commit_open FROM epm.application_state
                        WHERE workspace_id=%s AND application_id=%s''',
                        (scope.workspace_id,scope.application_id)).fetchone()
                    if not state or state['processing_mode']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
                    if state['schema_epoch']!=normalized['schemaEpoch'] or state['commit_open']:
                        raise ValueError('CLEANUP_SCHEMA_CHANGED')
                    if failures:raise ValueError('STALE_WORKER_FENCE')
                    with _native_boundary():
                        result=db.execute('SELECT epm.projection_generations_cleanup_step(%s,%s,%s,%s,%s) AS result',
                            (scope.workspace_id,scope.application_id,claim['job_id'],claim['claimant'],claim['claim_generation'])).fetchone()['result']
                    valid=isinstance(result,dict) and result.get('targetGeneration')==normalized['targetGeneration']
                    if valid and result.get('checkpoint') is True:
                        valid=(result.get('status')=='ready' and result.get('phase') in (
                            'numeric','text','detail','generic','members','projection','publish')
                            and type(result.get('deletedRows')) is int and 0<=result['deletedRows']<=128
                            and type(result.get('serializedBytes')) is int and result['serializedBytes']>=0
                            and (result['serializedBytes']<=1048576 or result['deletedRows']==1)
                            and type(result.get('quantumCount')) is int and result['quantumCount']>=1)
                    elif valid:
                        valid=(result.get('status')!='ready' and result.get('historyPreserved') is True
                            and result.get('activeGenerationRetained') is True
                            and result.get('rebuildJobId')==normalized['rebuildJobId']
                            and result.get('generationKind')==normalized['generationKind']
                            and type(result.get('committedRevision')) is int and result['committedRevision']>0)
                    if not valid:
                        raise ValueError('CLEANUP_NATIVE_RESULT_INVALID')
                    return result


def catalog():
    schema={'$schema':'https://json-schema.org/draft/2020-12/schema','type':'object','additionalProperties':False,
        'required':['languageVersion','function','arguments'],'properties':{'languageVersion':{'const':2},
        'function':{'const':FUNCTION},'arguments':{'type':'object','additionalProperties':False,
            'required':['rebuildJobId','generationKind','reason'],'properties':{
                'rebuildJobId':{'type':'string','pattern':'^[0-9a-f]{32}$'},
                'generationKind':{'enum':['abandoned','retired']},
                'reason':{'type':'string','minLength':1,'maxLength':500}}}}}
    return {FUNCTION:{'mode':'durable_write','permission':'admin','previewRequired':True,'idempotencyRequired':True,
        'workClass':'long','arguments':{'rebuildJobId':'Existing V2 recovery job ID',
            'generationKind':'abandoned target of a failed/cancelled build or retired source of a published build',
            'reason':'1–500 nonblank characters'},'result':'jobId then bounded hidden-row deletion checkpoints and receipt',
        'programContract':{'programSchema':schema,'examples':[{'program':{'languageVersion':2,'function':FUNCTION,
            'arguments':{'rebuildJobId':'a'*32,'generationKind':'retired','reason':'Reclaim an obsolete derived generation'}}}],
            'semanticRules':['Administrator permission is required at preview, admission, replay and each worker quantum.',
                'Native recovery metadata selects the target; arbitrary generation numbers or rows are forbidden.',
                'Active generations, canonical events, receipts and source history are never cleanup targets.',
                'Admission pins the usual revision vector; after admission business writes may advance while the exact hidden target and schema stay valid.',
                'Each quantum has a 20-second budget preserving shorter configured limits; successful checkpoints do not consume failure attempts.',
                'No active pointer or data/metadata/policy/schema revision changes; only the final technical receipt advances commit revision.'],
            'execution':{'scope':'one authorized application; one fixed hidden generation','compiler':COMPILER,'planDigest':PLAN_DIGEST}}}}
