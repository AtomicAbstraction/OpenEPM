"""Sealed public execution for a published reusable Allocation policy."""
from __future__ import annotations
from hashlib import sha256
import json
import re
from psycopg.rows import dict_row
from .planning_operation_policy_lowering import lower_bound_policy_to_legacy_v2
from .planning_operation_policy import FORMAT_V2
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import (PostgresJobQueue,_canonical_digest,
    _job_request_descriptor,_verify_job_replay_authorization)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_policy_resolution import resolve_published_planning_policy
from .postgres_planning_allocation import (FUNCTION,POLICY_COMPILER,
    POLICY_PLAN_DIGEST,POLICY_V2_COMPILER,POLICY_V2_PLAN_DIGEST,
    compile_allocation_program,
    decode_policy_allocation_program,encode_policy_allocation_program,
    validate_allocation_inputs)
from .postgres_processing_limits import configure_statement_timeout
from .postgres_expression import (published_input_status,
    RATIO_RESULT_COMPILER,RATIO_RESULT_PLAN_DIGEST)

PREVIEW='planning.operation.policy.allocation.preview'
RUN='planning.operation.policy.allocation.run'
FUNCTIONS=frozenset((PREVIEW,RUN))

def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode()).hexdigest()

def catalog():
    args={'policyId':'published Allocation policy ID','effectiveOn':'ISO date',
      'bindings':'typed parameters','source':'complete source coordinate',
      'basisTemplate':'complete basis coordinate template','resultKey':'publication key'}
    return {PREVIEW:{'mode':'calculation_preview','permission':'write',
      'requiredCapabilities':[],'arguments':args,
      'optionalArguments':{'basisPublishedInput':'required only by V2 PublishedRatio policy: resultKey/resultStateToken'},
      'result':'sealed source/basis/targets',
      'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
      RUN:{'mode':'durable_calculation','permission':'write',
      'requiredCapabilities':[],'arguments':{**args,'previewToken':'signed preview'},
      'optionalArguments':{'basisPublishedInput':'required only by V2 PublishedRatio policy'},
      'result':'durable exact allocation job','previewRequired':True,
      'idempotencyRequired':True,'workClass':'short'}}

class PostgresPublishedPlanningAllocation:
    def __init__(self,dsn,*,identity,preview_secret):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity
        from .postgres_language_v2 import PostgresLanguageV2
        self.language=PostgresLanguageV2(dsn,identity=identity,preview_secret=preview_secret)
    @staticmethod
    def _arguments(program,function,token=False):
        required={'policyId','effectiveOn','bindings','source','basisTemplate','resultKey'}
        if token:required.add('previewToken')
        if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
          or type(program['languageVersion']) is not int or program['languageVersion']!=2
          or program['function']!=function or not isinstance(program['arguments'],dict)
          or set(program['arguments']) not in (required,required|{'basisPublishedInput'})):
            raise ValueError('PLANNING_ALLOCATION_POLICY_PROGRAM_INVALID')
        return dict(program['arguments'])
    def _dependency(self,scope,pin):
        if (not isinstance(pin,dict) or set(pin)!={'resultKey','resultStateToken'}
                or not isinstance(pin['resultKey'],str)
                or re.fullmatch(r'[A-Za-z0-9._-]{8,128}',pin['resultKey']) is None
                or not isinstance(pin['resultStateToken'],str)
                or re.fullmatch(r'[0-9a-f]{64}',pin['resultStateToken']) is None):
            raise ValueError('PLANNING_ALLOCATION_PUBLISHED_RATIO_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute('SET TRANSACTION READ ONLY');PostgresNumericFactStore._set_scope(db,scope)
            PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write',function=RUN)
            row=db.execute('''SELECT p.result_key,p.state_token,
                p.source_operation_id AS job_id,
                p.source_function AS function_name,
                j.status,j.normalized_program,
                j.compiler_version,j.plan_digest FROM epm.calculation_result_state p
                JOIN epm.job j ON (j.workspace_id,j.application_id,j.job_id)=
                  (p.workspace_id,p.application_id,p.source_operation_id)
                WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s''',
                (scope.workspace_id,scope.application_id,pin['resultKey'])).fetchone()
            freshness=published_input_status(db,scope,{'publishedInputs':[pin]})
            count=(db.execute('''SELECT count(*)::integer AS n FROM
                epm.calculation_ratio_result_current WHERE workspace_id=%s
                AND application_id=%s AND result_key=%s''',(
                scope.workspace_id,scope.application_id,
                pin['resultKey'])).fetchone()['n'] if row else 0)
        if (row is None or row['status']!='published'
                or row['state_token']!=pin['resultStateToken']
                or row['function_name']!='facts.expression.calculate'
                or row['compiler_version']!=RATIO_RESULT_COMPILER
                or row['plan_digest']!=RATIO_RESULT_PLAN_DIGEST
                or row['normalized_program'].get('resultUnit')!={'type':'Ratio','scale':12}
                or freshness is None or not freshness['matchesAtRead'] or not 1<=count<=500):
            raise ValueError('PLANNING_ALLOCATION_PUBLISHED_RATIO_STALE')
        return dict(pin)
    def _compile(self,scope,args):
        bound,pointer=resolve_published_planning_policy(self.dsn,self.identity,scope,
          {k:args[k] for k in ('policyId','effectiveOn','bindings')},
          expected_kind='Allocation',function=RUN)
        v2=bound.get('policyFormat')==FORMAT_V2
        if v2 != ('basisPublishedInput' in args):
            raise ValueError('PLANNING_ALLOCATION_POLICY_PROGRAM_INVALID')
        dependency=self._dependency(scope,args['basisPublishedInput']) if v2 else None
        policy={k:bound[k] for k in ('policyId','policyDigest','metadataRevision','policyRevision')};policy.update(pointer)
        if v2: policy.update({'policyFormat':FORMAT_V2,'publishedDependency':dependency,
            'lineageBudget':{'maxCanonicalBytes':65536,'maxDepth':8}})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute('SET TRANSACTION READ ONLY');configure_statement_timeout(db,5000)
            PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(
                db,self.identity,scope,'write',function=RUN,arguments=args)
            state=db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,s.data_revision,s.policy_revision
              FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
              WHERE s.workspace_id=%s AND s.application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None or state['status']!='Active' or state['processing_mode']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
            if state['metadata_revision']!=policy['metadataRevision'] or state['policy_revision']!=policy['policyRevision']:raise ValueError('PLANNING_ALLOCATION_POLICY_STALE')
            row=db.execute('''SELECT state_token FROM epm.calculation_result_state
              WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
              (scope.workspace_id,scope.application_id,args['resultKey'])).fetchone();target_token=row['state_token'] if row else None
            execution={'source':args['source'],
              'basisTemplate':args['basisTemplate'],'resultKey':args['resultKey'],
              'expectedTargetStateToken':target_token}
            if v2:execution['basisPublishedInput']=args['basisPublishedInput']
            lowered=lower_bound_policy_to_legacy_v2(bound,execution)
            plan=compile_allocation_program(lowered.program,
                expected_target_state_token=target_token)
            source,total=validate_allocation_inputs(db,scope,plan)
            revisions={k:state[k] for k in ('metadata_revision','data_revision','policy_revision')}
        return plan,policy,source,total,revisions
    def preview(self,scope,program):
        args=self._arguments(program,PREVIEW);plan,policy,source,total,revisions=self._compile(scope,args)
        normalized=encode_policy_allocation_program(plan,policy)
        token,digest=self.language._sign_preview(scope,RUN,normalized,revisions,
          extra={'requestDigest':_digest(args),
                 'expectedTargetStateToken':plan.expected_target_state_token})
        return {'languageVersion':2,'function':RUN,'programDigest':digest,'revisionVector':revisions,
          'sourceAmount':format(source['amount'],'f'),'totalBasis':format(total,'f'),
          'targetCount':len(plan.target_members),'conservesSourceTotal':True,
          'remainderOrder':'largest_remainder_stable_member','reusablePolicy':policy,
          'compilerVersion':POLICY_V2_COMPILER if plan.published_ratio_basis else POLICY_COMPILER,
          'planDigest':POLICY_V2_PLAN_DIGEST if plan.published_ratio_basis else POLICY_PLAN_DIGEST,
          'engine':'postgres_exact_sql','previewToken':token}
    def _replay(self,scope,key,args,payload):
        if payload.get('requestDigest')!=_digest(args):raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write',function=RUN,arguments=args)
            p=db.execute('''SELECT job_id,status,function_name,normalized_program,compiler_version,program_digest,
              request_digest,plan_digest,expected_metadata_revision,expected_data_revision,expected_policy_revision,resource_class,
              verified_groups,authorization_scope_digest
              FROM epm.job WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
              (scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,key)).fetchone()
            if p is None:return None
            deps=db.execute('''SELECT depends_on_job_id FROM epm.job_dependency WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
              (scope.workspace_id,scope.application_id,p['job_id'])).fetchall()
            auth_scope=_verify_job_replay_authorization(db,scope,self.identity,p,
              access=access,function_name=p['function_name'])
        try:_,policy=decode_policy_allocation_program(p['normalized_program'])
        except ValueError as error:raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT') from error
        r=payload.get('revisions');dep_ids=tuple(x['depends_on_job_id'] for x in deps)
        expected_compiler=(POLICY_V2_COMPILER if policy.get('policyFormat')==FORMAT_V2 else POLICY_COMPILER)
        expected_digest=(POLICY_V2_PLAN_DIGEST if expected_compiler==POLICY_V2_COMPILER else POLICY_PLAN_DIGEST)
        if (p['function_name']!=FUNCTION or p['compiler_version']!=expected_compiler or p['plan_digest']!=expected_digest
          or p['program_digest']!=_canonical_digest(p['normalized_program']) or p['program_digest']!=payload.get('programDigest')
          or policy.get('policyId')!=args['policyId'] or not isinstance(r,dict)
          or [p['expected_metadata_revision'],p['expected_data_revision'],p['expected_policy_revision']]!=[r.get('metadata_revision'),r.get('data_revision'),r.get('policy_revision')]):raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        descriptor=_job_request_descriptor(scope,self.identity,
          function_name=FUNCTION,program_digest=p['program_digest'],
          compiler_version=expected_compiler,plan_digest=expected_digest,
          revisions=(p['expected_metadata_revision'],p['expected_data_revision'],
              p['expected_policy_revision']),resource_class=p['resource_class'],
          dependencies=dep_ids,authorization_scope_digest=auth_scope,
          verified_groups=access.groups)
        expected_dep_ids=()
        if dep_ids!=expected_dep_ids or _canonical_digest(descriptor)!=p['request_digest']:
            raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
        return {'jobId':p['job_id'],'status':p['status'],'duplicate':True}
    def run(self,scope,program,*,idempotency_key):
        args=self._arguments(program,RUN,True);token=args.pop('previewToken');payload=self.language._unpack_preview(scope,RUN,token)
        replay=self._replay(scope,idempotency_key,args,payload)
        if replay:return replay
        if set(payload)!={'scope','identity','function','programDigest','revisions','expiresAt','requestDigest','expectedTargetStateToken'}:raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        plan,policy,_,_,revisions=self._compile(scope,args);normalized=encode_policy_allocation_program(plan,policy)
        if (payload['programDigest']!=_canonical_digest(normalized) or payload['requestDigest']!=_digest(args)
          or payload['revisions']!=revisions or payload['expectedTargetStateToken']!=plan.expected_target_state_token):raise ValueError('STALE_OR_MISMATCHED_V2_PREVIEW')
        dependency=policy.get('publishedDependency')
        compiler=POLICY_V2_COMPILER if dependency else POLICY_COMPILER
        digest=POLICY_V2_PLAN_DIGEST if dependency else POLICY_PLAN_DIGEST
        return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,idempotency_key=idempotency_key,
          function_name=FUNCTION,normalized_program=normalized,compiler_version=compiler,plan_digest=digest,
          expected_metadata_revision=revisions['metadata_revision'],expected_data_revision=revisions['data_revision'],
          expected_policy_revision=revisions['policy_revision'],depends_on_job_ids=())
