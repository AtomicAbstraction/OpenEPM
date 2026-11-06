"""Domain-separated technical period-NCI evidence, never approval or posting.

Immutable scoped receipts hold bounded case bundles. Acquisition bundle tables,
allowlists, digests and approval/activation workflows are deliberately unchanged.
"""
from __future__ import annotations

from decimal import Decimal
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_period_nci import (FUNCTION as CANDIDATE, CORE_VERSION,
    parse_program, evaluate_in_transaction)

DOMAIN='period_nci'
EVALUATE='consolidation.policy.draft.period_nci.cases.evaluate'
RECORD='consolidation.policy.draft.period_nci.cases.record'
READ='consolidation.policy.draft.period_nci.cases.read'
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_CASE=re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_FIELDS=('candidateNciShare','candidateControllingShare')
_REJECTIONS=frozenset(('PERIOD_NCI_SCOPE_UNSUPPORTED','PERIOD_NCI_OWNERSHIP_RANGE_INVALID',
    'PERIOD_NCI_POLICY_FAMILY_UNSUPPORTED','PERIOD_NCI_ELECTION_REQUIRED',
    'PERIOD_NCI_AMBIGUOUS_PLACEMENT','PERIOD_NCI_PERIOD_END_REQUIRED',
    'PERIOD_NCI_CALENDAR_GAP','PERIOD_NCI_PERIOD_LIMIT','PERIOD_NCI_POLICY_PERIOD_COVERAGE',
    'PERIOD_NCI_POWN_UNAVAILABLE','PERIOD_NCI_OWNERSHIP_CHANGED','PERIOD_NCI_METHOD_UNSUPPORTED'))


def _expected(raw):
    if not isinstance(raw,dict):raise ValueError('PERIOD_CASE_EXPECTATION_INVALID')
    if raw.get('outcome')=='Rejected':
        if set(raw)!={'outcome','errorCode'} or not isinstance(raw['errorCode'],str) or raw['errorCode'] not in _REJECTIONS:
            raise ValueError('PERIOD_CASE_EXPECTATION_INVALID')
        return dict(raw)
    if raw.get('outcome')!='Amounts' or set(raw)!={'outcome',*_FIELDS}:
        raise ValueError('PERIOD_CASE_EXPECTATION_INVALID')
    values={}
    for key in _FIELDS:
        try:
            value=NumericCell.from_wire(present=True,amount=raw[key]).amount
        except (ValueError,ArithmeticError) as error:
            raise ValueError('PERIOD_CASE_EXPECTATION_INVALID') from error
        values[key]=format(Decimal(0) if value==0 else value,'.8f')
    return {'outcome':'Amounts',**values}


def compile_program(program,function):
    if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion']!=2
            or program['function']!=function or not isinstance(program['arguments'],dict)):
        raise ValueError('PERIOD_CASE_PROGRAM_INVALID')
    args=program['arguments']
    if function==READ:
        if set(args)!={'operationId'} or not isinstance(args['operationId'],str) or not _KEY.fullmatch(args['operationId']):
            raise ValueError('PERIOD_CASE_ARGUMENTS_INVALID')
        return dict(args)
    fields={'cases','expectedPolicyRevision'} | ({'expectedCommitRevision'} if function==RECORD else set())
    if (function not in (EVALUATE,RECORD) or set(args)!=fields
            or type(args['expectedPolicyRevision']) is not int or args['expectedPolicyRevision']<0
            or function==RECORD and (type(args['expectedCommitRevision']) is not int or args['expectedCommitRevision']<0)
            or not isinstance(args['cases'],list) or not 1<=len(args['cases'])<=20):
        raise ValueError('PERIOD_CASE_ARGUMENTS_INVALID')
    cases=[];seen=set()
    for item in args['cases']:
        if (not isinstance(item,dict) or set(item)!={'caseId','candidate','expected','sourceRefs'}
                or not isinstance(item['caseId'],str) or not _CASE.fullmatch(item['caseId']) or item['caseId'] in seen
                or not isinstance(item['sourceRefs'],list) or not 1<=len(item['sourceRefs'])<=10
                or any(not isinstance(ref,str) or not 1<=len(ref)<=1000 or ref!=ref.strip() or '\x00' in ref for ref in item['sourceRefs'])
                or len(set(item['sourceRefs']))!=len(item['sourceRefs'])):
            raise ValueError('PERIOD_CASE_ITEM_INVALID')
        candidate=item['candidate']
        if (not isinstance(candidate,dict) or set(candidate)!={'languageVersion','function','arguments'}
                or type(candidate['languageVersion']) is not int or candidate['languageVersion']!=2
                or candidate['function']!=CANDIDATE or not isinstance(candidate['arguments'],dict)
                or type(candidate['arguments'].get('expectedPolicyRevision')) is not int
                or candidate['arguments']['expectedPolicyRevision']!=args['expectedPolicyRevision']):
            raise ValueError('PERIOD_CASE_CANDIDATE_DOMAIN_OR_REVISION_INVALID')
        try:
            candidate=json.loads(json.dumps(candidate,ensure_ascii=False,allow_nan=False))
        except (TypeError,ValueError,RecursionError) as error:
            raise ValueError('PERIOD_CASE_CANDIDATE_INVALID') from error
        expected=_expected(item['expected'])
        # Strict core parsing still happens per case; only declared bounded
        # financial rejections can count as negative technical cases.
        cases.append({'caseId':item['caseId'],'candidate':candidate,'expected':expected,'sourceRefs':list(item['sourceRefs'])})
        seen.add(item['caseId'])
    return {**args,'cases':cases}


def _evaluate(db,scope,args,state):
    if state['policy_revision']!=args['expectedPolicyRevision']:
        raise ValueError('STALE_PERIOD_CASE_POLICY_REVISION')
    results=[]
    for item in args['cases']:
        try:
            candidate,policy=parse_program(item['candidate'])
            result=evaluate_in_transaction(db,scope,candidate,policy,state)
            actual={'outcome':'Amounts',**{key:result[key] for key in _FIELDS}}
            context={key:result[key] for key in ('policyId','policyVersion','policyFamily','draftDigest',
                'selectionDigest','basisKind','basisEligibility','relationshipId','parentEntityId','childEntityId','periodSources')}
        except ValueError as error:
            if str(error) not in _REJECTIONS:raise
            actual={'outcome':'Rejected','errorCode':str(error)};context=None
        results.append({**item,'actual':actual,'matched':actual==item['expected'],
            'candidateCoreVersion':CORE_VERSION,'candidateContext':context,
            'sourceReferenceCoverage':'CallerReferencesUnverified'})
    evidence={'policyDomain':DOMAIN,'candidateFunction':CANDIDATE,'candidateCoreVersion':CORE_VERSION,
        'cases':results,'policyRevision':state['policy_revision'],'observedCommitRevision':state['commit_revision'],
        'metadataRevision':state['metadata_revision'],'dataRevision':state['data_revision']}
    return {**evidence,'evaluationDigest':_canonical_digest(evidence),'caseCount':len(results),
        'allMatched':all(item['matched'] for item in results),'reviewStatus':'TechnicalUnreviewed',
        'operationalBasisVerified':False,'accountingApprovalSupported':False,'publicationSupported':False}


class PostgresPeriodPolicyCases:
    def __init__(self,dsn,*,identity):
        if not isinstance(dsn,str) or not dsn:raise ValueError('Runtime DSN required')
        if not isinstance(identity,VerifiedIdentity):raise ValueError('Verified identity required')
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def catalog():
        common={'cases':'1–20 distinct period-NCI candidates with exact expected signed shares or supported rejection and unverified sourceRefs',
            'expectedPolicyRevision':'current coherent nonnegative policy revision'}
        return {EVALUATE:{'mode':'read_only','permission':'read','arguments':common,
                'result':'domain-separated technical comparison; no review, source eligibility, approval or publication authority',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'},
            RECORD:{'mode':'atomic_write','permission':'admin','arguments':{**common,'expectedCommitRevision':'current commit revision'},
                'result':'immutable domain-tagged technical case receipt, not an acquisition bundle or accounting approval',
                'previewRequired':False,'idempotencyRequired':True,'workClass':'short'},
            READ:{'mode':'read_only','permission':'read','arguments':{'operationId':'period-case record operation ID'},
                'result':'immutable period-NCI technical evidence, including historical read while disabled',
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'}}

    def _open(self,db,scope,function,permission,*,write=False):
        if not isinstance(scope,ApplicationScope):raise ValueError('Application scope required')
        configure_statement_timeout(db, 10000)
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,permission)
        # Take the intended state lock once; never upgrade a shared capability
        # lock to an exclusive writer lock across concurrent recorders.
        state=db.execute('''SELECT s.metadata_revision,s.data_revision,s.policy_revision,s.commit_revision,
            s.processing_mode,s.enabled_capabilities,s.capability_revision,a.status AS application_status FROM epm.application_state s JOIN epm.application a
            USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s '''+
            ('FOR UPDATE OF s' if write else 'FOR SHARE OF s'),(scope.workspace_id,scope.application_id)).fetchone()
        if state is None:raise ValueError('APPLICATION_UNAVAILABLE')
        PostgresAccessChecker.require_capability_in_transaction(db,scope,function)
        return state

    def evaluate(self,scope,program):
        args=compile_program(program,EVALUATE)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self._open(db,scope,EVALUATE,'read')
                return _evaluate(db,scope,args,state)

    def record(self,scope,program,*,idempotency_key):
        if not isinstance(scope,ApplicationScope):raise ValueError('Application scope required')
        args=compile_program(program,RECORD)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('PERIOD_CASE_IDEMPOTENCY_KEY_INVALID')
        digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':{'languageVersion':2,'function':RECORD,'arguments':args}})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self._open(db,scope,RECORD,'admin',write=True)
                old=db.execute('''SELECT command_digest,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if old:
                    if old['command_digest']!=digest:raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return old['result']
                if state['processing_mode']!='Active' or state['application_status']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['commit_revision']!=args['expectedCommitRevision']:
                    raise ValueError('STALE_PERIOD_CASE_COMMIT_REVISION')
                evaluation=_evaluate(db,scope,args,state)
                result={'function':RECORD,'policyDomain':DOMAIN,'operationId':idempotency_key,
                    'evaluation':evaluation,'policyRevision':state['policy_revision']+1,
                    'committedRevision':state['commit_revision']+1,
                    'sourceActor':{'issuer':self.identity.issuer,'subjectId':self.identity.subject_id},
                    'reviewStatus':'TechnicalUnreviewed','accountingApprovalSupported':False,'publicationSupported':False}
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (result['policyRevision'],result['committedRevision'],scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,idempotency_key,digest,
                    _canonical_digest(result['sourceActor']),result['committedRevision'],Jsonb(result)))
                return result

    def read(self,scope,program):
        args=compile_program(program,READ)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                self._open(db,scope,READ,'read')
                row=db.execute('''SELECT result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s AND result->>'function'=%s AND result->>'policyDomain'=%s''',
                    (scope.workspace_id,scope.application_id,args['operationId'],RECORD,DOMAIN)).fetchone()
                if row is None:raise ValueError('PERIOD_CASE_BUNDLE_UNAVAILABLE')
                return row['result']
