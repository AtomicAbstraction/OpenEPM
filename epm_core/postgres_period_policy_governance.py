"""Independent period-NCI review, workspace approval and explicit activation.

These immutable policy events never authorize acquisition and never establish
operational basis eligibility. No period publisher is enabled by this module.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_period_nci import CORE_VERSION, FUNCTION as CANDIDATE, BASIS_KINDS
from .postgres_period_policy_cases import (DOMAIN,RECORD as CASE_RECORD,
    EVALUATE as CASE_EVALUATE,PostgresPeriodPolicyCases,compile_program as case_program,
    _evaluate as evaluate_cases)
from .postgres_policy_drafts import (_date,ELECTIONS_FUNCTION,
    _program as elections_program,validate_elections_in_transaction)
from .postgres_policy_source_values import (CapturedSourceValues,validate_locator,
    VERIFIER,PDF_VERIFIER,MAX_TOTAL_BYTES,MAX_DOCUMENT_BYTES,
    MAX_PDF_DOCUMENT_BYTES)

REVIEW='consolidation.policy.draft.period_nci.cases.review.record'
REVIEW_READ='consolidation.policy.draft.period_nci.cases.review.read'
APPROVE='consolidation.policy.period_nci.approval.record'
APPROVAL_READ='consolidation.policy.period_nci.approval.read'
ACTIVATE='consolidation.policy.period_nci.activate'
WITHDRAW='consolidation.policy.period_nci.withdraw'
ACTIVATION_READ='consolidation.policy.period_nci.activation.read'
CURRENT='consolidation.policy.period_nci.activation.current.read'
RESOLVE='consolidation.policy.period_nci.activation.resolve'
GOVERNANCE_VERSION='period-nci-governance-v1'
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_HASH=re.compile(r'[0-9a-f]{64}\Z')
_WRITES=frozenset((REVIEW,APPROVE,ACTIVATE,WITHDRAW))
_READS=frozenset((REVIEW_READ,APPROVAL_READ,ACTIVATION_READ,CURRENT,RESOLVE))
_REV={'expectedPolicyRevision','expectedCommitRevision'}
_EVIDENCE_KEYS=('policyDomain','candidateFunction','candidateCoreVersion','cases',
    'policyRevision','observedCommitRevision','metadataRevision','dataRevision')


def _key(value):return isinstance(value,str) and _KEY.fullmatch(value) is not None

def _hash(value):return isinstance(value,str) and _HASH.fullmatch(value) is not None

def _text(value,minimum=1,maximum=2000):
    return isinstance(value,str) and minimum<=len(value)<=maximum and value==value.strip() and '\x00' not in value


def compile_program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or not isinstance(raw['function'],str) or not isinstance(raw['arguments'],dict)):
        raise ValueError('PERIOD_GOVERNANCE_PROGRAM_INVALID')
    function,args=raw['function'],raw['arguments']
    shapes={REVIEW:_REV|{'bundleOperationId','expectedEvaluationDigest','basisKind','decision',
            'qualificationRef','sourceValueEvidence','rationale'},
        APPROVE:_REV|{'bundleOperationId','expectedReviewOperationId','expectedEvaluationDigest','basisKind',
            'sourceProvenanceConfirmed','reviewerQualificationConfirmed','accountingJudgmentConfirmed',
            'approvalEvidenceArtifactIds','rationale'},
        ACTIVATE:_REV|{'approvalId','expectedApprovalDigest','expectedPolicyBindingDigest','expectedActiveEventId',
            'effectiveFrom','effectiveBefore','reason'},
        WITHDRAW:_REV|{'variantKey','expectedActivationId','expectedActiveEventId','reason'},
        REVIEW_READ:{'operationId'},APPROVAL_READ:{'operationId'},ACTIVATION_READ:{'operationId'},
        CURRENT:{'variantKey'},RESOLVE:{'variantKey','effectiveOn','expectedPolicyRevision'}}
    if function not in shapes or set(args)!=shapes[function]:
        raise ValueError('PERIOD_GOVERNANCE_ARGUMENTS_INVALID')
    if any(type(args[key]) is not int or args[key]<0 for key in _REV if key in args):
        raise ValueError('PERIOD_GOVERNANCE_REVISION_INVALID')
    for field in ('bundleOperationId','expectedReviewOperationId','approvalId','expectedActivationId','operationId'):
        if field in args and not _key(args[field]):raise ValueError('PERIOD_GOVERNANCE_ID_INVALID')
    for field in ('expectedEvaluationDigest','expectedApprovalDigest','expectedPolicyBindingDigest','variantKey'):
        if field in args and not _hash(args[field]):raise ValueError('PERIOD_GOVERNANCE_DIGEST_INVALID')
    if 'expectedActiveEventId' in args and args['expectedActiveEventId']!='' and not _key(args['expectedActiveEventId']):
        raise ValueError('PERIOD_GOVERNANCE_ID_INVALID')
    if 'basisKind' in args and (not isinstance(args['basisKind'],str) or args['basisKind'] not in BASIS_KINDS):
        raise ValueError('PERIOD_GOVERNANCE_BASIS_UNSUPPORTED')
    for field in ('reason','rationale'):
        if field in args and not _text(args[field],10):raise ValueError('PERIOD_GOVERNANCE_REASON_INVALID')
    result=deepcopy(args)
    if function==REVIEW:
        if (args['decision'] not in ('Attest','Reject') or not _text(args['qualificationRef'],1,500)
                or not isinstance(args['sourceValueEvidence'],list) or len(args['sourceValueEvidence'])>40):
            raise ValueError('PERIOD_REVIEW_ARGUMENTS_INVALID')
        seen=set();evidence=[]
        for item in args['sourceValueEvidence']:
            if (not isinstance(item,dict) or set(item)!={'caseId','field','artifactId','valueLocator'}
                    or not _text(item['caseId'],1,100) or item['field'] not in ('basisAmount','ownershipPercent')
                    or not _key(item['artifactId']) or (item['caseId'],item['field']) in seen):
                raise ValueError('PERIOD_REVIEW_SOURCE_EVIDENCE_INVALID')
            evidence.append({**item,'valueLocator':validate_locator(item['valueLocator'])})
            seen.add((item['caseId'],item['field']))
        if args['decision']=='Attest' and not evidence:raise ValueError('PERIOD_REVIEW_SOURCE_EVIDENCE_REQUIRED')
        result['sourceValueEvidence']=sorted(evidence,key=lambda item:(item['caseId'],item['field']))
    if function==APPROVE:
        if (any(args[field] is not True for field in ('sourceProvenanceConfirmed','reviewerQualificationConfirmed','accountingJudgmentConfirmed'))
                or not isinstance(args['approvalEvidenceArtifactIds'],list)
                or not 1<=len(args['approvalEvidenceArtifactIds'])<=10
                or any(not _key(item) for item in args['approvalEvidenceArtifactIds'])
                or len(set(args['approvalEvidenceArtifactIds']))!=len(args['approvalEvidenceArtifactIds'])):
            raise ValueError('PERIOD_APPROVAL_ASSERTIONS_INVALID')
        result['approvalEvidenceArtifactIds']=sorted(args['approvalEvidenceArtifactIds'])
    if function==WITHDRAW and not _key(args['expectedActiveEventId']):
        raise ValueError('PERIOD_GOVERNANCE_ID_INVALID')
    if function==ACTIVATE and _date(args['effectiveFrom'])>=_date(args['effectiveBefore']):
        raise ValueError('PERIOD_ACTIVATION_DATE_RANGE_INVALID')
    if function==RESOLVE:_date(args['effectiveOn'])
    return function,result


def _load(db,scope,operation_id,functions):
    row=db.execute('''SELECT result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
        AND operation_id=%s AND result->>'policyDomain'=%s AND result->>'function'=ANY(%s::text[])''',
        (scope.workspace_id,scope.application_id,operation_id,DOMAIN,list(functions))).fetchone()
    if row is None:raise ValueError('PERIOD_POLICY_EVENT_UNAVAILABLE')
    return row['result']


def _latest(db,scope,function,bundle):
    row=db.execute('''SELECT result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
        AND result->>'policyDomain'='period_nci' AND result->>'function'=%s AND result->>'bundleOperationId'=%s
        ORDER BY committed_revision DESC LIMIT 1''',(scope.workspace_id,scope.application_id,function,bundle)).fetchone()
    return row['result'] if row else None


def _active(db,scope,key):
    row=db.execute('''SELECT result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
        AND result->>'policyDomain'='period_nci' AND result->>'variantKey'=%s
        AND result->>'function' IN ('consolidation.policy.period_nci.activate','consolidation.policy.period_nci.withdraw')
        ORDER BY committed_revision DESC LIMIT 1''',
        (scope.workspace_id,scope.application_id,key)).fetchone()
    return row['result'] if row else None


def _bundle(db,scope,bundle_id,digest):
    bundle=_load(db,scope,bundle_id,(CASE_RECORD,))
    evidence=bundle['evaluation']
    if (evidence['evaluationDigest']!=digest or _canonical_digest({key:evidence[key] for key in _EVIDENCE_KEYS})!=digest
            or evidence['candidateFunction']!=CANDIDATE or evidence['candidateCoreVersion']!=CORE_VERSION):
        raise ValueError('PERIOD_POLICY_BUNDLE_VERSION_OR_DIGEST_MISMATCH')
    return bundle


def _current_binding(db,scope,bundle,basis,state):
    observed=bundle['evaluation']
    if not observed['allMatched']:raise ValueError('PERIOD_POLICY_CASES_NOT_MATCHED')
    cases=[{key:deepcopy(item[key]) for key in ('caseId','candidate','expected','sourceRefs')} for item in observed['cases']]
    for item in cases:item['candidate']['arguments']['expectedPolicyRevision']=state['policy_revision']
    args=case_program({'languageVersion':2,'function':CASE_EVALUATE,'arguments':{
        'cases':cases,'expectedPolicyRevision':state['policy_revision']}},CASE_EVALUATE)
    evaluated=evaluate_cases(db,scope,args,state)
    if not evaluated['allMatched']:raise ValueError('PERIOD_POLICY_CASE_CONTEXT_STALE')
    for old,new in zip(observed['cases'],evaluated['cases']):
        if old['actual']!=new['actual'] or old['candidateContext']!=new['candidateContext']:
            raise ValueError('PERIOD_POLICY_CASE_CONTEXT_STALE')
    amounts=[item for item in evaluated['cases'] if item['actual']['outcome']=='Amounts']
    if not amounts or not any(NumericCell.from_wire(present=True,amount=item['candidate']['arguments']['basisAmount']).amount!=0 for item in amounts):
        raise ValueError('PERIOD_POLICY_AMOUNT_COVERAGE_REQUIRED')
    bindings=[]
    for item in amounts:
        context=item['candidateContext'];candidate=item['candidate']['arguments']
        if context['basisKind']!=basis:raise ValueError('PERIOD_POLICY_BASIS_BINDING_MISMATCH')
        bindings.append({'policyDomain':DOMAIN,'workspaceId':scope.workspace_id,'applicationId':scope.application_id,
            **{key:context[key] for key in ('policyId','policyVersion','policyFamily','draftDigest')},
            'candidateFunction':CANDIDATE,'candidateCoreVersion':CORE_VERSION,'governanceVersion':GOVERNANCE_VERSION,
            'selections':dict(sorted(candidate['selections'].items())),'basisKind':basis,'method':'Full',
            'signConvention':'signed_basis','rounding':'half_even_nci_owner_residual','presentation':'separate_attribution_split'})
    if any(binding!=bindings[0] for binding in bindings):raise ValueError('PERIOD_POLICY_MIXED_BINDING')
    return bindings[0],_canonical_digest([{'caseId':item['caseId'],'actual':item['actual'],
        'candidateContext':item['candidateContext']} for item in evaluated['cases']])


def _artifacts(db,scope,ids):
    ids=sorted(set(ids))
    if not ids or len(ids)>40:raise ValueError('PERIOD_POLICY_ARTIFACTS_REQUIRED')
    rows=db.execute('''SELECT artifact_id,source_ref,source_version,
        media_type,content_sha256,content_bytes,client_extraction_id,
        client_extraction_sha256,client_extraction_bytes
        FROM epm.policy_source_artifact WHERE workspace_id=%s AND application_id=%s AND artifact_id=ANY(%s::text[])''',
        (scope.workspace_id,scope.application_id,ids)).fetchall()
    if len(rows)!=len(ids):raise ValueError('PERIOD_POLICY_ARTIFACT_UNAVAILABLE')
    if (sum(row['content_bytes']+(row['client_extraction_bytes'] or 0)
            for row in rows)>MAX_TOTAL_BYTES or any(not 1<=row['content_bytes']<=
            (MAX_PDF_DOCUMENT_BYTES if row['media_type']=='application/pdf'
             else MAX_DOCUMENT_BYTES) for row in rows)):
        raise ValueError('PERIOD_POLICY_ARTIFACT_BUDGET_EXCEEDED')
    contents=db.execute('''SELECT artifact_id,media_type,
        CASE WHEN media_type='application/pdf'
             THEN client_extraction ELSE content END AS verification_content
        FROM epm.policy_source_artifact
        WHERE workspace_id=%s AND application_id=%s AND artifact_id=ANY(%s::text[])''',
        (scope.workspace_id,scope.application_id,ids)).fetchall()
    content={row['artifact_id']:(row['media_type'],
        None if row['verification_content'] is None
        else bytes(row['verification_content'])) for row in contents}
    result={}
    for row in rows:
        if row['media_type']=='application/pdf':
            data=content[row['artifact_id']][1]
            if (data is None or len(data)!=row['client_extraction_bytes']
                    or sha256(data).hexdigest()!=
                       row['client_extraction_sha256']):
                raise ValueError('POLICY_SOURCE_ARTIFACT_CORRUPT')
            result[row['artifact_id']]={**row,'client_extraction':data}
        else:
            data=content[row['artifact_id']][1]
            if len(data)!=row['content_bytes'] or sha256(data).hexdigest()!=row['content_sha256']:
                raise ValueError('POLICY_SOURCE_ARTIFACT_CORRUPT')
            result[row['artifact_id']]={**row,'content':data}
    return result


def _source_proof(db,scope,bundle,raw):
    amounts={item['caseId']:item for item in bundle['evaluation']['cases'] if item['actual']['outcome']=='Amounts'}
    needed={(case,field) for case in amounts for field in ('basisAmount','ownershipPercent')}
    if {(item['caseId'],item['field']) for item in raw}!=needed:
        raise ValueError('PERIOD_REVIEW_SOURCE_COVERAGE_INCOMPLETE')
    ids=[item['artifactId'] for item in raw]
    artifacts=_artifacts(db,scope,ids)
    checker=CapturedSourceValues();proof=[]
    for item in raw:
        case=amounts[item['caseId']];artifact=artifacts[item['artifactId']]
        if artifact['source_ref'] not in case['sourceRefs']:raise ValueError('PERIOD_REVIEW_SOURCE_REFERENCE_MISMATCH')
        expected=case['candidate']['arguments'][item['field']]
        verified=checker.verify(artifact,item['valueLocator'],expected)
        proof.append({**item,'verifiedValue':verified,'documentSha256':artifact['content_sha256'],
            'sourceRef':artifact['source_ref'],'sourceVersion':artifact['source_version'],
            'verifierVersion':PDF_VERIFIER if item['valueLocator']['kind']=='ClientPdfTextSpan' else VERIFIER,
            'extractionTrust':'ClientSuppliedHumanAttested' if item['valueLocator']['kind']=='ClientPdfTextSpan' else 'ServerVerifiedStructuredSource'})
    return sorted(proof,key=lambda item:(item['caseId'],item['field']))


def _verify_approval(approval):
    if (_canonical_digest(approval['manifest'])!=approval['approvalDigest']
            or _canonical_digest(approval['policyBinding'])!=approval['policyBindingDigest']
            or approval['manifest']['policyBinding']!=approval['policyBinding']):
        raise ValueError('PERIOD_POLICY_APPROVAL_CORRUPT')
    binding=approval['policyBinding']
    if binding['candidateFunction']!=CANDIDATE or binding['candidateCoreVersion']!=CORE_VERSION or binding['governanceVersion']!=GOVERNANCE_VERSION:
        raise ValueError('PERIOD_POLICY_VERSION_MISMATCH')


def _variant(scope,binding):
    return _canonical_digest({'policyDomain':DOMAIN,'scope':[scope.workspace_id,scope.application_id],'policyBinding':binding})


class PostgresPeriodPolicyGovernance:
    def __init__(self,dsn,*,identity):
        self.cases=PostgresPeriodPolicyCases(dsn,identity=identity)
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def catalog():
        writes={REVIEW:('admin','immutable independent review; captured numeric values are not source authenticity',
                {'bundleOperationId':'period bundle ID','expectedEvaluationDigest':'exact SHA256','basisKind':'period_profit_ytd or net_assets_at_period_end',
                 'decision':'Attest or Reject','qualificationRef':'explicit unverified professional qualification reference',
                 'sourceValueEvidence':'complete case/field/artifactId/valueLocator map for matching Amounts cases when Attest',
                 'rationale':'10–2000 characters'}),
            APPROVE:('workspace_admin','basis-specific workspace policy approval, pending activation; no operational posting',
                {'bundleOperationId':'period bundle ID','expectedReviewOperationId':'exact independent review ID',
                 'expectedEvaluationDigest':'exact SHA256','basisKind':'exact reviewed basis',
                 'sourceProvenanceConfirmed':'literal true','reviewerQualificationConfirmed':'literal true','accountingJudgmentConfirmed':'literal true',
                 'approvalEvidenceArtifactIds':'1–10 captured evidence IDs','rationale':'10–2000 characters'}),
            ACTIVATE:('workspace_admin','explicit effective-dated policy-variant event; no operational posting',
                {'approvalId':'period approval ID','expectedApprovalDigest':'exact SHA256','expectedPolicyBindingDigest':'exact SHA256',
                 'expectedActiveEventId':'current event ID or empty string','effectiveFrom':'ISO date','effectiveBefore':'exclusive ISO date','reason':'10–2000 characters'}),
            WITHDRAW:('workspace_admin','withdraw exactly the current activation without deleting history',
                {'variantKey':'exact scoped variant SHA256','expectedActivationId':'current activation ID',
                 'expectedActiveEventId':'exact current event ID','reason':'10–2000 characters'})}
        result={name:{'mode':'atomic_write','permission':permission,'arguments':{**arguments,
                'expectedPolicyRevision':'current nonnegative integer','expectedCommitRevision':'current nonnegative integer'},
                'result':description,'previewRequired':False,'idempotencyRequired':True,'workClass':'short'}
            for name,(permission,description,arguments) in writes.items()}
        for name in (REVIEW_READ,APPROVAL_READ,ACTIVATION_READ,CURRENT,RESOLVE):
            args=({'variantKey':'scoped SHA256'} if name in (CURRENT,RESOLVE) else {'operationId':'immutable period event ID'})
            if name==RESOLVE:args={**args,'effectiveOn':'ISO date','expectedPolicyRevision':'current nonnegative integer'}
            entry={'mode':'read_only','permission':'read','arguments':args,
                'result':('scoped period policy evidence or current variant; '
                    'this governance read creates no posting, while an active '
                    'compatible variant may be consumed separately by '
                    'consolidation.nci.period.publish'),
                'previewRequired':False,'idempotencyRequired':False,'workClass':'short'}
            if name in (CURRENT,RESOLVE):entry['operationalPublication']={
                    'function':'consolidation.nci.period.publish',
                    'boundary':'separate previewed durable publication requires an active compatible period-policy variant, saved basis definition and current operational source pins'}
            result[name]=entry
        return result

    def execute(self,scope,program,*,idempotency_key):
        if not isinstance(scope,ApplicationScope):raise ValueError('Application scope required')
        function,args=compile_program(program)
        if function not in _WRITES:raise ValueError('PERIOD_GOVERNANCE_WRITE_REQUIRED')
        if not _key(idempotency_key):raise ValueError('PERIOD_GOVERNANCE_IDEMPOTENCY_KEY_INVALID')
        digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':{'languageVersion':2,'function':function,'arguments':args}})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self.cases._open(db,scope,function,'admin' if function==REVIEW else 'workspace_admin',write=True)
                old=db.execute('''SELECT command_digest,result FROM epm.operation_receipt
                    WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if old:
                    if old['command_digest']!=digest:raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return old['result']
                if state['processing_mode']!='Active' or state['application_status']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['policy_revision']!=args['expectedPolicyRevision'] or state['commit_revision']!=args['expectedCommitRevision']:
                    raise ValueError('STALE_PERIOD_GOVERNANCE_REVISION')
                actor={'issuer':self.identity.issuer,'subjectId':self.identity.subject_id}
                if function==REVIEW:payload=self._review(db,scope,args,state,actor)
                elif function==APPROVE:payload=self._approve(db,scope,args,state,actor)
                elif function==ACTIVATE:payload=self._activate(db,scope,args,state)
                else:payload=self._withdraw(db,scope,args)
                result={'function':function,'policyDomain':DOMAIN,'operationId':idempotency_key,'actor':actor,
                    **payload,'policyRevision':state['policy_revision']+1,'committedRevision':state['commit_revision']+1,
                    'operationalPublicationSupported':False,'publicationSupported':False}
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (result['policyRevision'],result['committedRevision'],scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,idempotency_key,digest,
                    _canonical_digest(actor),result['committedRevision'],Jsonb(result)))
                return result

    def _review(self,db,scope,args,state,actor):
        bundle=_bundle(db,scope,args['bundleOperationId'],args['expectedEvaluationDigest'])
        if bundle['sourceActor']==actor:raise ValueError('PERIOD_POLICY_SELF_REVIEW_FORBIDDEN')
        if _latest(db,scope,REVIEW,args['bundleOperationId']):raise ValueError('PERIOD_POLICY_ALREADY_REVIEWED')
        binding=None;context=None;proof=[]
        if args['decision']=='Attest':
            binding,context=_current_binding(db,scope,bundle,args['basisKind'],state)
            proof=_source_proof(db,scope,bundle,args['sourceValueEvidence'])
        return {'bundleOperationId':args['bundleOperationId'],'evaluationDigest':args['expectedEvaluationDigest'],
            'decision':args['decision'],'basisKind':args['basisKind'],'policyBinding':binding,
            'policyBindingDigest':_canonical_digest(binding) if binding else None,'caseContextDigest':context,
            'sourceValueEvidence':proof,'declaredSourceValueEvidence':args['sourceValueEvidence'],
            'sourceValuesVerifiedFromCapturedBytes':args['decision']=='Attest',
            'qualificationRef':args['qualificationRef'],'machineVerifiedProfessionalQualification':False,
            'sourceAuthenticityVerified':False,'rationale':args['rationale'],
            'status':'ReviewerAttestedPendingApproval' if args['decision']=='Attest' else 'RejectedTechnicalEvidence'}

    def _approve(self,db,scope,args,state,actor):
        bundle=_bundle(db,scope,args['bundleOperationId'],args['expectedEvaluationDigest'])
        review=_load(db,scope,args['expectedReviewOperationId'],(REVIEW,))
        if (review['bundleOperationId']!=args['bundleOperationId'] or review['evaluationDigest']!=args['expectedEvaluationDigest']
                or review['decision']!='Attest' or not review['sourceValuesVerifiedFromCapturedBytes']):
            raise ValueError('PERIOD_POLICY_REVIEW_NOT_ATTESTED')
        if actor in (bundle['sourceActor'],review['actor']):raise ValueError('PERIOD_POLICY_DISTINCT_APPROVER_REQUIRED')
        if _latest(db,scope,APPROVE,args['bundleOperationId']):raise ValueError('PERIOD_POLICY_ALREADY_APPROVED')
        binding,context=_current_binding(db,scope,bundle,args['basisKind'],state)
        if binding!=review['policyBinding'] or context!=review['caseContextDigest']:
            raise ValueError('PERIOD_POLICY_REVIEW_CONTEXT_STALE')
        # Recheck immutable bytes and locators, not only caller attestations.
        raw=[{key:item[key] for key in ('caseId','field','artifactId','valueLocator')} for item in review['sourceValueEvidence']]
        if _source_proof(db,scope,bundle,raw)!=review['sourceValueEvidence']:raise ValueError('PERIOD_POLICY_REVIEW_EVIDENCE_CHANGED')
        artifacts=_artifacts(db,scope,args['approvalEvidenceArtifactIds'])
        manifest={'policyDomain':DOMAIN,'bundleOperationId':args['bundleOperationId'],
            'evaluationDigest':args['expectedEvaluationDigest'],'reviewOperationId':args['expectedReviewOperationId'],
            'policyBinding':binding,'caseContextDigest':context,'sourceActor':bundle['sourceActor'],'reviewer':review['actor'],
            'approver':actor,'reviewerQualificationRef':review['qualificationRef'],
            'sourceValueEvidence':review['sourceValueEvidence'],
            'approvalEvidenceArtifacts':[{key:item[key] for key in ('artifact_id','source_ref','source_version','media_type','content_sha256','content_bytes')}
                for _,item in sorted(artifacts.items())],
            'sourceProvenanceConfirmed':True,'reviewerQualificationConfirmed':True,'accountingJudgmentConfirmed':True,'rationale':args['rationale']}
        return {'bundleOperationId':args['bundleOperationId'],'reviewOperationId':args['expectedReviewOperationId'],
            'policyBinding':binding,'policyBindingDigest':_canonical_digest(binding),'variantKey':_variant(scope,binding),
            'approvalDigest':_canonical_digest(manifest),'manifest':manifest,
            'status':'WorkspaceApprovedPendingActivation','machineVerifiedProfessionalQualification':False,'sourceAuthenticityVerified':False}

    def _activate(self,db,scope,args,state):
        approval=_load(db,scope,args['approvalId'],(APPROVE,));_verify_approval(approval)
        if approval['approvalDigest']!=args['expectedApprovalDigest'] or approval['policyBindingDigest']!=args['expectedPolicyBindingDigest']:
            raise ValueError('PERIOD_POLICY_APPROVAL_BINDING_MISMATCH')
        binding=approval['policyBinding']
        bundle=_load(db,scope,approval['bundleOperationId'],(CASE_RECORD,))
        current,context=_current_binding(db,scope,bundle,binding['basisKind'],state)
        if current!=binding or context!=approval['manifest']['caseContextDigest']:
            raise ValueError('PERIOD_POLICY_APPROVAL_CONTEXT_STALE')
        draft=db.execute('''SELECT effective_from,effective_before FROM epm.policy_pack_draft WHERE workspace_id=%s
            AND application_id=%s AND policy_id=%s AND version=%s''',
            (scope.workspace_id,scope.application_id,binding['policyId'],binding['policyVersion'])).fetchone()
        if draft is None or not draft['effective_from']<=_date(args['effectiveFrom'])<_date(args['effectiveBefore'])<=draft['effective_before']:
            raise ValueError('PERIOD_POLICY_ACTIVATION_OUTSIDE_DRAFT')
        key=_variant(scope,binding);active=_active(db,scope,key)
        if (active['operationId'] if active else '')!=args['expectedActiveEventId']:
            raise ValueError('PERIOD_POLICY_ACTIVE_EVENT_CHANGED')
        return {'bundleOperationId':approval['bundleOperationId'],'approvalId':args['approvalId'],
            'approvalDigest':approval['approvalDigest'],'policyBinding':binding,'policyBindingDigest':approval['policyBindingDigest'],
            'variantKey':key,'effectiveFrom':args['effectiveFrom'],'effectiveBefore':args['effectiveBefore'],
            'previousEventId':args['expectedActiveEventId'],'reason':args['reason'],'status':'Active'}

    @staticmethod
    def _withdraw(db,scope,args):
        active=_active(db,scope,args['variantKey'])
        if (not active or active['function']!=ACTIVATE or active['operationId']!=args['expectedActivationId']
                or active['operationId']!=args['expectedActiveEventId']):
            raise ValueError('PERIOD_POLICY_ACTIVE_EVENT_CHANGED')
        return {'variantKey':args['variantKey'],'activationId':active['operationId'],'policyBinding':active['policyBinding'],
            'previousEventId':active['operationId'],'reason':args['reason'],'status':'Withdrawn'}

    def read(self,scope,program):
        function,args=compile_program(program)
        if function not in _READS:raise ValueError('PERIOD_GOVERNANCE_READ_REQUIRED')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self.cases._open(db,scope,function,'read')
                kinds={REVIEW_READ:(REVIEW,),APPROVAL_READ:(APPROVE,),ACTIVATION_READ:(ACTIVATE,WITHDRAW)}
                if function in kinds:return _load(db,scope,args['operationId'],kinds[function])
                active=_active(db,scope,args['variantKey'])
                if function==CURRENT:return {'defined':active is not None,'event':active,'policyRevision':state['policy_revision'],
                    'commitRevision':state['commit_revision'],'capabilityEnabled':'financial_consolidation' in state['enabled_capabilities'],
                    'capabilityRevision':state['capability_revision'],'operationalPublicationSupported':False}
                return self.resolve_in_transaction(db,scope,args,state)

    @staticmethod
    def resolve_in_transaction(db,scope,args,state):
        # Internal callers already hold workspace/current-grant/state locks.
        _,args=compile_program({'languageVersion':2,'function':RESOLVE,'arguments':args})
        active=_active(db,scope,args['variantKey'])
        if state['policy_revision']!=args['expectedPolicyRevision']:raise ValueError('STALE_PERIOD_GOVERNANCE_REVISION')
        if not active or active['function']!=ACTIVATE:raise ValueError('PERIOD_POLICY_VARIANT_NOT_ACTIVE')
        binding=active['policyBinding']
        if _variant(scope,binding)!=args['variantKey'] or binding['candidateCoreVersion']!=CORE_VERSION or binding['governanceVersion']!=GOVERNANCE_VERSION:
            raise ValueError('PERIOD_POLICY_VERSION_MISMATCH')
        if not _date(active['effectiveFrom'])<=_date(args['effectiveOn'])<_date(active['effectiveBefore']):
            raise ValueError('PERIOD_POLICY_EFFECTIVE_DATE_MISMATCH')
        query=elections_program({'languageVersion':2,'function':ELECTIONS_FUNCTION,'arguments':{
            'policyId':binding['policyId'],'effectiveOn':args['effectiveOn'],'selections':binding['selections'],
            'expectedPolicyRevision':state['policy_revision']}},ELECTIONS_FUNCTION)
        draft=validate_elections_in_transaction(db,scope,query,state)
        if draft['version']!=binding['policyVersion'] or draft['draftDigest']!=binding['draftDigest']:
            raise ValueError('PERIOD_POLICY_ACTIVE_DRAFT_MISMATCH')
        approval=_load(db,scope,active['approvalId'],(APPROVE,));_verify_approval(approval)
        if approval['approvalDigest']!=active['approvalDigest'] or approval['policyBinding']!=binding:
            raise ValueError('PERIOD_POLICY_ACTIVE_APPROVAL_MISMATCH')
        return {'status':'Active','activationId':active['operationId'],'variantKey':args['variantKey'],
            'policyBinding':binding,'policyBindingDigest':active['policyBindingDigest'],
            'policyRevision':state['policy_revision'],'operationalPublicationSupported':False,'publicationSupported':False}
