"""Workspace-governed approval of exact reviewed acquisition evidence.

Approval records accountable human assertions; it is not machine verification
of professional credentials, and it does not itself activate accounting.
"""
from __future__ import annotations

import re
import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


APPROVE = 'consolidation.policy.acquisition.approval.record'
READ = 'consolidation.policy.acquisition.approval.read'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')


def _program(raw, function):
    if (not isinstance(raw,dict)
            or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion']!=2 or raw['function']!=function
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('POLICY_APPROVAL_PROGRAM_INVALID')
    args=raw['arguments']
    if function==READ:
        if (set(args)!={'approvalId'} or not isinstance(args['approvalId'],str)
                or not _KEY.fullmatch(args['approvalId'])):
            raise ValueError('POLICY_APPROVAL_ARGUMENTS_INVALID')
        return args
    expected={'bundleOperationId','expectedReviewOperationId',
        'expectedEvaluationDigest','expectedPolicyRevision',
        'expectedCommitRevision','sourceProvenanceConfirmed',
        'reviewerQualificationConfirmed','accountingJudgmentConfirmed',
        'approvalEvidenceArtifactIds','rationale'}
    if (function!=APPROVE or set(args)!=expected
            or any(not isinstance(args[key],str) or not _KEY.fullmatch(args[key])
                   for key in ('bundleOperationId','expectedReviewOperationId'))
            or not isinstance(args['expectedEvaluationDigest'],str)
            or not _HASH.fullmatch(args['expectedEvaluationDigest'])
            or any(type(args[key]) is not int or args[key]<0 for key in
                   ('expectedPolicyRevision','expectedCommitRevision'))
            or any(args[key] is not True for key in
                   ('sourceProvenanceConfirmed','reviewerQualificationConfirmed',
                    'accountingJudgmentConfirmed'))
            or not isinstance(args['approvalEvidenceArtifactIds'],list)
            or not 1<=len(args['approvalEvidenceArtifactIds'])<=10
            or any(not isinstance(key,str) or not _KEY.fullmatch(key)
                   for key in args['approvalEvidenceArtifactIds'])
            or len(set(args['approvalEvidenceArtifactIds']))!=
                len(args['approvalEvidenceArtifactIds'])
            or not isinstance(args['rationale'],str)
            or not 10<=len(args['rationale'].strip())<=2000):
        raise ValueError('POLICY_APPROVAL_ARGUMENTS_INVALID')
    return args


class PostgresPolicyApprovals:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def approve(self,scope: ApplicationScope,program: object,*,
                idempotency_key: str) -> dict:
        if not isinstance(scope,ApplicationScope):
            raise ValueError('Application scope is required')
        args=_program(program,APPROVE)
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('POLICY_APPROVAL_IDEMPOTENCY_KEY_INVALID')
        keys=(scope.workspace_id,scope.application_id)
        digest=_canonical_digest({'scope':list(keys),'program':program,
            'identity':[self.identity.issuer,self.identity.subject_id]})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT policy_revision,commit_revision,
                    processing_mode FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'workspace_admin', function=APPROVE)
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest']!=digest or prior['actor_id']!=self.identity.subject_id:
                        raise ValueError('POLICY_APPROVAL_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['policy_revision']!=args['expectedPolicyRevision']
                        or state['commit_revision']!=args['expectedCommitRevision']):
                    raise ValueError('STALE_POLICY_APPROVAL_REVISION')
                row=db.execute('''SELECT b.evaluation_digest,b.cases,
                    b.source_actor_issuer,b.source_actor_subject,
                    r.review_operation_id,r.decision,r.qualification_ref,
                    r.review_evidence_refs,r.reviewer_issuer,r.reviewer_subject,
                    r.policy_revision,r.committed_revision,
                    r.evaluation_digest AS review_digest
                    FROM epm.policy_acquisition_case_bundle b
                    JOIN epm.policy_acquisition_case_review r
                    ON r.workspace_id=b.workspace_id
                    AND r.application_id=b.application_id
                    AND r.bundle_operation_id=b.operation_id
                    WHERE b.workspace_id=%s AND b.application_id=%s
                    AND b.operation_id=%s''',
                    (*keys,args['bundleOperationId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_APPROVAL_REVIEW_UNAVAILABLE')
                if (row['evaluation_digest']!=args['expectedEvaluationDigest']
                        or row['review_digest']!=row['evaluation_digest']
                        or row['review_operation_id']!=args['expectedReviewOperationId']
                        or row['policy_revision']!=state['policy_revision']
                        or row['committed_revision']!=state['commit_revision']):
                    raise ValueError('POLICY_APPROVAL_REVIEW_STALE')
                actor=(self.identity.issuer,self.identity.subject_id)
                author=(row['source_actor_issuer'],row['source_actor_subject'])
                reviewer=(row['reviewer_issuer'],row['reviewer_subject'])
                if actor in (author,reviewer) or author==reviewer:
                    raise ValueError('POLICY_APPROVAL_IDENTITY_SEPARATION_REQUIRED')
                if row['decision']!='Attest':
                    raise ValueError('POLICY_APPROVAL_REVIEW_NOT_ATTESTED')
                amounts=[item for item in row['cases']
                         if item['expected']['outcome']=='Amounts']
                if (not amounts or any(not item['matched']
                        or item.get('sourceValueCoverage')!='ExactInputsBound'
                        or item.get('capturedContentCoverage')!='ExactCapturedBytes'
                        or item.get('sourceLocatorCoverage')!='AllValuesVerified'
                        or not item.get('policyBinding',{}).get('candidateFunction')
                        or not item.get('policyBinding',{}).get('candidateCoreVersion')
                        for item in amounts)
                        or any(ref.startswith('synthetic:') for item in
                               row['cases'] for ref in item['sourceRefs'])
                        or row['qualification_ref'].startswith('synthetic:')
                        or any(ref.startswith('synthetic:')
                               for ref in row['review_evidence_refs'])):
                    raise ValueError('POLICY_APPROVAL_EVIDENCE_INCOMPLETE')
                artifact_ids=sorted(set(args['approvalEvidenceArtifactIds']))
                artifacts=db.execute('''SELECT artifact_id,source_ref,
                    source_version,content_sha256 FROM epm.policy_source_artifact
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=ANY(%s) ORDER BY artifact_id''',
                    (*keys,artifact_ids)).fetchall()
                if (len(artifacts)!=len(artifact_ids)
                        or any(item['source_ref'].startswith('synthetic:')
                               for item in artifacts)):
                    raise ValueError('POLICY_APPROVAL_SUPPORT_UNAVAILABLE')
                bindings={_canonical_digest(item['policyBinding']):
                          item['policyBinding'] for item in amounts}
                manifest={'workspaceId':scope.workspace_id,
                    'applicationId':scope.application_id,
                    'approver':list(actor),
                    'bundleOperationId':args['bundleOperationId'],
                    'evaluationDigest':row['evaluation_digest'],
                    'reviewOperationId':row['review_operation_id'],
                    'policyBindings':[bindings[key] for key in sorted(bindings)],
                    'sourceActor':list(author),'reviewer':list(reviewer),
                    'reviewerQualificationRef':row['qualification_ref'],
                    'reviewEvidenceRefs':row['review_evidence_refs'],
                    'approvalEvidenceArtifacts':[dict(item) for item in artifacts],
                    'sourceProvenanceConfirmed':True,
                    'reviewerQualificationConfirmed':True,
                    'accountingJudgmentConfirmed':True,
                    'rationale':args['rationale']}
                approval_digest=_canonical_digest(manifest)
                revision=state['commit_revision']+1
                policy_revision=state['policy_revision']+1
                result={'approvalId':idempotency_key,
                    'approvalDigest':approval_digest,'manifest':manifest,
                    'policyBindingDigests':sorted(bindings),
                    'status':'WorkspaceApprovedPendingActivation',
                    'policyRevision':policy_revision,'committedRevision':revision,
                    'qualificationAssessment':'WorkspaceAdministratorConfirmed',
                    'machineVerifiedProfessionalQualification':False,
                    'accountingExecutionSupported':False}
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,
                    commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision,revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                    actor_id,committed_revision,result) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,digest,self.identity.subject_id,
                     revision,Jsonb(result)))
                db.execute('''INSERT INTO epm.policy_acquisition_approval
                    (workspace_id,application_id,approval_id,bundle_operation_id,
                    review_operation_id,evaluation_digest,approval_digest,
                    manifest,approver_issuer,approver_subject,policy_revision,
                    committed_revision) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,args['bundleOperationId'],
                     row['review_operation_id'],row['evaluation_digest'],
                     approval_digest,Jsonb(manifest),*actor,policy_revision,revision))
                return result

    def read(self,scope: ApplicationScope,program: object) -> dict:
        args=_program(program,READ)
        if not isinstance(scope,ApplicationScope):
            raise ValueError('Application scope is required')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read', function=READ)
                row=db.execute('''SELECT a.*,s.policy_revision AS current_policy,
                    s.commit_revision AS current_commit,
                    (SELECT count(*) FROM epm.policy_activation_current p
                        JOIN epm.policy_activation_event e
                        ON e.workspace_id=p.workspace_id
                        AND e.application_id=p.application_id
                        AND e.event_id=p.activation_id
                        WHERE p.workspace_id=a.workspace_id
                        AND p.application_id=a.application_id
                        AND e.approval_id=a.approval_id AND p.status='Active')
                        AS active_variants
                    FROM epm.policy_acquisition_approval a
                    JOIN epm.application_state s USING(workspace_id,application_id)
                    WHERE a.workspace_id=%s AND a.application_id=%s
                    AND a.approval_id=%s''',
                    (scope.workspace_id,scope.application_id,args['approvalId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_APPROVAL_UNAVAILABLE')
                return {'approvalId':row['approval_id'],
                    'approvalDigest':row['approval_digest'],'manifest':row['manifest'],
                    'policyBindingDigests':[_canonical_digest(binding)
                        for binding in row['manifest']['policyBindings']],
                    'approver':{'issuer':row['approver_issuer'],
                                'subjectId':row['approver_subject']},
                    'policyRevision':row['policy_revision'],
                    'committedRevision':row['committed_revision'],
                    'approvedAt':row['approved_at'].isoformat(),
                    'currentAtRead':row['policy_revision']==row['current_policy']
                        and row['committed_revision']==row['current_commit'],
                    'status':('WorkspaceApproved' if row['active_variants'] else
                              'WorkspaceApprovedPendingActivation'),
                    'activeVariantCount':row['active_variants'],
                    'machineVerifiedProfessionalQualification':False,
                    'accountingExecutionSupported':False}
