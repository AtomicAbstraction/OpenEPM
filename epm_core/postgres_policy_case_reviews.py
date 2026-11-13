"""Identity-separated, immutable review trail for acquisition case bundles.

The reviewer claims and references are recorded, not independently verified.
No review result activates accounting execution or certifies a policy pack.
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


REVIEW_FUNCTION = 'consolidation.policy.draft.acquisition.cases.review.record'
READ_FUNCTION = 'consolidation.policy.draft.acquisition.cases.review.read'
EVIDENCE_FUNCTION = 'consolidation.policy.draft.acquisition.cases.evidence.inspect'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('POLICY_CASE_REVIEW_PROGRAM_INVALID')
    args = raw['arguments']
    if function in (READ_FUNCTION, EVIDENCE_FUNCTION):
        if (set(args) != {'bundleOperationId'}
                or not isinstance(args['bundleOperationId'], str)
                or not _KEY.fullmatch(args['bundleOperationId'])):
            raise ValueError('POLICY_CASE_REVIEW_ARGUMENTS_INVALID')
        return args
    if (function != REVIEW_FUNCTION
            or set(args) != {'bundleOperationId',
                'expectedEvaluationDigest', 'expectedPolicyRevision',
                'expectedCommitRevision', 'decision',
                'sourceValuesChecked', 'controlAssessmentChecked',
                'qualificationRef', 'reviewEvidenceRefs', 'rationale'}
            or not isinstance(args['bundleOperationId'], str)
            or not _KEY.fullmatch(args['bundleOperationId'])
            or not isinstance(args['expectedEvaluationDigest'], str)
            or not _DIGEST.fullmatch(args['expectedEvaluationDigest'])
            or any(type(args[key]) is not int or args[key] < 0
                   for key in ('expectedPolicyRevision',
                               'expectedCommitRevision'))
            or args['decision'] not in ('Attest', 'Reject')
            or type(args['sourceValuesChecked']) is not bool
            or type(args['controlAssessmentChecked']) is not bool
            or not isinstance(args['qualificationRef'], str)
            or not 1 <= len(args['qualificationRef'].strip()) <= 500
            or not isinstance(args['reviewEvidenceRefs'], list)
            or not 1 <= len(args['reviewEvidenceRefs']) <= 10
            or any(not isinstance(ref, str)
                   or not 1 <= len(ref.strip()) <= 500
                   for ref in args['reviewEvidenceRefs'])
            or len(set(args['reviewEvidenceRefs'])) !=
                len(args['reviewEvidenceRefs'])
            or not isinstance(args['rationale'], str)
            or not 10 <= len(args['rationale'].strip()) <= 2000):
        raise ValueError('POLICY_CASE_REVIEW_ARGUMENTS_INVALID')
    if (args['decision'] == 'Attest'
            and (not args['sourceValuesChecked']
                 or not args['controlAssessmentChecked'])):
        raise ValueError('POLICY_CASE_REVIEW_CONFIRMATIONS_REQUIRED')
    return args


class PostgresPolicyCaseReviews:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def record(self, scope: ApplicationScope, program: object, *,
               idempotency_key: str) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args = _program(program, REVIEW_FUNCTION)
        if (not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('POLICY_CASE_REVIEW_IDEMPOTENCY_KEY_INVALID')
        keys = (scope.workspace_id, scope.application_id)
        digest = _canonical_digest({'scope': list(keys),
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT s.policy_revision,
                    s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=REVIEW_FUNCTION)
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys, idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != digest
                            or prior['actor_id'] != self.identity.subject_id):
                        raise ValueError('POLICY_CASE_REVIEW_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['policy_revision'] != args['expectedPolicyRevision']
                        or state['commit_revision'] !=
                        args['expectedCommitRevision']):
                    raise ValueError('STALE_POLICY_CASE_REVIEW_REVISION')
                bundle = db.execute('''SELECT evaluation_digest,
                    policy_revision,committed_revision,
                    source_actor_issuer,source_actor_subject
                    FROM epm.policy_acquisition_case_bundle
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',
                    (*keys, args['bundleOperationId'])).fetchone()
                if bundle is None:
                    raise ValueError('POLICY_CASE_RECORD_UNAVAILABLE')
                if (bundle['evaluation_digest'] !=
                        args['expectedEvaluationDigest']
                        or bundle['policy_revision'] !=
                        state['policy_revision']
                        or bundle['committed_revision'] !=
                        state['commit_revision']):
                    raise ValueError('POLICY_CASE_REVIEW_STALE_BUNDLE')
                if (bundle['source_actor_issuer'] == self.identity.issuer
                        and bundle['source_actor_subject'] ==
                        self.identity.subject_id):
                    raise ValueError('POLICY_CASE_SELF_REVIEW_FORBIDDEN')
                if db.execute('''SELECT 1
                    FROM epm.policy_acquisition_case_review
                    WHERE workspace_id=%s AND application_id=%s
                    AND bundle_operation_id=%s''',
                    (*keys, args['bundleOperationId'])).fetchone():
                    raise ValueError('POLICY_CASE_ALREADY_REVIEWED')
                revision = state['commit_revision'] + 1
                policy_revision = state['policy_revision'] + 1
                status = ('ReviewerAttestedUnapproved'
                          if args['decision'] == 'Attest'
                          else 'RejectedTechnicalEvidence')
                result = {'operationId': idempotency_key,
                    'bundleOperationId': args['bundleOperationId'],
                    'evaluationDigest': bundle['evaluation_digest'],
                    'decision': args['decision'], 'status': status,
                    'policyRevision': policy_revision,
                    'committedRevision': revision,
                    'qualificationRefVerified': False,
                    'accountingExecutionSupported': False}
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                    command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key, digest,
                     self.identity.subject_id, revision, Jsonb(result)))
                db.execute('''INSERT INTO epm.policy_acquisition_case_review
                    (workspace_id,application_id,bundle_operation_id,
                    review_operation_id,evaluation_digest,decision,
                    source_values_checked,control_assessment_checked,
                    qualification_ref,review_evidence_refs,rationale,
                    reviewer_issuer,reviewer_subject,
                    policy_revision,committed_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, args['bundleOperationId'], idempotency_key,
                     bundle['evaluation_digest'], args['decision'],
                     args['sourceValuesChecked'],
                     args['controlAssessmentChecked'],
                     args['qualificationRef'],
                     Jsonb(args['reviewEvidenceRefs']), args['rationale'],
                     self.identity.issuer, self.identity.subject_id,
                     policy_revision, revision))
                return result

    def read(self, scope: ApplicationScope, program: object) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args = _program(program, READ_FUNCTION)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=READ_FUNCTION)
                row = db.execute('''SELECT r.review_operation_id,
                    r.bundle_operation_id,r.evaluation_digest,r.decision,
                    r.source_values_checked,r.control_assessment_checked,
                    r.qualification_ref,r.review_evidence_refs,r.rationale,
                    r.reviewer_issuer,r.reviewer_subject,r.policy_revision,
                    r.committed_revision,r.reviewed_at,
                    b.source_actor_issuer,b.source_actor_subject
                    FROM epm.policy_acquisition_case_review r
                    JOIN epm.policy_acquisition_case_bundle b
                    ON b.workspace_id=r.workspace_id
                    AND b.application_id=r.application_id
                    AND b.operation_id=r.bundle_operation_id
                    WHERE r.workspace_id=%s AND r.application_id=%s
                    AND r.bundle_operation_id=%s''',
                    (*keys, args['bundleOperationId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_CASE_REVIEW_UNAVAILABLE')
                return {'operationId': row['review_operation_id'],
                    'bundleOperationId': row['bundle_operation_id'],
                    'evaluationDigest': row['evaluation_digest'],
                    'decision': row['decision'],
                    'sourceValuesChecked': row['source_values_checked'],
                    'controlAssessmentChecked':
                        row['control_assessment_checked'],
                    'qualificationRef': row['qualification_ref'],
                    'qualificationRefVerified': False,
                    'reviewEvidenceRefs': row['review_evidence_refs'],
                    'rationale': row['rationale'],
                    'reviewer': {'issuer': row['reviewer_issuer'],
                                 'subjectId': row['reviewer_subject']},
                    'sourceActor': {
                        'issuer': row['source_actor_issuer'],
                        'subjectId': row['source_actor_subject']},
                    'policyRevision': row['policy_revision'],
                    'committedRevision': row['committed_revision'],
                    'reviewedAt': row['reviewed_at'].isoformat(),
                    'currentAtRead': (
                        row['policy_revision'] == state['policy_revision']
                        and row['committed_revision'] ==
                        state['commit_revision']),
                    'status': ('ReviewerAttestedUnapproved'
                        if row['decision'] == 'Attest'
                        else 'RejectedTechnicalEvidence'),
                    'accountingExecutionSupported': False}

    def inspect_evidence(self, scope: ApplicationScope,
                         program: object) -> dict:
        """Describe fixed-core evidence gaps without granting activation.

        Stored references, document digests and reviewer assertions are not
        independent proof of source authenticity or professional competence.
        """
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args = _program(program, EVIDENCE_FUNCTION)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=EVIDENCE_FUNCTION)
                row = db.execute('''SELECT b.operation_id,
                    b.evaluation_digest,b.policy_revision AS bundle_policy,
                    b.committed_revision AS bundle_commit,b.case_count,
                    b.cases,b.source_actor_issuer,b.source_actor_subject,
                    r.review_operation_id,r.evaluation_digest AS review_digest,
                    r.decision,r.source_values_checked,
                    r.control_assessment_checked,r.qualification_ref,
                    r.review_evidence_refs,r.reviewer_issuer,
                    r.reviewer_subject,r.policy_revision AS review_policy,
                    r.committed_revision AS review_commit,
                    a.approval_id,a.approval_digest,
                    a.policy_revision AS approval_policy,
                    a.committed_revision AS approval_commit
                    FROM epm.policy_acquisition_case_bundle b
                    LEFT JOIN epm.policy_acquisition_case_review r
                    ON r.workspace_id=b.workspace_id
                    AND r.application_id=b.application_id
                    AND r.bundle_operation_id=b.operation_id
                    LEFT JOIN epm.policy_acquisition_approval a
                    ON a.workspace_id=b.workspace_id
                    AND a.application_id=b.application_id
                    AND a.bundle_operation_id=b.operation_id
                    WHERE b.workspace_id=%s AND b.application_id=%s
                    AND b.operation_id=%s''',
                    (*keys, args['bundleOperationId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_CASE_RECORD_UNAVAILABLE')
                cases = row['cases']
                amount_cases = [item for item in cases
                    if item['expected']['outcome'] == 'Amounts']
                uncovered = [item['caseId'] for item in amount_cases
                    if item.get('sourceValueCoverage') != 'ExactInputsBound']
                uncaptured = [item['caseId'] for item in amount_cases
                    if item.get('capturedContentCoverage') !=
                       'ExactCapturedBytes']
                unlocated = [item['caseId'] for item in amount_cases
                    if item.get('sourceLocatorCoverage') !=
                       'AllValuesVerified']
                synthetic = [item['caseId'] for item in cases
                    if any(ref.startswith('synthetic:')
                        for ref in item['sourceRefs'])
                    or any(evidence['sourceRef'].startswith('synthetic:')
                        for evidence in item.get('sourceValueEvidence', []))]
                reviewed = row['review_operation_id'] is not None
                approved = row['approval_id'] is not None
                pinned_policy = (row['approval_policy'] if approved else
                    row['review_policy'] if reviewed else row['bundle_policy'])
                pinned_commit = (row['approval_commit'] if approved else
                    row['review_commit'] if reviewed else row['bundle_commit'])
                active_variants=0
                last_activation_action=None
                if approved:
                    latest=db.execute('''SELECT action,policy_revision,
                        committed_revision FROM epm.policy_activation_event
                        WHERE workspace_id=%s AND application_id=%s
                        AND approval_id=%s ORDER BY committed_revision DESC LIMIT 1''',
                        (*keys,row['approval_id'])).fetchone()
                    if latest:
                        pinned_policy=latest['policy_revision']
                        pinned_commit=latest['committed_revision']
                        last_activation_action=latest['action']
                    active_variants=db.execute('''SELECT count(*) AS count
                        FROM epm.policy_activation_current p
                        JOIN epm.policy_activation_event e
                        ON e.workspace_id=p.workspace_id
                        AND e.application_id=p.application_id
                        AND e.event_id=p.activation_id
                        WHERE p.workspace_id=%s AND p.application_id=%s
                        AND e.approval_id=%s AND p.status='Active' ''',
                        (*keys,row['approval_id'])).fetchone()['count']
                current = (pinned_policy == state['policy_revision']
                           and pinned_commit == state['commit_revision'])
                identity_distinct = (reviewed and
                    (row['source_actor_issuer'], row['source_actor_subject'])
                    != (row['reviewer_issuer'], row['reviewer_subject']))
                blockers = []
                if not current:
                    blockers.append('CASE_OR_REVIEW_REVISION_STALE')
                if not amount_cases:
                    blockers.append('AMOUNT_CASE_REQUIRED')
                if uncovered:
                    blockers.append('SOURCE_VALUE_COVERAGE_INCOMPLETE')
                if uncaptured:
                    blockers.append('SOURCE_BYTES_NOT_CAPTURED')
                if unlocated:
                    blockers.append('SOURCE_VALUE_LOCATORS_UNVERIFIED')
                if synthetic:
                    blockers.append('SYNTHETIC_SOURCE_REFERENCE')
                if not reviewed:
                    blockers.append('INDEPENDENT_REVIEW_MISSING')
                elif row['review_digest'] != row['evaluation_digest']:
                    blockers.append('REVIEW_BUNDLE_DIGEST_MISMATCH')
                elif row['decision'] != 'Attest':
                    blockers.append('INDEPENDENT_REVIEW_NOT_ATTESTED')
                elif not identity_distinct or not (
                        row['source_values_checked'] and
                        row['control_assessment_checked']):
                    blockers.append('INDEPENDENT_REVIEW_INVALID')
                # Human owner assessments remain distinct from machine
                # verification of origin/credentials. Activation is separate.
                blockers.extend(('SOURCE_AUTHENTICITY_UNVERIFIED',
                    'REVIEWER_QUALIFICATION_UNVERIFIED'))
                if not active_variants:
                    blockers.append('POLICY_ACTIVATION_REQUIRED' if approved else
                        'ACCOUNTING_POLICY_APPROVAL_UNAVAILABLE')
                return {
                    'bundleOperationId': row['operation_id'],
                    'evaluationDigest': row['evaluation_digest'],
                    'caseCount': row['case_count'],
                    'amountCaseCount': len(amount_cases),
                    'uncoveredAmountCaseIds': uncovered,
                    'uncapturedAmountCaseIds': uncaptured,
                    'unverifiedLocatorCaseIds': unlocated,
                    'syntheticReferenceCaseIds': synthetic,
                    'reviewOperationId': row['review_operation_id'],
                    'reviewDecision': row['decision'],
                    'approvalId':row['approval_id'],
                    'approvalDigest':row['approval_digest'],
                    'workspaceApprovalStatus':(
                        'WorkspaceApproved' if active_variants else
                        'WorkspaceApprovedPendingActivation' if approved else
                        'Unapproved'),
                    'activeVariantCount':active_variants,
                    'policyActivationStatus':('Active' if active_variants else
                        'Withdrawn' if last_activation_action=='Withdraw' else 'Inactive'),
                    'reviewDigestMatchesBundle': (reviewed and
                        row['review_digest'] == row['evaluation_digest']),
                    'reviewerIdentityDistinct': identity_distinct,
                    'currentAtRead': current,
                    'pinnedPolicyRevision': pinned_policy,
                    'pinnedCommitRevision': pinned_commit,
                    'observedPolicyRevision': state['policy_revision'],
                    'observedCommitRevision': state['commit_revision'],
                    'blockingReasons': blockers,
                    'activationEligible': False,
                    'accountingExecutionSupported': False,
                    'accountingPublicationAvailable':bool(active_variants),
                    'accountingPublicationFunction':(
                        'consolidation.acquisition.journal.publish'
                        if active_variants else None)}
