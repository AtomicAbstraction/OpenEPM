"""Bounded acquisition golden-case comparison against draft-only fixed core.

This is a technical fixture evaluator. Caller-supplied expectations and source
references are not accounting review, and no result permits publication.
"""
from __future__ import annotations

import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_acquisition_nci import (
    FUNCTION as ACQUISITION_FUNCTION, _program as _acquisition_program,
    _evaluate_in_transaction, _amount as _acquisition_amount,
    STEP_FUNCTION as STEP_ACQUISITION_FUNCTION,
    _step_program, _evaluate_step_in_transaction)
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_policy_source_values import (
    CapturedSourceValues, validate_locator, VERIFIER, PDF_VERIFIER,
    MAX_DOCUMENT_BYTES, MAX_PDF_DOCUMENT_BYTES, MAX_TOTAL_BYTES)


FUNCTION = 'consolidation.policy.draft.acquisition.cases.evaluate'
RECORD_FUNCTION = 'consolidation.policy.draft.acquisition.cases.record'
READ_FUNCTION = 'consolidation.policy.draft.acquisition.cases.read'
_ID = re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_CORE_VERSIONS = {ACQUISITION_FUNCTION:'acquisition-nci-candidate-v1',
                  STEP_ACQUISITION_FUNCTION:'acquisition-step-candidate-v1'}
_VALUE_FIELDS = {
    ACQUISITION_FUNCTION: ('ownershipPercent',
        'considerationTransferred', 'identifiableNetAssets', 'nciFairValue'),
    STEP_ACQUISITION_FUNCTION: ('priorInterestPercent',
        'additionalInterestPercent', 'finalOwnershipPercent',
        'priorInterestCarryingAmount', 'priorInterestFairValue',
        'considerationTransferred', 'identifiableNetAssets')}
_EXPECTED_REJECTIONS = frozenset({
    'ACQUISITION_NCI_SCOPE_UNSUPPORTED',
    'ACQUISITION_NCI_INPUT_RANGE_INVALID',
    'ACQUISITION_POWN_UNAVAILABLE',
    'ACQUISITION_POWN_MISMATCH',
    'ACQUISITION_PERIOD_DATE_MISMATCH',
    'NCI_MEASUREMENT_ELECTION_REQUIRED',
    'NCI_MEASUREMENT_FAMILY_CONFLICT',
    'NCI_MEASUREMENT_FAMILY_UNSUPPORTED',
    'NCI_FAIR_VALUE_REQUIRED',
    'NCI_FAIR_VALUE_NOT_APPLICABLE',
    'NCI_FULL_OWNERSHIP_CONFLICT',
    'BARGAIN_PURCHASE_REASSESSMENT_REQUIRED',
    'ACQUISITION_STEP_INPUT_RANGE_INVALID',
    'ACQUISITION_STEP_POLICY_UNSUPPORTED',
    'ACQUISITION_STEP_FINAL_POWN_MISMATCH',
})


def _expected(raw: object, candidate_function: str) -> dict:
    if not isinstance(raw, dict) or raw.get('outcome') not in (
            'Amounts', 'Rejected'):
        raise ValueError('POLICY_CASE_EXPECTATION_INVALID')
    if raw['outcome'] == 'Rejected':
        if (set(raw) != {'outcome', 'errorCode'}
                or raw['errorCode'] not in _EXPECTED_REJECTIONS):
            raise ValueError('POLICY_CASE_EXPECTATION_INVALID')
        return dict(raw)
    value_fields = (('nciAtAcquisition', 'goodwillCandidate')
        if candidate_function == ACQUISITION_FUNCTION else
        ('remeasurementGainOrLossCandidate', 'goodwillCandidate'))
    if set(raw) != {'outcome', *value_fields}:
        raise ValueError('POLICY_CASE_EXPECTATION_INVALID')
    result = {'outcome': 'Amounts'}
    for key in value_fields:
        amount = NumericCell.from_wire(present=True, amount=raw[key]).amount
        if amount < 0 and key != 'remeasurementGainOrLossCandidate':
            raise ValueError('POLICY_CASE_EXPECTATION_INVALID')
        result[key] = format(amount, '.8f')
    return result


def _source_value_evidence(item: dict) -> list[dict]:
    """Bind claimed document locations to every candidate monetary input.

    A digest supplied by the caller is not proof that the referenced original
    exists or is authentic. The only fixed-core assertion here is exact value
    equality and complete field coverage for this candidate.
    """
    raw = item['sourceValueEvidence']
    candidate = item['candidate'].get('arguments')
    if (item['expected']['outcome'] != 'Amounts'
            or not isinstance(candidate, dict)
            or not isinstance(raw, list)
            or not 1 <= len(raw) <= 7):
        raise ValueError('POLICY_CASE_SOURCE_VALUE_EVIDENCE_INVALID')
    function = item['candidate']['function']
    fields = _VALUE_FIELDS[function]
    required = {field for field in fields
                if candidate.get(field) is not None}
    if (function == ACQUISITION_FUNCTION
            and required not in ({'ownershipPercent',
                'considerationTransferred', 'identifiableNetAssets'},
                set(fields))
            or function == STEP_ACQUISITION_FUNCTION
            and required != set(fields)):
        raise ValueError('POLICY_CASE_SOURCE_VALUE_EVIDENCE_INVALID')
    normalized = {}
    for evidence in raw:
        if (not isinstance(evidence, dict)
                or set(evidence) not in (
                    {'field', 'value', 'sourceRef',
                     'documentSha256', 'locator'},
                    {'field', 'value', 'sourceRef',
                     'documentSha256', 'locator', 'artifactId'},
                    {'field', 'value', 'sourceRef',
                     'documentSha256', 'locator', 'artifactId',
                     'valueLocator'})
                or not isinstance(evidence['field'], str)
                or evidence['field'] not in required
                or evidence['field'] in normalized
                or not isinstance(evidence['sourceRef'], str)
                or evidence['sourceRef'] not in item['sourceRefs']
                or not isinstance(evidence['documentSha256'], str)
                or not _SHA256.fullmatch(evidence['documentSha256'])
                or ('artifactId' in evidence and
                    (not isinstance(evidence['artifactId'], str)
                     or not _KEY.fullmatch(evidence['artifactId'])))
                or not isinstance(evidence['locator'], str)
                or not 1 <= len(evidence['locator'].strip()) <= 250):
            raise ValueError('POLICY_CASE_SOURCE_VALUE_EVIDENCE_INVALID')
        field = evidence['field']
        try:
            asserted = _acquisition_amount(evidence['value'], field)
            candidate_value = _acquisition_amount(candidate[field], field)
        except ValueError as error:
            raise ValueError(
                'POLICY_CASE_SOURCE_VALUE_EVIDENCE_INVALID') from error
        if asserted != candidate_value:
            raise ValueError('POLICY_CASE_SOURCE_VALUE_MISMATCH')
        normalized[field] = {**evidence,
                             'value': format(asserted, '.8f')}
        if 'valueLocator' in evidence:
            normalized[field]['valueLocator'] = validate_locator(
                evidence['valueLocator'])
    if set(normalized) != required:
        raise ValueError('POLICY_CASE_SOURCE_VALUE_COVERAGE_INCOMPLETE')
    return [normalized[field] for field in fields
            if field in normalized]


def _program(raw: object) -> list[dict]:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != FUNCTION
            or not isinstance(raw['arguments'], dict)
            or set(raw['arguments']) != {'cases'}
            or not isinstance(raw['arguments']['cases'], list)
            or not 1 <= len(raw['arguments']['cases']) <= 20):
        raise ValueError('POLICY_CASE_PROGRAM_INVALID')
    cases = []
    seen = set()
    for item in raw['arguments']['cases']:
        if (not isinstance(item, dict)
                or set(item) not in ({'caseId', 'candidate', 'expected',
                                      'sourceRefs'},
                                     {'caseId', 'candidate', 'expected',
                                      'sourceRefs', 'sourceValueEvidence'})
                or not isinstance(item['caseId'], str)
                or not _ID.fullmatch(item['caseId'])
                or item['caseId'] in seen
                or not isinstance(item['candidate'], dict)
                or not isinstance(item['candidate'].get('function'), str)
                or item['candidate'].get('function') not in _VALUE_FIELDS
                or not isinstance(item['sourceRefs'], list)
                or not 1 <= len(item['sourceRefs']) <= 10
                or any(not isinstance(ref, str)
                       or not 1 <= len(ref.strip()) <= 500
                       for ref in item['sourceRefs'])):
            raise ValueError('POLICY_CASE_DEFINITION_INVALID')
        seen.add(item['caseId'])
        case = {'caseId': item['caseId'],
                'candidate': item['candidate'],
                'expected': _expected(item['expected'],
                    item['candidate']['function']),
                'sourceRefs': list(item['sourceRefs'])}
        if 'sourceValueEvidence' in item:
            case['sourceValueEvidence'] = _source_value_evidence(case | {
                'sourceValueEvidence': item['sourceValueEvidence']})
        cases.append(case)
    return cases


class PostgresPolicyCaseEvaluator:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def evaluate(self, scope: ApplicationScope, program: object) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        cases = _program(program)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                artifact_ids = {evidence['artifactId']
                    for item in cases
                    for evidence in item.get('sourceValueEvidence', [])
                    if 'artifactId' in evidence}
                all_artifact_ids = artifact_ids
                if len(artifact_ids) > 20:
                    raise ValueError('POLICY_CASE_ARTIFACT_LIMIT_EXCEEDED')
                artifacts = {}
                verified_values = {}
                located_ids = {evidence['artifactId']
                    for item in cases
                    for evidence in item.get('sourceValueEvidence', [])
                    if 'valueLocator' in evidence}
                if located_ids:
                    # Locators inspect document content, which is restricted
                    # to Administrators by the artifact content-read contract.
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'admin', function=FUNCTION)
                if all_artifact_ids:
                    artifacts = {row['artifact_id']: row for row in
                        db.execute('''SELECT artifact_id,source_ref,
                            source_version,content_sha256,media_type,
                            content_bytes,client_extraction_id,
                            client_extraction_sha256,
                            client_extraction_bytes
                            FROM epm.policy_source_artifact
                            WHERE workspace_id=%s AND application_id=%s
                            AND artifact_id=ANY(%s)''',
                            (scope.workspace_id, scope.application_id,
                             sorted(all_artifact_ids))).fetchall()}
                    if (any(artifacts[key]['content_bytes'] >
                            (MAX_PDF_DOCUMENT_BYTES if artifacts[key][
                                'media_type'] == 'application/pdf' else
                             MAX_DOCUMENT_BYTES) for key in located_ids
                            if key in artifacts)
                            or sum(artifacts[key]['content_bytes'] +
                                   (artifacts[key][
                                    'client_extraction_bytes'] or 0)
                                   for key in located_ids
                                   if key in artifacts)
                            > MAX_TOTAL_BYTES):
                        raise ValueError(
                            'POLICY_SOURCE_VALUE_DOCUMENT_BUDGET_EXCEEDED')
                    if located_ids:
                        for row in db.execute('''SELECT artifact_id,
                            CASE WHEN media_type='application/pdf'
                                 THEN client_extraction ELSE content END
                                 AS verification_content,
                            media_type
                            FROM epm.policy_source_artifact
                            WHERE workspace_id=%s AND application_id=%s
                            AND artifact_id=ANY(%s)''',
                            (scope.workspace_id,scope.application_id,
                             sorted(located_ids))).fetchall():
                            target = ('client_extraction'
                                      if row['media_type']=='application/pdf'
                                      else 'content')
                            artifacts[row['artifact_id']][target] = \
                                row['verification_content']
                    verifier = CapturedSourceValues()
                    for item in cases:
                        for evidence in item.get('sourceValueEvidence', []):
                            if 'artifactId' not in evidence:
                                continue
                            artifact = artifacts.get(evidence['artifactId'])
                            if (artifact is None or
                                artifact['source_ref'] != evidence['sourceRef']
                                or artifact['content_sha256'] !=
                                evidence['documentSha256']):
                                raise ValueError(
                                    'POLICY_CASE_CAPTURED_ARTIFACT_MISMATCH')
                            if 'valueLocator' in evidence:
                                locator = evidence['valueLocator']
                                value = verifier.verify(artifact,
                                    locator,evidence['value'])
                                verified_values.setdefault(
                                    item['caseId'], []).append({
                                        'field': evidence['field'],
                                        'artifactId': evidence['artifactId'],
                                        'valueLocator': evidence['valueLocator'],
                                        'value': value,
                                        'verifier': (PDF_VERIFIER if locator[
                                            'kind'] == 'ClientPdfTextSpan'
                                            else VERIFIER),
                                        'extractionTrust': (
                                            'ClientSuppliedUnreviewed'
                                            if locator['kind'] ==
                                                'ClientPdfTextSpan' else
                                            'ServerVerifiedStructuredSource')})
                rows = []
                for item in cases:
                    try:
                        if (item['candidate']['function'] ==
                                ACQUISITION_FUNCTION):
                            policy, amounts = _acquisition_program(
                                item['candidate'])
                            candidate = _evaluate_in_transaction(
                                db, scope, policy, amounts, state)
                            actual = {'outcome': 'Amounts',
                                'nciAtAcquisition':
                                    candidate['nciAtAcquisition'],
                                'goodwillCandidate':
                                    candidate['goodwillCandidate']}
                        else:
                            args, policy, amounts = _step_program(
                                item['candidate'])
                            candidate = _evaluate_step_in_transaction(
                                db, scope, args, policy, amounts, state)
                            actual = {'outcome': 'Amounts',
                                'remeasurementGainOrLossCandidate':
                                    candidate[
                                        'remeasurementGainOrLossCandidate'],
                                'goodwillCandidate':
                                    candidate['goodwillCandidate']}
                        lineage = {'draftDigest': candidate['draftDigest'],
                                   'selectionDigest':
                                       candidate['selectionDigest'],
                                   'ownershipSource':
                                       candidate['ownershipSource'],
                                   'calendarSource':
                                       candidate['calendarSource']}
                        binding = {'policyId':candidate['policyId'],
                            'candidateFunction':item['candidate']['function'],
                            'candidateCoreVersion':_CORE_VERSIONS[
                                item['candidate']['function']],
                            'policyVersion':candidate['policyVersion'],
                            'policyFamily':candidate['policyFamily'],
                            'effectiveOn':item['candidate']['arguments'][
                                'effectiveOn'],
                            'selections':dict(sorted(item['candidate'][
                                'arguments']['selections'].items())),
                            'draftDigest':candidate['draftDigest'],
                            'selectionDigest':candidate['selectionDigest']}
                    except ValueError as error:
                        code = str(error)
                        if code not in _EXPECTED_REJECTIONS:
                            raise
                        actual = {'outcome': 'Rejected', 'errorCode': code}
                        lineage = None
                        binding = None
                    row = {'caseId': item['caseId'],
                                 'expected': item['expected'],
                                 'actual': actual,
                                 'matched': item['expected'] == actual,
                                 'sourceRefs': item['sourceRefs'],
                                 'lineage': lineage}
                    if binding is not None:
                        row['policyBinding'] = binding
                    if 'sourceValueEvidence' in item:
                        row['sourceValueEvidence'] = (
                            item['sourceValueEvidence'])
                        row['sourceValueCoverage'] = 'ExactInputsBound'
                        row['sourceAuthenticityVerified'] = False
                        linked = [evidence for evidence in
                            item['sourceValueEvidence']
                            if 'artifactId' in evidence]
                        if linked:
                            row['capturedContentCoverage'] = (
                                'ExactCapturedBytes' if len(linked) ==
                                len(item['sourceValueEvidence']) else
                                'PartialCapturedBytes')
                            row['capturedArtifacts'] = [
                                {'artifactId': artifact_id,
                                 'sourceVersion':
                                     artifacts[artifact_id]['source_version'],
                                 'contentSha256':
                                     artifacts[artifact_id]['content_sha256']}
                                for artifact_id in sorted({evidence[
                                    'artifactId'] for evidence in linked})]
                        verified = verified_values.get(item['caseId'], [])
                        if verified:
                            row['sourceLocatorCoverage'] = (
                                'AllValuesVerified' if len(verified) ==
                                len(item['sourceValueEvidence']) else
                                'PartialValuesVerified')
                            row['sourceValueVerification'] = verified
                    rows.append(row)
                return {'cases': rows,
                        'matchedCount': sum(row['matched'] for row in rows),
                        'caseCount': len(rows),
                        'allMatched': all(row['matched'] for row in rows),
                        'evaluationDigest': _canonical_digest({
                            'scope': [scope.workspace_id,
                                      scope.application_id],
                            'policyRevision': state['policy_revision'],
                            'commitRevision': state['commit_revision'],
                            'cases': rows}),
                        'policyRevision': state['policy_revision'],
                        'observedCommitRevision': state['commit_revision'],
                        'reviewStatus': 'UnreviewedTechnicalFixture',
                        'publicationSupported': False}

    def record(self, scope: ApplicationScope, program: object, *,
               idempotency_key: str) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != RECORD_FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != {
                    'cases', 'expectedPolicyRevision',
                    'expectedCommitRevision'}
                or any(type(program['arguments'][key]) is not int
                       or program['arguments'][key] < 0
                       for key in ('expectedPolicyRevision',
                                   'expectedCommitRevision'))
                or not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('POLICY_CASE_RECORD_PROGRAM_INVALID')
        args = program['arguments']
        evaluation_program = {'languageVersion': 2, 'function': FUNCTION,
                              'arguments': {'cases': args['cases']}}
        _program(evaluation_program)
        command_digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': program})
        keys = (scope.workspace_id, scope.application_id)

        def prior_receipt(db):
            prior = db.execute('''SELECT command_digest,actor_id,result
                FROM epm.operation_receipt WHERE workspace_id=%s
                AND application_id=%s AND operation_id=%s''',
                (*keys, idempotency_key)).fetchone()
            if prior and (prior['command_digest'] != command_digest
                          or prior['actor_id'] != self.identity.subject_id):
                raise ValueError('POLICY_CASE_IDEMPOTENCY_CONFLICT')
            return prior['result'] if prior else None

        # Replay must remain valid even after later metadata changes. Recheck
        # the current grant before returning a prior receipt.
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=RECORD_FUNCTION)
                prior = prior_receipt(db)
                if prior is not None:
                    return prior

        evaluation = self.evaluate(scope, evaluation_program)
        if not evaluation['allMatched']:
            raise ValueError('POLICY_CASE_EXPECTATION_MISMATCH')
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
                    db, self.identity, scope, 'admin', function=RECORD_FUNCTION)
                prior = prior_receipt(db)
                if prior is not None:
                    return prior
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['policy_revision'] != args['expectedPolicyRevision']
                        or state['commit_revision'] !=
                        args['expectedCommitRevision']
                        or state['policy_revision'] !=
                        evaluation['policyRevision']
                        or state['commit_revision'] !=
                        evaluation['observedCommitRevision']):
                    raise ValueError('STALE_POLICY_CASE_EVALUATION')
                revision = state['commit_revision'] + 1
                policy_revision = state['policy_revision'] + 1
                result = {'operationId': idempotency_key,
                          'evaluationDigest':
                              evaluation['evaluationDigest'],
                          'caseCount': evaluation['caseCount'],
                          'status': 'UnreviewedTechnicalFixture',
                          'policyRevision': policy_revision,
                          'committedRevision': revision,
                          'accountingExecutionSupported': False}
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                    command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key, command_digest,
                     self.identity.subject_id, revision, Jsonb(result)))
                db.execute('''INSERT INTO epm.policy_acquisition_case_bundle
                    (workspace_id,application_id,operation_id,
                    evaluation_digest,policy_revision,
                    observed_commit_revision,committed_revision,
                    case_count,cases,source_actor_issuer,
                    source_actor_subject)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key,
                     evaluation['evaluationDigest'], policy_revision,
                     evaluation['observedCommitRevision'], revision,
                     evaluation['caseCount'], Jsonb(evaluation['cases']),
                     self.identity.issuer, self.identity.subject_id))
                return result

    def read_record(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != READ_FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != {'operationId'}
                or not isinstance(program['arguments']['operationId'], str)
                or not _KEY.fullmatch(program['arguments']['operationId'])):
            raise ValueError('POLICY_CASE_READ_PROGRAM_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=READ_FUNCTION)
                row = db.execute('''SELECT operation_id,evaluation_digest,
                    policy_revision,observed_commit_revision,
                    committed_revision,case_count,cases,
                    source_actor_issuer,source_actor_subject
                    FROM epm.policy_acquisition_case_bundle
                    WHERE workspace_id=%s AND application_id=%s
                    AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     program['arguments']['operationId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_CASE_RECORD_UNAVAILABLE')
                return {'operationId': row['operation_id'],
                        'evaluationDigest': row['evaluation_digest'],
                        'policyRevision': row['policy_revision'],
                        'observedCommitRevision':
                            row['observed_commit_revision'],
                        'committedRevision': row['committed_revision'],
                        'caseCount': row['case_count'],
                        'cases': row['cases'],
                        'sourceActor': {
                            'issuer': row['source_actor_issuer'],
                            'subjectId': row['source_actor_subject']},
                        'currentAtRead': (
                            row['policy_revision'] ==
                            state['policy_revision'] and
                            row['committed_revision'] ==
                            state['commit_revision']),
                        'reviewStatus': 'UnreviewedTechnicalFixture',
                        'accountingExecutionSupported': False}
