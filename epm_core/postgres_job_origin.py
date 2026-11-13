"""Fixed-core admission and current producer identity for durable result jobs.

A workflow name or result-key prefix never establishes ownership. The language
boundary binds the actual public operation, and the queue establishes the exact
child link atomically with its job. Legacy origin stays explicitly unresolved.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import re


@dataclass(frozen=True, slots=True)
class ApplicationRuleAdmission:
    application_rule_workflow_id: str
    unit_ordinal: int
    sealed_plan_digest: str
    public_operation_digest: str
    owner_certificate_digest: str
    workspace_id: str
    application_id: str
    issuer: str
    subject_id: str
    function_name: str

    def descriptor(self):
        return asdict(self)


_RULE_KEYS = frozenset(('application_rule_workflow_id', 'unit_ordinal',
    'sealed_plan_digest', 'public_operation_digest', 'owner_certificate_digest'))


def bind_public_operation(authority, scope, identity, program):
    """Mint a typed private admission only at the actual V2 operation boundary."""
    if authority is None or (type(authority) is dict and not (_RULE_KEYS & set(authority))):
        return authority
    from .postgres_jobs import _canonical_digest
    from .postgres_capability_contract import assert_source_job_purpose
    if (type(authority) is not dict or set(authority) != _RULE_KEYS
            or type(authority['unit_ordinal']) is not int or authority['unit_ordinal'] < 1
            or type(authority['application_rule_workflow_id']) is not str
            or re.fullmatch(r'[0-9a-f]{32}', authority['application_rule_workflow_id']) is None
            or any(type(authority[key]) is not str or re.fullmatch(r'[0-9a-f]{64}', authority[key]) is None
                for key in ('sealed_plan_digest', 'public_operation_digest', 'owner_certificate_digest'))
            or type(program) is not dict
            or _canonical_digest(program) != authority['public_operation_digest']):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_INVALID')
    assert_source_job_purpose(program.get('function'))
    return ApplicationRuleAdmission(**authority, workspace_id=scope.workspace_id,
        application_id=scope.application_id, issuer=identity.issuer,
        subject_id=identity.subject_id, function_name=program['function'])


def authority_descriptor(authority):
    return authority.descriptor() if isinstance(authority, ApplicationRuleAdmission) else authority


def _workflow(db, scope, workflow_id):
    row = db.execute('''SELECT * FROM epm.application_rule_workflow
        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s''',
        (scope.workspace_id, scope.application_id, workflow_id)).fetchone()
    if row is None:
        raise ValueError('APPLICATION_RULE_JOB_ORIGIN_UNAVAILABLE')
    return row


def _operation(row, ordinal, *, _budget=None):
    from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
    from .postgres_capability_contract import assert_source_plan_purpose
    from .python_plan_runner import SealedPlanRunner
    plan = PostgresApplicationRuleWorkflowStore._stored_plan(row)
    if _budget is not None:
        _budget[0] -= plan.unit_count
        if _budget[0] < 0:
            raise ValueError('CALCULATION_CURRENTNESS_PRODUCER_LIMIT')
    assert_source_plan_purpose(plan.canonical_plan, allow_definition=False)
    units = SealedPlanRunner._units(plan)
    if type(ordinal) is not int or not 1 <= ordinal <= len(units):
        raise ValueError('APPLICATION_RULE_JOB_UNIT_INVALID')
    return SealedPlanRunner._atomic_operation(units[ordinal - 1])


def verify_admission(db, scope, identity, admission, *, function_name, idempotency_key, dependencies):
    """Recheck the sealed origin inside the same app-locked queue transaction."""
    from .postgres_jobs import _canonical_digest
    from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
    from .postgres_access import PostgresAccessChecker
    from .postgres_dimensional_scope import resolve_effective_dimensional_scope
    if (not isinstance(admission, ApplicationRuleAdmission)
            or (admission.workspace_id, admission.application_id, admission.issuer, admission.subject_id,
                admission.function_name) != (scope.workspace_id, scope.application_id,
                    identity.issuer, identity.subject_id, function_name)):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_INVALID')
    row = _workflow(db, scope, admission.application_rule_workflow_id)
    if ((row['issuer'], row['subject_id']) != (identity.issuer, identity.subject_id)
            or row['plan_digest'] != admission.sealed_plan_digest
            or row.get('owner_certificate_digest') != admission.owner_certificate_digest
            or idempotency_key != f"rule-{row['workflow_id']}-{admission.unit_ordinal}"
            or row['status'] != 'running'):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_INVALID')
    PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write')
    access = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'rule_run',
        function='application.rule.run')
    current_scope = resolve_effective_dimensional_scope(db, identity, scope,
        access=access, function='application.rule.run').scope_digest
    if current_scope != row.get('authorization_scope_digest'):
        raise ValueError('APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
    PostgresApplicationRuleWorkflowStore._verify_current(db, scope, row)
    operation = _operation(row, admission.unit_ordinal)
    checkpoints = row['result'].get('checkpoints', [])
    if (_canonical_digest(operation) != admission.public_operation_digest
            or operation['function'] != function_name
            or len(checkpoints) + 1 != admission.unit_ordinal
            or any(item.get('committed') is not True for item in checkpoints)
            or dependencies != (() if not checkpoints else (checkpoints[-1]['jobId'],))):
        raise ValueError('APPLICATION_RULE_JOB_UNIT_INVALID')
    return row


def link_admission(db, scope, admission, job_id):
    db.execute('''INSERT INTO epm.application_rule_workflow_child
        (workspace_id,application_id,workflow_id,unit_ordinal,job_id)
        VALUES(%s,%s,%s,%s,%s)''', (scope.workspace_id, scope.application_id,
        admission.application_rule_workflow_id, admission.unit_ordinal, job_id))


def _origin(db, scope, job, *, _budget=None):
    # Some maintained publishers select a bounded job projection. Resolve its
    # exact immutable scoped identity, never infer origin from a key prefix.
    row = db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
        AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
        (scope.workspace_id, scope.application_id, job['issuer'], job['subject_id'],
         job['idempotency_key'])).fetchone()
    if row is None or (job.get('job_id') is not None and row['job_id'] != job['job_id']):
        raise ValueError('JOB_ORIGIN_UNAVAILABLE')
    links = db.execute('''SELECT workflow_id,unit_ordinal FROM epm.application_rule_workflow_child
        WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
        (scope.workspace_id, scope.application_id, row['job_id'])).fetchall()
    kind = row.get('admission_origin_kind')
    if kind == 'ordinary' and not links:
        return row, None, None
    if kind != 'application_rule' or len(links) != 1 or row.get('python_workflow_id') is not None:
        raise ValueError('JOB_ORIGIN_UNRESOLVED')
    link = links[0]
    workflow = _workflow(db, scope, link['workflow_id'])
    from .postgres_jobs import _canonical_digest
    operation = _operation(workflow, link['unit_ordinal'], _budget=_budget)
    if ((workflow['issuer'], workflow['subject_id']) != (row['issuer'], row['subject_id'])
            or operation['function'] != row['function_name']
            or row['program_digest'] != _canonical_digest(row['normalized_program'])
            or not workflow.get('owner_certificate_digest')):
        raise ValueError('APPLICATION_RULE_JOB_ORIGIN_INVALID')
    from .postgres_jobs import _job_request_descriptor
    from .postgres_access import VerifiedIdentity
    admission = ApplicationRuleAdmission(application_rule_workflow_id=workflow['workflow_id'],
        unit_ordinal=link['unit_ordinal'], sealed_plan_digest=workflow['plan_digest'],
        public_operation_digest=_canonical_digest(operation),
        owner_certificate_digest=workflow['owner_certificate_digest'],
        workspace_id=scope.workspace_id, application_id=scope.application_id,
        issuer=row['issuer'], subject_id=row['subject_id'], function_name=row['function_name'])
    dependencies = tuple(item['depends_on_job_id'] for item in db.execute('''SELECT depends_on_job_id
        FROM epm.job_dependency WHERE workspace_id=%s AND application_id=%s AND job_id=%s
        ORDER BY depends_on_job_id''', (scope.workspace_id, scope.application_id, row['job_id'])).fetchall())
    # A rule unit has zero or one predecessor. Ordering therefore remains exact
    # without inventing a second dependency-order registry.
    prior = db.execute('''SELECT job_id FROM epm.application_rule_workflow_child
        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s AND unit_ordinal=%s''',
        (scope.workspace_id, scope.application_id, workflow['workflow_id'], link['unit_ordinal'] - 1)).fetchone()
    expected_dependencies = () if link['unit_ordinal'] == 1 else ((prior['job_id'],) if prior else None)
    descriptor = _job_request_descriptor(scope, VerifiedIdentity(row['issuer'], row['subject_id'],
        tuple(row['verified_groups']), issued_at=row['token_issued_at']),
        function_name=row['function_name'], program_digest=row['program_digest'],
        compiler_version=row['compiler_version'], plan_digest=row['plan_digest'],
        revisions=(row['expected_metadata_revision'], row['expected_data_revision'], row['expected_policy_revision']),
        resource_class=row['resource_class'], dependencies=dependencies,
        authorization_scope_digest=row['authorization_scope_digest'],
        verified_groups=tuple(row['verified_groups']), execution_authority=admission)
    if (dependencies != expected_dependencies
            or row['idempotency_key'] != f"rule-{workflow['workflow_id']}-{link['unit_ordinal']}"
            or _canonical_digest(descriptor) != row['request_digest']):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_PROOF_INVALID')
    return row, workflow, link


def recover_rule_child(db, scope, identity, workflow_id, ordinal, operation):
    """Verify retained exact admission; never compile or admit its effects again."""
    from .postgres_jobs import _canonical_digest
    from .postgres_access import PostgresAccessChecker
    from .postgres_dimensional_scope import resolve_effective_dimensional_scope
    workflow = _workflow(db, scope, workflow_id)
    if ((workflow['issuer'], workflow['subject_id']) != (identity.issuer, identity.subject_id)
            or _canonical_digest(_operation(workflow, ordinal)) != _canonical_digest(operation)):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_PROOF_INVALID')
    PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write')
    access = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'rule_run', function='application.rule.run')
    if (resolve_effective_dimensional_scope(db, identity, scope, access=access,
            function='application.rule.run').scope_digest != workflow['authorization_scope_digest']):
        raise ValueError('APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
    row, actual, link = _origin(db, scope, {'issuer': identity.issuer, 'subject_id': identity.subject_id,
        'idempotency_key': f'rule-{workflow_id}-{ordinal}'})
    if actual is None or actual['workflow_id'] != workflow_id or link['unit_ordinal'] != ordinal:
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_PROOF_INVALID')
    return {'jobId': row['job_id'], 'status': row['status'], 'duplicate': True}


def require_publication_origin(db, scope, job):
    row, workflow, _ = _origin(db, scope, job)
    if workflow is not None:
        from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
        from .postgres_access import durable_execution_identity, PostgresAccessChecker
        identity = durable_execution_identity(workflow)
        PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write')
        PostgresAccessChecker.check_in_transaction(db, identity, scope, 'rule_run',
            function='application.rule.run')
        PostgresApplicationRuleWorkflowStore._verify_current(db, scope, workflow)
    return row


def result_producer_status(db, scope, job, *, _budget=None):
    """Semantic owner axis; profile/scoped freshness remains a separate gate."""
    from .postgres_jobs import _canonical_digest
    from .postgres_definition_lifecycle import definition_state_axes, resolution_context
    try:
        row, workflow, link = _origin(db, scope, job, _budget=_budget)
        if workflow is None:
            return {'originKind': 'ordinary', 'matchesAtRead': True, 'producer': None, 'reason': None}
        owner = db.execute('''SELECT * FROM epm.expression_rule_definition
            WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
            (scope.workspace_id, scope.application_id, workflow['rule_id'])).fetchone()
        producer = {'kind': 'ApplicationRule', 'definitionId': workflow['rule_id'],
            'stateToken': workflow['rule_state_token'], 'programDigest': workflow['program_digest'],
            'ownerCertificateDigest': workflow['owner_certificate_digest'],
            'workflowId': workflow['workflow_id'], 'unitOrdinal': link['unit_ordinal']}
        exact = (owner is not None and owner.get('definition_kind') == 'ApplicationRule'
            and owner['state_token'] == workflow['rule_state_token']
            and owner['program_digest'] == workflow['program_digest']
            and _canonical_digest(owner['program']) == workflow['program_digest']
            and _canonical_digest(owner.get('current_certificate')) == workflow['owner_certificate_digest'])
        axes = definition_state_axes(owner, resolution_context(db, scope, [owner])) if exact else None
        valid = bool(exact and axes['resultDefinitionValid'])
        return {'originKind': 'application_rule', 'matchesAtRead': valid, 'producer': producer,
            'reason': None if valid else 'owner_changed', 'definitionStatus': axes}
    except ValueError as error:
        return {'originKind': 'unresolved', 'matchesAtRead': False, 'producer': None,
            'reason': str(error)}


def published_dependency_evidence(status):
    """Project one successful bounded walk into immutable semantic watch pins."""
    if not status['matchesAtRead'] or status.get('truncated'):
        raise ValueError('CALCULATION_PRODUCER_PIN_STALE')
    unique = {}
    for item in status.get('dependencyEvidence', []):
        producer = item.get('producerStatus')
        if (not item.get('matchesAtRead') or item.get('truncated')
                or not isinstance(producer, dict) or not producer.get('matchesAtRead')
                or producer.get('originKind') not in ('ordinary', 'application_rule')):
            raise ValueError('CALCULATION_PRODUCER_PIN_UNRESOLVED')
        pin = {key: item[key] for key in ('resultKey', 'resultStateToken', 'resultContentDigest')}
        pin.update(originKind=producer['originKind'], producer=producer.get('producer'))
        key = (pin['resultKey'], pin['resultStateToken'])
        if key in unique and unique[key] != pin:
            raise ValueError('CALCULATION_PRODUCER_EVIDENCE_INVALID')
        unique[key] = pin
    evidence = [unique[key] for key in sorted(unique)]
    validate_dependency_evidence(evidence, status['resultKey'])
    return evidence


def validate_dependency_evidence(evidence, result_key):
    """Fail closed on legacy or malformed producer watches, without adoption."""
    if type(evidence) is not list or not 1 <= len(evidence) <= 1000:
        raise ValueError('CALCULATION_PRODUCER_PIN_UNRESOLVED')
    seen = set()
    for item in evidence:
        if (type(item) is not dict
                or set(item) != {'resultKey', 'resultStateToken', 'resultContentDigest', 'originKind', 'producer'}
                or type(item['resultKey']) is not str or not item['resultKey']
                or any(type(item[field]) is not str or re.fullmatch(r'[0-9a-f]{64}', item[field]) is None
                    for field in ('resultStateToken', 'resultContentDigest'))
                or (item['resultKey'], item['resultStateToken']) in seen):
            raise ValueError('CALCULATION_PRODUCER_EVIDENCE_INVALID')
        seen.add((item['resultKey'], item['resultStateToken']))
        producer = item['producer']
        if item['originKind'] == 'ordinary' and producer is None:
            continue
        if (item['originKind'] != 'application_rule' or type(producer) is not dict
                or set(producer) != {'kind', 'definitionId', 'stateToken', 'programDigest',
                    'ownerCertificateDigest', 'workflowId', 'unitOrdinal'}
                or producer['kind'] != 'ApplicationRule'
                or type(producer['definitionId']) is not str or not producer['definitionId']
                or type(producer['workflowId']) is not str
                or re.fullmatch(r'[0-9a-f]{32}', producer['workflowId']) is None
                or type(producer['unitOrdinal']) is not int or producer['unitOrdinal'] < 1
                or any(type(producer[field]) is not str or re.fullmatch(r'[0-9a-f]{64}', producer[field]) is None
                    for field in ('stateToken', 'programDigest', 'ownerCertificateDigest'))):
            raise ValueError('CALCULATION_PRODUCER_EVIDENCE_INVALID')
    if not any(key[0] == result_key for key in seen):
        raise ValueError('CALCULATION_PRODUCER_PIN_UNRESOLVED')
