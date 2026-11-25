"""Fixed-core admission and current producer identity for durable result jobs.

A workflow name or result-key prefix never establishes ownership. The language
boundary binds the actual public operation, and the queue establishes the exact
child link atomically with its job. Legacy origin stays explicitly unresolved.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .persistence_contract import ApplicationScope
    from .postgres_python_occurrence_control import PythonOccurrenceControl
    from .python_program_execution import WorkflowRecord


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


@dataclass(frozen=True, slots=True)
class PythonPlanAdmission:
    """Ephemeral public-operation proof; durable authority stays unchanged."""
    python_workflow_id: str
    delegation_id: str
    delegation_state_token: str
    schedule_id: str | None
    schedule_state_token: str | None
    workspace_id: str
    application_id: str
    issuer: str
    subject_id: str
    function_name: str
    public_operation_digest: str

    def descriptor(self):
        return {**self.legacy_descriptor(),
            'public_operation_digest':self.public_operation_digest}

    def legacy_descriptor(self):
        return {key:getattr(self,key) for key in _PYTHON_KEYS}


_RULE_KEYS = frozenset(('application_rule_workflow_id', 'unit_ordinal',
    'sealed_plan_digest', 'public_operation_digest', 'owner_certificate_digest'))
_PYTHON_KEYS = frozenset(('python_workflow_id','delegation_id',
    'delegation_state_token','schedule_id','schedule_state_token'))


def bind_public_operation(authority, scope, identity, program):
    """Mint a typed private admission only at the actual V2 operation boundary."""
    if type(authority) is dict and _PYTHON_KEYS & set(authority):
        from .postgres_jobs import _canonical_digest
        from .postgres_capability_contract import assert_source_job_purpose
        if set(authority)!=_PYTHON_KEYS or type(program) is not dict:
            raise ValueError('PYTHON_JOB_EXECUTION_AUTHORITY_INVALID')
        assert_source_job_purpose(program.get('function'))
        return PythonPlanAdmission(**authority,workspace_id=scope.workspace_id,
            application_id=scope.application_id,issuer=identity.issuer,
            subject_id=identity.subject_id,function_name=program['function'],
            public_operation_digest=_canonical_digest(program))
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
    return authority.descriptor() if isinstance(authority,
        (ApplicationRuleAdmission,PythonPlanAdmission)) else authority


def matches_retained_request(digest,descriptor,authority):
    """Owner-compiled replay may retain an accepted pre-binding Python hash.

    Callers must already construct the descriptor from their exact normalized
    operation, not merely copy a retained payload. This never proves an
    uncompiled old tail's relationship to a public unit.
    """
    from .postgres_jobs import _canonical_digest
    if _canonical_digest(descriptor)==digest:return True
    return (isinstance(authority,PythonPlanAdmission)
        and _canonical_digest({**descriptor,
            'executionAuthority':authority.legacy_descriptor()})==digest)


def _python_workflow(db,scope,workflow_id,*,_for_admission=False):
    row=db.execute('''SELECT w.*,a.canonical_plan,a.plan_digest,
        a.compiler_version,b.delegation_id,b.delegation_state_token,
        b.schedule_id,b.schedule_state_token
        FROM epm.python_program_workflow w
        JOIN epm.python_plan_artifact a USING(workspace_id,application_id,build_id)
        JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
        WHERE w.workspace_id=%s AND w.application_id=%s AND w.workflow_id=%s
          AND b.purpose='Plan' AND b.status='sealed'
          AND (b.issuer,b.subject_id)=(w.issuer,w.subject_id)'''
        + (' FOR UPDATE OF w' if _for_admission else ''),
        (scope.workspace_id,scope.application_id,workflow_id)).fetchone()
    if row is None:raise ValueError('PYTHON_WORKFLOW_UNAVAILABLE')
    return row


def _python_unit(row,ordinal):
    from .postgres_python_workflow import PostgresPythonWorkflowStore,_record
    from .python_plan_runner import SealedPlanRunner
    from .postgres_capability_contract import assert_source_plan_purpose
    record=_record(row)
    plan=PostgresPythonWorkflowStore._stored_plan(row)
    if record.plan_digest!=plan.digest or record.unit_count!=plan.unit_count:
        raise ValueError('PYTHON_WORKFLOW_PLAN_MISMATCH')
    assert_source_plan_purpose(plan.canonical_plan,allow_definition=False)
    units=SealedPlanRunner._units(plan)
    if type(ordinal) is not int or not 1<=ordinal<=len(units):
        raise ValueError('PYTHON_WORKFLOW_CHILD_RECOVERY_INVALID')
    return SealedPlanRunner._atomic_operation(units[ordinal-1])


def verify_python_admission(db,scope,identity,admission,*,function_name,
                            idempotency_key,dependencies):
    """Hold the exact parent row through insertion, serializing cancellation.

    The queue already holds application_state; workspace security locks are
    shared and do not serialize ordinary child admission against cancellation.
    """
    from .postgres_jobs import _canonical_digest
    from .postgres_python_workflow import PostgresPythonWorkflowStore,_record
    from .python_program_execution import WorkflowStatus
    if (not isinstance(admission,PythonPlanAdmission)
            or (admission.workspace_id,admission.application_id,admission.issuer,
                admission.subject_id,admission.function_name)!=(scope.workspace_id,
                scope.application_id,identity.issuer,identity.subject_id,function_name)):
        raise ValueError('PYTHON_JOB_PUBLIC_OPERATION_REQUIRED')
    row=_python_workflow(db,scope,admission.python_workflow_id,_for_admission=True)
    current=_record(row);ordinal=len(current.checkpoints)+1
    authority=admission.legacy_descriptor()
    if ((row['issuer'],row['subject_id'])!=(identity.issuer,identity.subject_id)
            or current.status!=WorkflowStatus.RUNNING
            or any(not item.committed for item in current.checkpoints)
            or idempotency_key!=f'py-{current.workflow_id}-{ordinal}'
            or dependencies!=(() if not current.checkpoints else (current.checkpoints[-1].job_id,))
            or any(authority[key]!=row[key] for key in _PYTHON_KEYS-{'python_workflow_id'})):
        raise ValueError('PYTHON_JOB_EXECUTION_AUTHORITY_INVALID')
    operation=_python_unit(row,ordinal)
    if (operation['function']!=function_name
            or _canonical_digest(operation)!=admission.public_operation_digest):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    store=PostgresPythonWorkflowStore('existing-transaction',identity=identity)
    access=store._authorize_bound_run(db,scope,current.build_id)
    store._assert_workflow_authorization_scope(db,scope,current.workflow_id,access=access)


def recover_python_cancellation_child(db,scope,identity,workflow,*,ordinal,operation):
    """Read exact retained proof; flag pre-binding rows for native-owner replay."""
    from .postgres_python_workflow import PostgresPythonWorkflowStore,_record
    from .postgres_access import PostgresAccessChecker
    from .postgres_jobs import (_canonical_digest,_job_request_descriptor,
        _verify_job_replay_authorization)
    from .python_program_execution import WorkflowStatus
    row=_python_workflow(db,scope,workflow.workflow_id)
    if ((row['issuer'],row['subject_id'])!=(identity.issuer,identity.subject_id)
            or _record(row)!=workflow or workflow.status!=WorkflowStatus.CANCEL_REQUESTED
            or ordinal!=len(workflow.checkpoints)+1
            or any(not point.committed for point in workflow.checkpoints)):
        raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
    actual=_python_unit(row,ordinal)
    if _canonical_digest(actual)!=_canonical_digest(operation):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    store=PostgresPythonWorkflowStore('existing-transaction',identity=identity)
    access=PostgresAccessChecker.check_in_transaction(db,identity,scope,
        'rule_run',function='python.program.run',arguments={'buildId':workflow.build_id})
    store._assert_workflow_authorization_scope(db,scope,workflow.workflow_id,access=access)
    key=f'py-{workflow.workflow_id}-{ordinal}'
    job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
        AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
        (scope.workspace_id,scope.application_id,identity.issuer,identity.subject_id,key)).fetchone()
    if job is None:return None
    authority={name:row[name] for name in _PYTHON_KEYS-{'python_workflow_id'}}
    authority['python_workflow_id']=workflow.workflow_id
    if (job['python_workflow_id']!=workflow.workflow_id
            or job['function_name']!=actual['function']
            or any(job['execution_'+field]!=authority[field] for field in
                ('delegation_id','delegation_state_token','schedule_id','schedule_state_token'))
            or _canonical_digest(job['normalized_program'])!=job['program_digest']):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    dependencies=tuple(item['depends_on_job_id'] for item in db.execute('''SELECT depends_on_job_id
        FROM epm.job_dependency WHERE workspace_id=%s AND application_id=%s AND job_id=%s
        ORDER BY depends_on_job_id''',(scope.workspace_id,scope.application_id,job['job_id'])).fetchall())
    if dependencies!=(() if not workflow.checkpoints else (workflow.checkpoints[-1].job_id,)):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    child_access=PostgresAccessChecker.check_in_transaction(db,identity,scope,'write',
        function=actual['function'],arguments=job['normalized_program'])
    auth_scope=_verify_job_replay_authorization(db,scope,identity,job,access=child_access,
        function_name=actual['function'])
    bound=bind_public_operation(authority,scope,identity,actual)
    descriptor=_job_request_descriptor(scope,identity,function_name=actual['function'],
        program_digest=job['program_digest'],compiler_version=job['compiler_version'],
        plan_digest=job['plan_digest'],revisions=tuple(job['expected_'+key]
            for key in ('metadata_revision','data_revision','policy_revision')),
        resource_class=job['resource_class'],dependencies=dependencies,
        authorization_scope_digest=auth_scope,verified_groups=child_access.groups,
        execution_authority=bound)
    descriptor['tokenIssuedAt']=job['token_issued_at']
    current_proof=_canonical_digest(descriptor)==job['request_digest']
    if not current_proof and _canonical_digest({**descriptor,
            'executionAuthority':authority})!=job['request_digest']:
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    # Current actor/control rights authorize observation and cancellation. The
    # original source need not remain executable to read its retained receipt.
    return {'jobId':job['job_id'],'currentProof':current_proof,
        'authority':authority,'dependencies':dependencies,'key':key}


@dataclass(frozen=True, slots=True)
class PythonControlProof:
    """Transaction-local validated parent/plan; never an execution authority."""
    scope: ApplicationScope
    control: PythonOccurrenceControl
    row: dict
    workflow: WorkflowRecord
    units: tuple[dict, ...]

    def operation(self, ordinal):
        from .python_plan_runner import SealedPlanRunner
        if type(ordinal) is not int or not 1 <= ordinal <= len(self.units):
            raise ValueError('PYTHON_WORKFLOW_CHILD_RECOVERY_INVALID')
        return SealedPlanRunner._atomic_operation(self.units[ordinal-1])


def python_control_proof(scope, control, row, workflow, plan):
    """Reuse the once-authorized/locked native owner's validated plan.

    The caller is the existing occurrence-control owner and holds the parent
    fence. The shared fixed runner remains the unit-shape owner. Its bounded
    linear validation is not repeated for each retained checkpoint.
    """
    from .postgres_python_workflow import _record
    from .python_plan_runner import SealedPlanRunner
    from .postgres_capability_contract import assert_source_plan_purpose
    if ((row['workspace_id'],row['application_id']) !=
            (scope.workspace_id,scope.application_id) or _record(row) != workflow
            or workflow.plan_digest != plan.digest or workflow.unit_count != plan.unit_count):
        raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
    assert_source_plan_purpose(plan.canonical_plan,allow_definition=False)
    units=tuple(SealedPlanRunner._units(plan))
    return PythonControlProof(scope,control,row,workflow,units)


def retained_python_control_prefix(db, proof):
    """Audit immutable native child links/receipts in one compact scoped query.

    The native checkpoint publisher inserts each child link with its checkpoint
    in one transaction. Links have scoped parent/job FKs and unique ordinals;
    callers cannot replace a prefix. We audit those actual persisted links and
    receipts rather than rehash every immutable job request on every quantum.
    Only the pending/recovered tail needs the full original request proof.
    """
    scope,workflow=proof.scope,proof.workflow
    points=workflow.checkpoints
    if any(not point.committed for point in points[:-1]):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    children=db.execute('''WITH selected AS MATERIALIZED (
        SELECT unit_ordinal,job_id FROM epm.python_program_workflow_child
        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s
        ORDER BY unit_ordinal LIMIT %s), dependencies AS (
        SELECT d.job_id,count(*) AS dependency_count,min(d.depends_on_job_id) AS predecessor
        FROM epm.job_dependency d JOIN selected c ON c.job_id=d.job_id
        WHERE d.workspace_id=%s AND d.application_id=%s GROUP BY d.job_id)
        SELECT c.unit_ordinal,c.job_id,j.job_id AS actual_job_id,j.function_name,
            j.status,j.receipt_revision,j.program_digest,
            (j.issuer=w.issuer AND j.subject_id=w.subject_id
             AND j.verified_groups=w.verified_groups
             AND j.authorization_scope_digest=w.authorization_scope_digest
             AND j.token_issued_at IS NOT DISTINCT FROM w.token_issued_at
             AND j.authority_kind IS NOT DISTINCT FROM w.authority_kind
             AND j.python_workflow_id=w.workflow_id
             AND j.idempotency_key='py-'||w.workflow_id||'-'||c.unit_ordinal::text
             AND j.execution_delegation_id IS NOT DISTINCT FROM b.delegation_id
             AND j.execution_delegation_state_token IS NOT DISTINCT FROM b.delegation_state_token
             AND j.execution_schedule_id IS NOT DISTINCT FROM b.schedule_id
             AND j.execution_schedule_state_token IS NOT DISTINCT FROM b.schedule_state_token
            ) AS original_binding_matches,
            COALESCE(d.dependency_count,0) AS dependency_count,d.predecessor,
            r.operation_id AS actual_receipt_id,r.committed_revision AS actual_receipt_revision,
            r.command_digest AS actual_receipt_digest,(r.actor_id=w.subject_id) AS receipt_actor_matches
        FROM selected c
        JOIN epm.python_program_workflow w ON w.workspace_id=%s AND w.application_id=%s
            AND w.workflow_id=%s
        JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
        LEFT JOIN epm.job j ON (j.workspace_id,j.application_id,j.job_id)=
            (w.workspace_id,w.application_id,c.job_id)
        LEFT JOIN epm.operation_receipt r ON (r.workspace_id,r.application_id,r.operation_id)=
            (j.workspace_id,j.application_id,j.job_id)
        LEFT JOIN dependencies d ON d.job_id=c.job_id
        ORDER BY c.unit_ordinal''',
        (scope.workspace_id,scope.application_id,workflow.workflow_id,len(points)+1,
         scope.workspace_id,scope.application_id,scope.workspace_id,scope.application_id,
         workflow.workflow_id)).fetchall()
    if len(children)!=len(points):raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    for point,child in zip(points,children,strict=True):
        previous=points[point.ordinal-2].job_id if point.ordinal>1 else None
        if ((child['unit_ordinal'],child['job_id'],child['actual_job_id']) !=
                (point.ordinal,point.job_id,point.job_id)
                or child['function_name']!=proof.operation(point.ordinal)['function']
                or child['original_binding_matches'] is not True
                or child['dependency_count']!=(0 if previous is None else 1)
                or child['predecessor']!=previous):
            raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
        if point.committed and (point.receipt_id!=point.job_id
                or child['status']!='published'
                or type(child['receipt_revision']) is not int
                or child['actual_receipt_id']!=point.job_id
                or child['actual_receipt_revision']!=child['receipt_revision']
                or child['actual_receipt_digest']!=child['program_digest']
                or child['receipt_actor_matches'] is not True):
            raise ValueError('WORKFLOW_CANCELLATION_CHILD_UNRESOLVED')
    return children


def python_control_child(db,scope,control,workflow,*,ordinal,operation,_proof=None):
    """Prove one original child without borrowing its execution permission.

    The current administrator controls the exact linked parent. Retained actor
    fields are used only to reconstruct the immutable request hash. Unbound
    legacy operations remain unresolved; this path never compiles or admits.
    """
    from .postgres_python_occurrence_control import authorize_control,verify_child_link
    from .postgres_access import durable_execution_identity
    from .postgres_jobs import _canonical_digest,_job_request_descriptor
    from .postgres_python_workflow import _record
    if _proof is None:
        occurrence,_=authorize_control(db,scope,control)
        row=_python_workflow(db,scope,workflow.workflow_id)
        verify_child_link(occurrence,row,family='workflow')
        if _record(row)!=workflow:
            raise ValueError('PYTHON_WORKFLOW_STALE_CONTROL_STATE')
        from .postgres_python_workflow import PostgresPythonWorkflowStore
        _proof=python_control_proof(scope,control,row,workflow,
            PostgresPythonWorkflowStore._stored_plan(row))
    elif (not isinstance(_proof,PythonControlProof) or _proof.scope!=scope
            or _proof.control is not control or _proof.workflow!=workflow):
        raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
    row=_proof.row
    actual=_proof.operation(ordinal)
    if _canonical_digest(actual)!=_canonical_digest(operation):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    key=f'py-{workflow.workflow_id}-{ordinal}'
    job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
        AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s''',
        (scope.workspace_id,scope.application_id,row['issuer'],row['subject_id'],key)).fetchone()
    if job is None:return None
    authority={name:row[name] for name in _PYTHON_KEYS-{'python_workflow_id'}}
    authority['python_workflow_id']=workflow.workflow_id
    if (job['python_workflow_id']!=workflow.workflow_id
            or job['function_name']!=actual['function']
            or any(job['execution_'+field]!=authority[field] for field in
                ('delegation_id','delegation_state_token','schedule_id','schedule_state_token'))
            or _canonical_digest(job['normalized_program'])!=job['program_digest']):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    dependencies=tuple(r['depends_on_job_id'] for r in db.execute('''SELECT depends_on_job_id
        FROM epm.job_dependency WHERE workspace_id=%s AND application_id=%s AND job_id=%s
        ORDER BY depends_on_job_id''',(scope.workspace_id,scope.application_id,job['job_id'])).fetchall())
    previous=workflow.checkpoints[ordinal-2].job_id if ordinal>1 and len(workflow.checkpoints)>=ordinal-1 else None
    if dependencies!=(() if previous is None else (previous,)):
        raise ValueError('PYTHON_WORKFLOW_CHILD_CONFLICT')
    original=durable_execution_identity(job)
    bound=bind_public_operation(authority,scope,original,actual)
    descriptor=_job_request_descriptor(scope,original,function_name=actual['function'],
        program_digest=job['program_digest'],compiler_version=job['compiler_version'],
        plan_digest=job['plan_digest'],revisions=tuple(job['expected_'+k]
            for k in ('metadata_revision','data_revision','policy_revision')),
        resource_class=job['resource_class'],dependencies=dependencies,
        authorization_scope_digest=job['authorization_scope_digest'],
        verified_groups=tuple(job['verified_groups']),execution_authority=bound)
    descriptor['tokenIssuedAt']=job['token_issued_at']
    if _canonical_digest(descriptor)!=job['request_digest']:
        raise ValueError('WORKFLOW_CANCELLATION_CHILD_PROOF_UNAVAILABLE')
    if job['status']=='published':
        receipt=db.execute('''SELECT operation_id,committed_revision,command_digest,actor_id
            FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
            AND operation_id=%s''',(scope.workspace_id,scope.application_id,job['job_id'])).fetchone()
        if (receipt is None or type(job['receipt_revision']) is not int
                or receipt['operation_id']!=job['job_id']
                or receipt['committed_revision']!=job['receipt_revision']
                or receipt['command_digest']!=job['program_digest']
                or receipt['actor_id']!=job['subject_id']):
            raise ValueError('WORKFLOW_CANCELLATION_CHILD_UNRESOLVED')
    return job


def _workflow(db, scope, workflow_id, *, _for_admission=False):
    row = db.execute('''SELECT * FROM epm.application_rule_workflow
        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s'''
        + (' FOR UPDATE' if _for_admission else ''),
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
    """Recheck and lock the parent after the queue application-state lock.

    This row lock, not the shared workspace security lock, orders admission
    against both direct and task-controller parent cancellation.
    """
    from .postgres_jobs import _canonical_digest
    from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
    from .postgres_access import PostgresAccessChecker
    from .postgres_dimensional_scope import resolve_effective_dimensional_scope
    if (not isinstance(admission, ApplicationRuleAdmission)
            or (admission.workspace_id, admission.application_id, admission.issuer, admission.subject_id,
                admission.function_name) != (scope.workspace_id, scope.application_id,
                    identity.issuer, identity.subject_id, function_name)):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_INVALID')
    row = _workflow(db, scope, admission.application_rule_workflow_id, _for_admission=True)
    if ((row['issuer'], row['subject_id']) != (identity.issuer, identity.subject_id)
            or row['plan_digest'] != admission.sealed_plan_digest
            or row.get('owner_certificate_digest') != admission.owner_certificate_digest
            or idempotency_key != f"rule-{row['workflow_id']}-{admission.unit_ordinal}"
            or row['status'] != 'running'):
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_INVALID')
    PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write',action='facts.write')
    access = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'rule_run',
        function='application.rule.run')
    current_scope = resolve_effective_dimensional_scope(db, identity, scope,
        access=access, function='application.rule.run').scope_digest
    if current_scope != row.get('authorization_scope_digest'):
        raise ValueError('APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
    PostgresApplicationRuleWorkflowStore._verify_current(db, scope, row)
    require_rule_execution_authority(db, scope, row)
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
    PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write',action='facts.write')
    access = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'rule_run', function='application.rule.run')
    if (resolve_effective_dimensional_scope(db, identity, scope, access=access,
            function='application.rule.run').scope_digest != workflow['authorization_scope_digest']):
        raise ValueError('APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
    row, actual, link = _origin(db, scope, {'issuer': identity.issuer, 'subject_id': identity.subject_id,
        'idempotency_key': f'rule-{workflow_id}-{ordinal}'})
    if actual is None or actual['workflow_id'] != workflow_id or link['unit_ordinal'] != ordinal:
        raise ValueError('APPLICATION_RULE_JOB_ADMISSION_PROOF_INVALID')
    return {'jobId': row['job_id'], 'status': row['status'], 'duplicate': True}


def require_publication_origin(db, scope, job, *, for_effect=True):
    row, workflow, _ = _origin(db, scope, job)
    if workflow is not None:
        from .postgres_application_rule_workflow import PostgresApplicationRuleWorkflowStore
        from .postgres_access import durable_execution_identity, PostgresAccessChecker
        identity = durable_execution_identity(workflow)
        PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write',action='facts.write')
        access = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'rule_run',
            function='application.rule.run')
        # Exact lookup proves the original immutable request under current
        # grants/scope. Mutable executable eligibility is only an effect gate.
        from .postgres_dimensional_scope import resolve_effective_dimensional_scope
        if (resolve_effective_dimensional_scope(db, identity, scope, access=access,
                function='application.rule.run').scope_digest != workflow['authorization_scope_digest']):
            raise ValueError('APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED')
        if for_effect:
            if workflow['status'] not in ('running','cancel_requested'):
                raise ValueError('APPLICATION_RULE_WORKFLOW_PARENT_CLOSED')
            PostgresApplicationRuleWorkflowStore._verify_current(db, scope, workflow)
            require_rule_execution_authority(db, scope, workflow)
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


# Generic scheduled Rule authority is retained by its immutable parent.
# This helper never infers an origin from an idempotency-key prefix.
_SCHEDULE_AUTHORITY_KEYS = frozenset(('occurrenceId', 'scheduleId',
    'scheduleStateToken', 'delegationId', 'delegationStateToken'))


def _schedule_authority(value):
    if (type(value) is not dict or set(value) != _SCHEDULE_AUTHORITY_KEYS
            or type(value['occurrenceId']) is not str
            or re.fullmatch(r'[0-9a-f]{32}', value['occurrenceId']) is None
            or type(value['scheduleId']) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,199}', value['scheduleId']) is None
            or type(value['delegationId']) is not str
            or re.fullmatch(r'[A-Za-z0-9._-]{1,200}', value['delegationId']) is None
            or any(type(value[key]) is not str
                or re.fullmatch(r'[0-9a-f]{64}', value[key]) is None
                for key in ('scheduleStateToken', 'delegationStateToken'))):
        raise ValueError('APPLICATION_RULE_SCHEDULE_AUTHORITY_INVALID')
    return dict(value)


def _retained_rule_pin(row):
    """Rebuild only the persisted pin, never current source metadata."""
    from .postgres_jobs import _canonical_digest
    result = row['result']
    keys = ('bindings', 'bindingDigest', 'bindingRequestDigest', 'argumentsDigest')
    if (type(result) is not dict or not set(keys) <= set(result)
            or type(result['bindings']) is not dict
            or _canonical_digest(result['bindings']) != result['bindingDigest']):
        raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED')
    return {'ruleId': row['rule_id'], 'stateToken': row['rule_state_token'],
        'programDigest': row['program_digest'],
        'metadataRevision': row['expected_metadata_revision'],
        'policyRevision': row['expected_policy_revision'],
        'schemaEpoch': row['expected_schema_epoch'],
        'owner_certificate_digest': row['owner_certificate_digest'],
        **{key: result[key] for key in keys},
        **({'memberListPins': result['memberListPins']} if 'memberListPins' in result else {})}


def _scheduled_rule_rows(db, scope, workflow_id):
    # Two rows suffice to refuse an ambiguous inherited link. The migration
    # supplies a scoped index; unrelated applications are never enumerated.
    return db.execute('''SELECT o.occurrence_id,o.schedule_id,
        o.schedule_state_token,o.due_at,o.application_rule_workflow_id,
        s.definition,s.definition_digest,s.rule_id,s.rule_state_token,
        s.rule_program_digest,s.execution_issuer,s.execution_subject,
        s.execution_groups,s.authorization_scope_digest,s.execution_token_issued_at,
        s.execution_authority_kind,s.delegation_id,s.delegation_state_token,
        s.status AS schedule_status
        FROM epm.application_schedule_occurrence o
        LEFT JOIN epm.application_schedule_definition s
          ON (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
             (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
        WHERE o.workspace_id=%s AND o.application_id=%s
          AND o.application_rule_workflow_id=%s
        ORDER BY o.occurrence_id LIMIT 2''',
        (scope.workspace_id, scope.application_id, workflow_id)).fetchall()


def _validate_linked_schedule(scope, workflow, schedule, authority):
    """Validate a retained matching schedule, without substituting new pins."""
    from .application_schedule import canonical_digest, execution_bindings, validate_definition
    from .postgres_application_schedules import _occurrence_id
    from .postgres_jobs import _canonical_digest
    if schedule['definition'] is None:
        raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED')
    definition = validate_definition(schedule['definition'])
    bindings = execution_bindings(definition)
    pin = _retained_rule_pin(workflow)
    if (workflow['idempotency_key'] != 'schedule-rule-' + schedule['occurrence_id']
            or authority != _schedule_authority({
                'occurrenceId': schedule['occurrence_id'], 'scheduleId': schedule['schedule_id'],
                'scheduleStateToken': schedule['schedule_state_token'],
                'delegationId': schedule['delegation_id'],
                'delegationStateToken': schedule['delegation_state_token']})
            or definition['scheduleId'] != schedule['schedule_id']
            or definition['delegation'] != {'delegationId': authority['delegationId'],
                'stateToken': authority['delegationStateToken']}
            or canonical_digest(definition) != schedule['definition_digest']
            or (schedule['execution_issuer'], schedule['execution_subject']) !=
               (workflow['issuer'], workflow['subject_id'])
            or tuple(schedule['execution_groups']) != tuple(workflow['verified_groups'])
            or schedule['authorization_scope_digest'] != workflow['authorization_scope_digest']
            or (schedule['execution_token_issued_at'], schedule['execution_authority_kind']) !=
               (workflow['token_issued_at'], workflow['authority_kind'])
            or (schedule['rule_id'], schedule['rule_state_token'], schedule['rule_program_digest']) !=
               (workflow['rule_id'], workflow['rule_state_token'], workflow['program_digest'])
            or (definition['target']['ruleId'], definition['target']['stateToken'],
                definition['target']['programDigest']) !=
               (workflow['rule_id'], workflow['rule_state_token'], workflow['program_digest'])
            or _canonical_digest(bindings) != pin['bindingRequestDigest']
            or _canonical_digest({'ruleId': workflow['rule_id'], 'bindings': bindings}) != pin['argumentsDigest']
            or _occurrence_id(scope, schedule['schedule_id'], schedule['schedule_state_token'],
                schedule['due_at'], schema_epoch=workflow['expected_schema_epoch']) != schedule['occurrence_id']):
        raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_INVALID')


def retained_rule_execution_origin(db, scope, workflow):
    """Prove original origin separately from current effect eligibility.

    New scheduled origin survives later definition replacement as an immutable
    fact. Old unlinked work stays unresolved; key shape is never origin proof.
    Completed outcome reads do not need this effect gate.
    """
    from .postgres_application_rules import SealedApplicationRule
    from .postgres_application_rule_workflow import (
        PostgresApplicationRuleWorkflowStore, rule_workflow_request_digest)
    from .postgres_access import durable_execution_identity
    kind = workflow.get('execution_origin_kind')
    if kind not in ('direct', 'scheduled', 'legacy_unresolved'):
        raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED')
    links = _scheduled_rule_rows(db, scope, workflow['workflow_id'])
    if kind == 'direct':
        if workflow.get('schedule_authority') is not None or links:
            raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_INVALID')
        return {'kind': 'direct', 'scheduleAuthority': None}
    if len(links) != 1:
        raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED')
    schedule = links[0]
    if kind == 'scheduled':
        authority = _schedule_authority(workflow.get('schedule_authority'))
        if (authority['occurrenceId'], authority['scheduleId'], authority['scheduleStateToken']) != (
                schedule['occurrence_id'], schedule['schedule_id'], schedule['schedule_state_token']):
            raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_INVALID')
    else:
        if workflow.get('schedule_authority') is not None or schedule['definition'] is None:
            raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_UNRESOLVED')
        authority = _schedule_authority({
            'occurrenceId': schedule['occurrence_id'], 'scheduleId': schedule['schedule_id'],
            'scheduleStateToken': schedule['schedule_state_token'],
            'delegationId': schedule['delegation_id'],
            'delegationStateToken': schedule['delegation_state_token']})
        _validate_linked_schedule(scope, workflow, schedule, authority)
    pin = _retained_rule_pin(workflow)
    plan = PostgresApplicationRuleWorkflowStore._stored_plan(workflow)
    sealed = SealedApplicationRule(plan, pin)
    digest = rule_workflow_request_digest(scope, durable_execution_identity(workflow),
        workflow['idempotency_key'], sealed,
        **({'execution_origin': {'kind': 'scheduled', 'scheduleAuthority': authority}}
            if kind == 'scheduled' else {}))
    if digest != workflow['request_digest']:
        raise ValueError('APPLICATION_RULE_EXECUTION_ORIGIN_INVALID')
    return {'kind': 'scheduled', 'scheduleAuthority': authority,
        'legacyProof': kind == 'legacy_unresolved'}


def require_rule_execution_authority(db, scope, workflow):
    """Effect gate under the existing application-state transaction fence.

    No parent/occurrence row lock is acquired after a publisher's job lock.
    Immutable receipt lookup remains separate from fresh effect eligibility.
    """
    from .postgres_access import AccessDenied
    origin = retained_rule_execution_origin(db, scope, workflow)
    if origin['kind'] == 'direct':
        return origin
    authority = origin['scheduleAuthority']
    links = _scheduled_rule_rows(db, scope, workflow['workflow_id'])
    if len(links) != 1 or links[0]['schedule_status'] != 'Active':
        raise AccessDenied('APPLICATION_RULE_SCHEDULE_AUTHORITY_UNAVAILABLE')
    try:
        _validate_linked_schedule(scope, workflow, links[0], authority)
    except ValueError as error:
        raise AccessDenied('APPLICATION_RULE_SCHEDULE_AUTHORITY_UNAVAILABLE') from error
    allowed = db.execute('''SELECT epm.execution_delegation_is_current(
        %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',
        (scope.workspace_id, scope.application_id, authority['delegationId'],
         authority['delegationStateToken'], workflow['issuer'], workflow['subject_id'],
         'application.rule.run', authority['scheduleId'])).fetchone()
    if allowed is None or allowed['allowed'] is not True:
        raise AccessDenied('APPLICATION_RULE_SCHEDULE_AUTHORITY_UNAVAILABLE')
    return origin


@dataclass(frozen=True, slots=True)
class ScheduledRuleAdmission:
    """Private occurrence claim. Public Rule programs cannot supply this."""
    occurrence_id: str
    schedule_id: str
    schedule_state_token: str
    delegation_id: str
    delegation_state_token: str
    claim_generation: int
    claimant: str
    schema_epoch: int

    def authority(self):
        if (type(self.claim_generation) is not int or self.claim_generation < 1
                or type(self.claimant) is not str or not 1 <= len(self.claimant) <= 200
                or type(self.schema_epoch) is not int or self.schema_epoch < 0):
            raise ValueError('APPLICATION_RULE_SCHEDULE_ADMISSION_INVALID')
        return _schedule_authority({'occurrenceId': self.occurrence_id,
            'scheduleId': self.schedule_id, 'scheduleStateToken': self.schedule_state_token,
            'delegationId': self.delegation_id,
            'delegationStateToken': self.delegation_state_token})


def prepare_scheduled_rule_admission(db, scope, identity, admission, *,
        rule_id, rule_state_token, program_digest, binding_request_digest,
        verified_groups, authorization_scope_digest):
    """Validate the exact claim after the caller locks application_state.

    The row lock lasts through parent INSERT and occurrence link. Sealing is
    completed before this short transaction, never under the mutation fence.
    """
    from .application_schedule import canonical_digest, execution_bindings, validate_definition
    from .postgres_application_schedules import PostgresApplicationSchedules, _occurrence_id
    from .postgres_access import AccessDenied, durable_authority_fields
    from .postgres_jobs import _canonical_digest
    if not isinstance(admission, ScheduledRuleAdmission):
        raise ValueError('APPLICATION_RULE_SCHEDULE_ADMISSION_INVALID')
    authority = admission.authority()
    row = db.execute('''SELECT o.*,s.definition,s.definition_digest,
        s.execution_issuer,s.execution_subject,s.execution_groups,
        s.execution_token_issued_at,s.execution_authority_kind,
        s.authorization_scope_digest,s.delegation_id,s.delegation_state_token,
        s.rule_id,s.rule_state_token,s.rule_program_digest,
        state.schema_epoch, o.lease_until>clock_timestamp() AS claim_live
        FROM epm.application_schedule_occurrence o
        JOIN epm.application_schedule_definition s
          ON (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
             (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
        JOIN epm.application_state state ON
          (state.workspace_id,state.application_id)=(o.workspace_id,o.application_id)
        WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s
          AND s.status='Active' AND state.processing_mode='Active'
        FOR UPDATE OF o''',
        (scope.workspace_id, scope.application_id, admission.occurrence_id)).fetchone()
    if (row is None or row['status'] != 'running'
            or row['application_rule_workflow_id'] is not None
            or row['claim_generation'] != admission.claim_generation
            or row['claimant'] != admission.claimant or row['claim_live'] is not True
            or row['schema_epoch'] != admission.schema_epoch
            or (row['schedule_id'], row['schedule_state_token'], row['delegation_id'],
                row['delegation_state_token']) !=
               (admission.schedule_id, admission.schedule_state_token,
                admission.delegation_id, admission.delegation_state_token)
            or (row['execution_issuer'], row['execution_subject']) !=
               (identity.issuer, identity.subject_id)
            or tuple(row['execution_groups']) != tuple(verified_groups)
            or tuple(row['execution_groups']) != tuple(identity.groups)
            or row['authorization_scope_digest'] != authorization_scope_digest
            or (row['execution_token_issued_at'], row['execution_authority_kind']) !=
               durable_authority_fields(identity)
            or (row['rule_id'], row['rule_state_token'], row['rule_program_digest']) !=
               (rule_id, rule_state_token, program_digest)):
        raise ValueError('APPLICATION_RULE_SCHEDULE_ADMISSION_INVALID')
    definition = validate_definition(row['definition'])
    if (canonical_digest(definition) != row['definition_digest']
            or definition['scheduleId'] != admission.schedule_id
            or definition['delegation'] != {'delegationId': admission.delegation_id,
                'stateToken': admission.delegation_state_token}
            or (definition['target']['ruleId'], definition['target']['stateToken'],
                definition['target']['programDigest']) !=
               (rule_id, rule_state_token, program_digest)
            or _canonical_digest(execution_bindings(definition)) != binding_request_digest
            or _occurrence_id(scope, admission.schedule_id, admission.schedule_state_token,
                row['due_at'], schema_epoch=admission.schema_epoch) != admission.occurrence_id):
        raise ValueError('APPLICATION_RULE_SCHEDULE_ADMISSION_INVALID')
    PostgresApplicationSchedules._assert_authorization_scope(db, scope, row,
        function='application.rule.run')
    allowed = db.execute('''SELECT epm.execution_delegation_is_current(
        %s,%s,%s,%s,%s,%s,%s,%s) AS allowed''',
        (scope.workspace_id, scope.application_id, admission.delegation_id,
         admission.delegation_state_token, identity.issuer, identity.subject_id,
         'application.rule.run', admission.schedule_id)).fetchone()
    if allowed is None or allowed['allowed'] is not True:
        raise AccessDenied('APPLICATION_RULE_SCHEDULE_AUTHORITY_UNAVAILABLE')
    return authority


def link_scheduled_rule_admission(db, scope, admission, workflow_id):
    """Complete the original parent admission before optional eager advance."""
    changed = db.execute('''UPDATE epm.application_schedule_occurrence
        SET application_rule_workflow_id=%s,updated_at=transaction_timestamp()
        WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
          AND application_rule_workflow_id IS NULL AND status='running'
          AND claim_generation=%s AND claimant=%s
          AND lease_until>clock_timestamp()''',
        (workflow_id, scope.workspace_id, scope.application_id,
         admission.occurrence_id, admission.claim_generation, admission.claimant)).rowcount
    if changed != 1:
        raise ValueError('APPLICATION_SCHEDULE_OCCURRENCE_STALE_CLAIM')


def schedule_control_parent(db, scope, occurrence):
    """Resolve an already identified parent for control, never fresh execution.

    Current owner/admin authorization remains the existing controller's job.
    No source/delegation eligibility is needed to account for or stop known work.
    A missing FK is not repaired by looking up a similarly shaped key.
    """
    workflow_id = occurrence.get('application_rule_workflow_id')
    if workflow_id is None:
        return None
    parent = db.execute('''SELECT * FROM epm.application_rule_workflow
        WHERE workspace_id=%s AND application_id=%s AND workflow_id=%s''',
        (scope.workspace_id, scope.application_id, workflow_id)).fetchone()
    task = db.execute('''SELECT issuer,subject_id FROM epm.task
        WHERE workspace_id=%s AND application_id=%s AND task_id=%s
          AND source_family='ApplicationScheduleOccurrence' AND source_id=%s''',
        (scope.workspace_id, scope.application_id, 'v:' + occurrence['occurrence_id'],
         occurrence['occurrence_id'])).fetchone()
    links = _scheduled_rule_rows(db, scope, workflow_id)
    if (parent is None or task is None or len(links) != 1
            or links[0]['occurrence_id'] != occurrence['occurrence_id']
            or (parent['issuer'], parent['subject_id']) != (task['issuer'], task['subject_id'])
            or parent['idempotency_key'] != 'schedule-rule-' + occurrence['occurrence_id']):
        raise ValueError('APPLICATION_SCHEDULE_WORKFLOW_CONFLICT')
    kind = parent.get('execution_origin_kind')
    if kind == 'scheduled':
        authority = _schedule_authority(parent.get('schedule_authority'))
        if (authority['occurrenceId'], authority['scheduleId'], authority['scheduleStateToken']) != (
                occurrence['occurrence_id'], occurrence['schedule_id'], occurrence['schedule_state_token']):
            raise ValueError('APPLICATION_SCHEDULE_WORKFLOW_CONFLICT')
    elif kind != 'legacy_unresolved' or parent.get('schedule_authority') is not None:
        raise ValueError('APPLICATION_SCHEDULE_WORKFLOW_CONFLICT')
    # An exact inherited FK plus original task/parent identity permits control;
    # this deliberately does not certify the old tail's effect origin.
    return parent


def retained_rule_control_record(db, scope, workflow):
    """Verify retained checkpoints for control without executable eligibility.

    Current controller grants/owner-or-admin checks belong to the caller.
    Uncheckpointed work is never adopted here. The shared runner separately
    proves any original lost-ack child before cancellation reconciliation.
    """
    from .postgres_access import durable_execution_identity
    from .postgres_application_rules import SealedApplicationRule
    from .postgres_application_rule_workflow import (
        PostgresApplicationRuleWorkflowStore, _record, rule_workflow_request_digest)
    from .python_program_execution import WorkflowStatus
    try:
        if (workflow['workspace_id'], workflow['application_id']) != (
                scope.workspace_id, scope.application_id):
            raise ValueError('scope')
        plan = PostgresApplicationRuleWorkflowStore._stored_plan(workflow)
        pin = _retained_rule_pin(workflow)
        kind = workflow.get('execution_origin_kind')
        if kind not in ('direct', 'scheduled', 'legacy_unresolved'):
            raise ValueError('origin')
        authority = (_schedule_authority(workflow.get('schedule_authority'))
            if kind == 'scheduled' else None)
        if kind != 'scheduled' and workflow.get('schedule_authority') is not None:
            raise ValueError('origin')
        descriptor = ({} if kind == 'legacy_unresolved' else {
            'execution_origin': {'kind': kind, 'scheduleAuthority': authority}})
        digest = rule_workflow_request_digest(scope, durable_execution_identity(workflow),
            workflow['idempotency_key'], SealedApplicationRule(plan, pin), **descriptor)
        if digest != workflow['request_digest']:
            raise ValueError('request')
        record = _record(workflow)
        checkpoints = record.checkpoints
        if (record.status == WorkflowStatus.ACCEPTED and checkpoints
                or any(not item.committed for item in checkpoints[:-1])):
            raise ValueError('prefix')
        if not checkpoints:
            return record
        children = db.execute('''SELECT c.unit_ordinal,j.job_id,j.issuer,j.subject_id,
            j.verified_groups,j.authorization_scope_digest,j.status,j.receipt_revision,
            j.function_name FROM epm.application_rule_workflow_child c JOIN epm.job j
            ON (j.workspace_id,j.application_id,j.job_id)=
               (c.workspace_id,c.application_id,c.job_id)
            WHERE c.workspace_id=%s AND c.application_id=%s AND c.workflow_id=%s
              AND c.unit_ordinal<=%s ORDER BY c.unit_ordinal''',
            (scope.workspace_id,scope.application_id,workflow['workflow_id'],len(checkpoints))).fetchall()
        if len(children) != len(checkpoints):
            raise ValueError('links')
        for checkpoint, child in zip(checkpoints, children, strict=True):
            # Unit operation shape is owned by the same fixed runner, including
            # composite units. Do not invent a function-name normalizer here.
            from .python_plan_runner import SealedPlanRunner
            operation = SealedPlanRunner._atomic_operation(
                plan.canonical_plan['units'][checkpoint.ordinal-1])
            if ((child['unit_ordinal'], child['job_id'], child['function_name']) !=
                    (checkpoint.ordinal, checkpoint.job_id, operation['function'])
                    or (child['issuer'], child['subject_id']) !=
                       (workflow['issuer'], workflow['subject_id'])
                    or tuple(child['verified_groups']) != tuple(workflow['verified_groups'])
                    or child['authorization_scope_digest'] != workflow['authorization_scope_digest']):
                raise ValueError('links')
            if checkpoint.committed:
                if (checkpoint.receipt_id != child['job_id'] or child['status'] != 'published'
                        or child['receipt_revision'] is None):
                    raise ValueError('receipt')
            else:
                # Only the attached pending child may be controlled. Reuse the
                # original typed admission descriptor, sealed unit and links.
                job, parent, link = _origin(db, scope, {
                    'issuer': workflow['issuer'], 'subject_id': workflow['subject_id'],
                    'idempotency_key': f"rule-{workflow['workflow_id']}-{checkpoint.ordinal}",
                    'job_id': checkpoint.job_id})
                if (parent is None or parent['workflow_id'] != workflow['workflow_id']
                        or link['unit_ordinal'] != checkpoint.ordinal
                        or job['job_id'] != checkpoint.job_id):
                    raise ValueError('pending')
        return record
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('WORKFLOW_CANCELLATION_CHILD_PROOF_UNAVAILABLE') from error
