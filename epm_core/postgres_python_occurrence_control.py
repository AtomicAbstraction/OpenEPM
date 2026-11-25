"""Private occurrence admission and cancellation provenance.

The occurrence owns its links and control request. Execution authority, the
current controller, and a later public reader are deliberately separate.
Nothing in this module executes Python, previews, submits, or reruns work.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import TypedDict

from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker,
                              durable_authority_fields, durable_execution_identity)
from .postgres_dimensional_scope import resolve_effective_dimensional_scope

CANCEL = 'python.schedule.occurrence.cancel'
PARKED = 'PYTHON_SCHEDULE_CANCELLATION_RECOVERY_PARKED'
UNRESOLVED = 'PYTHON_SCHEDULE_ADMISSION_UNRESOLVED'
CONTROL_REQUIRED = 'PYTHON_SCHEDULE_CONTROL_AUTHORITY_REQUIRED'
PARK_CODES = frozenset((PARKED, UNRESOLVED, CONTROL_REQUIRED))
_HEX = re.compile(r'[0-9a-f]{32}')
_SEAL_FIELDS = frozenset(('format', 'requestGeneration', 'cause', 'issuer',
    'subject_id', 'verified_groups', 'token_issued_at', 'authority_kind',
    'authorization_scope_digest'))


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()


def lock_state(db, scope):
    """Fence new occurrence admission/control before its row and child locks."""
    PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
    row = db.execute('''SELECT metadata_revision,policy_revision,schema_epoch
        FROM epm.application_state WHERE workspace_id=%s AND application_id=%s
          AND processing_mode='Active' FOR UPDATE''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise AccessDenied('APPLICATION_NOT_WRITABLE')
    return row


@dataclass(frozen=True, slots=True)
class PythonOccurrenceAdmission:
    occurrence_id: str
    claimant: str
    claim_generation: int
    schema_epoch: int
    phase: str

    def __post_init__(self):
        if (type(self.occurrence_id) is not str or not _HEX.fullmatch(self.occurrence_id)
                or type(self.claimant) is not str or not 1 <= len(self.claimant) <= 200
                or type(self.claim_generation) is not int or self.claim_generation < 1
                or type(self.schema_epoch) is not int or self.schema_epoch < 0
                or self.phase not in ('build', 'workflow')):
            raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')


def prepare_admission(db, scope, identity, admission, *, build_id,
                      workflow_id=None, build_arguments=None):
    """Caller holds state; lock the claim through child insert AND link."""
    from .postgres_python_schedules import _occurrence_id
    if not isinstance(admission, PythonOccurrenceAdmission):
        raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
    row = db.execute('''SELECT o.*,s.program_id,s.program_source_token,
        s.parameter_values,s.execution_issuer,s.execution_subject,s.execution_groups,
        s.execution_token_issued_at,s.execution_authority_kind,
        s.authorization_scope_digest,s.delegation_id,s.delegation_state_token,
        a.schema_epoch,a.metadata_revision,a.policy_revision,
        o.lease_until>clock_timestamp() AS claim_live
        FROM epm.python_program_occurrence o
        JOIN epm.python_program_schedule_definition s ON
          (s.workspace_id,s.application_id,s.schedule_id,s.state_token)=
          (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
        JOIN epm.application_state a ON (a.workspace_id,a.application_id)=(o.workspace_id,o.application_id)
        WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s
          AND s.status='Active' AND a.processing_mode='Active'
        FOR UPDATE OF o''', (scope.workspace_id, scope.application_id,
                             admission.occurrence_id)).fetchone()
    if (row is None or row['admission_protocol'] != 1
            or row['status'] not in ('running', 'building', 'running_program')
            or row['control_authority'] is not None
            or row['claimant'] != admission.claimant
            or row['claim_generation'] != admission.claim_generation
            or row['claim_live'] is not True or row['schema_epoch'] != admission.schema_epoch
            or (row['execution_issuer'], row['execution_subject']) !=
               (identity.issuer, identity.subject_id)
            or tuple(row['execution_groups']) != identity.groups
            or (row['execution_token_issued_at'], row['execution_authority_kind']) !=
               durable_authority_fields(identity)
            or _occurrence_id(scope,row['schedule_id'],row['schedule_state_token'],
                row['due_at'],schema_epoch=row['schema_epoch']) != admission.occurrence_id):
        raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
    original = durable_execution_identity(row, issuer='execution_issuer',
        subject='execution_subject', groups='execution_groups',
        token_issued_at='execution_token_issued_at', authority_kind='execution_authority_kind')
    PostgresAccessChecker.check_in_transaction(db, original, scope, 'rule_run',
        function='python.program.build' if admission.phase == 'build' else 'python.program.run')
    if admission.phase == 'build':
        expected = {'programId':row['program_id'], 'programSourceToken':row['program_source_token'],
            'parameters':row['parameter_values'], 'delegationId':row['delegation_id'],
            'delegationStateToken':row['delegation_state_token'], 'scheduleId':row['schedule_id'],
            'scheduleStateToken':row['schedule_state_token'],
            'expectedMetadataRevision':row['metadata_revision'],
            'expectedPolicyRevision':row['policy_revision'], 'expectedSchemaEpoch':row['schema_epoch']}
        if (build_arguments != expected or row['workflow_id'] is not None
                or row['build_id'] not in (None,build_id) or workflow_id is not None):
            raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
    elif (row['build_id'] != build_id or row['workflow_id'] not in (None,workflow_id)
            or type(workflow_id) is not str or not _HEX.fullmatch(workflow_id)):
        raise ValueError('PYTHON_SCHEDULE_ADMISSION_INVALID')
    return row


def link_admission(db, scope, admission, child_id):
    column, phase = (('build_id','building') if admission.phase == 'build'
                     else ('workflow_id','running_program'))
    changed = db.execute(f'''UPDATE epm.python_program_occurrence SET
        {column}=%s,status=%s,updated_at=transaction_timestamp()
        WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
          AND admission_protocol=1 AND control_authority IS NULL
          AND status IN ('running','building','running_program')
          AND ({column} IS NULL OR {column}=%s)
          AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()''',
        (child_id,phase,scope.workspace_id,scope.application_id,admission.occurrence_id,
         child_id,admission.claim_generation,admission.claimant)).rowcount
    if changed != 1:
        raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE')


def control_seal(db, scope, identity, generation, *, cause):
    if type(generation) is not int or generation < 1 or cause not in ('ExplicitCancel','ScheduleRotation'):
        raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
    access = PostgresAccessChecker.check_in_transaction(db,identity,scope,'admin',function=CANCEL)
    token, kind = durable_authority_fields(identity)
    return {'format':'python-occurrence-control-v1','requestGeneration':generation,
        'cause':cause,'issuer':identity.issuer,'subject_id':identity.subject_id,
        'verified_groups':list(access.groups),'token_issued_at':token,'authority_kind':kind,
        'authorization_scope_digest':resolve_effective_dimensional_scope(
            db,identity,scope,access=access,function=CANCEL).scope_digest}


def validate_seal(value):
    if (type(value) is not dict or set(value) != _SEAL_FIELDS
            or value['format'] != 'python-occurrence-control-v1'
            or type(value['requestGeneration']) is not int or value['requestGeneration'] < 1
            or value['cause'] not in ('ExplicitCancel','ScheduleRotation')
            or type(value['verified_groups']) is not list or len(value['verified_groups']) > 100
            or len(json.dumps(value,ensure_ascii=True)) > 131072):
        raise ValueError(CONTROL_REQUIRED)
    return durable_execution_identity(value)


@dataclass(frozen=True, slots=True)
class PythonOccurrenceControl:
    """A cancellation-only handle, not a VerifiedIdentity or execution service."""
    scope: ApplicationScope
    occurrence_id: str
    authority_digest: str
    request_generation: int

    def __post_init__(self):
        if (not isinstance(self.scope,ApplicationScope)
                or type(self.occurrence_id) is not str or not _HEX.fullmatch(self.occurrence_id)
                or type(self.authority_digest) is not str
                or re.fullmatch(r'[0-9a-f]{64}',self.authority_digest) is None
                or type(self.request_generation) is not int or self.request_generation<1):
            raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')

    @classmethod
    def from_row(cls, scope, row):
        validate_seal(row.get('control_authority'))
        return cls(scope,row['occurrence_id'],digest(row['control_authority']),
                   row['control_authority']['requestGeneration'])


def authorize_control(db, scope, control, *, lock=True):
    if (not isinstance(control,PythonOccurrenceControl) or control.scope != scope
            or not _HEX.fullmatch(control.occurrence_id)):
        raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
    if lock:
        lock_state(db,scope)
    row = db.execute('''SELECT o.*,t.issuer AS original_issuer,
        t.subject_id AS original_subject FROM epm.python_program_occurrence o
        JOIN epm.task t ON (t.workspace_id,t.application_id,t.source_id)=
          (o.workspace_id,o.application_id,o.occurrence_id)
          AND t.source_family='PythonScheduleOccurrence' AND t.task_id='s:'||o.occurrence_id
        WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s'''
        + (' FOR UPDATE OF o' if lock else ''),
        (scope.workspace_id,scope.application_id,control.occurrence_id)).fetchone()
    if (row is None or row['status'] != 'cancel_requested'
            or digest(row.get('control_authority')) != control.authority_digest
            or row['control_authority'].get('requestGeneration') != control.request_generation):
        raise ValueError('PYTHON_SCHEDULE_STALE_CONTROL')
    identity=validate_seal(row['control_authority'])
    PostgresAccessChecker.check_in_transaction(db,identity,scope,'admin',function=CANCEL)
    return row,identity


def verify_child_link(row, child, *, family):
    key = 'build_id' if family == 'build' else 'workflow_id'
    if (family not in ('build','workflow') or child is None
            or row[key] != child[key]
            or (row['workspace_id'],row['application_id']) !=
               (child['workspace_id'],child['application_id'])
            or (row['original_issuer'],row['original_subject']) !=
               (child['issuer'],child['subject_id'])
            or child['idempotency_key'] != ('py-schedule-build-' if family == 'build'
                                            else 'py-schedule-run-')+row['occurrence_id']):
        raise ValueError(UNRESOLVED)
    if family == 'build':
        if (child['schedule_id'],child['schedule_state_token']) != (
                row['schedule_id'],row['schedule_state_token']):
            raise ValueError(UNRESOLVED)
    elif child['build_id'] != row['build_id']:
        raise ValueError(UNRESOLVED)


def null_link_proves_absence(row):
    return (row['build_id'] is None and row['workflow_id'] is None and
        (row['admission_protocol'] == 1 or
         (row['status'] == 'ready' and row['claim_generation'] == 0 and row.get('first_claimed_at') is None)))


def public_occurrence(row):
    """Preserve the pre-386 wire; private authority must never escape SELECT *."""
    fields=('workspace_id','application_id','occurrence_id','schedule_id','due_at',
        'build_id','workflow_id','status','claim_generation','claimant','lease_until',
        'error_code','result','created_at','updated_at','worker_failures','next_attempt_at',
        'schedule_state_token','first_claimed_at')
    return {key:row[key] for key in fields}


def public_occurrence_schema(statuses):
    """Describe the existing public occurrence projection at the wire boundary."""
    from .postgres_numeric_catalog import obj

    identifier={'type':'string','pattern':r'^[0-9a-f]{32}(?![\s\S])'}
    id_or_none={'anyOf':[identifier,{'type':'null'}]}
    timestamp={'type':'string','format':'date-time'}
    optional_time={'type':['string','null'],'format':'date-time'}
    nonnegative={'type':'integer','minimum':0}
    text_or_none={'type':['string','null']}
    return obj({'workspace_id':{'type':'string'},'application_id':{'type':'string'},
        'occurrence_id':identifier,'schedule_id':{'type':'string'},'due_at':timestamp,
        'build_id':id_or_none,'workflow_id':id_or_none,'status':{'enum':list(statuses)},
        'claim_generation':nonnegative,'claimant':text_or_none,'lease_until':optional_time,
        'error_code':text_or_none,'result':{'type':['object','null'],
            'description':'Retained worker outcome. Read the linked build or workflow for its current result.'},
        'created_at':timestamp,'updated_at':timestamp,'worker_failures':nonnegative,
        'next_attempt_at':optional_time,'schedule_state_token':{'type':'string','pattern':r'^[0-9a-f]{64}(?![\s\S])'},
        'first_claimed_at':optional_time})


class OccurrenceCancellationResult(TypedDict):
    occurrenceId: str
    status: str
    committedEffectsRemain: bool | None


def retained_effects(row):
    """True only for retained confirmed receipts; no inferred zero outcome."""
    from .python_program_execution import WorkflowRecord,WorkflowStatus,UnitCheckpoint,MAX_OPERATIONS
    value=row.get('result')
    if type(value) is not dict:return None
    try:
        if (set(value)!={'workflowId','buildId','planDigest','status','unitCount',
                'committedUnits','remainingUnits','checkpoints'}
                or value['workflowId']!=row.get('workflow_id')
                or value['buildId']!=row.get('build_id')
                or type(value['checkpoints']) is not list or len(value['checkpoints'])>MAX_OPERATIONS
                or type(value['committedUnits']) is not int
                or type(value['remainingUnits']) is not int):return None
        record=WorkflowRecord(ApplicationScope(row['workspace_id'],row['application_id']),
            value['workflowId'],value['buildId'],value['planDigest'],value['unitCount'],
            WorkflowStatus(value['status']),tuple(UnitCheckpoint(
                item['ordinal'],item['jobId'],item['committed'],item['receiptId'])
                for item in value['checkpoints']))
        if (value['committedUnits']!=record.committed_units
                or value['remainingUnits']!=record.remaining_units):return None
        return True if record.committed_units>0 else None
    except (KeyError,TypeError,ValueError):return None


def linked_effects(row,before,after):
    """Derive certainty while the occurrence and exact child are locked."""
    if row['workflow_id'] is None:
        # A technical build cannot publish business effects. Only protocol1
        # proves that a missing workflow link also means no admitted parent.
        return False if row['admission_protocol']==1 else None
    if after.committed_units>0:return True
    if (row['admission_protocol']==1 and before.status.value=='accepted'
            and not before.checkpoints and after.status.value=='cancelled'):
        return False
    return None


class _NoExecution:
    """Poison capability: cancellation has no executable admission surface."""
    def __getattr__(self, name):
        raise ValueError('PYTHON_SCHEDULE_CONTROL_EXECUTION_FORBIDDEN')


class _CancellationStore:
    def __init__(self,owner,control):self.owner,self.control=owner,control
    def compare_and_set(self,current,updated):
        return self.owner.compare_occurrence_control(self.control,current,updated)
    def recover_cancelled_child(self,workflow,*,ordinal,operation,admission):
        return self.owner.recover_occurrence_control_child(self.control,workflow,
            ordinal=ordinal,operation=operation)
    def __getattr__(self,name):
        raise ValueError('PYTHON_SCHEDULE_CONTROL_EXECUTION_FORBIDDEN')


class _CancellationInspector:
    def __init__(self,owner,control):self.owner,self.control=owner,control
    def inspect(self,scope,job_id):
        if scope!=self.control.scope:raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
        return self.owner.occurrence_control_job(self.control,job_id)
    def request_cancel(self,scope,job_id):
        if scope!=self.control.scope:raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
        self.owner.occurrence_control_job(self.control,job_id,cancel=True)


def stop_linked(db,dsn,scope,control):
    """Reuse native state controllers on THIS transaction; no job/network call."""
    from .postgres_python_program_repository import PostgresPythonProgramRepository
    from .postgres_python_workflow import PostgresPythonWorkflowStore
    occurrence,identity=authorize_control(db,scope,control)
    if occurrence['workflow_id'] is not None:
        owner=PostgresPythonWorkflowStore(dsn,identity=identity)
        record,plan=owner.read_occurrence_control(scope,control,_connection=db)
        before=record
        if record.status.value in ('accepted','running'):
            record=owner.request_cancel_as_task_controller(scope,record.workflow_id,
                allow_application_admin=True,_connection=db)
        return occurrence,owner,record,plan,linked_effects(occurrence,before,record)
    if occurrence['build_id'] is not None:
        owner=PostgresPythonProgramRepository(dsn,None,identity=identity)
        record=owner.read_occurrence_control(scope,control,_connection=db)
        if record.status.value in ('accepted','ready','running'):
            record=owner.request_cancel_as_task_controller(scope,record.build_id,
                allow_application_admin=True,_connection=db)
        return occurrence,owner,record,None,linked_effects(occurrence,record,record)
    return occurrence,None,None,None,False if occurrence['admission_protocol']==1 else None


def reconcile_control(dsn,control):
    """One bounded cancellation quantum; all owner effects are stop/account only."""
    from psycopg.rows import dict_row
    from .postgres_connection import connect_postgres
    from .postgres_numeric_store import PostgresNumericFactStore
    from .postgres_processing_limits import configure_statement_timeout,configure_lock_wait
    from .python_plan_runner import SealedPlanRunner
    from .python_execution_contract import workflow_result,build_result
    if not isinstance(control,PythonOccurrenceControl):
        raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
    with connect_postgres(dsn,row_factory=dict_row) as db:
        with db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            PostgresNumericFactStore._set_scope(db,control.scope)
            row,owner,record,plan,_=stop_linked(db,dsn,control.scope,control)
    if record is None:
        if row['admission_protocol']!=1:raise ValueError(UNRESOLVED)
        return {'status':'cancelled','errorCode':None,'result':None}
    if row['workflow_id'] is None:
        if record.status.value=='cancel_requested':
            return {'status':'cancel_requested','result':None}
        if row['admission_protocol']!=1:raise ValueError(UNRESOLVED)
        return {'status':'failed' if record.status.value=='failed' else 'cancelled',
            'errorCode':'PYTHON_SCHEDULE_BUILD_FAILED' if record.status.value=='failed' else None,
            'result':build_result(record)}
    if record.status.value=='needs_inspection':
        raise ValueError('WORKFLOW_CANCELLATION_CHILD_UNRESOLVED')
    if record.status.value=='cancel_requested':
        record=SealedPlanRunner(_NoExecution(),_CancellationStore(owner,control),
            _CancellationInspector(owner,control)).advance(record,plan)
    outcomes={'published':('published',None),
        'partially_published':('failed','PYTHON_SCHEDULE_WORKFLOW_PARTIALLY_PUBLISHED'),
        'failed':('failed','PYTHON_SCHEDULE_WORKFLOW_FAILED'),'cancelled':('cancelled',None)}
    if record.status.value not in outcomes:
        return {'status':'cancel_requested','result':None}
    status,error=outcomes[record.status.value]
    return {'status':status,'errorCode':error,'result':workflow_result(record)}
