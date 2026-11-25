"""Server-owned bounded progression of generic Python schedule occurrences."""
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
                              durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout
from .postgres_python_build_public import PostgresPythonBuildPublic,BUILD
from .postgres_python_run import PostgresPythonRun,RUN
from .postgres_python_schedules import _occurrence_id
from .postgres_python_occurrence_control import (PythonOccurrenceAdmission,
    PythonOccurrenceControl,reconcile_control,lock_state,PARKED,UNRESOLVED,CONTROL_REQUIRED)
from .recurrence import CatchUpPolicy,due_from_interval

class PostgresPythonScheduleWorker:
 def __init__(self,*,worker_dsn,runtime_dsn,admission_factory,worker_id):
  if not all(type(v) is str and v for v in (worker_dsn,runtime_dsn,worker_id)) or not callable(admission_factory):raise ValueError('PYTHON_SCHEDULE_WORKER_CONFIGURATION_INVALID')
  self.worker_dsn,self.runtime_dsn,self.admission_factory,self.worker_id=worker_dsn,runtime_dsn,admission_factory,worker_id
 def _call(self,statement,values):
  with connect_postgres(self.worker_dsn,row_factory=dict_row) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    return db.execute(statement,values).fetchone()
 @staticmethod
 def _identity(row):
  return durable_execution_identity(row,issuer='execution_issuer',
   subject='execution_subject',groups='execution_groups',
   token_issued_at='execution_token_issued_at',
   authority_kind='execution_authority_kind')
 @classmethod
 def _assert_authorization_scope(cls,db,scope,row):
  identity=cls._identity(row)
  access=PostgresAccessChecker.check_in_transaction(db,identity,scope,'write')
  current=resolve_effective_dimensional_scope(
   db,identity,scope,access=access).scope_digest
  if (row.get('authorization_scope_digest') is None
      or row['authorization_scope_digest']!=current):
   raise AccessDenied('PYTHON_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED')
  return identity
 def materialize_once(self):
  c=self._call('SELECT * FROM epm.python_schedule_worker_claim(%s,65)',(self.worker_id,))
  if c is None:return None
  scope=ApplicationScope(c['workspace_id'],c['application_id'])
  settled=False
  try:
   with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
    with db.transaction():
     configure_statement_timeout(db,5000);configure_lock_wait(db)
     PostgresNumericFactStore._set_scope(db,scope)
     PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
     lock_state(db,scope)
     r=db.execute('''SELECT s.*,state.schema_epoch,clock_timestamp() now FROM epm.python_program_schedule_definition s JOIN epm.application_state state ON state.workspace_id=s.workspace_id AND state.application_id=s.application_id AND state.processing_mode='Active' WHERE s.workspace_id=%s AND s.application_id=%s AND s.schedule_id=%s AND s.status='Active' FOR UPDATE OF s''',(scope.workspace_id,scope.application_id,c['schedule_id'])).fetchone()
     if (r is None or r['schema_epoch']!=c['schema_epoch']
         or r['dispatch_generation']!=c['dispatch_generation']
         or r['dispatch_claimant']!=self.worker_id
         or r['dispatch_lease_until'] is None or r['dispatch_lease_until']<=r['now']):
      raise ValueError('PYTHON_SCHEDULE_STALE_MATERIALIZATION_FENCE')
     try:self._assert_authorization_scope(db,scope,r)
     except AccessDenied:
      db.execute('''UPDATE epm.python_program_schedule_definition
       SET dispatch_error_code=%s WHERE workspace_id=%s
         AND application_id=%s AND schedule_id=%s
         AND dispatch_generation=%s AND dispatch_claimant=%s''',(
       'PYTHON_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED',scope.workspace_id,
       scope.application_id,c['schedule_id'],c['dispatch_generation'],
       self.worker_id))
      return {'scheduleId':c['schedule_id'],'status':'blocked',
       'reasonCode':'PYTHON_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED'}
     due=due_from_interval(first_due_at=r['first_due_at'],interval_seconds=r['interval_seconds'],last_due_at=r['last_due_at'],through=r['now'],policy=CatchUpPolicy(r['catch_up_policy']),maximum=r['max_catch_up'])
     if not due:return None
     instant=due[0] if r['catch_up_policy']=='all' else due[-1]
     oid=_occurrence_id(scope,r['schedule_id'],r['state_token'],instant,schema_epoch=r['schema_epoch'])
     db.execute("INSERT INTO epm.python_program_occurrence(workspace_id,application_id,occurrence_id,schedule_id,schedule_state_token,due_at,status,admission_protocol) VALUES(%s,%s,%s,%s,%s,%s,'ready',1) ON CONFLICT DO NOTHING",(scope.workspace_id,scope.application_id,oid,r['schedule_id'],r['state_token'],instant))
     db.execute('UPDATE epm.python_program_schedule_definition SET last_due_at=%s,updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s AND state_token=%s',(instant,scope.workspace_id,scope.application_id,r['schedule_id'],r['state_token']))
     return {'occurrenceId':oid,'status':'ready'}
  except Exception as error:
   settled=True
   code=('PYTHON_SCHEDULE_INFRASTRUCTURE_FAILURE'
    if isinstance(error,(ConnectionError,OSError,TimeoutError))
    else 'PYTHON_SCHEDULE_MATERIALIZATION_FAILED')
   outcome=self._schedule_unexpected(scope,c,code)
   if outcome is None:
    raise ValueError('PYTHON_SCHEDULE_STALE_MATERIALIZATION_FENCE') from error
   return {'scheduleId':c['schedule_id'],'status':outcome,'errorCode':code}
  finally:
   if not settled:self._call('SELECT epm.python_schedule_worker_release(%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,c['schema_epoch'],c['schedule_id'],c['dispatch_generation'],self.worker_id))
 def advance_once(self):
  c=self._call('SELECT * FROM epm.python_occurrence_worker_claim(%s,65,32,8,2)',(self.worker_id,))
  if c is None:return None
  scope=ApplicationScope(c['workspace_id'],c['application_id']);oid=c['occurrence_id']
  r=None
  try:
   r=self._row(scope,oid,c['schema_epoch'])
   c={**c,'observed_status':r['status']}
   if r['status']=='cancel_requested':
    try:
     control=PythonOccurrenceControl.from_row(scope,r)
     outcome=reconcile_control(self.runtime_dsn,control)
    except AccessDenied:
     return self._park(scope,c,CONTROL_REQUIRED)
    except ValueError as error:
     if str(error)=='PYTHON_SCHEDULE_CONTROL_PARENT_BUSY':
      phase=self._phase(scope,c,'cancel_requested')
      return {'occurrenceId':oid,'status':phase}
     if str(error) in (UNRESOLVED,CONTROL_REQUIRED,
       'WORKFLOW_CANCELLATION_CHILD_PROOF_UNAVAILABLE','WORKFLOW_CANCELLATION_CHILD_UNRESOLVED',
       'PYTHON_WORKFLOW_CHILD_CONFLICT','PYTHON_WORKFLOW_STALE_CONTROL_STATE'):
      return self._park(scope,c,str(error) if str(error) in (UNRESOLVED,CONTROL_REQUIRED) else PARKED)
     raise
    if outcome['status']=='cancel_requested':
     phase=self._phase(scope,c,'cancel_requested')
     return {'occurrenceId':oid,'status':phase}
    return self._settle(scope,c,outcome['status'],outcome['errorCode'],outcome['result'])
   identity=self._identity(r)
   if r['workflow_id'] is not None:
    service=PostgresPythonRun(self.runtime_dsn,identity=identity,
     admission=self.admission_factory(identity))
    run=service.read(scope,r['workflow_id'])
    outcome=self._workflow_outcome(run['status'])
    if outcome is not None:
     return self._settle(scope,c,*outcome,run)
    phase='cancel_requested' if r['status']=='cancel_requested' else 'running_program'
    phase=self._phase(scope,c,phase)
    return {'occurrenceId':oid,'status':phase}
   if r['build_id'] is None:
    build=PostgresPythonBuildPublic(self.runtime_dsn,identity=identity).execute(scope,{'languageVersion':2,'function':BUILD,'arguments':{'programId':r['program_id'],'programSourceToken':r['program_source_token'],'parameters':r['parameter_values'],'expectedMetadataRevision':r['metadata_revision'],'expectedPolicyRevision':r['policy_revision'],'expectedSchemaEpoch':r['schema_epoch'],'delegationId':r['delegation_id'],'delegationStateToken':r['delegation_state_token'],'scheduleId':r['schedule_id'],'scheduleStateToken':r['schedule_state_token']}},idempotency_key='py-schedule-build-'+oid,
     _occurrence_admission=PythonOccurrenceAdmission(oid,self.worker_id,c['claim_generation'],c['schema_epoch'],'build'))
    phase=self._phase(scope,c,'building',build_id=build['buildId']);return {'occurrenceId':oid,'status':phase}
   build=PostgresPythonBuildPublic(self.runtime_dsn,identity=identity).read(scope,r['build_id'])
   if build['status'] in ('failed','cancelled'):return self._settle(scope,c,'failed','PYTHON_SCHEDULE_BUILD_FAILED',build)
   if build['status']!='sealed':
    phase=self._phase(scope,c,'building')
    return {'occurrenceId':oid,'status':phase}
   service=PostgresPythonRun(self.runtime_dsn,identity=identity,admission=self.admission_factory(identity),
    _occurrence_admission=PythonOccurrenceAdmission(oid,self.worker_id,c['claim_generation'],c['schema_epoch'],'workflow'))
   run=service.run(scope,{'languageVersion':2,'function':RUN,'arguments':{'buildId':r['build_id']}},idempotency_key='py-schedule-run-'+oid)
   phase=self._phase(scope,c,'running_program',workflow_id=run['workflowId']);return {'occurrenceId':oid,'status':phase}
  except (AccessDenied,ValueError) as error:
   code=str(error)
   if code=='PYTHON_SCHEDULE_STALE_WORKER_FENCE':raise
   if isinstance(error,AccessDenied) or code in (
      'PYTHON_EXECUTION_DELEGATION_INVALID','PYTHON_BUILD_UNAVAILABLE',
      'PYTHON_SEALED_BUILD_UNAVAILABLE'):
    if r is not None and r['status']=='cancel_requested':
     return self._park(scope,c,CONTROL_REQUIRED)
    if r is not None and r['workflow_id'] is not None:
     return self._settle(scope,c,'needs_inspection',
      'PYTHON_SCHEDULE_WORKFLOW_READ_UNAVAILABLE',None)
    return self._settle(scope,c,'failed',
     'PYTHON_SCHEDULE_AUTHORIZATION_REVOKED',None)
   outcome=self._unexpected(scope,c,'PYTHON_SCHEDULE_WORKER_FAILED')
   if outcome is None:
    raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE') from error
   return {'occurrenceId':oid,'status':outcome,
    'errorCode':'PYTHON_SCHEDULE_WORKER_FAILED'}
  except Exception as error:
   code=('PYTHON_SCHEDULE_INFRASTRUCTURE_FAILURE'
         if isinstance(error,(ConnectionError,OSError,TimeoutError))
         else 'PYTHON_SCHEDULE_WORKER_FAILED')
   outcome=self._unexpected(scope,c,code)
   if outcome is None:
    raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE') from error
   return {'occurrenceId':oid,'status':outcome,'errorCode':code}
  finally:self._call('SELECT epm.python_occurrence_worker_release(%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,c['schema_epoch'],oid,c['claim_generation'],self.worker_id))
 @staticmethod
 def _workflow_outcome(status):
  # Occurrences have no partial-success state. Keep the complete native result
  # and distinguish partial publication from both full success and rollback.
  return {'published':('published',None),
   'partially_published':('failed','PYTHON_SCHEDULE_WORKFLOW_PARTIALLY_PUBLISHED'),
   'failed':('failed','PYTHON_SCHEDULE_WORKFLOW_FAILED'),
   'cancelled':('cancelled',None),
   'needs_inspection':('needs_inspection','PYTHON_SCHEDULE_WORKFLOW_REQUIRES_INSPECTION')}.get(status)
 def _row(self,scope,oid,schema_epoch):
  with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope);row=db.execute('''SELECT o.*,v.program_id,v.program_source_token,v.parameter_values,v.execution_issuer,v.execution_subject,v.execution_groups,v.execution_token_issued_at,v.execution_authority_kind,v.authorization_scope_digest,v.delegation_id,v.delegation_state_token,s.metadata_revision,s.policy_revision,s.schema_epoch FROM epm.python_program_occurrence o LEFT JOIN epm.python_program_schedule_definition v ON (v.workspace_id,v.application_id,v.schedule_id,v.state_token)=(o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token) JOIN epm.application_state s ON s.workspace_id=o.workspace_id AND s.application_id=o.application_id WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s AND s.schema_epoch=%s AND s.processing_mode='Active' ''',(scope.workspace_id,scope.application_id,oid,schema_epoch)).fetchone()
    if row is None:raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE')
    return row
 def _phase(self,scope,c,status,build_id=None,workflow_id=None):
  with connect_postgres(self.runtime_dsn) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope)
    result=db.execute('''UPDATE epm.python_program_occurrence SET
     status=CASE WHEN status='cancel_requested' THEN status ELSE %s END,
     worker_failures=0,
     next_attempt_at=CASE WHEN status='cancel_requested' OR %s::text='cancel_requested'
      THEN clock_timestamp()+interval '1 second' ELSE NULL END,
     error_code=NULL,updated_at=transaction_timestamp()
     WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
       AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()
       AND EXISTS(SELECT 1 FROM epm.application_state incarnation
        WHERE incarnation.workspace_id=%s AND incarnation.application_id=%s
         AND incarnation.schema_epoch=%s AND incarnation.processing_mode='Active')
       AND status IN ('running','building','running_program','cancel_requested')
       AND (status=%s OR status=%s OR status='cancel_requested')
       AND (%s::text IS NULL OR build_id=%s)
       AND (%s::text IS NULL OR workflow_id=%s) RETURNING status''',(status,status,scope.workspace_id,scope.application_id,
     c['occurrence_id'],c['claim_generation'],self.worker_id,
     scope.workspace_id,scope.application_id,c['schema_epoch'],c['observed_status'],status,build_id,build_id,workflow_id,workflow_id))
    row=result.fetchone()
    if row is None:
     if build_id is not None or workflow_id is not None:
      observed=db.execute('''SELECT status FROM epm.python_program_occurrence
       WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
        AND control_authority IS NOT NULL
        AND status IN ('cancel_requested','cancelled','failed','published')
        AND (%s::text IS NULL OR build_id=%s) AND (%s::text IS NULL OR workflow_id=%s)
        AND EXISTS(SELECT 1 FROM epm.application_state a WHERE
         (a.workspace_id,a.application_id)=(%s,%s) AND a.schema_epoch=%s)''',
       (scope.workspace_id,scope.application_id,c['occurrence_id'],build_id,build_id,
        workflow_id,workflow_id,scope.workspace_id,scope.application_id,c['schema_epoch'])).fetchone()
      if observed is not None:return observed[0]
     raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE')
    return row[0]
 def _settle(self,scope,c,status,error,result):
  with connect_postgres(self.runtime_dsn) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope)
    changed=db.execute('''UPDATE epm.python_program_occurrence SET
     status=%s,error_code=%s,result=%s,claimant=NULL,lease_until=NULL,
     worker_failures=0,next_attempt_at=NULL,updated_at=transaction_timestamp()
     WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
       AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()
       AND EXISTS(SELECT 1 FROM epm.application_state incarnation
        WHERE incarnation.workspace_id=%s AND incarnation.application_id=%s
         AND incarnation.schema_epoch=%s AND incarnation.processing_mode='Active')
       AND status=%s''',(status,error,
     Jsonb(result) if result is not None else None,scope.workspace_id,
     scope.application_id,c['occurrence_id'],c['claim_generation'],
     self.worker_id,scope.workspace_id,scope.application_id,c['schema_epoch'],
     c['observed_status']))
    if changed.rowcount!=1:raise ValueError(
     'PYTHON_SCHEDULE_STALE_WORKER_FENCE')
    return {'occurrenceId':c['occurrence_id'],'status':status,
     'errorCode':error}
 def _park(self,scope,c,error):
  if error not in (PARKED,UNRESOLVED,CONTROL_REQUIRED):raise ValueError('PYTHON_SCHEDULE_CONTROL_INVALID')
  with connect_postgres(self.runtime_dsn) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope)
    changed=db.execute('''UPDATE epm.python_program_occurrence SET worker_failures=3,
     next_attempt_at=NULL,error_code=%s,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
     WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
      AND status='cancel_requested' AND claim_generation=%s AND claimant=%s
      AND lease_until>clock_timestamp() AND EXISTS(SELECT 1 FROM epm.application_state a
       WHERE (a.workspace_id,a.application_id)=(%s,%s) AND a.schema_epoch=%s
        AND a.processing_mode='Active')''',(error,scope.workspace_id,scope.application_id,
     c['occurrence_id'],c['claim_generation'],self.worker_id,scope.workspace_id,
     scope.application_id,c['schema_epoch']))
    if changed.rowcount!=1:raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE')
  return {'occurrenceId':c['occurrence_id'],'status':'cancel_requested','errorCode':error}
 def _unexpected(self,scope,c,error):
  row=self._call('''SELECT epm.python_occurrence_worker_unexpected(
   %s,%s,%s,%s,%s,%s,%s) AS outcome''',(scope.workspace_id,
   scope.application_id,c['schema_epoch'],c['occurrence_id'],c['claim_generation'],
   self.worker_id,error))
  return None if row is None else row['outcome']
 def _schedule_unexpected(self,scope,c,error):
  row=self._call('''SELECT epm.python_schedule_worker_settle_unexpected(
   %s,%s,%s,%s,%s,%s,%s) AS outcome''',(scope.workspace_id,
   scope.application_id,c['schema_epoch'],c['schedule_id'],c['dispatch_generation'],
   self.worker_id,error))
  return None if row is None else row['outcome']
