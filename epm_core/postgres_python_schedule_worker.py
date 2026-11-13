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
     db.execute("INSERT INTO epm.python_program_occurrence(workspace_id,application_id,occurrence_id,schedule_id,schedule_state_token,due_at,status) VALUES(%s,%s,%s,%s,%s,%s,'ready') ON CONFLICT DO NOTHING",(scope.workspace_id,scope.application_id,oid,r['schedule_id'],r['state_token'],instant))
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
  try:
   r=self._row(scope,oid,c['schema_epoch'])
   identity=self._identity(r)
   if r['status']=='cancel_requested':
    outcome=None
    if r['workflow_id'] is not None:
     outcome=PostgresPythonRun(self.runtime_dsn,identity=identity,
      admission=self.admission_factory(identity)).cancel(scope,r['workflow_id'])
    elif r['build_id'] is not None:
     outcome=PostgresPythonBuildPublic(
      self.runtime_dsn,identity=identity).cancel(scope,r['build_id'])
    return self._settle(scope,c,'cancelled',None,outcome)
   if r['build_id'] is None:
    build=PostgresPythonBuildPublic(self.runtime_dsn,identity=identity).execute(scope,{'languageVersion':2,'function':BUILD,'arguments':{'programId':r['program_id'],'programSourceToken':r['program_source_token'],'parameters':r['parameter_values'],'expectedMetadataRevision':r['metadata_revision'],'expectedPolicyRevision':r['policy_revision'],'expectedSchemaEpoch':r['schema_epoch'],'delegationId':r['delegation_id'],'delegationStateToken':r['delegation_state_token'],'scheduleId':r['schedule_id'],'scheduleStateToken':r['schedule_state_token']}},idempotency_key='py-schedule-build-'+oid)
    self._phase(scope,c,'building',build_id=build['buildId']);return {'occurrenceId':oid,'status':'building'}
   build=PostgresPythonBuildPublic(self.runtime_dsn,identity=identity).read(scope,r['build_id'])
   if build['status'] in ('failed','cancelled'):return self._settle(scope,c,'failed','PYTHON_SCHEDULE_BUILD_FAILED',build)
   if build['status']!='sealed':
    self._phase(scope,c,'building')
    return {'occurrenceId':oid,'status':'building'}
   service=PostgresPythonRun(self.runtime_dsn,identity=identity,admission=self.admission_factory(identity))
   if r['workflow_id'] is None:
    run=service.run(scope,{'languageVersion':2,'function':RUN,'arguments':{'buildId':r['build_id']}},idempotency_key='py-schedule-run-'+oid)
    self._phase(scope,c,'running_program',workflow_id=run['workflowId']);return {'occurrenceId':oid,'status':'running_program'}
   run=service.read(scope,r['workflow_id'])
   if run['status'] in ('published','partially_published'):return self._settle(scope,c,'published',None,run)
   if run['status'] in ('failed','cancelled','needs_inspection'):return self._settle(scope,c,'failed','PYTHON_SCHEDULE_WORKFLOW_FAILED',run)
   self._phase(scope,c,'running_program')
   return {'occurrenceId':oid,'status':'running_program'}
  except (AccessDenied,ValueError) as error:
   code=str(error)
   if isinstance(error,AccessDenied) or code in (
      'PYTHON_EXECUTION_DELEGATION_INVALID','PYTHON_BUILD_UNAVAILABLE',
      'PYTHON_SEALED_BUILD_UNAVAILABLE'):
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
 def _row(self,scope,oid,schema_epoch):
  with connect_postgres(self.runtime_dsn,row_factory=dict_row) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope);row=db.execute('''SELECT o.*,v.program_id,v.program_source_token,v.parameter_values,v.execution_issuer,v.execution_subject,v.execution_groups,v.execution_token_issued_at,v.execution_authority_kind,v.authorization_scope_digest,v.delegation_id,v.delegation_state_token,s.metadata_revision,s.policy_revision,s.schema_epoch FROM epm.python_program_occurrence o JOIN epm.python_program_schedule_definition v ON (v.workspace_id,v.application_id,v.schedule_id,v.state_token)=(o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token) JOIN epm.application_state s ON s.workspace_id=o.workspace_id AND s.application_id=o.application_id WHERE o.workspace_id=%s AND o.application_id=%s AND o.occurrence_id=%s AND s.schema_epoch=%s AND s.processing_mode='Active' ''',(scope.workspace_id,scope.application_id,oid,schema_epoch)).fetchone()
    if row is None:raise ValueError('PYTHON_SCHEDULE_STALE_WORKER_FENCE')
    return row
 def _phase(self,scope,c,status,build_id=None,workflow_id=None):
  with connect_postgres(self.runtime_dsn) as db:
   with db.transaction():
    configure_statement_timeout(db,5000);configure_lock_wait(db)
    PostgresNumericFactStore._set_scope(db,scope)
    result=db.execute('''UPDATE epm.python_program_occurrence SET
     status=%s,build_id=COALESCE(%s,build_id),
     workflow_id=COALESCE(%s,workflow_id),worker_failures=0,
     next_attempt_at=NULL,error_code=NULL,updated_at=transaction_timestamp()
     WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
       AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()
       AND EXISTS(SELECT 1 FROM epm.application_state incarnation
        WHERE incarnation.workspace_id=%s AND incarnation.application_id=%s
         AND incarnation.schema_epoch=%s AND incarnation.processing_mode='Active')''',(status,build_id,
     workflow_id,scope.workspace_id,scope.application_id,
     c['occurrence_id'],c['claim_generation'],self.worker_id,
     scope.workspace_id,scope.application_id,c['schema_epoch']))
    if result.rowcount!=1:raise ValueError(
     'PYTHON_SCHEDULE_STALE_WORKER_FENCE')
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
         AND incarnation.schema_epoch=%s AND incarnation.processing_mode='Active')''',(status,error,
     Jsonb(result) if result is not None else None,scope.workspace_id,
     scope.application_id,c['occurrence_id'],c['claim_generation'],
     self.worker_id,scope.workspace_id,scope.application_id,c['schema_epoch']))
    if changed.rowcount!=1:raise ValueError(
     'PYTHON_SCHEDULE_STALE_WORKER_FENCE')
    return {'occurrenceId':c['occurrence_id'],'status':status,
     'errorCode':error}
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
