"""Generic, immutable schedules for exact published Python program versions."""
from __future__ import annotations
from datetime import datetime,timezone
from hashlib import sha256
import json,re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
                              VerifiedIdentity,durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout,configure_lock_wait
from .recurrence import CatchUpPolicy,due_from_interval

SAVE='python.schedule.save';READ='python.schedule.read';LIST='python.schedule.list'
PUBLISH='python.schedule.publish';DEACTIVATE='python.schedule.deactivate'
RUN='python.schedule.run';OCCURRENCE_READ='python.schedule.occurrence.read'
CANCEL='python.schedule.occurrence.cancel'
FUNCTIONS=frozenset((SAVE,READ,LIST,PUBLISH,DEACTIVATE,RUN,OCCURRENCE_READ,CANCEL))
_ID=re.compile(r'^[A-Za-z0-9._-]{1,200}$');_KEY=re.compile(r'^[A-Za-z0-9._-]{8,128}$')
_OCCURRENCE_ID=re.compile(r'^[0-9a-f]{32}$')

def catalog():
    common={'requiredCapabilities':[],'previewRequired':False,'workClass':'short'}
    mutation={**common,'mode':'atomic_configuration','permission':'admin','idempotencyRequired':True}
    read={**common,'mode':'read_only','permission':'read','idempotencyRequired':False}
    return {SAVE:{**mutation,'arguments':{'scheduleId':'ID','expectedVersion':'latest or zero','expectedStateRevision':'state revision','programId':'published program','programVersion':'exact version','parameters':'typed object','intervalSeconds':'60-2678400','firstDueAt':'UTC','catchUpPolicy':'skip/latest/all','maxCatchUp':'1-36','delegationId':'exact authority','delegationVersion':'exact version','expectedMetadataRevision':'revision','expectedPolicyRevision':'revision','expectedSchemaEpoch':'epoch'},'result':'immutable schedule'},PUBLISH:{**mutation,'arguments':{'scheduleId':'ID','version':'version','expectedStateRevision':'revision','expectedMetadataRevision':'revision','expectedPolicyRevision':'revision','expectedSchemaEpoch':'epoch'},'result':'active pointer'},DEACTIVATE:{**mutation,'arguments':{'scheduleId':'ID','version':'version','expectedStateRevision':'revision','expectedMetadataRevision':'revision','expectedPolicyRevision':'revision','expectedSchemaEpoch':'epoch'},'result':'inactive pointer'},READ:{**read,'arguments':{'scheduleId':'ID'},'result':'schedule'},LIST:{**read,'arguments':{'limit':'1-100','afterScheduleId':'keyset'},'result':'page'},RUN:{**mutation,'arguments':{'scheduleId':'ID'},'result':'durable occurrence'},OCCURRENCE_READ:{**read,'arguments':{'occurrenceId':'ID'},'result':'occurrence'},CANCEL:{**mutation,'arguments':{'occurrenceId':'ID'},'result':'cancel requested'}}

def _utc(value):
    try:v=datetime.fromisoformat(value.replace('Z','+00:00'))
    except (AttributeError,ValueError) as e:raise ValueError('PYTHON_SCHEDULE_TIME_INVALID') from e
    if v.tzinfo is None or v.utcoffset()!=timezone.utc.utcoffset(v):raise ValueError('PYTHON_SCHEDULE_TIME_INVALID')
    return v.astimezone(timezone.utc)

class PostgresPythonSchedules:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('Verified identity is required')
        self.dsn,self.identity=dsn,identity
    @staticmethod
    def _scope(db,scope):PostgresNumericFactStore._set_scope(db,scope)
    @staticmethod
    def _execution_identity(row):
        return durable_execution_identity(row,issuer='execution_issuer',
            subject='execution_subject',groups='execution_groups',
            token_issued_at='execution_token_issued_at',
            authority_kind='execution_authority_kind')
    @classmethod
    def _assert_authorization_scope(cls,db,scope,row):
        identity=cls._execution_identity(row)
        access=PostgresAccessChecker.check_in_transaction(
            db,identity,scope,'write')
        current=resolve_effective_dimensional_scope(
            db,identity,scope,access=access).scope_digest
        if (row.get('authorization_scope_digest') is None
                or row['authorization_scope_digest']!=current):
            raise AccessDenied('PYTHON_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED')
        return current
    @staticmethod
    def _args(program,function):
        if type(program) is not dict or set(program)!={'languageVersion','function','arguments'} or program.get('languageVersion')!=2 or program.get('function')!=function or type(program.get('arguments')) is not dict:raise ValueError('PYTHON_SCHEDULE_PROGRAM_INVALID')
        return program['arguments']
    def execute(self,scope,program,*,idempotency_key=None):
        fn=program.get('function') if type(program) is dict else None
        if fn in (READ,LIST,OCCURRENCE_READ):return self.read(scope,program)
        if fn==RUN:return self.run_due(scope,program,idempotency_key=idempotency_key)
        if fn==CANCEL:return self.cancel(scope,program,idempotency_key=idempotency_key)
        if fn not in (SAVE,PUBLISH,DEACTIVATE) or type(idempotency_key) is not str or not _KEY.fullmatch(idempotency_key):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        a=self._args(program,fn);pins={'expectedMetadataRevision','expectedPolicyRevision','expectedSchemaEpoch'}
        common={'scheduleId','expectedStateRevision'}|pins
        required=(common|{'expectedVersion','programId','programVersion','parameters','intervalSeconds','firstDueAt','catchUpPolicy','maxCatchUp','delegationId','delegationVersion'} if fn==SAVE else common|{'version'})
        if set(a)!=required or type(a.get('scheduleId')) is not str or not _ID.fullmatch(a['scheduleId']):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        ints=({'expectedVersion','programVersion','intervalSeconds','maxCatchUp','delegationVersion'} if fn==SAVE else {'version'})|{'expectedStateRevision'}|pins
        if any(type(a.get(k)) is not int or a[k]<0 for k in ints):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        if fn==SAVE and (type(a['parameters']) is not dict or not 60<=a['intervalSeconds']<=2678400 or a['catchUpPolicy'] not in ('skip','latest','all') or not 1<=a['maxCatchUp']<=36 or not _ID.fullmatch(a['programId']) or not _ID.fullmatch(a['delegationId'])):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        first=_utc(a['firstDueAt']) if fn==SAVE else None
        digest=sha256(json.dumps({'scope':[scope.workspace_id,scope.application_id],'identity':[self.identity.issuer,self.identity.subject_id],'program':program},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db);self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=fn)
            old=db.execute('SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if old:
                if old['command_digest']!=digest or old['actor_id']!=self.identity.subject_id:raise ValueError('PYTHON_SCHEDULE_IDEMPOTENCY_CONFLICT')
                return old['result']
            state=db.execute('SELECT metadata_revision,policy_revision,schema_epoch,commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id)).fetchone()
            if state is None or (state['metadata_revision'],state['policy_revision'],state['schema_epoch'])!=(a['expectedMetadataRevision'],a['expectedPolicyRevision'],a['expectedSchemaEpoch']):raise ValueError('PYTHON_SCHEDULE_STALE_CONTEXT')
            pointer=db.execute('SELECT * FROM epm.python_program_schedule_state WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id,a['scheduleId'])).fetchone();current=pointer or {'latest_version':0,'active_version':None,'state_revision':0}
            if current['state_revision']!=a['expectedStateRevision']:raise ValueError('PYTHON_SCHEDULE_STALE_STATE')
            if fn==SAVE:
                version=a['expectedVersion']+1
                if current['latest_version']!=a['expectedVersion']:raise ValueError('PYTHON_SCHEDULE_STALE_VERSION')
                row=db.execute('''SELECT v.issuer,v.subject_id,
                    v.verified_groups,v.authorization_scope_digest
                    FROM epm.execution_delegation_version v
                    JOIN epm.python_program_publication p
                      ON p.workspace_id=v.workspace_id
                     AND p.application_id=v.application_id
                     AND p.program_id=%s AND p.version=%s
                     AND p.status='Published'
                    WHERE v.workspace_id=%s AND v.application_id=%s
                      AND v.delegation_id=%s AND v.version=%s''',(
                    a['programId'],a['programVersion'],scope.workspace_id,
                    scope.application_id,a['delegationId'],
                    a['delegationVersion'])).fetchone()
                if row is None or not all(db.execute('SELECT epm.execution_delegation_is_current(%s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed',(scope.workspace_id,scope.application_id,a['delegationId'],a['delegationVersion'],row['issuer'],row['subject_id'],operation,a['scheduleId'],version)).fetchone()['allowed'] for operation in ('python.program.build','python.program.run')):raise ValueError('PYTHON_SCHEDULE_AUTHORITY_INVALID')
                authority={'execution_issuer':row['issuer'],
                    'execution_subject':row['subject_id'],
                    'execution_groups':row['verified_groups'],
                    'authorization_scope_digest':
                        row['authorization_scope_digest']}
                self._assert_authorization_scope(db,scope,authority)
            else:
                version=a['version'];row=db.execute('SELECT * FROM epm.python_program_schedule_version WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s AND version=%s',(scope.workspace_id,scope.application_id,a['scheduleId'],version)).fetchone()
                if row is None:raise ValueError('PYTHON_SCHEDULE_VERSION_UNAVAILABLE')
                if fn==PUBLISH and not all(db.execute('SELECT epm.execution_delegation_is_current(%s,%s,%s,%s,%s,%s,%s,%s,%s) AS allowed',(scope.workspace_id,scope.application_id,row['delegation_id'],row['delegation_version'],row['execution_issuer'],row['execution_subject'],operation,a['scheduleId'],version)).fetchone()['allowed'] for operation in ('python.program.build','python.program.run')):raise ValueError('PYTHON_SCHEDULE_AUTHORITY_INVALID')
                if fn==PUBLISH:self._assert_authorization_scope(db,scope,row)
                if fn==PUBLISH and current['active_version']==version:raise ValueError('PYTHON_SCHEDULE_ALREADY_ACTIVE')
                if fn==DEACTIVATE and current['active_version']!=version:raise ValueError('PYTHON_SCHEDULE_ACTIVE_VERSION_MISMATCH')
            revision=state['commit_revision']+1;result={'operationId':idempotency_key,'scheduleId':a['scheduleId'],'version':version,'status':'Saved' if fn==SAVE else 'Published' if fn==PUBLISH else 'Deactivated','committedRevision':revision,'policyRevision':state['policy_revision']+1}
            db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
            if fn==SAVE:db.execute('''INSERT INTO epm.python_program_schedule_version(workspace_id,application_id,schedule_id,version,program_id,program_version,parameter_values,interval_seconds,first_due_at,catch_up_policy,max_catch_up,execution_issuer,execution_subject,delegation_id,delegation_version,operation_id,created_revision,execution_groups,authorization_scope_digest) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,a['scheduleId'],version,a['programId'],a['programVersion'],Jsonb(a['parameters']),a['intervalSeconds'],first,a['catchUpPolicy'],a['maxCatchUp'],row['issuer'],row['subject_id'],a['delegationId'],a['delegationVersion'],idempotency_key,revision,row['verified_groups'],row['authorization_scope_digest']))
            active=current['active_version'] if fn==SAVE else version if fn==PUBLISH else None
            if pointer:db.execute('UPDATE epm.python_program_schedule_state SET latest_version=%s,active_version=%s,state_revision=state_revision+1,last_due_at=CASE WHEN active_version IS DISTINCT FROM %s THEN NULL ELSE last_due_at END,dispatch_error_code=CASE WHEN active_version IS DISTINCT FROM %s THEN NULL ELSE dispatch_error_code END,dispatch_failure_count=CASE WHEN active_version IS DISTINCT FROM %s THEN 0 ELSE dispatch_failure_count END,dispatch_next_attempt_at=CASE WHEN active_version IS DISTINCT FROM %s THEN NULL ELSE dispatch_next_attempt_at END,updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s',(version if fn==SAVE else current['latest_version'],active,active,active,active,active,scope.workspace_id,scope.application_id,a['scheduleId']))
            else:db.execute('INSERT INTO epm.python_program_schedule_state(workspace_id,application_id,schedule_id,latest_version,active_version,state_revision) VALUES(%s,%s,%s,%s,NULL,1)',(scope.workspace_id,scope.application_id,a['scheduleId'],version))
            db.execute('UPDATE epm.application_state SET policy_revision=policy_revision+1,commit_revision=%s WHERE workspace_id=%s AND application_id=%s',(revision,scope.workspace_id,scope.application_id));return result

    def read(self,scope,program):
        fn=program.get('function');a=self._args(program,fn)
        if fn==OCCURRENCE_READ:
            if (set(a)!={'occurrenceId'} or type(a['occurrenceId']) is not str
                    or not _OCCURRENCE_ID.fullmatch(a['occurrenceId'])):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        elif fn==READ:
            if (set(a)!={'scheduleId'} or type(a['scheduleId']) is not str
                    or not _ID.fullmatch(a['scheduleId'])):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        elif fn==LIST:
            if (set(a)-{'limit','afterScheduleId'}
                    or type(a.get('limit',100)) is not int
                    or not 1<=a.get('limit',100)<=100
                    or (a.get('afterScheduleId') is not None and
                        (type(a['afterScheduleId']) is not str or
                         not _ID.fullmatch(a['afterScheduleId'])))):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        else:raise ValueError('PYTHON_SCHEDULE_FUNCTION_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            db.execute('SET TRANSACTION READ ONLY');self._scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=fn)
            if fn==OCCURRENCE_READ:
                row=db.execute('SELECT * FROM epm.python_program_occurrence WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s',(scope.workspace_id,scope.application_id,a.get('occurrenceId'))).fetchone();return {'defined':row is not None,'occurrence':dict(row) if row else None}
            exact=a.get('scheduleId') if fn==READ else None;limit=a.get('limit',100);after=a.get('afterScheduleId')
            rows=db.execute('''SELECT s.*,v.program_id,v.program_version,v.parameter_values,v.interval_seconds,v.first_due_at,v.catch_up_policy,v.max_catch_up,v.delegation_id,v.delegation_version FROM epm.python_program_schedule_state s JOIN epm.python_program_schedule_version v ON (v.workspace_id,v.application_id,v.schedule_id,v.version)=(s.workspace_id,s.application_id,s.schedule_id,s.latest_version) WHERE s.workspace_id=%s AND s.application_id=%s AND (%s::text IS NULL OR s.schedule_id=%s) AND (%s::text IS NULL OR s.schedule_id>%s) ORDER BY s.schedule_id LIMIT %s''',(scope.workspace_id,scope.application_id,exact,exact,after,after,limit+1)).fetchall();values=[dict(r) for r in rows[:limit]];return {'defined':bool(values),'schedule':values[0] if values else None} if fn==READ else {'schedules':values,'nextAfterScheduleId':rows[limit-1]['schedule_id'] if len(rows)>limit else None}

    def run_due(self,scope,program,*,idempotency_key):
        a=self._args(program,RUN)
        if set(a)!={'scheduleId'} or not _ID.fullmatch(a['scheduleId']):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=RUN)
            row=db.execute('''SELECT s.active_version,s.last_due_at,v.*,clock_timestamp() now FROM epm.python_program_schedule_state s JOIN epm.python_program_schedule_version v ON (v.workspace_id,v.application_id,v.schedule_id,v.version)=(s.workspace_id,s.application_id,s.schedule_id,s.active_version) WHERE s.workspace_id=%s AND s.application_id=%s AND s.schedule_id=%s FOR UPDATE OF s''',(scope.workspace_id,scope.application_id,a['scheduleId'])).fetchone()
            if row is None:raise ValueError('PYTHON_SCHEDULE_INACTIVE')
            self._assert_authorization_scope(db,scope,row)
            due=due_from_interval(first_due_at=row['first_due_at'],interval_seconds=row['interval_seconds'],last_due_at=row['last_due_at'],through=row['now'],policy=CatchUpPolicy(row['catch_up_policy']),maximum=row['max_catch_up'])
            if not due:return {'scheduleId':a['scheduleId'],'status':'NotDue','occurrence':None}
            instant=due[0] if row['catch_up_policy']=='all' else due[-1];raw=json.dumps([scope.workspace_id,scope.application_id,a['scheduleId'],row['active_version'],instant.isoformat()],separators=(',',':')).encode();oid=sha256(raw).hexdigest()[:32]
            db.execute('''INSERT INTO epm.python_program_occurrence(workspace_id,application_id,occurrence_id,schedule_id,schedule_version,due_at,status) VALUES(%s,%s,%s,%s,%s,%s,'ready') ON CONFLICT DO NOTHING''',(scope.workspace_id,scope.application_id,oid,a['scheduleId'],row['active_version'],instant));db.execute('UPDATE epm.python_program_schedule_state SET last_due_at=%s WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s',(instant,scope.workspace_id,scope.application_id,a['scheduleId']));return {'scheduleId':a['scheduleId'],'status':'Materialized','occurrenceId':oid,'dueAt':instant.isoformat()}

    def cancel(self,scope,program,*,idempotency_key):
        a=self._args(program,CANCEL)
        if set(a)!={'occurrenceId'} or type(a['occurrenceId']) is not str or not _OCCURRENCE_ID.fullmatch(a['occurrenceId']):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        return self.request_cancel_as_task_controller(scope,a['occurrenceId'])

    def request_cancel_as_task_controller(self,scope,occurrence_id):
        """Cancel one occurrence through its authoritative schedule policy."""
        if (not isinstance(scope,ApplicationScope)
                or type(occurrence_id) is not str
                or not _OCCURRENCE_ID.fullmatch(occurrence_id)):
            raise ValueError('PYTHON_SCHEDULE_OCCURRENCE_UNAVAILABLE')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            configure_statement_timeout(db,5000);configure_lock_wait(db)
            self._scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=CANCEL)
            row=db.execute('''SELECT status FROM epm.python_program_occurrence
                WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s
                FOR UPDATE''',(scope.workspace_id,scope.application_id,
                occurrence_id)).fetchone()
            if row is None:raise ValueError('PYTHON_SCHEDULE_OCCURRENCE_UNAVAILABLE')
            target=('cancelled' if row['status']=='ready' else
                'cancel_requested' if row['status'] in
                ('running','building','running_program') else row['status'])
            if target!=row['status']:
                db.execute('''UPDATE epm.python_program_occurrence SET status=%s,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s
                    AND application_id=%s AND occurrence_id=%s''',(target,
                    scope.workspace_id,scope.application_id,occurrence_id))
            return {'occurrenceId':occurrence_id,'status':target}
