"""One current durable schedule for an active Python program source."""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime,timezone
from hashlib import sha256
import json,re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .current_object_contract import is_state_token,new_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied,PostgresAccessChecker,
                              VerifiedIdentity,durable_execution_identity)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout,configure_lock_wait
from .recurrence import CatchUpPolicy,due_from_interval
from .postgres_python_occurrence_control import public_occurrence,OccurrenceCancellationResult

SAVE='python.schedule.save';READ='python.schedule.read';LIST='python.schedule.list'
ACTIVATE='python.schedule.activate';DEACTIVATE='python.schedule.deactivate'
RUN='python.schedule.run';OCCURRENCE_READ='python.schedule.occurrence.read'
OCCURRENCE_LIST='python.schedule.occurrence.list'
CANCEL='python.schedule.occurrence.cancel'
EFFECTS=frozenset((SAVE,ACTIVATE,DEACTIVATE,RUN,CANCEL))
READS=frozenset((READ,LIST,OCCURRENCE_READ,OCCURRENCE_LIST))
FUNCTIONS=EFFECTS | READS
_ID=re.compile(r'^[A-Za-z0-9._-]{1,200}$');_KEY=re.compile(r'^[A-Za-z0-9._-]{8,128}$')
_OCCURRENCE_ID_PATTERN=r'[0-9a-f]{32}'
_OCCURRENCE_ID=re.compile(_OCCURRENCE_ID_PATTERN)
_OCCURRENCE_PAGE_SIZE=100
_SCHEDULE_PAGE_SIZE=100
_OCCURRENCE_STATUS=('ready','running','building','running_program','published',
                    'failed','cancel_requested','cancelled','needs_inspection')
READ_AUTHORIZATION_STALE='PYTHON_SCHEDULE_READ_AUTHORIZATION_STALE'


def _schedule_fields():
    identifier={'type':'string','pattern':r'^[A-Za-z0-9._-]{1,200}(?![\s\S])'}
    token={'type':'string','pattern':r'^[0-9a-f]{64}(?![\s\S])'}
    return {'workspace_id':{'type':'string'},'application_id':{'type':'string'},
        'schedule_id':identifier,'state_token':token,'status':{'enum':['Saved','Active']},
        'program_id':{'type':'string'},'program_source_token':token,'parameter_values':{'type':'object'},
        'interval_seconds':{'type':'integer','minimum':60,'maximum':2678400},
        'first_due_at':{'type':'string','format':'date-time'},'catch_up_policy':{'enum':['skip','latest','all']},
        'max_catch_up':{'type':'integer','minimum':1,'maximum':36},
        'execution_issuer':{'type':'string','minLength':1,'maxLength':300},
        'execution_subject':{'type':'string','minLength':1,'maxLength':300},
        'delegation_id':identifier,'delegation_state_token':token,'updated_operation_id':{'type':'string'},
        'last_due_at':{'type':['string','null'],'format':'date-time'},
        'dispatch_error_code':{'type':['string','null']},
        'dispatch_failure_count':{'type':'integer','minimum':0,'maximum':3},
        'dispatch_next_attempt_at':{'type':['string','null'],'format':'date-time'},
        'updated_at':{'type':'string','format':'date-time'}}


_SCHEDULE_READ_COLUMNS=', '.join('s.'+field for field in _schedule_fields())


def schedule_read_contract(function):
    from .metadata_read_contract import read_contract,read_example
    from .postgres_numeric_catalog import obj
    from .postgres_python_occurrence_control import public_occurrence_schema

    common=['Application read authority is checked before returning a result. '
            'On '+READ_AUTHORIZATION_STALE+', refresh the application catalogue and read again.']
    if function==OCCURRENCE_LIST:
        return occurrence_list_contract()
    if function==OCCURRENCE_READ:
        occurrence_id={'type':'string','pattern':'^'+_OCCURRENCE_ID_PATTERN+r'(?![\s\S])'}
        arguments=obj({'occurrenceId':occurrence_id})
        result={'oneOf':[obj({'defined':{'const':False},'occurrence':{'type':'null'}}),
                         obj({'defined':{'const':True},'occurrence':public_occurrence_schema(_OCCURRENCE_STATUS)})]}
        examples=[read_example(function,{'occurrenceId':'b'*32},name='Open one scheduled occurrence',
            binding='Use an exact occurrence_id from the history page or occurrenceId from a Materialized start.')]
        rules=['A missing occurrence returns defined=false. A recorded cancellation request can still be unresolved.',
               'Use the exact build_id or workflow_id to inspect technical results under their own current authority. '
               'Occurrence status alone cannot prove committed or rolled-back effects.']
    else:
        fields=_schedule_fields()
        identifier=fields['schedule_id']
        schedule=obj(fields)
        rules=['The schedule shows the configured source, actor and delegation. The worker rechecks current authority '
               'before admission and publication. Saved, Active and dispatch status do not certify execution authority.',
               'last_due_at records the scheduler position, and dispatch_next_attempt_at is a dispatch retry time.']
        if function==READ:
            arguments=obj({'scheduleId':identifier})
            result={'oneOf':[obj({'defined':{'const':False},'schedule':{'type':'null'}}),
                             obj({'defined':{'const':True},'schedule':schedule})]}
            examples=[read_example(function,{'scheduleId':'example-python-schedule'},
                name='Inspect one current Python schedule',
                binding='Use the exact schedule ID returned by the list or a schedule write.')]
            rules.append('A missing schedule returns defined=false. Copy state_token into a reviewed manual start or configuration change.')
        elif function==LIST:
            cursor={'anyOf':[identifier,{'type':'null'}]}
            arguments=obj({'limit':{'type':'integer','minimum':1,'maximum':_SCHEDULE_PAGE_SIZE,
                                   'default':_SCHEDULE_PAGE_SIZE},'afterScheduleId':cursor},[])
            result=obj({'schedules':{'type':'array','maxItems':_SCHEDULE_PAGE_SIZE,'items':schedule},
                        'nextAfterScheduleId':cursor})
            examples=[read_example(function,{'limit':25},name='Read the first Python schedule page',
                binding='Use the selected authorized application.'),
                read_example(function,{'limit':25,'afterScheduleId':'example-python-schedule'},
                name='Continue the Python schedule list',binding='Copy the exact non-null nextAfterScheduleId.')]
            rules.append('The list reads current schedules in schedule ID order. A null continuation ends the current page sequence.')
        else:
            raise ValueError('PYTHON_SCHEDULE_FUNCTION_INVALID')
    return read_contract(function,arguments,result,owner='PostgresPythonSchedules',
                         examples=examples,semantic_rules=[*common,*rules])


def occurrence_list_contract():
    from .metadata_read_contract import read_contract,read_example
    from .postgres_numeric_catalog import obj

    identifier={'type':'string','pattern':'^'+_OCCURRENCE_ID_PATTERN+r'(?![\s\S])'}
    cursor={'anyOf':[identifier,{'type':'null'}]}
    limit={'type':'integer','minimum':1,'maximum':_OCCURRENCE_PAGE_SIZE}
    row=obj({'occurrence_id':identifier,'schedule_id':{'type':'string'},
        'due_at':{'type':'string','format':'date-time'},
        'status':{'enum':list(_OCCURRENCE_STATUS)}})
    return read_contract(OCCURRENCE_LIST,obj({'limit':limit,'afterOccurrenceId':cursor},[]),
        obj({'occurrences':{'type':'array','maxItems':_OCCURRENCE_PAGE_SIZE,'items':row},
             'nextAfterOccurrenceId':cursor}),owner='PostgresPythonSchedules',
        examples=[
            read_example(OCCURRENCE_LIST,{'limit':25},name='Read the most recent scheduled runs',
                binding='Select the authorized application before listing occurrences.'),
            read_example(OCCURRENCE_LIST,{'limit':25,'afterOccurrenceId':'b'*32},
                name='Continue from the preceding page',
                binding='Use the exact nextAfterOccurrenceId from that application. Stop when it is null.')],
        semantic_rules=[
            'Current application read authority is checked on each page. Results are ordered newest due time first, then by occurrence ID descending for equal due times.',
            'Use occurrence_id with python.schedule.occurrence.read to open one exact run. The list contains only the occurrence ID, schedule ID, due time and status.',
            'An unavailable cursor yields an empty page. Start a new first page to refresh current history.',
            'On '+READ_AUTHORIZATION_STALE+', refresh the application catalogue and read again.',
        ])

def effect_contract(function):
    from .metadata_read_contract import read_contract,read_example
    from .postgres_numeric_catalog import obj

    identifier={'type':'string','pattern':r'^[A-Za-z0-9._-]{1,200}(?![\s\S])'}
    occurrence={'type':'string','pattern':r'^[0-9a-f]{32}(?![\s\S])'}
    token={'type':'string','pattern':r'^[0-9a-f]{64}(?![\s\S])'}
    operation={'type':'string','pattern':r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'}
    revision={'type':'integer','minimum':0,'maximum':2**63-1}
    utc={'type':'string','format':'date-time'}
    pins=dict.fromkeys(('expectedMetadataRevision','expectedPolicyRevision','expectedSchemaEpoch'),revision)
    example={'scheduleId':'example-python-schedule'}
    binding='Use the current schedule ID and state token from python.schedule.read.'
    if function==RUN:
        arguments=obj({'scheduleId':identifier,'expectedStateToken':token},['scheduleId'])
        result={'oneOf':[
            obj({'scheduleId':identifier,'status':{'const':'Materialized'},'occurrenceId':occurrence,'dueAt':utc}),
            obj({'scheduleId':identifier,'status':{'const':'NotDue'},'occurrence':{'type':'null'}})]}
        example['expectedStateToken']='a'*64
    elif function==CANCEL:
        arguments=obj({'occurrenceId':occurrence})
        result=obj({'occurrenceId':occurrence,
            'status':{'enum':['cancelled','cancel_requested','published','failed']}})
        example={'occurrenceId':'b'*32}
        binding='Read the exact occurrence first. Use a new reviewed admission for any deliberate re-arm.'
    else:
        required={'scheduleId':identifier,**pins}
        example.update(dict.fromkeys(pins,1))
        if function==SAVE:
            required.update({'programId':identifier,'programSourceToken':token,'parameters':{'type':'object'},
                'intervalSeconds':{'type':'integer','minimum':60,'maximum':2678400},
                'firstDueAt':utc,'catchUpPolicy':{'enum':['skip','latest','all']},
                'maxCatchUp':{'type':'integer','minimum':1,'maximum':36},
                'delegationId':identifier,'delegationStateToken':token})
            arguments=obj({**required,'expectedStateToken':{'anyOf':[token,{'type':'null'}]}},list(required))
            example.update(programId='example-python-program',programSourceToken='b'*64,parameters={},
                intervalSeconds=3600,firstDueAt='2035-01-01T00:00:00Z',catchUpPolicy='latest',maxCatchUp=1,
                delegationId='example-delegation',delegationStateToken='c'*64)
            binding=('Choose an active Python program and delegation. Read current revisions. '
                     'When replacing a schedule, include its current state token.')
        else:
            arguments=obj({**required,'expectedStateToken':token})
            example['expectedStateToken']='a'*64
            binding+=' Read current revision pins before obtaining admission.'
        result=obj({'operationId':operation,'scheduleId':identifier,'stateToken':token,
            'policyRevision':revision,'status':{'const':'Active' if function==ACTIVATE else 'Saved'}})
    contract=read_contract(function,arguments,result,owner='PostgresPythonSchedules',
        examples=[read_example(function,example,name='Use the governed Python schedule operation',binding=binding)],
        semantic_rules=[
            'Current application administrator authority is checked on execution and replay.',
            'An expired admission can only recover the exact original retained outcome.',
            'Manual starts and cancellation record control outcomes without business publication.',
        ])
    contract['programContract']['recovery']=(
        'After an interrupted response, send the exact program and original admission. '
        'If the request expired without a retained outcome, read the current schedule or occurrence '
        'and explicitly review any new action.')
    return contract


def catalog():
    common={'requiredCapabilities':[],'previewRequired':False,'workClass':'short'}
    mutation={**common,'mode':'atomic_configuration','permission':'admin','idempotencyRequired':True}
    read={**common,'mode':'read_only','permission':'read','idempotencyRequired':False}
    revisions={'expectedMetadataRevision':'revision','expectedPolicyRevision':'revision','expectedSchemaEpoch':'epoch'}
    definition={'scheduleId':'ID','programId':'active program','programSourceToken':'exact current source token','parameters':'typed object','intervalSeconds':'60-2678400','firstDueAt':'UTC','catchUpPolicy':'skip/latest/all','maxCatchUp':'1-36','delegationId':'exact authority','delegationStateToken':'current delegation token'}
    result={SAVE:{**mutation,'arguments':{**definition,**revisions},'optionalArguments':{'expectedStateToken':'required to replace current schedule'},'result':'current Saved schedule and state token'},ACTIVATE:{**mutation,'arguments':{'scheduleId':'ID','expectedStateToken':'current state token',**revisions},'result':'current Active schedule and rotated state token'},DEACTIVATE:{**mutation,'arguments':{'scheduleId':'ID','expectedStateToken':'current state token',**revisions},'result':'current Saved schedule and rotated state token'},READ:{**read,'arguments':{'scheduleId':'ID'},'result':'current schedule'},LIST:{**read,'arguments':{'limit':'1-100','afterScheduleId':'keyset'},'result':'current page'},RUN:{**mutation,'arguments':{'scheduleId':'ID'},'result':'durable occurrence'},OCCURRENCE_READ:{**read,'arguments':{'occurrenceId':'ID'},'result':'occurrence'},OCCURRENCE_LIST:{**read,'arguments':{'limit':'1-100','afterOccurrenceId':'keyset'},'result':'current occurrence page'},CANCEL:{**mutation,'arguments':{'occurrenceId':'ID'},'result':'cancel requested'}}
    rules=[
        'Occurrence cancellation requires current application administrator authority; it does not borrow or renew the original execution delegation.',
        'New scheduled build/workflow admissions and their occurrence links commit atomically. Cancellation and schedule rotation fence later admissions.',
        'cancel_requested is unresolved control, not rollback or proof that no work was accepted. Known committed receipts remain retained.',
        'A parked occurrence exposes a fixed diagnostic in read_v2_task latestEvent. Inspect task s:<occurrenceId>; a proven buildId or workflowId leads to task p:<buildId> or w:<workflowId> under current task visibility.',
        'After restoring current administrator authority, repeat Cancel on the same occurrence through python.schedule.occurrence.cancel to re-arm cancellation reconciliation only. Access restoration alone does not re-arm it.',
        'A legacy occurrence with an unprovable link stays cancel_requested with PYTHON_SCHEDULE_ADMISSION_UNRESOLVED. A current administrator may inspect separately known child tasks and control them through their existing owners; no idempotency-key guess can attach work or certify the occurrence as cancelled.',
        'Later viewers use current read/task grants. Controller provenance remains private and grants no public child read, preview, submit, rebuild or rerun capability.'
    ]
    result[RUN]['optionalArguments']={'expectedStateToken':'pin the reviewed current schedule'}
    result[RUN]['semanticRules']=[
        'A manual start records its exact Materialized or NotDue outcome without a business publication.',
        'Keep the original admission for recovery. A deliberate later start requires a new admission.',
        'Supply expectedStateToken when starting a reviewed schedule. An unused stale request cannot start the replacement schedule.',
    ]
    for function in (CANCEL,OCCURRENCE_READ,OCCURRENCE_LIST,SAVE,ACTIVATE,DEACTIVATE):
        result[function]['semanticRules']=list(rules)
    result[CANCEL]['semanticRules'].append(
        'Repeating the same admission reads its original outcome. To re-arm after restoring authority, review the current occurrence and request a new admission.')
    for function in READS:
        result[function].update(schedule_read_contract(function))
    for function in EFFECTS:
        result[function].update(effect_contract(function))
    return result


def _utc(value):
    try:v=datetime.fromisoformat(value.replace('Z','+00:00'))
    except (AttributeError,ValueError) as e:raise ValueError('PYTHON_SCHEDULE_TIME_INVALID') from e
    if v.tzinfo is None or v.utcoffset()!=timezone.utc.utcoffset(v):raise ValueError('PYTHON_SCHEDULE_TIME_INVALID')
    return v.astimezone(timezone.utc)

def _occurrence_id(scope,schedule_id,state_token,due_at,*,schema_epoch):
    if (type(schema_epoch) is not int or schema_epoch<0
            or not is_state_token(state_token)
            or type(schedule_id) is not str or not _ID.fullmatch(schedule_id)
            or type(due_at) is not datetime or due_at.tzinfo is None):
        raise ValueError('PYTHON_SCHEDULE_OCCURRENCE_INVALID')
    raw=json.dumps(['openepm-python-occurrence-v3',scope.workspace_id,
        scope.application_id,schema_epoch,schedule_id,state_token,
        due_at.astimezone(timezone.utc).isoformat()],separators=(',',':')).encode()
    return sha256(raw).hexdigest()[:32]

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

    def _command_digest(self, scope, program, operation_id):
        if type(operation_id) is not str or not _KEY.fullmatch(operation_id):
            raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        value = {'scope': [scope.workspace_id, scope.application_id],
                 'identity': [self.identity.issuer, self.identity.subject_id],
                 'program': program}
        return sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                 ensure_ascii=True).encode()).hexdigest()

    def execute(self,scope,program,*,idempotency_key=None,replay_only=False):
        fn=program.get('function') if type(program) is dict else None
        if isinstance(fn,str) and fn in READS and not replay_only:return self.read(scope,program)
        if fn==RUN:return self.run_due(scope,program,idempotency_key=idempotency_key,replay_only=replay_only)
        if fn==CANCEL:return self.cancel(scope,program,idempotency_key=idempotency_key,replay_only=replay_only)
        if fn not in (SAVE,ACTIVATE,DEACTIVATE):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        digest=self._command_digest(scope,program,idempotency_key)
        a=self._args(program,fn);pins={'expectedMetadataRevision','expectedPolicyRevision','expectedSchemaEpoch'}
        definition={'scheduleId','programId','programSourceToken','parameters','intervalSeconds','firstDueAt','catchUpPolicy','maxCatchUp','delegationId','delegationStateToken'}
        required=(definition|pins if fn==SAVE else {'scheduleId','expectedStateToken'}|pins)
        if fn==SAVE and 'expectedStateToken' in a:required=required|{'expectedStateToken'}
        if set(a)!=required or type(a.get('scheduleId')) is not str or not _ID.fullmatch(a['scheduleId']):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        ints=({'intervalSeconds','maxCatchUp'} if fn==SAVE else set())|pins
        if any(type(a.get(k)) is not int or a[k]<0 for k in ints):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        if ((fn==SAVE and a.get('expectedStateToken') is not None and not is_state_token(a['expectedStateToken'])) or (fn!=SAVE and not is_state_token(a.get('expectedStateToken')))):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        if fn==SAVE and (not is_state_token(a.get('delegationStateToken')) or not is_state_token(a.get('programSourceToken'))):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        if fn==SAVE and (type(a['parameters']) is not dict or not 60<=a['intervalSeconds']<=2678400 or a['catchUpPolicy'] not in ('skip','latest','all') or not 1<=a['maxCatchUp']<=36 or not _ID.fullmatch(a['programId']) or not _ID.fullmatch(a['delegationId'])):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        first=_utc(a['firstDueAt']) if fn==SAVE else None
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            if replay_only:db.execute('SET TRANSACTION READ ONLY')
            configure_statement_timeout(db,5000);configure_lock_wait(db);self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=fn)
            # Fence competing submissions before asking whether either committed.
            if not replay_only:
                state=db.execute('SELECT metadata_revision,policy_revision,schema_epoch,commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id)).fetchone()
            old=db.execute('SELECT command_digest,actor_id,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
            if old:
                if old['command_digest']!=digest or old['actor_id']!=self.identity.subject_id:raise ValueError('PYTHON_SCHEDULE_IDEMPOTENCY_CONFLICT')
                return old['result']
            if replay_only:return None
            if state is None or (state['metadata_revision'],state['policy_revision'],state['schema_epoch'])!=(a['expectedMetadataRevision'],a['expectedPolicyRevision'],a['expectedSchemaEpoch']):raise ValueError('PYTHON_SCHEDULE_STALE_CONTEXT')
            current=db.execute('SELECT * FROM epm.python_program_schedule_definition WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s FOR UPDATE',(scope.workspace_id,scope.application_id,a['scheduleId'])).fetchone()
            expected=a.get('expectedStateToken')
            if (current is None)!=(expected is None) or (current is not None and current['state_token']!=expected):raise ValueError('PYTHON_SCHEDULE_STALE_STATE')
            if fn==SAVE:
                row=db.execute('''SELECT v.issuer,v.subject_id,
                    v.verified_groups,v.authorization_scope_digest
                    FROM epm.execution_delegation_definition v
                    JOIN epm.python_program_definition p
                      ON p.workspace_id=v.workspace_id
                     AND p.application_id=v.application_id
                     AND p.program_id=%s AND p.source_token=%s
                     AND p.status='Active'
                    WHERE v.workspace_id=%s AND v.application_id=%s
                      AND v.delegation_id=%s AND v.state_token=%s
                      AND v.status='Active' ''',(
                    a['programId'],a['programSourceToken'],scope.workspace_id,
                    scope.application_id,a['delegationId'],
                    a['delegationStateToken'])).fetchone()
                if row is None or not all(db.execute('SELECT epm.execution_delegation_is_current(%s,%s,%s,%s,%s,%s,%s,%s) AS allowed',(scope.workspace_id,scope.application_id,a['delegationId'],a['delegationStateToken'],row['issuer'],row['subject_id'],operation,a['scheduleId'])).fetchone()['allowed'] for operation in ('python.program.build','python.program.run')):raise ValueError('PYTHON_SCHEDULE_AUTHORITY_INVALID')
                if (row['issuer'],row['subject_id']) == (self.identity.issuer,self.identity.subject_id):
                    if type(self.identity.issued_at) is not int or self.identity.issued_at <= 0:
                        raise ValueError('DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED')
                    execution_token_issued_at = self.identity.issued_at
                    execution_authority_kind = 'HumanToken'
                elif row['issuer'].startswith('urn:openepm:'):
                    execution_token_issued_at = None
                    execution_authority_kind = 'Technical'
                else:
                    raise ValueError('DURABLE_HUMAN_TOKEN_ISSUED_AT_REQUIRED')
                authority={'execution_issuer':row['issuer'],
                    'execution_token_issued_at':execution_token_issued_at,
                    'execution_authority_kind':execution_authority_kind,
                    'execution_subject':row['subject_id'],
                    'execution_groups':row['verified_groups'],
                    'authorization_scope_digest':
                        row['authorization_scope_digest']}
                self._assert_authorization_scope(db,scope,authority)
            else:
                if current is None:raise ValueError('PYTHON_SCHEDULE_UNAVAILABLE')
                row=current
                if fn==ACTIVATE and not all(db.execute('SELECT epm.execution_delegation_is_current(%s,%s,%s,%s,%s,%s,%s,%s) AS allowed',(scope.workspace_id,scope.application_id,row['delegation_id'],row['delegation_state_token'],row['execution_issuer'],row['execution_subject'],operation,a['scheduleId'])).fetchone()['allowed'] for operation in ('python.program.build','python.program.run')):raise ValueError('PYTHON_SCHEDULE_AUTHORITY_INVALID')
                if fn==ACTIVATE:self._assert_authorization_scope(db,scope,row)
                if fn==ACTIVATE and current['status']=='Active':raise ValueError('PYTHON_SCHEDULE_ALREADY_ACTIVE')
                if fn==DEACTIVATE and current['status']!='Active':raise ValueError('PYTHON_SCHEDULE_NOT_ACTIVE')
            revision=state['commit_revision']+1;state_token=new_state_token();status='Saved' if fn in (SAVE,DEACTIVATE) else 'Active';result={'operationId':idempotency_key,'scheduleId':a['scheduleId'],'stateToken':state_token,'status':status,'policyRevision':state['policy_revision']+1}
            db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
            if fn==SAVE:
                values=(state_token,status,a['programId'],a['programSourceToken'],Jsonb(a['parameters']),a['intervalSeconds'],first,a['catchUpPolicy'],a['maxCatchUp'],row['issuer'],row['subject_id'],a['delegationId'],a['delegationStateToken'],idempotency_key,row['verified_groups'],row['authorization_scope_digest'],execution_token_issued_at,execution_authority_kind,scope.workspace_id,scope.application_id,a['scheduleId'])
                if current:db.execute('''UPDATE epm.python_program_schedule_definition SET state_token=%s,status=%s,program_id=%s,program_source_token=%s,parameter_values=%s,interval_seconds=%s,first_due_at=%s,catch_up_policy=%s,max_catch_up=%s,execution_issuer=%s,execution_subject=%s,delegation_id=%s,delegation_state_token=%s,updated_operation_id=%s,execution_groups=%s,authorization_scope_digest=%s,execution_token_issued_at=%s,execution_authority_kind=%s,last_due_at=NULL,dispatch_error_code=NULL,dispatch_failure_count=0,dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s''',values)
                else:db.execute('''INSERT INTO epm.python_program_schedule_definition(state_token,status,program_id,program_source_token,parameter_values,interval_seconds,first_due_at,catch_up_policy,max_catch_up,execution_issuer,execution_subject,delegation_id,delegation_state_token,updated_operation_id,execution_groups,authorization_scope_digest,execution_token_issued_at,execution_authority_kind,workspace_id,application_id,schedule_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',values)
            else:db.execute('''UPDATE epm.python_program_schedule_definition SET state_token=%s,status=%s,updated_operation_id=%s,last_due_at=NULL,dispatch_error_code=NULL,dispatch_failure_count=0,dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s''',(state_token,status,idempotency_key,scope.workspace_id,scope.application_id,a['scheduleId']))
            self._cancel_rotated(db,scope,a['scheduleId'],state_token)
            db.execute('UPDATE epm.application_state SET policy_revision=policy_revision+1,commit_revision=%s WHERE workspace_id=%s AND application_id=%s',(revision,scope.workspace_id,scope.application_id));return result

    def read(self,scope,program):
        fn=program.get('function');a=self._args(program,fn)
        if fn==OCCURRENCE_READ:
            if (set(a)!={'occurrenceId'} or type(a['occurrenceId']) is not str
                    or not _OCCURRENCE_ID.fullmatch(a['occurrenceId'])):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        elif fn==OCCURRENCE_LIST:
            limit=a.get('limit',_OCCURRENCE_PAGE_SIZE)
            after=a.get('afterOccurrenceId')
            if (set(a)-{'limit','afterOccurrenceId'}
                    or type(limit) is not int or not 1<=limit<=_OCCURRENCE_PAGE_SIZE
                    or (after is not None and
                        (type(after) is not str or not _OCCURRENCE_ID.fullmatch(after)))):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        elif fn==READ:
            if (set(a)!={'scheduleId'} or type(a['scheduleId']) is not str
                    or not _ID.fullmatch(a['scheduleId'])):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        elif fn==LIST:
            if (set(a)-{'limit','afterScheduleId'}
                    or type(a.get('limit',_SCHEDULE_PAGE_SIZE)) is not int
                    or not 1<=a.get('limit',_SCHEDULE_PAGE_SIZE)<=_SCHEDULE_PAGE_SIZE
                    or (a.get('afterScheduleId') is not None and
                        (type(a['afterScheduleId']) is not str or
                         not _ID.fullmatch(a['afterScheduleId'])))):
                raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        else:raise ValueError('PYTHON_SCHEDULE_FUNCTION_INVALID')
        with self._authorized_read(scope,fn) as db:
            if fn==OCCURRENCE_READ:
                row=db.execute('SELECT * FROM epm.python_program_occurrence WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s',(scope.workspace_id,scope.application_id,a.get('occurrenceId'))).fetchone();return {'defined':row is not None,'occurrence':public_occurrence(row) if row else None}
            if fn==OCCURRENCE_LIST:
                rows=db.execute('''WITH page_cursor AS (
                      SELECT due_at,occurrence_id
                      FROM epm.python_program_occurrence
                      WHERE workspace_id=%s AND application_id=%s
                        AND occurrence_id=%s
                    )
                    SELECT occurrence_id,schedule_id,due_at,status
                    FROM epm.python_program_occurrence
                    WHERE workspace_id=%s AND application_id=%s
                      AND (%s::text IS NULL OR (due_at,occurrence_id)<
                        (SELECT due_at,occurrence_id FROM page_cursor))
                    ORDER BY due_at DESC,occurrence_id DESC LIMIT %s''',(
                    scope.workspace_id,scope.application_id,after,
                    scope.workspace_id,scope.application_id,after,
                    limit+1)).fetchall()
                values=[dict(row) for row in rows[:limit]]
                return {'occurrences':values,'nextAfterOccurrenceId':
                    rows[limit-1]['occurrence_id'] if len(rows)>limit else None}
            exact=a.get('scheduleId') if fn==READ else None
            limit=a.get('limit',_SCHEDULE_PAGE_SIZE)
            after=a.get('afterScheduleId')
            rows=db.execute(f'''SELECT {_SCHEDULE_READ_COLUMNS}
                FROM epm.python_program_schedule_definition s
                JOIN epm.application_state state ON state.workspace_id=s.workspace_id
                  AND state.application_id=s.application_id
                WHERE s.workspace_id=%s AND s.application_id=%s
                  AND (%s::text IS NULL OR s.schedule_id=%s)
                  AND (%s::text IS NULL OR s.schedule_id>%s)
                ORDER BY s.schedule_id LIMIT %s''', (scope.workspace_id,scope.application_id,
                   exact,exact,after,after,limit+1)).fetchall()
            values=[dict(row) for row in rows[:limit]]
            if fn==READ:
                return {'defined':bool(values),'schedule':values[0] if values else None}
            return {'schedules':values,'nextAfterScheduleId':
                rows[limit-1]['schedule_id'] if len(rows)>limit else None}

    @contextmanager
    def _authorized_read(self, scope, function):
        """Project the selected row or page, then recheck the current directory."""
        with connect_postgres(self.dsn,row_factory=dict_row) as db, db.transaction():
            db.execute('SET TRANSACTION READ ONLY')
            configure_statement_timeout(db,5000)
            self._scope(db,scope)
            initial=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=function)
            yield db
            if PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=function)!=initial:
                raise ValueError(READ_AUTHORIZATION_STALE)

    @contextmanager
    def _control_transaction(self, scope, function, operation_id, command_digest, *, replay_only):
        from .postgres_python_occurrence_control import lock_state
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                if replay_only:
                    db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                configure_lock_wait(db)
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=function)
                prior = (self._prior_control(db, scope, operation_id, command_digest)
                         if operation_id is not None else None)
                if prior is None and not replay_only:
                    lock_state(db, scope)
                    # A concurrent original can publish while this request waits.
                    if operation_id is not None:
                        prior = self._prior_control(db, scope, operation_id, command_digest)
                yield db, prior

    @staticmethod
    def _prior_control(db, scope, operation_id, command_digest):
        row = db.execute('''SELECT command_digest,result
            FROM epm.python_schedule_control_receipt
            WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''', (
                scope.workspace_id, scope.application_id, operation_id)).fetchone()
        if row is None:
            return None
        if row['command_digest'] != command_digest:
            raise ValueError('PYTHON_SCHEDULE_IDEMPOTENCY_CONFLICT')
        return row['result']

    @staticmethod
    def _record_control(db, scope, operation_id, command_digest, result):
        db.execute('''INSERT INTO epm.python_schedule_control_receipt(
            workspace_id,application_id,operation_id,command_digest,result)
            VALUES(%s,%s,%s,%s,%s)''', (
                scope.workspace_id, scope.application_id, operation_id,
                command_digest, Jsonb(result)))
        return result

    def run_due(self,scope,program,*,idempotency_key,replay_only=False):
        a=self._args(program,RUN)
        if (set(a) not in ({'scheduleId'},{'scheduleId','expectedStateToken'})
                or type(a['scheduleId']) is not str or not _ID.fullmatch(a['scheduleId'])
                or ('expectedStateToken' in a and not is_state_token(a['expectedStateToken']))):
            raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        digest=self._command_digest(scope,program,idempotency_key)
        with self._control_transaction(scope,RUN,idempotency_key,digest,
                replay_only=replay_only) as (db,old):
            if old is not None or replay_only:return old
            row=db.execute('''SELECT s.*,state.schema_epoch,clock_timestamp() now FROM epm.python_program_schedule_definition s JOIN epm.application_state state ON state.workspace_id=s.workspace_id AND state.application_id=s.application_id WHERE s.workspace_id=%s AND s.application_id=%s AND s.schedule_id=%s AND s.status='Active' FOR UPDATE OF s''',(scope.workspace_id,scope.application_id,a['scheduleId'])).fetchone()
            if row is None:raise ValueError('PYTHON_SCHEDULE_INACTIVE')
            if a.get('expectedStateToken',row['state_token'])!=row['state_token']:
                raise ValueError('PYTHON_SCHEDULE_STALE_STATE')
            self._assert_authorization_scope(db,scope,row)
            due=due_from_interval(first_due_at=row['first_due_at'],interval_seconds=row['interval_seconds'],last_due_at=row['last_due_at'],through=row['now'],policy=CatchUpPolicy(row['catch_up_policy']),maximum=row['max_catch_up'])
            if not due:
                result={'scheduleId':a['scheduleId'],'status':'NotDue','occurrence':None}
            else:
                instant=due[0] if row['catch_up_policy']=='all' else due[-1]
                oid=_occurrence_id(scope,a['scheduleId'],row['state_token'],instant,schema_epoch=row['schema_epoch'])
                db.execute('''INSERT INTO epm.python_program_occurrence(workspace_id,application_id,occurrence_id,schedule_id,schedule_state_token,due_at,status,admission_protocol) VALUES(%s,%s,%s,%s,%s,%s,'ready',1) ON CONFLICT DO NOTHING''',(scope.workspace_id,scope.application_id,oid,a['scheduleId'],row['state_token'],instant))
                db.execute('UPDATE epm.python_program_schedule_definition SET last_due_at=%s WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s AND state_token=%s',(instant,scope.workspace_id,scope.application_id,a['scheduleId'],row['state_token']))
                result={'scheduleId':a['scheduleId'],'status':'Materialized','occurrenceId':oid,'dueAt':instant.isoformat()}
            return self._record_control(db,scope,idempotency_key,digest,result)

    def cancel(self,scope,program,*,idempotency_key,replay_only=False):
        a=self._args(program,CANCEL)
        if set(a)!={'occurrenceId'} or type(a['occurrenceId']) is not str or not _OCCURRENCE_ID.fullmatch(a['occurrenceId']):raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        digest=self._command_digest(scope,program,idempotency_key)
        native=self.request_cancel_as_task_controller(scope,a['occurrenceId'],
            operation_id=idempotency_key,command_digest=digest,replay_only=replay_only)
        if native is None:return None
        return {key:native[key] for key in ('occurrenceId','status')}

    def _cancel_rotated(self,db,scope,schedule_id,current_token):
        from .postgres_python_occurrence_control import control_seal
        # Capture this actual authorized caller, not the overwritten execution actor.
        seal=control_seal(db,scope,self.identity,1,cause='ScheduleRotation')
        db.execute('''WITH locked AS (
            SELECT occurrence_id FROM epm.python_program_occurrence
            WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s
              AND schedule_state_token<>%s AND status IN
                ('ready','running','building','running_program','cancel_requested','needs_inspection')
            ORDER BY occurrence_id FOR UPDATE)
            UPDATE epm.python_program_occurrence o SET
              status=CASE WHEN build_id IS NULL AND workflow_id IS NULL AND
                (admission_protocol=1 OR (status='ready' AND claim_generation=0 AND first_claimed_at IS NULL))
                THEN 'cancelled' ELSE 'cancel_requested' END,
              control_authority=jsonb_set(%s::jsonb,'{requestGeneration}',to_jsonb(claim_generation+1)),
              claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
              worker_failures=0,next_attempt_at=NULL,error_code=NULL,updated_at=transaction_timestamp()
            FROM locked WHERE o.workspace_id=%s AND o.application_id=%s
              AND o.occurrence_id=locked.occurrence_id''',
            (scope.workspace_id,scope.application_id,schedule_id,current_token,
             Jsonb(seal),scope.workspace_id,scope.application_id))

    def request_cancel_as_task_controller(self,scope,occurrence_id,*,
            operation_id=None,command_digest=None,replay_only=False) -> OccurrenceCancellationResult|None:
        """Persist current admin authority and stop admission before returning."""
        from .postgres_python_occurrence_control import (control_seal,
            null_link_proves_absence,PythonOccurrenceControl,stop_linked,UNRESOLVED,retained_effects)
        if (not isinstance(scope,ApplicationScope) or type(occurrence_id) is not str
                or not _OCCURRENCE_ID.fullmatch(occurrence_id)):
            raise ValueError('PYTHON_SCHEDULE_OCCURRENCE_UNAVAILABLE')
        if replay_only and operation_id is None:
            raise ValueError('PYTHON_SCHEDULE_ARGUMENTS_INVALID')
        with self._control_transaction(scope,CANCEL,operation_id,command_digest,
                replay_only=replay_only) as (db,prior):
            if prior is not None or replay_only:return prior
            row=db.execute('''SELECT * FROM epm.python_program_occurrence
                WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s FOR UPDATE''',
                (scope.workspace_id,scope.application_id,occurrence_id)).fetchone()
            if row is None:raise ValueError('PYTHON_SCHEDULE_OCCURRENCE_UNAVAILABLE')
            if row['status'] in ('published','failed','cancelled'):
                certainty=retained_effects(row)
                if certainty is None and row['status']!='published' and null_link_proves_absence(row):certainty=False
                result={'occurrenceId':occurrence_id,'status':row['status'],'committedEffectsRemain':certainty}
                if operation_id is not None:
                    return self._record_control(db,scope,operation_id,command_digest,result)
                return result
            absent=null_link_proves_absence(row)
            certainty=False if absent else retained_effects(row)
            target='cancelled' if absent else 'cancel_requested'
            seal=control_seal(db,scope,self.identity,row['claim_generation']+1,cause='ExplicitCancel')
            row=db.execute('''UPDATE epm.python_program_occurrence SET status=%s,
                control_authority=%s,claim_generation=claim_generation+1,
                claimant=NULL,lease_until=NULL,worker_failures=0,next_attempt_at=NULL,
                error_code=NULL,updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s RETURNING *''',
                (target,Jsonb(seal),scope.workspace_id,scope.application_id,occurrence_id)).fetchone()
            if target=='cancel_requested':
                control=PythonOccurrenceControl.from_row(scope,row)
                try:
                    # A savepoint preserves durable stop intent if original link proof is unavailable.
                    with db.transaction():
                        _,_,_,_,observed=stop_linked(db,self.dsn,scope,control)
                        if observed is not None:certainty=observed
                except ValueError as error:
                    if str(error) not in (UNRESOLVED,'WORKFLOW_CANCELLATION_CHILD_PROOF_UNAVAILABLE'):
                        raise
                    db.execute('''UPDATE epm.python_program_occurrence SET worker_failures=3,
                        error_code=%s WHERE workspace_id=%s AND application_id=%s AND occurrence_id=%s''',
                        (UNRESOLVED,scope.workspace_id,scope.application_id,occurrence_id))
            result={'occurrenceId':occurrence_id,'status':target,'committedEffectsRemain':certainty}
            if operation_id is not None:
                return self._record_control(db,scope,operation_id,command_digest,result)
            return result
