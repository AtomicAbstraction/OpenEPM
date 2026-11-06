"""Explicit activation/withdrawal of approved acquisition policy variants."""
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
from .postgres_policy_cases import _CORE_VERSIONS
from .postgres_policy_drafts import (
    _date, validate_elections_in_transaction,
    _program as _elections_program, ELECTIONS_FUNCTION)


ACTIVATE = 'consolidation.policy.acquisition.activate'
WITHDRAW = 'consolidation.policy.acquisition.withdraw'
READ = 'consolidation.policy.acquisition.activation.read'
RESOLVE = 'consolidation.policy.acquisition.activation.resolve'
CURRENT = 'consolidation.policy.acquisition.activation.current.read'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_ID = re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')


def variant_key(scope,policy_id,policy_version,selections,function):
    return _canonical_digest({'scope':[scope.workspace_id,scope.application_id],
        'policyId':policy_id,'policyVersion':policy_version,
        'selections':dict(sorted(selections.items())),
        'candidateFunction':function})


def _program(raw):
    if (not isinstance(raw,dict)
            or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion']!=2 or not isinstance(raw['function'],str)
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('POLICY_ACTIVATION_PROGRAM_INVALID')
    function,args=raw['function'],raw['arguments']
    expected={
        ACTIVATE:{'approvalId','expectedApprovalDigest','policyBindingDigest',
            'effectiveFrom','effectiveBefore','expectedActiveEventId',
            'expectedPolicyRevision','expectedCommitRevision','reason'},
        WITHDRAW:{'variantKey','expectedActivationId','expectedActiveEventId',
            'expectedPolicyRevision','expectedCommitRevision','reason'},
        READ:{'eventId'},
        CURRENT:{'policyId','policyVersion','candidateFunction','selections'},
        RESOLVE:{'policyId','policyVersion','candidateFunction','selections',
                 'effectiveOn','expectedPolicyRevision'}}
    if function not in expected or set(args)!=expected[function]:
        raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
    if function==READ:
        if not isinstance(args['eventId'],str) or not _KEY.fullmatch(args['eventId']):
            raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
        return function,args
    if function==CURRENT:
        _program({'languageVersion':2,'function':RESOLVE,'arguments':{
            **args,'effectiveOn':'2000-01-01','expectedPolicyRevision':0}})
        return function,args
    if type(args['expectedPolicyRevision']) is not int or args['expectedPolicyRevision']<0:
        raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
    if function==RESOLVE:
        if (not isinstance(args['policyId'],str) or not _ID.fullmatch(args['policyId'])
                or type(args['policyVersion']) is not int or args['policyVersion']<1
                or not isinstance(args['candidateFunction'],str)
                or args['candidateFunction'] not in _CORE_VERSIONS):
            raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
        _elections_program({'languageVersion':2,'function':ELECTIONS_FUNCTION,
            'arguments':{key:args[key] for key in ('policyId','selections',
                'effectiveOn','expectedPolicyRevision')}} ,ELECTIONS_FUNCTION)
        return function,args
    if (type(args['expectedCommitRevision']) is not int
            or args['expectedCommitRevision']<0
            or not isinstance(args['reason'],str)
            or not 10<=len(args['reason'])<=2000
            or len(args['reason'].strip())<10
            or not isinstance(args['expectedActiveEventId'],str)
            or args['expectedActiveEventId']!='' and
                not _KEY.fullmatch(args['expectedActiveEventId'])):
        raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
    if function==ACTIVATE:
        if (not isinstance(args['approvalId'],str) or not _KEY.fullmatch(args['approvalId'])
                or any(not isinstance(args[key],str) or not _HASH.fullmatch(args[key])
                       for key in ('expectedApprovalDigest','policyBindingDigest'))):
            raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
        if _date(args['effectiveFrom'])>=_date(args['effectiveBefore']):
            raise ValueError('POLICY_ACTIVATION_EFFECTIVE_RANGE_INVALID')
    elif (not isinstance(args['variantKey'],str) or not _HASH.fullmatch(args['variantKey'])
            or not isinstance(args['expectedActivationId'],str)
            or not _KEY.fullmatch(args['expectedActivationId'])):
        raise ValueError('POLICY_ACTIVATION_ARGUMENTS_INVALID')
    return function,args


def resolve_in_transaction(db,scope,args,state):
    if state['policy_revision']!=args['expectedPolicyRevision']:
        raise ValueError('STALE_POLICY_ACTIVATION_REVISION')
    key=variant_key(scope,args['policyId'],args['policyVersion'],
                    args['selections'],args['candidateFunction'])
    row=db.execute('''SELECT p.status,p.event_id,p.activation_id,e.manifest,
        e.policy_revision,e.committed_revision FROM epm.policy_activation_current p
        JOIN epm.policy_activation_event e ON e.workspace_id=p.workspace_id
        AND e.application_id=p.application_id AND e.event_id=p.activation_id
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.variant_key=%s''',
        (scope.workspace_id,scope.application_id,key)).fetchone()
    if row is None or row['status']!='Active':
        raise ValueError('POLICY_VARIANT_NOT_ACTIVE')
    manifest=row['manifest']
    binding=manifest['policyBinding']
    if (binding['policyVersion']!=args['policyVersion']
            or binding['candidateCoreVersion']!=_CORE_VERSIONS[args['candidateFunction']]):
        raise ValueError('POLICY_ACTIVE_VARIANT_VERSION_MISMATCH')
    on=_date(args['effectiveOn'])
    if not _date(manifest['effectiveFrom'])<=on<_date(manifest['effectiveBefore']):
        raise ValueError('POLICY_ACTIVE_VARIANT_DATE_MISMATCH')
    query=_elections_program({'languageVersion':2,'function':ELECTIONS_FUNCTION,
        'arguments':{key:args[key] for key in ('policyId','selections',
            'effectiveOn','expectedPolicyRevision')}},ELECTIONS_FUNCTION)
    draft=validate_elections_in_transaction(db,scope,query,state)
    if draft['draftDigest']!=binding['draftDigest'] or draft['version']!=binding['policyVersion']:
        raise ValueError('POLICY_ACTIVE_DRAFT_MISMATCH')
    return {'variantKey':key,'activationId':row['activation_id'],
        'activeEventId':row['event_id'],'approvalId':manifest['approvalId'],
        'approvalDigest':manifest['approvalDigest'],'policyBinding':binding,
        'resolvedOn':args['effectiveOn'],'draftDigest':draft['draftDigest'],
        'selectionDigest':draft['selectionDigest'],
        'effectiveFrom':manifest['effectiveFrom'],
        'effectiveBefore':manifest['effectiveBefore'],
        'policyRevision':state['policy_revision'],
        'status':'ActiveGovernedVariant','accountingExecutionSupported':False,
        'accountingPublicationAvailable':True,
        'accountingPublicationFunction':'consolidation.acquisition.journal.publish'}


class PostgresPolicyActivation:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    def execute(self,scope: ApplicationScope,program: object,*,idempotency_key: str) -> dict:
        if not isinstance(scope,ApplicationScope):
            raise ValueError('Application scope is required')
        function,args=_program(program)
        if function not in (ACTIVATE,WITHDRAW):
            raise ValueError('POLICY_ACTIVATION_WRITE_REQUIRED')
        if not isinstance(idempotency_key,str) or not _KEY.fullmatch(idempotency_key):
            raise ValueError('POLICY_ACTIVATION_IDEMPOTENCY_KEY_INVALID')
        keys=(scope.workspace_id,scope.application_id)
        command_digest=_canonical_digest({'scope':list(keys),'program':program,
            'identity':[self.identity.issuer,self.identity.subject_id]})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT policy_revision,commit_revision,
                    processing_mode FROM epm.application_state WHERE
                    workspace_id=%s AND application_id=%s FOR UPDATE''',keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'workspace_admin', function=function)
                prior=db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys,idempotency_key)).fetchone()
                if prior:
                    if prior['command_digest']!=command_digest or prior['actor_id']!=self.identity.subject_id:
                        raise ValueError('POLICY_ACTIVATION_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if state['processing_mode']!='Active':
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['policy_revision']!=args['expectedPolicyRevision']
                        or state['commit_revision']!=args['expectedCommitRevision']):
                    raise ValueError('STALE_POLICY_ACTIVATION_REVISION')
                if function==ACTIVATE:
                    approval=db.execute('''SELECT approval_digest,manifest FROM
                        epm.policy_acquisition_approval WHERE workspace_id=%s
                        AND application_id=%s AND approval_id=%s''',
                        (*keys,args['approvalId'])).fetchone()
                    if (approval is None or approval['approval_digest']!=args['expectedApprovalDigest']
                            or _canonical_digest(approval['manifest'])!=approval['approval_digest']):
                        raise ValueError('POLICY_ACTIVATION_APPROVAL_MISMATCH')
                    bindings=[item for item in approval['manifest']['policyBindings']
                              if _canonical_digest(item)==args['policyBindingDigest']]
                    if len(bindings)!=1:
                        raise ValueError('POLICY_ACTIVATION_BINDING_UNAPPROVED')
                    binding=bindings[0]
                    if _CORE_VERSIONS.get(binding['candidateFunction'])!=binding['candidateCoreVersion']:
                        raise ValueError('POLICY_ACTIVATION_CORE_VERSION_MISMATCH')
                    query=_elections_program({'languageVersion':2,'function':ELECTIONS_FUNCTION,
                        'arguments':{'policyId':binding['policyId'],
                            'effectiveOn':args['effectiveFrom'],
                            'selections':binding['selections'],
                            'expectedPolicyRevision':state['policy_revision']}},ELECTIONS_FUNCTION)
                    draft=validate_elections_in_transaction(db,scope,query,state)
                    if (draft['version']!=binding['policyVersion']
                            or draft['draftDigest']!=binding['draftDigest']):
                        raise ValueError('POLICY_ACTIVATION_DRAFT_MISMATCH')
                    if _date(args['effectiveBefore'])>_date(draft['effectiveBefore']):
                        raise ValueError('POLICY_ACTIVATION_EFFECTIVE_RANGE_INVALID')
                    key=variant_key(scope,binding['policyId'],binding['policyVersion'],
                                    binding['selections'],
                                    binding['candidateFunction'])
                    approval_id=args['approvalId']
                    activation_id=idempotency_key
                    action,status='Activate','Active'
                    manifest={'workspaceId':scope.workspace_id,
                        'applicationId':scope.application_id,'variantKey':key,
                        'approvalId':approval_id,'approvalDigest':approval['approval_digest'],
                        'policyBindingDigest':args['policyBindingDigest'],
                        'policyBinding':binding,'effectiveFrom':args['effectiveFrom'],
                        'effectiveBefore':args['effectiveBefore'],'reason':args['reason']}
                else:
                    key=args['variantKey']
                pointer=db.execute('''SELECT event_id,activation_id,status
                    FROM epm.policy_activation_current WHERE workspace_id=%s
                    AND application_id=%s AND variant_key=%s''',(*keys,key)).fetchone()
                if (pointer['event_id'] if pointer else '')!=args['expectedActiveEventId']:
                    raise ValueError('POLICY_ACTIVATION_POINTER_STALE')
                if function==WITHDRAW:
                    if (pointer is None or pointer['status']!='Active'
                            or pointer['activation_id']!=args['expectedActivationId']):
                        raise ValueError('POLICY_WITHDRAWAL_TARGET_NOT_ACTIVE')
                    activated=db.execute('''SELECT approval_id,manifest FROM
                        epm.policy_activation_event WHERE workspace_id=%s
                        AND application_id=%s AND event_id=%s''',
                        (*keys,pointer['activation_id'])).fetchone()
                    approval_id=activated['approval_id']
                    activation_id=pointer['activation_id']
                    action,status='Withdraw','Withdrawn'
                    manifest={**activated['manifest'],'withdrawalReason':args['reason']}
                revision=state['commit_revision']+1
                policy_revision=state['policy_revision']+1
                result={'eventId':idempotency_key,'variantKey':key,
                    'activationId':activation_id,'approvalId':approval_id,
                    'status':status,'policyRevision':policy_revision,
                    'committedRevision':revision,'accountingExecutionSupported':False,
                    'accountingPublicationAvailable':status=='Active',
                    'accountingPublicationFunction':(
                        'consolidation.acquisition.journal.publish'
                        if status=='Active' else None)}
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,
                    commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision,revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                    actor_id,committed_revision,result) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,command_digest,self.identity.subject_id,
                     revision,Jsonb(result)))
                db.execute('''INSERT INTO epm.policy_activation_event
                    (workspace_id,application_id,event_id,variant_key,action,
                    approval_id,activation_id,previous_event_id,manifest,
                    actor_issuer,actor_subject,policy_revision,committed_revision)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys,idempotency_key,key,action,approval_id,
                     activation_id if action=='Withdraw' else None,
                     pointer['event_id'] if pointer else None,Jsonb(manifest),
                     self.identity.issuer,self.identity.subject_id,policy_revision,revision))
                db.execute('''INSERT INTO epm.policy_activation_current
                    (workspace_id,application_id,variant_key,event_id,activation_id,status)
                    VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT
                    (workspace_id,application_id,variant_key) DO UPDATE SET
                    event_id=EXCLUDED.event_id,activation_id=EXCLUDED.activation_id,
                    status=EXCLUDED.status''',
                    (*keys,key,idempotency_key,activation_id,status))
                return result

    def read(self,scope: ApplicationScope,program: object) -> dict:
        if not isinstance(scope,ApplicationScope):
            raise ValueError('Application scope is required')
        function,args=_program(program)
        if function not in (READ,RESOLVE,CURRENT):
            raise ValueError('POLICY_ACTIVATION_READ_REQUIRED')
        keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read', function=function)
                if function==RESOLVE:
                    return resolve_in_transaction(db,scope,args,state)
                if function==CURRENT:
                    key=variant_key(scope,args['policyId'],args['policyVersion'],
                        args['selections'],args['candidateFunction'])
                    current=db.execute('''SELECT p.event_id,p.activation_id,p.status,
                        e.manifest FROM epm.policy_activation_current p
                        JOIN epm.policy_activation_event e
                        ON e.workspace_id=p.workspace_id
                        AND e.application_id=p.application_id
                        AND e.event_id=p.activation_id
                        WHERE p.workspace_id=%s AND p.application_id=%s
                        AND p.variant_key=%s''',(*keys,key)).fetchone()
                    return {'variantKey':key,
                        'currentEventId':current['event_id'] if current else '',
                        'activationId':current['activation_id'] if current else None,
                        'status':current['status'] if current else 'NeverActivated',
                        'activationManifest':current['manifest'] if current else None,
                        'policyRevision':state['policy_revision'],
                        'commitRevision':state['commit_revision'],
                        'accountingExecutionSupported':False,
                        'accountingPublicationAvailable':bool(current)
                            and current['status']=='Active',
                        'accountingPublicationFunction':(
                            'consolidation.acquisition.journal.publish'
                            if current and current['status']=='Active' else None)}
                row=db.execute('''SELECT e.*,p.event_id AS current_event,
                    p.activation_id AS current_activation,p.status AS current_status
                    FROM epm.policy_activation_event e
                    JOIN epm.policy_activation_current p
                    USING(workspace_id,application_id,variant_key)
                    WHERE e.workspace_id=%s AND e.application_id=%s
                    AND e.event_id=%s''',(*keys,args['eventId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_ACTIVATION_EVENT_UNAVAILABLE')
                return {'eventId':row['event_id'],'variantKey':row['variant_key'],
                    'action':row['action'],'approvalId':row['approval_id'],
                    'manifest':row['manifest'],
                    'actor':{'issuer':row['actor_issuer'],'subjectId':row['actor_subject']},
                    'policyRevision':row['policy_revision'],
                    'committedRevision':row['committed_revision'],
                    'recordedAt':row['recorded_at'].isoformat(),
                    'currentEventId':row['current_event'],
                    'currentActivationId':row['current_activation'],
                    'currentStatus':row['current_status'],
                    'isCurrentEvent':row['event_id']==row['current_event'],
                    'isCurrentActivation':row['event_id']==row['current_activation']
                        and row['action']=='Activate',
                    'eventStatus':('Active' if row['action']=='Activate'
                        and row['event_id']==row['current_activation']
                        and row['current_status']=='Active' else
                        'Withdrawn' if row['action']=='Activate'
                        and row['event_id']==row['current_activation'] else
                        'Replaced' if row['action']=='Activate' else 'WithdrawalRecorded'),
                    'accountingExecutionSupported':False,
                    'accountingPublicationAvailable':row['current_status']=='Active',
                    'accountingPublicationFunction':(
                        'consolidation.acquisition.journal.publish'
                        if row['current_status']=='Active' else None)}
