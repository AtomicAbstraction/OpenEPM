"""Reviewed generic-cube planning slice and optional submission transitions.

The server owns signing, identity, revisions and receipts. PostgreSQL triggers
on fact projections enforce committed locks inside every fact transaction.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
import uuid
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import new_state_token,require_state_token
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .operation_admission_contract import is_signed_operation_id


_LOCK_ID=re.compile(r'[0-9a-f]{32}\Z')
ALL_FUNCTIONS=frozenset({
    'cube.write.scope.lock','cube.write.scope.submit',
    'cube.write.scope.approve','cube.write.scope.reopen'})
PUBLIC_READ='cube.write.scope.read'
PUBLIC_WORKLIST='cube.write.scope.worklist'


def _compile(program: object) -> dict:
    if (not isinstance(program,dict)
            or set(program)!={'languageVersion','function','arguments'}
            or type(program['languageVersion']) is not int
            or program['languageVersion']!=2
            or program['function'] not in ALL_FUNCTIONS
            or not isinstance(program['arguments'],dict)):
        raise ValueError('V2_PLANNING_LOCK_FUNCTION_INVALID')
    function=program['function']
    args=program['arguments']
    if function=='cube.write.scope.lock':
        expected={'scopeMembers','scopeAll','reason'}
    elif function=='cube.write.scope.submit':
        expected={'scopeMembers','scopeAll','reviewerIssuer',
                  'reviewerSubjectId','reason'}
    elif function=='cube.write.scope.approve':
        expected={'lockId','expectedSubmissionStateToken',
                  'reason'}
    else:
        expected={'lockId','expectedStateToken','reason'}
    if (set(args)!=expected
            or not isinstance(args['reason'],str)
            or not 1<=len(args['reason'])<=500
            or '\x00' in args['reason']):
        raise ValueError('V2_PLANNING_LOCK_ARGUMENTS_INVALID')
    normalized={'function':function,'reason':args['reason']}
    if function in ('cube.write.scope.lock','cube.write.scope.submit'):
        members=args['scopeMembers']
        all_scope=args['scopeAll']
        if (not isinstance(members,dict) or len(members)>32
                or type(all_scope) is not bool
                or all_scope!=(len(members)==0)
                or any(not isinstance(axis,str) or not 1<=len(axis)<=200
                       or not isinstance(member,str) or not 1<=len(member)<=200
                       for axis,member in members.items())):
            raise ValueError('V2_PLANNING_LOCK_SCOPE_INVALID')
        normalized['scopeMembers']=dict(sorted(members.items()))
        normalized['scopeAll']=all_scope
        if function=='cube.write.scope.submit':
            for field in ('reviewerIssuer','reviewerSubjectId'):
                if (not isinstance(args[field],str)
                        or not 1<=len(args[field])<=300):
                    raise ValueError('V2_PLANNING_REVIEWER_INVALID')
                normalized[field]=args[field]
    else:
        token_field=('expectedSubmissionStateToken'
                       if function=='cube.write.scope.approve'
                       else 'expectedStateToken')
        if (not isinstance(args['lockId'],str)
                or not _LOCK_ID.fullmatch(args['lockId'])
                or type(args[token_field]) is not str):
            raise ValueError('V2_PLANNING_TRANSITION_TARGET_INVALID')
        require_state_token(args[token_field],
                            error='V2_PLANNING_TRANSITION_TARGET_INVALID')
        normalized['lockId']=args['lockId']
        normalized[token_field]=args[token_field]
    return normalized


class PostgresPlanningLocks:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(preview_secret,bytes) or len(preview_secret)<32:
            raise ValueError('A server-owned preview secret is required')
        self.dsn=dsn
        self.identity=identity
        self.preview_secret=preview_secret

    @staticmethod
    def _scope_members(db,scope: ApplicationScope,members: dict) -> None:
        if not members:
            return
        pairs=[{'dimension_id':axis,'member_id':member}
               for axis,member in members.items()]
        found=db.execute('''SELECT input.dimension_id,input.member_id,
            m.member_id IS NOT NULL AS active
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            JOIN epm.dimension d ON d.workspace_id=%s
            AND d.application_id=%s AND d.dimension_id=input.dimension_id
            AND d.status='Active'
            LEFT JOIN epm.member m ON m.workspace_id=d.workspace_id
            AND m.application_id=d.application_id
            AND m.dimension_id=d.dimension_id
            AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb(pairs),scope.workspace_id,
             scope.application_id)).fetchall()
        if len(found)!=len(pairs) or any(not row['active'] for row in found):
            raise ValueError('PLANNING_LOCK_SCOPE_MEMBER_UNAVAILABLE')

    @staticmethod
    def _state(db,scope: ApplicationScope,*,lock: bool) -> dict:
        state=db.execute('''SELECT a.status,s.processing_mode,
            s.metadata_revision,s.data_revision,s.policy_revision,
            s.commit_revision FROM epm.application_state s
            JOIN epm.application a USING (workspace_id,application_id)
            WHERE s.workspace_id=%s AND s.application_id=%s
            '''+('FOR UPDATE OF s' if lock else ''),
            (scope.workspace_id,scope.application_id)).fetchone()
        if state is None:
            raise ValueError('APPLICATION_UNAVAILABLE')
        return state

    @staticmethod
    def _require_writable(state: dict) -> None:
        if state['status']!='Active' or state['processing_mode']!='Active':
            raise ValueError('APPLICATION_NOT_WRITABLE')

    def preview(self,scope: ApplicationScope,program: dict) -> dict:
        normalized=_compile(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,
                    self._permission(normalized['function']))
                state=self._state(db,scope,lock=False)
                self._require_writable(state)
                if normalized['function'] in (
                        'cube.write.scope.lock','cube.write.scope.submit'):
                    self._scope_members(db,scope,normalized['scopeMembers'])
                    if normalized['function']=='cube.write.scope.submit':
                        reviewer=VerifiedIdentity(
                            normalized['reviewerIssuer'],
                            normalized['reviewerSubjectId'])
                        PostgresAccessChecker.check_in_transaction(
                            db,reviewer,scope,'admin')
                    target={'scopeMembers':normalized['scopeMembers'],
                            'scopeAll':normalized['scopeAll']}
                    if normalized['function']=='cube.write.scope.submit':
                        target['reviewer']={
                            'issuer':reviewer.issuer,
                            'subjectId':reviewer.subject_id}
                elif normalized['function']=='cube.write.scope.approve':
                    submission=self._submission_row(
                        db,scope,normalized['lockId'])
                    if (submission['status']!='Submitted'
                            or submission['state_token']!=normalized[
                               'expectedSubmissionStateToken']):
                        raise ValueError('PLANNING_SUBMISSION_STALE')
                    self._require_assigned_reviewer(submission)
                    target={'lockId':normalized['lockId'],
                            'submissionStateToken':submission['state_token']}
                else:
                    target=self._locked_row(db,scope,normalized['lockId'])
                    if (target['status']!='Locked' or
                            target['state_token']!=normalized['expectedStateToken']):
                        raise ValueError('PLANNING_LOCK_STALE')
                    target={'lockId':normalized['lockId'],
                            'stateToken':target['state_token']}
                revisions=[state['metadata_revision'],
                           state['data_revision'],
                           state['policy_revision']]
        payload={'scope':[scope.workspace_id,scope.application_id],
                 'identity':[self.identity.issuer,self.identity.subject_id],
                 'programDigest':_canonical_digest(normalized),
                 'revisions':revisions,'expiresAt':int(time.time())+300}
        raw=json.dumps(payload,sort_keys=True,separators=(',',':'),
                       ensure_ascii=False).encode('utf-8')
        token=base64.urlsafe_b64encode(raw+hmac.new(
            self.preview_secret,raw,sha256).digest()).decode('ascii')
        return {'languageVersion':2,'function':program['function'],
                'target':target,'revisionVector':{
                    'metadata':revisions[0],'data':revisions[1],
                    'policy':revisions[2]},'previewToken':token}

    @staticmethod
    def _locked_row(db,scope,lock_id):
        row=db.execute('''SELECT lock_id,status,state_token,scope_members,
            scope_all,locked_revision,reopened_revision
            FROM epm.cube_write_scope_lock WHERE workspace_id=%s
            AND application_id=%s AND lock_id=%s FOR UPDATE''',
            (scope.workspace_id,scope.application_id,lock_id)).fetchone()
        if row is None:
            raise ValueError('PLANNING_LOCK_UNAVAILABLE')
        return row

    @staticmethod
    def _permission(function: str) -> str:
        return ('write' if function=='cube.write.scope.submit' else 'admin')

    @staticmethod
    def _submission_row(db,scope,lock_id):
        row=db.execute('''SELECT status,state_token,reviewer_issuer,
            reviewer_subject_id FROM epm.cube_write_scope_submission
            WHERE workspace_id=%s AND application_id=%s AND lock_id=%s
            FOR UPDATE''',
            (scope.workspace_id,scope.application_id,lock_id)).fetchone()
        if row is None:
            raise ValueError('PLANNING_SUBMISSION_UNAVAILABLE')
        return row

    def _require_assigned_reviewer(self,row):
        if (row['reviewer_issuer']!=self.identity.issuer
                or row['reviewer_subject_id']!=self.identity.subject_id):
            raise ValueError('PLANNING_REVIEWER_ASSIGNMENT_REQUIRED')

    def _verify(self,token,scope,normalized,state):
        if not isinstance(token,str) or len(token)>4096:
            raise ValueError('PLANNING_LOCK_PREVIEW_INVALID')
        try:
            packed=base64.b64decode(token,altchars=b'-_',validate=True)
            raw,signature=packed[:-32],packed[-32:]
            if not hmac.compare_digest(hmac.new(
                    self.preview_secret,raw,sha256).digest(),signature):
                raise ValueError('signature')
            payload=json.loads(raw)
        except (ValueError,TypeError,binascii.Error) as error:
            raise ValueError('PLANNING_LOCK_PREVIEW_INVALID') from error
        if (not isinstance(payload,dict)
                or set(payload)!={'scope','identity','programDigest',
                                   'revisions','expiresAt'}
                or payload['scope']!=[scope.workspace_id,scope.application_id]
                or payload['identity']!=[self.identity.issuer,
                                         self.identity.subject_id]
                or payload['programDigest']!=_canonical_digest(normalized)
                or payload['revisions']!=[
                    state['metadata_revision'],state['data_revision'],
                    state['policy_revision']]
                or type(payload['expiresAt']) is not int
                or payload['expiresAt']<time.time()):
            raise ValueError('PLANNING_LOCK_PREVIEW_STALE')

    def replay(self,scope: ApplicationScope,program: dict,*,
               idempotency_key: str|None=None) -> dict|None:
        """Return an exact committed result before mutable-state validation.

        Current application authorization is deliberately rechecked.  The
        receipt digest then distinguishes an exact transport replay from a
        changed command attempting to reuse the same idempotency key.
        """
        normalized=_compile(program)
        request_digest,operation_id=self._receipt_identity(
            scope,normalized,idempotency_key=idempotency_key)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,
                    self._permission(normalized['function']))
                previous=db.execute('''SELECT command_digest,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     operation_id)).fetchone()
                if previous is None:
                    return None
                if previous['command_digest']!=request_digest:
                    raise ValueError('PLANNING_LOCK_IDEMPOTENCY_CONFLICT')
                return previous['result']

    def _receipt_identity(self,scope,normalized,*,idempotency_key=None):
        request_digest=_canonical_digest({
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'program':normalized})
        if not is_signed_operation_id(idempotency_key):
            raise ValueError('OPERATION_ADMISSION_REQUIRED')
        return request_digest,idempotency_key

    def apply(self,scope: ApplicationScope,program: dict,*,
              preview_token: str,idempotency_key: str|None=None) -> dict:
        normalized=_compile(program)
        request_digest,operation_id=self._receipt_identity(
            scope,normalized,idempotency_key=idempotency_key)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                state=self._state(db,scope,lock=True)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,
                    self._permission(normalized['function']))
                previous=db.execute('''SELECT command_digest,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     operation_id)).fetchone()
                if previous:
                    if previous['command_digest']!=request_digest:
                        raise ValueError('PLANNING_LOCK_IDEMPOTENCY_CONFLICT')
                    return previous['result']
                self._require_writable(state)
                self._verify(preview_token,scope,normalized,state)
                revision=state['commit_revision']+1
                if normalized['function'] in (
                        'cube.write.scope.lock','cube.write.scope.submit'):
                    self._scope_members(db,scope,normalized['scopeMembers'])
                    if normalized['function']=='cube.write.scope.submit':
                        reviewer=VerifiedIdentity(
                            normalized['reviewerIssuer'],
                            normalized['reviewerSubjectId'])
                        PostgresAccessChecker.check_in_transaction(
                            db,reviewer,scope,'admin')
                    lock_id=uuid.uuid4().hex
                    lock_state_token=new_state_token()
                    result={'lockId':lock_id,
                            'status':('Submitted' if normalized['function']==
                                      'cube.write.scope.submit' else 'Locked'),
                            'stateToken':lock_state_token,
                            'committedRevision':revision,
                            'scopeMembers':normalized['scopeMembers'],
                            'scopeAll':normalized['scopeAll']}
                    db.execute('''INSERT INTO epm.cube_write_scope_lock
                        (workspace_id,application_id,lock_id,issuer,
                         subject_id,idempotency_key,request_digest,
                         scope_members,scope_all,status,state_token,reason,
                         locked_revision) VALUES (%s,%s,%s,%s,%s,%s,%s,
                         %s,%s,'Locked',%s,%s,%s)''',
                        (scope.workspace_id,scope.application_id,lock_id,
                         self.identity.issuer,self.identity.subject_id,
                         operation_id,request_digest,
                         Jsonb(normalized['scopeMembers']),
                         normalized['scopeAll'],lock_state_token,
                         normalized['reason'],revision))
                    self._lock_event(db,scope,lock_id,1,'Locked',
                                     normalized['reason'],revision)
                    if normalized['function']=='cube.write.scope.submit':
                        submission_state_token=new_state_token()
                        db.execute('''INSERT INTO epm.cube_write_scope_submission
                            (workspace_id,application_id,lock_id,
                             submitter_issuer,submitter_subject_id,
                             reviewer_issuer,reviewer_subject_id,status,
                             state_token,submitted_revision)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,'Submitted',%s,%s)''',
                            (scope.workspace_id,scope.application_id,lock_id,
                             self.identity.issuer,self.identity.subject_id,
                             reviewer.issuer,reviewer.subject_id,
                             submission_state_token,revision))
                        self._submission_event(
                            db,scope,lock_id,1,'Submitted',
                            normalized['reason'],revision)
                        result['reviewer']={'issuer':reviewer.issuer,
                            'subjectId':reviewer.subject_id}
                        result['submissionStateToken']=submission_state_token
                elif normalized['function']=='cube.write.scope.approve':
                    lock_id=normalized['lockId']
                    submission=self._submission_row(db,scope,lock_id)
                    if (submission['status']!='Submitted'
                            or submission['state_token']!=normalized[
                               'expectedSubmissionStateToken']):
                        raise ValueError('PLANNING_SUBMISSION_STALE')
                    self._require_assigned_reviewer(submission)
                    if self._locked_row(db,scope,lock_id)['status']!='Locked':
                        raise ValueError('PLANNING_LOCK_STALE')
                    submission_state_token=new_state_token()
                    db.execute('''UPDATE epm.cube_write_scope_submission
                        SET status='Approved',state_token=%s,
                            approved_revision=%s,
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND lock_id=%s''',
                        (submission_state_token,revision,scope.workspace_id,
                         scope.application_id,lock_id))
                    self._submission_event(db,scope,lock_id,2,'Approved',
                                           normalized['reason'],revision)
                    result={'lockId':lock_id,'status':'Approved',
                            'submissionStateToken':submission_state_token,
                            'committedRevision':revision}
                else:
                    lock_id=normalized['lockId']
                    target=self._locked_row(db,scope,lock_id)
                    if (target['status']!='Locked' or
                            target['state_token']!=normalized['expectedStateToken']):
                        raise ValueError('PLANNING_LOCK_STALE')
                    lock_state_token=new_state_token()
                    db.execute('''UPDATE epm.cube_write_scope_lock
                        SET status='Open',state_token=%s,
                            reopened_revision=%s,
                            updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s
                        AND lock_id=%s''',
                        (lock_state_token,revision,scope.workspace_id,
                         scope.application_id,lock_id))
                    result={'lockId':lock_id,'status':'Open',
                            'stateToken':lock_state_token,
                            'committedRevision':revision}
                    self._lock_event(db,scope,lock_id,2,'Reopened',
                                     normalized['reason'],revision)
                    submission=db.execute('''SELECT status,state_token FROM
                        epm.cube_write_scope_submission WHERE workspace_id=%s
                        AND application_id=%s AND lock_id=%s FOR UPDATE''',
                        (scope.workspace_id,scope.application_id,
                         lock_id)).fetchone()
                    if submission:
                        if submission['status'] not in ('Submitted','Approved'):
                            raise ValueError('PLANNING_SUBMISSION_STALE')
                        submission_state_token=new_state_token()
                        db.execute('''UPDATE epm.cube_write_scope_submission
                            SET status='Reopened',state_token=%s,
                                reopened_revision=%s,
                                updated_at=transaction_timestamp()
                            WHERE workspace_id=%s AND application_id=%s
                            AND lock_id=%s''',
                            (submission_state_token,revision,scope.workspace_id,
                             scope.application_id,lock_id))
                        self._submission_event(
                            db,scope,lock_id,(2 if submission['status']=='Submitted'
                                else 3),'Reopened',
                            normalized['reason'],revision)
                        result['submissionStatus']='Reopened'
                        result['submissionStateToken']=submission_state_token
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=policy_revision+1,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (revision,scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                     command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id,scope.application_id,
                     operation_id,request_digest,self.identity.subject_id,
                     revision,Jsonb(result)))
                return result

    def _lock_event(self,db,scope,lock_id,ordinal,kind,reason,revision):
        db.execute('''INSERT INTO epm.cube_write_scope_lock_event
            (workspace_id,application_id,lock_id,event_ordinal,
             kind,issuer,subject_id,reason,committed_revision)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (scope.workspace_id,scope.application_id,lock_id,
             ordinal,kind,self.identity.issuer,self.identity.subject_id,
             reason,revision))

    def _submission_event(self,db,scope,lock_id,ordinal,kind,reason,revision):
        db.execute('''INSERT INTO epm.cube_write_scope_submission_event
            (workspace_id,application_id,lock_id,event_ordinal,
             kind,issuer,subject_id,reason,committed_revision)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
            (scope.workspace_id,scope.application_id,lock_id,
             ordinal,kind,self.identity.issuer,self.identity.subject_id,
             reason,revision))

    def read(self,scope: ApplicationScope,lock_id: str) -> dict:
        if not isinstance(lock_id,str) or not _LOCK_ID.fullmatch(lock_id):
            raise ValueError('PLANNING_LOCK_ID_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                row=db.execute('''SELECT l.lock_id,l.status,l.state_token,
                    l.scope_members,l.scope_all,l.locked_revision,
                    l.reopened_revision,s.status AS submission_status,
                    s.state_token AS submission_state_token,s.reviewer_issuer,
                    s.reviewer_subject_id,s.submitted_revision,
                    s.approved_revision,
                    s.reopened_revision AS submission_reopened_revision
                    FROM epm.cube_write_scope_lock l
                    LEFT JOIN epm.cube_write_scope_submission s
                    ON s.workspace_id=l.workspace_id
                    AND s.application_id=l.application_id
                    AND s.lock_id=l.lock_id
                    WHERE l.workspace_id=%s AND l.application_id=%s
                    AND l.lock_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     lock_id)).fetchone()
                if row is None:
                    raise ValueError('PLANNING_LOCK_UNAVAILABLE')
                result={'lockId':row['lock_id'],'status':row['status'],
                        'stateToken':row['state_token'],
                        'scopeMembers':row['scope_members'],
                        'scopeAll':row['scope_all'],
                        'lockedRevision':row['locked_revision'],
                        'reopenedRevision':row['reopened_revision']}
                if row['submission_status'] is not None:
                    result['submission']={
                        'status':row['submission_status'],
                        'stateToken':row['submission_state_token'],
                        'reviewer':{
                            'issuer':row['reviewer_issuer'],
                            'subjectId':row['reviewer_subject_id']},
                        'submittedRevision':row['submitted_revision'],
                        'approvedRevision':row['approved_revision'],
                        'reopenedRevision':row['submission_reopened_revision']}
                return result

    def worklist(self,scope: ApplicationScope,*,limit: int=100,
                 after_lock_id: str|None=None,
                 include_resolved: bool=False) -> dict:
        """Read this verified reviewer's assigned submissions.

        This is a technical read: it does not advance application revisions.
        The exact reviewer identity is part of the query even though RLS and a
        fresh Administrator grant are also enforced, so one administrator
        cannot enumerate another reviewer's assignments.
        """
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError('PLANNING_WORKLIST_LIMIT_INVALID')
        if (after_lock_id is not None
                and (not isinstance(after_lock_id,str)
                     or not _LOCK_ID.fullmatch(after_lock_id))):
            raise ValueError('PLANNING_WORKLIST_CURSOR_INVALID')
        if type(include_resolved) is not bool:
            raise ValueError('PLANNING_WORKLIST_RESOLUTION_FILTER_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                rows=db.execute('''SELECT l.lock_id,l.status,l.state_token,
                    l.scope_members,l.scope_all,l.locked_revision,
                    l.reopened_revision,s.status AS submission_status,
                    s.state_token AS submission_state_token,s.submitter_issuer,
                    s.submitter_subject_id,s.submitted_revision,
                    s.approved_revision,
                    s.reopened_revision AS submission_reopened_revision
                    FROM epm.cube_write_scope_submission s
                    JOIN epm.cube_write_scope_lock l
                    ON l.workspace_id=s.workspace_id
                    AND l.application_id=s.application_id
                    AND l.lock_id=s.lock_id
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    AND s.reviewer_issuer=%s AND s.reviewer_subject_id=%s
                    AND (%s OR s.status='Submitted')
                    AND (%s::text IS NULL OR s.lock_id>%s)
                    ORDER BY s.lock_id LIMIT %s''',
                    (scope.workspace_id,scope.application_id,
                     self.identity.issuer,self.identity.subject_id,
                     include_resolved,after_lock_id,after_lock_id,
                     limit+1)).fetchall()
                has_more=len(rows)>limit
                visible=rows[:limit]
                items=[]
                for row in visible:
                    items.append({
                        'lockId':row['lock_id'],
                        'lockStatus':row['status'],
                        'lockStateToken':row['state_token'],
                        'scopeMembers':row['scope_members'],
                        'scopeAll':row['scope_all'],
                        'lockedRevision':row['locked_revision'],
                        'reopenedRevision':row['reopened_revision'],
                        'submissionStatus':row['submission_status'],
                        'submissionStateToken':row['submission_state_token'],
                        'submitter':{
                            'issuer':row['submitter_issuer'],
                            'subjectId':row['submitter_subject_id']},
                        'submittedRevision':row['submitted_revision'],
                        'approvedRevision':row['approved_revision'],
                        'submissionReopenedRevision':
                            row['submission_reopened_revision']})
                return {'items':items,
                        'nextAfterLockId':(
                            visible[-1]['lock_id'] if has_more else None)}
