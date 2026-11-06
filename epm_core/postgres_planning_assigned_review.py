"""Assignment-bound, sequential planning review without changing legacy V2."""
from __future__ import annotations
import base64,hmac,json,time,uuid
from datetime import datetime,timezone
from hashlib import sha256
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .planning_assignment import compile_planning_assignment_set
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .planning_assigned_review import (FUNCTIONS,READ,REOPEN,REVIEW,SUBMIT,catalog,
    compile_program,issuer_bound_principal_matches,scope_overlaps_selectors)

def active_assignment_covers(db,scope,members):
 row=db.execute('''SELECT v.definition FROM epm.planning_assignment_state s
  JOIN epm.planning_assignment_version v ON v.workspace_id=s.workspace_id
  AND v.application_id=s.application_id
  AND v.assignment_set_id=s.active_assignment_set_id
  AND v.version=s.active_version WHERE s.workspace_id=%s
  AND s.application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
 if not row:return False
 model=compile_planning_assignment_set(row['definition']);now=datetime.now(timezone.utc)
 return any(item.effective_from<=now and (item.effective_to is None or now<=item.effective_to)
  and scope_overlaps_selectors(members,item.member_selectors)
  for item in model.assignments)

class PostgresAssignedReview:
 def __init__(self,dsn,*,identity,preview_secret):
  if not isinstance(identity,VerifiedIdentity) or not isinstance(preview_secret,bytes) or len(preview_secret)<32:raise ValueError('Assigned review requires verified identity and secret')
  self.dsn,self.identity,self.secret=dsn,identity,preview_secret
 def _receipt(self,scope,n):
  digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],'identity':[self.identity.issuer,self.identity.subject_id],'program':n})
  op='planning-assigned-'+sha256(json.dumps({'scope':[scope.workspace_id,scope.application_id],'actor':[self.identity.issuer,self.identity.subject_id],'key':n['idempotencyKey']},sort_keys=True,separators=(',',':')).encode()).hexdigest();return digest,op
 def _state(self,db,scope,lock=False):
  row=db.execute('SELECT metadata_revision,data_revision,policy_revision,commit_revision,processing_mode FROM epm.application_state WHERE workspace_id=%s AND application_id=%s'+(' FOR UPDATE' if lock else ''),(scope.workspace_id,scope.application_id)).fetchone()
  if not row or row['processing_mode']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
  return row
 def _assignment(self,db,scope,n,*,access_role,groups=(),lock=False):
  row=db.execute('''SELECT s.pointer_version,v.* FROM epm.planning_assignment_state s JOIN epm.planning_assignment_version v ON v.workspace_id=s.workspace_id AND v.application_id=s.application_id AND v.assignment_set_id=s.active_assignment_set_id AND v.version=s.active_version WHERE s.workspace_id=%s AND s.application_id=%s'''+(' FOR UPDATE OF s' if lock else ''),(scope.workspace_id,scope.application_id)).fetchone()
  if not row or (row['assignment_set_id'],row['version'],row['canonical_digest'])!=(n['assignmentSetId'],n['assignmentVersion'],n['assignmentDigest']):raise ValueError('ASSIGNED_REVIEW_ASSIGNMENT_STALE')
  model=compile_planning_assignment_set(row['definition']);item=next((x for x in model.assignments if x.assignment_id==n['assignmentId']),None)
  if not item:raise ValueError('ASSIGNED_REVIEW_ASSIGNMENT_UNAVAILABLE')
  if item.workflow_role!=access_role:raise ValueError('ASSIGNED_REVIEW_ROLE_REQUIRED')
  policy=db.execute('SELECT active_policy_id,active_version FROM epm.cube_write_policy_state WHERE workspace_id=%s AND application_id=%s',(scope.workspace_id,scope.application_id)).fetchone()
  if not policy or (policy['active_policy_id'],policy['active_version'])!=(model.policy_link.policy_id,model.policy_link.version):raise ValueError('ASSIGNED_REVIEW_POLICY_STALE')
  control=db.execute('SELECT * FROM epm.planning_assignment_control_current WHERE workspace_id=%s AND application_id=%s AND assignment_set_id=%s AND assignment_version=%s AND assignment_id=%s'+(' FOR UPDATE' if lock else ''),(scope.workspace_id,scope.application_id,model.assignment_set_id,model.version,item.assignment_id)).fetchone()
  cv=control['control_version'] if control else 0
  if cv!=n['expectedControlVersion']:raise ValueError('ASSIGNED_REVIEW_CONTROL_STALE')
  now=datetime.now(timezone.utc);effective=item.effective_from<=now and (item.effective_to is None or now<=item.effective_to)
  if not effective:raise ValueError('ASSIGNED_REVIEW_ASSIGNMENT_INACTIVE')
  if control:
   expired=(control['delegation_expires_at'] is not None and
            control['delegation_expires_at']<=now)
   if expired:
    assigned=(control['delegator_issuer']==self.identity.issuer and
              control['delegator_subject_id']==self.identity.subject_id)
   elif control['assignee_subject_id'] is not None:
    assigned=(control['assignee_issuer']==self.identity.issuer and
              control['assignee_subject_id']==self.identity.subject_id)
   else:
    # Group claims are meaningful only under the immutable assignment
    # version's issuer; a same-named group from another issuer never matches.
    assigned=(row['creator_issuer']==self.identity.issuer and
              control['assignee_group_id'] in groups)
  else:
   assigned=issuer_bound_principal_matches(row['creator_issuer'],
    self.identity.issuer,self.identity.subject_id,groups,
    item.subjects,item.groups)
  if not assigned:raise ValueError('ASSIGNED_REVIEW_ASSIGNEE_REQUIRED')
  members=n['scopeMembers'];selectors=dict(item.member_selectors)
  if any(axis not in members or members[axis] not in allowed for axis,allowed in selectors.items()):raise ValueError('ASSIGNED_REVIEW_SCOPE_NOT_ASSIGNED')
  axes=db.execute("SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s AND application_id=%s AND status='Active'",(scope.workspace_id,scope.application_id)).fetchall();axis_ids={x['dimension_id'] for x in axes}
  if not set(members)<=axis_ids or not set(selectors)<=axis_ids:raise ValueError('ASSIGNED_REVIEW_SCOPE_AXIS_UNAVAILABLE')
  pairs=[{'dimension_id':a,'member_id':m} for a,m in members.items()]
  selector_pairs=[{'dimension_id':a,'member_id':m}
   for a,allowed in selectors.items() for m in allowed]
  active=db.execute('''SELECT count(*) n FROM jsonb_to_recordset(%s::jsonb) x(dimension_id text,member_id text) JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s AND m.dimension_id=x.dimension_id AND m.member_id=x.member_id AND m.status='Active' ''',(Jsonb(pairs),scope.workspace_id,scope.application_id)).fetchone()['n']
  if active!=len(pairs):raise ValueError('ASSIGNED_REVIEW_SCOPE_MEMBER_UNAVAILABLE')
  selector_active=db.execute('''SELECT count(*) n FROM jsonb_to_recordset(%s::jsonb) x(dimension_id text,member_id text) JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s AND m.dimension_id=x.dimension_id AND m.member_id=x.member_id AND m.status='Active' ''',(Jsonb(selector_pairs),scope.workspace_id,scope.application_id)).fetchone()['n']
  if selector_active!=len(selector_pairs):raise ValueError('ASSIGNED_REVIEW_SELECTOR_MEMBER_UNAVAILABLE')
  return model,item,cv,row['creator_issuer']
 def _review_row(self,db,scope,n,groups=(),lock=False):
  row=db.execute('''SELECT a.*,r.reviewer_kind,r.reviewer_issuer,r.reviewer_id,l.status AS lock_status,l.version AS lock_version FROM epm.cube_write_scope_assigned_submission a JOIN epm.cube_write_scope_assigned_reviewer r ON r.workspace_id=a.workspace_id AND r.application_id=a.application_id AND r.lock_id=a.lock_id AND r.reviewer_ordinal=a.current_step JOIN epm.cube_write_scope_lock l ON l.workspace_id=a.workspace_id AND l.application_id=a.application_id AND l.lock_id=a.lock_id WHERE a.workspace_id=%s AND a.application_id=%s AND a.lock_id=%s'''+(' FOR UPDATE OF a,l' if lock else ''),(scope.workspace_id,scope.application_id,n['lockId'])).fetchone()
  if not row or row['workflow_version']!=n['expectedWorkflowVersion'] or row['status'] not in ('Submitted','InReview') or row['lock_status']!='Locked':raise ValueError('ASSIGNED_REVIEW_STALE')
  matched=(row['reviewer_issuer']==self.identity.issuer and (row['reviewer_id']==self.identity.subject_id if row['reviewer_kind']=='Subject' else row['reviewer_id'] in groups))
  if not matched:raise ValueError('ASSIGNED_REVIEW_CURRENT_REVIEWER_REQUIRED')
  return row
 def _token(self,payload):
  raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode();return base64.urlsafe_b64encode(raw+hmac.new(self.secret,raw,sha256).digest()).decode()
 def _verify(self,token,payload):
  try:packed=base64.b64decode(token,altchars=b'-_',validate=True);raw,sig=packed[:-32],packed[-32:];actual=json.loads(raw)
  except Exception as e:raise ValueError('ASSIGNED_REVIEW_PREVIEW_INVALID') from e
  if not hmac.compare_digest(sig,hmac.new(self.secret,raw,sha256).digest()) or actual!=payload or actual['expiresAt']<int(time.time()):raise ValueError('ASSIGNED_REVIEW_PREVIEW_STALE')
 def preview(self,scope,program):
  n=compile_program(program)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write' if n['function']==SUBMIT else 'admin' if n['function']==REOPEN else 'read');state=self._state(db,scope)
    if n['function']==SUBMIT:self._assignment(db,scope,n,access_role=access.role,groups=access.groups)
    elif n['function']==REVIEW:self._review_row(db,scope,n,groups=access.groups)
    else:
     row=db.execute("SELECT status,workflow_version FROM epm.cube_write_scope_assigned_submission WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(scope.workspace_id,scope.application_id,n['lockId'])).fetchone()
     if not row or row['status']!='Approved' or row['workflow_version']!=n['expectedWorkflowVersion']:raise ValueError('ASSIGNED_REVIEW_STALE')
  payload={'scope':[scope.workspace_id,scope.application_id],'identity':[self.identity.issuer,self.identity.subject_id],'digest':_canonical_digest(n),'revisions':[state['metadata_revision'],state['data_revision'],state['policy_revision']],'expiresAt':int(time.time())+300}
  return {'languageVersion':2,'function':program['function'],'revisionVector':dict(zip(('metadata','data','policy'),payload['revisions'])),'previewToken':self._token(payload)}
 def replay(self,scope,program):
  n=compile_program(program)
  if n['function']==READ:raise ValueError('ASSIGNED_REVIEW_READ_INVALID')
  digest,op=self._receipt(scope,n)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope)
    PostgresAccessChecker.check_in_transaction(
     db,self.identity,scope,'write' if n['function']==SUBMIT else
     'admin' if n['function']==REOPEN else 'read')
    row=db.execute('''SELECT command_digest,result FROM epm.operation_receipt
     WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
     (scope.workspace_id,scope.application_id,op)).fetchone()
    if not row:return None
    if row['command_digest']!=digest:
     raise ValueError('ASSIGNED_REVIEW_IDEMPOTENCY_CONFLICT')
    return row['result']
 def worklist(self,scope,*,limit=100):
  if type(limit) is not int or not 1<=limit<=100:raise ValueError('ASSIGNED_REVIEW_WORKLIST_LIMIT_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read')
    rows=db.execute('''SELECT a.lock_id,a.assignment_set_id,a.assignment_version,a.assignment_id,a.current_step,a.step_count,a.status,a.workflow_version,r.reviewer_kind,r.reviewer_id,l.scope_members,l.scope_all FROM epm.cube_write_scope_assigned_submission a JOIN epm.cube_write_scope_assigned_reviewer r ON r.workspace_id=a.workspace_id AND r.application_id=a.application_id AND r.lock_id=a.lock_id AND r.reviewer_ordinal=a.current_step JOIN epm.cube_write_scope_lock l ON l.workspace_id=a.workspace_id AND l.application_id=a.application_id AND l.lock_id=a.lock_id WHERE a.workspace_id=%s AND a.application_id=%s AND a.status IN('Submitted','InReview') AND r.reviewer_issuer=%s AND ((r.reviewer_kind='Subject' AND r.reviewer_id=%s) OR (r.reviewer_kind='Group' AND r.reviewer_id=ANY(%s::text[]))) ORDER BY a.lock_id LIMIT %s''',(scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,list(access.groups),limit)).fetchall()
    return {'items':[{'lockId':r['lock_id'],'assignmentSetId':r['assignment_set_id'],'assignmentVersion':r['assignment_version'],'assignmentId':r['assignment_id'],'currentStep':r['current_step'],'stepCount':r['step_count'],'status':r['status'],'workflowVersion':r['workflow_version'],'scopeMembers':r['scope_members'],'scopeAll':r['scope_all']} for r in rows]}
 def read(self,scope,program):
  n=compile_program(program)
  if n['function']!=READ:raise ValueError('ASSIGNED_REVIEW_READ_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read')
    row=db.execute('''SELECT a.*,s.submitter_issuer,s.submitter_subject_id,l.scope_members,l.scope_all,l.status AS lock_status FROM epm.cube_write_scope_assigned_submission a JOIN epm.cube_write_scope_submission s ON s.workspace_id=a.workspace_id AND s.application_id=a.application_id AND s.lock_id=a.lock_id JOIN epm.cube_write_scope_lock l ON l.workspace_id=a.workspace_id AND l.application_id=a.application_id AND l.lock_id=a.lock_id WHERE a.workspace_id=%s AND a.application_id=%s AND a.lock_id=%s''',(scope.workspace_id,scope.application_id,n['lockId'])).fetchone()
    if not row:raise ValueError('ASSIGNED_REVIEW_UNAVAILABLE')
    chain=db.execute('SELECT reviewer_ordinal,reviewer_kind,reviewer_issuer,reviewer_id FROM epm.cube_write_scope_assigned_reviewer WHERE workspace_id=%s AND application_id=%s AND lock_id=%s ORDER BY reviewer_ordinal',(scope.workspace_id,scope.application_id,n['lockId'])).fetchall()
    visible=(access.role=='Administrator' or (row['submitter_issuer'],row['submitter_subject_id'])==(self.identity.issuer,self.identity.subject_id) or any(x['reviewer_ordinal']==row['current_step'] and x['reviewer_issuer']==self.identity.issuer and (x['reviewer_id']==self.identity.subject_id if x['reviewer_kind']=='Subject' else x['reviewer_id'] in access.groups) for x in chain))
    if not visible:raise ValueError('ASSIGNED_REVIEW_VISIBILITY_REQUIRED')
    events=db.execute('SELECT event_ordinal,workflow_version,action,reviewer_ordinal,actor_issuer,actor_subject_id,reason,committed_revision FROM epm.cube_write_scope_assigned_review_event WHERE workspace_id=%s AND application_id=%s AND lock_id=%s ORDER BY event_ordinal',(scope.workspace_id,scope.application_id,n['lockId'])).fetchall()
    return {'lockId':n['lockId'],'assignmentSetId':row['assignment_set_id'],'assignmentVersion':row['assignment_version'],'assignmentDigest':row['assignment_digest'],'assignmentId':row['assignment_id'],'policy':{'id':row['policy_id'],'version':row['policy_version'],'digest':row['policy_digest']},'controlVersion':row['control_version'],'status':row['status'],'workflowVersion':row['workflow_version'],'currentStep':row['current_step'],'stepCount':row['step_count'],'lockStatus':row['lock_status'],'scopeMembers':row['scope_members'],'scopeAll':row['scope_all'],'submitter':{'issuer':row['submitter_issuer'],'subjectId':row['submitter_subject_id']},'reviewerChain':[{'ordinal':x['reviewer_ordinal'],'kind':x['reviewer_kind'],'issuer':x['reviewer_issuer'],'id':x['reviewer_id']} for x in chain],'events':[dict(x) for x in events]}
 def apply(self,scope,program,*,preview_token):
  n=compile_program(program);digest,op=self._receipt(scope,n)
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);access=PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write' if n['function']==SUBMIT else 'admin' if n['function']==REOPEN else 'read');state=self._state(db,scope,True)
    prior=db.execute('SELECT command_digest,result FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s AND operation_id=%s',(scope.workspace_id,scope.application_id,op)).fetchone()
    if prior:
     if prior['command_digest']!=digest:raise ValueError('ASSIGNED_REVIEW_IDEMPOTENCY_CONFLICT')
     return prior['result']
    payload={'scope':[scope.workspace_id,scope.application_id],'identity':[self.identity.issuer,self.identity.subject_id],'digest':_canonical_digest(n),'revisions':[state['metadata_revision'],state['data_revision'],state['policy_revision']],'expiresAt':0}
    # expiry differs; verify signed content explicitly while retaining pins.
    try:packed=base64.b64decode(preview_token,altchars=b'-_',validate=True);raw,sig=packed[:-32],packed[-32:];signed=json.loads(raw)
    except Exception as e:raise ValueError('ASSIGNED_REVIEW_PREVIEW_INVALID') from e
    if not hmac.compare_digest(sig,hmac.new(self.secret,raw,sha256).digest()) or signed.get('scope')!=payload['scope'] or signed.get('identity')!=payload['identity'] or signed.get('digest')!=payload['digest'] or signed.get('revisions')!=payload['revisions'] or signed.get('expiresAt',0)<int(time.time()):raise ValueError('ASSIGNED_REVIEW_PREVIEW_STALE')
    revision=state['commit_revision']+1
    if n['function']==SUBMIT:
     model,item,cv,assignment_issuer=self._assignment(db,scope,n,access_role=access.role,groups=access.groups,lock=True);lock_id=uuid.uuid4().hex;chain=[{'kind':r.kind,'issuer':assignment_issuer,'id':r.identifier} for r in item.reviewer_chain];chain_digest=_canonical_digest(chain)
     db.execute("INSERT INTO epm.cube_write_scope_lock(workspace_id,application_id,lock_id,issuer,subject_id,idempotency_key,request_digest,scope_members,scope_all,status,version,reason,locked_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,false,'Locked',1,%s,%s)",(scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,self.identity.subject_id,n['idempotencyKey'],digest,Jsonb(n['scopeMembers']),n['reason'],revision))
     first=chain[0];legacy_subject=(first['id'] if first['kind']=='Subject' else '__assigned_group_non_authoritative__');db.execute("INSERT INTO epm.cube_write_scope_submission(workspace_id,application_id,lock_id,submitter_issuer,submitter_subject_id,reviewer_issuer,reviewer_subject_id,status,version,submitted_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,'Submitted',1,%s)",(scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,self.identity.subject_id,self.identity.issuer,legacy_subject,revision))
     db.execute("INSERT INTO epm.cube_write_scope_lock_event VALUES(%s,%s,%s,1,'Locked',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,self.identity.subject_id,n['reason'],revision));db.execute("INSERT INTO epm.cube_write_scope_submission_event VALUES(%s,%s,%s,1,'Submitted',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,self.identity.subject_id,n['reason'],revision))
     db.execute("INSERT INTO epm.cube_write_scope_assigned_submission VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,'Submitted',1)",(scope.workspace_id,scope.application_id,lock_id,model.assignment_set_id,model.version,model.digest,item.assignment_id,model.policy_link.policy_id,model.policy_link.version,model.policy_link.digest,cv,chain_digest,len(chain)))
     for i,r in enumerate(chain,1):db.execute('INSERT INTO epm.cube_write_scope_assigned_reviewer VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,lock_id,i,r['kind'],r['issuer'],r['id']))
     db.execute("INSERT INTO epm.cube_write_scope_assigned_review_event(workspace_id,application_id,lock_id,event_ordinal,workflow_version,action,actor_issuer,actor_subject_id,reason,committed_revision) VALUES(%s,%s,%s,1,1,'Submitted',%s,%s,%s,%s)",(scope.workspace_id,scope.application_id,lock_id,self.identity.issuer,self.identity.subject_id,n['reason'],revision));result={'lockId':lock_id,'status':'Submitted','workflowVersion':1,'currentStep':1,'stepCount':len(chain),'committedRevision':revision}
    elif n['function']==REVIEW:
     row=self._review_row(db,scope,n,groups=access.groups,lock=True);nextv=row['workflow_version']+1
     if n['action']=='Return':
      db.execute("UPDATE epm.cube_write_scope_assigned_submission SET status='Returned',workflow_version=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(nextv,scope.workspace_id,scope.application_id,n['lockId']));db.execute("UPDATE epm.cube_write_scope_lock SET status='Open',version=version+1,reopened_revision=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(revision,scope.workspace_id,scope.application_id,n['lockId']));db.execute("UPDATE epm.cube_write_scope_submission SET status='Reopened',version=2,reopened_revision=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(revision,scope.workspace_id,scope.application_id,n['lockId']));db.execute("INSERT INTO epm.cube_write_scope_lock_event VALUES(%s,%s,%s,2,'Reopened',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,n['lockId'],self.identity.issuer,self.identity.subject_id,n['reason'],revision));db.execute("INSERT INTO epm.cube_write_scope_submission_event VALUES(%s,%s,%s,2,'Reopened',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,n['lockId'],self.identity.issuer,self.identity.subject_id,n['reason'],revision));action,status,step='Returned','Returned',row['current_step']
     elif row['current_step']<row['step_count']:
      step=row['current_step']+1;db.execute("UPDATE epm.cube_write_scope_assigned_submission SET status='InReview',current_step=%s,workflow_version=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(step,nextv,scope.workspace_id,scope.application_id,n['lockId']));action,status='Advanced','InReview'
     else:
      step=row['current_step'];db.execute("UPDATE epm.cube_write_scope_assigned_submission SET status='Approved',workflow_version=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(nextv,scope.workspace_id,scope.application_id,n['lockId']));db.execute("UPDATE epm.cube_write_scope_submission SET status='Approved',version=2,approved_revision=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(revision,scope.workspace_id,scope.application_id,n['lockId']));db.execute("INSERT INTO epm.cube_write_scope_submission_event VALUES(%s,%s,%s,2,'Approved',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,n['lockId'],self.identity.issuer,self.identity.subject_id,n['reason'],revision));action=status='Approved'
     ordinal=db.execute('SELECT coalesce(max(event_ordinal),0)+1 n FROM epm.cube_write_scope_assigned_review_event WHERE workspace_id=%s AND application_id=%s AND lock_id=%s',(scope.workspace_id,scope.application_id,n['lockId'])).fetchone()['n'];db.execute('INSERT INTO epm.cube_write_scope_assigned_review_event(workspace_id,application_id,lock_id,event_ordinal,workflow_version,action,reviewer_ordinal,actor_issuer,actor_subject_id,reason,committed_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,n['lockId'],ordinal,nextv,action,row['current_step'],self.identity.issuer,self.identity.subject_id,n['reason'],revision));result={'lockId':n['lockId'],'status':status,'workflowVersion':nextv,'currentStep':step,'stepCount':row['step_count'],'committedRevision':revision}
    else:
     row=db.execute("SELECT * FROM epm.cube_write_scope_assigned_submission WHERE workspace_id=%s AND application_id=%s AND lock_id=%s FOR UPDATE",(scope.workspace_id,scope.application_id,n['lockId'])).fetchone()
     if not row or row['status']!='Approved' or row['workflow_version']!=n['expectedWorkflowVersion']:raise ValueError('ASSIGNED_REVIEW_STALE')
     nextv=row['workflow_version']+1;db.execute("UPDATE epm.cube_write_scope_assigned_submission SET status='Reopened',workflow_version=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(nextv,scope.workspace_id,scope.application_id,n['lockId']));db.execute("UPDATE epm.cube_write_scope_lock SET status='Open',version=2,reopened_revision=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(revision,scope.workspace_id,scope.application_id,n['lockId']));db.execute("UPDATE epm.cube_write_scope_submission SET status='Reopened',version=3,reopened_revision=%s WHERE workspace_id=%s AND application_id=%s AND lock_id=%s",(revision,scope.workspace_id,scope.application_id,n['lockId']));db.execute("INSERT INTO epm.cube_write_scope_lock_event VALUES(%s,%s,%s,2,'Reopened',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,n['lockId'],self.identity.issuer,self.identity.subject_id,n['reason'],revision));db.execute("INSERT INTO epm.cube_write_scope_submission_event VALUES(%s,%s,%s,3,'Reopened',%s,%s,%s,%s,transaction_timestamp())",(scope.workspace_id,scope.application_id,n['lockId'],self.identity.issuer,self.identity.subject_id,n['reason'],revision));ordinal=db.execute('SELECT coalesce(max(event_ordinal),0)+1 n FROM epm.cube_write_scope_assigned_review_event WHERE workspace_id=%s AND application_id=%s AND lock_id=%s',(scope.workspace_id,scope.application_id,n['lockId'])).fetchone()['n'];db.execute("INSERT INTO epm.cube_write_scope_assigned_review_event(workspace_id,application_id,lock_id,event_ordinal,workflow_version,action,actor_issuer,actor_subject_id,reason,committed_revision) VALUES(%s,%s,%s,%s,%s,'Reopened',%s,%s,%s,%s)",(scope.workspace_id,scope.application_id,n['lockId'],ordinal,nextv,self.identity.issuer,self.identity.subject_id,n['reason'],revision));result={'lockId':n['lockId'],'status':'Reopened','workflowVersion':nextv,'committedRevision':revision}
    db.execute('UPDATE epm.application_state SET policy_revision=policy_revision+1,commit_revision=%s WHERE workspace_id=%s AND application_id=%s',(revision,scope.workspace_id,scope.application_id));db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(scope.workspace_id,scope.application_id,op,digest,self.identity.subject_id,revision,Jsonb(result)));return result
