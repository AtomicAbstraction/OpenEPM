from __future__ import annotations
import hashlib,json,re,uuid
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait,configure_statement_timeout

_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
class PostgresTransferCleanup:
 def __init__(self,dsn,*,identity):self.dsn,self.identity=dsn,identity
 def request(self,scope,*,idempotency_key,batch_limit=100):
  if not isinstance(self.identity,VerifiedIdentity) or not _KEY.fullmatch(idempotency_key) or type(batch_limit)is not int or not 1<=batch_limit<=1000:raise ValueError('TRANSFER_CLEANUP_REQUEST_INVALID')
  command={'scope':[scope.workspace_id,scope.application_id],'actor':[self.identity.issuer,self.identity.subject_id],'limit':batch_limit};digest=hashlib.sha256(json.dumps(command,sort_keys=True,separators=(',',':')).encode()).hexdigest()
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
   prior=db.execute('SELECT * FROM epm.transfer_cleanup_request WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s',(scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,idempotency_key)).fetchone()
   if prior:
    if prior['request_digest']!=digest:raise ValueError('TRANSFER_CLEANUP_REQUEST_CONFLICT')
    return prior
   return db.execute("INSERT INTO epm.transfer_cleanup_request(workspace_id,application_id,request_id,issuer,subject_id,idempotency_key,request_digest,batch_limit,status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'Accepted') RETURNING *",(scope.workspace_id,scope.application_id,uuid.uuid4().hex,self.identity.issuer,self.identity.subject_id,idempotency_key,digest,batch_limit)).fetchone()
 def read(self,scope,request_id):
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin');row=db.execute('SELECT * FROM epm.transfer_cleanup_request WHERE workspace_id=%s AND application_id=%s AND request_id=%s',(scope.workspace_id,scope.application_id,request_id)).fetchone()
   if not row:raise ValueError('TRANSFER_CLEANUP_UNAVAILABLE')
   return row
 def request_cancel_as_task_controller(self,scope,request_id):
  """Interrupt one cleanup through its native lease fence as current admin."""
  if (not isinstance(scope,ApplicationScope) or not isinstance(request_id,str)
      or re.fullmatch(r'[0-9a-f]{32}',request_id) is None):
   raise ValueError('TRANSFER_CLEANUP_UNAVAILABLE')
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   configure_statement_timeout(db,5000);configure_lock_wait(db)
   PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
   PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin')
   row=db.execute('''SELECT request_id,status FROM epm.transfer_cleanup_request
    WHERE workspace_id=%s AND application_id=%s AND request_id=%s''',
    (scope.workspace_id,scope.application_id,request_id)).fetchone()
   if row is None:raise ValueError('TRANSFER_CLEANUP_UNAVAILABLE')
   db.execute('SELECT epm.transfer_cleanup_cancel(%s,%s,%s)',
    (scope.workspace_id,scope.application_id,request_id))
   return db.execute('''SELECT request_id,status FROM epm.transfer_cleanup_request
    WHERE workspace_id=%s AND application_id=%s AND request_id=%s''',
    (scope.workspace_id,scope.application_id,request_id)).fetchone()

class PostgresTransferCleanupWorker:
 def __init__(self,dsn,*,worker_id):
  if not isinstance(worker_id,str) or not 1<=len(worker_id)<=200:raise ValueError('TRANSFER_CLEANUP_WORKER_INVALID')
  self.dsn,self.worker_id=dsn,worker_id
 def claim(self,scope,request_id,*,lease_seconds=120):
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   row=db.execute('''SELECT * FROM epm.transfer_cleanup_claim(
    %s,%s,%s,%s,%s::integer)''',(scope.workspace_id,scope.application_id,
      request_id,self.worker_id,lease_seconds)).fetchone()
   if not row:raise ValueError('TRANSFER_CLEANUP_NOT_CLAIMABLE')
   return row
 def execute(self,scope,request_id,claim_generation):
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   return db.execute('SELECT epm.transfer_cleanup_execute(%s,%s,%s,%s,%s) AS result',(scope.workspace_id,scope.application_id,request_id,self.worker_id,claim_generation)).fetchone()['result']

class PostgresTransferCleanupScheduledDispatch:
 """Bounded adapter for a scheduler's already-authorized request batch.

 Discovery remains outside this adapter: callers must supply exact scoped
 request identities obtained from the durable cleanup queue.  Sorting prevents
 caller order from starving a later application across repeated batches.
 """
 def __init__(self,dsn,*,worker_id):
  self.worker=PostgresTransferCleanupWorker(dsn,worker_id=worker_id)
 def dispatch(self,requests,*,lease_seconds=120):
  if (not isinstance(requests,(tuple,list)) or isinstance(requests,(str,bytes))
      or not 1<=len(requests)<=100 or type(lease_seconds)is not int
      or not 30<=lease_seconds<=300):
   raise ValueError('TRANSFER_CLEANUP_DISPATCH_INVALID')
  normalized=[]
  for item in requests:
   if (not isinstance(item,tuple) or len(item)!=2
       or not isinstance(item[0],ApplicationScope)
       or not isinstance(item[1],str) or not re.fullmatch(r'[0-9a-f]{32}',item[1])):
    raise ValueError('TRANSFER_CLEANUP_DISPATCH_INVALID')
   normalized.append(item)
  identities={(scope.workspace_id,scope.application_id,request_id)
              for scope,request_id in normalized}
  if len(identities)!=len(normalized):raise ValueError('TRANSFER_CLEANUP_DISPATCH_DUPLICATE')
  results=[]
  for scope,request_id in sorted(normalized,key=lambda value:(
      value[0].workspace_id,value[0].application_id,value[1])):
   claim=self.worker.claim(scope,request_id,lease_seconds=lease_seconds)
   results.append({'workspaceId':scope.workspace_id,
     'applicationId':scope.application_id,'requestId':request_id,
     'result':self.worker.execute(scope,request_id,claim['claim_generation'])})
  return results
