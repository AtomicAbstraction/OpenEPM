"""PostgreSQL repository for crash-durable export source checkpoints."""
from __future__ import annotations
import json, re, uuid
from hashlib import sha256
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .persistence_contract import ApplicationScope
from .postgres_access import (PostgresAccessChecker,VerifiedIdentity,
                              durable_authority_fields)
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout

_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
def _digest(v): return sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

class PostgresExportProducerCheckpoint:
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity): raise ValueError('verified identity required')
  self.dsn,self.identity=dsn,identity
 def _tx(self,scope,permission='read'):
  db=connect_postgres(self.dsn,row_factory=dict_row);PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,permission);return db
 def _authorization_scope_digest(self,db,scope):
  return resolve_effective_dimensional_scope(
   db,self.identity,scope,function='facts.transfer.export.request').scope_digest
 def _require_current_authorization_scope(self,db,scope,rid):
  row=db.execute('''SELECT authorization_scope_digest
   FROM epm.fact_export_producer_request WHERE workspace_id=%s
   AND application_id=%s AND request_id=%s''',(
    scope.workspace_id,scope.application_id,rid)).fetchone()
  if (row is None or row['authorization_scope_digest'] is None
      or row['authorization_scope_digest']!=
      self._authorization_scope_digest(db,scope)):
   raise ValueError('EXPORT_PRODUCER_AUTHORIZATION_SCOPE_CHANGED')
 def begin(self,scope,*,idempotency_key,origin,snapshot_revision,
           metadata_revision,security_revision,expires_at,schema,members):
  if not _KEY.fullmatch(idempotency_key): raise ValueError('EXPORT_PRODUCER_REQUEST_INVALID')
  if type(security_revision) is not int or security_revision < 0:
   raise ValueError('EXPORT_PRODUCER_REQUEST_INVALID')
  with self._tx(scope) as db,db.transaction():
   configure_statement_timeout(db,5000)
   authorization_scope_digest=self._authorization_scope_digest(db,scope)
   request={'scope':[scope.workspace_id,scope.application_id],'origin':origin,'snapshot':snapshot_revision,'metadata':metadata_revision,'security':security_revision,'expires':expires_at,'schema':schema,'members':members,'actor':[self.identity.issuer,self.identity.subject_id],'verifiedGroups':list(self.identity.groups),'authorizationScopeDigest':authorization_scope_digest};digest=_digest(request)
   db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",(
    '|'.join((scope.workspace_id,scope.application_id,self.identity.issuer,
              self.identity.subject_id,idempotency_key)),))
   prior=db.execute('SELECT * FROM epm.fact_export_producer_request WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s',(scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,idempotency_key)).fetchone()
   if prior:
    if prior['request_digest']!=digest: raise ValueError('EXPORT_PRODUCER_REQUEST_CONFLICT')
    return prior
   state=db.execute('''SELECT security_revision FROM epm.application_state
    WHERE workspace_id=%s AND application_id=%s''',(
      scope.workspace_id,scope.application_id)).fetchone()
   if state is None or state['security_revision']!=security_revision:
    raise ValueError('EXPORT_PRODUCER_SECURITY_STALE')
   rid=uuid.uuid4().hex
   token_issued_at,authority_kind=durable_authority_fields(self.identity)
   return db.execute("INSERT INTO epm.fact_export_producer_request(workspace_id,application_id,request_id,issuer,subject_id,idempotency_key,request_digest,origin,snapshot_revision,metadata_revision,security_revision,expires_at_epoch,schema_identity,members,status,verified_groups,authorization_scope_digest,token_issued_at,authority_kind) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Accepted',%s,%s,%s,%s) RETURNING *",(scope.workspace_id,scope.application_id,rid,self.identity.issuer,self.identity.subject_id,idempotency_key,digest,origin,snapshot_revision,metadata_revision,security_revision,expires_at,Jsonb(schema),Jsonb(members or {}),list(self.identity.groups),authorization_scope_digest,token_issued_at,authority_kind)).fetchone()
 def claim(self,scope,rid,worker,seconds=120):
  with self._tx(scope) as db,db.transaction():
   self._require_current_authorization_scope(db,scope,rid)
   return db.execute('''SELECT * FROM epm.export_producer_claim(
   %s,%s,%s,%s,%s::integer)''',(scope.workspace_id,scope.application_id,rid,worker,seconds)).fetchone()
 def pages(self,scope,rid):
  with self._tx(scope) as db,db.transaction():
   self._require_current_authorization_scope(db,scope,rid)
   return [row['page'] for row in db.execute('SELECT page FROM epm.fact_export_producer_page WHERE workspace_id=%s AND application_id=%s AND request_id=%s ORDER BY page_index',(scope.workspace_id,scope.application_id,rid)).fetchall()]
 def read(self,scope,rid):
  with self._tx(scope) as db,db.transaction():
   row=db.execute('SELECT * FROM epm.fact_export_producer_request WHERE workspace_id=%s AND application_id=%s AND request_id=%s AND issuer=%s AND subject_id=%s',(scope.workspace_id,scope.application_id,rid,self.identity.issuer,self.identity.subject_id)).fetchone()
   if row is None: raise ValueError('EXPORT_PRODUCER_REQUEST_UNAVAILABLE')
   self._require_current_authorization_scope(db,scope,rid)
   return row
 def find_by_idempotency(self,scope,key):
  if not isinstance(key,str) or not _KEY.fullmatch(key): raise ValueError('EXPORT_PRODUCER_REQUEST_INVALID')
  with self._tx(scope) as db,db.transaction():
   return db.execute('SELECT * FROM epm.fact_export_producer_request WHERE workspace_id=%s AND application_id=%s AND issuer=%s AND subject_id=%s AND idempotency_key=%s',(scope.workspace_id,scope.application_id,self.identity.issuer,self.identity.subject_id,key)).fetchone()
 def rerun_as_task_controller(self,scope,rid,*,idempotency_key):
  """Create a fresh retained export attempt from failed/cancelled work.

  Export history is retention bounded.  A source whose native request has
  already been cleaned cannot be reconstructed from the task projection and
  therefore remains unavailable.  For a retained source, preserve its pinned
  snapshot, metadata, schema and member filters, while issuing a fresh bounded
  expiry.  This is owner-only because the source request contains the owner's
  read scope and must never be adopted by an Administrator.
  """
  if (not isinstance(scope,ApplicationScope) or not isinstance(rid,str)
      or re.fullmatch(r'[0-9a-f]{32}',rid) is None
      or not isinstance(idempotency_key,str)
      or _KEY.fullmatch(idempotency_key) is None):
   raise ValueError('EXPORT_PRODUCER_RERUN_ARGUMENTS_INVALID')
  identity=(self.identity.issuer,self.identity.subject_id)
  seed={'domain':'openepm-export-producer-rerun-v1',
        'scope':[scope.workspace_id,scope.application_id],
        'identity':list(identity),'sourceRequestId':rid,
        'idempotencyKey':idempotency_key}
  new_rid=_digest(seed)[:32]
  with self._tx(scope) as db,db.transaction():
   configure_statement_timeout(db,5000);configure_lock_wait(db)
   db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",(
    '|'.join((scope.workspace_id,scope.application_id,*identity,
              idempotency_key)),))
   prior=db.execute('''SELECT * FROM epm.fact_export_producer_request
    WHERE workspace_id=%s AND application_id=%s AND issuer=%s
      AND subject_id=%s AND idempotency_key=%s''',(
       scope.workspace_id,scope.application_id,*identity,
       idempotency_key)).fetchone()
   if prior is not None:
    if prior['rerun_of_request_id']!=rid:
     raise ValueError('EXPORT_PRODUCER_REQUEST_CONFLICT')
    return prior
   source=db.execute('''SELECT * FROM epm.fact_export_producer_request
    WHERE workspace_id=%s AND application_id=%s AND request_id=%s
      AND issuer=%s AND subject_id=%s''',(
       scope.workspace_id,scope.application_id,rid,*identity)).fetchone()
   if source is None or source['status'] not in ('Cancelled','Failed'):
    raise ValueError('EXPORT_PRODUCER_RERUN_NOT_SUPPORTED')
   if (type(source.get('security_revision')) is not int
       or source['security_revision'] < 0):
    raise ValueError('EXPORT_PRODUCER_SECURITY_CERTIFICATE_UNAVAILABLE')
   state=db.execute('''SELECT security_revision FROM epm.application_state
    WHERE workspace_id=%s AND application_id=%s''',(
      scope.workspace_id,scope.application_id)).fetchone()
   if state is None or state['security_revision']!=source['security_revision']:
    raise ValueError('EXPORT_PRODUCER_SECURITY_STALE')
   now=db.execute("SELECT extract(epoch from clock_timestamp())::bigint AS value").fetchone()['value']
   original_ttl=source['expires_at_epoch']-int(source['created_at'].timestamp())
   ttl=max(60,min(86400,original_ttl))
   expires_at=now+ttl
   authorization_scope_digest=self._authorization_scope_digest(db,scope)
   request={'scope':[scope.workspace_id,scope.application_id],
    'origin':source['origin'],'snapshot':source['snapshot_revision'],
    'metadata':source['metadata_revision'],'expires':expires_at,
    'security':source['security_revision'],
    'schema':source['schema_identity'],'members':source['members'],
    'actor':list(identity),'verifiedGroups':list(self.identity.groups),
    'authorizationScopeDigest':authorization_scope_digest}
   token_issued_at,authority_kind=durable_authority_fields(self.identity)
   return db.execute('''INSERT INTO epm.fact_export_producer_request(
    workspace_id,application_id,request_id,issuer,subject_id,idempotency_key,
    request_digest,origin,snapshot_revision,metadata_revision,
    security_revision,expires_at_epoch,schema_identity,members,status,
    rerun_of_request_id,verified_groups,authorization_scope_digest,
    token_issued_at,authority_kind)
    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'Accepted',%s,%s,%s,%s,%s)
    RETURNING *''',(scope.workspace_id,scope.application_id,new_rid,*identity,
      idempotency_key,_digest(request),source['origin'],
      source['snapshot_revision'],source['metadata_revision'],
      source['security_revision'],expires_at,
      Jsonb(source['schema_identity']),Jsonb(source['members']),rid,
      list(self.identity.groups),authorization_scope_digest,token_issued_at,
      authority_kind)).fetchone()
 def append(self,scope,rid,worker,generation,index,request_cursor,next_cursor,page):
  with self._tx(scope) as db,db.transaction():
   self._require_current_authorization_scope(db,scope,rid)
   return db.execute('SELECT epm.export_producer_append(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) AS result',(scope.workspace_id,scope.application_id,rid,worker,generation,index,request_cursor,next_cursor,page['contentDigest'],Jsonb(page))).fetchone()['result']
 def seal(self,scope,rid,worker,generation,manifest):
  with self._tx(scope) as db,db.transaction():
   self._require_current_authorization_scope(db,scope,rid)
   return db.execute('SELECT epm.export_producer_seal(%s,%s,%s,%s,%s,%s) AS result',(scope.workspace_id,scope.application_id,rid,worker,generation,Jsonb(manifest))).fetchone()['result']
 def cancel(self,scope,rid):
  return self.request_cancel_as_task_controller(scope,rid)
 def request_cancel_as_task_controller(self,scope,rid,*,
                                       allow_application_admin=False):
  """Cancel through the native export fence under current authority."""
  if (not isinstance(scope,ApplicationScope) or not isinstance(rid,str)
      or re.fullmatch(r'[0-9a-f]{32}',rid) is None
      or type(allow_application_admin) is not bool):
   raise ValueError('EXPORT_PRODUCER_REQUEST_UNAVAILABLE')
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   configure_statement_timeout(db,5000);configure_lock_wait(db)
   PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
   PostgresAccessChecker.check_in_transaction(
    db,self.identity,scope,'read')
   row=db.execute('''SELECT * FROM epm.export_producer_cancel_control(
    %s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,rid,
    self.identity.issuer,self.identity.subject_id,
    allow_application_admin)).fetchone()
   if row is None:
    raise ValueError('EXPORT_PRODUCER_REQUEST_UNAVAILABLE')
   return row
 def claim_publish(self,scope,rid,worker,seconds=120):
  if (not isinstance(worker,str) or not 1<=len(worker)<=200
      or type(seconds)is not int or not 30<=seconds<=300):
   raise ValueError('EXPORT_PRODUCER_PUBLISH_CLAIM_INVALID')
  with self._tx(scope) as db,db.transaction():
   self._require_current_authorization_scope(db,scope,rid)
   return db.execute('''SELECT * FROM epm.export_producer_publish_claim(
    %s,%s,%s,%s,%s::integer)''',(scope.workspace_id,scope.application_id,rid,worker,seconds)).fetchone()
 def complete(self,scope,rid,worker,generation,artifact_id,manifest_digest,
              payload_digest):
  with self._tx(scope) as db,db.transaction():
   self._require_current_authorization_scope(db,scope,rid)
   return db.execute('SELECT epm.export_producer_publish_complete(%s,%s,%s,%s,%s,%s,%s,%s) AS result',(scope.workspace_id,scope.application_id,rid,worker,generation,artifact_id,manifest_digest,payload_digest)).fetchone()['result']
