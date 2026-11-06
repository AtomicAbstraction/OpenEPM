"""Atomic bounded relationship changes and matching hierarchy publication."""
from __future__ import annotations

import base64
from collections import deque
from hashlib import sha256
import hmac
import json
import re
import time

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore


PREVIEW='metadata.hierarchy.relationships.preview'
APPLY='metadata.hierarchy.relationships.apply'
FUNCTIONS=frozenset((PREVIEW,APPLY))
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z')
_KEY=re.compile(r'[A-Za-z0-9._-]{8,200}\Z')
_MAX_MEMBERS=5000
_MAX_EDGES=10000
_MAX_PATHS=100000


def catalog():
    common={'dimensionId':'active non-Currency dimension ID',
      'changes':'1–100 Create/Activate/Deactivate relationship changes',
      'expectedMetadataRevision':'current nonnegative metadata revision',
      'expectedHierarchyVersion':'current positive active hierarchy version'}
    return {PREVIEW:{'mode':'read_only','permission':'admin',
      'arguments':common,'result':'signed exact graph/closure impact and pins',
      'previewRequired':False,'idempotencyRequired':False,'workClass':'medium'},
      APPLY:{'mode':'atomic_write','permission':'admin',
      'arguments':{**common,'previewToken':'server-signed exact preview'},
      'result':'one metadata/commit revision, hierarchy version and receipt',
      'previewRequired':True,'idempotencyRequired':True,'workClass':'medium'}}


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),
      ensure_ascii=False,allow_nan=False).encode()


def _compile(program,function,*,token):
    required={'dimensionId','changes','expectedMetadataRevision',
              'expectedHierarchyVersion'}|({'previewToken'} if token else set())
    if (not isinstance(program,dict)
      or set(program)!={'languageVersion','function','arguments'}
      or type(program['languageVersion']) is not int
      or program['languageVersion']!=2 or program['function']!=function
      or not isinstance(program['arguments'],dict)
      or set(program['arguments'])!=required):
        raise ValueError('HIERARCHY_PATCH_PROGRAM_INVALID')
    args=dict(program['arguments']);changes=args['changes']
    if (not isinstance(args['dimensionId'],str)
      or _ID.fullmatch(args['dimensionId']) is None
      or type(args['expectedMetadataRevision']) is not int
      or args['expectedMetadataRevision']<0
      or type(args['expectedHierarchyVersion']) is not int
      or args['expectedHierarchyVersion']<1
      or not isinstance(changes,list) or not 1<=len(changes)<=100
      or (token and (not isinstance(args['previewToken'],str)
                     or not args['previewToken']))):
        raise ValueError('HIERARCHY_PATCH_ARGUMENTS_INVALID')
    normalized=[];seen=set()
    for change in changes:
      if not isinstance(change,dict) or change.get('action') not in (
              'Create','Activate','Deactivate'):
        raise ValueError('HIERARCHY_PATCH_CHANGE_INVALID')
      action=change['action']
      expected=({'action','relationshipId','parentMemberId','childMemberId'}
        if action=='Create' else {'action','relationshipId'})
      if set(change)!=expected or any(not isinstance(change[key],str)
          or _ID.fullmatch(change[key]) is None for key in expected-{'action'}):
        raise ValueError('HIERARCHY_PATCH_CHANGE_INVALID')
      relationship=change['relationshipId']
      if relationship in seen:raise ValueError('HIERARCHY_PATCH_DUPLICATE')
      seen.add(relationship);normalized.append(dict(change))
    args['changes']=sorted(normalized,key=lambda item:item['relationshipId'])
    return args


def _closure(members,edges):
    if len(members)>_MAX_MEMBERS or len(edges)>_MAX_EDGES:
        raise ValueError('HIERARCHY_PATCH_GRAPH_LIMIT')
    children={member:[] for member in members};indegree={member:0 for member in members}
    for relationship,parent,child in edges:
      if parent not in children or child not in children or parent==child:
        raise ValueError('HIERARCHY_PATCH_MEMBER_INVALID')
      children[parent].append(child);indegree[child]+=1
    ready=deque(sorted(member for member in members if indegree[member]==0));seen=0
    while ready:
      parent=ready.popleft();seen+=1
      for child in sorted(children[parent]):
        indegree[child]-=1
        if indegree[child]==0:ready.append(child)
    if seen!=len(members):raise ValueError('HIERARCHY_PATCH_CYCLE')
    result={};visits=0
    for ancestor in sorted(members):
      stack=[(ancestor,0)]
      while stack:
        descendant,depth=stack.pop();visits+=1
        if visits>_MAX_PATHS:raise ValueError('HIERARCHY_PATCH_PATH_LIMIT')
        key=(ancestor,descendant);old=result.get(key)
        result[key]=(min(old[0],depth),old[1]+1) if old else (depth,1)
        stack.extend((child,depth+1) for child in children[descendant])
    return result


class PostgresHierarchyRelationshipPatch:
  def __init__(self,dsn,*,identity,preview_secret):
    if not isinstance(identity,VerifiedIdentity):raise ValueError('Verified identity required')
    if not isinstance(preview_secret,bytes) or len(preview_secret)<32:
      raise ValueError('Preview secret must be 32+ bytes')
    self.dsn,self.identity,self.secret=dsn,identity,preview_secret

  def _token(self,scope,payload):
    body={**payload,'scope':[scope.workspace_id,scope.application_id],
      'identity':[self.identity.issuer,self.identity.subject_id],
      'expiresAt':int(time.time())+300}
    raw=_canonical(body);signature=hmac.new(self.secret,raw,sha256).digest()
    return (base64.urlsafe_b64encode(raw).decode().rstrip('=')+'.'+
      base64.urlsafe_b64encode(signature).decode().rstrip('='))

  def _unpack(self,scope,token):
    try:
      encoded_raw,encoded_signature=token.split('.',1)
      raw=base64.urlsafe_b64decode(encoded_raw+'='*((4-len(encoded_raw)%4)%4))
      signature=base64.urlsafe_b64decode(encoded_signature+'='*((4-len(encoded_signature)%4)%4))
      payload=json.loads(raw)
    except Exception as error:
      raise ValueError('HIERARCHY_PATCH_PREVIEW_INVALID') from error
    if (not hmac.compare_digest(signature,hmac.new(self.secret,raw,sha256).digest())
      or payload.get('scope')!=[scope.workspace_id,scope.application_id]
      or payload.get('identity')!=[self.identity.issuer,self.identity.subject_id]
      or type(payload.get('expiresAt')) is not int
      or payload['expiresAt']<int(time.time())):
      raise ValueError('HIERARCHY_PATCH_PREVIEW_INVALID')
    return payload

  @staticmethod
  def _resolve(db,scope,args):
    keys=(scope.workspace_id,scope.application_id)
    state=db.execute('''SELECT s.metadata_revision,s.commit_revision,
      s.processing_mode,a.status FROM epm.application_state s JOIN epm.application a
      USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s''',keys).fetchone()
    dimension=db.execute('''SELECT status,model_role FROM epm.dimension WHERE
      workspace_id=%s AND application_id=%s AND dimension_id=%s''',(*keys,args['dimensionId'])).fetchone()
    active=db.execute('''SELECT h.version,v.metadata_revision,v.sealed,
      v.membership_semantics FROM epm.hierarchy_active h
      JOIN epm.hierarchy_version v USING(workspace_id,application_id,dimension_id,version)
      WHERE h.workspace_id=%s AND h.application_id=%s AND h.dimension_id=%s''',(*keys,args['dimensionId'])).fetchone()
    if (state is None or state['status']!='Active' or state['processing_mode']!='Active'):
      raise ValueError('APPLICATION_NOT_WRITABLE')
    if state['metadata_revision']!=args['expectedMetadataRevision']:
      raise ValueError('STALE_METADATA_REVISION')
    if (dimension is None or dimension['status']!='Active'
      or dimension['model_role']=='Currency'):
      raise ValueError('HIERARCHY_PATCH_DIMENSION_INVALID')
    if (active is None or not active['sealed']
      or active['version']!=args['expectedHierarchyVersion']
      or active['metadata_revision']!=state['metadata_revision']):
      raise ValueError('HIERARCHY_PATCH_ACTIVE_VERSION_STALE')
    members={row['member_id'] for row in db.execute('''SELECT member_id FROM epm.member
      WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND status='Active' ''',(*keys,args['dimensionId'])).fetchall()}
    rows=db.execute('''SELECT relationship_id,parent_member_id,child_member_id,status
      FROM epm.relationship WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s''',(*keys,args['dimensionId'])).fetchall()
    relationships={row['relationship_id']:dict(row) for row in rows};changed=[]
    endpoints={(row['parent_member_id'],row['child_member_id']):rid
      for rid,row in relationships.items()}
    for change in args['changes']:
      rid=change['relationshipId'];existing=relationships.get(rid)
      if change['action']=='Create':
        if existing is not None:raise ValueError('HIERARCHY_PATCH_RELATIONSHIP_EXISTS')
        if change['parentMemberId'] not in members or change['childMemberId'] not in members:
          raise ValueError('HIERARCHY_PATCH_MEMBER_INVALID')
        pair=(change['parentMemberId'],change['childMemberId'])
        if pair in endpoints:
          raise ValueError('HIERARCHY_PATCH_RELATIONSHIP_EXISTS')
        relationships[rid]={'relationship_id':rid,'parent_member_id':change['parentMemberId'],
          'child_member_id':change['childMemberId'],'status':'Active'}
        endpoints[pair]=rid
      else:
        if existing is None:raise ValueError('HIERARCHY_PATCH_RELATIONSHIP_UNAVAILABLE')
        target='Active' if change['action']=='Activate' else 'Inactive'
        if existing['status']==target:raise ValueError('HIERARCHY_PATCH_STATUS_UNCHANGED')
        existing['status']=target
      changed.append(rid)
    active_edges=sorted((rid,row['parent_member_id'],row['child_member_id'])
      for rid,row in relationships.items() if row['status']=='Active')
    closure=_closure(members,active_edges)
    # Deactivation must not strand current ownership. Activation must not expose
    # a stale typed relationship attribute reference.
    deactivated=[c['relationshipId'] for c in args['changes'] if c['action']=='Deactivate']
    if deactivated and db.execute('''SELECT 1 FROM epm.ownership_value_current
      WHERE workspace_id=%s AND application_id=%s AND present
      AND relationship_id=ANY(%s::text[]) LIMIT 1''',(*keys,deactivated)).fetchone():
      raise ValueError('RELATIONSHIP_HAS_ACTIVE_OWNERSHIP')
    activated=[c['relationshipId'] for c in args['changes'] if c['action'] in ('Create','Activate')]
    if activated and db.execute('''SELECT 1 FROM epm.semantic_column c JOIN epm.relationship r
      ON r.workspace_id=c.workspace_id AND r.application_id=c.application_id
      AND r.dimension_id=c.dimension_id LEFT JOIN epm.member m ON m.workspace_id=r.workspace_id
      AND m.application_id=r.application_id AND m.dimension_id=c.properties->>'referenceDimensionId'
      AND m.member_id=r.custom_values->>('Custom'||lpad(c.slot::text,2,'0')) AND m.status='Active'
      WHERE c.workspace_id=%s AND c.application_id=%s AND c.dimension_id=%s
      AND c.scope='Relationship' AND c.properties->>'valueType'='MemberReference'
      AND r.relationship_id=ANY(%s::text[]) AND r.custom_values ? ('Custom'||lpad(c.slot::text,2,'0'))
      AND m.member_id IS NULL LIMIT 1''',(*keys,args['dimensionId'],activated)).fetchone():
      raise ValueError('SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE')
    closure_rows=[{'ancestorMemberId':a,'descendantMemberId':d,
      'minDepth':depth,'pathCount':count} for (a,d),(depth,count) in sorted(closure.items())]
    prior_paths={(row['ancestor_member_id'],row['descendant_member_id'],
      row['min_depth'],row['path_count']) for row in db.execute('''SELECT ancestor_member_id,
      descendant_member_id,min_depth,path_count FROM epm.hierarchy_closure
      WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND version=%s''',(
      *keys,args['dimensionId'],active['version'])).fetchall()}
    next_paths={(row['ancestorMemberId'],row['descendantMemberId'],
      row['minDepth'],row['pathCount']) for row in closure_rows}
    plan={'dimensionId':args['dimensionId'],'changes':args['changes'],
      'metadataRevision':state['metadata_revision'],'hierarchyVersion':active['version'],
      'membershipSemantics':active['membership_semantics'],
      'nextHierarchyVersion':db.execute('''SELECT coalesce(max(version),0)+1 n FROM epm.hierarchy_version
        WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s''',(*keys,args['dimensionId'])).fetchone()['n'],
      'graphDigest':sha256(_canonical(active_edges)).hexdigest(),
      'closureDigest':sha256(_canonical(closure_rows)).hexdigest(),
      'memberCount':len(members),'edgeCount':len(active_edges),
      'closureCount':len(closure_rows),
      'affectedPathCount':len(prior_paths^next_paths),
      'affectedRelationshipIds':changed}
    return state,plan,closure

  def preview(self,scope,program):
    args=_compile(program,PREVIEW,token=False)
    with connect_postgres(self.dsn,row_factory=dict_row) as db:
      with db.transaction():
        db.execute('SET TRANSACTION READ ONLY');PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=PREVIEW,arguments=args)
        _,plan,_=self._resolve(db,scope,args)
    token=self._token(scope,{'function':APPLY,'plan':plan})
    return {**plan,'previewToken':token}

  def apply(self,scope,program,*,idempotency_key):
    args=_compile(program,APPLY,token=True);token=args.pop('previewToken')
    if not isinstance(idempotency_key,str) or _KEY.fullmatch(idempotency_key) is None:
      raise ValueError('HIERARCHY_PATCH_IDEMPOTENCY_INVALID')
    request_digest=sha256(_canonical(args)).hexdigest();keys=(scope.workspace_id,scope.application_id)
    with connect_postgres(self.dsn,row_factory=dict_row) as db:
      with db.transaction():
        PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        state=db.execute('''SELECT s.metadata_revision,s.commit_revision,s.processing_mode,a.status
          FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
          WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',keys).fetchone()
        PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'admin',function=APPLY,arguments=args)
        prior=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
          WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',(*keys,idempotency_key)).fetchone()
        if prior:
          if prior['command_digest']!=request_digest or prior['actor_id']!=self.identity.subject_id:
            raise ValueError('HIERARCHY_PATCH_IDEMPOTENCY_CONFLICT')
          return prior['result']
        payload=self._unpack(scope,token)
        _,plan,closure=self._resolve(db,scope,args)
        if payload.get('function')!=APPLY or payload.get('plan')!=plan:
          raise ValueError('HIERARCHY_PATCH_PREVIEW_STALE')
        for change in args['changes']:
          if change['action']=='Create':
            db.execute('''INSERT INTO epm.relationship(workspace_id,application_id,
              relationship_id,dimension_id,parent_member_id,child_member_id)
              VALUES(%s,%s,%s,%s,%s,%s)''',(*keys,change['relationshipId'],args['dimensionId'],
              change['parentMemberId'],change['childMemberId']))
          else:
            db.execute('''UPDATE epm.relationship SET status=%s,updated_at=transaction_timestamp()
              WHERE workspace_id=%s AND application_id=%s AND relationship_id=%s''',(
              'Active' if change['action']=='Activate' else 'Inactive',*keys,change['relationshipId']))
        metadata_revision=state['metadata_revision']+1;revision=state['commit_revision']+1
        result={'kind':'hierarchy.build','operation':'relationship.patch',
          'version':plan['nextHierarchyVersion'],'closureCount':len(closure),
          'affectedPathCount':plan['affectedPathCount'],
          'memberCount':plan['memberCount'],'edgeCount':plan['edgeCount'],
          'metadataRevision':metadata_revision,'committedRevision':revision,
          'graphDigest':plan['graphDigest'],'closureDigest':plan['closureDigest'],
          'affectedRelationshipIds':plan['affectedRelationshipIds']}
        db.execute('''UPDATE epm.application_state SET metadata_revision=%s,commit_revision=%s
          WHERE workspace_id=%s AND application_id=%s''',(metadata_revision,revision,*keys))
        db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
          command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
          *keys,idempotency_key,request_digest,self.identity.subject_id,revision,Jsonb(result)))
        version=plan['nextHierarchyVersion']
        db.execute('''INSERT INTO epm.hierarchy_version(workspace_id,application_id,dimension_id,
          version,metadata_revision,operation_id,membership_semantics)
          VALUES(%s,%s,%s,%s,%s,%s,%s)''',(
          *keys,args['dimensionId'],version,metadata_revision,idempotency_key,
          plan['membershipSemantics']))
        with db.cursor() as cursor:
          cursor.executemany('''INSERT INTO epm.hierarchy_closure(workspace_id,application_id,
            dimension_id,version,ancestor_member_id,descendant_member_id,min_depth,path_count)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s)''',[(*keys,args['dimensionId'],version,a,d,depth,count)
              for (a,d),(depth,count) in sorted(closure.items())])
        db.execute('''UPDATE epm.hierarchy_active SET version=%s,activated_at=transaction_timestamp()
          WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s''',(
          version,*keys,args['dimensionId']))
        return result
