"""Durable calculated-only publication of an explicit inventory UP schedule."""
from decimal import Decimal
import json,re
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from .consolidation_inventory_unrealized_profit import InventoryUnrealizedProfitSchedule
from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope,Coordinate
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import (PostgresJobQueue,_canonical_digest,
                            _require_python_job_authority)
from .postgres_job_final_fence import finish_published_job
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .postgres_consolidation_full import enforce_consolidation_target_policy
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .current_object_contract import collection_token,is_state_token,new_state_token

REQUEST='consolidation.inventory.unrealized_profit.request'
READ='consolidation.inventory.unrealized_profit.read'
SCHEDULE_SAVE='consolidation.inventory.unrealized.schedule.save'
SCHEDULE_READ='consolidation.inventory.unrealized.schedule.read'
SCHEDULE_LIST='consolidation.inventory.unrealized.schedule.list'
SCHEDULE_ACTIVATE='consolidation.inventory.unrealized.schedule.activate'
SCHEDULE_DEACTIVATE='consolidation.inventory.unrealized.schedule.deactivate'
SCHEDULE_FUNCTIONS=frozenset((SCHEDULE_SAVE,SCHEDULE_READ,SCHEDULE_LIST,
 SCHEDULE_ACTIVATE,SCHEDULE_DEACTIVATE))
COMPILER='inventory-unrealized-profit-v2-typed-unit'
PLAN_DIGEST=_canonical_digest({'function':REQUEST,'version':2,
 'outputs':['Opening','Creation','Release','Closing'],
 'equation':'Opening+Creation+Release=Closing','currency':'typed-unit-not-axis',
 'effects':'calculated-generation-only','accountingPolicyStatus':'Unreviewed'})
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z');_SCHEDULE_ID=re.compile(r'[A-Za-z0-9._-]{1,200}\Z');_JOB=re.compile(r'[0-9a-f]{32}\Z')
_ROLES=('Opening','Creation','Release','Closing')

def schedule_catalog():
 mutation={'mode':'atomic_configuration','permission':'admin','previewRequired':False,
  'idempotencyRequired':True,'workClass':'short'}
 read={'mode':'read_only','permission':'read','previewRequired':False,
  'idempotencyRequired':False,'workClass':'short'}
 return {
  SCHEDULE_SAVE:{**mutation,'arguments':{'definition':'current schedule definition','expectedStateToken':'null for create; current token for replace'},'result':'saved current schedule'},
  SCHEDULE_ACTIVATE:{**mutation,'arguments':{'scheduleId':'ID','expectedStateToken':'current token','definitionDigest':'current digest','expectedPolicyRevision':'current'},'result':'active current schedule'},
  SCHEDULE_DEACTIVATE:{**mutation,'arguments':{'scheduleId':'ID','expectedStateToken':'current token','definitionDigest':'current digest','expectedPolicyRevision':'current'},'result':'saved current schedule'},
  SCHEDULE_READ:{**read,'arguments':{'scheduleId':'ID'},'result':'current schedule'},
  SCHEDULE_LIST:{**read,'arguments':{'limit':'1-100','afterScheduleId':'keyset','collectionToken':'optional continuation fence'},'result':'authorized current schedule page'}}

def _schedule_program(program):
 if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
  or type(program.get('languageVersion')) is not int or program['languageVersion']!=2
  or program.get('function') not in SCHEDULE_FUNCTIONS
  or not isinstance(program.get('arguments'),dict)):
  raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_PROGRAM_INVALID')
 return program['function'],program['arguments']

def _schedule_source_pins_current(schedule,state):
 return ((schedule.expected_metadata_revision,schedule.expected_data_revision,
          schedule.expected_policy_revision)==
         (state['metadata_revision'],state['data_revision'],
          state['policy_revision']))

def _schedule_change_source_allowed(schedule,state,*,deactivate):
 return deactivate or _schedule_source_pins_current(schedule,state)

class PostgresInventoryUnrealizedSchedules:
 """One current schedule per stable ID, consumed by the publication kernel."""
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
  self.dsn,self.identity=dsn,identity
 @staticmethod
 def _target(schedule_id):
  if not isinstance(schedule_id,str) or not _SCHEDULE_ID.fullmatch(schedule_id):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_TARGET_INVALID')
 def _prepare(self,db,scope,function,permission='admin'):
  PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
  PostgresAccessChecker.check_in_transaction(db,self.identity,scope,permission,function=function)
  row=db.execute('''SELECT a.status,s.processing_mode,s.metadata_revision,
   s.data_revision,s.policy_revision,s.commit_revision
   FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
   WHERE s.workspace_id=%s AND s.application_id=%s FOR UPDATE OF s''',
   (scope.workspace_id,scope.application_id)).fetchone()
  if not row or row['status']!='Active' or row['processing_mode']!='Active':
   raise ValueError('APPLICATION_NOT_WRITABLE')
  return row
 @staticmethod
 def _verify(row):
  if not row:raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_UNAVAILABLE')
  parsed=InventoryUnrealizedProfitSchedule.parse(row['definition'])
  if (parsed.schedule_id!=row['schedule_id']
   or parsed.effective_on!=row['effective_on'] or parsed.digest!=row['definition_digest']
   or not is_state_token(row['state_token']) or row['status'] not in ('Saved','Active')):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_STORAGE_INVALID')
  return parsed
 @staticmethod
 def _current_result(parsed,row,*,definition=False):
  result={'scheduleId':parsed.schedule_id,'stateToken':row['state_token'],
   'effectiveOn':parsed.effective_on.isoformat(),'definitionDigest':parsed.digest,
   'status':row['status'],'operationId':row['operation_id']}
  if definition:result['definition']=parsed.normalized()
  return result
 @staticmethod
 def _mutation(function,args,scope,identity,key):
  return {'scope':[scope.workspace_id,scope.application_id],
   'actor':[identity.issuer,identity.subject_id],'function':function,
   'arguments':args,'idempotencyKey':key}
 @staticmethod
 def _key(value):
  if not isinstance(value,str) or not _KEY.fullmatch(value):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_REQUEST_KEY_INVALID')
 def _prior(self,db,scope,key,digest):
  row=db.execute('''SELECT command_digest,actor_id,result FROM epm.operation_receipt
   WHERE workspace_id=%s AND application_id=%s AND operation_id=%s''',
   (scope.workspace_id,scope.application_id,key)).fetchone()
  if row and (row['command_digest']!=digest or row['actor_id']!=self.identity.subject_id):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_IDEMPOTENCY_CONFLICT')
  return row['result'] if row else None
 def save(self,scope,definition,*,expected_state_token,idempotency_key):
  parsed=InventoryUnrealizedProfitSchedule.parse(definition);self._key(idempotency_key)
  if expected_state_token is not None and not is_state_token(expected_state_token):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_SAVE_ARGUMENTS_INVALID')
  normalized=parsed.normalized();args={'definition':normalized,
   'expectedStateToken':expected_state_token}
  digest=_canonical_digest(self._mutation(SCHEDULE_SAVE,args,scope,self.identity,idempotency_key))
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   app=self._prepare(db,scope,SCHEDULE_SAVE)
   prior=self._prior(db,scope,idempotency_key,digest)
   if prior is not None:return prior
   if not _schedule_source_pins_current(parsed,app):
    raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_SOURCE_STALE')
   current=db.execute('''SELECT * FROM epm.inventory_unrealized_schedule_definition
    WHERE workspace_id=%s AND application_id=%s
    AND schedule_id=%s FOR UPDATE''',
    (scope.workspace_id,scope.application_id,parsed.schedule_id)).fetchone()
   if ((current is None) != (expected_state_token is None)
    or current is not None and current['state_token']!=expected_state_token):
    raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_STATE_STALE')
   revision=app['commit_revision']+1;token=new_state_token()
   row=db.execute('''INSERT INTO epm.inventory_unrealized_schedule_definition(
    workspace_id,application_id,schedule_id,state_token,status,effective_on,definition,
    definition_digest,operation_id) VALUES(%s,%s,%s,%s,'Saved',%s,%s,%s,%s)
    ON CONFLICT(workspace_id,application_id,schedule_id) DO UPDATE SET
     state_token=EXCLUDED.state_token,status='Saved',effective_on=EXCLUDED.effective_on,
     definition=EXCLUDED.definition,definition_digest=EXCLUDED.definition_digest,
     operation_id=EXCLUDED.operation_id,
     updated_at=transaction_timestamp()
    RETURNING *''',(scope.workspace_id,scope.application_id,parsed.schedule_id,token,
     parsed.effective_on,Jsonb(normalized),parsed.digest,idempotency_key)).fetchone()
   db.execute('''UPDATE epm.application_state SET commit_revision=%s WHERE
    workspace_id=%s AND application_id=%s''',(revision,scope.workspace_id,scope.application_id))
   result={**self._current_result(self._verify(row),row),'policyRevision':app['policy_revision']}
   db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
    operation_id,command_digest,actor_id,committed_revision,result)
    VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,
    idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
   return result
 def change(self,scope,*,schedule_id,expected_state_token,definition_digest,
            expected_policy_revision,idempotency_key,deactivate):
  self._target(schedule_id);self._key(idempotency_key)
  if (not is_state_token(expected_state_token)
   or not isinstance(definition_digest,str) or not re.fullmatch(r'[0-9a-f]{64}',definition_digest)
   or type(expected_policy_revision) is not int or expected_policy_revision<0):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_CHANGE_ARGUMENTS_INVALID')
  function=SCHEDULE_DEACTIVATE if deactivate else SCHEDULE_ACTIVATE
  args={'scheduleId':schedule_id,'expectedStateToken':expected_state_token,
   'definitionDigest':definition_digest,
   'expectedPolicyRevision':expected_policy_revision}
  digest=_canonical_digest(self._mutation(function,args,scope,self.identity,idempotency_key))
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   app=self._prepare(db,scope,function)
   prior=self._prior(db,scope,idempotency_key,digest)
   if prior is not None:return prior
   if app['policy_revision']!=expected_policy_revision:
    raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_POLICY_STALE')
   row=db.execute('''SELECT * FROM epm.inventory_unrealized_schedule_definition
    WHERE workspace_id=%s AND application_id=%s
    AND schedule_id=%s FOR UPDATE''',(scope.workspace_id,scope.application_id,schedule_id)).fetchone()
   if not row:raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_UNAVAILABLE')
   if row['state_token']!=expected_state_token or row['definition_digest']!=definition_digest:
    raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_STATE_STALE')
   parsed=self._verify(row)
   # Revocation is a safety operation and must remain possible after the
   # immutable source pins become stale.  Activation still proves every pin.
   if not _schedule_change_source_allowed(parsed,app,deactivate=deactivate):
    raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_SOURCE_STALE')
   if deactivate:
    if row['status']!='Active':raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_ACTIVE_MISMATCH')
    status='Saved'
   else:
    if row['status']=='Active':raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_ALREADY_ACTIVE')
    status='Active'
   revision=app['commit_revision']+1;token=new_state_token()
   row=db.execute('''UPDATE epm.inventory_unrealized_schedule_definition SET
    status=%s,state_token=%s,operation_id=%s,
    updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s
    AND schedule_id=%s RETURNING *''',(status,token,idempotency_key,
    scope.workspace_id,scope.application_id,schedule_id)).fetchone()
   db.execute('''UPDATE epm.application_state SET commit_revision=%s WHERE
    workspace_id=%s AND application_id=%s''',(revision,scope.workspace_id,scope.application_id))
   result={**self._current_result(parsed,row),'policyRevision':app['policy_revision']}
   db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,
    operation_id,command_digest,actor_id,committed_revision,result)
    VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,
    idempotency_key,digest,self.identity.subject_id,revision,Jsonb(result)))
   return result
 def read(self,scope,schedule_id):
  self._target(schedule_id)
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   db.execute('SET TRANSACTION READ ONLY');PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=SCHEDULE_READ)
   row=db.execute('''SELECT * FROM epm.inventory_unrealized_schedule_definition
    WHERE workspace_id=%s AND application_id=%s
    AND schedule_id=%s''',(scope.workspace_id,scope.application_id,schedule_id)).fetchone()
   return self._current_result(self._verify(row),row,definition=True)
 def list(self,scope,*,limit=100,after_schedule_id=None,expected_collection_token=None):
  if (type(limit) is not int or not 1<=limit<=100
   or after_schedule_id is not None and (not isinstance(after_schedule_id,str)
    or not _SCHEDULE_ID.fullmatch(after_schedule_id))):
   raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_LIST_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   db.execute('SET TRANSACTION READ ONLY');PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=SCHEDULE_LIST)
   all_rows=db.execute('''SELECT * FROM epm.inventory_unrealized_schedule_definition
    WHERE workspace_id=%s AND application_id=%s ORDER BY schedule_id''',
    (scope.workspace_id,scope.application_id)).fetchall()
   token=collection_token((row['schedule_id'],row['state_token']) for row in all_rows)
   if expected_collection_token is not None and expected_collection_token!=token:
    raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_COLLECTION_STALE')
   rows=db.execute('''SELECT * FROM epm.inventory_unrealized_schedule_definition
    WHERE workspace_id=%s AND application_id=%s AND
    (%s::text IS NULL OR schedule_id>%s) ORDER BY schedule_id LIMIT %s''',
    (scope.workspace_id,scope.application_id,after_schedule_id,after_schedule_id,limit+1)).fetchall()
   values=[self._current_result(self._verify(row),row,definition=True) for row in rows[:limit]]
   return {'schedules':values,'collectionToken':token,
    'nextCursor':values[-1]['scheduleId'] if len(rows)>limit else None}
 def execute_program(self,scope,program,*,idempotency_key=None):
  function,args=_schedule_program(program)
  if function==SCHEDULE_SAVE and set(args)=={'definition','expectedStateToken'} and idempotency_key is not None:
   return self.save(scope,args['definition'],expected_state_token=args['expectedStateToken'],idempotency_key=idempotency_key)
  if function in (SCHEDULE_ACTIVATE,SCHEDULE_DEACTIVATE) and set(args)=={
   'scheduleId','expectedStateToken','definitionDigest','expectedPolicyRevision'} and idempotency_key is not None:
   return self.change(scope,schedule_id=args['scheduleId'],expected_state_token=args['expectedStateToken'],
    definition_digest=args['definitionDigest'],expected_policy_revision=args['expectedPolicyRevision'],
    idempotency_key=idempotency_key,deactivate=function==SCHEDULE_DEACTIVATE)
  raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_WRITE_INVALID')
 def read_program(self,scope,program):
  function,args=_schedule_program(program)
  if function==SCHEDULE_READ and set(args)=={'scheduleId'}:
   return self.read(scope,args['scheduleId'])
  if function==SCHEDULE_LIST and not set(args)-{'limit','afterScheduleId','collectionToken'}:
   return self.list(scope,limit=args.get('limit',100),after_schedule_id=args.get('afterScheduleId'),
    expected_collection_token=args.get('collectionToken'))
  raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_READ_INVALID')

def compile_publication(raw,expected_publication_revision=None):
 if (not isinstance(raw,dict) or raw.get('languageVersion')!=2 or raw.get('function')!=REQUEST
  or set(raw)!={'languageVersion','function','arguments'} or not isinstance(raw.get('arguments'),dict)):
  raise ValueError('INVENTORY_UNREALIZED_PUBLICATION_PROGRAM_INVALID')
 a=raw['arguments'];required={'definition','targetMembers','resultKey','expectedPublicationRevision'}
 if (set(a)!=required or not isinstance(a['resultKey'],str) or not _KEY.fullmatch(a['resultKey'])
  or type(a['expectedPublicationRevision']) is not int or a['expectedPublicationRevision']<0
  or expected_publication_revision is not None and a['expectedPublicationRevision']!=expected_publication_revision
  or not isinstance(a['targetMembers'],dict) or set(a['targetMembers'])!=set(_ROLES)):
  raise ValueError('INVENTORY_UNREALIZED_PUBLICATION_ARGUMENTS_INVALID')
 schedule=InventoryUnrealizedProfitSchedule.parse(a['definition'])
 targets={role:dict(Coordinate.from_mapping(a['targetMembers'][role]).members) for role in _ROLES}
 if len({Coordinate.from_mapping(v).series_key for v in targets.values()})!=4:
  raise ValueError('INVENTORY_UNREALIZED_TARGET_AMBIGUOUS')
 doc={'version':2,'function':REQUEST,'definition':schedule.normalized(),
  'targetMembers':targets,'resultKey':a['resultKey'],
  'expectedPublicationRevision':a['expectedPublicationRevision'],
  'accountingPolicyStatus':'Unreviewed','effects':'calculated-generation-only'}
 return doc

def decode_publication(doc):
 if not isinstance(doc,dict) or doc.get('version')!=2:raise ValueError('UNSUPPORTED_INVENTORY_UNREALIZED_JOB')
 plan=compile_publication({'languageVersion':2,'function':REQUEST,'arguments':{
  'definition':doc.get('definition'),'targetMembers':doc.get('targetMembers'),
  'resultKey':doc.get('resultKey'),'expectedPublicationRevision':doc.get('expectedPublicationRevision')}})
 if plan!=doc:raise ValueError('NONCANONICAL_INVENTORY_UNREALIZED_JOB')
 return plan

def _candidate(db,scope,doc,*,lock=False):
 schedule=InventoryUnrealizedProfitSchedule.parse(doc['definition']);keys=(scope.workspace_id,scope.application_id)
 state=db.execute('''SELECT s.*,a.status application_status FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id) WHERE s.workspace_id=%s AND s.application_id=%s''' + (' FOR UPDATE OF s' if lock else ''),keys).fetchone()
 if (not state or state['application_status']!='Active' or state['processing_mode']!='Active'
  or (state['metadata_revision'],state['data_revision'],state['policy_revision'])!=(schedule.expected_metadata_revision,schedule.expected_data_revision,schedule.expected_policy_revision)):
  raise ValueError('INVENTORY_UNREALIZED_SOURCE_REVISION_STALE')
 schedule_row=db.execute('''SELECT state_token,status,definition,definition_digest
  FROM epm.inventory_unrealized_schedule_definition
  WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s''',
  (*keys,schedule.schedule_id)).fetchone()
 if (not schedule_row or schedule_row['status']!='Active'
  or schedule_row['definition']!=schedule.normalized()
  or schedule_row['definition_digest']!=schedule.digest):
  raise ValueError('INVENTORY_UNREALIZED_SCHEDULE_NOT_CURRENT')
 roles=db.execute("""SELECT model_role,dimension_id FROM epm.dimension WHERE workspace_id=%s AND application_id=%s AND status='Active' ORDER BY dimension_id""",keys).fetchall()
 selected=[r for r in roles if r['model_role'] in ('Account','Movement','Entity','Currency')]
 if len({r['model_role'] for r in selected})!=len(selected):raise ValueError('INVENTORY_UNREALIZED_ROLE_AMBIGUOUS')
 active={r['dimension_id'] for r in roles};by={r['model_role']:r['dimension_id'] for r in selected}
 if set(('Account','Entity','Currency'))-set(by) or by['Currency']!=schedule.currency_dimension_id:raise ValueError('INVENTORY_UNREALIZED_ROLE_REQUIRED')
 axes=active-{by['Currency']};vary={by['Account']}|({by['Movement']} if 'Movement' in by else set())
 points={k:Coordinate.from_mapping(v) for k,v in doc['targetMembers'].items()}
 for point in points.values():PostgresSourceBatch._check_scope_members(db,scope,dict(point.members))
 source_members=[dict(p.members) for p in schedule.pins]
 if any(set(v)!=axes for v in [*doc['targetMembers'].values(),*source_members]):raise ValueError('INVENTORY_UNREALIZED_FULL_GRAIN_REQUIRED')
 baseline={a:m for a,m in doc['targetMembers']['Opening'].items() if a not in vary}
 if any({a:m for a,m in v.items() if a not in vary}!=baseline for v in [*doc['targetMembers'].values(),*source_members]):raise ValueError('INVENTORY_UNREALIZED_CONTEXT_MISMATCH')
 currency=db.execute('''SELECT entity_default_currency_member_id currency FROM epm.member WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s AND member_id=%s AND status='Active' ''',(*keys,by['Entity'],baseline[by['Entity']])).fetchone()
 if not currency or currency['currency']!=schedule.currency_member_id:raise ValueError('INVENTORY_UNREALIZED_FUNCTIONAL_CURRENCY_MISMATCH')
 values={};lineage=[]
 for pin in schedule.pins:
  PostgresSourceBatch._check_scope_members(db,scope,dict(pin.members));point=Coordinate.from_mapping(dict(pin.members))
  row=db.execute('''SELECT c.members,n.amount,n.change_id,n.last_revision FROM epm.coordinate c JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s AND n.present''',(*keys,point.series_key)).fetchone()
  if not row or row['members']!=dict(pin.members) or row['change_id']!=pin.change_id:raise ValueError('INVENTORY_UNREALIZED_SOURCE_STALE')
  values[pin.change_id]=format(row['amount'],'f');lineage.append({'members':row['members'],'changeId':row['change_id'],'lastRevision':row['last_revision'],'amount':format(row['amount'],'.8f')})
 calc=schedule.calculate(values);calc['functionalCurrencyContext']={'entity':{'dimensionId':by['Entity'],'memberId':baseline[by['Entity']]}}
 amounts={'Opening':calc['sourcePins'] and values[schedule.prior_unrealized_profit.change_id],'Creation':calc['creationCandidate'],'Release':format(-Decimal(calc['releaseCandidate']),'.8f'),'Closing':calc['closingDeferredProfitCandidate']}
 if Decimal(amounts['Opening'])+Decimal(amounts['Creation'])+Decimal(amounts['Release'])!=Decimal(amounts['Closing']):raise ValueError('INVENTORY_UNREALIZED_RECONCILIATION_FAILED')
 evidence=[{'kind':'InventoryUnrealizedProfit','scheduleDigest':schedule.digest,'sources':lineage,'currency':calc['currency'],'equation':'Opening+Creation+Release=Closing'}]
 encoded=json.dumps(evidence,sort_keys=True,ensure_ascii=True).encode('ascii')
 if len(encoded)>65536:raise ValueError('INVENTORY_UNREALIZED_LINEAGE_LIMIT')
 return state,schedule,points,amounts,evidence,calc,schedule_row['state_token']

def _candidate_identity(candidate):
 _,schedule,points,amounts,evidence,calc,state_token=candidate
 return {'schedule':schedule.normalized(),
  'scheduleStateToken':state_token,
  'points':{role:dict(point.members) for role,point in points.items()},
  'amounts':amounts,'evidence':evidence,'calculation':calc}

def enforce_inventory_unrealized_dimensional_security(db,identity,scope,candidate):
 _,schedule,points,_,_,_,_=candidate
 sources=tuple(Coordinate.from_mapping(dict(pin.members))
               for pin in schedule.pins)
 if not sources or set(points)!=set(_ROLES):
  raise ValueError('INVENTORY_UNREALIZED_SECURITY_COORDINATES_INVALID')
 authorize_coordinates(db,identity,scope,sources,kind=AccessKind.READ)
 authorize_coordinates(db,identity,scope,
  tuple(points[role] for role in _ROLES),kind=AccessKind.WRITE)

def source_status(db,scope,result):
 try:
  lineage=result['sourceLookupLineage'][0]['sources'];pins=result['revisionPins']
  schedule_id=result['scheduleId'];schedule_state_token=result['scheduleStateToken']
  schedule_digest=result['scheduleDigest'];entity=result['functionalCurrencyContext']['entity']
  currency=result['outputUnit']
  if (not isinstance(lineage,list) or not lineage
   or not isinstance(pins,dict) or set(pins)!={'metadata','data','policy'}
   or any(type(pins[key]) is not int or pins[key]<0 for key in pins)
   or not isinstance(schedule_id,str) or not _SCHEDULE_ID.fullmatch(schedule_id)
   or not is_state_token(schedule_state_token)
   or not isinstance(schedule_digest,str) or not re.fullmatch(r'[0-9a-f]{64}',schedule_digest)
   or not isinstance(entity,dict) or set(entity)!={'dimensionId','memberId'}
   or any(not isinstance(entity[key],str) for key in entity)
   or not isinstance(currency,dict) or set(currency)!={'dimensionId','memberId'}
   or any(not isinstance(currency[key],str) for key in currency)
   or any(not isinstance(item,dict) or not isinstance(item.get('members'),dict)
    or not isinstance(item.get('changeId'),str) for item in lineage)):
   return {'matchesAtRead':False}
 except (KeyError,TypeError,IndexError):return {'matchesAtRead':False}
 state=db.execute('''SELECT metadata_revision,data_revision,policy_revision
  FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
  (scope.workspace_id,scope.application_id)).fetchone()
 schedule=db.execute('''SELECT state_token,status,definition_digest
  FROM epm.inventory_unrealized_schedule_definition
  WHERE workspace_id=%s AND application_id=%s AND schedule_id=%s''',
  (scope.workspace_id,scope.application_id,schedule_id)).fetchone()
 functional=db.execute('''SELECT entity_default_currency_member_id currency
  FROM epm.member WHERE workspace_id=%s AND application_id=%s
   AND dimension_id=%s AND member_id=%s AND status='Active' ''',
  (scope.workspace_id,scope.application_id,entity['dimensionId'],entity['memberId'])).fetchone()
 current=bool(state and schedule and functional
  and (state['metadata_revision'],state['data_revision'],state['policy_revision'])==
      (pins['metadata'],pins['data'],pins['policy'])
  and schedule['status']=='Active' and schedule['state_token']==schedule_state_token
  and schedule['definition_digest']==schedule_digest
  and functional['currency']==currency['memberId'])
 for item in lineage:
  try:point=Coordinate.from_mapping(item['members'])
  except (TypeError,ValueError):return {'matchesAtRead':False}
  row=db.execute('''SELECT c.members,n.change_id,n.present FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s''',(scope.workspace_id,scope.application_id,point.series_key)).fetchone()
  current &= bool(row and row['present'] and row['members']==item['members'] and row['change_id']==item['changeId'])
 return {'matchesAtRead':current,'sourceCount':len(lineage),
  'revisionPinsMatch':bool(state and (state['metadata_revision'],state['data_revision'],state['policy_revision'])==(pins['metadata'],pins['data'],pins['policy'])),
  'scheduleCurrent':bool(schedule and schedule['status']=='Active'
   and schedule['state_token']==schedule_state_token and schedule['definition_digest']==schedule_digest),
  'functionalCurrencyCurrent':bool(functional and functional['currency']==currency['memberId'])}

class PostgresInventoryUnrealizedPublication:
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
  self.dsn,self.identity=dsn,identity
 def inspect(self,scope,program):
  doc=compile_publication(program)
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write',function=REQUEST)
   state,schedule,points,amounts,evidence,calc,_=_candidate(db,scope,doc)
   enforce_inventory_unrealized_dimensional_security(
    db,self.identity,scope,(state,schedule,points,amounts,evidence,calc))
   pointer=db.execute('SELECT committed_revision AS published_revision FROM epm.calculation_result_state WHERE workspace_id=%s AND application_id=%s AND result_key=%s',(scope.workspace_id,scope.application_id,doc['resultKey'])).fetchone()
   if (pointer['published_revision'] if pointer else 0)!=doc['expectedPublicationRevision']:raise ValueError('STALE_INVENTORY_UNREALIZED_POINTER')
  return doc,{'amounts':amounts,'sourceLookupLineage':evidence,'schedule':calc},state
 def admit(self,scope,program,*,idempotency_key):
  doc,_,state=self.inspect(scope,program)
  return PostgresJobQueue(self.dsn,identity=self.identity).submit(scope,idempotency_key=idempotency_key,function_name=REQUEST,normalized_program=doc,compiler_version=COMPILER,plan_digest=PLAN_DIGEST,expected_metadata_revision=state['metadata_revision'],expected_data_revision=state['data_revision'],expected_policy_revision=state['policy_revision'],resource_class='short',authorization_function=REQUEST)
 def publish(self,claim):
  if (not isinstance(claim,dict)
   or not isinstance(claim.get('workspace_id'),str)
   or not isinstance(claim.get('application_id'),str)
   or not isinstance(claim.get('job_id'),str)
   or not _JOB.fullmatch(claim['job_id'])
   or not isinstance(claim.get('claimant'),str)
   or type(claim.get('claim_generation')) is not int):
   raise ValueError('INVALID_WORKER_CLAIM')
  scope=ApplicationScope(claim['workspace_id'],claim['application_id']);keys=(scope.workspace_id,scope.application_id)
  with connect_postgres(self.dsn,row_factory=dict_row) as before,before.transaction():
   PostgresNumericFactStore._set_scope(before,scope)
   initial_access=PostgresAccessChecker.check_in_transaction(before,
    self.identity,scope,'write',function=REQUEST)
   job=before.execute('''SELECT *,lease_until>clock_timestamp() unexpired
    FROM epm.job WHERE workspace_id=%s AND application_id=%s
    AND job_id=%s''',(*keys,claim['job_id'])).fetchone()
   receipt=before.execute('''SELECT command_digest,actor_id,result
    FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
    AND operation_id=%s''',(*keys,claim['job_id'])).fetchone()
   if receipt:
    if (not job or receipt['command_digest']!=job['program_digest']
     or receipt['actor_id']!=job['subject_id']):
     raise ValueError('INVENTORY_UNREALIZED_RECEIPT_CONFLICT')
    return receipt['result']
   if (not job or job['issuer']!=self.identity.issuer
    or job['subject_id']!=self.identity.subject_id):
    raise ValueError('INVENTORY_UNREALIZED_JOB_UNAVAILABLE')
   if (job['status']!='running'
    or job['claim_generation']!=claim['claim_generation']
    or job['claimant']!=claim['claimant'] or not job['unexpired']):
    raise ValueError('STALE_WORKER_FENCE')
   _require_python_job_authority(before,scope,job)
   if job['function_name']!=REQUEST:
    raise ValueError('UNSUPPORTED_INVENTORY_UNREALIZED_JOB')
   doc=decode_publication(job['normalized_program'])
   if (job['compiler_version']!=COMPILER or job['plan_digest']!=PLAN_DIGEST
    or job['program_digest']!=_canonical_digest(doc)):
    raise ValueError('UNSUPPORTED_INVENTORY_UNREALIZED_JOB')
   initial_candidate=_candidate(before,scope,doc)
   enforce_inventory_unrealized_dimensional_security(
    before,self.identity,scope,initial_candidate)
   state,schedule,points,amounts,evidence,calc,schedule_state_token=initial_candidate
   if any(job['expected_'+kind+'_revision']!=state[kind+'_revision']
          for kind in ('metadata','data','policy')):
    raise ValueError('STALE_JOB_INPUT_REVISION')
   pointer=before.execute('''SELECT committed_revision AS published_revision
    FROM epm.calculation_result_state WHERE workspace_id=%s
    AND application_id=%s AND result_key=%s''',(*keys,
    doc['resultKey'])).fetchone()
   if (pointer['published_revision'] if pointer else 0)!=doc['expectedPublicationRevision']:
    raise ValueError('STALE_INVENTORY_UNREALIZED_POINTER')
   for point in points.values():
    enforce_consolidation_target_policy(before,scope,point,
                                        initial_access.role)
  initial_job=job;initial_identity=_candidate_identity(initial_candidate)
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
   # Acquire the application publication row before capability authorization.
   # The latter takes a shared state-row lock, so checking first would let two
   # publishers both hold FOR SHARE and then deadlock while upgrading here.
   # The workspace fence already prevents authority/capability mutation; the
   # current identity is still rechecked before any effect is written.
   final_candidate=_candidate(db,scope,doc,lock=True)
   enforce_inventory_unrealized_dimensional_security(
    db,self.identity,scope,final_candidate)
   state,schedule,points,amounts,evidence,calc,schedule_state_token=final_candidate
   access=PostgresAccessChecker.check_in_transaction(
    db,self.identity,scope,'write',function=REQUEST)
   job=db.execute('''SELECT * FROM epm.job WHERE workspace_id=%s
    AND application_id=%s AND job_id=%s FOR UPDATE''',
    (*keys,claim['job_id'])).fetchone()
   receipt=db.execute('''SELECT command_digest,actor_id,result
    FROM epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
    AND operation_id=%s''',(*keys,claim['job_id'])).fetchone()
   if receipt:
    if (not job or receipt['command_digest']!=job['program_digest']
     or receipt['actor_id']!=job['subject_id']):
     raise ValueError('INVENTORY_UNREALIZED_RECEIPT_CONFLICT')
    return receipt['result']
   immutable=('issuer','subject_id','function_name','normalized_program',
    'program_digest','compiler_version','plan_digest',
    'expected_metadata_revision','expected_data_revision',
    'expected_policy_revision')
   if not job or any(job[key]!=initial_job[key] for key in immutable):
    raise ValueError('STALE_WORKER_FENCE')
   unexpired=db.execute('SELECT %s::timestamptz>clock_timestamp() ok',
    (job['lease_until'],)).fetchone()['ok']
   if (job['status']!='running'
    or job['claim_generation']!=claim['claim_generation']
    or job['claimant']!=claim['claimant'] or not unexpired):
    raise ValueError('STALE_WORKER_FENCE')
   _require_python_job_authority(db,scope,job)
   if (job['function_name']!=REQUEST or job['compiler_version']!=COMPILER
    or job['plan_digest']!=PLAN_DIGEST
    or job['program_digest']!=_canonical_digest(doc)):
    raise ValueError('UNSUPPORTED_INVENTORY_UNREALIZED_JOB')
   if any(job['expected_'+kind+'_revision']!=state[kind+'_revision']
          for kind in ('metadata','data','policy')):
    raise ValueError('STALE_JOB_INPUT_REVISION')
   if _candidate_identity(final_candidate)!=initial_identity:
    raise ValueError('STALE_INVENTORY_UNREALIZED_CANDIDATE')
   pointer=db.execute('''SELECT committed_revision AS published_revision
    FROM epm.calculation_result_state WHERE workspace_id=%s
    AND application_id=%s AND result_key=%s''',(*keys,
    doc['resultKey'])).fetchone()
   if (pointer['published_revision'] if pointer else 0)!=doc['expectedPublicationRevision']:
    raise ValueError('STALE_INVENTORY_UNREALIZED_POINTER')
   for point in points.values():
    enforce_consolidation_target_policy(db,scope,point,access.role)
   revision=state['commit_revision']+1;digest=_canonical_digest(evidence);generation=claim['job_id'];unit=(schedule.currency_dimension_id,schedule.currency_member_id)
   db.execute('''INSERT INTO epm.calculation_operation_staging(workspace_id,application_id,generation_id,job_id,result_key,source_commit_revision,source_metadata_revision,source_policy_revision,function_name,factor,row_count,published_revision) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,4,%s)''',(*keys,generation,generation,doc['resultKey'],state['commit_revision'],state['metadata_revision'],state['policy_revision'],REQUEST,revision))
   rows=[]
   for role in _ROLES:
    cid=PostgresNumericFactStore._coordinate_id(db,scope,points[role]);amount=Decimal(amounts[role]);rows.append({'role':role,'members':dict(points[role].members),'amount':format(amount,'.8f')})
    db.execute('''INSERT INTO epm.calculation_unit_result_staging(workspace_id,application_id,generation_id,coordinate_id,output_unit_currency_dimension_id,output_unit_currency_member_id,source_amount,source_change_id,source_evidence_digest,amount,rate_strategy,rate_numerator,rate_denominator,rate_sources,source_lookup_lineage) VALUES(%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,'identity-same-currency',1,1,%s,%s)''',(*keys,generation,cid,*unit,Decimal(calc['transferMargin']),digest,amount,Jsonb([{'kind':'Identity','currency':{'dimensionId':unit[0],'memberId':unit[1]}}]),Jsonb(evidence)))
   result={'function':REQUEST,'compilerVersion':COMPILER,'generationId':generation,'resultKey':doc['resultKey'],'publishedRevision':revision,'committedRevision':revision,'rows':rows,'outputUnit':{'dimensionId':unit[0],'memberId':unit[1]},'sourceLookupLineage':evidence,'sourceEvidenceDigest':digest,'scheduleId':schedule.schedule_id,'scheduleStateToken':schedule_state_token,'scheduleDigest':schedule.digest,'revisionPins':{'metadata':state['metadata_revision'],'data':state['data_revision'],'policy':state['policy_revision']},'functionalCurrencyContext':calc['functionalCurrencyContext'],'accountingPolicyStatus':'Unreviewed','wholeStatementCertified':False,'effects':'CalculatedGenerationOnly'}
   from .postgres_calculation_impact import calculation_publication_impact,record_calculation_impact
   impact=calculation_publication_impact(operation_id=generation,causal_revision=revision,result_key=doc['resultKey'],existed=pointer is not None);result['impactDigest']=impact.digest
   from .postgres_current_result_publication import advance_result_head_during_conversion
   advance_result_head_during_conversion(db,scope,result_key=doc['resultKey'],operation_id=generation,committed_revision=revision);db.execute('UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s',(revision,*keys));db.execute('INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)',(*keys,generation,job['program_digest'],job['subject_id'],revision,Jsonb(result)));record_calculation_impact(db,scope,operation_id=generation,impact=impact);finish_published_job(db,scope,claim,revision=revision,result=result);return result
 def read(self,scope,result_key):
  if not isinstance(result_key,str) or not _KEY.fullmatch(result_key):raise ValueError('INVENTORY_UNREALIZED_RESULT_KEY_INVALID')
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=READ)
   row=db.execute('''SELECT p.source_operation_id AS generation_id,p.committed_revision AS published_revision,j.result FROM epm.calculation_result_state p JOIN epm.job j ON j.workspace_id=p.workspace_id AND j.application_id=p.application_id AND j.job_id=p.source_operation_id WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s AND p.source_function=%s''',(scope.workspace_id,scope.application_id,result_key,REQUEST)).fetchone()
   if not row:raise ValueError('INVENTORY_UNREALIZED_RESULT_UNAVAILABLE')
   current=source_status(db,scope,row['result'])
   return {**row['result'],'currentSourceStatus':current,
           'stale':not current['matchesAtRead']}
