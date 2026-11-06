"""Reader-safe CTA journal handoff to structural reconciliation and close."""
import re
from psycopg.rows import dict_row

from .dimensional_security_policy import AccessKind
from .persistence_contract import ApplicationScope,Coordinate
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_cta_bridge import PostgresCtaBridge
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_numeric_store import PostgresNumericFactStore

FUNCTION='consolidation.cta.bridge.close-handoff.read'
_ID=re.compile(r'[0-9a-f]{32}\Z')

def compile_program(program):
 if (not isinstance(program,dict)
  or set(program)!={'languageVersion','function','arguments'}
  or program.get('languageVersion')!=2 or program.get('function')!=FUNCTION
  or not isinstance(program.get('arguments'),dict)
  or set(program['arguments'])!={'bridgeId'}
  or not isinstance(program['arguments']['bridgeId'],str)
  or not _ID.fullmatch(program['arguments']['bridgeId'])):
  raise ValueError('CTA_CLOSE_HANDOFF_PROGRAM_INVALID')
 return {'version':1,'function':FUNCTION,
  'bridgeId':program['arguments']['bridgeId']}

def build_handoff(plan,bridge,record,lines,state,account_dimension):
 if bridge.get('stale'):
  raise ValueError('CTA_CLOSE_HANDOFF_SOURCE_STALE')
 if len(lines)!=2 or sum(row['signed_amount'] for row in lines)!=0:
  raise ValueError('CTA_CLOSE_HANDOFF_JOURNAL_INVALID')
 compiler=record['compiler_version'];currency=record['currency_dimension_id']
 if (not isinstance(account_dimension,str) or not account_dimension
  or compiler not in ('cta-bridge-v2','cta-bridge-v3-typed-unit')
  or any(account_dimension not in row['members'] for row in lines)
  or (compiler=='cta-bridge-v2' and any(
       row['members'].get(currency)!=record['currency_member_id']
       for row in lines))
  or (compiler=='cta-bridge-v3-typed-unit' and any(
       currency in row['members'] for row in lines))):
  raise ValueError('CTA_CLOSE_HANDOFF_GRAIN_INVALID')
 period=record['effective_period'];scope_members={
  period['scenarioDimension']:period['scenarioId'],
  period['yearDimension']:period['yearId'],
  period['periodDimension']:period['periodId']}
 pins={'expectedMetadataRevision':state['metadata_revision'],
   'expectedDataRevision':state['data_revision'],
   'expectedPolicyRevision':state['policy_revision'],
   'expectedCommitRevision':state['commit_revision']}
 source=({'sourceKind':'CtaBridge','bridgeId':plan['bridgeId']}
   if compiler=='cta-bridge-v2' else
   {'sourceKind':'CtaBridgeUnit','bridgeId':plan['bridgeId'],
    'currencyDimensionId':record['currency_dimension_id'],
    'currencyMemberId':record['currency_member_id']})
 terms=[{'sourceIndex':0,'sectionId':f'cta-posted-line-{row["line_ordinal"]}',
   'accountMemberId':row['members'][account_dimension],
   'members':dict(row['members']),'sign':1}
   for row in lines]
 reconciliation={'languageVersion':2,
   'function':'consolidation.statement.reconciliation.preview',
   'arguments':{'equationId':f'cta-bridge-{plan["bridgeId"]}',
    'sources':[source],'terms':terms,**pins}}
 result={'bridgeId':plan['bridgeId'],'bridgeDigest':record['bridge_digest'],
  'committedRevision':record['committed_revision'],
  'currencyUnit':{'dimensionId':record['currency_dimension_id'],
                  'memberId':record['currency_member_id']},
  'closeScopeMembers':scope_members,
  'reconciliationSource':source,
  'reconciliationProgram':reconciliation,
  'postedLines':[{'lineOrdinal':row['line_ordinal'],
   'members':row['members'],'amount':format(row['signed_amount'],'.8f'),
   'sourceRef':row['source_ref']} for row in lines],
  'revisionPins':pins,
  'sourceStatus':{'stale':bridge['stale'],
                  'staleReasons':bridge['staleReasons']},
  'nextFunction':'consolidation.statement.reconciliation.preview',
  'accountingPolicyStatus':'Unreviewed','structuralOnly':True,
  'wholeStatementCertified':False,'effects':'None'}
 if record['compiler_version']=='cta-bridge-v2':
  result['journalId']=record['journal_id']
 else:
  result['typedEffectStore']='cta_bridge_unit_effect'
 return result

class PostgresCtaCloseHandoff:
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
  self.dsn,self.identity=dsn,identity
 def read(self,scope:ApplicationScope,program:dict)->dict:
  plan=compile_program(program);bridge=PostgresCtaBridge(
   self.dsn,identity=self.identity).read(scope,plan['bridgeId'])
  if bridge.get('status')!='Posted':raise ValueError('CTA_CLOSE_HANDOFF_BRIDGE_UNAVAILABLE')
  with connect_postgres(self.dsn,row_factory=dict_row) as db,db.transaction():
   db.execute('SET TRANSACTION READ ONLY');PostgresNumericFactStore._set_scope(db,scope)
   PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=FUNCTION)
   state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,
    commit_revision FROM epm.application_state WHERE workspace_id=%s
    AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
   record=db.execute('''SELECT journal_id,compiler_version,bridge_digest,currency_dimension_id,
    currency_member_id,effective_period,committed_revision FROM epm.cta_bridge
    WHERE workspace_id=%s AND application_id=%s AND bridge_id=%s''',(
    scope.workspace_id,scope.application_id,plan['bridgeId'])).fetchone()
   if not state or not record or record['bridge_digest']!=bridge['bridgeDigest']:
    raise ValueError('CTA_CLOSE_HANDOFF_BRIDGE_UNAVAILABLE')
   if state['commit_revision']!=bridge.get('observedCommitRevision'):
    raise ValueError('CTA_CLOSE_HANDOFF_STALE')
   axes=db.execute('''SELECT dimension_id FROM epm.dimension
    WHERE workspace_id=%s AND application_id=%s AND model_role='Account'
    AND status='Active' ''',(scope.workspace_id,scope.application_id)).fetchall()
   if len(axes)!=1:raise ValueError('CTA_CLOSE_HANDOFF_ACCOUNT_AXIS_REQUIRED')
   if record['compiler_version']=='cta-bridge-v3-typed-unit':
    lines=db.execute('''SELECT e.effect_ordinal AS line_ordinal,
      e.amount AS signed_amount,e.source_ref,c.members
      FROM epm.cta_bridge_unit_effect e JOIN epm.coordinate c USING
        (workspace_id,application_id,coordinate_id)
      WHERE e.workspace_id=%s AND e.application_id=%s AND e.bridge_id=%s
        AND e.currency_dimension_id=%s AND e.currency_member_id=%s
      ORDER BY e.effect_ordinal''',(scope.workspace_id,scope.application_id,
      plan['bridgeId'],record['currency_dimension_id'],
      record['currency_member_id'])).fetchall()
   elif record['compiler_version']=='cta-bridge-v2':
    lines=db.execute('''SELECT l.line_ordinal,l.signed_amount,l.source_ref,
      c.members FROM epm.manual_journal_line l JOIN epm.coordinate c USING
        (workspace_id,application_id,coordinate_id)
      WHERE l.workspace_id=%s AND l.application_id=%s AND l.journal_id=%s
      ORDER BY l.line_ordinal''',(scope.workspace_id,scope.application_id,
      record['journal_id'])).fetchall()
   else:raise ValueError('CTA_CLOSE_HANDOFF_BRIDGE_UNAVAILABLE')
   authorize_coordinates(db,self.identity,scope,tuple(
    Coordinate.from_mapping(row['members']) for row in
    [*bridge.get('sources',()),*lines]),kind=AccessKind.READ)
   after=db.execute('''SELECT metadata_revision,data_revision,policy_revision,
    commit_revision FROM epm.application_state WHERE workspace_id=%s
    AND application_id=%s''',(scope.workspace_id,scope.application_id)).fetchone()
   if after!=state:raise ValueError('CTA_CLOSE_HANDOFF_STALE')
  return build_handoff(plan,bridge,record,lines,state,axes[0]['dimension_id'])
