"""Authorized exact preview for a bounded structural statement pack."""
from psycopg.rows import dict_row
from .consolidation_statement_pack import compile_pack,reconcile_pack
from .persistence_contract import ApplicationScope,Coordinate
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_calculation_status import published_result_status
from .postgres_consolidation_layout import resolve_active_layout
from .postgres_cta_bridge import (_dependency_pointers_current,
    expected_current_data_revision)

FUNCTION='consolidation.statement.pack.preview'

def _current(db,scope,row):
 status=published_result_status(db,scope,row['result_key'],row['state_token'])
 # All producer evidence participates in the verdict. The statement response
 # retains only its established source-profile projection, not unrelated
 # driver coordinates or context records inspected internally.
 profile={
  'consolidation.method.total.publish':'methodTotalSourceStatus',
  'consolidation.inventory.unrealized_profit.request':'inventoryUnrealizedSourceStatus',
  'consolidation.full.typed.contribute':'typedFullContextStatus',
  'facts.expression.calculate':'publishedInputStatus',
  'currency.calculation.translation.publish':'publishedCalculationTranslationStatus',
  'consolidation.full.aggregate':'publishedChildStatus',
  'consolidation.full.translated.aggregate':'publishedTranslationStatus',
 }.get(row['function_name'])
 if (row['function_name']=='consolidation.nci.period.publish' and
     row.get('compiler_version') in ('period-nci-attribution-v7-typed-unit',
      'period-nci-attribution-v8-ic-adjusted-typed-unit')):
  profile='periodNciSourceStatus'
 nested=status['profileStatuses'].get(profile)
 return status['inputRevisionStatus'],nested,(status['matchesAtRead'] and
  row['expected_metadata_revision']==row['source_metadata_revision'] and
  row['expected_policy_revision']==row['source_policy_revision'])

def _typed_evidence(row):
 raw_change=row['source_change_id'];evidence=row['source_evidence_digest'];stored_lineage=row['source_lookup_lineage']
 if raw_change is not None:
  if evidence is not None:raise ValueError('STATEMENT_PACK_TYPED_EVIDENCE_INVALID')
  return {'sourceChangeId':raw_change}
 if (not isinstance(evidence,str) or len(evidence)!=64
     or not isinstance(stored_lineage,list)
     or _canonical_digest(stored_lineage)!=evidence
     or not isinstance(row['receipt_result'],dict)
     or row['receipt_result'].get('sourceLookupLineage')!=stored_lineage):
  raise ValueError('STATEMENT_PACK_TYPED_EVIDENCE_INVALID')
 return {'sourceEvidenceDigest':evidence,
         'sourceLookupLineage':stored_lineage}

def _equity_chain_unit_certified(db,keys,source,unit_dimension,unit_member):
 """Accept only the current final output of a published configured chain."""
 row=db.execute('''SELECT s.sequence_id
   FROM epm.expression_rule_sequence s
   JOIN epm.calculation_result_state r
     ON r.workspace_id=s.workspace_id AND r.application_id=s.application_id
    AND r.result_key=%s AND r.state_token=%s
   JOIN epm.application_state a
     ON a.workspace_id=s.workspace_id AND a.application_id=s.application_id
   JOIN epm.hierarchy_state h
     ON h.workspace_id=s.workspace_id AND h.application_id=s.application_id
    AND h.dimension_id=s.manifest#>>'{equityChain,hierarchy,dimensionId}' AND h.hierarchy_id=epm.default_hierarchy_id(h.workspace_id,h.application_id,h.dimension_id)
   CROSS JOIN LATERAL jsonb_array_elements(
     s.manifest->'equityChain'->'periods') WITH ORDINALITY ep(period,ordinal)
   WHERE s.workspace_id=%s AND s.application_id=%s
     AND s.status='published' AND s.manifest ? 'equityChain'
     AND ep.ordinal=jsonb_array_length(
       s.manifest->'equityChain'->'periods')
     AND ep.period->>'resultKey'=%s
     AND s.job_ids->>((ep.ordinal-1)::integer)=r.source_operation_id
     AND s.manifest#>>'{equityChain,currencyDimensionId}'=%s
     AND s.manifest#>>'{equityChain,currencyMemberId}'=%s
     AND (s.manifest#>>'{equityChain,expectedMetadataRevision}')::bigint=
       a.metadata_revision
     AND (s.manifest#>>'{equityChain,expectedPolicyRevision}')::bigint=
       a.policy_revision
     AND (s.manifest#>>'{equityChain,expectedAuthorizationRevision}')::bigint=
       a.capability_revision
     AND s.manifest#>>'{equityChain,hierarchy,stateToken}'=h.state_token
   ORDER BY s.created_at DESC LIMIT 2''',(source['resultKey'],
     source['resultStateToken'],*keys,source['resultKey'],
     unit_dimension,unit_member)).fetchall()
 if len(row)>1:raise ValueError('STATEMENT_PACK_UNIT_AMBIGUOUS')
 return row[0]['sequence_id'] if row else None

def _calculation_journal_line(db,keys,source,point,unit_dimension,unit_member):
 rows=db.execute('''SELECT j.journal_id,j.committed_revision,j.reversal_of,
   l.line_ordinal,l.coordinate_id AS line_coordinate_id,
   l.signed_amount,l.source_ref,c.members,
   s.result_key,s.result_state_token,s.result_content_digest,
   s.source_operation_id,s.source_committed_revision,s.source_amount,
   s.journal_id AS calculation_source_journal_id,
   s.source_coordinate_id,s.unit_dimension_id,s.unit_member_id,
   s.dependency_status,o.result AS receipt_result,
   ol.coordinate_id AS original_coordinate_id,
   ol.signed_amount AS original_signed_amount
   FROM epm.manual_journal j
   JOIN epm.operation_receipt o
     ON o.workspace_id=j.workspace_id
    AND o.application_id=j.application_id
    AND o.operation_id=j.journal_id
   JOIN epm.manual_journal_line l
     ON l.workspace_id=j.workspace_id
    AND l.application_id=j.application_id
    AND l.journal_id=j.journal_id
   JOIN epm.coordinate c
     ON c.workspace_id=l.workspace_id
    AND c.application_id=l.application_id
    AND c.coordinate_id=l.coordinate_id
   JOIN epm.manual_journal_calculation_source s
     ON s.workspace_id=l.workspace_id
    AND s.application_id=l.application_id
    AND s.journal_id=COALESCE(j.reversal_of,l.journal_id)
    AND s.line_ordinal=l.line_ordinal
   LEFT JOIN epm.manual_journal_line ol
     ON ol.workspace_id=j.workspace_id
    AND ol.application_id=j.application_id
    AND ol.journal_id=j.reversal_of
    AND ol.line_ordinal=l.line_ordinal
   WHERE j.workspace_id=%s AND j.application_id=%s
     AND j.journal_id=%s AND l.line_ordinal=%s AND c.series_key=%s
   ORDER BY l.line_ordinal LIMIT 2''',(*keys,source['journalId'],
     source['lineOrdinal'],point.series_key)).fetchall()
 if len(rows)!=1:raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
 row=rows[0];receipt=row['receipt_result']
 if (row['journal_id']!=source['journalId']
     or row['line_ordinal']!=source['lineOrdinal']
     or row['committed_revision']!=source['committedRevision']
     or row['members']!=source['members']
     or row['unit_dimension_id']!=source['currencyDimensionId']
     or row['unit_member_id']!=source['currencyMemberId']
     or row['unit_dimension_id']!=unit_dimension
     or row['unit_member_id']!=unit_member
     or not isinstance(receipt,dict)
     or receipt.get('journalId')!=source['journalId']
     or receipt.get('status')!='Posted'
     or receipt.get('committedRevision')!=source['committedRevision']
     or receipt.get('reversalOf')!=row['reversal_of']
     or (row['reversal_of'] is None and
         row['calculation_source_journal_id']!=row['journal_id'])
     or (row['reversal_of'] is not None and (
         row['calculation_source_journal_id']!=row['reversal_of']
         or row['original_coordinate_id'] is None
         or row['original_coordinate_id']!=row['line_coordinate_id']
         or row['signed_amount']!=-row['original_signed_amount']))
     or not isinstance(row['dependency_status'],dict)):
  raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
 return row['signed_amount'],{
   'journalId':row['journal_id'],'lineOrdinal':row['line_ordinal'],
   'committedRevision':row['committed_revision'],
   'reversalOf':row['reversal_of'],'sourceRef':row['source_ref'],
   'calculationSource':{
     'journalId':row['calculation_source_journal_id'],
     'resultKey':row['result_key'],
     'resultStateToken':row['result_state_token'],
     'resultContentDigest':row['result_content_digest'],
     'sourceOperationId':row['source_operation_id'],
     'sourceCommittedRevision':row['source_committed_revision'],
     'sourceAmount':format(row['source_amount'],'.8f'),
     'sourceCoordinateId':row['source_coordinate_id'],
     'outputUnit':{'currencyDimensionId':row['unit_dimension_id'],
                   'currencyMemberId':row['unit_member_id']},
     'dependencyStatus':row['dependency_status']}}

def _acquisition_journal_line(db,keys,source,point,unit_dimension,unit_member):
 rows=db.execute('''SELECT j.journal_id,j.acquisition_key,j.committed_revision,
   j.reversal_of,j.activation_id,j.currency_dimension_id,j.currency_member_id,
   j.status,l.line_ordinal,l.line_role,l.signed_amount,c.members,
   o.result AS receipt_result,e.action AS activation_action
   FROM epm.acquisition_journal j
   JOIN epm.operation_receipt o
     ON o.workspace_id=j.workspace_id
    AND o.application_id=j.application_id
    AND o.operation_id=j.journal_id
   JOIN epm.acquisition_journal_line l
     ON l.workspace_id=j.workspace_id
    AND l.application_id=j.application_id
    AND l.journal_id=j.journal_id
   JOIN epm.coordinate c
     ON c.workspace_id=l.workspace_id
    AND c.application_id=l.application_id
    AND c.coordinate_id=l.coordinate_id
   JOIN epm.policy_activation_event e
     ON e.workspace_id=j.workspace_id
    AND e.application_id=j.application_id
    AND e.event_id=j.activation_id
   WHERE j.workspace_id=%s AND j.application_id=%s
     AND j.journal_id=%s AND l.line_ordinal=%s AND c.series_key=%s
   ORDER BY l.line_ordinal LIMIT 2''',(*keys,source['journalId'],
     source['lineOrdinal'],point.series_key)).fetchall()
 if len(rows)!=1:raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
 row=rows[0];receipt=row['receipt_result']
 if (row['journal_id']!=source['journalId']
     or row['line_ordinal']!=source['lineOrdinal']
     or row['line_role']!=source['lineRole']
     or row['committed_revision']!=source['committedRevision']
     or row['members']!=source['members']
     or row['currency_dimension_id']!=source['currencyDimensionId']
     or row['currency_member_id']!=source['currencyMemberId']
     or row['currency_dimension_id']!=unit_dimension
     or row['currency_member_id']!=unit_member
     or row['status']!='Posted'
     or row['activation_action']!='Activate'
     or not isinstance(receipt,dict)
     or receipt.get('journalId')!=source['journalId']
     or receipt.get('status')!='Posted'
     or receipt.get('layer')!='acquisition_journal'
     or receipt.get('committedRevision')!=source['committedRevision']
     or receipt.get('reversalOf')!=row['reversal_of']):
  raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
 return row['signed_amount'],{
   'journalId':row['journal_id'],'lineOrdinal':row['line_ordinal'],
   'lineRole':row['line_role'],'committedRevision':row['committed_revision'],
   'acquisitionKey':row['acquisition_key'],'activationId':row['activation_id'],
   'reversalOf':row['reversal_of'],
   'outputUnit':{'currencyDimensionId':row['currency_dimension_id'],
                 'currencyMemberId':row['currency_member_id']}}

class PostgresStatementPack:
 def __init__(self,dsn,*,identity):
  if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
  self.dsn,self.identity=dsn,identity
 @staticmethod
 def catalog():
  return {FUNCTION:{'mode':'read_only','permission':'read','previewRequired':False,'idempotencyRequired':False,'workClass':'short','arguments':{'packId':'bounded structural pack identity','sources':'2-64 pinned CalculationAmount, TypedUnitAmount, CtaBridge, CalculationJournalLine or AcquisitionJournalLine sources','equations':'2-32 exact same-unit, fixed-grain equations','expectedMetadataRevision':'current','expectedDataRevision':'current','expectedPolicyRevision':'current','expectedCommitRevision':'current'},'result':'exact multi-equation structural proof; Unreviewed and no effects',
   'workflowRoute':{'stages':['consolidation.period.close.request','consolidation.period.close.read','consolidation.period.close.reopen'],
    'boundary':'the separate preview-bound close request consumes this exact statement-pack program and lineage digest, creates the scoped period lock and immutable Unreviewed receipt, and only an explicit reviewed reopen releases that lock'}}}
 def read(self,scope,raw):
  plan=compile_pack(raw,FUNCTION);keys=(scope.workspace_id,scope.application_id);amounts={};lineage=[]
  with connect_postgres(self.dsn,row_factory=dict_row) as db:
   with db.transaction():
    PostgresNumericFactStore._set_scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id);PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=FUNCTION)
    state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision,enabled_capabilities FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',keys).fetchone()
    columns={'expectedMetadataRevision':'metadata_revision','expectedDataRevision':'data_revision','expectedPolicyRevision':'policy_revision','expectedCommitRevision':'commit_revision'}
    if not state or 'financial_consolidation' not in state['enabled_capabilities'] or any(state[columns[k]]!=v for k,v in plan['pins'].items()):raise ValueError('STALE_STATEMENT_PACK_PINS')
    roles=db.execute('''SELECT model_role,dimension_id FROM epm.dimension
      WHERE workspace_id=%s AND application_id=%s AND status='Active'
      AND model_role IN ('Entity','Period','Currency')
      ORDER BY model_role,dimension_id''',keys).fetchall()
    by_role={}
    for row in roles:
     if row['model_role'] in by_role:raise ValueError('STATEMENT_PACK_ROLE_AMBIGUOUS')
     by_role[row['model_role']]=row['dimension_id']
    if set(by_role)!={'Entity','Period','Currency'}:raise ValueError('STATEMENT_PACK_ROLE_REQUIRED')
    for equation in plan['equations']:
     fixed=equation['fixedMembers']
     if (equation['currencyDimensionId']!=by_role['Currency']
         or by_role['Currency'] in fixed
         or by_role['Entity'] not in fixed or by_role['Period'] not in fixed):
      raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
    source_units={}
    for equation in plan['equations']:
     unit=(equation['currencyDimensionId'],equation['currencyMemberId'])
     for term in equation['terms']:
      if (term['sourceId'] in source_units
          and source_units[term['sourceId']]!=unit):
       raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
      source_units[term['sourceId']]=unit
    for source in plan['sources']:
     point=Coordinate.from_mapping(source['members']);kind=source['sourceKind']
     unit_dimension,unit_member=source_units[source['sourceId']]
     if unit_dimension in source['members']:
      raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
     if kind=='CtaBridge':
      rows=db.execute('''SELECT b.bridge_digest,b.status,b.layout_state_token,
        b.layout_digest,b.data_revision,b.currency_dimension_id,
        b.compiler_version,
        b.currency_member_id,l.signed_amount AS amount,c.members
        FROM epm.cta_bridge b JOIN epm.manual_journal_line l
          ON l.workspace_id=b.workspace_id AND l.application_id=b.application_id
         AND l.journal_id=b.journal_id
        JOIN epm.coordinate c
          ON c.workspace_id=l.workspace_id
         AND c.application_id=l.application_id
         AND c.coordinate_id=l.coordinate_id
        WHERE b.workspace_id=%s AND b.application_id=%s AND b.bridge_id=%s
          AND b.compiler_version='cta-bridge-v2' AND c.series_key=%s
        UNION ALL
        SELECT b.bridge_digest,b.status,b.layout_state_token,b.layout_digest,
          b.data_revision,b.currency_dimension_id,b.compiler_version,
          b.currency_member_id,
          e.amount,c.members FROM epm.cta_bridge b
        JOIN epm.cta_bridge_unit_effect e
          ON e.workspace_id=b.workspace_id
         AND e.application_id=b.application_id
         AND e.bridge_id=b.bridge_id
        JOIN epm.coordinate c
          ON c.workspace_id=e.workspace_id
         AND c.application_id=e.application_id
         AND c.coordinate_id=e.coordinate_id
        WHERE b.workspace_id=%s AND b.application_id=%s AND b.bridge_id=%s
          AND b.compiler_version='cta-bridge-v3-typed-unit' AND c.series_key=%s
        LIMIT 2''',(*keys,source['bridgeId'],point.series_key,
          *keys,source['bridgeId'],point.series_key)).fetchall()
      if (len(rows)!=1 or rows[0]['status']!='Posted'
          or rows[0]['members']!=source['members']
          or rows[0]['currency_dimension_id']!=unit_dimension
          or rows[0]['currency_member_id']!=unit_member):raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
      row=rows[0];resolve_active_layout(db,scope,expected_state_token=row['layout_state_token'],expected_digest=row['layout_digest'])
      source_rows=db.execute('''SELECT s.result_key,s.result_state_token,s.result_content_digest,s.source_operation_id,s.source_committed_revision,s.source_function,s.dependency_status,p.state_token AS observed_state_token,p.source_function AS function_name,j.status AS job_status,j.normalized_program,j.expected_metadata_revision,j.expected_data_revision,j.expected_policy_revision,p.source_metadata_revision,p.source_policy_revision FROM epm.cta_bridge_source s LEFT JOIN epm.calculation_result_state p ON p.workspace_id=s.workspace_id AND p.application_id=s.application_id AND p.result_key=s.result_key LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id AND j.application_id=p.application_id AND j.job_id=p.source_operation_id WHERE s.workspace_id=%s AND s.application_id=%s AND s.bridge_id=%s ORDER BY s.source_ordinal''',(*keys,source['bridgeId'])).fetchall()
      statuses=[]
      for dependency in source_rows:
       nested={'matchesAtRead':_dependency_pointers_current(db,scope,dependency['dependency_status']),'certificate':dependency['dependency_status']}
       expected_current_data=expected_current_data_revision(
        row['compiler_version'],row['data_revision'])
       direct={'matchesAtRead':dependency['expected_metadata_revision']==state['metadata_revision'] and dependency['expected_policy_revision']==state['policy_revision'] and dependency['expected_data_revision']==row['data_revision'] and state['data_revision']==expected_current_data,'expected':{'metadata':dependency['expected_metadata_revision'],'data':dependency['expected_data_revision'],'policy':dependency['expected_policy_revision']},'observed':{'metadata':state['metadata_revision'],'data':state['data_revision'],'policy':state['policy_revision']},'observedCommitRevision':state['commit_revision']}
       if (dependency['result_state_token']!=dependency['observed_state_token'] or dependency['job_status']!='published' or dependency['source_function']!=dependency['function_name'] or dependency['expected_metadata_revision']!=dependency['source_metadata_revision'] or dependency['expected_policy_revision']!=dependency['source_policy_revision'] or not direct['matchesAtRead'] or (nested is not None and not nested['matchesAtRead'])):raise ValueError('STATEMENT_PACK_CTA_SOURCE_STALE')
       statuses.append({'resultKey':dependency['result_key'],'resultStateToken':dependency['result_state_token'],'resultContentDigest':dependency['result_content_digest'],'inputRevisionStatus':direct,'dependencyStatus':nested})
      if not statuses:raise ValueError('STATEMENT_PACK_CTA_SOURCE_STALE')
      amount=row['amount'];detail={'bridgeDigest':row['bridge_digest'],'layoutStateToken':row['layout_state_token'],'layoutDigest':row['layout_digest'],'sourceStatus':statuses}
     elif kind=='CalculationJournalLine':
      amount,detail=_calculation_journal_line(
       db,keys,source,point,unit_dimension,unit_member)
     elif kind=='AcquisitionJournalLine':
      amount,detail=_acquisition_journal_line(
       db,keys,source,point,unit_dimension,unit_member)
     else:
      if kind=='CalculationAmount':
       functional=db.execute('''SELECT m.entity_default_currency_member_id,
           EXISTS(SELECT 1 FROM epm.dimension cd JOIN epm.member cm
             ON cm.workspace_id=cd.workspace_id
            AND cm.application_id=cd.application_id
            AND cm.dimension_id=cd.dimension_id
            WHERE cd.workspace_id=d.workspace_id
              AND cd.application_id=d.application_id
              AND cd.dimension_id=%s AND cd.model_role='Currency'
              AND cd.status='Active' AND cm.member_id=%s
              AND cm.status='Active') AS unit_active
         FROM epm.dimension d JOIN epm.member m
           ON m.workspace_id=d.workspace_id
          AND m.application_id=d.application_id
          AND m.dimension_id=d.dimension_id
         WHERE d.workspace_id=%s AND d.application_id=%s
           AND d.dimension_id=%s AND d.model_role='Entity'
           AND d.status='Active' AND m.member_id=%s AND m.status='Active' ''',
        (unit_dimension,unit_member,*keys,by_role['Entity'],
         source['members'][by_role['Entity']])).fetchall()
       if (len(functional)!=1
           or not functional[0]['unit_active']
           or functional[0]['entity_default_currency_member_id']!=unit_member):
        raise ValueError('STATEMENT_PACK_UNIT_GRAIN_MISMATCH')
      table=('calculation_unit_result_current' if kind=='TypedUnitAmount'
             else 'calculation_result_current');unit_sql=(' AND r.output_unit_currency_dimension_id=%s AND r.output_unit_currency_member_id=%s' if kind=='TypedUnitAmount' else '');params=(*keys,source['resultKey'],source['resultStateToken'],point.series_key,*(([source['currencyDimensionId'],source['currencyMemberId']]) if kind=='TypedUnitAmount' else []))
      typed_columns=(',r.source_amount,r.source_change_id,'
        'r.source_evidence_digest,r.source_lookup_lineage,r.rate_strategy,'
        'r.rate_numerator,r.rate_denominator,r.rate_sources' if
        kind=='TypedUnitAmount' else '')
      rows=db.execute(f'''SELECT c.members,r.amount,p.result_key,p.state_token,
        p.source_function AS function_name,p.source_metadata_revision,
        p.source_policy_revision,j.compiler_version,
        j.status,j.normalized_program,j.expected_metadata_revision,
        j.expected_data_revision,j.expected_policy_revision,
        o.result AS receipt_result{typed_columns}
        FROM epm.calculation_result_state p
        JOIN epm.job j
          ON j.workspace_id=p.workspace_id
         AND j.application_id=p.application_id
         AND j.job_id=p.source_operation_id
        JOIN epm.operation_receipt o
          ON o.workspace_id=p.workspace_id
         AND o.application_id=p.application_id
         AND o.operation_id=p.source_operation_id
        JOIN epm.{table} r
          ON r.workspace_id=p.workspace_id
         AND r.application_id=p.application_id
         AND r.result_key=p.result_key
        JOIN epm.coordinate c
          ON c.workspace_id=r.workspace_id
         AND c.application_id=r.application_id
         AND c.coordinate_id=r.coordinate_id
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s
          AND p.state_token=%s
          AND c.series_key=%s {unit_sql}
        ORDER BY c.coordinate_id LIMIT 2''',params).fetchall()
      if len(rows)!=1 or rows[0]['status']!='published' or rows[0]['members']!=source['members']:raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
      row=rows[0];direct,nested,current=_current(db,scope,row)
      chain_sequence_id=None
      if (kind=='CalculationAmount' and row['function_name'] not in
          ('consolidation.full.contribute','consolidation.full.aggregate')):
       if row['function_name']=='facts.expression.calculate':
        chain_sequence_id=_equity_chain_unit_certified(
         db,keys,source,unit_dimension,unit_member)
       if chain_sequence_id is None:
        raise ValueError('STATEMENT_PACK_UNIT_UNVERIFIABLE')
      if not current:raise ValueError('STATEMENT_PACK_SOURCE_STALE_OR_UNAVAILABLE')
      amount=row['amount'];detail={'function':row['function_name'],'compilerVersion':row['compiler_version'],'resultStateToken':source['resultStateToken'],'inputRevisionStatus':direct,'dependencyStatus':nested}
      if chain_sequence_id is not None:
       detail.update({'unitEvidence':'EquityRollforwardChain',
        'equityChainSequenceId':chain_sequence_id})
      if kind=='TypedUnitAmount':
       evidence_fields=_typed_evidence(row)
       detail.update({'sourceAmount':format(row['source_amount'],'.8f'),
        **evidence_fields,'rateStrategy':row['rate_strategy'],
        'rateNumerator':str(row['rate_numerator']),
        'rateDenominator':str(row['rate_denominator']),
        'rateSources':row['rate_sources'],
        'outputUnit':{'currencyDimensionId':source['currencyDimensionId'],
                      'currencyMemberId':source['currencyMemberId']}})
     amounts[source['sourceId']]=amount;lineage.append({'sourceId':source['sourceId'],'sourceKind':kind,'members':source['members'],**detail})
    after=db.execute('''SELECT commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',keys).fetchone()
    if after['commit_revision']!=state['commit_revision']:raise ValueError('STALE_STATEMENT_PACK_PINS')
  equations=reconcile_pack(plan,amounts);digest=_canonical_digest({'plan':plan,'lineage':lineage,'equations':equations})
  return {'packId':plan['packId'],'packVersion':2,'equations':equations,'allReconciled':all(e['reconciled'] for e in equations),'sources':lineage,'lineageDigest':digest,'accountingPolicyStatus':'Unreviewed','structuralOnly':True,'wholeStatementCertified':False,'effects':'None'}
