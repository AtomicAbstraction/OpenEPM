"""Structural exact reconciliation of pinned published calculation rows.

This is deliberately not an accounting-policy opinion, close certificate or
period lock.  It proves only the caller-declared bounded equation over current
result states.
"""
from decimal import Decimal, localcontext
import re

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_cta_bridge import cta_bridge_sources_current
from .current_object_contract import require_state_token

FUNCTION = 'consolidation.statement.reconciliation.preview'
VERSION_V1 = 'structural-statement-reconciliation-v1'
VERSION_V2 = 'structural-statement-reconciliation-v2'
VERSION_V3 = 'structural-statement-reconciliation-v3-cta-unit'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def compile_program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or raw.get('languageVersion')!=2 or raw.get('function')!=FUNCTION
            or not isinstance(raw.get('arguments'),dict)):
        raise ValueError('STATEMENT_RECONCILIATION_PROGRAM_INVALID')
    args=raw['arguments'];fields={'equationId','sources','terms','expectedMetadataRevision',
        'expectedDataRevision','expectedPolicyRevision','expectedCommitRevision'}
    if (set(args)!=fields or not isinstance(args['equationId'],str)
            or not _KEY.fullmatch(args['equationId'])
            or any(not _integer(args[name]) for name in fields if name.startswith('expected'))
            or not isinstance(args['sources'],list) or not 1<=len(args['sources'])<=32
            or not isinstance(args['terms'],list) or not 2<=len(args['terms'])<=128):
        raise ValueError('STATEMENT_RECONCILIATION_ARGUMENTS_INVALID')
    sources=[]; version = 1
    for source in args['sources']:
        if isinstance(source,dict) and source.get('sourceKind') in (
                'CtaBridge','CtaBridgeUnit'):
            expected={'sourceKind','bridgeId'}
            if source.get('sourceKind')=='CtaBridgeUnit':
                expected|={'currencyDimensionId','currencyMemberId'}
            if (set(source) != expected
                    or not isinstance(source.get('bridgeId'),str)
                    or not _JOB.fullmatch(source['bridgeId'])
                    or any(not isinstance(source.get(name),str)
                           or not source[name].strip()
                           for name in expected-{'sourceKind','bridgeId'})):
                raise ValueError('STATEMENT_RECONCILIATION_SOURCE_INVALID')
            sources.append(dict(source)); version = max(version,(3 if
                source['sourceKind']=='CtaBridgeUnit' else 2))
        else:
            expected = {'resultKey','resultStateToken'}
            if isinstance(source,dict) and source.get('sourceKind')=='Calculation':
                expected = expected | {'sourceKind'}; version = max(version,2)
            if (not isinstance(source,dict) or set(source)!=expected
                    or not isinstance(source['resultKey'],str)
                    or not _KEY.fullmatch(source['resultKey'])
                    ):
                raise ValueError('STATEMENT_RECONCILIATION_SOURCE_INVALID')
            require_state_token(source['resultStateToken'],
                                error='STATEMENT_RECONCILIATION_SOURCE_INVALID')
            sources.append(dict(source))
    identities = [(item.get('sourceKind','Calculation'),
      item.get('bridgeId',item.get('resultKey')),
      item.get('resultStateToken')) for item in sources]
    if len(set(identities))!=len(sources):
        raise ValueError('STATEMENT_RECONCILIATION_SOURCE_DUPLICATE')
    terms=[];seen=set();used=set()
    for term in args['terms']:
        if (not isinstance(term,dict) or set(term)!={'sourceIndex','sectionId','accountMemberId','members','sign'}
                or not _integer(term['sourceIndex']) or term['sourceIndex']>=len(sources)
                or not isinstance(term['sectionId'],str) or not _KEY.fullmatch(term['sectionId'])
                or not isinstance(term['accountMemberId'],str) or not term['accountMemberId'].strip()
                or term['sign'] not in (-1,1) or isinstance(term['sign'],bool)):
            raise ValueError('STATEMENT_RECONCILIATION_TERM_INVALID')
        try:members=dict(Coordinate.from_mapping(term['members']).members)
        except (TypeError,ValueError,AttributeError) as error:raise ValueError('STATEMENT_RECONCILIATION_TERM_INVALID') from error
        identity=(term['sourceIndex'],tuple(sorted(members.items())))
        if identity in seen:raise ValueError('STATEMENT_RECONCILIATION_TERM_DUPLICATE')
        seen.add(identity);used.add(term['sourceIndex'])
        terms.append({**term,'members':members})
    if used != set(range(len(sources))):
        raise ValueError('STATEMENT_RECONCILIATION_SOURCE_UNUSED')
    for index,source in enumerate(sources):
        if (source.get('sourceKind')=='CtaBridgeUnit'
                and any(source['currencyDimensionId'] in term['members']
                        for term in terms if term['sourceIndex']==index)):
            raise ValueError(
                'STATEMENT_RECONCILIATION_CURRENCY_AXIS_FORBIDDEN')
    if len({term['sectionId'] for term in terms}) < 2:
        raise ValueError('STATEMENT_RECONCILIATION_SECTIONS_INSUFFICIENT')
    return {'version':version,'function':FUNCTION,'equationId':args['equationId'],
        'sources':sources,'terms':terms,'pins':{name:args[name] for name in fields if name.startswith('expected')}}


def reconcile_terms(rows):
    with localcontext() as precision:
        precision.prec=80
        sections={};total=Decimal(0);result=[]
        for row in rows:
            amount=Decimal(row['amount']);signed=amount*row['sign']
            total+=signed;sections[row['sectionId']]=sections.get(row['sectionId'],Decimal(0))+signed
            result.append({**row,'amount':format(amount,'.8f'),'signedAmount':format(signed,'.8f')})
        NumericCell(True,total,'')
    return result,{key:format(value,'.8f') for key,value in sorted(sections.items())},format(total,'.8f')


def compiler_version(plan):
    return (VERSION_V3 if plan.get('version') == 3 else
            VERSION_V2 if plan.get('version') == 2 else VERSION_V1)


class PostgresStatementReconciliation:
    def __init__(self,dsn,*,identity):
        if not isinstance(identity,VerifiedIdentity):raise ValueError('A verified identity is required')
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def catalog():
        return {FUNCTION:{'mode':'read_only','permission':'read','previewRequired':False,
            'idempotencyRequired':False,'workClass':'short','arguments':{
                'equationId':'8-128 safe structural equation identity',
                'sources':'1-32 exact calculation pins or CTA bridge; CtaBridgeUnit carries Currency as a typed unit, never a coordinate axis',
                'terms':'2-128 explicit sourceIndex/section/account/full-members/sign(+1|-1) terms',
                'expectedMetadataRevision':'current integer','expectedDataRevision':'current integer',
                'expectedPolicyRevision':'current integer','expectedCommitRevision':'current integer'},
            'result':'exact structural equation diagnostics and immutable lineage digest; Unreviewed and no effects',
            'workflowRoute':{
                'stages':['consolidation.period.close.request',
                    'consolidation.period.close.read',
                    'consolidation.period.close.reopen'],
                'boundary':'the separate preview-bound close request consumes this exact reconciliation program and lineage digest, creates the scoped period lock and immutable Unreviewed receipt, and only an explicit reviewed reopen releases that lock'}}}

    def read(self,scope,raw):
        plan=compile_program(raw);keys=(scope.workspace_id,scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read',function=FUNCTION)
                # Capability enforcement deliberately takes a row-level share
                # lock; all subsequent statements in this fixed service are
                # SELECTs, so callers still have no mutation surface.
                state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision,
                    enabled_capabilities FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',keys).fetchone()
                if not state or 'financial_consolidation' not in state['enabled_capabilities']:
                    raise ValueError('APPLICATION_CAPABILITY_DISABLED')
                revision_columns = {
                    'expectedMetadataRevision': 'metadata_revision',
                    'expectedDataRevision': 'data_revision',
                    'expectedPolicyRevision': 'policy_revision',
                    'expectedCommitRevision': 'commit_revision',
                }
                for name,value in plan['pins'].items():
                    if state[revision_columns[name]] != value:
                        raise ValueError('STALE_STATEMENT_RECONCILIATION_PINS')
                account=db.execute('''SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND model_role='Account' AND status='Active' ''',keys).fetchall()
                if len(account)!=1:raise ValueError('STATEMENT_RECONCILIATION_ACCOUNT_AXIS_REQUIRED')
                axis=account[0]['dimension_id'];loaded=[];lineage=[]
                for index,source in enumerate(plan['sources']):
                    if source.get('sourceKind') in ('CtaBridge','CtaBridgeUnit'):
                        bridge = db.execute('''SELECT b.bridge_id,b.bridge_digest,
                            b.journal_id,b.committed_revision,b.status,
                            b.compiler_version,
                            b.currency_dimension_id,b.currency_member_id
                            FROM epm.cta_bridge b
                            WHERE b.workspace_id=%s AND b.application_id=%s
                            AND b.bridge_id=%s''',
                            (*keys,source['bridgeId'])).fetchone()
                        if not bridge or bridge['status'] != 'Posted':
                            raise ValueError(
                                'STALE_STATEMENT_RECONCILIATION_SOURCE')
                        if not cta_bridge_sources_current(
                                db,scope,bridge['bridge_id']):
                            raise ValueError(
                                'STALE_STATEMENT_RECONCILIATION_SOURCE')
                        if source.get('sourceKind')=='CtaBridgeUnit' and (
                                source['currencyDimensionId']!=bridge['currency_dimension_id']
                                or source['currencyMemberId']!=bridge['currency_member_id']):
                            raise ValueError(
                                'STATEMENT_RECONCILIATION_UNIT_MISMATCH')
                        terms=[term for term in plan['terms']
                               if term['sourceIndex']==index]
                        for term in terms:
                            if term['members'].get(axis)!=term['accountMemberId']:
                                raise ValueError(
                                    'STATEMENT_RECONCILIATION_ACCOUNT_MISMATCH')
                            point=Coordinate.from_mapping(term['members'])
                            if source.get('sourceKind')=='CtaBridgeUnit':
                                if source['currencyDimensionId'] in term['members']:
                                    raise ValueError(
                                      'STATEMENT_RECONCILIATION_CURRENCY_AXIS_FORBIDDEN')
                                if bridge['compiler_version']=='cta-bridge-v3-typed-unit':
                                  row=db.execute('''SELECT e.amount FROM
                                    epm.cta_bridge_unit_effect e JOIN epm.coordinate c
                                    USING(workspace_id,application_id,coordinate_id)
                                    WHERE e.workspace_id=%s AND e.application_id=%s
                                    AND e.bridge_id=%s AND c.series_key=%s
                                    AND e.currency_dimension_id=%s
                                    AND e.currency_member_id=%s''',(*keys,
                                    bridge['bridge_id'],point.series_key,
                                    source['currencyDimensionId'],
                                    source['currencyMemberId'])).fetchall()
                                else:
                                  row=db.execute('''SELECT l.signed_amount AS amount
                                    FROM epm.manual_journal_line l JOIN epm.coordinate c
                                    USING(workspace_id,application_id,coordinate_id)
                                    WHERE l.workspace_id=%s AND l.application_id=%s
                                    AND l.journal_id=%s AND c.series_key=%s
                                    AND NOT (c.members ? %s)''',(*keys,
                                    bridge['journal_id'],point.series_key,
                                    source['currencyDimensionId'])).fetchall()
                            else:
                                row=db.execute('''SELECT l.signed_amount AS amount
                                FROM epm.manual_journal_line l JOIN
                                epm.coordinate c USING(
                                  workspace_id,application_id,coordinate_id)
                                WHERE l.workspace_id=%s
                                AND l.application_id=%s
                                AND l.journal_id=%s AND c.series_key=%s''',
                                (*keys,bridge['journal_id'],
                                 point.series_key)).fetchall()
                            if len(row)!=1:
                                raise ValueError(
                                  'STATEMENT_RECONCILIATION_TERM_UNAVAILABLE')
                            loaded.append({**term,'amount':row[0]['amount']})
                        lineage.append({'sourceKind':source['sourceKind'],
                          **({'currencyDimensionId':source['currencyDimensionId'],
                              'currencyMemberId':source['currencyMemberId']}
                             if source['sourceKind']=='CtaBridgeUnit' else {}),
                          **dict(bridge)})
                        continue
                    generation=db.execute('''SELECT p.state_token,p.content_digest,
                        p.source_function AS function_name,p.source_commit_revision,
                        p.source_metadata_revision,p.source_policy_revision,
                        p.source_program_digest AS program_digest,j.status
                        FROM epm.calculation_result_state p
                        JOIN epm.job j ON j.workspace_id=p.workspace_id
                        AND j.application_id=p.application_id
                        AND j.job_id=p.source_operation_id
                        WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s''',(*keys,source['resultKey'])).fetchone()
                    if (not generation
                            or generation['state_token']!=source['resultStateToken']
                            or generation['status']!='published'):
                        raise ValueError('STALE_STATEMENT_RECONCILIATION_SOURCE')
                    terms=[term for term in plan['terms'] if term['sourceIndex']==index]
                    for term in terms:
                        if term['members'].get(axis)!=term['accountMemberId']:
                            raise ValueError('STATEMENT_RECONCILIATION_ACCOUNT_MISMATCH')
                        point=Coordinate.from_mapping(term['members'])
                        row=db.execute('''SELECT r.amount FROM epm.calculation_result_current r JOIN epm.coordinate c
                            USING(workspace_id,application_id,coordinate_id) WHERE r.workspace_id=%s
                            AND r.application_id=%s AND r.result_key=%s AND c.series_key=%s''',
                            (*keys,source['resultKey'],point.series_key)).fetchall()
                        if len(row)!=1:raise ValueError('STATEMENT_RECONCILIATION_TERM_UNAVAILABLE')
                        loaded.append({**term,'amount':row[0]['amount']})
                    lineage.append({**source,**{key:generation[key] for key in ('function_name','source_commit_revision',
                        'source_metadata_revision','source_policy_revision','program_digest')}})
                after=db.execute('''SELECT commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',keys).fetchone()
                if after['commit_revision']!=state['commit_revision']:
                    raise ValueError('STALE_STATEMENT_RECONCILIATION_PINS')
        terms,sections,total=reconcile_terms(loaded)
        return {'equationId':plan['equationId'],'reconciled':Decimal(total)==0,
            'signedTotal':total,'sections':sections,'terms':terms,'sources':lineage,
            'lineageDigest':_canonical_digest({'plan':plan,'sources':lineage,'terms':terms}),
            'accountingPolicyStatus':'Unreviewed','structuralOnly':True,
            'closeCertified':False,'periodLocked':False,
            'compilerVersion': compiler_version(plan)}
