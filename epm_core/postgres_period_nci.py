"""Policy-draft period NCI candidate with explicit eligible basis and exact split.

This is the fixed candidate kernel for a distinct future governed operation.
It does not approve an account's meaning or authorize accounting publication.
"""
from datetime import date, timedelta
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_policy_drafts import ELECTIONS_FUNCTION, _program as policy_program, validate_elections_in_transaction
from .postgres_ownership import PostgresOwnershipValues

FUNCTION='consolidation.nci.period.measure.inspect'
CORE_VERSION='period-nci-candidate-v1'
BASIS_KINDS=frozenset(('period_profit_ytd','net_assets_at_period_end'))
_ID=re.compile(r'[^\x00]{1,200}\Z')


def amount(value,field):
    if not isinstance(value,str): raise ValueError('PERIOD_NCI_DECIMAL_STRING_REQUIRED')
    try:
        result=Decimal(value)
        NumericCell(True,result,'')
    except (ValueError,ArithmeticError) as error:
        raise ValueError('PERIOD_NCI_AMOUNT_INVALID') from error
    return Decimal(0) if result == 0 else result


def split_basis(basis,pown):
    """Retain signed amount and assign the final rounding residual to owners."""
    basis=amount(basis,'basisAmount');pown=amount(pown,'ownershipPercent')
    if not Decimal(0)<pown<=Decimal(100): raise ValueError('PERIOD_NCI_OWNERSHIP_RANGE_INVALID')
    with localcontext() as precision:
        precision.prec=80
        exact=basis*(Decimal(100)-pown)/Decimal(100)
        if exact == 0: exact = Decimal(0)
        nci=exact.quantize(Decimal('.00000001'),rounding=ROUND_HALF_EVEN)
        if nci == 0: nci = Decimal(0)
        controlling=basis-nci
    NumericCell(True,nci,'');NumericCell(True,controlling,'')
    return {'basisAmount':format(basis,'.8f'),'ownershipPercent':format(pown,'.8f'),
        'candidateNciShare':format(nci,'.8f'),'candidateControllingShare':format(controlling,'.8f'),
        'exactCandidateNciShare':format(exact,'f'),'rounding':'half_even_nci_owner_residual'}


def parse_program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or raw['function']!=FUNCTION or not isinstance(raw['arguments'],dict)):
        raise ValueError('PERIOD_NCI_PROGRAM_INVALID')
    args=raw['arguments']
    required={'policyId','effectiveOn','selections','expectedPolicyRevision',
        'relationshipId','scenarioId','yearId','periodId','method','controlConfirmed',
        'basisKind','basisEligibilityConfirmed','basisAmount','ownershipPercent'}
    if (set(args)!=required or any(not isinstance(args[key],str) or not _ID.fullmatch(args[key])
            or args[key]!=args[key].strip() for key in ('relationshipId','scenarioId','yearId','periodId'))):
        raise ValueError('PERIOD_NCI_ARGUMENTS_INVALID')
    if (args['method']!='Full' or args['controlConfirmed'] is not True
            or args['basisEligibilityConfirmed'] is not True
            or not isinstance(args['basisKind'],str) or args['basisKind'] not in BASIS_KINDS):
        raise ValueError('PERIOD_NCI_SCOPE_UNSUPPORTED')
    split_basis(args['basisAmount'],args['ownershipPercent'])
    policy=policy_program({'languageVersion':2,'function':ELECTIONS_FUNCTION,
        'arguments':{key:args[key] for key in ('policyId','effectiveOn','selections','expectedPolicyRevision')}},ELECTIONS_FUNCTION)
    return args,policy


def evaluate_in_transaction(db,scope,args,policy,state):
    draft=validate_elections_in_transaction(db,scope,policy,state)
    if draft['family'] not in ('IFRS','US_GAAP'): raise ValueError('PERIOD_NCI_POLICY_FAMILY_UNSUPPORTED')
    if (draft['selections'].get('periodNciAttribution')!='pro_rata_full_method'
            or draft['selections'].get('negativeBasisTreatment')!='allow_signed_attribution'):
        raise ValueError('PERIOD_NCI_ELECTION_REQUIRED')
    keys=(scope.workspace_id,scope.application_id)
    query={key:args[key] for key in ('relationshipId','scenarioId','yearId','periodId')}
    PostgresOwnershipValues._active_context(db,scope,{**query,'account':'POWN'})
    # A shared child cannot inherit an ambiguous consolidation placement.
    placement=db.execute('''SELECT r.parent_member_id,r.child_member_id,
        (SELECT count(*) FROM epm.relationship other WHERE other.workspace_id=r.workspace_id
         AND other.application_id=r.application_id AND other.dimension_id=r.dimension_id
         AND other.child_member_id=r.child_member_id AND other.status='Active') AS parent_count
        FROM epm.relationship r WHERE r.workspace_id=%s AND r.application_id=%s
        AND r.relationship_id=%s''',(*keys,args['relationshipId'])).fetchone()
    if placement is None or placement['parent_count']!=1: raise ValueError('PERIOD_NCI_AMBIGUOUS_PLACEMENT')
    periods=db.execute('''SELECT period_member_id,ordinal,starts_on,ends_before,change_id,last_revision
        FROM epm.calendar_period_current WHERE workspace_id=%s AND application_id=%s
        AND year_member_id=%s ORDER BY ordinal''',(*keys,args['yearId'])).fetchall()
    current=next((p for p in periods if p['period_member_id']==args['periodId']),None)
    if current is None or policy['effectiveOn']!=current['ends_before']-timedelta(days=1):
        raise ValueError('PERIOD_NCI_PERIOD_END_REQUIRED')
    selected=([p for p in periods if p['ordinal']<=current['ordinal']]
        if args['basisKind']=='period_profit_ytd' else [current])
    if args['basisKind']=='period_profit_ytd' and ([p['ordinal'] for p in selected]!=list(range(1,current['ordinal']+1))
            or any(a['ends_before']!=b['starts_on'] for a,b in zip(selected,selected[1:]))):
        raise ValueError('PERIOD_NCI_CALENDAR_GAP')
    if not 1<=len(selected)<=120: raise ValueError('PERIOD_NCI_PERIOD_LIMIT')
    if args['basisKind']=='period_profit_ytd' and (date.fromisoformat(draft['effectiveFrom'])>selected[0]['starts_on'] or date.fromisoformat(draft['effectiveBefore'])<current['ends_before']):
        raise ValueError('PERIOD_NCI_POLICY_PERIOD_COVERAGE')
    rows=db.execute('''SELECT period_member_id,account_name,amount,change_id,last_revision
        FROM epm.ownership_value_current WHERE workspace_id=%s AND application_id=%s
        AND relationship_id=%s AND scenario_member_id=%s AND year_member_id=%s
        AND period_member_id=ANY(%s::text[]) AND present
        AND account_name IN ('POWN','PCON','Active','Method')''',
        (*keys,args['relationshipId'],args['scenarioId'],args['yearId'],[p['period_member_id'] for p in selected])).fetchall()
    by_period={p['period_member_id']:{} for p in selected}
    for row in rows: by_period[row['period_member_id']][row['account_name']]=row
    ownership=amount(args['ownershipPercent'],'ownershipPercent')
    lineage=[]
    for period in selected:
        values=by_period[period['period_member_id']]
        if 'POWN' not in values: raise ValueError('PERIOD_NCI_POWN_UNAVAILABLE')
        if values['POWN']['amount']!=ownership: raise ValueError('PERIOD_NCI_OWNERSHIP_CHANGED')
        if ('Method' in values and values['Method']['amount']!=1
                or 'Active' in values and values['Active']['amount']==0
                or 'PCON' in values and values['PCON']['amount']!=100):
            raise ValueError('PERIOD_NCI_METHOD_UNSUPPORTED')
        lineage.append({'periodId':period['period_member_id'],'calendarChangeId':period['change_id'],
            'calendarRevision':period['last_revision'],'ownership':{key:{'amount':format(value['amount'],'.8f'),
                'changeId':value['change_id'],'lastRevision':value['last_revision']} for key,value in values.items()},
            'pconFallback':'PCON' not in values})
    result=split_basis(args['basisAmount'],args['ownershipPercent'])
    return {**result,'function':FUNCTION,'candidateCoreVersion':CORE_VERSION,
        'policyId':draft['policyId'],'policyVersion':draft['version'],'policyFamily':draft['family'],
        'draftDigest':draft['draftDigest'],'selectionDigest':draft['selectionDigest'],
        'policyRevision':state['policy_revision'],'observedCommitRevision':state['commit_revision'],
        'basisKind':args['basisKind'],'basisEligibility':'CallerConfirmedUnverified',
        'relationshipId':args['relationshipId'],'parentEntityId':placement['parent_member_id'],
        'childEntityId':placement['child_member_id'],'periodSources':lineage,
        'reviewStatus':'DraftUnreviewed','publicationSupported':False,
        'requiredBeforePosting':['approved period-specific variant and independent accounting fixtures',
            'eligible operational source/account and generation pins','presentation targets and balanced attribution workflow']}


class PostgresPeriodNciInspector:
    def __init__(self,dsn,*,identity):
        if not isinstance(dsn,str) or not dsn: raise ValueError('Runtime DSN required')
        if not isinstance(identity,VerifiedIdentity): raise ValueError('Verified identity required')
        self.dsn,self.identity=dsn,identity

    def inspect(self,scope,program):
        args,policy=parse_program(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'read', function=FUNCTION)
                state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None: raise ValueError('APPLICATION_UNAVAILABLE')
                return evaluate_in_transaction(db,scope,args,policy,state)
