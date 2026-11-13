"""Explicit owner-declared period basis and validated published contribution.

A policy approval is not an account-purpose declaration. This layer binds both
and reads actual full-grain pre-NCI generations. It never posts attribution.
"""
from datetime import date
from decimal import Decimal, localcontext
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import Coordinate, NumericCell
from .postgres_jobs import _canonical_digest
from .postgres_period_policy_cases import DOMAIN, PostgresPeriodPolicyCases
from .postgres_period_policy_governance import (
    PostgresPeriodPolicyGovernance, _load, _latest, _artifacts)
from .postgres_period_nci import FUNCTION as CANDIDATE, parse_program, evaluate_in_transaction
from .postgres_calculation_status import published_translation_status
from .postgres_consolidation_translated import decode_translated_full
from .postgres_source_batch import PostgresSourceBatch
from .postgres_consolidation_aggregate import (
    decode_full_aggregate, validate_full_aggregate, supported_full_compiler,
    FUNCTIONAL_SOURCE_LAYERS)
from .consolidation_contribution_input import (
    COMPILER as CERTIFIED_COMPILER, PLAN_DIGEST as CERTIFIED_PLAN_DIGEST,
    compile_full_contribution_input)
from .postgres_contribution_input import AUTH_FUNCTION as CERTIFIED_FUNCTION


DEFINE='consolidation.nci.period.basis.define'
REVOKE='consolidation.nci.period.basis.revoke'
READ='consolidation.nci.period.basis.read'
INSPECT='consolidation.nci.period.source.inspect'
VERSION='period-nci-published-basis-v1'
LOCAL_VERSION='period-nci-local-published-basis-v2'
CERTIFIED_VERSION='period-nci-certified-full-basis-v4'
CERTIFIED_KIND='published_certified_full_contribution'
CERTIFIED_CONTRACT='owner_declared_certified_full_contribution_v1'
TYPED_FULL_VERSION='period-nci-typed-full-basis-v7'
TYPED_FULL_KIND='published_typed_full_contribution'
TYPED_FULL_CONTRACT='owner_declared_typed_full_contribution_v1'
IC_TYPED_FULL_VERSION='period-nci-ic-adjusted-typed-full-basis-v8'
IC_TYPED_FULL_KIND='published_ic_adjusted_typed_full_contribution'
IC_TYPED_FULL_CONTRACT='owner_declared_ic_adjusted_typed_full_contribution_v1'
from .postgres_period_nci_composition import VERSION as COMPOSED_VERSION, KIND as COMPOSED_KIND

SOURCE_VERSIONS={COMPOSED_KIND:COMPOSED_VERSION,'published_translated_full_contribution':VERSION,
    'published_local_full_contribution':LOCAL_VERSION,CERTIFIED_KIND:CERTIFIED_VERSION,
    TYPED_FULL_KIND:TYPED_FULL_VERSION,
    IC_TYPED_FULL_KIND:IC_TYPED_FULL_VERSION}
READS=frozenset((READ,INSPECT))
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_HASH=re.compile(r'[0-9a-f]{64}\Z')
_JOB=re.compile(r'[0-9a-f]{32}\Z')
_TYPES={'net_assets_at_period_end':frozenset(('BALANCE','ASSET','LIABILITY','BALANCERECURRING')),
        'period_profit_ytd':frozenset(('FLOW','REVENUE','EXPENSE'))}
_TIME={'net_assets_at_period_end':'as_of_period_end','period_profit_ytd':'year_to_date'}


def _matches(pattern,value):return isinstance(value,str) and pattern.fullmatch(value) is not None

def _id(value):
    return isinstance(value,str) and 1<=len(value)<=200 and value==value.strip() and '\x00' not in value


def compile_program(raw):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or not isinstance(raw['function'],str) or raw['function'] not in (DEFINE,REVOKE,READ,INSPECT)
            or not isinstance(raw['arguments'],dict)):
        raise ValueError('PERIOD_BASIS_PROGRAM_INVALID')
    function,args=raw['function'],dict(raw['arguments'])
    revisions={'expectedPolicyRevision','expectedCommitRevision'}
    if function==DEFINE:
        fields={'variantKey','activationId','effectiveOn','basisKind','accountMemberId','currencyMemberId',
            'viewMemberId','timeBasis','sourceKind','evidenceArtifactIds','rationale','expectedMetadataRevision'}|revisions
        composed=args.get('sourceKind')==COMPOSED_KIND
        if composed:fields=fields|{'components'}
        valid=(set(args)==fields and _matches(_HASH,args['variantKey']) and _matches(_KEY,args['activationId'])
            and isinstance(args['basisKind'],str) and args['basisKind'] in _TIME
            and args['timeBasis']==_TIME[args['basisKind']]
            and isinstance(args['sourceKind'],str) and args['sourceKind'] in SOURCE_VERSIONS
            and all(_id(args[key]) for key in ('accountMemberId','currencyMemberId'))
            and (args['viewMemberId'] is None or _id(args['viewMemberId']))
            and isinstance(args['evidenceArtifactIds'],list) and 1<=len(args['evidenceArtifactIds'])<=10
            and all(_matches(_KEY,item) for item in args['evidenceArtifactIds'])
            and len(set(args['evidenceArtifactIds']))==len(args['evidenceArtifactIds']))
        if valid and composed:
            from .postgres_period_nci_composition import components
            args['components']=components(args['components'])
        if valid:
            try:valid=isinstance(args['effectiveOn'],str) and date.fromisoformat(args['effectiveOn']).isoformat()==args['effectiveOn']
            except ValueError:valid=False
        counters=revisions|{'expectedMetadataRevision'};reason='rationale'
    elif function==REVOKE:
        valid=set(args)=={'definitionId','expectedDefinitionDigest','reason'}|revisions
        valid=valid and _matches(_KEY,args['definitionId']) and _matches(_HASH,args['expectedDefinitionDigest'])
        counters=revisions;reason='reason'
    elif function==READ:
        valid=set(args)=={'definitionId'} and _matches(_KEY,args['definitionId'])
        counters=set();reason=None
    else:
        fields={'definitionId','expectedDefinitionDigest','relationshipId','parentMembers','expectedPolicyRevision'}
        valid=(set(args) in (fields|{'source'},fields|{'sources'})
            and _matches(_KEY,args['definitionId']) and _matches(_HASH,args['expectedDefinitionDigest'])
            and _id(args['relationshipId']))
        if valid and 'sources' in args:
            pins=args['sources']
            valid=(isinstance(pins,list) and 2<=len(pins)<=16 and all(isinstance(item,dict)
                and set(item)=={'definitionId','source'} and _matches(_KEY,item['definitionId']) for item in pins))
            if valid:
                valid=len({item['definitionId'] for item in pins})==len(pins)
                args['sources']=sorted([{'definitionId':item['definitionId'],'source':dict(item['source'])}
                    for item in pins if isinstance(item['source'],dict)],key=lambda item:item['definitionId'])
                valid=valid and len(args['sources'])==len(pins)
            sources=[item['source'] for item in args['sources']] if valid else []
        else:sources=[args.get('source')]
        if valid:
            valid=all(isinstance(pin,dict) and set(pin)=={'resultKey','generationId','publishedRevision'}
                and _matches(_KEY,pin['resultKey']) and _matches(_JOB,pin['generationId'])
                and type(pin['publishedRevision']) is int and pin['publishedRevision']>0 for pin in sources)
        if valid:
            try:
                args['parentMembers']=dict(Coordinate.from_mapping(args['parentMembers']).members)
                valid=1<=len(args['parentMembers'])<=32 and all(_id(axis) and _id(member) for axis,member in args['parentMembers'].items())
            except (TypeError,ValueError,AttributeError):valid=False
        counters={'expectedPolicyRevision'};reason=None
    if (not valid or any(type(args[key]) is not int or args[key]<0 for key in counters)
            or reason is not None and (not isinstance(args[reason],str) or not 10<=len(args[reason])<=2000
                or args[reason]!=args[reason].strip() or '\x00' in args[reason])):
        raise ValueError('PERIOD_BASIS_ARGUMENTS_INVALID')
    if function==DEFINE:args['evidenceArtifactIds']=sorted(args['evidenceArtifactIds'])
    return function,args


def _roles(db,scope):
    rows=db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active' ''',
        (scope.workspace_id,scope.application_id)).fetchall()
    roles={};axes=[]
    for row in rows:
        if row['model_role'] and row['model_role']!='Custom':
            if row['model_role'] in roles:raise ValueError('PERIOD_BASIS_MODEL_AMBIGUOUS')
            roles[row['model_role']]=row['dimension_id']
        if row['model_role']!='Currency':axes.append(row['dimension_id'])
    if not {'Account','Currency','Entity','Scenario','Year','Period'}<=set(roles):
        raise ValueError('PERIOD_BASIS_FINANCIAL_ROLES_REQUIRED')
    return roles,sorted(axes)


def _members(db,scope,args,basis):
    roles,axes=_roles(db,scope)
    view=args['viewMemberId']
    if ('View' in roles)!=(view is not None):raise ValueError('PERIOD_BASIS_VIEW_DECLARATION_REQUIRED')
    result={}
    for role,member in [('Account',args['accountMemberId']),('Currency',args['currencyMemberId'])]+([('View',view)] if view else []):
        row=db.execute('''SELECT financial_account_type AS account_type FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND member_id=%s AND status='Active' ''',
            (scope.workspace_id,scope.application_id,roles[role],member)).fetchone()
        if row is None:raise ValueError('PERIOD_BASIS_MEMBER_UNAVAILABLE')
        result[role]=member
        if role=='Account' and row['account_type'] not in _TYPES[basis]:raise ValueError('PERIOD_BASIS_ACCOUNT_TYPE_UNSUPPORTED')
    return {'roles':roles,'factAxes':axes,'members':result}


def _definition(db,scope,definition_id,digest=None):
    row=_load(db,scope,definition_id,(DEFINE,))
    if (_canonical_digest(row['manifest'])!=row['definitionDigest']
            or row['manifest']['basisCoreVersion'] not in SOURCE_VERSIONS.values()
            or row['manifest']['basisCoreVersion']!=SOURCE_VERSIONS.get(row['manifest']['declaration'].get('sourceKind'))):
        raise ValueError('PERIOD_BASIS_DEFINITION_CORRUPT_OR_UNSUPPORTED')
    if digest is not None and row['definitionDigest']!=digest:raise ValueError('PERIOD_BASIS_DEFINITION_DIGEST_MISMATCH')
    return row


def validate_certified_full_source(row,pin,decl,roles,actual_currency):
    """Validate one immutable certified-Full generation without trusting its receipt alone."""
    try:plan=compile_full_contribution_input(row['normalized_program'])
    except (TypeError,KeyError,ValueError) as error:raise ValueError('PERIOD_BASIS_CERTIFIED_FULL_REQUIRED') from error
    doc=plan.document;receipt=row['job_result']
    if (row['function_name']!=CERTIFIED_FUNCTION or row['compiler_version']!=CERTIFIED_COMPILER
            or row['plan_digest']!=CERTIFIED_PLAN_DIGEST or row['program_digest']!=plan.digest
            or not isinstance(receipt,dict) or receipt.get('programDigest')!=plan.digest
            or receipt.get('generationId')!=pin['generationId'] or receipt.get('resultKey')!=pin['resultKey']
            or receipt.get('relationshipId')!=doc['relationshipId']
            or receipt.get('targetMembers')!=doc['targetMembers']
            or receipt.get('amount')!=format(row['amount'],'.8f')
            or actual_currency!=decl['currencyMemberId']):
        raise ValueError('PERIOD_BASIS_CERTIFIED_FULL_REQUIRED')
    return plan,receipt.get('accountingStage'),[{
        'relationshipId':doc['relationshipId'],'childEntityId':receipt.get('childEntityId'),
        'amount':receipt.get('amount'),'pown':receipt.get('pown'),
        'sourceChangeId':row['source_change_id']}]


def validated_full_source(db,scope,args,state,spec,roles):
    """Read and reconcile one whole Full generation, reusable across placements."""
    parent=args['parentMembers'];decl=spec['declaration']
    pin=args['source'];keys=(scope.workspace_id,scope.application_id)
    rows=db.execute('''SELECT p.source_operation_id AS current_generation_id,p.committed_revision AS current_published_revision,
        p.source_function AS function_name,p.result_key,p.row_count,
        j.status AS job_status,j.result AS job_result,
        j.normalized_program,j.compiler_version,j.plan_digest,j.program_digest,j.expected_metadata_revision,j.expected_data_revision,j.expected_policy_revision,
        c.members,r.amount,r.source_change_id
        FROM epm.calculation_result_state p
        JOIN epm.job j ON j.workspace_id=p.workspace_id
          AND j.application_id=p.application_id AND j.job_id=p.source_operation_id
        JOIN epm.calculation_result_current r ON r.workspace_id=p.workspace_id
          AND r.application_id=p.application_id AND r.result_key=p.result_key
        JOIN epm.coordinate c ON c.workspace_id=r.workspace_id AND c.application_id=r.application_id AND c.coordinate_id=r.coordinate_id
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s LIMIT 2''',(*keys,pin['resultKey'])).fetchall()
    if len(rows)!=1:raise ValueError('PERIOD_BASIS_SINGLE_PUBLISHED_FULL_REQUIRED')
    row=rows[0]
    if (row['current_generation_id']!=pin['generationId'] or row['current_published_revision']!=pin['publishedRevision']
            or any(row['expected_'+kind+'_revision']!=state[kind+'_revision'] for kind in ('metadata','data','policy'))):
        raise ValueError('STALE_PUBLISHED_INPUT')
    receipt=row['job_result']
    certified=spec['basisCoreVersion']==CERTIFIED_VERSION
    local=spec['basisCoreVersion']==LOCAL_VERSION
    if certified:
        currency=db.execute('''SELECT entity_default_currency_member_id AS currency_id
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND member_id=%s AND status='Active' ''',
            (*keys,roles['Entity'],parent[roles['Entity']])).fetchone()
        plan,stage,sources=validate_certified_full_source(row,pin,decl,roles,
            currency['currency_id'] if currency else None)
        doc=plan.document;unit_matches=context_matches=True
    elif local:
        try:plan=decode_full_aggregate(row['normalized_program'])
        except (TypeError,KeyError,ValueError) as error:raise ValueError('PERIOD_BASIS_LOCAL_FULL_REQUIRED') from error
        if (row['function_name']!='consolidation.full.aggregate'
                or plan.source_layer not in FUNCTIONAL_SOURCE_LAYERS
                or not supported_full_compiler(row['compiler_version'],row['plan_digest'],row['normalized_program'])
                or row['program_digest']!=_canonical_digest(row['normalized_program'])):
            raise ValueError('PERIOD_BASIS_LOCAL_FULL_REQUIRED')
        stage=plan.normalized_program['accountingStage']
        # Reconcile live facts, ownership and recursive published children under
        # the caller's state lock. A claimed alignment Boolean is not unit proof.
        actual=validate_full_aggregate(db,scope,plan)
        currency=db.execute('''SELECT entity_default_currency_member_id AS currency_id
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND member_id=%s AND status='Active' ''',
            (*keys,roles['Entity'],parent[roles['Entity']])).fetchone()
        unit_matches=currency is not None and currency['currency_id']==decl['currencyMemberId']
        context_matches=(isinstance(receipt,dict) and actual['sources']==receipt.get('sources')
            and actual['sourceChangeId']==row['source_change_id'] and actual['amount']==row['amount'])
    else:
        try:plan=decode_translated_full(row['normalized_program'])
        except (TypeError,KeyError,ValueError) as error:raise ValueError('PERIOD_BASIS_TRANSLATED_FULL_REQUIRED') from error
        stage=plan.accounting_stage
        unit_matches=(plan.target_currency_member_id==decl['currencyMemberId']
            and isinstance(receipt,dict) and receipt.get('targetCurrencyMemberId')==decl['currencyMemberId'])
        context_matches=row['function_name']=='consolidation.full.translated.aggregate'
        status=published_translation_status(db,scope,row['normalized_program'])
        if not status['matchesAtRead']:raise ValueError('STALE_PUBLISHED_INPUT')
    expected_parent=doc['targetMembers'] if certified else dict(plan.parent_members)
    if (not context_matches or not unit_matches or row['result_key']!=pin['resultKey']
            or row['row_count']!=1 or row['job_status']!='published' or not isinstance(receipt,dict)
            or row['members']!=parent or expected_parent!=parent
            or (receipt.get('targetMembers') if certified else receipt.get('parentMembers'))!=parent
            or receipt.get('accountingStage')!=stage
            or not certified and receipt.get('sourceLayer','translated_full')!=plan.source_layer
            or receipt.get('accountingPolicyStatus')!='Unreviewed'
            or not certified and (not isinstance(receipt.get('sources'),list) or not 1<=len(receipt['sources'])<=201)):
        raise ValueError('PERIOD_BASIS_SOURCE_CONTEXT_MISMATCH')
    if not certified:sources=receipt['sources']
    try:
        with localcontext() as precision:
            precision.prec=80
            total=sum((Decimal(item['amount']) for item in sources),Decimal(0))
        NumericCell(True,total,'')
    except (TypeError,KeyError,ArithmeticError,ValueError) as error:raise ValueError('PERIOD_BASIS_SOURCE_RECONCILIATION_FAILED') from error
    if total!=row['amount'] or receipt.get('amount')!=format(total,'.8f') or (not certified and receipt.get('sourceChangeId')!=row['source_change_id']):
        raise ValueError('PERIOD_BASIS_SOURCE_RECONCILIATION_FAILED')
    return row,receipt,plan,stage


def validated_typed_full_source(db,scope,args,state,spec,roles):
    """Resolve one current Currency-typed Full contribution without a Currency axis."""
    from .postgres_consolidation_full import (TYPED_FUNCTION,TYPED_COMPILER,
        TYPED_PLAN_DIGEST,TYPED_IC_COMPILER,TYPED_IC_PLAN_DIGEST,
        decode_typed_full_contribution,
        typed_full_context_status)
    ic_adjusted=spec.get('basisCoreVersion')==IC_TYPED_FULL_VERSION
    expected_compiler=(TYPED_IC_COMPILER if ic_adjusted else TYPED_COMPILER)
    expected_plan=(TYPED_IC_PLAN_DIGEST if ic_adjusted else TYPED_PLAN_DIGEST)
    expected_stage=('pre_nci_untranslated_ic_adjusted' if ic_adjusted else
                    'pre_nci_untranslated_uneliminated')
    pin=args['source'];decl=spec['declaration'];keys=(scope.workspace_id,scope.application_id)
    rows=db.execute('''SELECT p.source_operation_id AS current_generation_id,
      p.committed_revision AS current_published_revision,
      p.source_function AS function_name,p.result_key,p.row_count,
      j.status AS job_status,j.result AS job_result,
      j.normalized_program,j.compiler_version,j.plan_digest,j.program_digest,
      j.expected_metadata_revision,j.expected_data_revision,
      j.expected_policy_revision,c.members,r.amount,r.source_amount,
      r.source_change_id,r.source_evidence_digest,
      r.output_unit_currency_dimension_id,
      r.output_unit_currency_member_id,r.source_lookup_lineage
      FROM epm.calculation_result_state p
      JOIN epm.job j ON j.workspace_id=p.workspace_id
       AND j.application_id=p.application_id AND j.job_id=p.source_operation_id
      JOIN epm.calculation_unit_result_current r ON r.workspace_id=p.workspace_id
       AND r.application_id=p.application_id AND r.result_key=p.result_key
      JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
       AND c.application_id=r.application_id AND c.coordinate_id=r.coordinate_id
      WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s
      ORDER BY c.series_key LIMIT 2''',(*keys,pin['resultKey'])).fetchall()
    if len(rows)!=1:raise ValueError('PERIOD_BASIS_TYPED_FULL_REQUIRED')
    row=rows[0]
    try:plan=decode_typed_full_contribution(row['normalized_program'])
    except (TypeError,KeyError,ValueError) as error:
        raise ValueError('PERIOD_BASIS_TYPED_FULL_REQUIRED') from error
    receipt=row['job_result'];parent=args['parentMembers']
    context=typed_full_context_status(db,scope,row['normalized_program'],receipt)
    if (row['current_generation_id']!=pin['generationId']
        or row['current_published_revision']!=pin['publishedRevision']
        or row['function_name']!=TYPED_FUNCTION
        or row['compiler_version']!=expected_compiler
        or row['plan_digest']!=expected_plan
        or row['program_digest']!=_canonical_digest(row['normalized_program'])
        or row['job_status']!='published' or row['row_count']!=1
        or not isinstance(receipt,dict) or receipt.get('function')!=TYPED_FUNCTION
        or receipt.get('targetMembers')!=parent or row['members']!=parent
        or roles['Currency'] in parent
        or row['output_unit_currency_dimension_id']!=roles['Currency']
        or row['output_unit_currency_member_id']!=decl['currencyMemberId']
        or receipt.get('outputUnit')!={'dimensionId':roles['Currency'],
                                      'memberId':decl['currencyMemberId']}
        or receipt.get('amount')!=format(row['amount'],'.8f')
        or receipt.get('sourceChangeId')!=row['source_change_id']
        or receipt.get('relationshipId')!=args['relationshipId']
        or receipt.get('accountingStage')!=expected_stage
        or ic_adjusted and (plan.source_layer!='raw_plus_ic_elimination'
            or not plan.ic_result_state_token
            or receipt.get('sourceLayer')!='raw_plus_ic_elimination'
            or receipt.get('icResultStateToken')!=plan.ic_result_state_token
            or row['source_change_id'] is not None
            or not row['source_lookup_lineage']
            or row['source_evidence_digest']!=
                _canonical_digest(row['source_lookup_lineage'])
            or receipt.get('sourceLookupLineage')!=row['source_lookup_lineage']
            or receipt.get('sourceEvidenceDigest')!=
                row['source_evidence_digest'])
        or not ic_adjusted and getattr(plan,'source_layer','raw')!='raw'
        or receipt.get('accountingPolicyStatus')!='Unreviewed'
        or any(row['expected_'+kind+'_revision']!=state[kind+'_revision']
               for kind in ('metadata','data','policy'))
        or not context.get('matchesAtRead')):
        raise ValueError('PERIOD_BASIS_TYPED_FULL_CONTEXT_MISMATCH')
    return row,receipt,plan,context


def inspect_in_transaction(db,scope,args,state):
    """Caller holds workspace/current authority/state locks; no separate snapshot."""
    definition=_definition(db,scope,args['definitionId'],args['expectedDefinitionDigest'])
    if definition['manifest']['basisCoreVersion']==COMPOSED_VERSION:
        from .postgres_period_nci_composition import inspect_composition
        return inspect_composition(db,scope,args,state,definition)
    if 'sources' in args:raise ValueError('PERIOD_BASIS_SINGLE_SOURCE_REQUIRED')
    if _latest(db,scope,REVOKE,args['definitionId']):raise ValueError('PERIOD_BASIS_REVOKED')
    spec=definition['manifest'];decl=spec['declaration']
    metadata=_members(db,scope,decl,decl['basisKind'])
    if metadata!=spec['metadataBinding'] or state['metadata_revision']!=spec['metadataRevision']:
        raise ValueError('PERIOD_BASIS_METADATA_CHANGED')
    if state['policy_revision']!=args['expectedPolicyRevision']:raise ValueError('STALE_PERIOD_BASIS_POLICY_REVISION')
    parent=args['parentMembers'];roles=metadata['roles']
    if (set(parent)!=set(metadata['factAxes']) or parent.get(roles['Account'])!=decl['accountMemberId']
            or 'View' in roles and parent.get(roles['View'])!=decl['viewMemberId']):
        raise ValueError('PERIOD_BASIS_SOURCE_GRAIN_OR_ACCOUNT_MISMATCH')
    PostgresSourceBatch._check_scope_members(db,scope,parent)
    pin=args['source'];keys=(scope.workspace_id,scope.application_id)
    typed=spec['basisCoreVersion'] in (TYPED_FULL_VERSION,IC_TYPED_FULL_VERSION)
    if typed:
        row,receipt,plan,typed_context=validated_typed_full_source(
            db,scope,args,state,spec,roles)
        stage=receipt['accountingStage']
    else:
        row,receipt,plan,stage=validated_full_source(db,scope,args,state,spec,roles)
    sources=([{'relationshipId':plan.document['relationshipId'],
        'childEntityId':receipt['childEntityId'],'amount':receipt['amount'],
        'pown':receipt['pown'],'sourceChangeId':row['source_change_id']}]
        if spec['basisCoreVersion']==CERTIFIED_VERSION else
        [{'relationshipId':receipt['relationshipId'],
          'childEntityId':receipt['childEntityId'],'amount':receipt['amount'],
          'pown':receipt['pown'],'sourceChangeId':receipt['sourceChangeId']}]
        if typed else receipt['sources'])
    selected=[item for item in sources if item.get('relationshipId')==args['relationshipId'] and not item.get('parentSource')]
    if len(selected)!=1:raise ValueError('PERIOD_BASIS_DIRECT_RELATIONSHIP_REQUIRED')
    source=selected[0]
    calendar=db.execute('''SELECT ends_before FROM epm.calendar_period_current WHERE workspace_id=%s
        AND application_id=%s AND year_member_id=%s AND period_member_id=%s''',
        (*keys,parent[roles['Year']],parent[roles['Period']])).fetchone()
    if calendar is None:raise ValueError('PERIOD_BASIS_CALENDAR_REQUIRED')
    from datetime import timedelta
    effective=(calendar['ends_before']-timedelta(days=1)).isoformat()
    active=PostgresPeriodPolicyGovernance.resolve_in_transaction(db,scope,{
        'variantKey':decl['variantKey'],'effectiveOn':effective,'expectedPolicyRevision':state['policy_revision']},state)
    if active['activationId']!=decl['activationId'] or active['policyBindingDigest']!=spec['policyBindingDigest']:
        raise ValueError('PERIOD_BASIS_ACTIVATION_CHANGED')
    binding=active['policyBinding']
    candidate={'languageVersion':2,'function':CANDIDATE,'arguments':{
        'policyId':binding['policyId'],'effectiveOn':effective,'selections':binding['selections'],
        'expectedPolicyRevision':state['policy_revision'],'relationshipId':args['relationshipId'],
        'scenarioId':parent[roles['Scenario']],'yearId':parent[roles['Year']],'periodId':parent[roles['Period']],
        'method':'Full','controlConfirmed':True,'basisKind':decl['basisKind'],'basisEligibilityConfirmed':True,
        'basisAmount':source['amount'],'ownershipPercent':source['pown']}}
    parsed,policy=parse_program(candidate)
    measured=evaluate_in_transaction(db,scope,parsed,policy,state)
    if measured['parentEntityId']!=parent[roles['Entity']] or measured['childEntityId']!=source.get('childEntityId'):
        raise ValueError('PERIOD_BASIS_DIRECT_RELATIONSHIP_REQUIRED')
    evidence={'basisCoreVersion':spec['basisCoreVersion'],'definitionId':args['definitionId'],'definitionDigest':definition['definitionDigest'],
        'activationId':active['activationId'],'policyBindingDigest':active['policyBindingDigest'],
        'basisKind':decl['basisKind'],'timeBasis':decl['timeBasis'],'source':pin,'sourceChangeId':row['source_change_id'],
        'sourceAccountingStage':stage,'parentMembers':parent,'currencyMemberId':decl['currencyMemberId'],
        'relationshipId':args['relationshipId'],'contribution':source,'periodSources':measured['periodSources'],
        'basisAmount':measured['basisAmount'],'ownershipPercent':measured['ownershipPercent'],
        'candidateNciShare':measured['candidateNciShare'],'candidateControllingShare':measured['candidateControllingShare'],
        'metadataRevision':state['metadata_revision'],'dataRevision':state['data_revision'],
        'policyRevision':state['policy_revision'],'observedCommitRevision':state['commit_revision']}
    if typed:
        evidence.update(outputUnit=receipt['outputUnit'],
            sourceLookupLineage=row['source_lookup_lineage'],
            sourceContextStatus=typed_context)
    return {**evidence,'sourceEvidenceDigest':_canonical_digest(evidence),'operationalSourceValidated':True,
        'basisEligibility':'OwnerDeclaredPublishedContributionValidated','accountingMeaning':'WorkspaceOwnerDeclared',
        'independentAccountingCertification':False,'publicationSupported':False}


class PostgresPeriodNciBasis:
    def __init__(self,dsn,*,identity):
        self.cases=PostgresPeriodPolicyCases(dsn,identity=identity)
        self.dsn,self.identity=dsn,identity

    @staticmethod
    def catalog():
        common={'previewRequired':False,'workClass':'short'}
        return {
            DEFINE:{**common,'mode':'atomic_write','permission':'workspace_admin','idempotencyRequired':True,
                'arguments':{'variantKey':'approved variant SHA256','activationId':'exact active event','effectiveOn':'ISO date in active interval',
                    'basisKind':'approved basis kind','accountMemberId':'explicit leaf basis account','currencyMemberId':'consolidation currency',
                    'viewMemberId':'explicit YTD/snapshot view or null without View axis','timeBasis':'year_to_date or as_of_period_end',
                    'sourceKind':'published_translated_full_contribution, published_local_full_contribution, published_certified_full_contribution, published_typed_full_contribution, published_ic_adjusted_typed_full_contribution or published_composed_full_contribution','components':'composed kind only: 2–16 unique leaf definitionId/digest/sign(+1 or -1)', 'evidenceArtifactIds':'1–10 captured artifacts','rationale':'owner accounting-purpose declaration',
                    'expectedMetadataRevision':'current integer','expectedPolicyRevision':'current integer','expectedCommitRevision':'current integer'},
                'result':'immutable owner-declared source definition; no posting'},
            REVOKE:{**common,'mode':'atomic_write','permission':'workspace_admin','idempotencyRequired':True,
                'arguments':{'definitionId':'exact definition operation ID','expectedDefinitionDigest':'exact SHA256','reason':'explicit reason',
                    'expectedPolicyRevision':'current integer','expectedCommitRevision':'current integer'},'result':'immutable revocation; history preserved'},
            READ:{**common,'mode':'read_only','permission':'read','idempotencyRequired':False,
                'arguments':{'definitionId':'immutable scoped definition ID'},'result':'definition plus separate current revocation'},
            INSPECT:{**common,'mode':'read_only','permission':'read','idempotencyRequired':False,
                'arguments':{'definitionId':'immutable scoped definition ID','expectedDefinitionDigest':'exact SHA256',
                    'source':'single-kind resultKey/generationId/publishedRevision','sources':'composed kind only: exact component definitionId/source pins','relationshipId':'direct contribution relationship',
                    'parentMembers':'exact complete published output grain','expectedPolicyRevision':'current integer'},
                'result':'validated actual contribution and attribution candidate; this read has no effects and the separate period-NCI publisher revalidates the same source contract',
                'operationalPublication':{
                    'function':'consolidation.nci.period.publish',
                    'boundary':'separate previewed durable publication requires the active compatible period policy, current immutable basis definition, exact source evidence and target accounts'}}}

    def execute(self,scope,program,*,idempotency_key):
        function,args=compile_program(program)
        if function not in (DEFINE,REVOKE) or not _matches(_KEY,idempotency_key):raise ValueError('PERIOD_BASIS_WRITE_OR_KEY_INVALID')
        digest=_canonical_digest({'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],'function':function,'arguments':args})
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self.cases._open(db,scope,function,'workspace_admin',write=True)
                old=db.execute('''SELECT command_digest,result FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',(scope.workspace_id,scope.application_id,idempotency_key)).fetchone()
                if old:
                    if old['command_digest']!=digest:raise ValueError('IDEMPOTENCY_KEY_REUSED')
                    return old['result']
                if state['processing_mode']!='Active' or state['application_status']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(state[kind+'_revision']!=args['expected'+kind.title()+'Revision'] for kind in ('policy','commit')):
                    raise ValueError('STALE_PERIOD_BASIS_REVISION')
                if function==DEFINE:
                    if state['metadata_revision']!=args['expectedMetadataRevision']:raise ValueError('STALE_PERIOD_BASIS_METADATA_REVISION')
                    active=PostgresPeriodPolicyGovernance.resolve_in_transaction(db,scope,{
                        'variantKey':args['variantKey'],'effectiveOn':args['effectiveOn'],'expectedPolicyRevision':state['policy_revision']},state)
                    if active['activationId']!=args['activationId'] or active['policyBinding']['basisKind']!=args['basisKind']:
                        raise ValueError('PERIOD_BASIS_APPROVED_VARIANT_MISMATCH')
                    metadata=_members(db,scope,args,args['basisKind'])
                    roles=metadata['roles']
                    if db.execute('''SELECT 1 FROM epm.relationship WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND parent_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
                        (scope.workspace_id,scope.application_id,roles['Account'],args['accountMemberId'])).fetchone():
                        raise ValueError('PERIOD_BASIS_LEAF_ACCOUNT_REQUIRED')
                    artifacts=_artifacts(db,scope,args['evidenceArtifactIds'])
                    manifest={'basisCoreVersion':SOURCE_VERSIONS[args['sourceKind']],'policyDomain':DOMAIN,'workspaceId':scope.workspace_id,
                        'applicationId':scope.application_id,'declaration':{key:value for key,value in args.items() if not key.startswith('expected')},
                        'metadataBinding':metadata,'metadataRevision':state['metadata_revision'],
                        'policyBindingDigest':active['policyBindingDigest'],
                        'evidence':[{key:item[key] for key in ('artifact_id','source_ref','source_version','content_sha256','content_bytes')}
                            for _,item in sorted(artifacts.items())]}
                    if args['sourceKind']==COMPOSED_KIND:
                        from .postgres_period_nci_composition import bind_components
                        manifest['componentBindings']=bind_components(db,scope,args,state,metadata,active['policyBindingDigest'])
                    payload={'manifest':manifest,'definitionDigest':_canonical_digest(manifest),'status':'OwnerDeclared'}
                else:
                    definition=_definition(db,scope,args['definitionId'],args['expectedDefinitionDigest'])
                    if _latest(db,scope,REVOKE,args['definitionId']):raise ValueError('PERIOD_BASIS_ALREADY_REVOKED')
                    payload={'bundleOperationId':args['definitionId'],'definitionId':args['definitionId'],
                        'definitionDigest':definition['definitionDigest'],'reason':args['reason'],'status':'Revoked'}
                actor={'issuer':self.identity.issuer,'subjectId':self.identity.subject_id}
                result={'function':function,'policyDomain':DOMAIN,'operationId':idempotency_key,'actor':actor,**payload,
                    'policyRevision':state['policy_revision']+1,'committedRevision':state['commit_revision']+1,'publicationSupported':False}
                from .postgres_calculation_impact import object_impact
                definition_id=(idempotency_key if function==DEFINE
                    else args['definitionId'])
                impact=object_impact(source_kind='definition',
                    operation_id=idempotency_key,
                    causal_revision=result['committedRevision'],
                    domain='definition',object_type='period-nci-basis',
                    object_id=definition_id,
                    change='activate' if function==DEFINE else 'deactivate',
                    reason='definition_changed',old_presence='unknown',
                    new_presence='present' if function==DEFINE else 'absent')
                result['impactDigest']=impact.digest
                db.execute('''UPDATE epm.application_state SET policy_revision=%s,commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',
                    (result['policyRevision'],result['committedRevision'],scope.workspace_id,scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',(scope.workspace_id,scope.application_id,idempotency_key,digest,
                    _canonical_digest(actor),result['committedRevision'],Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=idempotency_key,impact=impact)
                return result

    def read(self,scope,program):
        function,args=compile_program(program)
        if function not in READS:raise ValueError('PERIOD_BASIS_READ_REQUIRED')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self.cases._open(db,scope,function,'read')
                if function==READ:
                    return {'definition':_definition(db,scope,args['definitionId']),
                        'revocation':_latest(db,scope,REVOKE,args['definitionId']),
                        'policyRevision':state['policy_revision'],'publicationSupported':False}
                return inspect_in_transaction(db,scope,args,state)
