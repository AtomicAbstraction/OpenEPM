"""Durable separate period attribution, never an acquisition offset journal.

All amounts derive from the policy-bound actual-source validator. Published
splits live in sealed calculation generations, not in raw facts or Full input.
"""
from dataclasses import dataclass
from decimal import Decimal, localcontext
import json
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .current_object_contract import require_state_token
from .dimensional_security_policy import AccessKind
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_planning_write_guard import enforce_active_planning_policy
from .postgres_period_nci_basis import (INSPECT, _TYPES, compile_program as compile_source,
    inspect_in_transaction, _id, VERSION, LOCAL_VERSION, CERTIFIED_VERSION,
    CERTIFIED_CONTRACT,TYPED_FULL_VERSION,TYPED_FULL_CONTRACT,
    IC_TYPED_FULL_VERSION,IC_TYPED_FULL_CONTRACT)
from .postgres_period_policy_cases import PostgresPeriodPolicyCases

PUBLISH='consolidation.nci.period.publish'
WITHDRAW='consolidation.nci.period.withdraw'
COMPILER='period-nci-attribution-v1'
STAGE='period_nci_attribution_split'
PLAN_DIGEST=_canonical_digest({'compiler':COMPILER,'stage':STAGE,
    'basis':'owner_declared_current_translated_full_contribution',
    'split':'signed_half_even_nci_owner_residual','outputs':'two_distinct_account_coordinates',
    'withdrawal':'exact_current_generation_empty_tombstone','engine':'postgres_exact_numeric'})
LOCAL_CONTRACT='owner_declared_current_local_functional_full_contribution_v2'
LOCAL_COMPILER='period-nci-attribution-v2'
LOCAL_PLAN_DIGEST=_canonical_digest({'compiler':LOCAL_COMPILER,'stage':STAGE,
    'basis':LOCAL_CONTRACT,'basisCoreVersion':LOCAL_VERSION,
    'split':'signed_half_even_nci_owner_residual','outputs':'two_distinct_account_coordinates',
    'engine':'postgres_exact_numeric'})
CERTIFIED_COMPILER='period-nci-attribution-v6'
CERTIFIED_PLAN_DIGEST=_canonical_digest({'compiler':CERTIFIED_COMPILER,'stage':STAGE,
    'basis':CERTIFIED_CONTRACT,'basisCoreVersion':CERTIFIED_VERSION,
    'source':'sealed_certified_full_contribution','split':'signed_half_even_nci_owner_residual',
    'outputs':'two_distinct_account_coordinates','engine':'postgres_exact_numeric'})
TYPED_FULL_COMPILER='period-nci-attribution-v7-typed-unit'
TYPED_FULL_PLAN_DIGEST=_canonical_digest({'compiler':TYPED_FULL_COMPILER,
    'stage':STAGE,'basis':TYPED_FULL_CONTRACT,
    'basisCoreVersion':TYPED_FULL_VERSION,
    'source':'sealed_typed_full_contribution','currency':'typed_unit_not_axis',
    'split':'signed_half_even_nci_owner_residual',
    'outputs':'two_distinct_typed_unit_account_coordinates',
    'engine':'postgres_exact_numeric'})
IC_TYPED_FULL_COMPILER='period-nci-attribution-v8-ic-adjusted-typed-unit'
IC_TYPED_FULL_PLAN_DIGEST=_canonical_digest({
    'compiler':IC_TYPED_FULL_COMPILER,'stage':STAGE,
    'basis':IC_TYPED_FULL_CONTRACT,'basisCoreVersion':IC_TYPED_FULL_VERSION,
    'source':'sealed_ic_adjusted_typed_full_contribution',
    'currency':'typed_unit_not_axis','icGeneration':'exact_current',
    'split':'signed_half_even_nci_owner_residual',
    'outputs':'two_distinct_typed_unit_account_coordinates',
    'engine':'postgres_exact_numeric'})


from .postgres_period_nci_composition import VERSION as COMPOSED_VERSION, CONTRACT as COMPOSED_CONTRACT
COMPOSED_COMPILER='period-nci-attribution-v3'
COMPOSED_PLAN_DIGEST=_canonical_digest({'compiler':COMPOSED_COMPILER,'stage':STAGE,
    'basis':COMPOSED_CONTRACT,'basisCoreVersion':COMPOSED_VERSION,
    'composition':'exact_signed_sum_before_rounding','outputs':'two_distinct_account_coordinates',
    'engine':'postgres_exact_numeric'})

from .postgres_company_nci import (VERSION as COMPANY_VERSION,CONTRACT as COMPANY_CONTRACT,
    STAGE as COMPANY_STAGE,FUNCTION as COMPANY_INSPECT,compile_program as compile_company,
    inspect_in_transaction as inspect_company)
COMPANY_COMPILER='period-nci-attribution-v4'
COMPANY_PLAN_DIGEST=_canonical_digest({'compiler':COMPANY_COMPILER,'stage':COMPANY_STAGE,
    'basis':COMPANY_CONTRACT,'companyCoreVersion':COMPANY_VERSION,
    'coverage':'all_active_direct_leaf_full_relationships',
    'rounding':'exact_component_sum_then_per_relationship_half_even',
    'ownParent':'explicit_current_component_basis_no_nci',
    'outputs':'two_distinct_company_accounts_no_gross_row','engine':'postgres_exact_numeric'})

from .postgres_lower_company_nci import VERSION as LOWER_COMPANY_VERSION,CONTRACT as LOWER_COMPANY_CONTRACT,STAGE as LOWER_COMPANY_STAGE
LOWER_COMPANY_COMPILER='period-nci-attribution-v5'
LOWER_COMPANY_PLAN_DIGEST=_canonical_digest({'compiler':LOWER_COMPANY_COMPILER,'stage':LOWER_COMPANY_STAGE,
    'basis':LOWER_COMPANY_CONTRACT,'companyCoreVersion':LOWER_COMPANY_VERSION,
    'propagation':'carry_lower_nci_allocate_owner_basis','policy':'explicit_lower_company_election',
    'sources':'current_local_full_and_reconciled_lower_presentations','graphLimit':200,
    'rounding':'half_even_additional_nci_owner_residual','engine':'postgres_exact_numeric'})

def source_contract_for(evidence):
    if evidence.get('companyCoreVersion')==LOWER_COMPANY_VERSION:return LOWER_COMPANY_CONTRACT
    if evidence.get('companyCoreVersion')==COMPANY_VERSION:return COMPANY_CONTRACT
    version=evidence.get('basisCoreVersion')
    if version==VERSION:return None
    if version==LOCAL_VERSION:return LOCAL_CONTRACT
    if version==CERTIFIED_VERSION:return CERTIFIED_CONTRACT
    if version==TYPED_FULL_VERSION:return TYPED_FULL_CONTRACT
    if version==IC_TYPED_FULL_VERSION:return IC_TYPED_FULL_CONTRACT
    if version==COMPOSED_VERSION:return COMPOSED_CONTRACT
    raise ValueError('PERIOD_ATTRIBUTION_SOURCE_CONTRACT_UNSUPPORTED')


def existing_typed_storage_contract(pointer):
    """Seed preliminary validation from an existing typed publication.

    Preview validates the current pointer before it can resolve the replacement
    source.  Preserve only the exact typed storage contract here; the newly
    resolved evidence is still recompiled and checked below.
    """
    if not isinstance(pointer,dict) or not isinstance(pointer.get('result'),dict):
        return None
    contract=pointer['result'].get('sourceContract')
    return contract if contract in (TYPED_FULL_CONTRACT,
                                     IC_TYPED_FULL_CONTRACT) else None


_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_JOB=re.compile(r'[0-9a-f]{32}\Z')
_HASH=re.compile(r'[0-9a-f]{64}\Z')

def _typed_lineage(lineage):
    encoded=json.dumps(lineage,sort_keys=True,ensure_ascii=True,
        separators=(', ',': ')).encode('ascii')
    if len(encoded)>65536:raise ValueError('PERIOD_ATTRIBUTION_LINEAGE_LIMIT')
    return lineage

def _typed_publication_evidence(summary):
    evidence=summary['sourceEvidence'];unit=evidence['outputUnit']
    lineage=_typed_lineage([{
        'kind':'TypedFullNciBasis','source':evidence['source'],
        'relationshipId':evidence['relationshipId'],
        'sourceAmount':evidence['basisAmount'],
        'sourceChangeId':evidence['sourceChangeId'],
        'sourceLookupLineage':evidence['sourceLookupLineage'],
        'sourceContextStatus':evidence['sourceContextStatus'],
        'ownershipPercent':evidence['ownershipPercent'],
        'outputUnit':unit,'sourceDigest':summary['sourceDigest']}])
    return lineage,_canonical_digest(lineage)

def _complete_typed_receipt(result,summary,lineage,lineage_digest,revision):
    evidence=summary['sourceEvidence']
    contract=(source_contract_for(evidence) if evidence.get('basisCoreVersion')
              else TYPED_FULL_CONTRACT)
    result.update(outputUnit=summary['sourceEvidence']['outputUnit'],
        effects='CalculatedGenerationOnly',sourceContract=contract,
        accountingPolicyStatus='Unreviewed',wholeStatementCertified=False,
        publishedRevision=revision,sourceDigest=summary['sourceDigest'],
        sourceEvidenceDigest=lineage_digest,sourceLookupLineage=lineage)
    return result


def _match(pattern,value):return isinstance(value,str) and pattern.fullmatch(value) is not None


@dataclass(frozen=True)
class AttributionPlan:
    function:str
    arguments:dict
    expected_publication_revision:int
    expected_source_digest:str|None
    source_contract:str|None=None

    @property
    def result_key(self):return self.arguments['resultKey']

    @property
    def compiler_version(self):
        return {LOCAL_CONTRACT:LOCAL_COMPILER,CERTIFIED_CONTRACT:CERTIFIED_COMPILER,
            TYPED_FULL_CONTRACT:TYPED_FULL_COMPILER,
            IC_TYPED_FULL_CONTRACT:IC_TYPED_FULL_COMPILER,
            COMPOSED_CONTRACT:COMPOSED_COMPILER,COMPANY_CONTRACT:COMPANY_COMPILER,
            LOWER_COMPANY_CONTRACT:LOWER_COMPANY_COMPILER,None:COMPILER}[self.source_contract]

    @property
    def plan_digest(self):
        return {LOCAL_CONTRACT:LOCAL_PLAN_DIGEST,CERTIFIED_CONTRACT:CERTIFIED_PLAN_DIGEST,
            TYPED_FULL_CONTRACT:TYPED_FULL_PLAN_DIGEST,
            IC_TYPED_FULL_CONTRACT:IC_TYPED_FULL_PLAN_DIGEST,
            COMPOSED_CONTRACT:COMPOSED_PLAN_DIGEST,COMPANY_CONTRACT:COMPANY_PLAN_DIGEST,
            LOWER_COMPANY_CONTRACT:LOWER_COMPANY_PLAN_DIGEST,None:PLAN_DIGEST}[self.source_contract]

    @property
    def accounting_stage(self):return LOWER_COMPANY_STAGE if 'lowerCompanies' in self.arguments else COMPANY_STAGE if 'decisions' in self.arguments else STAGE

    @property
    def normalized_program(self):
        program={'version':2,'function':self.function,'arguments':self.arguments,
            'resultKey':self.result_key,'expectedPublicationRevision':self.expected_publication_revision,
            'expectedSourceDigest':self.expected_source_digest,'accountingStage':self.accounting_stage}
        if self.source_contract is not None:program['sourceContract']=self.source_contract
        return program


def compile_attribution(raw,*,expected_publication_revision,expected_source_digest=None,source_contract=None):
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2
            or not isinstance(raw['function'],str) or raw['function'] not in (PUBLISH,WITHDRAW)
            or not isinstance(raw['arguments'],dict)
            or type(expected_publication_revision) is not int or expected_publication_revision<0
            or source_contract is not None and source_contract not in (LOCAL_CONTRACT,CERTIFIED_CONTRACT,
                TYPED_FULL_CONTRACT,IC_TYPED_FULL_CONTRACT,COMPOSED_CONTRACT,
                COMPANY_CONTRACT,LOWER_COMPANY_CONTRACT)):
        raise ValueError('PERIOD_ATTRIBUTION_PROGRAM_INVALID')
    function=raw['function'];args=raw['arguments']
    if function==PUBLISH:
        fields={'definitionId','expectedDefinitionDigest','parentMembers','expectedPolicyRevision','targetAccounts','resultKey'}
        company='decisions' in args
        fields=fields|({'decisions','includeParentSource'} if company else {'relationshipId'})
        if company and 'lowerCompanies' in args:fields=fields|{'lowerCompanies'}
        if set(args) not in (fields|{'source'},fields|{'sources'}):
            raise ValueError('PERIOD_ATTRIBUTION_ARGUMENTS_INVALID')
        source_args={key:value for key,value in args.items() if key not in ('targetAccounts','resultKey')}
        if company:source=compile_company({'languageVersion':2,'function':COMPANY_INSPECT,'arguments':source_args})
        else:_,source=compile_source({'languageVersion':2,'function':INSPECT,'arguments':source_args})
        targets=args['targetAccounts']
        if (not isinstance(targets,dict) or set(targets)!={'nci','controlling'}
                or not all(_id(value) for value in targets.values()) or targets['nci']==targets['controlling']
                or expected_source_digest is not None and not _match(_HASH,expected_source_digest)):
            raise ValueError('PERIOD_ATTRIBUTION_TARGETS_OR_DIGEST_INVALID')
        args={**source,'targetAccounts':dict(targets),'resultKey':args['resultKey']}
        if args['resultKey'] in ([source['source']['resultKey']] if 'source' in source else [item['source']['resultKey'] for item in source['sources']]):
            raise ValueError('PERIOD_ATTRIBUTION_SOURCE_KEY_REUSE')
    else:
        if (set(args)!={'resultKey','resultStateToken','reason'}
                or not isinstance(args['reason'],str) or not 10<=len(args['reason'])<=2000
                or args['reason']!=args['reason'].strip() or '\x00' in args['reason']
                or expected_source_digest is not None or source_contract is not None):
            raise ValueError('PERIOD_ATTRIBUTION_WITHDRAW_ARGUMENTS_INVALID')
        require_state_token(args['resultStateToken'],
                            error='PERIOD_ATTRIBUTION_WITHDRAW_ARGUMENTS_INVALID')
    if not _match(_KEY,args['resultKey']):raise ValueError('PERIOD_ATTRIBUTION_RESULT_KEY_INVALID')
    # Snapshot nested client dictionaries before any transaction or signature.
    args=json.loads(json.dumps(args,ensure_ascii=False,allow_nan=False))
    return AttributionPlan(function,args,expected_publication_revision,expected_source_digest,source_contract)


def decode_attribution(raw):
    fields={'version','function','arguments','resultKey','expectedPublicationRevision','expectedSourceDigest','accountingStage'}
    if (not isinstance(raw,dict) or set(raw) not in (fields,fields|{'sourceContract'})
            or type(raw['version']) is not int or raw['version']!=2 or raw['accountingStage'] not in (STAGE,COMPANY_STAGE,LOWER_COMPANY_STAGE)):
        raise ValueError('UNSUPPORTED_PERIOD_ATTRIBUTION_JOB_PROGRAM')
    plan=compile_attribution({'languageVersion':2,'function':raw['function'],'arguments':raw['arguments']},
        expected_publication_revision=raw['expectedPublicationRevision'],expected_source_digest=raw['expectedSourceDigest'],
        source_contract=raw.get('sourceContract'))
    if (plan.normalized_program!=raw or plan.function==PUBLISH and not _match(_HASH,plan.expected_source_digest)):
        raise ValueError('NONCANONICAL_PERIOD_ATTRIBUTION_JOB_PROGRAM')
    return plan


def _pointer(db,scope,key):
    return db.execute('''SELECT current_result.state_token,
        current_result.source_operation_id AS generation_id,
        current_result.committed_revision AS published_revision,
        current_result.source_function AS function_name,j.result
        FROM epm.calculation_result_state current_result
        JOIN epm.job j ON j.workspace_id=current_result.workspace_id
          AND j.application_id=current_result.application_id
          AND j.job_id=current_result.source_operation_id
        WHERE current_result.workspace_id=%s
          AND current_result.application_id=%s
          AND current_result.result_key=%s''',
        (scope.workspace_id,scope.application_id,key)).fetchone()


def evidence_digest(evidence):
    # Observer commit changes for unrelated calculation publications do not
    # change an immutable source. Actual source/revision/authority pins remain.
    if evidence.get('basisCoreVersion')==COMPOSED_VERSION or evidence.get('companyCoreVersion')==LOWER_COMPANY_VERSION:
        def stable(value):
            if isinstance(value,dict):return {key:stable(item) for key,item in value.items()
                if key not in ('sourceEvidenceDigest','observedCommitRevision')}
            if isinstance(value,list):return [stable(item) for item in value]
            return value
        return _canonical_digest(stable(evidence))
    return _canonical_digest({key:value for key,value in evidence.items()
        if key not in ('sourceEvidenceDigest','observedCommitRevision')})


def _source_arguments(plan):return {key:value for key,value in plan.arguments.items() if key not in ('targetAccounts','resultKey')}


def _check_target_locks(db,scope,rows):
    if db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb) input(members jsonb)
        JOIN epm.cube_write_scope_lock l ON l.workspace_id=%s AND l.application_id=%s
        AND l.status='Locked' AND (l.scope_all OR input.members @> l.scope_members) LIMIT 1''',
        (Jsonb(rows),scope.workspace_id,scope.application_id)).fetchone():raise ValueError('PLANNING_SLICE_LOCKED')


def validate_attribution(db,scope,plan,state):
    pointer=_pointer(db,scope,plan.result_key)
    if (pointer['published_revision'] if pointer else 0)!=plan.expected_publication_revision:
        raise ValueError('STALE_PUBLICATION_POINTER')
    if pointer and pointer['function_name'] not in (PUBLISH,WITHDRAW):raise ValueError('PERIOD_ATTRIBUTION_RESULT_KEY_CONFLICT')
    if plan.function==WITHDRAW:
        if (not pointer or pointer['function_name']!=PUBLISH or
                pointer['state_token'] != plan.arguments['resultStateToken']):
            raise ValueError('PERIOD_ATTRIBUTION_CURRENT_GENERATION_CHANGED')
        _check_target_locks(db,scope,pointer['result']['rows'])
        return {'rows':[],'previous':pointer,'economicIdentity':pointer['result']['economicIdentity'],'sourceEvidence':None}
    evidence=(inspect_company if 'decisions' in plan.arguments else inspect_in_transaction)(db,scope,_source_arguments(plan),state)
    if plan.expected_source_digest is not None and plan.source_contract!=source_contract_for(evidence):
        raise ValueError('PERIOD_ATTRIBUTION_SOURCE_CONTRACT_MISMATCH')
    digest=evidence_digest(evidence)
    if plan.expected_source_digest is not None and plan.expected_source_digest!=digest:
        raise ValueError('STALE_PERIOD_ATTRIBUTION_SOURCE_EVIDENCE')
    typed=plan.source_contract in (TYPED_FULL_CONTRACT,IC_TYPED_FULL_CONTRACT)
    if pointer and bool(pointer['result'].get('outputUnit'))!=typed:
        raise ValueError('PERIOD_ATTRIBUTION_RESULT_STORAGE_KIND_CHANGED')
    account_roles=db.execute('''SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
        AND model_role='Account' AND status='Active' ''',(scope.workspace_id,scope.application_id)).fetchall()
    if len(account_roles)!=1:raise ValueError('PERIOD_ATTRIBUTION_ACCOUNT_AXIS_REQUIRED')
    axis=account_roles[0]['dimension_id'];targets=plan.arguments['targetAccounts'];parent=evidence['parentMembers']
    rows=[];keys=(scope.workspace_id,scope.application_id)
    for role,field in (('nci','candidateNciShare'),('controlling','candidateControllingShare')):
        member=targets[role]
        if member==parent[axis] or member in {item['accountMemberId'] for item in evidence.get('basisComposition',evidence.get('components',[]))}:
            raise ValueError('PERIOD_ATTRIBUTION_TARGET_IS_BASIS')
        account=db.execute('''SELECT financial_account_type FROM epm.member WHERE workspace_id=%s
            AND application_id=%s AND dimension_id=%s AND member_id=%s AND status='Active' ''',(*keys,axis,member)).fetchone()
        if account is None or account['financial_account_type'] not in _TYPES[evidence['basisKind']]:
            raise ValueError('PERIOD_ATTRIBUTION_TARGET_ACCOUNT_TYPE_INVALID')
        if db.execute('''SELECT 1 FROM epm.relationship WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=%s AND parent_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',(*keys,axis,member)).fetchone():
            raise ValueError('PERIOD_ATTRIBUTION_TARGET_LEAF_REQUIRED')
        point=Coordinate.from_mapping({**parent,axis:member})
        if db.execute('''SELECT 1 FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n
            USING(workspace_id,application_id,coordinate_id) LEFT JOIN epm.text_cell_current t
            USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s AND c.application_id=%s
            AND c.series_key=%s AND (n.present OR t.present) LIMIT 1''',(*keys,point.series_key)).fetchone():
            raise ValueError('PERIOD_ATTRIBUTION_TARGET_RAW_PRESENT')
        rows.append({'role':role,'members':dict(point.members),'amount':evidence[field]})
    _check_target_locks(db,scope,rows)
    with localcontext() as precision:
        precision.prec=80
        if sum((Decimal(row['amount']) for row in rows),Decimal(0))!=Decimal(evidence['basisAmount']):
            raise ValueError('PERIOD_ATTRIBUTION_RECONCILIATION_FAILED')
    identity={'parentMembers':parent,
        **({'relationshipIds':[row['relationshipId'] for row in evidence['relationships']],
            'presentationKind':'company_propagated_full' if evidence['companyCoreVersion']==LOWER_COMPANY_VERSION else 'company_direct_full'} if 'companyCoreVersion' in evidence else {'relationshipId':evidence['relationshipId']}),
        'targetAccounts':targets,'basisKind':evidence['basisKind'],'currencyMemberId':evidence['currencyMemberId']}
    if 'basisComposition' in evidence:identity['basisComposition']=evidence['basisComposition']
    if 'companyCoreVersion' in evidence:
        identity['basisComposition']=sorted([{'accountMemberId':item['accountMemberId'],'sign':item['sign']}
            for item in evidence['components']],key=lambda item:item['accountMemberId'])
        identity['includeParentSource']=evidence['includeParentSource']
    if pointer and pointer['result']['economicIdentity']!=identity:raise ValueError('PERIOD_ATTRIBUTION_ECONOMIC_IDENTITY_CHANGED')
    return {'rows':rows,'sourceEvidence':evidence,'sourceDigest':digest,'previous':pointer,'economicIdentity':identity}


def _lower_presentation_coordinates(db,scope,evidence):
    """Return only the exact pinned lower-company presentation rows consumed."""
    pins=evidence.get('lowerCompanies',[])
    if not isinstance(pins,list):raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
    coordinates=[]
    for item in pins:
        presentation=item.get('presentation') if isinstance(item,dict) else None
        generation=presentation.get('generationId') if isinstance(presentation,dict) else None
        if not _match(_JOB,generation):raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
        rows=db.execute('''SELECT members FROM (
            SELECT c.members FROM epm.calculation_result_current r
            JOIN epm.calculation_result_state s USING(workspace_id,application_id,result_key)
            JOIN epm.coordinate c USING(workspace_id,application_id,coordinate_id)
            WHERE r.workspace_id=%s AND r.application_id=%s AND s.source_operation_id=%s
            UNION ALL
            SELECT c.members FROM epm.calculation_unit_result_current r
            JOIN epm.calculation_result_state s USING(workspace_id,application_id,result_key)
            JOIN epm.coordinate c USING(workspace_id,application_id,coordinate_id)
            WHERE r.workspace_id=%s AND r.application_id=%s AND s.source_operation_id=%s
            ) source_rows ORDER BY members::text''',(scope.workspace_id,scope.application_id,generation,
                scope.workspace_id,scope.application_id,generation)).fetchall()
        if len(rows)!=2:raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
        coordinates.extend(Coordinate.from_mapping(row['members']) for row in rows)
    return coordinates


def period_attribution_security_coordinates(db,scope,plan,summary):
    """Resolve exact source reads and result writes from trusted validated evidence.

    The source validator has already pinned the immutable publication.  Security
    is evaluated on the economic parent-basis coordinate actually consumed,
    not every unrelated row that happens to share its source generation.
    """
    if plan.function==WITHDRAW:
        previous=summary.get('previous')
        rows=(previous.get('result',{}).get('rows') if isinstance(previous,dict) else None)
        if not isinstance(rows,list) or not rows:raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
        return (),tuple(Coordinate.from_mapping(row['members']) for row in rows)
    evidence=summary.get('sourceEvidence')
    if not isinstance(evidence,dict) or not isinstance(evidence.get('parentMembers'),dict):
        raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
    reads=[]
    if evidence.get('basisCoreVersion')==COMPOSED_VERSION:
        components=evidence.get('components')
        if not isinstance(components,list) or not components:raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
        for component in components:
            proof=component.get('evidence') if isinstance(component,dict) else None
            members=proof.get('parentMembers') if isinstance(proof,dict) else None
            if not isinstance(members,dict):raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
            reads.append(Coordinate.from_mapping(members))
    elif 'companyCoreVersion' in evidence:
        roles=db.execute('''SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s
            AND application_id=%s AND model_role='Account' AND status='Active' ''',
            (scope.workspace_id,scope.application_id)).fetchall()
        components=evidence.get('components')
        if len(roles)!=1 or not isinstance(components,list) or not components:
            raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
        axis=roles[0]['dimension_id']
        for component in components:
            account=component.get('accountMemberId') if isinstance(component,dict) else None
            if not isinstance(account,str):raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
            reads.append(Coordinate.from_mapping({**evidence['parentMembers'],axis:account}))
        reads.extend(_lower_presentation_coordinates(db,scope,evidence))
    else:
        reads.append(Coordinate.from_mapping(evidence['parentMembers']))
    rows=summary.get('rows')
    if not isinstance(rows,list) or len(rows)!=2:raise ValueError('PERIOD_ATTRIBUTION_SOURCE_LINEAGE_INVALID')
    writes=tuple(Coordinate.from_mapping(row['members']) for row in rows)
    return tuple(reads),writes


def enforce_period_attribution_dimensional_security(db,identity,scope,plan,summary):
    reads,writes=period_attribution_security_coordinates(db,scope,plan,summary)
    authorize_coordinates(db,identity,scope,reads,kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,writes,kind=AccessKind.WRITE)


def source_status(db,scope,program):
    """Read-only currentness; safe for the read-only generic paged scanner."""
    try:
        plan=decode_attribution(program)
        if plan.function==WITHDRAW:return {'matchesAtRead':True,'reason':'Withdrawn','sourceRequired':False}
        state=db.execute('''SELECT metadata_revision,data_revision,policy_revision,commit_revision,enabled_capabilities
            FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id,scope.application_id)).fetchone()
        if not state or 'financial_consolidation' not in state['enabled_capabilities']:
            return {'matchesAtRead':False,'reason':'APPLICATION_CAPABILITY_DISABLED'}
        evidence=(inspect_company if 'decisions' in plan.arguments else inspect_in_transaction)(db,scope,_source_arguments(plan),state)
        after=db.execute('''SELECT commit_revision FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id,scope.application_id)).fetchone()
        matches=(plan.source_contract==source_contract_for(evidence) and evidence_digest(evidence)==plan.expected_source_digest and after['commit_revision']==state['commit_revision'])
        return {'matchesAtRead':matches,'reason':None if matches else 'STALE_PERIOD_ATTRIBUTION_SOURCE_EVIDENCE',
            **({'source':plan.arguments['source']} if 'source' in plan.arguments else {'sources':plan.arguments['sources']}),
            'definitionId':plan.arguments['definitionId']}
    except ValueError as error:
        return {'matchesAtRead':False,'reason':str(error)}


class PostgresPeriodAttributionPublisher:
    def __init__(self,dsn,*,identity):
        self.cases=PostgresPeriodPolicyCases(dsn,identity=identity)
        self.dsn,self.identity=dsn,identity

    def publish(self,claim):
        if (not isinstance(claim,dict) or not all(isinstance(claim.get(key),str) for key in ('workspace_id','application_id','claimant'))
                or not _match(_JOB,claim.get('job_id')) or type(claim.get('claim_generation')) is not int):
            raise ValueError('INVALID_WORKER_CLAIM')
        scope=ApplicationScope(claim['workspace_id'],claim['application_id']);keys=(scope.workspace_id,scope.application_id)
        # Resolve and calculate the complete candidate before taking the
        # application/job publication locks.  This transaction still checks
        # current identity, lifecycle, claim, immutable compiler/program and
        # input revisions; the final fence repeats every mutable check.
        with connect_postgres(self.dsn,row_factory=dict_row) as before:
            with before.transaction():
                PostgresNumericFactStore._set_scope(before,scope)
                PostgresAccessChecker.lock_workspace(before,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    before,self.identity,scope,'write')
                configure_statement_timeout(before,10000)
                initial_state=before.execute('''SELECT s.*,
                    a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s''',
                    keys).fetchone()
                if not initial_state:raise ValueError('APPLICATION_UNAVAILABLE')
                initial_job=before.execute('''SELECT *,
                    lease_until>clock_timestamp() AS unexpired FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s''',
                    (*keys,claim['job_id'])).fetchone()
                if (not initial_job
                        or initial_job['issuer']!=self.identity.issuer
                        or initial_job['subject_id']!=self.identity.subject_id):
                    raise ValueError('JOB_UNAVAILABLE')
                if (initial_job['status']!='running'
                        or initial_job['claim_generation']!=claim['claim_generation']
                        or initial_job['claimant']!=claim['claimant']
                        or not initial_job['unexpired']):
                    raise ValueError('STALE_WORKER_FENCE')
                plan=decode_attribution(initial_job['normalized_program'])
                if (initial_job['function_name']!=plan.function
                        or initial_job['compiler_version']!=plan.compiler_version
                        or initial_job['plan_digest']!=plan.plan_digest
                        or initial_job['program_digest']!=
                            _canonical_digest(plan.normalized_program)):
                    raise ValueError('UNSUPPORTED_PERIOD_ATTRIBUTION_JOB')
                if (initial_state['processing_mode']!='Active'
                        or initial_state['application_status']!='Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(initial_state[kind+'_revision']!=
                       initial_job['expected_'+kind+'_revision']
                       for kind in ('metadata','data','policy')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                candidate=validate_attribution(
                    before,scope,plan,initial_state)
                enforce_period_attribution_dimensional_security(
                    before,self.identity,scope,plan,candidate)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db,self.identity,scope,'write')
                configure_statement_timeout(db, 10000)
                # The job function chooses only between two fixed capabilities;
                # never trust a caller-provided claim's function or program.
                state=db.execute('''SELECT s.*,a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING(workspace_id,application_id) WHERE s.workspace_id=%s
                    AND s.application_id=%s FOR UPDATE OF s''',keys).fetchone()
                if not state:raise ValueError('APPLICATION_UNAVAILABLE')
                job=db.execute('''SELECT *,lease_until>clock_timestamp() AS unexpired FROM epm.job
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s FOR UPDATE''',(*keys,claim['job_id'])).fetchone()
                if not job or job['issuer']!=self.identity.issuer or job['subject_id']!=self.identity.subject_id:
                    raise ValueError('JOB_UNAVAILABLE')
                immutable=('issuer','subject_id','function_name',
                    'normalized_program','program_digest','compiler_version',
                    'plan_digest','expected_metadata_revision',
                    'expected_data_revision','expected_policy_revision')
                if any(job[key]!=initial_job[key] for key in immutable):
                    raise ValueError('STALE_WORKER_FENCE')
                if (job['status']!='running' or job['claim_generation']!=claim['claim_generation']
                        or job['claimant']!=claim['claimant'] or not job['unexpired']):raise ValueError('STALE_WORKER_FENCE')
                final_plan=decode_attribution(job['normalized_program'])
                if (final_plan.normalized_program!=plan.normalized_program
                        or job['function_name']!=final_plan.function
                        or job['compiler_version']!=final_plan.compiler_version
                        or job['plan_digest']!=final_plan.plan_digest
                        or job['program_digest']!=
                            _canonical_digest(final_plan.normalized_program)):
                    raise ValueError('UNSUPPORTED_PERIOD_ATTRIBUTION_JOB')
                plan=final_plan
                access=PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'write',function=plan.function)
                if state['processing_mode']!='Active' or state['application_status']!='Active':raise ValueError('APPLICATION_NOT_WRITABLE')
                if any(state[kind+'_revision']!=job['expected_'+kind+'_revision'] for kind in ('metadata','data','policy')):
                    raise ValueError('STALE_JOB_INPUT_REVISION')
                summary=validate_attribution(db,scope,plan,state)
                enforce_period_attribution_dimensional_security(
                    db,self.identity,scope,plan,summary)
                # Observer commit fields are deliberately absent from the
                # semantic source digest.  Compare the actual output, source,
                # economic identity and target pointer so an unrelated commit
                # can progress without allowing the candidate to change.
                def identity(value):
                    previous=value['previous']
                    return {'rows':value['rows'],
                        'sourceDigest':value.get('sourceDigest'),
                        'economicIdentity':value['economicIdentity'],
                        'previousGenerationId':(
                            previous['generation_id'] if previous else None),
                        'previousPublishedRevision':(
                            previous['published_revision'] if previous else 0)}
                if identity(summary)!=identity(candidate):
                    raise ValueError('STALE_PERIOD_ATTRIBUTION_CANDIDATE')
                policy_rows=(summary['rows'] if plan.function==PUBLISH
                    else summary['previous']['result']['rows'])
                policy_evidence=enforce_active_planning_policy(
                    db,scope,writes=tuple((Coordinate.from_mapping(
                        row['members']),'Set' if plan.function==PUBLISH
                        else 'Clear') for row in policy_rows),
                    workflow_role=access.role,ordered_actions=True)
                revision=state['commit_revision']+1
                db.execute('''INSERT INTO epm.calculation_operation_staging(workspace_id,application_id,generation_id,job_id,
                    result_key,source_commit_revision,source_metadata_revision,source_policy_revision,function_name,factor,row_count,published_revision)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s)''',(*keys,claim['job_id'],claim['job_id'],plan.result_key,
                    state['commit_revision'],state['metadata_revision'],state['policy_revision'],plan.function,len(summary['rows']),revision))
                typed=(plan.source_contract in
                       (TYPED_FULL_CONTRACT,IC_TYPED_FULL_CONTRACT))
                typed_lineage=None;typed_lineage_digest=None
                if typed:
                    typed_lineage,typed_lineage_digest=(
                        _typed_publication_evidence(summary))
                for row in summary['rows']:
                    point=Coordinate.from_mapping(row['members'])
                    coordinate=PostgresNumericFactStore._coordinate_id(db,scope,point)
                    if typed:
                        evidence=summary['sourceEvidence'];unit=evidence['outputUnit']
                        db.execute('''INSERT INTO epm.calculation_unit_result_staging(
                          workspace_id,application_id,generation_id,coordinate_id,
                          output_unit_currency_dimension_id,
                          output_unit_currency_member_id,source_amount,
                          source_change_id,source_evidence_digest,amount,
                          rate_strategy,rate_numerator,
                          rate_denominator,rate_sources,source_lookup_lineage)
                          VALUES(%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,
                           'identity-same-currency',1,1,%s,%s)''',
                          (*keys,claim['job_id'],coordinate,unit['dimensionId'],
                           unit['memberId'],evidence['basisAmount'],
                           typed_lineage_digest,row['amount'],
                           Jsonb([{'kind':'Identity','currency':unit}]),
                           Jsonb(typed_lineage)))
                    else:
                        db.execute('''INSERT INTO epm.calculation_result_staging(workspace_id,application_id,generation_id,coordinate_id,
                            source_amount,source_change_id,amount) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
                            (*keys,claim['job_id'],coordinate,summary['sourceEvidence']['basisAmount'],summary['sourceDigest'],row['amount']))
                previous=summary['previous']
                result={'function':plan.function,'generationId':claim['job_id'],'resultKey':plan.result_key,
                    'status':'Published' if plan.function==PUBLISH else 'Withdrawn','rowCount':len(summary['rows']),
                    'accountingStage':plan.accounting_stage,'presentation':
                        'separate_company_attribution_split' if 'decisions' in plan.arguments else 'separate_attribution_split','economicIdentity':summary['economicIdentity'],
                    'rows':summary['rows'],'sourceEvidence':summary['sourceEvidence'],
                    'previousGenerationId':previous['generation_id'] if previous else None,
                    'previousPublishedRevision':previous['published_revision'] if previous else 0,
                    'sourceCommitRevision':state['commit_revision'],'committedRevision':revision,
                    'independentAccountingCertification':False,
                    'engine':'postgres_exact_numeric',
                    'planningPolicy':policy_evidence}
                if typed:
                    _complete_typed_receipt(result,summary,typed_lineage,
                        typed_lineage_digest,revision)
                if plan.function==WITHDRAW:
                    result.update(
                        withdrawnResultStateToken=
                            plan.arguments['resultStateToken'],
                        reason=plan.arguments['reason'])
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=plan.result_key,existed=previous is not None,
                    withdrawn=plan.function==WITHDRAW)
                result['impactDigest']=impact.digest
                db.execute('''UPDATE epm.application_state SET commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',(revision,*keys))
                db.execute('''INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)''',(*keys,claim['job_id'],job['program_digest'],job['subject_id'],revision,Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                from .postgres_current_result_publication import advance_result_head_during_conversion
                advance_result_head_during_conversion(db,scope,
                    result_key=plan.result_key,operation_id=claim['job_id'],
                    committed_revision=revision)
                updated=db.execute('''UPDATE epm.job SET status='published',receipt_revision=%s,result=%s,claimant=NULL,lease_until=NULL,
                    updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND job_id=%s
                    AND status='running' AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()''',
                    (revision,Jsonb(result),*keys,claim['job_id'],claim['claim_generation'],claim['claimant'])).rowcount
                if updated!=1:raise ValueError('STALE_WORKER_FENCE')
                return result
