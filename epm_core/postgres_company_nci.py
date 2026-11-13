"""Company source coverage and exact direct-company presentation.

One fixed source validation per component, then explicit per-relationship splits.
No publication, gross mutation or implicit propagation of lower-company interests.
"""
from datetime import timedelta
from decimal import Decimal, localcontext

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row

from .persistence_contract import NumericCell
from .postgres_jobs import _canonical_digest
from .postgres_period_nci import FUNCTION as CANDIDATE,parse_program,evaluate_in_transaction
from .postgres_period_nci_basis import (INSPECT,COMPOSED_VERSION,compile_program as compile_basis,
    _definition,_members,validated_full_source,REVOKE)
from .postgres_period_nci_composition import bind_components
from .postgres_period_policy_cases import PostgresPeriodPolicyCases
from .postgres_period_policy_governance import PostgresPeriodPolicyGovernance,_latest
from .postgres_source_batch import PostgresSourceBatch

FUNCTION='consolidation.nci.company.source.inspect'
VERSION='company-nci-direct-full-source-v1'
CONTRACT='owner_declared_current_direct_company_full_v4'
STAGE='company_nci_attribution_split'
from .postgres_lower_company_nci import (VERSION as LOWER_VERSION,CONTRACT as LOWER_CONTRACT,
    compile_pins,validate_lower,owner_basis,ELECTION as LOWER_ELECTION,CHOICE as LOWER_CHOICE)


def compile_program(raw):
    fields={'definitionId','expectedDefinitionDigest','parentMembers','expectedPolicyRevision',
        'decisions','includeParentSource'}
    if (not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'}
            or type(raw['languageVersion']) is not int or raw['languageVersion']!=2 or raw['function']!=FUNCTION
            or not isinstance(raw['arguments'],dict) or set(raw['arguments']) not in (fields|{'source'},fields|{'sources'},
                fields|{'source','lowerCompanies'},fields|{'sources','lowerCompanies'})):
        raise ValueError('COMPANY_NCI_PROGRAM_INVALID')
    args=raw['arguments'];decisions=args['decisions']
    if (type(args['includeParentSource']) is not bool or not isinstance(decisions,list) or not 1<=len(decisions)<=200
            or any(not isinstance(item,dict) or set(item)!={'relationshipId','method','controlConfirmed'}
                or not isinstance(item['relationshipId'],str) or not 1<=len(item['relationshipId'])<=200
                or item['relationshipId']!=item['relationshipId'].strip() or '\x00' in item['relationshipId']
                or not isinstance(item['method'],str) or type(item['controlConfirmed']) is not bool for item in decisions)):
        raise ValueError('COMPANY_NCI_DECISIONS_INVALID')
    if len({item['relationshipId'] for item in decisions})!=len(decisions):
        raise ValueError('COMPANY_NCI_DUPLICATE_RELATIONSHIP')
    if any(item['method']!='Full' for item in decisions):raise ValueError('COMPANY_NCI_METHOD_UNSUPPORTED')
    if any(not item['controlConfirmed'] for item in decisions):raise ValueError('COMPANY_NCI_CONTROL_REQUIRED')
    _,source=compile_basis({'languageVersion':2,'function':INSPECT,'arguments':{
        **{key:value for key,value in args.items() if key not in ('decisions','includeParentSource','lowerCompanies')},
        'relationshipId':decisions[0]['relationshipId']}})
    source.pop('relationshipId')
    return {**source,'decisions':sorted([dict(item) for item in decisions],key=lambda item:item['relationshipId']),
        'includeParentSource':args['includeParentSource'],
        **({'lowerCompanies':compile_pins(args['lowerCompanies'])} if 'lowerCompanies' in args else {})}


def inspect_in_transaction(db,scope,args,state,*,_traversal=None,_path=()):
    keys=(scope.workspace_id,scope.application_id)
    definition=_definition(db,scope,args['definitionId'],args['expectedDefinitionDigest'])
    spec=definition['manifest'];decl=spec['declaration']
    if _latest(db,scope,REVOKE,args['definitionId']):raise ValueError('PERIOD_BASIS_REVOKED')
    metadata=_members(db,scope,decl,decl['basisKind']);roles=metadata['roles'];parent=args['parentMembers']
    if metadata!=spec['metadataBinding'] or spec['metadataRevision']!=state['metadata_revision']:
        raise ValueError('PERIOD_BASIS_METADATA_CHANGED')
    if state['policy_revision']!=args['expectedPolicyRevision']:raise ValueError('STALE_PERIOD_BASIS_POLICY_REVISION')
    if set(parent)!=set(metadata['factAxes']) or parent.get(roles['Account'])!=decl['accountMemberId']:
        raise ValueError('PERIOD_BASIS_SOURCE_GRAIN_OR_ACCOUNT_MISMATCH')
    PostgresSourceBatch._check_scope_members(db,scope,parent)
    traversal=_traversal if _traversal is not None else {'remaining':200}
    node=parent[roles['Entity']]
    if node in _path:raise ValueError('LOWER_COMPANY_SOURCE_CYCLE')
    if traversal['remaining']<=0:raise ValueError('LOWER_COMPANY_SOURCE_GRAPH_LIMIT')
    traversal['remaining']-=1
    path=(*_path,node);propagated='lowerCompanies' in args
    relationships=db.execute('''SELECT r.relationship_id,r.child_member_id,
        EXISTS(SELECT 1 FROM epm.relationship lower_edge WHERE lower_edge.workspace_id=r.workspace_id
          AND lower_edge.application_id=r.application_id AND lower_edge.dimension_id=r.dimension_id
          AND lower_edge.parent_member_id=r.child_member_id AND lower_edge.hierarchy_id=r.hierarchy_id AND lower_edge.status='Active') AS has_children
        FROM epm.relationship r WHERE r.workspace_id=%s AND r.application_id=%s
        AND r.dimension_id=%s AND r.parent_member_id=%s AND r.hierarchy_id=epm.default_hierarchy_id(r.workspace_id,r.application_id,r.dimension_id) AND r.status='Active'
        ORDER BY r.relationship_id LIMIT 201''',(*keys,roles['Entity'],parent[roles['Entity']])).fetchall()
    if not 1<=len(relationships)<=200:raise ValueError('COMPANY_NCI_RELATIONSHIP_LIMIT')
    if [item['relationshipId'] for item in args['decisions']]!=[row['relationship_id'] for row in relationships]:
        raise ValueError('COMPANY_NCI_RELATIONSHIP_COVERAGE_MISMATCH')
    if len({row['child_member_id'] for row in relationships})!=len(relationships):
        raise ValueError('COMPANY_NCI_DUPLICATE_CHILD')
    grouped={row['relationship_id'] for row in relationships if row['has_children']}
    if not propagated and grouped:raise ValueError('COMPANY_NCI_LOWER_PRESENTATION_REQUIRED')
    lower_pins={item['relationshipId']:item['presentation'] for item in args.get('lowerCompanies',[])}
    if propagated and set(lower_pins)!=grouped:raise ValueError('LOWER_COMPANY_PRESENTATION_COVERAGE_MISMATCH')
    composed=spec['basisCoreVersion']==COMPOSED_VERSION
    if composed:
        if 'sources' not in args:raise ValueError('PERIOD_COMPOSITION_SOURCES_REQUIRED')
        bindings=bind_components(db,scope,decl,state,metadata,spec['policyBindingDigest'])
        if bindings!=spec['componentBindings']:raise ValueError('PERIOD_COMPOSITION_BINDING_CHANGED')
        pins={item['definitionId']:item['source'] for item in args['sources']}
        if set(pins)!={item['definitionId'] for item in bindings}:raise ValueError('PERIOD_COMPOSITION_SOURCE_COVERAGE_MISMATCH')
        from .persistence_contract import Coordinate
        point=Coordinate.from_mapping(parent)
        if db.execute('''SELECT 1 FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n
            USING(workspace_id,application_id,coordinate_id) LEFT JOIN epm.text_cell_current t
            USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s AND c.application_id=%s
            AND c.series_key=%s AND (n.present OR t.present) LIMIT 1''',(*keys,point.series_key)).fetchone():
            raise ValueError('PERIOD_COMPOSITION_ANCHOR_RAW_PRESENT')
    else:
        if 'source' not in args:raise ValueError('PERIOD_BASIS_SINGLE_SOURCE_REQUIRED')
        bindings=[{'definitionId':args['definitionId'],'expectedDefinitionDigest':args['expectedDefinitionDigest'],
            'accountMemberId':decl['accountMemberId'],'sign':1}]
        pins={args['definitionId']:args['source']}
    calendar=db.execute('''SELECT ends_before FROM epm.calendar_period_current WHERE workspace_id=%s AND application_id=%s
        AND year_member_id=%s AND period_member_id=%s''',(*keys,parent[roles['Year']],parent[roles['Period']])).fetchone()
    if calendar is None:raise ValueError('PERIOD_BASIS_CALENDAR_REQUIRED')
    effective=(calendar['ends_before']-timedelta(days=1)).isoformat()
    active=PostgresPeriodPolicyGovernance.resolve_in_transaction(db,scope,{
        'variantKey':decl['variantKey'],'effectiveOn':effective,'expectedPolicyRevision':state['policy_revision']},state)
    if active['activationId']!=decl['activationId'] or active['policyBindingDigest']!=spec['policyBindingDigest']:
        raise ValueError('PERIOD_BASIS_ACTIVATION_CHANGED')
    if propagated and active['policyBinding']['selections'].get(LOWER_ELECTION)!=LOWER_CHOICE:
        raise ValueError('LOWER_COMPANY_EXPLICIT_POLICY_ELECTION_REQUIRED')
    components=[];stage=None
    for item in bindings:
        leaf=_definition(db,scope,item['definitionId'],item['expectedDefinitionDigest'])['manifest']
        leaf_parent={**parent,roles['Account']:item['accountMemberId']}
        row,receipt,plan,actual_stage=validated_full_source(db,scope,{'source':pins[item['definitionId']],
            'parentMembers':leaf_parent},state,leaf,roles)
        if stage is not None and stage!=actual_stage:raise ValueError('PERIOD_COMPOSITION_SOURCE_CONTEXT_MISMATCH')
        stage=actual_stage
        if propagated and actual_stage!='pre_nci_untranslated_currency_aligned':
            raise ValueError('LOWER_COMPANY_TRANSLATION_REQUIRED')
        owns=[source for source in receipt['sources'] if source.get('relationshipId') is None]
        declared_own=plan.include_parent_source if hasattr(plan,'include_parent_source') else plan.parent_translation is not None
        if declared_own!=args['includeParentSource']:raise ValueError('COMPANY_NCI_PARENT_SOURCE_DECISION_MISMATCH')
        if (args['includeParentSource'] and len(owns)!=1) or not args['includeParentSource'] and owns:
            raise ValueError('COMPANY_NCI_PARENT_COMPONENT_MISSING')
        children=[source for source in receipt['sources'] if source.get('relationshipId') is not None]
        if sorted(source.get('relationshipId','') for source in children)!=[r['relationship_id'] for r in relationships]:
            raise ValueError('COMPANY_NCI_SOURCE_COVERAGE_MISMATCH')
        components.append({**item,'source':pins[item['definitionId']],'sourceChangeId':row['source_change_id'],
            'grossBasisAmount':format(row['amount'],'.8f'),'ownParentContribution':owns[0] if owns else None,
            'contributions':children})
    rows=[];lower_proofs=[];binding=active['policyBinding']
    with localcontext() as precision:
        precision.prec=80
        gross=sum((Decimal(item['grossBasisAmount'])*item['sign'] for item in components),Decimal(0))
        own=sum((Decimal(item['ownParentContribution']['amount'])*item['sign'] for item in components),Decimal(0)) if args['includeParentSource'] else Decimal(0)
        for relationship in relationships:
            selected=[(item,next(source for source in item['contributions'] if source['relationshipId']==relationship['relationship_id'])) for item in components]
            basis=sum((Decimal(source['amount'])*item['sign'] for item,source in selected),Decimal(0))
            if len({source['pown'] for _,source in selected})!=1:raise ValueError('COMPANY_NCI_OWNERSHIP_CONTEXT_MISMATCH')
            carried=Decimal(0);eligible=basis
            if relationship['relationship_id'] in lower_pins:
                proof=validate_lower(db,scope,lower_pins[relationship['relationship_id']],state,
                    child=relationship['child_member_id'],parent=parent,roles=roles,components=components,selected=selected,
                    active={**active,'declaration':decl},traversal=traversal,path=path)
                if Decimal(proof['grossBasisAmount'])!=basis:raise ValueError('LOWER_COMPANY_GROSS_RECONCILIATION_FAILED')
                carried=Decimal(proof['lowerNciShare']);eligible=owner_basis(basis,carried)
                lower_proofs.append({'relationshipId':relationship['relationship_id'],**proof})
            candidate={'languageVersion':2,'function':CANDIDATE,'arguments':{
                'policyId':binding['policyId'],'effectiveOn':effective,'selections':binding['selections'],
                'expectedPolicyRevision':state['policy_revision'],'relationshipId':relationship['relationship_id'],
                'scenarioId':parent[roles['Scenario']],'yearId':parent[roles['Year']],'periodId':parent[roles['Period']],
                'method':'Full','controlConfirmed':True,'basisKind':decl['basisKind'],'basisEligibilityConfirmed':True,
                'basisAmount':format(eligible,'.8f'),'ownershipPercent':selected[0][1]['pown']}}
            parsed,policy=parse_program(candidate);measured=evaluate_in_transaction(db,scope,parsed,policy,state)
            if measured['parentEntityId']!=parent[roles['Entity']] or measured['childEntityId']!=relationship['child_member_id']:
                raise ValueError('PERIOD_BASIS_DIRECT_RELATIONSHIP_REQUIRED')
            rows.append({'relationshipId':relationship['relationship_id'],'childEntityId':relationship['child_member_id'],
                'method':'Full','basisAmount':format(basis,'.8f'),'ownershipPercent':measured['ownershipPercent'],
                'nciShare':format(carried+Decimal(measured['candidateNciShare']),'.8f'),'controllingShare':measured['candidateControllingShare'],
                **({'lowerNciShare':format(carried,'.8f'),'eligibleOwnerBasisAmount':measured['basisAmount'],
                    'additionalNciShare':measured['candidateNciShare']} if propagated else {}),
                'periodSources':measured['periodSources']})
        nci=sum((Decimal(row['nciShare']) for row in rows),Decimal(0))
        controlling=own+sum((Decimal(row['controllingShare']) for row in rows),Decimal(0))
        if gross!=own+sum((Decimal(row['basisAmount']) for row in rows),Decimal(0)) or gross!=nci+controlling:
            raise ValueError('COMPANY_NCI_RECONCILIATION_FAILED')
        for value in (gross,own,nci,controlling):NumericCell(True,value,'')
    evidence={'function':FUNCTION,'companyCoreVersion':LOWER_VERSION if propagated else VERSION,'definitionId':args['definitionId'],
        'definitionDigest':definition['definitionDigest'],'parentMembers':parent,'basisKind':decl['basisKind'],
        'currencyMemberId':decl['currencyMemberId'],'viewMemberId':decl['viewMemberId'],'timeBasis':decl['timeBasis'],
        'activationId':active['activationId'],'policyBindingDigest':active['policyBindingDigest'],
        'components':components,'relationships':rows,'relationshipCount':len(rows),'coverage':'AllActiveDirectFullPlacementsWithPinnedLowerInterests' if propagated else 'AllActiveDirectLeafFullPlacements',
        'includeParentSource':args['includeParentSource'],'ownParentBasisAmount':format(own,'.8f') if args['includeParentSource'] else None,
        'grossBasisAmount':format(gross,'.8f'),'nciShare':format(nci,'.8f'),'controllingShare':format(controlling,'.8f'),
        'basisAmount':format(gross,'.8f'),'candidateNciShare':format(nci,'.8f'),'candidateControllingShare':format(controlling,'.8f'),
        'roundingOrder':'exact_component_sum_then_per_relationship_half_even_nci_owner_residual',
        **({'lowerCompanies':lower_proofs,'propagation':'carry_lower_nci_allocate_owner_basis'} if propagated else {}),
        'metadataRevision':state['metadata_revision'],'dataRevision':state['data_revision'],
        'policyRevision':state['policy_revision'],'observedCommitRevision':state['commit_revision']}
    return {**evidence,'sourceEvidenceDigest':_canonical_digest(evidence),'operationalSourceValidated':True,
        'presentation':'separate_propagated_company_attribution_preview' if propagated else 'separate_direct_company_attribution_preview','publicationSupported':False,
        'independentAccountingCertification':False,'accountingMeaning':'WorkspaceOwnerDeclared'}


class PostgresCompanyNciInspector:
    def __init__(self,dsn,*,identity):
        self.dsn=dsn;self.cases=PostgresPeriodPolicyCases(dsn,identity=identity)

    @staticmethod
    def catalog():
        return {FUNCTION:{'mode':'read_only','permission':'read','previewRequired':False,'idempotencyRequired':False,'workClass':'medium',
            'arguments':{'definitionId':'single/composed owner basis','expectedDefinitionDigest':'exact SHA256',
                'parentMembers':'complete parent basis grain','source':'single basis Full pin','sources':'composed exact component Full pins',
                'decisions':'complete unique active direct relationshipId/Full/controlConfirmed:true list, 1–200',
                'lowerCompanies':'prospective propagated profile only: exact grouped relationshipId/presentation pins; explicit policy election required',
                'includeParentSource':'explicit Boolean matching all component Full decisions','expectedPolicyRevision':'current integer'},
            'result':'reconciled gross/own-parent/per-relationship NCI/controlling presentation; this read has no effects and lower-company interests retain their separate authority',
            'operationalPublication':{
                'function':'consolidation.nci.period.publish',
                'boundary':'separate previewed durable publication revalidates the active compatible period policy, immutable company basis, complete direct-relationship coverage, pinned lower-company presentations, exact source evidence and target accounts'}}}

    def read(self,scope,program):
        args=compile_program(program)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self.cases._open(db,scope,FUNCTION,'read')
                return inspect_in_transaction(db,scope,args,state)
