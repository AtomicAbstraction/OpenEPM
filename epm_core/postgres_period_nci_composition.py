"""Versioned explicit composition of validated leaf-account contributions.

The anchor names the economic basis; it is not an input amount or an automatically
expanded account hierarchy. Every signed component has a current source proof.
"""
from decimal import Decimal, localcontext

from .persistence_contract import Coordinate, NumericCell
from .postgres_jobs import _canonical_digest
from .postgres_period_nci import split_basis

VERSION='period-nci-composed-published-basis-v3'
KIND='published_composed_full_contribution'
CONTRACT='owner_declared_current_composed_full_contribution_v3'


def components(raw):
    from .postgres_period_nci_basis import _matches,_KEY,_HASH
    if not isinstance(raw,list) or not 2<=len(raw)<=16:
        raise ValueError('PERIOD_COMPOSITION_COMPONENTS_INVALID')
    result=[]
    for item in raw:
        if (not isinstance(item,dict) or set(item)!={'definitionId','expectedDefinitionDigest','sign'}
                or not _matches(_KEY,item['definitionId']) or not _matches(_HASH,item['expectedDefinitionDigest'])
                or type(item['sign']) is not int or item['sign'] not in (-1,1)):
            raise ValueError('PERIOD_COMPOSITION_COMPONENTS_INVALID')
        result.append(dict(item))
    if len({x['definitionId'] for x in result})!=len(result):
        raise ValueError('PERIOD_COMPOSITION_DUPLICATE_COMPONENT')
    return sorted(result,key=lambda item:item['definitionId'])


def bind_components(db,scope,args,state,metadata,policy_digest):
    from .postgres_period_nci_basis import _definition,_members,REVOKE
    from .postgres_period_policy_governance import _latest
    bindings=[];accounts=set()
    for item in args['components']:
        definition=_definition(db,scope,item['definitionId'],item['expectedDefinitionDigest'])
        spec=definition['manifest'];decl=spec['declaration']
        if spec['basisCoreVersion']==VERSION:
            raise ValueError('PERIOD_COMPOSITION_RECURSION_UNSUPPORTED')
        if _latest(db,scope,REVOKE,item['definitionId']):raise ValueError('PERIOD_BASIS_REVOKED')
        current=_members(db,scope,decl,decl['basisKind'])
        if (spec['metadataRevision']!=state['metadata_revision'] or current!=spec['metadataBinding']
                or current['roles']!=metadata['roles'] or current['factAxes']!=metadata['factAxes']
                or spec['policyBindingDigest']!=policy_digest
                or any(decl[key]!=args[key] for key in ('variantKey','activationId','basisKind','currencyMemberId','viewMemberId','timeBasis'))):
            raise ValueError('PERIOD_COMPOSITION_CONTEXT_MISMATCH')
        account=decl['accountMemberId']
        if account in accounts or account==args['accountMemberId']:
            raise ValueError('PERIOD_COMPOSITION_ACCOUNT_OVERLAP')
        accounts.add(account)
        bindings.append({**item,'accountMemberId':account,'basisCoreVersion':spec['basisCoreVersion']})
    return bindings


def inspect_composition(db,scope,args,state,definition):
    from .postgres_period_nci_basis import (_members,inspect_in_transaction,REVOKE)
    from .postgres_period_policy_governance import _latest
    spec=definition['manifest'];decl=spec['declaration']
    if 'sources' not in args:raise ValueError('PERIOD_COMPOSITION_SOURCES_REQUIRED')
    if _latest(db,scope,REVOKE,args['definitionId']):raise ValueError('PERIOD_BASIS_REVOKED')
    metadata=_members(db,scope,decl,decl['basisKind']);roles=metadata['roles'];axis=roles['Account']
    if metadata!=spec['metadataBinding'] or state['metadata_revision']!=spec['metadataRevision']:
        raise ValueError('PERIOD_BASIS_METADATA_CHANGED')
    if state['policy_revision']!=args['expectedPolicyRevision']:raise ValueError('STALE_PERIOD_BASIS_POLICY_REVISION')
    if (set(args['parentMembers'])!=set(metadata['factAxes'])
            or args['parentMembers'].get(axis)!=decl['accountMemberId']):
        raise ValueError('PERIOD_BASIS_SOURCE_GRAIN_OR_ACCOUNT_MISMATCH')
    bindings=bind_components(db,scope,decl,state,metadata,spec['policyBindingDigest'])
    if bindings!=spec['componentBindings']:raise ValueError('PERIOD_COMPOSITION_BINDING_CHANGED')
    pins={item['definitionId']:item['source'] for item in args['sources']}
    if set(pins)!={item['definitionId'] for item in bindings}:
        raise ValueError('PERIOD_COMPOSITION_SOURCE_COVERAGE_MISMATCH')
    point=Coordinate.from_mapping(args['parentMembers'])
    if db.execute('''SELECT 1 FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n
        USING(workspace_id,application_id,coordinate_id) LEFT JOIN epm.text_cell_current t
        USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s AND c.application_id=%s
        AND c.series_key=%s AND (n.present OR t.present) LIMIT 1''',
        (scope.workspace_id,scope.application_id,point.series_key)).fetchone():
        raise ValueError('PERIOD_COMPOSITION_ANCHOR_RAW_PRESENT')
    proofs=[];first=None
    for item in bindings:
        proof=inspect_in_transaction(db,scope,{'definitionId':item['definitionId'],
            'expectedDefinitionDigest':item['expectedDefinitionDigest'],'source':pins[item['definitionId']],
            'parentMembers':{**args['parentMembers'],axis:item['accountMemberId']},
            'relationshipId':args['relationshipId'],'expectedPolicyRevision':args['expectedPolicyRevision']},state)
        if first is None:first=proof
        elif any(proof[key]!=first[key] for key in ('ownershipPercent','periodSources','sourceAccountingStage')):
            raise ValueError('PERIOD_COMPOSITION_SOURCE_CONTEXT_MISMATCH')
        proofs.append({**item,'evidence':proof})
    with localcontext() as precision:
        precision.prec=80
        basis=sum((Decimal(item['evidence']['basisAmount'])*item['sign'] for item in proofs),Decimal(0))
    NumericCell(True,basis,'')
    split=split_basis(format(basis,'.8f'),first['ownershipPercent'])
    evidence={'basisCoreVersion':VERSION,'definitionId':args['definitionId'],'definitionDigest':definition['definitionDigest'],
        'activationId':first['activationId'],'policyBindingDigest':first['policyBindingDigest'],
        'basisKind':decl['basisKind'],'timeBasis':decl['timeBasis'],'sources':args['sources'],
        'sourceAccountingStage':first['sourceAccountingStage'],'parentMembers':args['parentMembers'],
        'currencyMemberId':decl['currencyMemberId'],'relationshipId':args['relationshipId'],
        'periodSources':first['periodSources'],'components':proofs,
        'basisComposition':[{'accountMemberId':item['accountMemberId'],'sign':item['sign']} for item in sorted(bindings,key=lambda x:x['accountMemberId'])],
        'basisAmount':split['basisAmount'],'ownershipPercent':split['ownershipPercent'],
        'candidateNciShare':split['candidateNciShare'],'candidateControllingShare':split['candidateControllingShare'],
        'roundingOrder':'exact_component_sum_then_half_even_nci_owner_residual',
        'metadataRevision':state['metadata_revision'],'dataRevision':state['data_revision'],
        'policyRevision':state['policy_revision'],'observedCommitRevision':state['commit_revision']}
    return {**evidence,'sourceEvidenceDigest':_canonical_digest(evidence),'operationalSourceValidated':True,
        'basisEligibility':'OwnerDeclaredComposedContributionsValidated','accountingMeaning':'WorkspaceOwnerDeclared',
        'independentAccountingCertification':False,'publicationSupported':False}
