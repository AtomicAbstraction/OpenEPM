"""Prospective local Full propagation of explicitly pinned lower-company interests."""
from decimal import Decimal,localcontext

from .persistence_contract import NumericCell
from .postgres_jobs import _canonical_digest

VERSION='company-nci-propagated-full-source-v2'
CONTRACT='owner_declared_current_company_lower_interests_v5'
STAGE='company_nci_propagated_split'
ELECTION='lowerCompanyNciTreatment'
CHOICE='carry_lower_nci_allocate_owner_basis'


def compile_pins(raw):
    from .postgres_period_nci_basis import _matches,_KEY,_JOB,_id
    if not isinstance(raw,list) or not 1<=len(raw)<=200:raise ValueError('LOWER_COMPANY_PINS_INVALID')
    result=[]
    for item in raw:
        if (not isinstance(item,dict) or set(item)!={'relationshipId','presentation'} or not _id(item['relationshipId'])
                or not isinstance(item['presentation'],dict) or set(item['presentation'])!={'resultKey','generationId','publishedRevision'}):
            raise ValueError('LOWER_COMPANY_PINS_INVALID')
        pin=item['presentation']
        if (not _matches(_KEY,pin['resultKey']) or not _matches(_JOB,pin['generationId'])
                or type(pin['publishedRevision']) is not int or pin['publishedRevision']<=0):
            raise ValueError('LOWER_COMPANY_PINS_INVALID')
        result.append({'relationshipId':item['relationshipId'],'presentation':dict(pin)})
    if len({item['relationshipId'] for item in result})!=len(result):raise ValueError('LOWER_COMPANY_DUPLICATE_PIN')
    return sorted(result,key=lambda item:item['relationshipId'])


def owner_basis(gross,lower_nci):
    with localcontext() as precision:
        precision.prec=80
        result=Decimal(gross)-Decimal(lower_nci)
    NumericCell(True,result,'')
    return result


def validate_lower(db,scope,pin,state,*,child,parent,roles,components,selected,active,traversal,path):
    # Lazy imports keep the fixed source/compiler registry acyclic at import time.
    from .postgres_period_nci_publication import (PUBLISH,COMPANY_CONTRACT,COMPANY_COMPILER,
        decode_attribution,evidence_digest,source_contract_for,_source_arguments)
    from .postgres_company_nci import inspect_in_transaction
    keys=(scope.workspace_id,scope.application_id)
    row=db.execute('''SELECT p.source_operation_id AS generation_id,
        p.committed_revision AS published_revision,
        p.source_function AS function_name,p.row_count,
        j.status,j.result,j.normalized_program,j.compiler_version,j.plan_digest,j.program_digest,
        j.expected_metadata_revision,j.expected_data_revision,j.expected_policy_revision,
        o.result AS immutable_receipt,o.command_digest
        FROM epm.calculation_result_state p
        JOIN epm.job j ON j.workspace_id=p.workspace_id
        AND j.application_id=p.application_id AND j.job_id=p.source_operation_id
        JOIN epm.operation_receipt o ON o.workspace_id=j.workspace_id AND o.application_id=j.application_id AND o.operation_id=j.job_id
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s''',(*keys,pin['resultKey'])).fetchone()
    if not row or row['generation_id']!=pin['generationId'] or row['published_revision']!=pin['publishedRevision']:
        raise ValueError('STALE_LOWER_COMPANY_PRESENTATION')
    if (row['function_name']!=PUBLISH or row['status']!='published' or row['row_count']!=2
            or any(row['expected_'+kind+'_revision']!=state[kind+'_revision'] for kind in ('metadata','data','policy'))):
        raise ValueError('LOWER_COMPANY_PRESENTATION_UNSUPPORTED_OR_STALE')
    plan=decode_attribution(row['normalized_program'])
    if (plan.source_contract not in (COMPANY_CONTRACT,CONTRACT) or plan.function!=PUBLISH
            or row['compiler_version']!=plan.compiler_version or row['plan_digest']!=plan.plan_digest
            or row['program_digest']!=_canonical_digest(plan.normalized_program)
            or row['command_digest']!=row['program_digest'] or row['immutable_receipt']!=row['result']):
        raise ValueError('LOWER_COMPANY_COMPILER_OR_RECEIPT_INVALID')
    receipt=row['result']
    expected_parent={**parent,roles['Entity']:child}
    if plan.arguments.get('parentMembers')!=expected_parent:raise ValueError('LOWER_COMPANY_GRAIN_MISMATCH')
    proof=inspect_in_transaction(db,scope,_source_arguments(plan),state,_traversal=traversal,_path=path)
    if (source_contract_for(proof)!=plan.source_contract or evidence_digest(proof)!=plan.expected_source_digest
            or not isinstance(receipt,dict) or receipt.get('generationId')!=pin['generationId']
            or receipt.get('resultKey')!=pin['resultKey'] or receipt.get('committedRevision')!=pin['publishedRevision']
            or receipt.get('accountingStage')!=plan.accounting_stage
            or receipt.get('presentation')!='separate_company_attribution_split'
            or evidence_digest(receipt.get('sourceEvidence',{}))!=plan.expected_source_digest):
        raise ValueError('STALE_LOWER_COMPANY_SOURCE_EVIDENCE')
    if any(proof[key]!=active[key] for key in ('activationId','policyBindingDigest')):
        raise ValueError('LOWER_COMPANY_POLICY_CONTEXT_MISMATCH')
    for key in ('basisKind','currencyMemberId','viewMemberId','timeBasis'):
        if proof[key]!=active['declaration'][key]:raise ValueError('LOWER_COMPANY_BASIS_CONTEXT_MISMATCH')
    lower={item['accountMemberId']:item for item in proof['components']}
    if set(lower)!={item['accountMemberId'] for item in components}:raise ValueError('LOWER_COMPANY_COMPONENT_COVERAGE_MISMATCH')
    for component,contribution in selected:
        actual=lower[component['accountMemberId']]
        if any(component[key]!=actual[key] for key in ('definitionId','expectedDefinitionDigest','sign')):
            raise ValueError('LOWER_COMPANY_COMPONENT_IDENTITY_MISMATCH')
        # v5 is local, same-unit propagation. FX of lower interests needs its
        # own typed translation pins and must not be inferred from gross FX.
        if (contribution.get('selectedLayer')!='published_full_aggregate'
                or any(contribution.get(key)!=actual['source'][key] for key in ('resultKey','generationId','publishedRevision'))
                or contribution['amount']!=actual['grossBasisAmount']):
            raise ValueError('LOWER_COMPANY_GROSS_SOURCE_PIN_MISMATCH')
    values=db.execute('''SELECT c.members,r.amount,r.source_amount,r.source_change_id
        FROM epm.calculation_result_current r JOIN epm.coordinate c USING(workspace_id,application_id,coordinate_id)
        WHERE r.workspace_id=%s AND r.application_id=%s AND r.result_key=%s ORDER BY c.series_key''',
        (*keys,pin['resultKey'])).fetchall()
    expected={plan.arguments['targetAccounts']['nci']:proof['nciShare'],
        plan.arguments['targetAccounts']['controlling']:proof['controllingShare']}
    if (len(values)!=2 or not isinstance(receipt.get('rows'),list) or len(receipt['rows'])!=2
            or {item.get('role') for item in receipt['rows']}!={'nci','controlling'}):
        raise ValueError('LOWER_COMPANY_ROWS_INVALID')
    for value in values:
        account=value['members'].get(roles['Account'])
        if (account not in expected or value['members']!={**expected_parent,roles['Account']:account}
                or format(value['amount'],'.8f')!=expected[account]
                or value['source_amount']!=Decimal(proof['grossBasisAmount'])
                or value['source_change_id']!=plan.expected_source_digest):
            raise ValueError('LOWER_COMPANY_ROWS_INVALID')
    for item in receipt['rows']:
        role=item['role'];account=plan.arguments['targetAccounts'][role]
        if item.get('members')!={**expected_parent,roles['Account']:account} or item.get('amount')!=expected[account]:
            raise ValueError('LOWER_COMPANY_ROWS_INVALID')
    return {'presentation':pin,'sourceDigest':plan.expected_source_digest,'sourceEvidence':proof,
        'grossBasisAmount':proof['grossBasisAmount'],'lowerNciShare':proof['nciShare'],
        'lowerControllingShare':proof['controllingShare']}
