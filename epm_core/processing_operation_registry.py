"""Executable operation-family inventory for processing and recovery audits.

This registry classifies public contracts; it does not replace the fixed core's
authorization, locking, queue, lease, publication, or cleanup implementation.
Unknown functions fail closed so a new public surface cannot silently escape
the P08 operation-family review.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json

STANDARD_FIELDS=frozenset((
    'mode','permission','previewRequired','idempotencyRequired','workClass',
    'arguments','result','requiredCapabilities'))
PROCESSING_REGISTRY_FORMAT='openepm-processing-operation-registry-v3'

PRODUCT_PURPOSES={
    'application_policy':'govern application-wide planning policy and state',
    'bulk_transfer':'move governed business data into or out of an application',
    'calculation':'calculate and publish governed multidimensional results',
    'execution_delegation':'govern delegated and scheduled execution authority',
    'fact_read':'read authorized multidimensional business data',
    'fact_write':'write authorized multidimensional business data',
    'financial_stage':'perform governed financial processing stages',
    'identity_directory':'govern platform identities, groups and memberships',
    'lifecycle':'govern workspace and application lifecycle',
    'metadata':'define and inspect the application object model',
    'metadata_layout':'build and activate governed dimensional layouts',
    'planning_calculation':'perform governed planning calculations',
    'planning_workflow':'run governed planning workflows',
    'platform_lifecycle':'create and govern platform workspaces',
    'python_build':'validate and build typed business-rule source',
    'python_program':'manage typed business-rule source and execution',
    'reset':'perform an explicitly admitted workspace reset',
    'saved_rule':'manage and execute governed business rules',
    'schedule':'manage governed execution schedules',
    'security':'govern application and workspace access',
    'selection':'evaluate authorized multidimensional selections',
    'technical_query':'run bounded technical queries without business publication',
}

WORK_BUDGETS={
    'short': {'class':'short','terminalDeadlineSeconds':5},
    'small': {'class':'small','terminalDeadlineSeconds':5},
    'bounded_read': {'class':'bounded_read','terminalDeadlineSeconds':30},
    'bounded_write': {'class':'bounded_write','terminalDeadlineSeconds':30},
    'medium': {'class':'medium','terminalDeadlineSeconds':120},
    'long': {'class':'long','terminalDeadlineSeconds':900},
}

READ_MODES=frozenset(('read','read_only','read_only_preview','calculation_preview',
                      'preview'))
DURABLE_MODES=frozenset((
    'durable_atomic_adjustment','durable_business_workflow',
    'durable_calculation','durable_job','durable_query','durable_sequence',
    'durable_source_publication','durable_staging','durable_technical_build',
    'durable_technical_query','durable_workflow','durable_write'))

EXTERNAL_FUNCTIONS={
    'workspace.application.create':'lifecycle',
    'workspace.application.purge.prepare':'lifecycle',
    'workspace.application.purge.quiesce':'lifecycle',
    'workspace.application.purge.apply':'lifecycle',
    'security.workspace.access.set':'security',
    'security.workspace.group-access.set':'security',
    'security.workspace.group-access.list':'security',
    'workspace.reset.prepare':'reset',
    'workspace.reset.quiesce':'reset',
    'workspace.reset.settle':'reset',
    'workspace.reset.resume':'reset',
    'workspace.reset.apply':'reset',
}


def external_function_catalog()->dict:
    """Return the workspace/control operations with full shared descriptors.

    These operations live outside the application-language catalogue because
    they use narrower database roles and workspace scopes.  They are still
    public operations, so the shared registry must describe—not merely name—
    their admission, effect, preview, replay and execution contracts.
    """
    from .postgres_security_language import PostgresSecurityLanguage
    from .postgres_workspace_lifecycle import PostgresWorkspaceLifecycle
    from .postgres_application_purge import catalog as application_purge_catalog
    from .postgres_workspace_reset import PostgresWorkspaceResetPreview

    merged={}
    sources=(
        (application_purge_catalog(),'lifecycle','workspace_lifecycle_adapter'),
        (PostgresWorkspaceLifecycle.catalog()['functions'],'lifecycle',
         'workspace_lifecycle_adapter'),
        (PostgresSecurityLanguage.workspace_catalog()['functions'],'security',
         'workspace_security_adapter'),
        (PostgresWorkspaceResetPreview.catalog()['functions'],'reset',
         'workspace_reset_lifecycle_adapter'),
    )
    for catalog,family,boundary in sources:
        for name,specification in catalog.items():
            if name in merged:
                raise ValueError('PROCESSING_EXTERNAL_OPERATION_DUPLICATE:'+name)
            merged[name]={**specification,'requiredCapabilities':[],
                          '_family':family,'_handlerBoundary':boundary}
    # Apply is deliberately absent from the ordinary reset listener.  It is
    # nevertheless a public operation of the isolated migration-owner service.
    merged['workspace.reset.apply']={
        'mode':'atomic_write',
        'permission':'platform_operator_and_workspace_admin_and_migration_owner',
        'arguments':{'manifestDigest':'sha256 from prepare',
                     'expiresAt':'epoch seconds from prepare',
                     'signature':'signature from prepare'},
        'result':'retained reset receipt after bounded workspace deletion',
        'previewRequired':True,'idempotencyRequired':True,
        'workClass':'long','requiredCapabilities':[],
        '_family':'reset','_handlerBoundary':'isolated_migration_owner_adapter'}
    if set(merged)!=set(EXTERNAL_FUNCTIONS):
        missing=set(EXTERNAL_FUNCTIONS)-set(merged)
        unexpected=set(merged)-set(EXTERNAL_FUNCTIONS)
        raise ValueError('PROCESSING_EXTERNAL_OPERATION_DRIFT:'+
                         ','.join(sorted(missing))+':'+
                         ','.join(sorted(unexpected)))
    for name,specification in merged.items():
        if specification['_family']!=EXTERNAL_FUNCTIONS[name]:
            raise ValueError('PROCESSING_EXTERNAL_FAMILY_DRIFT:'+name)
    return merged


def application_family(name:str,specification:dict)->str:
    if not isinstance(name,str) or not isinstance(specification,dict):
        raise ValueError('PROCESSING_OPERATION_CONTRACT_INVALID')
    missing=set(STANDARD_FIELDS)-set(specification)
    if missing:
        raise ValueError('PROCESSING_OPERATION_FIELDS_MISSING:'+
                         name+':'+','.join(sorted(missing)))
    if name.startswith('metadata.layout.populated.'):
        return 'metadata_layout'
    if name.startswith('metadata.'):
        return 'metadata'
    if name.startswith('source.evidence.'):
        return 'metadata'
    if name.startswith('grid.definition.'):
        return 'application_policy'
    if name.startswith('cube.write.'):
        return 'application_policy'
    if name.startswith(('facts.source.','facts.transfer.','facts.export.')):
        return 'bulk_transfer'
    if name.startswith(('facts.cube.aggregate.', 'facts.cube.resolved.')):
        return 'technical_query'
    if name.startswith('cube.aggregate.'):
        return 'technical_query'
    if name.startswith('cube.selection.'):
        return 'selection'
    if name.startswith('calculation.'):
        return 'calculation'
    if name.startswith(('python.program.build', 'python.program.test')):
        return 'python_build'
    if name.startswith('python.'):
        return 'python_program'
    if name.startswith('facts.planning.'):
        return 'planning_calculation'
    if name.startswith(('consolidation.','currency.','financial.')):
        return 'financial_stage'
    if name.startswith('rules.'):
        return 'saved_rule'
    if name.startswith('calculated.member.'):
        return 'saved_rule'
    if name.startswith('application.rule.'):
        return 'saved_rule'
    if name.startswith('schedule.'):
        return 'schedule'
    if name.startswith('planning.'):
        return 'planning_workflow'
    if name.startswith('application.'):
        return 'application_policy'
    if name.startswith('security.'):
        return 'security'
    if name.startswith('execution.'):
        return 'execution_delegation'
    if name.startswith('facts.'):
        if specification['mode'] in READ_MODES:
            return 'fact_read'
        if specification['mode'] in (
                'durable_calculation','durable_sequence','calculation_preview'):
            return 'calculation'
        return 'fact_write'
    raise ValueError('PROCESSING_OPERATION_UNCLASSIFIED:'+name)


def effect_class(specification:dict)->str:
    mode=specification['mode']
    if mode in READ_MODES:
        return 'read_or_preview_no_publication'
    if mode in ('durable_query','durable_technical_query',
                'durable_technical_build','technical_artifact_write',
                'technical_control'):
        return 'technical_certificate_no_business_revision'
    if mode=='durable_staging':
        return 'durable_private_stage_before_publication'
    if mode in DURABLE_MODES:
        return 'durable_server_owned_effect'
    return 'inline_atomic_effect'


def replay_contract(name:str,specification:dict)->dict:
    """Return the transport-independent replay and reconciliation contract."""
    effect=effect_class(specification)
    if effect=='read_or_preview_no_publication':
        return {'idempotency':'not_applicable','uncertainOutcome':'repeat_read',
                'reconciliation':{'strategy':'repeat_authorized_read'}}
    if specification['idempotencyRequired']:
        return {
            'idempotency':
                'same_key_same_content_returns_original_changed_content_conflicts',
            'uncertainOutcome':'exact_replay_before_new_intent',
            'reconciliation':{
                'strategy':'resubmit_same_key_and_identical_content',
                'changedContent':'typed_conflict'}}
    status_reads={
        'cube.aggregate.request':'cube.aggregate.read',
        'cube.aggregate.cancel':'cube.aggregate.read',
        'facts.cube.aggregate.request':'facts.cube.aggregate.read',
        'facts.cube.aggregate.cancel':'facts.cube.aggregate.read',
        'facts.cube.resolved.request':'facts.cube.resolved.result.read',
        'facts.cube.resolved.cancel':'facts.cube.resolved.result.read',
        'metadata.layout.populated.activate.cancel':
            'metadata.layout.populated.activate.read',
        'metadata.layout.populated.replace.cancel':
            'metadata.layout.populated.replace.read',
    }
    if name in status_reads:
        return {'idempotency':'operation_is_not_client_replayable',
                'uncertainOutcome':'authorized_status_read_before_new_intent',
                'reconciliation':{'strategy':'call_authorized_status_function',
                                  'function':status_reads[name]}}
    if name.endswith('.save'):
        return {'idempotency':'operation_is_not_client_replayable',
                'uncertainOutcome':'authorized_named_version_read',
                'reconciliation':{'strategy':'call_authorized_status_function',
                                  'function':name[:-5]+'.read'}}
    if name in ('facts.source.cancel',
                'consolidation.full.sequence.cancel',
                'rules.expression.sequence.cancel'):
        return {'idempotency':'operation_is_not_client_replayable',
                'uncertainOutcome':'repeat_terminal_control',
                'reconciliation':{
                    'strategy':'repeat_compare_and_set_terminal_control'}}
    raise ValueError('PROCESSING_OPERATION_RECONCILIATION_UNCLASSIFIED:'+name)


def preview_contract(specification:dict)->str:
    return ('exact_server_preview_program_digest_and_dependency_pins'
            if specification['previewRequired'] else 'not_required')


def _registry_entry(name:str,specification:dict,*,family:str,
                    handler_boundary:str,scope:str)->dict:
    missing=set(STANDARD_FIELDS)-set(specification)
    if scope=='platform':
        missing.discard('requiredCapabilities')
        if specification.get('permission')!='platform_operator':
            raise ValueError('PROCESSING_PLATFORM_PERMISSION_INVALID:'+name)
    if missing:
        raise ValueError('PROCESSING_OPERATION_FIELDS_MISSING:'+
                         name+':'+','.join(sorted(missing)))
    from .postgres_capability_contract import source_purpose
    if family not in PRODUCT_PURPOSES:
        raise ValueError('PROCESSING_OPERATION_PURPOSE_UNCLASSIFIED:'+name)
    return {'function':name,'family':family,'scope':scope,
            'productPurpose':PRODUCT_PURPOSES[family],
            'sourcePurpose':source_purpose(name),
            'mode':specification['mode'],'permission':specification['permission'],
            'argumentSchema':specification['arguments'],
            'resultSchema':specification['result'],
            'previewRequired':specification['previewRequired'],
            'idempotencyRequired':specification['idempotencyRequired'],
            'workClass':specification['workClass'],
            'effectClass':effect_class(specification),
            'previewBinding':preview_contract(specification),
            'replay':replay_contract(name,specification),
            'executionBudget':execution_budget(specification),
            'handlerBoundary':handler_boundary,
            'effectOwner':handler_boundary}


def execution_budget(specification:dict)->dict:
    work_class=specification['workClass']
    if work_class not in WORK_BUDGETS:
        raise ValueError('PROCESSING_OPERATION_WORK_CLASS_UNCLASSIFIED:'+work_class)
    return dict(WORK_BUDGETS[work_class])


def build_registry(functions:dict)->dict:
    if not isinstance(functions,dict):
        raise ValueError('PROCESSING_OPERATION_REGISTRY_INVALID')
    from .postgres_security_language import PostgresSecurityLanguage
    security_functions=PostgresSecurityLanguage.catalog()['functions']
    application_functions=dict(functions)
    for name,specification in security_functions.items():
        if name in application_functions:
            if application_functions[name]!=specification:
                raise ValueError('PROCESSING_APPLICATION_OPERATION_DUPLICATE:'+name)
            application_functions[name]={**specification,
                                         'requiredCapabilities':[]}
        else:
            application_functions[name]={**specification,
                                         'requiredCapabilities':[]}
    entries=[]
    for name,specification in sorted(application_functions.items()):
        family=application_family(name,specification)
        entries.append(_registry_entry(name,specification,family=family,
            handler_boundary=('application_security_adapter'
                if name in security_functions
                else 'fixed_python_application_language'),
            scope='application'))
    counts=Counter(entry['family'] for entry in entries)
    external=[]
    for name,specification in sorted(external_function_catalog().items()):
        external.append(_registry_entry(name,specification,
            family=specification['_family'],
            handler_boundary=specification['_handlerBoundary'],
            scope='workspace'))
    platform=[]
    for name,specification in sorted(platform_function_catalog().items()):
        family=('identity_directory' if name.startswith('identity.')
                else 'platform_lifecycle')
        boundary=('platform_identity_directory_adapter'
                  if family=='identity_directory'
                  else 'platform_provisioning_adapter')
        platform.append(_registry_entry(name,specification,family=family,
            handler_boundary=boundary,scope='platform'))
    return {'format':PROCESSING_REGISTRY_FORMAT,
            'applicationFunctionCount':len(entries),
            'applicationFamilyCounts':dict(sorted(counts.items())),
            'applicationFunctions':entries,'externalFunctions':external,
            'platformFunctions':platform}


def platform_function_catalog()->dict:
    """Return the exact public platform catalogue under the shared contract."""
    from .postgres_identity_directory import catalog as identity_catalog
    from .postgres_platform_provision import PostgresPlatformProvisioner
    provision=PostgresPlatformProvisioner.catalog()['functions']
    identity=identity_catalog()['functions']
    merged={**provision,**identity}
    if len(merged)!=len(provision)+len(identity):
        raise ValueError('PROCESSING_PLATFORM_OPERATION_DUPLICATE')
    return merged


def operation_contracts(functions:dict,*,scope:str)->dict:
    """Select exact executable descriptors for one transport catalogue."""
    if not isinstance(functions,dict) or scope not in (
            'application','workspace','platform'):
        raise ValueError('PROCESSING_OPERATION_SELECTION_INVALID')
    if scope=='application':
        from .postgres_language_v2 import PostgresLanguageV2
        registry=build_registry(PostgresLanguageV2.catalog()['functions'])
    elif scope=='workspace':
        registry=build_registry({})
    else:
        registry=build_registry({})
    entries=registry[{'application':'applicationFunctions',
                      'workspace':'externalFunctions',
                      'platform':'platformFunctions'}[scope]]
    indexed={entry['function']:entry for entry in entries}
    missing=set(functions)-set(indexed)
    if missing:
        raise ValueError('PROCESSING_OPERATION_SELECTION_UNCLASSIFIED:'+
                         ','.join(sorted(missing)))
    selected={}
    for name in sorted(functions):
        entry=dict(indexed[name])
        specification=functions[name]
        for field in ('permission','previewRequired','idempotencyRequired',
                      'workClass'):
            if entry[field]!=specification[field]:
                raise ValueError('PROCESSING_OPERATION_SELECTION_DRIFT:'+
                                 name+':'+field)
        selected[name]=entry
    return selected


def processing_registry_digest(contracts:dict)->str:
    """Bind the complete semantic contract set returned by discovery."""
    if (not isinstance(contracts,dict) or any(
            not isinstance(name,str) or not isinstance(value,dict)
            for name,value in contracts.items())):
        raise ValueError('PROCESSING_OPERATION_REGISTRY_INVALID')
    envelope={'format':PROCESSING_REGISTRY_FORMAT,'contracts':contracts}
    try:
        raw=json.dumps(envelope,sort_keys=True,separators=(',',':'),
            ensure_ascii=True,allow_nan=False).encode('ascii')
    except (TypeError,ValueError,UnicodeEncodeError) as exc:
        raise ValueError('PROCESSING_OPERATION_REGISTRY_INVALID') from exc
    return sha256(raw).hexdigest()


def admit_operation(program:object,*,scope:str,
                    handler_boundary:str|None=None)->dict:
    """Resolve one public program to its authoritative transport contract."""
    if (not isinstance(program,dict)
            or not isinstance(program.get('function'),str)):
        raise ValueError('PROCESSING_OPERATION_PROGRAM_INVALID')
    name=program['function']
    if scope=='application':
        from .postgres_language_v2 import PostgresLanguageV2
        from .postgres_security_language import PostgresSecurityLanguage
        specification=(PostgresLanguageV2.catalog()['functions'].get(name)
                       or PostgresSecurityLanguage.catalog()[
                           'functions'].get(name))
    elif scope=='workspace':
        specification=external_function_catalog().get(name)
    elif scope=='platform':
        specification=platform_function_catalog().get(name)
    else:
        raise ValueError('PROCESSING_OPERATION_SELECTION_INVALID')
    if specification is None:
        raise ValueError('PROCESSING_OPERATION_NOT_REGISTERED:'+name)
    contract=operation_contracts({name:specification},scope=scope)[name]
    if (handler_boundary is not None
            and contract['handlerBoundary']!=handler_boundary):
        raise ValueError('PROCESSING_OPERATION_HANDLER_MISMATCH:'+name)
    return contract
