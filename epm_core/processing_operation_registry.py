"""Executable operation-family inventory for processing and recovery audits.

This registry classifies public contracts; it does not replace the fixed core's
authorization, locking, queue, lease, publication, or cleanup implementation.
Unknown functions fail closed so a new public surface cannot silently escape
the P08 operation-family review.
"""
from __future__ import annotations

from collections import Counter

STANDARD_FIELDS=frozenset((
    'mode','permission','previewRequired','idempotencyRequired','workClass',
    'arguments','result','requiredCapabilities'))
PROCESSING_REGISTRY_FORMAT='openepm-processing-operation-registry-v2'

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
    from .postgres_workspace_reset import PostgresWorkspaceResetPreview

    merged={}
    sources=(
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
    missing=STANDARD_FIELDS-set(specification)
    if missing:
        raise ValueError('PROCESSING_OPERATION_FIELDS_MISSING:'+
                         name+':'+','.join(sorted(missing)))
    if name.startswith('metadata.layout.populated.'):
        return 'metadata_layout'
    if name.startswith('metadata.'):
        return 'metadata'
    if name.startswith('grid.definition.'):
        return 'application_policy'
    if name.startswith('cube.write.'):
        return 'application_policy'
    if name.startswith(('facts.source.','facts.transfer.','facts.export.')):
        return 'bulk_transfer'
    if name.startswith('facts.cube.aggregate.'):
        return 'technical_query'
    if name.startswith('cube.aggregate.'):
        return 'technical_query'
    if name.startswith('cube.selection.'):
        return 'selection'
    if name.startswith('python.program.build'):
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
    if name in ('consolidation.full.sequence.cancel',
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
    missing=STANDARD_FIELDS-set(specification)
    if missing:
        raise ValueError('PROCESSING_OPERATION_FIELDS_MISSING:'+
                         name+':'+','.join(sorted(missing)))
    return {'function':name,'family':family,'scope':scope,
            'mode':specification['mode'],'permission':specification['permission'],
            'previewRequired':specification['previewRequired'],
            'idempotencyRequired':specification['idempotencyRequired'],
            'workClass':specification['workClass'],
            'effectClass':effect_class(specification),
            'previewBinding':preview_contract(specification),
            'replay':replay_contract(name,specification),
            'executionBudget':execution_budget(specification),
            'handlerBoundary':handler_boundary}


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
    return {'format':PROCESSING_REGISTRY_FORMAT,
            'applicationFunctionCount':len(entries),
            'applicationFamilyCounts':dict(sorted(counts.items())),
            'applicationFunctions':entries,'externalFunctions':external}


def operation_contracts(functions:dict,*,scope:str)->dict:
    """Select exact executable descriptors for one transport catalogue."""
    if not isinstance(functions,dict) or scope not in ('application','workspace'):
        raise ValueError('PROCESSING_OPERATION_SELECTION_INVALID')
    if scope=='application':
        from .postgres_language_v2 import PostgresLanguageV2
        registry=build_registry(PostgresLanguageV2.catalog()['functions'])
    else:
        registry=build_registry({})
    entries=registry['externalFunctions' if scope=='workspace'
                     else 'applicationFunctions']
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
    else:
        raise ValueError('PROCESSING_OPERATION_SELECTION_INVALID')
    if specification is None:
        raise ValueError('PROCESSING_OPERATION_NOT_REGISTERED:'+name)
    contract=operation_contracts({name:specification},scope=scope)[name]
    if (handler_boundary is not None
            and contract['handlerBoundary']!=handler_boundary):
        raise ValueError('PROCESSING_OPERATION_HANDLER_MISMATCH:'+name)
    return contract
