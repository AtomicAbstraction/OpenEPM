"""Current typed definition ownership; callers own authorization and transaction.

The rule/list row is the business identity. Source and compiler output are its
current representations; a diagnostic build is never a runtime owner lookup.
"""
from __future__ import annotations

from psycopg.types.json import Jsonb

from .postgres_capability_contract import SOURCE_PURPOSE_CONTRACT

OWNER_TABLES = {
    'ApplicationRule': ('expression_rule_definition', 'rule_id'),
    'CalculatedMember': ('expression_rule_definition', 'rule_id'),
    'ExpressionRule': ('expression_rule_definition', 'rule_id'),
    'MemberList': ('member_list_definition', 'list_id'),
}
STORED_KINDS = {'application.rule.plan': 'ApplicationRule',
    'calculated.member.definition': 'CalculatedMember',
    'facts.expression.calculate': 'ExpressionRule'}


def owner_kind(row):
    return 'MemberList' if 'list_id' in row else row['definition_kind']


def effective_state(row, *, metadata_revision=None, schema_epoch=None):
    if row is None:
        return {'defined': False, 'valid': False, 'active': False,
            'sourceCurrent': False, 'resultCurrent': None, 'executable':False, 'reason': 'not_defined'}
    source_current = row['ownership_state'] != 'Unresolved'
    payload = row.get('definition') if 'list_id' in row else row.get('program')
    certificate = row.get('current_certificate')
    digest=row.get('canonical_digest') if 'list_id' in row else row.get('program_digest')
    valid = bool(source_current and payload is not None and isinstance(certificate,dict)
        and certificate.get('format')=='openepm-current-definition-certificate-v1'
        and certificate.get('semanticsVersion')=='openepm-current-definition-v1'
        and certificate.get('sourcePurposeContract')==SOURCE_PURPOSE_CONTRACT
        and certificate.get('kind')==owner_kind(row)
        and certificate.get('definitionId')==row.get('list_id',row.get('rule_id'))
        and certificate.get('compiledDigest')==digest
        and certificate.get('metadataRevision')==row['metadata_revision']
        and (row['ownership_state']!='Source' or (
            certificate.get('sourceToken')==row['source_token'] and
            certificate.get('sourceDigest')==row['source_digest']))
        and (row['ownership_state']!='Configuration' or (
            certificate.get('acceptance')=='FixedValidation' and
            certificate.get('compilerVersion')=='openepm-fixed-definition-v1')))
    reason = ('ownership_unresolved' if not source_current else
              'validation_required' if not valid else None)
    if valid and metadata_revision is not None and row['metadata_revision'] != metadata_revision:
        valid, reason = False, 'metadata_stale'
    if valid and schema_epoch is not None and certificate.get('schemaEpoch')!=schema_epoch:
        valid,reason=False,'schema_stale'
    active = row['status'] in ('Active', 'Published') and source_current
    if reason is None and not active:
        reason = 'inactive'
    return {'defined': True, 'valid': valid, 'active': active,
        'sourceCurrent': source_current, 'resultCurrent': None, 'executable':bool(active and valid),
        'reason': reason, 'status': 'Unavailable' if not source_current else
        'Active' if active else 'Inactive'}


def source_binding(row):
    """Resolve only the direct owner pins; diagnostic expiry is irrelevant."""
    if row['ownership_state'] != 'Source':
        return None
    return {'programId': row['source_program_id'],
        'programSourceToken': row['source_token'], 'sourceDigest': row['source_digest'],
        'buildId': row.get('source_build_id'),
        'active': row['status'] in ('Active', 'Published')}


def resolution_context(db, scope, owners):
    """Batch current acceptance cuts for one authorized scoped read/transition."""
    state = db.execute('''SELECT metadata_revision,schema_epoch FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None:
        raise ValueError('APPLICATION_UNAVAILABLE')
    ids = sorted({row['source_program_id'] for row in owners
                  if row and row['ownership_state']=='Source'})
    environments = {}
    if ids:
        environments = {r['program_id']:r for r in db.execute('''SELECT s.program_id,
            s.environment_id,s.environment_state_token,e.manifest,e.manifest_digest
            FROM epm.python_program_definition s JOIN epm.python_environment_definition e
            ON(e.workspace_id,e.application_id,e.environment_id,e.state_token)=
              (s.workspace_id,s.application_id,s.environment_id,s.environment_state_token)
            WHERE s.workspace_id=%s AND s.application_id=%s AND s.program_id=ANY(%s)
              AND e.status='Active' ''',
            (scope.workspace_id,scope.application_id,ids)).fetchall()}
    dependencies = {}
    for table,key,kinds in (
            ('expression_rule_definition','rule_id',{'ApplicationRule','CalculatedMember','ExpressionRule'}),
            ('member_list_definition','list_id',{'MemberList'})):
        selected = sorted({r[key] for r in owners if r and owner_kind(r) in kinds})
        if not selected:
            continue
        kind_column = "'MemberList'" if key=='list_id' else 'definition_kind'
        payload_column = 'definition' if key=='list_id' else 'program'
        rows = db.execute(f'''SELECT {key} id,{kind_column} kind,
            epm.definition_dependency_digest(workspace_id,application_id,{kind_column},{payload_column}) digest
            FROM epm.{table} WHERE workspace_id=%s AND application_id=%s AND {key}=ANY(%s)''',
            (scope.workspace_id,scope.application_id,selected)).fetchall()
        dependencies.update({(r['kind'],r['id']):r['digest'] for r in rows})
    return {**state,'environments':environments,'dependencies':dependencies}


def _current_state(row, context, *, require_metadata_cut):
    state = effective_state(row,
        metadata_revision=context['metadata_revision'] if require_metadata_cut else None,
        schema_epoch=context['schema_epoch'])
    if row is None or not state['valid']:
        return state
    cert = row['current_certificate']
    key=(owner_kind(row),row.get('rule_id',row.get('list_id')))
    if cert.get('dependencyDigest')!=context['dependencies'].get(key):
        return {**state,'valid':False,'executable':False,'reason':'dependency_stale'}
    if row['ownership_state']=='Source':
        environment=context['environments'].get(row['source_program_id'])
        if environment is None or (cert.get('environmentId'),cert.get('environmentStateToken')) != (
                environment['environment_id'],environment['environment_state_token']):
            return {**state,'valid':False,'executable':False,'reason':'source_environment_stale'}
        manifest=environment['manifest']
        compilers=manifest.get('compilerVersions',[manifest.get('compilerVersion')])
        from .postgres_jobs import _canonical_digest
        if _canonical_digest(manifest)!=environment['manifest_digest'] or cert.get('compilerVersion') not in compilers:
            return {**state,'valid':False,'executable':False,'reason':'compiler_unavailable'}
    return state


def current_state(row, context):
    return _current_state(row, context, require_metadata_cut=True)


def definition_state_axes(row, context):
    """Separate run admission from the accepted identity of a published result.

    A different application metadata cut still requires execution revalidation.
    It does not by itself invalidate an existing result: its certified scoped
    dependencies and processed impacts decide that separately. Every other
    current owner, source, certificate, schema, environment and static reference
    check remains common. This result axis alone never establishes freshness.
    """
    execution = current_state(row, context)
    semantic = _current_state(row, context, require_metadata_cut=False)
    return {'execution': execution,
        'resultDefinitionValid': bool(semantic['valid'] and semantic['active']),
        'resultDefinitionReason': semantic['reason']}


def assert_current_executable(db, scope, row):
    state=current_state(row,resolution_context(db,scope,[row]))
    if not state['sourceCurrent']:
        raise ValueError('DEFINITION_OWNERSHIP_UNRESOLVED')
    if not state['valid']:
        raise ValueError('DEFINITION_CURRENT_VALIDATION_REQUIRED:'+state['reason'])
    if not state['active']:
        raise ValueError('PYTHON_DEFINITION_SOURCE_NOT_ACTIVE' if row['ownership_state']=='Source'
                         else 'DEFINITION_NOT_ACTIVE')


def read_owner(db, scope, declaration, *, lock=False):
    table, key = OWNER_TABLES[declaration['kind']]
    row = db.execute(f'''SELECT * FROM epm.{table} WHERE workspace_id=%s
        AND application_id=%s AND {key}=%s''' + (' FOR UPDATE' if lock else ''),
        (scope.workspace_id, scope.application_id, declaration['definitionId'])).fetchone()
    if row and (owner_kind(row) != declaration['kind'] or
            declaration['kind'] == 'MemberList' and row['dimension_id'] != declaration['dimensionId']):
        raise ValueError('DEFINITION_OWNER_IDENTITY_MISMATCH')
    return row


def source_owner_states(db, scope, sources):
    """Program compatibility views use the same typed-owner state as rules/lists."""
    ids=sorted({s['program_id'] for s in sources if s and s.get('declared_output') is not None})
    if not ids:
        return {}
    owners=[]
    for table in ('expression_rule_definition','member_list_definition'):
        owners.extend(db.execute(f'''SELECT * FROM epm.{table} WHERE workspace_id=%s
            AND application_id=%s AND source_program_id=ANY(%s)''',
            (scope.workspace_id,scope.application_id,ids)).fetchall())
    context=resolution_context(db,scope,owners)
    return {r['source_program_id']:{**current_state(r,context),
        'definition':{'kind':owner_kind(r),'definitionId':r.get('list_id',r.get('rule_id'))}}
        for r in owners}


def source_for_build(db, scope, build_id):
    if build_id is None:
        return None
    row = db.execute('''SELECT s.*,b.build_id,b.program_source_token
        FROM epm.python_program_build b JOIN epm.python_program_definition s
        ON(s.workspace_id,s.application_id,s.program_id,s.source_token)=
          (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
        WHERE b.workspace_id=%s AND b.application_id=%s AND b.build_id=%s''',
        (scope.workspace_id, scope.application_id, build_id)).fetchone()
    if row is None:
        raise ValueError('PYTHON_DEFINITION_SOURCE_UNAVAILABLE')
    return row


def certificate(db, scope, *, kind, definition_id, digest, metadata_revision,
                source_build_id=None, payload=None):
    if source_build_id is not None:
        value = db.execute('''SELECT epm.definition_certificate_for_build(%s,%s,%s,%s,%s,%s) value''',
            (scope.workspace_id, scope.application_id, source_build_id, kind, definition_id, digest)).fetchone()['value']
        if value is None:
            raise ValueError('DEFINITION_VALIDATED_BUILD_REQUIRED')
        return value
    state = db.execute('''SELECT schema_epoch FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    if payload is None:
        raise ValueError('DEFINITION_CERTIFICATE_PAYLOAD_REQUIRED')
    dependency_digest=db.execute('''SELECT epm.definition_dependency_digest(%s,%s,%s,%s) digest''',
        (scope.workspace_id,scope.application_id,kind,Jsonb(payload))).fetchone()['digest']
    return {'format': 'openepm-current-definition-certificate-v1',
        'semanticsVersion':'openepm-current-definition-v1','sourcePurposeContract':SOURCE_PURPOSE_CONTRACT,
        'dependencyDigest':dependency_digest,
        'acceptance': 'FixedValidation', 'kind': kind, 'definitionId': definition_id,
        'compiledDigest': digest, 'compilerVersion': 'openepm-fixed-definition-v1',
        'metadataRevision': metadata_revision, 'schemaEpoch': state['schema_epoch'],
        'impactTestAccepted': False}


def require_declared_output(db, scope, source_program, target, definition):
    if source_program is None:
        raise ValueError('PYTHON_DECLARED_OUTPUT_REQUIRED')
    row = db.execute('''SELECT declared_output FROM epm.python_program_definition
        WHERE workspace_id=%s AND application_id=%s AND program_id=%s AND source_token=%s''',
        (scope.workspace_id, scope.application_id, *source_program)).fetchone()
    declared = row and row['declared_output']
    expected = dict(target)
    if target['kind'] == 'MemberList':
        expected['dimensionId'] = definition['dimensionId']
    if declared != expected:
        raise ValueError('PYTHON_DECLARED_OUTPUT_MISMATCH' if declared else 'PYTHON_DECLARED_OUTPUT_REQUIRED')


def _symbolic_references(kind, payload):
    """Project fixed current business references, not runtime parameter values."""
    if payload is None or kind == 'MemberList':
        return set()
    result = set()
    def walk(value):
        if isinstance(value, dict):
            if value.get('kind') == 'member_list' and isinstance(value.get('listId'), str):
                result.add(('list', value['listId']))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(payload)
    if kind == 'CalculatedMember':
        for dependency in payload['arguments']['dependencies']:
            result.add(('rule', dependency['definitionId']))
    return result


def replace_references(db, scope, *, kind, definition_id, payload):
    consumer = 'list' if kind == 'MemberList' else 'rule'
    db.execute('''DELETE FROM epm.current_definition_reference WHERE workspace_id=%s
        AND application_id=%s AND consumer_kind=%s AND consumer_id=%s''',
        (scope.workspace_id, scope.application_id, consumer, definition_id))
    for producer, identity in sorted(_symbolic_references(kind, payload)):
        db.execute(f'''INSERT INTO epm.current_definition_reference(workspace_id,application_id,
            consumer_{consumer}_id,producer_{producer}_id) VALUES(%s,%s,%s,%s)''',
            (scope.workspace_id, scope.application_id, definition_id, identity))


def _active_blockers(db, scope, source):
    blockers = []
    for row in db.execute('''SELECT build_id,status FROM epm.python_program_build
        WHERE workspace_id=%s AND application_id=%s AND program_id=%s
        AND status IN('accepted','ready','running','cancel_requested') ORDER BY build_id''',
        (scope.workspace_id, scope.application_id, source['program_id'])).fetchall():
        blockers.append({'kind': 'python-build', 'id': row['build_id'], 'state': row['status']})
    for row in db.execute('''SELECT schedule_id,status FROM epm.python_program_schedule_definition
        WHERE workspace_id=%s AND application_id=%s AND program_id=%s AND status='Active'
        ORDER BY schedule_id''',
        (scope.workspace_id, scope.application_id, source['program_id'])).fetchall():
        blockers.append({'kind': 'python-schedule', 'id': row['schedule_id'], 'state': row['status']})
    for row in db.execute('''SELECT f.workflow_id,f.status FROM epm.python_program_workflow f
        JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
        WHERE b.workspace_id=%s AND b.application_id=%s AND b.program_id=%s
          AND f.status IN('accepted','running','cancel_requested','needs_inspection') ORDER BY f.workflow_id''',
        (scope.workspace_id,scope.application_id,source['program_id'])).fetchall():
        blockers.append({'kind':'python-workflow','id':row['workflow_id'],'state':row['status']})
    declared = source.get('declared_output')
    if declared:
        producer = 'list' if declared['kind']=='MemberList' else 'rule'
        for row in db.execute('''SELECT f.consumer_kind,f.consumer_id,
            coalesce(r.status,l.status) status FROM epm.current_definition_reference f
            LEFT JOIN epm.expression_rule_definition r ON
             (r.workspace_id,r.application_id,r.rule_id)=(f.workspace_id,f.application_id,f.consumer_rule_id)
            LEFT JOIN epm.member_list_definition l ON
             (l.workspace_id,l.application_id,l.list_id)=(f.workspace_id,f.application_id,f.consumer_list_id)
            WHERE f.workspace_id=%s AND f.application_id=%s AND f.producer_kind=%s
             AND f.producer_id=%s AND coalesce(r.status,l.status) IN('Active','Published')
            ORDER BY f.consumer_kind,f.consumer_id''',
            (scope.workspace_id,scope.application_id,producer,declared['definitionId'])).fetchall():
            blockers.append({'kind':row['consumer_kind'],'id':row['consumer_id'],'state':row['status']})
    if declared and declared['kind'] != 'MemberList':
        for row in db.execute('''SELECT workflow_id,status FROM epm.application_rule_workflow
            WHERE workspace_id=%s AND application_id=%s AND rule_id=%s
            AND status IN('accepted','running','cancel_requested','needs_inspection') ORDER BY workflow_id''',
            (scope.workspace_id, scope.application_id, declared['definitionId'])).fetchall():
            blockers.append({'kind': 'rule-workflow', 'id': row['workflow_id'], 'state': row['status']})
        for row in db.execute('''SELECT schedule_id,status FROM epm.application_schedule_definition
            WHERE workspace_id=%s AND application_id=%s AND rule_id=%s AND status='Active'
            ORDER BY schedule_id''',
            (scope.workspace_id, scope.application_id, declared['definitionId'])).fetchall():
            blockers.append({'kind': 'rule-schedule', 'id': row['schedule_id'], 'state': row['status']})
    return blockers


class DefinitionReferenceBlocked(ValueError):
    def __init__(self, blockers):
        self.blockers = blockers
        super().__init__('DEFINITION_REFERENCES_BLOCK_REMOVAL')


def require_no_active_references(db, scope, source):
    blockers = _active_blockers(db, scope, source)
    if blockers:
        raise DefinitionReferenceBlocked(blockers)


def _impact(db, scope, *, kind, definition_id, operation_id, revision, change):
    from .calculation_impact_contract import compile_calculation_impact
    from .postgres_calculation_impact import record_calculation_impact
    impact = compile_calculation_impact({'format': 'openepm-calculation-impact-v1',
        'sourceKind': 'definition', 'sourceId': operation_id, 'causalRevision': revision,
        'effects': [{'domain': 'definition', 'change': change,
            'objectType': {'MemberList': 'member-list', 'CalculatedMember': 'calculated-member',
                'ApplicationRule': 'application-rule'}[kind],
            'objectId': definition_id, 'scope': [], 'reason': 'definition_changed',
            'oldPresence': 'present', 'newPresence': 'absent'}]})
    record_calculation_impact(db, scope, operation_id=operation_id, impact=impact)


def retire_source_payloads(db, scope, source):
    rows=db.execute('''SELECT f.workflow_id,f.status FROM epm.python_program_workflow f
        JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
        WHERE b.workspace_id=%s AND b.application_id=%s AND b.program_id=%s
          AND b.program_source_token=%s
          AND f.status IN('accepted','running','cancel_requested','needs_inspection')
        ORDER BY f.workflow_id''',
        (scope.workspace_id,scope.application_id,source['program_id'],source['source_token'])).fetchall()
    if rows:
        raise DefinitionReferenceBlocked([{'kind':'python-workflow','id':r['workflow_id'],
            'state':r['status']} for r in rows])
    db.execute('SELECT epm.definition_source_payload_retire(%s,%s,%s,%s)',
        (scope.workspace_id,scope.application_id,source['program_id'],source['source_token']))


def save_source_owner(db, scope, *, definition, current_source, state_token, source_token,
                      operation_id, revision, identity, metadata_revision, expected_owner_token=None):
    declared = definition.get('declaredOutput')
    if current_source and current_source.get('declared_output') != declared:
        if current_source.get('declared_output') is not None:
            raise ValueError('DEFINITION_OWNER_RETARGET_REQUIRES_REPLACEMENT')
    if current_source:
        require_no_active_references(db, scope, current_source)
        retire_source_payloads(db,scope,current_source)
    if declared is None:
        if expected_owner_token is not None:
            raise ValueError('DEFINITION_OWNER_TOKEN_WITHOUT_DECLARATION')
        return
    owner = read_owner(db, scope, declared, lock=True)
    if owner:
        same_source = owner['ownership_state'] == 'Source' and owner['source_program_id'] == definition['programId']
        if not same_source and expected_owner_token != owner['state_token']:
            raise ValueError('DEFINITION_OWNER_ADOPTION_TOKEN_REQUIRED')
        if same_source and expected_owner_token is not None and expected_owner_token != owner['state_token']:
            raise ValueError('DEFINITION_OWNER_STATE_CONFLICT')
        if owner['ownership_state'] == 'Source' and not same_source:
            raise ValueError('DEFINITION_OWNER_ALREADY_HAS_SOURCE')
    elif expected_owner_token is not None:
        raise ValueError('DEFINITION_OWNER_NOT_FOUND')
    kind, object_id = declared['kind'], declared['definitionId']
    table, key = OWNER_TABLES[kind]
    if owner:
        payload_column, digest_column = ('definition','canonical_digest') if kind == 'MemberList' else ('program','program_digest')
        db.execute(f'''UPDATE epm.{table} SET ownership_state='Source',source_program_id=%s,
            source_token=%s,source_digest=%s,state_token=%s,status='Inactive',
            {payload_column}=NULL,{digest_column}=NULL,current_certificate=NULL,source_build_id=NULL,
            metadata_revision=%s,updated_operation_id=%s,updated_at=transaction_timestamp()
            WHERE workspace_id=%s AND application_id=%s AND {key}=%s''',
            (definition['programId'],source_token,definition['sourceDigest'],state_token,
             metadata_revision,operation_id,scope.workspace_id,scope.application_id,object_id))
        replace_references(db, scope, kind=kind, definition_id=object_id, payload=None)
        _impact(db,scope,kind=kind,definition_id=object_id,operation_id=operation_id,revision=revision,change='replace')
    elif kind == 'MemberList':
        db.execute('''INSERT INTO epm.member_list_definition(workspace_id,application_id,list_id,
            dimension_id,name,state_token,status,metadata_revision,creator_issuer,creator_subject_id,
            ownership_state,source_program_id,source_token,source_digest,updated_operation_id)
            VALUES(%s,%s,%s,%s,%s,%s,'Inactive',%s,%s,%s,'Source',%s,%s,%s,%s)''',
            (scope.workspace_id,scope.application_id,object_id,declared['dimensionId'],object_id,
             state_token,metadata_revision,identity.issuer,identity.subject_id,
             definition['programId'],source_token,definition['sourceDigest'],operation_id))
    else:
        db.execute('''INSERT INTO epm.expression_rule_definition(workspace_id,application_id,rule_id,
            definition_kind,state_token,status,metadata_revision,updated_issuer,updated_subject_id,
            ownership_state,source_program_id,source_token,source_digest,updated_operation_id)
            VALUES(%s,%s,%s,%s,%s,'Inactive',%s,%s,%s,'Source',%s,%s,%s,%s)''',
            (scope.workspace_id,scope.application_id,object_id,kind,state_token,metadata_revision,
             identity.issuer,identity.subject_id,definition['programId'],source_token,
             definition['sourceDigest'],operation_id))


def transition_source_owner(db, scope, *, source, delete, state_token, operation_id, revision):
    require_no_active_references(db, scope, source)
    declared = source.get('declared_output')
    if delete:
        retire_source_payloads(db,scope,source)
    if declared is None:
        return
    owner = read_owner(db, scope, declared, lock=True)
    if owner is None or owner['source_program_id'] != source['program_id']:
        raise ValueError('DEFINITION_SOURCE_OWNER_INCOMPLETE')
    kind, object_id = declared['kind'], declared['definitionId']
    table, key = OWNER_TABLES[kind]
    if delete:
        producer = 'list' if kind == 'MemberList' else 'rule'
        blockers = [{'kind': r['consumer_kind'], 'id': r['consumer_id']} for r in db.execute('''
            SELECT consumer_kind,consumer_id FROM epm.current_definition_reference
            WHERE workspace_id=%s AND application_id=%s AND producer_kind=%s AND producer_id=%s
            ORDER BY consumer_kind,consumer_id''',
            (scope.workspace_id,scope.application_id,producer,object_id)).fetchall()]
        for r in db.execute('''SELECT schedule_id FROM epm.python_program_schedule_definition
            WHERE workspace_id=%s AND application_id=%s AND program_id=%s ORDER BY schedule_id''',
            (scope.workspace_id,scope.application_id,source['program_id'])).fetchall():
            blockers.append({'kind':'python-schedule','id':r['schedule_id']})
        if kind != 'MemberList':
            for relation, identity_column, label in (
                    ('application_schedule_definition','schedule_id','rule-schedule'),
                    ('application_rule_workflow','workflow_id','rule-workflow')):
                for r in db.execute(f'''SELECT {identity_column} id FROM epm.{relation}
                    WHERE workspace_id=%s AND application_id=%s AND rule_id=%s ORDER BY {identity_column}''',
                    (scope.workspace_id,scope.application_id,object_id)).fetchall():
                    blockers.append({'kind':label,'id':r['id']})
        if blockers:
            raise DefinitionReferenceBlocked(blockers)
        db.execute(f'''DELETE FROM epm.{table} WHERE workspace_id=%s AND application_id=%s AND {key}=%s''',
            (scope.workspace_id,scope.application_id,object_id))
    else:
        db.execute(f'''UPDATE epm.{table} SET status='Inactive',state_token=%s,updated_operation_id=%s,
            updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s AND {key}=%s''',
            (state_token,operation_id,scope.workspace_id,scope.application_id,object_id))
    _impact(db,scope,kind=kind,definition_id=object_id,operation_id=operation_id,revision=revision,
            change='delete' if delete else 'deactivate')
