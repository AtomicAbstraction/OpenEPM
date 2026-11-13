"""Fixed validators and activation of typed, source-owned definition artifacts.

Authored Python executes only in the builder. This boundary consumes its sealed
JSON artifact through the same canonicalizers and stores as ordinary definitions.
"""
from __future__ import annotations

from hashlib import sha256
from .postgres_capability_contract import SOURCE_AUTHORING_RETIRED_FUNCTIONS as RETIRED_PUBLIC_AUTHORING


KINDS = {
    'application.rule.save': 'ApplicationRule',
    'calculated.member.save': 'CalculatedMember',
}
RETIRED_SOURCE_DEFINITIONS = frozenset(('metadata.member_list.save',))

def definition_specification(function):
    """Fixed internal validators remain authoritative after JSON authoring retires."""
    if function == 'application.rule.save':
        from .postgres_application_rules import catalog
    elif function == 'calculated.member.save':
        from .postgres_calculated_members import catalog
    else:
        raise ValueError('PYTHON_DEFINITION_KIND_UNSUPPORTED')
    return catalog()[function]


def descriptor(plan: dict) -> dict | None:
    units = plan.get('units', [])
    operations = [operation for unit in units for operation in unit.get('operations', [])]
    if any(operation.get('function') in RETIRED_SOURCE_DEFINITIONS
           for operation in operations if isinstance(operation, dict)):
        raise ValueError('PYTHON_SOURCE_FUNCTION_FORBIDDEN')
    definitions = [operation for operation in operations if operation.get('function') in KINDS]
    if not definitions:
        return None
    if len(units) != 1 or len(operations) != 1:
        raise ValueError('PYTHON_DEFINITION_MIXED_PLAN_FORBIDDEN')
    operation = definitions[0]
    function, args = operation['function'], operation['arguments']
    value = args['definition']
    identity = (args['ruleId'] if KINDS[function] == 'ApplicationRule'
                else value['definitionId'])
    return {'kind': KINDS[function], 'definitionId': identity}


def service_for(function, dsn, identity):
    if function == 'application.rule.save':
        from .postgres_application_rules import PostgresApplicationRules
        return PostgresApplicationRules(dsn, identity=identity)
    if function == 'calculated.member.save':
        from .postgres_calculated_members import PostgresCalculatedMembers
        return PostgresCalculatedMembers(dsn, identity=identity)
    raise ValueError('PYTHON_DEFINITION_KIND_UNSUPPORTED')


def validate_definition(db, scope, program, *, dsn, identity, source_program=None):
    function = program['function']
    service = service_for(function, dsn, identity)
    args = program['arguments']
    definition = service._parse(program, function)['plan']
    service._validate_definition(db, scope, definition)
    target = descriptor({'units': [{'operations': [program]}]})
    from .postgres_definition_lifecycle import require_declared_output, read_owner
    require_declared_output(db, scope, source_program, target, definition)
    declared = target
    prior = read_owner(db, scope, declared)
    if prior is None or prior['ownership_state'] != 'Source' or (
            prior['source_program_id'], prior['source_token']) != source_program:
        raise ValueError('PYTHON_DEFINITION_SOURCE_MISMATCH')
    if args.get('expectedStateToken', prior['state_token']) != prior['state_token']:
        raise ValueError('PYTHON_DEFINITION_STATE_CONFLICT')
    args['expectedStateToken'] = prior['state_token']
    return definition


def source_binding(db, scope, owner):
    # Callers pass the typed owner, never a diagnostic build locator.
    from .postgres_definition_lifecycle import source_binding as resolve
    return resolve(owner)


def assert_source_active(db, scope, owner):
    from .postgres_definition_lifecycle import assert_current_executable
    assert_current_executable(db,scope,owner)


def activate_definition(db, scope, *, dsn, identity, plan, build_id, operation_id):
    target = descriptor(plan)
    if target is None:
        return None
    from .postgres_definition_lifecycle import source_for_build, read_owner
    source = source_for_build(db, scope, build_id)
    declared = source['declared_output']
    if declared is None or {key: declared[key] for key in ('kind','definitionId')} != target:
        raise ValueError('PYTHON_DECLARED_OUTPUT_MISMATCH')
    prior = read_owner(db, scope, declared, lock=True)
    if prior is None or prior['source_program_id'] != source['program_id']:
        raise ValueError('PYTHON_DEFINITION_SOURCE_MISMATCH')
    operation = plan['units'][0]['operations'][0]
    if operation['arguments'].get('expectedStateToken') != prior['state_token']:
        raise ValueError('PYTHON_DEFINITION_STATE_CONFLICT')
    service = service_for(operation['function'], dsn, identity)
    saved = service.execute(scope, operation,
        idempotency_key='def-save-' + sha256(operation_id.encode()).hexdigest(),
        _connection=db, _source_build_id=build_id)
    current = db.execute('''SELECT metadata_revision,policy_revision FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s''',
        (scope.workspace_id, scope.application_id)).fetchone()
    args = {'expectedMetadataRevision': current['metadata_revision'],
        'expectedPolicyRevision': current['policy_revision'], 'expectedStateToken': saved['stateToken']}
    args['ruleId' if target['kind'] == 'ApplicationRule' else 'definitionId'] = target['definitionId']
    function = service.PUBLISH
    activated = service.execute(scope, {'languageVersion': 2, 'function': function, 'arguments': args},
        idempotency_key='def-active-' + sha256(operation_id.encode()).hexdigest(),
        _connection=db, _source_build_id=build_id)
    owner = read_owner(db, scope, declared)
    return {**target, 'stateToken': activated['stateToken'], 'source': source_binding(db, scope, owner)}
