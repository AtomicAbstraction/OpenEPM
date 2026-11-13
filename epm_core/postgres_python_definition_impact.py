"""Read-only calculated-definition tests through the expression kernel."""
from .postgres_python_definitions import descriptor


def evaluate_readonly_definition(db, snapshot, scope, operation, identity, parameters):
    from .postgres_access import PostgresAccessChecker
    PostgresAccessChecker.check_in_transaction(db, identity, scope, 'read')
    target = descriptor({'units': [{'operations': [operation]}]})
    definition = operation['arguments']['definition']
    if target['kind'] != 'CalculatedMember':
        raise ValueError('PYTHON_IMPACT_DEFINITION_KIND_UNSUPPORTED')
    if parameters:
        raise ValueError('PYTHON_IMPACT_DEFINITION_PARAMETERS_UNDECLARED')
    from .postgres_calculated_members import (
        _install_selected_domain_members, expression_program_for_definition,
        PostgresCalculatedMembers)
    from .postgres_selection_preview import resolve_selection_in_transaction
    from .postgres_expression import compile_expression_program, evaluate_dynamic_expression, resolve_published_inputs
    # Validate dependency graph through the same publication contract. No
    # publication is created; conflict checks intentionally retain live rules.
    PostgresCalculatedMembers._validate_publication(db, scope,
        {'ruleId': target['definitionId']},
        {'program': {'arguments': definition}}, register_template=False)
    from .postgres_dimensional_scope import resolve_effective_dimensional_scope
    authority = resolve_effective_dimensional_scope(db, identity, scope,
        function='python.program.test')
    resolved = resolve_selection_in_transaction(snapshot, scope,
        definition['sourceSelection'], operation['arguments']['expectedMetadataRevision'],
        authority=authority)
    program = expression_program_for_definition(definition,
        result_key=definition['resultKey'] or 'definition.test')
    _install_selected_domain_members(snapshot, resolved,
        program['arguments']['selectedDomain'])
    inputs = resolve_published_inputs(snapshot, scope, program['arguments']['expression'])
    plan = compile_expression_program(program, expected_target_state_token=None, published_inputs=inputs)
    rows = evaluate_dynamic_expression(snapshot, scope, identity, plan,
        authorization_db=db, definition_test=True)
    return {'definitionResult': {**target, 'evaluation': definition['evaluation'],
        'rows': rows, 'rowCount': len(rows), 'bindings': {}, 'persisted': False}}
