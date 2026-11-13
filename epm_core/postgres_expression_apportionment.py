"""Trusted adapters for the generic v36 apportionment calculation profile."""
from __future__ import annotations

import json
import re
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from decimal import Decimal, localcontext
from fractions import Fraction

from .dimensional_security_policy import AccessKind
from .expression_apportionment import (
    COMPILER, FUNCTION, PLAN_DIGEST, RELATION_COMPILER,
    RELATION_PLAN_DIGEST, MAX_RESULT_BYTES, apportion_units,
    input_coordinates, normalize_program, normalize_request,
    normalize_relation_program, normalize_relation_request,
    target_coordinates, topological_components,
)
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_expression import ExpressionPlan, _decimal, validate_expression_metadata
from .postgres_fact_batch import ensure_coordinates, numeric_inputs, validate_coordinates
from .postgres_numeric_sequence_expression import evaluate_partitions, instructions
from .postgres_planning_write_guard import enforce_active_planning_policy


def _walk(node):
    yield node
    for field in ('left', 'right', 'test', 'then', 'else'):
        if field in node:
            yield from _walk(node[field])


def _declared(coordinates):
    return [{'ordinal': index, 'series_key': item.series_key, 'members': dict(item.members)}
            for index, item in enumerate(coordinates, 1)]


def _component_refs(expression):
    return {node['componentId'] for node in _walk(expression) if node['op'] == 'ComponentAmount'}


def _direct_inputs(expression, source):
    result = set()
    for node in _walk(expression):
        if node['op'] == 'SourceAmount':
            result.add(Coordinate.from_mapping(source).series_key)
        elif node['op'] == 'SourceValue':
            result.add(Coordinate.from_mapping({**source, **node['memberOverrides']}).series_key)
    return result


def _fixed_amount(value):
    with localcontext() as context:
        context.prec = 80
        decimal = Decimal(value.numerator) / Decimal(value.denominator)
    if abs(value) >= 10**20 or value * 10**8 != int(value * 10**8):
        raise ValueError('EXPRESSION_RESULT_OUT_OF_RANGE')
    return format(decimal, '.8f')


def _literalize(node, source, inputs, components):
    op = node['op']
    if op in ('SourceAmount', 'SourceValue'):
        members = source if op == 'SourceAmount' else {**source, **node['memberOverrides']}
        row = inputs[Coordinate.from_mapping(members).series_key]
        ratio = node.get('valueType') == 'ratio'
        return {'op': 'RatioLiteral' if ratio else 'AmountLiteral',
                'decimal': _decimal(format(Decimal(row['amount']), 'f'), amount=not ratio)}
    if op == 'ComponentAmount':
        return {'op': 'AmountLiteral', 'decimal': _fixed_amount(components[node['componentId']])}
    return {key: _literalize(value, source, inputs, components)
            if key in ('left', 'right', 'test', 'then', 'else') else value
            for key, value in node.items()}


def _rational(db, expression, source, inputs, components):
    normalized = _literalize(expression, source, inputs, components)
    # Reuse the existing typed exact-rational instruction kernel. Neither the
    # calculation profile nor private Test owns another expression evaluator.
    # The original tree was already typed by normalize_request. Recompiling
    # substituted source values as literals would incorrectly reject a zero
    # denominator in an unselected If branch; the shared kernel owns that
    # dynamic selected-branch error check.
    tape = instructions([{'op': 'set', 'ordinal': 1, 'series_key': 'prepared',
                          'expression': normalized}])
    values = evaluate_partitions(db, tape, [{'partition_key': 'prepared', 'states': {}}],
                                 exact_results=True)
    if len(values) != 1 or values[0]['denominator'] is None or values[0]['denominator'] <= 0:
        raise ValueError('EXPRESSION_APPORTIONMENT_RATIONAL_RESULT_INVALID')
    row = values[0]
    if row['numerator'] != int(row['numerator']) or row['denominator'] != int(row['denominator']):
        raise ValueError('EXPRESSION_APPORTIONMENT_RATIONAL_RESULT_INVALID')
    return Fraction(int(row['numerator']), int(row['denominator']))


def prepare(db, scope, identity, request, *, role, private=None):
    """Authorize and read bounded inputs once, evaluate privately, return rows."""
    request = normalize_request(request)
    source = request['sourceMembers']
    anchor = Coordinate.from_mapping(source)
    inputs = input_coordinates(request)  # Includes anchor/control; bound before fetch.
    targets = target_coordinates(request)
    validate_coordinates(db, scope, _declared((*inputs, *targets)))
    authorize_coordinates(db, identity, scope, list(inputs), kind=AccessKind.READ)
    authorize_coordinates(db, identity, scope, list(targets), kind=AccessKind.WRITE)
    policy = enforce_active_planning_policy(db, scope,
        writes=tuple((item, 'Set') for item in targets), workflow_role=role)
    profile = request['apportionment']
    expressions = [profile['control']] + [item['expression'] for item in profile['components']]
    for expression in expressions:
        validate_expression_metadata(db, scope, ExpressionPlan(tuple(source.items()),
            expression, request['resultKey'], 0))
    # A vector amount profile must not publish Amounts into ratio measures.
    measure_axes = db.execute("""SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
          AND model_role='Account'""", (scope.workspace_id, scope.application_id)).fetchall()
    if len(measure_axes) != 1:
        raise ValueError('EXPRESSION_APPORTIONMENT_MEASURE_UNAVAILABLE')
    measure_axis = measure_axes[0]['dimension_id']
    measures = sorted({dict(item.members)[measure_axis] for item in (*targets, anchor)})
    found = db.execute("""SELECT member_id,numeric_value_kind FROM epm.member
        WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
          AND member_id=ANY(%s::text[]) AND status='Active'""",
        (scope.workspace_id, scope.application_id, measure_axis, measures)).fetchall()
    if (len(found) != len(measures)
            or any(row['numeric_value_kind'] != 'amount' for row in found)):
        raise ValueError('EXPRESSION_MEASURE_NUMERIC_KIND_MISMATCH')
    declared = _declared(inputs)
    values = (private.numeric_inputs(db, scope, declared) if private is not None
              else numeric_inputs(db, scope, declared))
    if len(values) != len(inputs) or {row['series_key'] for row in values} != {
            item.series_key for item in inputs}:
        raise ValueError('EXPRESSION_APPORTIONMENT_INPUT_SHAPE_INVALID')
    by_key = {row['series_key']: row for row in values}
    members_by_key = {item.series_key: dict(item.members) for item in inputs}
    for item in inputs:
        row = by_key[item.series_key]
        if row['members'] is not None and row['members'] != dict(item.members):
            raise ValueError('COORDINATE_HASH_COLLISION')
        if not row['present'] or row['text_present'] or row['amount'] is None:
            raise ValueError('EXPRESSION_SOURCE_LOOKUP_CELL_MISSING')
    quantum = Fraction(profile['quantum'])
    control = _rational(db, profile['control'], source, by_key, {})
    if control / quantum != int(control / quantum):
        raise ValueError('EXPRESSION_APPORTIONMENT_CONTROL_QUANTUM_MISMATCH')
    if abs(control) >= 10**20:
        raise ValueError('EXPRESSION_RESULT_OUT_OF_RANGE')
    components = {item['componentId']: item for item in profile['components']}
    amounts = {}
    component_inputs = {}
    contributions = {item.series_key: 0 for item in targets}
    output_components = {item.series_key: set() for item in targets}
    for identity_key in topological_components(request):
        component = components[identity_key]
        amount = _rational(db, component['expression'], source, by_key, amounts)
        weighted = {}
        ties = {}
        for item in component['targets']:
            members = {**source, **item['memberOverrides']}
            key = Coordinate.from_mapping(members).series_key
            weighted[key] = Fraction(item['weight'])
            ties[key] = tuple(members[axis] for axis in profile['tieDimensions'])
        source_units, shares, _ = apportion_units(amount, weighted, quantum=quantum,
            rounding=component['sourceRounding'], tie_keys=ties)
        amounts[identity_key] = source_units * quantum
        dependencies = _direct_inputs(component['expression'], source)
        for dependency in _component_refs(component['expression']):
            dependencies.update(component_inputs[dependency])
        component_inputs[identity_key] = dependencies
        for key, units in shares.items():
            contributions[key] += units
            output_components[key].add(identity_key)
    if sum(contributions.values()) * quantum != control:
        raise ValueError('EXPRESSION_APPORTIONMENT_CONTROL_MISMATCH')
    control_inputs = _direct_inputs(profile['control'], source) | {anchor.series_key}
    rows = []
    result_bytes = 2
    for target in targets:
        key = target.series_key
        dependencies = set(control_inputs)
        for component_id in output_components[key]:
            dependencies.update(component_inputs[component_id])
        lineage = [{'inputKind': 'RawAmount',
            'memberOverrides': {axis: member for axis, member in members_by_key[input_key].items()
                                if member != source[axis]},
            'sourceMembers': members_by_key[input_key], 'sourceSeriesKey': input_key,
            'sourceAmount': format(Decimal(by_key[input_key]['amount']), '.8f'),
            'sourceChangeId': by_key[input_key]['change_id']}
            for input_key in sorted(dependencies)]
        rows.append({'series_key': key, 'members': dict(target.members),
            'amount': _fixed_amount(contributions[key] * quantum),
            'source_amount': format(Decimal(by_key[anchor.series_key]['amount']), '.8f'),
            'source_change_id': by_key[anchor.series_key]['change_id'],
            'source_present': True, 'source_lookup_lineage': lineage})
        result_bytes += len(json.dumps(rows[-1], sort_keys=True, separators=(',', ':'),
                                       ensure_ascii=False, allow_nan=False).encode()) + 1
        if result_bytes > MAX_RESULT_BYTES:
            raise ValueError('EXPRESSION_APPORTIONMENT_RESULT_LIMIT')
    if private is not None:
        private.visits += len(inputs) + sum(len(item['targets']) for item in components.values())
        if private.visits > 100_000:
            raise ValueError('PYTHON_IMPACT_VISIT_LIMIT')
    return {'rows': rows, 'inputs': [{
        'seriesKey': row['series_key'], 'members': members_by_key[row['series_key']],
        'amount': format(Decimal(row['amount']), '.8f'), 'changeId': row['change_id'],
        'textChangeId': row['text_change_id'], 'hasDetail': row['has_detail']}
        for row in values], 'planningPolicy': policy}


def _relation_expression(node, values, domain, anchor, measure_axis):
    operation = node['op']
    if operation == 'RelationOperand':
        operand = next((item for item in domain['operands']
                        if item['operandId'] == node['operandId']), None)
        if operand is None:
            raise ValueError('EXPRESSION_APPORTIONMENT_RELATION_OPERAND_INVALID')
        members = dict(anchor)
        for binding in operand['memberColumns']:
            members[binding['dimensionId']] = values[binding['columnId']]
        return {'op': 'SourceValue',
            'memberOverrides': {axis: member for axis, member in members.items()
                                if anchor[axis] != member},
            'valueType': node['valueType'],
            'measureDimensionId': measure_axis}
    if operation in ('SourceAmount', 'ComponentAmount', 'AmountLiteral',
                     'RatioLiteral'):
        return dict(node)
    return {key: _relation_expression(child, values, domain, anchor,
                                      measure_axis)
            if key in ('left', 'right', 'test', 'then', 'else') else child
            for key, child in node.items()}


def materialize_relation_requests(db, scope, request):
    """Resolve current policy rows into server-private v36 group requests."""
    request = normalize_relation_request(request)
    dimensions = db.execute('''SELECT dimension_id,model_role FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND status='Active'
        ORDER BY dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()
    active = tuple(row['dimension_id'] for row in dimensions)
    measures = [row['dimension_id'] for row in dimensions
                if row['model_role'] == 'Account']
    if len(measures) != 1:
        raise ValueError('EXPRESSION_APPORTIONMENT_MEASURE_UNAVAILABLE')
    from .postgres_applicability_relations import resolve_apportionment_domain
    resolved = resolve_apportionment_domain(
        db, scope, request['apportionmentDomain'],
        active_dimensions=active)
    domain = resolved['domain']
    rows = db.execute('''SELECT row_id,values
        FROM epm.applicability_relation_row
        WHERE workspace_id=%s AND application_id=%s AND relation_id=%s
        ORDER BY row_id''', (scope.workspace_id, scope.application_id,
        domain['relationId'])).fetchall()
    formulas = {item['formulaId']: item['expression']
                for item in request['formulas']}
    anchor_columns = {item['dimensionId']: item['columnId']
                      for item in domain['anchorMemberColumns']}
    target_columns = {item['dimensionId']: item['columnId']
                      for item in domain['targetMemberColumns']}
    grouped = {}
    used_formulas = set()
    for row in rows:
        values = row['values']; group_id = values[domain['groupColumnId']]
        anchor = {axis: values[column]
                  for axis, column in anchor_columns.items()}
        group = grouped.setdefault(group_id, {'anchor': anchor,
            'quantum': values[domain['quantumColumnId']], 'rows': []})
        if group['anchor'] != anchor:
            raise ValueError('APPORTIONMENT_DOMAIN_GROUP_INCONSISTENT')
        formula_id = values[domain['formulaColumnId']]
        if formula_id not in formulas:
            raise ValueError('EXPRESSION_APPORTIONMENT_FORMULA_UNAVAILABLE')
        used_formulas.add(formula_id)
        target = {axis: values[target_columns.get(axis, column)]
                  for axis, column in anchor_columns.items()}
        group['rows'].append({'values': values, 'target': target,
                              'formulaId': formula_id})
    if used_formulas != set(formulas):
        raise ValueError('EXPRESSION_APPORTIONMENT_FORMULA_UNUSED')
    requests = []
    for group_id, group in sorted(grouped.items()):
        anchor = group['anchor']; components = {}
        control = None
        for item in group['rows']:
            values = item['values']
            component_id = values[domain['componentColumnId']]
            expression = _relation_expression(formulas[item['formulaId']],
                values, domain, anchor, measures[0])
            candidate = components.setdefault(component_id, {
                'componentId': component_id, 'expression': expression,
                'sourceRounding': values[domain['roundingColumnId']],
                'targets': []})
            if (candidate['expression'] != expression
                    or candidate['sourceRounding'] !=
                       values[domain['roundingColumnId']]):
                raise ValueError('APPORTIONMENT_DOMAIN_COMPONENT_INCONSISTENT')
            candidate['targets'].append({'memberOverrides': {
                axis: member for axis, member in item['target'].items()
                if anchor[axis] != member},
                'weight': values[domain['weightColumnId']]})
            materialized_control = _relation_expression(request['control'],
                values, domain, anchor, measures[0])
            if control is None:
                control = materialized_control
            elif control != materialized_control:
                raise ValueError('APPORTIONMENT_DOMAIN_GROUP_INCONSISTENT')
        requests.append(normalize_request({'sourceMembers': anchor,
            'resultKey': request['resultKey'], 'apportionment': {
                'version': 1, 'quantum': group['quantum'],
                'tieDimensions': domain['tieDimensions'], 'control': control,
                'components': list(components.values())}}))
    if len(requests) != resolved['groupCount']:
        raise ValueError('APPORTIONMENT_DOMAIN_GROUP_COUNT_MISMATCH')
    return requests, resolved


def prepare_relation(db, scope, identity, request, *, role, private=None):
    requests, resolved = materialize_relation_requests(db, scope, request)
    rows, inputs, policies = [], [], []
    targets = set()
    for group in requests:
        result = prepare(db, scope, identity, group, role=role,
                         private=private)
        for row in result['rows']:
            if row['series_key'] in targets:
                raise ValueError('APPORTIONMENT_DOMAIN_TARGET_NOT_EXCLUSIVE')
            targets.add(row['series_key']); rows.append(row)
        inputs.extend(result['inputs']); policies.append(
            result['planningPolicy'])
    return {'rows': rows, 'inputs': inputs, 'planningPolicies': policies,
            'groupCount': resolved['groupCount'], 'relation': resolved}


def evaluate_private(db, scope, operation, private, identity, role, *, unit):
    from .postgres_python_expression_impact import _baseline, _rows
    request = normalize_program(operation)
    prepared = prepare(db, scope, identity, request, role=role, private=private)
    key = request['resultKey']
    if key not in private.calculations:
        baseline, state_token = _baseline(private.snapshot_db or db, scope, key)
        private.calculations[key] = {'original': baseline, 'current': baseline,
                                    'stateToken': state_token, 'units': []}
    state = private.calculations[key]
    authorize_coordinates(db, identity, scope,
        [Coordinate.from_mapping(row['members']) for row in state['original'].values()],
        kind=AccessKind.READ)
    before = state['current']
    after = {row['series_key']: {'members': row['members'], 'cell': {
        'present': True, 'amount': row['amount'], 'valueType': 'AmountLiteral'}}
        for row in prepared['rows']}
    state['current'] = after
    state['units'].append(unit)
    if len(private.original) + sum(len(item['original'].keys() | item['current'].keys())
            for item in private.calculations.values()) > 10_000:
        raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
    return _rows(key, before, after, [unit], state['stateToken'])


def evaluate_relation_private(db, scope, operation, private, identity, role,
                              *, unit):
    from .postgres_python_expression_impact import _baseline, _rows
    request = normalize_relation_program(operation)
    prepared = prepare_relation(db, scope, identity, request, role=role,
                                private=private)
    key = request['resultKey']
    if key not in private.calculations:
        baseline, state_token = _baseline(private.snapshot_db or db,
                                          scope, key)
        private.calculations[key] = {'original': baseline,
            'current': baseline, 'stateToken': state_token, 'units': []}
    state = private.calculations[key]
    authorize_coordinates(db, identity, scope,
        [Coordinate.from_mapping(row['members'])
         for row in state['original'].values()], kind=AccessKind.READ)
    before = state['current']
    after = {row['series_key']: {'members': row['members'], 'cell': {
        'present': True, 'amount': row['amount'],
        'valueType': 'AmountLiteral'}} for row in prepared['rows']}
    state['current'] = after; state['units'].append(unit)
    if len(private.original) + sum(len(item['original'].keys()
            | item['current'].keys()) for item in
            private.calculations.values()) > 10_000:
        raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
    return _rows(key, before, after, [unit], state['stateToken'])


def digest(program):
    return sha256(json.dumps(program, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def admission_program(request, *, expected_publication_revision, schema_epoch):
    request = normalize_request(request)
    if (type(expected_publication_revision) is not int or expected_publication_revision < 0
            or type(schema_epoch) is not int or schema_epoch < 1):
        raise ValueError('EXPRESSION_APPORTIONMENT_ADMISSION_INVALID')
    return {'version': 2, 'function': FUNCTION, 'operation': 'Apportionment',
        'compiler': COMPILER, **request,
        'expectedPublicationRevision': expected_publication_revision,
        'schemaEpoch': schema_epoch}


def relation_admission_program(request, *, expected_target_state_token,
                               schema_epoch):
    request = normalize_relation_request(request)
    if ((expected_target_state_token is not None
            and (type(expected_target_state_token) is not str
                 or re.fullmatch(r'[0-9a-f]{64}',
                                 expected_target_state_token) is None))
            or type(schema_epoch) is not int or schema_epoch < 1):
        raise ValueError('EXPRESSION_APPORTIONMENT_ADMISSION_INVALID')
    return {'version': 2, 'function': FUNCTION,
        'operation': 'RelationApportionment',
        'compiler': RELATION_COMPILER, **request,
        'expectedTargetStateToken': expected_target_state_token,
        'schemaEpoch': schema_epoch}


def validate_admission(program, expected_digest=None):
    if not isinstance(program, dict):
        raise ValueError('EXPRESSION_APPORTIONMENT_ADMISSION_INVALID')
    normalized = admission_program({key: program.get(key) for key in
        ('sourceMembers', 'resultKey', 'apportionment')},
        expected_publication_revision=program.get('expectedPublicationRevision'),
        schema_epoch=program.get('schemaEpoch'))
    if normalized != program or (expected_digest is not None
                                  and digest(normalized) != expected_digest):
        raise ValueError('EXPRESSION_APPORTIONMENT_ADMISSION_INVALID')
    return normalized


def validate_relation_admission(program, expected_digest=None):
    if not isinstance(program, dict):
        raise ValueError('EXPRESSION_APPORTIONMENT_ADMISSION_INVALID')
    normalized = relation_admission_program({key: program.get(key) for key in
        ('apportionmentDomain', 'control', 'formulas', 'resultKey')},
        expected_target_state_token=program.get('expectedTargetStateToken'),
        schema_epoch=program.get('schemaEpoch'))
    if (normalized != program or expected_digest is not None
            and digest(normalized) != expected_digest):
        raise ValueError('EXPRESSION_APPORTIONMENT_ADMISSION_INVALID')
    return normalized


def request_from_program(program):
    if program.get('operation') == 'RelationApportionment':
        return {key: program[key] for key in
            ('apportionmentDomain', 'control', 'formulas', 'resultKey')}
    return {key: program[key] for key in
            ('sourceMembers', 'resultKey', 'apportionment')}


def replay(dsn, identity, scope, program, *, idempotency_key, dependencies, execution_authority):
    """Recover exact accepted content before requiring a fresh preview token."""
    from .postgres_jobs import PostgresJobQueue, _require_python_job_authority
    relation = (program.get('operation') == 'RelationApportionment'
        or isinstance(program.get('arguments'), dict)
        and 'apportionmentDomain' in program['arguments'])
    request = ((normalize_relation_program(program) if relation
                else normalize_program(program))
        if program.get('languageVersion') == 2 else request_from_program(
            validate_relation_admission(program) if relation
            else validate_admission(program)))
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with db.transaction():
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(db, identity, scope, 'write', function=FUNCTION)
            prior = db.execute("""SELECT * FROM epm.job WHERE workspace_id=%s AND application_id=%s
                AND issuer=%s AND subject_id=%s AND idempotency_key=%s""", (scope.workspace_id,
                scope.application_id, identity.issuer, identity.subject_id, idempotency_key)).fetchone()
            if prior is None:
                return None
            compiler = RELATION_COMPILER if relation else COMPILER
            plan_digest = RELATION_PLAN_DIGEST if relation else PLAN_DIGEST
            if (prior['function_name'] != FUNCTION
                    or prior['compiler_version'] != compiler
                    or prior['plan_digest'] != plan_digest):
                raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
            normalized = (validate_relation_admission(
                prior['normalized_program'], prior['program_digest']) if relation
                else validate_admission(
                    prior['normalized_program'], prior['program_digest']))
            if (request_from_program(normalized) != request or
                    program.get('version') == 2 and normalized != program):
                raise ValueError('QUEUE_IDEMPOTENCY_CONFLICT')
            state = _current_state(db, scope)
            if state['schema_epoch'] != normalized['schemaEpoch']:
                raise ValueError('STALE_JOB_INPUT_REVISION')
            _require_python_job_authority(db, scope, prior)
    # The ordinary queue owns exact authority/dependency/scope replay comparison.
    return PostgresJobQueue(dsn, identity=identity).submit(scope,
        idempotency_key=idempotency_key, function_name=FUNCTION, normalized_program=normalized,
        compiler_version=(RELATION_COMPILER if relation else COMPILER),
        plan_digest=(RELATION_PLAN_DIGEST if relation else PLAN_DIGEST),
        expected_metadata_revision=prior['expected_metadata_revision'],
        expected_data_revision=prior['expected_data_revision'],
        expected_policy_revision=prior['expected_policy_revision'],
        resource_class=prior['resource_class'],
        depends_on_job_ids=dependencies, execution_authority=execution_authority)


def _current_state(db, scope, *, lock=False):
    state = db.execute("""SELECT a.status,s.processing_mode,s.metadata_revision,
        s.data_revision,s.policy_revision,s.commit_revision,s.schema_epoch
        FROM epm.application_state s JOIN epm.application a USING(workspace_id,application_id)
        WHERE s.workspace_id=%s AND s.application_id=%s""" +
        (' FOR UPDATE OF s' if lock else ''),
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None or state['status'] != 'Active' or state['processing_mode'] != 'Active':
        raise ValueError('APPLICATION_NOT_WRITABLE')
    return state


def _current_job(db, scope, identity, claim, state, *, lock=False):
    job = db.execute("""SELECT * FROM epm.job WHERE workspace_id=%s
        AND application_id=%s AND job_id=%s""" + (' FOR UPDATE' if lock else ''),
        (scope.workspace_id, scope.application_id, claim['job_id'])).fetchone()
    if (job is None or job['issuer'] != identity.issuer or job['subject_id'] != identity.subject_id
            or job['status'] != 'running' or job['claim_generation'] != claim['claim_generation']
            or job['claimant'] != claim['claimant'] or not db.execute(
                'SELECT %s::timestamptz>clock_timestamp() valid',
                (job['lease_until'],)).fetchone()['valid']):
        raise ValueError('STALE_WORKER_FENCE')
    relation = job['compiler_version'] == RELATION_COMPILER
    if (job['function_name'] != FUNCTION
            or job['compiler_version'] not in (COMPILER, RELATION_COMPILER)
            or job['plan_digest'] != (
                RELATION_PLAN_DIGEST if relation else PLAN_DIGEST)):
        raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
    from .postgres_jobs import _require_python_job_authority
    _require_python_job_authority(db, scope, job)
    program = (validate_relation_admission(
        job['normalized_program'], job['program_digest']) if relation
        else validate_admission(
            job['normalized_program'], job['program_digest']))
    if (program['schemaEpoch'] != state['schema_epoch'] or any(
            state[key] != job['expected_' + key] for key in
            ('metadata_revision', 'data_revision', 'policy_revision'))):
        raise ValueError('STALE_JOB_INPUT_REVISION')
    return job, program


class PostgresApportionmentPublisher:
    """Prepare privately, then publish through existing calculation/job fences."""
    def __init__(self, dsn, *, identity):
        self.dsn, self.identity = dsn, identity

    def publish(self, claim):
        scope = ApplicationScope(claim['workspace_id'], claim['application_id'])
        statement_budget = {
            'short': 5000, 'medium': 300000, 'long': 600000,
        }.get(claim.get('resource_class'))
        if statement_budget is None:
            raise ValueError('JOB_RESOURCE_CLASS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                # All input amounts are fetched in one bounded SQL statement;
                # final revision fencing rejects any intervening data change.
                # Authorization remains current READ COMMITTED. Read-only also
                # avoids capability state-row locks during private computation.
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, statement_budget)
                PostgresNumericFactStore._set_scope(db, scope)
                state = _current_state(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=FUNCTION)
                _, program = _current_job(db, scope, self.identity, claim, state)
                request = request_from_program(program)
                relation = program.get('operation') == 'RelationApportionment'
                prepared = (prepare_relation(db, scope, self.identity, request,
                    role=access.role) if relation else prepare(
                    db, scope, self.identity, request, role=access.role))
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, statement_budget)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                state = _current_state(db, scope, lock=True)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write', function=FUNCTION)
                job, current = _current_job(db, scope, self.identity, claim, state, lock=True)
                if current != program:
                    raise ValueError('UNSUPPORTED_EXPRESSION_JOB_PROGRAM')
                # Current authorization is checked again after the private snapshot.
                if relation:
                    groups, _ = materialize_relation_requests(
                        db, scope, request)
                    inputs = sorted({item for group in groups
                        for item in input_coordinates(group)},
                        key=lambda item: item.series_key)
                    targets = tuple(sorted({item for group in groups
                        for item in target_coordinates(group)},
                        key=lambda item: item.series_key))
                else:
                    inputs = list(input_coordinates(request))
                    targets = target_coordinates(request)
                authorize_coordinates(db, self.identity, scope,
                    inputs, kind=AccessKind.READ)
                authorize_coordinates(db, self.identity, scope, list(targets), kind=AccessKind.WRITE)
                policy = enforce_active_planning_policy(db, scope,
                    writes=tuple((target, 'Set') for target in targets), workflow_role=access.role)
                pointer = db.execute("""SELECT state_token,
                    committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s AND result_key=%s""",
                    (scope.workspace_id, scope.application_id, request['resultKey'])).fetchone()
                if relation:
                    if (pointer['state_token'] if pointer else None) != program.get(
                            'expectedTargetStateToken'):
                        raise ValueError('STALE_RESULT_STATE')
                elif ((pointer['published_revision'] if pointer else 0)
                        != program['expectedPublicationRevision']):
                    raise ValueError('STALE_PUBLICATION_POINTER')
                dependency_artifact = None
                if relation:
                    from .postgres_expression_dependencies import (
                        prepare_relation_apportionment_dependency_state)
                    dependency_artifact = (
                        prepare_relation_apportionment_dependency_state(
                            db, scope, request, job_id=claim['job_id'],
                            state=state, compiler_version=RELATION_COMPILER))
                rows = prepared['rows']
                ensure_coordinates(db, scope, rows)
                revision = state['commit_revision'] + 1
                db.execute("""INSERT INTO epm.calculation_operation_staging(workspace_id,application_id,
                    generation_id,job_id,result_key,source_commit_revision,source_metadata_revision,
                    source_policy_revision,function_name,row_count,published_revision,
                    generation_kind)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (
                    scope.workspace_id, scope.application_id, claim['job_id'], claim['job_id'],
                    request['resultKey'], state['commit_revision'], state['metadata_revision'],
                    state['policy_revision'], FUNCTION, len(rows), revision,
                    'partition_manifest' if relation else 'flat'))
                inserted = db.execute("""INSERT INTO epm.calculation_result_staging(workspace_id,application_id,
                    generation_id,coordinate_id,source_amount,source_change_id,amount,
                    source_lookup_lineage,source_present)
                    SELECT %s,%s,%s,c.coordinate_id,x.source_amount::numeric,x.source_change_id,
                        x.amount::numeric,x.source_lookup_lineage,true
                    FROM jsonb_to_recordset(%s::jsonb) x(series_key text,members jsonb,
                        source_amount text,source_change_id text,amount text,source_lookup_lineage jsonb)
                    JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s
                        AND c.series_key=x.series_key AND c.members=x.members""", (
                    scope.workspace_id, scope.application_id, claim['job_id'], Jsonb(rows),
                    scope.workspace_id, scope.application_id)).rowcount
                if inserted != len(rows):
                    raise ValueError('CALCULATION_SOURCE_CHANGED')
                partition_manifest = None
                if dependency_artifact is not None:
                    from .postgres_calculated_members import (
                        stage_dependency_partition_manifest)
                    partition_manifest = stage_dependency_partition_manifest(
                        db, scope, dependency_artifact,
                        generation_id=claim['job_id'], row_count=inserted)
                from .postgres_current_result_publication import advance_result_head_during_conversion
                published = advance_result_head_during_conversion(db,scope,
                    result_key=request['resultKey'],operation_id=claim['job_id'],
                    committed_revision=revision)
                dependency_result = None
                if dependency_artifact is not None:
                    from .postgres_calculated_members import (
                        publish_materialization_dependency_state)
                    dependency_result = publish_materialization_dependency_state(
                        db, scope, dependency_artifact,
                        result_state_token=published['state_token'],
                        partition_manifest=partition_manifest)
                # No top-level source values: existing authorized row lineage is the
                # only result-read path carrying input amounts and change IDs.
                result = {'generationId': claim['job_id'], 'resultKey': request['resultKey'],
                    'rowCount': inserted, 'sourceCommitRevision': state['commit_revision'],
                    'committedRevision': revision, 'engine': 'postgres_exact_rational_apportionment',
                    'resultStateToken': published['state_token'],
                    'compilerVersion': (RELATION_COMPILER if relation else COMPILER),
                    'inputCount': len(prepared['inputs']),
                    **({'groupCount': prepared['groupCount'],
                        'relationId': request['apportionmentDomain']['relationId'],
                        'planningPolicyCount': len(prepared['planningPolicies'])}
                       if relation else {
                        'quantum': request['apportionment']['quantum'],
                        'componentCount': len(request['apportionment']['components']),
                        'planningPolicy': policy})}
                if dependency_result is not None:
                    result['dependencyState'] = dependency_result
                from .postgres_calculation_impact import (
                    calculation_publication_impact)
                impact=calculation_publication_impact(
                    operation_id=claim['job_id'],causal_revision=revision,
                    result_key=request['resultKey'],existed=pointer is not None)
                result['impactDigest']=impact.digest
                db.execute("""UPDATE epm.application_state SET commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s""", (revision,
                    scope.workspace_id, scope.application_id))
                db.execute("""INSERT INTO epm.operation_receipt(workspace_id,application_id,
                    operation_id,command_digest,actor_id,committed_revision,result)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)""", (scope.workspace_id, scope.application_id,
                    claim['job_id'], job['program_digest'], job['subject_id'], revision, Jsonb(result)))
                from .postgres_calculation_impact import record_calculation_impact
                record_calculation_impact(db,scope,
                    operation_id=claim['job_id'],impact=impact)
                changed = db.execute("""UPDATE epm.job SET status='published',receipt_revision=%s,
                    result=%s,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
                    WHERE workspace_id=%s AND application_id=%s AND job_id=%s AND status='running'
                        AND claim_generation=%s AND claimant=%s AND lease_until>clock_timestamp()""",
                    (revision, Jsonb(result), scope.workspace_id, scope.application_id, claim['job_id'],
                     claim['claim_generation'], claim['claimant'])).rowcount
                if changed != 1:
                    raise ValueError('STALE_WORKER_FENCE')
                return result
