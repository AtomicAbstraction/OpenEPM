"""Identity-aware, no-effect validation for Python-generated V2 operations."""
from __future__ import annotations

import json
from typing import Mapping

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_capability_contract import (filter_catalog,
    assert_source_operation_purpose)
from .postgres_connection import connect_postgres
from .postgres_language_v2 import PostgresLanguageV2
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


def _proposed_expression_references(arguments):
    """Inspect only canonical expression child slots before profile lowering."""
    found = set()
    pending = [(arguments.get('expression'), 0)]
    visits = 0
    while pending:
        node, depth = pending.pop()
        visits += 1
        if type(node) is not dict:
            continue
        if depth > 12 or visits > 64:
            raise ValueError('EXPRESSION_COMPLEXITY_OR_SHAPE_INVALID')
        if node.get('op') in ('PublishedAmount', 'PublishedUnitAmount', 'PublishedRatio'):
            key = node.get('resultKey')
            if type(key) is str:
                found.add(key)
        pending.extend((node[key], depth + 1) for key in
            ('left', 'right', 'test', 'then', 'else', 'source') if key in node)
    return found


class PostgresPythonBuildOperationValidator:
    """Validate through shared compilers without admitting any effect.

    Numeric definition validation resolves types and references independently
    of current cell values. Impact Test evaluates their ordered effects later.
    Other functions retain their authoritative no-effect preview compiler.
    """

    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes, metadata_revision: int,
                 policy_revision: int, schema_epoch: int,
                 language=None, source_program=None):
        if (type(dsn) is not str or not dsn
                or not isinstance(identity, VerifiedIdentity)
                or type(preview_secret) is not bytes or len(preview_secret) < 32
                or any(type(value) is not int or value < 0 for value in
                       (metadata_revision, policy_revision, schema_epoch))):
            raise ValueError('PYTHON_BUILD_VALIDATOR_CONFIGURATION_INVALID')
        self.dsn, self.identity = dsn, identity
        self.preview_secret = preview_secret
        self.expected = (metadata_revision, policy_revision, schema_epoch)
        self.source_program = source_program
        self._ordered = None
        self.language = language or PostgresLanguageV2(
            dsn, identity=identity, preview_secret=preview_secret)

    def for_plan(self, scope, proposed):
        """Isolate proposed output descriptors for one ordered compilation."""
        from .python_plan_runner import SealedPlanRunner
        from .python_program_execution import MAX_OPERATIONS
        # Count list lengths before inspecting any operation or allocating
        # descriptors, so the prepass cannot outrun the shared envelope budget.
        operation_count = 0
        for unit in proposed['units']:
            if type(unit) is dict and type(unit.get('operations')) is list:
                operation_count += len(unit['operations'])
                if operation_count > MAX_OPERATIONS:
                    raise ValueError('PYTHON_PLAN_OPERATION_LIMIT')
        declared = set()
        candidates = []
        for unit in proposed['units']:
            if type(unit) is not dict or type(unit.get('operations')) is not list:
                continue  # The shared envelope validator reports malformed units.
            operations = unit['operations']
            valid = all(type(operation) is dict and set(operation) == {
                'languageVersion', 'function', 'arguments'} and
                operation['languageVersion'] == 2 and type(operation['function']) is str
                and type(operation['arguments']) is dict for operation in operations)
            if valid and any(operation['function'] == 'facts.expression.calculate'
                    for operation in operations):
                SealedPlanRunner._atomic_operation(unit)
            for operation in operations:
                if type(operation) is not dict or type(operation.get('arguments')) is not dict:
                    continue
                key = operation['arguments'].get('resultKey')
                if type(key) is str:
                    declared.add(key)
                references = (_proposed_expression_references(operation['arguments'])
                    if operation.get('function') == 'facts.expression.calculate' else set())
                candidates.append((key if type(key) is str else None, references))
        needed = set().union(*(references for _, references in candidates)) & declared
        # The new descriptor budget applies only to the proposed-output chain;
        # ordinary plans retain the shared envelope's existing operation limit.
        if sum(key in needed or bool(references & needed) for key, references in candidates) > 500:
            raise ValueError('PYTHON_BUILD_ORDERED_OPERATION_LIMIT')
        child = PostgresPythonBuildOperationValidator(self.dsn, identity=self.identity,
            preview_secret=self.preview_secret, metadata_revision=self.expected[0],
            policy_revision=self.expected[1], schema_epoch=self.expected[2],
            language=self.language, source_program=self.source_program)
        child._ordered = {'scope': scope, 'declared': declared, 'needed': needed, 'outputs': {},
            'ordinal': 0, 'coordinates': 0, 'visits': 0}
        return child

    def _charge_ordered(self, visits):
        self._ordered['visits'] += visits
        if self._ordered['visits'] > 100_000:
            raise ValueError('PYTHON_BUILD_ORDERED_VISIT_LIMIT')

    def _record_output(self, arguments, descriptor):
        if (self._ordered is None or type(arguments.get('resultKey')) is not str
                or arguments['resultKey'] not in self._ordered['needed']):
            return
        key = arguments['resultKey']
        prior = self._ordered['outputs'].get(key)
        size = self._ordered['coordinates'] - (len(prior['coordinates']) if prior else 0)
        size += len(descriptor['coordinates']) if descriptor else 0
        if size > 10_000:
            raise ValueError('PYTHON_BUILD_ORDERED_COORDINATE_LIMIT')
        self._ordered['coordinates'] = size
        # Even an unsupported later publisher supersedes the earlier descriptor.
        self._ordered['outputs'][key] = descriptor

    def _authorize_expression_metadata(self, db, scope, plan):
        from psycopg.types.json import Jsonb
        from .postgres_authoring_context import metadata_row_allowed
        from .postgres_dimensional_scope import resolve_effective_dimensional_scope
        from .postgres_expression import (published_lookups, published_ratio_lookups,
            published_unit_lookups, source_lookups, source_text_lookups)
        pairs = set(plan.source_members) | set(plan.target_members)
        pairs.update((axis, member) for axis, members in plan.source_member_sets for member in members)
        for _, overrides in (*published_lookups(plan.expression), *published_ratio_lookups(plan.expression)):
            pairs.update(overrides)
        for overrides in (*source_lookups(plan.expression), *source_text_lookups(plan.expression)):
            pairs.update(overrides)
        lookups = published_unit_lookups(plan.expression)
        for _, overrides, _ in lookups:
            pairs.update(overrides)
        unit = tuple(plan.amount_unit[:2]) if plan.amount_unit else None
        if lookups:
            currencies = db.execute('''SELECT dimension_id FROM epm.dimension
                WHERE workspace_id=%s AND application_id=%s AND status='Active'
                AND model_role='Currency' ORDER BY dimension_id''',
                (scope.workspace_id, scope.application_id)).fetchall()
            if len(currencies) != 1:
                raise ValueError('EXPRESSION_AMOUNT_UNIT_UNAVAILABLE')
            axis = currencies[0]['dimension_id']
            pairs.update((axis, currency) for _, _, currency in lookups)
            inferred = (axis, lookups[0][2])
            if unit is not None and unit != inferred:
                raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
            unit = inferred
        if unit:
            pairs.add(unit)
        self._charge_ordered(len(pairs))
        authority = resolve_effective_dimensional_scope(db, self.identity, scope)
        dimensions = sorted({axis for axis, _ in pairs})
        rows = db.execute('''SELECT dimension_id,read_security_tags,write_security_tags
            FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=ANY(%s::text[]) AND status='Active' ORDER BY dimension_id''',
            (scope.workspace_id, scope.application_id, dimensions)).fetchall()
        if ([row['dimension_id'] for row in rows] != dimensions or any(
                not metadata_row_allowed(authority, row['dimension_id'], row) for row in rows)):
            raise ValueError('METADATA_NAME_UNAVAILABLE')
        rows = db.execute('''SELECT m.dimension_id,m.member_id,m.read_security_tags,m.write_security_tags
            FROM jsonb_to_recordset(%s::jsonb) input(dimension_id text,member_id text)
            JOIN epm.member m ON m.workspace_id=%s AND m.application_id=%s
             AND m.dimension_id=input.dimension_id AND m.member_id=input.member_id
             AND m.status='Active' ORDER BY m.dimension_id,m.member_id''',
            (Jsonb([{'dimension_id': axis, 'member_id': member} for axis, member in sorted(pairs)]),
             scope.workspace_id, scope.application_id)).fetchall()
        if ([(row['dimension_id'], row['member_id']) for row in rows] != sorted(pairs) or any(
                not metadata_row_allowed(authority, row['dimension_id'], row) for row in rows)):
            raise ValueError('METADATA_NAME_UNAVAILABLE')
        return unit

    def _external_unit_inputs(self, db, scope, lookups, drivers, unit):
        from psycopg.types.json import Jsonb
        from .persistence_contract import Coordinate
        from .postgres_calculation_status import published_input_status
        keys = sorted({key for key, _, _ in lookups})
        if not keys:
            return
        heads = db.execute('''SELECT result_key,state_token,payload_kind FROM epm.calculation_result_state
            WHERE workspace_id=%s AND application_id=%s AND result_key=ANY(%s::text[])
            ORDER BY result_key''', (scope.workspace_id, scope.application_id, keys)).fetchall()
        if [row['result_key'] for row in heads] != keys:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNAVAILABLE')
        pins = [{'resultKey': row['result_key'], 'resultStateToken': row['state_token']} for row in heads]
        status = published_input_status(db, scope, {'publishedInputs': pins})
        if status is None or not status['matchesAtRead'] or status.get('truncated'):
            raise ValueError('STALE_PUBLISHED_INPUT')
        if any(row['payload_kind'] != 'typed_currency' for row in heads):
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
        requested = {}
        for key, overrides, currency in lookups:
            for driver in drivers:
                coordinate = Coordinate.from_mapping({**dict(driver.members), **dict(overrides)})
                requested[(key, coordinate.series_key, currency)] = dict(coordinate.members)
        if not requested:
            return
        rows = db.execute('''SELECT input.result_key,input.series_key,input.currency,
            r.output_unit_currency_dimension_id AS dimension_id
            FROM jsonb_to_recordset(%s::jsonb) input(
                result_key text,series_key text,members jsonb,currency text)
            JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s
             AND c.series_key=input.series_key AND c.members=input.members
            JOIN epm.calculation_unit_result_current r USING(workspace_id,application_id,coordinate_id)
            WHERE r.result_key=input.result_key AND r.output_unit_currency_member_id=input.currency''',
            (Jsonb([{'result_key': key, 'series_key': series, 'currency': currency, 'members': members}
                for (key, series, currency), members in sorted(requested.items())]),
             scope.workspace_id, scope.application_id)).fetchall()
        if (len(rows) != len(requested) or
                {(row['result_key'], row['series_key'], row['currency']) for row in rows} != set(requested)
                or any((row['dimension_id'], row['currency']) != unit for row in rows)):
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')

    def _validate_ordered_expression(self, db, scope, program):
        """Compile a bounded scalar definition; descriptors never carry values/pins."""
        from .postgres_expression import (compile_expression_program, expression_references,
            expression_driver_coordinates, expression_source_coordinates,
            expression_target_coordinates, published_unit_lookups,
            validate_expression_metadata, validate_amount_unit_coordinates)
        from .persistence_contract import Coordinate
        from .postgres_fact_batch import validate_coordinates
        from .postgres_dimensional_security_enforcement import authorize_coordinates
        from .dimensional_security_policy import AccessKind
        args = program['arguments']
        supported = {'sourceMembers', 'sourceMemberSets', 'targetMembers', 'expression',
            'resultKey', 'resultUnit', 'requiredSourceCount', 'amountUnit'}
        proposed_references = _proposed_expression_references(args)
        internal = proposed_references & self._ordered['declared']
        for key in internal:
            if key not in self._ordered['outputs']:
                raise ValueError('PYTHON_BUILD_RESULT_FORWARD_REFERENCE')
            descriptor = self._ordered['outputs'][key]
            if descriptor is None:
                raise ValueError('PYTHON_BUILD_RESULT_PROFILE_UNSUPPORTED')
            if descriptor['ordinal'] >= self._ordered['ordinal']:
                raise ValueError('PYTHON_BUILD_RESULT_FORWARD_REFERENCE')
        if set(args) - supported:
            if internal:
                raise ValueError('PYTHON_BUILD_RESULT_PROFILE_UNSUPPORTED')
            return False, None
        if not internal and (type(args.get('resultKey')) is not str
                or args['resultKey'] not in self._ordered['needed']):
            return False, None
        plan = compile_expression_program(program, expected_target_state_token=None,
            published_inputs=None)
        references = expression_references(plan.expression)
        lookups = published_unit_lookups(plan.expression)
        if set(references) != {key for key, _, _ in lookups}:
            if internal:
                raise ValueError('PYTHON_BUILD_RESULT_PROFILE_UNSUPPORTED')
            return False, None  # Existing external-only profiles keep ordinary preview.
        unit = self._authorize_expression_metadata(db, scope, plan)
        validate_expression_metadata(db, scope, plan)
        drivers = expression_driver_coordinates(db, scope, plan, max_coordinates=500)
        sources = expression_source_coordinates(db, scope, plan, driver_coordinates=drivers)
        targets = expression_target_coordinates(db, scope, plan, len(drivers))
        self._charge_ordered(len(drivers) + len(sources) + len(targets) + len(drivers) * len(lookups))
        expected_targets = {Coordinate.from_mapping({**dict(driver.members),
            **dict(plan.target_members)}) for driver in drivers}
        if set(targets) != expected_targets:
            raise ValueError('CALCULATION_SOURCE_CHANGED')
        if len(set(targets)) != len(targets):
            raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
        validate_coordinates(db, scope, [{'ordinal': index, 'series_key': coordinate.series_key,
            'members': dict(coordinate.members)} for index, coordinate in enumerate((*sources, *targets), 1)])
        authorize_coordinates(db, self.identity, scope, sources, kind=AccessKind.READ)
        authorize_coordinates(db, self.identity, scope, targets, kind=AccessKind.WRITE)
        validate_amount_unit_coordinates(db, scope, plan, [dict(item.members) for item in drivers])
        for key, overrides, currency in lookups:
            if key not in internal:
                continue
            descriptor = self._ordered['outputs'][key]
            if descriptor['kind'] != 'amount' or descriptor['unit'] != unit or unit[1] != currency:
                raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
            for driver in drivers:
                coordinate = Coordinate.from_mapping({**dict(driver.members), **dict(overrides)})
                if coordinate not in descriptor['coordinates']:
                    raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
        self._external_unit_inputs(db, scope,
            tuple(lookup for lookup in lookups if lookup[0] not in internal), drivers, unit)
        return True, {'ordinal': self._ordered['ordinal'], 'kind': 'ratio' if plan.result_unit else 'amount',
            'unit': unit, 'coordinates': frozenset(targets)}

    def _read_state(self, scope: ApplicationScope) -> dict:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 15000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch,enabled_capabilities FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or tuple(state[key] for key in
                        ('metadata_revision','policy_revision','schema_epoch')) != self.expected:
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                return dict(state)

    def validate_operation(self, scope: ApplicationScope, function: str,
                           arguments: Mapping[str, object]) -> dict:
        if (not isinstance(scope, ApplicationScope) or type(function) is not str
                or type(arguments) is not dict):
            raise ValueError('PYTHON_BUILD_OPERATION_INVALID')
        if self._ordered is not None:
            if self._ordered['scope'] != scope:
                raise ValueError('PYTHON_BUILD_ORDERED_SCOPE_MISMATCH')
            self._ordered['ordinal'] += 1
        descriptor = None
        state = self._read_state(scope)
        from .postgres_python_definitions import KINDS, validate_definition, definition_specification
        typed_definition = None
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 15000)
                PostgresNumericFactStore._set_scope(db, scope)
                catalog = filter_catalog(PostgresLanguageV2.catalog(),
                                         state['enabled_capabilities'])
                specification = (definition_specification(function) if function in KINDS
                                 else catalog['functions'].get(function))
                if specification is None:
                    raise ValueError('PYTHON_BUILD_FUNCTION_UNAVAILABLE')
                assert_source_operation_purpose(function, dict(arguments))
                if not specification.get('previewRequired', False) and function not in KINDS:
                    raise ValueError('PYTHON_BUILD_FUNCTION_NO_EFFECT_VALIDATOR')
                permission = specification.get('permission')
                if permission not in ('write', 'admin', 'rule_design',
                                      'rule_publish', 'rule_run'):
                    raise ValueError('PYTHON_BUILD_FUNCTION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(db, self.identity,
                    scope, permission, function=function,
                    arguments=dict(arguments))
                from .postgres_authoring_references import bind_authoring_references
                arguments = bind_authoring_references(db, scope, self.identity,
                    arguments, metadata_revision=self.expected[0], function=function)
                program = {'languageVersion': 2, 'function': function,
                           'arguments': dict(arguments)}
                if function in KINDS:
                    if any(arguments.get(name) != pin for name, pin in zip(
                            ('expectedMetadataRevision', 'expectedPolicyRevision'), self.expected[:2])):
                        raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                    typed_definition = validate_definition(db, scope, program,
                        dsn=self.dsn, identity=self.identity, source_program=self.source_program)
                    definition_checked = True
                elif function == 'facts.expression.calculate' and self._ordered is not None:
                    definition_checked, descriptor = self._validate_ordered_expression(db, scope, program)
                else:
                    definition_checked = self._validate_numeric_definition(db, scope, program)
        if function == 'application.rule.save':
            from .python_plan_summary import (require_no_static_errors,
                                               static_plan_summary)
            structural_plan = {'format': 'openepm-python-plan-v1', 'units': [{
                'name': 'definition-validation', 'operations': [{
                    'languageVersion': 2, 'function': function,
                    'arguments': {**dict(arguments),
                                  'definition': typed_definition}}]}]}
            summary = static_plan_summary(structural_plan, {'entries': []},
                plan_digest='0' * 64, source_digest='0' * 64)
            require_no_static_errors(summary)
            from .postgres_application_rules import bind_definition, definition_plan
            from .python_program_execution import validate_proposed_plan
            bound, _ = bind_definition(typed_definition, None, samples=True)
            if any(operation['function'] in KINDS for unit in bound['units']
                    for operation in unit['operations']):
                raise ValueError('PYTHON_DEFINITION_NESTING_FORBIDDEN')
            validate_proposed_plan(scope, definition_plan(bound), registry=self,
                compiler_version='application-rule-v1')
        if definition_checked:
            self._read_state(scope)
            normalized = ({**program['arguments'], 'definition': typed_definition}
                          if typed_definition is not None else program['arguments'])
            normalized = json.loads(json.dumps(normalized, sort_keys=True,
                separators=(',', ':'), ensure_ascii=True, allow_nan=False))
            self._record_output(arguments, descriptor)
            return normalized
        program = {'languageVersion': 2, 'function': function,
                   'arguments': dict(arguments)}
        # This path compiles, resolves metadata, enforces work bounds and signs
        # a disposable preview.  It never calls submit/apply/publish.
        result = self.language.preview(scope, program)
        if (type(result) is not dict or result.get('function') != function
                or 'previewToken' not in result):
            raise ValueError('PYTHON_BUILD_PREVIEW_VALIDATION_FAILED')
        vector = result.get('revisionVector')
        if vector is not None:
            if type(vector) is not dict:
                raise ValueError('PYTHON_BUILD_PREVIEW_VALIDATION_FAILED')
            aliases = (('metadata_revision', 'metadataRevision', self.expected[0]),
                       ('policy_revision', 'policyRevision', self.expected[1]),
                       ('schema_epoch', 'schemaEpoch', self.expected[2]))
            for snake, camel, expected in aliases:
                present = [vector[name] for name in (snake, camel)
                           if name in vector]
                if present and any(value != expected for value in present):
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
        # Preview uses its own transaction.  Its result is provisional until a
        # second read proves that all build pins still match after compilation.
        self._read_state(scope)
        try:
            normalized = json.loads(json.dumps(arguments, sort_keys=True,
                separators=(',', ':'), ensure_ascii=True, allow_nan=False))
        except (TypeError, ValueError) as error:
            raise ValueError('PYTHON_BUILD_OPERATION_NOT_CANONICAL') from error
        self._record_output(arguments, descriptor)
        return normalized

    def _validate_numeric_definition(self, db, scope, program):
        """Compile metadata references, never require a preceding effect live."""
        function = program['function']
        if function == 'facts.numeric.transform':
            from .postgres_numeric_transform import compile_program
            from .postgres_cube_select import PostgresCubeSelect
            normalized = compile_program(program)
            arguments = normalized['arguments']
            if arguments['expectedMetadataRevision'] != self.expected[0]:
                raise ValueError('STALE_METADATA_REVISION')
            PostgresCubeSelect._resolve(db, scope, arguments['selection'], self.expected[0])
            return True
        if function not in ('facts.numeric.sequence', 'facts.numeric.batch'):
            return False
        from .postgres_numeric_sequence import (compile_program, validate_coordinates,
                                                enforce_sequence_dimensional_security)
        if function == 'facts.numeric.sequence':
            normalized = compile_program(program)
        else:
            from .postgres_language_v2 import compile_numeric_program
            mutations = compile_numeric_program(program)
            normalized = {'function': function, 'statements': [
                {'series_key': item.coordinate.series_key,
                 'members': dict(item.coordinate.members), 'ordinal': index}
                for index, item in enumerate(mutations, 1)]}
        validate_coordinates(db, scope, normalized)
        enforce_sequence_dimensional_security(db, self.identity, scope, normalized)
        return True
