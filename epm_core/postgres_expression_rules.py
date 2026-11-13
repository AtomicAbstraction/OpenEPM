"""Current typed expression-rule definitions and activation state.

Saving replaces the one current inactive definition. Only an Active,
metadata-current definition may later be resolved for a rule run. All programs
remain fixed-core data and opaque state tokens fence every mutation.
"""
from __future__ import annotations

import re
from contextlib import nullcontext

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_expression import (FUNCTION as EXPRESSION_FUNCTION,
                                  compile_expression_program,
                                  decode_expression_program,
                                  expression_references,
                                  published_lookups,
                                  published_ratio_lookups,
                                  published_unit_lookups, source_lookups,
                                  source_text_lookups,
                                  _decimal)
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from .current_object_contract import new_state_token, require_state_token
from .postgres_definition_lifecycle import (
    STORED_KINDS, certificate, current_state, resolution_context, replace_references)


SAVE = 'rules.expression.save'
PUBLISH = 'rules.expression.activate'
READ = 'rules.expression.read'
LIST = 'rules.expression.list'
RUN = 'rules.expression.run'
_ID = re.compile(r'[A-Za-z0-9._-]{1,100}\Z')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_PARAM = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')


def bind_rule_calculation(program: dict, bindings: object = None,
                          *, authoring: bool = False
                          ) -> tuple[dict, dict | None]:
    """Substitute typed literal and member IDs, never executable text."""
    if (not isinstance(program, dict)
            or not isinstance(program.get('arguments'), dict)):
        raise ValueError('EXPRESSION_RULE_TEMPLATE_INVALID')
    args = program['arguments']
    parameters = args.get('parameters')
    if parameters is None:
        if bindings not in (None, {}):
            raise ValueError('EXPRESSION_RULE_BINDINGS_UNEXPECTED')
        return program, None
    def conversion_declaration(value: object) -> bool:
        if (not isinstance(value, dict)
                or set(value) != {'type', 'sample'}
                or value.get('type') != 'currencyConversion'
                or not isinstance(value.get('sample'), dict)):
            return False
        sample = value['sample']
        try:
            candidate = {'languageVersion': 2,
                'function': EXPRESSION_FUNCTION,
                'arguments': {'sourceMembers': {'sample-axis': 'sample'},
                    'expression': {'op': 'CurrencyConvert',
                        'source': {'op': 'SourceAmount'}, **sample,
                        'rounding': 'half-even-final-8'},
                    'resultKey': 'saved-rule.sample.currency'}}
            compile_expression_program(candidate,
                expected_target_state_token=None, published_inputs=())
        except ValueError:
            return False
        return 'rounding' not in sample and 'source' not in sample

    if (not isinstance(parameters, dict)
            or not 1 <= len(parameters) <= 8
            or any(not isinstance(name, str) or not _PARAM.fullmatch(name)
                   or not (kind in ('amount', 'ratio')
                           if isinstance(kind, str) else
                           (isinstance(kind, dict)
                            and set(kind) == {'type', 'dimensionId',
                                              'sampleMemberId'}
                            and kind['type'] == 'member'
                            and isinstance(kind['dimensionId'], str)
                            and 1 <= len(kind['dimensionId']) <= 200
                            and kind['dimensionId'] ==
                                kind['dimensionId'].strip()
                            and '\x00' not in kind['dimensionId']
                            and isinstance(kind['sampleMemberId'], str)
                            and 1 <= len(kind['sampleMemberId']) <= 200
                            and kind['sampleMemberId'] ==
                                kind['sampleMemberId'].strip()
                            and '\x00' not in kind['sampleMemberId'])
                           or conversion_declaration(kind))
                   for name, kind in parameters.items())):
        raise ValueError('EXPRESSION_RULE_PARAMETERS_INVALID')
    if authoring:
        values = {name: (kind['sample'] if isinstance(kind, dict)
                         and kind.get('type') == 'currencyConversion'
                         else kind['sampleMemberId'] if isinstance(kind, dict)
                         else '1') for name, kind in parameters.items()}
    else:
        if not isinstance(bindings, dict) or set(bindings) != set(parameters):
            raise ValueError('EXPRESSION_RULE_BINDINGS_INVALID')
        values = {}
        for name, kind in sorted(parameters.items()):
            value = bindings[name]
            if isinstance(kind, dict) and kind.get('type') == 'member':
                if (not isinstance(value, str) or not 1 <= len(value) <= 200
                        or value != value.strip() or '\x00' in value):
                    raise ValueError('EXPRESSION_RULE_MEMBER_BINDING_INVALID')
                values[name] = value
            elif isinstance(kind, dict):
                if not conversion_declaration({'type': 'currencyConversion',
                                                'sample': value}):
                    raise ValueError(
                        'EXPRESSION_RULE_CURRENCY_BINDING_INVALID')
                values[name] = value
            else:
                values[name] = _decimal(value, amount=kind == 'amount')
    used: set[str] = set()
    budget = [0]
    def member(value: object, axis: str) -> object:
        if not isinstance(value, dict):
            return value
        name = value.get('name')
        declaration = parameters.get(name) if isinstance(name, str) else None
        if (set(value) != {'type', 'name'}
                or value.get('type') != 'MemberParameter'
                or not isinstance(declaration, dict)
                or declaration['dimensionId'] != axis):
            raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
        used.add(name)
        return values[name]

    def substitute(node: object, depth: int = 0) -> object:
        budget[0] += 1
        if depth > 12 or budget[0] > 64 or not isinstance(node, dict):
            raise ValueError('EXPRESSION_RULE_TEMPLATE_INVALID')
        if node.get('op') == 'Parameter':
            name = node.get('name')
            if (set(node) != {'op', 'name'} or not isinstance(name, str)
                    or name not in parameters
                    or isinstance(parameters[name], dict)):
                raise ValueError('EXPRESSION_RULE_PARAMETER_REFERENCE_INVALID')
            used.add(name)
            return {'op': ('AmountLiteral' if parameters[name] == 'amount'
                           else 'RatioLiteral'), 'decimal': values[name]}
        if node.get('op') == 'CurrencyConvert':
            reference = node.get('conversionParameter')
            name = reference.get('name') if isinstance(reference, dict) else None
            declaration = parameters.get(name) if isinstance(name, str) else None
            if (set(node) != {'op', 'source', 'conversionParameter', 'rounding'}
                    or node.get('source') != {'op': 'SourceAmount'}
                    or node.get('rounding') != 'half-even-final-8'
                    or not isinstance(reference, dict)
                    or set(reference) != {'type', 'name'}
                    or reference.get('type') != 'CurrencyConversionParameter'
                    or not isinstance(declaration, dict)
                    or declaration.get('type') != 'currencyConversion'):
                raise ValueError(
                    'EXPRESSION_RULE_CURRENCY_REFERENCE_INVALID')
            used.add(name)
            return {'op': 'CurrencyConvert', 'source': {'op': 'SourceAmount'},
                    **values[name], 'rounding': 'half-even-final-8'}
        result = {key: (substitute(value, depth + 1)
                        if key in ('left', 'right', 'test', 'then', 'else')
                        and isinstance(value, dict) else value)
                  for key, value in node.items()}
        if node.get('op') in ('PublishedAmount', 'PublishedRatio',
                              'PublishedUnitAmount',
                              'SourceValue','SourceTextPredicate') and (
                'memberOverrides' in node):
            overrides = node['memberOverrides']
            if not isinstance(overrides, dict):
                raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
            result['memberOverrides'] = {
                axis: member(value, axis) for axis, value in overrides.items()}
        if node.get('op') == 'PublishedUnitAmount':
            result['outputUnitCurrencyMemberId'] = member(
                node.get('outputUnitCurrencyMemberId'),
                _member_parameter_dimension(
                    node.get('outputUnitCurrencyMemberId'), parameters,
                    'EXPRESSION_RULE_UNIT_REFERENCE_INVALID'))
        return result
    bound = dict(args)
    bound.pop('parameters')
    for key in ('sourceMembers', 'targetMembers'):
        if key in args:
            values_map = args[key]
            if not isinstance(values_map, dict):
                raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
            bound[key] = {axis: member(value, axis)
                          for axis, value in values_map.items()}
    if 'amountUnit' in args:
        unit = args['amountUnit']
        if not isinstance(unit, dict) or 'dimensionId' not in unit:
            raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
        bound['amountUnit'] = {**unit, 'memberId': member(
            unit.get('memberId'), unit['dimensionId'])}
    for key in ('targetMemberSet', 'reduceMemberSet'):
        if key in args:
            item = args[key]
            if not isinstance(item, dict) or not isinstance(
                    item.get('dimensionId'), str):
                raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
            axis = item['dimensionId']; replaced = dict(item)
            for field in ('memberIds', 'sourceMemberIds'):
                if field in item:
                    if not isinstance(item[field], list):
                        raise ValueError(
                            'EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
                    replaced[field] = [member(value, axis)
                                       for value in item[field]]
            if 'targetMemberId' in item:
                replaced['targetMemberId'] = member(
                    item['targetMemberId'], axis)
            if 'weightExpression' in item:
                replaced['weightExpression'] = substitute(
                    item['weightExpression'])
            bound[key] = replaced
    if 'reduceMemberSets' in args:
        reductions = args['reduceMemberSets']
        if (not isinstance(reductions, dict)
                or set(reductions) != {'selections', 'measures'}
                or not isinstance(reductions['selections'], list)):
            raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
        selections = []
        for item in reductions['selections']:
            if (not isinstance(item, dict)
                    or not isinstance(item.get('dimensionId'), str)
                    or not isinstance(item.get('sourceMemberIds'), list)
                    or 'targetMemberId' not in item):
                raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
            axis = item['dimensionId']
            selections.append({**item,
                'sourceMemberIds': [member(value, axis)
                                    for value in item['sourceMemberIds']],
                'targetMemberId': member(item['targetMemberId'], axis)})
        bound['reduceMemberSets'] = {
            'selections': selections, 'measures': reductions['measures']}
    for key in ('targetMemberSets', 'sourceDomain'):
        if key in args:
            if not isinstance(args[key], list):
                raise ValueError('EXPRESSION_RULE_MEMBER_REFERENCE_INVALID')
            bound[key] = [{**item, 'memberIds': [member(value,
                item.get('dimensionId')) for value in item.get('memberIds', [])]}
                if isinstance(item, dict) else item for item in args[key]]
    bound['expression'] = substitute(args.get('expression'))
    if used != set(parameters):
        raise ValueError('EXPRESSION_RULE_PARAMETER_UNUSED')
    return {**program, 'arguments': bound}, (
        None if authoring else dict(sorted(values.items())))


def _member_parameter_dimension(value: object, parameters: dict,
                                error: str) -> str:
    if not isinstance(value, dict):
        return ''
    name = value.get('name')
    declaration = parameters.get(name) if isinstance(name, str) else None
    if (not isinstance(declaration, dict)
            or declaration.get('type') != 'member'):
        raise ValueError(error)
    return declaration['dimensionId']


def member_parameter_names(program: dict) -> list[str]:
    parameters = program['arguments'].get('parameters') or {}
    return sorted(name for name, declaration in parameters.items()
                  if isinstance(declaration, dict)
                  and declaration.get('type') == 'member')


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2
            or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('V2_EXPRESSION_RULE_FUNCTION_INVALID')
    args = raw['arguments']
    if function == LIST:
        if set(args) - {'limit', 'afterRuleId',
                        'expectedMetadataRevision',
                        'expectedPolicyRevision'}:
            raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
        limit = args.get('limit', 100)
        after = args.get('afterRuleId')
        if (type(limit) is not int or not 1 <= limit <= 100
                or (after is not None and
                    (not isinstance(after, str)
                     or not _ID.fullmatch(after)))
                or any(type(args[key]) is not int or args[key] < 0
                       for key in ('expectedMetadataRevision',
                                   'expectedPolicyRevision') if key in args)
                or (after is not None and
                    not {'expectedMetadataRevision',
                         'expectedPolicyRevision'} <= set(args))):
            raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
        return args
    if (not isinstance(args.get('ruleId'), str)
            or not _ID.fullmatch(args['ruleId'])):
        raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
    if function == READ:
        if set(args) != {'ruleId'}:
            raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
        return args
    required = ({'ruleId', 'calculation', 'expectedStateToken',
                 'expectedMetadataRevision', 'expectedPolicyRevision'}
                if function == SAVE else
                {'ruleId', 'expectedStateToken', 'expectedMetadataRevision',
                 'expectedPolicyRevision'})
    if (set(args) != required
            or any(type(args[key]) is not int or args[key] < 0
                   for key in ('expectedMetadataRevision',
                               'expectedPolicyRevision'))):
        raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
    if function == SAVE:
        if args['expectedStateToken'] is not None:
            require_state_token(args['expectedStateToken'],
                                error='V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
    else:
        require_state_token(args['expectedStateToken'],
                            error='V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
    if function == SAVE:
        calculation = {'languageVersion': 2,
                       'function': EXPRESSION_FUNCTION,
                       'arguments': args['calculation']}
        sample, _ = bind_rule_calculation(calculation, authoring=True)
        plan = compile_expression_program(
            sample, expected_target_state_token=None)
        return {**args, 'calculation': calculation,
                'plan': plan}
    return args


def _active_members(db, scope: ApplicationScope, plan) -> None:
    pairs = set(plan.source_members) | set(plan.target_members)
    pairs.update((axis,member) for axis,members in plan.source_member_sets
                 for member in members)
    for _, overrides in published_lookups(plan.expression):
        pairs.update(overrides)
    for _, overrides in published_ratio_lookups(plan.expression):
        pairs.update(overrides)
    for _, overrides, _ in published_unit_lookups(plan.expression):
        pairs.update(overrides)
    for overrides in source_lookups(plan.expression):
        pairs.update(overrides)
    for overrides in source_text_lookups(plan.expression):
        pairs.update(overrides)
    if plan.weight_expression:
        for overrides in source_lookups(plan.weight_expression):
            pairs.update(overrides)
    if plan.target_member_set:
        axis, members = plan.target_member_set
        pairs.update((axis, member) for member in members)
    if plan.reduce_member_set:
        axis, members, target, _ = plan.reduce_member_set
        pairs.update((axis, member) for member in (*members, target))
    if plan.reduce_member_sets:
        selections, _ = plan.reduce_member_sets
        for axis, members, target in selections:
            pairs.update((axis, member) for member in (*members, target))
    for axis, members in plan.target_member_sets or ():
        pairs.update((axis, member) for member in members)
    for axis, members in plan.source_domain or ():
        pairs.update((axis, member) for member in members)
    if plan.amount_unit:
        pairs.add((plan.amount_unit[0], plan.amount_unit[1]))
    unit_members = {unit for _, _, unit in
                    published_unit_lookups(plan.expression)}
    conversion = (plan.expression if plan.expression.get('op') ==
                  'CurrencyConvert' else None)
    if conversion:
        unit_members.update((conversion['fromCurrencyMemberId'],
                             conversion['toCurrencyMemberId'],
                             conversion['outputUnitCurrencyMemberId']))
    if unit_members:
        currency = db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s
              AND model_role='Currency' AND status='Active'
            ORDER BY dimension_id''',
            (scope.workspace_id, scope.application_id)).fetchall()
        if len(currency) != 1:
            raise ValueError('EXPRESSION_RULE_CURRENCY_ROLE_AMBIGUOUS')
        pairs.update((currency[0]['dimension_id'], member)
                     for member in unit_members)
    if not pairs:
        return
    rows = db.execute('''SELECT input.dimension_id,input.member_id,
        d.dimension_id IS NOT NULL AND m.member_id IS NOT NULL AS active
        FROM jsonb_to_recordset(%s::jsonb)
          AS input(dimension_id text,member_id text)
        LEFT JOIN epm.dimension d ON d.workspace_id=%s
         AND d.application_id=%s AND d.dimension_id=input.dimension_id
         AND d.status='Active'
        LEFT JOIN epm.member m ON m.workspace_id=%s
         AND m.application_id=%s AND m.dimension_id=input.dimension_id
         AND m.member_id=input.member_id AND m.status='Active' ''',
        (Jsonb([{'dimension_id': axis, 'member_id': member}
                for axis, member in sorted(pairs)]),
         scope.workspace_id, scope.application_id,
         scope.workspace_id, scope.application_id)).fetchall()
    if len(rows) != len(pairs) or any(not row['active'] for row in rows):
        raise ValueError('EXPRESSION_RULE_MEMBER_UNAVAILABLE')


def verify_published_rule(db, scope: ApplicationScope, pin: dict,
                          bound_program: dict | None = None) -> dict:
    row = db.execute('''SELECT state_token,status,program,program_digest,
        metadata_revision
        FROM epm.expression_rule_definition
        WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
        (scope.workspace_id, scope.application_id,
         pin['ruleId'])).fetchone()
    if (row is None or row['status'] != 'Active'
            or row['state_token'] != pin['stateToken']
            or row['program_digest'] != pin['programDigest']
            or _canonical_digest(row['program']) != pin['programDigest']):
        raise ValueError('STALE_EXPRESSION_RULE_STATE')
    expected, values = bind_rule_calculation(
        row['program'], pin.get('bindings'))
    if ((values is None) != ('bindings' not in pin)
            or (values is not None and pin['bindings'] != values)):
        raise ValueError('EXPRESSION_RULE_BINDINGS_INVALID')
    names = member_parameter_names(row['program'])
    if (pin.get('memberParameters', []) != names
            or ('memberParameters' in pin) != bool(names)):
        raise ValueError('EXPRESSION_RULE_MEMBER_BINDINGS_INVALID')
    if bound_program is not None:
        expected_pins = _shape_pins(expected['arguments']['expression'])
        plan = compile_expression_program(expected,
            expected_target_state_token=None, published_inputs=expected_pins)
        try:
            observed_plan = (compile_expression_program(bound_program,
                expected_target_state_token=None,
                published_inputs=_shape_pins(
                    bound_program['arguments']['expression']))
                if bound_program.get('languageVersion') == 2
                else decode_expression_program(bound_program))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError('EXPRESSION_RULE_BOUND_PROGRAM_MISMATCH') from error
        if _rule_plan_shape(observed_plan) != _rule_plan_shape(plan):
            raise ValueError('EXPRESSION_RULE_BOUND_PROGRAM_MISMATCH')
    return row


def _rule_plan_shape(plan) -> dict:
    """Canonical authored calculation, excluding execution-time pins."""
    value = dict(plan.normalized_program)
    for field in ('expectedTargetStateToken', 'publishedInputs',
                  'savedRule', 'driverPolicy'):
        value.pop(field, None)
    if 'contextDependencies' in value:
        ownership=('kind','sourceId','relationshipId','scenarioId','yearId',
            'periodId','account','expectedPresent','expectedAmount',
            'expectedChangeId')
        calendar=('kind','sourceId','yearId','periodId','effectiveOn',
                  'expectedChangeId')
        value['contextDependencies']=[{key:item[key] for key in (
            ownership if item.get('kind')=='OwnershipValue' else calendar)}
            for item in value['contextDependencies']]
    return value


def _shape_pins(expression: dict) -> tuple[dict, ...]:
    """Deterministic non-persisted pins used only to canonicalize a rule."""
    return tuple({'resultKey': key, 'resultStateToken': '0' * 64}
                 for key in expression_references(expression))


class PostgresExpressionRules:
    SAVE, PUBLISH, READ, LIST = SAVE, PUBLISH, READ, LIST
    STORED_FUNCTION = EXPRESSION_FUNCTION
    _parse = staticmethod(_program)
    _validate_definition = staticmethod(_active_members)

    @staticmethod
    def _summary(calculation):
        return {'resultKey':calculation['resultKey'],
                'parameterDeclarations':calculation.get('parameters',{})}

    @staticmethod
    def _validate_publication(db, scope, args, definition):
        """Extension hook for definition families with dependency graphs."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def resolve_published(self, scope: ApplicationScope,
                          raw: dict) -> tuple[dict, dict]:
        if (not isinstance(raw, dict)
                or set(raw) != {'languageVersion','function','arguments'}
                or type(raw['languageVersion']) is not int
                or raw['languageVersion'] != 2
                or raw['function'] != RUN
                or not isinstance(raw['arguments'], dict)
                or set(raw['arguments']) not in (
                    {'ruleId'}, {'ruleId', 'bindings'})
                or not isinstance(raw['arguments']['ruleId'], str)
                or not _ID.fullmatch(raw['arguments']['ruleId'])):
            raise ValueError('V2_EXPRESSION_RULE_RUN_ARGUMENTS_INVALID')
        rule_id = raw['arguments']['ruleId']
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'rule_run')
                row = db.execute('''SELECT *
                    FROM epm.expression_rule_definition
                    WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     rule_id)).fetchone()
                if (row is None or row['status'] != 'Active'
                        or row['program'].get('function')!=self.STORED_FUNCTION):
                    raise ValueError('EXPRESSION_RULE_NOT_PUBLISHED')
                from .postgres_python_definitions import assert_source_active
                assert_source_active(db,scope,row)
                if row['metadata_revision'] != state['metadata_revision']:
                    raise ValueError('EXPRESSION_RULE_METADATA_STALE')
                if _canonical_digest(row['program']) != row['program_digest']:
                    raise ValueError('EXPRESSION_RULE_DEFINITION_CORRUPT')
                pin = {'ruleId': rule_id, 'stateToken': row['state_token'],
                       'programDigest': row['program_digest']}
                bound, values = bind_rule_calculation(
                    row['program'], raw['arguments'].get('bindings'))
                if values is not None:
                    pin['bindings'] = values
                names = member_parameter_names(row['program'])
                if names:
                    pin['memberParameters'] = names
                return bound, pin

    def execute(self, scope: ApplicationScope, raw: dict, *,
                idempotency_key: str, _connection=None,
                _source_build_id: str | None = None) -> dict:
        function = raw.get('function') if isinstance(raw, dict) else None
        retire = getattr(self, 'RETIRE', None)
        is_retire = retire is not None and function == retire
        if function not in (self.SAVE, self.PUBLISH) and not is_retire:
            raise ValueError('V2_EXPRESSION_RULE_FUNCTION_INVALID')
        args = self._parse(raw, function)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('EXPRESSION_RULE_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': raw})
        connection = (nullcontext(_connection) if _connection is not None
                      else connect_postgres(self.dsn, row_factory=dict_row))
        with connection as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT s.metadata_revision,
                    s.policy_revision,s.commit_revision,s.processing_mode,
                    a.status AS application_status FROM epm.application_state s
                    JOIN epm.application a USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'write')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope,
                    'rule_design' if function == self.SAVE else 'rule_publish')
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                      AND application_id=%s AND operation_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != digest
                            or prior['actor_id'] != self.identity.subject_id):
                        raise ValueError('EXPRESSION_RULE_IDEMPOTENCY_CONFLICT')
                    PostgresNumericFactStore._require_replay_impact(
                        db,scope,idempotency_key,prior)
                    return prior['result']
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != args['expectedMetadataRevision']:
                    raise ValueError('STALE_METADATA_REVISION')
                if state['policy_revision'] != args['expectedPolicyRevision']:
                    raise ValueError('STALE_POLICY_REVISION')
                revision = state['commit_revision'] + 1
                impact = None
                current = db.execute('''SELECT *
                    FROM epm.expression_rule_definition
                    WHERE workspace_id=%s AND application_id=%s AND rule_id=%s
                    FOR UPDATE''', (scope.workspace_id,scope.application_id,
                    args['ruleId'])).fetchone()
                if is_retire:
                    if (current is None
                            or current['definition_kind'] !=
                                STORED_KINDS[self.STORED_FUNCTION]
                            or current['state_token'] != args['expectedStateToken']
                            or current['program_digest'] !=
                                args['expectedProgramDigest']):
                        raise ValueError('EXPRESSION_RULE_STATE_STALE')
                    if current['ownership_state'] != 'Unresolved':
                        raise ValueError('APPLICATION_RULE_RETIREMENT_NOT_UNRESOLVED')
                    replacement = db.execute('''SELECT *
                        FROM epm.expression_rule_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND rule_id=%s FOR SHARE''',(
                        scope.workspace_id,scope.application_id,
                        args['replacementRuleId'])).fetchone()
                    if (replacement is None
                            or replacement['definition_kind'] !=
                                STORED_KINDS[self.STORED_FUNCTION]
                            or replacement['state_token'] !=
                                args['expectedReplacementStateToken']
                            or replacement['program_digest'] !=
                                args['expectedReplacementProgramDigest']):
                        raise ValueError('APPLICATION_RULE_REPLACEMENT_STALE')
                    from .postgres_definition_lifecycle import (
                        assert_current_executable, DefinitionReferenceBlocked)
                    assert_current_executable(db,scope,replacement)
                    blockers=[]
                    for row in db.execute('''SELECT consumer_kind,consumer_id
                        FROM epm.current_definition_reference
                        WHERE workspace_id=%s AND application_id=%s
                          AND producer_kind='rule' AND producer_id=%s
                        ORDER BY consumer_kind,consumer_id''',(
                        scope.workspace_id,scope.application_id,
                        args['ruleId'])).fetchall():
                        blockers.append({'kind':row['consumer_kind'],
                                         'id':row['consumer_id']})
                    for table,key,label in (
                            ('application_schedule_definition','schedule_id',
                             'rule-schedule'),
                            ('application_rule_workflow','workflow_id',
                             'rule-workflow')):
                        for row in db.execute(f'''SELECT {key} id FROM epm.{table}
                            WHERE workspace_id=%s AND application_id=%s
                              AND rule_id=%s ORDER BY {key}''',(
                            scope.workspace_id,scope.application_id,
                            args['ruleId'])).fetchall():
                            blockers.append({'kind':label,'id':row['id']})
                    if blockers:
                        raise DefinitionReferenceBlocked(blockers)
                    replace_references(db,scope,
                        kind=STORED_KINDS[self.STORED_FUNCTION],
                        definition_id=args['ruleId'],payload=None)
                    db.execute('''DELETE FROM epm.expression_rule_definition
                        WHERE workspace_id=%s AND application_id=%s
                          AND rule_id=%s''',(
                        scope.workspace_id,scope.application_id,args['ruleId']))
                    from .calculation_impact_contract import (
                        compile_calculation_impact)
                    impact=compile_calculation_impact({
                        'format':'openepm-calculation-impact-v1',
                        'sourceKind':'definition','sourceId':idempotency_key,
                        'causalRevision':revision,'effects':[{
                            'domain':'definition','change':'delete',
                            'objectType':'application-rule',
                            'objectId':args['ruleId'],'scope':[],
                            'reason':'definition_changed',
                            'oldPresence':'present','newPresence':'absent'}]})
                    policy_revision=state['policy_revision']+1
                    result={'operationId':idempotency_key,
                        'ruleId':args['ruleId'],'status':'Retired',
                        'replacementRuleId':args['replacementRuleId'],
                        'replacementStateToken':replacement['state_token'],
                        'replacementProgramDigest':replacement['program_digest'],
                        'metadataRevision':state['metadata_revision'],
                        'policyRevision':policy_revision,
                        'committedRevision':revision,
                        'impactDigest':impact.digest}
                elif function == self.SAVE:
                    expected = args.get('expectedStateToken')
                    if ((current is None and expected is not None)
                            or (current is not None and expected is None)
                            or (current is not None
                                and current['state_token'] != expected)):
                        raise ValueError('EXPRESSION_RULE_STATE_STALE')
                    if current and current['definition_kind']!=STORED_KINDS[self.STORED_FUNCTION]:
                        raise ValueError('RULE_DEFINITION_KIND_CONFLICT')
                    if current and current['ownership_state']=='Unresolved':
                        raise ValueError('DEFINITION_OWNERSHIP_UNRESOLVED')
                    if current and current['ownership_state']=='Source':
                        from .postgres_definition_lifecycle import source_for_build
                        next_source = source_for_build(db,scope,_source_build_id)
                        if next_source is None or next_source['program_id']!=current['source_program_id']:
                            raise ValueError('PYTHON_DEFINITION_SOURCE_REQUIRED')
                    self._validate_definition(db, scope, args['plan'])
                    program_digest = _canonical_digest(args['calculation'])
                    acceptance = certificate(db,scope,kind=STORED_KINDS[self.STORED_FUNCTION],
                        definition_id=args['ruleId'],digest=program_digest,
                        metadata_revision=state['metadata_revision'],source_build_id=_source_build_id,payload=args['calculation'])
                    state_token = new_state_token()
                    policy_revision = (state['policy_revision'] + 1
                        if current and current['status'] == 'Active'
                        else state['policy_revision'])
                    result = {'operationId': idempotency_key,
                              'ruleId': args['ruleId'],
                              'stateToken': state_token,
                              'status': 'Saved',
                              'programDigest': program_digest,
                              'metadataRevision': state['metadata_revision'],
                              'policyRevision': policy_revision}
                    if current and current['status'] == 'Active':
                        from .calculation_impact_contract import (
                            compile_calculation_impact)
                        impact=compile_calculation_impact({
                            'format':'openepm-calculation-impact-v1',
                            'sourceKind':'definition',
                            'sourceId':idempotency_key,
                            'causalRevision':revision,'effects':[{
                                'domain':'definition','change':'deactivate',
                                'objectType':('calculated-member' if
                                    self.STORED_FUNCTION=='calculated.member.definition'
                                    else 'application-rule'),
                                'objectId':args['ruleId'],'scope':[],
                                'reason':'definition_changed',
                                'oldPresence':'present','newPresence':'absent'}]})
                        result['impactDigest']=impact.digest
                else:
                    if (current is None
                            or current['state_token'] != args['expectedStateToken']
                            or current['definition_kind']!=STORED_KINDS[self.STORED_FUNCTION]):
                        raise ValueError('EXPRESSION_RULE_STATE_STALE')
                    if (current['ownership_state']=='Source'
                            and current['source_build_id'] != _source_build_id):
                        raise ValueError('PYTHON_DEFINITION_SOURCE_ACTIVATION_REQUIRED')
                    if current['metadata_revision'] != state[
                            'metadata_revision']:
                        raise ValueError('EXPRESSION_RULE_METADATA_STALE')
                    if current['status'] == 'Active':
                        raise ValueError('EXPRESSION_RULE_ALREADY_ACTIVE')
                    if current['ownership_state']=='Unresolved':
                        raise ValueError('DEFINITION_OWNERSHIP_UNRESOLVED')
                    if current['program'] is None:
                        raise ValueError('DEFINITION_CURRENT_VALIDATION_REQUIRED')
                    validated_plan=(compile_expression_program(
                        bind_rule_calculation(current['program'],authoring=True)[0],
                        expected_target_state_token=None) if self.STORED_FUNCTION==EXPRESSION_FUNCTION
                        else current['program']['arguments'])
                    self._validate_definition(db,scope,validated_plan)
                    self._validate_publication(db, scope, args, current)
                    acceptance=(current['current_certificate'] if current['ownership_state']=='Source'
                        else certificate(db,scope,kind=STORED_KINDS[self.STORED_FUNCTION],
                            definition_id=args['ruleId'],digest=current['program_digest'],
                            metadata_revision=state['metadata_revision'],payload=current['program']))
                    if acceptance is None:
                        raise ValueError('DEFINITION_CURRENT_VALIDATION_REQUIRED')
                    policy_revision = state['policy_revision'] + 1
                    state_token = new_state_token()
                    result = {'operationId': idempotency_key,
                              'ruleId': args['ruleId'],
                              'stateToken': state_token,
                              'status': 'Active',
                              'programDigest': current['program_digest'],
                              'policyRevision': policy_revision}
                    definition_type = ({
                        'calculated.member.definition':
                            'calculated-member',
                        'application.rule.plan':
                            'application-rule',
                    }.get(self.STORED_FUNCTION,'expression-rule'))
                    from .calculation_impact_contract import (
                        compile_calculation_impact)
                    effects=[{
                        'domain':'definition','change':'activate',
                        'objectType':definition_type,
                        'objectId':args['ruleId'],
                        'scope':[],'reason':'definition_changed',
                        'oldPresence':'absent','newPresence':'present'}]
                    impact=compile_calculation_impact({
                        'format':'openepm-calculation-impact-v1',
                        'sourceKind':'definition',
                        'sourceId':idempotency_key,
                        'causalRevision':revision,'effects':effects})
                    result['impactDigest']=impact.digest
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, revision, scope.workspace_id,
                     scope.application_id))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,command_digest,
                     actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (scope.workspace_id, scope.application_id,
                     idempotency_key, digest, self.identity.subject_id,
                     revision, Jsonb(result)))
                if is_retire:
                    pass
                elif function == self.SAVE:
                    db.execute('''INSERT INTO epm.expression_rule_definition
                        (workspace_id,application_id,rule_id,program,
                         program_digest,state_token,status,metadata_revision,
                         source_build_id,updated_operation_id,
                         updated_issuer,updated_subject_id,definition_kind,current_certificate,
                         ownership_state,source_program_id,source_token,source_digest)
                        VALUES (%s,%s,%s,%s,%s,%s,'Saved',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT(workspace_id,application_id,rule_id)
                        DO UPDATE SET program=EXCLUDED.program,
                          program_digest=EXCLUDED.program_digest,
                          state_token=EXCLUDED.state_token,status='Saved',
                          metadata_revision=EXCLUDED.metadata_revision,
                          source_build_id=EXCLUDED.source_build_id,
                          current_certificate=EXCLUDED.current_certificate,
                          updated_operation_id=EXCLUDED.updated_operation_id,
                          updated_issuer=EXCLUDED.updated_issuer,
                          updated_subject_id=EXCLUDED.updated_subject_id,
                          updated_at=transaction_timestamp()''',
                        (scope.workspace_id, scope.application_id,
                         args['ruleId'], Jsonb(args['calculation']),
                         program_digest,state_token,state['metadata_revision'],
                         _source_build_id,idempotency_key,self.identity.issuer,
                         self.identity.subject_id,STORED_KINDS[self.STORED_FUNCTION],Jsonb(acceptance),
                         current['ownership_state'] if current else 'Configuration',
                         current.get('source_program_id') if current else None,
                         current.get('source_token') if current else None,
                         current.get('source_digest') if current else None))
                else:
                    db.execute('''UPDATE epm.expression_rule_definition SET
                        state_token=%s,status='Active',current_certificate=%s,updated_operation_id=%s,
                        updated_issuer=%s,updated_subject_id=%s,
                        updated_at=transaction_timestamp()
                        WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
                        (state_token,Jsonb(acceptance),idempotency_key,self.identity.issuer,
                         self.identity.subject_id,
                         scope.workspace_id, scope.application_id,
                         args['ruleId']))
                if not is_retire:
                    replace_references(db,scope,kind=STORED_KINDS[self.STORED_FUNCTION],
                        definition_id=args['ruleId'],payload=args['calculation'] if function==self.SAVE else current['program'])
                if impact is not None:
                    from .postgres_calculation_impact import (
                        record_calculation_impact)
                    record_calculation_impact(db,scope,
                        operation_id=idempotency_key,impact=impact)
                return result

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = self._parse(raw, self.READ)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,
                    policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                row = db.execute('''SELECT *
                    FROM epm.expression_rule_definition
                    WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['ruleId'])).fetchone()
                if row and row['definition_kind']!=STORED_KINDS[self.STORED_FUNCTION]:
                    row=None
                from .postgres_python_definitions import source_binding
                source = source_binding(db, scope, row) if row else None
                return {'ruleId': args['ruleId'],
                        'source': source,
                        'defined': row is not None,
                        'stateToken': row['state_token'] if row else None,
                        **current_state(row,resolution_context(db,scope,[row])),
                        'program': row['program'] if row else None,
                        'programDigest': row['program_digest'] if row else None,
                        'definitionMetadataRevision': (
                            row['metadata_revision'] if row else None),
                        'currentMetadataRevision': state['metadata_revision'],
                        'updatedOperationId': (
                            row['updated_operation_id'] if row else None),
                        'updatedAt': row['updated_at'].isoformat() if row else None,
                        'policyRevision': state['policy_revision']}

    def list_published(self, scope: ApplicationScope, raw: dict) -> dict:
        """Page current definitions; no historical or unpublished copy exists."""
        args = self._parse(raw, self.LIST)
        limit = args.get('limit', 100)
        after = args.get('afterRuleId')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,
                    policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                if any(state[f'{name}_revision'] !=
                       args.get(f'expected{name.capitalize()}Revision',
                                state[f'{name}_revision'])
                       for name in ('metadata', 'policy')):
                    raise ValueError('STALE_EXPRESSION_RULE_LIST_REVISION')
                rows = db.execute('''SELECT v.*
                    FROM epm.expression_rule_definition v
                    WHERE v.workspace_id=%s AND v.application_id=%s
                      AND v.definition_kind=%s
                      AND (%s::text IS NULL OR v.rule_id>%s)
                    ORDER BY v.rule_id LIMIT %s''',
                    (scope.workspace_id, scope.application_id,
                     STORED_KINDS[self.STORED_FUNCTION], after, after, limit + 1)).fetchall()
                result = []
                owner_context=resolution_context(db,scope,rows[:limit])
                for row in rows[:limit]:
                    if row['program'] is not None and _canonical_digest(row['program']) != row['program_digest']:
                        raise ValueError('EXPRESSION_RULE_DEFINITION_CORRUPT')
                    calculation = row['program']['arguments'] if row['program'] is not None else None
                    result.append({
                        'ruleId': row['rule_id'],
                        'stateToken': row['state_token'],
                        'programDigest': row['program_digest'],
                        'sourceBuildId': row['source_build_id'],
                        **current_state(row,owner_context),
                        **(self._summary(calculation) if calculation is not None else {}),
                        'definitionMetadataRevision':
                            row['metadata_revision'],
                        'metadataCurrent': row['metadata_revision'] ==
                            state['metadata_revision'],
                    })
                return {'rows': result,
                        'metadataRevision': state['metadata_revision'],
                        'policyRevision': state['policy_revision'],
                        'hasMore': len(rows) > limit,
                        'nextAfterRuleId': (result[-1]['ruleId']
                                            if len(rows) > limit else None)}
