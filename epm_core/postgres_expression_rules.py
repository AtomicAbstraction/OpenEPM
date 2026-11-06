"""Immutable typed expression-rule versions and an atomic publication pointer.

Saving is authoring, not execution. Only a published, metadata-current version
may later be resolved for a rule run. All programs remain fixed-core data.
"""
from __future__ import annotations

import re

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


SAVE = 'rules.expression.version.save'
PUBLISH = 'rules.expression.version.publish'
READ = 'rules.expression.version.read'
LIST = 'rules.expression.version.list'
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
                expected_publication_revision=0, published_inputs=())
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
        if (set(args) not in ({'ruleId'}, {'ruleId', 'version'})
                or ('version' in args and (type(args['version']) is not int
                                           or args['version'] < 1))):
            raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
        return args
    required = ({'ruleId', 'version', 'calculation',
                 'expectedMetadataRevision', 'expectedPolicyRevision'}
                if function == SAVE else
                {'ruleId', 'version', 'expectedMetadataRevision',
                 'expectedPolicyRevision'})
    if (set(args) != required
            or type(args['version']) is not int or args['version'] < 1
            or any(type(args[key]) is not int or args[key] < 0
                   for key in ('expectedMetadataRevision',
                               'expectedPolicyRevision'))):
        raise ValueError('V2_EXPRESSION_RULE_ARGUMENTS_INVALID')
    if function == SAVE:
        calculation = {'languageVersion': 2,
                       'function': EXPRESSION_FUNCTION,
                       'arguments': args['calculation']}
        sample, _ = bind_rule_calculation(calculation, authoring=True)
        plan = compile_expression_program(
            sample, expected_publication_revision=0)
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
    row = db.execute('''SELECT p.version,p.published_revision,
        v.program,v.program_digest,v.metadata_revision
        FROM epm.expression_rule_publication p
        JOIN epm.expression_rule_version v
          ON v.workspace_id=p.workspace_id
         AND v.application_id=p.application_id
         AND v.rule_id=p.rule_id AND v.version=p.version
        WHERE p.workspace_id=%s AND p.application_id=%s
          AND p.rule_id=%s''',
        (scope.workspace_id, scope.application_id,
         pin['ruleId'])).fetchone()
    if (row is None or row['version'] != pin['version']
            or row['published_revision'] != pin['publishedRevision']
            or row['program_digest'] != pin['programDigest']
            or _canonical_digest(row['program']) != pin['programDigest']):
        raise ValueError('STALE_EXPRESSION_RULE_PUBLICATION')
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
            expected_publication_revision=0, published_inputs=expected_pins)
        try:
            observed_plan = (compile_expression_program(bound_program,
                expected_publication_revision=0,
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
    for field in ('expectedPublicationRevision', 'publishedInputs',
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
    return tuple({'resultKey': key, 'generationId': '0' * 32,
                  'publishedRevision': 1}
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
                row = db.execute('''SELECT p.version,p.published_revision,
                    v.program,v.program_digest,v.metadata_revision
                    FROM epm.expression_rule_publication p
                    JOIN epm.expression_rule_version v
                      ON v.workspace_id=p.workspace_id
                     AND v.application_id=p.application_id
                     AND v.rule_id=p.rule_id AND v.version=p.version
                    WHERE p.workspace_id=%s AND p.application_id=%s
                      AND p.rule_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     rule_id)).fetchone()
                if row is None or row['program'].get('function')!=self.STORED_FUNCTION:
                    raise ValueError('EXPRESSION_RULE_NOT_PUBLISHED')
                if row['metadata_revision'] != state['metadata_revision']:
                    raise ValueError('EXPRESSION_RULE_METADATA_STALE')
                if _canonical_digest(row['program']) != row['program_digest']:
                    raise ValueError('EXPRESSION_RULE_DEFINITION_CORRUPT')
                pin = {'ruleId': rule_id, 'version': row['version'],
                       'programDigest': row['program_digest'],
                       'publishedRevision': row['published_revision']}
                bound, values = bind_rule_calculation(
                    row['program'], raw['arguments'].get('bindings'))
                if values is not None:
                    pin['bindings'] = values
                names = member_parameter_names(row['program'])
                if names:
                    pin['memberParameters'] = names
                return bound, pin

    def execute(self, scope: ApplicationScope, raw: dict, *,
                idempotency_key: str) -> dict:
        function = raw.get('function') if isinstance(raw, dict) else None
        if function not in (self.SAVE, self.PUBLISH):
            raise ValueError('V2_EXPRESSION_RULE_FUNCTION_INVALID')
        args = self._parse(raw, function)
        if not isinstance(idempotency_key, str) or not _KEY.fullmatch(
                idempotency_key):
            raise ValueError('EXPRESSION_RULE_IDEMPOTENCY_KEY_INVALID')
        digest = _canonical_digest({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'program': raw})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
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
                    return prior['result']
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if state['metadata_revision'] != args['expectedMetadataRevision']:
                    raise ValueError('STALE_METADATA_REVISION')
                if state['policy_revision'] != args['expectedPolicyRevision']:
                    raise ValueError('STALE_POLICY_REVISION')
                revision = state['commit_revision'] + 1
                if function == self.SAVE:
                    latest = db.execute('''SELECT version,program FROM epm.expression_rule_version
                        WHERE workspace_id=%s AND application_id=%s AND rule_id=%s
                        ORDER BY version DESC LIMIT 1''',
                        (scope.workspace_id,scope.application_id,args['ruleId'])).fetchone()
                    if latest and latest['program'].get('function')!=self.STORED_FUNCTION:
                        raise ValueError('RULE_DEFINITION_KIND_CONFLICT')
                    if args['version'] != (latest['version'] if latest else 0) + 1:
                        raise ValueError('EXPRESSION_RULE_VERSION_NOT_NEXT')
                    self._validate_definition(db, scope, args['plan'])
                    program_digest = _canonical_digest(args['calculation'])
                    result = {'operationId': idempotency_key,
                              'ruleId': args['ruleId'],
                              'version': args['version'],
                              'status': 'Saved',
                              'programDigest': program_digest,
                              'metadataRevision': state['metadata_revision'],
                              'policyRevision': state['policy_revision'],
                              'committedRevision': revision}
                    policy_revision = state['policy_revision']
                else:
                    definition = db.execute('''SELECT program,program_digest,
                        metadata_revision FROM epm.expression_rule_version
                        WHERE workspace_id=%s AND application_id=%s
                          AND rule_id=%s AND version=%s''',
                        (scope.workspace_id, scope.application_id,
                         args['ruleId'], args['version'])).fetchone()
                    if definition is None or definition['program'].get('function')!=self.STORED_FUNCTION:
                        raise ValueError('EXPRESSION_RULE_VERSION_UNAVAILABLE')
                    if definition['metadata_revision'] != state[
                            'metadata_revision']:
                        raise ValueError('EXPRESSION_RULE_METADATA_STALE')
                    self._validate_publication(db, scope, args, definition)
                    published = db.execute('''SELECT version FROM
                        epm.expression_rule_publication WHERE workspace_id=%s
                          AND application_id=%s AND rule_id=%s''',
                        (scope.workspace_id, scope.application_id,
                         args['ruleId'])).fetchone()
                    if published and published['version'] == args['version']:
                        raise ValueError('EXPRESSION_RULE_VERSION_ALREADY_PUBLISHED')
                    policy_revision = state['policy_revision'] + 1
                    result = {'operationId': idempotency_key,
                              'ruleId': args['ruleId'],
                              'version': args['version'],
                              'status': 'Published',
                              'programDigest': definition['program_digest'],
                              'policyRevision': policy_revision,
                              'committedRevision': revision}
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
                if function == self.SAVE:
                    db.execute('''INSERT INTO epm.expression_rule_version
                        (workspace_id,application_id,rule_id,version,program,
                         program_digest,metadata_revision,
                         created_operation_id,created_revision,
                         created_issuer,created_subject_id)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (scope.workspace_id, scope.application_id,
                         args['ruleId'], args['version'],
                         Jsonb(args['calculation']), program_digest,
                         state['metadata_revision'], idempotency_key,
                         revision, self.identity.issuer,
                         self.identity.subject_id))
                else:
                    db.execute('''INSERT INTO epm.expression_rule_publication
                        (workspace_id,application_id,rule_id,version,
                         published_operation_id,published_revision)
                        VALUES (%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (workspace_id,application_id,rule_id)
                        DO UPDATE SET version=EXCLUDED.version,
                            published_operation_id=EXCLUDED.published_operation_id,
                            published_revision=EXCLUDED.published_revision,
                            updated_at=transaction_timestamp()''',
                        (scope.workspace_id, scope.application_id,
                         args['ruleId'], args['version'],
                         idempotency_key, revision))
                return result

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = self._parse(raw, self.READ)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                pointer = db.execute('''SELECT version,published_revision
                    FROM epm.expression_rule_publication
                    WHERE workspace_id=%s AND application_id=%s
                      AND rule_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['ruleId'])).fetchone()
                version = args.get('version') or (
                    pointer['version'] if pointer else None)
                row = (db.execute('''SELECT version,program,program_digest,
                    metadata_revision,created_revision,created_at
                    FROM epm.expression_rule_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND rule_id=%s AND version=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['ruleId'], version)).fetchone()
                    if version is not None else None)
                if row and row['program'].get('function')!=self.STORED_FUNCTION:
                    row=None;pointer=None
                return {'ruleId': args['ruleId'],
                        'defined': row is not None,
                        'version': row['version'] if row else version,
                        'status': ('Published' if row and pointer and
                                   row['version'] == pointer['version'] else
                                   'Saved' if row else None),
                        'program': row['program'] if row else None,
                        'programDigest': row['program_digest'] if row else None,
                        'definitionMetadataRevision': (
                            row['metadata_revision'] if row else None),
                        'currentMetadataRevision': state['metadata_revision'],
                        'publishedRevision': (
                            pointer['published_revision'] if pointer and row
                            and row['version'] == pointer['version'] else None),
                        'createdRevision': (
                            row['created_revision'] if row else None),
                        'createdAt': row['created_at'].isoformat() if row else None,
                        'policyRevision': state['policy_revision'],
                        'commitRevision': state['commit_revision']}

    def list_published(self, scope: ApplicationScope, raw: dict) -> dict:
        """Page current publications, never unpublished draft definitions."""
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
                rows = db.execute('''SELECT p.rule_id,p.version,
                    p.published_revision,v.program,v.program_digest,
                    v.metadata_revision
                    FROM epm.expression_rule_publication p
                    JOIN epm.expression_rule_version v
                      ON v.workspace_id=p.workspace_id
                     AND v.application_id=p.application_id
                     AND v.rule_id=p.rule_id AND v.version=p.version
                    WHERE p.workspace_id=%s AND p.application_id=%s
                      AND v.program->>'function'=%s
                      AND (%s::text IS NULL OR p.rule_id>%s)
                    ORDER BY p.rule_id LIMIT %s''',
                    (scope.workspace_id, scope.application_id,
                     self.STORED_FUNCTION, after, after, limit + 1)).fetchall()
                result = []
                for row in rows[:limit]:
                    if _canonical_digest(row['program']) != row['program_digest']:
                        raise ValueError('EXPRESSION_RULE_DEFINITION_CORRUPT')
                    calculation = row['program']['arguments']
                    result.append({
                        'ruleId': row['rule_id'],
                        'version': row['version'],
                        'publishedRevision': row['published_revision'],
                        'programDigest': row['program_digest'],
                        **self._summary(calculation),
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
