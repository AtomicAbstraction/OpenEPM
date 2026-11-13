"""Durable calculated publication for explicit Unreviewed cash-flow mappings."""
from __future__ import annotations

from psycopg.rows import dict_row

from .consolidation_cash_flow_publication import CashFlowPublication
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_expression_sequence import (
    FUNCTION as SEQUENCE_RUN, READ as SEQUENCE_READ,
    PostgresExpressionSequence)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


INSPECT = 'consolidation.cash_flow.publication.inspect'
REQUEST = 'consolidation.cash_flow.publication.request'
READ = 'consolidation.cash_flow.publication.read'
_NAMES = ('Operating', 'Investing', 'Financing', 'Reconciliation')


def enforce_cash_flow_dimensional_security(
        db, identity, scope, mapping: CashFlowPublication, *, readback: bool):
    """Authorize every mapped input and output before wrapper inspection."""
    inputs = (mapping.opening, mapping.closing,
              *(line.source for line in mapping.lines))
    input_coordinates = tuple(
        Coordinate.from_mapping(dict(pin.members)) for pin in inputs)
    targets = dict(mapping.targets)
    if set(targets) != set(_NAMES):
        raise ValueError('CASH_FLOW_SECURITY_COORDINATES_INVALID')
    output_coordinates = tuple(
        Coordinate.from_mapping(dict(targets[name])) for name in _NAMES)
    authorize_coordinates(db, identity, scope, input_coordinates,
                          kind=AccessKind.READ)
    authorize_coordinates(db, identity, scope, output_coordinates,
                          kind=(AccessKind.READ if readback
                                else AccessKind.WRITE))


def _arguments(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or raw.get('languageVersion') != 2
            or raw.get('function') != function
            or not isinstance(raw.get('arguments'), dict)):
        raise ValueError('CASH_FLOW_PUBLICATION_PROGRAM_INVALID')
    args = raw['arguments']
    if function == READ:
        if (set(args) != {'sequenceId'}
                or not isinstance(args['sequenceId'], str)):
            raise ValueError('CASH_FLOW_PUBLICATION_READ_INVALID')
    elif (set(args) != {'definition', 'ruleIds'}
            or not isinstance(args.get('ruleIds'), list)
            or len(args['ruleIds']) != 4):
        raise ValueError('CASH_FLOW_PUBLICATION_REQUEST_INVALID')
    return args


def _sequence(args: dict) -> dict:
    return {'languageVersion': 2, 'function': SEQUENCE_RUN,
            'arguments': {'ruleIds': args['ruleIds']}}


def _add(left: dict, right: dict) -> dict:
    return {'op': 'Add', 'left': left, 'right': right}


def _negative(value: dict) -> dict:
    return {'op': 'Multiply', 'left': value,
            'right': {'op': 'RatioLiteral', 'decimal': '-1'}}


def _source_expression(base: dict, lines) -> dict:
    expression = None
    for line in lines:
        members = dict(line.members)
        overrides = {axis: member for axis, member in members.items()
                     if base.get(axis) != member}
        term = {'op': 'PublishedUnitAmount',
                'resultKey': line.source.result_key,
                'memberOverrides': overrides,
                'outputUnitCurrencyMemberId':
                    line.source.output_unit_currency_member_id}
        if line.direction == -1:
            term = _negative(term)
        expression = term if expression is None else _add(expression, term)
    return expression


def configured_programs(mapping: CashFlowPublication) -> list[dict]:
    targets = dict(mapping.targets)
    keys = dict(mapping.result_keys)
    programs = []
    for section in _NAMES[:-1]:
        lines = [line for line in mapping.lines if line.section == section]
        base = dict(lines[0].members)
        target = {axis: member for axis, member in dict(targets[section]).items()
                  if base.get(axis) != member}
        programs.append({'languageVersion': 2,
          'function': 'facts.expression.calculate', 'arguments': {
            'sourceMembers': base,
            'expression': _source_expression(base, lines),
            'targetMembers': target,
            'resultKey': keys[section]}})
    base = dict(mapping.lines[0].members)
    opening = {'op': 'PublishedUnitAmount',
      'resultKey': mapping.opening.result_key,
      'memberOverrides': dict(mapping.opening.members),
      'outputUnitCurrencyMemberId': mapping.currency_member_id}
    closing = {'op': 'PublishedUnitAmount',
      'resultKey': mapping.closing.result_key,
      'memberOverrides': dict(mapping.closing.members),
      'outputUnitCurrencyMemberId': mapping.currency_member_id}
    expression = opening
    for section in _NAMES[:-1]:
        expression = _add(expression, {'op': 'PublishedUnitAmount',
          'resultKey': keys[section],
          'memberOverrides': dict(targets[section]),
          'outputUnitCurrencyMemberId': mapping.currency_member_id})
    expression = _add(expression, _negative(closing))
    target = {axis: member for axis, member in
              dict(targets['Reconciliation']).items()
              if base.get(axis) != member}
    programs.append({'languageVersion': 2,
      'function': 'facts.expression.calculate', 'arguments': {
        'sourceMembers': base, 'expression': expression,
        'targetMembers': target,
        'resultKey': keys['Reconciliation']}})
    return programs


def _validate(mapping: CashFlowPublication, preview: dict) -> dict:
    expected = configured_programs(mapping)
    steps = preview['steps']
    if len(steps) != 4:
        raise ValueError('CASH_FLOW_PUBLICATION_STEP_COUNT_INVALID')
    if [step['resultKey'] for step in steps] != [
            program['arguments']['resultKey'] for program in expected]:
        raise ValueError('CASH_FLOW_PUBLICATION_RESULT_ORDER_INVALID')
    if any(step.get('boundProgram') != program
           for step, program in zip(steps, expected)):
        raise ValueError('CASH_FLOW_PUBLICATION_RULE_MISMATCH')
    if any(step['version'] != mapping.mapping_version for step in steps):
        raise ValueError('CASH_FLOW_PUBLICATION_VERSION_MISMATCH')
    external = {pin['resultKey']: pin for pin in preview['externalInputs']}
    expected_external = {pin.result_key: {
        'resultKey': pin.result_key, 'generationId': pin.generation_id,
        'publishedRevision': pin.published_revision}
        for pin in (mapping.opening, mapping.closing,
                    *(line.source for line in mapping.lines))}
    if external != expected_external:
        raise ValueError('CASH_FLOW_BALANCE_GENERATION_STALE')
    return {'mapping': mapping.normalized(), 'mappingDigest': mapping.digest,
      'calculatedOutputs': [{'section': name,
        'resultKey': dict(mapping.result_keys)[name],
        'checkpoint': index + 1}
        for index, name in enumerate(_NAMES)],
      'steps': steps, 'externalInputs': preview['externalInputs']}


class PostgresCashFlowPublication:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity
        self.preview_secret = preview_secret

    def _mapping(self, scope: ApplicationScope, args: dict
                 ) -> CashFlowPublication:
        mapping = CashFlowPublication.parse(args['definition'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'rule_run', function=REQUEST)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,capability_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or any((
                    state['metadata_revision'] !=
                        mapping.expected_metadata_revision,
                    state['data_revision'] != mapping.expected_data_revision,
                    state['policy_revision'] != mapping.expected_policy_revision,
                    state['capability_revision'] !=
                        mapping.expected_authorization_revision))):
                    raise ValueError('CASH_FLOW_PUBLICATION_REVISION_STALE')
                currency = db.execute('''SELECT 1 FROM epm.dimension d
                    JOIN epm.member m ON m.workspace_id=d.workspace_id
                      AND m.application_id=d.application_id
                      AND m.dimension_id=d.dimension_id
                    WHERE d.workspace_id=%s AND d.application_id=%s
                      AND d.model_role='Currency' AND d.status='Active'
                      AND m.member_id=%s AND m.status='Active' ''',
                    (scope.workspace_id, scope.application_id,
                     mapping.currency_member_id)).fetchone()
                if currency is None:
                    raise ValueError('CASH_FLOW_CURRENCY_UNAVAILABLE')
                for dimension, state_token in mapping.hierarchy_pins:
                    active = db.execute('''SELECT state_token FROM
                        epm.hierarchy_state WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id)''',
                        (scope.workspace_id, scope.application_id,
                         dimension)).fetchone()
                    if active is None or active['state_token'] != state_token:
                        raise ValueError('CASH_FLOW_HIERARCHY_STALE')
                input_pins = (mapping.opening, mapping.closing,
                              *(line.source for line in mapping.lines))
                for pin in input_pins:
                    members = dict(pin.members)
                    PostgresSourceBatch._check_scope_members(db, scope, members)
                enforce_cash_flow_dimensional_security(
                    db, self.identity, scope, mapping, readback=False)
                for pin in input_pins:
                    members = dict(pin.members)
                    coordinate = Coordinate.from_mapping(members)
                    rows = db.execute('''SELECT c.members,
                        r.output_unit_currency_member_id FROM
                        epm.coordinate c JOIN epm.calculation_unit_result_current r
                          USING(workspace_id,application_id,coordinate_id)
                        WHERE c.workspace_id=%s AND c.application_id=%s
                          AND c.series_key=%s AND r.result_key=%s
                          AND r.output_unit_currency_member_id=%s
                        ORDER BY r.output_unit_currency_dimension_id LIMIT 2''',
                        (scope.workspace_id, scope.application_id,
                         coordinate.series_key, pin.result_key,
                         pin.output_unit_currency_member_id)).fetchall()
                    if len(rows) != 1:
                        raise ValueError('CASH_FLOW_TYPED_UNIT_SOURCE_MISSING')
                    if rows[0]['members'] != members:
                        raise ValueError('COORDINATE_HASH_COLLISION')
        return mapping

    def inspect(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _arguments(raw, INSPECT)
        mapping = self._mapping(scope, args)
        preview = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).preview(
                scope, _sequence(args),
                manifest_extension={'cashFlowReconciliation':
                                    mapping.normalized()})
        return {**_validate(mapping, preview),
          'accountingPolicyStatus': 'Unreviewed',
          'effects': {'published': False, 'rawFactsChanged': False}}

    def preview(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _arguments(raw, REQUEST)
        mapping = self._mapping(scope, args)
        result = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).preview(
                scope, _sequence(args),
                manifest_extension={'cashFlowReconciliation':
                                    mapping.normalized()})
        return {**result, 'function': REQUEST,
                'cashFlowPlan': _validate(mapping, result),
                'accountingPolicyStatus': 'Unreviewed'}

    def submit(self, scope: ApplicationScope, raw: dict, *,
               preview_token: str, idempotency_key: str) -> dict:
        args = _arguments(raw, REQUEST)
        mapping = self._mapping(scope, args)
        return PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).submit(
                scope, _sequence(args), preview_token=preview_token,
                idempotency_key=idempotency_key,
                manifest_extension={'cashFlowReconciliation':
                                    mapping.normalized()})

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _arguments(raw, READ)
        sequence = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).read(scope, {
              'languageVersion': 2, 'function': SEQUENCE_READ,
              'arguments': {'sequenceId': args['sequenceId']}})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=READ)
                row = db.execute('''SELECT manifest FROM
                    epm.expression_rule_sequence WHERE workspace_id=%s
                    AND application_id=%s AND sequence_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     args['sequenceId'])).fetchone()
                if (row is None or 'cashFlowReconciliation' not in
                        row['manifest']):
                    raise ValueError('CASH_FLOW_PUBLICATION_UNAVAILABLE')
                mapping = CashFlowPublication.parse(
                    row['manifest']['cashFlowReconciliation'])
                enforce_cash_flow_dimensional_security(
                    db, self.identity, scope, mapping, readback=True)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,capability_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                context_stale = (state is None or any((
                    state['metadata_revision'] !=
                        mapping.expected_metadata_revision,
                    state['data_revision'] != mapping.expected_data_revision,
                    state['policy_revision'] != mapping.expected_policy_revision,
                    state['capability_revision'] !=
                        mapping.expected_authorization_revision)))
                hierarchy_stale = False
                for dimension, state_token in mapping.hierarchy_pins:
                    active = db.execute('''SELECT state_token FROM
                        epm.hierarchy_state WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id)''',
                        (scope.workspace_id, scope.application_id,
                         dimension)).fetchone()
                    if active is None or active['state_token'] != state_token:
                        hierarchy_stale = True
                source_stale = False
                input_pins = (mapping.opening, mapping.closing,
                              *(line.source for line in mapping.lines))
                for pin in input_pins:
                    coordinate = Coordinate.from_mapping(dict(pin.members))
                    typed = db.execute('''SELECT c.members FROM
                        epm.coordinate c JOIN epm.calculation_unit_result_current r
                          USING(workspace_id,application_id,coordinate_id)
                        WHERE c.workspace_id=%s AND c.application_id=%s
                          AND c.series_key=%s AND r.result_key=%s
                          AND r.output_unit_currency_member_id=%s''',
                        (scope.workspace_id, scope.application_id,
                         coordinate.series_key, pin.result_key,
                         pin.output_unit_currency_member_id)).fetchone()
                    if typed is None or typed['members'] != dict(pin.members):
                        source_stale = True
                keys = [pin.result_key for pin in input_pins] + [
                        key for _, key in mapping.result_keys]
                publications = db.execute('''SELECT result_key,
                    source_operation_id AS generation_id,
                    committed_revision AS published_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                      AND result_key=ANY(%s::text[])''',
                    (scope.workspace_id, scope.application_id,
                     keys)).fetchall()
                current = {item['result_key']: item for item in publications}
                reconciliation_key = dict(mapping.result_keys)[
                    'Reconciliation']
                reconciliation = current.get(reconciliation_key)
                result_rows = ([] if reconciliation is None else
                    db.execute('''SELECT amount,
                        output_unit_currency_member_id
                        FROM epm.calculation_unit_result_current
                        WHERE workspace_id=%s AND application_id=%s
                          AND result_key=%s''',
                        (scope.workspace_id, scope.application_id,
                         reconciliation_key)).fetchall())
        balances_stale = any(current.get(pin.result_key) != {
            'result_key': pin.result_key, 'generation_id': pin.generation_id,
            'published_revision': pin.published_revision}
            for pin in input_pins)
        output_stale = any(index < len(sequence['jobIds']) and
            (current.get(key) is None or
             current[key]['generation_id'] != sequence['jobIds'][index])
            for index, (_, key) in enumerate(mapping.result_keys))
        result_unavailable = (len(result_rows) != 1 or
            (len(result_rows) == 1 and
             result_rows[0]['output_unit_currency_member_id'] !=
             mapping.currency_member_id))
        difference = (None if result_unavailable else
                      format(result_rows[0]['amount'], '.8f'))
        stale = (context_stale or hierarchy_stale or source_stale
                 or balances_stale or output_stale or result_unavailable)
        return {**sequence, 'mappingId': mapping.mapping_id,
          'mappingVersion': mapping.mapping_version,
          'mappingDigest': mapping.digest,
          'accountingPolicyStatus': 'Unreviewed',
          'calculatedOutputs': [{'section': name, 'resultKey': key,
             'jobId': (sequence['jobIds'][index]
                       if index < len(sequence['jobIds']) else None)}
             for index, (name, key) in enumerate(mapping.result_keys)],
          'stale': stale,
          'staleReasons': [reason for condition, reason in (
            (context_stale, 'CONTEXT_STALE'),
            (hierarchy_stale, 'HIERARCHY_STALE'),
            (source_stale, 'SOURCE_CORRECTION_STALE'),
            (balances_stale, 'BALANCE_GENERATION_STALE'),
            (output_stale, 'OUTPUT_REPUBLISHED'),
            (result_unavailable, 'RECONCILIATION_RESULT_UNAVAILABLE'))
            if condition],
          'difference': difference,
          'reconciled': difference == '0.00000000',
          'effects': {'rawFactsChanged': False,
                      'authoritativeFactsPosted': False}}
