"""Capability-gated adapter from equity-chain plans to durable rule sequences."""
from __future__ import annotations

from psycopg.rows import dict_row

from .consolidation_equity_rollforward_chain import EquityRollforwardChain
from .persistence_contract import ApplicationScope
from .persistence_contract import Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_expression_sequence import (
    FUNCTION as SEQUENCE_RUN, READ as SEQUENCE_READ,
    PostgresExpressionSequence)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch


INSPECT = 'consolidation.equity.rollforward.chain.inspect'
REQUEST = 'consolidation.equity.rollforward.chain.request'
READ = 'consolidation.equity.rollforward.chain.read'


def _arguments(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or raw.get('languageVersion') != 2
            or raw.get('function') != function
            or not isinstance(raw.get('arguments'), dict)):
        raise ValueError('EQUITY_CHAIN_PROGRAM_INVALID')
    args = raw['arguments']
    if function == READ:
        if (set(args) != {'sequenceId'}
                or not isinstance(args['sequenceId'], str)):
            raise ValueError('EQUITY_CHAIN_READ_INVALID')
        return args
    if (set(args) not in ({'definition', 'ruleIds'},
                          {'definition', 'ruleIds', 'bindings'})
            or not isinstance(args.get('ruleIds'), list)
            or not 2 <= len(args['ruleIds']) <= 8
            or ('bindings' in args and not isinstance(args['bindings'], dict))):
        raise ValueError('EQUITY_CHAIN_REQUEST_INVALID')
    return args


def _sequence_program(args: dict) -> dict:
    sequence = {'ruleIds': args['ruleIds']}
    if 'bindings' in args:
        sequence['bindings'] = args['bindings']
    return {'languageVersion': 2, 'function': SEQUENCE_RUN,
            'arguments': sequence}


def _validate_plan(chain: EquityRollforwardChain, preview: dict) -> dict:
    steps = preview['steps']
    if len(steps) != len(chain.periods):
        raise ValueError('EQUITY_CHAIN_PERIOD_RULE_COUNT_MISMATCH')
    if [step['resultKey'] for step in steps] != [
            period.result_key for period in chain.periods]:
        raise ValueError('EQUITY_CHAIN_PERIOD_RESULT_MISMATCH')
    external = {item['resultKey']: item for item in preview['externalInputs']}
    first = chain.periods[0].prior_close
    if (set(external) != {first.result_key}
            or external.get(first.result_key) != {
            'resultKey': first.result_key,
            'generationId': first.generation_id,
            'publishedRevision': first.published_revision}):
        raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_STALE')
    for index, period in enumerate(chain.periods):
        expected = period.prior_close.result_key
        if set(steps[index]['references']) != {expected}:
            raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_DEPENDENCY_MISSING')
        if index and expected != steps[index - 1]['resultKey']:
            raise ValueError('EQUITY_CHAIN_PRIOR_CLOSE_SEQUENCE_INVALID')
        if steps[index].get('boundProgram') != _period_program(chain, period):
            raise ValueError('EQUITY_CHAIN_PERIOD_RULE_MISMATCH')
    return {'chain': chain.normalized(),
            'atomicPeriods': [{'periodId': period.period_id,
              'resultKey': period.result_key,
              'dependsOnResultKey': period.prior_close.result_key,
              'checkpoint': index + 1}
             for index, period in enumerate(chain.periods)],
            'steps': steps, 'externalInputs': preview['externalInputs']}


def _period_program(chain: EquityRollforwardChain, period) -> dict:
    base = dict(period.movements[0].source.members)
    opening_overrides = {
      chain.hierarchy_dimension_id: chain.total_equity_member_id,
      'Period': period.prior_close.period_id}
    expression = {'op': 'PublishedAmount',
                  'resultKey': period.prior_close.result_key,
                  'memberOverrides': opening_overrides}
    for movement in period.movements:
        members = dict(movement.source.members)
        overrides = {axis: member for axis, member in members.items()
                     if base.get(axis) != member}
        term = ({'op': 'SourceAmount'} if not overrides else
          {'op': 'SourceValue', 'memberOverrides': overrides,
           'measureDimensionId': chain.hierarchy_dimension_id,
           'valueType': 'amount'})
        if movement.direction == -1:
            term = {'op': 'Multiply', 'left': term,
                    'right': {'op': 'RatioLiteral', 'decimal': '-1'}}
        expression = {'op': 'Add', 'left': expression, 'right': term}
    return {'languageVersion': 2, 'function': 'facts.expression.calculate',
      'arguments': {'sourceMembers': base, 'expression': expression,
        'targetMembers': {
          chain.hierarchy_dimension_id: chain.total_equity_member_id},
        'resultKey': period.result_key}}


class PostgresEquityRollforwardChain:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity
        self.preview_secret = preview_secret

    def _chain(self, scope: ApplicationScope, args: dict) -> EquityRollforwardChain:
        chain = EquityRollforwardChain.parse(args['definition'])
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=REQUEST)
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    capability_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                active = db.execute('''SELECT a.version FROM epm.hierarchy_active a
                    JOIN epm.hierarchy_version v ON v.workspace_id=a.workspace_id
                      AND v.application_id=a.application_id
                      AND v.dimension_id=a.dimension_id AND v.version=a.version
                    WHERE a.workspace_id=%s AND a.application_id=%s
                      AND a.dimension_id=%s AND v.sealed''',
                    (scope.workspace_id, scope.application_id,
                     chain.hierarchy_dimension_id)).fetchone()
                if state is None or active is None:
                    raise ValueError('EQUITY_CHAIN_CONTEXT_UNAVAILABLE')
                if (state['metadata_revision'] != chain.expected_metadata_revision
                        or state['policy_revision'] != chain.expected_policy_revision
                        or state['capability_revision'] !=
                            chain.expected_authorization_revision
                        or active['version'] != chain.hierarchy_version):
                    raise ValueError('EQUITY_CHAIN_REVISION_STALE')
                for period in chain.periods:
                    for movement in period.movements:
                        members = dict(movement.source.members)
                        PostgresSourceBatch._check_scope_members(
                            db, scope, members)
                        coordinate = Coordinate.from_mapping(members)
                        row = db.execute('''SELECT c.members,n.change_id
                            FROM epm.coordinate c JOIN epm.numeric_cell_current n
                              ON n.workspace_id=c.workspace_id
                             AND n.application_id=c.application_id
                             AND n.coordinate_id=c.coordinate_id
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.series_key=%s AND n.present''',
                            (scope.workspace_id, scope.application_id,
                             coordinate.series_key)).fetchone()
                        if row is None:
                            raise ValueError('EQUITY_CHAIN_MOVEMENT_MISSING')
                        if row['members'] != members:
                            raise ValueError('COORDINATE_HASH_COLLISION')
                        if row['change_id'] != movement.source.change_id:
                            raise ValueError('EQUITY_CHAIN_MOVEMENT_STALE')
        return chain

    def inspect(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _arguments(raw, INSPECT)
        chain = self._chain(scope, args)
        preview = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).preview(
                scope, _sequence_program(args),
                manifest_extension={'equityChain': chain.normalized()})
        return {**_validate_plan(chain, preview),
                'accountingPolicyStatus': 'Unreviewed',
                'effects': {'published': False,
                            'authoritativeFactsChanged': False}}

    def preview(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _arguments(raw, REQUEST)
        chain = self._chain(scope, args)
        result = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).preview(
                scope, _sequence_program(args),
                manifest_extension={'equityChain': chain.normalized()})
        plan = _validate_plan(chain, result)
        return {**result, 'function': REQUEST, 'chainPlan': plan,
                'accountingPolicyStatus': 'Unreviewed'}

    def submit(self, scope: ApplicationScope, raw: dict, *,
               preview_token: str, idempotency_key: str) -> dict:
        args = _arguments(raw, REQUEST)
        chain = self._chain(scope, args)
        return PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).submit(
                scope, _sequence_program(args), preview_token=preview_token,
                idempotency_key=idempotency_key,
                manifest_extension={'equityChain': chain.normalized()})

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _arguments(raw, READ)
        sequence_raw = {'languageVersion': 2, 'function': SEQUENCE_READ,
                        'arguments': {'sequenceId': args['sequenceId']}}
        sequence = PostgresExpressionSequence(
            self.dsn, identity=self.identity,
            preview_secret=self.preview_secret).read(scope, sequence_raw)
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
                if row is None or 'equityChain' not in row['manifest']:
                    raise ValueError('EQUITY_CHAIN_SEQUENCE_UNAVAILABLE')
                chain = EquityRollforwardChain.parse(
                    row['manifest']['equityChain'])
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    capability_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                active = db.execute('''SELECT version FROM epm.hierarchy_active
                    WHERE workspace_id=%s AND application_id=%s
                      AND dimension_id=%s''',
                    (scope.workspace_id, scope.application_id,
                     chain.hierarchy_dimension_id)).fetchone()
                movement_stale = []
                for period in chain.periods:
                    stale = False
                    for movement in period.movements:
                        coordinate = Coordinate.from_mapping(
                            dict(movement.source.members))
                        current_source = db.execute('''SELECT c.members,n.change_id
                            FROM epm.coordinate c JOIN epm.numeric_cell_current n
                              ON n.workspace_id=c.workspace_id
                             AND n.application_id=c.application_id
                             AND n.coordinate_id=c.coordinate_id
                            WHERE c.workspace_id=%s AND c.application_id=%s
                              AND c.series_key=%s AND n.present''',
                            (scope.workspace_id, scope.application_id,
                             coordinate.series_key)).fetchone()
                        if (current_source is None
                                or current_source['members'] !=
                                    dict(movement.source.members)
                                or current_source['change_id'] !=
                                    movement.source.change_id):
                            stale = True
                    movement_stale.append(stale)
                keys = sorted({period.result_key for period in chain.periods}
                              | {period.prior_close.result_key
                                 for period in chain.periods})
                publications = db.execute('''SELECT result_key,generation_id,
                    published_revision FROM epm.calculation_publication
                    WHERE workspace_id=%s AND application_id=%s
                      AND result_key=ANY(%s::text[])''',
                    (scope.workspace_id, scope.application_id, keys)).fetchall()
        current = {item['result_key']: item for item in publications}
        context_stale = (state is None or active is None
            or state['metadata_revision'] != chain.expected_metadata_revision
            or state['policy_revision'] != chain.expected_policy_revision
            or state['capability_revision'] !=
                chain.expected_authorization_revision
            or active['version'] != chain.hierarchy_version)
        checkpoints, upstream_stale = [], False
        for index, period in enumerate(chain.periods):
            job_id = (sequence['jobIds'][index]
                      if index < len(sequence['jobIds']) else None)
            pointer = current.get(period.result_key)
            prior_pointer = current.get(period.prior_close.result_key)
            expected_prior_generation = (period.prior_close.generation_id
                if index == 0 else sequence['jobIds'][index - 1]
                if index - 1 < len(sequence['jobIds']) else None)
            prior_stale = (expected_prior_generation is not None and (
                prior_pointer is None or prior_pointer['generation_id'] !=
                    expected_prior_generation))
            output_stale = job_id is not None and (pointer is None
                or pointer['generation_id'] != job_id)
            own_stale = (context_stale or movement_stale[index]
                         or prior_stale or output_stale)
            stale = upstream_stale or own_stale
            checkpoints.append({'periodId': period.period_id,
              'resultKey': period.result_key, 'checkpoint': index + 1,
              'jobId': job_id,
              'publishedRevision': (pointer['published_revision']
                                    if pointer else None),
              'status': ('Pending' if job_id is None else
                         'Stale' if stale else 'Published'),
              'stale': stale,
              'staleReason': ('UPSTREAM_PERIOD_STALE' if upstream_stale
                else 'CONTEXT_REVISION_STALE' if context_stale
                else 'CURRENT_PERIOD_SOURCE_STALE' if movement_stale[index]
                else 'PRIOR_CLOSE_REPUBLISHED' if prior_stale
                else 'OUTPUT_REPUBLISHED' if output_stale else None)})
            upstream_stale = stale
        return {**sequence, 'chain': chain.normalized(),
                'checkpoints': checkpoints,
                'stale': any(item['stale'] for item in checkpoints),
                'accountingPolicyStatus': 'Unreviewed',
                'effects': {'authoritativeFactsChanged': False}}
