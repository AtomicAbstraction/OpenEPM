"""Read aligned stored or published observations at one authorized cube revision."""
from decimal import Decimal, localcontext

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import require_state_token
from .dimensional_security_policy import AccessKind
from .metadata_read_contract import obj, read_contract, read_example
from .persistence_contract import AMOUNT_INTEGER_DIGITS, AMOUNT_SCALE, Coordinate
from .postgres_access import PostgresAccessChecker
from .postgres_calculation_scan import PostgresCalculationScan, _RESULT_KEY
from .postgres_connection import connect_postgres
from .postgres_cube_query import (
    MAX_FILTER_AXES, MAX_FILTER_ID_LENGTH, PostgresCubeQuery, _FILTER_ID, _filter_members)
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_resolved_cube_read import load_resolved_read_snapshot

FUNCTION = 'facts.cube.scenario.compare.read'
MAX_PAIRS = 100
SNAPSHOT_STALE = 'SCENARIO_COMPARISON_SNAPSHOT_STALE'
_RATIO_SCALE = 12
_RATIO_INTEGER_DIGITS = 8


def comparison_program_contract():
    identifier = {'type': 'string', 'minLength': 1, 'maxLength': MAX_FILTER_ID_LENGTH,
                  'pattern': '^' + _FILTER_ID.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
    revision = {'type': 'integer', 'minimum': 0}
    members = {'type': 'object', 'minProperties': 1, 'maxProperties': MAX_FILTER_AXES - 1,
               'propertyNames': identifier, 'additionalProperties': identifier}
    scenario = {'baselineMemberId': identifier, 'alternativeMemberId': identifier}
    amount_unit = {'oneOf': [
        {'const': 'amount'},
        obj({'type': {'const': 'Currency'}, 'dimensionId': identifier, 'memberId': identifier}),
    ]}
    ratio_unit = obj({'type': {'const': 'Ratio'}, 'scale': {'const': _RATIO_SCALE}})
    def calculation(unit):
        return obj({'resultKey': {'type': 'string',
            'pattern': '^' + _RESULT_KEY.pattern.removesuffix(r'\Z') + r'(?![\s\S])'},
            'resultStateToken': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'},
            'unit': unit})

    arguments = obj({**scenario, 'expectedMetadataRevision': revision,
        'coordinates': {'type': 'array', 'minItems': 1, 'maxItems': MAX_PAIRS,
                        'uniqueItems': True, 'items': members},
        'calculation': calculation({'oneOf': [amount_unit, ratio_unit]})},
        required=[*scenario, 'expectedMetadataRevision', 'coordinates'])

    def decimal(integer_digits, scale=AMOUNT_SCALE):
        return {'type': 'string', 'pattern': rf'^-?[0-9]{{1,{integer_digits}}}\.[0-9]{{{scale}}}(?![\s\S])'}

    raw_observation = {'oneOf': [obj({'kind': {'const': kind}, 'value': schema,
        'lastRevision': {'type': 'null'} if kind == 'missing' else revision})
        for kind, schema in (('numeric', decimal(AMOUNT_INTEGER_DIGITS)),
                             ('text', {'type': 'string'}), ('missing', {'type': 'null'}))]}
    def comparison(observation, statuses, difference):
        fields = obj({'members': members, 'baseline': observation, 'alternative': observation,
            'status': {'enum': statuses}, 'difference': {'anyOf': [difference, {'type': 'null'}]}})
        return {**fields, 'if': {'properties': {'status': {'const': 'numeric'}}},
                'then': {'properties': {'difference': difference}},
                'else': {'properties': {'difference': {'type': 'null'}}}}

    common = {**scenario, 'scenarioDimensionId': identifier,
        'complete': {'const': True},
        'snapshot': obj(dict.fromkeys(('metadataRevision', 'dataRevision', 'policyRevision',
                                      'commitRevision', 'securityRevision'), revision))}
    def results(items):
        return {'type': 'array', 'minItems': 1, 'maxItems': MAX_PAIRS, 'items': items}

    raw = obj({**common, 'layer': {'const': 'raw'}, 'comparisons': results(comparison(
        raw_observation, ['numeric', 'missing_input', 'different_types', 'text_equal', 'text_changed'],
        decimal(AMOUNT_INTEGER_DIGITS + 1)))})
    def calculated(unit, digits, scale):
        observation = {'oneOf': [
            obj({'kind': {'const': 'numeric'}, 'value': decimal(digits, scale)}),
            obj({'kind': {'const': 'missing'}, 'value': {'type': 'null'}}),
        ]}
        return obj({**common, 'layer': {'const': 'calculated'}, 'calculation': calculation(unit),
            'comparisons': results(comparison(observation, ['numeric', 'missing_input'],
                decimal(digits + 1, scale)))})

    result = {'oneOf': [raw, calculated(amount_unit, AMOUNT_INTEGER_DIGITS, AMOUNT_SCALE),
                         calculated(ratio_unit, _RATIO_INTEGER_DIGITS, _RATIO_SCALE)]}
    members_example = {'Account': 'Cost', 'Entity': 'Department', 'Year': 'Y2026',
                       'Period': 'M01', 'View': 'Point', 'Value': 'Native', 'DataType': 'Authored'}
    example = {'baselineMemberId': 'Baseline', 'alternativeMemberId': 'Alternative',
               'expectedMetadataRevision': 1, 'coordinates': [members_example]}
    contract = read_contract(FUNCTION, arguments, result, owner='PostgresCubeQuery', examples=[
        read_example(FUNCTION, example,
            name='Compare two stored scenarios at the same coordinate',
            binding='Replace the scenario member IDs and revision with current authorized values. '
                    'Supply one active member ID on every fact axis except the Scenario axis.'),
        read_example(FUNCTION, {**example, 'calculation': {'resultKey': 'capacity.current',
            'resultStateToken': '1' * 64, 'unit': {'type': 'Ratio', 'scale': _RATIO_SCALE}}},
            name='Compare a current published ratio across scenarios',
            binding='Use the current result key and state token and one output unit from the authorized calculation read. '
                    'Both scenarios use the same publication and the same selected unit.')],
        semantic_rules=[
            'Use two different current members on the application’s Scenario role axis. Each selected coordinate fixes all other fact axes, including the modeled time and unit context.',
            'The core requires READ for both coordinates of every pair, even if a value is missing. It returns a complete bounded set in request order at one current snapshot.',
            'For two stored numeric amounts, difference is alternative minus baseline as an exact decimal string. No conversion, aggregation, calculation, or promotion occurs.',
            'Missing, present zero and present empty text remain distinct. Difference is null for a missing value, different value types, or a pair of text values.',
            'Pass calculation to read the same current publication for both sides. The core refuses stale results and subtracts exact published values in the one requested unit. A coordinate without a value in that unit is missing.',
        ])
    contract['programContract']['recovery'] = (
        'Refresh application context after a stale snapshot or changed authorization. '
        'If the layout changed, rebuild the coordinates using the current fact axes before comparing again. '
        'Reread the current published result after its state changes. '
        'Rediscover current authorized members if the selected grain is unavailable.')
    return contract


def _compile(program):
    if (type(program) is not dict or set(program) != {'languageVersion', 'function', 'arguments'}
            or type(program['languageVersion']) is not int or program['languageVersion'] != 2
            or program['function'] != FUNCTION or type(program['arguments']) is not dict):
        raise ValueError('SCENARIO_COMPARISON_PROGRAM_INVALID')
    args = program['arguments']
    required = {'baselineMemberId', 'alternativeMemberId', 'expectedMetadataRevision', 'coordinates'}
    if (not required <= set(args) or set(args) - required - {'calculation'}
            or type(args['expectedMetadataRevision']) is not int or args['expectedMetadataRevision'] < 0
            or type(args['coordinates']) is not list or not 1 <= len(args['coordinates']) <= MAX_PAIRS):
        raise ValueError('SCENARIO_COMPARISON_ARGUMENTS_INVALID')
    scenarios = tuple(_filter_members({key: args[key]})[key]
                      for key in ('baselineMemberId', 'alternativeMemberId'))
    if scenarios[0] == scenarios[1]:
        raise ValueError('SCENARIO_COMPARISON_DISTINCT_MEMBERS_REQUIRED')
    coordinates = tuple(Coordinate.from_mapping(_filter_members(point)) for point in args['coordinates'])
    if any(len(point.members) >= MAX_FILTER_AXES for point in coordinates):
        raise ValueError('SCENARIO_COMPARISON_GRAIN_MISMATCH')
    if len(coordinates) != len(set(coordinates)):
        raise ValueError('SCENARIO_COMPARISON_DUPLICATE_COORDINATE')
    calculation = _calculation_reference(args['calculation']) if 'calculation' in args else None
    return scenarios, coordinates, args['expectedMetadataRevision'], calculation


def _calculation_reference(value):
    if (type(value) is not dict or set(value) != {'resultKey', 'resultStateToken', 'unit'}
            or not isinstance(value['resultKey'], str) or not _RESULT_KEY.fullmatch(value['resultKey'])):
        raise ValueError('SCENARIO_COMPARISON_CALCULATION_INVALID')
    require_state_token(value['resultStateToken'], error='SCENARIO_COMPARISON_CALCULATION_INVALID')
    unit = value['unit']
    if unit == 'amount' or (type(unit) is dict and unit == {'type': 'Ratio', 'scale': _RATIO_SCALE}
                             and type(unit['scale']) is int):
        return value
    if type(unit) is dict and set(unit) == {'type', 'dimensionId', 'memberId'} and unit['type'] == 'Currency':
        _filter_members({'dimension': unit['dimensionId'], 'member': unit['memberId']})
        return value
    raise ValueError('SCENARIO_COMPARISON_CALCULATION_INVALID')


def _observation(row):
    if row is None:
        return {'kind': 'missing', 'value': None, 'lastRevision': None}
    return {'kind': row['kind'], 'value': row['amount'] if row['kind'] == 'numeric' else row['text'],
            'lastRevision': row['lastRevision']}


def _compare(members, baseline, alternative):
    kinds = (baseline['kind'], alternative['kind'])
    difference = None
    if 'missing' in kinds:
        status = 'missing_input'
    elif kinds == ('numeric', 'numeric'):
        status = 'numeric'
        with localcontext(prec=AMOUNT_INTEGER_DIGITS + max(AMOUNT_SCALE, _RATIO_SCALE) + 1):
            difference = format(Decimal(alternative['value']) - Decimal(baseline['value']), 'f')
    elif kinds == ('text', 'text'):
        status = 'text_equal' if baseline['value'] == alternative['value'] else 'text_changed'
    else:
        status = 'different_types'
    return {'members': dict(members.members), 'baseline': baseline, 'alternative': alternative,
            'status': status, 'difference': difference}


def _read_calculated(db, scope, reader, access, calculation, requested):
    page = reader.scan_in_transaction(db, scope, result_key=calculation['resultKey'],
        expected_result_state_token=calculation['resultStateToken'], expected_access=access,
        limit=500, max_source_rows=500, series_keys=tuple(requested))
    if page['hasMore']:
        raise ValueError('RESOURCE_LIMIT')
    if not page['resultCurrentness']['matchesAtRead'] or not page['inputRevisionStatus']['matchesAtRead']:
        raise ValueError('CALCULATION_REQUIRED')
    observed = {}
    for row in page['rows']:
        key = row['seriesKey']
        if requested.get(key) != row['members']:
            raise ValueError('COORDINATE_HASH_COLLISION')
        unit = row.get('resultUnit', row.get('outputUnit', 'amount'))
        if unit != calculation['unit']:
            continue
        if key in observed:
            raise ValueError('SCENARIO_COMPARISON_AMBIGUOUS_RESULT')
        value = row['value']['decimal'] if 'value' in row else row['amount']
        observed[key] = {'kind': 'numeric', 'value': value}
    return observed


def read_comparison(dsn, identity, scope, program, *, cursor_secret):
    scenarios, coordinates, metadata_revision, calculation = _compile(program)
    key = (scope.workspace_id, scope.application_id)
    with connect_postgres(dsn, row_factory=dict_row) as db, db.transaction():
        db.execute('SET TRANSACTION READ ONLY')
        configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)
        access = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'read', function=FUNCTION)
        snapshot = load_resolved_read_snapshot(db, scope)
        if snapshot['metadataRevision'] != metadata_revision:
            raise ValueError('STALE_METADATA_REVISION')
        # Read the active grain with the state that selected it. A publication
        # after the opening snapshot must not turn valid intent into a grain error.
        layout = db.execute('''SELECT s.metadata_revision,s.commit_revision,
                   l.dimensions,l.role_dimensions->>'Scenario' AS scenario
            FROM epm.application_state s LEFT JOIN epm.coordinate_layout l
              USING (workspace_id,application_id,schema_epoch)
            WHERE s.workspace_id=%s AND s.application_id=%s''', key).fetchone()
        if (layout is None or layout['metadata_revision'] != snapshot['metadataRevision']
                or layout['commit_revision'] != snapshot['commitRevision']):
            raise ValueError(SNAPSHOT_STALE)
        if not layout['dimensions'] or layout['scenario'] not in layout['dimensions']:
            raise ValueError('SCENARIO_COMPARISON_GRAIN_UNAVAILABLE')
        axis = layout['scenario']
        grain = set(layout['dimensions']) - {axis}
        if any(set(dict(point.members)) != grain for point in coordinates):
            raise ValueError('SCENARIO_COMPARISON_GRAIN_MISMATCH')
        pairs = [tuple(Coordinate.from_mapping({**dict(point.members), axis: scenario})
                       for scenario in scenarios) for point in coordinates]
        points = tuple(point for pair in pairs for point in pair)
        authorize_coordinates(db, identity, scope, points, kind=AccessKind.READ,
                              expected_access=access)
        members = sorted({member for point in points for member in point.members})
        active = db.execute('''SELECT count(*) AS active FROM jsonb_to_recordset(%s::jsonb)
            AS requested(dimension_id text,member_id text)
            JOIN epm.member m USING (dimension_id,member_id)
            WHERE m.workspace_id=%s AND m.application_id=%s AND m.status='Active' ''',
            (Jsonb([{'dimension_id': dim, 'member_id': member} for dim, member in members]),
             *key)).fetchone()['active']
        if active != len(members):
            raise ValueError('SCENARIO_COMPARISON_MEMBER_UNAVAILABLE')
        requested = {point.series_key: dict(point.members) for point in points}
        if len(requested) != len(points):
            raise ValueError('COORDINATE_HASH_COLLISION')
        if calculation is None:
            revision = snapshot['commitRevision']
            rows = PostgresCubeQuery._page(db, scope, {}, '', revision, revision, False,
                                           len(points), series_keys=tuple(requested))
            if any(requested.get(row['seriesKey']) != row['members'] for row in rows):
                raise ValueError('COORDINATE_HASH_COLLISION')
            observed = {row['seriesKey']: _observation(row) for row in rows}
            missing = _observation(None)
            source = {'layer': 'raw'}
        else:
            reader = PostgresCalculationScan(dsn, identity=identity, cursor_secret=cursor_secret)
            observed = _read_calculated(db, scope, reader, access, calculation, requested)
            missing = {'kind': 'missing', 'value': None}
            source = {'layer': 'calculated', 'calculation': calculation}
        comparisons = [_compare(point, observed.get(baseline.series_key, missing),
                                observed.get(alternative.series_key, missing))
                       for point, (baseline, alternative) in zip(coordinates, pairs, strict=True)]
        current = PostgresAccessChecker.check_in_transaction(db, identity, scope, 'read', function=FUNCTION)
        if current != access:
            raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
        if load_resolved_read_snapshot(db, scope) != snapshot:
            raise ValueError(SNAPSHOT_STALE)
    return {'scenarioDimensionId': axis, 'baselineMemberId': scenarios[0], 'alternativeMemberId': scenarios[1],
            **source, 'complete': True,
            'snapshot': {key: value for key, value in snapshot.items()
                         if key not in ('impactEpoch', 'processedImpactEpoch')},
            'comparisons': comparisons}
