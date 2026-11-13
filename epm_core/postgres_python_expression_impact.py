"""Private scalar result publications using the canonical fixed SQL compiler.

Only bounded existing-fact sources are supported. Current calculation results
remain separate from raw facts; private results are never inserted into either
store.
"""
from decimal import Decimal,localcontext

import psycopg
from psycopg.types.json import Jsonb

from .dimensional_security_policy import AccessKind
from .persistence_contract import Coordinate
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_expression import (compile_expression_program, _sql,
    _dynamic_division_failure_sql, source_lookups, published_unit_lookups,
    validate_expression_metadata, validate_amount_unit_coordinates)
from .postgres_calculation_status import published_input_status
from .postgres_fact_batch import validate_coordinates
from .postgres_planning_write_guard import enforce_active_planning_policy

FUNCTION='facts.expression.calculate'
SUPPORTED_NODES = frozenset(('SourceAmount', 'SourceValue', 'AmountLiteral',
    'RatioLiteral', 'Add', 'Subtract', 'Multiply', 'Divide', 'Compare', 'If',
    'PublishedUnitAmount'))


def compile_private(operation):
    args=operation.get('arguments',{})
    if 'applicabilityDomain' in args:
        return compile_expression_program(
            operation, expected_target_state_token=None)
    if 'apportionmentDomain' in args:
        from .expression_apportionment import normalize_relation_program
        return normalize_relation_program(operation)
    if 'apportionment' in args:
        from .expression_apportionment import normalize_program
        return normalize_program(operation)
    def inspect(node):
        if not isinstance(node,dict):return
        op=node.get('op')
        if op in ('PublishedAmount','PublishedRatio'):
            raise ValueError('PYTHON_IMPACT_EXPRESSION_PUBLISHED_INPUT_UNSUPPORTED')
        if op == 'SourceTextPredicate':
            raise ValueError('PYTHON_IMPACT_EXPRESSION_RAW_LOOKUP_UNSUPPORTED')
        if op not in SUPPORTED_NODES:
            raise ValueError('PYTHON_IMPACT_EXPRESSION_PROFILE_UNSUPPORTED')
        for key in ('left','right','test','then','else'):
            if key in node:inspect(node[key])
    inspect(args.get('expression'))
    if set(args)-{'sourceMembers','sourceMemberSets','targetMembers','expression',
                  'resultKey','resultUnit','requiredSourceCount','amountUnit',
                  'reduceMemberSet'}:
        raise ValueError('PYTHON_IMPACT_EXPRESSION_PROFILE_UNSUPPORTED')
    plan=compile_expression_program(operation,expected_target_state_token=None)
    if (plan.reduce_member_set is not None
            and (plan.weight_expression is not None
                 or plan.reduce_member_set[3] not in (
                     ('SumAmount','CountPresent'),
                     ('AverageAmount','CountPresent')))):
        raise ValueError('PYTHON_IMPACT_EXPRESSION_PROFILE_UNSUPPORTED')
    return plan


def _evaluate_applicability(db,scope,operation,private,identity,role,*,unit):
    """Evaluate a pinned sparse business relation without persisting results."""
    from .postgres_expression import (
        _applicability_row_windows,
        _applicability_source_coordinates_for_rows,
        _applicability_target_coordinates_for_rows,
        _published_joins,
        _resolved_applicability_sql,
        _sql,
        enforce_expression_target_policy,
        source_count)
    plan=compile_expression_program(operation,expected_target_state_token=None)
    count=source_count(db,scope,plan,identity=identity)
    enforce_expression_target_policy(db,scope,plan,count,role)
    joins,join_params,aliases,_,_=_published_joins(plan)
    _,lowering=_resolved_applicability_sql(db,scope,plan)
    joins='\n'.join((joins,lowering.joins))
    join_params.extend(lowering.join_parameters)
    aliases.update(lowering.aliases)
    aliases.update({key:(lowering.aliases[key],params)
        for key,params in lowering.value_parameters.items()})
    expression_sql,expression_params=_sql(plan.expression,aliases)
    scale=12 if plan.result_unit==('Ratio',12) else 8
    value_type='RatioLiteral' if scale==12 else 'AmountLiteral'
    after={};observed=0
    for row_ids in _applicability_row_windows(db,scope,plan):
        sources=_applicability_source_coordinates_for_rows(
            db,scope,plan,row_ids)
        targets=_applicability_target_coordinates_for_rows(
            db,scope,plan,row_ids)
        authorize_coordinates(db,identity,scope,sources,kind=AccessKind.READ)
        authorize_coordinates(db,identity,scope,targets,kind=AccessKind.WRITE)
        rows=db.execute(f'''SELECT {lowering.target_members_sql} AS members,
                epm.round_half_even({expression_sql},{scale}) AS value
            FROM epm.coordinate c JOIN epm.numeric_cell_current n
              ON n.workspace_id=c.workspace_id
             AND n.application_id=c.application_id
             AND n.coordinate_id=c.coordinate_id
            {joins}
            WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
              AND ({lowering.required_predicate})
              AND applicability_row.row_id=ANY(%s::text[])
            ORDER BY applicability_row.row_id''',(
            *lowering.target_parameters,*expression_params,*join_params,
            scope.workspace_id,scope.application_id,list(row_ids))).fetchall()
        if len(rows)!=len(targets) or any(row['value'] is None for row in rows):
            raise ValueError('PYTHON_IMPACT_INPUT_SHAPE_INVALID')
        for row in rows:
            coordinate=Coordinate.from_mapping(row['members'])
            if coordinate.series_key in after:
                raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
            after[coordinate.series_key]={'members':dict(coordinate.members),
                'cell':{'present':True,
                    'amount':format(row['value'],f'.{scale}f'),
                    'valueType':value_type}}
        observed+=len(rows)
    if observed!=count:
        raise ValueError('CALCULATION_SOURCE_CHANGED')
    key=plan.result_key
    if key not in private.calculations:
        baseline,state_token=_baseline(private.snapshot_db or db,scope,key)
        private.calculations[key]={'original':baseline,'current':baseline,
            'stateToken':state_token,'units':[]}
    state=private.calculations[key]
    authorize_coordinates(db,identity,scope,
        [Coordinate.from_mapping(row['members'])
         for row in state['original'].values()],kind=AccessKind.READ)
    before=state['current'];state['current']=after;state['units'].append(unit)
    private.visits+=observed
    if private.visits>100_000:
        raise ValueError('PYTHON_IMPACT_VISIT_LIMIT')
    if len(private.original)+sum(len(item['original'].keys()
            | item['current'].keys()) for item in
            private.calculations.values())>10_000:
        raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
    return _rows(key,before,after,[unit],state['stateToken'])


def _baseline(db,scope,result_key):
    pointer=db.execute('''SELECT state_token,payload_kind
        FROM epm.calculation_result_state
        WHERE workspace_id=%s AND application_id=%s AND result_key=%s''',
        (scope.workspace_id,scope.application_id,result_key)).fetchone()
    if pointer is None:return {},None
    ids=(scope.workspace_id,scope.application_id,result_key)
    rows=db.execute('''SELECT c.series_key,c.members,r.amount::text AS amount,'AmountLiteral' AS value_type,NULL::jsonb AS output_unit
        FROM epm.calculation_result_current r JOIN epm.coordinate c USING(workspace_id,application_id,coordinate_id)
        WHERE r.workspace_id=%s AND r.application_id=%s AND r.result_key=%s
        UNION ALL
        SELECT c.series_key,c.members,r.ratio::text AS amount,'RatioLiteral' AS value_type,NULL::jsonb AS output_unit
        FROM epm.calculation_ratio_result_current r JOIN epm.coordinate c USING(workspace_id,application_id,coordinate_id)
        WHERE r.workspace_id=%s AND r.application_id=%s AND r.result_key=%s
        UNION ALL
        SELECT c.series_key,c.members,r.amount::text AS amount,'AmountLiteral' AS value_type,
            jsonb_build_object('dimensionId',r.output_unit_currency_dimension_id,
                              'memberId',r.output_unit_currency_member_id) AS output_unit
        FROM epm.calculation_unit_result_current r JOIN epm.coordinate c USING(workspace_id,application_id,coordinate_id)
        WHERE r.workspace_id=%s AND r.application_id=%s AND r.result_key=%s
        ORDER BY series_key LIMIT 10001''',(*ids,*ids,*ids)).fetchall()
    if len(rows)>10000:raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
    if len({row['series_key'] for row in rows})!=len(rows):
        raise ValueError('PYTHON_IMPACT_EXPRESSION_RESULT_TYPE_CONFLICT')
    return {row['series_key']:{'members':row['members'],'cell':{'present':True,
        'amount':row['amount'],'valueType':row['value_type'],
        **({'outputUnit':row['output_unit']} if row['output_unit'] is not None else {})}} for row in rows},pointer['state_token']


def _cell(row):
    return {'present':False,'amount':None} if row is None else row['cell']


def _rows(key,before,after,units,state_token):
    result=[]
    for series in sorted(before.keys()|after.keys()):
        left,right=_cell(before.get(series)),_cell(after.get(series))
        scale=12 if any(cell.get('valueType')=='RatioLiteral' for cell in (left,right)) else 8
        with localcontext() as context:
            context.prec=80
            delta=format(Decimal(right['amount'] or '0')-Decimal(left['amount'] or '0'),f'.{scale}f')
        if (left['present'] and right['present'] and
                (left.get('outputUnit') != right.get('outputUnit') or
                 left.get('valueType') != right.get('valueType'))):
            delta = None
        result.append({'storage':'calculation','resultKey':key,'seriesKey':series,
            'members':(after.get(series) or before[series])['members'],
            'beforeResultStateToken':state_token,'before':left,'after':right,
            'delta':delta,'units':list(units)})
    return result


def _lookup_inputs(db, scope, plan, sources, private, identity):
    """Bind canonical raw lookups to the same snapshot and prior private effects.

    The shared compiler defines lookup identity/types and SQL arithmetic. This
    adapter supplies bounded, currently authorized values, never another
    expression evaluator or a read from an uncommitted business store.
    """
    lookups = source_lookups(plan.expression)
    if not lookups or not sources:
        return lookups, [[] for _ in sources]
    coordinates = {}
    by_source = []
    for source in sources:
        keys = []
        for overrides in lookups:
            coordinate = Coordinate.from_mapping({**source['members'], **dict(overrides)})
            prior = coordinates.setdefault(coordinate.series_key, coordinate)
            if prior != coordinate:
                raise ValueError('COORDINATE_HASH_COLLISION')
            keys.append(coordinate.series_key)
        by_source.append(keys)
    declared = [{'ordinal': index, 'series_key': key, 'members': dict(coordinate.members)}
        for index, (key, coordinate) in enumerate(sorted(coordinates.items()), 1)]
    validate_coordinates(db, scope, declared)
    authorize_coordinates(db, identity, scope, list(coordinates.values()), kind=AccessKind.READ)
    values = private.numeric_inputs(db, scope, declared)
    if any(not value['present'] or value['text_present'] for value in values):
        raise ValueError('EXPRESSION_SOURCE_LOOKUP_CELL_MISSING')
    by_key = {value['series_key']: _amount_string(value['amount']) for value in values}
    private.visits += sum(len(keys) for keys in by_source)
    if private.visits > 100000:
        raise ValueError('PYTHON_IMPACT_VISIT_LIMIT')
    return lookups, [[by_key[key] for key in keys] for keys in by_source]


def _amount_string(value):
    return format(Decimal(value), '.8f')



def _raw_epoch(private):
    # Every private raw effect advances its real publication's data revision,
    # including a same-value write. Counting effects preserves that distinction.
    return sum(len(steps) for steps in private.steps.values())


def _private_version(private, key):
    return len(private.calculations.get(key, {}).get('units', ()))


def _current_private_dependencies(private, state):
    if (state.get('rawEpoch') != _raw_epoch(private) or any(
            _private_version(private, key) != version
            for key, version in state.get('dependencies', {}).items())):
        raise ValueError('STALE_PUBLISHED_INPUT')


def _external_dependency_versions(status, private):
    """Retain only bounded identities from the canonical currentness walk."""
    versions = {}
    def visit(value):
        if isinstance(value, dict):
            if 'resultKey' in value:
                key = value['resultKey']
                if _private_version(private, key):
                    raise ValueError('STALE_PUBLISHED_INPUT')
                versions[key] = 0
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(status)
    return versions


def _published_inputs(db, scope, plan, sources, private, identity):
    """Resolve typed operands from private generations or the exact snapshot.

    The compiler supplies lookup identity and arithmetic. This adapter performs
    current authorization, canonical persisted dependency checks and private
    generation checks before supplying any numeric values to that compiler.
    """
    lookups = published_unit_lookups(plan.expression)
    if not lookups:
        return (), [[] for _ in sources], None, {}
    if not sources:
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
    coordinates = {}
    requests = {}
    source_keys = []
    for source in sources:
        keys = []
        for key, overrides, currency in lookups:
            coordinate = Coordinate.from_mapping({**source['members'], **dict(overrides)})
            prior = coordinates.setdefault(coordinate.series_key, coordinate)
            if prior != coordinate:
                raise ValueError('COORDINATE_HASH_COLLISION')
            lookup = (key, coordinate.series_key, currency)
            requests[lookup] = coordinate
            keys.append(lookup)
        source_keys.append(keys)
    declared = [{'ordinal': index, 'series_key': coordinate.series_key,
        'members': dict(coordinate.members)}
        for index, coordinate in enumerate(coordinates.values(), 1)]
    validate_coordinates(db, scope, declared)
    authorize_coordinates(db, identity, scope, list(coordinates.values()), kind=AccessKind.READ)
    external = sorted({key for key, _, _ in requests if not _private_version(private, key)})
    snapshot = private.snapshot_db or db
    dependencies = {}
    cells = {}
    if external:
        if _raw_epoch(private):
            raise ValueError('STALE_PUBLISHED_INPUT')
        heads = snapshot.execute('''SELECT result_key,state_token FROM epm.calculation_result_state
            WHERE workspace_id=%s AND application_id=%s AND result_key=ANY(%s::text[])
            ORDER BY result_key''', (scope.workspace_id, scope.application_id, external)).fetchall()
        if [row['result_key'] for row in heads] != external:
            raise ValueError('EXPRESSION_PUBLISHED_INPUT_UNAVAILABLE')
        pins = [{'resultKey': row['result_key'], 'resultStateToken': row['state_token']} for row in heads]
        status = published_input_status(snapshot, scope, {'publishedInputs': pins})
        if status is None or not status['matchesAtRead']:
            raise ValueError('STALE_PUBLISHED_INPUT')
        dependencies.update(_external_dependency_versions(status, private))
        selected = [{'result_key': key, 'series_key': series, 'members': dict(coordinate.members),
                     'currency': currency} for (key, series, currency), coordinate in requests.items()
                    if key in external]
        rows = snapshot.execute('''SELECT input.result_key,input.series_key,input.currency,
            r.amount::text AS amount,r.output_unit_currency_dimension_id AS dimension_id
            FROM jsonb_to_recordset(%s::jsonb) input(
                result_key text,series_key text,members jsonb,currency text)
            JOIN epm.coordinate c ON c.workspace_id=%s AND c.application_id=%s
                AND c.series_key=input.series_key AND c.members=input.members
            JOIN epm.calculation_unit_result_current r USING(workspace_id,application_id,coordinate_id)
            WHERE r.result_key=input.result_key AND r.output_unit_currency_member_id=input.currency''',
            (Jsonb(selected), scope.workspace_id, scope.application_id)).fetchall()
        for row in rows:
            lookup = (row['result_key'], row['series_key'], row['currency'])
            if lookup in cells:
                raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
            cells[lookup] = {'present': True, 'amount': row['amount'],
                'outputUnit': {'dimensionId': row['dimension_id'], 'memberId': row['currency']}}
    output_unit = None
    for lookup, coordinate in requests.items():
        key, series, currency = lookup
        version = _private_version(private, key)
        if version:
            state = private.calculations[key]
            _current_private_dependencies(private, state)
            dependencies.update(state['dependencies'])
            dependencies[key] = version
            row = state['current'].get(series)
            if row is not None and row['members'] != dict(coordinate.members):
                raise ValueError('COORDINATE_HASH_COLLISION')
            cells[lookup] = _cell(row)
        cell = cells.get(lookup)
        if cell is None or not cell['present'] or cell.get('outputUnit', {}).get('memberId') != currency:
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_INPUT_UNAVAILABLE')
        if output_unit is None:
            output_unit = cell['outputUnit']
        elif output_unit != cell['outputUnit']:
            raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
    if plan.amount_unit and output_unit != {'dimensionId': plan.amount_unit[0], 'memberId': plan.amount_unit[1]}:
        raise ValueError('EXPRESSION_PUBLISHED_UNIT_MIXED_OR_MISSING')
    private.visits += len(sources) * len(lookups)
    if private.visits > 100000:
        raise ValueError('PYTHON_IMPACT_VISIT_LIMIT')
    return lookups, [[cells[key]['amount'] for key in keys] for keys in source_keys], output_unit, dependencies

def evaluate(db,scope,operation,private,identity,role,*,unit):
    if 'applicabilityDomain' in operation.get('arguments', {}):
        return _evaluate_applicability(
            db,scope,operation,private,identity,role,unit=unit)
    if 'apportionmentDomain' in operation.get('arguments', {}):
        from .postgres_expression_apportionment import evaluate_relation_private
        return evaluate_relation_private(db,scope,operation,private,identity,
                                         role,unit=unit)
    if 'apportionment' in operation.get('arguments', {}):
        from .postgres_expression_apportionment import evaluate_private
        return evaluate_private(db,scope,operation,private,identity,role,unit=unit)
    plan=compile_private(operation)
    selectors={axis:[member] for axis,member in plan.source_members}
    selectors.update({axis:list(members) for axis,members in plan.source_member_sets})
    if plan.reduce_member_set:
        selectors[plan.reduce_member_set[0]]=list(plan.reduce_member_set[1])
    validate_expression_metadata(db,scope,plan)
    selected=private.select_existing_facts(db,scope,member_sets=selectors,
        snapshot_revision=private.snapshot_revision,limit=10001)
    if len(selected)>10000:raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
    sources=[row for row in selected if row['kind']=='numeric' and row['present']]
    if len(sources)>500:raise ValueError('CALCULATION_RESULT_LIMIT')
    if plan.required_source_count is not None and len(sources)!=plan.required_source_count:
        raise ValueError('EXPRESSION_REQUIRED_SOURCE_COUNT_MISMATCH')
    coordinates=[Coordinate.from_mapping(row['members']) for row in sources]
    if plan.reduce_member_set:
        reduction_axis,_,reduction_target,_=plan.reduce_member_set
        targets=[Coordinate.from_mapping({**row['members'],
            reduction_axis:reduction_target}) for row in sources]
    else:
        targets=[Coordinate.from_mapping({**row['members'],
            **dict(plan.target_members)}) for row in sources]
        if len(set(targets))!=len(targets):
            raise ValueError('EXPRESSION_TARGET_COORDINATE_COLLISION')
    distinct_targets=tuple(dict.fromkeys(targets))
    validate_coordinates(db,scope,[{'ordinal':i,'series_key':coordinate.series_key,
        'members':dict(coordinate.members)} for i,coordinate in enumerate(
            (*coordinates,*distinct_targets),1)])
    authorize_coordinates(db,identity,scope,coordinates,kind=AccessKind.READ)
    authorize_coordinates(db,identity,scope,distinct_targets,kind=AccessKind.WRITE)
    enforce_active_planning_policy(db,scope,writes=tuple(
        (target,'Set') for target in distinct_targets),workflow_role=role)
    validate_amount_unit_coordinates(db, scope, plan, [row['members'] for row in sources])
    published, published_values, output_unit, dependencies = _published_inputs(
        db, scope, plan, sources, private, identity)
    if plan.amount_unit:
        output_unit = {'dimensionId': plan.amount_unit[0], 'memberId': plan.amount_unit[1]}
    lookups, lookup_values = _lookup_inputs(db, scope, plan, sources, private, identity)
    key=plan.result_key
    if key not in private.calculations:
        baseline,state_token=_baseline(private.snapshot_db or db,scope,key)
        private.calculations[key]={'original':baseline,'current':baseline,
            'stateToken':state_token,'units':[]}
    state=private.calculations[key]
    # Replacing a result generation also removes its old output rows. Their
    # before-values require current read permission before they can be exposed.
    authorize_coordinates(db,identity,scope,
        [Coordinate.from_mapping(row['members']) for row in state['original'].values()],kind=AccessKind.READ)
    before=state['current']
    aliases = {('raw', overrides): f'lookup_{index}' for index, overrides in enumerate(lookups)}
    joins = '\n'.join(f'CROSS JOIN LATERAL (SELECT (i.lookups->>{index})::numeric AS amount) lookup_{index}'
                      for index in range(len(lookups)))
    aliases.update({('published_unit', *lookup): f'published_{index}'
                    for index, lookup in enumerate(published)})
    joins += '\n' + '\n'.join(
        f'CROSS JOIN LATERAL (SELECT (i.published->>{index})::numeric AS amount) published_{index}'
        for index in range(len(published)))
    expression,parameters=_sql(plan.expression,aliases,source_sql='i.amount')
    failure,failure_parameters=_dynamic_division_failure_sql(plan.expression,aliases,source_sql='i.amount')
    scale=12 if plan.result_unit==('Ratio',12) else 8
    numeric_type='numeric(20,12)' if scale==12 else 'numeric(28,8)'
    payload=[{'ordinal':i,'amount':row['amount'],'lookups':lookup_values[i],
              'published':published_values[i],
              'targetKey':targets[i].series_key,
              'targetMembers':dict(targets[i].members)}
             for i,row in enumerate(sources)]
    try:
        if plan.reduce_member_set:
            average=plan.reduce_member_set[3]==(
                'AverageAmount','CountPresent')
            aggregate=(f'sum({expression})/count(*)' if average
                       else f'sum({expression})')
            values=db.execute(f'''WITH input AS (SELECT * FROM
                jsonb_to_recordset(%s::jsonb) i(ordinal integer,
                amount numeric,lookups jsonb,published jsonb,
                target_key text,target_members jsonb))
                SELECT i.target_key,i.target_members,
                 bool_or(({failure})) AS invalid,
                 epm.round_half_even({aggregate},{scale})::{numeric_type}
                   AS value,count(*) AS count_present
                FROM input i {joins}
                GROUP BY i.target_key,i.target_members
                ORDER BY i.target_key''',(
                    Jsonb(payload),*failure_parameters,*parameters)).fetchall()
        else:
            values=db.execute(f'''WITH input AS (SELECT * FROM
                jsonb_to_recordset(%s::jsonb) i(ordinal integer,
                amount numeric,lookups jsonb,published jsonb,
                target_key text,target_members jsonb))
                SELECT i.ordinal,({failure}) AS invalid,
                 epm.round_half_even({expression},{scale})::{numeric_type}
                   AS value
                FROM input i {joins} ORDER BY i.ordinal''',(
                    Jsonb(payload),*failure_parameters,*parameters)).fetchall()
    except psycopg.errors.NumericValueOutOfRange as error:
        raise ValueError('EXPRESSION_RATIO_RESULT_OUT_OF_RANGE' if scale==12 else 'EXPRESSION_RESULT_OUT_OF_RANGE') from error
    if any(row['invalid'] or row['value'] is None for row in values):
        raise ValueError('EXPRESSION_DIVISOR_ZERO_OR_MISSING')
    expected_count=(len(distinct_targets) if plan.reduce_member_set
                    else len(sources))
    if len(values)!=expected_count:
        raise ValueError('PYTHON_IMPACT_INPUT_SHAPE_INVALID')
    if plan.reduce_member_set:
        after={row['target_key']:{'members':row['target_members'],'cell':{
            'present':True,'amount':format(row['value'],f'.{scale}f'),
            'valueType':'RatioLiteral' if scale==12 else 'AmountLiteral',
            'countPresent':row['count_present'],
            **({'outputUnit':dict(output_unit)}
               if output_unit is not None else {})}} for row in values}
    else:
        after={target.series_key:{'members':dict(target.members),'cell':{
            'present':True,'amount':format(row['value'],f'.{scale}f'),
            'valueType':'RatioLiteral' if scale==12 else 'AmountLiteral',
            **({'outputUnit':dict(output_unit)}
               if output_unit is not None else {})}}
            for target,row in zip(targets,values,strict=True)}
    private.visits+=len(sources)
    if private.visits>100000:raise ValueError('PYTHON_IMPACT_VISIT_LIMIT')
    state['current']=after;state['units'].append(unit)
    state['rawEpoch'] = _raw_epoch(private)
    state['dependencies'] = dependencies
    if len(private.original)+sum(len(item['original'].keys()|item['current'].keys())
            for item in private.calculations.values())>10000:
        raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
    return _rows(key,before,after,[unit],state['stateToken'])


def final_rows(private):
    return [row for key,state in sorted(private.calculations.items())
            for row in _rows(key,state['original'],state['current'],state['units'],state['stateToken'])]
