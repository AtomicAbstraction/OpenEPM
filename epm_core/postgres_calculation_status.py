"""Conservative read-time revision and published-dependency status."""
from __future__ import annotations

from psycopg.types.json import Jsonb
from .postgres_consolidation_stages import TRANSLATED_STAGES, ACQUISITION_LOCAL_STAGES


def input_revision_status(row: dict) -> dict:
    expected = {name: row[f'expected_{name}_revision']
                for name in ('metadata', 'data', 'policy')}
    current = {name: row[f'current_{name}_revision']
               for name in ('metadata', 'data', 'policy')}
    return {'matchesAtRead': expected == current,
            'expected': expected, 'observed': current,
            'observedCommitRevision': row['observed_commit_revision']}


def typed_expression_raw_driver_status(db, scope, generation_id: str,
                                       program: dict) -> dict | None:
    """Recheck every v29 row's exact present raw driver.

    The v29 publisher stores one RawDriver lineage object per output row.
    Present zero is valid. A clear, replacement change ID, amount change,
    malformed/missing lineage, or additional driver object makes the result
    stale. Published operands are checked separately by
    :func:`published_input_status`.
    """
    if (not isinstance(program,dict) or 'amountUnit' not in program):
        return None
    source_members=program.get('sourceMembers')
    if (not isinstance(source_members,dict)
            or any(not isinstance(axis,str) or not isinstance(member,str)
                   for axis,member in source_members.items())):
        return {'matchesAtRead':False,'truncated':True,
                'requiredSourceCount':program.get('requiredSourceCount'),
                'storedRowCount':0,'currentDriverCount':0,'drivers':[]}
    stored=db.execute('''SELECT r.coordinate_id,r.source_amount,
        r.source_change_id,driver.driver_count,driver.item
        FROM epm.calculation_unit_result r
        LEFT JOIN LATERAL (SELECT count(*) AS driver_count,
          min(value::text)::jsonb AS item
          FROM jsonb_array_elements(r.source_lookup_lineage) value
          WHERE value->>'inputKind'='RawDriver') driver ON true
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.generation_id=%s ORDER BY r.coordinate_id LIMIT 501''',(
        scope.workspace_id,scope.application_id,generation_id)).fetchall()
    current=db.execute('''SELECT c.coordinate_id,c.series_key,c.members,
        n.amount,n.change_id FROM epm.coordinate c
        JOIN epm.numeric_cell_current n USING(
          workspace_id,application_id,coordinate_id)
        WHERE c.workspace_id=%s AND c.application_id=%s AND n.present
          AND c.members @> %s::jsonb
        ORDER BY c.series_key LIMIT 501''',(
        scope.workspace_id,scope.application_id,Jsonb(source_members)
        )).fetchall()
    required=program.get('requiredSourceCount')
    malformed=False;stored_by_series={}
    expected_fields={'inputKind','sourcePresent','sourceCoordinateId','sourceMembers',
        'sourceSeriesKey','sourceAmount','sourceChangeId'}
    for row in stored:
        item=row['item'] if isinstance(row['item'],dict) else {}
        valid=(row['driver_count']==1 and set(item)==expected_fields
            and item.get('sourcePresent') is True
            and row['source_change_id']==item.get('sourceChangeId')
            and format(row['source_amount'],'.8f')==item.get('sourceAmount'))
        series=item.get('sourceSeriesKey')
        if (not valid or not isinstance(series,str) or series in stored_by_series
                or not isinstance(item.get('sourceMembers'),dict)):
            malformed=True
        else:
            stored_by_series[series]=(row,item)
    current_by_series={};current_duplicate=False
    for row in current:
        series=row['series_key']
        if series in current_by_series:current_duplicate=True
        current_by_series[series]=row
    matches=[]
    for series in sorted(set(stored_by_series)|set(current_by_series)):
        stored_pair=stored_by_series.get(series);observed=current_by_series.get(series)
        stored_row,item=(stored_pair if stored_pair is not None else (None,{}))
        valid=(stored_row is not None and observed is not None
            and item.get('sourceCoordinateId')==observed['coordinate_id']
            and item.get('sourceMembers')==observed['members']
            and item.get('sourceChangeId')==observed['change_id']
            and item.get('sourceAmount')==format(observed['amount'],'.8f'))
        matches.append({'sourceSeriesKey':series,
            'storedCoordinateId':item.get('sourceCoordinateId'),
            'currentCoordinateId':(observed['coordinate_id']
                                   if observed is not None else None),
            'sourceChangeId':item.get('sourceChangeId'),
            'observedChangeId':(observed['change_id']
                                if observed is not None else None),
            'sourcePresent':item.get('sourcePresent'),
            'observedPresent':observed is not None,
            'matchesAtRead':valid})
    truncated=len(stored)>500 or len(current)>500
    count_valid=(required is None or (len(stored)==required
                                      and len(current)==required))
    return {'matchesAtRead':not truncated and not malformed
            and not current_duplicate and count_valid
            and len(stored_by_series)==len(stored)
            and len(current_by_series)==len(current)
            and set(stored_by_series)==set(current_by_series)
            and all(item['matchesAtRead'] for item in matches),
            'truncated':truncated,'requiredSourceCount':required,
            'storedRowCount':len(stored),'currentDriverCount':len(current),
            'drivers':matches}


def expression_context_dependency_status(db,scope,program:dict,*,
        _budget:list[int]|None=None)->dict|None:
    dependencies=(program.get('contextDependencies')
                  if isinstance(program,dict) else None)
    if dependencies is None:
        return None
    try:
        from .expression_context_dependencies import normalize_sealed,status
        sealed=normalize_sealed(dependencies)
    except (TypeError,ValueError):
        return {'matchesAtRead':False,'truncated':False,'dependencies':[]}
    return status(db,scope,sealed,budget=_budget)


def published_translation_status(db, scope, program: dict, *,
                                 _path: frozenset[tuple[str,str]] | None = None,
                                 _budget: list[int] | None = None) -> dict:
    """Recheck direct FX/Full pins and nested translated Full generations."""
    path=_path if _path is not None else frozenset()
    budget=_budget if _budget is not None else [1000]
    if not isinstance(program,dict):
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    decisions = program.get('decisions', [])
    if (not isinstance(decisions, list) or not 1 <= len(decisions) <= 200
            or any(not isinstance(item, dict) or not {
                'relationshipId','resultKey','generationId',
                'publishedRevision'} <= set(item) for item in decisions)):
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    parent=program.get('parentTranslation')
    if parent is not None and (not isinstance(parent,dict) or not {
            'resultKey','generationId','publishedRevision'} <= set(parent)):
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    requested=[{'relationship_id':item['relationshipId'],
        'result_key':item['resultKey'],
        'generation_id':item['generationId'],
        'published_revision':item['publishedRevision']}
        for item in decisions]
    if parent is not None:
        requested.append({'relationship_id':'__parent__',
            'result_key':parent['resultKey'],
            'generation_id':parent['generationId'],
            'published_revision':parent['publishedRevision']})
    if len(requested)>budget[0]:
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    budget[0]-=len(requested)
    rows=db.execute('''SELECT input.relationship_id,input.result_key,
        input.generation_id,input.published_revision,
        p.generation_id AS observed_generation_id,
        p.published_revision AS observed_published_revision,
        g.function_name,j.status AS job_status,j.normalized_program,
        j.expected_metadata_revision,j.expected_data_revision,
        j.expected_policy_revision,
        s.metadata_revision AS current_metadata_revision,
        s.data_revision AS current_data_revision,
        s.policy_revision AS current_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
            relationship_id text,result_key text,generation_id text,
            published_revision bigint)
        LEFT JOIN epm.calculation_publication p
          ON p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=input.result_key
        LEFT JOIN epm.calculation_generation g
          ON g.workspace_id=%s AND g.application_id=%s
          AND g.generation_id=input.generation_id
          AND g.result_key=input.result_key
        LEFT JOIN epm.job j ON j.workspace_id=g.workspace_id
          AND j.application_id=g.application_id AND j.job_id=g.job_id
        JOIN epm.application_state s ON s.workspace_id=%s
          AND s.application_id=%s
        ORDER BY input.relationship_id''',
        (Jsonb(requested),
         scope.workspace_id,scope.application_id,
         scope.workspace_id,scope.application_id,
         scope.workspace_id,scope.application_id)).fetchall()
    dependencies=[]
    truncated=False
    for row in rows:
        identity=(row['result_key'],row['generation_id'])
        matches=(row['generation_id']==row['observed_generation_id']
            and row['published_revision']==
                row['observed_published_revision']
            and row['function_name'] in (
                'currency.translation.publish',
                'currency.calculation.translation.publish',
                'consolidation.full.translated.aggregate')
            and row['job_status']=='published'
            and identity not in path
            and all(row['expected_'+kind+'_revision']==
                    row['current_'+kind+'_revision']
                    for kind in ('metadata','data','policy')))
        if row['relationship_id']=='__parent__' and row[
                'function_name']!='currency.translation.publish':
            matches=False
        nested=None
        if matches and row['function_name']==(
                'consolidation.full.translated.aggregate'):
            nested=published_translation_status(db,scope,
                row['normalized_program'],_path=path|{identity},
                _budget=budget)
            if not nested['matchesAtRead']:
                matches=False
            if nested['truncated']:
                truncated=True
        if matches and row['function_name']==(
                'currency.calculation.translation.publish'):
            nested=published_calculation_translation_status(db,scope,
                row['normalized_program'],_path=path|{identity},
                _budget=budget)
            if not nested['matchesAtRead']:
                matches=False
            if nested['truncated']:
                truncated=True
        dependency={'relationshipId':(
                None if row['relationship_id']=='__parent__' else
                row['relationship_id']),
            'parentSource':row['relationship_id']=='__parent__',
            'resultKey':row['result_key'],
            'generationId':row['generation_id'],
            'publishedRevision':row['published_revision'],
            'observedGenerationId':row['observed_generation_id'],
            'observedPublishedRevision':row['observed_published_revision'],
            'matchesAtRead':matches}
        if nested is not None:
            dependency['nested']=nested
        dependencies.append(dependency)
    return {'matchesAtRead':len(rows)==len(requested) and all(
        item['matchesAtRead'] for item in dependencies),
        'truncated':truncated,'dependencies':dependencies}


def published_calculation_translation_status(db,scope,program:dict,*,
        _path:frozenset[tuple[str,str]]|None=None,
        _budget:list[int]|None=None) -> dict:
    """Boundedly follow the period-specific lower Full pins of an FX bridge."""
    path=_path if _path is not None else frozenset()
    budget=_budget if _budget is not None else [1000]
    source_layer=(program.get('sourceLayer','translated_full')
                  if isinstance(program,dict) else None)
    source_basis=(program.get('sourceBasis',
        'translated_full' if source_layer=='translated_full' else
        'local_full') if isinstance(program,dict) else None)
    expected_function=(
        'consolidation.full.translated.aggregate'
        if source_basis=='translated_full' and isinstance(source_layer,str)
            and source_layer in TRANSLATED_STAGES else
        'consolidation.full.aggregate'
        if source_basis=='local_full' and isinstance(source_layer,str)
            and source_layer in {'raw_plus_ic_elimination',
                'raw_plus_manual_journal_plus_ic_elimination',
                *ACQUISITION_LOCAL_STAGES}
        else None)
    pins=program.get('periodPins',[]) if isinstance(program,dict) else []
    if (expected_function is None
            or not isinstance(pins,list) or not 1<=len(pins)<=120
            or len(pins)>budget[0]
            or any(not isinstance(pin,dict) or not {
                'periodId','resultKey','generationId',
                'publishedRevision'}<=set(pin) for pin in pins)):
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    budget[0]-=len(pins)
    rows=db.execute('''SELECT input.period_id,input.result_key,
        input.generation_id,input.published_revision,
        p.generation_id AS observed_generation_id,
        p.published_revision AS observed_published_revision,
        g.function_name,j.status AS job_status,j.normalized_program,
        j.expected_metadata_revision,j.expected_data_revision,
        j.expected_policy_revision,
        s.metadata_revision AS current_metadata_revision,
        s.data_revision AS current_data_revision,
        s.policy_revision AS current_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
          period_id text,result_key text,generation_id text,
          published_revision bigint)
        LEFT JOIN epm.calculation_publication p ON
          p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=input.result_key
        LEFT JOIN epm.calculation_generation g ON
          g.workspace_id=%s AND g.application_id=%s
          AND g.generation_id=input.generation_id
          AND g.result_key=input.result_key
        LEFT JOIN epm.job j ON j.workspace_id=g.workspace_id
          AND j.application_id=g.application_id AND j.job_id=g.job_id
        JOIN epm.application_state s ON s.workspace_id=%s
          AND s.application_id=%s ORDER BY input.period_id''',
        (Jsonb([{'period_id':pin['periodId'],
            'result_key':pin['resultKey'],
            'generation_id':pin['generationId'],
            'published_revision':pin['publishedRevision']}
            for pin in pins]),scope.workspace_id,scope.application_id,
         scope.workspace_id,scope.application_id,
         scope.workspace_id,scope.application_id)).fetchall()
    dependencies=[]
    truncated=False
    for row in rows:
        identity=(row['result_key'],row['generation_id'])
        matches=(row['generation_id']==row['observed_generation_id']
            and row['published_revision']==
                row['observed_published_revision']
            and row['function_name']==expected_function
            and row['job_status']=='published'
            and identity not in path
            and all(row['expected_'+kind+'_revision']==
                    row['current_'+kind+'_revision']
                    for kind in ('metadata','data','policy')))
        nested=None
        if matches and source_basis=='translated_full':
            nested=published_translation_status(db,scope,
                row['normalized_program'],_path=path|{identity},
                _budget=budget)
            matches=nested['matchesAtRead']
            truncated|=nested['truncated']
        elif matches:
            nested=published_child_status(db,scope,
                row['normalized_program'])
            if nested is not None:
                matches=nested['matchesAtRead']
                truncated|=nested['truncated']
        dependency={'periodId':row['period_id'],
            'resultKey':row['result_key'],
            'generationId':row['generation_id'],
            'publishedRevision':row['published_revision'],
            'observedGenerationId':row['observed_generation_id'],
            'observedPublishedRevision':row['observed_published_revision'],
            'matchesAtRead':matches}
        if nested is not None:
            dependency['nested']=nested
        dependencies.append(dependency)
    return {'matchesAtRead':len(rows)==len(pins) and not truncated
        and all(item['matchesAtRead'] for item in dependencies),
        'truncated':truncated,'dependencies':dependencies}


def published_child_status(db, scope, program: dict) -> dict | None:
    """Check a Full result's pinned child tree in bounded, per-level queries.

    A parent pointer can remain unchanged when a grandchild is republished.
    Following immutable child programs prevents that from appearing current.
    Publishers hold the application-state lock while calling this; a read is
    a conservative observation, not an accounting certificate.
    """
    pinned = program.get('publishedChildren', [])
    if not pinned:
        return None
    dependencies = []
    frontier = [(None, item) for item in pinned]
    seen = set()
    truncated = False
    for depth in range(32):
        if not frontier:
            break
        if len(dependencies) + len(frontier) > 1000:
            truncated = True
            break
        for _, item in frontier:
            identity = (item['resultKey'], item['generationId'])
            if identity in seen:
                truncated = True
                break
            seen.add(identity)
        if truncated:
            break
        rows = db.execute('''SELECT input.ordinal,input.relationship_id,
            input.result_key,input.generation_id,input.published_revision,
            p.generation_id AS observed_generation_id,
            p.published_revision AS observed_published_revision,
            g.function_name,j.status AS job_status,j.normalized_program,
            j.expected_metadata_revision,j.expected_data_revision,
            j.expected_policy_revision,
            s.metadata_revision AS current_metadata_revision,
            s.data_revision AS current_data_revision,
            s.policy_revision AS current_policy_revision
            FROM jsonb_to_recordset(%s::jsonb) AS input(
                ordinal int,relationship_id text,result_key text,
                generation_id text,published_revision bigint)
            LEFT JOIN epm.calculation_publication p
              ON p.workspace_id=%s AND p.application_id=%s
             AND p.result_key=input.result_key
            LEFT JOIN epm.calculation_generation g
              ON g.workspace_id=%s AND g.application_id=%s
             AND g.generation_id=input.generation_id
             AND g.result_key=input.result_key
            LEFT JOIN epm.job j
              ON j.workspace_id=g.workspace_id
             AND j.application_id=g.application_id AND j.job_id=g.job_id
            JOIN epm.application_state s ON s.workspace_id=%s
              AND s.application_id=%s
            ORDER BY input.ordinal''',
            (Jsonb([{'ordinal': ordinal,
                     'relationship_id': item['relationshipId'],
                     'result_key': item['resultKey'],
                     'generation_id': item['generationId'],
                     'published_revision': item['publishedRevision']}
                    for ordinal, (_, item) in enumerate(frontier)]),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        next_frontier = []
        for row in rows:
            parent_key, _ = frontier[row['ordinal']]
            child_program = row['normalized_program']
            valid = (row['generation_id'] ==
                     row['observed_generation_id'] and
                     row['published_revision'] ==
                     row['observed_published_revision'] and
                     row['function_name'] == 'consolidation.full.aggregate'
                     and row['job_status'] == 'published' and
                     all(row[f'expected_{kind}_revision'] ==
                         row[f'current_{kind}_revision']
                         for kind in ('metadata','data','policy')) and
                     isinstance(child_program, dict) and
                     isinstance(child_program.get('publishedChildren', []),
                                list))
            dependencies.append({
                'depth': depth + 1,
                'parentResultKey': parent_key,
                'relationshipId': row['relationship_id'],
                'resultKey': row['result_key'],
                'generationId': row['generation_id'],
                'publishedRevision': row['published_revision'],
                'observedGenerationId': row['observed_generation_id'],
                'observedPublishedRevision':
                    row['observed_published_revision'],
                'matchesAtRead': valid})
            if valid:
                for nested in child_program.get('publishedChildren', []):
                    if not isinstance(nested, dict) or set(nested) != {
                            'relationshipId', 'resultKey', 'generationId',
                            'publishedRevision'}:
                        truncated = True
                        break
                    next_frontier.append((row['result_key'], nested))
        if truncated:
            break
        frontier = next_frontier
    else:
        truncated = bool(frontier)
    return {'matchesAtRead': not truncated and all(
                item['matchesAtRead'] for item in dependencies),
            'truncated': truncated, 'dependencies': dependencies}


def published_input_status(db, scope, program: dict, *,
                           _path: frozenset[tuple[str, str]] | None = None,
                           _budget: list[int] | None = None,
                           allow_newer_data: bool = False) -> dict | None:
    """Check an expression's pinned generations and their dependency graph.

    The graph is immutable and publication always points to older generations.
    A shared budget bounds traversal even if stored job data is malformed.
    """
    pinned = program.get('publishedInputs', [])
    if not pinned:
        return None
    path = _path if _path is not None else frozenset()
    budget = _budget if _budget is not None else [1000]
    if len(pinned) > budget[0]:
        return {'matchesAtRead': False, 'truncated': True,
                'dependencies': []}
    budget[0] -= len(pinned)
    rows = db.execute('''SELECT input.result_key,input.generation_id,
        input.published_revision,
        p.generation_id AS observed_generation_id,
        p.published_revision AS observed_published_revision,
        g.function_name,j.status AS job_status,j.normalized_program,
        j.compiler_version,
        j.expected_metadata_revision,j.expected_data_revision,
        j.expected_policy_revision,
        s.metadata_revision AS current_metadata_revision,
        s.data_revision AS current_data_revision,
        s.policy_revision AS current_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
            result_key text,generation_id text,published_revision bigint)
        LEFT JOIN epm.calculation_publication p
          ON p.workspace_id=%s AND p.application_id=%s
         AND p.result_key=input.result_key
        LEFT JOIN epm.calculation_generation g
          ON g.workspace_id=%s AND g.application_id=%s
         AND g.generation_id=input.generation_id
         AND g.result_key=input.result_key
        LEFT JOIN epm.job j
          ON j.workspace_id=g.workspace_id
         AND j.application_id=g.application_id AND j.job_id=g.job_id
        JOIN epm.application_state s
          ON s.workspace_id=%s AND s.application_id=%s
        ORDER BY input.result_key''',
        (Jsonb([{'result_key': item['resultKey'],
                 'generation_id': item['generationId'],
                 'published_revision': item['publishedRevision']}
                for item in pinned]),
         scope.workspace_id, scope.application_id,
         scope.workspace_id, scope.application_id,
         scope.workspace_id, scope.application_id)).fetchall()
    if len(rows) != len(pinned):
        return {'matchesAtRead': False, 'truncated': False,
                'dependencies': []}
    dependencies = []
    truncated = False
    for row in rows:
        identity = (row['result_key'], row['generation_id'])
        child_program = row['normalized_program']
        valid = (row['generation_id'] == row['observed_generation_id'] and
                 row['published_revision'] ==
                    row['observed_published_revision'] and
                 row['job_status'] == 'published' and
                 isinstance(child_program, dict) and
                 row['expected_metadata_revision'] ==
                    row['current_metadata_revision'] and
                 (row['expected_data_revision'] <=
                    row['current_data_revision'] if allow_newer_data else
                  row['expected_data_revision'] ==
                    row['current_data_revision']) and
                 row['expected_policy_revision'] ==
                    row['current_policy_revision'] and
                 identity not in path)
        nested = None
        if valid:
            if row['function_name'] == 'consolidation.full.aggregate':
                nested = published_child_status(db, scope, child_program)
                if nested is not None:
                    budget[0] -= len(nested['dependencies'])
            elif row['function_name'] == (
                    'consolidation.full.translated.aggregate'):
                nested = published_translation_status(db, scope,
                    child_program,_path=path | {identity},_budget=budget)
            elif row['function_name'] == (
                    'currency.calculation.translation.publish'):
                nested = published_calculation_translation_status(
                    db,scope,child_program,
                    _path=path | {identity},_budget=budget)
            elif row['function_name'] == 'facts.expression.calculate':
                published_nested = published_input_status(
                    db, scope, child_program,
                    _path=path | {identity}, _budget=budget,
                    allow_newer_data=allow_newer_data)
                raw_nested = (typed_expression_raw_driver_status(
                    db,scope,row['generation_id'],child_program)
                    if row['compiler_version'] in (
                        'typed-numeric-expression-v29',
                        'typed-numeric-expression-v32') else None)
                context_nested=expression_context_dependency_status(
                    db,scope,child_program,_budget=budget)
                nested={'matchesAtRead':
                    (published_nested is None or
                     published_nested['matchesAtRead']) and
                    (raw_nested is None or raw_nested['matchesAtRead']) and
                    (context_nested is None or
                     context_nested['matchesAtRead']),
                    'truncated':bool(
                        (published_nested and published_nested['truncated']) or
                        (raw_nested and raw_nested['truncated']) or
                        (context_nested and context_nested['truncated'])),
                    'publishedInputStatus':published_nested,
                    'rawDriverStatus':raw_nested,
                    'contextDependencyStatus':context_nested}
            if budget[0] < 0:
                truncated = True
                valid = False
        if nested is not None and not nested['matchesAtRead']:
            valid = False
        dependencies.append({
            'resultKey': row['result_key'],
            'generationId': row['generation_id'],
            'publishedRevision': row['published_revision'],
            'observedGenerationId': row['observed_generation_id'],
            'observedPublishedRevision':
                row['observed_published_revision'],
            'matchesAtRead': valid,
            'nested': nested})
    return {'matchesAtRead': not truncated and all(
                item['matchesAtRead'] for item in dependencies),
            'truncated': truncated, 'dependencies': dependencies}
