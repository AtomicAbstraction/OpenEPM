"""Conservative read-time revision and published-dependency status."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from psycopg.types.json import Jsonb
from .postgres_consolidation_stages import TRANSLATED_STAGES, ACQUISITION_LOCAL_STAGES


def manifest_currentness_status(db, scope, result_state_token: str, *,
        _budget=None, impact_barrier=None) -> dict | None:
    """Authenticate one current partition certificate, then evaluate its scopes.

    Missing manifests remain distinct from legacy flat results. A partial,
    corrupt or mismatched certificate can never establish complete freshness.
    """
    from .calculation_dependency_contract import (compile_dependency_template,
        compile_execution_manifest, validate_manifest_against_template,
        calculation_instance_binding)
    from .calculation_partition_manifest_contract import compile_partition_manifest
    from .postgres_calculation_dependencies import read_scope_freshness
    from .postgres_calculation_impact import impact_processing_barrier
    row = db.execute('''SELECT m.*,b.stage,b.definition_id,b.definition_state_token,
        b.parameters,b.binding,b.template_digest,t.definition_digest,t.template,
        t.schema_epoch template_schema_epoch,s.schema_epoch current_schema_epoch
        FROM epm.calculation_partition_manifest_current m
        JOIN epm.calculation_instance_binding b USING(workspace_id,application_id,binding_digest)
        JOIN epm.calculation_dependency_template t USING(workspace_id,application_id,template_digest)
        JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE m.workspace_id=%s AND m.application_id=%s AND m.result_state_token=%s''',
        (scope.workspace_id, scope.application_id, result_state_token)).fetchone()
    if row is None:
        return None
    result = {'resultStateToken': result_state_token,
        'bindingDigest': row['binding_digest'], 'definitionDigest': row['definition_digest'],
        'definitionId': row['definition_id'], 'definitionStateToken': row['definition_state_token'],
        'templateDigest': row['template_digest'], 'stage': row['stage'],
        'matchesAtRead': False, 'partitions': [], 'certificateValid': False}
    try:
        template = compile_dependency_template(row['template'])
        manifest = compile_partition_manifest(row['partition_map'])
        value = manifest.normalized
        binding = calculation_instance_binding(template_digest=template.digest,
            definition_id=row['definition_id'], definition_state_token=row['definition_state_token'],
            stage=row['stage'], parameters=row['parameters'],
            partition_policy_version=row['partition_policy_version'])
        targets = {item['partitionKey'] for item in template.normalized['targets']}
        if (manifest.digest != row['partition_map_digest']
                or template.digest != row['template_digest']
                or template.normalized['definitionDigest'] != row['definition_digest']
                or template.normalized['definitionId'] != row['definition_id']
                or binding != row['binding'] or binding['bindingDigest'] != row['binding_digest']
                or value['bindingDigest'] != row['binding_digest']
                or value['executionManifestDigest'] != row['execution_manifest_digest']
                or value['partitionPolicyVersion'] != row['partition_policy_version']
                or row['template_schema_epoch'] != row['current_schema_epoch']
                or value['coverage'] != 'complete' or template.normalized['coverage'] != 'complete'
                or set(manifest.partitions) != targets):
            return result
        partitions = value['partitions']
        if _budget is not None:
            _budget[0] -= len(partitions)
            if _budget[0] < 0:
                return {**result, 'truncated': True}
        observed = db.execute('''SELECT partition_key,certificate_digest,presence,row_count
            FROM epm.calculation_partition_current WHERE workspace_id=%s AND application_id=%s
            AND result_key=%s ORDER BY partition_key''',
            (scope.workspace_id, scope.application_id, row['result_key'])).fetchall()
        expected = [{'partition_key': p['partitionKey'], 'certificate_digest': p['certificateDigest'],
            'presence': p['presence'], 'row_count': p['rowCount']} for p in partitions]
        if [dict(item) for item in observed] != expected:
            return result
        certificate_ids = sorted({p['certificateDigest'] for p in partitions}
            | {row['execution_manifest_digest']})
        certificates = db.execute('''SELECT manifest_digest,manifest,schema_epoch
            FROM epm.calculation_execution_manifest WHERE workspace_id=%s AND application_id=%s
            AND manifest_digest=ANY(%s::text[])''',
            (scope.workspace_id, scope.application_id, certificate_ids)).fetchall()
        by_digest = {}
        for item in certificates:
            execution = compile_execution_manifest(item['manifest'])
            validate_manifest_against_template(template, execution)
            from .postgres_job_origin import validate_dependency_evidence
            for resolved in execution.normalized['resolvedDependencies']:
                symbolic = template.normalized['dependencies'][resolved['templateOrdinal']]
                if symbolic['objectType'] == 'calculation-result':
                    validate_dependency_evidence(resolved['token'].get('publishedDependencyEvidence'),
                        symbolic['objectId'])
            if (execution.digest != item['manifest_digest']
                    or item['schema_epoch'] != row['current_schema_epoch']
                    or execution.normalized['schemaEpoch'] != row['current_schema_epoch']
                    or execution.normalized['bindingDigest'] != row['binding_digest']
                    or execution.normalized['coverage'] != 'complete'):
                return result
            by_digest[execution.digest] = execution
        if set(by_digest) != set(certificate_ids) or any(
                p['partitionKey'] not in by_digest[p['certificateDigest']].normalized['targetPartitions']
                for p in partitions):
            return result
    except (ValueError, TypeError, KeyError):
        return result
    definition_status = None
    if row['stage'] == 'materialize':
        from .postgres_definition_lifecycle import definition_state_axes, resolution_context
        from .postgres_jobs import _canonical_digest
        from .calculated_member_contract import calculated_member_digest
        owner = db.execute('''SELECT * FROM epm.expression_rule_definition
            WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
            (scope.workspace_id, scope.application_id, row['definition_id'])).fetchone()
        if (owner is None or owner['state_token'] != row['definition_state_token']
                or not isinstance(owner.get('program'), dict)
                or owner['program'].get('function') != 'calculated.member.definition'
                or _canonical_digest(owner['program']) != owner['program_digest']):
            return {**result, 'definitionStatus': {'resultDefinitionValid': False,
                'resultDefinitionReason': 'definition_changed'}}
        definition = owner['program']['arguments']
        from .postgres_calculated_members import dependency_template_compiler
        if template.normalized['compilerVersion'] != dependency_template_compiler(definition):
            return {**result, 'definitionStatus': {'resultDefinitionValid': False,
                'resultDefinitionReason': 'compiler_changed'}}
        if calculated_member_digest(definition, active_dimensions=[
                d['dimensionId'] for d in definition['sourceSelection']['dimensions']]) != row['definition_digest']:
            return result
        definition_status = definition_state_axes(owner, resolution_context(db, scope, [owner]))
    barrier = impact_barrier if impact_barrier is not None else impact_processing_barrier(db, scope)
    statuses = []
    for partition in partitions:
        status = read_scope_freshness(db, scope, binding_digest=row['binding_digest'],
            stage=row['stage'], partition_key=partition['partitionKey'],
            expected_definition_digest=row['definition_digest'], impact_barrier=barrier)
        matches = (status['currentResultStateToken'] == result_state_token
            and status['presence'] == partition['presence']
            and status.get('dependencyTokenDigest') == partition['certificateDigest'])
        statuses.append({'partitionKey': partition['partitionKey'], **status,
            'matchesRequestedResultState': matches,
            'matchesAtRead': status['freshness'] == 'current' and matches})
    return {**result, 'certificateValid': True, 'partitions': statuses,
        'compilerVersion': template.normalized['compilerVersion'],
        'definitionStatus': definition_status,
        'matchesAtRead': bool(statuses) and all(p['matchesAtRead'] for p in statuses)
            and (definition_status is None or definition_status['resultDefinitionValid'])}


def input_revision_status(row: dict) -> dict:
    expected = {name: row[f'expected_{name}_revision']
                for name in ('metadata', 'data', 'policy')}
    current = {name: row[f'current_{name}_revision']
               for name in ('metadata', 'data', 'policy')}
    return {'matchesAtRead': expected == current,
            'expected': expected, 'observed': current,
            'observedCommitRevision': row['observed_commit_revision']}


def typed_expression_raw_driver_status(db, scope, result_key: str,
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
        FROM epm.calculation_unit_result_current r
        LEFT JOIN LATERAL (SELECT count(*) AS driver_count,
          min(value::text)::jsonb AS item
          FROM jsonb_array_elements(r.source_lookup_lineage) value
          WHERE value->>'inputKind'='RawDriver') driver ON true
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.result_key=%s ORDER BY r.coordinate_id LIMIT 501''',(
        scope.workspace_id,scope.application_id,result_key)).fetchall()
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
    if len(path) >= 32 or not isinstance(program,dict):
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
        p.source_operation_id AS observed_generation_id,
        p.committed_revision AS observed_published_revision,
        p.source_function AS function_name,j.status AS job_status,j.normalized_program,
        j.expected_metadata_revision,j.expected_data_revision,
        j.expected_policy_revision,
        s.metadata_revision AS current_metadata_revision,
        s.data_revision AS current_data_revision,
        s.policy_revision AS current_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
            relationship_id text,result_key text,generation_id text,
            published_revision bigint)
        LEFT JOIN epm.calculation_result_state p
          ON p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=input.result_key
        LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
          AND j.application_id=p.application_id
          AND j.job_id=p.source_operation_id
        JOIN epm.application_state s ON s.workspace_id=%s
          AND s.application_id=%s
        ORDER BY input.relationship_id''',
        (Jsonb(requested),
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
    if (len(path) >= 32 or expected_function is None
            or not isinstance(pins,list) or not 1<=len(pins)<=120
            or len(pins)>budget[0]
            or any(not isinstance(pin,dict) or not {
                'periodId','resultKey','generationId',
                'publishedRevision'}<=set(pin) for pin in pins)):
        return {'matchesAtRead':False,'truncated':True,'dependencies':[]}
    budget[0]-=len(pins)
    rows=db.execute('''SELECT input.period_id,input.result_key,
        input.generation_id,input.published_revision,
        p.source_operation_id AS observed_generation_id,
        p.committed_revision AS observed_published_revision,
        p.source_function AS function_name,j.status AS job_status,j.normalized_program,
        j.expected_metadata_revision,j.expected_data_revision,
        j.expected_policy_revision,
        s.metadata_revision AS current_metadata_revision,
        s.data_revision AS current_data_revision,
        s.policy_revision AS current_policy_revision
        FROM jsonb_to_recordset(%s::jsonb) AS input(
          period_id text,result_key text,generation_id text,
          published_revision bigint)
        LEFT JOIN epm.calculation_result_state p ON
          p.workspace_id=%s AND p.application_id=%s
          AND p.result_key=input.result_key
        LEFT JOIN epm.job j ON j.workspace_id=p.workspace_id
          AND j.application_id=p.application_id
          AND j.job_id=p.source_operation_id
        JOIN epm.application_state s ON s.workspace_id=%s
          AND s.application_id=%s ORDER BY input.period_id''',
        (Jsonb([{'period_id':pin['periodId'],
            'result_key':pin['resultKey'],
            'generation_id':pin['generationId'],
            'published_revision':pin['publishedRevision']}
            for pin in pins]),scope.workspace_id,scope.application_id,
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
                row['normalized_program'],_budget=budget,_path=path|{identity})
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


def published_child_status(db, scope, program: dict, *, _budget=None, _path=None) -> dict | None:
    """Check a Full result's pinned child tree in bounded, per-level queries.

    A parent pointer can remain unchanged when a grandchild is republished.
    Following each current child program prevents that from appearing current.
    Publishers hold the application-state lock while calling this; a read is
    a conservative observation, not an accounting certificate.
    """
    pinned = program.get('publishedChildren', [])
    if not pinned:
        return None
    dependencies = []
    budget = _budget if _budget is not None else [1000]
    path = _path if _path is not None else frozenset()
    frontier = [(None, item, path) for item in pinned]
    truncated = False
    for depth in range(32):
        if not frontier:
            break
        if len(frontier) > budget[0]:
            truncated = True
            break
        budget[0] -= len(frontier)
        for _, item, ancestry in frontier:
            identity = (item['resultKey'], item['resultStateToken'])
            if identity in ancestry or len(ancestry) >= 32:
                truncated = True
                break
        if truncated:
            break
        rows = db.execute('''SELECT input.ordinal,input.relationship_id,
            input.result_key,input.result_state_token,
            p.state_token AS observed_state_token,p.content_digest,
            p.source_function AS function_name,j.status AS job_status,j.normalized_program,
            j.expected_metadata_revision,j.expected_data_revision,
            j.expected_policy_revision,
            s.metadata_revision AS current_metadata_revision,
            s.data_revision AS current_data_revision,
            s.policy_revision AS current_policy_revision
            FROM jsonb_to_recordset(%s::jsonb) AS input(
                ordinal int,relationship_id text,result_key text,
                result_state_token text)
            LEFT JOIN epm.calculation_result_state p
              ON p.workspace_id=%s AND p.application_id=%s
             AND p.result_key=input.result_key
            LEFT JOIN epm.job j
              ON j.workspace_id=p.workspace_id
             AND j.application_id=p.application_id
             AND j.job_id=p.source_operation_id
            JOIN epm.application_state s ON s.workspace_id=%s
              AND s.application_id=%s
            ORDER BY input.ordinal''',
            (Jsonb([{'ordinal': ordinal,
                     'relationship_id': item['relationshipId'],
                     'result_key': item['resultKey'],
                     'result_state_token': item['resultStateToken']}
                    for ordinal, (_, item, _) in enumerate(frontier)]),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        next_frontier = []
        for row in rows:
            parent_key, _, ancestry = frontier[row['ordinal']]
            child_program = row['normalized_program']
            valid = (row['result_state_token'] ==
                     row['observed_state_token'] and
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
                'resultStateToken': row['result_state_token'],
                'resultContentDigest': row['content_digest'],
                'matchesAtRead': valid})
            if valid:
                for nested in child_program.get('publishedChildren', []):
                    if not isinstance(nested, dict) or set(nested) != {
                            'relationshipId', 'resultKey',
                            'resultStateToken'}:
                        truncated = True
                        break
                    next_frontier.append((row['result_key'], nested, ancestry | {
                        (row['result_key'], row['result_state_token'])}))
        if truncated:
            break
        frontier = next_frontier
    else:
        truncated = bool(frontier)
    return {'matchesAtRead': not truncated and all(
                item['matchesAtRead'] for item in dependencies),
            'truncated': truncated, 'dependencies': dependencies}


class _CurrentnessRead:
    def __init__(self, db, scope, budget):
        self.db, self.scope = db, scope
        self.budget = budget if budget is not None else [1000]
        self.path = ()
        self.memo = {}
        self.evidence = {}
        self.cut = None


_CURRENTNESS_READ = ContextVar('openepm_currentness_read', default=None)


@contextmanager
def _currentness_read(db, scope, budget=None):
    current = _CURRENTNESS_READ.get()
    if current is not None:
        if current.db is not db or current.scope != scope:
            raise ValueError('CALCULATION_CURRENTNESS_SCOPE_MISMATCH')
        yield current
        return
    current = _CurrentnessRead(db, scope, budget)
    token = _CURRENTNESS_READ.set(current)
    try:
        yield current
        if current.cut is not None:
            after = db.execute('''SELECT metadata_revision current_metadata_revision,
                data_revision current_data_revision,policy_revision current_policy_revision,
                commit_revision observed_commit_revision,schema_epoch,impact_epoch,processed_impact_epoch
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s''',
                (scope.workspace_id, scope.application_id)).fetchone()
            if after is None or _read_cut(after) != current.cut:
                raise ValueError('CALCULATION_CURRENTNESS_READ_CUT_CHANGED')
    finally:
        _CURRENTNESS_READ.reset(token)


def _read_cut(row):
    return tuple(row[key] for key in ('current_metadata_revision', 'current_data_revision',
        'current_policy_revision', 'observed_commit_revision', 'schema_epoch',
        'impact_epoch', 'processed_impact_epoch'))


def _producer_statuses(db, scope, row, context, *, allow_newer_data=False):
    """Keep producer-specific evidence around the shared scope decision."""
    function, program = row['function_name'], row['normalized_program']
    statuses = {}
    if function == 'facts.expression.calculate':
        statuses['publishedInputStatus'] = published_input_status(db, scope, program,
            allow_newer_data=allow_newer_data)
        statuses['rawDriverStatus'] = (typed_expression_raw_driver_status(
            db, scope, row['result_key'], program) if row['compiler_version'] in (
                'typed-numeric-expression-v29', 'typed-numeric-expression-v32') else None)
        raw = statuses['rawDriverStatus']
        if raw is not None:
            context.budget[0] -= max(raw.get('storedRowCount', 0), raw.get('currentDriverCount', 0))
        statuses['contextDependencyStatus'] = expression_context_dependency_status(
            db, scope, program, _budget=context.budget)
    elif function == 'consolidation.full.aggregate':
        statuses['publishedChildStatus'] = published_child_status(db, scope, program,
            _budget=context.budget, _path=frozenset(context.path))
    elif function == 'consolidation.full.translated.aggregate':
        statuses['publishedTranslationStatus'] = published_translation_status(db, scope,
            program, _budget=context.budget, _path=frozenset(context.path))
    elif function == 'currency.calculation.translation.publish':
        statuses['publishedCalculationTranslationStatus'] = published_calculation_translation_status(
            db, scope, program, _budget=context.budget, _path=frozenset(context.path))
    elif function in ('consolidation.nci.period.publish', 'consolidation.nci.period.withdraw'):
        from .postgres_period_nci_publication import source_status
        statuses['periodNciSourceStatus'] = source_status(db, scope, program)
    elif function == 'consolidation.equity.contribution.publish':
        from .postgres_equity_method_publication import context_status, source_status
        statuses['equitySourceStatus'] = source_status(db, scope, row['job_result'])
        statuses['equityContextStatus'] = context_status(db, scope, program, row['job_result'])
    elif function == 'consolidation.proportional.contribution.publish':
        from .postgres_proportional_publication import context_status, source_status
        statuses['proportionalSourceStatus'] = source_status(db, scope, row['job_result'])
        statuses['proportionalContextStatus'] = context_status(db, scope, program, row['job_result'])
    elif function == 'consolidation.method.total.publish':
        from .postgres_consolidation_method_total import source_status
        statuses['methodTotalSourceStatus'] = source_status(db, scope, row['job_result'])
    elif function == 'consolidation.inventory.unrealized_profit.request':
        from .postgres_inventory_unrealized_publication import source_status
        statuses['inventoryUnrealizedSourceStatus'] = source_status(db, scope, row['job_result'])
    elif function == 'consolidation.full.typed.contribute':
        from .postgres_consolidation_full import typed_full_context_status
        statuses['typedFullContextStatus'] = typed_full_context_status(db, scope, program, row['job_result'])
    elif function == 'facts.planning.allocate.weighted' and program.get('publishedRatioBasis') is not None:
        statuses['publishedRatioBasisStatus'] = published_input_status(db, scope,
            {'publishedInputs': [program['publishedRatioBasis']]})
    return {name: status for name, status in statuses.items() if status is not None}


def _evidence_record(status, allow_newer_data):
    return {key: status[key] for key in (
        'resultKey', 'resultStateToken', 'observedResultStateToken',
        'resultContentDigest', 'matchesAtRead', 'truncated', 'freshness', 'basis',
        'producerStatus')} | {
        'allowNewerData': allow_newer_data}


def _with_dependency_evidence(status, context, outer):
    if outer:
        return {**status, 'dependencyEvidence': [context.evidence[key]
            for key in sorted(context.evidence)]}
    return status


def published_result_status(db, scope, result_key, result_state_token, *, allow_newer_data=False):
    """One read-only verdict for an exact head and its bounded dependency closure.

    Certified scopes supersede global revision equality. Flat results keep the
    conservative legacy cut; neither a missing certificate nor pending impact
    processing can silently promote an uncertified result.
    """
    outer = _CURRENTNESS_READ.get() is None
    with _currentness_read(db, scope) as context:
        status = _published_result_status(db, scope, result_key, result_state_token,
            context, allow_newer_data=allow_newer_data)
        return _with_dependency_evidence(status, context, outer)


def _published_result_status(db, scope, result_key, result_state_token, context, *, allow_newer_data):
    status = _evaluate_published_result_status(db, scope, result_key, result_state_token,
        context, allow_newer_data=allow_newer_data)
    key = (result_key, result_state_token, allow_newer_data)
    if key not in context.evidence and len(context.evidence) >= 1000:
        raise ValueError('CALCULATION_CURRENTNESS_EVIDENCE_LIMIT')
    context.evidence[key] = _evidence_record(status, allow_newer_data)
    return status


def _evaluate_published_result_status(db, scope, result_key, result_state_token, context, *, allow_newer_data):
    identity = (result_key, result_state_token)
    failed = {'resultKey': result_key, 'resultStateToken': result_state_token,
        'observedResultStateToken': None, 'resultContentDigest': None,
        'matchesAtRead': False, 'truncated': False, 'freshness': 'unavailable',
        'profileStatuses': {}, 'manifestCurrentnessStatus': None,
        'definitionStatus': None, 'basis': 'unavailable', 'producerStatus': None,
        'impactBarrier': None, 'inputRevisionStatus': {'matchesAtRead': False}}
    context.budget[0] -= 1
    if context.budget[0] < 0 or len(context.path) >= 32 or identity in context.path:
        return {**failed, 'truncated': True}
    row = db.execute('''SELECT p.result_key,p.state_token,p.content_digest,
        p.payload_layout generation_kind,p.source_function function_name,
        p.source_operation_id producing_operation_id,j.status job_status,
        j.normalized_program,j.compiler_version,j.result job_result,
        j.issuer,j.subject_id,j.idempotency_key,j.job_id,j.program_digest,
        j.admission_origin_kind,j.python_workflow_id,j.function_name admitted_function_name,
        p.source_program_digest,p.source_compiler_version,
        j.expected_metadata_revision,j.expected_data_revision,j.expected_policy_revision,
        s.metadata_revision current_metadata_revision,s.data_revision current_data_revision,
        s.policy_revision current_policy_revision,s.commit_revision observed_commit_revision,
        s.schema_epoch,s.impact_epoch,s.processed_impact_epoch
        FROM epm.calculation_result_state p JOIN epm.job j
        ON(j.workspace_id,j.application_id,j.job_id)=(p.workspace_id,p.application_id,p.source_operation_id)
        JOIN epm.application_state s ON(s.workspace_id,s.application_id)=(p.workspace_id,p.application_id)
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.result_key=%s''',
        (scope.workspace_id, scope.application_id, result_key)).fetchone()
    if row is None:
        return failed
    failed.update(observedResultStateToken=row['state_token'], resultContentDigest=row['content_digest'])
    if (row['state_token'] != result_state_token or row['job_status'] != 'published'
            or not isinstance(row['normalized_program'], dict)
            or row['admitted_function_name'] != row['function_name']
            or row['source_program_digest'] != row['program_digest']
            or row['source_compiler_version'] != row['compiler_version']):
        return failed
    cut = _read_cut(row)
    if context.cut is None:
        context.cut = cut
    elif context.cut != cut:
        raise ValueError('CALCULATION_CURRENTNESS_READ_CUT_CHANGED')
    memo_key = (identity, cut, allow_newer_data)
    if memo_key in context.memo:
        # Full profiles occur once. Repeated DAG edges keep an exact verdict
        # and identity reference; the outer read carries the unique closure.
        return {**context.memo[memo_key], 'profileStatuses': {},
            'manifestCurrentnessStatus': None, 'definitionStatus': None,
            'evidenceReference': {'resultKey': result_key, 'resultStateToken': result_state_token,
                'allowNewerData': allow_newer_data}}
    before = context.path
    context.path = (*before, identity)
    try:
        revision = input_revision_status(row)
        if allow_newer_data:
            revision['matchesAtRead'] = (row['expected_metadata_revision'] == row['current_metadata_revision']
                and row['expected_policy_revision'] == row['current_policy_revision']
                and row['expected_data_revision'] <= row['current_data_revision'])
        revision['revisionMatchesAtRead'] = revision['matchesAtRead']
        barrier = {'impactEpoch': row['impact_epoch'], 'processedImpactEpoch': row['processed_impact_epoch'],
            'pending': row['impact_epoch'] > row['processed_impact_epoch']}
        manifest = manifest_currentness_status(db, scope, result_state_token,
            _budget=context.budget, impact_barrier=barrier)
        scoped = row['generation_kind'] == 'partition_manifest'
        base_current = (manifest is not None and manifest['matchesAtRead']
            and manifest.get('compilerVersion') == row['compiler_version'] if scoped
            else manifest is None and revision['matchesAtRead'] and not barrier['pending'])
        from .postgres_job_origin import result_producer_status
        producer = result_producer_status(db, scope, row, _budget=context.budget)
        # Unclassified legacy payloads are inspectable as unresolved; they
        # cannot acquire authority by decoding a historical execution profile.
        statuses = ({} if producer['originKind'] == 'unresolved' else
            _producer_statuses(db, scope, row, context, allow_newer_data=allow_newer_data))
        truncated = context.budget[0] < 0 or bool(manifest and manifest.get('truncated')) or any(
            item.get('truncated', False) for item in statuses.values())
        matches = (base_current and producer['matchesAtRead'] and not truncated
            and all(item['matchesAtRead'] for item in statuses.values()))
        result = {**failed, 'matchesAtRead': matches, 'truncated': truncated,
            'basis': 'scoped_manifest' if scoped else 'legacy_revisions',
            'freshness': 'impact_coverage_pending' if barrier['pending'] else 'current' if matches else 'stale',
            'inputRevisionStatus': {**revision, 'matchesAtRead': matches},
            'impactBarrier': barrier, 'manifestCurrentnessStatus': manifest,
            'definitionStatus': manifest.get('definitionStatus') if manifest else None,
            'profileStatuses': statuses, 'producerStatus': producer}
        if not truncated:
            context.memo[memo_key] = result
        return result
    finally:
        context.path = before


def published_input_status(db, scope, program: dict, *,
                           _path: frozenset[tuple[str, str]] | None = None,
                           _budget: list[int] | None = None,
                           allow_newer_data: bool = False) -> dict | None:
    """Evaluate strict current-state pins with one shared recursive read budget."""
    pinned = program.get('publishedInputs', [])
    if not pinned:
        return None
    if (not isinstance(pinned, list) or any(not isinstance(item, dict)
            or set(item) != {'resultKey', 'resultStateToken'}
            or not isinstance(item['resultKey'], str)
            or not isinstance(item['resultStateToken'], str) for item in pinned)):
        return {'matchesAtRead': False, 'truncated': True, 'dependencies': []}
    outer = _CURRENTNESS_READ.get() is None
    with _currentness_read(db, scope, _budget) as context:
        prior = context.path
        if _path is not None:
            context.path = (*context.path, *sorted(set(_path) - set(context.path)))
        try:
            dependencies = []
            for pin in pinned:
                status = _published_result_status(db, scope, pin['resultKey'], pin['resultStateToken'],
                    context, allow_newer_data=allow_newer_data)
                dependencies.append({'resultKey': pin['resultKey'], 'resultStateToken': pin['resultStateToken'],
                    'observedResultStateToken': status['observedResultStateToken'],
                    'resultContentDigest': status['resultContentDigest'], 'matchesAtRead': status['matchesAtRead'],
                    'nested': status['profileStatuses'], 'currentness': {
                        key: value for key, value in status.items() if key != 'profileStatuses'}})
                if status['truncated']:
                    return _with_dependency_evidence({'matchesAtRead': False, 'truncated': True,
                        'dependencies': dependencies}, context, outer)
            return _with_dependency_evidence({'matchesAtRead': all(item['matchesAtRead'] for item in dependencies),
                'truncated': False, 'dependencies': dependencies}, context, outer)
        finally:
            context.path = prior
