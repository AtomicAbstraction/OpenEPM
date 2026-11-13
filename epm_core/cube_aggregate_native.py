"""Native exact-SQL compute stage for the durable public aggregate lifecycle.

The stage grants no publication authority. Its bounded output is persisted and
made visible only by the fixed service after fresh authorization and fencing.
"""
import json
import threading
import time

from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .cube_aggregate_ir import compile_cube_aggregate
from .cube_aggregate_lifecycle import POSTGRES_EXACT_DIMENSIONAL_BACKEND
from .dimensional_security_policy import (
    AcrossDimensions, HierarchyTags,
    MemberTagCardinality, MixedSelection, UntaggedDenyPrecedence,
    UntaggedMember, WithinDimension)
from .persistence_contract import ApplicationScope
from .postgres_access import (AccessDenied, PostgresAccessChecker, VerifiedIdentity,
                              assert_nonowner_role)
from .postgres_connection import connect_postgres
from .postgres_cube_query import _ROLE_COLUMNS
from .postgres_cube_select import PostgresCubeSelect
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout

_STATE = '''SELECT commit_revision,data_revision,metadata_revision,policy_revision,
    security_revision,schema_epoch,active_projection_generation FROM epm.application_state
    WHERE workspace_id=%s AND application_id=%s'''

_MEASURE_PROJECTIONS = {
    'SumAmount': ('sum(n.amount)::text', 'sum_amount'),
    'CountPresent': ('count(*)::text', 'count_present'),
    'MinAmount': ('min(n.amount)::text', 'min_amount'),
    'MaxAmount': ('max(n.amount)::text', 'max_amount'),
}


def _measure_projections(measures):
    """Return only requested fixed SQL aggregates in canonical measure order."""
    if (type(measures) not in (tuple, list) or not measures
            or any(measure not in _MEASURE_PROJECTIONS for measure in measures)
            or len(set(measures)) != len(measures)):
        raise ValueError('CUBE_AGGREGATE_MEASURES_INVALID')
    return tuple((measure, *_MEASURE_PROJECTIONS[measure]) for measure in measures)


class _CancellationBridge:
    """Cancel only the connection owned by this exact compute invocation."""
    def __init__(self,connection,event):
        self.connection,self.event=connection,event
        self.stop=threading.Event();self.thread=None
    def __enter__(self):
        if self.event is not None:
            def watch():
                while not self.stop.wait(.05):
                    if self.event.is_set():self.connection.cancel();return
            self.thread=threading.Thread(target=watch,daemon=True)
            self.thread.start()
        return self
    def __exit__(self,*unused):
        self.stop.set()
        if self.thread is not None:self.thread.join(timeout=1)


class NativeCubeAggregateStage:
    backend_profile = POSTGRES_EXACT_DIMENSIONAL_BACKEND
    # Preserve the already qualified certificate label; this refactor must not
    # reinterpret existing technical results.
    compute_profile = 'cube-aggregate-native-unwired-v1'

    def __init__(self, dsn, *, identity, qualification_observer=None):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        if qualification_observer is not None and not callable(qualification_observer):
            raise ValueError('CUBE_AGGREGATE_QUALIFICATION_OBSERVER_INVALID')
        assert_nonowner_role(dsn, 'epm_runtime', ('coordinate_layout', 'dimension'))
        self.dsn, self.identity = dsn, identity
        self._qualification_observer = qualification_observer
        self._qualification_explain = None

    def _authorize(self, scope, pins=None, authorization_scope_digest=None):
        # The shared checker requires RC. Keep its security fence brief; never
        # carry the workspace grant-writer fence into the analytical scan.
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read',
                    function='facts.cube.aggregate.request')
                current = db.execute(_STATE, (scope.workspace_id, scope.application_id)).fetchone()
                if current is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if pins and any(current[k] != pins[k] for k in
                                ('metadata_revision', 'policy_revision',
                                 'security_revision', 'schema_epoch')):
                    raise ValueError('CUBE_AGGREGATE_STALE_CONTEXT')
                dimensional_scope = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access)
                if (authorization_scope_digest is not None
                        and dimensional_scope.scope_digest !=
                            authorization_scope_digest):
                    raise AccessDenied(
                        'CUBE_AGGREGATE_AUTHORIZATION_SCOPE_CHANGED')
                return dimensional_scope

    def _configure_backend(self, db, query, params):
        """Server-owned engine hook; the public request has no backend field."""
        if self._qualification_observer is not None:
            explained = db.execute(sql.SQL('EXPLAIN (COSTS OFF) ')+query,
                                   params).fetchall()
            self._qualification_explain = '\n'.join(
                str(value) for row in explained for value in row.values())
            if not self._qualification_explain or 'DuckDBScan' in self._qualification_explain:
                raise ValueError('POSTGRES_NATIVE_PLAN_NOT_SELECTED')
        return self.backend_profile, self.compute_profile

    @staticmethod
    def _security_profile(dimensional_scope):
        """Adapt the shared effective scope to fixed aggregate SQL inputs."""
        if dimensional_scope.policy is None:
            return None
        policy = dimensional_scope.policy
        if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
            raise ValueError('DIMENSIONAL_HIERARCHY_POLICY_NOT_INTEGRATED')
        return {'policy': policy,
                'assignments': dimensional_scope.read_assignments,
                'bypass': dimensional_scope.administrator_bypass}

    @staticmethod
    def _security_sql(profile, dimension_count):
        """Compile fixed SQL authorization over each full source coordinate."""
        if profile is None or profile['bypass']:
            return sql.SQL(''), sql.SQL(''), [], None
        policy = profile['policy']
        match = (sql.SQL('m.read_security_tags && assigned.tags')
                 if policy.within_dimension is WithinDimension.ANY_TAG else
                 sql.SQL('m.read_security_tags <@ assigned.tags'))
        untagged_protected = (policy.untagged_member is UntaggedMember.DENY)
        protected = sql.SQL(
            'cardinality(m.read_security_tags)>0{}').format(
                sql.SQL(' OR cardinality(m.read_security_tags)=0')
                if untagged_protected else sql.SQL(''))
        join = sql.SQL('''JOIN epm.coordinate c
              ON c.workspace_id=n.workspace_id
             AND c.application_id=n.application_id
             AND c.coordinate_id=n.coordinate_id
            JOIN LATERAL (
              SELECT count(*) AS axis_count,
                count(m.member_id) AS found_count,
                count(*) FILTER (WHERE {protected}) AS protected_count,
                count(*) FILTER (WHERE cardinality(m.read_security_tags)>0
                  AND {match}) AS matched_count,
                coalesce(bool_or(cardinality(m.read_security_tags)=0),false)
                  AS has_untagged,
                coalesce(bool_or(cardinality(m.read_security_tags)>1),false)
                  AS cardinality_violation
              FROM jsonb_each_text(c.members) axis(dimension_id,member_id)
              LEFT JOIN epm.member m
                ON m.workspace_id=c.workspace_id
               AND m.application_id=c.application_id
               AND m.dimension_id=axis.dimension_id
               AND m.member_id=axis.member_id AND m.status='Active'
              CROSS JOIN LATERAL (SELECT coalesce(array_agg(tag),
                  ARRAY[]::text[]) AS tags FROM jsonb_array_elements_text(
                    coalesce(%s::jsonb->axis.dimension_id,'[]'::jsonb))
                    AS item(tag)
              ) assigned
            ) security ON true''').format(protected=protected, match=match)
        matched = (sql.SQL('security.matched_count=security.protected_count')
                   if policy.across_dimensions is AcrossDimensions.EVERY_PROTECTED
                   else sql.SQL('security.matched_count>0'))
        allowed = sql.SQL('''security.axis_count={dimensions}
            AND security.found_count={dimensions}
            {cardinality}
            {untagged}
            AND (security.protected_count=0 OR {matched})''').format(
                dimensions=sql.Literal(dimension_count),
                cardinality=(sql.SQL('AND NOT security.cardinality_violation')
                    if policy.member_tag_cardinality is
                       MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                    else sql.SQL('')),
                untagged=(sql.SQL('AND NOT security.has_untagged')
                    if (untagged_protected and policy.untagged_deny_precedence
                        is UntaggedDenyPrecedence.ABSOLUTE) else sql.SQL('')),
                matched=matched)
        return join, sql.SQL(' AND ({})').format(allowed), [
            Jsonb(profile['assignments'])], allowed

    def compute(self, scope, arguments, *, max_groups=100000,
                max_result_bytes=33554432, statement_timeout_ms=5000,
                cancel_event=None):
        """Compute current snapshot only; limits are trusted server options.

        No snapshot token/generation/engine can be authored. Generic models need
        no financial configuration. Financial roles can be fixed/grouped, but
        financial unit/additivity qualification remains a future admission gate.
        """
        compute_started = time.perf_counter()
        materialization_seconds = 0.0
        if not isinstance(scope, ApplicationScope):
            raise ValueError('CUBE_AGGREGATE_SCOPE_INVALID')
        if (type(max_groups) is not int or not 1 <= max_groups <= 100000
                or type(max_result_bytes) is not int or not 1 <= max_result_bytes <= 33554432
                or type(statement_timeout_ms) is not int or not 1 <= statement_timeout_ms <= 20000):
            raise ValueError('CUBE_AGGREGATE_SERVER_BUDGET_INVALID')
        if cancel_event is not None and not isinstance(cancel_event,threading.Event):
            raise ValueError('CUBE_AGGREGATE_CANCEL_EVENT_INVALID')
        dimensional_scope = self._authorize(scope)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
                configure_statement_timeout(db, statement_timeout_ms)
                PostgresNumericFactStore._set_scope(db, scope)
                pins = db.execute(_STATE, (scope.workspace_id, scope.application_id)).fetchone()
                if pins is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                dims = db.execute('''SELECT dimension_id,model_role FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s AND status='Active'
                    AND model_role IS DISTINCT FROM 'Currency' ORDER BY dimension_id''',
                    (scope.workspace_id, scope.application_id)).fetchall()
                roles = {d['dimension_id']: d['model_role'] for d in dims}
                plan = compile_cube_aggregate(arguments, input_dimensions=sorted(roles), dimension_roles=roles)
                if plan.generic_pins:
                    generic_pins=dict(plan.generic_pins)
                    artifact=db.execute('''SELECT 1 FROM epm.sealed_cube_selection
                        WHERE workspace_id=%s AND application_id=%s
                        AND selection_id=%s AND issuer=%s AND subject_id=%s
                        AND resolution_digest=%s AND metadata_revision=%s
                        AND policy_revision=%s AND expires_at>clock_timestamp()''',(
                        scope.workspace_id,scope.application_id,
                        generic_pins['selectionId'],self.identity.issuer,
                        self.identity.subject_id,generic_pins['resolutionDigest'],
                        generic_pins['metadataRevision'],
                        generic_pins['policyRevision'])).fetchone()
                    if (artifact is None
                            or pins['metadata_revision']!=generic_pins['metadataRevision']
                            or pins['policy_revision']!=generic_pins['policyRevision']):
                        raise ValueError('CUBE_AGGREGATE_SEALED_SELECTION_STALE')
                if plan.hierarchy_pins:
                    hierarchy_pins=dict(plan.hierarchy_pins)
                    if (pins['metadata_revision']!=hierarchy_pins['metadataRevision']
                            or pins['policy_revision']!=hierarchy_pins['policyRevision']
                            or len(plan.reduce_dimensions)!=1):
                        raise ValueError('CUBE_AGGREGATE_HIERARCHY_BINDING_STALE')
                    hierarchy_state=db.execute('''SELECT membership_semantics
                        FROM epm.hierarchy_state WHERE workspace_id=%s
                        AND application_id=%s AND dimension_id=%s
                        AND hierarchy_id=%s AND state_token=%s''',(
                        scope.workspace_id,scope.application_id,
                        plan.reduce_dimensions[0],hierarchy_pins['hierarchyId'],
                        hierarchy_pins['hierarchyStateToken'])).fetchone()
                    expected_membership=('placement'
                        if plan.aggregation=='hierarchy_placement_weighted_sum'
                        else 'unique_member')
                    if (hierarchy_state is None
                            or hierarchy_state['membership_semantics']!=
                            expected_membership):
                        raise ValueError('CUBE_AGGREGATE_HIERARCHY_BINDING_STALE')
                layout = db.execute('''SELECT dimensions,role_dimensions,custom_dimensions
                    FROM epm.coordinate_layout WHERE workspace_id=%s AND application_id=%s
                    AND schema_epoch=%s''', (scope.workspace_id, scope.application_id, pins['schema_epoch'])).fetchone()
                if layout is None or sorted(layout['dimensions']) != list(plan.input_dimensions):
                    raise ValueError('CUBE_AGGREGATE_LAYOUT_UNAVAILABLE')
                # Compatibility adapter: selector semantics stay exactly those
                # of select, while aggregate owns the output/reduction grain.
                selection = {'grain': {'mode': 'full_coordinate', 'dimensions': list(plan.input_dimensions)},
                             'selectors': plan.normalized_arguments['selectors']}
                sets, hierarchy = PostgresCubeSelect._resolve(db, scope, selection, pins['metadata_revision'])
                configure_statement_timeout(db, statement_timeout_ms)
                columns = {axis: sql.SQL('p.{}').format(sql.Identifier(_ROLE_COLUMNS[role]))
                           for role, axis in layout['role_dimensions'].items() if role in _ROLE_COLUMNS}
                columns.update({axis: sql.SQL('p.custom_members[{}]').format(sql.Literal(index))
                                for index, axis in enumerate(layout['custom_dimensions'], 1)})
                if set(columns) != set(plan.input_dimensions):
                    raise ValueError('CUBE_AGGREGATE_LAYOUT_UNAVAILABLE')
                operator_weight = None
                placement_count_weight = None
                if plan.operator_weights:
                    factors=[]
                    for axis,weights in plan.operator_weights:
                        cases=sql.SQL(' ').join(
                            sql.SQL('WHEN {} THEN {}').format(
                                sql.Literal(member),sql.Literal(weight))
                            for member,weight in weights)
                        factors.append(sql.SQL('(CASE {} {} ELSE NULL END)').format(
                            columns[axis],cases))
                    operator_weight=sql.SQL(' * ').join(factors)
                elif plan.placement_weights:
                    sum_factors=[]
                    count_factors=[]
                    for axis,weights in plan.placement_weights:
                        sum_cases=sql.SQL(' ').join(
                            sql.SQL('WHEN {} THEN {}').format(
                                sql.Literal(member),sql.Literal(values[0]))
                            for member,values in weights)
                        count_cases=sql.SQL(' ').join(
                            sql.SQL('WHEN {} THEN {}').format(
                                sql.Literal(member),sql.Literal(values[1]))
                            for member,values in weights)
                        sum_factors.append(sql.SQL('(CASE {} {} ELSE NULL END)').format(
                            columns[axis],sum_cases))
                        count_factors.append(sql.SQL('(CASE {} {} ELSE NULL END)').format(
                            columns[axis],count_cases))
                    operator_weight=sql.SQL(' * ').join(sum_factors)
                    placement_count_weight=sql.SQL(' * ').join(count_factors)
                grouping = [sql.SQL('{} COLLATE "C"').format(columns[axis]) for axis in plan.group_by]
                predicates = [sql.SQL('{}=ANY(%s::text[])').format(columns[axis]) for axis in sorted(sets)]
                group_select = [sql.SQL('{} AS {}').format(expr, sql.Identifier('g'+str(i)))
                                for i, expr in enumerate(grouping)]
                measure_projections = _measure_projections(plan.measures)
                aggregate_select=[]
                for measure,expression,alias in measure_projections:
                    projected=(sql.SQL('sum(n.amount * ({}))::text').format(
                        operator_weight) if measure=='SumAmount'
                        and operator_weight is not None else
                        sql.SQL('sum({})::text').format(placement_count_weight)
                        if measure=='CountPresent'
                        and placement_count_weight is not None
                        else sql.SQL(expression))
                    aggregate_select.append(sql.SQL('{} AS {}').format(
                        projected,sql.Identifier(alias)))
                security_profile = self._security_profile(dimensional_scope)
                security_join, security_filter, security_params, security_allowed = (
                    self._security_sql(security_profile, len(plan.input_dimensions)))
                source = sql.SQL('''FROM epm.numeric_cell_current n
                    JOIN epm.coordinate_projection p ON p.workspace_id=n.workspace_id
                      AND p.application_id=n.application_id AND p.coordinate_id=n.coordinate_id
                    {security_join}
                    WHERE n.workspace_id=%s AND n.application_id=%s AND n.present
                      AND p.fact_table_id='cube' AND p.schema_epoch=%s
                      {filters} {operator_filter}''').format(
                        security_join=security_join,
                        filters=(sql.SQL(' AND ')+sql.SQL(' AND ').join(predicates)
                                 if predicates else sql.SQL('')),
                        operator_filter=(sql.SQL(' AND ({})>0').format(
                            placement_count_weight)
                            if placement_count_weight is not None else
                            sql.SQL(' AND ({})<>0').format(operator_weight)
                            if operator_weight is not None
                            else sql.SQL('')))
                source_params = [*security_params, scope.workspace_id,
                                 scope.application_id, pins['schema_epoch'],
                                 *(sets[axis] for axis in sorted(sets))]
                if security_allowed is not None:
                    preflight = db.execute(sql.SQL('''SELECT
                        coalesce(bool_or(security.axis_count<>{dimensions}
                          OR security.found_count<>{dimensions}),false)
                          AS member_invalid,
                        coalesce(bool_or(security.cardinality_violation),false)
                          AS cardinality_invalid,
                        coalesce(bool_or(NOT ({allowed})),false) AS denied
                        {source}''').format(
                            dimensions=sql.Literal(len(plan.input_dimensions)),
                            allowed=security_allowed, source=source),
                        source_params).fetchone()
                    if preflight['member_invalid']:
                        raise ValueError('DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE')
                    if (preflight['cardinality_invalid'] and
                            security_profile['policy'].member_tag_cardinality is
                            MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED):
                        raise ValueError(
                            'MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION')
                    if (preflight['denied'] and
                            security_profile['policy'].mixed_selection is
                            MixedSelection.REJECT_ALL):
                        raise AccessDenied('DIMENSIONAL_SELECTION_REJECTED')
                query = sql.SQL('''SELECT {selects}
                    {source} {security_filter}
                    {group_by} {ordering} LIMIT %s''').format(
                        selects=sql.SQL(', ').join(group_select + aggregate_select),
                        source=source, security_filter=security_filter,
                        group_by=sql.SQL('GROUP BY ')+sql.SQL(', ').join(grouping) if grouping else sql.SQL(''),
                        ordering=sql.SQL('ORDER BY ')+sql.SQL(', ').join(grouping) if grouping else sql.SQL(''))
                params = [*source_params, max_groups+1]
                backend, profile = self._configure_backend(db, query, params)
                result = {'profile': profile, 'planDigest': plan.plan_digest,
                          'backend': backend, 'groupBy': list(plan.group_by),
                          'sourcePins': dict(pins), 'hierarchyStateTokens': hierarchy,
                          'layout': {'dimensions': list(plan.input_dimensions),
                                     'roles': dict(plan.dimension_roles),
                                     **({'operatorWeights': {
                                         axis:dict(weights) for axis,weights
                                         in plan.operator_weights}}
                                        if plan.operator_weights else {}),
                                     **({'placementWeights': {
                                         axis:{member:{'sumWeight':values[0],
                                                       'countWeight':values[1]}
                                               for member,values in weights}
                                         for axis,weights in plan.placement_weights}}
                                        if plan.placement_weights else {}),
                                     **({'hierarchyPins':dict(plan.hierarchy_pins)}
                                        if plan.hierarchy_pins else {})},
                          'rows': []}
                overhead = len(json.dumps(result, separators=(',', ':'), ensure_ascii=True).encode())
                size = overhead
                # Iterate only bounded aggregate output; no source-cell fetch or
                # Python amount arithmetic. SQL computes all exact aggregates.
                # A named portal prevents psycopg from buffering every output
                # group before the byte gate. At most16 aggregate rows are
                # prefetched; this is never a source-cell iterator.
                with _CancellationBridge(db,cancel_event):
                    with db.cursor(name='epm_cube_aggregate_output') as output:
                        output.itersize = 16
                        output.execute(query, params)
                        for row in output:
                            materialization_started = time.perf_counter()
                            if len(result['rows']) == max_groups:
                                raise ValueError('CUBE_AGGREGATE_GROUP_BUDGET')
                            item = {'members': {axis: row['g'+str(i)] for i, axis in enumerate(plan.group_by)}}
                            if 'SumAmount' in plan.measures:
                                item['sumAmount'] = row['sum_amount']
                            if 'CountPresent' in plan.measures:
                                item['countPresent'] = row['count_present']
                            if 'MinAmount' in plan.measures:
                                item['minAmount'] = row['min_amount']
                            if 'MaxAmount' in plan.measures:
                                item['maxAmount'] = row['max_amount']
                            size += len(json.dumps(item, separators=(',', ':'), ensure_ascii=True).encode()) + bool(result['rows'])
                            if size > max_result_bytes:
                                raise ValueError('CUBE_AGGREGATE_RESULT_BUDGET')
                            result['rows'].append(item)
                            materialization_seconds += (
                                time.perf_counter() - materialization_started)
                if size > max_result_bytes:
                    raise ValueError('CUBE_AGGREGATE_RESULT_BUDGET')
        # New RC snapshot catches revocation and metadata/policy/schema changes
        # during compute; data changes are allowed for this captured snapshot.
        self._authorize(scope, pins, dimensional_scope.scope_digest)
        if self._qualification_observer is not None:
            total_seconds = time.perf_counter() - compute_started
            self._qualification_observer({
                'databaseMs': max(0.0, total_seconds - materialization_seconds) * 1000,
                'materializationMs': materialization_seconds * 1000,
                'explainPlan': self._qualification_explain,
                'backendMarker': ('DuckDBScan' if self.backend_profile ==
                    'pg_duckdb_exact_sum_count_v1' else 'PostgreSQL'),
                'memoryLimitBytes': getattr(self, 'memory_bytes', None),
                'spillLimitBytes': getattr(self, 'spill_bytes', None)})
        return result


class CandidatePgDuckDbCubeAggregateStage(NativeCubeAggregateStage):
    """Private qualification stage; never selected by the public route.

    It deliberately uses the identical compiled SQL, transaction, scope and
    cancellation bridge as the native stage.  The candidate fails closed unless
    the pinned safety settings are visible and EXPLAIN proves DuckDBScan for the
    exact statement that will execute.
    """
    backend_profile = 'pg_duckdb_exact_sum_count_v1'
    compute_profile = 'cube-aggregate-pgduckdb-candidate-v1'
    memory_bytes = 256 * 1024 * 1024
    spill_bytes = 256 * 1024 * 1024

    def _configure_backend(self, db, query, params):
        db.execute('SET LOCAL duckdb.force_execution=true')
        db.execute('SET LOCAL duckdb.max_workers_per_postgres_scan=0')
        db.execute('SET LOCAL duckdb.threads_for_postgres_scan=1')
        db.execute("SET LOCAL duckdb.max_memory='256MB'")
        db.execute("SET LOCAL duckdb.max_temp_directory_size='256MB'")
        rows = db.execute("""SELECT name,setting FROM pg_settings WHERE name IN
            ('duckdb.enable_external_access','duckdb.autoinstall_known_extensions',
             'duckdb.autoload_known_extensions','duckdb.convert_unsupported_numeric_to_double',
             'duckdb.max_workers_per_postgres_scan','duckdb.threads_for_postgres_scan',
             'duckdb.max_memory','duckdb.max_temp_directory_size')""").fetchall()
        settings = {row['name']: row['setting'] for row in rows}
        expected = {'duckdb.enable_external_access': 'off',
            'duckdb.autoinstall_known_extensions': 'off',
            'duckdb.autoload_known_extensions': 'off',
            'duckdb.convert_unsupported_numeric_to_double': 'off',
            'duckdb.max_workers_per_postgres_scan': '0',
            'duckdb.threads_for_postgres_scan': '1'}
        bounded = db.execute("""SELECT
            pg_size_bytes(current_setting('duckdb.max_memory')) AS memory_bytes,
            pg_size_bytes(current_setting('duckdb.max_temp_directory_size')) AS spill_bytes""").fetchone()
        if (any(settings.get(key) != value for key, value in expected.items())
                or set(settings) != set(expected) | {
                    'duckdb.max_memory', 'duckdb.max_temp_directory_size'}
                or not bounded
                or bounded['memory_bytes'] > self.memory_bytes
                or bounded['spill_bytes'] > self.spill_bytes
                or bounded['memory_bytes'] <= 0 or bounded['spill_bytes'] <= 0):
            raise ValueError('PGDUCKDB_CANDIDATE_SETTINGS_UNSAFE')
        explained = db.execute(sql.SQL('EXPLAIN (COSTS OFF) ')+query,
                               params).fetchall()
        plan = '\n'.join(str(value) for row in explained for value in row.values())
        if 'DuckDBScan' not in plan:
            raise ValueError('PGDUCKDB_CANDIDATE_NOT_SELECTED')
        self._qualification_explain = plan
        return self.backend_profile, self.compute_profile
