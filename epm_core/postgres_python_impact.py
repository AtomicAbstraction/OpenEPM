"""Private rule effects evaluated by the same fixed kernels as publication.

Fact reads use a read-only repeatable-read transaction; authorization is checked
through a separate read-only READ COMMITTED transaction. A bounded in-memory
fact provider carries earlier proposed effects between units; it never calls a
publisher, creates an application, or modifies a database fact. Unsupported
units fail preflight before any computation is reported as a complete test.
"""
from __future__ import annotations

from contextlib import ExitStack
from decimal import Decimal, localcontext
import json
import time

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_cube_query import PostgresCubeQuery
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_fact_batch import numeric_inputs
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .python_plan_runner import SealedPlanRunner
from .python_program_execution import SealedPlan

FORMAT = 'openepm-python-impact-v1'
MAX_CELLS = 10_000
MAX_UNITS = 500
MAX_VISITS = 100_000
MAX_BYTES = 16 * 1024 * 1024
MAX_SECONDS = 20
SUPPORTED = frozenset(('facts.numeric.transform', 'facts.numeric.sequence',
                       'facts.numeric.batch', 'facts.text.batch',
                       'facts.line-detail.replace', 'facts.composite.batch',
                       'facts.expression.calculate'))
READONLY_DEFINITIONS = frozenset(('calculated.member.save',))


def catalog_limits():
    """Describe the evaluator actually used by browser and MCP Test requests."""
    from .postgres_python_expression_impact import SUPPORTED_NODES
    from .expression_apportionment import (COMPILER as APPORTIONMENT_COMPILER,
        RELATION_COMPILER as RELATION_APPORTIONMENT_COMPILER,
        MAX_COMPONENTS, MAX_FORMULAS, MAX_INPUTS, MAX_TARGETS,
        MAX_CONTRIBUTIONS, MAX_RESULT_BYTES)
    return {'cells': MAX_CELLS, 'units': MAX_UNITS, 'statementVisits': MAX_VISITS,
            'resultBytes': MAX_BYTES, 'impactSeconds': MAX_SECONDS,
            'supported': sorted(SUPPORTED),
            'readOnlyDefinitions': sorted(READONLY_DEFINITIONS),
            'expressionNodes': sorted(SUPPORTED_NODES),
            'apportionment': {'profile': APPORTIONMENT_COMPILER,
                'maxComponents': MAX_COMPONENTS, 'maxInputs': MAX_INPUTS, 'maxTargets': MAX_TARGETS,
                'maxContributions': MAX_CONTRIBUTIONS, 'maxPreparedResultBytes': MAX_RESULT_BYTES, 'componentReference': 'ComponentAmount (local DAG only)',
                'resultLayer': 'calculation', 'rounding': 'declared quantum; exact largest remainder'},
            'groupedRelationApportionment': {
                'profile': RELATION_APPORTIONMENT_COMPILER,
                'maxRelationRows': 100000, 'maxBusinessGroups': 10000,
                'maxFormulaShapes': MAX_FORMULAS,
                'clientWorkControls': False,
                'resultLayer': 'calculation',
                'rounding': 'relation-declared quantum; exact largest remainder'},
            'expressionScope': 'bounded existing numeric facts, typed present raw lookups and exact same-currency current or earlier private published inputs; fixed compiler shape, type, authority, freshness and result limits also apply',
            'unsupported': 'rejected before evaluation; no partial success'}


def _amount(value):
    return None if value is None else format(Decimal(value), '.8f')


def _cell(row,detail=None):
    if row['text_present']:
        return {'present':True,'kind':'text','text':row['text_value'],'amount':None}
    cell={'present':row['present'],
          'amount':_amount(row['amount']) if row['present'] else None}
    if detail is not None:
        cell.update(kind='line-detail',items=[dict(item) for item in detail['items']])
    return cell


def _delta(before, after):
    if before.get('kind')=='text' or after.get('kind')=='text':return None
    with localcontext() as context:
        context.prec = 80
        return format(Decimal(after['amount'] or '0') -
                      Decimal(before['amount'] or '0'), '.8f')


def _counts(rows):
    return {'selected': len(rows),
        'changed': sum(row['before'] != row['after'] for row in rows),
        'created': sum(not row['before']['present'] and row['after']['present']
                       for row in rows),
        'cleared': sum(row['before']['present'] and not row['after']['present']
                       for row in rows)}


def validate_impact_size(value):
    if len(json.dumps(value, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode('ascii')) > MAX_BYTES:
        raise ValueError('PYTHON_IMPACT_RESULT_BYTE_LIMIT')


class PrivateFactState:
    """Trusted bounded provider for existing numeric/text/detail kernels."""

    def __init__(self, snapshot_db=None, snapshot_revision=None):
        self.snapshot_db = snapshot_db
        self.snapshot_revision = snapshot_revision
        self.original = {}
        self.current = {}
        self.original_details = {}
        self.current_details = {}
        self.members = {}
        self.steps = {}
        self.visits = 0
        self.calculations = {}

    def numeric_inputs(self, db, scope, rows):
        source = numeric_inputs(self.snapshot_db or db, scope, rows)
        if len(source) != len(rows):
            raise ValueError('PYTHON_IMPACT_INPUT_SHAPE_INVALID')
        declared_rows = {row['series_key']: row for row in rows}
        if (len(declared_rows) != len(source)
                or {row['series_key'] for row in source} != set(declared_rows)):
            raise ValueError('PYTHON_IMPACT_INPUT_SHAPE_INVALID')
        result = []
        for row in source:
            key = row['series_key']
            declared = declared_rows[key]
            # Keep the real coordinate identity and detail/type flags. The
            # shared preparation code remains responsible for checking them.
            if key not in self.original:
                if len(self.original) >= MAX_CELLS:
                    raise ValueError('PYTHON_IMPACT_CELL_LIMIT')
                self.original[key] = dict(row)
                self.members[key] = dict(declared['members'])
            if self.members[key] != declared['members']:
                raise ValueError('COORDINATE_HASH_COLLISION')
            result.append(dict(self.current.get(key, row)))
        return result

    def detail_inputs(self,db,scope,coordinate):
        from .postgres_fact_batch import validate_coordinates
        declared={'ordinal':1,'series_key':coordinate.series_key,
                  'members':dict(coordinate.members)}
        validate_coordinates(db,scope,[declared])
        current=self.numeric_inputs(db,scope,[declared])[0]
        key=coordinate.series_key
        if key not in self.original_details:
            source=self.snapshot_db or db
            original=self.original[key]
            detail=(None if original['coordinate_id'] is None else source.execute(
                """SELECT items,total,change_id FROM epm.line_detail_current
                 WHERE workspace_id=%s AND application_id=%s AND coordinate_id=%s""",
                (scope.workspace_id,scope.application_id,original['coordinate_id'])).fetchone())
            self.original_details[key]=None if detail is None else dict(detail)
        detail=self.current_details.get(key,self.original_details[key])
        cell=(None if not current['present'] and not current['change_id'] else
              {name:current[name] for name in ('present','amount','change_id')})
        return current['coordinate_id'],current['text_present'],cell,detail

    def cell(self,key,*,original=False):
        if original:return _cell(self.original[key],self.original_details.get(key))
        return _cell(self.current.get(key,self.original[key]),
                     self.current_details.get(key,self.original_details.get(key)))

    def select_existing_facts(self, db, scope, *, member_sets,
                              snapshot_revision, limit):
        # Cleared original cells may occupy early positions in the base page.
        # Overfetch by the bounded overlay so that removal cannot hide a later
        # match. Both the source and union remain bounded.
        revision = (snapshot_revision if self.snapshot_revision is None
                    else self.snapshot_revision)
        source = PostgresCubeQuery._page(self.snapshot_db or db, scope, {}, '', revision,
            revision, False, limit + len(self.current),
            member_sets=member_sets)
        rows = {row['seriesKey']: row for row in source}
        for key, state in self.current.items():
            members = self.members[key]
            if not all(members.get(axis) in selected
                       for axis, selected in member_sets.items()):
                continue
            if not state['present']:
                if state['text_present']:
                    # Clearing numeric absence does not clear existing text.
                    rows[key] = {'seriesKey': key, 'members': members,
                        'kind': 'text', 'present': True, 'amount': None,
                        'text': state['text_value'],
                        'changeId': state['text_change_id'],
                        'numericChangeId': state['change_id'],
                        'textChangeId': state['text_change_id'],
                        'lastRevision': None}
                else:
                    rows.pop(key, None)
                continue
            rows[key] = {'seriesKey': key, 'members': members,
                'kind': 'numeric', 'present': True, 'amount': _amount(state['amount']),
                'text': None, 'changeId': state['change_id'],
                'numericChangeId': state['change_id'],
                'textChangeId': state['text_change_id'], 'lastRevision': None}
        return [rows[key] for key in sorted(rows)[:limit]]

    def apply(self, normalized, trace, *, unit, revision):
        statements=normalized['statements']
        if len(statements)!=len(trace):raise ValueError('PYTHON_IMPACT_TRACE_INVALID')
        self.visits+=len(statements)
        if self.visits>MAX_VISITS:raise ValueError('PYTHON_IMPACT_VISIT_LIMIT')
        before={}
        family=normalized['function']
        for row,effect in zip(statements,trace,strict=True):
            key=row['series_key']
            if row['ordinal']!=effect['ordinal'] or key not in self.original:
                raise ValueError('PYTHON_IMPACT_TRACE_INVALID')
            prior=self.current.get(key,self.original[key])
            before.setdefault(key,self.cell(key))
            change_id=f"{revision}:{row['ordinal']}"
            if family=='facts.text.batch':
                self.current[key]={**prior,'text_present':row['op']=='set',
                    'text_value':row['value'] if row['op']=='set' else None,
                    'text_change_id':change_id}
            elif family=='facts.line-detail.replace':
                amount=Decimal(effect['amount'])
                self.current[key]={**prior,'present':True,'amount':amount,
                    'has_detail':True,'change_id':change_id}
                self.current_details[key]={'items':[dict(item) for item in effect['items']],
                    'total':amount,'change_id':change_id}
            else:
                amount=effect['amount']
                self.current[key]={**prior,'present':amount is not None,
                    'amount':Decimal(amount) if amount is not None else None,
                    'change_id':change_id}
            self.steps.setdefault(key,[]).append(unit)
        return [{'seriesKey':key,'members':self.members[key],
                 'before':before[key],'after':self.cell(key),
                 'delta':_delta(before[key],self.cell(key))} for key in sorted(before)]

    def final_rows(self):
        from .postgres_python_expression_impact import final_rows
        return [{'seriesKey':key,'members':self.members[key],
                 'before':self.cell(key,original=True),
                 'beforeChangeId':(self.original[key]['text_change_id']
                    if self.original[key]['text_present'] else self.original[key]['change_id']),
                 **({'beforeDetailChangeId':(self.original_details[key]['change_id']
                    if self.original_details.get(key) is not None else '')}
                    if key in self.original_details else {}),
                 'after':self.cell(key),
                 'delta':_delta(self.cell(key,original=True),self.cell(key)),
                 'units':sorted(set(self.steps[key]))} for key in sorted(self.current)]+final_rows(self)


class PostgresPythonImpactEvaluator:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not dsn or not isinstance(identity, VerifiedIdentity):
            raise ValueError('PYTHON_IMPACT_CONFIGURATION_INVALID')
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def preflight(plan: SealedPlan, *, definition_parameters=None,
                  resolved_bindings=None):
        units = SealedPlanRunner._units(plan)
        from .postgres_python_definitions import descriptor
        target=descriptor(plan.canonical_plan)
        parameters={} if definition_parameters is None else definition_parameters
        if type(parameters) is not dict:
            raise ValueError('PYTHON_DEFINITION_PARAMETERS_INVALID')
        if target is None and parameters:
            raise ValueError('PYTHON_DEFINITION_PARAMETERS_UNEXPECTED')
        if target is not None and target['kind']=='ApplicationRule':
            from .postgres_application_rules import bind_definition
            definition=units[0]['operations'][0]['arguments']['definition']
            bound,_=bind_definition(definition,parameters,resolved_bindings=resolved_bindings)
            units=bound['units']
        if len(units) > MAX_UNITS:
            raise ValueError('PYTHON_IMPACT_UNIT_LIMIT')
        operations = [SealedPlanRunner._atomic_operation(unit) for unit in units]
        supported=(READONLY_DEFINITIONS if target is not None
                   and target['kind']=='CalculatedMember' else SUPPORTED)
        for operation in operations:
            if operation['function'] not in supported:
                raise ValueError('PYTHON_IMPACT_FUNCTION_UNSUPPORTED')
            if operation['function']=='facts.expression.calculate':
                from .postgres_python_expression_impact import compile_private
                compile_private(operation)
        return units, operations

    def evaluate(self, scope: ApplicationScope, plan: SealedPlan, *,
                 metadata_revision: int, policy_revision: int, schema_epoch: int,
                 definition_parameters=None):
        started = time.monotonic()
        SealedPlanRunner._units(plan)
        from .postgres_python_definitions import descriptor
        definition=descriptor(plan.canonical_plan)
        parameters={} if definition_parameters is None else definition_parameters
        if type(parameters) is not dict:
            raise ValueError('PYTHON_DEFINITION_PARAMETERS_INVALID')
        with ExitStack() as stack:
            db = stack.enter_context(connect_postgres(self.dsn, row_factory=dict_row))
            snapshot = stack.enter_context(connect_postgres(self.dsn, row_factory=dict_row))
            # A selected-domain impact test writes only to this session-local
            # relation. Create it before opening the repeatable-read, read-only
            # business-data snapshot; rows can then be replaced inside that
            # snapshot without granting writes to application tables.
            snapshot.autocommit = True
            snapshot.execute('''CREATE TEMP TABLE IF NOT EXISTS
                epm_selected_domain_member(dimension_id text NOT NULL,
                member_id text NOT NULL,PRIMARY KEY(dimension_id,member_id))
                ON COMMIT PRESERVE ROWS''')
            snapshot.autocommit = False
            stack.enter_context(snapshot.transaction())
            snapshot.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            configure_statement_timeout(snapshot, 5000)
            PostgresNumericFactStore._set_scope(snapshot, scope)
            with db.transaction():
                # Identity/grants must be rechecked at READ COMMITTED. Only
                # business fact reads use the separate MVCC snapshot; current
                # metadata/authority pins are checked around the evaluation.
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(db,
                    self.identity, scope, 'rule_design', function='python.program.test')
                state = snapshot.execute('''SELECT s.metadata_revision,s.policy_revision,
                    s.data_revision,s.commit_revision,s.schema_epoch,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (state is None or state['status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if tuple(state[k] for k in ('metadata_revision', 'policy_revision',
                        'schema_epoch')) != (metadata_revision, policy_revision, schema_epoch):
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                authority = resolve_effective_dimensional_scope(db, self.identity,
                    scope, access=access, function='python.program.test').scope_digest
                resolved_bindings=None
                definition_result=definition
                if definition is not None and definition['kind']=='ApplicationRule':
                    from .postgres_application_rules import PostgresApplicationRules,bind_definition
                    rule=plan.canonical_plan['units'][0]['operations'][0]['arguments']['definition']
                    resolved_bindings,member_list_pins=PostgresApplicationRules(
                        self.dsn,identity=self.identity)._resolve_member_list_bindings(
                            scope,rule,parameters,metadata_revision=metadata_revision)
                    _,bindings=bind_definition(rule,parameters,resolved_bindings=resolved_bindings)
                    definition_result={**definition,'bindings':bindings,
                        **({'memberListPins':list(member_list_pins)} if member_list_pins else {})}
                units,operations=self.preflight(plan,definition_parameters=parameters,
                                               resolved_bindings=resolved_bindings)
                private = PrivateFactState(snapshot, state['commit_revision'])
                steps = []
                for index, (unit, operation) in enumerate(zip(units, operations, strict=True), 1):
                    if time.monotonic() - started > MAX_SECONDS:
                        raise ValueError('PYTHON_IMPACT_TIME_LIMIT')
                    if operation['function'] in READONLY_DEFINITIONS:
                        from .postgres_python_definition_impact import evaluate_readonly_definition
                        evaluated=evaluate_readonly_definition(db,snapshot,scope,operation,
                            self.identity,parameters)
                        definition_result=evaluated['definitionResult']
                        rows=[]
                    else:
                        current_access = PostgresAccessChecker.check_in_transaction(db,
                            self.identity, scope, 'write', function=operation['function'],
                            arguments=operation['arguments'])
                        rows=self._evaluate_unit(db,scope,operation,private,current_access.role,
                            unit=index,revision=state['commit_revision']+index)
                    steps.append({'unit': index, 'name': unit['name'],
                        'function': operation['function'], 'status': 'evaluated',
                        'commitBoundary': index, 'counts': _counts(rows), 'rows': rows})
                    validate_impact_size(steps)
                current_access = PostgresAccessChecker.check_in_transaction(db,
                    self.identity, scope, 'rule_design', function='python.program.test')
                current = db.execute('''SELECT s.metadata_revision,s.policy_revision,
                    s.schema_epoch,s.processing_mode,a.status
                    FROM epm.application_state s JOIN epm.application a
                    USING(workspace_id,application_id)
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (current is None or current['status'] != 'Active'
                        or current['processing_mode'] != 'Active'
                        or tuple(current[key] for key in ('metadata_revision',
                            'policy_revision', 'schema_epoch')) !=
                           (metadata_revision, policy_revision, schema_epoch)):
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                if resolve_effective_dimensional_scope(db, self.identity, scope,
                        access=current_access, function='python.program.test').scope_digest != authority:
                    raise ValueError('PYTHON_IMPACT_AUTHORIZATION_CHANGED')
                rows = private.final_rows()
                result = {'format': FORMAT, 'status': 'complete',
                    'planDigest': plan.digest, 'compilerVersion': plan.compiler_version,
                    'baseline': {key: state[key] for key in ('metadata_revision',
                        'data_revision', 'policy_revision', 'commit_revision', 'schema_epoch')},
                    'authorizationScopeDigest': authority, 'counts': _counts(rows),
                    'statementVisits': private.visits, 'rows': rows, 'units': steps,
                    'businessDataChanged': False}
                if definition_result is not None:
                    result['definitionResult']=definition_result
                validate_impact_size(result)
                if time.monotonic() - started > MAX_SECONDS:
                    raise ValueError('PYTHON_IMPACT_TIME_LIMIT')
                return result

    def _evaluate_unit(self,db,scope,operation,private,role,*,unit,revision):
        if operation['function']=='facts.expression.calculate':
            from .postgres_python_expression_impact import evaluate
            return evaluate(db,scope,operation,private,self.identity,role,unit=unit)
        if operation['function']=='facts.composite.batch':
            return self._evaluate_composite(db,scope,operation,private,role,
                                           unit=unit,revision=revision)
        normalized,trace=self._evaluate_operation(db,scope,operation,private,role)
        return private.apply(normalized,trace,unit=unit,revision=revision)

    def _prepare_detail(self,db,scope,values,private,role,*,ordinal=1,policy=True):
        from .postgres_line_detail import PostgresLineDetailStore,prepare_detail_items
        from .postgres_numeric_sequence import enforce_sequence_dimensional_security
        from .postgres_planning_write_guard import enforce_active_planning_policy
        coordinate,items,cell_change,detail_change=values
        normalized={'function':'facts.line-detail.replace','statements':[{
            'ordinal':ordinal,'series_key':coordinate.series_key,
            'members':dict(coordinate.members)}]}
        enforce_sequence_dimensional_security(db,self.identity,scope,normalized)
        current=private.detail_inputs(db,scope,coordinate)
        PostgresLineDetailStore._validate_inputs(current,cell_change,detail_change)
        total,encoded=prepare_detail_items(items)
        if policy:enforce_active_planning_policy(db,scope,
            writes=((coordinate,'ReplaceDetail'),),workflow_role=role)
        return normalized,[{'ordinal':ordinal,'amount':_amount(total),'items':encoded}]

    def _evaluate_composite(self,db,scope,operation,private,role,*,unit,revision):
        from .postgres_composite_fact_batch import (compile_program,_prepare_composite,
                                                    ordered_operations)
        from .postgres_numeric_sequence import enforce_sequence_dimensional_security
        from .postgres_numeric_batch import prepare as numeric_prepare
        from .postgres_text_batch import prepare as text_prepare
        plan=compile_program(operation)
        decoded,_,_=_prepare_composite(db,scope,plan,role,fact_state=private)
        combined={}
        for family,values,offset in ordered_operations(decoded,revision):
            if family=='facts.line-detail.replace':
                normalized,trace=self._prepare_detail(db,scope,values,private,role,
                                                      ordinal=offset+1,policy=False)
            else:
                prepare=numeric_prepare if family=='facts.numeric.batch' else text_prepare
                trace=prepare(db,scope,values,ordinal_offset=offset,fact_state=private)
                normalized={'function':family,'statements':trace}
                enforce_sequence_dimensional_security(db,self.identity,scope,normalized)
            for row in private.apply(normalized,trace,unit=unit,revision=revision):
                key=row['seriesKey']
                if key not in combined:combined[key]=row
                else:
                    combined[key]['after']=row['after']
                    combined[key]['delta']=_delta(combined[key]['before'],row['after'])
        return [combined[key] for key in sorted(combined)]

    def _evaluate_operation(self, db, scope, operation, private, role):
        from .postgres_numeric_sequence import (compile_program, initial_state,
            evaluate_from_initial, enforce_sequence_dimensional_security,
            enforce_sequence_target_policy)
        if operation['function']=='facts.text.batch':
            from .postgres_language_v2 import compile_text_program
            from .postgres_text_batch import prepare
            values=compile_text_program(operation)
            rows=prepare(db,scope,values,fact_state=private)
            normalized={'function':'facts.text.batch','statements':rows}
            enforce_sequence_dimensional_security(db,self.identity,scope,normalized)
            enforce_sequence_target_policy(db,scope,normalized,role)
            return normalized,rows
        if operation['function']=='facts.line-detail.replace':
            from .postgres_line_detail_job import compile_program as compile_detail
            return self._prepare_detail(db,scope,compile_detail(operation),private,role)
        if operation['function'] == 'facts.numeric.transform':
            from .postgres_numeric_transform import compile_program as compile_transform, prepare
            candidate = prepare(db, scope, compile_transform(operation), identity=self.identity,
                                workflow_role=role, fact_state=private)
            return candidate['normalized'], candidate['trace']
        if operation['function'] == 'facts.numeric.batch':
            from .postgres_language_v2 import compile_numeric_program
            from .postgres_numeric_batch import prepare
            mutations = compile_numeric_program(operation)
            rows = prepare(db, scope, mutations, fact_state=private)
            normalized = {'function': 'facts.numeric.sequence', 'statements': rows}
            enforce_sequence_dimensional_security(db, self.identity, scope, normalized)
            enforce_sequence_target_policy(db, scope, normalized, role)
            # Batch publication uses the same preparation rows directly.
            return normalized, rows
        normalized = compile_program(operation)
        enforce_sequence_dimensional_security(db, self.identity, scope, normalized)
        initial = initial_state(db, scope, normalized, fact_state=private)
        enforce_sequence_target_policy(db, scope, normalized, role)
        return normalized, evaluate_from_initial(db, normalized, initial)
