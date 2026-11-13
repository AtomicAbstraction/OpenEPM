"""Authorized structural coverage of one explicit mixed-method direct scope."""
from __future__ import annotations

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_method_coverage import (
    FUNCTION, compile_coverage, coverage_digest)
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_consolidation_assess import PostgresConsolidationAssessment
from .postgres_equity_method_publication import (
    context_status as equity_context_status,
    source_status as equity_source_status)
from .postgres_proportional_publication import (
    context_status as proportional_context_status,
    source_status as proportional_source_status)
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


_FUNCTION_BY_METHOD = {
    'Full': 'consolidation.full.contribute',
    'Equity': 'consolidation.equity.contribution.publish',
    'Proportional': 'consolidation.proportional.contribution.publish'}


class PostgresConsolidationMethodCoverage:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, program: dict) -> dict:
        plan = compile_coverage(program)
        assessment = PostgresConsolidationAssessment(
            self.dsn, identity=self.identity).preview_method(
                scope, plan['methodPreviewProgram'])
        if assessment.get('previewDigest') != plan['expectedMethodPreviewDigest']:
            raise ValueError('METHOD_COVERAGE_PREVIEW_STALE')
        expected = {row['relationshipId']: row
                    for row in assessment['placements']
                    if row['method'] != 'None'}
        pins = {row['relationshipId']: row for row in plan['publicationPins']}
        if set(expected) != set(pins):
            raise ValueError('METHOD_COVERAGE_SCOPE_MISMATCH')
        rows = []
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=FUNCTION)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                preview_args = plan['methodPreviewProgram']['arguments']
                if (state is None
                        or state['metadata_revision'] !=
                            preview_args['expectedMetadataRevision']
                        or state['policy_revision'] !=
                            preview_args['expectedPolicyRevision']
                        or state['commit_revision'] !=
                            preview_args['expectedCommitRevision']
                        or state['data_revision'] != plan['expectedDataRevision']):
                    raise ValueError('METHOD_COVERAGE_REVISION_STALE')
                for relationship_id in sorted(expected):
                    placement, pin = expected[relationship_id], pins[relationship_id]
                    if (placement['method'] != pin['method']
                            or placement['issues']):
                        raise ValueError('METHOD_COVERAGE_METHOD_UNAVAILABLE')
                    rows.append(self._resolve_pin(
                        db, scope, assessment, placement, pin))
                units = {(row['outputUnit']['dimensionId'],
                          row['outputUnit']['memberId']) for row in rows}
                if len(units) > 1:
                    raise ValueError('METHOD_COVERAGE_CURRENCY_MISMATCH')
                after = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if after != state:
                    raise ValueError('METHOD_COVERAGE_REVISION_STALE')
        digest = coverage_digest(plan, rows)
        return {'parentEntityId': assessment['parentEntityId'],
                'scenarioId': assessment['scenarioId'],
                'yearId': assessment['yearId'],
                'periodId': assessment['periodId'],
                'placements': rows, 'placementCount': len(rows),
                'complete': True, 'coverageDigest': digest,
                'statementPackSources': [row['statementPackSource'] for row in rows],
                'accountingPolicyStatus': 'Unreviewed',
                'structuralOnly': True, 'wholeStatementCertified': False,
                'effects': 'None'}

    def _resolve_pin(self, db, scope, assessment, placement, pin):
        keys = (scope.workspace_id, scope.application_id)
        typed = pin['method'] != 'Full' or 'currencyDimensionId' in pin
        expected_function=('consolidation.full.typed.contribute'
            if pin['method']=='Full' and typed else
            _FUNCTION_BY_METHOD[pin['method']])
        table = ('calculation_unit_result_current' if typed
                 else 'calculation_result_current')
        unit_sql = ('''AND r.output_unit_currency_dimension_id=%s
                       AND r.output_unit_currency_member_id=%s''' if typed else '')
        unit_params = ((pin['currencyDimensionId'], pin['currencyMemberId'])
                       if typed else ())
        found = db.execute(f'''SELECT p.state_token,p.content_digest,
            p.source_function AS function_name,p.source_metadata_revision,
            p.source_policy_revision,
            j.status,j.normalized_program,j.expected_metadata_revision,
            j.expected_data_revision,j.expected_policy_revision,j.result,
            o.result AS receipt_result,c.members,r.amount
            FROM epm.calculation_result_state p
            JOIN epm.job j ON j.workspace_id=p.workspace_id
             AND j.application_id=p.application_id
             AND j.job_id=p.source_operation_id
            JOIN epm.operation_receipt o ON o.workspace_id=p.workspace_id
             AND o.application_id=p.application_id
             AND o.operation_id=p.source_operation_id
            JOIN epm.{table} r ON r.workspace_id=p.workspace_id
             AND r.application_id=p.application_id
             AND r.result_key=p.result_key
            JOIN epm.coordinate c ON c.workspace_id=r.workspace_id
             AND c.application_id=r.application_id
             AND c.coordinate_id=r.coordinate_id
            WHERE p.workspace_id=%s AND p.application_id=%s
              AND p.result_key=%s AND p.state_token=%s {unit_sql}
            ORDER BY c.series_key LIMIT 2''', (*keys, pin['resultKey'],
            pin['resultStateToken'], *unit_params)).fetchall()
        if len(found) != 1:
            raise ValueError('METHOD_COVERAGE_PUBLICATION_UNAVAILABLE')
        row = found[0]; receipt = row['receipt_result']
        publication_context = self._publication_context(
            pin['method'], row['normalized_program'])
        if (row['function_name'] != expected_function
                or row['status'] != 'published'
                or not isinstance(receipt, dict)
                or receipt.get('relationshipId') != pin['relationshipId']
                or receipt.get('parentEntityId') != assessment['parentEntityId']
                or receipt.get('childEntityId') != placement['childEntityId']
                or publication_context != {
                    'relationshipId': pin['relationshipId'],
                    'scenarioId': assessment['scenarioId'],
                    'yearId': assessment['yearId'],
                    'periodId': assessment['periodId'],
                    'effectiveOn': assessment['effectiveOn'],
                    'policyId': assessment['policyId'],
                    'policyStateToken': assessment['policyStateToken'],
                    'policyDigest': assessment['policyDigest']}
                or row['source_metadata_revision'] !=
                    row['expected_metadata_revision']
                or row['source_policy_revision'] !=
                    row['expected_policy_revision']):
            raise ValueError('METHOD_COVERAGE_PUBLICATION_MISMATCH')
        source_status = context_status = {'matchesAtRead': True}
        if pin['method'] == 'Equity':
            source_status = equity_source_status(db, scope, receipt)
            context_status = equity_context_status(
                db, scope, row['normalized_program'], receipt)
        elif pin['method'] == 'Proportional':
            source_status = proportional_source_status(db, scope, receipt)
            context_status = proportional_context_status(
                db, scope, row['normalized_program'], receipt)
        else:
            if typed:
                from .postgres_consolidation_full import typed_full_context_status
                context_status=typed_full_context_status(
                    db,scope,row['normalized_program'],receipt)
                source_status=(context_status.get('sourceStatus')
                    if receipt.get('sourceLayer')=='raw_plus_ic_elimination'
                    else self._full_source_status(db,scope,receipt))
            else:
                source_status = self._full_source_status(db, scope, receipt)
        if not source_status['matchesAtRead'] or not context_status['matchesAtRead']:
            raise ValueError('METHOD_COVERAGE_SOURCE_STALE')
        source = {'sourceId': 'method-' + pin['relationshipId'],
                  'sourceKind': 'TypedUnitAmount' if typed else 'CalculationAmount',
                  'members': row['members'], 'resultKey': pin['resultKey'],
                  'resultStateToken': pin['resultStateToken']}
        if typed:
            source.update({'currencyDimensionId': pin['currencyDimensionId'],
                           'currencyMemberId': pin['currencyMemberId']})
        output_unit = ({'dimensionId': pin['currencyDimensionId'],
                        'memberId': pin['currencyMemberId']} if typed else
                       self._full_output_unit(db, scope, receipt))
        return {'relationshipId': pin['relationshipId'],
                'childEntityId': placement['childEntityId'],
                'method': pin['method'], 'amount': format(row['amount'], '.8f'),
                'outputUnit': output_unit,
                'sourceStatus': source_status,
                'contextStatus': context_status,
                'statementPackSource': source}

    @staticmethod
    def _full_source_status(db, scope, receipt):
        try:
            coordinate = Coordinate.from_mapping(receipt['sourceMembers'])
            expected_change = receipt['sourceChangeId']
        except (KeyError, TypeError, ValueError):
            return {'matchesAtRead': False}
        row = db.execute('''SELECT n.present,n.change_id,c.members
            FROM epm.coordinate c LEFT JOIN epm.numeric_cell_current n USING
              (workspace_id,application_id,coordinate_id)
            WHERE c.workspace_id=%s AND c.application_id=%s
              AND c.series_key=%s''', (scope.workspace_id,
            scope.application_id, coordinate.series_key)).fetchone()
        return {'matchesAtRead': bool(row and row['present']
            and row['members'] == dict(coordinate.members)
            and row['change_id'] == expected_change),
            'sourceChangeId': expected_change}

    @staticmethod
    def _publication_context(method, normalized):
        try:
            args = (normalized if method == 'Full'
                    else normalized['previewProgram']['arguments'])
            if method != 'Full':
                method_args = args['methodPreviewProgram']['arguments']
                policy = {'policyId': method_args['policyId'],
                          'policyStateToken': method_args['policyStateToken'],
                          'policyDigest': method_args['policyDigest']}
            else:
                method_args = args
                policy = {'policyId': args['policy']['policyId'],
                          'policyStateToken': args['policy']['stateToken'],
                          'policyDigest': args['policy']['digest']}
            return {'relationshipId': args['relationshipId'],
                    'scenarioId': method_args['scenarioId'],
                    'yearId': method_args['yearId'],
                    'periodId': method_args['periodId'],
                    'effectiveOn':(args['policy']['effectiveOn']
                        if method=='Full' else method_args['effectiveOn']),
                    **policy}
        except (KeyError, TypeError):
            return None

    @staticmethod
    def _full_output_unit(db, scope, receipt):
        try:
            target = receipt['targetMembers']
        except (KeyError, TypeError):
            raise ValueError('METHOD_COVERAGE_FULL_UNIT_UNAVAILABLE') from None
        rows = db.execute('''SELECT e.dimension_id AS entity_dimension_id,
            c.dimension_id AS currency_dimension_id,
            m.entity_default_currency_member_id AS currency_member_id
            FROM epm.dimension e JOIN epm.dimension c
              ON c.workspace_id=e.workspace_id
             AND c.application_id=e.application_id
             AND c.model_role='Currency' AND c.status='Active'
            JOIN epm.member m ON m.workspace_id=e.workspace_id
             AND m.application_id=e.application_id
             AND m.dimension_id=e.dimension_id
             AND m.member_id=%s::jsonb->>e.dimension_id AND m.status='Active'
            WHERE e.workspace_id=%s AND e.application_id=%s
              AND e.model_role='Entity' AND e.status='Active'
            ORDER BY e.dimension_id,c.dimension_id LIMIT 2''',
            (Jsonb(target), scope.workspace_id, scope.application_id)).fetchall()
        if (len(rows) != 1 or not rows[0]['currency_member_id']):
            raise ValueError('METHOD_COVERAGE_FULL_UNIT_UNAVAILABLE')
        return {'dimensionId': rows[0]['currency_dimension_id'],
                'memberId': rows[0]['currency_member_id']}
