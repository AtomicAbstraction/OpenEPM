"""Read-only NCI candidate attribution for a pinned translated Full source.

This deliberately does not produce a journal or a published calculation.
Eligibility of an Account as net assets or period profit, acquisition-date
measurement, goodwill and presentation require an approved policy pack.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, NumericCell
from .current_object_contract import require_state_token
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_calculation_status import published_translation_status
from .postgres_consolidation_translated import decode_translated_full
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'consolidation.nci.attribution.inspect'
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


class PostgresNciAttributionInspector:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)):
            raise ValueError('NCI_INSPECT_PROGRAM_INVALID')
        args = program['arguments']
        if (set(args) != {'resultKey', 'resultStateToken', 'relationshipId'}
                or not isinstance(args['resultKey'], str)
                or not _KEY.fullmatch(args['resultKey'])
                or not isinstance(args['relationshipId'], str)
                or not 1 <= len(args['relationshipId']) <= 200
                or args['relationshipId'] != args['relationshipId'].strip()
                or '\x00' in args['relationshipId']):
            raise ValueError('NCI_INSPECT_ARGUMENTS_INVALID')
        require_state_token(args['resultStateToken'],
                            error='NCI_INSPECT_ARGUMENTS_INVALID')
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                row = db.execute('''SELECT current_result.state_token AS
                    current_result_state_token,
                    current_result.source_function AS function_name,
                    current_result.result_key,current_result.row_count,
                    j.status AS job_status,j.result AS job_result,
                    j.normalized_program,j.expected_metadata_revision,
                    j.expected_data_revision,j.expected_policy_revision,
                    c.members,r.amount
                    FROM epm.calculation_result_state current_result
                    JOIN epm.job j ON
                      j.workspace_id=current_result.workspace_id
                      AND j.application_id=current_result.application_id
                      AND j.job_id=current_result.source_operation_id
                    JOIN epm.calculation_result_current r ON
                      r.workspace_id=current_result.workspace_id
                      AND r.application_id=current_result.application_id
                      AND r.result_key=current_result.result_key
                    JOIN epm.coordinate c ON
                      c.workspace_id=r.workspace_id
                      AND c.application_id=r.application_id
                      AND c.coordinate_id=r.coordinate_id
                    WHERE current_result.workspace_id=%s
                      AND current_result.application_id=%s
                      AND current_result.result_key=%s
                    FOR SHARE OF current_result''',
                    (*keys, args['resultKey'])).fetchone()
                if (row is None
                        or row['current_result_state_token'] !=
                            args['resultStateToken']):
                    raise ValueError('STALE_PUBLISHED_INPUT')
                receipt = row['job_result']
                try:
                    plan = decode_translated_full(row['normalized_program'])
                except (TypeError, KeyError, ValueError) as error:
                    raise ValueError('NCI_INSPECT_FULL_SOURCE_REQUIRED') from error
                if (row['function_name'] !=
                        'consolidation.full.translated.aggregate'
                        or row['result_key'] != args['resultKey']
                        or row['row_count'] != 1
                        or row['job_status'] != 'published'
                        or not isinstance(receipt, dict)
                        or receipt.get('accountingStage') !=
                            plan.accounting_stage
                        or receipt.get('sourceLayer', 'translated_full') !=
                            plan.source_layer
                        or receipt.get('accountingPolicyStatus') !=
                            'Unreviewed'
                        or receipt.get('parentMembers') != row['members']
                        or not isinstance(receipt.get('sources'), list)):
                    raise ValueError('NCI_INSPECT_FULL_SOURCE_REQUIRED')
                if any(row['expected_'+kind+'_revision'] !=
                       state[kind+'_revision']
                       for kind in ('metadata', 'data', 'policy')):
                    raise ValueError('STALE_PUBLISHED_INPUT')
                status = published_translation_status(
                    db, scope, row['normalized_program'])
                if not status['matchesAtRead']:
                    raise ValueError('STALE_PUBLISHED_INPUT')
                selected = [source for source in receipt['sources']
                            if isinstance(source, dict) and
                            source.get('relationshipId') ==
                            args['relationshipId']]
                if len(selected) != 1 or selected[0].get('parentSource'):
                    raise ValueError('NCI_INSPECT_RELATIONSHIP_UNAVAILABLE')
                source = selected[0]
                try:
                    full_amounts = [Decimal(item['amount'])
                                    for item in receipt['sources']]
                except (KeyError, TypeError, ArithmeticError) as error:
                    raise ValueError('NCI_INSPECT_SOURCE_INVALID') from error
                with localcontext() as precision:
                    precision.prec = 80
                    full_total = sum(full_amounts, Decimal(0))
                if (any(not value.is_finite() for value in full_amounts)
                        or full_total != row['amount']):
                    raise ValueError('NCI_INSPECT_SOURCE_INVALID')
                parent = row['members']
                roles = db.execute('''SELECT model_role,dimension_id
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active'
                    AND model_role IN ('Scenario','Year','Period','Entity')''',
                    keys).fetchall()
                role_map = {role['model_role']: role['dimension_id']
                            for role in roles}
                if len(roles) != 4 or len(role_map) != 4:
                    raise ValueError('NCI_INSPECT_MODEL_ROLES_REQUIRED')
                context = {role: parent[role_map[role]] for role in role_map}
                edge = db.execute('''SELECT r.parent_member_id,
                    r.child_member_id,r.status,
                    pown.amount AS pown,pcon.amount AS pcon,
                    active.amount AS active_value,
                    method.amount AS method_value
                    FROM epm.relationship r
                    LEFT JOIN epm.ownership_value_current pown ON
                      pown.workspace_id=r.workspace_id
                      AND pown.application_id=r.application_id
                      AND pown.relationship_id=r.relationship_id
                      AND pown.scenario_member_id=%s
                      AND pown.year_member_id=%s
                      AND pown.period_member_id=%s
                      AND pown.account_name='POWN' AND pown.present
                    LEFT JOIN epm.ownership_value_current pcon ON
                      pcon.workspace_id=r.workspace_id
                      AND pcon.application_id=r.application_id
                      AND pcon.relationship_id=r.relationship_id
                      AND pcon.scenario_member_id=%s
                      AND pcon.year_member_id=%s
                      AND pcon.period_member_id=%s
                      AND pcon.account_name='PCON' AND pcon.present
                    LEFT JOIN epm.ownership_value_current active ON
                      active.workspace_id=r.workspace_id
                      AND active.application_id=r.application_id
                      AND active.relationship_id=r.relationship_id
                      AND active.scenario_member_id=%s
                      AND active.year_member_id=%s
                      AND active.period_member_id=%s
                      AND active.account_name='Active' AND active.present
                    LEFT JOIN epm.ownership_value_current method ON
                      method.workspace_id=r.workspace_id
                      AND method.application_id=r.application_id
                      AND method.relationship_id=r.relationship_id
                      AND method.scenario_member_id=%s
                      AND method.year_member_id=%s
                      AND method.period_member_id=%s
                      AND method.account_name='Method' AND method.present
                    WHERE r.workspace_id=%s AND r.application_id=%s
                      AND r.dimension_id=%s AND r.relationship_id=%s AND EXISTS(SELECT 1 FROM epm.hierarchy_definition hierarchy
          WHERE hierarchy.workspace_id=r.workspace_id AND hierarchy.application_id=r.application_id
            AND hierarchy.dimension_id=r.dimension_id AND hierarchy.hierarchy_id=r.hierarchy_id
            AND hierarchy.status='Active') ''',
                    (context['Scenario'], context['Year'],
                     context['Period'])*4 +
                    (*keys, role_map['Entity'], args['relationshipId'])
                    ).fetchone()
                if (edge is None or edge['status'] != 'Active'
                        or edge['parent_member_id'] != context['Entity']
                        or edge['child_member_id'] !=
                            source.get('childEntityId')
                        or edge['pown'] is None
                        or edge['pcon'] not in (None, Decimal(100))
                        or edge['active_value'] == 0
                        or edge['method_value'] is not None
                        or format(edge['pown'], '.8f') != source.get('pown')):
                    raise ValueError('NCI_INSPECT_OWNERSHIP_CHANGED')
                amount = Decimal(source['amount'])
                NumericCell(True, amount, '')
                if not Decimal(0) <= edge['pown'] <= Decimal(100):
                    raise ValueError('NCI_INSPECT_SOURCE_INVALID')
                with localcontext() as precision:
                    precision.prec = 80
                    exact_nci = amount * (
                        Decimal(100)-edge['pown']) / Decimal(100)
                    nci = exact_nci.quantize(
                        Decimal('0.00000001'), rounding=ROUND_HALF_EVEN)
                    controlling = amount-nci
                NumericCell(True, nci, '')
                NumericCell(True, controlling, '')
                return {'resultKey': args['resultKey'],
                    'resultStateToken': args['resultStateToken'],
                    'relationshipId': args['relationshipId'],
                    'parentMembers': parent,
                    'childEntityId': edge['child_member_id'],
                    'grossContribution': format(amount, '.8f'),
                    'pown': format(edge['pown'], '.8f'),
                    'effectivePcon': '100.00000000',
                    'pconFallback': edge['pcon'] is None,
                    'candidateNciShare': format(nci, '.8f'),
                    'candidateControllingShare': format(controlling, '.8f'),
                    'exactCandidateNciShare': format(exact_nci, 'f'),
                    'sourceChangeId': source['sourceChangeId'],
                    'sourceLayer': plan.source_layer,
                    'sourceAccountingStage': plan.accounting_stage,
                    'observedCommitRevision': state['commit_revision'],
                    'accountingPolicyStatus': 'Unreviewed',
                    'basisEligibility': 'Unverified',
                    'publicationSupported': False,
                    'requiredBeforePosting': [
                        'approved eligible net-assets or profit basis',
                        'acquisition-date measurement and goodwill policy',
                        'presentation and journal target accounts',
                        'externally reviewed policy fixture']}
