"""Bounded reciprocal intercompany balance inspection, without posting.

This reports signed raw balances and an exact residual only when both Entity
currencies are explicitly configured and equal. It is not an elimination or
an accounting-policy decision.
"""
from __future__ import annotations

from decimal import Decimal, localcontext

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, Coordinate
from .dimensional_security_policy import AccessKind
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .current_object_contract import require_stable_identifier as _identifier


FUNCTION = 'consolidation.ic.pair.inspect'
_ROLES = {'Scenario', 'Year', 'Period', 'Entity', 'Account', 'ICP'}
_MAX_AMOUNT = Decimal('99999999999999999999.99999999')


class PostgresIntercompanyPairInspector:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) !=
                    {'leftMembers', 'rightMembers'}):
            raise ValueError('IC_PAIR_PROGRAM_INVALID')
        sides = []
        for key in ('leftMembers', 'rightMembers'):
            value = program['arguments'][key]
            if not isinstance(value, dict) or not 1 <= len(value) <= 32:
                raise ValueError('IC_PAIR_COORDINATE_INVALID')
            sides.append({_identifier(axis, 'Dimension ID'):
                          _identifier(member, 'Member ID')
                          for axis, member in value.items()})
        left, right = sides
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,commit_revision,currency_settings
                    FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                dimensions = db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active' ''',
                    (scope.workspace_id, scope.application_id)).fetchall()
                axes = {row['dimension_id'] for row in dimensions
                        if row['model_role'] != 'Currency'}
                roles = {}
                for row in dimensions:
                    if row['model_role'] in _ROLES | {'Value','View'}:
                        if row['model_role'] in roles:
                            raise ValueError('IC_PAIR_MODEL_ROLE_AMBIGUOUS')
                        roles[row['model_role']] = row['dimension_id']
                if sum(row['model_role'] == 'Currency'
                       for row in dimensions) != 1:
                    raise ValueError('IC_PAIR_CURRENCY_ROLE_REQUIRED')
                if not _ROLES <= set(roles):
                    raise ValueError('IC_PAIR_FINANCIAL_MODEL_REQUIRED')
                if set(left) != axes or set(right) != axes:
                    raise ValueError('IC_PAIR_COORDINATE_GRAIN_MISMATCH')
                PostgresSourceBatch._check_scope_members(db, scope, left)
                PostgresSourceBatch._check_scope_members(db, scope, right)
                authorize_coordinates(
                    db, self.identity, scope,
                    (Coordinate.from_mapping(left),
                     Coordinate.from_mapping(right)),
                    kind=AccessKind.READ)
                if 'Value' in roles:
                    settings = state['currency_settings']
                    if ('View' not in roles or settings is None
                            or settings.get('validatedMetadataRevision') !=
                                state['metadata_revision']
                            or any(members[roles['Value']] !=
                                   settings.get('entityCurrencyValueMemberId')
                                   or members[roles['View']] !=
                                   settings.get('ytdViewMemberId')
                                   for members in sides)):
                        raise ValueError('IC_PAIR_VALUE_STAGE_REQUIRED')
                entity, icp = roles['Entity'], roles['ICP']
                if (left[entity] == right[entity]
                        or left[icp] == right[icp]
                        or any(left[axis] != right[axis] for axis in axes
                               if axis not in (entity, icp,
                                               roles['Account']))):
                    raise ValueError('IC_PAIR_NOT_RECIPROCAL_OR_CONTEXT_MISMATCH')
                mapping_definition = db.execute('''SELECT slot,properties
                    FROM epm.semantic_column WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND scope='Member'
                    AND lower(display_name)='icp entity mapping' ''',
                    (scope.workspace_id,scope.application_id,icp)).fetchone()
                if (mapping_definition is None
                        or mapping_definition['properties'].get('valueType')
                            != 'MemberReference'
                        or mapping_definition['properties'].get(
                            'referenceDimensionId') != entity):
                    raise ValueError('IC_PAIR_MAPPING_DEFINITION_REQUIRED')
                slot = mapping_definition['slot']
                key = f'Custom{slot:02d}'
                mapped = db.execute('''SELECT member_id,custom_values
                    FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id=ANY(%s::text[]) AND status='Active' ''',
                    (scope.workspace_id,scope.application_id,icp,
                     [left[icp],right[icp]])).fetchall()
                if len(mapped) != 2:
                    raise ValueError('IC_PAIR_ICP_MEMBER_UNAVAILABLE')
                mapped_entity = {row['member_id']:
                                 row['custom_values'].get(key)
                                 for row in mapped}
                if (mapped_entity[left[icp]] != right[entity]
                        or mapped_entity[right[icp]] != left[entity]):
                    raise ValueError('IC_PAIR_COUNTERPARTY_MAPPING_MISMATCH')
                for entity_id in (left[entity],right[entity]):
                    candidates = db.execute('''SELECT member_id FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                          AND dimension_id=%s AND status='Active'
                          AND custom_values->>%s=%s LIMIT 2''',
                        (scope.workspace_id,scope.application_id,icp,
                         key,entity_id)).fetchall()
                    if len(candidates) != 1:
                        raise ValueError('IC_PAIR_COUNTERPARTY_MAPPING_AMBIGUOUS')
                for members in sides:
                    if db.execute('''SELECT 1 FROM epm.relationship
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=%s AND parent_member_id=%s
                        AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
                        (scope.workspace_id, scope.application_id,
                         roles['Account'], members[roles['Account']])).fetchone():
                        raise ValueError('IC_PAIR_ACCOUNT_LEAF_REQUIRED')
                account = roles['Account']
                account_mapping = db.execute('''SELECT slot,properties
                    FROM epm.semantic_column WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND scope='Member'
                    AND lower(display_name)='ic reciprocal account' ''',
                    (scope.workspace_id,scope.application_id,account)).fetchone()
                if (account_mapping is None
                        or account_mapping['properties'].get('valueType')
                            != 'MemberReference'
                        or account_mapping['properties'].get(
                            'referenceDimensionId') != account):
                    raise ValueError('IC_PAIR_ACCOUNT_MAPPING_DEFINITION_REQUIRED')
                account_slot = account_mapping['slot']
                account_key = f'Custom{account_slot:02d}'
                account_members = db.execute('''SELECT member_id,custom_values
                    FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id=ANY(%s::text[]) AND status='Active' ''',
                    (scope.workspace_id,scope.application_id,account,
                     [left[account],right[account]])).fetchall()
                if len(account_members) != 2 or left[account] == right[account]:
                    raise ValueError('IC_PAIR_DISTINCT_ACCOUNTS_REQUIRED')
                mapped_account = {row['member_id']:
                                  row['custom_values'].get(account_key)
                                  for row in account_members}
                if (mapped_account[left[account]] != right[account]
                        or mapped_account[right[account]] != left[account]):
                    raise ValueError('IC_PAIR_ACCOUNT_MAPPING_MISMATCH')
                currencies = db.execute('''SELECT member_id,
                    entity_default_currency_member_id AS currency_id
                    FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id=ANY(%s::text[]) AND status='Active' ''',
                    (scope.workspace_id, scope.application_id, entity,
                     [left[entity], right[entity]])).fetchall()
                if len(currencies) != 2:
                    raise ValueError('IC_PAIR_ENTITY_UNAVAILABLE')
                currency_by_entity = {row['member_id']: row['currency_id']
                                      for row in currencies}
                configured_currency = currency_by_entity[left[entity]]
                active_currency = (configured_currency is not None and
                    db.execute('''SELECT 1 FROM epm.member m
                        JOIN epm.dimension d ON d.workspace_id=m.workspace_id
                          AND d.application_id=m.application_id
                          AND d.dimension_id=m.dimension_id
                        WHERE m.workspace_id=%s AND m.application_id=%s
                          AND m.member_id=%s AND m.status='Active'
                          AND d.status='Active' AND d.model_role='Currency'
                        LIMIT 1''',
                        (scope.workspace_id, scope.application_id,
                         configured_currency)).fetchone() is not None)
                values = []
                for members in sides:
                    coordinate = Coordinate.from_mapping(members)
                    value = db.execute('''SELECT c.coordinate_id,c.members,
                        n.amount,n.change_id
                        FROM epm.coordinate c JOIN epm.numeric_cell_current n
                          ON n.workspace_id=c.workspace_id
                         AND n.application_id=c.application_id
                         AND n.coordinate_id=c.coordinate_id
                        WHERE c.workspace_id=%s AND c.application_id=%s
                          AND c.series_key=%s AND n.present''',
                        (scope.workspace_id, scope.application_id,
                         coordinate.series_key)).fetchone()
                    if value and value['members'] != members:
                        raise ValueError('COORDINATE_HASH_COLLISION')
                    values.append(value)
                journal_rows = db.execute('''SELECT l.coordinate_id,
                    sum(l.signed_amount) AS adjustment,
                    count(*) AS line_count,
                    max(j.committed_revision) AS last_revision
                    FROM epm.manual_journal_line l
                    JOIN epm.manual_journal j USING
                      (workspace_id,application_id,journal_id)
                    WHERE l.workspace_id=%s AND l.application_id=%s
                    AND l.coordinate_id=ANY(%s::bigint[])
                    AND j.committed_revision<=%s
                    GROUP BY l.coordinate_id''',
                    (scope.workspace_id,scope.application_id,
                     [value['coordinate_id'] for value in values if value],
                     state['commit_revision'])).fetchall()
                journals = {row['coordinate_id']: row
                            for row in journal_rows}
        left_currency = currency_by_entity[left[entity]]
        right_currency = currency_by_entity[right[entity]]
        comparable = (active_currency
                      and left_currency == right_currency)
        issues = []
        if not comparable:
            issues.append('IC_PAIR_CURRENCY_ALIGNMENT_REQUIRED')
        if values[0] is None or values[1] is None:
            issues.append('IC_PAIR_SOURCE_MISSING')
        sign_compatible = (values[0] is not None and values[1] is not None
                           and values[0]['amount'] * values[1]['amount'] <= 0)
        if comparable and all(values) and not sign_compatible:
            issues.append('IC_PAIR_OPPOSITE_SIGNS_REQUIRED')
        amount_left = values[0]['amount'] if values[0] else None
        amount_right = values[1]['amount'] if values[1] else None
        adjustments = [journals.get(value['coordinate_id'])
                       if value else None for value in values]
        with localcontext() as decimal_context:
            decimal_context.prec = 64
            residual = (amount_left + amount_right
                        if comparable and sign_compatible else None)
            matched = (min(abs(amount_left), abs(amount_right))
                       if comparable and sign_compatible else None)
            layered_amounts = [
                value['amount'] + (journal['adjustment'] if journal
                                   else Decimal(0)) if value else None
                for value,journal in zip(values,adjustments)]
            layered_signs = (all(value is not None for value in layered_amounts)
                             and (0 in layered_amounts or
                                  (layered_amounts[0] > 0) !=
                                  (layered_amounts[1] > 0)))
            layered_in_range = all(value is None or abs(value)<=_MAX_AMOUNT
                                   for value in layered_amounts)
            layered_residual = (sum(layered_amounts,Decimal(0))
                if comparable and layered_signs and layered_in_range else None)
            layered_matched = (min(abs(value) for value in layered_amounts)
                if comparable and layered_signs and layered_in_range else None)
        layered_issues = []
        if not comparable:
            layered_issues.append('IC_PAIR_CURRENCY_ALIGNMENT_REQUIRED')
        if any(value is None for value in layered_amounts):
            layered_issues.append('IC_PAIR_SOURCE_MISSING')
        elif comparable and not layered_signs:
            layered_issues.append('IC_PAIR_LAYERED_OPPOSITE_SIGNS_REQUIRED')
        if not layered_in_range:
            layered_issues.append('IC_PAIR_LAYERED_AMOUNT_OUT_OF_RANGE')
        def formatted(value: Decimal | None) -> str | None:
            return format(value, '.8f') if value is not None else None
        def side_layer(index: int) -> dict:
            journal = adjustments[index]
            return {'journalAdjustment':
                        formatted(journal['adjustment'] if journal
                                  else Decimal(0)) if values[index] else None,
                    'journalLineCount': journal['line_count'] if journal else 0,
                    'lastJournalRevision': (journal['last_revision']
                                            if journal else None),
                    'layeredAmount': formatted(layered_amounts[index])}
        return {
            'left': {'members': left, 'amount': formatted(amount_left),
                     'changeId': values[0]['change_id'] if values[0] else None,
                     **side_layer(0),
                     'entityCurrencyMemberId': left_currency,
                     'mappedCounterpartyEntityId':mapped_entity[left[icp]],
                     'mappedReciprocalAccountId':mapped_account[left[account]]},
            'right': {'members': right, 'amount': formatted(amount_right),
                      'changeId': values[1]['change_id'] if values[1] else None,
                      **side_layer(1),
                      'entityCurrencyMemberId': right_currency,
                      'mappedCounterpartyEntityId':mapped_entity[right[icp]],
                      'mappedReciprocalAccountId':mapped_account[right[account]]},
            'matchedMagnitude': formatted(matched),
            'signedResidual': formatted(residual),
            'exactlyMatched': residual == 0 if residual is not None else False,
            'layeredMatchedMagnitude': formatted(layered_matched),
            'layeredSignedResidual': formatted(layered_residual),
            'layeredExactlyMatched': (layered_residual == 0
                                     if layered_residual is not None else False),
            'layeredIssues': layered_issues,
            'layeredMatchBasis': 'RawNumericPlusPostedManualJournal',
            'counterpartyMappingStatus': 'ConfiguredMemberReference',
            'counterpartyMappingSlot':slot,
            'accountMappingStatus': 'ConfiguredMemberReference',
            'accountMappingSlot': account_slot,
            'issues': issues,
            'metadataRevision': state['metadata_revision'],
            'dataRevision': state['data_revision'],
            'policyRevision': state['policy_revision'],
            'commitRevision': state['commit_revision'],
            'accountingPolicyStatus': 'Unreviewed',
            'eliminationPublished': False,
        }
