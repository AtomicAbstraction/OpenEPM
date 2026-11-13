"""Read raw, current parent-scoped IC offset and posted journal layers.

This unreviewed source view never changes raw facts, rematches the IC pair
after journal posting, or certifies a parent consolidation/accounting policy.
"""
from __future__ import annotations

from decimal import Decimal, localcontext

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope, Coordinate
from .persistence_contract import NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_source_batch import PostgresSourceBatch
from .current_object_contract import require_stable_identifier as _identifier


FUNCTION = 'consolidation.ic.adjusted.balance.read'
_MAX_AMOUNT = Decimal('99999999999999999999.99999999')


def resolve_ic_adjusted_source(db,scope,*,parent,members,state,
                               expected_state_token=None,
                               allow_manual_journals=True,
                               require_elimination=True,
                               include_journal_lineage=False):
    """Resolve one raw coordinate and its exact current parent IC layer."""
    coordinate=Coordinate.from_mapping(members);keys=(scope.workspace_id,scope.application_id)
    raw=db.execute('''SELECT c.coordinate_id,c.members,n.amount,n.change_id
      FROM epm.coordinate c JOIN epm.numeric_cell_current n USING
       (workspace_id,application_id,coordinate_id)
      WHERE c.workspace_id=%s AND c.application_id=%s AND c.series_key=%s
       AND n.present''',(*keys,coordinate.series_key)).fetchone()
    if raw is None:raise ValueError('IC_ADJUSTED_BALANCE_SOURCE_MISSING')
    if raw['members']!=members:raise ValueError('COORDINATE_HASH_COLLISION')
    lines=db.execute('''SELECT s.state_token,s.pair_key,
      s.source_metadata_revision,s.source_policy_revision,s.signed_residual,
      s.matched_magnitude,l.line_ordinal,l.coordinate_id,l.signed_amount,
      l.source_change_id,n.change_id AS current_change_id,c.members
      FROM epm.ic_elimination_state s
      JOIN epm.ic_elimination_current_line target ON
       target.workspace_id=s.workspace_id
       AND target.application_id=s.application_id
       AND target.parent_entity_member_id=s.parent_entity_member_id
       AND target.pair_key=s.pair_key AND target.coordinate_id=%s
      JOIN epm.ic_elimination_current_line l ON
       l.workspace_id=s.workspace_id
       AND l.application_id=s.application_id
       AND l.parent_entity_member_id=s.parent_entity_member_id
       AND l.pair_key=s.pair_key
      JOIN epm.coordinate c ON c.workspace_id=l.workspace_id
       AND c.application_id=l.application_id AND c.coordinate_id=l.coordinate_id
      LEFT JOIN epm.numeric_cell_current n ON n.workspace_id=l.workspace_id
       AND n.application_id=l.application_id AND n.coordinate_id=l.coordinate_id
       AND n.present
      WHERE s.workspace_id=%s AND s.application_id=%s
       AND s.parent_entity_member_id=%s
       AND s.status='PublishedUnreviewed'
      ORDER BY s.pair_key,l.line_ordinal LIMIT 5''',
      (raw['coordinate_id'],*keys,parent)).fetchall()
    if not lines and require_elimination:
        raise ValueError('IC_ADJUSTED_BALANCE_CURRENT_ELIMINATION_REQUIRED')
    if lines and (len(lines)!=2 or len({row['state_token'] for row in lines})!=1
        or {row['line_ordinal'] for row in lines}!={1,2}
        or sum((row['signed_amount'] for row in lines),Decimal(0))!=0
        or lines[0]['source_metadata_revision']!=state['metadata_revision']
        or lines[0]['source_policy_revision']!=state['policy_revision']
        or any(row['source_change_id']!=row['current_change_id'] for row in lines)):
        raise ValueError('IC_ADJUSTED_BALANCE_STALE')
    state_token=lines[0]['state_token'] if lines else None
    if expected_state_token is not None and state_token!=expected_state_token:
        raise ValueError('IC_ADJUSTED_BALANCE_STATE_CHANGED')
    selected=[row for row in lines if row['coordinate_id']==raw['coordinate_id']]
    if lines and len(selected)!=1:raise ValueError('IC_ADJUSTED_BALANCE_LINEAGE_INVALID')
    journals=db.execute('''SELECT count(*) AS line_count,
      COALESCE(sum(l.signed_amount),0) AS signed_amount,
      max(j.committed_revision) AS last_revision
      FROM epm.manual_journal_line l JOIN epm.manual_journal j USING
       (workspace_id,application_id,journal_id)
      WHERE l.workspace_id=%s AND l.application_id=%s AND l.coordinate_id=%s
       AND j.committed_revision<=%s''',(*keys,raw['coordinate_id'],
       state['commit_revision'])).fetchone()
    if not allow_manual_journals and journals['line_count']:
        raise ValueError('TYPED_CONTRIBUTION_MANUAL_JOURNAL_UNSUPPORTED')
    journal_lines=[]
    if include_journal_lineage:
        journal_lines=db.execute('''SELECT j.journal_id,l.line_ordinal,
          l.signed_amount,l.source_ref,j.committed_revision
          FROM epm.manual_journal_line l JOIN epm.manual_journal j USING
           (workspace_id,application_id,journal_id)
          WHERE l.workspace_id=%s AND l.application_id=%s
           AND l.coordinate_id=%s AND j.committed_revision<=%s
          ORDER BY j.committed_revision,j.journal_id,l.line_ordinal
          LIMIT 65''',(*keys,raw['coordinate_id'],
           state['commit_revision'])).fetchall()
        if (len(journal_lines)!=journals['line_count']
                or len(journal_lines)>64
                or sum((row['signed_amount'] for row in journal_lines),
                       Decimal(0))!=journals['signed_amount']
                or (max((row['committed_revision'] for row in journal_lines),
                        default=None)!=journals['last_revision'])):
            raise ValueError('TYPED_CONTRIBUTION_JOURNAL_LINEAGE_LIMIT')
        journal_lines=[{'journalId':row['journal_id'],
          'lineOrdinal':row['line_ordinal'],
          'signedAmount':format(row['signed_amount'],'.8f'),
          'sourceRef':row['source_ref'],
          'committedRevision':row['committed_revision']}
          for row in journal_lines]
    offset=selected[0]['signed_amount'] if selected else Decimal(0)
    with localcontext() as context:
        context.prec=64;adjusted=raw['amount']+offset
        layered=adjusted+(journals['signed_amount'] if allow_manual_journals else 0)
    NumericCell(True,layered,'')
    return {'raw':raw,'lines':lines,'resultStateToken':state_token,
      'pairKey':lines[0]['pair_key'] if lines else None,'offset':offset,
      'adjustedAmount':adjusted,'layeredAmount':layered,
      'matchedMagnitude':lines[0]['matched_magnitude'] if lines else None,
      'signedResidual':lines[0]['signed_residual'] if lines else None,
      'journals':journals,'journalLines':journal_lines}


class PostgresIcAdjustedBalance:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def read(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion','function','arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != {'parentEntityId','members'}
                or not isinstance(program['arguments']['members'], dict)
                or not 1 <= len(program['arguments']['members']) <= 32):
            raise ValueError('IC_ADJUSTED_BALANCE_PROGRAM_INVALID')
        args = program['arguments']
        parent = _identifier(args['parentEntityId'], 'Parent Entity ID')
        members = {_identifier(axis, 'Dimension ID'):
                   _identifier(member, 'Member ID')
                   for axis, member in args['members'].items()}
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                state = db.execute('''SELECT metadata_revision,
                    policy_revision,commit_revision,currency_settings
                    FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                dimensions = db.execute('''SELECT dimension_id,model_role
                    FROM epm.dimension WHERE workspace_id=%s
                    AND application_id=%s AND status='Active' ''',
                    (scope.workspace_id,scope.application_id)).fetchall()
                axes = {row['dimension_id'] for row in dimensions
                        if row['model_role'] != 'Currency'}
                role_ids = {}
                for role in ('Entity','Account','ICP'):
                    matches = [row['dimension_id'] for row in dimensions
                               if row['model_role'] == role]
                    if len(matches) != 1:
                        raise ValueError('IC_ADJUSTED_BALANCE_MODEL_INVALID')
                    role_ids[role] = matches[0]
                if (sum(row['model_role'] == 'Currency'
                        for row in dimensions) != 1
                        or set(members) != axes):
                    raise ValueError('IC_ADJUSTED_BALANCE_GRAIN_INVALID')
                value_axes = [row['dimension_id'] for row in dimensions
                              if row['model_role'] == 'Value']
                view_axes = [row['dimension_id'] for row in dimensions
                             if row['model_role'] == 'View']
                if value_axes:
                    settings = state['currency_settings']
                    if (len(value_axes) != 1 or len(view_axes) != 1
                            or settings is None
                            or settings.get('validatedMetadataRevision') !=
                                state['metadata_revision']
                            or members[value_axes[0]] !=
                                settings.get('entityCurrencyValueMemberId')
                            or members[view_axes[0]] !=
                                settings.get('ytdViewMemberId')):
                        raise ValueError('IC_ADJUSTED_BALANCE_VALUE_STAGE_REQUIRED')
                entity_axis = role_ids['Entity']
                PostgresSourceBatch._check_scope_members(db, scope, members)
                if not db.execute('''SELECT 1 FROM epm.member WHERE
                    workspace_id=%s AND application_id=%s AND
                    dimension_id=%s AND member_id=%s AND status='Active' ''',
                    (scope.workspace_id,scope.application_id,
                     entity_axis,parent)).fetchone():
                    raise ValueError('IC_ADJUSTED_BALANCE_PARENT_UNAVAILABLE')
                if db.execute('''SELECT 1 FROM epm.relationship WHERE
                    workspace_id=%s AND application_id=%s AND
                    dimension_id=%s AND parent_member_id=%s
                    AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' LIMIT 1''',
                    (scope.workspace_id,scope.application_id,
                     role_ids['Account'],members[role_ids['Account']]
                     )).fetchone():
                    raise ValueError('IC_ADJUSTED_BALANCE_ACCOUNT_LEAF_REQUIRED')
                placement = db.execute('''SELECT count(*) AS total,
                    count(*) FILTER (WHERE parent_member_id=%s) AS selected
                    FROM epm.relationship WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND child_member_id=%s AND hierarchy_id=epm.default_hierarchy_id(workspace_id,application_id,dimension_id) AND status='Active' ''',
                    (parent,scope.workspace_id,scope.application_id,
                     entity_axis,members[entity_axis])).fetchone()
                if placement['total'] != 1 or placement['selected'] != 1:
                    raise ValueError('IC_ADJUSTED_BALANCE_PARENT_SCOPE_REQUIRED')
                resolved=resolve_ic_adjusted_source(db,scope,parent=parent,
                    members=members,state=state,allow_manual_journals=True,
                    require_elimination=False)
                raw=resolved['raw'];offset=resolved['offset']
                state_token=resolved['resultStateToken']
                matched=resolved['matchedMagnitude'];residual=resolved['signedResidual']
                journals=resolved['journals'];amount=resolved['adjustedAmount']
                layered=resolved['layeredAmount']
        if abs(amount) > _MAX_AMOUNT or abs(layered) > _MAX_AMOUNT:
            raise ValueError('IC_ADJUSTED_BALANCE_AMOUNT_OUT_OF_RANGE')
        NumericCell(True,layered,'')
        return {'parentEntityId': parent,
                'sourceMembers': members,
                'sourceAmount': format(raw['amount'],'.8f'),
                'sourceChangeId': raw['change_id'],
                'eliminationOffset': format(offset,'.8f'),
                'adjustedAmount': format(amount,'.8f'),
                'journalAdjustment': format(journals['signed_amount'],'.8f'),
                'journalLineCount': journals['line_count'],
                'lastJournalRevision': journals['last_revision'],
                'layeredAmount': format(layered,'.8f'),
                'layeredAccountingStage': (
                    'pre_nci_untranslated_journal_ic_adjusted'
                    if state_token and journals['line_count'] else
                    'pre_nci_untranslated_ic_adjusted'
                    if state_token else
                    'pre_nci_untranslated_journal_adjusted'
                    if journals['line_count'] else 'raw_numeric_source'),
                'icMatchingBasis': ('RawNumericSource' if state_token
                                    else None),
                'resultStateToken': state_token,
                'matchedMagnitude': (format(matched,'.8f')
                                     if matched is not None else None),
                'signedResidual': (format(residual,'.8f')
                                   if residual is not None else None),
                'status': ('CurrentUnreviewed' if state_token else
                           'NoCurrentElimination'),
                'accountingPolicyStatus': 'Unreviewed',
                'rawFactsChanged': False,
                'commitRevision': state['commit_revision']}
