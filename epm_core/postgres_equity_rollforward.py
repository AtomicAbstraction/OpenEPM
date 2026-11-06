"""Authorized, snapshot-pinned structural equity-rollforward inspection."""
from __future__ import annotations

from psycopg.rows import dict_row

from .consolidation_equity_rollforward import EquityRollforward
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_source_batch import PostgresSourceBatch
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates


FUNCTION = 'consolidation.equity.rollforward.inspect'


class PostgresEquityRollforward:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def inspect(self, scope: ApplicationScope, program: object) -> dict:
        if (not isinstance(scope, ApplicationScope) or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)
                or set(program['arguments']) != {'definition'}):
            raise ValueError('EQUITY_ROLLFORWARD_PROGRAM_INVALID')
        definition = EquityRollforward.parse(program['arguments']['definition'])
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read', function=FUNCTION)
                state = db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',
                    keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (state['metadata_revision'] != definition.expected_metadata_revision
                        or state['data_revision'] != definition.expected_data_revision
                        or state['policy_revision'] != definition.expected_policy_revision):
                    raise ValueError('EQUITY_ROLLFORWARD_SOURCE_REVISION_STALE')
                currency = db.execute('''SELECT 1 FROM epm.dimension d
                    JOIN epm.member m ON m.workspace_id=d.workspace_id
                      AND m.application_id=d.application_id
                      AND m.dimension_id=d.dimension_id
                    WHERE d.workspace_id=%s AND d.application_id=%s
                      AND d.dimension_id=%s AND d.model_role='Currency'
                      AND d.status='Active' AND m.member_id=%s
                      AND m.status='Active' ''', (*keys,
                    definition.currency_dimension_id,
                    definition.currency_member_id)).fetchone()
                if currency is None:
                    raise ValueError('EQUITY_ROLLFORWARD_CURRENCY_UNAVAILABLE')
                resolved = []
                for pin in definition.pins:
                    members = dict(pin.members)
                    PostgresSourceBatch._check_scope_members(db, scope, members)
                    coordinate = Coordinate.from_mapping(members)
                    resolved.append((pin, members, coordinate))
                authorize_coordinates(db, self.identity, scope,
                    (item[2] for item in resolved), kind=AccessKind.READ)
                values, lineage = {}, []
                for pin, members, coordinate in resolved:
                    row = db.execute('''SELECT c.members,n.amount,n.change_id,
                        n.last_revision FROM epm.coordinate c
                        JOIN epm.numeric_cell_current n ON
                          n.workspace_id=c.workspace_id
                          AND n.application_id=c.application_id
                          AND n.coordinate_id=c.coordinate_id
                        WHERE c.workspace_id=%s AND c.application_id=%s
                          AND c.series_key=%s AND n.present''',
                        (*keys, coordinate.series_key)).fetchone()
                    if row is None:
                        raise ValueError('EQUITY_ROLLFORWARD_SOURCE_MISSING')
                    if row['members'] != members:
                        raise ValueError('COORDINATE_HASH_COLLISION')
                    if row['change_id'] != pin.change_id:
                        raise ValueError('EQUITY_ROLLFORWARD_SOURCE_CHANGE_STALE')
                    values[pin.change_id] = format(row['amount'], 'f')
                    lineage.append({'members': members,
                        'changeId': pin.change_id,
                        'lastRevision': row['last_revision']})
        result = definition.reconcile(values)
        return {**result, 'commitRevision': state['commit_revision'],
                'lineage': lineage,
                'effects': {'businessRevisionChanged': False,
                  'published': False, 'rawFactsChanged': False},
                'limitations': ['Unreviewed explicit structural mapping only',
                  'Unique sources at one identical complete non-Currency grain only',
                  'No currency conversion', 'No statement publication']}
