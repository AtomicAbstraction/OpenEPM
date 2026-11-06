"""Exact planning-variant comparison over raw numeric plus manual journals."""
from __future__ import annotations

from decimal import Decimal, localcontext

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate, NumericCell
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import PostgresVersionCompare, _identifier


FUNCTION = 'planning.version.adjusted.compare'


class PostgresAdjustedVersionCompare:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)):
            raise ValueError('ADJUSTED_VERSION_ARGUMENTS_INVALID')
        args = program['arguments']
        required = {'dimensionId', 'baseMemberId', 'targetMemberId',
                    'coordinates'}
        if (not required <= set(args)
                or set(args) - (required | {'snapshotRevision'})):
            raise ValueError('ADJUSTED_VERSION_ARGUMENTS_INVALID')
        dimension = _identifier(args['dimensionId'], 'Dimension ID')
        base = _identifier(args['baseMemberId'], 'Base member ID')
        target = _identifier(args['targetMemberId'], 'Target member ID')
        if base == target:
            raise ValueError('VERSION_COMPARE_DISTINCT_MEMBERS_REQUIRED')
        coordinates = args['coordinates']
        if not isinstance(coordinates, list) or not 1 <= len(coordinates) <= 500:
            raise ValueError('ADJUSTED_VERSION_BOUNDS_INVALID')
        others = []
        seen = set()
        for item in coordinates:
            if (not isinstance(item, dict) or len(item) > 31
                    or dimension in item):
                raise ValueError('ADJUSTED_VERSION_COORDINATE_INVALID')
            other = {_identifier(axis, 'Dimension ID'):
                     _identifier(member, 'Member ID')
                     for axis, member in item.items()}
            key = tuple(sorted(other.items()))
            if key in seen:
                raise ValueError('VERSION_COMPARE_DUPLICATE_COORDINATE')
            seen.add(key)
            others.append(other)
        snapshot = args.get('snapshotRevision')
        if snapshot is not None and (type(snapshot) is not int or snapshot < 0):
            raise ValueError('SNAPSHOT_REVISION_INVALID')

        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,
                    commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if snapshot is None:
                    snapshot = state['commit_revision']
                if snapshot > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
                metadata_revision = state['metadata_revision']
                PostgresVersionCompare._validate_metadata(
                    db, scope, dimension, base, target, others)
                requested = []
                for ordinal, other in enumerate(others):
                    for variant, member in (('base', base), ('target', target)):
                        members = {**other, dimension: member}
                        requested.append({
                            'ordinal': ordinal, 'variant': variant,
                            'series_key': Coordinate.from_mapping(
                                members).series_key,
                            'members': members})
                rows = db.execute('''WITH requested AS (
                    SELECT * FROM jsonb_to_recordset(%s::jsonb)
                    AS r(ordinal integer,variant text,series_key text,
                         members jsonb))
                    SELECT r.ordinal,r.variant,r.members,
                        c.members AS stored_members,
                        n.present AS source_present,
                        n.resulting_amount AS source_amount,
                        n.change_id AS source_change_id,
                        n.committed_revision AS source_revision,
                        t.present AS text_present,
                        j.adjustment_amount,j.line_count,
                        j.last_journal_revision
                    FROM requested r
                    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
                      AND c.application_id=%s AND c.series_key=r.series_key
                    LEFT JOIN LATERAL (
                        SELECT present,resulting_amount,change_id,
                            committed_revision
                        FROM epm.numeric_fact_event
                        WHERE workspace_id=c.workspace_id
                        AND application_id=c.application_id
                        AND coordinate_id=c.coordinate_id
                        AND committed_revision<=%s
                        ORDER BY committed_revision DESC,line_ordinal DESC
                        LIMIT 1) n ON true
                    LEFT JOIN LATERAL (
                        SELECT present FROM epm.text_fact_event
                        WHERE workspace_id=c.workspace_id
                        AND application_id=c.application_id
                        AND coordinate_id=c.coordinate_id
                        AND committed_revision<=%s
                        ORDER BY committed_revision DESC,line_ordinal DESC
                        LIMIT 1) t ON true
                    LEFT JOIN LATERAL (
                        SELECT COALESCE(sum(l.signed_amount),0)
                            AS adjustment_amount,
                            count(*) AS line_count,
                            max(h.committed_revision)
                            AS last_journal_revision
                        FROM epm.manual_journal_line l
                        JOIN epm.manual_journal h USING
                            (workspace_id,application_id,journal_id)
                        WHERE l.workspace_id=c.workspace_id
                        AND l.application_id=c.application_id
                        AND l.coordinate_id=c.coordinate_id
                        AND h.committed_revision<=%s) j ON true
                    ORDER BY r.ordinal,r.variant''',
                    (Jsonb(requested), scope.workspace_id,
                     scope.application_id, snapshot, snapshot,
                     snapshot)).fetchall()
                after = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after is None or
                        after['metadata_revision'] != metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
        states = {}
        for row in rows:
            if (row['stored_members'] is not None
                    and row['stored_members'] != row['members']):
                raise ValueError('COORDINATE_HASH_COLLISION')
            if row['text_present']:
                raise ValueError('ADJUSTED_BALANCE_TEXT_COORDINATE')
            source_present = bool(row['source_present'])
            adjustment = row['adjustment_amount']
            present = source_present or adjustment != 0
            with localcontext() as context:
                context.prec = 64
                adjusted = ((row['source_amount'] if source_present
                             else Decimal(0)) + adjustment)
            if present:
                NumericCell(True, adjusted, '')
            states[(row['ordinal'], row['variant'])] = {
                'kind': 'numeric' if present else 'missing',
                'present': present,
                'amount': format(adjusted, '.8f') if present else None,
                'sourcePresent': source_present,
                'sourceAmount': (format(row['source_amount'], '.8f')
                                 if source_present else None),
                'sourceChangeId': (row['source_change_id']
                                   if source_present else ''),
                'sourceLastRevision': (row['source_revision']
                                       if source_present else None),
                'adjustmentAmount': format(adjustment, '.8f'),
                'journalLineCount': row['line_count'],
                'lastJournalRevision': row['last_journal_revision']}
        result_rows = []
        for ordinal, other in enumerate(others):
            base_cell = states[(ordinal, 'base')]
            target_cell = states[(ordinal, 'target')]
            delta = (format(Decimal(target_cell['amount']) -
                            Decimal(base_cell['amount']), '.8f')
                     if base_cell['present'] and target_cell['present']
                     else None)
            result_rows.append({'otherMembers': other,
                'base': base_cell, 'target': target_cell,
                'delta': delta,
                'equal': (base_cell['kind'] == target_cell['kind'] and
                          base_cell['amount'] == target_cell['amount'])})
        return {'layer': 'raw_plus_manual_journal',
                'dimensionId': dimension, 'baseMemberId': base,
                'targetMemberId': target,
                'snapshotRevision': snapshot,
                'metadataRevision': metadata_revision,
                'rows': result_rows}
