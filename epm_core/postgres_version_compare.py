"""Exact, snapshot-pinned comparisons of two members of a planning axis.

The caller supplies a bounded set of complete coordinates excluding the
comparison axis. The fixed core resolves both variants in one scoped read;
missing, numeric and text values remain distinct.
"""
from __future__ import annotations

from decimal import Decimal

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'planning.version.compare'


def comparison_freshness(*, snapshot_revision: int,
                         pinned_metadata_revision: int,
                         current_commit_revision: int,
                         current_metadata_revision: int) -> dict:
    """Describe whether a stable comparison snapshot is still current.

    A later business commit does not invalidate the snapshot result, but it
    must be visible to callers.  A metadata change is different: it can change
    coordinate interpretation and therefore fails the read rather than being
    represented as a harmless stale result.
    """
    values = (snapshot_revision, pinned_metadata_revision,
              current_commit_revision, current_metadata_revision)
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError('VERSION_COMPARE_FRESHNESS_INVALID')
    if current_commit_revision < snapshot_revision:
        raise ValueError('VERSION_COMPARE_REVISION_REGRESSION')
    metadata_matches = current_metadata_revision == pinned_metadata_revision
    return {'isCurrent': metadata_matches and
            snapshot_revision == current_commit_revision,
            'metadataMatches': metadata_matches,
            'currentCommitRevision': current_commit_revision}


def _identifier(value: object, label: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 200
            or value != value.strip() or '\x00' in value):
        raise ValueError(f'{label} must be a nonempty stable ID of at most 200 characters')
    return value


class PostgresVersionCompare:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn = dsn
        self.identity = identity

    def read(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)):
            raise ValueError('VERSION_COMPARE_ARGUMENTS_INVALID')
        args = program['arguments']
        required = {'dimensionId', 'baseMemberId', 'targetMemberId',
                    'coordinates'}
        if (not required <= set(args)
                or set(args) - (required | {'snapshotRevision'})):
            raise ValueError('VERSION_COMPARE_ARGUMENTS_INVALID')
        dimension = _identifier(args['dimensionId'], 'Dimension ID')
        base_member = _identifier(args['baseMemberId'], 'Base member ID')
        target_member = _identifier(args['targetMemberId'], 'Target member ID')
        if base_member == target_member:
            raise ValueError('VERSION_COMPARE_DISTINCT_MEMBERS_REQUIRED')
        coordinates = args['coordinates']
        if (not isinstance(coordinates, list)
                or not 1 <= len(coordinates) <= 500):
            raise ValueError('VERSION_COMPARE_BOUNDS_INVALID')
        other_coordinates = []
        seen = set()
        for item in coordinates:
            if (not isinstance(item, dict) or len(item) > 31
                    or dimension in item):
                raise ValueError('VERSION_COMPARE_COORDINATE_INVALID')
            other = {_identifier(axis, 'Dimension ID'):
                     _identifier(member, 'Member ID')
                     for axis, member in item.items()}
            key = tuple(sorted(other.items()))
            if key in seen:
                raise ValueError('VERSION_COMPARE_DUPLICATE_COORDINATE')
            seen.add(key)
            other_coordinates.append(other)
        snapshot = args.get('snapshotRevision')
        if (snapshot is not None and
                (type(snapshot) is not int or snapshot < 0)):
            raise ValueError('SNAPSHOT_REVISION_INVALID')

        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if snapshot is None:
                    snapshot = state['commit_revision']
                if snapshot > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
                revision = state['metadata_revision']
                self._validate_metadata(db, scope, dimension,
                                        base_member, target_member,
                                        other_coordinates)
                requested = []
                for ordinal, other in enumerate(other_coordinates):
                    for variant, member in (('base', base_member),
                                            ('target', target_member)):
                        members = {**other, dimension: member}
                        requested.append({
                            'ordinal': ordinal, 'variant': variant,
                            'series_key': Coordinate.from_mapping(
                                members).series_key,
                            'members': members,
                        })
                rows = db.execute('''WITH requested AS (
                    SELECT * FROM jsonb_to_recordset(%s::jsonb)
                    AS r(ordinal integer, variant text, series_key text,
                         members jsonb))
                    SELECT r.ordinal,r.variant,r.members,
                        c.members AS stored_members,
                        n.present AS numeric_present,
                        n.resulting_amount AS amount,
                        n.change_id AS numeric_change_id,
                        n.committed_revision AS numeric_revision,
                        t.present AS text_present,
                        t.resulting_value AS text_value,
                        t.change_id AS text_change_id,
                        t.committed_revision AS text_revision
                    FROM requested r
                    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
                        AND c.application_id=%s AND c.series_key=r.series_key
                    LEFT JOIN LATERAL (
                        SELECT present,resulting_amount,change_id,
                            committed_revision FROM epm.numeric_fact_event
                        WHERE workspace_id=c.workspace_id
                        AND application_id=c.application_id
                        AND coordinate_id=c.coordinate_id
                        AND committed_revision<=%s
                        ORDER BY committed_revision DESC,line_ordinal DESC
                        LIMIT 1) n ON true
                    LEFT JOIN LATERAL (
                        SELECT present,resulting_value,change_id,
                            committed_revision FROM epm.text_fact_event
                        WHERE workspace_id=c.workspace_id
                        AND application_id=c.application_id
                        AND coordinate_id=c.coordinate_id
                        AND committed_revision<=%s
                        ORDER BY committed_revision DESC,line_ordinal DESC
                        LIMIT 1) t ON true
                    ORDER BY r.ordinal,r.variant''',
                    (Jsonb(requested), scope.workspace_id,
                     scope.application_id, snapshot, snapshot)).fetchall()
                after = db.execute('''SELECT metadata_revision,commit_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if after is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                freshness = comparison_freshness(
                    snapshot_revision=snapshot,
                    pinned_metadata_revision=revision,
                    current_commit_revision=after['commit_revision'],
                    current_metadata_revision=after['metadata_revision'])
                if not freshness['metadataMatches']:
                    raise ValueError('STALE_METADATA_REVISION')
        states = {}
        for row in rows:
            if (row['stored_members'] is not None
                    and row['stored_members'] != row['members']):
                raise ValueError('COORDINATE_HASH_COLLISION')
            states[(row['ordinal'], row['variant'])] = self._cell(row)
        result = []
        for ordinal, other in enumerate(other_coordinates):
            base = states[(ordinal, 'base')]
            target = states[(ordinal, 'target')]
            delta = None
            if base['kind'] == target['kind'] == 'numeric':
                delta = format(Decimal(target['amount']) -
                               Decimal(base['amount']), '.8f')
            result.append({'otherMembers': other, 'base': base,
                           'target': target, 'delta': delta,
                           'equal': base['kind'] == target['kind'] and
                           base['amount'] == target['amount'] and
                           base['text'] == target['text']})
        return {'dimensionId': dimension, 'baseMemberId': base_member,
                'targetMemberId': target_member,
                'snapshotRevision': snapshot,
                'metadataRevision': revision, 'freshness': freshness,
                'rows': result}

    @staticmethod
    def _validate_metadata(db, scope, dimension, base, target, coordinates):
        active_axes = {row['dimension_id'] for row in db.execute('''
            SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s
            AND status='Active'
            AND model_role IS DISTINCT FROM 'Currency' ''',
            (scope.workspace_id, scope.application_id)).fetchall()}
        if dimension not in active_axes:
            raise ValueError('VERSION_COMPARE_DIMENSION_UNAVAILABLE')
        if any(set(other) | {dimension} != active_axes
               for other in coordinates):
            raise ValueError('COORDINATE_DIMENSIONS_MISMATCH')
        pairs = {(dimension, base), (dimension, target)}
        for other in coordinates:
            pairs.update(other.items())
        found = db.execute('''SELECT input.dimension_id,input.member_id
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            JOIN epm.member m ON m.workspace_id=%s
            AND m.application_id=%s
            AND m.dimension_id=input.dimension_id
            AND m.member_id=input.member_id AND m.status='Active' ''',
            (Jsonb([{'dimension_id': axis, 'member_id': member}
                    for axis, member in pairs]),
             scope.workspace_id, scope.application_id)).fetchall()
        if set((row['dimension_id'], row['member_id']) for row in found) != pairs:
            raise ValueError('VERSION_COMPARE_MEMBER_UNAVAILABLE')

    @staticmethod
    def _cell(row: dict) -> dict:
        numeric = bool(row['numeric_present'])
        text = bool(row['text_present'])
        if numeric and text:
            raise ValueError('COORDINATE_TYPE_CONFLICT')
        kind = 'numeric' if numeric else 'text' if text else 'missing'
        return {'kind': kind, 'present': numeric or text,
                'amount': format(row['amount'], '.8f') if numeric else None,
                'text': row['text_value'] if text else None,
                'changeId': (row['numeric_change_id'] if numeric else
                             row['text_change_id'] if text else ''),
                'lastRevision': (row['numeric_revision'] if numeric else
                                 row['text_revision'] if text else None)}
