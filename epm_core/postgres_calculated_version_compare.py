"""Exact comparison of two planning members in one published generation."""
from __future__ import annotations

from decimal import Decimal
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import PostgresVersionCompare, _identifier


FUNCTION = 'planning.version.calculation.compare'
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


class PostgresCalculatedVersionCompare:
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
            raise ValueError('CALCULATED_VERSION_ARGUMENTS_INVALID')
        args = program['arguments']
        required = {'resultKey', 'dimensionId', 'baseMemberId',
                    'targetMemberId', 'coordinates'}
        if (not required <= set(args)
                or set(args) - (required | {'expectedPublishedRevision'})):
            raise ValueError('CALCULATED_VERSION_ARGUMENTS_INVALID')
        result_key = args['resultKey']
        if not isinstance(result_key, str) or not _RESULT_KEY.fullmatch(result_key):
            raise ValueError('RESULT_KEY_INVALID')
        dimension = _identifier(args['dimensionId'], 'Dimension ID')
        base = _identifier(args['baseMemberId'], 'Base member ID')
        target = _identifier(args['targetMemberId'], 'Target member ID')
        if base == target:
            raise ValueError('VERSION_COMPARE_DISTINCT_MEMBERS_REQUIRED')
        coordinates = args['coordinates']
        if not isinstance(coordinates, list) or not 1 <= len(coordinates) <= 500:
            raise ValueError('CALCULATED_VERSION_BOUNDS_INVALID')
        others = []
        seen = set()
        for item in coordinates:
            if (not isinstance(item, dict) or len(item) > 31
                    or dimension in item):
                raise ValueError('CALCULATED_VERSION_COORDINATE_INVALID')
            other = {_identifier(axis, 'Dimension ID'):
                     _identifier(member, 'Member ID')
                     for axis, member in item.items()}
            key = tuple(sorted(other.items()))
            if key in seen:
                raise ValueError('VERSION_COMPARE_DUPLICATE_COORDINATE')
            seen.add(key)
            others.append(other)
        expected = args.get('expectedPublishedRevision')
        if expected is not None and (type(expected) is not int or expected < 1):
            raise ValueError('PUBLISHED_REVISION_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,
                    data_revision,policy_revision,commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresVersionCompare._validate_metadata(
                    db, scope, dimension, base, target, others)
                published = db.execute('''SELECT p.generation_id,
                    p.published_revision,g.source_commit_revision,
                    g.source_metadata_revision,g.source_policy_revision
                    FROM epm.calculation_publication p
                    JOIN epm.calculation_generation g
                    ON g.workspace_id=p.workspace_id
                    AND g.application_id=p.application_id
                    AND g.generation_id=p.generation_id
                    AND g.result_key=p.result_key
                    WHERE p.workspace_id=%s AND p.application_id=%s
                    AND p.result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     result_key)).fetchone()
                if published is None:
                    raise ValueError('PUBLICATION_UNAVAILABLE')
                if (expected is not None
                        and published['published_revision'] != expected):
                    raise ValueError('STALE_PUBLICATION_POINTER')
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
                        c.members AS stored_members,x.amount,
                        x.source_amount,x.source_change_id
                    FROM requested r
                    LEFT JOIN epm.coordinate c ON c.workspace_id=%s
                      AND c.application_id=%s AND c.series_key=r.series_key
                    LEFT JOIN epm.calculation_result x
                      ON x.workspace_id=c.workspace_id
                     AND x.application_id=c.application_id
                     AND x.coordinate_id=c.coordinate_id
                     AND x.generation_id=%s
                    ORDER BY r.ordinal,r.variant''',
                    (Jsonb(requested), scope.workspace_id,
                     scope.application_id,
                     published['generation_id'])).fetchall()
                current = db.execute('''SELECT s.metadata_revision,
                    p.generation_id,p.published_revision
                    FROM epm.application_state s
                    JOIN epm.calculation_publication p
                    ON p.workspace_id=s.workspace_id
                    AND p.application_id=s.application_id
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    AND p.result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     result_key)).fetchone()
                if (current is None or current['metadata_revision'] !=
                        state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                if (current['generation_id'] != published['generation_id']
                        or current['published_revision'] !=
                            published['published_revision']):
                    raise ValueError('STALE_PUBLICATION_POINTER')
        states = {}
        for row in rows:
            if (row['stored_members'] is not None
                    and row['stored_members'] != row['members']):
                raise ValueError('COORDINATE_HASH_COLLISION')
            amount = row['amount']
            states[(row['ordinal'], row['variant'])] = {
                'kind': 'numeric' if amount is not None else 'missing',
                'present': amount is not None,
                'amount': format(amount, '.8f') if amount is not None else None,
                'sourceAmount': (format(row['source_amount'], '.8f')
                                 if amount is not None else None),
                'sourceChangeId': (row['source_change_id']
                                   if amount is not None else None)}
        result_rows = []
        for ordinal, other in enumerate(others):
            base_cell = states[(ordinal, 'base')]
            target_cell = states[(ordinal, 'target')]
            delta = (format(Decimal(target_cell['amount']) -
                            Decimal(base_cell['amount']), '.8f')
                     if base_cell['present'] and target_cell['present']
                     else None)
            result_rows.append({
                'otherMembers': other, 'base': base_cell,
                'target': target_cell, 'delta': delta,
                'equal': (base_cell['kind'] == target_cell['kind'] and
                          base_cell['amount'] == target_cell['amount'])})
        return {'layer': 'calculated', 'resultKey': result_key,
                'dimensionId': dimension, 'baseMemberId': base,
                'targetMemberId': target,
                'generationId': published['generation_id'],
                'publishedRevision': published['published_revision'],
                'sourceCommitRevision': published['source_commit_revision'],
                'sourceMetadataRevision':
                    published['source_metadata_revision'],
                'sourcePolicyRevision': published['source_policy_revision'],
                'metadataRevision': state['metadata_revision'],
                'observedCommitRevision': state['commit_revision'],
                'rows': result_rows}
