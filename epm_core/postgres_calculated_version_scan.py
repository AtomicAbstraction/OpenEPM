"""Signed, generation-pinned pages of calculated planning variances."""
from __future__ import annotations

import base64
import binascii
from decimal import Decimal
import hmac
import json
import re
import time
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import PostgresVersionCompare, _identifier


FUNCTION = 'planning.version.calculation.scan'
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_GENERATION_ID = re.compile(r'[0-9a-f]{32}\Z')
_MISSING = {'kind': 'missing', 'present': False, 'amount': None,
            'sourceAmount': None, 'sourceChangeId': None}


class PostgresCalculatedVersionScan(PostgresCubeQuery):
    def scan(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)):
            raise ValueError('CALCULATED_VERSION_SCAN_ARGUMENTS_INVALID')
        args = program['arguments']
        if 'cursor' in args:
            if set(args) != {'cursor'}:
                raise ValueError('CALCULATED_VERSION_CURSOR_IS_COMPLETE_REQUEST')
            pin = self._unpack_scan(args['cursor'], scope)
            result_key = pin['resultKey']
            generation_id = pin['generationId']
            published_revision = pin['publishedRevision']
            dimension = pin['dimensionId']
            base, target = pin['baseMemberId'], pin['targetMemberId']
            filters = _filter_members(pin['members'])
            limit = pin['limit']
            metadata_revision = pin['metadataRevision']
            after = pin['after']
        else:
            required = {'resultKey', 'dimensionId',
                        'baseMemberId', 'targetMemberId'}
            if (not required <= set(args)
                    or set(args) - (required | {'members', 'limit'})):
                raise ValueError('CALCULATED_VERSION_SCAN_ARGUMENTS_INVALID')
            result_key = args['resultKey']
            generation_id = None
            published_revision = None
            dimension = _identifier(args['dimensionId'], 'Dimension ID')
            base = _identifier(args['baseMemberId'], 'Base member ID')
            target = _identifier(args['targetMemberId'], 'Target member ID')
            filters = _filter_members(args.get('members', {}))
            limit = args.get('limit', 100)
            metadata_revision = None
            after = ''
        if (not isinstance(result_key, str)
                or not _RESULT_KEY.fullmatch(result_key)
                or base == target or dimension in filters
                or type(limit) is not int or not 1 <= limit <= 500):
            raise ValueError('CALCULATED_VERSION_SCAN_BOUNDS_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (metadata_revision is not None and
                        metadata_revision != state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                metadata_revision = state['metadata_revision']
                PostgresVersionCompare._validate_metadata(
                    db, scope, dimension, base, target, [])
                if filters:
                    found = db.execute('''SELECT input.dimension_id,
                        input.member_id FROM jsonb_to_recordset(%s::jsonb)
                        AS input(dimension_id text,member_id text)
                        JOIN epm.dimension d ON d.workspace_id=%s
                        AND d.application_id=%s
                        AND d.dimension_id=input.dimension_id
                        AND d.status='Active'
                        JOIN epm.member m ON m.workspace_id=d.workspace_id
                        AND m.application_id=d.application_id
                        AND m.dimension_id=d.dimension_id
                        AND m.member_id=input.member_id
                        AND m.status='Active' ''',
                        (Jsonb([{'dimension_id': axis, 'member_id': member}
                                for axis, member in filters.items()]),
                         scope.workspace_id, scope.application_id)).fetchall()
                    if set((r['dimension_id'], r['member_id'])
                           for r in found) != set(filters.items()):
                        raise ValueError('CUBE_FILTER_MEMBER_UNAVAILABLE')
                if generation_id is None:
                    publication = db.execute('''SELECT generation_id,
                        published_revision FROM epm.calculation_publication
                        WHERE workspace_id=%s AND application_id=%s
                        AND result_key=%s''',
                        (scope.workspace_id, scope.application_id,
                         result_key)).fetchone()
                    if publication is None:
                        raise ValueError('PUBLICATION_UNAVAILABLE')
                    generation_id = publication['generation_id']
                    published_revision = publication['published_revision']
                generation = db.execute('''SELECT source_commit_revision
                    FROM epm.calculation_generation
                    WHERE workspace_id=%s AND application_id=%s
                    AND generation_id=%s AND result_key=%s
                    AND published_revision=%s''',
                    (scope.workspace_id, scope.application_id,
                     generation_id, result_key,
                     published_revision)).fetchone()
                if generation is None:
                    raise ValueError('CALCULATION_GENERATION_UNAVAILABLE')
                rows = db.execute('''WITH candidates AS (
                    SELECT c.members - %s AS other_members,
                        CASE WHEN cm.member_id=%s THEN 'base'
                             ELSE 'target' END AS variant,
                        x.amount,x.source_amount,x.source_change_id
                    FROM epm.calculation_result x
                    JOIN epm.coordinate c
                      ON c.workspace_id=x.workspace_id
                     AND c.application_id=x.application_id
                     AND c.coordinate_id=x.coordinate_id
                    JOIN epm.coordinate_member cm
                      ON cm.workspace_id=c.workspace_id
                     AND cm.application_id=c.application_id
                     AND cm.coordinate_id=c.coordinate_id
                    WHERE x.workspace_id=%s AND x.application_id=%s
                      AND x.generation_id=%s
                      AND cm.dimension_id=%s
                      AND cm.member_id IN (%s,%s)
                      AND c.members @> %s::jsonb
                      AND (c.members - %s)::text > %s
                )
                SELECT other_members,other_members::text AS page_key,
                    jsonb_object_agg(variant,jsonb_build_object(
                        'amount',amount::text,
                        'sourceAmount',source_amount::text,
                        'sourceChangeId',source_change_id)) AS variants,
                    count(*) FILTER (WHERE variant='base') AS base_count,
                    count(*) FILTER (WHERE variant='target') AS target_count
                FROM candidates GROUP BY other_members
                ORDER BY other_members::text LIMIT %s''',
                    (dimension, base, scope.workspace_id,
                     scope.application_id, generation_id,
                     dimension, base, target, Jsonb(filters),
                     dimension, after, limit + 1)).fetchall()
                after_state = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after_state is None or
                        after_state['metadata_revision'] != metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
        page = []
        for row in rows[:limit]:
            if row['base_count'] > 1 or row['target_count'] > 1:
                raise ValueError('CALCULATED_VERSION_SOURCE_CONFLICT')
            variants = row['variants']
            base_cell = self._cell(variants.get('base'))
            target_cell = self._cell(variants.get('target'))
            delta = (format(Decimal(target_cell['amount']) -
                            Decimal(base_cell['amount']), '.8f')
                     if base_cell['present'] and target_cell['present']
                     else None)
            page.append({'otherMembers': row['other_members'],
                         'base': base_cell, 'target': target_cell,
                         'delta': delta,
                         'equal': (base_cell['kind'] == target_cell['kind']
                                   and base_cell['amount'] ==
                                       target_cell['amount'])})
        has_more = len(rows) > limit
        next_cursor = self._pack({
            'function': FUNCTION,
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'resultKey': result_key, 'generationId': generation_id,
            'publishedRevision': published_revision,
            'dimensionId': dimension, 'baseMemberId': base,
            'targetMemberId': target, 'members': filters,
            'limit': limit, 'metadataRevision': metadata_revision,
            'after': rows[limit - 1]['page_key'],
            'expiresAt': int(time.time()) + 3600,
        }) if has_more else None
        return {'layer': 'calculated', 'resultKey': result_key,
                'generationId': generation_id,
                'publishedRevision': published_revision,
                'sourceCommitRevision': generation['source_commit_revision'],
                'dimensionId': dimension, 'baseMemberId': base,
                'targetMemberId': target, 'members': filters,
                'metadataRevision': metadata_revision,
                'rows': page, 'hasMore': has_more,
                'nextCursor': next_cursor}

    @staticmethod
    def _cell(value: dict | None) -> dict:
        if value is None:
            return dict(_MISSING)
        return {'kind': 'numeric', 'present': True,
                'amount': format(Decimal(value['amount']), '.8f'),
                'sourceAmount': format(Decimal(value['sourceAmount']), '.8f'),
                'sourceChangeId': value['sourceChangeId']}

    def _unpack_scan(self, token: object,
                     scope: ApplicationScope) -> dict:
        if not isinstance(token, str) or len(token) > 32768:
            raise ValueError('CALCULATED_VERSION_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.cursor_secret, raw, sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('CALCULATED_VERSION_CURSOR_INVALID') from error
        if (not isinstance(payload, dict)
                or set(payload) != {'function', 'scope', 'identity',
                                    'resultKey', 'generationId',
                                    'publishedRevision', 'dimensionId',
                                    'baseMemberId', 'targetMemberId',
                                    'members', 'limit', 'metadataRevision',
                                    'after', 'expiresAt'}
                or payload['function'] != FUNCTION
                or payload['scope'] != [scope.workspace_id,
                                        scope.application_id]
                or payload['identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or not isinstance(payload['resultKey'], str)
                or not _RESULT_KEY.fullmatch(payload['resultKey'])
                or not isinstance(payload['generationId'], str)
                or not _GENERATION_ID.fullmatch(payload['generationId'])
                or any(not isinstance(payload[key], str)
                       or not 1 <= len(payload[key]) <= 200
                       for key in ('dimensionId', 'baseMemberId',
                                   'targetMemberId'))
                or not isinstance(payload['members'], dict)
                or not isinstance(payload['after'], str)
                or len(payload['after']) > 15000
                or type(payload['limit']) is not int
                or not 1 <= payload['limit'] <= 500
                or type(payload['metadataRevision']) is not int
                or payload['metadataRevision'] < 0
                or type(payload['publishedRevision']) is not int
                or payload['publishedRevision'] < 1
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < time.time()):
            raise ValueError('CALCULATED_VERSION_CURSOR_INVALID')
        return payload
