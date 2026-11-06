"""Signed pages of planning variances over raw plus manual journals."""
from __future__ import annotations

import base64
import binascii
from decimal import Decimal, localcontext
import hmac
import json
import time
from hashlib import sha256

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import PostgresVersionCompare, _identifier


FUNCTION = 'planning.version.adjusted.scan'
_MISSING = {'kind': 'missing', 'present': False, 'amount': None,
            'sourcePresent': False, 'sourceAmount': None,
            'sourceChangeId': '', 'sourceLastRevision': None,
            'adjustmentAmount': '0.00000000', 'journalLineCount': 0,
            'lastJournalRevision': None}


class PostgresAdjustedVersionScan(PostgresCubeQuery):
    def scan(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program['languageVersion']) is not int
                or program['languageVersion'] != 2
                or program['function'] != FUNCTION
                or not isinstance(program['arguments'], dict)):
            raise ValueError('ADJUSTED_VERSION_SCAN_ARGUMENTS_INVALID')
        args = program['arguments']
        if 'cursor' in args:
            if set(args) != {'cursor'}:
                raise ValueError('ADJUSTED_VERSION_CURSOR_IS_COMPLETE_REQUEST')
            pin = self._unpack_scan(args['cursor'], scope)
            dimension = pin['dimensionId']
            base, target = pin['baseMemberId'], pin['targetMemberId']
            filters = _filter_members(pin['members'])
            limit = pin['limit']
            snapshot = pin['snapshotRevision']
            metadata_revision = pin['metadataRevision']
            after = pin['after']
        else:
            required = {'dimensionId','baseMemberId','targetMemberId'}
            if (not required <= set(args)
                    or set(args) - (required | {
                        'members','limit','snapshotRevision'})):
                raise ValueError('ADJUSTED_VERSION_SCAN_ARGUMENTS_INVALID')
            dimension = _identifier(args['dimensionId'], 'Dimension ID')
            base = _identifier(args['baseMemberId'], 'Base member ID')
            target = _identifier(args['targetMemberId'], 'Target member ID')
            filters = _filter_members(args.get('members', {}))
            limit = args.get('limit', 100)
            snapshot = args.get('snapshotRevision')
            metadata_revision = None
            after = ''
        if (base == target or dimension in filters
                or type(limit) is not int or not 1 <= limit <= 500
                or (snapshot is not None and
                    (type(snapshot) is not int or snapshot < 0))):
            raise ValueError('ADJUSTED_VERSION_SCAN_BOUNDS_INVALID')
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
                if (metadata_revision is not None and
                        metadata_revision != state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                metadata_revision = state['metadata_revision']
                if snapshot is None:
                    snapshot = state['commit_revision']
                if snapshot > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
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
                rows = db.execute('''WITH candidates AS (
                    SELECT c.members - %s AS other_members,
                        CASE WHEN cm.member_id=%s THEN 'base'
                             ELSE 'target' END AS variant,
                        n.present AS source_present,
                        n.resulting_amount AS source_amount,
                        n.change_id AS source_change_id,
                        n.committed_revision AS source_revision,
                        t.present AS text_present,
                        j.adjustment_amount,j.line_count,
                        j.last_journal_revision
                    FROM epm.coordinate_member cm
                    JOIN epm.coordinate c
                      ON c.workspace_id=cm.workspace_id
                     AND c.application_id=cm.application_id
                     AND c.coordinate_id=cm.coordinate_id
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
                    WHERE cm.workspace_id=%s AND cm.application_id=%s
                      AND cm.dimension_id=%s
                      AND cm.member_id IN (%s,%s)
                      AND c.members @> %s::jsonb
                      AND (c.members - %s)::text > %s
                      AND (COALESCE(n.present,false)
                           OR j.adjustment_amount<>0)
                )
                SELECT other_members,other_members::text AS page_key,
                    jsonb_object_agg(variant,jsonb_build_object(
                        'sourcePresent',source_present,
                        'sourceAmount',source_amount::text,
                        'sourceChangeId',source_change_id,
                        'sourceLastRevision',source_revision,
                        'adjustmentAmount',adjustment_amount::text,
                        'journalLineCount',line_count,
                        'lastJournalRevision',last_journal_revision,
                        'textPresent',text_present)) AS variants,
                    count(*) FILTER (WHERE variant='base') AS base_count,
                    count(*) FILTER (WHERE variant='target') AS target_count
                FROM candidates GROUP BY other_members
                ORDER BY other_members::text LIMIT %s''',
                    (dimension, base, snapshot, snapshot, snapshot,
                     scope.workspace_id, scope.application_id,
                     dimension, base, target, Jsonb(filters),
                     dimension, after, limit + 1)).fetchall()
                after_state = db.execute('''SELECT metadata_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after_state is None or
                        after_state['metadata_revision'] != metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
        page = []
        for row in rows[:limit]:
            if row['base_count'] > 1 or row['target_count'] > 1:
                raise ValueError('ADJUSTED_VERSION_SOURCE_CONFLICT')
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
            'dimensionId': dimension, 'baseMemberId': base,
            'targetMemberId': target, 'members': filters,
            'limit': limit, 'snapshotRevision': snapshot,
            'metadataRevision': metadata_revision,
            'after': rows[limit - 1]['page_key'],
            'expiresAt': int(time.time()) + 3600,
        }) if has_more else None
        return {'layer': 'raw_plus_manual_journal',
                'dimensionId': dimension, 'baseMemberId': base,
                'targetMemberId': target, 'members': filters,
                'snapshotRevision': snapshot,
                'metadataRevision': metadata_revision,
                'rows': page, 'hasMore': has_more,
                'nextCursor': next_cursor}

    @staticmethod
    def _cell(value: dict | None) -> dict:
        if value is None:
            return dict(_MISSING)
        if value['textPresent']:
            raise ValueError('ADJUSTED_BALANCE_TEXT_COORDINATE')
        source_present = bool(value['sourcePresent'])
        adjustment = Decimal(value['adjustmentAmount'])
        with localcontext() as context:
            context.prec = 64
            adjusted = ((Decimal(value['sourceAmount']) if source_present
                         else Decimal(0)) + adjustment)
        NumericCell(True, adjusted, '')
        return {'kind': 'numeric', 'present': True,
                'amount': format(adjusted, '.8f'),
                'sourcePresent': source_present,
                'sourceAmount': (format(Decimal(value['sourceAmount']), '.8f')
                                 if source_present else None),
                'sourceChangeId': (value['sourceChangeId']
                                   if source_present else ''),
                'sourceLastRevision': (value['sourceLastRevision']
                                       if source_present else None),
                'adjustmentAmount': format(adjustment, '.8f'),
                'journalLineCount': value['journalLineCount'],
                'lastJournalRevision': value['lastJournalRevision']}

    def _unpack_scan(self, token: object,
                     scope: ApplicationScope) -> dict:
        if not isinstance(token, str) or len(token) > 32768:
            raise ValueError('ADJUSTED_VERSION_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.cursor_secret, raw, sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('ADJUSTED_VERSION_CURSOR_INVALID') from error
        if (not isinstance(payload, dict)
                or set(payload) != {'function','scope','identity',
                                    'dimensionId','baseMemberId',
                                    'targetMemberId','members','limit',
                                    'snapshotRevision','metadataRevision',
                                    'after','expiresAt'}
                or payload['function'] != FUNCTION
                or payload['scope'] != [scope.workspace_id,
                                        scope.application_id]
                or payload['identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or any(not isinstance(payload[key], str)
                       or not 1 <= len(payload[key]) <= 200
                       for key in ('dimensionId','baseMemberId',
                                   'targetMemberId'))
                or not isinstance(payload['members'], dict)
                or not isinstance(payload['after'], str)
                or len(payload['after']) > 15000
                or type(payload['limit']) is not int
                or not 1 <= payload['limit'] <= 500
                or type(payload['snapshotRevision']) is not int
                or payload['snapshotRevision'] < 0
                or type(payload['metadataRevision']) is not int
                or payload['metadataRevision'] < 0
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < time.time()):
            raise ValueError('ADJUSTED_VERSION_CURSOR_INVALID')
        return payload
