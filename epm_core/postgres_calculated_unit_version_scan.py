"""Signed, generation- and Currency-unit-pinned planning variance pages."""
from __future__ import annotations

import base64
import binascii
from decimal import Decimal
import hmac
import json
import re
import time
from hashlib import sha256

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_version_compare import PostgresVersionCompare, _identifier
from .postgres_calculated_unit_version_compare import (
    _context_status, _generation_status, _load_generation, _publication_status,
    _validate_currency_unit)


FUNCTION = 'planning.version.unit-calculation.scan'
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_GENERATION_ID = re.compile(r'[0-9a-f]{32}\Z')
_MISSING = {'kind': 'missing', 'present': False, 'amount': None,
            'sourceAmount': None, 'sourceChangeId': None,
            'rateLineage': None}


class PostgresCalculatedUnitVersionScan(PostgresCubeQuery):
    def scan(self, scope: ApplicationScope, program: dict) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(program, dict)
                or set(program) != {'languageVersion', 'function', 'arguments'}
                or type(program.get('languageVersion')) is not int
                or program.get('languageVersion') != 2
                or program.get('function') != FUNCTION
                or not isinstance(program.get('arguments'), dict)):
            raise ValueError('CALCULATED_UNIT_VERSION_SCAN_ARGUMENTS_INVALID')
        args = program['arguments']
        if 'cursor' in args:
            if set(args) != {'cursor'}:
                raise ValueError(
                    'CALCULATED_UNIT_VERSION_CURSOR_IS_COMPLETE_REQUEST')
            pin = self._unpack_scan(args['cursor'], scope)
            result_key = pin['resultKey']
            generation_id = pin['generationId']
            published_revision = pin['publishedRevision']
            currency_dimension = pin['currencyDimensionId']
            currency_member = pin['currencyMemberId']
            dimension = pin['dimensionId']
            base, target = pin['baseMemberId'], pin['targetMemberId']
            filters = _filter_members(pin['members'])
            limit = pin['limit']
            metadata_revision = pin['metadataRevision']
            after = pin['after']
        else:
            required = {'resultKey', 'currencyDimensionId',
                        'currencyMemberId', 'dimensionId',
                        'baseMemberId', 'targetMemberId'}
            if (not required <= set(args)
                    or set(args) - (required | {'members', 'limit'})):
                raise ValueError(
                    'CALCULATED_UNIT_VERSION_SCAN_ARGUMENTS_INVALID')
            result_key = args['resultKey']
            generation_id = None
            published_revision = None
            currency_dimension = _identifier(
                args['currencyDimensionId'], 'Currency dimension ID')
            currency_member = _identifier(
                args['currencyMemberId'], 'Currency member ID')
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
                or currency_dimension in filters
                or type(limit) is not int or not 1 <= limit <= 500):
            raise ValueError('CALCULATED_UNIT_VERSION_SCAN_BOUNDS_INVALID')

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
                if (metadata_revision is not None
                        and metadata_revision != state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                metadata_revision = state['metadata_revision']
                _validate_currency_unit(
                    db, scope, currency_dimension, currency_member)
                PostgresVersionCompare._validate_metadata(
                    db, scope, dimension, base, target, [])
                if filters:
                    found = db.execute('''SELECT input.dimension_id,
                        input.member_id FROM jsonb_to_recordset(%s::jsonb)
                        AS input(dimension_id text,member_id text)
                        JOIN epm.member m ON m.workspace_id=%s
                        AND m.application_id=%s
                        AND m.dimension_id=input.dimension_id
                        AND m.member_id=input.member_id
                        AND m.status='Active'
                        JOIN epm.dimension d ON d.workspace_id=m.workspace_id
                        AND d.application_id=m.application_id
                        AND d.dimension_id=m.dimension_id
                        AND d.status='Active'
                        AND d.model_role IS DISTINCT FROM 'Currency' ''',
                        (Jsonb([{'dimension_id': axis, 'member_id': member}
                                for axis, member in filters.items()]),
                         scope.workspace_id, scope.application_id)).fetchall()
                    if set((row['dimension_id'], row['member_id'])
                           for row in found) != set(filters.items()):
                        raise ValueError('CUBE_FILTER_MEMBER_UNAVAILABLE')
                generation = _load_generation(
                    db, scope, result_key, generation_id,
                    published_revision)
                generation_id = generation['generation_id']
                published_revision = generation['published_revision']
                unit_exists = db.execute('''SELECT 1
                    FROM epm.calculation_unit_result
                    WHERE workspace_id=%s AND application_id=%s
                      AND generation_id=%s
                      AND output_unit_currency_dimension_id=%s
                      AND output_unit_currency_member_id=%s LIMIT 1''',
                    (scope.workspace_id, scope.application_id, generation_id,
                     currency_dimension, currency_member)).fetchone()
                if unit_exists is None:
                    raise ValueError('CALCULATED_UNIT_RESULT_UNAVAILABLE')
                filter_sql, filter_params = [], []
                for axis, member in filters.items():
                    filter_sql.append('''AND EXISTS (SELECT 1
                        FROM epm.coordinate_member fm
                        WHERE fm.workspace_id=c.workspace_id
                          AND fm.application_id=c.application_id
                          AND fm.coordinate_id=c.coordinate_id
                          AND fm.dimension_id=%s AND fm.member_id=%s)''')
                    filter_params.extend((axis, member))
                rows = db.execute(f'''WITH candidates AS (
                    SELECT c.members - %s AS other_members,
                        CASE WHEN cm.member_id=%s THEN 'base'
                             ELSE 'target' END AS variant,
                        x.amount,x.source_amount,x.source_change_id,
                        x.rate_strategy,x.rate_numerator,x.rate_denominator,
                        x.rate_sources
                    FROM epm.calculation_unit_result x
                    JOIN epm.coordinate c USING
                        (workspace_id,application_id,coordinate_id)
                    JOIN epm.coordinate_member cm USING
                        (workspace_id,application_id,coordinate_id)
                    WHERE x.workspace_id=%s AND x.application_id=%s
                      AND x.generation_id=%s
                      AND x.output_unit_currency_dimension_id=%s
                      AND x.output_unit_currency_member_id=%s
                      AND cm.dimension_id=%s
                      AND cm.member_id IN (%s,%s)
                      {''.join(filter_sql)}
                      AND (c.members - %s)::text > %s
                )
                SELECT other_members,other_members::text AS page_key,
                    jsonb_object_agg(variant,jsonb_build_object(
                        'amount',amount::text,
                        'sourceAmount',source_amount::text,
                        'sourceChangeId',source_change_id,
                        'rateStrategy',rate_strategy,
                        'rateNumerator',rate_numerator::text,
                        'rateDenominator',rate_denominator::text,
                        'rateSources',rate_sources)) AS variants,
                    count(*) FILTER (WHERE variant='base') AS base_count,
                    count(*) FILTER (WHERE variant='target') AS target_count
                FROM candidates GROUP BY other_members
                ORDER BY other_members::text LIMIT %s''',
                    (dimension, base, scope.workspace_id,
                     scope.application_id, generation_id,
                     currency_dimension, currency_member, dimension,
                     base, target, *filter_params, dimension, after,
                     limit + 1)).fetchall()
                after_state = db.execute('''SELECT metadata_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after_state is None or
                        after_state['metadata_revision'] != metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
                publication = _publication_status(
                    db, scope, result_key, generation_id,
                    published_revision)
                status = _generation_status(db, scope, generation)
                context = _context_status(publication, status)
        page = []
        for row in rows[:limit]:
            if row['base_count'] > 1 or row['target_count'] > 1:
                raise ValueError('CALCULATED_UNIT_VERSION_SOURCE_CONFLICT')
            variants = row['variants']
            base_cell = self._cell(variants.get('base'))
            target_cell = self._cell(variants.get('target'))
            delta = (format(Decimal(target_cell['amount']) -
                            Decimal(base_cell['amount']), '.8f')
                     if base_cell['present'] and target_cell['present']
                     else None)
            page.append({'otherMembers': row['other_members'],
                'base': base_cell, 'target': target_cell, 'delta': delta,
                'equal': (base_cell['kind'] == target_cell['kind'] and
                          base_cell['amount'] == target_cell['amount'])})
        has_more = len(rows) > limit
        next_cursor = self._pack({
            'function': FUNCTION,
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'resultKey': result_key, 'generationId': generation_id,
            'publishedRevision': published_revision,
            'currencyDimensionId': currency_dimension,
            'currencyMemberId': currency_member,
            'dimensionId': dimension, 'baseMemberId': base,
            'targetMemberId': target, 'members': filters,
            'limit': limit, 'metadataRevision': metadata_revision,
            'after': rows[limit - 1]['page_key'],
            'expiresAt': int(time.time()) + 3600,
        }) if has_more else None
        return {'layer': 'calculated_typed_unit', 'resultKey': result_key,
            'generationId': generation_id,
            'publishedRevision': published_revision,
            'sourceCommitRevision': generation['source_commit_revision'],
            'sourceMetadataRevision': generation['source_metadata_revision'],
            'sourcePolicyRevision': generation['source_policy_revision'],
            'outputUnit': {'type': 'Currency',
                'dimensionId': currency_dimension, 'memberId': currency_member},
            'dimensionId': dimension, 'baseMemberId': base,
            'targetMemberId': target, 'members': filters,
            'metadataRevision': metadata_revision,
            'publicationStatus': publication, **status,
            'contextStatus': context,
            'rows': page, 'hasMore': has_more,
            'nextCursor': next_cursor}

    @staticmethod
    def _cell(value: dict | None) -> dict:
        if value is None:
            return dict(_MISSING)
        return {'kind': 'numeric', 'present': True,
            'amount': format(Decimal(value['amount']), '.8f'),
            'sourceAmount': format(Decimal(value['sourceAmount']), '.8f'),
            'sourceChangeId': value['sourceChangeId'],
            'rateLineage': {'strategy': value['rateStrategy'],
                'exactFactor': {'numerator': value['rateNumerator'],
                                'denominator': value['rateDenominator']},
                'sources': value['rateSources']}}

    def _unpack_scan(self, token: object, scope: ApplicationScope) -> dict:
        if not isinstance(token, str) or len(token) > 32768:
            raise ValueError('CALCULATED_UNIT_VERSION_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.cursor_secret, raw, sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError(
                'CALCULATED_UNIT_VERSION_CURSOR_INVALID') from error
        expected = {'function', 'scope', 'identity', 'resultKey',
            'generationId', 'publishedRevision', 'currencyDimensionId',
            'currencyMemberId', 'dimensionId', 'baseMemberId',
            'targetMemberId', 'members', 'limit', 'metadataRevision',
            'after', 'expiresAt'}
        if (not isinstance(payload, dict) or set(payload) != expected
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
                       for key in ('currencyDimensionId', 'currencyMemberId',
                                   'dimensionId', 'baseMemberId',
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
            raise ValueError('CALCULATED_UNIT_VERSION_CURSOR_INVALID')
        return payload

    def _pack(self, payload: dict) -> str:
        raw = json.dumps(payload, sort_keys=True,
                         separators=(',', ':')).encode()
        return base64.b64encode(
            raw + hmac.new(self.cursor_secret, raw, sha256).digest(),
            altchars=b'-_').decode()
