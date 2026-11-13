"""Reader-safe, snapshot and current-state pinned side-by-side cube layers.

The view never treats a calculated result as an adjustment and never
derives a final accounting balance.  Raw, manual journal, adjusted input and
one selected current calculated result remain separately labelled evidence.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
import time
from decimal import Decimal, localcontext
from hashlib import sha256

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .current_object_contract import require_state_token
from .postgres_access import PostgresAccessChecker
from .postgres_calculation_status import published_result_status
from .postgres_calculation_visibility import (
    redact_calculation_lineage, redact_expression_lineage)
from .postgres_dimensional_security_enforcement import filter_read_rows
from .postgres_capability_contract import producer_capability_status
from .postgres_connection import connect_postgres
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


FUNCTION = 'facts.cube.layer-report.scan'
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_SERIES_KEY = re.compile(r'[0-9a-f]{64}\Z')


def _program(value: object) -> dict:
    if (not isinstance(value, dict)
            or set(value) != {'languageVersion', 'function', 'arguments'}
            or type(value['languageVersion']) is not int
            or value['languageVersion'] != 2
            or value['function'] != FUNCTION
            or not isinstance(value['arguments'], dict)):
        raise ValueError('LAYER_REPORT_PROGRAM_INVALID')
    args = value['arguments']
    if set(args) == {'cursor'}:
        if not isinstance(args['cursor'], str):
            raise ValueError('LAYER_REPORT_ARGUMENTS_INVALID')
        return args
    if (set(args) - {'members', 'snapshotRevision', 'resultKey',
                     'resultStateToken', 'limit'}
            or not {'resultKey', 'resultStateToken'} <= set(args)
            or not isinstance(args['resultKey'], str)
            or not _RESULT_KEY.fullmatch(args['resultKey'])
            or type(args.get('limit', 100)) is not int
            or not 1 <= args.get('limit', 100) <= 500
            or ('snapshotRevision' in args and
                (type(args['snapshotRevision']) is not int
                 or args['snapshotRevision'] < 0))):
        raise ValueError('LAYER_REPORT_ARGUMENTS_INVALID')
    require_state_token(args['resultStateToken'],
                        error='LAYER_REPORT_ARGUMENTS_INVALID')
    return {**args, 'members': _filter_members(args.get('members', {})),
            'limit': args.get('limit', 100)}


class PostgresCubeLayerReport(PostgresCubeQuery):
    def read(self, scope: ApplicationScope, program: dict) -> dict:
        args = _program(program)
        if 'cursor' in args:
            request = self._unpack_layer(args['cursor'], scope)
        else:
            request = {**args, 'after': '', 'metadataRevision': None,
                       'securityRevision': None, 'expiresAt': int(time.time()) + 3600}
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,security_revision,data_revision,
                    policy_revision,commit_revision,enabled_capabilities,
                    capability_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (request['metadataRevision'] is not None
                        and request['metadataRevision'] !=
                            state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                if (request['securityRevision'] is not None
                        and request['securityRevision'] != state['security_revision']):
                    raise ValueError('STALE_SECURITY_REVISION')
                metadata_revision = state['metadata_revision']
                security_revision = state['security_revision']
                snapshot = request.get('snapshotRevision')
                if snapshot is None:
                    snapshot = state['commit_revision']
                if snapshot > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
                current_result = db.execute('''SELECT state_token,
                    source_operation_id,committed_revision
                    FROM epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                      AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     request['resultKey'])).fetchone()
                if (current_result is None or current_result['state_token'] !=
                        request['resultStateToken']):
                    raise ValueError('LAYER_REPORT_RESULT_STATE_STALE')
                generation_id = current_result['source_operation_id']
                generation = self._generation(
                    db, scope, request['resultKey'], generation_id,
                    current_result['committed_revision'])
                self._require_untyped(generation)
                self._validate_filters(db, scope, request['members'])
                rows = self._page(db, scope, request['members'],
                    request['after'], snapshot, request['resultKey'],
                    request['limit'] + 1)
                raw_page = rows[:request['limit']]
                permitted = filter_read_rows(db, self.identity, scope, raw_page)
                page = [_wire_row(row) for row in permitted]
                restricted = len(permitted) != len(raw_page)
                for row in page:
                    if not row['calculated']['present']:
                        continue
                    lineage = {'members': row['members'], **row['calculated']}
                    if generation['function_name'] == 'facts.expression.calculate':
                        redact_expression_lineage(db, self.identity, scope,
                            generation['normalized_program'], [lineage])
                    redact_calculation_lineage(db, self.identity, scope, [lineage])
                    row['calculated'] = {key: value for key, value in lineage.items()
                        if key != 'members'}
                    if lineage.get('sourceLineageRestricted'):
                        row['sourceLineageRestricted'] = True
                        restricted = True
                currentness = published_result_status(
                    db, scope, request['resultKey'], request['resultStateToken'])
                current = db.execute('''SELECT state_token FROM
                    epm.calculation_result_state
                    WHERE workspace_id=%s AND application_id=%s
                      AND result_key=%s''',
                    (scope.workspace_id, scope.application_id,
                     request['resultKey'])).fetchone()
                after_state = db.execute('''SELECT metadata_revision,security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                      AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (after_state is None or after_state['metadata_revision'] !=
                        metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
                if after_state['security_revision'] != security_revision:
                    raise ValueError('STALE_SECURITY_REVISION')
                if (current is None or current['state_token'] !=
                        request['resultStateToken']):
                    raise ValueError('LAYER_REPORT_RESULT_STATE_CHANGED_RESTART')
                # Full profiles are internal evidence and may describe source
                # coordinates outside this authorized output page. Only their
                # verdicts are public; dependency and producer identities stay internal.
                profiles = currentness['profileStatuses']
                deep = {'matchesAtRead': all(item['matchesAtRead'] for item in profiles.values()),
                    'dependencies': {name: {'matchesAtRead': item['matchesAtRead'],
                        'truncated': bool(item.get('truncated'))}
                        for name, item in profiles.items()}}
        has_more = len(rows) > request['limit']
        next_cursor = (self._pack_layer({
            'function': FUNCTION,
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'members': request['members'], 'after': raw_page[-1]['series_key'],
            'snapshotRevision': snapshot,
            'metadataRevision': metadata_revision,
            'securityRevision': security_revision,
            'resultKey': request['resultKey'],
            'resultStateToken': request['resultStateToken'],
            'limit': request['limit'], 'expiresAt': request['expiresAt']})
            if has_more else None)
        revision_status = currentness['inputRevisionStatus']
        result = {'rows': page, 'hasMore': has_more,
            'nextCursor': next_cursor, 'snapshotRevision': snapshot,
            'metadataRevision': metadata_revision,
            'securityRevision': security_revision,
            'layers': ['raw', 'manualJournal', 'adjusted', 'calculated'],
            'calculation': {'resultKey': request['resultKey'],
                'resultStateToken': request['resultStateToken'],
                'function': generation['function_name'],
                'inputRevisionStatus': revision_status,
                'resultCurrentness': {key: currentness[key] for key in (
                    'basis', 'freshness', 'matchesAtRead', 'impactBarrier', 'definitionStatus')},
                'producerCapabilities': producer_capability_status(
                    generation['function_name'],
                    generation['normalized_program'],
                    generation['enabled_capabilities'],
                    generation['capability_revision'])},
            'arithmetic': 'raw_plus_manual_only_calculated_separate'}
        if restricted:
            result['sourceLineageRestricted'] = True
        else:
            result['calculation']['deepSourceStatus'] = deep
        return result

    @staticmethod
    def _generation(db, scope, result_key, generation_id,
                    published_revision):
        row = db.execute('''SELECT p.source_function AS function_name,
            p.source_commit_revision,p.source_metadata_revision,
            p.committed_revision AS published_revision,
            j.normalized_program,j.compiler_version,j.result AS job_result,
            j.expected_metadata_revision,j.expected_data_revision,
            j.expected_policy_revision,
            s.metadata_revision AS current_metadata_revision,
            s.data_revision AS current_data_revision,
            s.policy_revision AS current_policy_revision,
            s.commit_revision AS observed_commit_revision,
            s.enabled_capabilities,s.capability_revision
            FROM epm.calculation_result_state p JOIN epm.job j
              ON j.workspace_id=p.workspace_id
             AND j.application_id=p.application_id
             AND j.job_id=p.source_operation_id
            JOIN epm.application_state s
              ON s.workspace_id=p.workspace_id
             AND s.application_id=p.application_id
            WHERE p.workspace_id=%s AND p.application_id=%s
              AND p.source_operation_id=%s AND p.result_key=%s''',
            (scope.workspace_id, scope.application_id,
             generation_id, result_key)).fetchone()
        if row is None or row['published_revision'] != published_revision:
            raise ValueError('CALCULATION_GENERATION_UNAVAILABLE')
        return row

    @staticmethod
    def _require_untyped(generation):
        program = generation['normalized_program']
        expression = program.get('expression') if isinstance(program, dict) else None
        if ((isinstance(program, dict) and program.get('amountUnit') is not None)
                or generation['compiler_version'] in (
                'typed-numeric-expression-v22',
                'typed-numeric-expression-v23',
                'typed-numeric-expression-v24')
                or (isinstance(expression, dict)
                    and expression.get('op') == 'CurrencyConvert')
                or generation['function_name'] in (
                    'currency.amount.translate.publish',
                    'consolidation.equity.contribution.publish',
                    'consolidation.proportional.contribution.publish')):
            raise ValueError(
                'LAYER_REPORT_TYPED_RESULT_USE_CALCULATION_UNIT_READ')

    @staticmethod
    def _validate_filters(db, scope, members):
        if not members:
            return
        rows = db.execute('''SELECT input.dimension_id,input.member_id,
            d.dimension_id IS NOT NULL AND d.status='Active'
              AND d.model_role IS DISTINCT FROM 'Currency'
              AND m.member_id IS NOT NULL AND m.status='Active' AS valid
            FROM jsonb_to_recordset(%s::jsonb)
            AS input(dimension_id text,member_id text)
            LEFT JOIN epm.dimension d ON d.workspace_id=%s
             AND d.application_id=%s AND d.dimension_id=input.dimension_id
            LEFT JOIN epm.member m ON m.workspace_id=%s
             AND m.application_id=%s AND m.dimension_id=input.dimension_id
             AND m.member_id=input.member_id''',
            (Jsonb([{'dimension_id': axis, 'member_id': member}
                    for axis, member in members.items()]),
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchall()
        if len(rows) != len(members) or any(not row['valid'] for row in rows):
            raise ValueError('CUBE_FILTER_MEMBER_UNAVAILABLE')

    @staticmethod
    def _page(db, scope, members, after, snapshot, result_key, limit):
        predicates = []
        params = []
        for axis, member in members.items():
            predicates.append('''AND EXISTS(SELECT 1 FROM
                epm.coordinate_member cm WHERE cm.workspace_id=c.workspace_id
                AND cm.application_id=c.application_id
                AND cm.coordinate_id=c.coordinate_id
                AND cm.dimension_id=%s AND cm.member_id=%s)''')
            params.extend((axis, member))
        rows = db.execute(f'''WITH candidates AS (
            SELECT coordinate_id FROM epm.numeric_fact_event
             WHERE workspace_id=%s AND application_id=%s
               AND committed_revision<=%s
            UNION SELECT l.coordinate_id FROM epm.manual_journal_line l
             JOIN epm.manual_journal h USING(workspace_id,application_id,journal_id)
             WHERE l.workspace_id=%s AND l.application_id=%s
               AND h.committed_revision<=%s
            UNION SELECT coordinate_id FROM epm.calculation_result_current
             WHERE workspace_id=%s AND application_id=%s
               AND result_key=%s)
            SELECT c.series_key,c.members,n.present AS raw_present,
              n.resulting_amount AS raw_amount,n.change_id AS raw_change_id,
              n.committed_revision AS raw_revision,t.present AS text_present,
              j.adjustment_amount,j.line_count,j.last_journal_revision,
              r.source_amount,r.source_change_id,r.source_present,
              r.amount AS calculated_amount,r.source_lookup_lineage
            FROM candidates x JOIN epm.coordinate c
              ON c.workspace_id=%s AND c.application_id=%s
             AND c.coordinate_id=x.coordinate_id
            LEFT JOIN LATERAL(SELECT present,resulting_amount,change_id,
              committed_revision FROM epm.numeric_fact_event
              WHERE workspace_id=c.workspace_id
                AND application_id=c.application_id
                AND coordinate_id=c.coordinate_id
                AND committed_revision<=%s
              ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1) n ON true
            LEFT JOIN LATERAL(SELECT present FROM epm.text_fact_event
              WHERE workspace_id=c.workspace_id
                AND application_id=c.application_id
                AND coordinate_id=c.coordinate_id
                AND committed_revision<=%s
              ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1) t ON true
            LEFT JOIN LATERAL(SELECT COALESCE(sum(l.signed_amount),0)
              AS adjustment_amount,count(*) AS line_count,
              max(h.committed_revision) AS last_journal_revision
              FROM epm.manual_journal_line l JOIN epm.manual_journal h
              USING(workspace_id,application_id,journal_id)
              WHERE l.workspace_id=c.workspace_id
                AND l.application_id=c.application_id
                AND l.coordinate_id=c.coordinate_id
                AND h.committed_revision<=%s) j ON true
            LEFT JOIN epm.calculation_result_current r
              ON r.workspace_id=c.workspace_id
             AND r.application_id=c.application_id
             AND r.coordinate_id=c.coordinate_id AND r.result_key=%s
            WHERE c.series_key>%s {''.join(predicates)}
            ORDER BY c.series_key LIMIT %s''',
            (scope.workspace_id, scope.application_id, snapshot,
             scope.workspace_id, scope.application_id, snapshot,
             scope.workspace_id, scope.application_id, result_key,
             scope.workspace_id, scope.application_id,
             snapshot, snapshot, snapshot, result_key, after,
             *params, limit)).fetchall()
        return rows

    def _pack_layer(self, payload):
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False).encode()
        return base64.urlsafe_b64encode(raw + hmac.new(
            self.cursor_secret, raw, sha256).digest()).decode()

    def _unpack_layer(self, token, scope):
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError('LAYER_REPORT_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(signature, hmac.new(
                    self.cursor_secret, raw, sha256).digest()):
                raise ValueError('signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('LAYER_REPORT_CURSOR_INVALID') from error
        expected = {'function', 'scope', 'identity', 'members', 'after',
            'snapshotRevision', 'metadataRevision', 'securityRevision', 'resultKey',
            'resultStateToken', 'limit', 'expiresAt'}
        if (not isinstance(payload, dict) or set(payload) != expected
                or payload['function'] != FUNCTION
                or payload['scope'] != [scope.workspace_id, scope.application_id]
                or payload['identity'] != [self.identity.issuer,
                                           self.identity.subject_id]
                or not isinstance(payload['after'], str)
                or not _SERIES_KEY.fullmatch(payload['after'])
                or type(payload['snapshotRevision']) is not int
                or payload['snapshotRevision'] < 0
                or type(payload['metadataRevision']) is not int
                or payload['metadataRevision'] < 0
                or type(payload['securityRevision']) is not int
                or payload['securityRevision'] < 0
                or type(payload['limit']) is not int
                or not 1 <= payload['limit'] <= 500
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < time.time()
                or not isinstance(payload['resultKey'], str)
                or not _RESULT_KEY.fullmatch(payload['resultKey'])):
            raise ValueError('LAYER_REPORT_CURSOR_INVALID')
        require_state_token(payload['resultStateToken'],
                            error='LAYER_REPORT_CURSOR_INVALID')
        payload['members'] = _filter_members(payload['members'])
        return payload


def _wire_row(row):
    if row['text_present']:
        raise ValueError('LAYER_REPORT_NUMERIC_TEXT_CONFLICT')
    raw_present = bool(row['raw_present'])
    adjustment = row['adjustment_amount'] or Decimal(0)
    # Presence is evidence, not a non-zero test.  A journal can deliberately
    # establish or reverse an intersection to present zero.
    adjusted_present = raw_present or bool(row['line_count'])
    adjusted = None
    if adjusted_present:
        with localcontext() as context:
            context.prec = 64
            adjusted = (row['raw_amount'] if raw_present else Decimal(0)) + adjustment
        NumericCell(True, adjusted, '')
    calculated_present = row['calculated_amount'] is not None
    return {'seriesKey': row['series_key'], 'members': row['members'],
        'raw': {'present': raw_present,
            'amount': format(row['raw_amount'], '.8f') if raw_present else None,
            'changeId': row['raw_change_id'] or '',
            'lastRevision': row['raw_revision']},
        'manualJournal': {'contributed': bool(row['line_count']),
            'netAmount': format(adjustment, '.8f'),
            'lineCount': row['line_count'] or 0,
            'lastRevision': row['last_journal_revision']},
        'adjusted': {'present': adjusted_present,
            'amount': format(adjusted, '.8f') if adjusted_present else None},
        'calculated': {'present': calculated_present,
            'amount': (format(row['calculated_amount'], '.8f')
                       if calculated_present else None),
            'sourceAmount': (format(row['source_amount'], '.8f')
                             if calculated_present and
                                row['source_amount'] is not None else None),
            'sourceChangeId': row['source_change_id'] or '',
            'sourcePresent': (row['source_present']
                              if calculated_present else None),
            'sourceLookupLineage': ((row['source_lookup_lineage'] or [])
                                    if calculated_present else [])}}
