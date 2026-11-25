"""Bounded snapshot reads of raw numeric facts plus manual journals.

This is a two-layer arithmetic read, not a consolidation policy result.
Only coordinates with a present numeric source or nonzero net manual
adjustment are returned. Present text at a returned point is an error.
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

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope, NumericCell
from .postgres_access import PostgresAccessChecker
from .postgres_cube_query import (
    MAX_CURSOR_CHARACTERS, MAX_FILTER_AXES, MAX_FILTER_ID_LENGTH, MAX_PAGE_SIZE,
    PostgresCubeQuery, _FILTER_ID, _filter_members, _read_authorization_digest,
)
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import authorized_read_page
from .postgres_manual_journal import ADJUSTED_READ_FUNCTION
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'facts.numeric.adjusted.scan'
PUBLIC_READS = frozenset((FUNCTION, ADJUSTED_READ_FUNCTION))
_SERIES_KEY = re.compile(r'[0-9a-f]{64}\Z')


def read_program_contract(function: str) -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    paged = function == FUNCTION
    revision = {'type': 'integer', 'minimum': 0}
    nullable_revision = {**revision, 'type': ['integer', 'null']}
    identifier = {'type': 'string', 'minLength': 1}
    point = {'type': 'object', 'minProperties': 1,
             'propertyNames': identifier, 'additionalProperties': identifier}
    amount = {'type': 'string', 'pattern': r'^-?[0-9]{1,20}\.[0-9]{8}(?![\s\S])'}
    net_adjustment = {'type': 'string', 'pattern': r'^-?[0-9]+\.[0-9]{8}(?![\s\S])'}
    nullable_amount = {**amount, 'type': ['string', 'null']}
    presence = {
        'sourcePresent': {'type': 'boolean'}, 'sourceAmount': nullable_amount,
        'sourceChangeId': {'type': 'string'}, 'sourceLastRevision': nullable_revision,
        'adjustedPresent': {'type': 'boolean'}, 'adjustedAmount': nullable_amount,
    }
    source_invariant = {
        'if': {'properties': {'sourcePresent': {'const': True}}},
        'then': {'properties': {'sourceAmount': amount, 'sourceChangeId': identifier,
                                'sourceLastRevision': revision}},
        'else': {'properties': {'sourceAmount': {'type': 'null'}, 'sourceChangeId': {'const': ''},
                                'sourceLastRevision': {'type': 'null'}}},
    }
    adjusted_invariant = {
        'if': {'properties': {'adjustedPresent': {'const': True}}},
        'then': {'properties': {'adjustedAmount': amount}},
        'else': {'properties': {'adjustedAmount': {'type': 'null'}}},
    }
    position = {'snapshotRevision': revision, 'metadataRevision': revision}
    journal = {'members': point, 'adjustmentAmount': net_adjustment,
               'lastJournalRevision': nullable_revision}
    rules = [
        'A snapshot pins committed facts and manual-journal entries. The core checks present-day application and dimensional authority.',
        'adjustmentAmount is the exact net of retained manual-journal lines and linked reversals. Full consolidation is a separate calculation.',
    ]
    if paged:
        filter_id = {**identifier, 'maxLength': MAX_FILTER_ID_LENGTH,
            'pattern': '^' + _FILTER_ID.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
        cursor = {'type': 'string', 'minLength': 1, 'maxLength': MAX_CURSOR_CHARACTERS}
        arguments = obj({
            'members': {'type': ['object', 'null'], 'maxProperties': MAX_FILTER_AXES,
                        'propertyNames': filter_id, 'additionalProperties': filter_id},
            'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_PAGE_SIZE, 'default': 100},
            'snapshotRevision': nullable_revision, 'cursor': {**cursor, 'type': ['string', 'null']},
        }, [])
        arguments['if'] = {'required': ['cursor'], 'properties': {'cursor': {'type': 'string'}}}
        arguments['then'] = {'properties': {'members': {'type': 'null'},
                                             'snapshotRevision': {'type': 'null'}}}
        row = {**obj({**journal, **presence, 'adjustedPresent': {'const': True},
                      'adjustedAmount': amount, 'journalLineCount': revision,
                      'seriesKey': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}}),
               **source_invariant}
        result = {**obj({**position, 'securityRevision': revision,
            'rows': {'type': 'array', 'items': row, 'maxItems': MAX_PAGE_SIZE},
            'nextCursor': {**cursor, 'type': ['string', 'null']}, 'hasMore': {'type': 'boolean'},
            'layers': {'const': ['raw_numeric', 'manual_journal']}}),
            'if': {'properties': {'hasMore': {'const': True}}},
            'then': {'properties': {'nextCursor': cursor, 'rows': {'minItems': 1}}},
            'else': {'properties': {'nextCursor': {'type': 'null'}}}}
        examples = [
            read_example(function, {'limit': 100}, name='Read the first authorized adjusted page',
                binding='Use the authorized application. An application with no visible adjusted values returns a terminal empty page.'),
            read_example(function, {'cursor': 'example-cursor'}, name='Continue the same adjusted snapshot',
                binding='Copy nextCursor from the previous page under the same identity. The cursor supplies filters and snapshot revision.'),
        ]
        rules += [
            'The scan lists visible coordinates with a present raw numeric source or nonzero net adjustment. Present zero is included. Missing source fields are null with an empty sourceChangeId.',
            'Page size may change on continuation. The cursor pins scope, identity, effective authority, security and metadata. The core fails closed if it cannot prove a complete authorized page within the candidate budget.',
        ]
        owner = 'PostgresAdjustedScan.scan_adjusted'
        recovery = 'Restart from the first page after cursor expiry, a rejected cursor or a change in metadata or authorization.'
    else:
        arguments = obj({'members': {**point, 'maxProperties': MAX_FILTER_AXES},
                         'snapshotRevision': nullable_revision}, ['members'])
        result = {**obj({**position, **journal, **presence, 'lineCount': revision}),
                  'allOf': [source_invariant, adjusted_invariant]}
        rules.append('A missing source and zero net adjustment produce adjustedPresent=false and adjustedAmount=null. A present zero or a present source offset by adjustments returns adjustedPresent=true and an exact zero. A present text cell is unavailable as a numeric adjusted read.')
        examples = [read_example(function, {'members': {'Account': 'Debit'}},
            name='Read a single full-grain journal coordinate',
            binding='Replace the example selection with one current member ID on every active fact axis in the authorized financial application.')]
        owner = 'PostgresManualJournal.read_balance'
        recovery = 'Refresh current metadata and authority. Verify the full coordinate and use a committed snapshot revision before retrying.'
    contract = read_contract(function, arguments, result, owner=owner, examples=examples,
                             semantic_rules=rules)
    contract['programContract']['recovery'] = recovery
    return contract


class PostgresAdjustedScan(PostgresCubeQuery):
    def scan_adjusted(self, scope: ApplicationScope, *,
                      members: dict[str,str] | None = None,
                      limit: int = 100, cursor: str | None = None,
                      snapshot_revision: int | None = None) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or type(limit) is not int or not 1 <= limit <= MAX_PAGE_SIZE):
            raise ValueError('ADJUSTED_SCAN_BOUNDS_INVALID')
        expected_authorization = None
        if cursor is not None:
            if members is not None or snapshot_revision is not None:
                raise ValueError('ADJUSTED_CURSOR_IS_COMPLETE_REQUEST')
            payload = self._unpack_adjusted(cursor,scope)
            members = _filter_members(payload['members'])
            after = payload['after']
            snapshot_revision = payload['snapshotRevision']
            metadata_revision = payload['metadataRevision']
            security_revision = payload['securityRevision']
            expected_authorization = payload['authorizationDigest']
        else:
            members = _filter_members({} if members is None else members)
            after = ''
            metadata_revision = None
            security_revision = None
        if (snapshot_revision is not None and
                (type(snapshot_revision) is not int or snapshot_revision < 0)):
            raise ValueError('SNAPSHOT_REVISION_INVALID')
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db,scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
                authorization = _read_authorization_digest(access)
                if expected_authorization is not None and authorization != expected_authorization:
                    raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
                state=db.execute('''SELECT metadata_revision,security_revision,
                    commit_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (metadata_revision is not None and
                        metadata_revision != state['metadata_revision']):
                    raise ValueError('STALE_METADATA_REVISION')
                if (security_revision is not None and
                        security_revision != state['security_revision']):
                    raise ValueError('STALE_SECURITY_REVISION')
                if snapshot_revision is None:
                    snapshot_revision=state['commit_revision']
                if snapshot_revision > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
                metadata_revision=state['metadata_revision']
                security_revision=state['security_revision']
                if members:
                    found=db.execute('''SELECT input.dimension_id,
                        input.member_id,m.member_id IS NOT NULL AS found
                        FROM jsonb_to_recordset(%s::jsonb)
                        AS input(dimension_id text,member_id text)
                        LEFT JOIN epm.member m ON m.workspace_id=%s
                        AND m.application_id=%s
                        AND m.dimension_id=input.dimension_id
                        AND m.member_id=input.member_id''',
                        (Jsonb([{'dimension_id':axis,'member_id':member}
                                for axis,member in members.items()]),
                         scope.workspace_id,
                         scope.application_id)).fetchall()
                    if any(not row['found'] for row in found):
                        raise ValueError('CUBE_FILTER_MEMBER_UNAVAILABLE')
                rows, has_more, next_after = authorized_read_page(
                    db, self.identity, scope, after=after, limit=limit,
                    fetch=lambda anchor, count: self._page_adjusted(
                        db, scope, members, anchor, snapshot_revision, count),
                    cursor_key=lambda row: row['series_key'], expected_access=access)
                after_state=db.execute('''SELECT metadata_revision,
                    security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id,scope.application_id)).fetchone()
                if (not after_state or after_state['metadata_revision'] !=
                        metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
                if after_state['security_revision'] != security_revision:
                    raise ValueError('STALE_SECURITY_REVISION')
                if PostgresAccessChecker.check_in_transaction(db, self.identity, scope, 'read') != access:
                    raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
                page = [self._adjusted_row(row) for row in rows]
        next_cursor=(self._pack({
            'function':FUNCTION,
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'members':members,'after':next_after,
            'snapshotRevision':snapshot_revision,
            'metadataRevision':metadata_revision,
            'securityRevision':security_revision,
            'authorizationDigest':authorization,
            'expiresAt':int(time.time())+3600,
        }) if has_more else None)
        return {'rows':page,'nextCursor':next_cursor,'hasMore':has_more,
                'snapshotRevision':snapshot_revision,
                'metadataRevision':metadata_revision,
                'securityRevision':security_revision,
                'layers':['raw_numeric','manual_journal']}

    @staticmethod
    def _page_adjusted(db,scope,members,after,revision,fetch_limit):
        predicates=[]
        filter_params=[]
        for axis,member in members.items():
            predicates.append('''AND EXISTS (SELECT 1 FROM
                epm.coordinate_member cm
                WHERE cm.workspace_id=c.workspace_id
                AND cm.application_id=c.application_id
                AND cm.coordinate_id=c.coordinate_id
                AND cm.dimension_id=%s AND cm.member_id=%s)''')
            filter_params.extend((axis,member))
        query=f'''SELECT c.series_key,c.members,
            n.present AS source_present,n.resulting_amount AS source_amount,
            n.change_id AS source_change_id,
            n.committed_revision AS source_revision,
            t.present AS text_present,
            j.adjustment_amount,j.line_count,j.last_journal_revision
            FROM epm.coordinate c
            LEFT JOIN LATERAL (
                SELECT present,resulting_amount,change_id,committed_revision
                FROM epm.numeric_fact_event
                WHERE workspace_id=c.workspace_id
                AND application_id=c.application_id
                AND coordinate_id=c.coordinate_id
                AND committed_revision<=%s
                ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1
            ) n ON true
            LEFT JOIN LATERAL (
                SELECT present FROM epm.text_fact_event
                WHERE workspace_id=c.workspace_id
                AND application_id=c.application_id
                AND coordinate_id=c.coordinate_id
                AND committed_revision<=%s
                ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1
            ) t ON true
            LEFT JOIN LATERAL (
                SELECT COALESCE(sum(l.signed_amount),0) AS adjustment_amount,
                       count(*) AS line_count,
                       max(h.committed_revision) AS last_journal_revision
                FROM epm.manual_journal_line l
                JOIN epm.manual_journal h USING
                    (workspace_id,application_id,journal_id)
                WHERE l.workspace_id=c.workspace_id
                AND l.application_id=c.application_id
                AND l.coordinate_id=c.coordinate_id
                AND h.committed_revision<=%s
            ) j ON true
            WHERE c.workspace_id=%s AND c.application_id=%s
            AND c.series_key>%s
            {''.join(predicates)}
            AND (COALESCE(n.present,false) OR j.adjustment_amount<>0)
            ORDER BY c.series_key LIMIT %s'''
        return db.execute(query,(
            revision,revision,revision,scope.workspace_id,
            scope.application_id,after,*filter_params,fetch_limit)).fetchall()

    @staticmethod
    def _adjusted_row(row):
        if row['text_present']:
            raise ValueError('ADJUSTED_BALANCE_TEXT_COORDINATE')
        source_present = bool(row['source_present'])
        adjustment = row['adjustment_amount']
        with localcontext() as context:
            context.prec = 64
            adjusted = (row['source_amount'] if source_present else Decimal(0)) + adjustment
        NumericCell(True, adjusted, '')
        return {
            'seriesKey': row['series_key'], 'members': row['members'],
            'sourcePresent': source_present,
            'sourceAmount': format(row['source_amount'], '.8f') if source_present else None,
            'sourceChangeId': row['source_change_id'] if source_present else '',
            'sourceLastRevision': row['source_revision'] if source_present else None,
            'adjustmentAmount': format(adjustment, '.8f'),
            'journalLineCount': row['line_count'],
            'lastJournalRevision': row['last_journal_revision'],
            'adjustedPresent': True,
            'adjustedAmount': format(adjusted, '.8f'),
        }

    def _unpack_adjusted(self,token,scope):
        if not isinstance(token,str) or len(token)>MAX_CURSOR_CHARACTERS:
            raise ValueError('ADJUSTED_CURSOR_INVALID')
        try:
            packed=base64.b64decode(token,altchars=b'-_',validate=True)
            raw,signature=packed[:-32],packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.cursor_secret,raw,sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload=json.loads(raw)
        except (ValueError,TypeError,binascii.Error) as error:
            raise ValueError('ADJUSTED_CURSOR_INVALID') from error
        if (not isinstance(payload,dict)
                or set(payload)!={'function','scope','identity','members',
                                  'after','snapshotRevision',
                                  'metadataRevision','securityRevision',
                                  'authorizationDigest',
                                  'expiresAt'}
                or payload['function']!=FUNCTION
                or payload['scope']!=[scope.workspace_id,scope.application_id]
                or payload['identity']!=[self.identity.issuer,
                                        self.identity.subject_id]
                or not isinstance(payload['after'],str)
                or not _SERIES_KEY.fullmatch(payload['after'])
                or type(payload['snapshotRevision']) is not int
                or payload['snapshotRevision']<0
                or type(payload['metadataRevision']) is not int
                or payload['metadataRevision']<0
                or type(payload['securityRevision']) is not int
                or payload['securityRevision']<0
                or not isinstance(payload['authorizationDigest'],str)
                or not _SERIES_KEY.fullmatch(payload['authorizationDigest'])
                or type(payload['expiresAt']) is not int
                or payload['expiresAt']<time.time()):
            raise ValueError('ADJUSTED_CURSOR_INVALID')
        return payload
