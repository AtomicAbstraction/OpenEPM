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
from .postgres_cube_query import PostgresCubeQuery, _filter_members
from .postgres_dimensional_security_enforcement import filter_read_rows
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = 'facts.numeric.adjusted.scan'
_SERIES_KEY = re.compile(r'[0-9a-f]{64}\Z')


class PostgresAdjustedScan(PostgresCubeQuery):
    def scan_adjusted(self, scope: ApplicationScope, *,
                      members: dict[str,str] | None = None,
                      limit: int = 100, cursor: str | None = None,
                      snapshot_revision: int | None = None) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or type(limit) is not int or not 1 <= limit <= 500):
            raise ValueError('ADJUSTED_SCAN_BOUNDS_INVALID')
        if cursor is not None:
            if members is not None or snapshot_revision is not None:
                raise ValueError('ADJUSTED_CURSOR_IS_COMPLETE_REQUEST')
            payload = self._unpack_adjusted(cursor,scope)
            members = _filter_members(payload['members'])
            after = payload['after']
            snapshot_revision = payload['snapshotRevision']
            metadata_revision = payload['metadataRevision']
            security_revision = payload['securityRevision']
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
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'read')
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
                rows=self._page_adjusted(db,scope,members,after,
                                         snapshot_revision,limit+1)
                raw_page=rows[:limit]
                page=filter_read_rows(db,self.identity,scope,raw_page)
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
        has_more=len(rows)>limit
        next_cursor=(self._pack({
            'function':FUNCTION,
            'scope':[scope.workspace_id,scope.application_id],
            'identity':[self.identity.issuer,self.identity.subject_id],
            'members':members,'after':raw_page[-1]['seriesKey'],
            'snapshotRevision':snapshot_revision,
            'metadataRevision':metadata_revision,
            'securityRevision':security_revision,
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
        raw=db.execute(query,(
            revision,revision,revision,scope.workspace_id,
            scope.application_id,after,*filter_params,fetch_limit)).fetchall()
        rows=[]
        for row in raw:
            if row['text_present']:
                raise ValueError('ADJUSTED_BALANCE_TEXT_COORDINATE')
            source_present=bool(row['source_present'])
            adjustment=row['adjustment_amount']
            with localcontext() as context:
                context.prec=64
                adjusted=(row['source_amount'] if source_present else
                          Decimal(0))+adjustment
            NumericCell(True,adjusted,'')
            rows.append({
                'seriesKey':row['series_key'],'members':row['members'],
                'sourcePresent':source_present,
                'sourceAmount':(format(row['source_amount'],'.8f') if
                                source_present else None),
                'sourceChangeId':(row['source_change_id'] if
                                  source_present else ''),
                'sourceLastRevision':(row['source_revision'] if
                                      source_present else None),
                'adjustmentAmount':format(adjustment,'.8f'),
                'journalLineCount':row['line_count'],
                'lastJournalRevision':row['last_journal_revision'],
                'adjustedPresent':True,
                'adjustedAmount':format(adjusted,'.8f'),
            })
        return rows

    def _unpack_adjusted(self,token,scope):
        if not isinstance(token,str) or len(token)>16384:
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
                or type(payload['expiresAt']) is not int
                or payload['expiresAt']<time.time()):
            raise ValueError('ADJUSTED_CURSOR_INVALID')
        return payload
