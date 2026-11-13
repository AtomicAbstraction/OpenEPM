"""Bounded, snapshot-pinned PostgreSQL reads over the generic EPM cube.

This reads authoritative numeric/text fact state only. Calculation generations,
source layers, hierarchy selectors and analytical acceleration are separate
contracts; no public caller supplies SQL or a database role.
"""
from __future__ import annotations

import base64
import binascii
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
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_enforcement import authorized_read_page
from .postgres_numeric_store import PostgresNumericFactStore


_SERIES_KEY = re.compile(r'[0-9a-f]{64}\Z')
_ROLE_COLUMNS = {
    'Entity': 'entity_member', 'Account': 'account_member',
    'Scenario': 'scenario_member', 'Year': 'year_member',
    'Period': 'period_member', 'Value': 'value_member', 'View': 'view_member',
    'ICP': 'icp_member', 'DataType': 'data_type_member',
}


def _filter_members(value: object) -> dict[str, str]:
    if (not isinstance(value, dict) or len(value) > 32
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in value.items())):
        raise ValueError('CUBE_FILTER_INVALID')
    return dict(sorted(value.items()))


class PostgresCubeQuery:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        if not isinstance(cursor_secret, bytes) or len(cursor_secret) < 32:
            raise ValueError('A server-owned cursor secret of 32+ bytes is required')
        self.dsn = dsn
        self.identity = identity
        self.cursor_secret = cursor_secret

    def scan(self, scope: ApplicationScope, *,
             members: dict[str, str] | None = None,
             limit: int | None = None, cursor: str | None = None,
             snapshot_revision: int | None = None,
             include_missing: bool = False,
             include_zero: bool = True) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or (limit is not None and (type(limit) is not int
                    or not 1 <= limit <= 500))
                or not isinstance(include_missing, bool)
                or not isinstance(include_zero, bool)):
            raise ValueError('CUBE_QUERY_BOUNDS_INVALID')
        if cursor is not None:
            if (members is not None or snapshot_revision is not None
                    or include_missing or not include_zero):
                raise ValueError('CUBE_CURSOR_IS_COMPLETE_REQUEST')
            payload = self._unpack(cursor, scope)
            if limit is not None and limit != payload['limit']:
                raise ValueError('CUBE_CURSOR_PAGE_SIZE_CHANGED')
            limit = payload['limit']
            members = _filter_members(payload['members'])
            after = payload['after']
            snapshot_revision = payload['snapshotRevision']
            metadata_revision = payload['metadataRevision']
            security_revision = payload['securityRevision']
            include_missing = payload['includeMissing']
            include_zero = payload['includeZero']
        else:
            limit = 100 if limit is None else limit
            members = _filter_members({} if members is None else members)
            after = ''
            metadata_revision = None
            security_revision = None
        if (snapshot_revision is not None and
                (type(snapshot_revision) is not int or snapshot_revision < 0)):
            raise ValueError('SNAPSHOT_REVISION_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'read')
                state = db.execute('''SELECT metadata_revision,commit_revision,
                    security_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if (metadata_revision is not None and
                        state['metadata_revision'] != metadata_revision):
                    raise ValueError('STALE_METADATA_REVISION')
                if (security_revision is not None and
                        state['security_revision'] != security_revision):
                    raise ValueError('STALE_SECURITY_REVISION')
                if snapshot_revision is None:
                    snapshot_revision = state['commit_revision']
                if snapshot_revision > state['commit_revision']:
                    raise ValueError('SNAPSHOT_NOT_COMMITTED')
                metadata_revision = state['metadata_revision']
                security_revision = state['security_revision']
                if members:
                    found = db.execute('''SELECT input.dimension_id,
                        input.member_id,m.member_id IS NOT NULL AS found
                        FROM jsonb_to_recordset(%s::jsonb)
                        AS input(dimension_id text,member_id text)
                        LEFT JOIN epm.member m ON m.workspace_id=%s
                        AND m.application_id=%s
                        AND m.dimension_id=input.dimension_id
                        AND m.member_id=input.member_id''',
                        (Jsonb([{'dimension_id': axis, 'member_id': member}
                                for axis, member in members.items()]),
                         scope.workspace_id,
                         scope.application_id)).fetchall()
                    if any(not row['found'] for row in found):
                        raise ValueError('CUBE_FILTER_MEMBER_UNAVAILABLE')
                def fetch_page(page_after: str,
                               fetch_limit: int) -> list[dict]:
                    return self._page(
                        db, scope, members, page_after, snapshot_revision,
                        state['commit_revision'], include_missing, fetch_limit,
                        include_zero=include_zero)
                page, has_more, next_after = authorized_read_page(
                    db, self.identity, scope, after=after, limit=limit,
                    fetch=fetch_page, cursor_key=lambda row: row['seriesKey'])
                source = ('postgres_current' if snapshot_revision ==
                          state['commit_revision'] else 'postgres_event_history')
                # READ COMMITTED lets a writer publish between state and page
                # statements. Recheck after the page; if it advanced, rebuild
                # this page from immutable events at the pinned revision.
                after_state = db.execute('''SELECT metadata_revision,
                    commit_revision,security_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if after_state['metadata_revision'] != metadata_revision:
                    raise ValueError('STALE_METADATA_REVISION')
                if after_state['security_revision'] != security_revision:
                    raise ValueError('STALE_SECURITY_REVISION')
                if (source == 'postgres_current' and
                        after_state['commit_revision'] != snapshot_revision):
                    def fetch_history(page_after: str,
                                      fetch_limit: int) -> list[dict]:
                        return self._page(
                            db, scope, members, page_after, snapshot_revision,
                            after_state['commit_revision'], include_missing,
                            fetch_limit, include_zero=include_zero)
                    page, has_more, next_after = authorized_read_page(
                        db, self.identity, scope, after=after, limit=limit,
                        fetch=fetch_history,
                        cursor_key=lambda row: row['seriesKey'])
                    source = 'postgres_event_history'
                    # The fallback resolves layout in fresh READ COMMITTED
                    # statements too. Reject metadata changed after the first
                    # recheck instead of returning it under the old cursor pin.
                    final_state = db.execute('''SELECT metadata_revision,
                        security_revision FROM
                        epm.application_state WHERE workspace_id=%s
                        AND application_id=%s''',
                        (scope.workspace_id, scope.application_id)).fetchone()
                    if (final_state is None or
                            final_state['metadata_revision'] != metadata_revision):
                        raise ValueError('STALE_METADATA_REVISION')
                    if final_state['security_revision'] != security_revision:
                        raise ValueError('STALE_SECURITY_REVISION')
                # Assignment and policy mutations advance the dedicated
                # security revision.  READ COMMITTED may otherwise let the
                # page query and authorization filter observe two different
                # revisions, or let a later cursor continue under new grants.
                final_security = db.execute('''SELECT security_revision FROM
                    epm.application_state WHERE workspace_id=%s
                    AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if (final_security is None or
                        final_security['security_revision'] != security_revision):
                    raise ValueError('STALE_SECURITY_REVISION')
        next_cursor = (self._pack({
            'scope': [scope.workspace_id, scope.application_id],
            'identity': [self.identity.issuer, self.identity.subject_id],
            'members': members, 'after': next_after,
            'snapshotRevision': snapshot_revision,
            'metadataRevision': metadata_revision,
            'securityRevision': security_revision,
            'includeMissing': include_missing,
            'includeZero': include_zero,
            'limit': limit,
            'expiresAt': int(time.time()) + 3600,
        }) if has_more else None)
        return {'rows': page, 'nextCursor': next_cursor,
                'hasMore': has_more,
                'snapshotRevision': snapshot_revision,
                'metadataRevision': metadata_revision,
                'securityRevision': security_revision,
                'source': source}

    @staticmethod
    def _page(db, scope: ApplicationScope, members: dict[str, str],
              after: str, snapshot_revision: int, current_revision: int,
              include_missing: bool, fetch_limit: int, *,
              member_sets: dict[str, list[str]] | None = None,
              include_zero: bool = True) -> list[dict]:
        current = snapshot_revision == current_revision
        if current:
            # Each protected view has at most one current row per coordinate:
            # its backing primary key includes workspace/application/generation/
            # coordinate, and application_state selects one active generation.
            # Keep the correlated point lookup below the security barrier so a
            # cold estimate cannot rescan the whole projection for every cell.
            numeric = '''LEFT JOIN LATERAL (
                SELECT n.* FROM epm.numeric_cell_current n
                WHERE n.workspace_id=c.workspace_id
                AND n.application_id=c.application_id
                AND n.coordinate_id=c.coordinate_id LIMIT 1
            ) n ON true'''
            text = '''LEFT JOIN LATERAL (
                SELECT t.* FROM epm.text_cell_current t
                WHERE t.workspace_id=c.workspace_id
                AND t.application_id=c.application_id
                AND t.coordinate_id=c.coordinate_id LIMIT 1
            ) t ON true'''
            numeric_amount = 'n.amount'
            text_value = 't.text_value'
            numeric_revision = 'n.last_revision'
            text_revision = 't.last_revision'
            extra_params: list[object] = []
        else:
            numeric = '''LEFT JOIN LATERAL (
                SELECT present,resulting_amount,change_id,committed_revision
                FROM epm.numeric_fact_event
                WHERE workspace_id=c.workspace_id
                AND application_id=c.application_id
                AND coordinate_id=c.coordinate_id
                AND committed_revision<=%s
                ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1
            ) n ON true'''
            text = '''LEFT JOIN LATERAL (
                SELECT present,resulting_value,change_id,committed_revision
                FROM epm.text_fact_event
                WHERE workspace_id=c.workspace_id
                AND application_id=c.application_id
                AND coordinate_id=c.coordinate_id
                AND committed_revision<=%s
                ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1
            ) t ON true'''
            numeric_amount = 'n.resulting_amount'
            text_value = 't.resulting_value'
            numeric_revision = 'n.committed_revision'
            text_revision = 't.committed_revision'
            extra_params = [snapshot_revision, snapshot_revision]
        layout = db.execute('''SELECT l.schema_epoch,l.dimensions,
            l.role_dimensions,l.custom_dimensions FROM epm.coordinate_layout l
            JOIN epm.application_state s USING(workspace_id,application_id,schema_epoch)
            WHERE l.workspace_id=%s AND l.application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if layout is None:
            raise ValueError('APPLICATION_LAYOUT_UNAVAILABLE')
        # Only the original high-frequency model roles have dedicated
        # projection columns.  Optional semantic roles (for example Movement)
        # remain authoritative in the coordinate's members document.  Do not
        # assume that every role admitted by metadata has a physical column.
        columns = {axis: _ROLE_COLUMNS[role]
                   for role, axis in layout['role_dimensions'].items()
                   if role in _ROLE_COLUMNS}
        document_axes = {
            axis for role, axis in layout['role_dimensions'].items()
            if role not in _ROLE_COLUMNS
        }
        positions = {axis: index for index, axis in
                     enumerate(layout['custom_dimensions'], 1)}
        projection_predicates = []
        projection_params: list[object] = []
        coordinate_predicates = []
        coordinate_params: list[object] = []
        selections = ({axis: [member] for axis, member in members.items()}
                      if member_sets is None else member_sets)
        for axis, selected in sorted(selections.items()):
            if axis in columns:
                # Column names come only from the fixed role map above.
                projection_predicates.append(f'AND p.{columns[axis]}=ANY(%s)')
                projection_params.append(selected)
            elif axis in positions:
                # Retain exact dimension identity at the pinned array
                # position, including when typed membership drives candidates.
                projection_predicates.append(f'AND p.custom_members && %s::text[] '
                                  f'AND p.custom_members[{positions[axis]}]=ANY(%s)')
                projection_params.extend((selected, selected))
            elif axis in document_axes:
                # The axis name is a bound value, never caller SQL.  This path
                # preserves optional role semantics until a separately
                # qualified physical projection is introduced.
                coordinate_predicates.append('AND c.members->>%s=ANY(%s)')
                coordinate_params.extend((axis, selected))
            else:
                # Currency registries are metadata, not a cube fact axis.
                return []
        # Coordinates are shared with calculations and journals. Registration
        # alone is not raw-fact membership, even when include_missing is true.
        # Current tombstones retain change IDs just like immutable events, so
        # this predicate gives both readers the same reconstructable universe.
        existed_at_snapshot = ('AND (n.change_id IS NOT NULL OR '
                               't.change_id IS NOT NULL)')
        custom_driver = next((axis for axis in sorted(selections)
            if axis in positions), None)
        if any(axis in columns for axis in selections):
            custom_driver = None
        if projection_predicates:
            # Resolve indexed membership once through the protected view. A
            # coordinate-first ORDER BY/LIMIT plan could otherwise probe many
            # unrelated cells before finding a few selected members.
            prefix = f"""WITH selected_projection AS MATERIALIZED (
                SELECT p.workspace_id,p.application_id,p.coordinate_id
                FROM epm.coordinate_projection p
                WHERE p.workspace_id=%s AND p.application_id=%s
                AND p.fact_table_id='cube' AND p.schema_epoch=%s
                {''.join(projection_predicates)})"""
            candidate_parameters = (scope.workspace_id, scope.application_id,
                layout['schema_epoch'], *projection_params)
            if custom_driver is not None:
                # Array-overlap cannot cross a security barrier to use GIN.
                # The existing protected typed membership view supplies an
                # indexed dimension/member candidate set instead. Its PK has
                # one row per coordinate/dimension in the active generation.
                prefix = f"""WITH selected_projection AS MATERIALIZED (
                    SELECT p.workspace_id,p.application_id,p.coordinate_id
                    FROM epm.coordinate_member m JOIN LATERAL (
                        SELECT p.* FROM epm.coordinate_projection p
                        WHERE p.workspace_id=m.workspace_id AND p.application_id=m.application_id
                        AND p.coordinate_id=m.coordinate_id
                        AND p.fact_table_id='cube' AND p.schema_epoch=%s
                        {''.join(projection_predicates)} LIMIT 1
                    ) p ON true
                    WHERE m.workspace_id=%s AND m.application_id=%s
                    AND m.dimension_id=%s AND m.member_id=ANY(%s))"""
                candidate_parameters = (layout['schema_epoch'], *projection_params,
                    scope.workspace_id, scope.application_id, custom_driver,
                    selections[custom_driver])
            source = f"""FROM selected_projection p JOIN LATERAL (
                SELECT c.* FROM epm.coordinate c
                WHERE c.workspace_id=p.workspace_id AND c.application_id=p.application_id
                AND c.coordinate_id=p.coordinate_id AND c.series_key>%s
                {''.join(coordinate_predicates)} LIMIT 1
            ) c ON true {numeric} {text}"""
            scope_predicate = 'WHERE true'
            parameters = (*candidate_parameters, after,
                *coordinate_params, *extra_params)
        else:
            prefix = ''
            source = f"""FROM epm.coordinate c {numeric} {text}
                JOIN LATERAL (
                    SELECT p.* FROM epm.coordinate_projection p
                    WHERE p.workspace_id=c.workspace_id
                    AND p.application_id=c.application_id AND p.coordinate_id=c.coordinate_id
                    AND p.fact_table_id='cube' AND p.schema_epoch=%s LIMIT 1
                ) p ON true"""
            scope_predicate = f"""WHERE c.workspace_id=%s AND c.application_id=%s
                AND c.series_key>%s {''.join(coordinate_predicates)}"""
            parameters = (*extra_params, layout['schema_epoch'],
                scope.workspace_id, scope.application_id, after, *coordinate_params)
        query = f"""{prefix}SELECT c.series_key,c.members,
            n.present AS numeric_present,{numeric_amount} AS amount,
            n.change_id AS numeric_change_id,
            {numeric_revision} AS numeric_revision,
            t.present AS text_present,{text_value} AS text_value,
            t.change_id AS text_change_id,
            {text_revision} AS text_revision
            {source} {scope_predicate}
            AND (%s OR COALESCE(n.present,false) OR COALESCE(t.present,false))
            AND (%s OR NOT COALESCE(n.present,false) OR {numeric_amount}<>0)
            {existed_at_snapshot}
            ORDER BY c.series_key LIMIT %s"""
        raw = db.execute(query, (*parameters, include_missing, include_zero,
                                 fetch_limit)).fetchall()
        result = []
        for row in raw:
            numeric_present = bool(row['numeric_present'])
            text_present = bool(row['text_present'])
            if numeric_present and text_present:
                raise ValueError('COORDINATE_TYPE_CONFLICT')
            kind = ('numeric' if numeric_present else
                    'text' if text_present else 'missing')
            result.append({
                'seriesKey': row['series_key'], 'members': row['members'],
                'kind': kind, 'present': kind != 'missing',
                'amount': (format(row['amount'], 'f')
                           if numeric_present else None),
                'text': row['text_value'] if text_present else None,
                'changeId': (row['numeric_change_id'] if numeric_present else
                             row['text_change_id'] if text_present else ''),
                'numericChangeId': row['numeric_change_id'] or '',
                'textChangeId': row['text_change_id'] or '',
                'lastRevision': (row['numeric_revision'] if numeric_present else
                                 row['text_revision'] if text_present else None),
            })
        return result

    def _pack(self, payload: dict) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False).encode('utf-8')
        signature = hmac.new(self.cursor_secret, raw, sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).decode('ascii')

    def _unpack(self, token: object, scope: ApplicationScope) -> dict:
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError('CUBE_CURSOR_INVALID')
        try:
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                    hmac.new(self.cursor_secret, raw, sha256).digest(),
                    signature):
                raise ValueError('Invalid signature')
            payload = json.loads(raw)
        except (ValueError, TypeError, binascii.Error) as error:
            raise ValueError('CUBE_CURSOR_INVALID') from error
        if (not isinstance(payload, dict)
                or set(payload) != {'scope', 'identity', 'members', 'after',
                                   'snapshotRevision', 'metadataRevision',
                                   'securityRevision', 'includeMissing',
                                   'includeZero', 'limit',
                                   'expiresAt'}
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
                or type(payload['includeMissing']) is not bool
                or type(payload['includeZero']) is not bool
                or type(payload['limit']) is not int
                or not 1 <= payload['limit'] <= 500
                or type(payload['expiresAt']) is not int
                or payload['expiresAt'] < time.time()):
            raise ValueError('CUBE_CURSOR_INVALID')
        return payload
