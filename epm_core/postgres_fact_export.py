"""Snapshot-pinned, typed export pages for EPM source-data transfer."""
from __future__ import annotations

from decimal import Decimal
import hmac

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_cube_query import PostgresCubeQuery
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore


_EXPORT_SCHEMA = {
    'id': 'openepm.fact-transfer-page',
    'version': 1,
    'coordinate': 'stable-dimension-member-map',
    'literalTypes': ['AmountLiteral', 'TextLiteral', 'LineDetailLiteral'],
    'sourceReference': 'required-stable-origin',
}


def _valid_export_row(row: object) -> bool:
    if (not isinstance(row, dict)
            or set(row) != {'members', 'value', 'sourceRef'}
            or not isinstance(row['members'], dict)
            or not row['members']
            or any(not isinstance(axis, str) or not axis
                   or not isinstance(member, str) or not member
                   for axis, member in row['members'].items())
            or not isinstance(row['sourceRef'], str)
            or not row['sourceRef']
            or not isinstance(row['value'], dict)):
        return False
    literal = row['value']
    if literal.get('type') == 'AmountLiteral':
        return (set(literal) == {'type', 'decimal'}
                and isinstance(literal['decimal'], str))
    if literal.get('type') == 'TextLiteral':
        return (set(literal) == {'type', 'text'}
                and isinstance(literal['text'], str))
    if literal.get('type') == 'LineDetailLiteral':
        return (set(literal) == {'type', 'items'}
                and isinstance(literal['items'], list)
                and all(isinstance(item, dict)
                        and set(item) == {'description', 'decimal'}
                        and isinstance(item['description'], str)
                        and isinstance(item['decimal'], str)
                        for item in literal['items']))
    return False


def _content_digest(scope: ApplicationScope, result: dict) -> str:
    """Return the portable identity of one semantic export page.

    The opaque continuation cursor and physical read backend are deliberately
    excluded: cursor expiry and a current-to-history fallback must not alter
    the identity of the same snapshot-pinned transfer content.  The caller
    already knows the scoped application used for the request, so scope is
    bound into the digest without duplicating it in every row.
    """
    return _canonical_digest({
        'scope': [scope.workspace_id, scope.application_id],
        'schema': result['schema'],
        'snapshotRevision': result['snapshotRevision'],
        'metadataRevision': result['metadataRevision'],
        'securityRevision': result['securityRevision'],
        'rows': result['rows'],
        'hasMore': result['hasMore'],
    })


class PostgresFactExport:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes):
        self.cube = PostgresCubeQuery(
            dsn, identity=identity, cursor_secret=cursor_secret)
        self.dsn = dsn
        self.identity = identity

    def page(self, scope: ApplicationScope, *,
             members: dict[str, str] | None = None,
             limit: int = 50, cursor: str | None = None,
             snapshot_revision: int | None = None) -> dict:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError('EXPORT_PAGE_BOUNDS_INVALID')
        page = self.cube.scan(scope, members=members, limit=limit,
                              cursor=cursor,
                              snapshot_revision=snapshot_revision)
        keys = [row['seriesKey'] for row in page['rows']]
        detail = {}
        if keys:
            # Immutable events are used even for the latest page. A writer may
            # commit between cube.scan and this query, but the pinned revision
            # still selects exactly the detail visible to the exported facts.
            with connect_postgres(self.dsn, row_factory=dict_row) as db:
                with db.transaction():
                    db.execute('SET TRANSACTION READ ONLY')
                    configure_statement_timeout(db, 5000)
                    PostgresNumericFactStore._set_scope(db, scope)
                    PostgresAccessChecker.check_in_transaction(
                        db, self.identity, scope, 'read')
                    state = db.execute('''SELECT metadata_revision,
                        security_revision FROM
                        epm.application_state WHERE workspace_id=%s
                        AND application_id=%s''',
                        (scope.workspace_id, scope.application_id)).fetchone()
                    if (state is None or state['metadata_revision'] !=
                            page['metadataRevision']):
                        raise ValueError('STALE_METADATA_REVISION')
                    if state['security_revision'] != page['securityRevision']:
                        raise ValueError('STALE_SECURITY_REVISION')
                    raw = db.execute('''SELECT DISTINCT ON (c.series_key)
                        c.series_key,d.items,d.total,d.change_id,d.present
                        FROM epm.coordinate c JOIN epm.line_detail_event d
                        ON d.workspace_id=c.workspace_id
                        AND d.application_id=c.application_id
                        AND d.coordinate_id=c.coordinate_id
                        WHERE c.workspace_id=%s AND c.application_id=%s
                        AND c.series_key=ANY(%s)
                        AND d.committed_revision<=%s
                        ORDER BY c.series_key,d.committed_revision DESC,
                        d.event_id DESC''',
                        (scope.workspace_id, scope.application_id, keys,
                         page['snapshotRevision'])).fetchall()
                    detail = {row['series_key']: row for row in raw}
                    after = db.execute('''SELECT metadata_revision,
                        security_revision FROM
                        epm.application_state WHERE workspace_id=%s
                        AND application_id=%s''',
                        (scope.workspace_id, scope.application_id)).fetchone()
                    if (after is None or after['metadata_revision'] !=
                            page['metadataRevision']):
                        raise ValueError('STALE_METADATA_REVISION')
                    if after['security_revision'] != page['securityRevision']:
                        raise ValueError('STALE_SECURITY_REVISION')
        rows = []
        for row in page['rows']:
            source = detail.get(row['seriesKey'])
            if source and source['present']:
                if (row['kind'] != 'numeric'
                        or row['amount'] != format(source['total'], 'f')
                        or row['changeId'] != source['change_id']):
                    raise ValueError('EXPORT_DETAIL_NUMERIC_INCONSISTENT')
                literal = {'type': 'LineDetailLiteral', 'items': [
                    {'description': item['description'],
                     'decimal': format(Decimal(item['amount']), 'f')}
                    for item in source['items']]}
            elif row['kind'] == 'numeric':
                literal = {'type': 'AmountLiteral', 'decimal': row['amount']}
            elif row['kind'] == 'text':
                literal = {'type': 'TextLiteral', 'text': row['text']}
            else:
                raise ValueError('EXPORT_UNEXPECTED_MISSING_CELL')
            rows.append({'members': row['members'], 'value': literal,
                         'sourceRef': 'export:' + row['seriesKey']})
        schema = {**_EXPORT_SCHEMA,
                  'literalTypes': list(_EXPORT_SCHEMA['literalTypes'])}
        result = {'schema': schema, 'rows': rows,
                  'nextCursor': page['nextCursor'],
                  'hasMore': page['hasMore'],
                  'snapshotRevision': page['snapshotRevision'],
                  'metadataRevision': page['metadataRevision'],
                  'securityRevision': page['securityRevision'],
                  'source': page['source']}
        result['contentDigest'] = _content_digest(scope, result)
        return result

    @staticmethod
    def content_digest_matches(scope: ApplicationScope, result: dict) -> bool:
        """Verify a returned page after transport or durable artifact storage."""
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(result, dict)
                or result.get('schema') != _EXPORT_SCHEMA
                or not isinstance(result.get('rows'), list)
                or any(not _valid_export_row(row) for row in result['rows'])
                or type(result.get('snapshotRevision')) is not int
                or result['snapshotRevision'] < 0
                or type(result.get('metadataRevision')) is not int
                or result['metadataRevision'] < 0
                or type(result.get('securityRevision')) is not int
                or result['securityRevision'] < 0
                or not isinstance(result.get('hasMore'), bool)
                or not isinstance(result.get('contentDigest'), str)
                or len(result['contentDigest']) != 64):
            return False
        try:
            return hmac.compare_digest(result['contentDigest'],
                                       _content_digest(scope, result))
        except (KeyError, TypeError, ValueError):
            return False
