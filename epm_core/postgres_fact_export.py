"""Snapshot-pinned, typed export pages for EPM source-data transfer."""
from __future__ import annotations

from decimal import Decimal
import hmac

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_cube_query import MAX_CURSOR_CHARACTERS, PostgresCubeQuery, cube_member_filter_schema
from .postgres_jobs import _canonical_digest


FUNCTION = 'facts.export.page'
MAX_EXPORT_PAGE_SIZE = 50
_EXPORT_SCHEMA = {
    'id': 'openepm.fact-transfer-page',
    'version': 1,
    'coordinate': 'stable-dimension-member-map',
    'literalTypes': ['AmountLiteral', 'TextLiteral', 'LineDetailLiteral'],
    'sourceReference': 'required-stable-origin',
}


def export_row_schema() -> dict:
    from .postgres_numeric_catalog import obj

    text = {'type': 'string'}
    member = {'type': 'string', 'minLength': 1}
    coordinate = {'type': 'object', 'minProperties': 1, 'propertyNames': member,
                  'additionalProperties': member}
    line = obj({'description': text, 'decimal': text})
    value = {'oneOf': [obj({'type': {'const': 'AmountLiteral'}, 'decimal': text}),
                       obj({'type': {'const': 'TextLiteral'}, 'text': text}),
                       obj({'type': {'const': 'LineDetailLiteral'},
                            'items': {'type': 'array', 'items': line}})]}
    return obj({'members': coordinate, 'value': value,
                'sourceRef': {'type': 'string', 'pattern': r'^export:[0-9a-f]{64}(?![\s\S])'}})


def export_page_program_contract() -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    revision = {'type': 'integer', 'minimum': 0}
    cursor = {'type': 'string', 'minLength': 1, 'maxLength': MAX_CURSOR_CHARACTERS}
    nullable_cursor = {**cursor, 'type': ['string', 'null']}
    arguments = obj({
        'members': cube_member_filter_schema(),
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': MAX_EXPORT_PAGE_SIZE,
                  'default': MAX_EXPORT_PAGE_SIZE},
        'cursor': nullable_cursor, 'snapshotRevision': {**revision, 'type': ['integer', 'null']},
    }, [])
    arguments['if'] = {'required': ['cursor'], 'properties': {'cursor': {'type': 'string'}}}
    arguments['then'] = {'properties': {'members': {'type': 'null'}, 'snapshotRevision': {'type': 'null'}}}
    result = obj({
        'schema': {'const': _EXPORT_SCHEMA},
        'rows': {'type': 'array', 'maxItems': MAX_EXPORT_PAGE_SIZE, 'items': export_row_schema()},
        'nextCursor': nullable_cursor, 'hasMore': {'type': 'boolean'},
        'snapshotRevision': revision, 'metadataRevision': revision, 'securityRevision': revision,
        'source': {'enum': ['postgres_current', 'postgres_event_history']},
        'contentDigest': {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'},
    })
    result['if'] = {'properties': {'hasMore': {'const': True}}}
    result['then'] = {'properties': {'nextCursor': cursor, 'rows': {'minItems': 1}}}
    result['else'] = {'properties': {'nextCursor': {'type': 'null'}}}
    contract = read_contract(FUNCTION, arguments, result, owner='PostgresFactExport.page', examples=[
        read_example(FUNCTION, {'limit': 10}, name='Read the first typed export page',
            binding='Select the authorized application. Omit members for a bounded page over visible facts.'),
        read_example(FUNCTION, {'cursor': 'example-cursor', 'limit': 10}, name='Continue the same typed export',
            binding='Copy nextCursor from the previous export page and retain its original limit. Use the same application and verified identity.'),
    ], semantic_rules=[
        'The page exports present facts as typed exact amounts, text or ordered supporting detail at one committed revision.',
        'Present numeric zero, present empty text and a present empty supporting-detail set retain their original type and presence.',
        'Current READ authority covers both raw facts and their detail until the response is assembled. Use the previous nextCursor and the same limit until hasMore is false.',
        'In a group-assigned application the facts.export duty permits the transfer operation. Every exported row remains bounded by the requester’s current facts.read assignments.',
        'contentDigest binds application scope, schema, snapshot, metadata and security revisions, rows and continuation presence. Cursor refresh and physical current or history read do not change the digest.',
    ])
    contract['programContract']['recovery'] = (
        'Restart after stale metadata, security or access and use the chosen committed snapshot again only '
        'under current authority. Keep the original page size when continuing an authorized page.')
    return contract


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

    def page(self, scope: ApplicationScope, *,
             members: dict[str, str] | None = None,
             limit: int = MAX_EXPORT_PAGE_SIZE, cursor: str | None = None,
             snapshot_revision: int | None = None) -> dict:
        if type(limit) is not int or not 1 <= limit <= MAX_EXPORT_PAGE_SIZE:
            raise ValueError('EXPORT_PAGE_BOUNDS_INVALID')
        with self.cube._scan_page(scope, members=members, limit=limit, cursor=cursor,
                                  snapshot_revision=snapshot_revision, operation=FUNCTION) as (db, page):
            keys = [row['seriesKey'] for row in page['rows']]
            detail = self._read_detail(db, scope, keys, page['snapshotRevision']) if keys else {}
            return self._export_page(scope, page, detail)

    @staticmethod
    def _read_detail(db, scope, keys, snapshot_revision):
        # Read immutable detail at the raw page's committed revision, even if
        # a writer advances the current detail while the export assembles.
        rows = db.execute('''SELECT DISTINCT ON (c.series_key)
            c.series_key,d.items,d.total,d.change_id,d.present
            FROM epm.coordinate c JOIN epm.line_detail_event d
            ON d.workspace_id=c.workspace_id
            AND d.application_id=c.application_id
            AND d.coordinate_id=c.coordinate_id
            WHERE c.workspace_id=%s AND c.application_id=%s
            AND c.series_key=ANY(%s)
            AND d.committed_revision<=%s
            ORDER BY c.series_key,d.committed_revision DESC,d.event_id DESC''',
            (scope.workspace_id, scope.application_id, keys, snapshot_revision)).fetchall()
        return {row['series_key']: row for row in rows}

    @staticmethod
    def _export_page(scope, page, detail):
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
