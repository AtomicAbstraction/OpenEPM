"""Pure cumulative identity for a complete snapshot-pinned fact export.

The builder consumes pages already returned and verified by the fixed export
service.  It never rereads or recalculates cube data.  Persistence, download
authorization and retention are deliberately separate concerns.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
import hmac
import json
import re

from .persistence_contract import ApplicationScope
from .postgres_fact_export import PostgresFactExport, _EXPORT_SCHEMA


CONTRACT_VERSION = 'openepm-complete-export-manifest-v2'
LEGACY_CONTRACT_VERSION = 'openepm-complete-export-manifest-v1'
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_KEY = re.compile(r'export:([0-9a-f]{64})\Z')
_MAX_PAGES = 100000
_MAX_ROWS = 100000000
_MAX_BYTES = 1099511627776  # 1 TiB of canonical typed row payloads.


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _cursor_digest(value: str | None) -> str | None:
    return (None if value is None
            else sha256(value.encode('utf-8')).hexdigest())


class ExportArtifactStatus(StrEnum):
    BUILDING = 'building'
    COMPLETE = 'complete'


@dataclass(frozen=True, slots=True)
class ExportArtifactLimits:
    max_pages: int = 10000
    max_rows: int = 5000000
    max_bytes: int = 1073741824

    def __post_init__(self) -> None:
        if (type(self.max_pages) is not int
                or not 1 <= self.max_pages <= _MAX_PAGES
                or type(self.max_rows) is not int
                or not 1 <= self.max_rows <= _MAX_ROWS
                or type(self.max_bytes) is not int
                or not 1 <= self.max_bytes <= _MAX_BYTES):
            raise ValueError('EXPORT_ARTIFACT_LIMITS_INVALID')

    def wire(self) -> dict:
        return {'maxPages': self.max_pages, 'maxRows': self.max_rows,
                'maxBytes': self.max_bytes}


def _seed(scope: ApplicationScope, schema: dict, snapshot_revision: int,
          metadata_revision: int, security_revision: int | None,
          expires_at: int,
          limits: ExportArtifactLimits, *,
          contract_version: str = CONTRACT_VERSION) -> str:
    return sha256(_canonical({
        'contractVersion': contract_version,
        'scope': [scope.workspace_id, scope.application_id],
        'schema': schema,
        'snapshotRevision': snapshot_revision,
        'metadataRevision': metadata_revision,
        **({} if security_revision is None else {
            'securityRevision': security_revision}),
        'expiresAt': expires_at,
        'limits': limits.wire(),
    })).hexdigest()


def _advance(prior: str, entry: dict) -> str:
    return sha256(_canonical({'prior': prior, 'page': entry})).hexdigest()


def _page_entry(scope: ApplicationScope, page_index: int,
                request_cursor: str | None, page: dict) -> tuple[dict, str]:
    if (type(page_index) is not int or page_index < 0
            or (request_cursor is not None
                and (not isinstance(request_cursor, str)
                     or not 1 <= len(request_cursor) <= 16384))
            or not PostgresFactExport.content_digest_matches(scope, page)
            or page.get('schema') != _EXPORT_SCHEMA
            or not isinstance(page.get('nextCursor'), (str, type(None)))
            or (isinstance(page.get('nextCursor'), str)
                and not 1 <= len(page['nextCursor']) <= 16384)
            or not isinstance(page.get('rows'), list)
            or len(page['rows']) > 50):
        raise ValueError('EXPORT_ARTIFACT_PAGE_INVALID')
    if page['hasMore'] != (page['nextCursor'] is not None):
        raise ValueError('EXPORT_ARTIFACT_CURSOR_INVALID')
    if page['hasMore'] and not page['rows']:
        raise ValueError('EXPORT_ARTIFACT_EMPTY_CONTINUATION')
    keys = []
    counts = {'amount': 0, 'text': 0, 'lineDetail': 0}
    kinds = {'AmountLiteral': 'amount', 'TextLiteral': 'text',
             'LineDetailLiteral': 'lineDetail'}
    for row in page['rows']:
        match = _KEY.fullmatch(row['sourceRef'])
        if match is None:
            raise ValueError('EXPORT_ARTIFACT_SOURCE_KEY_INVALID')
        keys.append(match.group(1))
        counts[kinds[row['value']['type']]] += 1
    if keys != sorted(set(keys)):
        raise ValueError('EXPORT_ARTIFACT_KEYSET_ORDER_INVALID')
    row_bytes = len(_canonical(page['rows']))
    entry = {
        'pageIndex': page_index,
        'requestCursorDigest': _cursor_digest(request_cursor),
        'nextCursorDigest': _cursor_digest(page['nextCursor']),
        'contentDigest': page['contentDigest'],
        'rowCount': len(page['rows']),
        'rowBytes': row_bytes,
        'typeCounts': counts,
        'firstKey': keys[0] if keys else None,
        'lastKey': keys[-1] if keys else None,
        'hasMore': page['hasMore'],
    }
    return entry, keys[-1] if keys else ''


@dataclass(frozen=True, slots=True)
class ExportArtifactBuilder:
    scope: ApplicationScope
    schema: dict
    snapshot_revision: int
    metadata_revision: int
    security_revision: int
    expires_at: int
    limits: ExportArtifactLimits
    status: ExportArtifactStatus
    pages: tuple[bytes, ...]
    cumulative_digest: str
    total_rows: int
    total_bytes: int
    type_counts: tuple[int, int, int]
    expected_cursor: str | None
    last_key: str
    terminal: bool

    def __post_init__(self) -> None:
        if (not isinstance(self.scope, ApplicationScope)
                or self.schema != _EXPORT_SCHEMA
                or not isinstance(self.limits, ExportArtifactLimits)
                or not _valid_nonnegative_int(self.security_revision)
                or not isinstance(self.status, ExportArtifactStatus)
                or not isinstance(self.pages, tuple)
                or any(not isinstance(page, bytes) for page in self.pages)
                or not isinstance(self.cumulative_digest, str)
                or not _DIGEST.fullmatch(self.cumulative_digest)
                or not _valid_nonnegative_int(self.total_rows)
                or not _valid_nonnegative_int(self.total_bytes)
                or not isinstance(self.type_counts, tuple)
                or len(self.type_counts) != 3
                or any(not _valid_nonnegative_int(value)
                       for value in self.type_counts)
                or not isinstance(self.terminal, bool)
                or (self.status == ExportArtifactStatus.COMPLETE
                    and (not self.terminal or not self.pages
                         or self.expected_cursor is not None))):
            raise ValueError('EXPORT_ARTIFACT_STATE_INVALID')
        if (self.status == ExportArtifactStatus.COMPLETE
                and not export_artifact_manifest_matches(
                    self._manifest_value(), scope=self.scope,
                    expires_at=self.expires_at)):
            raise ValueError('EXPORT_ARTIFACT_STATE_INVALID')

    @classmethod
    def begin(cls, scope: ApplicationScope, *, snapshot_revision: int,
              metadata_revision: int, expires_at: int,
              security_revision: int = 0,
              schema: dict | None = None,
              limits: ExportArtifactLimits | None = None):
        if (not isinstance(scope, ApplicationScope)
                or type(snapshot_revision) is not int or snapshot_revision < 0
                or type(metadata_revision) is not int or metadata_revision < 0
                or type(security_revision) is not int or security_revision < 0
                or type(expires_at) is not int or not 1 <= expires_at < 2**63):
            raise ValueError('EXPORT_ARTIFACT_BEGIN_INVALID')
        schema = (_EXPORT_SCHEMA if schema is None else schema)
        try:
            detached = json.loads(_canonical(schema))
        except (RecursionError, TypeError, ValueError, UnicodeError) as error:
            raise ValueError('EXPORT_ARTIFACT_SCHEMA_INVALID') from error
        if detached != _EXPORT_SCHEMA:
            raise ValueError('EXPORT_ARTIFACT_SCHEMA_INVALID')
        limits = limits or ExportArtifactLimits()
        if not isinstance(limits, ExportArtifactLimits):
            raise ValueError('EXPORT_ARTIFACT_LIMITS_INVALID')
        return cls(scope, detached, snapshot_revision, metadata_revision,
                   security_revision, expires_at, limits,
                   ExportArtifactStatus.BUILDING, (),
                   _seed(scope, detached, snapshot_revision,
                         metadata_revision, security_revision, expires_at,
                         limits),
                   0, 0, (0, 0, 0), None, '', False)

    def append(self, *, page_index: int, request_cursor: str | None,
               page: dict):
        if self.status == ExportArtifactStatus.COMPLETE:
            raise ValueError('EXPORT_ARTIFACT_FINALIZED')
        if self.terminal:
            raise ValueError('EXPORT_ARTIFACT_PAGE_AFTER_TERMINAL')
        if page_index != len(self.pages):
            raise ValueError('EXPORT_ARTIFACT_PAGE_INDEX_DISCONTINUITY')
        if request_cursor != self.expected_cursor:
            raise ValueError('EXPORT_ARTIFACT_CURSOR_DISCONTINUITY')
        entry, last_key = _page_entry(
            self.scope, page_index, request_cursor, page)
        if (page['snapshotRevision'] != self.snapshot_revision
                or page['metadataRevision'] != self.metadata_revision
                or page['securityRevision'] != self.security_revision
                or page['schema'] != self.schema):
            raise ValueError('EXPORT_ARTIFACT_PIN_DRIFT')
        if page_index > 0 and not page['rows']:
            raise ValueError('EXPORT_ARTIFACT_EMPTY_LATER_PAGE')
        if self.last_key and entry['firstKey'] <= self.last_key:
            raise ValueError('EXPORT_ARTIFACT_KEYSET_DISCONTINUITY')
        rows = self.total_rows + entry['rowCount']
        byte_count = self.total_bytes + entry['rowBytes']
        pages = len(self.pages) + 1
        if (pages > self.limits.max_pages or rows > self.limits.max_rows
                or byte_count > self.limits.max_bytes):
            raise ValueError('EXPORT_ARTIFACT_LIMIT_EXCEEDED')
        counts = tuple(self.type_counts[index] + entry['typeCounts'][kind]
                       for index, kind in enumerate(
                           ('amount', 'text', 'lineDetail')))
        return replace(
            self, pages=(*self.pages, _canonical(entry)),
            cumulative_digest=_advance(self.cumulative_digest, entry),
            total_rows=rows, total_bytes=byte_count, type_counts=counts,
            expected_cursor=page['nextCursor'],
            last_key=last_key or self.last_key,
            terminal=not page['hasMore'])

    def finalize(self, *, expires_at: int):
        if self.status == ExportArtifactStatus.COMPLETE:
            raise ValueError('EXPORT_ARTIFACT_FINALIZED')
        if type(expires_at) is not int or expires_at != self.expires_at:
            raise ValueError('EXPORT_ARTIFACT_EXPIRY_MISMATCH')
        if not self.terminal or not self.pages or self.expected_cursor is not None:
            raise ValueError('EXPORT_ARTIFACT_INCOMPLETE')
        return replace(self, status=ExportArtifactStatus.COMPLETE)

    def _manifest_value(self) -> dict:
        result = {
            'contractVersion': CONTRACT_VERSION,
            'status': self.status.value,
            'scope': {'workspaceId': self.scope.workspace_id,
                      'applicationId': self.scope.application_id},
            'schema': self.schema,
            'snapshotRevision': self.snapshot_revision,
            'metadataRevision': self.metadata_revision,
            'securityRevision': self.security_revision,
            'expiresAt': self.expires_at,
            'limits': self.limits.wire(),
            'pages': [json.loads(page) for page in self.pages],
            'pageCount': len(self.pages),
            'totalRowCount': self.total_rows,
            'totalRowBytes': self.total_bytes,
            'typeCounts': {'amount': self.type_counts[0],
                           'text': self.type_counts[1],
                           'lineDetail': self.type_counts[2]},
            'cumulativeDigest': self.cumulative_digest,
        }
        result['manifestDigest'] = sha256(_canonical(result)).hexdigest()
        return result

    def manifest(self) -> dict:
        if self.status != ExportArtifactStatus.COMPLETE:
            raise ValueError('EXPORT_ARTIFACT_INCOMPLETE')
        return self._manifest_value()


def _valid_nonnegative_int(value: object) -> bool:
    return type(value) is int and value >= 0


def export_artifact_manifest_matches(manifest: object, *,
                                     scope: ApplicationScope | None = None,
                                     expires_at: int | None = None) -> bool:
    """Verify a sealed artifact without rereading any exported source rows."""
    if not isinstance(manifest, dict):
        return False
    version = manifest.get('contractVersion')
    required = {'contractVersion', 'status', 'scope', 'schema',
                'snapshotRevision', 'metadataRevision', 'expiresAt', 'limits',
                'pages', 'pageCount', 'totalRowCount', 'totalRowBytes',
                'typeCounts', 'cumulativeDigest', 'manifestDigest'}
    if version == CONTRACT_VERSION:
        required.add('securityRevision')
    if (set(manifest) != required
            or version not in (CONTRACT_VERSION, LEGACY_CONTRACT_VERSION)
            or manifest.get('status') != ExportArtifactStatus.COMPLETE.value
            or not isinstance(manifest.get('scope'), dict)
            or set(manifest['scope']) != {'workspaceId', 'applicationId'}
            or not all(isinstance(manifest['scope'][key], str)
                       and manifest['scope'][key]
                       for key in ('workspaceId', 'applicationId'))
            or manifest.get('schema') != _EXPORT_SCHEMA
            or not _valid_nonnegative_int(manifest.get('snapshotRevision'))
            or not _valid_nonnegative_int(manifest.get('metadataRevision'))
            or (version == CONTRACT_VERSION and not _valid_nonnegative_int(
                manifest.get('securityRevision')))
            or type(manifest.get('expiresAt')) is not int
            or not 1 <= manifest['expiresAt'] < 2**63
            or not isinstance(manifest.get('pages'), list)
            or not manifest['pages']
            or not _valid_nonnegative_int(manifest.get('pageCount'))
            or manifest['pageCount'] != len(manifest['pages'])
            or not _valid_nonnegative_int(manifest.get('totalRowCount'))
            or not _valid_nonnegative_int(manifest.get('totalRowBytes'))
            or not isinstance(manifest.get('typeCounts'), dict)
            or set(manifest['typeCounts']) != {'amount', 'text', 'lineDetail'}
            or any(not _valid_nonnegative_int(value)
                   for value in manifest['typeCounts'].values())
            or not isinstance(manifest.get('cumulativeDigest'), str)
            or not _DIGEST.fullmatch(manifest['cumulativeDigest'])
            or not isinstance(manifest.get('manifestDigest'), str)
            or not _DIGEST.fullmatch(manifest['manifestDigest'])):
        return False
    if scope is not None and (not isinstance(scope, ApplicationScope)
            or manifest['scope'] != {'workspaceId': scope.workspace_id,
                                     'applicationId': scope.application_id}):
        return False
    if expires_at is not None and (type(expires_at) is not int
                                   or expires_at != manifest['expiresAt']):
        return False
    try:
        limits = ExportArtifactLimits(
            manifest['limits']['maxPages'], manifest['limits']['maxRows'],
            manifest['limits']['maxBytes'])
        expected_scope = ApplicationScope(manifest['scope']['workspaceId'],
                                          manifest['scope']['applicationId'])
        cumulative = _seed(expected_scope, manifest['schema'],
                           manifest['snapshotRevision'],
                           manifest['metadataRevision'],
                           manifest.get('securityRevision'),
                           manifest['expiresAt'], limits,
                           contract_version=version)
        total_rows = total_bytes = 0
        type_counts = {'amount': 0, 'text': 0, 'lineDetail': 0}
        prior_next = None
        prior_key = ''
        for index, entry in enumerate(manifest['pages']):
            fields = {'pageIndex', 'requestCursorDigest', 'nextCursorDigest',
                      'contentDigest', 'rowCount', 'rowBytes', 'typeCounts',
                      'firstKey', 'lastKey', 'hasMore'}
            if (not isinstance(entry, dict) or set(entry) != fields
                    or type(entry.get('pageIndex')) is not int
                    or entry['pageIndex'] != index
                    or entry.get('requestCursorDigest') != prior_next
                    or not isinstance(entry.get('contentDigest'), str)
                    or not _DIGEST.fullmatch(entry['contentDigest'])
                    or not _valid_nonnegative_int(entry.get('rowCount'))
                    or entry['rowCount'] > 50
                    or not _valid_nonnegative_int(entry.get('rowBytes'))
                    or not isinstance(entry.get('typeCounts'), dict)
                    or set(entry['typeCounts']) != set(type_counts)
                    or any(not _valid_nonnegative_int(value)
                           for value in entry['typeCounts'].values())
                    or sum(entry['typeCounts'].values()) != entry['rowCount']
                    or not isinstance(entry.get('hasMore'), bool)
                    or entry['hasMore'] !=
                       (entry.get('nextCursorDigest') is not None)
                    or (entry.get('requestCursorDigest') is not None
                        and not _DIGEST.fullmatch(
                            entry['requestCursorDigest']))
                    or (entry.get('nextCursorDigest') is not None
                        and not _DIGEST.fullmatch(entry['nextCursorDigest']))
                    or (entry['rowCount'] == 0) !=
                       (entry.get('firstKey') is None
                        and entry.get('lastKey') is None)
                    or (entry['rowCount'] > 0
                        and (not isinstance(entry.get('firstKey'), str)
                             or not _DIGEST.fullmatch(entry['firstKey'])
                             or not isinstance(entry.get('lastKey'), str)
                             or not _DIGEST.fullmatch(entry['lastKey'])
                             or entry['firstKey'] > entry['lastKey']))
                    or (prior_key and entry.get('firstKey') <= prior_key)
                    or (index > 0 and entry['rowCount'] == 0)
                    or (index < len(manifest['pages']) - 1
                        and not entry['hasMore'])
                    or (index == len(manifest['pages']) - 1
                        and entry['hasMore'])):
                return False
            total_rows += entry['rowCount']
            total_bytes += entry['rowBytes']
            for kind in type_counts:
                type_counts[kind] += entry['typeCounts'][kind]
            cumulative = _advance(cumulative, entry)
            prior_next = entry['nextCursorDigest']
            prior_key = entry['lastKey'] or prior_key
        if (manifest['pageCount'] > limits.max_pages
                or total_rows > limits.max_rows
                or total_bytes > limits.max_bytes
                or total_rows != manifest['totalRowCount']
                or total_bytes != manifest['totalRowBytes']
                or type_counts != manifest['typeCounts']
                or cumulative != manifest['cumulativeDigest']):
            return False
        unsigned = dict(manifest)
        claimed = unsigned.pop('manifestDigest')
        return hmac.compare_digest(
            claimed, sha256(_canonical(unsigned)).hexdigest())
    except (KeyError, RecursionError, TypeError, ValueError, UnicodeError):
        return False


def canonical_export_artifact_json(manifest: dict) -> bytes:
    if not export_artifact_manifest_matches(manifest):
        raise ValueError('EXPORT_ARTIFACT_MANIFEST_INVALID')
    return _canonical(manifest)
