"""Pure, canonical row-payload chunks for a finalized export artifact.

This contract binds transported rows to the already sealed export manifest.
It deliberately does not persist, encrypt, compress, or authorize downloads.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
import re

from .export_artifact_manifest import export_artifact_manifest_matches
from .persistence_contract import ApplicationScope
from .postgres_fact_export import (
    PostgresFactExport, _EXPORT_SCHEMA, _content_digest, _valid_export_row)


CONTRACT_VERSION = 'openepm-export-payload-v2'
MAX_CHUNK_ROWS = 500
MAX_CHUNK_BYTES = 8 * 1024 * 1024
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_OPAQUE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z')
_SOURCE = re.compile(r'export:([0-9a-f]{64})\Z')


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _counts(rows: list[dict]) -> dict[str, int]:
    result = {'amount': 0, 'text': 0, 'lineDetail': 0}
    names = {'AmountLiteral': 'amount', 'TextLiteral': 'text',
             'LineDetailLiteral': 'lineDetail'}
    for row in rows:
        result[names[row['value']['type']]] += 1
    return result


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and _OPAQUE.fullmatch(value) is not None


def _validate_rows(rows: object) -> list[dict]:
    if (not isinstance(rows, list)
            or any(not _valid_export_row(row) for row in rows)):
        raise ValueError('EXPORT_PAYLOAD_ROWS_INVALID')
    keys = []
    for row in rows:
        match = _SOURCE.fullmatch(row['sourceRef'])
        if match is None:
            raise ValueError('EXPORT_PAYLOAD_SOURCE_INVALID')
        keys.append(match.group(1))
    if keys != sorted(set(keys)):
        raise ValueError('EXPORT_PAYLOAD_ROW_ORDER_INVALID')
    try:
        # Detach caller-owned structures and reject non-JSON values.
        return json.loads(_canonical(rows))
    except (RecursionError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError('EXPORT_PAYLOAD_ROWS_INVALID') from error


def _chunk_value(*, artifact_id: str, manifest: dict, page_entry: dict,
                 chunk_index: int, rows: list[dict], final: bool,
                 ciphertext_ref: dict | None) -> dict:
    value = {
        'contractVersion': CONTRACT_VERSION,
        'artifactId': artifact_id,
        'manifestDigest': manifest['manifestDigest'],
        'pageIndex': page_entry['pageIndex'],
        'chunkIndex': chunk_index,
        'pageEntryDigest': _digest(page_entry),
        'pageContentDigest': page_entry['contentDigest'],
        'rows': rows,
        'rowCount': len(rows),
        'rowBytes': len(_canonical(rows)),
        'typeCounts': _counts(rows),
        'firstKey': (rows[0]['sourceRef'][7:] if rows else None),
        'lastKey': (rows[-1]['sourceRef'][7:] if rows else None),
        'finalChunkForPage': final,
        'ciphertextRef': ciphertext_ref,
    }
    value['chunkDigest'] = _digest(value)
    return value


def compile_export_payload(
        artifact_id: str, scope: ApplicationScope, manifest: dict,
        pages: list[dict], *, max_chunk_rows: int = MAX_CHUNK_ROWS,
        max_chunk_bytes: int = MAX_CHUNK_BYTES,
        ciphertext_refs: dict[str, dict] | None = None) -> dict:
    """Seal actual page rows against a complete export manifest.

    ``ciphertext_refs`` may only associate server-generated opaque key/object
    identifiers with a ``"page:chunk"``. Cryptography and ciphertext bytes are
    intentionally outside this pure contract.
    """
    if (not _valid_id(artifact_id) or not isinstance(scope, ApplicationScope)
            or not export_artifact_manifest_matches(manifest, scope=scope)
            or not isinstance(pages, list)
            or len(pages) != manifest['pageCount']
            or type(max_chunk_rows) is not int
            or not 1 <= max_chunk_rows <= MAX_CHUNK_ROWS
            or type(max_chunk_bytes) is not int
            or not 2 <= max_chunk_bytes <= MAX_CHUNK_BYTES
            or not isinstance(ciphertext_refs or {}, dict)):
        raise ValueError('EXPORT_PAYLOAD_INPUT_INVALID')
    refs = ciphertext_refs or {}
    used_refs: set[str] = set()
    chunks = []
    prior_key = ''
    for page_index, (page, entry) in enumerate(
            zip(pages, manifest['pages'], strict=True)):
        if (not isinstance(page, dict)
                or page.get('schema') != _EXPORT_SCHEMA
                or page.get('snapshotRevision') != manifest['snapshotRevision']
                or page.get('metadataRevision') != manifest['metadataRevision']
                or page.get('hasMore') != entry['hasMore']
                or not PostgresFactExport.content_digest_matches(scope, page)):
            raise ValueError('EXPORT_PAYLOAD_PAGE_INVALID')
        rows = _validate_rows(page.get('rows'))
        if (len(rows) != entry['rowCount']
                or len(_canonical(rows)) != entry['rowBytes']
                or _counts(rows) != entry['typeCounts']
                or page['contentDigest'] != entry['contentDigest']):
            raise ValueError('EXPORT_PAYLOAD_MANIFEST_MISMATCH')
        if rows and (rows[0]['sourceRef'][7:] != entry['firstKey']
                     or rows[-1]['sourceRef'][7:] != entry['lastKey']
                     or (prior_key and rows[0]['sourceRef'][7:] <= prior_key)):
            raise ValueError('EXPORT_PAYLOAD_MANIFEST_MISMATCH')
        prior_key = entry['lastKey'] or prior_key
        groups: list[list[dict]] = []
        current: list[dict] = []
        for row in rows:
            candidate = [*current, row]
            if (len(candidate) > max_chunk_rows
                    or len(_canonical(candidate)) > max_chunk_bytes):
                if not current:
                    raise ValueError('EXPORT_PAYLOAD_ROW_TOO_LARGE')
                groups.append(current)
                current = [row]
                if len(_canonical(current)) > max_chunk_bytes:
                    raise ValueError('EXPORT_PAYLOAD_ROW_TOO_LARGE')
            else:
                current = candidate
        groups.append(current)  # An empty export has one explicit empty chunk.
        for chunk_index, group in enumerate(groups):
            ref_key = f'{page_index}:{chunk_index}'
            ref = refs.get(ref_key)
            if ref is not None:
                if (not isinstance(ref, dict)
                        or set(ref) != {'keyId', 'objectId'}
                        or not all(_valid_id(value) for value in ref.values())):
                    raise ValueError('EXPORT_PAYLOAD_CIPHERTEXT_REF_INVALID')
                ref = dict(ref)
                used_refs.add(ref_key)
            chunks.append(_chunk_value(
                artifact_id=artifact_id, manifest=manifest, page_entry=entry,
                chunk_index=chunk_index, rows=group,
                final=chunk_index == len(groups) - 1,
                ciphertext_ref=ref))
    if used_refs != set(refs):
        raise ValueError('EXPORT_PAYLOAD_CIPHERTEXT_REF_UNUSED')
    result = {
        'contractVersion': CONTRACT_VERSION,
        'status': 'complete',
        'artifactId': artifact_id,
        'manifestDigest': manifest['manifestDigest'],
        'scope': {'workspaceId': scope.workspace_id,
                  'applicationId': scope.application_id},
        'snapshotRevision': manifest['snapshotRevision'],
        'metadataRevision': manifest['metadataRevision'],
        'securityRevision': manifest['securityRevision'],
        'chunkCount': len(chunks),
        'rowCount': sum(chunk['rowCount'] for chunk in chunks),
        # Whole-payload bytes retain the manifest's canonical per-page array
        # accounting; chunk framing bytes are recorded on each chunk.
        'rowBytes': manifest['totalRowBytes'],
        'typeCounts': {kind: sum(chunk['typeCounts'][kind] for chunk in chunks)
                       for kind in ('amount', 'text', 'lineDetail')},
        'chunks': chunks,
    }
    result['payloadDigest'] = _digest(result)
    if not export_payload_matches(result, scope=scope, artifact_id=artifact_id,
                                  manifest=manifest):
        raise ValueError('EXPORT_PAYLOAD_STATE_INVALID')
    return result


def export_payload_chunk_matches(chunk: object, *, artifact_id: str,
                                 manifest: dict) -> bool:
    """Verify one stored chunk against its sealed manifest page identity."""
    try:
        fields = {'contractVersion', 'artifactId', 'manifestDigest',
                  'pageIndex', 'chunkIndex', 'pageEntryDigest',
                  'pageContentDigest', 'rows', 'rowCount', 'rowBytes',
                  'typeCounts', 'firstKey', 'lastKey',
                  'finalChunkForPage', 'ciphertextRef', 'chunkDigest'}
        if (not isinstance(chunk, dict) or set(chunk) != fields
                or chunk['contractVersion'] != CONTRACT_VERSION
                or chunk['artifactId'] != artifact_id
                or not _valid_id(artifact_id)
                or chunk['manifestDigest'] != manifest.get('manifestDigest')
                or type(chunk['pageIndex']) is not int
                or not 0 <= chunk['pageIndex'] < len(manifest['pages'])
                or type(chunk['chunkIndex']) is not int
                or chunk['chunkIndex'] < 0
                or type(chunk['rowCount']) is not int
                or not 0 <= chunk['rowCount'] <= MAX_CHUNK_ROWS
                or type(chunk['rowBytes']) is not int
                or not 0 <= chunk['rowBytes'] <= MAX_CHUNK_BYTES
                or not isinstance(chunk['finalChunkForPage'], bool)
                or len(_canonical(chunk)) > MAX_CHUNK_BYTES):
            return False
        entry = manifest['pages'][chunk['pageIndex']]
        if (chunk['pageEntryDigest'] != _digest(entry)
                or chunk['pageContentDigest'] != entry['contentDigest']):
            return False
        rows = _validate_rows(chunk['rows'])
        if (chunk['rowCount'] != len(rows)
                or chunk['rowBytes'] != len(_canonical(rows))
                or chunk['typeCounts'] != _counts(rows)
                or chunk['firstKey'] !=
                   (rows[0]['sourceRef'][7:] if rows else None)
                or chunk['lastKey'] !=
                   (rows[-1]['sourceRef'][7:] if rows else None)):
            return False
        ref = chunk['ciphertextRef']
        if (ref is not None and (not isinstance(ref, dict)
                or set(ref) != {'keyId', 'objectId'}
                or not all(_valid_id(value) for value in ref.values()))):
            return False
        unsigned = dict(chunk)
        claimed = unsigned.pop('chunkDigest')
        return (isinstance(claimed, str) and _DIGEST.fullmatch(claimed)
                and hmac.compare_digest(claimed, _digest(unsigned)))
    except (IndexError, KeyError, RecursionError, TypeError, ValueError,
            UnicodeError):
        return False


def export_payload_matches(payload: object, *, scope: ApplicationScope,
                           artifact_id: str, manifest: dict) -> bool:
    """Verify completeness and every row without source-data rereads."""
    try:
        required = {'contractVersion', 'status', 'artifactId',
                    'manifestDigest', 'scope', 'snapshotRevision',
                    'metadataRevision', 'securityRevision', 'chunkCount',
                    'rowCount', 'rowBytes',
                    'typeCounts', 'chunks', 'payloadDigest'}
        if (not isinstance(payload, dict) or set(payload) != required
                or payload['contractVersion'] != CONTRACT_VERSION
                or payload['status'] != 'complete'
                or payload['artifactId'] != artifact_id
                or not _valid_id(artifact_id)
                or not export_artifact_manifest_matches(manifest, scope=scope)
                or payload['manifestDigest'] != manifest['manifestDigest']
                or payload['scope'] != {'workspaceId': scope.workspace_id,
                                        'applicationId': scope.application_id}
                or payload['snapshotRevision'] != manifest['snapshotRevision']
                or payload['metadataRevision'] != manifest['metadataRevision']
                or payload['securityRevision'] != manifest['securityRevision']
                or type(payload['chunkCount']) is not int
                or payload['chunkCount'] != len(payload['chunks'])
                or not payload['chunks']):
            return False
        expected_page = expected_chunk = 0
        reconstructed: list[list[dict]] = [[] for _ in manifest['pages']]
        for chunk in payload['chunks']:
            fields = {'contractVersion', 'artifactId', 'manifestDigest',
                      'pageIndex', 'chunkIndex', 'pageEntryDigest',
                      'pageContentDigest', 'rows', 'rowCount', 'rowBytes',
                      'typeCounts', 'firstKey', 'lastKey',
                      'finalChunkForPage', 'ciphertextRef', 'chunkDigest'}
            if (not export_payload_chunk_matches(
                        chunk, artifact_id=artifact_id, manifest=manifest)
                    or not isinstance(chunk, dict) or set(chunk) != fields
                    or chunk['contractVersion'] != CONTRACT_VERSION
                    or chunk['artifactId'] != artifact_id
                    or chunk['manifestDigest'] != manifest['manifestDigest']
                    or type(chunk['pageIndex']) is not int
                    or chunk['pageIndex'] != expected_page
                    or type(chunk['chunkIndex']) is not int
                    or chunk['chunkIndex'] != expected_chunk
                    or chunk['pageIndex'] >= len(manifest['pages'])
                    or type(chunk['rowCount']) is not int
                    or not 0 <= chunk['rowCount'] <= MAX_CHUNK_ROWS
                    or type(chunk['rowBytes']) is not int
                    or not 0 <= chunk['rowBytes'] <= MAX_CHUNK_BYTES
                    or not isinstance(chunk['finalChunkForPage'], bool)):
                return False
            entry = manifest['pages'][expected_page]
            if (chunk['pageEntryDigest'] != _digest(entry)
                    or chunk['pageContentDigest'] != entry['contentDigest']):
                return False
            rows = _validate_rows(chunk['rows'])
            if (chunk['rowCount'] != len(rows)
                    or (not rows and (entry['rowCount'] != 0
                                      or expected_chunk != 0
                                      or not chunk['finalChunkForPage']))
                    or chunk['rowBytes'] != len(_canonical(rows))
                    or chunk['typeCounts'] != _counts(rows)
                    or chunk['firstKey'] !=
                       (rows[0]['sourceRef'][7:] if rows else None)
                    or chunk['lastKey'] !=
                       (rows[-1]['sourceRef'][7:] if rows else None)):
                return False
            ref = chunk['ciphertextRef']
            if (ref is not None and (not isinstance(ref, dict)
                    or set(ref) != {'keyId', 'objectId'}
                    or not all(_valid_id(value) for value in ref.values()))):
                return False
            unsigned = dict(chunk)
            claimed = unsigned.pop('chunkDigest')
            if (not isinstance(claimed, str) or not _DIGEST.fullmatch(claimed)
                    or not hmac.compare_digest(claimed, _digest(unsigned))):
                return False
            reconstructed[expected_page].extend(rows)
            if chunk['finalChunkForPage']:
                expected_page += 1
                expected_chunk = 0
            else:
                expected_chunk += 1
        if expected_page != len(manifest['pages']) or expected_chunk != 0:
            return False
        totals = {'amount': 0, 'text': 0, 'lineDetail': 0}
        total_bytes = 0
        for index, rows in enumerate(reconstructed):
            entry = manifest['pages'][index]
            page = {'schema': manifest['schema'], 'rows': rows,
                    'hasMore': entry['hasMore'],
                    'snapshotRevision': manifest['snapshotRevision'],
                    'metadataRevision': manifest['metadataRevision']}
            page['securityRevision'] = manifest['securityRevision']
            page['contentDigest'] = _content_digest(scope, page)
            counts = _counts(rows)
            if (page['contentDigest'] != entry['contentDigest']
                    or len(rows) != entry['rowCount']
                    or len(_canonical(rows)) != entry['rowBytes']
                    or counts != entry['typeCounts']):
                return False
            total_bytes += len(_canonical(rows))
            for kind in totals:
                totals[kind] += counts[kind]
        if (type(payload['rowCount']) is not int
                or payload['rowCount'] != manifest['totalRowCount']
                or type(payload['rowBytes']) is not int
                or payload['rowBytes'] != total_bytes
                or payload['typeCounts'] != totals):
            return False
        unsigned = dict(payload)
        claimed = unsigned.pop('payloadDigest')
        return (isinstance(claimed, str) and _DIGEST.fullmatch(claimed)
                and hmac.compare_digest(claimed, _digest(unsigned)))
    except (IndexError, KeyError, RecursionError, TypeError, ValueError,
            UnicodeError):
        return False


def canonical_export_payload_json(payload: dict, *, scope: ApplicationScope,
                                  artifact_id: str, manifest: dict) -> bytes:
    if not export_payload_matches(payload, scope=scope,
                                  artifact_id=artifact_id,
                                  manifest=manifest):
        raise ValueError('EXPORT_PAYLOAD_INVALID')
    return _canonical(payload)
