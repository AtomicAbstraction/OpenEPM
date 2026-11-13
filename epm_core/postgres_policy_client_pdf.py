"""Validation of client-produced PDF text without parsing PDF bytes.

The fixed core treats the original PDF as inert, content-addressed evidence.
An MCP client may submit a separate bounded JSON extraction manifest.  This
module validates that manifest's structure and hashes; it does not assert that
the submitted text is a truthful rendering of the PDF.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re


SCHEMA_VERSION = 'openepm-client-pdf-extraction-v1'
MEDIA_TYPE = 'application/json'
TRUST = 'ClientSuppliedUnreviewed'
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PAGE_TEXT_BYTES = 200_000
MAX_PAGES = 100
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('POLICY_SOURCE_CLIENT_PDF_MANIFEST_INVALID')
        result[key] = value
    return result


def validate_manifest(content: bytes, *, document_artifact_id: str,
                      document_sha256: str) -> dict:
    if (not isinstance(content, bytes)
            or not 1 <= len(content) <= MAX_MANIFEST_BYTES
            or not isinstance(document_artifact_id, str)
            or not _ID.fullmatch(document_artifact_id)
            or not isinstance(document_sha256, str)
            or not _HASH.fullmatch(document_sha256)):
        raise ValueError('POLICY_SOURCE_CLIENT_PDF_MANIFEST_INVALID')
    try:
        raw = json.loads(content.decode('utf-8', errors='strict'),
                         object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError('POLICY_SOURCE_CLIENT_PDF_MANIFEST_INVALID') from error
    if (not isinstance(raw, dict)
            or set(raw) != {'schemaVersion', 'documentArtifactId',
                            'documentSha256', 'extractor', 'pages'}
            or raw['schemaVersion'] != SCHEMA_VERSION
            or raw['documentArtifactId'] != document_artifact_id
            or raw['documentSha256'] != document_sha256
            or not isinstance(raw['extractor'], dict)
            or set(raw['extractor']) != {'name', 'version'}
            or any(not isinstance(raw['extractor'][key], str)
                   or not 1 <= len(raw['extractor'][key]) <= 100
                   or raw['extractor'][key] != raw['extractor'][key].strip()
                   for key in ('name', 'version'))
            or not isinstance(raw['pages'], list)
            or not 1 <= len(raw['pages']) <= MAX_PAGES):
        raise ValueError('POLICY_SOURCE_CLIENT_PDF_MANIFEST_INVALID')
    pages = {}
    total_text_bytes = 0
    for item in raw['pages']:
        if (not isinstance(item, dict)
                or set(item) != {'page', 'text', 'textSha256'}
                or type(item['page']) is not int
                or not 1 <= item['page'] <= MAX_PAGES
                or item['page'] in pages
                or not isinstance(item['text'], str)
                or not isinstance(item['textSha256'], str)
                or not _HASH.fullmatch(item['textSha256'])):
            raise ValueError('POLICY_SOURCE_CLIENT_PDF_MANIFEST_INVALID')
        encoded = item['text'].encode('utf-8')
        total_text_bytes += len(encoded)
        if (not encoded or len(encoded) > MAX_PAGE_TEXT_BYTES
                or total_text_bytes > MAX_MANIFEST_BYTES
                or sha256(encoded).hexdigest() != item['textSha256']):
            raise ValueError('POLICY_SOURCE_CLIENT_PDF_MANIFEST_INVALID')
        pages[item['page']] = {'page': item['page'], 'pageText': item['text'],
            'pageTextSha256': item['textSha256']}
    return {'schemaVersion': SCHEMA_VERSION,
        'documentArtifactId': document_artifact_id,
        'documentSha256': document_sha256,
        'extractor': dict(raw['extractor']),
        'pages': pages,
        'extractionTrust': TRUST}
