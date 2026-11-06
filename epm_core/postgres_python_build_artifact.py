"""Bounded caller-owned inspection of immutable sealed Python build artifacts.

Cursors intentionally have no time expiry: every page performs fresh database
authorization and revalidates the same immutable artifact digests.  Rotating
the server-owned signing secret invalidates outstanding cursors.  This is not
an expiring bearer-token contract and responses must not describe it as one.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
from hashlib import sha256

from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_python_program_repository import PostgresPythonProgramRepository


SECTIONS = frozenset({'Plan', 'SourceMap', 'BuildLog'})
PAGE_BYTES = 64 * 1024
MAX_CURSOR_BYTES = 4096


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


class PostgresPythonBuildArtifact:
    """Read immutable artifacts without executing or admitting their plan."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 cursor_secret: bytes):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('Verified identity is required')
        if not isinstance(cursor_secret, bytes) or len(cursor_secret) < 32:
            raise ValueError('A server-owned cursor secret is required')
        self.identity = identity
        self.cursor_secret = cursor_secret
        self.repository = PostgresPythonProgramRepository(
            dsn, None, identity=identity)

    def read(self, scope: ApplicationScope, *, build_id: str,
             section: str, cursor: str | None = None) -> dict:
        if section not in SECTIONS:
            raise ValueError('PYTHON_BUILD_ARTIFACT_SECTION_INVALID')
        artifact = self.repository.read_sealed_artifact(scope, build_id)
        raw = artifact['sections'][section]
        section_digest = sha256(raw).hexdigest()
        offset = 0
        if cursor is not None:
            value = self._unpack(cursor)
            expected = {'version': 1,
                'scope': [scope.workspace_id, scope.application_id],
                'identity': [self.identity.issuer, self.identity.subject_id],
                'buildId': build_id, 'section': section,
                'planDigest': artifact['planDigest'],
                'sourceDigest': artifact['sourceDigest'],
                'sectionDigest': section_digest}
            if any(value.get(key) != item for key, item in expected.items()):
                raise ValueError('PYTHON_BUILD_ARTIFACT_CURSOR_INVALID')
            offset = value.get('offset')
            if (type(offset) is not int or offset <= 0
                    or offset >= len(raw) or offset % PAGE_BYTES != 0):
                raise ValueError('PYTHON_BUILD_ARTIFACT_CURSOR_INVALID')
        end = min(offset + PAGE_BYTES, len(raw))
        next_cursor = None
        if end < len(raw):
            next_cursor = self._pack({'version': 1,
                'scope': [scope.workspace_id, scope.application_id],
                'identity': [self.identity.issuer, self.identity.subject_id],
                'buildId': build_id, 'section': section,
                'planDigest': artifact['planDigest'],
                'sourceDigest': artifact['sourceDigest'],
                'sectionDigest': section_digest, 'offset': end})
        return {'buildId': build_id, 'section': section,
                'encoding': 'base64', 'offset': offset, 'totalBytes': len(raw),
                'chunkBase64': base64.b64encode(raw[offset:end]).decode('ascii'),
                'nextCursor': next_cursor,
                'planDigest': artifact['planDigest'],
                'sourceDigest': artifact['sourceDigest'],
                'sectionDigest': section_digest,
                'compilerVersion': artifact['compilerVersion'],
                'unitCount': artifact['unitCount']}

    def _pack(self, value: dict) -> str:
        raw = _canonical(value)
        signature = hmac.new(self.cursor_secret, raw, sha256).digest()
        return base64.urlsafe_b64encode(raw + signature).decode('ascii')

    def _unpack(self, token: object) -> dict:
        if type(token) is not str or not 1 <= len(token) <= MAX_CURSOR_BYTES:
            raise ValueError('PYTHON_BUILD_ARTIFACT_CURSOR_INVALID')
        try:
            raw_signed = base64.b64decode(token.encode('ascii'), altchars=b'-_',
                                          validate=True)
            if len(raw_signed) <= 32:
                raise ValueError
            raw, signature = raw_signed[:-32], raw_signed[-32:]
            if not hmac.compare_digest(
                    signature, hmac.new(self.cursor_secret, raw, sha256).digest()):
                raise ValueError
            value = json.loads(raw.decode('ascii'))
        except (UnicodeEncodeError, UnicodeDecodeError, binascii.Error,
                json.JSONDecodeError, ValueError) as error:
            raise ValueError('PYTHON_BUILD_ARTIFACT_CURSOR_INVALID') from error
        if type(value) is not dict or set(value) != {
                'version', 'scope', 'identity', 'buildId', 'section',
                'planDigest', 'sourceDigest', 'sectionDigest', 'offset'}:
            raise ValueError('PYTHON_BUILD_ARTIFACT_CURSOR_INVALID')
        return value
