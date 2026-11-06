"""Opaque, identity-bound MCP endpoint identifiers.

The identifier is routing metadata, never a bearer credential.  HTTP callers
must still authenticate, and the gateway compares the path against the
verified issuer/subject before dispatching any MCP request.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from urllib.parse import urlsplit


PREFIX = '/api/application/mcp/users/'
_IDENTIFIER = re.compile(r'^epu_[A-Za-z0-9_-]{43}$')
_DOMAIN = b'openepm.personal-mcp-endpoint.v1\0'


def endpoint_secret(secret_hex: str) -> bytes:
    try:
        secret = bytes.fromhex(secret_hex)
    except (TypeError, ValueError) as error:
        raise ValueError('PERSONAL_MCP_SECRET_INVALID') from error
    if len(secret) < 32:
        raise ValueError('PERSONAL_MCP_SECRET_INVALID')
    return secret


def personal_identifier(secret: bytes, issuer: str, subject: str) -> str:
    if (not isinstance(secret, bytes) or len(secret) < 32 or
            not isinstance(issuer, str) or not issuer or
            not isinstance(subject, str) or not subject):
        raise ValueError('PERSONAL_MCP_IDENTITY_INVALID')
    digest = hmac.new(secret, _DOMAIN + issuer.encode('utf-8') + b'\0' +
                      subject.encode('utf-8'), hashlib.sha256).digest()
    return 'epu_' + base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')


def personal_path(secret: bytes, issuer: str, subject: str) -> str:
    return PREFIX + personal_identifier(secret, issuer, subject)


def is_personal_path(path: object) -> bool:
    return (isinstance(path, str) and path.startswith(PREFIX) and
            _IDENTIFIER.fullmatch(path[len(PREFIX):]) is not None)


def personal_endpoint(origin: str, secret: bytes, issuer: str,
                      subject: str) -> str:
    parsed = urlsplit(origin)
    if (not origin or parsed.path not in ('', '/') or parsed.query or
            parsed.fragment or parsed.username or parsed.password or
            parsed.scheme != 'https' or not parsed.hostname):
        raise ValueError('PERSONAL_MCP_ORIGIN_INVALID')
    return origin.rstrip('/') + personal_path(secret, issuer, subject)

