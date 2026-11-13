"""Public OAuth resource metadata derived only from trusted deployment settings.

This module describes MCP resources; it authenticates no caller and grants no
application permission. The real MCP request still enters PostgresAccessGate.
"""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
from urllib.parse import urlsplit

from .personal_mcp_endpoint import is_personal_path

METADATA_PATH = '/.well-known/oauth-protected-resource'
APPLICATION_PATH = '/api/application/mcp'
PUBLIC_PATHS = (APPLICATION_PATH, '/api/workspace/mcp', '/api/platform/mcp')
PUBLIC_MODULES = frozenset(('platform_postgres_router_mcp_server',
    'platform_postgres_workspace_mcp_server', 'platform_postgres_platform_mcp_server'))


def _url(value: str, *, origin: bool):
    if (not isinstance(value, str) or not value
            or any(ord(char) <= 32 or ord(char) >= 127 or char in '\\"<>' for char in value)):
        raise ValueError('MCP_OAUTH_DISCOVERY_URL_INVALID')
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError as error:
        raise ValueError('MCP_OAUTH_DISCOVERY_URL_INVALID') from error
    if not host:
        raise ValueError('MCP_OAUTH_DISCOVERY_URL_INVALID')
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host)
                or '..' in host):
            raise ValueError('MCP_OAUTH_DISCOVERY_URL_INVALID')
    loopback = host in ('127.0.0.1', 'localhost', '::1')
    if (parsed.scheme not in (('https', 'http') if origin and loopback else ('https',))
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or origin and parsed.path not in ('', '/')
            or port is not None and not 1 <= port <= 65535):
        raise ValueError('MCP_OAUTH_DISCOVERY_URL_INVALID')
    return parsed


def validated_public_origin(raw: str) -> tuple[str, str] | None:
    """The one explicit HTTPS origin (or loopback HTTP) admitted by transport."""
    value = raw.strip()
    if not value:
        return None
    parsed = _url(value, origin=True)
    host = '[' + parsed.hostname + ']' if ':' in parsed.hostname else parsed.hostname
    if parsed.port is not None:
        host += ':' + str(parsed.port)
    return parsed.scheme + '://' + host, host


def resource_path(path: object) -> str | None:
    if isinstance(path, str) and (path in PUBLIC_PATHS or is_personal_path(path)):
        return path
    return None


@dataclass(frozen=True, slots=True)
class ProtectedResourceDiscovery:
    origin: str
    issuer: str

    def __post_init__(self):
        origin = validated_public_origin(self.origin)
        if origin is None:
            raise ValueError('MCP_OAUTH_DISCOVERY_URL_INVALID')
        # Preserve the configured issuer identifier exactly after validation.
        # It is not the internal signing-key URL and never comes from a header.
        _url(self.issuer, origin=False)
        object.__setattr__(self, 'origin', origin[0])

    def document(self, path: str) -> dict | None:
        if path == METADATA_PATH:
            target = APPLICATION_PATH
        elif path.startswith(METADATA_PATH + '/'):
            target = resource_path(path[len(METADATA_PATH):])
        else:
            return None
        if target is None:
            return None
        return {'resource': self.origin + target,
            'authorization_servers': [self.issuer],
            'bearer_methods_supported': ['header'],
            'scopes_supported': ['openid', 'profile'],
            'resource_name': 'Open EPM'}

    def challenge(self, path: object) -> bytes:
        target = resource_path(path)
        if target is None:
            return b'Bearer'
        return ('Bearer resource_metadata="' + self.origin + METADATA_PATH + target +
                '", scope="openid profile"').encode('ascii')

    async def respond(self, scope, receive, send, *, transport_security) -> bool:
        """Serve only known public metadata paths; never alias a business path."""
        path = scope.get('path', '')
        document = self.document(path)
        if document is None:
            return False
        # Metadata bypasses token verification, not the existing Host/Origin
        # fence. Reuse the SDK transport validator rather than a second policy.
        from starlette.requests import Request
        rejected = await transport_security.validate_request(Request(scope, receive))
        if rejected is not None:
            await rejected(scope, receive, send)
            return True
        headers = [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]
        if scope.get('query_string', b''):
            status, body = 404, b'{"error":"METADATA_PATH_UNAVAILABLE"}'
        elif scope.get('method') not in ('GET', 'HEAD'):
            status, body = 405, b'{"error":"METADATA_METHOD_NOT_ALLOWED"}'
            headers.append((b'allow', b'GET, HEAD'))
        else:
            status = 200
            body = json.dumps(document, sort_keys=True, separators=(',', ':')).encode('utf-8')
        headers.append((b'content-length', str(len(body)).encode('ascii')))
        await send({'type': 'http.response.start', 'status': status, 'headers': headers})
        await send({'type': 'http.response.body',
                    'body': b'' if scope.get('method') == 'HEAD' else body})
        return True
