"""Authenticated loopback HTTP transport for the PostgreSQL V2 MCP listener.

Every HTTP request, including discovery, must present a valid MCP-audience
Access JWT. The SDK runs stateless HTTP, so sessions cannot change owner.
"""
from __future__ import annotations

import json
import hmac
import os
from urllib.parse import urlsplit

from platform_postgres_mcp_server import application, server
from mcp.server.transport_security import TransportSecuritySettings
from epm_core.postgres_auth import AuthError, mode
from epm_core.postgres_mcp_execution import (
    authenticate_http, check_startup, EXECUTION_MODULES, verified_mcp_request)
from epm_core.postgres_execution_policy import HTTP_POST_SECONDS, TIMEOUT_RESPONSE_SECONDS
from epm_core.postgres_http_budget import bounded_request, HTTPRequestDeadlineUnknown
from epm_core.personal_mcp_endpoint import (is_personal_path, personal_path,
                                            endpoint_secret)


class ExactMCPPathAlias:
    """Map one exact public listener path to ``/mcp``."""

    def __init__(self, app, public_path: str):
        if (not isinstance(public_path,str) or not public_path.startswith('/')
                or public_path.endswith('/') or public_path.count('/') < 2):
            raise ValueError('PUBLIC_MCP_PATH_INVALID')
        self.app=app
        self.public_path=public_path

    async def __call__(self,scope,receive,send):
        if scope.get('type')=='http' and scope.get('path')==self.public_path:
            scope=dict(scope)
            scope['path']='/mcp'
            if 'raw_path' in scope:
                scope['raw_path']=b'/mcp'
        return await self.app(scope,receive,send)


class PersonalMCPPathAlias:
    """Map a syntactically valid personal application path to ``/mcp``."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get('type') == 'http' and is_personal_path(scope.get('path')):
            scope = dict(scope)
            scope['path'] = '/mcp'
            if 'raw_path' in scope:
                scope['raw_path'] = b'/mcp'
        return await self.app(scope, receive, send)



class PostgresAccessGate:
    def __init__(self, app, *, execution_module='platform_postgres_mcp_server'):
        if mode() != 'oidc':
            raise RuntimeError('PostgreSQL MCP HTTP requires verified JWTs')
        self.app = app
        if execution_module not in EXECUTION_MODULES:
            raise RuntimeError('Invalid fixed listener execution module')
        self.execution_module = execution_module

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope.get('method') != 'POST':
            return await self._authenticated(scope, receive, send)
        return await bounded_request(self._authenticated,scope,receive,send,
            seconds=HTTP_POST_SECONDS,response_seconds=TIMEOUT_RESPONSE_SECONDS)

    async def _authenticated(self, scope, receive, send):
        if scope['type'] == 'http':
            header_name = b'authorization'
            assertions = [value for key,value in scope.get('headers',[])
                          if key.lower()==header_name]
            if len(assertions)!=1:
                await send({'type':'http.response.start','status':401,
                            'headers':[(b'content-type',b'application/json'),
                                       (b'cache-control',b'no-store')]})
                await send({'type':'http.response.body',
                            'body':b'{"error":"One identity assertion is required"}'})
                return
            headers = {key.decode('latin-1').lower():value.decode('latin-1')
                       for key,value in scope.get('headers',[])}
            try:
                identity_headers = {name:value for name,value in headers.items()
                    if name == 'authorization'}
                principal = await authenticate_http(self.execution_module, identity_headers)
            except AuthError as error:
                body = json.dumps({'error':str(error)},separators=(',',':')).encode()
                response_headers = [(b'content-type',b'application/json'),
                                    (b'cache-control',b'no-store')]
                if error.status == 503:
                    response_headers.append((b'retry-after',b'1'))
                await send({'type':'http.response.start','status':error.status,
                            'headers':response_headers})
                await send({'type':'http.response.body','body':body})
                return
            request_path = scope.get('path','')
            if request_path.startswith('/api/application/mcp/users/'):
                try:
                    expected = personal_path(endpoint_secret(os.environ.get(
                        'EPM_PG_PREVIEW_SECRET_HEX','')), principal.issuer,
                        principal.subject)
                except ValueError:
                    await send({'type':'http.response.start','status':503,
                                'headers':[(b'content-type',b'application/json'),
                                           (b'cache-control',b'no-store')]})
                    await send({'type':'http.response.body',
                                'body':b'{"error":"PERSONAL_MCP_CONFIGURATION_INVALID"}'})
                    return
                if not hmac.compare_digest(request_path, expected):
                    await send({'type':'http.response.start','status':403,
                                'headers':[(b'content-type',b'application/json'),
                                           (b'cache-control',b'no-store')]})
                    await send({'type':'http.response.body',
                                'body':b'{"error":"PERSONAL_MCP_IDENTITY_MISMATCH"}'})
                    return
            with verified_mcp_request(principal):
                await self.app(scope,receive,send)
            return
        await self.app(scope,receive,send)


def port() -> int:
    raw = os.environ.get('EPM_PG_MCP_PORT','5191')
    if not raw.isdecimal() or not 1024 <= int(raw) <= 65535:
        raise ValueError('EPM_PG_MCP_PORT must be 1024–65535')
    return int(raw)


def bind_host() -> str:
    host=os.environ.get('EPM_PG_BIND_HOST','127.0.0.1')
    if host not in ('127.0.0.1','0.0.0.0'):
        raise ValueError('EPM_PG_BIND_HOST must be a loopback or container bind')
    return host


def public_mcp_origin() -> tuple[str,str] | None:
    """Return the exact external Origin and Host admitted by the proxy.

    DNS-rebinding protection must remain enabled in containers.  The proxy
    preserves the public Host header, so loopback-only defaults make every
    legitimate public MCP request fail before authentication.  Admit only one
    explicitly configured credential-free origin; never add a wildcard.
    """
    raw=os.environ.get('EPM_PUBLIC_MCP_ORIGIN','').strip()
    if not raw:
        return None
    parsed=urlsplit(raw)
    loopback=parsed.hostname in ('127.0.0.1','localhost','::1')
    if (parsed.scheme not in (('http','https') if loopback else ('https',))
            or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ('','/')):
        raise ValueError(
            'EPM_PUBLIC_MCP_ORIGIN must be a credential-free HTTPS origin '
            'or loopback HTTP origin')
    try:
        port=parsed.port
    except ValueError as error:
        raise ValueError('EPM_PUBLIC_MCP_ORIGIN has an invalid port') from error
    host=('['+parsed.hostname+']' if ':' in parsed.hostname
          else parsed.hostname)
    if port is not None:
        host += ':'+str(port)
    origin=parsed.scheme+'://'+host
    return origin,host


def transport_security() -> TransportSecuritySettings:
    allowed_hosts=['127.0.0.1:*','localhost:*','[::1]:*']
    allowed_origins=['http://127.0.0.1:*','http://localhost:*',
                     'http://[::1]:*']
    public=public_mcp_origin()
    if public is not None:
        origin,host=public
        allowed_hosts.append(host)
        allowed_origins.append(origin)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins)


def build_app():
    # Fail closed before listening if binding, secret or RLS role are unsafe.
    check_startup('platform_postgres_mcp_server')
    inner = server.streamable_http_app(
        host=bind_host(),streamable_http_path='/mcp',
        json_response=True,stateless_http=True,
        max_request_body_size=10_000_000,
        transport_security=transport_security())
    return PostgresAccessGate(inner)


if __name__=='__main__':
    import uvicorn
    uvicorn.run(build_app(),host=bind_host(),port=port(),log_level='info')
