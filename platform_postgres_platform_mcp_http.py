"""Authenticated loopback HTTP entry point for the V2 platform listener."""
from __future__ import annotations

import os

from platform_postgres_platform_mcp_server import application,server
from platform_postgres_mcp_http import (
    ExactMCPPathAlias, PostgresAccessGate, transport_security, bind_host,
)
from platform_postgres_platform_browser_http import build_browser_app
from epm_core.postgres_mcp_execution import check_startup, PLATFORM_WEB_MODULE


class PlatformRouteMux:
    def __init__(self, mcp_app, browser_app):
        self.mcp_app = mcp_app
        self.browser_app = browser_app

    async def __call__(self, scope, receive, send):
        if scope.get('type') == 'http' and scope.get('path','').startswith('/browser/'):
            return await self.browser_app(scope, receive, send)
        return await self.mcp_app(scope, receive, send)


def build_app():
    check_startup('platform_postgres_platform_mcp_server')
    check_startup(PLATFORM_WEB_MODULE)
    inner=server.streamable_http_app(
        host=bind_host(),streamable_http_path='/mcp',
        json_response=True,stateless_http=True,
        max_request_body_size=1_000_000,
        transport_security=transport_security())
    mcp = PostgresAccessGate(
        ExactMCPPathAlias(inner,'/api/platform/mcp'),
        execution_module='platform_postgres_platform_mcp_server')
    browser = PostgresAccessGate(build_browser_app(),
        execution_module=PLATFORM_WEB_MODULE)
    return PlatformRouteMux(mcp, browser)


def port() -> int:
    raw=os.environ.get('EPM_PG_PLATFORM_MCP_PORT','5193')
    if not raw.isdecimal() or not 1024 <= int(raw) <= 65535:
        raise ValueError('EPM_PG_PLATFORM_MCP_PORT must be 1024–65535')
    return int(raw)


if __name__=='__main__':
    import uvicorn
    uvicorn.run(build_app(),host=bind_host(),port=port(),log_level='info')
