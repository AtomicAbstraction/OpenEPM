"""Authenticated loopback HTTP entry point for the V2 application router."""
from __future__ import annotations

import os

from platform_postgres_router_mcp_server import router,server
from platform_postgres_mcp_http import (
    ExactMCPPathAlias, PersonalMCPPathAlias, PostgresAccessGate,
    transport_security, bind_host,
)
from epm_core.postgres_mcp_execution import check_startup


def build_app():
    check_startup('platform_postgres_router_mcp_server')
    inner=server.streamable_http_app(
        host=bind_host(),streamable_http_path='/mcp',
        json_response=True,stateless_http=True,
        max_request_body_size=10_000_000,
        transport_security=transport_security())
    return PostgresAccessGate(
        ExactMCPPathAlias(PersonalMCPPathAlias(inner),'/api/application/mcp'),
        execution_module='platform_postgres_router_mcp_server')


def port() -> int:
    raw=os.environ.get('EPM_PG_ROUTER_MCP_PORT','5194')
    if not raw.isdecimal() or not 1024 <= int(raw) <= 65535:
        raise ValueError('EPM_PG_ROUTER_MCP_PORT must be 1024–65535')
    return int(raw)


if __name__=='__main__':
    import uvicorn
    uvicorn.run(build_app(),host=bind_host(),port=port(),log_level='info')
