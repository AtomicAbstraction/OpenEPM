"""Authenticated loopback HTTP entry point for the workspace V2 listener."""
from __future__ import annotations

import os

from platform_postgres_workspace_mcp_server import application, server
from platform_postgres_mcp_http import (
    ExactMCPPathAlias, PostgresAccessGate, transport_security, bind_host,
)
from epm_core.postgres_mcp_execution import check_startup


def build_app():
    check_startup('platform_postgres_workspace_mcp_server')
    inner = server.streamable_http_app(
        host=bind_host(), streamable_http_path='/mcp',
        json_response=True, stateless_http=True,
        max_request_body_size=1_000_000,
        transport_security=transport_security())
    return PostgresAccessGate(
        ExactMCPPathAlias(inner,'/api/workspace/mcp'),
        execution_module='platform_postgres_workspace_mcp_server')


def port() -> int:
    raw = os.environ.get('EPM_PG_WORKSPACE_MCP_PORT', '5192')
    if not raw.isdecimal() or not 1024 <= int(raw) <= 65535:
        raise ValueError('EPM_PG_WORKSPACE_MCP_PORT must be 1024–65535')
    return int(raw)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(build_app(), host=bind_host(), port=port(), log_level='info')
