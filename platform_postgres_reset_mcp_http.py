"""Disabled-by-default HTTP entry point for owner-only V2 reset apply."""
from __future__ import annotations

import os

from platform_postgres_mcp_http import (
    PostgresAccessGate, bind_host, transport_security)
from platform_postgres_reset_mcp_server import server
from epm_core.postgres_mcp_execution import check_startup


def build_app():
    if os.environ.get('EPM_RESET_APPLY_ENABLED') != '1':
        raise RuntimeError('RESET_APPLY_LISTENER_DISABLED')
    if os.environ.get('EPM_RESET_REPLACEMENT_READY') != '1':
        raise RuntimeError('RESET_REPLACEMENT_NOT_READY')
    if os.environ.get('EPM_RESET_ENDPOINTS_RETIRED') != '1':
        raise RuntimeError('RESET_ENDPOINTS_NOT_RETIRED')
    check_startup('platform_postgres_reset_mcp_server')
    inner = server.streamable_http_app(
        host=bind_host(), streamable_http_path='/mcp',
        json_response=True, stateless_http=True,
        max_request_body_size=1_000_000,
        transport_security=transport_security())
    return PostgresAccessGate(inner, execution_module='platform_postgres_reset_mcp_server')


def port() -> int:
    raw = os.environ.get('EPM_PG_RESET_MCP_PORT', '5196')
    if not raw.isdecimal() or not 1024 <= int(raw) <= 65535:
        raise ValueError('EPM_PG_RESET_MCP_PORT must be 1024–65535')
    return int(raw)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(build_app(), host=bind_host(), port=port(), log_level='info')
