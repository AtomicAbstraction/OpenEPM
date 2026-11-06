"""Platform-bound V2 MCP listener for authorized workspace creation."""
from __future__ import annotations

import logging
import os
from mcp.server import MCPServer
from epm_core.postgres_mcp_execution import bounded_tool
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
import psycopg
from epm_core.postgres_processing_limits import BUSY_CODE

from epm_core.postgres_auth import AuthError, access_token
from epm_core.keycloak_directory import KeycloakDirectoryError
from epm_core.postgres_platform_mcp_application import PostgresPlatformMCPApplication
from epm_core.deployment_secrets import configured_text

LOG=logging.getLogger(__name__)
server=MCPServer('Open EPM PostgreSQL V2 Platform',instructions=(
    'A verified, enrolled platform operator may create a blank workspace '
    'through a typed V2 program. No SQL or caller-supplied identity is accepted.'))


def application() -> PostgresPlatformMCPApplication:
    return PostgresPlatformMCPApplication(
        configured_text(os.environ,'EPM_PG_PROVISION_DSN',
                        'EPM_PG_PROVISION_DSN_FILE'))


def _startup_role_check():
    application().assert_runtime_role()


def _assertion(ctx: Context) -> str:
    try:
        headers=ctx.headers or {}
    except (AttributeError,ValueError):
        headers={}
    return access_token(headers)


def _call(operation):
    try:
        return operation()
    except (AuthError,KeycloakDirectoryError,ValueError) as error:
        raise ToolError(str(error)) from error
    except psycopg.errors.LockNotAvailable as error:
        raise ToolError(BUSY_CODE + '; no new job is implied; retry the same request key') from error
    except psycopg.Error as error:
        LOG.exception('PostgreSQL platform operation failed')
        raise ToolError('POSTGRES_OPERATION_FAILED') from error


@bounded_tool(server)
def list_v2_platform_functions(ctx: Context) -> dict:
    """Discover functions granted to the verified platform operator."""
    return _call(lambda:application().catalog(_assertion(ctx)))


@bounded_tool(server)
def execute_v2_platform_program(program: dict,idempotency_key: str,
                                ctx: Context) -> dict:
    """Create a blank workspace and first Administrator atomically."""
    return _call(lambda:application().create(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_platform_program(program: dict,ctx: Context) -> dict:
    """Read bounded native-user or stable-group directory metadata."""
    return _call(lambda:application().read(_assertion(ctx),program))
