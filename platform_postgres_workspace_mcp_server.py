"""Workspace-bound PostgreSQL V2 MCP lifecycle listener."""
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
from epm_core.deployment_secrets import configured_hex_bytes, configured_text
from epm_core.postgres_workspace_mcp_application import PostgresWorkspaceMCPApplication
from epm_core.published_skill_delivery import (
    bootstrap_instructions, read_published_skill, register_skill_resources,
)

LOG = logging.getLogger(__name__)
server = MCPServer('Open EPM PostgreSQL V2 Workspace', instructions=bootstrap_instructions(
    'This listener is bound to one workspace. An authenticated workspace '
    'administrator may create a blank application through a typed V2 program. '
    'No SQL, arbitrary code or caller-supplied workspace scope is accepted.'))
register_skill_resources(server)


def _optional_secret(direct_name: str, file_name: str) -> str | None:
    if os.environ.get(direct_name) or os.environ.get(file_name):
        return configured_text(os.environ, direct_name, file_name)
    return None


def application() -> PostgresWorkspaceMCPApplication:
    if (os.environ.get('EPM_PG_PREVIEW_SECRET_HEX')
            or os.environ.get('EPM_PG_PREVIEW_SECRET_FILE')):
        reset_secret = configured_hex_bytes(
            os.environ, 'EPM_PG_PREVIEW_SECRET_HEX',
            'EPM_PG_PREVIEW_SECRET_FILE')
    else:
        reset_secret = None
    return PostgresWorkspaceMCPApplication(
        configured_text(os.environ, 'EPM_PG_LIFECYCLE_DSN',
                        'EPM_PG_LIFECYCLE_DSN_FILE'),
        os.environ.get('EPM_PG_WORKSPACE_ID', ''),
        security_dsn=_optional_secret('EPM_PG_SECURITY_DSN',
                                      'EPM_PG_SECURITY_DSN_FILE'),
        reset_secret=reset_secret,
        endpoint_inventory_json=os.environ.get(
            'EPM_RESET_ENDPOINT_INVENTORY_JSON'))


def _startup_role_check():
    application().assert_runtime_role()


def _assertion(ctx: Context) -> str:
    try:
        headers = ctx.headers or {}
    except (AttributeError, ValueError):
        headers = {}
    return access_token(headers)


def _call(operation):
    try:
        return operation()
    except (AuthError, ValueError) as error:
        raise ToolError(str(error)) from error
    except psycopg.errors.LockNotAvailable as error:
        raise ToolError(BUSY_CODE + '; no new job is implied; retry the same request key') from error
    except psycopg.Error as error:
        LOG.exception('PostgreSQL workspace operation failed')
        raise ToolError('POSTGRES_OPERATION_FAILED') from error


@bounded_tool(server)
def read_openepm_published_skill(ctx: Context, part: str = 'manifest',
                                 chunk_index: int | None = None) -> dict:
    """Read the packaged skill manifest, content or one verified chunk."""
    return read_published_skill(part, chunk_index)


@bounded_tool(server)
def list_v2_workspace_functions(ctx: Context) -> dict:
    """Discover available workspace functions for this verified administrator."""
    return _call(lambda: application().catalog(_assertion(ctx)))


@bounded_tool(server)
def execute_v2_application_purge(program: dict,ctx: Context,
                                 idempotency_key: str | None = None) -> dict:
    """Inspect, quiesce or purge exactly one application; retain workspace and identity."""
    return _call(lambda:application().application_purge(
        _assertion(ctx),program,idempotency_key=idempotency_key))


@bounded_tool(server)
def execute_v2_workspace_program(program: dict, idempotency_key: str,
                                 ctx: Context) -> dict:
    """Create one blank application with an idempotent V2 program."""
    return _call(lambda: application().create(
        _assertion(ctx), program, idempotency_key=idempotency_key))


@bounded_tool(server)
def set_v2_workspace_access(program: dict, idempotency_key: str,
                            ctx: Context) -> dict:
    """Grant or revoke one user or group Administrator through fixed core."""
    return _call(lambda: application().access(
        _assertion(ctx), program, idempotency_key=idempotency_key))


@bounded_tool(server)
def read_v2_workspace_access(program: dict, ctx: Context) -> dict:
    """Read bounded workspace group grants through the fixed security store."""
    return _call(lambda: application().read_access(_assertion(ctx), program))


@bounded_tool(server)
def prepare_v2_workspace_reset(program: dict, ctx: Context) -> dict:
    """Return a signed, owner-checked workspace target manifest; delete nothing."""
    return _call(lambda: application().prepare_reset(_assertion(ctx), program))


@bounded_tool(server)
def transition_v2_workspace_reset(program: dict, idempotency_key: str,
                                  ctx: Context) -> dict:
    """Quiesce, settle jobs or resume the bound workspace with fixed V2."""
    return _call(lambda: application().transition_reset(
        _assertion(ctx), program, idempotency_key=idempotency_key))
