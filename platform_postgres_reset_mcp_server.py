"""Dedicated owner-credential MCP boundary for exact V2 workspace reset."""
from __future__ import annotations

import logging
import os

from mcp.server import MCPServer
from epm_core.postgres_mcp_execution import bounded_tool
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
import psycopg
from epm_core.postgres_processing_limits import BUSY_CODE

from epm_core.postgres_access import VerifiedIdentity
from epm_core.postgres_auth import AuthError, access_token
from epm_core.postgres_verified_principal import principal_claims
from epm_core.postgres_workspace_reset_apply import PostgresWorkspaceResetApply
from epm_core.published_skill_delivery import (
    bootstrap_instructions, read_published_skill, register_skill_resources,
)


LOG = logging.getLogger(__name__)
server = MCPServer('Open EPM PostgreSQL V2 Reset Apply', instructions=bootstrap_instructions(
    'Dedicated exact-workspace reset endpoint. Only a verified platform '
    'operator who is also workspace Administrator may apply a fresh signed '
    'maintenance manifest. This endpoint must run only after deployment '
    'replacement and endpoint-retirement checks.'))
register_skill_resources(server)


def application(assertion: str) -> PostgresWorkspaceResetApply:
    principal = principal_claims(assertion, 'mcp')
    secret_hex = os.environ.get('EPM_PG_PREVIEW_SECRET_HEX', '')
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError as error:
        raise ValueError('RESET_SECRET_INVALID') from error
    return PostgresWorkspaceResetApply(
        os.environ.get('EPM_POSTGRES_ADMIN_DSN', ''),
        identity=VerifiedIdentity(principal['issuer'], principal['subject'],
                                  principal.get('groups', ()),
                                  issued_at=principal['issuedAt']),
        secret=secret,
        endpoint_inventory_json=os.environ.get(
            'EPM_RESET_ENDPOINT_INVENTORY_JSON'),
        replacement_ready=os.environ.get(
            'EPM_RESET_REPLACEMENT_READY') == '1',
        endpoints_retired=os.environ.get(
            'EPM_RESET_ENDPOINTS_RETIRED') == '1')


def _startup_role_check():
    try:
        secret = bytes.fromhex(os.environ.get('EPM_PG_PREVIEW_SECRET_HEX', ''))
    except ValueError as error:
        raise RuntimeError('RESET_SECRET_INVALID') from error
    PostgresWorkspaceResetApply(
        os.environ.get('EPM_POSTGRES_ADMIN_DSN', ''),
        identity=VerifiedIdentity('startup-check', 'reset-listener'),
        secret=secret, endpoint_inventory_json=os.environ.get(
            'EPM_RESET_ENDPOINT_INVENTORY_JSON')).assert_owner_role()


def _assertion(ctx: Context) -> str:
    try:
        headers = ctx.headers or {}
    except (AttributeError, ValueError):
        headers = {}
    return access_token(headers)


@bounded_tool(server)
def read_openepm_published_skill(ctx: Context, part: str = 'manifest',
                                 chunk_index: int | None = None) -> dict:
    """Read the packaged skill manifest, content or one verified chunk."""
    return read_published_skill(part, chunk_index)


@bounded_tool(server)
def apply_v2_workspace_reset(program: dict, idempotency_key: str,
                             ctx: Context) -> dict:
    """Apply one owner-checked signed reset for the fixed workspace."""
    try:
        return application(_assertion(ctx)).apply(
            os.environ.get('EPM_PG_WORKSPACE_ID', ''), program,
            idempotency_key=idempotency_key)
    except (AuthError, ValueError) as error:
        raise ToolError(str(error)) from error
    except psycopg.errors.LockNotAvailable as error:
        raise ToolError(BUSY_CODE + '; no new job is implied; retry the same request key') from error
    except psycopg.Error as error:
        LOG.exception('PostgreSQL workspace reset apply failed')
        raise ToolError('POSTGRES_RESET_OPERATION_FAILED') from error
