#!/usr/bin/env python3
"""Loopback-only MCP listener for disposable aggregate qualification.

This is intentionally not imported by any production listener or packaged
Compose service.  It accepts no SQL and exposes only one fixed lifecycle tool.
"""
from __future__ import annotations

from hmac import compare_digest
import json
import os

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.server.mcpserver.exceptions import ToolError

from epm_core.cube_aggregate_public_qualification import (
    OPT_IN, postgres_lifecycle_measurement)
from epm_core.cube_aggregate_qualification_mcp import (
    BENCHMARK_TOOL, CANCEL_BENCHMARK_TOOL, TOOL)
from epm_core.cube_aggregate_qualification_runtime import (
    DisposableAggregateResultCleaner)
from epm_core.persistence_contract import ApplicationScope
from epm_core.postgres_access import VerifiedIdentity


server = MCPServer('Open EPM disposable aggregate qualification')


def _environment():
    if os.environ.get(OPT_IN) != '1':
        raise RuntimeError('PGDUCKDB_PUBLIC_QUALIFICATION_OPT_IN_REQUIRED')
    token = os.environ.get('EPM_PGDUCKDB_QUALIFICATION_TOKEN', '')
    secret = os.environ.get('EPM_PG_PREVIEW_SECRET_HEX', '')
    if len(token) < 32:
        raise RuntimeError('PGDUCKDB_PUBLIC_QUALIFICATION_TOKEN_INVALID')
    try:
        preview_secret = bytes.fromhex(secret)
    except ValueError as error:
        raise RuntimeError('PGDUCKDB_PUBLIC_PREVIEW_SECRET_INVALID') from error
    if len(preview_secret) < 32:
        raise RuntimeError('PGDUCKDB_PUBLIC_PREVIEW_SECRET_INVALID')
    scope = ApplicationScope(os.environ['EPM_PG_WORKSPACE_ID'],
                             os.environ['EPM_PG_APPLICATION_ID'])
    identity = VerifiedIdentity(os.environ['EPM_QUALIFICATION_ISSUER'],
                                os.environ['EPM_QUALIFICATION_SUBJECT_ID'],
                                issued_at=1)
    arguments = json.loads(os.environ['EPM_QUALIFICATION_AGGREGATE_ARGUMENTS'])
    dimensions = json.loads(os.environ['EPM_QUALIFICATION_INPUT_DIMENSIONS'])
    roles = json.loads(os.environ['EPM_QUALIFICATION_DIMENSION_ROLES'])
    dsn = os.environ['EPM_PG_RUNTIME_DSN']
    return token, dsn, preview_secret, scope, identity, arguments, dimensions, roles


def _benchmark_identity():
    try:
        value = json.loads(os.environ['EPM_QUALIFICATION_BENCHMARK_IDENTITY'])
    except (KeyError, json.JSONDecodeError) as error:
        raise RuntimeError('PGDUCKDB_BENCHMARK_IDENTITY_REQUIRED') from error
    required = {'transport', 'sourceCommit', 'schemaVersion',
        'databaseImageDigest', 'hardwareProfileDigest',
        'authorizationPolicyDigest', 'sourceCells'}
    if (type(value) is not dict or set(value) != required
            or type(value['sourceCells']) is not int
            or value['sourceCells'] <= 0):
        raise RuntimeError('PGDUCKDB_BENCHMARK_IDENTITY_INVALID')
    return value


@server.tool()
def measure_disposable_cube_aggregate_lifecycle(
        requested_backend: str, pair_id: str) -> dict:
    try:
        _, dsn, secret, scope, identity, arguments, dimensions, roles = _environment()
        cleaner = DisposableAggregateResultCleaner(
            dsn, scope=scope, identity=identity)
        cleaner.assert_disposable()
        measurement = postgres_lifecycle_measurement(
            dsn=dsn, identity=identity, preview_secret=secret, scope=scope,
            arguments=arguments, input_dimensions=dimensions,
            dimension_roles=roles, requested_backend=requested_backend,
            cleanup=cleaner)
        return measurement.run(pair_id)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ToolError(str(error)) from error


@server.tool()
def benchmark_disposable_cube_aggregate_lifecycle(
        requested_backend: str, pair_id: str) -> dict:
    try:
        _, dsn, secret, scope, identity, arguments, dimensions, roles = _environment()
        cleaner = DisposableAggregateResultCleaner(
            dsn, scope=scope, identity=identity)
        cleaner.assert_disposable()
        measurement = postgres_lifecycle_measurement(
            dsn=dsn, identity=identity, preview_secret=secret, scope=scope,
            arguments=arguments, input_dimensions=dimensions,
            dimension_roles=roles, requested_backend=requested_backend,
            cleanup=cleaner, benchmark_identity=_benchmark_identity())
        return measurement.run_benchmark(pair_id)
    except (KeyError, TypeError, ValueError, RuntimeError,
            json.JSONDecodeError) as error:
        raise ToolError(str(error)) from error


@server.tool()
def cancel_disposable_cube_aggregate_lifecycle(
        requested_backend: str, pair_id: str) -> dict:
    try:
        _, dsn, secret, scope, identity, arguments, dimensions, roles = _environment()
        cleaner = DisposableAggregateResultCleaner(
            dsn, scope=scope, identity=identity)
        cleaner.assert_disposable()
        benchmark_identity = _benchmark_identity()
        source_cells = benchmark_identity.get('sourceCells')
        measurement = postgres_lifecycle_measurement(
            dsn=dsn, identity=identity, preview_secret=secret, scope=scope,
            arguments=arguments, input_dimensions=dimensions,
            dimension_roles=roles, requested_backend=requested_backend,
            cleanup=cleaner, benchmark_identity=benchmark_identity)
        return measurement.run_cancellation_benchmark(
            pair_id, source_cells=source_cells)
    except (KeyError, TypeError, ValueError, RuntimeError,
            json.JSONDecodeError) as error:
        raise ToolError(str(error)) from error


class BearerGate:
    def __init__(self, app, token: str): self.app, self.token = app, token
    async def __call__(self, scope, receive, send):
        if scope['type'] == 'http':
            values = [value.decode('latin-1') for key, value in
                      scope.get('headers', []) if key.lower() == b'authorization']
            expected = 'Bearer ' + self.token
            if len(values) != 1 or not compare_digest(values[0], expected):
                await send({'type': 'http.response.start', 'status': 401,
                            'headers': [(b'content-type', b'application/json'),
                                        (b'cache-control', b'no-store')]})
                await send({'type': 'http.response.body',
                            'body': b'{"error":"qualification token required"}'})
                return
        await self.app(scope, receive, send)


def build_app():
    token, *_ = _environment()
    inner = server.streamable_http_app(
        host='127.0.0.1', streamable_http_path='/mcp', json_response=True,
        stateless_http=True, max_request_body_size=4096,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=['127.0.0.1:*', 'localhost:*'],
            allowed_origins=['http://127.0.0.1:*', 'http://localhost:*']))
    return BearerGate(inner, token)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(build_app(), host='127.0.0.1',
                port=int(os.environ.get('EPM_QUALIFICATION_MCP_PORT', '8765')),
                log_level='info')
