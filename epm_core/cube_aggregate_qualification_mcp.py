"""Opt-in MCP client for paired aggregate qualification measurements.

The remote listener is a qualification-only deployment backed by disposable
PostgreSQL resources.  Requested backend selection is sent only to that
listener; the production MCP contract has no such argument.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import json
import os

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .cube_aggregate_acceleration import ACCELERATED, NATIVE
from .cube_aggregate_public_qualification import OPT_IN
from .cube_aggregate_qualification import PairedPublicAggregateQualification


TOOL = 'measure_disposable_cube_aggregate_lifecycle'
BENCHMARK_TOOL = 'benchmark_disposable_cube_aggregate_lifecycle'
CANCEL_BENCHMARK_TOOL = 'cancel_disposable_cube_aggregate_lifecycle'


def _response(value) -> dict:
    if value.is_error:
        raise RuntimeError(f'PGDUCKDB_PUBLIC_MCP_TOOL_FAILED: {value.content}')
    result = value.structured_content
    if result is None and value.content:
        result = json.loads(value.content[0].text)
    if type(result) is not dict:
        raise ValueError('PGDUCKDB_PUBLIC_MCP_RESPONSE_INVALID')
    return result


class QualificationMcpTransport:
    def __init__(self, url: str, bearer_token: str, *, timeout: float = 120):
        if (os.environ.get(OPT_IN) != '1' or type(url) is not str
                or not url.startswith(('http://127.0.0.1:',
                                       'http://localhost:'))
                or type(bearer_token) is not str or len(bearer_token) < 32
                or type(timeout) not in (int, float) or timeout <= 0):
            raise ValueError('PGDUCKDB_PUBLIC_MCP_TRANSPORT_DISABLED')
        self.url, self.bearer_token, self.timeout = url, bearer_token, timeout

    @asynccontextmanager
    async def session(self):
        async with httpx.AsyncClient(
                headers={'Authorization': 'Bearer ' + self.bearer_token},
                timeout=self.timeout) as http:
            async with streamable_http_client(self.url,
                                               http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as client:
                    await client.initialize()
                    yield client

    async def measure(self, requested_backend: str, pair_id: str) -> dict:
        async with self.session() as client:
            return _response(await client.call_tool(TOOL, {
                'requested_backend': requested_backend, 'pair_id': pair_id}))

    async def benchmark(self, requested_backend: str, pair_id: str) -> dict:
        async with self.session() as client:
            return _response(await client.call_tool(BENCHMARK_TOOL, {
                'requested_backend': requested_backend, 'pair_id': pair_id}))

    async def cancel_benchmark(self, requested_backend: str, pair_id: str) -> dict:
        async with self.session() as client:
            return _response(await client.call_tool(CANCEL_BENCHMARK_TOOL, {
                'requested_backend': requested_backend, 'pair_id': pair_id}))


class BenchmarkMcpObservationExecutor:
    """Bind strict matrix cases to the qualification MCP and host sampler."""
    def __init__(self, transport: QualificationMcpTransport, *,
                 resource_sampler, identity: dict):
        if (not isinstance(transport, QualificationMcpTransport)
                or not hasattr(resource_sampler, 'measure')
                or type(identity) is not dict):
            raise ValueError('PGDUCKDB_BENCHMARK_EXECUTOR_INVALID')
        self.transport = transport
        self.resource_sampler = resource_sampler
        self.identity = dict(identity)

    async def execute(self, case: dict) -> dict:
        if type(case) is not dict or not {'requestedBackend', 'pairId'} <= set(case):
            raise ValueError('PGDUCKDB_BENCHMARK_CASE_INVALID')
        response, resources = await self.resource_sampler.measure(lambda:
            self.transport.benchmark(case['requestedBackend'], case['pairId']))
        benchmark = response.get('benchmark') if type(response) is dict else None
        if (type(benchmark) is not dict or type(resources) is not dict
                or response.get('selectedBackend') != case['requestedBackend']):
            raise ValueError('PGDUCKDB_BENCHMARK_OBSERVATION_UNAVAILABLE')
        expected_identity = {key: self.identity[key] for key in (
            'transport', 'sourceCommit', 'schemaVersion', 'databaseImageDigest',
            'hardwareProfileDigest', 'authorizationPolicyDigest')}
        if any(benchmark.get(key) != value for key, value in expected_identity.items()):
            raise ValueError('PGDUCKDB_BENCHMARK_IDENTITY_MISMATCH')
        plan_text = benchmark.get('explainPlan')
        if type(plan_text) is not str or not plan_text:
            raise ValueError('PGDUCKDB_BENCHMARK_EXPLAIN_UNAVAILABLE')
        return {**expected_identity,
            'selectedBackend': response['selectedBackend'],
            'requestDigest': benchmark.get('requestDigest'),
            'planDigest': benchmark.get('planDigest'),
            'sourcePinsDigest': benchmark.get('sourcePinsDigest'),
            'resultDigest': benchmark.get('resultDigest'),
            'timings': benchmark.get('timings'),
            'explain': {'actual': True,
                'planDigest': __import__('hashlib').sha256(
                    plan_text.encode('utf-8')).hexdigest(),
                'backendMarker': benchmark.get('backendMarker'),
                'planText': plan_text}, 'resources': resources}

    async def cancellation(self, requested_backend: str, pair_id: str,
                           source_pins_digest: str) -> dict:
        if (requested_backend not in (NATIVE, ACCELERATED)
                or type(pair_id) is not str or not pair_id
                or type(source_pins_digest) is not str
                or len(source_pins_digest) != 64):
            raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_INVALID')
        response, _ = await self.resource_sampler.measure(lambda:
            self.transport.cancel_benchmark(requested_backend, pair_id))
        expected_marker = ('DuckDBScan' if requested_backend == ACCELERATED
                           else 'PostgreSQL')
        if (type(response) is not dict
                or response.get('selectedBackend') != requested_backend
                or response.get('backendMarker') != expected_marker
                or response.get('ownedBySubject') is not True
                or response.get('terminalStatus') != 'cancelled'
                or response.get('partialResultVisible') is not False):
            raise ValueError('PGDUCKDB_BENCHMARK_CANCELLATION_FAILED')
        return {'requestedBackend': requested_backend, 'ownedBySubject': True,
            'terminalStatus': 'cancelled', 'partialResultVisible': False,
            'sourcePinsDigest': source_pins_digest,
            'sourceCells': response.get('sourceCells')}


async def record_paired_over_mcp(*, profile: dict, controls: dict,
                                 transport: QualificationMcpTransport,
                                 pairs: int = 5, clock=None) -> dict:
    """Record paired full-MCP timings using one session per lifecycle."""
    if not isinstance(transport, QualificationMcpTransport):
        raise ValueError('PGDUCKDB_PUBLIC_MCP_TRANSPORT_INVALID')

    # The recorder is synchronous by design, so collect each network operation
    # here and replay only its measured envelope through its validation logic.
    responses = []
    for index in range(pairs):
        pair_id = f'pair-{index:03d}'
        order = (NATIVE, ACCELERATED) if index % 2 == 0 \
            else (ACCELERATED, NATIVE)
        for requested in order:
            before = (clock or __import__('time').perf_counter)()
            response = await transport.measure(requested, pair_id)
            after = (clock or __import__('time').perf_counter)()
            responses.append((requested, pair_id, response, before, after))

    iterator = iter(responses)
    ticks = iter([tick for item in responses for tick in item[3:5]])
    def run(requested, pair_id):
        actual_requested, actual_pair, response, _, _ = next(iterator)
        if (actual_requested, actual_pair) != (requested, pair_id):
            raise ValueError('PGDUCKDB_PUBLIC_MCP_ORDER_INVALID')
        return response
    return PairedPublicAggregateQualification(profile=profile,
        controls=controls, run=run, clock=lambda: next(ticks)).record(pairs=pairs)
