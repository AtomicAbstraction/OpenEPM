"""Minimal internal HTTP transport for capability-bound builder reads."""
from __future__ import annotations

import asyncio
import json

from .persistence_contract import ApplicationScope
from .python_build_capability import (CONTEXT_READ, SOURCE_READ,
                                      PythonBuildReadBroker)

MAX_REQUEST = 8192
MAX_RESPONSE = 2 * 1024 * 1024
REQUEST_BODY_TIMEOUT_SECONDS = 5.0
MAX_CONCURRENT_REQUESTS = 32


class PythonBuildBrokerASGI:
    """One internal POST route; deliberately not an MCP/business dispatcher."""

    def __init__(self, broker: PythonBuildReadBroker):
        if not isinstance(broker, PythonBuildReadBroker):
            raise ValueError("PYTHON_BUILD_BROKER_CONFIGURATION_INVALID")
        self.broker = broker
        self._slots = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    async def __call__(self, scope, receive, send):
        if (scope.get('type') != 'http' or scope.get('method') != 'POST'
                or scope.get('path') != '/internal/python-build/read'):
            await self._respond(send, 404, {'error': 'NOT_FOUND'})
            return
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=0.1)
        except TimeoutError:
            await self._respond(send, 503, {'error': 'BROKER_CAPACITY_EXCEEDED'})
            return
        try:
            await self._read(scope, receive, send)
        finally:
            self._slots.release()

    async def _read(self, scope, receive, send):
        body = bytearray()
        deadline = asyncio.get_running_loop().time() + REQUEST_BODY_TIMEOUT_SECONDS
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await self._respond(send, 408, {'error': 'REQUEST_TIMEOUT'})
                return
            try:
                event = await asyncio.wait_for(receive(), timeout=remaining)
            except TimeoutError:
                await self._respond(send, 408, {'error': 'REQUEST_TIMEOUT'})
                return
            if event.get('type') != 'http.request':
                await self._respond(send, 400, {'error': 'INVALID_REQUEST'})
                return
            body.extend(event.get('body', b''))
            if len(body) > MAX_REQUEST:
                await self._respond(send, 413, {'error': 'REQUEST_TOO_LARGE'})
                return
            if not event.get('more_body', False):
                break
        try:
            value = json.loads(body)
            from openepm.metadata_references import BOOTSTRAP_CONTRACT_DIGEST
            if type(value) is dict and value.get('authoringContractDigest') != BOOTSTRAP_CONTRACT_DIGEST:
                await self._respond(send, 409, {'error': 'PYTHON_BUILD_AUTHORING_CONTRACT_UNSUPPORTED'})
                return
            required = {'workspaceId', 'applicationId', 'buildId',
                        'claimGeneration', 'action', 'capabilityToken', 'authoringContractDigest'}
            if (type(value) is not dict or set(value) != required
                    or value['action'] not in (SOURCE_READ, CONTEXT_READ)
                    or type(value['claimGeneration']) is not int
                    or value['claimGeneration'] < 1):
                raise ValueError
            application_scope = ApplicationScope(value['workspaceId'],
                                                 value['applicationId'])
            result = self.broker.read(value['capabilityToken'],
                scope=application_scope, build_id=value['buildId'],
                action=value['action'],
                claim_generation=value['claimGeneration'])
            await self._respond(send, 200, result)
        except Exception:
            # Do not disclose which identity, grant, program or claim failed.
            await self._respond(send, 403, {'error': 'CAPABILITY_DENIED'})

    @staticmethod
    async def _respond(send, status: int, value: dict):
        body = json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True).encode('ascii')
        if len(body) > MAX_RESPONSE:
            status, body = 500, b'{"error":"RESPONSE_TOO_LARGE"}'
        await send({'type': 'http.response.start', 'status': status,
                    'headers': [(b'content-type', b'application/json'),
                                (b'cache-control', b'no-store'),
                                (b'x-content-type-options', b'nosniff')]})
        await send({'type': 'http.response.body', 'body': body})
