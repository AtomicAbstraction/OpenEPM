#!/usr/bin/env python3
"""Qualify an exact historical business-request retry through public MCP."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys

import httpx2
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.qualify_macos_pilot_fpna_foundation import program, response
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback)


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
REVISION_KEYS = (
    "metadataRevision", "dataRevision", "policyRevision", "schemaEpoch",
    "commitRevision")
FUNCTION = "metadata.dimension.create"
IDEMPOTENCY_KEY = "pilot-fpna-dimension-scenario"
HISTORICAL_PROGRAM = program(FUNCTION, {
    "dimensionId": "Scenario",
    "name": "Scenario",
    "modelRole": "Scenario",
    "expectedMetadataRevision": 0,
})


def validate(workspace_id: str, application_id: str,
             output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-idempotent-retry-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "function": FUNCTION,
        "idempotencyKey": IDEMPOTENCY_KEY,
        "historicalExpectedMetadataRevision": 0,
        "output": str(output),
        "publicMcpOnly": True,
        "databaseAccess": False,
        "newBusinessEffectExpected": False,
    }


def revisions(value: dict) -> dict[str, object]:
    return {key: value[key] for key in REVISION_KEYS}


def validate_replay(first: dict, second: dict, before: dict,
                    after: dict) -> None:
    if first != second:
        raise RuntimeError("same historical request returned different results")
    if revisions(before) != revisions(after):
        raise RuntimeError("same historical request changed current revisions")
    result = first.get("result")
    if (not isinstance(result, dict)
            or result.get("operationId") != IDEMPOTENCY_KEY
            or result.get("committedRevision") != 1
            or result.get("changedCount") != 1):
        raise RuntimeError("historical Scenario receipt is invalid")


async def execute(plan: dict[str, object]) -> dict[str, object]:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot idempotent-retry qualification",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"),
        storage, redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    scope = {"workspace_id": plan["workspaceId"],
             "application_id": plan["applicationId"]}
    call_count = 0

    async with httpx2.AsyncClient(
            auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                ENDPOINTS["application"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()

                async def call(tool: str, arguments: dict) -> dict:
                    nonlocal call_count
                    call_count += 1
                    return response(await session.call_tool(tool, arguments))

                async def read_capabilities() -> dict:
                    value = await call("read_v2_program", {
                        **scope,
                        "program": program("application.capabilities.read", {})})
                    return value["result"]

                before = await read_capabilities()
                arguments = {
                    **scope,
                    "program": HISTORICAL_PROGRAM,
                    "idempotency_key": IDEMPOTENCY_KEY,
                }
                first = await call("execute_v2_metadata_program", arguments)
                second = await call("execute_v2_metadata_program", arguments)
                after = await read_capabilities()
                validate_replay(first, second, before, after)

    return {
        **plan,
        "format": "openepm-macos-pilot-idempotent-retry-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "firstReplay": first,
        "secondReplayIdentical": True,
        "businessRevisionsBefore": revisions(before),
        "businessRevisionsAfter": revisions(after),
        "currentMetadataRevisionWasBeyondHistoricalExpectation": (
            before["metadataRevision"] > 0),
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "newBusinessEffectPerformed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(
            arguments.workspace_id, arguments.application_id, arguments.output)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(json.dumps({"passed": True, "output": str(arguments.output)},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
