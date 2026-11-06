#!/usr/bin/env python3
"""Qualify concurrent same-key delivery through public MCP."""
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


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
REVISION_KEYS = (
    "metadataRevision", "dataRevision", "policyRevision", "schemaEpoch",
    "commitRevision")


def validate(workspace_id: str, application_id: str, idempotency_key: str,
             output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if (IDENTIFIER.fullmatch(idempotency_key) is None
            or not 8 <= len(idempotency_key) <= 128):
        raise ValueError("idempotency key is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-concurrent-retry-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "idempotencyKey": idempotency_key,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "businessMutationExpected": False,
        "temporaryTechnicalBatchExpected": True,
        "cleanupRequired": True,
        "output": str(output),
    }


def revisions(value: dict) -> dict[str, object]:
    return {key: value[key] for key in REVISION_KEYS}


def validate_concurrent(results: list[dict]) -> str:
    if len(results) != 2:
        raise RuntimeError("exactly two concurrent results are required")
    batch_ids = {item.get("batchId") for item in results}
    duplicate_markers = sorted(item.get("duplicate") for item in results)
    if (len(batch_ids) != 1 or None in batch_ids
            or duplicate_markers != [False, True]
            or any(item.get("status") != "staging" for item in results)):
        raise RuntimeError("concurrent delivery did not resolve to one batch")
    return next(iter(batch_ids))


async def execute(plan: dict[str, object]) -> dict[str, object]:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot concurrent-retry qualification",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"),
        storage, redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    scope = {"workspace_id": plan["workspaceId"],
             "application_id": plan["applicationId"]}
    call_count = 0
    batch_id = None
    cleanup = None

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

                async def capabilities() -> dict:
                    value = await call("read_v2_program", {
                        **scope,
                        "program": program("application.capabilities.read", {})})
                    return value["result"]

                before = await capabilities()
                begin = program("facts.source.begin", {
                    "idempotencyKey": plan["idempotencyKey"],
                    "mode": "merge", "scopeMembers": {}, "scopeAll": True,
                    "expectedMetadataRevision": before["metadataRevision"],
                    "expectedDataRevision": before["dataRevision"],
                })
                request = {**scope, "program": begin}
                try:
                    raw_results = await asyncio.gather(
                        call("execute_v2_source_program", request),
                        call("execute_v2_source_program", request))
                    results = [value["result"] for value in raw_results]
                    batch_id = validate_concurrent(results)
                    task_id = "b:" + batch_id
                    running = await call("read_v2_task", {
                        **scope, "task_id": task_id,
                        "after_event": 0, "event_limit": 100})
                    if (running["sourceFamily"] != "SourceBatch"
                            or running["status"] != "Running"
                            or not running["interruptible"]):
                        raise RuntimeError("temporary source task is invalid")
                    cleanup = await call("interrupt_v2_task", {
                        **scope, "task_id": task_id})
                    if (cleanup["status"] != "Interrupted"
                            or cleanup["committedEffectsRemain"] is not False):
                        raise RuntimeError("temporary batch cleanup failed")
                    terminal = await call("read_v2_task", {
                        **scope, "task_id": task_id,
                        "after_event": 0, "event_limit": 100})
                    if terminal["status"] != "Interrupted":
                        raise RuntimeError("cancelled source task is not terminal")
                    replay = (await call("execute_v2_source_program", request))[
                        "result"]
                    if (replay.get("batchId") != batch_id
                            or replay.get("status") != "cancelled"
                            or replay.get("duplicate") is not True):
                        raise RuntimeError("cancelled batch replay changed identity")
                    after = await capabilities()
                    if revisions(after) != revisions(before):
                        raise RuntimeError(
                            "concurrent technical retry changed business revisions")
                finally:
                    if batch_id is not None and cleanup is None:
                        try:
                            cleanup = await call("interrupt_v2_task", {
                                **scope, "task_id": "b:" + batch_id})
                        except Exception:
                            pass

    return {
        **plan,
        "format": "openepm-macos-pilot-concurrent-retry-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "concurrentResults": results,
        "oneBatchId": batch_id,
        "taskBeforeCleanup": running,
        "cleanup": cleanup,
        "taskAfterCleanup": terminal,
        "replayAfterCleanup": replay,
        "businessRevisionsBefore": revisions(before),
        "businessRevisionsAfter": revisions(after),
        "committedEffectsRemain": False,
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "businessMutationPerformed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(
            arguments.workspace_id, arguments.application_id,
            arguments.idempotency_key, arguments.output)
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
