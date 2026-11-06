#!/usr/bin/env python3
"""Qualify a representative universal-task rerun through public MCP."""
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

from scripts.qualify_macos_pilot_aggregate_worker_restart import expected_rows
from scripts.qualify_macos_pilot_fpna_foundation import program, response
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback)


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
QUERY_ID = re.compile(r"^[0-9a-f]{32}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
TERMINAL = frozenset(("Succeeded", "Failed", "Interrupted"))
REVISION_KEYS = (
    "metadataRevision", "dataRevision", "policyRevision", "schemaEpoch",
    "commitRevision")


def validate(workspace_id: str, application_id: str, query_id: str,
             idempotency_key: str, output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if QUERY_ID.fullmatch(query_id) is None:
        raise ValueError("query ID is invalid")
    if IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        raise ValueError("idempotency key is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-universal-task-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "sourceQueryId": query_id,
        "sourceTaskId": "c:" + query_id,
        "idempotencyKey": idempotency_key,
        "output": str(output),
        "publicMcpOnly": True,
        "databaseAccess": False,
        "businessMutationExpected": False,
    }


def task_from_page(page: dict, task_id: str) -> dict:
    matches = [task for task in page.get("tasks", [])
               if task.get("taskId") == task_id]
    if len(matches) != 1:
        raise RuntimeError("source task is not uniquely visible")
    return matches[0]


def revision_projection(value: dict) -> dict[str, object]:
    return {key: value[key] for key in REVISION_KEYS}


async def execute(plan: dict[str, object]) -> dict[str, object]:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot universal-task qualification",
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

                async def read(function: str, arguments: dict) -> dict:
                    value = await call("read_v2_program", {
                        **scope, "program": program(function, arguments)})
                    return value["result"]

                tools = {tool.name for tool in (await session.list_tools()).tools}
                required = {
                    "list_v2_tasks", "read_v2_task", "read_v2_task_logs",
                    "rerun_v2_task", "read_v2_program"}
                missing = required - tools
                if missing:
                    raise RuntimeError(
                        "required tools missing: " + ", ".join(sorted(missing)))

                before = await read("application.capabilities.read", {})
                raw = await read("facts.cube.scan", {
                    "members": {"Account": "Sales"}, "limit": 500})
                expected = expected_rows(raw["rows"])
                if not expected:
                    raise RuntimeError("aggregate source selection is empty")

                page = await call("list_v2_tasks", {
                    **scope, "after_sequence": 0, "limit": 500})
                source_summary = task_from_page(page, str(plan["sourceTaskId"]))
                source = await call("read_v2_task", {
                    **scope, "task_id": plan["sourceTaskId"],
                    "after_event": 0, "event_limit": 100})
                if (source_summary["sourceFamily"] != "CubeAggregate"
                        or source["sourceFamily"] != "CubeAggregate"
                        or source["status"] not in TERMINAL
                        or not source["rerunSupported"]):
                    raise RuntimeError("source aggregate task is not rerunnable")
                source_logs = await call("read_v2_task_logs", {
                    **scope, "task_id": plan["sourceTaskId"],
                    "after_event": 0, "event_limit": 100,
                    "after_character": 0, "character_limit": 1024})
                if source_logs["taskId"] != plan["sourceTaskId"]:
                    raise RuntimeError("bounded task logs changed task identity")

                rerun = await call("rerun_v2_task", {
                    **scope, "task_id": plan["sourceTaskId"],
                    "idempotency_key": plan["idempotencyKey"]})
                replay = await call("rerun_v2_task", {
                    **scope, "task_id": plan["sourceTaskId"],
                    "idempotency_key": plan["idempotencyKey"]})
                if replay != rerun:
                    raise RuntimeError("same-key task rerun was not idempotent")
                if (rerun["sourceTaskId"] != plan["sourceTaskId"]
                        or rerun["taskId"] == plan["sourceTaskId"]
                        or not str(rerun["taskId"]).startswith("c:")):
                    raise RuntimeError("rerun did not create distinct aggregate work")

                rerun_task = None
                for _ in range(300):
                    rerun_task = await call("read_v2_task", {
                        **scope, "task_id": rerun["taskId"],
                        "after_event": 0, "event_limit": 100})
                    if rerun_task["status"] in TERMINAL:
                        break
                    await asyncio.sleep(.2)
                else:
                    raise RuntimeError("rerun task did not reach a terminal state")
                if rerun_task["status"] != "Succeeded":
                    raise RuntimeError("rerun task did not succeed")

                result = await read("facts.cube.aggregate.read", {
                    "queryId": rerun["taskId"][2:], "pageSize": 100})
                if result["status"] != "sealed":
                    raise RuntimeError("rerun aggregate did not seal")
                actual = sorted([{
                    "members": row["members"],
                    "sumAmount": row["sumAmount"],
                    "countPresent": row["countPresent"],
                } for row in result["rows"]], key=lambda row: tuple(
                    row["members"][axis] for axis in (
                        "Scenario", "Year", "Period", "Account")))
                if actual != expected:
                    raise RuntimeError("rerun aggregate result is not exact")
                rerun_logs = await call("read_v2_task_logs", {
                    **scope, "task_id": rerun["taskId"],
                    "after_event": 0, "event_limit": 100,
                    "after_character": 0, "character_limit": 1024})
                after = await read("application.capabilities.read", {})
                if revision_projection(after) != revision_projection(before):
                    raise RuntimeError("technical task rerun changed business revisions")

    return {
        **plan,
        "format": "openepm-macos-pilot-universal-task-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "sourceTask": source,
        "sourceLogPage": source_logs,
        "rerun": rerun,
        "sameKeyReplay": True,
        "rerunTask": rerun_task,
        "rerunLogPage": rerun_logs,
        "resultRows": actual,
        "sourceRowCount": len(raw["rows"]),
        "businessRevisionsBefore": revision_projection(before),
        "businessRevisionsAfter": revision_projection(after),
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "businessMutationPerformed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--query-id", required=True)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(
            arguments.workspace_id, arguments.application_id,
            arguments.query_id, arguments.idempotency_key, arguments.output)
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
