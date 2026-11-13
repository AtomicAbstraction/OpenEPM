#!/usr/bin/env python3
"""Qualify one live read-only aggregate across a packaged worker restart."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import re
import subprocess
import sys
import time

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
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\s]{1,80}Z$")
WORKER = "openepm-macos-pilot-worker-1"
DIMENSIONS = ["Scenario", "Year", "Period", "Department", "Account"]


def validate(workspace_id: str, application_id: str,
             output: Path, *, resume_query_id: str | None = None,
             worker_started_before: str | None = None) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    if (resume_query_id is None) != (worker_started_before is None):
        raise ValueError("resume query and prior worker start must be paired")
    if (resume_query_id is not None
            and IDENTIFIER.fullmatch(resume_query_id) is None):
        raise ValueError("resume query ID is invalid")
    if (worker_started_before is not None
            and TIMESTAMP.fullmatch(worker_started_before) is None):
        raise ValueError("prior worker start timestamp is invalid")
    return {
        "format": "openepm-macos-pilot-aggregate-worker-restart-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "publicMcpOnlyForProductOperations": True,
        "databaseAccess": False,
        "workerContainer": WORKER,
        "businessMutationExpected": False,
        "resumeQueryId": resume_query_id,
        "workerStartedAtBefore": worker_started_before,
        "output": str(output),
    }


def docker(*arguments: str) -> str:
    completed = subprocess.run(
        ["docker", *arguments], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise RuntimeError("docker command failed: " + completed.stderr.strip())
    return completed.stdout.strip()


def inspect(format_value: str) -> str:
    return docker("inspect", "--format", format_value, WORKER)


def wait_worker_healthy() -> None:
    for _ in range(100):
        try:
            if inspect("{{.State.Health.Status}}") == "healthy":
                return
        except RuntimeError:
            pass
        time.sleep(.2)
    raise RuntimeError("worker did not become healthy after restart")


def expected_rows(raw_rows: list[dict]) -> list[dict[str, object]]:
    totals: dict[tuple[str, str, str, str], Decimal] = {}
    counts: dict[tuple[str, str, str, str], int] = {}
    for row in raw_rows:
        key = tuple(row["members"][axis] for axis in (
            "Scenario", "Year", "Period", "Account"))
        totals[key] = totals.get(key, Decimal(0)) + Decimal(
            row["amount"])
        counts[key] = counts.get(key, 0) + 1
    return [{
        "members": dict(zip(
            ("Scenario", "Year", "Period", "Account"), key,
            strict=True)),
        "sumAmount": format(totals[key], ".8f"),
        "countPresent": str(counts[key]),
    } for key in sorted(totals)]


async def execute(plan: dict[str, object]) -> dict[str, object]:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot aggregate restart qualification",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"),
        storage, redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    scope = {"workspace_id": plan["workspaceId"],
             "application_id": plan["applicationId"]}
    call_count = 0
    worker_paused = False

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

                discovered = await call("list_v2_functions", scope)
                required = {
                    "application.capabilities.read", "facts.cube.scan",
                    "facts.cube.aggregate.request",
                    "facts.cube.aggregate.read",
                }
                missing = required - set(discovered.get("functions", []))
                if missing:
                    raise RuntimeError(
                        "required functions missing: "
                        + ", ".join(sorted(missing)))
                before = await read("application.capabilities.read", {})
                if (before["metadataRevision"] != 34
                        or before["dataRevision"] != 6
                        or before["policyRevision"] != 10
                        or before["schemaEpoch"] != 5
                        or before["commitRevision"] != 55):
                    raise RuntimeError("live pilot dependency changed")
                raw = await read("facts.cube.scan", {
                    "members": {"Account": "Sales"}, "limit": 500})
                expected = expected_rows(raw["rows"])
                if not expected:
                    raise RuntimeError("aggregate source selection is empty")

                query = {
                    "source": "raw_numeric",
                    "grain": {
                        "inputDimensions": DIMENSIONS,
                        "groupBy": [
                            "Scenario", "Year", "Period", "Account"],
                        "reduceDimensions": ["Department"],
                    },
                    "selectors": {
                        "Account": {"kind": "Members",
                                    "memberIds": ["Sales"]},
                    },
                    "measures": [
                        {"kind": "SumAmount"},
                        {"kind": "CountPresent"},
                    ],
                    "missing": "exclude",
                    "aggregation": "unique_coordinate_sum",
                }
                resume_query_id = plan.get("resumeQueryId")
                if resume_query_id is None:
                    started_before = inspect("{{.State.StartedAt}}")
                    try:
                        docker("pause", WORKER)
                        worker_paused = True
                        if inspect("{{.State.Paused}}") != "true":
                            raise RuntimeError("worker pause was not observed")
                        requested = await read(
                            "facts.cube.aggregate.request", {
                                "query": query,
                                "limits": {"pageSize": 100,
                                           "ttlSeconds": 900},
                            })
                        if requested.get("status") != "ready":
                            raise RuntimeError(
                                "aggregate was not durably ready before restart")
                        docker("restart", WORKER)
                        worker_paused = False
                        wait_worker_healthy()
                    finally:
                        if worker_paused:
                            try:
                                docker("unpause", WORKER)
                            finally:
                                worker_paused = False
                            if (inspect("{{.State.Health.Status}}")
                                    != "healthy"):
                                docker("restart", WORKER)
                                wait_worker_healthy()
                else:
                    started_before = str(plan["workerStartedAtBefore"])
                    requested = {"queryId": resume_query_id,
                                 "status": "ready"}
                started_after = inspect("{{.State.StartedAt}}")
                if started_after == started_before:
                    raise RuntimeError("worker start identity did not change")

                sealed = None
                for _ in range(200):
                    sealed = await read("facts.cube.aggregate.read", {
                        "queryId": requested["queryId"], "pageSize": 100})
                    if sealed["status"] == "sealed":
                        break
                    if sealed["status"] in {
                            "failed", "cancelled", "expired"}:
                        raise RuntimeError(
                            "aggregate failed after restart: " + repr(sealed))
                    await asyncio.sleep(.2)
                else:
                    raise RuntimeError(
                        "aggregate did not seal after worker restart")
                if any(row.get("emptyScalar", False) is not False
                       for row in sealed["rows"]):
                    raise RuntimeError("nonempty grouped result shape changed")
                actual = sorted([{
                    "members": row["members"],
                    "sumAmount": row["sumAmount"],
                    "countPresent": row["countPresent"],
                } for row in sealed["rows"]],
                                key=lambda row: tuple(
                                    row["members"][axis] for axis in (
                                        "Scenario", "Year", "Period",
                                        "Account")))
                if actual != expected:
                    raise RuntimeError("aggregate result is not exact")
                replay = await read("facts.cube.aggregate.read", {
                    "queryId": requested["queryId"], "pageSize": 100})
                if replay != sealed:
                    raise RuntimeError("aggregate read replay changed")
                after = await read("application.capabilities.read", {})
                if ({key: after[key] for key in (
                        "metadataRevision", "dataRevision", "policyRevision",
                        "schemaEpoch", "commitRevision")}
                        != {key: before[key] for key in (
                            "metadataRevision", "dataRevision",
                            "policyRevision", "schemaEpoch",
                            "commitRevision")}):
                    raise RuntimeError(
                        "technical aggregate changed business revisions")

    return {
        **plan,
        "format": "openepm-macos-pilot-aggregate-worker-restart-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "queryId": requested["queryId"],
        "acceptedWhileWorkerPaused": True,
        "acceptedStatus": requested["status"],
        "workerStartedAtBefore": started_before,
        "workerStartedAtAfter": started_after,
        "workerRestartObserved": True,
        "resumedAfterVerifierMismatch": resume_query_id is not None,
        "sealedAfterRestart": True,
        "stableReplay": True,
        "rows": actual,
        "sourceRowCount": len(raw["rows"]),
        "technicalCertificate": sealed.get("technicalCertificate"),
        "businessRevisionsBefore": {
            "metadata": before["metadataRevision"],
            "data": before["dataRevision"],
            "policy": before["policyRevision"],
            "schemaEpoch": before["schemaEpoch"],
            "commit": before["commitRevision"],
        },
        "businessRevisionsAfter": {
            "metadata": after["metadataRevision"],
            "data": after["dataRevision"],
            "policy": after["policyRevision"],
            "schemaEpoch": after["schemaEpoch"],
            "commit": after["commitRevision"],
        },
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "businessMutationPerformed": False,
        "hostControl": "bounded restart of exact packaged worker container",
        "operatorDiagnosticUsedToLocateSealedQuery": (
            resume_query_id is not None),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--resume-query-id")
    parser.add_argument("--worker-started-before")
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(
            arguments.workspace_id, arguments.application_id,
            arguments.output, resume_query_id=arguments.resume_query_id,
            worker_started_before=arguments.worker_started_before)
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
