#!/usr/bin/env python3
"""Qualify one live calculated-result request across exact retries."""
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
RESULT_KEY = "pilot.driver.retry.result"
IDEMPOTENCY_KEY = "pilot-driver-retry-qualification-v1"
REVISION_KEYS = (
    "metadataRevision", "dataRevision", "policyRevision", "schemaEpoch",
    "commitRevision")


def validate(workspace_id: str, application_id: str,
             output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-calculation-retry-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "resultKey": RESULT_KEY,
        "idempotencyKey": IDEMPOTENCY_KEY,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "rawFactMutationExpected": False,
        "oneCalculatedPublicationExpected": True,
        "output": str(output),
    }


def revisions(value: dict) -> dict[str, object]:
    return {key: value[key] for key in REVISION_KEYS}


def validate_replays(first: dict, inflight: dict, published: dict) -> None:
    job_id = first.get("jobId")
    if (not isinstance(job_id, str) or len(job_id) != 32
            or first.get("duplicate") is not False):
        raise RuntimeError("initial calculation admission is invalid")
    for phase, value in (("in-flight", inflight), ("published", published)):
        if value.get("jobId") != job_id or value.get("duplicate") is not True:
            raise RuntimeError(phase + " calculation retry was not idempotent")


async def execute(plan: dict[str, object]) -> dict[str, object]:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot calculation-retry qualification",
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

                async def policy(function: str, arguments: dict,
                                 key: str | None = None) -> dict:
                    request = {**scope,
                        "program": program(function, arguments)}
                    if key is not None:
                        request["idempotency_key"] = key
                    value = await call(
                        "execute_v2_planning_operation_policy", request)
                    return value["result"]

                before = await read("application.capabilities.read", {})
                common = {"Scenario": "Plan", "Year": "FY26",
                          "Period": "P1", "Department": "DeptA"}
                arguments = {
                    "policyId": "pilot.driver",
                    "effectiveOn": "2026-10-31", "bindings": {},
                    "inputMemberMappings": {
                        "Amount": {**common, "Account": "DriverAmount"},
                        "Rate": {**common, "Account": "DriverRate"}},
                    "outputMemberMapping": {"Account": "DriverOutput"},
                    "activeGrain": ["Account", "Department", "Period",
                                    "Scenario", "Year"],
                    "measureDimensionId": "Account",
                    "resultKey": RESULT_KEY,
                }
                preview = await policy(
                    "planning.operation.policy.driver.preview", arguments)
                run_program = {**arguments,
                               "previewToken": preview["previewToken"]}
                first = await policy(
                    "planning.operation.policy.driver.run", run_program,
                    IDEMPOTENCY_KEY)
                inflight = await policy(
                    "planning.operation.policy.driver.run", run_program,
                    IDEMPOTENCY_KEY)
                job = None
                for _ in range(200):
                    job = await call("read_v2_job", {
                        **scope, "job_id": first["jobId"]})
                    if job.get("status") == "published":
                        break
                    if job.get("status") in {
                            "failed", "cancelled", "needs_inspection"}:
                        raise RuntimeError(
                            "calculation retry job failed: " + repr(job))
                    await asyncio.sleep(.2)
                else:
                    raise RuntimeError("calculation retry job did not publish")
                after_publication = await read(
                    "application.capabilities.read", {})
                published = await policy(
                    "planning.operation.policy.driver.run", run_program,
                    IDEMPOTENCY_KEY)
                after_replay = await read("application.capabilities.read", {})
                validate_replays(first, inflight, published)
                if revisions(after_replay) != revisions(after_publication):
                    raise RuntimeError("post-publication retry changed revisions")
                calculated = await read("facts.calculation.read", {
                    "resultKey": RESULT_KEY})
                if (len(calculated["rows"]) != 1
                        or calculated["rows"][0]["amount"] != "10.00000000"
                        or calculated["rows"][0]["members"] != {
                            **common, "Account": "DriverOutput"}):
                    raise RuntimeError("calculation retry result is not exact")
                raw = await read("facts.cube.scan", {
                    "members": {**common, "Account": "DriverOutput"},
                    "limit": 10})
                if raw["rows"]:
                    raise RuntimeError("calculation retry created a raw fact")

    return {
        **plan,
        "format": "openepm-macos-pilot-calculation-retry-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "previewPlanDigest": preview.get("planDigest"),
        "firstAdmission": first,
        "inflightReplay": inflight,
        "publishedReplay": published,
        "job": job,
        "calculatedResult": calculated,
        "rawTargetRows": raw["rows"],
        "businessRevisionsBefore": revisions(before),
        "businessRevisionsAfterPublication": revisions(after_publication),
        "businessRevisionsAfterReplay": revisions(after_replay),
        "oneJobAcrossRetries": True,
        "postPublicationReplayChangedRevisions": False,
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
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
