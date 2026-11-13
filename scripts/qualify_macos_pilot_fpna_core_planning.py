#!/usr/bin/env python3
"""Qualify live scenario seed, driver and rollup through public MCP only."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
from decimal import Decimal
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

from epm_core.planning_operation_policy import FORMAT
from scripts.qualify_macos_pilot_fpna_foundation import program, response
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback)


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
METADATA_REVISION = 34


def validate(workspace_id: str, application_id: str,
             output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-fpna-core-planning-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "expectedMetadataRevision": METADATA_REVISION,
        "operations": ["scenario-seed", "typed-driver", "hierarchy-rollup"],
        "output": str(output),
    }


async def execute(plan: dict[str, object]) -> dict[str, object]:
    server_url = ENDPOINTS["application"]
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        server_url,
        OAuthClientMetadata(
            client_name="Open EPM pilot core planning",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"),
        storage, redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    scope = {"workspace_id": plan["workspaceId"],
             "application_id": plan["applicationId"]}
    call_count = 0

    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                server_url, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()

                async def call(tool: str, arguments: dict) -> dict:
                    nonlocal call_count
                    call_count += 1
                    return response(await session.call_tool(tool, arguments))

                async def optional(tool: str, arguments: dict) -> dict | None:
                    nonlocal call_count
                    call_count += 1
                    value = await session.call_tool(tool, arguments)
                    return None if value.is_error else response(value)

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

                async def wait_published(job_id: str) -> dict:
                    state = None
                    for _ in range(100):
                        state = await call("read_v2_job", {
                            **scope, "job_id": job_id})
                        if state.get("status") == "published":
                            return state
                        if state.get("status") in {
                                "failed", "cancelled", "needs_inspection"}:
                            raise RuntimeError(
                                "pilot planning job failed: " + repr(state))
                        await asyncio.sleep(.2)
                    raise RuntimeError(
                        "pilot planning job did not publish: " + repr(state))

                discovered = await call("list_v2_functions", scope)
                functions = set(discovered.get("functions", []))
                required = {
                    "planning.operation.policy.save",
                    "planning.operation.policy.activate",
                    "planning.operation.policy.seed.preview",
                    "planning.operation.policy.seed.run",
                    "planning.operation.policy.driver.preview",
                    "planning.operation.policy.driver.run",
                    "planning.operation.policy.rollup.preview",
                    "planning.operation.policy.rollup.run",
                    "facts.calculation.read", "facts.export.page",
                }
                if required - functions:
                    raise RuntimeError("required planning functions missing: "
                                       + ", ".join(sorted(required-functions)))

                state = await read("application.capabilities.read", {})
                if state["metadataRevision"] != METADATA_REVISION:
                    raise RuntimeError("unexpected live metadata revision")
                if state["enabledCapabilities"] != []:
                    raise RuntimeError("generic FP&A capability boundary changed")

                seed_definition = {
                    "format": FORMAT, "policyId": "pilot.seed",
                    "kind": "Seed", "effectiveFrom": "2026-01-01",
                    "effectiveBefore": "2027-01-01",
                    "metadataRevision": METADATA_REVISION,
                    "policyRevision": 0, "parameters": {},
                    "definition": {
                        "scenarioDimension": "Scenario",
                        "sourceMember": "Actual", "targetMember": "Plan",
                        "filterMembers": {}, "mode": "replace",
                        "provenancePolicy": "copy_source_lineage",
                    },
                }
                seed_saved = await policy(
                    "planning.operation.policy.save",
                    {"definition": seed_definition}, "pilot-seed-save")
                await policy("planning.operation.policy.activate", {
                    "policyId": "pilot.seed",
                    "expectedStateToken": seed_saved["stateToken"],
                    "canonicalDigest": seed_saved["canonicalDigest"],
                }, "pilot-seed-activate")

                plan_page = await read(
                    "facts.export.page", {"members": {"Scenario": "Plan"}})
                seed_replayed = False
                if not (len(plan_page["rows"]) == 6 and all(
                        row["members"]["Account"] != "Extra"
                        for row in plan_page["rows"])):
                    seed_arguments = {
                        "policyId": "pilot.seed",
                        "effectiveOn": "2026-10-31", "bindings": {},
                    }
                    seed_preview = await policy(
                        "planning.operation.policy.seed.preview", seed_arguments)
                    if (seed_preview["sourceRowCount"] != 6
                            or seed_preview["mode"] != "replace"
                            or seed_preview["provenancePolicy"]
                            != "copy_source_lineage"):
                        raise RuntimeError("seed preview is not exact")
                    seed_program = {**seed_arguments,
                                    "previewToken": seed_preview["previewToken"]}
                    seeded = await policy(
                        "planning.operation.policy.seed.run", seed_program,
                        "pilot-seed-run-v1")
                    seed_replay = await policy(
                        "planning.operation.policy.seed.run", seed_program,
                        "pilot-seed-run-v1")
                    if (seed_replay.get("duplicate") is not True
                            or seed_replay.get("batchId") != seeded.get("batchId")):
                        raise RuntimeError("seed replay is not stable")
                    seed_replayed = True
                    plan_page = await read(
                        "facts.export.page", {"members": {"Scenario": "Plan"}})
                if (len(plan_page["rows"]) != 6 or any(
                        row["members"]["Account"] == "Extra"
                        for row in plan_page["rows"])
                        or sorted(row["value"]["type"]
                                  for row in plan_page["rows"]) != [
                            "AmountLiteral", "AmountLiteral", "AmountLiteral",
                            "AmountLiteral", "LineDetailLiteral", "TextLiteral"]):
                    raise RuntimeError("seed output is incomplete")

                common = {"Scenario": "Plan", "Year": "FY26",
                          "Period": "P1", "Department": "DeptA"}
                driver_definition = {
                    "format": FORMAT, "policyId": "pilot.driver",
                    "kind": "Driver", "effectiveFrom": "2026-01-01",
                    "effectiveBefore": "2027-01-01",
                    "metadataRevision": METADATA_REVISION,
                    "policyRevision": 1, "parameters": {},
                    "definition": {
                        "calculationKind": "MultiplyAmountByRatio",
                        "inputs": [
                            {"name": "Amount", "members": {
                                "kind": "Members", "memberIds": [
                                    "Plan", "FY26", "P1", "DeptA",
                                    "DriverAmount"]}, "unit": "Amount",
                             "grain": ["Account", "Department", "Period",
                                       "Scenario", "Year"]},
                            {"name": "Rate", "members": {
                                "kind": "Members", "memberIds": [
                                    "Plan", "FY26", "P1", "DeptA",
                                    "DriverRate"]}, "unit": "Ratio",
                             "grain": ["Account", "Department", "Period",
                                       "Scenario", "Year"]},
                        ],
                        "output": {"members": {"kind": "Members",
                            "memberIds": ["DriverOutput"]}, "unit": "Amount",
                            "grain": ["Account", "Department", "Period",
                                      "Scenario", "Year"]},
                        "dependencies": [],
                    },
                }
                driver_saved = await policy(
                    "planning.operation.policy.save",
                    {"definition": driver_definition}, "pilot-driver-save")
                await policy("planning.operation.policy.activate", {
                    "policyId": "pilot.driver",
                    "expectedStateToken": driver_saved["stateToken"],
                    "canonicalDigest": driver_saved["canonicalDigest"],
                }, "pilot-driver-activate")
                driver_read = await optional("read_v2_program", {
                    **scope, "program": program("facts.calculation.read", {
                        "resultKey": "pilot.driver.result"})})
                driver_job_id = None
                driver_replayed = False
                if driver_read is None:
                    driver_arguments = {
                        "policyId": "pilot.driver",
                        "effectiveOn": "2026-10-31", "bindings": {},
                        "inputMemberMappings": {
                            "Amount": {**common, "Account": "DriverAmount"},
                            "Rate": {**common, "Account": "DriverRate"}},
                        "outputMemberMapping": {"Account": "DriverOutput"},
                        "activeGrain": ["Account", "Department", "Period",
                                        "Scenario", "Year"],
                        "measureDimensionId": "Account",
                        "resultKey": "pilot.driver.result",
                    }
                    driver_preview = await policy(
                        "planning.operation.policy.driver.preview",
                        driver_arguments)
                    if (driver_preview["driverPolicy"]["policyDigest"]
                            != driver_saved["canonicalDigest"]):
                        raise RuntimeError("driver policy digest changed")
                    driver_program = {**driver_arguments,
                        "previewToken": driver_preview["previewToken"]}
                    driver_accepted = await policy(
                        "planning.operation.policy.driver.run", driver_program,
                        "pilot-driver-run-v1")
                    driver_job_id = driver_accepted["jobId"]
                    await wait_published(driver_job_id)
                    replay = await policy(
                        "planning.operation.policy.driver.run", driver_program,
                        "pilot-driver-run-v1")
                    if (replay.get("duplicate") is not True
                            or replay.get("jobId") != driver_job_id):
                        raise RuntimeError("driver replay is not stable")
                    driver_replayed = True
                    driver_read = await call("read_v2_program", {
                        **scope, "program": program("facts.calculation.read", {
                            "resultKey": "pilot.driver.result"})})
                driver_result = driver_read["result"]
                if (len(driver_result["rows"]) != 1
                        or driver_result["rows"][0]["amount"] != "10.00000000"
                        or driver_result["rows"][0]["members"] != {
                            **common, "Account": "DriverOutput"}):
                    raise RuntimeError("driver output is not exact")

                rollup_definition = {
                    "format": FORMAT, "policyId": "pilot.rollup",
                    "kind": "Rollup", "effectiveFrom": "2026-01-01",
                    "effectiveBefore": "2027-01-01",
                    "metadataRevision": METADATA_REVISION,
                    "policyRevision": 2, "parameters": {},
                    "definition": {"dimension": "Department",
                        "parent": "Total", "slice": {"kind": "Members",
                            "memberIds": ["Plan", "FY26", "P1", "Sales"]},
                        "sharedMemberPolicy": "unique_member",
                        "placementIds": []},
                }
                rollup_saved = await policy(
                    "planning.operation.policy.save",
                    {"definition": rollup_definition}, "pilot-rollup-save")
                await policy("planning.operation.policy.activate", {
                    "policyId": "pilot.rollup",
                    "expectedStateToken": rollup_saved["stateToken"],
                    "canonicalDigest": rollup_saved["canonicalDigest"],
                }, "pilot-rollup-activate")
                rollup_read = await optional("read_v2_program", {
                    **scope, "program": program("facts.calculation.read", {
                        "resultKey": "pilot.rollup.result"})})
                rollup_job_id = None
                rollup_replayed = False
                if rollup_read is None:
                    rollup_arguments = {
                        "policyId": "pilot.rollup",
                        "effectiveOn": "2026-10-31", "bindings": {},
                        "otherMembers": {"Scenario": "Plan", "Year": "FY26",
                            "Period": "P1", "Account": "Sales"},
                        "resultKey": "pilot.rollup.result",
                    }
                    rollup_preview = await policy(
                        "planning.operation.policy.rollup.preview",
                        rollup_arguments)
                    if (rollup_preview["amount"] != "300.00000000"
                            or rollup_preview["sourceCount"] != 2
                            or rollup_preview["reusablePolicy"]["policyDigest"]
                            != rollup_saved["canonicalDigest"]):
                        raise RuntimeError("rollup preview is not exact")
                    rollup_program = {**rollup_arguments,
                        "previewToken": rollup_preview["previewToken"]}
                    rollup_accepted = await policy(
                        "planning.operation.policy.rollup.run", rollup_program,
                        "pilot-rollup-run-v1")
                    rollup_job_id = rollup_accepted["jobId"]
                    await wait_published(rollup_job_id)
                    replay = await policy(
                        "planning.operation.policy.rollup.run", rollup_program,
                        "pilot-rollup-run-v1")
                    if (replay.get("duplicate") is not True
                            or replay.get("jobId") != rollup_job_id):
                        raise RuntimeError("rollup replay is not stable")
                    rollup_replayed = True
                    rollup_read = await call("read_v2_program", {
                        **scope, "program": program("facts.calculation.read", {
                            "resultKey": "pilot.rollup.result"})})
                rollup_result = rollup_read["result"]
                if (len(rollup_result["rows"]) != 1
                        or rollup_result["rows"][0]["amount"] != "300.00000000"
                        or rollup_result["rows"][0]["members"] != {
                            "Scenario": "Plan", "Year": "FY26",
                            "Period": "P1", "Department": "Total",
                            "Account": "Sales"}):
                    raise RuntimeError("rollup output is not exact")
                sources = rollup_result["rows"][0]["rollupSources"]
                if [(item["members"]["Department"], item["amount"])
                        for item in sources] != [
                            ("DeptA", "100.00000000"),
                            ("DeptB", "200.00000000")]:
                    raise RuntimeError("rollup lineage is incomplete")

                final_state = await read("application.capabilities.read", {})

    return {
        **plan,
        "format": "openepm-macos-pilot-fpna-core-planning-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed", "serverName": initialized.server_info.name,
        "seed": {"policyDigest": seed_saved["canonicalDigest"],
                 "exactMixedTypeReplace": True,
                 "extraTargetCleared": True,
                 "replayedDuringRun": seed_replayed},
        "driver": {"policyDigest": driver_saved["canonicalDigest"],
                   "jobId": driver_job_id,
                   "exactAmount": "10.00000000",
                   "typedFullGrain": True,
                   "replayedDuringRun": driver_replayed},
        "rollup": {"policyDigest": rollup_saved["canonicalDigest"],
                   "jobId": rollup_job_id,
                   "exactAmount": "300.00000000",
                   "completeLineage": True,
                   "replayedDuringRun": rollup_replayed},
        "finalRevisions": {
            "metadata": final_state["metadataRevision"],
            "data": final_state["dataRevision"],
            "policy": final_state["policyRevision"],
            "commit": final_state["commitRevision"],
        },
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "identityValueRetained": False,
        "businessMutationPerformed": True,
        "mutationBoundary": "authorized fixed-core public application MCP",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(arguments.workspace_id, arguments.application_id,
                        arguments.output)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "workspaceId": result["workspaceId"],
                      "applicationId": result["applicationId"],
                      "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
