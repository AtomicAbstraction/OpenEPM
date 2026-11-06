#!/usr/bin/env python3
"""Qualify live exact spreading and allocation through public MCP only."""
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
START_DATA_REVISION = 2
START_POLICY_REVISION = 3


def validate(workspace_id: str, application_id: str,
             output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-fpna-spread-allocation-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "expectedStartingRevisions": {
            "metadata": METADATA_REVISION,
            "data": START_DATA_REVISION,
            "policy": START_POLICY_REVISION,
        },
        "operations": ["exact-spread", "conserving-allocation",
                       "locked-target-denial"],
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
            client_name="Open EPM pilot spread and allocation",
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

                async def read(function: str, arguments: dict) -> dict:
                    value = await call("read_v2_program", {
                        **scope, "program": program(function, arguments)})
                    return value["result"]

                async def source(function: str, arguments: dict) -> dict:
                    value = await call("execute_v2_source_program", {
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

                required = {
                    "facts.source.begin", "facts.source.append",
                    "facts.source.seal", "facts.source.preview",
                    "facts.source.publish", "facts.calculation.read",
                    "planning.operation.policy.save",
                    "planning.operation.policy.publish",
                    "planning.operation.policy.spread.preview",
                    "planning.operation.policy.spread.run",
                    "planning.operation.policy.allocation.preview",
                    "planning.operation.policy.allocation.run",
                    "planning.slice.lock", "planning.slice.reopen",
                }
                discovered = await call("list_v2_functions", scope)
                functions = set(discovered.get("functions", []))
                if required - functions:
                    raise RuntimeError("required planning functions missing: "
                                       + ", ".join(sorted(required-functions)))

                initial = await read("application.capabilities.read", {})
                expected = plan["expectedStartingRevisions"]
                if any(initial[name + "Revision"] != expected[name]
                       for name in ("metadata", "data", "policy")):
                    raise RuntimeError(
                        "live pilot revisions do not match the sealed dependency")
                if initial["enabledCapabilities"] != []:
                    raise RuntimeError("generic FP&A capability boundary changed")

                rows = [
                    {"members": {"Scenario": "Plan", "Year": "FY26",
                        "Period": "SpreadSource", "Department": "DeptA",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral",
                               "decimal": "10.00000001"},
                     "sourceRef": "pilot-spread-source"},
                    {"members": {"Scenario": "Plan", "Year": "FY26",
                        "Period": "P2", "Department": "Total",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral",
                               "decimal": "0.00000001"},
                     "sourceRef": "pilot-allocation-source"},
                    *[{"members": {"Scenario": "Plan", "Year": "FY26",
                            "Period": "P2", "Department": department,
                            "Account": "DriverRate"},
                       "value": {"type": "AmountLiteral", "decimal": "1"},
                       "sourceRef": "pilot-allocation-basis-" + department}
                      for department in ("DeptA", "DeptB")],
                ]
                batch = await source("facts.source.begin", {
                    "idempotencyKey": "pilot-spread-allocation-source-v1",
                    "mode": "merge", "scopeMembers": {}, "scopeAll": True,
                    "expectedMetadataRevision": METADATA_REVISION,
                    "expectedDataRevision": START_DATA_REVISION,
                })
                chunk = await source("facts.source.append", {
                    "batchId": batch["batchId"], "chunkIndex": 0,
                    "rows": rows})
                await source("facts.source.seal", {
                    "batchId": batch["batchId"], "expectedRows": len(rows),
                    "expectedContentDigest": chunk["contentDigest"]})
                preview = await source("facts.source.preview", {
                    "batchId": batch["batchId"]})
                published = await source("facts.source.publish", {
                    "batchId": batch["batchId"],
                    "previewToken": preview["previewToken"]})

                spread_definition = {
                    "format": FORMAT, "policyId": "pilot.spread",
                    "version": 1, "kind": "Spread",
                    "effectiveFrom": "2026-01-01",
                    "effectiveBefore": "2027-01-01",
                    "metadataRevision": METADATA_REVISION,
                    "policyRevision": START_POLICY_REVISION,
                    "parameters": {}, "definition": {
                        "sourceMembers": {"kind": "Members", "memberIds": [
                            "Plan", "FY26", "SpreadSource", "DeptA", "Sales"]},
                        "targetDimension": "Period",
                        "targetMembers": {"kind": "Members",
                                          "memberIds": ["P1", "P2"]},
                        "calendarPolicy": "selection_order",
                        "totalPreservation": "exact",
                        "roundingPolicy": "largestRemainderStableMember",
                    },
                }
                spread_saved = await policy(
                    "planning.operation.policy.save",
                    {"definition": spread_definition})
                await policy("planning.operation.policy.publish", {
                    "policyId": "pilot.spread", "version": 1,
                    "expectedPointerVersion": 0,
                }, "pilot-spread-publish-v1")
                spread_arguments = {
                    "policyId": "pilot.spread", "effectiveOn": "2026-10-31",
                    "bindings": {}, "source": {
                        "Scenario": "Plan", "Year": "FY26",
                        "Period": "SpreadSource", "Department": "DeptA",
                        "Account": "Sales"},
                    "resultKey": "pilot.spread.result",
                }
                spread_preview = await policy(
                    "planning.operation.policy.spread.preview",
                    spread_arguments)
                if (spread_preview["sourceAmount"] != "10.00000001"
                        or spread_preview["targetCount"] != 2
                        or spread_preview["conservesSourceTotal"] is not True):
                    raise RuntimeError("spread preview is not exact")
                spread_program = {**spread_arguments,
                    "previewToken": spread_preview["previewToken"]}
                spread_accepted = await policy(
                    "planning.operation.policy.spread.run", spread_program,
                    "pilot-spread-run-v1")
                await wait_published(spread_accepted["jobId"])
                spread_replay = await policy(
                    "planning.operation.policy.spread.run", spread_program,
                    "pilot-spread-run-v1")
                spread_result = await read("facts.calculation.read", {
                    "resultKey": "pilot.spread.result"})
                spread_amounts = {row["members"]["Period"]: row["amount"]
                                  for row in spread_result["rows"]}
                if (spread_amounts != {"P1": "5.00000001",
                                       "P2": "5.00000000"}
                        or sum(Decimal(value) for value in spread_amounts.values())
                        != Decimal("10.00000001")
                        or spread_replay.get("duplicate") is not True
                        or spread_replay.get("jobId")
                        != spread_accepted["jobId"]):
                    raise RuntimeError("spread output or replay is not exact")

                allocation_definition = {
                    "format": FORMAT, "policyId": "pilot.allocation",
                    "version": 1, "kind": "Allocation",
                    "effectiveFrom": "2026-01-01",
                    "effectiveBefore": "2027-01-01",
                    "metadataRevision": METADATA_REVISION,
                    "policyRevision": START_POLICY_REVISION + 1,
                    "parameters": {}, "definition": {
                        "sourceMembers": {"kind": "Members", "memberIds": [
                            "Plan", "FY26", "P2", "Total", "Sales"]},
                        "basisMembers": {"kind": "Members", "memberIds": [
                            "Plan", "FY26", "P2", "Total", "DriverRate"]},
                        "targetDimension": "Department",
                        "targetMembers": {"kind": "Members",
                                          "memberIds": ["DeptA", "DeptB"]},
                        "lockedTargetPolicy": "reject",
                        "conservationScope": "sourceCoordinate",
                        "remainderPolicy": "largestRemainderStableMember",
                    },
                }
                allocation_saved = await policy(
                    "planning.operation.policy.save",
                    {"definition": allocation_definition})
                await policy("planning.operation.policy.publish", {
                    "policyId": "pilot.allocation", "version": 1,
                    "expectedPointerVersion": 0,
                }, "pilot-allocation-publish-v1")
                allocation_arguments = {
                    "policyId": "pilot.allocation",
                    "effectiveOn": "2026-10-31", "bindings": {},
                    "source": {"Scenario": "Plan", "Year": "FY26",
                        "Period": "P2", "Department": "Total",
                        "Account": "Sales"},
                    "basisTemplate": {"Scenario": "Plan", "Year": "FY26",
                        "Period": "P2", "Department": "Total",
                        "Account": "DriverRate"},
                    "resultKey": "pilot.allocation.result",
                }
                allocation_preview = await policy(
                    "planning.operation.policy.allocation.preview",
                    allocation_arguments)
                if (allocation_preview["sourceAmount"] != "0.00000001"
                        or allocation_preview["totalBasis"] != "2.00000000"
                        or allocation_preview["targetCount"] != 2):
                    raise RuntimeError("allocation preview is not exact")
                allocation_program = {**allocation_arguments,
                    "previewToken": allocation_preview["previewToken"]}
                allocation_accepted = await policy(
                    "planning.operation.policy.allocation.run",
                    allocation_program, "pilot-allocation-run-v1")
                await wait_published(allocation_accepted["jobId"])
                allocation_replay = await policy(
                    "planning.operation.policy.allocation.run",
                    allocation_program, "pilot-allocation-run-v1")
                allocation_result = await read("facts.calculation.read", {
                    "resultKey": "pilot.allocation.result"})
                allocation_amounts = {
                    row["members"]["Department"]: row["amount"]
                    for row in allocation_result["rows"]}
                if (allocation_amounts != {"DeptA": "0.00000001",
                                           "DeptB": "0.00000000"}
                        or sum(Decimal(value)
                               for value in allocation_amounts.values())
                        != Decimal("0.00000001")
                        or allocation_replay.get("duplicate") is not True
                        or allocation_replay.get("jobId")
                        != allocation_accepted["jobId"]):
                    raise RuntimeError("allocation output or replay is not exact")
                if not all(row["source_change_id"]
                           and row["basis"]["changeId"]
                           for row in allocation_result["rows"]):
                    raise RuntimeError("allocation lineage is incomplete")

                lock_program = program("planning.slice.lock", {
                    "scopeMembers": {"Department": "DeptA",
                                     "Account": "Sales"},
                    "scopeAll": False,
                    "reason": "Pilot allocation locked-target validation",
                    "idempotencyKey": "pilot-allocation-lock-v1",
                })
                lock_preview = await call("preview_v2_program", {
                    **scope, "program": lock_program})
                locked = await call("apply_v2_planning_transition", {
                    **scope, "program": lock_program,
                    "preview_token": lock_preview["previewToken"]})
                denied = await session.call_tool(
                    "execute_v2_planning_operation_policy", {
                        **scope, "program": program(
                            "planning.operation.policy.allocation.preview", {
                                **allocation_arguments,
                                "resultKey": "pilot.allocation.locked"})})
                call_count += 1
                if (not denied.is_error
                        or "PLANNING_SLICE_LOCKED" not in str(denied.content)):
                    raise RuntimeError("locked allocation target was not denied")
                reopen_program = program("planning.slice.reopen", {
                    "lockId": locked["lockId"], "expectedLockVersion": 1,
                    "reason": "Pilot allocation target validation complete",
                    "idempotencyKey": "pilot-allocation-reopen-v1",
                })
                reopen_preview = await call("preview_v2_program", {
                    **scope, "program": reopen_program})
                reopened = await call("apply_v2_planning_transition", {
                    **scope, "program": reopen_program,
                    "preview_token": reopen_preview["previewToken"]})
                if reopened.get("status") != "Open":
                    raise RuntimeError("locked allocation target did not reopen")

                final = await read("application.capabilities.read", {})

    return {
        **plan,
        "format": "openepm-macos-pilot-fpna-spread-allocation-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed", "serverName": initialized.server_info.name,
        "source": {"batchId": batch["batchId"],
                   "receiptId": published.get("receiptId"),
                   "rowCount": len(rows)},
        "spread": {"policyDigest": spread_saved["canonicalDigest"],
                   "jobId": spread_accepted["jobId"],
                   "amounts": spread_amounts,
                   "exactTotal": "10.00000001",
                   "stableReplay": True},
        "allocation": {
            "policyDigest": allocation_saved["canonicalDigest"],
            "jobId": allocation_accepted["jobId"],
            "amounts": allocation_amounts,
            "exactTotal": "0.00000001", "completeLineage": True,
            "stableReplay": True, "lockedTargetDenied": True,
            "targetReopened": True,
        },
        "finalRevisions": {
            "metadata": final["metadataRevision"],
            "data": final["dataRevision"],
            "policy": final["policyRevision"],
            "commit": final["commitRevision"],
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
