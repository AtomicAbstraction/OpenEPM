#!/usr/bin/env python3
"""Build the live Mac pilot's generic FP&A foundation through public MCP."""
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

from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback)
from epm_core.postgres_capability_contract import (
    CONSOLIDATION_FUNCTIONS, DISABLED_SAFE_FUNCTIONS)


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
REQUIRED_FUNCTIONS = frozenset({
    "metadata.dimension.create", "metadata.member.create",
    "metadata.member.numeric-kind.set", "metadata.relationship.create",
    "metadata.calendar.period.set", "metadata.hierarchy.build",
    "facts.source.begin", "facts.source.append", "facts.source.seal",
    "facts.source.preview", "facts.source.publish", "facts.export.page",
})


def active_specialized_functions(functions: set[str]) -> set[str]:
    """Return capability-gated operations that can create new financial work."""
    return functions.intersection(CONSOLIDATION_FUNCTIONS).difference(
        DISABLED_SAFE_FUNCTIONS)


def program(function: str, arguments: dict[str, object]) -> dict[str, object]:
    return {"languageVersion": 2, "function": function,
            "arguments": arguments}


def validate(workspace_id: str, application_id: str,
             output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-fpna-foundation-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "consolidationExpectedDisabled": True,
        "dimensions": ["Scenario", "Year", "Period", "Department", "Account"],
        "sourceValueTypes": ["AmountLiteral", "TextLiteral",
                             "LineDetailLiteral"],
        "output": str(output),
    }


def response(value) -> dict[str, object]:
    if value.is_error:
        raise RuntimeError("MCP tool failed: " + repr(value.content))
    result = value.structured_content
    if result is None:
        if not value.content or not hasattr(value.content[0], "text"):
            raise RuntimeError("MCP tool returned no structured result")
        result = json.loads(value.content[0].text)
    if not isinstance(result, dict):
        raise RuntimeError("MCP tool returned an invalid result")
    return result


async def execute(plan: dict[str, object]) -> dict[str, object]:
    server_url = ENDPOINTS["application"]
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        server_url,
        OAuthClientMetadata(
            client_name="Open EPM pilot FP&A foundation",
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

                async def call(tool: str, arguments: dict[str, object]) -> dict:
                    nonlocal call_count
                    call_count += 1
                    return response(await session.call_tool(tool, arguments))

                discovered = await call("list_v2_functions", scope)
                functions = set(discovered.get("functions", []))
                missing = REQUIRED_FUNCTIONS - functions
                if missing:
                    raise RuntimeError("required FP&A functions missing: "
                                       + ", ".join(sorted(missing)))
                active_specialized = active_specialized_functions(functions)
                if active_specialized:
                    raise RuntimeError(
                        "active consolidation functions are exposed in generic FP&A: "
                        + ", ".join(sorted(active_specialized)))
                safe_historical = sorted(
                    functions.intersection(DISABLED_SAFE_FUNCTIONS))

                revision = 0
                metadata_results: list[dict] = []

                async def metadata(function: str, arguments: dict,
                                   key: str) -> dict:
                    nonlocal revision
                    result = await call("execute_v2_metadata_program", {
                        **scope,
                        "program": program(function, {
                            **arguments,
                            "expectedMetadataRevision": revision,
                        }),
                        "idempotency_key": key,
                    })
                    metadata_results.append(result)
                    revision += 1
                    return result["result"]

                for dimension, role in (
                        ("Scenario", "Scenario"), ("Year", "Year"),
                        ("Period", "Period"), ("Department", "Custom"),
                        ("Account", "Account")):
                    await metadata("metadata.dimension.create", {
                        "dimensionId": dimension, "name": dimension,
                        "modelRole": role,
                    }, "pilot-fpna-dimension-" + dimension.lower())

                members = (
                    ("Scenario", "Actual"), ("Scenario", "Plan"),
                    ("Scenario", "Rolling"), ("Year", "FY26"),
                    ("Year", "FY27"), ("Period", "P1"),
                    ("Period", "P2"), ("Period", "P3"),
                    ("Period", "P4"), ("Period", "SpreadSource"),
                    ("Department", "Total"), ("Department", "DeptA"),
                    ("Department", "DeptB"), ("Account", "Sales"),
                    ("Account", "Comment"), ("Account", "Detail"),
                    ("Account", "Extra"), ("Account", "DriverAmount"),
                    ("Account", "DriverRate"),
                    ("Account", "DriverOutput"),
                )
                for dimension, member in members:
                    await metadata("metadata.member.create", {
                        "dimensionId": dimension, "memberId": member,
                        "name": member,
                    }, "pilot-fpna-member-" + dimension.lower() + "-"
                        + member.lower())

                for member, kind in (("DriverAmount", "amount"),
                                     ("DriverRate", "ratio"),
                                     ("DriverOutput", "amount")):
                    await metadata("metadata.member.numeric-kind.set", {
                        "dimensionId": "Account", "memberId": member,
                        "numericValueKind": kind,
                    }, "pilot-fpna-numeric-kind-" + member.lower())

                for relationship_id, child in (("dept-a", "DeptA"),
                                                ("dept-b", "DeptB")):
                    await metadata("metadata.relationship.create", {
                        "dimensionId": "Department",
                        "relationshipId": relationship_id,
                        "parentMemberId": "Total", "childMemberId": child,
                    }, "pilot-fpna-relationship-" + relationship_id)

                calendar_changes = []
                for year, period, ordinal, start, end in (
                        ("FY26", "P1", 1, "2026-01-01", "2026-02-01"),
                        ("FY26", "P2", 2, "2026-02-01", "2026-03-15"),
                        ("FY26", "P3", 3, "2026-03-15", "2026-12-20"),
                        ("FY27", "P4", 4, "2026-12-20", "2027-02-10")):
                    result = await call("execute_v2_calendar_program", {
                        **scope,
                        "program": program("metadata.calendar.period.set", {
                            "yearId": year, "periodId": period,
                            "ordinal": ordinal, "startsOn": start,
                            "endsBefore": end, "expectedChangeId": "",
                            "expectedMetadataRevision": revision,
                        }),
                        "idempotency_key": "pilot-fpna-calendar-" + period.lower(),
                    })
                    calendar_changes.append(result["result"]["changeId"])
                    revision += 1

                hierarchy_response = await call(
                    "execute_v2_metadata_program", {
                        **scope,
                        "program": program("metadata.hierarchy.build", {
                            "dimensionId": "Department",
                            "expectedMetadataRevision": revision,
                        }),
                        "idempotency_key": "pilot-fpna-department-hierarchy",
                    })
                hierarchy = hierarchy_response["result"]
                if hierarchy.get("version") != 1 \
                        or hierarchy.get("closureCount") != 5:
                    raise RuntimeError("department hierarchy result is invalid")

                common = {"Scenario": "Actual", "Year": "FY26",
                          "Period": "P1", "Department": "DeptA"}
                rows = [
                    {"members": {**common, "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "100"},
                     "sourceRef": "pilot-number-a"},
                    {"members": {**common, "Department": "DeptB",
                                  "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "200"},
                     "sourceRef": "pilot-number-b"},
                    {"members": {**common, "Account": "Comment"},
                     "value": {"type": "TextLiteral", "text": "baseline"},
                     "sourceRef": "pilot-text"},
                    {"members": {**common, "Account": "Detail"},
                     "value": {"type": "LineDetailLiteral", "items": [
                         {"description": "base", "decimal": "60"},
                         {"description": "adjustment", "decimal": "40"},
                     ]}, "sourceRef": "pilot-detail"},
                    {"members": {**common, "Scenario": "Plan",
                                  "Account": "Extra"},
                     "value": {"type": "AmountLiteral", "decimal": "9"},
                     "sourceRef": "pilot-replace-target"},
                    {"members": {**common, "Account": "DriverAmount"},
                     "value": {"type": "AmountLiteral", "decimal": "80"},
                     "sourceRef": "pilot-driver-amount"},
                    {"members": {**common, "Account": "DriverRate"},
                     "value": {"type": "AmountLiteral", "decimal": "0.125"},
                     "sourceRef": "pilot-driver-rate"},
                ]

                async def source(function: str, arguments: dict) -> dict:
                    result = await call("execute_v2_source_program", {
                        **scope, "program": program(function, arguments)})
                    return result["result"]

                batch = await source("facts.source.begin", {
                    "idempotencyKey": "pilot-fpna-foundation-source-v1",
                    "mode": "merge", "scopeMembers": {}, "scopeAll": True,
                    "expectedMetadataRevision": revision,
                    "expectedDataRevision": 0,
                })
                chunk = await source("facts.source.append", {
                    "batchId": batch["batchId"], "chunkIndex": 0,
                    "rows": rows,
                })
                await source("facts.source.seal", {
                    "batchId": batch["batchId"], "expectedRows": len(rows),
                    "expectedContentDigest": chunk["contentDigest"],
                })
                preview = await source("facts.source.preview", {
                    "batchId": batch["batchId"]})
                published = await source("facts.source.publish", {
                    "batchId": batch["batchId"],
                    "previewToken": preview["previewToken"],
                })
                page = (await call("read_v2_program", {
                    **scope,
                    "program": program("facts.export.page", {
                        "members": {"Scenario": "Actual"}}),
                }))["result"]
                types = sorted(row["value"]["type"] for row in page["rows"])
                if types != ["AmountLiteral"] * 4 + [
                        "LineDetailLiteral", "TextLiteral"]:
                    raise RuntimeError("exact mixed source export is incomplete")
                detail = next(row for row in page["rows"]
                              if row["value"]["type"] == "LineDetailLiteral")
                detail_values = {
                    item["description"]: Decimal(item["decimal"])
                    for item in detail["value"]["items"]}
                if detail_values != {"base": Decimal("60"),
                                     "adjustment": Decimal("40")}:
                    raise RuntimeError("supporting detail did not round-trip exactly")

                replay = await call("execute_v2_metadata_program", {
                    **scope,
                    "program": program("metadata.dimension.create", {
                        "dimensionId": "Scenario", "name": "Scenario",
                        "modelRole": "Scenario",
                        "expectedMetadataRevision": 0,
                    }),
                    "idempotency_key": "pilot-fpna-dimension-scenario",
                })
                if replay != metadata_results[0]:
                    raise RuntimeError("metadata idempotency replay changed result")

    return {
        **plan,
        "format": "openepm-macos-pilot-fpna-foundation-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "functionCount": len(functions),
        "activeConsolidationFunctionsHidden": True,
        "historicalSafeConsolidationFunctions": safe_historical,
        "metadataRevision": revision,
        "dimensionsCreated": 5,
        "membersCreated": len(members),
        "calendarPeriodsCreated": len(calendar_changes),
        "departmentHierarchyVersion": hierarchy["version"],
        "sourceBatchId": batch["batchId"],
        "sourceReceiptId": published.get("receiptId"),
        "sourceRowsPublished": len(rows),
        "actualRowsRead": len(page["rows"]),
        "numericTextAndDetailExact": True,
        "metadataReplayStable": True,
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
