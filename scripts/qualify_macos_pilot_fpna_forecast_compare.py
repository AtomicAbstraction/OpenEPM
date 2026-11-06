#!/usr/bin/env python3
"""Qualify the live rolling forecast and scenario comparison via public MCP."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
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

from scripts.qualify_macos_pilot_fpna_foundation import program, response
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback)


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
METADATA_REVISION = 34
START_DATA_REVISION = 3
START_POLICY_REVISION = 7
START_SCHEMA_EPOCH = 5


def validate(workspace_id: str, application_id: str,
             output: Path, *, resume_occurrence_id: str | None = None
             ) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    if (resume_occurrence_id is not None
            and IDENTIFIER.fullmatch(resume_occurrence_id) is None):
        raise ValueError("resume occurrence ID is invalid")
    return {
        "format": "openepm-macos-pilot-fpna-forecast-compare-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "expectedStartingRevisions": {
            "metadata": METADATA_REVISION,
            "data": START_DATA_REVISION,
            "policy": START_POLICY_REVISION,
        },
        "operations": ["irregular-cross-year-forecast",
                       "durable-occurrence", "scenario-comparison"],
        "resumeOccurrenceId": resume_occurrence_id,
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
            client_name="Open EPM pilot forecast and comparison",
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

                required = {
                    "facts.planning.forecast.definition.save",
                    "facts.planning.forecast.definition.activate",
                    "facts.planning.forecast.occurrence.request",
                    "facts.planning.forecast.occurrence.read",
                    "execution.delegation.create", "planning.version.compare",
                    "planning.version.scan", "facts.export.page",
                    "security.identity.current.read",
                }
                discovered = await call("list_v2_functions", scope)
                functions = set(discovered.get("functions", []))
                if required - functions:
                    raise RuntimeError("required planning functions missing: "
                                       + ", ".join(sorted(required-functions)))

                initial = await read("application.capabilities.read", {})
                expected = plan["expectedStartingRevisions"]
                resume_occurrence_id = plan.get("resumeOccurrenceId")
                if resume_occurrence_id is not None:
                    if (initial["metadataRevision"] != METADATA_REVISION
                            or initial["dataRevision"] != 6
                            or initial["policyRevision"] != 10
                            or initial["schemaEpoch"] != START_SCHEMA_EPOCH
                            or initial["commitRevision"] != 55):
                        raise RuntimeError(
                            "completed forecast dependency has changed")
                    if initial["enabledCapabilities"] != []:
                        raise RuntimeError(
                            "generic FP&A capability boundary changed")
                    current_identity = await read(
                        "security.identity.current.read", {})
                    if current_identity.get("verifiedByServer") is not True:
                        raise RuntimeError(
                            "server-verified identity is unavailable")
                    definition = (await call(
                        "execute_v2_forecast_definition", {
                            **scope, "program": program(
                                "facts.planning.forecast.definition.read", {
                                    "definitionId": "pilot.forecast",
                                    "version": 1})}))['result']
                    if (definition.get("version") != 1
                            or definition.get("configuration", {}).get(
                                "targetMember") != "Rolling"):
                        raise RuntimeError(
                            "durable forecast definition is unavailable")
                    settled = (await call(
                        "execute_v2_forecast_occurrence_control", {
                            **scope, "program": program(
                                "facts.planning.forecast.occurrence.read", {
                                    "occurrenceId": resume_occurrence_id})
                        }))['result']
                    if settled.get("status") != "progress_committed":
                        raise RuntimeError(
                            "durable forecast occurrence is not committed")
                    selection = [(row["year_id"], row["period_id"],
                                  row["source_scenario_id"])
                                 for row in settled["calendar_selection"]]
                    if selection != [("FY26", "P2", "Actual"),
                                     ("FY26", "P3", "Actual"),
                                     ("FY27", "P4", "Plan")]:
                        raise RuntimeError(
                            "forecast calendar selection is incorrect")
                    forecast_export = await read("facts.export.page", {
                        "members": {"Scenario": "Rolling",
                                    "Department": "DeptA",
                                    "Account": "Sales"}})
                    forecast_amounts = {
                        (row["members"]["Year"],
                         row["members"]["Period"]):
                            row["value"]["decimal"]
                        for row in forecast_export["rows"]}
                    if forecast_amounts != {
                            ("FY26", "P2"): "110.00000000",
                            ("FY26", "P3"): "120.00000000",
                            ("FY27", "P4"): "130.00000000"}:
                        raise RuntimeError("forecast output is not exact")
                    compare_program = {
                        "dimensionId": "Scenario",
                        "baseMemberId": "Actual",
                        "targetMemberId": "Plan", "coordinates": [
                            {"Year": "FY27", "Period": "P4",
                             "Department": "DeptB", "Account": "Sales"},
                            {"Year": "FY27", "Period": "P4",
                             "Department": "DeptB", "Account": "Extra"},
                        ]}
                    before_compare = await read(
                        "application.capabilities.read", {})
                    compared = await read(
                        "planning.version.compare", compare_program)
                    after_compare = await read(
                        "application.capabilities.read", {})
                    by_account = {row["otherMembers"]["Account"]: row
                                  for row in compared["rows"]}
                    sales, extra = by_account["Sales"], by_account["Extra"]
                    if ((sales["base"]["amount"],
                         sales["target"]["amount"], sales["delta"]) != (
                            "10.00000000", "13.00000000", "3.00000000")
                            or extra["base"]["kind"] != "missing"
                            or extra["target"]["kind"] != "numeric"
                            or extra["target"]["amount"] != "0.00000000"
                            or extra["delta"] is not None or extra["equal"]
                            or before_compare["commitRevision"]
                            != after_compare["commitRevision"]):
                        raise RuntimeError(
                            "scenario comparison is not exact/read-only")
                    return {
                        **plan,
                        "format": (
                            "openepm-macos-pilot-fpna-forecast-compare-v1"),
                        "generatedAt": datetime.now(timezone.utc).isoformat(),
                        "status": "passed",
                        "serverName": initialized.server_info.name,
                        "forecast": {
                            "definitionVersion": definition["version"],
                            "occurrenceId": resume_occurrence_id,
                            "status": settled["status"],
                            "batchId": settled["batch_id"],
                            "committedRevision": settled[
                                "committed_revision"],
                            "calendarSelection": [list(item)
                                                  for item in selection],
                            "amounts": {
                                year + "/" + period: amount
                                for (year, period), amount
                                in forecast_amounts.items()},
                            "sourceRowsPreserved": True,
                        },
                        "comparison": {
                            "salesBase": sales["base"]["amount"],
                            "salesTarget": sales["target"]["amount"],
                            "salesDelta": sales["delta"],
                            "missingVersusPresentZeroDistinct": True,
                            "readOnlyCommitStable": True,
                            "snapshotRevision": compared[
                                "snapshotRevision"],
                        },
                        "finalRevisions": {
                            "metadata": after_compare["metadataRevision"],
                            "data": after_compare["dataRevision"],
                            "policy": after_compare["policyRevision"],
                            "commit": after_compare["commitRevision"],
                        },
                        "mcpCallCount": call_count,
                        "oauthAuthorizationCodeRetained": False,
                        "oauthTokenRetained": False,
                        "identityValueRetained": False,
                        "businessMutationPerformed": False,
                        "mutationBoundary": None,
                        "resumeEvidence": {
                            "method": "public MCP reads only",
                            "operatorDiagnosticUsedToLocateOccurrence": True,
                            "diagnosticBusinessMutation": False,
                            "reason": (
                                "original journey completed before local "
                                "evidence serialization failed"),
                        },
                    }
                start_pair = (initial["dataRevision"],
                              initial["policyRevision"])
                resuming_definition = start_pair == (
                    START_DATA_REVISION + 1, START_POLICY_REVISION + 2)
                if (initial["metadataRevision"] != expected["metadata"]
                        or initial["schemaEpoch"] != START_SCHEMA_EPOCH
                        or start_pair not in ((START_DATA_REVISION,
                                              START_POLICY_REVISION),
                                             (START_DATA_REVISION + 1,
                                              START_POLICY_REVISION + 2))):
                    raise RuntimeError(
                        "live pilot revisions do not match the sealed dependency")
                if initial["enabledCapabilities"] != []:
                    raise RuntimeError("generic FP&A capability boundary changed")

                forecast_rows = [
                    {"members": {"Scenario": "Actual", "Year": "FY26",
                        "Period": "P2", "Department": "DeptA",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "110"},
                     "sourceRef": "pilot-forecast-actual-p2"},
                    {"members": {"Scenario": "Actual", "Year": "FY26",
                        "Period": "P3", "Department": "DeptA",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "120"},
                     "sourceRef": "pilot-forecast-actual-p3"},
                    {"members": {"Scenario": "Plan", "Year": "FY27",
                        "Period": "P4", "Department": "DeptA",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "130"},
                     "sourceRef": "pilot-forecast-plan-p4"},
                ]
                batch = await source("facts.source.begin", {
                    "idempotencyKey": "pilot-forecast-source-v1",
                    "mode": "merge", "scopeMembers": {}, "scopeAll": True,
                    "expectedMetadataRevision": METADATA_REVISION,
                    "expectedDataRevision": START_DATA_REVISION,
                })
                if resuming_definition:
                    forecast_source = {"receiptId": None, "resumed": True}
                    existing_source = await read("facts.export.page", {
                        "members": {"Department": "DeptA",
                                    "Account": "Sales"}})
                    existing = {(row["members"]["Scenario"],
                                 row["members"]["Year"],
                                 row["members"]["Period"]):
                                    row["value"].get("decimal")
                                for row in existing_source["rows"]
                                if row["value"]["type"] == "AmountLiteral"}
                    if any(existing.get((row["members"]["Scenario"],
                                         row["members"]["Year"],
                                         row["members"]["Period"]))
                           != format(Decimal(row["value"]["decimal"]), ".8f")
                           for row in forecast_rows):
                        raise RuntimeError(
                            "durable forecast source replay is incomplete")
                else:
                    chunk = await source("facts.source.append", {
                        "batchId": batch["batchId"], "chunkIndex": 0,
                        "rows": forecast_rows})
                    await source("facts.source.seal", {
                        "batchId": batch["batchId"],
                        "expectedRows": len(forecast_rows),
                        "expectedContentDigest": chunk["contentDigest"]})
                    batch_preview = await source("facts.source.preview", {
                        "batchId": batch["batchId"]})
                    forecast_source = await source("facts.source.publish", {
                        "batchId": batch["batchId"],
                        "previewToken": batch_preview["previewToken"]})

                configuration = {
                    "name": "Pilot irregular cross-year forecast",
                    "scenarioDimension": "Scenario",
                    "actualMember": "Actual", "priorForecastMember": "Plan",
                    "targetMember": "Rolling", "yearDimension": "Year",
                    "periodDimension": "Period",
                    "filterMembers": {"Department": "DeptA",
                                      "Account": "Sales"},
                    "mode": "replace", "advancePeriods": 1,
                    "horizonPeriods": 3, "windowStart": "2026-01-01",
                    "actualThrough": "2026-02-01",
                    "windowEndExclusive": "2026-12-20",
                }
                definition_request = {
                    **scope,
                    "program": program(
                        "facts.planning.forecast.definition.save", {
                            "definitionId": "pilot.forecast",
                            "expectedVersion": 0, "expectedStateRevision": 0,
                            "configuration": configuration,
                            "reason": "Pilot irregular cross-year forecast",
                            "expectedMetadataRevision": METADATA_REVISION,
                            "expectedPolicyRevision": START_POLICY_REVISION,
                            "expectedSchemaEpoch": START_SCHEMA_EPOCH,
                        }),
                    "idempotency_key": "pilot-forecast-save-v1",
                }
                saved = (await call(
                    "execute_v2_forecast_definition",
                    definition_request))["result"]
                activated = (await call("execute_v2_forecast_definition", {
                    **scope,
                    "program": program(
                        "facts.planning.forecast.definition.activate", {
                            "definitionId": "pilot.forecast", "version": 1,
                            "expectedStateRevision": 1,
                            "reason": "Activate pilot forecast",
                            "expectedMetadataRevision": METADATA_REVISION,
                            "expectedPolicyRevision": START_POLICY_REVISION + 1,
                            "expectedSchemaEpoch": START_SCHEMA_EPOCH,
                        }),
                    "idempotency_key": "pilot-forecast-activate-v1",
                }))["result"]

                current_identity = await read(
                    "security.identity.current.read", {})
                issuer = current_identity.get("issuer")
                subject = current_identity.get("subjectId")
                if (current_identity.get("verifiedByServer") is not True
                        or not isinstance(issuer, str) or not issuer
                        or not isinstance(subject, str) or not subject):
                    raise RuntimeError("server-verified identity is unavailable")
                delegation_pins = await read("application.capabilities.read", {})
                now = datetime.now(timezone.utc)
                delegated = (await call("execute_v2_execution_delegation", {
                    **scope,
                    "program": program("execution.delegation.create", {
                        "delegationId": "pilot-forecast-delegation",
                        "version": 1, "issuer": issuer,
                        "subjectId": subject,
                        "operationScope": [
                            "facts.planning.forecast.occurrence.request"],
                        "validFrom": (now-timedelta(minutes=1)).isoformat(),
                        "validUntil": (now+timedelta(hours=1)).isoformat(),
                        "scheduleId": None, "scheduleVersion": None,
                        "expectedMetadataRevision":
                            delegation_pins["metadataRevision"],
                        "expectedPolicyRevision":
                            delegation_pins["policyRevision"],
                        "expectedSchemaEpoch": delegation_pins["schemaEpoch"],
                    }),
                    "idempotency_key": "pilot-forecast-delegation-v1",
                }))["result"]
                occurrence_program = program(
                    "facts.planning.forecast.occurrence.request", {
                        "definitionId": "pilot.forecast",
                        "dueAt": now.isoformat(),
                        "actualClosedThrough": "2026-12-20",
                        "delegationId": "pilot-forecast-delegation",
                        "delegationVersion": 1,
                    })
                occurrence = (await call(
                    "execute_v2_forecast_occurrence_control", {
                        **scope, "program": occurrence_program}))["result"]
                occurrence_replay = (await call(
                    "execute_v2_forecast_occurrence_control", {
                        **scope, "program": occurrence_program}))["result"]
                if occurrence_replay["occurrenceId"] != occurrence["occurrenceId"]:
                    raise RuntimeError("forecast occurrence replay changed identity")
                occurrence_read = program(
                    "facts.planning.forecast.occurrence.read", {
                        "occurrenceId": occurrence["occurrenceId"]})
                settled = None
                for _ in range(240):
                    settled = (await call(
                        "execute_v2_forecast_occurrence_control", {
                            **scope, "program": occurrence_read}))["result"]
                    if settled["status"] == "progress_committed":
                        break
                    if settled["status"] in {
                            "failed", "needs_inspection", "cancelled"}:
                        raise RuntimeError(
                            "forecast occurrence failed: " + repr(settled))
                    await asyncio.sleep(.25)
                else:
                    raise RuntimeError("forecast occurrence did not settle")
                selection = [(row["year_id"], row["period_id"],
                              row["source_scenario_id"])
                             for row in settled["calendar_selection"]]
                if selection != [("FY26", "P2", "Actual"),
                                  ("FY26", "P3", "Actual"),
                                  ("FY27", "P4", "Plan")]:
                    raise RuntimeError("forecast calendar selection is incorrect")
                forecast_export = await read("facts.export.page", {
                    "members": {"Scenario": "Rolling",
                                "Department": "DeptA", "Account": "Sales"}})
                forecast_amounts = {
                    (row["members"]["Year"], row["members"]["Period"]):
                        row["value"]["decimal"]
                    for row in forecast_export["rows"]}
                if forecast_amounts != {
                        ("FY26", "P2"): "110.00000000",
                        ("FY26", "P3"): "120.00000000",
                        ("FY27", "P4"): "130.00000000"}:
                    raise RuntimeError("forecast output is not exact")

                compare_state = await read("application.capabilities.read", {})
                compare_rows = [
                    {"members": {"Scenario": "Actual", "Year": "FY27",
                        "Period": "P4", "Department": "DeptB",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "10"},
                     "sourceRef": "pilot-compare-actual"},
                    {"members": {"Scenario": "Plan", "Year": "FY27",
                        "Period": "P4", "Department": "DeptB",
                        "Account": "Sales"},
                     "value": {"type": "AmountLiteral", "decimal": "13"},
                     "sourceRef": "pilot-compare-plan"},
                    {"members": {"Scenario": "Plan", "Year": "FY27",
                        "Period": "P4", "Department": "DeptB",
                        "Account": "Extra"},
                     "value": {"type": "AmountLiteral", "decimal": "0"},
                     "sourceRef": "pilot-compare-present-zero"},
                ]
                compare_batch = await source("facts.source.begin", {
                    "idempotencyKey": "pilot-compare-source-v1",
                    "mode": "merge", "scopeMembers": {}, "scopeAll": True,
                    "expectedMetadataRevision": compare_state["metadataRevision"],
                    "expectedDataRevision": compare_state["dataRevision"],
                })
                compare_chunk = await source("facts.source.append", {
                    "batchId": compare_batch["batchId"], "chunkIndex": 0,
                    "rows": compare_rows})
                await source("facts.source.seal", {
                    "batchId": compare_batch["batchId"],
                    "expectedRows": len(compare_rows),
                    "expectedContentDigest": compare_chunk["contentDigest"]})
                compare_preview = await source("facts.source.preview", {
                    "batchId": compare_batch["batchId"]})
                compare_source = await source("facts.source.publish", {
                    "batchId": compare_batch["batchId"],
                    "previewToken": compare_preview["previewToken"]})

                compare_program = {
                    "dimensionId": "Scenario", "baseMemberId": "Actual",
                    "targetMemberId": "Plan", "coordinates": [
                        {"Year": "FY27", "Period": "P4",
                         "Department": "DeptB", "Account": "Sales"},
                        {"Year": "FY27", "Period": "P4",
                         "Department": "DeptB", "Account": "Extra"},
                    ]}
                before_compare = await read("application.capabilities.read", {})
                compared = await read("planning.version.compare",
                                      compare_program)
                after_compare = await read("application.capabilities.read", {})
                by_account = {row["otherMembers"]["Account"]: row
                              for row in compared["rows"]}
                sales = by_account["Sales"]
                extra = by_account["Extra"]
                if ((sales["base"]["amount"], sales["target"]["amount"],
                     sales["delta"]) != (
                        "10.00000000", "13.00000000", "3.00000000")
                        or extra["base"]["kind"] != "missing"
                        or extra["target"]["kind"] != "numeric"
                        or extra["target"]["amount"] != "0.00000000"
                        or extra["delta"] is not None or extra["equal"]
                        or before_compare["commitRevision"]
                        != after_compare["commitRevision"]):
                    raise RuntimeError("scenario comparison is not exact/read-only")

                final = await read("application.capabilities.read", {})

    return {
        **plan,
        "format": "openepm-macos-pilot-fpna-forecast-compare-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed", "serverName": initialized.server_info.name,
        "forecast": {
            "sourceBatchId": batch["batchId"],
            "sourceReceiptId": forecast_source.get("receiptId"),
            "resumedFromDurableDefinition": resuming_definition,
            "definitionVersion": saved["latestVersion"],
            "activatedStateRevision": activated["stateRevision"],
            "delegationVersion": delegated["version"],
            "occurrenceId": occurrence["occurrenceId"],
            "occurrenceReplayStable": True,
            "status": settled["status"],
            "batchId": settled["batch_id"],
            "committedRevision": settled["committed_revision"],
            "calendarSelection": [list(item) for item in selection],
            "amounts": {year + "/" + period: amount
                        for (year, period), amount in forecast_amounts.items()},
            "sourceRowsPreserved": True,
        },
        "comparison": {
            "sourceBatchId": compare_batch["batchId"],
            "sourceReceiptId": compare_source.get("receiptId"),
            "salesBase": sales["base"]["amount"],
            "salesTarget": sales["target"]["amount"],
            "salesDelta": sales["delta"],
            "missingVersusPresentZeroDistinct": True,
            "readOnlyCommitStable": True,
            "snapshotRevision": compared["snapshotRevision"],
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
    parser.add_argument("--resume-occurrence-id")
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(
            arguments.workspace_id, arguments.application_id,
            arguments.output,
            resume_occurrence_id=arguments.resume_occurrence_id)
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
