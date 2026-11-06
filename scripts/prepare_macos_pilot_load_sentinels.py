#!/usr/bin/env python3
"""Create per-application load sentinels through authorized public MCP only."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import httpx2
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.bootstrap_macos_pilot_application import IDENTIFIER, response
from scripts.qualify_macos_pilot_load import _write_evidence
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


FORMAT = "openepm-macos-pilot-load-sentinels-v1"
REQUIRED_FUNCTIONS = {
    "application.capabilities.read",
    "facts.generic.table.create",
    "facts.generic.value.read",
    "facts.generic.value.set",
}


class SentinelPreparationError(ValueError):
    pass


def _text(value: object, label: str, maximum: int) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or value != value.strip()):
        raise SentinelPreparationError(f"PILOT_SENTINEL_{label}_INVALID")
    return value


def validate_manifest(value: object, output: Path) -> dict:
    if type(value) is not dict or set(value) != {
            "format", "workspaceId", "applications"}:
        raise SentinelPreparationError("PILOT_SENTINEL_MANIFEST_INVALID")
    workspace = value["workspaceId"]
    if (value["format"] != FORMAT or not isinstance(workspace, str)
            or IDENTIFIER.fullmatch(workspace) is None):
        raise SentinelPreparationError("PILOT_SENTINEL_MANIFEST_INVALID")
    applications = value["applications"]
    if not isinstance(applications, list) or len(applications) not in (5, 6):
        raise SentinelPreparationError("PILOT_SENTINEL_APPLICATIONS_INVALID")
    normalized = []
    identities: set[str] = set()
    table_names: set[str] = set()
    reader_keys: set[str] = set()
    reader_values: set[str] = set()
    writer_prefixes: set[str] = set()
    for item in applications:
        if type(item) is not dict or set(item) != {
                "applicationId", "tableName", "readerSeriesKey",
                "readerExpectation", "writerExpectation"}:
            raise SentinelPreparationError(
                "PILOT_SENTINEL_APPLICATION_INVALID")
        application = item["applicationId"]
        if (not isinstance(application, str)
                or IDENTIFIER.fullmatch(application) is None
                or application in identities):
            raise SentinelPreparationError(
                "PILOT_SENTINEL_APPLICATION_INVALID")
        table_name = _text(item["tableName"], "TABLE_NAME", 200)
        reader_key = _text(item["readerSeriesKey"], "READER_KEY", 1000)
        reader_value = _text(item["readerExpectation"],
                             "READER_EXPECTATION", 1000)
        writer_prefix = _text(item["writerExpectation"],
                              "WRITER_EXPECTATION", 500)
        if (table_name in table_names or reader_key in reader_keys
                or reader_value in reader_values
                or writer_prefix in writer_prefixes):
            raise SentinelPreparationError(
                "PILOT_SENTINEL_VALUES_NOT_DISTINCT")
        identities.add(application); table_names.add(table_name)
        reader_keys.add(reader_key); reader_values.add(reader_value)
        writer_prefixes.add(writer_prefix)
        normalized.append({
            "applicationId": application,
            "tableName": table_name,
            "readerSeriesKey": reader_key,
            "readerExpectation": reader_value,
            "writerExpectation": writer_prefix,
        })
    if not output.is_absolute() or output.suffix != ".json":
        raise SentinelPreparationError("PILOT_SENTINEL_OUTPUT_INVALID")
    return {
        "format": FORMAT,
        "workspaceId": workspace,
        "applications": normalized,
        "output": str(output),
        "publicMcpOnly": True,
        "databaseAccess": False,
        "businessMutationPerformed": False,
    }


def program(function: str, arguments: dict) -> dict:
    return {"languageVersion": 2, "function": function,
            "arguments": arguments}


async def apply_plan(plan: dict, call) -> list[dict]:
    prepared = []
    for item in plan["applications"]:
        scope = {"workspace_id": plan["workspaceId"],
                 "application_id": item["applicationId"]}
        catalog = await call("list_v2_functions", scope)
        functions = catalog.get("functions")
        names = set(functions) if isinstance(functions, dict) else set(
            functions if isinstance(functions, list) else [])
        missing = REQUIRED_FUNCTIONS - names
        if missing:
            raise RuntimeError("required sentinel functions missing: "
                               + ", ".join(sorted(missing)))

        state = (await call("read_v2_program", {
            **scope,
            "program": program("application.capabilities.read", {}),
        }))["result"]
        table_request = {
            **scope,
            "program": program("facts.generic.table.create", {
                "name": item["tableName"],
                "shortDescription": "Mac pilot load sentinel table",
                "semanticDefinition": (
                    "Non-dimensional JSON sentinels and unique load-run "
                    "write probes for this application."),
                "expectedMetadataRevision": state["metadataRevision"],
            }),
            "idempotency_key": (
                "pilot-load-sentinel-table-v1:" + item["applicationId"]),
        }
        table = await call("execute_v2_generic_fact_program", table_request)
        if await call("execute_v2_generic_fact_program", table_request) != table:
            raise RuntimeError("sentinel table replay changed result")
        table_id = table["result"]["tableId"]

        current = (await call("read_v2_program", {
            **scope,
            "program": program("application.capabilities.read", {}),
        }))["result"]
        sentinel_request = {
            **scope,
            "program": program("facts.generic.value.set", {
                "tableId": table_id,
                "seriesKey": item["readerSeriesKey"],
                "value": item["readerExpectation"],
                "expectedChangeId": "",
                "expectedDataRevision": current["dataRevision"],
            }),
            "idempotency_key": (
                "pilot-load-reader-sentinel-v1:" + item["applicationId"]),
        }
        sentinel = await call("execute_v2_generic_fact_program",
                              sentinel_request)
        if (await call("execute_v2_generic_fact_program", sentinel_request)
                != sentinel):
            raise RuntimeError("reader sentinel replay changed result")
        observed = (await call("read_v2_program", {
            **scope,
            "program": program("facts.generic.value.read", {
                "tableId": table_id,
                "seriesKey": item["readerSeriesKey"],
            }),
        }))["result"]
        if (observed.get("exists") is not True
                or observed.get("value") != item["readerExpectation"]
                or observed.get("changeId") != sentinel["result"].get(
                    "changeId")):
            raise RuntimeError("reader sentinel verification failed")
        prepared.append({
            "workspaceId": plan["workspaceId"],
            "applicationId": item["applicationId"],
            "genericTableId": table_id,
            "readerSeriesKey": item["readerSeriesKey"],
            "readerExpectation": item["readerExpectation"],
            "writerExpectation": item["writerExpectation"],
            "tableReplayIdentical": True,
            "sentinelReplayIdentical": True,
            "sentinelReadVerified": True,
        })
    return prepared


async def execute(plan: dict) -> dict:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"], OAuthClientMetadata(
            client_name="Open EPM pilot load sentinel preparation",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"), storage,
        redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                ENDPOINTS["application"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()

                async def call(tool: str, arguments: dict) -> dict:
                    return response(await session.call_tool(tool, arguments))

                applications = await apply_plan(plan, call)
    return {
        **plan,
        "format": "openepm-macos-pilot-load-sentinels-result-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "applications": applications,
        "oauthTokenRetained": False,
        "identityValueRetained": False,
        "businessMutationPerformed": True,
        "mutationBoundary": "authorized fixed-core public application MCP",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        value = json.loads(arguments.manifest.read_text(encoding="utf-8"))
        plan = validate_manifest(value, arguments.output)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
        _write_evidence(arguments.output, result)
    except (OSError, ValueError, RuntimeError,
            json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({"passed": True,
                      "applicationCount": len(result["applications"]),
                      "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
