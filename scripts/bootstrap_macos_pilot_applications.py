#!/usr/bin/env python3
"""Create the exact two programmable UAT applications through public MCP."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

import httpx2
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata

from scripts.bootstrap_macos_pilot_application import IDENTIFIER, response
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


FORMAT = "openepm-programmable-uat-applications-v2"


def validate_manifest(value: object, output: Path) -> dict:
    if type(value) is not dict or set(value) != {
            "format", "workspaceId", "applications"}:
        raise ValueError("pilot application manifest shape is invalid")
    if value["format"] != FORMAT or IDENTIFIER.fullmatch(
            value["workspaceId"] if isinstance(value["workspaceId"], str)
            else "") is None:
        raise ValueError("pilot application manifest identity is invalid")
    applications = value["applications"]
    if not isinstance(applications, list) or len(applications) != 2:
        raise ValueError("exactly two programmable UAT applications are required")
    normalized = []
    identifiers = set()
    for application in applications:
        if type(application) is not dict or set(application) != {
                "applicationId", "name"}:
            raise ValueError("pilot application entry shape is invalid")
        application_id = application["applicationId"]
        name = application["name"]
        if (not isinstance(application_id, str)
                or IDENTIFIER.fullmatch(application_id) is None
                or application_id in identifiers
                or not isinstance(name, str) or not 1 <= len(name) <= 200
                or name != name.strip()):
            raise ValueError("pilot application entry is invalid")
        identifiers.add(application_id)
        normalized.append({"applicationId": application_id, "name": name,
                           "enabledCapabilities": []})
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {"format": FORMAT, "workspaceId": value["workspaceId"],
            "applications": normalized, "output": str(output),
            "publicMcpOnly": True, "databaseAccess": False,
            "existingWorkspaceRequired": True,
            "businessMutationPerformed": False}


async def apply_plan(plan: dict, call) -> list[dict]:
    results = []
    for application in plan["applications"]:
        program = {"languageVersion": 2,
                   "function": "workspace.application.create",
                   "arguments": {"applicationId": application["applicationId"],
                                 "name": application["name"],
                                 "kind": "multidimensional"}}
        arguments = {
            "program": program,
            "idempotency_key": ("pilot-additional-application-v1:"
                                + plan["workspaceId"] + ":"
                                + application["applicationId"]),
        }
        first = await call("execute_v2_workspace_program", arguments)
        replay = await call("execute_v2_workspace_program", arguments)
        if (first != replay or first.get("workspaceId") != plan["workspaceId"]
                or first.get("applicationId") != application["applicationId"]
                or first.get("enabledCapabilities") != []):
            raise RuntimeError("pilot application result did not match the sealed plan")
        results.append({"applicationId": application["applicationId"],
                        "name": application["name"],
                        "replayIdentical": True,
                        "enabledCapabilities": []})
    return results


async def execute(plan: dict) -> dict:
    storage = MemoryStorage()
    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)
    provider = OAuthClientProvider(
        ENDPOINTS["workspace"], OAuthClientMetadata(
            client_name="Open EPM additional pilot applications",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"), storage,
        redirect_handler=redirect_handler, callback_handler=receive_callback)
    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                ENDPOINTS["workspace"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()
                tools = {tool.name for tool in (await session.list_tools()).tools}
                if "execute_v2_workspace_program" not in tools:
                    raise RuntimeError("workspace application create tool is unavailable")
                async def call(tool: str, arguments: dict) -> dict:
                    return response(await session.call_tool(tool, arguments))
                applications = await apply_plan(plan, call)
    return {**plan, "generatedAt": datetime.now(timezone.utc).isoformat(),
            "status": "passed", "applications": applications,
            "workspaceMcp": {"serverName": initialized.server_info.name,
                             "singleSession": True,
                             "oauthTokenRetained": False,
                             "identityValueRetained": False},
            "businessMutationPerformed": True,
            "mutationBoundary": "authorized fixed-core public workspace MCP",
            "catalogueTarget": "exactly_two_programmable_applications"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        manifest = json.loads(arguments.manifest.read_text(encoding="utf-8"))
        plan = validate_manifest(manifest, arguments.output)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        parser.error(str(error))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True,
                      "applicationCount": len(result["applications"]),
                      "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
