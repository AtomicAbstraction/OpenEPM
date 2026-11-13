#!/usr/bin/env python3
"""Create the first Mac-pilot workspace/application through public MCP only."""
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

from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback)


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")


def validate(workspace_id: str, workspace_name: str, application_id: str,
             application_name: str, output: Path) -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    for label, value in (("workspace", workspace_name),
                         ("application", application_name)):
        if (not isinstance(value, str) or not 1 <= len(value) <= 200
                or value != value.strip()):
            raise ValueError(label + " name is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    return {
        "format": "openepm-macos-pilot-application-bootstrap-plan-v1",
        "publicMcpOnly": True,
        "databaseAccess": False,
        "workspaceId": workspace_id,
        "workspaceName": workspace_name,
        "applicationId": application_id,
        "applicationName": application_name,
        "enabledCapabilities": [],
        "output": str(output),
    }


def response(value) -> dict:
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


async def call_scope(endpoint: str, tool: str,
                     arguments: dict[str, object]) -> tuple[dict, dict]:
    server_url = ENDPOINTS[endpoint]
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        server_url,
        OAuthClientMetadata(
            client_name="Open EPM pilot bootstrap",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"),
        storage, redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                server_url, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()
                first = response(await session.call_tool(tool, arguments))
                replay = response(await session.call_tool(tool, arguments))
    return first, {
        "serverName": initialized.server_info.name,
        "replayIdentical": replay == first,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "identityValueRetained": False,
    }


async def execute(plan: dict[str, object]) -> dict[str, object]:
    workspace_program = {
        "languageVersion": 2,
        "function": "platform.workspace.create",
        "arguments": {"workspaceId": plan["workspaceId"],
                      "name": plan["workspaceName"]},
    }
    workspace, platform = await call_scope(
        "platform", "execute_v2_platform_program", {
            "program": workspace_program,
            "idempotency_key": "pilot-bootstrap-workspace-v1",
        })
    application_program = {
        "languageVersion": 2,
        "function": "workspace.application.create",
        "arguments": {"applicationId": plan["applicationId"],
                      "name": plan["applicationName"], "kind": "multidimensional",
                      "enabledCapabilities": []},
    }
    application, workspace_scope = await call_scope(
        "workspace", "execute_v2_workspace_program", {
            "program": application_program,
            "idempotency_key": "pilot-bootstrap-application-v1",
        })
    if (workspace.get("workspaceId") != plan["workspaceId"]
            or application.get("workspaceId") != plan["workspaceId"]
            or application.get("applicationId") != plan["applicationId"]
            or application.get("enabledCapabilities") != []
            or platform["replayIdentical"] is not True
            or workspace_scope["replayIdentical"] is not True):
        raise RuntimeError("pilot bootstrap result did not match the fixed plan")
    return {
        **plan,
        "format": "openepm-macos-pilot-application-bootstrap-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "workspace": workspace,
        "application": application,
        "platformMcp": platform,
        "workspaceMcp": workspace_scope,
        "businessMutationPerformed": True,
        "mutationBoundary": "authorized fixed-core public MCP programs",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--workspace-name", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--application-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(arguments.workspace_id, arguments.workspace_name,
                        arguments.application_id, arguments.application_name,
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
