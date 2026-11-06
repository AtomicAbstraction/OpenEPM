#!/usr/bin/env python3
"""Verify live model bindings and create bounded pilot forecast delegations."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
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

from epm_core.macos_pilot_load import STEADY_ROLES, build_standard_workload
from scripts.bootstrap_macos_pilot_application import response
from scripts.provision_macos_pilot_application_access import (
    AccessManifestError, _read_protected_json, _read_roster,
    validate_manifest as validate_access_manifest,
)
from scripts.qualify_macos_pilot_load import _write_evidence
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


FORMAT = "openepm-macos-pilot-load-bindings-v1"
REQUIRED_FUNCTIONS = {"application.capabilities.read",
                      "facts.planning.forecast.definition.read",
                      "execution.delegation.read",
                      "execution.delegation.create"}


class PilotLoadBindingError(ValueError):
    pass


def _time(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise PilotLoadBindingError(f"PILOT_BINDING_{label}_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PilotLoadBindingError(
            f"PILOT_BINDING_{label}_INVALID") from error
    if parsed.tzinfo is None:
        raise PilotLoadBindingError(f"PILOT_BINDING_{label}_INVALID")
    return parsed.astimezone(timezone.utc)


def validate_manifest(value: object, manifest_path: Path,
                      output: Path) -> dict:
    if type(value) is not dict or set(value) != {
            "format", "accessManifest", "applications", "model",
            "delegationWindow"}:
        raise PilotLoadBindingError("PILOT_BINDING_MANIFEST_INVALID")
    if value["format"] != FORMAT or not manifest_path.is_absolute():
        raise PilotLoadBindingError("PILOT_BINDING_MANIFEST_INVALID")
    if (not output.is_absolute() or output.suffix != ".json"
            or output.exists() or output.is_symlink()
            or not output.parent.is_dir() or output.parent.is_symlink()):
        raise PilotLoadBindingError("PILOT_BINDING_OUTPUT_INVALID")
    access_path = Path(str(value["accessManifest"]))
    if not access_path.is_absolute():
        raise PilotLoadBindingError("PILOT_BINDING_ACCESS_INVALID")
    access_raw = _read_protected_json(access_path, "BINDING_ACCESS_MANIFEST")
    probe = output.parent / (output.name + ".access-validation")
    if probe.exists() or probe.is_symlink():
        raise PilotLoadBindingError("PILOT_BINDING_ACCESS_INVALID")
    access = validate_access_manifest(access_raw, access_path, probe)
    rosters = {item["label"]: _read_roster(
        Path(item["rosterFile"]), access["issuer"], access["audience"])
        for item in access_raw["identities"]}
    agents = [item for item in access_raw["identities"]
              if item["kind"] == "agent"]

    window = value["delegationWindow"]
    if type(window) is not dict or set(window) != {"validFrom", "validUntil"}:
        raise PilotLoadBindingError("PILOT_BINDING_WINDOW_INVALID")
    start = _time(window["validFrom"], "VALID_FROM")
    finish = _time(window["validUntil"], "VALID_UNTIL")
    if finish <= start or (finish - start).total_seconds() < 7200:
        raise PilotLoadBindingError("PILOT_BINDING_WINDOW_INVALID")

    applications = value["applications"]
    if (not isinstance(applications, list)
            or len(applications) != len(access["applications"])):
        raise PilotLoadBindingError("PILOT_BINDING_APPLICATIONS_INVALID")
    normalized = []
    seen = set(); covered = set()
    for item in applications:
        if (type(item) is not dict or set(item) - {
                "applicationId", "workloadRoles", "importRow", "forecast"}
                or set(item) < {"applicationId", "workloadRoles"}):
            raise PilotLoadBindingError("PILOT_BINDING_APPLICATION_INVALID")
        application_id = item["applicationId"]
        roles = item["workloadRoles"]
        if (application_id in seen or application_id not in access["applications"]
                or not isinstance(roles, list) or not roles
                or len(roles) != len(set(roles))
                or not set(roles).issubset(STEADY_ROLES)):
            raise PilotLoadBindingError("PILOT_BINDING_APPLICATION_INVALID")
        entry = {"applicationId": application_id,
                 "workloadRoles": list(roles)}
        if "import" in roles:
            row = item.get("importRow")
            if (not isinstance(row, dict)
                    or set(row) != {"members", "value", "sourceRef"}
                    or row["value"] != {"type": "AmountLiteral",
                                         "decimal": "1.00000000"}
                    or row["sourceRef"] != "pilot-load-import"):
                raise PilotLoadBindingError("PILOT_BINDING_IMPORT_INVALID")
            entry["importRow"] = row
        elif "importRow" in item:
            raise PilotLoadBindingError("PILOT_BINDING_IMPORT_INVALID")
        if "forecast" in roles:
            forecast = item.get("forecast")
            if (not isinstance(forecast, dict) or set(forecast) != {
                    "definitionId", "version", "actualClosedThrough",
                    "delegationIdPrefix", "delegationVersion"}
                    or not isinstance(forecast["version"], int)
                    or forecast["version"] < 1
                    or not isinstance(forecast["delegationVersion"], int)
                    or forecast["delegationVersion"] < 1
                    or not isinstance(forecast["definitionId"], str)
                    or not forecast["definitionId"]
                    or not isinstance(forecast["delegationIdPrefix"], str)
                    or not forecast["delegationIdPrefix"]):
                raise PilotLoadBindingError("PILOT_BINDING_FORECAST_INVALID")
            _time(forecast["actualClosedThrough"] + "T00:00:00Z",
                  "ACTUAL_CLOSED_THROUGH")
            delegations = {}
            for index, agent in enumerate(agents, 1):
                if agent["roles"].get(application_id) not in {
                        "Editor", "Administrator"}:
                    raise PilotLoadBindingError(
                        "PILOT_BINDING_FORECAST_AGENT_UNAUTHORIZED")
                delegation_id = f"{forecast['delegationIdPrefix']}-{index}"
                if len(delegation_id) > 200:
                    raise PilotLoadBindingError(
                        "PILOT_BINDING_FORECAST_INVALID")
                delegations[rosters[agent["label"]]["subject"]] = {
                    "delegationId": delegation_id,
                    "version": forecast["delegationVersion"]}
            entry["forecast"] = {**forecast, "delegations": delegations}
        elif "forecast" in item:
            raise PilotLoadBindingError("PILOT_BINDING_FORECAST_INVALID")
        seen.add(application_id); covered.update(roles); normalized.append(entry)
    if seen != set(access["applications"]) or covered != set(STEADY_ROLES):
        raise PilotLoadBindingError("PILOT_BINDING_APPLICATIONS_INVALID")

    model = value["model"]
    if type(model) is not dict or set(model) != {
            "calculationSource", "targetDimension", "targetMembers",
            "aggregateDimensions"}:
        raise PilotLoadBindingError("PILOT_BINDING_MODEL_INVALID")
    build_standard_workload(model["calculationSource"],
                            model["targetDimension"], model["targetMembers"],
                            model["aggregateDimensions"])
    return {"format": FORMAT, "workspaceId": access["workspaceId"],
            "issuer": access["issuer"], "applications": normalized,
            "model": model,
            "validFrom": window["validFrom"],
            "validUntil": window["validUntil"],
            "output": str(output)}


def program(function: str, arguments: dict) -> dict:
    return {"languageVersion": 2, "function": function,
            "arguments": arguments}


async def apply_plan(plan: dict, call) -> list[dict]:
    effects = []
    for application in plan["applications"]:
        forecast = application.get("forecast")
        if forecast is None:
            continue
        scope = {"workspace_id": plan["workspaceId"],
                 "application_id": application["applicationId"]}
        catalog = await call("list_v2_functions", scope)
        functions = catalog.get("functions", [])
        names = set(functions) if not isinstance(functions, dict) else set(
            functions)
        if REQUIRED_FUNCTIONS - names:
            raise RuntimeError("PILOT_BINDING_REQUIRED_FUNCTION_MISSING")
        definition = (await call("execute_v2_forecast_definition", {
            **scope, "program": program(
                "facts.planning.forecast.definition.read", {
                    "definitionId": forecast["definitionId"],
                    "version": forecast["version"]})}))["result"]
        if (definition.get("definitionId") != forecast["definitionId"]
                or definition.get("version") != forecast["version"]):
            raise RuntimeError("PILOT_BINDING_FORECAST_DEFINITION_MISMATCH")

        for subject, requested in forecast["delegations"].items():
            existing = (await call("read_v2_program", {
                **scope, "program": program("execution.delegation.read", {
                    "delegationId": requested["delegationId"]})}))["result"]
            delegation = existing.get("delegation")
            if existing.get("defined"):
                exact = (delegation.get("active_version") == requested["version"]
                         and delegation.get("latest_version") == requested["version"]
                         and delegation.get("issuer") == plan["issuer"]
                         and delegation.get("subject_id") == subject
                         and delegation.get("operation_scope") == [
                             "facts.planning.forecast.occurrence.request"]
                         and _time(str(delegation.get("valid_from")),
                                   "OBSERVED_VALID_FROM").isoformat()
                             == _time(plan["validFrom"], "VALID_FROM").isoformat()
                         and _time(str(delegation.get("valid_until")),
                                   "OBSERVED_VALID_UNTIL").isoformat()
                             == _time(plan["validUntil"], "VALID_UNTIL").isoformat()
                         and delegation.get("schedule_id") is None
                         and delegation.get("schedule_version") is None)
                if not exact:
                    raise RuntimeError("PILOT_BINDING_DELEGATION_CONFLICT")
                status = "reused"
            else:
                state = (await call("read_v2_program", {
                    **scope, "program": program(
                        "application.capabilities.read", {})}))["result"]
                arguments = {
                    "delegationId": requested["delegationId"],
                    "version": requested["version"],
                    "issuer": plan["issuer"], "subjectId": subject,
                    "operationScope": [
                        "facts.planning.forecast.occurrence.request"],
                    "validFrom": plan["validFrom"],
                    "validUntil": plan["validUntil"],
                    "scheduleId": None, "scheduleVersion": None,
                    "expectedMetadataRevision": state["metadataRevision"],
                    "expectedPolicyRevision": state["policyRevision"],
                    "expectedSchemaEpoch": state["schemaEpoch"]}
                digest = hashlib.sha256(json.dumps({
                    "applicationId": application["applicationId"],
                    "delegationId": requested["delegationId"],
                    "version": requested["version"], "subject": subject,
                }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                created = (await call("execute_v2_execution_delegation", {
                    **scope, "program": program(
                        "execution.delegation.create", arguments),
                    "idempotency_key": "pilot-load-delegation-" + digest,
                }))["result"]
                if (created.get("delegationId") != requested["delegationId"]
                        or created.get("version") != requested["version"]
                        or created.get("status") != "Active"):
                    raise RuntimeError("PILOT_BINDING_DELEGATION_CREATE_FAILED")
                status = "created"
            effects.append({"applicationId": application["applicationId"],
                            "delegationId": requested["delegationId"],
                            "version": requested["version"],
                            "subject": subject, "status": status})
    return effects


def result(plan: dict, effects: list[dict]) -> dict:
    applications = []
    for item in plan["applications"]:
        binding = {"applicationId": item["applicationId"],
                   "workloadRoles": item["workloadRoles"]}
        if "importRow" in item:
            binding["importRow"] = item["importRow"]
        if "forecast" in item:
            forecast = item["forecast"]
            binding["forecastProfile"] = {
                "definitionId": forecast["definitionId"],
                "actualClosedThrough": forecast["actualClosedThrough"],
                "delegations": forecast["delegations"]}
        applications.append(binding)
    return {"format": "openepm-macos-pilot-load-bindings-result-v1",
            "status": "passed", "generatedAt": datetime.now(
                timezone.utc).isoformat(),
            "workspaceId": plan["workspaceId"], "model": plan["model"],
            "applicationBindings": applications, "effects": effects,
            "businessMutationPerformed": any(
                item["status"] == "created" for item in effects),
            "mutationBoundary": "authorized fixed-core public application MCP",
            "databaseAccess": False}


def redacted(plan: dict, effects: list[dict] | None = None) -> dict:
    return {"format": plan["format"],
            "applicationCount": len(plan["applications"]),
            "forecastApplicationCount": sum(
                "forecast" in item for item in plan["applications"]),
            "delegationCount": sum(len(item.get("forecast", {}).get(
                "delegations", {})) for item in plan["applications"]),
            "effectCount": None if effects is None else len(effects),
            "modelBindingConfigured": True,
            "rawSubjectsIncluded": False, "credentialPathsIncluded": False,
            "businessMutationPerformed": bool(effects) and any(
                item["status"] == "created" for item in effects)}


async def execute(plan: dict) -> list[dict]:
    storage = MemoryStorage()
    async def redirect(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)
    provider = OAuthClientProvider(
        ENDPOINTS["application"], OAuthClientMetadata(
            client_name="Open EPM pilot load binding preparation",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"), storage,
        redirect_handler=redirect, callback_handler=receive_callback)
    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                ENDPOINTS["application"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                async def call(tool: str, arguments: dict) -> dict:
                    return response(await session.call_tool(tool, arguments))
                return await apply_plan(plan, call)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        value = _read_protected_json(arguments.manifest, "BINDING_MANIFEST")
        plan = validate_manifest(value, arguments.manifest, arguments.output)
        if not arguments.execute:
            print(json.dumps(redacted(plan), sort_keys=True))
            return 0
        effects = asyncio.run(execute(plan))
        _write_evidence(arguments.output, result(plan, effects))
    except (AccessManifestError, PilotLoadBindingError, OSError, RuntimeError,
            json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(redacted(plan, effects), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
