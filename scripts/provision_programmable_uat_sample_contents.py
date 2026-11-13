#!/usr/bin/env python3
"""Populate the exact two programmable UAT applications through public MCP."""
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
from scripts.programmable_uat_sample_contract import (
    build_calculated_member_definitions, build_substantial_application_rule,
    build_metadata_plan, contract_digest,
    validate_sample_manifest,
)
from scripts.programmable_source_authoring import (
    active_environment, application_rule_source, author_and_activate,
    calculated_member_source, save_named_selection,
)
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


TERMINAL_JOBS = {"published", "failed", "cancelled", "needs_inspection"}
TERMINAL_RULES = {"published", "failed", "partially_published", "cancelled",
                  "needs_inspection"}

def _replay_projection(value):
    """Compare authoritative effects while allowing an explicit replay marker."""
    if isinstance(value, dict):
        return {key: _replay_projection(item) for key, item in value.items()
                if key != "duplicate"}
    if isinstance(value, list):
        return [_replay_projection(item) for item in value]
    return value


def _same_replay(first, replay, tool):
    """Pin an admitted operation while its separately polled work progresses.

    Mutation receipts still compare every authoritative field. Job admission
    returns the current job status, and build admission returns the current
    build record; neither promises to freeze progress between two requests.
    """
    left, right = _replay_projection(first), _replay_projection(replay)
    if tool == 'submit_v2_program':
        if (not isinstance(left, dict) or not isinstance(right, dict)
                or not isinstance(left.get('jobId'), str) or not left['jobId']
                or left['jobId'] != right.get('jobId')):
            return False
        left.pop('status', None)
        right.pop('status', None)
    elif tool == 'execute_v2_python_program_build':
        a = left.get('result') if isinstance(left, dict) else None
        b = right.get('result') if isinstance(right, dict) else None
        if (not isinstance(a, dict) or not isinstance(b, dict)
                or not isinstance(a.get('buildId'), str) or not a['buildId']
                or a['buildId'] != b.get('buildId')):
            return False
        for field in ('status', 'attempts', 'claimGeneration'):
            a.pop(field, None)
            b.pop(field, None)
        # A newly completed build can acquire its sealed artifact or failure
        # diagnostics. If already observed, that evidence must remain exact.
        for field in ('planDigest', 'errorCode', 'diagnostics'):
            if field in a and field in b and a[field] != b[field]:
                return False
            a.pop(field, None)
            b.pop(field, None)
    return left == right


async def _exact_replay(call, tool: str, arguments: dict, label: str) -> dict:
    try:
        first = await call(tool, arguments)
        replay = await call(tool, arguments)
    except Exception as error:
        raise RuntimeError("SAMPLE_OPERATION_FAILED:" + label + ":" + str(error)) from error
    if not _same_replay(first, replay, tool):
        raise RuntimeError("SAMPLE_REPLAY_MISMATCH:" + label)
    return first


async def _wait_job(call, scope: dict, job_id: str) -> dict:
    for _ in range(240):
        state = await call("read_v2_job", {**scope, "job_id": job_id})
        if state.get("status") in TERMINAL_JOBS:
            if state["status"] != "published":
                raise RuntimeError("SAMPLE_JOB_FAILED:" + state["status"])
            return state
        await asyncio.sleep(.25)
    raise RuntimeError("SAMPLE_JOB_TIMEOUT")


async def _wait_rule(call, scope: dict, workflow_id: str) -> dict:
    program = {"languageVersion": 2, "function": "application.rule.run.read",
               "arguments": {"workflowId": workflow_id}}
    for _ in range(480):
        state = await call("read_v2_program", {**scope, "program": program})
        result = state.get("result", {})
        if result.get("status") in TERMINAL_RULES:
            if result["status"] != "published":
                raise RuntimeError("SAMPLE_RULE_FAILED:" + result["status"])
            return result
        await asyncio.sleep(.25)
    raise RuntimeError("SAMPLE_RULE_TIMEOUT")


async def apply_sample(application: dict, workspace_id: str, call) -> dict:
    """Apply and verify one validated sample through public router tools only."""
    scope = {"workspace_id": workspace_id,
             "application_id": application["applicationId"]}
    metadata = build_metadata_plan(application)
    metadata_receipts = []
    for operation in metadata.operations:
        value = await _exact_replay(call, "execute_v2_metadata_program", {
            **scope, "program": operation["program"],
            "idempotency_key": operation["idempotencyKey"]},
            operation["idempotencyKey"])
        metadata_receipts.append(value)

    prefix = "programmable-uat-v1-" + application["applicationId"]
    environment = await active_environment(call, scope, key_prefix=prefix)
    definition_receipts = []
    for definition in application["memberLists"]:
        definition_receipts.append(await save_named_selection(call, scope,
            definition=definition,
            key_prefix=prefix + "-list-" + definition["listId"]))
    grid = application["grid"]
    grid_definition={**grid["definition"],"selection":{
        **grid["definition"]["selection"],
        "metadataRevision":metadata.final_revision}}
    await _exact_replay(call, "execute_v2_metadata_program", {**scope,
        "program": {"languageVersion": 2, "function": "grid.definition.save",
            "arguments": {"gridId":grid["gridId"],
                "definition":grid_definition,
                "expectedMetadataRevision": metadata.final_revision}},
        "idempotency_key": prefix + "-grid-" + grid["gridId"]}, prefix + "-grid")

    calculated_receipts = []
    for definition in build_calculated_member_definitions(application,
            metadata_revision=metadata.final_revision):
        calculated_receipts.append(await author_and_activate(call, scope,
            program_id="source-calculated-" + definition["definitionId"],
            source=calculated_member_source(definition),
            declared_output={"kind":"CalculatedMember","definitionId":definition["definitionId"]},
            key_prefix=prefix + "-calculated-" + definition["definitionId"], environment=environment))

    definition, bindings = build_substantial_application_rule(application)
    rule_id = application["applicationId"] + ".full-rule"
    rule_source = await author_and_activate(call, scope,
        program_id="source-rule-" + rule_id,
        source=application_rule_source(rule_id, definition),
        declared_output={"kind":"ApplicationRule","definitionId":rule_id},
        key_prefix=prefix + "-rule", environment=environment, definition_parameters=bindings)
    current = (await call("read_v2_program", {**scope, "program": {
        "languageVersion": 2, "function": "application.rule.read",
        "arguments": {"ruleId": rule_id}}}))["result"]
    rule_activation = {"operationId": current["updatedOperationId"],
        "status": current["status"],
        "active": current["active"],
        "executable": current["executable"],
        "stateToken": current["stateToken"],
        "programDigest": current["programDigest"]}
    accepted = await _exact_replay(call, "execute_v2_expression_rule_program", {**scope,
        "program": {"languageVersion": 2, "function": "application.rule.run",
            "arguments": {"ruleId": rule_id, "bindings": bindings,
                "expectedStateToken": current["stateToken"],
                "expectedProgramDigest": current["programDigest"]}},
        "idempotency_key": prefix + "-rule-run"}, prefix + "-rule-run")
    workflow_id = accepted["result"]["workflowId"]
    rule_result = await _wait_rule(call, scope, workflow_id)

    calculated_results = []
    for descriptor in application["calculatedMembers"]:
        compiled = (await call("read_v2_program", {**scope, "program": {
            "languageVersion": 2, "function": "calculated.member.read",
            "arguments": {"definitionId": descriptor["definitionId"]}}}))["result"]
        exact = {"definitionId": descriptor["definitionId"],
                 "expectedStateToken": compiled["stateToken"],
                 "expectedProgramDigest": compiled["programDigest"]}
        if descriptor["evaluation"] == "dynamic":
            result = await call("read_v2_program", {**scope,
                "program": {"languageVersion": 2,
                    "function": "calculated.member.evaluate",
                    "arguments": exact}})
            if not result.get("result", {}).get("dynamic"):
                raise RuntimeError("SAMPLE_DYNAMIC_RESULT_INVALID")
            calculated_results.append(result["result"])
            continue
        program = {"languageVersion": 2,
            "function": "calculated.member.materialize",
            "arguments": exact}
        preview = await call("preview_v2_program", {**scope, "program": program})
        token = preview.get("previewToken")
        if not isinstance(token, str) or not token:
            raise RuntimeError("SAMPLE_MATERIALIZE_PREVIEW_INVALID")
        submitted = await call("submit_v2_program", {**scope, "program": program,
            "preview_token": token,
            "idempotency_key": "programmable-uat-v1-" +
                application["applicationId"] + "-materialize-" +
                descriptor["definitionId"]})
        job_id = submitted.get("jobId")
        if not isinstance(job_id, str) or not job_id:
            raise RuntimeError("SAMPLE_MATERIALIZE_JOB_MISSING")
        calculated_results.append(await _wait_job(call, scope, job_id))

    list_results = []
    for definition in application["memberLists"]:
        value = await call("read_v2_program", {**scope,
            "program": {"languageVersion": 2,
                "function": "metadata.member_list.evaluate",
                "arguments": {"listId": definition["listId"],
                    "parameters": {},
                    "expectedMetadataRevision": metadata.final_revision}}})
        if not value.get("result", {}).get("memberIds"):
            raise RuntimeError("SAMPLE_MEMBER_LIST_EMPTY")
        list_results.append(value["result"])
    grid = application["grid"]
    grid_result = await call("read_v2_program", {**scope,
        "program": {"languageVersion": 2, "function": "grid.definition.read",
            "arguments": {"gridId": grid["gridId"]}}})
    if grid_result.get("result",{}).get("definition")!=grid_definition:
        raise RuntimeError("SAMPLE_GRID_DEFINITION_DRIFT")
    final_state = await call("read_v2_program", {**scope,
        "program": {"languageVersion": 2, "function": "application.state.read",
                    "arguments": {}}})
    state = final_state.get("result", {})
    if (state.get("metadataRevision") != metadata.final_revision
            or state.get("status") != "Active"):
        raise RuntimeError("SAMPLE_FINAL_STATE_INVALID")
    return {"applicationId": application["applicationId"],
        "metadataRevision": metadata.final_revision,
        "policyRevision": state["policyRevision"],
        "metadataOperationCount": len(metadata_receipts),
        "definitionOperationCount": len(definition_receipts),
        "calculatedMemberOperationCount": len(calculated_receipts),
        "workflowId": workflow_id,
        "workflowStatus": rule_result["status"],
        "ruleId": application["applicationId"] + ".full-rule",
        "ruleBindings": bindings,
        "ruleSource": rule_source,
        "ruleArgumentsDigest": rule_result.get("argumentsDigest"),
        "ruleActivation": {key: rule_activation[key] for key in (
            "operationId", "status", "active", "executable", "stateToken",
            "programDigest")},
        "rulePrimitiveCount": rule_result.get("operationCount", 14),
        "calculatedResultCount": len(calculated_results),
        "memberListResultCount": len(list_results),
        "gridId": grid_result.get("result", {}).get("gridId"),
        "databaseAccess": False, "exactReplayChecked": True}


def prepare(manifest: object, workspace_id: str, output: Path) -> dict:
    if IDENTIFIER.fullmatch(workspace_id) is None or not output.is_absolute():
        raise ValueError("SAMPLE_PROVISION_SCOPE_INVALID")
    value = validate_sample_manifest(manifest)
    return {"format": "openepm-programmable-uat-sample-provision-v1",
        "workspaceId": workspace_id, "contractDigest": contract_digest(value),
        "applications": value["applications"], "output": str(output),
        "publicMcpOnly": True, "databaseAccess": False,
        "businessMutationPerformed": False}


async def execute(plan: dict) -> dict:
    storage = MemoryStorage()
    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)
    provider = OAuthClientProvider(
        ENDPOINTS["application"], OAuthClientMetadata(
            client_name="Open EPM programmable UAT sample provisioner",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"), storage,
        redirect_handler=redirect_handler, callback_handler=receive_callback)
    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                ENDPOINTS["application"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()
                tools = {tool.name for tool in (await session.list_tools()).tools}
                required = {"execute_v2_metadata_program",
                    "execute_v2_expression_rule_program", "preview_v2_program",
                    "submit_v2_program", "read_v2_job", "read_v2_program"}
                if not required <= tools:
                    raise RuntimeError("SAMPLE_PUBLIC_TOOLS_UNAVAILABLE")
                async def call(tool: str, arguments: dict) -> dict:
                    return response(await session.call_tool(tool, arguments))
                applications = [await apply_sample(application,
                    plan["workspaceId"], call) for application in plan["applications"]]
    return {**plan, "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed", "applications": applications,
        "businessMutationPerformed": True,
        "mutationBoundary": "authorized fixed-core public application MCP",
        "applicationMcp": {"serverName": initialized.server_info.name,
            "singleSession": True, "oauthTokenRetained": False,
            "identityValueRetained": False}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = prepare(json.loads(arguments.manifest.read_text(encoding="utf-8")),
                       arguments.workspace_id, arguments.output)
        if not arguments.execute:
            print(json.dumps({key: value for key, value in plan.items()
                              if key != "applications"}, sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        parser.error(str(error))
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
    print(json.dumps({"passed": True,
        "applicationCount": len(result["applications"]),
        "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
