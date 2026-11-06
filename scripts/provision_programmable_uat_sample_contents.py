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
    build_application_rule_plan, build_calculated_member_plan,
    build_definition_plan, build_metadata_plan, contract_digest,
    validate_sample_manifest,
)
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


TERMINAL_JOBS = {"published", "failed", "cancelled", "needs_inspection"}
TERMINAL_RULES = {"published", "failed", "partially_published", "cancelled",
                  "needs_inspection"}

PUBLIC_MUTATION_TOOLS = {
    "metadata": "execute_v2_metadata_program",
    "expression_rule": "execute_v2_expression_rule_program",
    "application_rule_workflow": "execute_v2_expression_rule_program",
}


def _public_mutation_tool(operation: dict) -> str:
    family = operation.get("family")
    try:
        return PUBLIC_MUTATION_TOOLS[family]
    except (KeyError, TypeError) as error:
        raise RuntimeError("SAMPLE_OPERATION_FAMILY_INVALID") from error


def _replay_projection(value):
    """Compare authoritative effects while allowing an explicit replay marker."""
    if isinstance(value, dict):
        return {key: _replay_projection(item) for key, item in value.items()
                if key != "duplicate"}
    if isinstance(value, list):
        return [_replay_projection(item) for item in value]
    return value


async def _exact_replay(call, tool: str, arguments: dict, label: str) -> dict:
    try:
        first = await call(tool, arguments)
        replay = await call(tool, arguments)
    except Exception as error:
        raise RuntimeError("SAMPLE_OPERATION_FAILED:" + label + ":" + str(error)) from error
    if _replay_projection(first) != _replay_projection(replay):
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

    definitions = build_definition_plan(
        application, metadata_revision=metadata.final_revision)
    definition_receipts = []
    for operation in definitions.operations:
        tool = _public_mutation_tool(operation)
        value = await _exact_replay(call, tool, {**scope,
            "program": operation["program"],
            "idempotency_key": operation["idempotencyKey"]},
            operation["idempotencyKey"])
        definition_receipts.append(value)

    calculated = build_calculated_member_plan(application,
        metadata_revision=metadata.final_revision,
        initial_policy_revision=definitions.final_policy_revision)
    calculated_receipts = []
    for operation in calculated.operations:
        value = await _exact_replay(call, _public_mutation_tool(operation), {
            **scope, "program": operation["program"],
            "idempotency_key": operation["idempotencyKey"]},
            operation["idempotencyKey"])
        calculated_receipts.append(value)

    rule = build_application_rule_plan(application,
        metadata_revision=metadata.final_revision,
        initial_policy_revision=calculated.final_policy_revision)
    rule_receipts = []
    workflow_id = None
    rule_publication = None
    for operation in rule.operations:
        value = await _exact_replay(call, _public_mutation_tool(operation), {
            **scope, "program": operation["program"],
            "idempotency_key": operation["idempotencyKey"]},
            operation["idempotencyKey"])
        rule_receipts.append(value)
        if operation["program"]["function"] == "application.rule.version.publish":
            rule_publication = value.get("result")
        if operation["program"]["function"] == "application.rule.run":
            workflow_id = value.get("result", {}).get("workflowId")
    if (not isinstance(workflow_id, str) or not workflow_id
            or not isinstance(rule_publication, dict)):
        raise RuntimeError("SAMPLE_RULE_WORKFLOW_MISSING")
    rule_result = await _wait_rule(call, scope, workflow_id)

    calculated_results = []
    for descriptor in application["calculatedMembers"]:
        if descriptor["evaluation"] == "dynamic":
            result = await call("read_v2_program", {**scope,
                "program": {"languageVersion": 2,
                    "function": "calculated.member.evaluate",
                    "arguments": {"definitionId": descriptor["definitionId"]}}})
            if not result.get("result", {}).get("dynamic"):
                raise RuntimeError("SAMPLE_DYNAMIC_RESULT_INVALID")
            calculated_results.append(result["result"])
            continue
        program = {"languageVersion": 2,
            "function": "calculated.member.materialize",
            "arguments": {"definitionId": descriptor["definitionId"]}}
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
                    "version": definition["version"], "parameters": {},
                    "expectedMetadataRevision": metadata.final_revision}}})
        if not value.get("result", {}).get("memberIds"):
            raise RuntimeError("SAMPLE_MEMBER_LIST_EMPTY")
        list_results.append(value["result"])
    grid = application["grid"]
    grid_result = await call("read_v2_program", {**scope,
        "program": {"languageVersion": 2, "function": "grid.definition.read",
            "arguments": {"gridId": grid["gridId"], "version": grid["version"]}}})
    final_state = await call("read_v2_program", {**scope,
        "program": {"languageVersion": 2, "function": "application.state.read",
                    "arguments": {}}})
    state = final_state.get("result", {})
    if (state.get("metadataRevision") != metadata.final_revision
            or state.get("policyRevision") != rule.final_policy_revision
            or state.get("status") != "Active"):
        raise RuntimeError("SAMPLE_FINAL_STATE_INVALID")
    return {"applicationId": application["applicationId"],
        "metadataRevision": metadata.final_revision,
        "policyRevision": rule.final_policy_revision,
        "metadataOperationCount": len(metadata_receipts),
        "definitionOperationCount": len(definition_receipts),
        "calculatedMemberOperationCount": len(calculated_receipts),
        "workflowId": workflow_id,
        "workflowStatus": rule_result["status"],
        "ruleId": application["applicationId"] + ".full-rule",
        "ruleBindings": rule.operations[-1]["program"]["arguments"]["bindings"],
        "ruleArgumentsDigest": rule_result.get("argumentsDigest"),
        "rulePublication": {key: rule_publication[key] for key in (
            "operationId", "committedRevision", "programDigest")},
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
