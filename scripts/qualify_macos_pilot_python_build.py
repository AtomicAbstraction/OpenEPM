#!/usr/bin/env python3
"""Qualify the live MCP -> gVisor builder -> sealed-plan -> worker journey.

The script retains OAuth tokens only in memory and performs every product-state
change through the public application MCP endpoint.  It never connects to the
database or invokes the trusted sandbox launcher directly.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from hashlib import sha256
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
HEX32 = re.compile(r"^[0-9a-f]{32}$")
TERMINAL_BUILD = frozenset({"sealed", "failed", "cancelled"})
TERMINAL_WORKFLOW = frozenset({
    "published", "partially_published", "failed", "cancelled",
    "needs_inspection",
})
SOURCE = (
    "from openepm import Program\n"
    "def build(context, parameters):\n"
    "    return Program.one('facts.numeric.batch', "
    "{'mutations': parameters['mutations']}, name='pilot-python')\n"
)
# Pins on the first public environment registration in this established pilot.
# They are used only to replay its immutable receipt after later policy writes;
# a fresh installation registers against its current pins instead.
PILOT_ENVIRONMENT_TARGET_ORIGINAL_PINS = {
    "expectedMetadataRevision": 34,
    "expectedPolicyRevision": 22,
    "expectedSchemaEpoch": 5,
}
TARGETS = (
    {"Scenario": "Plan", "Year": "FY27", "Period": "P4",
     "Department": "DeptB", "Account": "Extra"},
    {"Scenario": "Rolling", "Year": "FY27", "Period": "P4",
     "Department": "DeptB", "Account": "Extra"},
    {"Scenario": "Plan", "Year": "FY27", "Period": "P4",
     "Department": "DeptA", "Account": "Extra"},
)


def validate(workspace_id: str, application_id: str, output: Path,
             *, qualification_id: str = "pilot-python-live5") -> dict[str, object]:
    if IDENTIFIER.fullmatch(workspace_id) is None:
        raise ValueError("workspace ID is invalid")
    if IDENTIFIER.fullmatch(application_id) is None:
        raise ValueError("application ID is invalid")
    if not output.is_absolute():
        raise ValueError("output must be absolute")
    if IDENTIFIER.fullmatch(qualification_id) is None:
        raise ValueError("qualification ID is invalid")
    return {
        "format": "openepm-macos-pilot-python-build-plan-v1",
        "workspaceId": workspace_id,
        "applicationId": application_id,
        "profileId": "openepm-python-1:v3",
        "environmentId": "openepm-python-1",
        "environmentVersion": 3,
        "programId": "pilot-python-live2",
        "programVersion": 3,
        "qualificationId": qualification_id,
        "publicMcpOnly": True,
        "databaseAccess": False,
        "sandboxRuntimeExpected": "runsc",
        "output": str(output),
    }


def tool_error(value) -> str:
    if not value.is_error:
        raise RuntimeError("MCP tool unexpectedly succeeded")
    return repr(value.content)


def pins(state: dict) -> dict[str, int]:
    names = ("metadataRevision", "policyRevision", "schemaEpoch")
    if any(type(state.get(name)) is not int or state[name] < 0
           for name in names):
        raise RuntimeError("application revision pins are invalid")
    return {"expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": state["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]}


def next_pins(current: dict, result: dict) -> dict:
    updated = dict(current)
    for name in ("metadataRevision", "policyRevision", "schemaEpoch"):
        if name in result:
            updated[name] = result[name]
    return updated


def exact_row(rows: list[dict], coordinate: dict[str, str]) -> dict | None:
    matches = [row for row in rows
               if (row.get("coordinate") or row.get("members")) == coordinate]
    if len(matches) > 1:
        raise RuntimeError("cube scan returned duplicate exact coordinates")
    return matches[0] if matches else None


def exact_amount(row: dict | None) -> Decimal | None:
    if row is None:
        return None
    value = row.get("value")
    if (type(value) is dict and value.get("type") == "AmountLiteral"
            and type(value.get("decimal")) is str):
        raw = value["decimal"]
    elif (value is None and row.get("kind") == "numeric"
          and row.get("present") is True and type(row.get("amount")) is str):
        raw = row["amount"]
    else:
        raise RuntimeError("cube scan did not return a typed amount; row keys="
                           + repr(sorted(row)) + ", value type="
                           + type(value).__name__)
    try:
        return Decimal(raw)
    except InvalidOperation as error:
        raise RuntimeError("cube scan returned an invalid exact amount") from error


def stable_build_id(scope: dict[str, str], identity: dict,
                    idempotency_key: str) -> str:
    """Mirror the public, owner-bound build identity for crash recovery."""
    issuer = identity.get("issuer")
    subject_id = identity.get("subjectId")
    if (set(scope) != {"workspace_id", "application_id"}
            or any(type(scope[name]) is not str for name in scope)
            or type(issuer) is not str or type(subject_id) is not str
            or type(idempotency_key) is not str):
        raise RuntimeError("build identity inputs are invalid")
    raw = json.dumps({
        "domain": "openepm-python-build-v1",
        "scope": [scope["workspace_id"], scope["application_id"]],
        "identity": [issuer, subject_id],
        "idempotencyKey": idempotency_key,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return sha256(raw).hexdigest()[:32]


def single_numeric_mutation(plan: object) -> dict:
    """Return the one mutation this bounded qualification is allowed to seal."""
    if (type(plan) is not dict or plan.get("format") != "openepm-python-plan-v1"
            or type(plan.get("units")) is not list or len(plan["units"]) != 1):
        raise RuntimeError("sealed plan does not contain one atomic unit")
    operations = plan["units"][0].get("operations")
    if type(operations) is not list or len(operations) != 1:
        raise RuntimeError("sealed plan does not contain one operation")
    operation = operations[0]
    if (type(operation) is not dict
            or operation.get("languageVersion") != 2
            or operation.get("function") != "facts.numeric.batch"
            or type(operation.get("arguments")) is not dict):
        raise RuntimeError("sealed plan operation is not the approved numeric batch")
    mutations = operation["arguments"].get("mutations")
    if type(mutations) is not list or len(mutations) != 1:
        raise RuntimeError("sealed plan does not contain one numeric mutation")
    mutation = mutations[0]
    if (type(mutation) is not dict or set(mutation) != {
            "coordinate", "op", "value", "expectedChangeId"}
            or mutation.get("op") != "set"
            or type(mutation.get("coordinate")) is not dict
            or type(mutation.get("expectedChangeId")) is not str):
        raise RuntimeError("sealed numeric mutation is invalid")
    exact_amount({"value": mutation.get("value")})
    return mutation


async def poll_build(call, scope: dict, build_id: str, *, attempts: int = 90) -> dict:
    if HEX32.fullmatch(build_id) is None:
        raise RuntimeError("build ID is invalid")
    value = None
    for _ in range(attempts):
        value = await call("read_v2_python_program_build", {
            **scope, "build_id": build_id})
        if value.get("status") in TERMINAL_BUILD:
            return value
        await asyncio.sleep(1)
    raise RuntimeError("Python build did not reach a terminal state: " + repr(value))


async def poll_workflow(call, scope: dict, workflow_id: str,
                        *, attempts: int = 120) -> dict:
    if HEX32.fullmatch(workflow_id) is None:
        raise RuntimeError("workflow ID is invalid")
    value = None
    for _ in range(attempts):
        value = await call("read_v2_python_program_workflow", {
            **scope, "workflow_id": workflow_id})
        if value.get("status") in TERMINAL_WORKFLOW:
            return value
        await asyncio.sleep(1)
    raise RuntimeError("Python workflow did not reach a terminal state: " + repr(value))


async def read_artifact(call, scope: dict, build_id: str,
                        section: str) -> tuple[dict, bytes]:
    cursor = None
    offset = 0
    chunks: list[bytes] = []
    first = None
    while True:
        page = await call("read_v2_python_program_build_artifact", {
            **scope, "build_id": build_id, "section": section,
            "cursor": cursor})
        first = first or page
        if page.get("offset") != offset:
            raise RuntimeError("artifact page offset changed")
        chunk = base64.b64decode(page["chunkBase64"], validate=True)
        chunks.append(chunk)
        offset += len(chunk)
        cursor = page.get("nextCursor")
        if cursor is None:
            break
    raw = b"".join(chunks)
    if (offset != first.get("totalBytes")
            or sha256(raw).hexdigest() != first.get("sectionDigest")):
        raise RuntimeError("artifact digest verification failed")
    return first, raw


async def execute(plan: dict[str, object]) -> dict[str, object]:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot Python-build qualification",
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
                ENDPOINTS["application"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()

                async def call(tool: str, arguments: dict) -> dict:
                    nonlocal call_count
                    call_count += 1
                    return response(await session.call_tool(tool, arguments))

                state = (await call("read_v2_program", {
                    **scope, "program": program(
                        "application.capabilities.read", {})}))["result"]
                identity = (await call("read_v2_program", {
                    **scope, "program": program(
                        "security.identity.current.read", {})}))["result"]
                if identity.get("verifiedByServer") is not True:
                    raise RuntimeError("current identity was not server verified")

                invalid = await session.call_tool(
                    "execute_v2_python_program_registry", {
                        **scope, "program": program(
                            "python.environment.register", {
                                "environmentId": "unapproved-python",
                                "version": 1,
                                "profileId": "caller-controlled-profile",
                                **pins(state),
                            }),
                        "idempotency_key": "pilot-python-environment-invalid",
                    })
                call_count += 1
                invalid_error = tool_error(invalid)
                if "PYTHON_ENVIRONMENT_ARGUMENT_INVALID" not in invalid_error:
                    raise RuntimeError("unknown deployment profile did not fail closed")

                register_arguments = {
                    "environmentId": plan["environmentId"],
                    "version": plan["environmentVersion"],
                    "profileId": plan["profileId"],
                    **pins(state),
                }
                register_request = {
                    **scope, "program": program(
                        "python.environment.register", register_arguments),
                    "idempotency_key": (
                        "pilot-python-environment-register-v"
                        + str(plan["environmentVersion"])),
                }
                raw_registration = await session.call_tool(
                    "execute_v2_python_program_registry", register_request)
                call_count += 1
                registration_was_fresh = not raw_registration.is_error
                if raw_registration.is_error:
                    if "PYTHON_ENVIRONMENT_IDEMPOTENCY_CONFLICT" not in repr(
                            raw_registration.content):
                        raise RuntimeError("environment registration failed: "
                                           + repr(raw_registration.content))
                    register_request["program"] = program(
                        "python.environment.register", {
                            "environmentId": plan["environmentId"],
                            "version": plan["environmentVersion"],
                            "profileId": plan["profileId"],
                            **PILOT_ENVIRONMENT_TARGET_ORIGINAL_PINS,
                        })
                    registered = await call(
                        "execute_v2_python_program_registry", register_request)
                else:
                    registered = response(raw_registration)
                replayed_registration = await call(
                    "execute_v2_python_program_registry", register_request)
                if registered != replayed_registration:
                    raise RuntimeError("environment registration replay changed")
                if registration_was_fresh:
                    state = next_pins(state, registered["result"])

                observed_program = (await call("read_v2_program", {
                    **scope, "program": program("python.program.read", {
                        "programId": plan["programId"],
                        "version": plan["programVersion"],
                    })})) ["result"]
                if observed_program.get("defined"):
                    expected_program = {
                        "version": plan["programVersion"], "sourceText": SOURCE,
                        "entryPoint": "build",
                        "parameterSchema": {"type": "object"},
                        "environmentId": plan["environmentId"],
                        "environmentVersion": plan["environmentVersion"],
                    }
                    mismatched = [name for name, expected in
                        expected_program.items()
                        if observed_program.get(name) != expected]
                    if mismatched:
                        raise RuntimeError("existing pilot program differs: "
                                           + ", ".join(mismatched))
                else:
                    saved = await call("execute_v2_python_program_registry", {
                        **scope, "program": program("python.program.save", {
                            "programId": plan["programId"],
                            "version": plan["programVersion"],
                            "sourceText": SOURCE, "entryPoint": "build",
                            "parameterSchema": {"type": "object"},
                            "environmentId": plan["environmentId"],
                            "environmentVersion": plan["environmentVersion"],
                            **pins(state),
                        }),
                        "idempotency_key": (
                            "pilot-python-live2-v"
                            + str(plan["programVersion"]) + "-save"),
                    })
                    state = next_pins(state, saved["result"])
                    observed_program = {"status": "Saved"}
                if observed_program.get("status") != "Published":
                    published = await call(
                        "execute_v2_python_program_registry", {
                            **scope, "program": program(
                                "python.program.publish", {
                                    "programId": plan["programId"],
                                    "version": plan["programVersion"],
                                    **pins(state),
                                }),
                            "idempotency_key": (
                                "pilot-python-live2-v"
                                + str(plan["programVersion"]) + "-publish"),
                        })
                    state = next_pins(state, published["result"])

                observed_delegation = (await call("read_v2_program", {
                    **scope, "program": program("execution.delegation.read", {
                        "delegationId": "pilot-python-live2",
                    })})) ["result"]
                if observed_delegation.get("defined"):
                    delegation_record = observed_delegation["delegation"]
                    if (delegation_record.get("latest_version") != 1
                            or delegation_record.get("active_version") != 1
                            or delegation_record.get("issuer") != identity["issuer"]
                            or delegation_record.get("subject_id") !=
                                identity["subjectId"]
                            or set(delegation_record.get("operation_scope", [])) !=
                                {"python.program.build", "python.program.run"}):
                        raise RuntimeError(
                            "existing pilot delegation differs from qualification")
                else:
                    delegation = await call(
                        "execute_v2_execution_delegation", {
                            **scope, "program": program(
                                "execution.delegation.create", {
                                    "delegationId": "pilot-python-live2",
                                    "version": 1,
                                    "issuer": identity["issuer"],
                                    "subjectId": identity["subjectId"],
                                    "operationScope": ["python.program.build",
                                                       "python.program.run"],
                                    "validFrom": "2026-01-01T00:00:00+00:00",
                                    "validUntil": "2030-01-01T00:00:00+00:00",
                                    "scheduleId": None,
                                    "scheduleVersion": None,
                                    **pins(state),
                                }),
                            "idempotency_key":
                                "pilot-python-live2-delegation",
                        })
                    state = next_pins(state, delegation["result"])

                build_key = plan["qualificationId"] + "-build"
                expected_build_id = stable_build_id(scope, identity, build_key)
                recovered = False
                try:
                    accepted = await call("read_v2_python_program_build", {
                        **scope, "build_id": expected_build_id})
                    recovered = True
                except RuntimeError as error:
                    if "PYTHON_BUILD_UNAVAILABLE" not in str(error):
                        raise
                    target = None
                    prior = None
                    for candidate in TARGETS:
                        scan = (await call("read_v2_program", {
                            **scope, "program": program("facts.cube.scan", {
                                "members": candidate, "limit": 2})}))["result"]
                        row = exact_row(scan.get("rows", []), candidate)
                        if row is None:
                            target, prior = candidate, None
                            break
                    if target is None:
                        target = TARGETS[0]
                        scan = (await call("read_v2_program", {
                            **scope, "program": program("facts.cube.scan", {
                                "members": target, "limit": 2})}))["result"]
                        prior = exact_row(scan.get("rows", []), target)
                    expected_change = "" if prior is None else prior["changeId"]
                    prior_amount = exact_amount(prior)
                    value = ("123.456" if prior_amount != Decimal("123.456")
                             else "124.456")
                    parameters = {"mutations": [{
                        "coordinate": target, "op": "set",
                        "value": {"type": "AmountLiteral", "decimal": value},
                        "expectedChangeId": expected_change,
                    }]}
                    build_program = program("python.program.build", {
                        "programId": plan["programId"],
                        "programVersion": plan["programVersion"],
                        "parameters": parameters,
                        "delegationId": "pilot-python-live2",
                        "delegationVersion": 1,
                        "scheduleId": None, "scheduleVersion": None,
                        **pins(state),
                    })
                    build_request = {**scope, "program": build_program,
                        "idempotency_key": build_key}
                    accepted = (await call(
                        "execute_v2_python_program_build", build_request))["result"]
                    replayed_build = (await call(
                        "execute_v2_python_program_build", build_request))["result"]
                    if accepted["buildId"] != replayed_build["buildId"]:
                        raise RuntimeError("build admission replay changed identity")
                if accepted["buildId"] != expected_build_id:
                    raise RuntimeError("public build identity derivation changed")
                build = await poll_build(call, scope, accepted["buildId"])
                if build.get("status") != "sealed":
                    raise RuntimeError("real sandbox build did not seal: " + repr(build))
                artifact, raw_plan = await read_artifact(
                    call, scope, build["buildId"], "Plan")
                decoded_plan = json.loads(raw_plan)
                if (artifact.get("planDigest") != build.get("planDigest")
                        or decoded_plan.get("format") != "openepm-python-plan-v1"):
                    raise RuntimeError("sealed public plan evidence is invalid")
                mutation = single_numeric_mutation(decoded_plan)
                target = mutation["coordinate"]
                value = mutation["value"]["decimal"]

                run_request = {**scope,
                    "program": program("python.program.run", {
                        "buildId": build["buildId"]}),
                    "idempotency_key": plan["qualificationId"] + "-run"}
                running = (await call(
                    "execute_v2_python_program_run", run_request))["result"]
                replayed_run = (await call(
                    "execute_v2_python_program_run", run_request))["result"]
                if running["workflowId"] != replayed_run["workflowId"]:
                    raise RuntimeError("workflow replay changed identity")
                workflow = await poll_workflow(
                    call, scope, running["workflowId"])
                if (workflow.get("status") != "published"
                        or workflow.get("committedUnits") != 1):
                    raise RuntimeError("sealed plan did not publish exactly one unit: "
                                       + repr(workflow))
                final_scan = (await call("read_v2_program", {
                    **scope, "program": program("facts.cube.scan", {
                        "members": target, "limit": 2})}))["result"]
                final_row = exact_row(final_scan.get("rows", []), target)
                if exact_amount(final_row) != Decimal(value):
                    raise RuntimeError("Python-published value was not readable")

                cancel_program = program("python.program.build", {
                    "programId": plan["programId"],
                    "programVersion": plan["programVersion"],
                    "parameters": {"mutations": [mutation]},
                    "delegationId": "pilot-python-live2",
                    "delegationVersion": 1,
                    "scheduleId": None, "scheduleVersion": None,
                    **pins(state),
                })
                cancel_request = {**scope, "program": cancel_program,
                    "idempotency_key": plan["qualificationId"] + "-cancel"}
                cancel_build = (await call(
                    "execute_v2_python_program_build", cancel_request))["result"]
                try:
                    cancelled = await call("cancel_v2_python_program_build", {
                        **scope, "build_id": cancel_build["buildId"]})
                except RuntimeError:
                    cancelled = await poll_build(call, scope,
                                                 cancel_build["buildId"])
                if cancelled.get("status") not in {"cancelled", "cancel_requested"}:
                    raise RuntimeError("build cancellation lost its race: "
                                       + repr(cancelled))
                cancelled = await poll_build(call, scope, cancel_build["buildId"])
                if cancelled.get("status") != "cancelled":
                    raise RuntimeError("cancelled build reached an effectful state")

    return {
        **plan,
        "format": "openepm-macos-pilot-python-build-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "serverName": initialized.server_info.name,
        "recoveredAcceptedBuild": recovered,
        "unknownProfileRejected": True,
        "environmentRegistrationReplayIdentical": True,
        "deploymentOwnedImageDigest": registered["result"]["imageDigest"],
        "buildId": build["buildId"],
        "buildStatus": build["status"],
        "buildAttemptCount": build["attempts"],
        "sealedPlanDigest": build["planDigest"],
        "sealedPlanUnitCount": artifact["unitCount"],
        "workflowId": workflow["workflowId"],
        "workflowStatus": workflow["status"],
        "committedUnits": workflow["committedUnits"],
        "targetCoordinate": target,
        "publishedValue": value,
        "cancelledBuildId": cancelled["buildId"],
        "cancelledBuildStatus": cancelled["status"],
        "mcpCallCount": call_count,
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "identityValueRetained": False,
        "directDatabaseAccess": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--qualification-id", default="pilot-python-live5")
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(arguments.workspace_id, arguments.application_id,
                        arguments.output,
                        qualification_id=arguments.qualification_id)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
    except (ValueError, RuntimeError) as error:
        parser.error(str(error))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "output": str(arguments.output)},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
