#!/usr/bin/env python3
"""Public-MCP clean-host proof for isolated Python build and publication."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import stat
import sys
import time
import urllib.parse


HEX64 = re.compile(r"^[a-f0-9]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
REQUEST_PREFIX = re.compile(r"^[A-Za-z0-9._-]{8,96}$")


class ProbeError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def exact_json(value: object) -> bool:
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(type(key) is str and exact_json(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return all(exact_json(item) for item in value)
    return value is None or type(value) in (str, int, bool)


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ProbeError(f"{field} is invalid")
    return value


def _https(value: object) -> str:
    try:
        parsed = urllib.parse.urlsplit(value) if isinstance(value, str) else None
        port = parsed.port if parsed is not None else None
    except ValueError as error:
        raise ProbeError("mcpEndpoint is invalid") from error
    if (parsed is None or parsed.scheme != "https" or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or port == 0
            or not parsed.path.startswith("/")):
        raise ProbeError("mcpEndpoint must be credential-free HTTPS")
    return value


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid Python publication probe configuration: {error}") \
            from error
    expected = {"format", "builderImage", "mcpEndpoint", "workspaceId",
        "applicationId", "programId", "environmentId",
        "environmentVersion", "delegationId",
        "executionIssuer", "executionSubjectId",
        "requestPrefix", "expectedSourceDigest", "expectedResult",
        "resultFunction", "resultArguments", "resultPath", "timeoutSeconds"}
    if not isinstance(value, dict) or set(value) != expected \
            or value.get("format") != "openepm-python-build-publication-probe-v3" \
            or not isinstance(value.get("builderImage"), str) \
            or not value["builderImage"].startswith("sha256:") \
            or HEX64.fullmatch(value["builderImage"][7:]) is None:
        raise ProbeError("Python publication probe configuration is invalid")
    value["mcpEndpoint"] = _https(value["mcpEndpoint"])
    for field in ("workspaceId", "applicationId", "programId", "environmentId",
                  "delegationId", "resultFunction"):
        _identifier(value.get(field), field)
    for field in ("executionIssuer", "executionSubjectId"):
        item = value.get(field)
        if not isinstance(item, str) or not item or len(item) > 300 \
                or any(ord(character) < 32 or ord(character) == 127
                       for character in item):
            raise ProbeError(f"{field} is invalid")
    for field in ("environmentVersion",):
        if type(value.get(field)) is not int or value[field] < 1:
            raise ProbeError(f"{field} is invalid")
    if not isinstance(value.get("requestPrefix"), str) \
            or REQUEST_PREFIX.fullmatch(value["requestPrefix"]) is None:
        raise ProbeError("requestPrefix is invalid")
    if not isinstance(value.get("expectedSourceDigest"), str) \
            or HEX64.fullmatch(value["expectedSourceDigest"]) is None:
        raise ProbeError("expectedSourceDigest is invalid")
    if not isinstance(value.get("expectedResult"), str) \
            or not value["expectedResult"] \
            or len(value["expectedResult"].encode("utf-8")) > 4096 \
            or any(character in value["expectedResult"] for character in "\r\n\x00"):
        raise ProbeError("expectedResult is invalid")
    if not isinstance(value.get("resultArguments"), dict) \
            or not exact_json(value["resultArguments"]) \
            or len(canonical(value["resultArguments"])) > 65536 \
            or not isinstance(value.get("resultPath"), list) \
            or not value["resultPath"] \
            or any(not isinstance(item, str) or not item or len(item) > 200
                   for item in value["resultPath"]):
        raise ProbeError("result read contract is invalid")
    if type(value.get("timeoutSeconds")) is not int \
            or not 10 <= value["timeoutSeconds"] <= 300:
        raise ProbeError("timeoutSeconds is invalid")
    return value


def token(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink() or not path.is_file() \
            or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProbeError("Python build token must be protected, regular and non-symbolic")
    value = path.read_text(encoding="utf-8").strip()
    if not value or len(value) > 16384 or any(character.isspace() for character in value):
        raise ProbeError("Python build token is invalid")
    return value


def _unwrap(value: object) -> dict:
    if not isinstance(value, dict):
        raise ProbeError("public MCP result is not an object")
    result = value.get("result", value)
    if not isinstance(result, dict):
        raise ProbeError("public MCP result payload is not an object")
    return result


def _pins(value: dict, application):
    try:
        from openepm import BuildContext
        return BuildContext(application, value["metadataRevision"],
                            value["policyRevision"], value["schemaEpoch"])
    except (KeyError, TypeError, ValueError) as error:
        raise ProbeError("application revision pins are unavailable") from error


def _wait(read, *, terminal: str, failed: set[str], deadline: float,
          sleeper=time.sleep, clock=time.monotonic) -> dict:
    while True:
        value = _unwrap(read())
        status = value.get("status")
        if status == terminal:
            return value
        if status in failed:
            raise ProbeError(f"public workflow terminated as {status}")
        if clock() >= deadline:
            raise ProbeError("public workflow did not reach its terminal state")
        sleeper(0.2)


def _path(value: object, path: list[str]) -> object:
    current = value
    for item in path:
        if isinstance(current, dict) and item in current:
            current = current[item]
        elif (isinstance(current, list) and item.isdecimal()
              and int(item) < len(current)):
            current = current[int(item)]
        else:
            raise ProbeError("configured resultPath is unavailable")
    return current


def default_client(endpoint: str, bearer: str):
    try:
        from openepm import EpmClient, HttpsMcpTransport
    except ImportError as error:
        raise ProbeError("the public openepm SDK is unavailable") from error
    return EpmClient(HttpsMcpTransport(endpoint, lambda: bearer,
        timeout_seconds=30, max_response_bytes=10_000_000))


def run(config: dict, bearer: str, source_text: str, *, client_factory=default_client,
        clock=time.monotonic, sleeper=time.sleep) -> dict:
    forbidden_before = {name for name in sys.modules
        if name == "epm_core" or name.startswith("epm_core.")
        or name == "psycopg" or name.startswith("psycopg.")}
    try:
        from openepm import Application
        from openepm.transport import McpTransportError
    except ImportError as error:
        raise ProbeError("the public openepm SDK is unavailable") from error
    application = Application(config["workspaceId"], config["applicationId"])
    client = client_factory(config["mcpEndpoint"], bearer)
    if (not isinstance(source_text, str) or not source_text
            or "\x00" in source_text or len(source_text.encode("utf-8")) > 1024 * 1024
            or sha256(source_text.encode("utf-8")).hexdigest()
                != config["expectedSourceDigest"]):
        raise ProbeError("qualification program source differs from its contract")
    state_before = _unwrap(client.read(
        application, "application.state.read", {}))
    context = _pins(state_before, application)
    environment = _unwrap(client.read(application, "python.environment.read",
        {"environmentId": config["environmentId"]}))
    if (environment.get("defined") is not True
            or not isinstance(environment.get("environment"), dict)
            or not isinstance(environment["environment"].get("stateToken"), str)):
        raise ProbeError("qualification Python environment is unavailable")
    environment_state_token = environment["environment"]["stateToken"]
    registered = _unwrap(client.read_python_program(application,
        config["programId"]))
    if registered.get("defined") is not True:
        saved = _unwrap(client.save_python_program(context,
            program_id=config["programId"],
            source_text=source_text, entry_point="build",
            parameter_schema={"type": "object", "additionalProperties": False},
            environment_id=config["environmentId"],
            environment_state_token=environment_state_token,
            request_key=config["requestPrefix"] + "-save"))
        context = _pins(saved, application)
        registered = _unwrap(client.read_python_program(application,
            config["programId"]))
    if (registered.get("sourceDigest") != config["expectedSourceDigest"]
            or registered.get("environmentId") != config["environmentId"]
            or registered.get("environmentVersion") != config["environmentVersion"]):
        raise ProbeError("qualification program identity is invalid")
    if registered.get("status") != "Active":
        validation = registered.get("validation")
        if (not isinstance(validation, dict) or validation.get("purpose") != "Validation"
                or not isinstance(validation.get("buildId"), str)):
            raise ProbeError("saved qualification source has no automatic Validation")
        validated = _wait(lambda: client.read_python_build(application, validation["buildId"]),
            terminal="sealed", failed={"failed", "cancelled", "expired"},
            deadline=clock() + config["timeoutSeconds"], sleeper=sleeper, clock=clock)
        if validated.get("purpose") != "Validation" or validated.get("buildId") != validation["buildId"]:
            raise ProbeError("qualification source Validation purpose differs")
        registered = _unwrap(client.read_python_program(application,
            config["programId"]))
        current = registered.get("validation", {})
        if (registered.get("sourceDigest") != config["expectedSourceDigest"]
                or current.get("buildId") != validation["buildId"]
                or current.get("purpose") != "Validation"
                or current.get("status") != "sealed" or current.get("current") is not True):
            raise ProbeError("qualification source Validation is not current")
        context = _pins(_unwrap(client.read(application, "application.state.read", {})), application)
        published = _unwrap(client.activate_python_program(context,
            program_id=config["programId"],
            expected_state_token=registered["stateToken"],
            request_key=config["requestPrefix"] + "-publish",
            validation_build_id=validation["buildId"]))
        context = _pins(published, application)
    delegation = _unwrap(client.read(application, "execution.delegation.read",
        {"delegationId": config["delegationId"]}))
    if delegation.get("defined") is not True:
        now = datetime.now(timezone.utc)
        client.create_execution_delegation(context,
            delegation_id=config["delegationId"],
            issuer=config["executionIssuer"],
            subject_id=config["executionSubjectId"],
            operation_scope=["python.program.build", "python.program.run"],
            valid_from=(now - timedelta(minutes=1)).isoformat(),
            valid_until=(now + timedelta(hours=2)).isoformat(),
            request_key=config["requestPrefix"] + "-delegation")
    else:
        item = delegation.get("delegation")
        if (not isinstance(item, dict)
                or item.get("status") != "Active"
                or item.get("issuer") != config["executionIssuer"]
                or item.get("subject_id") != config["executionSubjectId"]
                or item.get("operation_scope") != [
                    "python.program.build", "python.program.run"]):
            raise ProbeError("qualification execution delegation differs")
    state_ready = _unwrap(client.read(
        application, "application.state.read", {}))
    context = _pins(state_ready, application)
    prefix = config["requestPrefix"]
    registered = _unwrap(client.read_python_program(application,
        config["programId"]))
    delegation = _unwrap(client.read(application, "execution.delegation.read",
        {"delegationId": config["delegationId"]}))["delegation"]
    build = _unwrap(client.build_python_program(context,
        program_id=config["programId"], program_source_token=registered["sourceToken"],
        parameters={}, delegation_id=config["delegationId"],
        delegation_state_token=delegation["state_token"],
        request_key=prefix + "-build"))
    build_id = build.get("buildId")
    replay = _unwrap(client.build_python_program(context,
        program_id=config["programId"], program_source_token=registered["sourceToken"],
        parameters={}, delegation_id=config["delegationId"],
        delegation_state_token=delegation["state_token"],
        request_key=prefix + "-build"))
    if not isinstance(build_id, str) or replay.get("buildId") != build_id:
        raise ProbeError("Python build idempotency replay changed identity")
    deadline = clock() + config["timeoutSeconds"]
    sealed = _wait(lambda: client.read_python_build(application, build_id),
        terminal="sealed", failed={"failed", "cancelled"}, deadline=deadline,
        sleeper=sleeper, clock=clock)
    if sealed.get("attempts") != 1 or sealed.get("claimGeneration") != 1 \
            or not isinstance(sealed.get("planDigest"), str) \
            or HEX64.fullmatch(sealed["planDigest"]) is None:
        raise ProbeError("sealed build execution identity is invalid")
    artifacts = {name: client.inspect_python_build_artifact(application,
        build_id=build_id, section=name)
        for name in ("Plan", "SourceMap", "BuildLog")}
    if any(item.plan_digest != sealed["planDigest"] for item in artifacts.values()):
        raise ProbeError("sealed build artifact identity differs")
    try:
        observation = json.loads(artifacts["BuildLog"].content)
    except (TypeError, json.JSONDecodeError) as error:
        raise ProbeError("builder observation log is invalid") from error
    expected_observation = {"format": "openepm-builder-observation-v1",
        "sourceExecutionCount": 1,
        "databaseCredentialsPresent": False, "trustedCorePresent": False,
        "dockerSocketPresent": False, "sourceMounted": False}
    if observation != expected_observation:
        raise ProbeError("builder isolation observation is incomplete")
    started = _unwrap(client.run_python_program(application, build_id=build_id,
        request_key=prefix + "-run"))
    workflow_id = started.get("workflowId")
    if not isinstance(workflow_id, str):
        raise ProbeError("Python workflow identity is unavailable")
    workflow = _wait(lambda: client.read_python_workflow(application, workflow_id),
        terminal="published", failed={"failed", "cancelled", "needs_inspection"},
        deadline=deadline, sleeper=sleeper)
    run_replay = _unwrap(client.run_python_program(application, build_id=build_id,
        request_key=prefix + "-run"))
    build_after = _unwrap(client.read_python_build(application, build_id))
    if run_replay.get("workflowId") != workflow_id or build_after != sealed:
        raise ProbeError("sealed workflow replay rebuilt or changed identity")
    readback = _unwrap(client.read(application, config["resultFunction"],
                                   config["resultArguments"]))
    result = _path(readback, config["resultPath"])
    if result != config["expectedResult"]:
        raise ProbeError("published Python result differs")
    checkpoints = workflow.get("checkpoints")
    if not isinstance(checkpoints, list) or not checkpoints \
            or any(not isinstance(item, dict) or item.get("committed") is not True
                   or not isinstance(item.get("receiptId"), str)
                   for item in checkpoints):
        raise ProbeError("published workflow receipt lineage is incomplete")
    denial_state_before = _unwrap(client.read(
        application, "application.state.read", {}))
    denied = False
    denied_delegation = ("denied-" + sha256(
        config["delegationId"].encode("utf-8")).hexdigest()[:32])
    try:
        client.build_python_program(context, program_id=config["programId"],
            program_source_token=registered["sourceToken"], parameters={},
            delegation_id=denied_delegation,
            delegation_state_token=delegation["state_token"],
            request_key=prefix + "-denied")
    except McpTransportError:
        denied = True
    state_after = _unwrap(client.read(
        application, "application.state.read", {}))
    before_revision = sha256(str(
        denial_state_before.get("dataRevision")).encode()).hexdigest()
    after_revision = sha256(str(state_after.get("dataRevision")).encode()).hexdigest()
    if not denied or before_revision != after_revision:
        raise ProbeError("denied Python build changed business state")
    receipt_ids = [item["receiptId"] for item in checkpoints]
    artifact_digest = sha256(canonical({name: item.section_digest
        for name, item in sorted(artifacts.items())})).hexdigest()
    forbidden = sorted(name for name in sys.modules
        if name == "epm_core" or name.startswith("epm_core.")
        or name == "psycopg" or name.startswith("psycopg.")
        if name not in forbidden_before)
    if forbidden:
        raise ProbeError("qualification probe imported trusted core or database modules")
    return {"format": "openepm-python-build-publication-result-v3",
        "configuredBuilderImage": config["builderImage"],
        "buildId": build_id, "workflowId": workflow_id,
        "buildAttempts": sealed["attempts"],
        "buildClaimGeneration": sealed["claimGeneration"],
        "buildReplaySame": True, "capabilityActionCount": 2,
        "capabilityGenerationBound": True,
        "sourceExecutionCount": observation["sourceExecutionCount"],
        "sealedRunWithoutRebuild": True, "artifactSha256": artifact_digest,
        "planSha256": sealed["planDigest"], "result": result,
        "receiptSha256": sha256(canonical(receipt_ids)).hexdigest(),
        "lineageSha256": sha256(canonical(checkpoints)).hexdigest(),
        "denialZeroEffect": True, "denialRevisionBefore": before_revision,
        "denialRevisionAfter": after_revision,
        "databaseCredentialsPresent": False, "trustedCorePresent": False,
        "dockerSocketPresent": False, "sourceMounted": False,
        "publicSdkOnly": True, "publicMcpHttps": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--source-file", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        source_path = arguments.source_file.absolute()
        if source_path.is_symlink() or not source_path.is_file():
            raise ProbeError("qualification source must be a regular non-symbolic file")
        value = run(load(arguments.config.resolve()),
                    token(arguments.token_file.absolute()),
                    source_path.read_text(encoding="utf-8"))
    except (ProbeError, OSError, UnicodeError) as error:
        parser.error(str(error))
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
