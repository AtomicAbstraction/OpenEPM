#!/usr/bin/env python3
"""Provision the clean private replacement through Keycloak OIDC MCP only.

The supplied short-lived OIDC credential is read from an owner-only file,
bound to the exact issuer, MCP audience, client and immutable administrator
subject, retained only in process memory, and never printed or copied into
replacement state. PostgreSQL is not accessed by this client.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import time

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from scripts.bootstrap_macos_pilot_application import response
from scripts.bootstrap_macos_pilot_applications import (
    apply_plan as apply_applications, validate_manifest,
)
from scripts import macos_pilot_owner_uat_controller as owner
from scripts import macos_pilot_programmable_replacement as replacement
from scripts.provision_programmable_uat_sample_contents import (
    apply_sample, prepare as prepare_samples,
)


ENDPOINTS = {
    "platform": "http://127.0.0.1:5393/mcp",
    "workspace": "http://127.0.0.1:5392/mcp",
    "application": "http://127.0.0.1:5394/mcp",
}
MINIMUM_CREDENTIAL_LIFETIME_SECONDS = 120
AUTHENTICATED_READINESS_TIMEOUT_SECONDS = 90
AUTHENTICATED_READINESS_INTERVAL_SECONDS = 2


class PrivateProvisionError(RuntimeError):
    pass


def _jwt_claims(token: str) -> dict:
    parts = token.split(".")
    try:
        value = json.loads(base64.urlsafe_b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4))) if len(parts) == 3 else None
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrivateProvisionError("private credential is invalid") from exc
    if not isinstance(value, dict):
        raise PrivateProvisionError("private credential is invalid")
    return value


def load_credential(path: Path, record_path: Path, expected_subject: str,
                    expected_issuer: str,
                    expected_audience: str) -> tuple[str, dict]:
    for item in (path, record_path):
        try:
            metadata = item.stat(follow_symlinks=False)
        except OSError as exc:
            raise PrivateProvisionError("private credential is unavailable") from exc
        if (item.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise PrivateProvisionError("private credential file is unsafe")
    try:
        token = path.read_text(encoding="utf-8").strip()
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrivateProvisionError("private credential is invalid") from exc
    claims = _jwt_claims(token)
    audiences = claims.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    if (not isinstance(record, dict)
            or record.get("format") != "openepm-private-oidc-credential-v1"
            or record.get("credentialKind") != "oidc_access_token"
            or record.get("subject") != expected_subject
            or claims.get("sub") != expected_subject
            or record.get("issuer") != expected_issuer
            or claims.get("iss") != expected_issuer
            or not isinstance(audiences, list)
            or record.get("audience") != expected_audience
            or expected_audience not in audiences
            or record.get("clientId") != "openepm-mcp"
            or claims.get("azp") != "openepm-mcp"
            or not isinstance(claims.get("exp"), (int, float))
            or claims["exp"] < time.time() + MINIMUM_CREDENTIAL_LIFETIME_SECONDS
            or record.get("credentialExpiresAt") != int(claims["exp"])):
        raise PrivateProvisionError("private credential binding differs")
    return token, record


def remove_credential_pair(path: Path, record_path: Path,
                           protected_parent: Path) -> None:
    parent = protected_parent.resolve(strict=True)
    if (path.parent.resolve(strict=True) != parent
            or record_path.parent.resolve(strict=True) != parent):
        raise PrivateProvisionError("private credential directory differs")
    for item in (path, record_path):
        metadata = item.stat(follow_symlinks=False)
        if (item.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise PrivateProvisionError("private credential file is unsafe")
    path.unlink(); record_path.unlink()
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def credential_directory(root: Path) -> Path:
    directory = root / "credentials"
    directory.mkdir(mode=0o700, exist_ok=True)
    metadata = directory.stat(follow_symlinks=False)
    if (directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
            or directory.resolve(strict=True) != directory
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()):
        raise PrivateProvisionError("private credential directory is unsafe")
    return directory


async def _with_session(endpoint: str, token: str, operation):
    async with httpx2.AsyncClient(
            headers={"Authorization": "Bearer " + token},
            follow_redirects=False, timeout=120) as client:
        async with streamable_http_client(
                ENDPOINTS[endpoint], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                initialized = await session.initialize()
                tools = {tool.name for tool in
                         (await session.list_tools()).tools}

                async def call(name: str, arguments: dict) -> dict:
                    if name not in tools:
                        raise PrivateProvisionError(
                            "private MCP tool is unavailable: " + name)
                    return response(await session.call_tool(name, arguments))

                result = await operation(call)
                return result, initialized.server_info.name


async def wait_authenticated_mcp_ready(
        token: str,
        timeout_seconds: int = AUTHENTICATED_READINESS_TIMEOUT_SECONDS,
        interval_seconds: float = AUTHENTICATED_READINESS_INTERVAL_SECONDS,
        clock=time.monotonic,
) -> dict[str, str]:
    """Wait until every private MCP surface accepts the bound identity.

    This probe initializes a session and lists tools only.  It cannot create
    or mutate business state, so retrying a cold-start race is safe.
    """
    if timeout_seconds <= 0 or interval_seconds <= 0:
        raise PrivateProvisionError("private readiness timing is invalid")
    deadline = clock() + timeout_seconds

    async def no_effect(_call):
        return {"ready": True}

    while True:
        try:
            servers = {}
            for endpoint in ENDPOINTS:
                _result, server = await _with_session(
                    endpoint, token, no_effect)
                servers[endpoint] = server
            return servers
        except Exception as exc:  # bounded retry of transient startup errors
            remaining = deadline - clock()
            if remaining <= 0:
                raise PrivateProvisionError(
                    "private authenticated MCP readiness timed out") from exc
            await asyncio.sleep(min(interval_seconds, remaining))


async def provision(plan: dict, token: str) -> dict:
    workspace_id = plan["workspaceId"]

    async def create_workspace(call):
        arguments = {"program": {"languageVersion": 2,
            "function": "platform.workspace.create",
            "arguments": {"workspaceId": workspace_id,
                          "name": "Open EPM Programmable UAT"}},
            "idempotency_key": "programmable-uat-workspace-v1"}
        first = await call("execute_v2_platform_program", arguments)
        replay = await call("execute_v2_platform_program", arguments)
        if first != replay or first.get("workspaceId") != workspace_id:
            raise PrivateProvisionError("private workspace replay differs")
        return first

    workspace, platform_server = await _with_session(
        "platform", token, create_workspace)

    async def create_applications(call):
        return await apply_applications(plan, call)

    applications, workspace_server = await _with_session(
        "workspace", token, create_applications)

    async def populate(call):
        return [await apply_sample(application, workspace_id, call)
                for application in plan["sampleApplications"]]

    samples, application_server = await _with_session(
        "application", token, populate)
    return {
        "workspace": workspace,
        "applications": applications,
        "samples": samples,
        "servers": {"platform": platform_server,
                    "workspace": workspace_server,
                    "application": application_server},
    }


def build_plan(application_manifest: object, sample_manifest: object,
               workspace_id: str, output: Path) -> dict:
    if not output.is_absolute():
        raise PrivateProvisionError("private provision output must be absolute")
    application_plan = validate_manifest(application_manifest, output)
    sample_plan = prepare_samples(sample_manifest, workspace_id, output)
    if ([item["applicationId"] for item in application_plan["applications"]]
            != [item["applicationId"] for item in
                sample_plan["applications"]]):
        raise PrivateProvisionError("private application manifests differ")
    return {
        "format": "openepm-programmable-private-provision-v1",
        "workspaceId": workspace_id,
        "applications": application_plan["applications"],
        "sampleApplications": sample_plan["applications"],
        "contractDigest": sample_plan["contractDigest"],
        "output": str(output),
        "governedMcpOnly": True,
        "databaseAccess": False,
        "businessMutationPerformed": False,
    }


def prepare_plan(args) -> tuple[Path, dict, dict]:
    root = args.state_root.resolve()
    state = replacement.status(argparse.Namespace(state_root=root))
    initial = (state.get("state"), state.get("expectedApplications"))
    if (initial != ("prepared-empty", 0)
            and not (state.get("state") == "provisioning-failed"
                     and state.get("expectedApplications") in (0, 1, 2)
                     and state.get("lastProvisionFailedAt"))):
        raise PrivateProvisionError("clean replacement is not prepared")
    _command, values = replacement.base(root)
    application_manifest = json.loads(
        args.application_manifest.read_text(encoding="utf-8"))
    sample_manifest = json.loads(
        args.sample_manifest.read_text(encoding="utf-8"))
    plan = build_plan(application_manifest, sample_manifest,
                      values["EPM_PG_WORKSPACE_ID"], args.output.resolve())
    return root, state, {"values": values, "plan": plan}


def execute(args) -> dict:
    root, state, prepared = prepare_plan(args)
    values, plan = prepared["values"], prepared["plan"]
    protected_credentials = credential_directory(root)
    token, binding = load_credential(
        args.credential.resolve(), args.credential_record.resolve(),
        values["EPM_PLATFORM_OPERATOR_SUBJECT"],
        values["EPM_OIDC_ISSUER"], values["EPM_OIDC_AUD_MCP"])
    command, environment = replacement.base(root)
    started = datetime.now(timezone.utc).isoformat()
    try:
        owner.all_up(command, environment)
        readiness = asyncio.run(wait_authenticated_mcp_ready(token))
        result = asyncio.run(provision(plan, token))
        database = replacement.compose(
            command, "ps", "-q", "db", environment=environment)
        if replacement.application_count(database) != 2:
            raise PrivateProvisionError("private application count differs")
        evidence = replacement.verify_private(
            root, state["applicationImage"], state["databaseImage"],
            state["expectedSchema"], expected_applications=2)
        if evidence["applications"] != 2:
            raise PrivateProvisionError("private verification count differs")
    except BaseException:
        observed = state.get("expectedApplications", 0)
        try:
            database = replacement.compose(
                command, "ps", "-q", "db", environment=environment)
            if database:
                observed = replacement.application_count(database)
        except BaseException:
            # Preserve the primary governed-operation failure; the next
            # guarded private upgrade rechecks the authoritative count.
            pass
        if observed not in (0, 1, 2):
            observed = state.get("expectedApplications", 0)
        state.update(lastProvisionFailedAt=started,
                     state=("provisioning-failed" if observed
                            else "prepared-empty"),
                     expectedApplications=observed)
        owner.write_json(owner.state_path(root), state)
        raise
    finally:
        replacement.quiesce_prepared(
            command, environment, state.get("identityMode", "cloudflare"))
    record = {
        **plan,
        "status": "passed",
        "provisionedAt": started,
        "applications": result["applications"],
        "samples": result["samples"],
        "servers": result["servers"],
        "authenticatedReadiness": readiness,
        "credential": {"issuer": binding["issuer"],
                       "subjectSha256": __import__("hashlib").sha256(
                           binding["subject"].encode()).hexdigest(),
                       "loginIdSha256": binding["loginIdSha256"],
                       "retained": False,
                       "printed": False},
        "privateVerification": evidence,
        "businessMutationPerformed": True,
        "mutationBoundary": "authenticated fixed-core MCP on private ports",
    }
    owner.write_json(args.output, record)
    state.update(state="prepared-populated", expectedApplications=2,
                 populatedAt=started, sampleContractDigest=plan["contractDigest"],
                 privateVerification=evidence)
    state.pop("lastProvisionFailedAt", None)
    owner.write_json(owner.state_path(root), state)
    try:
        remove_credential_pair(
            args.credential.resolve(), args.credential_record.resolve(),
            protected_credentials)
    except BaseException:
        state.update(credentialCleanupPending=True)
        owner.write_json(owner.state_path(root), state)
        raise
    state.update(credentialConsumedAndRemoved=True)
    state.pop("credentialCleanupPending", None)
    owner.write_json(owner.state_path(root), state)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=
                        replacement.ROOT /
                        "deploy/macos-pilot/.runtime/programmable-next")
    parser.add_argument("--credential", type=Path)
    parser.add_argument("--credential-record", type=Path)
    parser.add_argument("--application-manifest", type=Path, required=True)
    parser.add_argument("--sample-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--plan-only", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.plan_only:
            _root, _state, prepared = prepare_plan(arguments)
            plan = prepared["plan"]
            result = {"passed": True, "planOnly": True,
                      "workspaceId": plan["workspaceId"],
                      "applicationIds": [item["applicationId"] for item in
                                         plan["applications"]],
                      "contractDigest": plan["contractDigest"],
                      "databaseAccess": False,
                      "businessMutationPerformed": False}
            print(json.dumps(result, sort_keys=True))
            return 0
        if arguments.credential is None or arguments.credential_record is None:
            raise PrivateProvisionError(
                "private credential and record are required for execution")
        result = execute(arguments)
    except (OSError, KeyError, ValueError, RuntimeError,
            json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(json.dumps({"passed": True,
        "applicationCount": len(result["applications"]),
        "credentialRetained": False,
        "databaseAccess": False,
        "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
