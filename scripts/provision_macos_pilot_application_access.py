#!/usr/bin/env python3
"""Provision the real Mac-pilot application grants through public MCP only."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit

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
from scripts.enroll_macos_pilot_load_identity import LABEL, SHA256
from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


FORMAT = "openepm-macos-pilot-application-access-v1"
ROSTER_FORMAT = "openepm-macos-pilot-load-identity-v1"
ROLES = {"Reader", "Editor", "Administrator"}
SUPPORTED_CREDENTIAL_KINDS = {
    "refreshable_bundle",  # Legacy JWT-only enrollment bundle.
    "refreshable_oauth_bundle_v2",
    "static_jwt",
    "static_opaque_bundle_v2",
}


class AccessManifestError(ValueError):
    pass


def _protected_descriptor(path: Path, label: str) -> int:
    if (not path.is_absolute() or not path.name
            or any(part in {"", ".", ".."} for part in path.parts[1:])):
        raise AccessManifestError(f"PILOT_ACCESS_{label}_UNSAFE")
    directory_flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    directory = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        if stat.S_IMODE(os.fstat(directory).st_mode) & 0o077:
            raise AccessManifestError(f"PILOT_ACCESS_{label}_UNSAFE")
        file_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW
        descriptor = os.open(path.name, file_flags, dir_fd=directory)
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            os.close(descriptor)
            raise AccessManifestError(f"PILOT_ACCESS_{label}_UNSAFE")
        return descriptor
    finally:
        os.close(directory)


def _read_protected_json(path: Path, label: str) -> dict:
    try:
        descriptor = _protected_descriptor(path, label)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except AccessManifestError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AccessManifestError(f"PILOT_ACCESS_{label}_INVALID") from error
    if type(value) is not dict:
        raise AccessManifestError(f"PILOT_ACCESS_{label}_INVALID")
    return value


def _verify_protected_file(path: Path, label: str) -> None:
    try:
        descriptor = _protected_descriptor(path, label)
    except OSError as error:
        raise AccessManifestError(f"PILOT_ACCESS_{label}_UNSAFE") from error
    os.close(descriptor)


def _read_roster(path: Path, issuer: str, audience: str) -> dict:
    value = _read_protected_json(path, "ROSTER")
    required = {"format", "label", "subject", "subjectSha256", "issuer",
                "audience", "loginIdSha256", "credentialFile",
                "credentialKind", "expiresAt"}
    if type(value) is not dict or set(value) != required:
        raise AccessManifestError("PILOT_ACCESS_ROSTER_INVALID")
    subject = value["subject"]
    digest = (hashlib.sha256(subject.encode()).hexdigest()
              if isinstance(subject, str) else "")
    credential_file = value["credentialFile"]
    if (value["format"] != ROSTER_FORMAT
            or LABEL.fullmatch(value["label"] if isinstance(
                value["label"], str) else "") is None
            or not isinstance(subject, str) or not subject
            or any(ord(char) < 32 for char in subject)
            or value["subjectSha256"] != digest
            or value["issuer"] != issuer
            or value["audience"] != audience
            or not isinstance(credential_file, str)
            or not Path(credential_file).is_absolute()
            or not isinstance(value["credentialKind"], str)
            or value["credentialKind"] not in SUPPORTED_CREDENTIAL_KINDS
            or isinstance(value["expiresAt"], bool)
            or not isinstance(value["expiresAt"], int)
            or value["expiresAt"] <= 0
            or SHA256.fullmatch(value["loginIdSha256"] if isinstance(
                value["loginIdSha256"], str) else "") is None):
        raise AccessManifestError("PILOT_ACCESS_ROSTER_INVALID")
    _verify_protected_file(Path(credential_file), "CREDENTIAL")
    return value


def _issuer(value: object) -> str:
    if not isinstance(value, str):
        raise AccessManifestError("PILOT_ACCESS_ISSUER_INVALID")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.netloc or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or value.endswith("/")):
        raise AccessManifestError("PILOT_ACCESS_ISSUER_INVALID")
    return value


def validate_manifest(value: object, manifest_path: Path,
                      output_path: Path) -> dict:
    _verify_protected_file(manifest_path, "MANIFEST")
    if type(value) is not dict or set(value) != {
            "format", "issuer", "audience", "workspaceId", "applications",
            "identities", "controlLabel", "revocationLabel", "isolation"}:
        raise AccessManifestError("PILOT_ACCESS_MANIFEST_INVALID")
    issuer = _issuer(value["issuer"])
    audience = value["audience"]
    workspace_id = value["workspaceId"]
    if (value["format"] != FORMAT or not isinstance(workspace_id, str)
            or IDENTIFIER.fullmatch(workspace_id) is None
            or not isinstance(audience, str) or not audience
            or audience != audience.strip()):
        raise AccessManifestError("PILOT_ACCESS_MANIFEST_INVALID")
    applications = value["applications"]
    if (not isinstance(applications, list)
            or len(applications) not in (5, 6)
            or any(not isinstance(item, str)
                   or IDENTIFIER.fullmatch(item) is None
                   for item in applications)
            or len(applications) != len(set(applications))):
        raise AccessManifestError("PILOT_ACCESS_APPLICATIONS_INVALID")
    identities = value["identities"]
    if not isinstance(identities, list) or len(identities) != 10:
        raise AccessManifestError("PILOT_ACCESS_IDENTITIES_INVALID")

    normalized = []
    labels: set[str] = set()
    subjects: set[str] = set()
    subject_digests: set[str] = set()
    email_digests: set[str] = set()
    roster_paths: set[Path] = set()
    credential_paths: set[Path] = set()
    agent_count = 0
    for item in identities:
        if type(item) is not dict or set(item) != {
                "label", "kind", "rosterFile", "roles"}:
            raise AccessManifestError("PILOT_ACCESS_IDENTITY_INVALID")
        label, kind = item["label"], item["kind"]
        if (not isinstance(label, str) or LABEL.fullmatch(label) is None
                or label in labels or kind not in {"agent", "human"}
                or not isinstance(item["rosterFile"], str)):
            raise AccessManifestError("PILOT_ACCESS_IDENTITY_INVALID")
        roster_path = Path(item["rosterFile"])
        if roster_path in roster_paths:
            raise AccessManifestError("PILOT_ACCESS_ROSTER_DUPLICATE")
        roster = _read_roster(roster_path, issuer, audience)
        credential_path = Path(roster["credentialFile"])
        if roster["label"] != label:
            raise AccessManifestError("PILOT_ACCESS_ROSTER_LABEL_MISMATCH")
        roles = item["roles"]
        if (type(roles) is not dict or not set(roles) <= set(applications)
                or any(role not in ROLES for role in roles.values())):
            raise AccessManifestError("PILOT_ACCESS_ROLES_INVALID")
        labels.add(label)
        if (roster["subject"] in subjects
                or roster["subjectSha256"] in subject_digests
                or roster["loginIdSha256"] in email_digests
                or credential_path in credential_paths):
            raise AccessManifestError("PILOT_ACCESS_SUBJECT_DUPLICATE")
        subjects.add(roster["subject"])
        subject_digests.add(roster["subjectSha256"])
        email_digests.add(roster["loginIdSha256"])
        roster_paths.add(roster_path)
        credential_paths.add(credential_path)
        agent_count += kind == "agent"
        normalized.append({"label": label, "kind": kind,
                           "subject": roster["subject"],
                           "subjectSha256": roster["subjectSha256"],
                           "roles": roles})
    if agent_count not in (3, 4):
        raise AccessManifestError("PILOT_ACCESS_AGENT_COUNT_INVALID")

    control_label = value["controlLabel"]
    revocation_label = value["revocationLabel"]
    isolation = value["isolation"]
    if (control_label not in labels or revocation_label not in labels
            or revocation_label == control_label or type(isolation) is not dict
            or set(isolation) != {"label", "deniedApplicationId"}
            or isolation["label"] not in labels
            or isolation["label"] == control_label
            or isolation["label"] == revocation_label
            or isolation["deniedApplicationId"] not in applications):
        raise AccessManifestError("PILOT_ACCESS_CONTROLS_INVALID")
    denied_label = isolation["label"]
    denied_application = isolation["deniedApplicationId"]
    for identity in normalized:
        expected = set(applications)
        if identity["label"] == denied_label:
            expected.remove(denied_application)
        if set(identity["roles"]) != expected:
            raise AccessManifestError("PILOT_ACCESS_SCOPE_MATRIX_INVALID")
        roles = set(identity["roles"].values())
        if identity["label"] == control_label:
            if identity["kind"] != "human" or roles != {"Administrator"}:
                raise AccessManifestError("PILOT_ACCESS_CONTROL_ROLE_INVALID")
        elif identity["kind"] == "agent" and roles != {"Editor"}:
            raise AccessManifestError("PILOT_ACCESS_AGENT_ROLE_INVALID")
        elif identity["kind"] == "human" and roles != {"Reader"}:
            raise AccessManifestError("PILOT_ACCESS_HUMAN_ROLE_INVALID")
    revocation = next(item for item in normalized
                      if item["label"] == revocation_label)
    if (revocation["kind"] != "agent"
            or any(role != "Editor" for role in revocation["roles"].values())):
        raise AccessManifestError("PILOT_ACCESS_REVOCATION_ROLE_INVALID")
    for application_id in applications:
        if not any(identity["label"] != control_label
                   and identity["roles"].get(application_id)
                   in {"Editor", "Administrator"}
                   for identity in normalized):
            raise AccessManifestError("PILOT_ACCESS_EFFECTOR_MISSING")
    if (not output_path.is_absolute() or not output_path.parent.is_dir()
            or output_path.parent.is_symlink()
            or output_path.exists() or output_path.is_symlink()):
        raise AccessManifestError("PILOT_ACCESS_OUTPUT_INVALID")
    manifest_digest = hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    plan_digest = hashlib.sha256(json.dumps({
        "workspaceId": workspace_id, "applications": applications,
        "identities": [{"kind": item["kind"],
                        "subjectSha256": item["subjectSha256"],
                        "roles": item["roles"]} for item in normalized],
        "controlLabel": control_label, "revocationLabel": revocation_label,
        "isolation": isolation,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"format": FORMAT, "issuer": issuer, "audience": audience,
            "workspaceId": workspace_id, "applications": applications,
            "identities": normalized, "controlLabel": control_label,
            "revocationLabel": revocation_label,
            "isolation": isolation, "manifestDigest": manifest_digest,
            "planDigest": plan_digest,
            "output": str(output_path)}


def redacted_plan(plan: dict) -> dict:
    return {"format": plan["format"], "workspaceId": plan["workspaceId"],
            "applicationCount": len(plan["applications"]),
            "identityCount": len(plan["identities"]),
            "agentIdentityCount": sum(item["kind"] == "agent"
                                      for item in plan["identities"]),
            "grantCount": sum(len(item["roles"])
                              for item in plan["identities"]),
            "revokeCount": 1,
            "manifestDigest": plan["manifestDigest"],
            "planDigest": plan["planDigest"],
            "controlIdentityConfigured": True,
            "deliberateIsolationOmissionConfigured": True,
            "publicMcpOnly": True, "databaseAccess": False,
            "businessMutationPerformed": False,
            "rawSubjectsIncluded": False, "emailsIncluded": False,
            "tokenContentsIncluded": False,
            "credentialPathsIncluded": False, "rosterPathsIncluded": False}


async def apply_plan(plan: dict, call) -> list[dict]:
    effects = []
    denied_label = plan["isolation"]["label"]
    denied_application = plan["isolation"]["deniedApplicationId"]
    for identity_index, identity in enumerate(plan["identities"]):
        for application_index, application_id in enumerate(plan["applications"]):
            role = identity["roles"].get(application_id)
            revoke = (identity["label"] == denied_label
                      and application_id == denied_application)
            if role is None and not revoke:
                raise RuntimeError("PILOT_ACCESS_SCOPE_MATRIX_INVALID")
            action = "revoke" if revoke else "grant"
            program = {"languageVersion": 2,
                       "function": "security.application.access.set",
                       "arguments": {"subjectId": identity["subject"],
                                     "action": action, "role": role}}
            operation_digest = hashlib.sha256(json.dumps({
                "workspaceId": plan["workspaceId"],
                "applicationId": application_id,
                "subjectSha256": identity["subjectSha256"],
                "action": action, "role": role,
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            key = "pilot-access-v1-" + operation_digest
            arguments = {"workspace_id": plan["workspaceId"],
                         "application_id": application_id,
                         "program": program, "idempotency_key": key}
            first = await call("set_v2_application_access", arguments)
            replay = await call("set_v2_application_access", arguments)
            if first != replay:
                raise RuntimeError("PILOT_ACCESS_REPLAY_MISMATCH")
            result = first.get("result")
            if (first.get("languageVersion") != 2
                    or first.get("function") != "security.application.access.set"
                    or not isinstance(result, dict)
                    or result.get("workspaceId") != plan["workspaceId"]
                    or result.get("applicationId") != application_id
                    or result.get("action") != action
                    or result.get("role") != role):
                raise RuntimeError("PILOT_ACCESS_RESULT_MISMATCH")
            effects.append({"identity": f"identity-{identity_index + 1:02d}",
                            "subjectSha256": identity["subjectSha256"],
                            "application": f"application-{application_index + 1:02d}",
                            "action": action, "role": role,
                            "replayIdentical": True})
    return effects


async def execute(plan: dict) -> dict:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"], OAuthClientMetadata(
            client_name="Open EPM Mac pilot access provisioning",
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
                if "set_v2_application_access" not in tools:
                    raise RuntimeError("PILOT_ACCESS_TOOL_UNAVAILABLE")

                async def call(tool: str, arguments: dict) -> dict:
                    return response(await session.call_tool(tool, arguments))

                effects = await apply_plan(plan, call)
    result = redacted_plan(plan)
    return {**result, "status": "passed", "effects": effects,
            "serverName": initialized.server_info.name,
            "businessMutationPerformed": True,
            "mutationBoundary": "authorized fixed-core public application MCP",
            "oauthTokenRetained": False}


def _write_evidence(path: Path, value: dict) -> None:
    temporary = path.with_name(
        "." + path.name + ".tmp-" + os.urandom(8).hex())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        manifest_path = arguments.manifest
        output_path = arguments.output
        value = _read_protected_json(manifest_path, "MANIFEST")
        plan = validate_manifest(value, manifest_path, output_path)
        if not arguments.execute:
            print(json.dumps(redacted_plan(plan), sort_keys=True))
            return 0
        result = asyncio.run(execute(plan))
        _write_evidence(output_path, result)
    except (AccessManifestError, OSError, RuntimeError,
            json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps({"passed": True,
                      "operationCount": len(result["effects"]),
                      "output": str(output_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
