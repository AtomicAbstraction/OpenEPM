#!/usr/bin/env python3
"""Build the portable, non-secret clean-Linux phase context from a plan.

The output contains host paths and public endpoints, never token or key
contents. Exact component image identities are copied from the qualification
plan so an operator cannot transcribe a different image into the run context.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import urllib.parse


class ContextError(ValueError):
    pass


COMPONENTS = {"application", "database", "operations", "builder",
              "notebook", "hub", "identity", "proxy", "browser_gateway",
              "browser_session_store"}


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContextError(f"invalid qualification plan: {error}") from error
    if not isinstance(value, dict):
        raise ContextError("qualification plan must be an object")
    return value


def absolute(value: str, label: str) -> str:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ContextError(f"{label} must be an absolute non-traversing host path")
    return value


def endpoint(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ContextError("MCP endpoint is invalid") from error
    if parsed.scheme != "https" or not parsed.hostname \
            or parsed.username is not None or parsed.password is not None \
            or parsed.fragment or port == 0:
        raise ContextError("MCP endpoint must be credential-free HTTPS")
    return value


def identifier(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value):
        raise ContextError(f"{label} is invalid")
    return value


def build(plan: dict, *, mcp_endpoint: str, mcp_token_file: str,
          browser_identity_secrets_directory: str, python_build_token_file: str,
          notebook_hub_api_endpoint: str,
          notebook_hub_api_token_file: str,
          notebook_qualification_username: str,
          notebook_isolation_username: str,
          notebook_restored_user_api_token_file: str,
          notebook_isolation_user_api_token_file: str,
          notebook_restored_server_api_endpoint: str,
          notebook_launcher_profile_file: str,
          source_backup_attestation: str, source_attestation_key_file: str,
          backup_export_root: str, backup_maximum_bytes: int,
          proxy_retirement_maximum_bytes: int, database_container: str,
          database_user: str, database_name: str,
          restore_target_project: str) -> dict:
    if plan.get("format") != "openepm-clean-linux-qualification-plan-v1" \
            or plan.get("status") != "execution-required" \
            or plan.get("qualificationClaimed") is not False:
        raise ContextError("qualification plan is not execution-required")
    images = plan.get("nativeImageDigests")
    if not isinstance(images, dict) or set(images) != COMPONENTS \
            or any(not isinstance(value, str)
                   or not re.fullmatch(r"sha256:[a-f0-9]{64}", value)
                   for value in images.values()):
        raise ContextError("qualification plan image bindings are incomplete")
    if type(backup_maximum_bytes) is not int \
            or not 1 <= backup_maximum_bytes <= 1024 ** 4:
        raise ContextError("backup maximum bytes is invalid")
    if type(proxy_retirement_maximum_bytes) is not int \
            or not 1024 <= proxy_retirement_maximum_bytes <= 1024 ** 3:
        raise ContextError("proxy retirement maximum bytes is invalid")
    hub_endpoint = endpoint(notebook_hub_api_endpoint)
    hub = urllib.parse.urlsplit(hub_endpoint)
    if hub.path.rstrip("/") != "/hub/api" or hub.query:
        raise ContextError("notebook Hub API endpoint must end in /hub/api")
    qualification_username = identifier(
        notebook_qualification_username, "notebook qualification username")
    if not re.fullmatch(r"u-[a-f0-9]{32}", qualification_username):
        raise ContextError("notebook qualification username is invalid")
    isolation_username = identifier(
        notebook_isolation_username, "notebook isolation username")
    if (not re.fullmatch(r"u-[a-f0-9]{32}", isolation_username)
            or isolation_username == qualification_username):
        raise ContextError("notebook isolation username is invalid")
    return {
        "bundleRoot": ".", "bundleManifest": "qualification-bundle-manifest.json",
        "releaseManifest": "release-manifest.json", "cleanHost": True,
        "images": {key: images[key] for key in sorted(images)},
        "epmctl": "epmctl", "browserProbeExecutable": "browser-probe",
        "browserProbeConfig": "browser-probe.json",
        "pythonBuildProbeExecutable": "python-build-publication-probe",
        "pythonBuildProbeConfig": "python-build-publication-probe.json",
        "headlessRunscProfile": "headless-runsc-profile.json",
        "notebookRunscProfile": "notebook-runsc-profile.json",
        "populatedVerifier": "populated-verifier",
        "restoredPopulatedVerifier": "restored-populated-verifier",
        "mcpRequest": "mcp-request.json",
        "sourceAttestationModule": "create_openepm_source_backup_attestation.py",
        "mcpEndpoint": endpoint(mcp_endpoint),
        "mcpTokenFile": absolute(mcp_token_file, "MCP token file"),
        "browserIdentitySecretsDirectory": absolute(
            browser_identity_secrets_directory,
            "browser identity secrets directory"),
        "pythonBuildTokenFile": absolute(
            python_build_token_file, "Python-build token file"),
        "notebookHubApiEndpoint": hub_endpoint,
        "notebookHubApiTokenFile": absolute(
            notebook_hub_api_token_file, "notebook Hub API token file"),
        "notebookQualificationUsername": qualification_username,
        "notebookIsolationUsername": isolation_username,
        "notebookRestoredUserApiTokenFile": absolute(
            notebook_restored_user_api_token_file,
            "restored notebook user API token file"),
        "notebookIsolationUserApiTokenFile": absolute(
            notebook_isolation_user_api_token_file,
            "isolation notebook user API token file"),
        "notebookRestoredServerApiEndpoint": endpoint(
            notebook_restored_server_api_endpoint),
        "notebookLauncherProfileFile": absolute(
            notebook_launcher_profile_file, "notebook launcher profile file"),
        "notebookLauncherJournalUnit": "openepm-notebook-launcher.service",
        "sandboxLauncherJournalUnit": "openepm-sandbox-launcher.service",
        "sourceBackupAttestation": absolute(
            source_backup_attestation, "source backup attestation"),
        "sourceAttestationKeyFile": absolute(
            source_attestation_key_file, "source attestation key file"),
        "backupExportRoot": absolute(backup_export_root, "backup export root"),
        "backupMaximumBytes": backup_maximum_bytes,
        "proxyRetirementMaximumBytes": proxy_retirement_maximum_bytes,
        "databaseContainer": identifier(database_container, "database container"),
        "databaseUser": identifier(database_user, "database user"),
        "databaseName": identifier(database_name, "database name"),
        "restoreTargetProject": identifier(
            restore_target_project, "restore target project"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mcp-endpoint", required=True)
    for name in ("mcp-token-file", "browser-identity-secrets-directory",
                 "python-build-token-file",
                 "notebook-hub-api-endpoint", "notebook-hub-api-token-file",
                 "notebook-qualification-username", "notebook-isolation-username",
                 "notebook-restored-user-api-token-file",
                 "notebook-isolation-user-api-token-file",
                 "notebook-restored-server-api-endpoint",
                 "notebook-launcher-profile-file",
                 "source-backup-attestation", "source-attestation-key-file",
                 "backup-export-root"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--backup-maximum-bytes", type=int, required=True)
    parser.add_argument("--proxy-retirement-maximum-bytes", type=int,
                        default=256 * 1024 * 1024)
    parser.add_argument("--database-container", default="openepm-db")
    parser.add_argument("--database-user", default="openepm_read")
    parser.add_argument("--database-name", default="openepm")
    parser.add_argument("--restore-target-project", default="openepm-restore")
    arguments = parser.parse_args()
    if arguments.output.exists() or arguments.output.is_symlink():
        parser.error("output already exists")
    try:
        value = build(load(arguments.plan.resolve()),
            mcp_endpoint=arguments.mcp_endpoint,
            mcp_token_file=arguments.mcp_token_file,
            browser_identity_secrets_directory=
                arguments.browser_identity_secrets_directory,
            python_build_token_file=arguments.python_build_token_file,
            notebook_hub_api_endpoint=arguments.notebook_hub_api_endpoint,
            notebook_hub_api_token_file=arguments.notebook_hub_api_token_file,
            notebook_qualification_username=arguments.notebook_qualification_username,
            notebook_isolation_username=arguments.notebook_isolation_username,
            notebook_restored_user_api_token_file=
                arguments.notebook_restored_user_api_token_file,
            notebook_isolation_user_api_token_file=
                arguments.notebook_isolation_user_api_token_file,
            notebook_restored_server_api_endpoint=
                arguments.notebook_restored_server_api_endpoint,
            notebook_launcher_profile_file=arguments.notebook_launcher_profile_file,
            source_backup_attestation=arguments.source_backup_attestation,
            source_attestation_key_file=arguments.source_attestation_key_file,
            backup_export_root=arguments.backup_export_root,
            backup_maximum_bytes=arguments.backup_maximum_bytes,
            proxy_retirement_maximum_bytes=arguments.proxy_retirement_maximum_bytes,
            database_container=arguments.database_container,
            database_user=arguments.database_user,
            database_name=arguments.database_name,
            restore_target_project=arguments.restore_target_project)
    except ContextError as error:
        parser.error(str(error))
    arguments.output.write_bytes(canonical(value) + b"\n")
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
