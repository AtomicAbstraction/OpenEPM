#!/usr/bin/env python3
"""Prepare protected marker-owned Compose and sandbox material for V18.

This stage writes configuration only. It does not start EPM services or alter
the retained owner deployment.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "deploy/macos-pilot"))

from initialize_python_build import initialize as initialize_python_build  # noqa: E402
from tests.v18_local_sustained_identity import (  # noqa: E402
    MARKER, PROVIDER_DIGEST)


IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MIGRATION = re.compile(r"([0-9]{4})_[a-z0-9_]+\.sql\Z")
APP_SERVICES = frozenset(("migrate", "bootstrap-roles", "bootstrap-operator",
    "platform", "workspace", "router", "web", "worker", "reset-apply",
    "python-build-secret-init", "bootstrap-python-coordinator",
    "python-build-broker"))
DB_SERVICES = frozenset(("backup-volume-init", "db", "recovery-init",
    "recovery-db", "backup-export", "backup-import"))
ALL_SERVICES = APP_SERVICES | DB_SERVICES


class V18RuntimePreparationError(ValueError):
    pass


def _fail(code: str) -> None:
    raise V18RuntimePreparationError(code)


def _write_once(path: Path, value: str, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _image_id(reference: str) -> str:
    completed = subprocess.run(["docker", "image", "inspect", "--format",
        "{{.Id}}", reference], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=30, check=False)
    if completed.returncode or not IMAGE.fullmatch(completed.stdout.strip()):
        _fail("V18_RUNTIME_IMAGE_UNAVAILABLE")
    return completed.stdout.strip()


def _quote(value: str) -> str:
    return json.dumps(value)


def _latest_schema_migration() -> int:
    versions = []
    for path in (ROOT / "schema/postgres").glob("*.sql"):
        match = MIGRATION.fullmatch(path.name)
        if match is not None:
            versions.append(int(match.group(1)))
    if not versions or len(versions) != len(set(versions)):
        _fail("V18_RUNTIME_SCHEMA_INVENTORY_INVALID")
    maximum = max(versions)
    if set(versions) != set(range(1, maximum + 1)):
        _fail("V18_RUNTIME_SCHEMA_INVENTORY_INVALID")
    return maximum


def prepare(*, marker: str, directory: Path, application_reference: str,
            application_digest: str, database_reference: str,
            database_digest: str, builder_digest: str,
            compose_executable: Path) -> dict:
    directory = directory.resolve(strict=True)
    identity_path = directory / "identity-manifest.json"
    if (not MARKER.fullmatch(marker) or directory.is_symlink()
            or directory.stat().st_mode & 0o077
            or not identity_path.is_file() or identity_path.is_symlink()
            or identity_path.stat().st_mode & 0o077
            or not all(IMAGE.fullmatch(item) for item in (
                application_digest, database_digest, builder_digest))
            or not compose_executable.is_absolute()
            or not compose_executable.is_file()
            or compose_executable.is_symlink()
            or not compose_executable.stat().st_mode & 0o111):
        _fail("V18_RUNTIME_CONFIGURATION_INVALID")
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise V18RuntimePreparationError(
            "V18_RUNTIME_IDENTITY_INVALID") from error
    expected_identity = {"format", "container", "imageDigest", "issuer",
        "jwksUrl", "audience", "subject", "tokenFile", "caFile",
        "authorizationFlow", "refreshable", "ownershipMarker"}
    if (type(identity) is not dict or set(identity) != expected_identity
            or identity["format"] != "openepm-v18-identity-v1"
            or identity["imageDigest"] != PROVIDER_DIGEST
            or identity["ownershipMarker"] != marker
            or identity["refreshable"] is not True
            or identity["audience"] != "epm-real-mcp"):
        _fail("V18_RUNTIME_IDENTITY_INVALID")
    token = Path(identity["tokenFile"])
    ca = Path(identity["caFile"])
    if (not token.is_file() or token.is_symlink()
            or token.stat().st_mode & 0o077
            or not ca.is_file() or ca.is_symlink()
            or token.resolve().parent != directory
            or ca.resolve().parent != directory):
        _fail("V18_RUNTIME_IDENTITY_INVALID")
    token = token.resolve()
    ca = ca.resolve()
    if (_image_id(application_reference) != application_digest
            or _image_id(database_reference) != database_digest
            or _image_id(builder_digest) != builder_digest):
        _fail("V18_RUNTIME_IMAGE_MISMATCH")

    project = "openepm-" + marker
    workspace = marker + "-workspace"
    application = marker + "-application"
    sandbox_host = "/run/openepm-sandbox/" + project
    endpoints = [{"kind": "application_mcp",
        "url": "http://127.0.0.1:5394/api/application/mcp",
        "workspaceId": workspace, "applicationId": application},
        {"kind": "web_inspector", "url": "http://127.0.0.1:5395/",
         "workspaceId": "", "applicationId": ""},
        {"kind": "workspace_mcp",
         "url": "http://127.0.0.1:5392/api/workspace/mcp",
         "workspaceId": workspace, "applicationId": ""}]
    inventory = json.dumps({"endpoints": sorted(endpoints, key=lambda item: (
        item["kind"], item["workspaceId"], item["applicationId"],
        item["url"]))}, sort_keys=True, separators=(",", ":"))
    values = {
        "EPM_APPLICATION_IMAGE": application_reference,
        "EPM_DATABASE_IMAGE": database_reference,
        "EPM_POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_RUNTIME_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_ACCESS_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_WORKER_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_LIFECYCLE_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_PROVISION_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_SECURITY_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_PREVIEW_SECRET_HEX": secrets.token_hex(32),
        "EPM_AUTH_MODE": "oidc", "EPM_OIDC_ISSUER": identity["issuer"],
        "EPM_OIDC_JWKS_URL": identity["jwksUrl"],
        "EPM_OIDC_AUD_MCP": identity["audience"],
        "EPM_OIDC_AUD_WEB": "epm-real-web",
        "EPM_PUBLIC_WEB_ORIGIN": "http://127.0.0.1:5395",
        "EPM_PUBLIC_MCP_ORIGIN": "http://127.0.0.1:5394",
        "EPM_PLATFORM_OPERATOR_ISSUER": identity["issuer"],
        "EPM_PLATFORM_OPERATOR_SUBJECT": identity["subject"],
        "EPM_PG_WORKSPACE_ID": workspace,
        "EPM_RESET_ENDPOINT_INVENTORY_JSON": inventory,
        "EPM_RESET_APPLY_ENABLED": "1",
        "EPM_RESET_REPLACEMENT_READY": "1",
        "EPM_RESET_ENDPOINTS_RETIRED": "1",
        "EPM_PYTHON_BUILD_BROKER_IP": "172.30.253.2",
        "EPM_PYTHON_BUILD_SANDBOX_SUBNET": "172.30.253.0/28",
    }
    environment = directory / "compose.env"
    _write_once(environment, "".join(
        f"{key}={value}\n" for key, value in sorted(values.items())))
    python_runtime = directory / "python-build"
    initialize_python_build(environment, python_runtime,
        builder_image=builder_digest, project_name=project,
        environment_version=1)

    override = directory / "override.yaml"
    lines = ["services:"]
    for service in sorted(ALL_SERVICES):
        image = database_reference if service in DB_SERVICES \
            else application_reference
        lines.extend((f"  {service}:", f"    image: {_quote(image)}",
            "    build: !reset null", "    pull_policy: never",
            "    labels:", f"      org.openepm.v18-ownership: {_quote(marker)}"))
        if service == "workspace":
            lines.append('    ports: !override ["127.0.0.1:5392:5192"]')
        elif service == "platform":
            lines.append('    ports: !override ["127.0.0.1:5393:5193"]')
        elif service == "router":
            lines.append('    ports: !override ["127.0.0.1:5394:5194"]')
        elif service == "web":
            lines.append('    ports: !override ["127.0.0.1:5395:5195"]')
        elif service == "reset-apply":
            lines.append('    ports: !override ["127.0.0.1:5396:5196"]')
        if service in {"platform", "workspace", "router", "web",
                       "reset-apply"}:
            lines.extend(("    environment:",
                "      SSL_CERT_FILE: /run/v18-oidc-ca.pem"))
            mounts = [f"{ca}:/run/v18-oidc-ca.pem:ro"]
            if service == "router":
                mounts.insert(0,
                    "python_build_secrets:/run/openepm-python-secrets:ro")
            lines.append("    volumes: !override")
            lines.extend("      - " + _quote(mount) for mount in mounts)
        if service == "worker":
            lines.extend(("    environment:",
                "      EPM_SANDBOX_CONTROL_SOCKET: "
                "/run/openepm-sandbox/sandbox-launcher.sock",
                "    volumes: !override",
                "      - python_build_secrets:/run/openepm-python-secrets:ro",
                f"      - {_quote(sandbox_host + ':/run/openepm-sandbox:ro')}"))
    _write_once(override, "\n".join(lines) + "\n", 0o600)

    base = (ROOT / "deploy/postgres/compose.yaml").resolve()
    python_compose = (ROOT / "deploy/macos-pilot/"
                      "python-build.compose.yaml").resolve()
    source_commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{commit}"], cwd=ROOT, text=True,
        timeout=30).strip()
    source_tree = subprocess.check_output(
        ["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True,
        timeout=30).strip()
    schema_migration = _latest_schema_migration()
    result = {"format": "openepm-v18-compose-runtime-v1",
        "marker": marker, "project": project, "workspaceId": workspace,
        "applicationId": application, "sourceCommit": source_commit,
        "sourceTree": source_tree, "schemaMigration": schema_migration,
        "applicationImage": {
            "reference": application_reference, "digest": application_digest},
        "databaseImage": {"reference": database_reference,
                          "digest": database_digest},
        "builderImageDigest": builder_digest,
        "composeExecutable": str(compose_executable),
        "composeFiles": [str(base), str(python_compose), str(override)],
        "composeEnvFile": str(environment), "identityManifest": str(identity_path),
        "sandboxHostDirectory": sandbox_host,
        "sandboxControlSocket": "/run/openepm-sandbox/sandbox-launcher.sock",
        "sandboxNetwork": project + "_sandbox",
        "sandboxSubnet": "172.30.253.0/28", "sandboxBrokerIp": "172.30.253.2",
        "endpoints": {"platform": "http://127.0.0.1:5393/api/platform/mcp",
            "workspace": "http://127.0.0.1:5392/api/workspace/mcp",
            "application": "http://127.0.0.1:5394/api/application/mcp",
            "web": "http://127.0.0.1:5395/",
            "reset": "http://127.0.0.1:5396/mcp"},
        "pythonRuntimeManifestSha256": sha256(
            (python_runtime / "manifest.json").read_bytes()).hexdigest(),
        "ownerRuntimeChanged": False}
    manifest = directory / "runtime-manifest.json"
    _write_once(manifest, json.dumps(result, sort_keys=True,
        separators=(",", ":")) + "\n")
    return {**result, "manifest": str(manifest)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--application-reference", required=True)
    parser.add_argument("--application-digest", required=True)
    parser.add_argument("--database-reference", required=True)
    parser.add_argument("--database-digest", required=True)
    parser.add_argument("--builder-digest", required=True)
    parser.add_argument("--compose-executable", type=Path, required=True)
    arguments = parser.parse_args()
    result = prepare(**vars(arguments))
    print(json.dumps({"status": "prepared", "manifest": result["manifest"],
        "project": result["project"], "secretsPrinted": False},
        sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
