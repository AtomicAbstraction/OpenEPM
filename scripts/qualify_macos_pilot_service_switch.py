#!/usr/bin/env python3
"""Qualify candidate activation and old-service rollback in owned projects.

The shared Mac pilot is captured read-only before and after.  Candidate and
rollback services use two unique Compose projects, two distinct database
volumes and one temporary loopback port set sequentially.  No shared service,
volume, image tag, ingress rule or business row is changed.
"""
from __future__ import annotations

import argparse
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.capture_macos_pilot_running_state import (
    capture as capture_running, compose_frontend, protected_env_value)
from scripts.qualify_macos_pilot_backup_restore import (
    create_group_roles, logical_data_digest)


SOURCE_CONTAINER = "openepm-macos-pilot-db-1"
SOURCE_PROJECT = "openepm-macos-pilot"
BACKUP_ROOT = "/var/lib/postgresql/base_backups"
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
BACKUP_NAME = re.compile(r"^pilot-pre-upgrade-[0-9]{8}T[0-9]{6}Z[.]dump$")
PROJECT = re.compile(r"^openepm-pilot-switch-[a-z0-9]{12}-(candidate|rollback)$")
PORTS = {"workspace": 5292, "platform": 5293, "router": 5294, "web": 5295}
INTERNAL_PORTS = {"workspace": 5192, "platform": 5193,
                  "router": 5194, "web": 5195}
SERVICE_ORDER = ("platform", "workspace", "router", "web", "worker")
LOGIN_ROLES = (
    ("epm_runtime_login", "epm_runtime", "EPM_PG_RUNTIME_PASSWORD"),
    ("epm_access_login", "epm_access", "EPM_PG_ACCESS_PASSWORD"),
    ("epm_worker_login", "epm_worker", "EPM_PG_WORKER_PASSWORD"),
    ("epm_lifecycle_login", "epm_lifecycle", "EPM_PG_LIFECYCLE_PASSWORD"),
    ("epm_provision_login", "epm_provision", "EPM_PG_PROVISION_PASSWORD"),
    ("epm_security_login", "epm_security", "EPM_PG_SECURITY_PASSWORD"),
    ("epm_python_coordinator_login", "epm_python_coordinator",
     "EPM_PG_PYTHON_COORDINATOR_PASSWORD"),
)


class SwitchError(ValueError):
    pass


def plan(*, backup_name: str, backup_sha256: str, old_application_image: str,
         candidate_application_image: str, database_image: str,
         source_schema: int, candidate_schema: int, application_count: int,
         captured_at_utc: str, env_file: Path, compose_file: Path,
         python_compose_file: Path, output: Path) -> dict[str, object]:
    if BACKUP_NAME.fullmatch(backup_name) is None:
        raise SwitchError("backup name is not an exact pre-upgrade identity")
    if DIGEST.fullmatch(backup_sha256) is None:
        raise SwitchError("backup SHA-256 is invalid")
    for label, value in (("old application", old_application_image),
                         ("candidate application", candidate_application_image),
                         ("database", database_image)):
        if IMAGE.fullmatch(value) is None:
            raise SwitchError(label + " image must be an exact sha256 identity")
    if old_application_image == candidate_application_image:
        raise SwitchError("old and candidate application images must differ")
    if (isinstance(source_schema, bool) or not isinstance(source_schema, int)
            or isinstance(candidate_schema, bool)
            or not isinstance(candidate_schema, int)
            or source_schema < 1 or candidate_schema <= source_schema):
        raise SwitchError("schema transition is invalid")
    if isinstance(application_count, bool) or application_count not in (5, 6):
        raise SwitchError("application count must be five or six")
    if UTC.fullmatch(captured_at_utc) is None:
        raise SwitchError("capture time is invalid")
    try:
        datetime.strptime(captured_at_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as failure:
        raise SwitchError("capture time is invalid") from failure
    for label, path in (("environment", env_file), ("Compose", compose_file),
                        ("Python Compose", python_compose_file)):
        if not path.is_absolute() or not path.is_file():
            raise SwitchError(label + " file is unavailable")
    if not output.is_absolute() or output.exists():
        raise SwitchError("output must be a new absolute path")
    return {
        "format": "openepm-macos-pilot-disposable-service-switch-plan-v1",
        "sharedPilotMutation": False,
        "ownedDisposableServiceSwitch": True,
        "backup": {"name": backup_name, "sha256": backup_sha256},
        "oldApplicationImage": old_application_image,
        "candidateApplicationImage": candidate_application_image,
        "databaseImage": database_image,
        "sourceSchema": source_schema,
        "candidateSchema": candidate_schema,
        "applicationCount": application_count,
        "capturedAtUtc": captured_at_utc,
        "envFile": str(env_file),
        "composeFile": str(compose_file),
        "pythonComposeFile": str(python_compose_file),
        "output": str(output),
    }


def run(argv: list[str], *, environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(argv, cwd=ROOT, env=environment, text=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise RuntimeError((completed.stderr or completed.stdout).strip()
                           or "command failed")
    return completed.stdout.strip()


def docker(*arguments: str) -> str:
    return run(["docker", *arguments])


def docker_logs(container: str) -> str:
    completed = subprocess.run(
        ["docker", "logs", "--tail", "80", container], cwd=ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return (completed.stdout + completed.stderr).strip()


def file_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as failure:
        raise SwitchError("protected pilot environment is unreadable") from failure
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise SwitchError("protected pilot environment contains an invalid line")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            raise SwitchError("protected pilot environment key is invalid or repeated")
        values[key] = value
    required = {
        "EPM_AUTH_MODE", "EPM_OIDC_ISSUER", "EPM_OIDC_JWKS_URL",
        "EPM_OIDC_AUD_MCP", "EPM_OIDC_AUD_WEB", "EPM_PUBLIC_WEB_ORIGIN",
        "EPM_PUBLIC_MCP_ORIGIN", "EPM_PLATFORM_OPERATOR_ISSUER",
        "EPM_PLATFORM_OPERATOR_SUBJECT", "EPM_PG_WORKSPACE_ID",
    }
    if required - values.keys() or any(not values[key] for key in required):
        raise SwitchError("protected pilot environment is incomplete")
    if values["EPM_AUTH_MODE"] != "oidc":
        raise SwitchError("shared pilot authentication mode is not OIDC")
    if values.get("EPM_PILOT_PYTHON_BUILD_ENABLED", "0") not in ("0", "1"):
        raise SwitchError("shared Python-build setting is invalid")
    return values


def write_phase_environment(source: dict[str, str], target: Path,
                            secret_dir: Path) -> dict[str, str]:
    values = dict(source)
    values.update({
        "EPM_POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_RUNTIME_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_ACCESS_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_WORKER_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_LIFECYCLE_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_PROVISION_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_SECURITY_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_PYTHON_COORDINATOR_PASSWORD": secrets.token_urlsafe(32),
        "EPM_PG_PREVIEW_SECRET_HEX": secrets.token_hex(32),
        "EPM_PILOT_PYTHON_SECRET_DIR": str(secret_dir),
    })
    target.write_text("".join(key + "=" + value + "\n"
                              for key, value in sorted(values.items())),
                      encoding="utf-8")
    target.chmod(0o600)
    return values


def write_python_secrets(directory: Path, values: dict[str, str],
                         application_image: str, project: str) -> None:
    directory.mkdir(mode=0o700)
    files = {
        "epm_worker_dsn": ("host=db port=5432 user=epm_worker_login password="
                           + values["EPM_PG_WORKER_PASSWORD"] + " dbname=postgres"),
        "epm_runtime_dsn": ("host=db port=5432 user=epm_runtime_login password="
                            + values["EPM_PG_RUNTIME_PASSWORD"] + " dbname=postgres"),
        "epm_preview_secret": values["EPM_PG_PREVIEW_SECRET_HEX"],
        "epm_python_coordinator_password":
            values["EPM_PG_PYTHON_COORDINATOR_PASSWORD"],
        "epm_python_coordinator_dsn": (
            "host=db port=5432 user=epm_python_coordinator_login password="
            + values["EPM_PG_PYTHON_COORDINATOR_PASSWORD"] + " dbname=postgres"),
        "epm_python_build_capability_key": secrets.token_urlsafe(48),
        "epm_python_builder_profiles.json": json.dumps({"profiles": [{
            "environmentId": "service-switch-only",
            "environmentVersion": 1,
            "image": application_image,
            "network": project + "_sandbox",
            "compilerVersions": ["openepm-python-v1"],
        }]}, sort_keys=True),
        "epm_sandbox_control_key": secrets.token_urlsafe(48),
        # Required by the pilot's protected-directory contract but never used
        # by this broker-only qualification.
        "sandbox-launcher.pyz": "qualification-broker-only\n",
        "manifest.json": json.dumps({"qualification": "broker-only"}),
    }
    for name, content in files.items():
        path = directory / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o400)


def compose_override(application_image: str, database_image: str) -> str:
    lines = ["services:"]
    app_services = ("migrate", "bootstrap-roles", "bootstrap-operator",
                    "platform", "workspace", "router", "web",
                    "worker", "reset-apply", "python-build-secret-init",
                    "bootstrap-python-coordinator", "python-build-broker")
    # ``db`` starts ``backup-volume-init`` through depends_on, so freeze that
    # helper as well; no qualification step may fall back to a mutable local
    # database tag while claiming exact-image execution.
    for service in ("backup-volume-init", "db", *app_services):
        image = database_image if service == "db" else application_image
        if service == "backup-volume-init":
            image = database_image
        lines.extend((f"  {service}:", f"    image: {image}",
                      "    build: !reset null", "    pull_policy: never"))
        if service in PORTS:
            lines.append("    ports: !override [\"127.0.0.1:%d:%d\"]" %
                         (PORTS[service], INTERNAL_PORTS[service]))
        elif service == "python-build-broker":
            lines.append("    networks: !override [default]")
    return "\n".join(lines) + "\n"


def compose_base(frontend: list[str], project: str, env_file: Path,
                 compose_file: Path, python_compose_file: Path,
                 override: Path) -> list[str]:
    if PROJECT.fullmatch(project) is None or project == SOURCE_PROJECT:
        raise SwitchError("owned project identity is unsafe")
    return [*frontend, "--project-name", project, "--env-file", str(env_file),
            "-f", str(compose_file), "-f", str(python_compose_file),
            "-f", str(override)]


def compose(base: list[str], *arguments: str,
            environment: dict[str, str]) -> str:
    return run([*base, *arguments], environment=environment)


def cleanup_owned_project(project: str) -> None:
    """Remove only resources carrying one validated disposable project label."""
    if PROJECT.fullmatch(project) is None or project == SOURCE_PROJECT:
        raise SwitchError("refusing cleanup of an unsafe project identity")
    label = "label=com.docker.compose.project=" + project
    containers = docker("ps", "-aq", "--filter", label).splitlines()
    if containers:
        docker("rm", "-f", *containers)
    volumes = docker("volume", "ls", "-q", "--filter", label).splitlines()
    for volume in volumes:
        docker("volume", "rm", volume)
    networks = docker("network", "ls", "-q", "--filter", label).splitlines()
    for network in networks:
        docker("network", "rm", network)


def wait_health(container: str, service: str) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        status = docker("inspect", "-f", "{{if .State.Health}}"
                        "{{.State.Health.Status}}{{else}}missing{{end}}", container)
        if status == "healthy":
            return
        if status == "unhealthy":
            health = docker("inspect", "-f", "{{json .State.Health.Log}}",
                            container)
            logs = docker_logs(container)
            raise RuntimeError(
                "service became unhealthy: " + service +
                "\nhealth=" + health[-6000:] + "\nlogs=" + logs[-6000:])
        time.sleep(.5)
    logs = docker_logs(container)
    raise RuntimeError("service health timed out: " + service +
                       "\nlogs=" + logs[-6000:])


def schema_state(container: str) -> dict[str, object]:
    raw = docker("exec", container, "psql", "-U", "postgres", "-d",
                 "postgres", "-AtX", "-v", "ON_ERROR_STOP=1", "-c", """
        SELECT json_build_object(
          'rows',count(*),'minimum',min(version),'maximum',max(version),
          'orderedDigestMd5',md5(string_agg(
            version::text||':'||checksum,',' ORDER BY version)),
          'sha256Shape',bool_and(checksum ~ '^[0-9a-f]{64}$'))
        FROM epm.schema_migration""")
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("sha256Shape") is not True:
        raise RuntimeError("schema identity is invalid")
    return value


def application_count(container: str) -> int:
    value = docker("exec", container, "psql", "-U", "postgres", "-d",
                   "postgres", "-AtX", "-c",
                   "SELECT count(*) FROM epm.application")
    if not value.isdecimal():
        raise RuntimeError("application count is invalid")
    return int(value)


def create_login_roles(container: str, values: dict[str, str]) -> None:
    statements = []
    for login, group, key in LOGIN_ROLES:
        password = values[key]
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,}", password):
            raise SwitchError("generated service password is unsafe")
        statements.append(
            f"CREATE ROLE {login} LOGIN INHERIT PASSWORD '{password}' "
            "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;"
            f" GRANT {group} TO {login};")
    docker("exec", container, "psql", "-U", "postgres", "-d", "postgres",
           "-v", "ON_ERROR_STOP=1", "-c", " ".join(statements))


def unsigned_status(service: str) -> int:
    method = "GET" if service == "web" else "POST"
    data = None if method == "GET" else b"{}"
    query = request.Request(
        f"http://127.0.0.1:{PORTS[service]}/" +
        ("" if service == "web" else "mcp"), data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {})
    try:
        with request.build_opener(request.ProxyHandler({})).open(
                query, timeout=5) as response:
            return response.status
    except error.HTTPError as failure:
        return failure.code


def inspect_exact(container: str, image: str, *, health: bool) -> dict[str, object]:
    value = json.loads(docker("inspect", container))[0]
    state = value["State"]
    if value.get("Image") != image or state.get("Running") is not True:
        raise RuntimeError("service image/process identity differs")
    if health and (state.get("Health") or {}).get("Status") != "healthy":
        raise RuntimeError("service health differs")
    if not health and state.get("Health") is not None:
        raise RuntimeError("broker unexpectedly has a Docker healthcheck")
    return {"image": image, "running": True,
            "health": "healthy" if health else "not-configured"}


def broker_denial(container: str) -> int:
    code = docker("exec", container, "python", "-c", """
import json,urllib.error,urllib.request
from openepm.metadata_references import BOOTSTRAP_CONTRACT_DIGEST
body=json.dumps({'workspaceId':'w','applicationId':'a','buildId':'b',
 'claimGeneration':1,'action':'python.build.source.read',
 'capabilityToken':'invalid',
 'authoringContractDigest':BOOTSTRAP_CONTRACT_DIGEST}).encode()
q=urllib.request.Request('http://127.0.0.1:5198/internal/python-build/read',
 data=body,headers={'content-type':'application/json'},method='POST')
try:
 urllib.request.urlopen(q,timeout=5); print('200:UNEXPECTED_SUCCESS')
except urllib.error.HTTPError as e:
 payload=json.loads(e.read())
 print(f"{e.code}:{payload.get('error')}")
""")
    if code != "403:CAPABILITY_DENIED":
        raise RuntimeError("broker did not deny an invalid capability")
    return 403


def wait_broker_ready(container: str, timeout_seconds: float = 30) -> int:
    """Require the broker process to serve its authenticated denial boundary."""
    if (not isinstance(container, str) or not container
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0 or timeout_seconds > 120):
        raise ValueError("BROKER_READINESS_ARGUMENT_INVALID")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            return broker_denial(container)
        except (RuntimeError, json.JSONDecodeError):
            time.sleep(.25)
    raise RuntimeError("Python build broker did not become ready")


def shared_base(frontend: list[str], env_file: Path, compose_file: Path,
                python_compose_file: Path) -> list[str]:
    base = [*frontend, "--project-name", SOURCE_PROJECT, "--env-file",
            str(env_file), "-f", str(compose_file)]
    if protected_env_value(env_file, "EPM_PILOT_PYTHON_BUILD_ENABLED") == "1":
        base.extend(("-f", str(python_compose_file)))
    return base


def shared_fingerprint(record: dict[str, object]) -> dict[str, object]:
    services = record.get("services")
    if not isinstance(services, dict):
        raise SwitchError("shared capture has no service inventory")
    return {
        "applicationImage": record.get("applicationImage"),
        "databaseImage": record.get("databaseImage"),
        "schema": record.get("schema"),
        "applicationCount": record.get("applicationCount"),
        "pythonBuildBrokerEnabled": record.get("pythonBuildBrokerEnabled"),
        "services": {name: {
            "imageId": item.get("imageId"), "running": item.get("running"),
            "healthConfigured": item.get("healthConfigured"),
            "healthStatus": item.get("healthStatus")}
            for name, item in sorted(services.items())},
        "ports": record.get("ports"),
        "unsignedDenials": record.get("unsignedDenials"),
    }


def phase(*, name: str, project: str, application_image: str,
          expected_schema: int, archive: Path, base: list[str],
          environment: dict[str, str], python_enabled: bool) -> dict[str, object]:
    compose(base, "--profile", "setup", "up", "--no-build", "-d", "db",
            environment=environment)
    db = compose(base, "ps", "-q", "db", environment=environment)
    if not re.fullmatch(r"[0-9a-f]{12,64}", db):
        raise RuntimeError("owned database container is missing")
    wait_health(db, name + ":db")
    database_observation = inspect_exact(
        db, environment["EPM_DATABASE_IMAGE"], health=True)
    docker("cp", str(archive), db + ":/tmp/pilot.dump")
    docker("exec", "-u", "0:0", db, "chmod", "0444", "/tmp/pilot.dump")
    acl_text = docker("exec", db, "sh", "-ec",
                      "pg_restore --list /tmp/pilot.dump | "
                      "awk '/ ACL | DEFAULT ACL / {n++} END {print n+0}'")
    if not acl_text.isdecimal() or int(acl_text) <= 0:
        raise SwitchError("protected archive has no privilege ACL entries")
    create_group_roles(db)
    docker("exec", db, "pg_restore", "-U", "postgres", "-d", "postgres",
           "--exit-on-error", "--no-owner", "/tmp/pilot.dump")
    archive_digest = logical_data_digest(db)
    source_schema = schema_state(db)
    source_count = application_count(db)
    create_login_roles(db, environment)
    compose(base, "--profile", "setup", "run", "--rm", "migrate",
            environment=environment)
    current_schema = schema_state(db)
    if current_schema.get("maximum") != expected_schema:
        raise SwitchError(name + " schema differs from expectation")
    if application_count(db) != source_count:
        raise SwitchError(name + " migration changed application count")
    if python_enabled:
        # The router startup contract requires the deployment-owned builder
        # profile even when no build is executed.  Match the real controller:
        # initialize protected Python secrets before starting core services.
        compose(base, "--profile", "python-build-setup", "run", "--rm",
                "python-build-secret-init", environment=environment)
    observed: dict[str, object] = {}
    denials: dict[str, int] = {}
    for service in SERVICE_ORDER:
        profiles = ("--profile", "workspace") if service == "workspace" \
            else ("--profile", "v2")
        compose(base, *profiles, "up", "--no-build", "-d", service,
                environment=environment)
        container = compose(base, "ps", "-q", service,
                            environment=environment)
        wait_health(container, name + ":" + service)
        observed[service] = inspect_exact(
            container, application_image, health=True)
        if service in PORTS:
            status = unsigned_status(service)
            if status != 401:
                raise SwitchError(name + " unsigned boundary did not return 401")
            denials[service] = status
        compose(base, "stop", service, environment=environment)
        compose(base, "rm", "-f", service, environment=environment)
    broker: dict[str, object] = {"enabled": python_enabled,
                                "buildExecutionTested": False}
    if python_enabled:
        compose(base, "--profile", "python-build", "up", "--no-build", "-d",
                "python-build-broker", environment=environment)
        container = compose(base, "ps", "-q", "python-build-broker",
                            environment=environment)
        denied = wait_broker_ready(container)
        broker.update(inspect_exact(
            container, application_image, health=False))
        broker["invalidCapabilityStatus"] = denied
        compose(base, "stop", "python-build-broker", environment=environment)
        compose(base, "rm", "-f", "python-build-broker",
                environment=environment)
    compose(base, "stop", "db", environment=environment)
    return {
        "project": project,
        "applicationImage": application_image,
        "databaseImage": database_observation["image"],
        "databaseHealth": database_observation,
        "archiveSchema": source_schema,
        "schema": current_schema,
        "applicationCount": source_count,
        "archiveLogicalDataSha256": archive_digest,
        "archiveAclEntries": int(acl_text),
        "services": observed,
        "unsignedDenials": denials,
        "healthPassed": True,
        "unsignedDenialsPassed": True,
        "pythonBuildBroker": broker,
    }


def execute(value: dict[str, object]) -> dict[str, object]:
    if os.environ.get("EPM_PILOT_SERVICE_SWITCH_DISPOSABLE") != "1":
        raise SwitchError("owned disposable service-switch opt-in is required")
    for port in PORTS.values():
        with socket.socket() as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                raise SwitchError("qualification port is already occupied")
    frontend = compose_frontend()
    env_file = Path(str(value["envFile"]))
    compose_file = Path(str(value["composeFile"]))
    python_compose_file = Path(str(value["pythonComposeFile"]))
    source_values = parse_env(env_file)
    python_enabled = source_values.get("EPM_PILOT_PYTHON_BUILD_ENABLED") == "1"
    before = capture_running(
        shared_base(frontend, env_file, compose_file, python_compose_file),
        captured_at=str(value["capturedAtUtc"]))
    before_fp = shared_fingerprint(before)
    if before_fp["applicationImage"] != value["oldApplicationImage"] \
            or before_fp["databaseImage"] != value["databaseImage"] \
            or before_fp["schema"].get("maximum") != value["sourceSchema"] \
            or before_fp["applicationCount"] != value["applicationCount"]:
        raise SwitchError("shared pilot differs from the requested source identity")
    token = secrets.token_hex(6)
    candidate_project = "openepm-pilot-switch-" + token + "-candidate"
    rollback_project = "openepm-pilot-switch-" + token + "-rollback"
    cleanup_errors: list[str] = []
    projects: list[tuple[list[str], dict[str, str]]] = []
    backup = value["backup"]
    assert isinstance(backup, dict)
    source_path = BACKUP_ROOT + "/" + str(backup["name"])
    with tempfile.TemporaryDirectory(
            prefix=".epm-pilot-service-switch-", dir=ROOT) as temporary:
        folder = Path(temporary)
        archive = folder / str(backup["name"])
        try:
            docker("cp", SOURCE_CONTAINER + ":" + source_path, str(archive))
            if file_digest(archive) != backup["sha256"]:
                raise SwitchError("protected backup SHA-256 mismatch")
            results: dict[str, dict[str, object]] = {}
            for phase_name, project, image, expected in (
                    ("candidate", candidate_project,
                     str(value["candidateApplicationImage"]),
                     int(value["candidateSchema"])),
                    ("rollback", rollback_project,
                     str(value["oldApplicationImage"]),
                     int(value["sourceSchema"]))):
                phase_dir = folder / phase_name
                phase_dir.mkdir(mode=0o700)
                secrets_dir = phase_dir / "secrets"
                phase_env = phase_dir / "compose.env"
                phase_values = write_phase_environment(
                    source_values, phase_env, secrets_dir)
                phase_values["EPM_APPLICATION_IMAGE"] = image
                phase_values["EPM_DATABASE_IMAGE"] = str(value["databaseImage"])
                write_python_secrets(secrets_dir, phase_values, image, project)
                override = phase_dir / "override.yaml"
                override.write_text(compose_override(
                    image, str(value["databaseImage"])), encoding="utf-8")
                override.chmod(0o600)
                base = compose_base(frontend, project, phase_env, compose_file,
                                    python_compose_file, override)
                process_env = os.environ.copy()
                process_env.update(phase_values)
                projects.append((base, process_env))
                results[phase_name] = phase(
                    name=phase_name, project=project,
                    application_image=image, expected_schema=expected,
                    archive=archive, base=base, environment=process_env,
                    python_enabled=python_enabled)
                if results[phase_name]["applicationCount"] \
                        != value["applicationCount"]:
                    raise SwitchError(phase_name + " application count differs")
                if results[phase_name]["archiveSchema"].get("maximum") \
                        != value["sourceSchema"]:
                    raise SwitchError(phase_name + " archive schema differs")
            if results["candidate"]["archiveLogicalDataSha256"] \
                    != results["rollback"]["archiveLogicalDataSha256"]:
                raise SwitchError("candidate and rollback archives differ logically")
            if results["candidate"]["archiveSchema"] != before_fp["schema"] \
                    or results["rollback"]["archiveSchema"] != before_fp["schema"]:
                raise SwitchError("restored archive schema differs from shared source")
            # Candidate project/volume still exists here, after rollback passed.
            candidate_volumes = docker("volume", "ls", "--filter",
                "label=com.docker.compose.project=" + candidate_project,
                "--format", "{{.Name}}")
            rollback_volumes = docker("volume", "ls", "--filter",
                "label=com.docker.compose.project=" + rollback_project,
                "--format", "{{.Name}}")
            candidate_set = set(candidate_volumes.splitlines())
            rollback_set = set(rollback_volumes.splitlines())
            if not candidate_set or not rollback_set or candidate_set & rollback_set:
                raise SwitchError(
                    "candidate and rollback volumes are absent or not distinct")
            after = capture_running(
                shared_base(frontend, env_file, compose_file,
                            python_compose_file),
                captured_at=str(value["capturedAtUtc"]))
            after_fp = shared_fingerprint(after)
            if before_fp != after_fp:
                raise SwitchError("shared pilot changed during qualification")
            public_plan = {key: item for key, item in value.items()
                           if key not in ("envFile", "composeFile",
                                          "pythonComposeFile")}
            result = {
                **public_plan,
                "format": "openepm-macos-pilot-disposable-service-switch-v1",
                "planFormat": value["format"],
                "passed": True,
                "ownedDisposableServiceSwitchTested": True,
                "liveSharedPilotMutationTested": False,
                "sourceBefore": before_fp,
                "sourceAfter": after_fp,
                "sharedPilotUnchanged": True,
                "candidate": results["candidate"],
                "rollback": results["rollback"],
                "sourceStateRestored": True,
                "candidateVolumePreservedUntilRollbackPassed": True,
                "switchSequence": ["candidate-services-running-sequentially",
                                   "candidate-services-stopped",
                                   "rollback-services-running-sequentially",
                                   "rollback-services-stopped"],
                "pythonBuildBrokerEnabled": python_enabled,
                "limitations": [
                    "Services were qualified sequentially to stay within the "
                    "owner Mac's bounded Docker memory; this is not a capacity test.",
                    "The shared pilot, public tunnel ingress and business data were "
                    "not switched or mutated.",
                    "The broker process and invalid-capability denial were tested; "
                    "a real sandbox build and launcher-network switch were not.",
                    "An actual activation requires a new quiesced backup and has a "
                    "point of no return before candidate writes are admitted.",
                ],
            }
        finally:
            for base, process_env in reversed(projects):
                try:
                    compose(base, "down", "--volumes", "--remove-orphans",
                            environment=process_env)
                except Exception as failure:
                    cleanup_errors.append(str(failure))
            for project in (candidate_project, rollback_project):
                try:
                    cleanup_owned_project(project)
                except Exception as failure:
                    cleanup_errors.append(str(failure))
            if cleanup_errors:
                raise RuntimeError("owned service-switch cleanup failed: " +
                                   "; ".join(cleanup_errors))
    for project in (candidate_project, rollback_project):
        if docker("ps", "-a", "--filter", "label=com.docker.compose.project=" +
                  project, "--format", "{{.ID}}").strip() \
                or docker("volume", "ls", "--filter",
                          "label=com.docker.compose.project=" + project,
                          "--format", "{{.Name}}").strip() \
                or docker("network", "ls", "--filter",
                          "label=com.docker.compose.project=" + project,
                          "--format", "{{.Name}}").strip():
            raise RuntimeError("owned service-switch resources remain after cleanup")
    result["cleanup"] = {
        "candidateProjectRemoved": True,
        "rollbackProjectRemoved": True,
        "ownedVolumesRemoved": True,
        "temporaryArchiveCopyRemoved": True,
        "cleanupErrors": [],
    }
    return result


def write_evidence(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="." + path.name + ".", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-name", required=True)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--old-application-image", required=True)
    parser.add_argument("--candidate-application-image", required=True)
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--source-schema", type=int, required=True)
    parser.add_argument("--candidate-schema", type=int, required=True)
    parser.add_argument("--application-count", type=int, required=True)
    parser.add_argument("--captured-at-utc", required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--compose-file", type=Path, required=True)
    parser.add_argument("--python-compose-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        value = plan(
            backup_name=arguments.backup_name,
            backup_sha256=arguments.backup_sha256,
            old_application_image=arguments.old_application_image,
            candidate_application_image=arguments.candidate_application_image,
            database_image=arguments.database_image,
            source_schema=arguments.source_schema,
            candidate_schema=arguments.candidate_schema,
            application_count=arguments.application_count,
            captured_at_utc=arguments.captured_at_utc,
            env_file=arguments.env_file,
            compose_file=arguments.compose_file,
            python_compose_file=arguments.python_compose_file,
            output=arguments.output)
        if not arguments.execute:
            print(json.dumps(value, sort_keys=True))
            return 0
        result = execute(value)
        write_evidence(arguments.output, result)
    except (OSError, SwitchError, RuntimeError, json.JSONDecodeError) as failure:
        parser.error(str(failure))
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
