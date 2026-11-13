#!/usr/bin/env python3
"""Capture read-only exact state for Mac-pilot upgrade readiness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import socket
import subprocess
from urllib import error, request


IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
NETWORK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SERVICES = ("db", "platform", "workspace", "router", "web", "worker")
APP_SERVICES = SERVICES[1:]
OPTIONAL_SERVICE = "python-build-broker"
ENDPOINTS = {
    "web": ("GET", "http://127.0.0.1:5195/"),
    "platformMcp": ("POST", "http://127.0.0.1:5193/mcp"),
    "workspaceMcp": ("POST", "http://127.0.0.1:5192/mcp"),
    "applicationMcp": ("POST", "http://127.0.0.1:5194/mcp"),
}


class CaptureError(ValueError):
    pass


def system_run(argv: list[str]) -> str:
    completed = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise CaptureError("read-only command failed: " + completed.stderr.strip())
    return completed.stdout.strip()


def compose_frontend(run=system_run) -> list[str]:
    """Select the same supported Compose frontends as the pilot controller."""
    try:
        run(["docker", "compose", "version"])
        return ["docker", "compose"]
    except CaptureError as docker_plugin_error:
        try:
            run(["docker-compose", "version"])
            return ["docker-compose"]
        except CaptureError as standalone_error:
            raise CaptureError("Docker Compose is unavailable") from (
                standalone_error if standalone_error else docker_plugin_error)


def protected_env_value(path: Path, key: str) -> str:
    try:
        matches = [line[len(key) + 1:] for line in path.read_text(
            encoding="utf-8").splitlines() if line.startswith(key + "=")]
    except (OSError, UnicodeError) as error:
        raise CaptureError("pilot environment is unavailable") from error
    if len(matches) > 1:
        raise CaptureError(f"pilot environment repeats {key}")
    return matches[0] if matches else ""


def default_port_probe(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            return True
    except OSError:
        return False


def default_unsigned_probe(method: str, url: str) -> int:
    data = b"{}" if method == "POST" else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    query = request.Request(url, data=data, headers=headers, method=method)
    opener = request.build_opener(request.ProxyHandler({}))
    try:
        with opener.open(query, timeout=5) as response:
            return response.status
    except error.HTTPError as failure:
        return failure.code
    except OSError as failure:
        raise CaptureError("unsigned boundary probe failed") from failure


def capture(base: list[str], *, run=system_run,
            port_probe=default_port_probe,
            unsigned_probe=default_unsigned_probe,
            captured_at: str) -> dict:
    running_names = tuple(filter(None, run(
        [*base, "ps", "--status", "running", "--services"]).splitlines()))
    allowed = {*SERVICES, OPTIONAL_SERVICE}
    if not set(SERVICES).issubset(running_names) \
            or len(running_names) != len(set(running_names)) \
            or set(running_names) - allowed:
        raise CaptureError("running Compose service inventory is incomplete or unexpected")
    broker_enabled = OPTIONAL_SERVICE in running_names
    selected_services = (*SERVICES, *((OPTIONAL_SERVICE,) if broker_enabled else ()))
    observed: dict[str, dict] = {}
    network_references: dict[str, str] = {}
    app_image: str | None = None
    db_image: str | None = None
    app_labels: dict[str, str] | None = None
    for service in selected_services:
        identity = run([*base, "ps", "-q", service])
        if re.fullmatch(r"[0-9a-f]{12,64}", identity) is None:
            raise CaptureError(f"expected one running container for {service}")
        try:
            inspected = json.loads(run(["docker", "inspect", identity]))
            item = inspected[0]
            state, config = item["State"], item["Config"]
            networks = item["NetworkSettings"]["Networks"]
            labels = config.get("Labels") or {}
            image = item["Image"]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as failure:
            raise CaptureError(f"invalid Docker inspection for {service}") from failure
        health = state.get("Health")
        if service == OPTIONAL_SERVICE:
            health_valid = health is None
            health_fields = {"healthConfigured": False,
                             "healthStatus": "not-configured"}
        else:
            health_valid = isinstance(health, dict) and health.get("Status") == "healthy"
            health_fields = {"healthConfigured": True, "healthStatus": "healthy"}
        if not isinstance(networks, dict) or not networks or len(networks) > 4 \
                or any(not isinstance(name, str) or NETWORK_NAME.fullmatch(name) is None
                       or not isinstance(details, dict)
                       or not isinstance(details.get("NetworkID"), str)
                       or DIGEST.fullmatch(details["NetworkID"]) is None
                       for name, details in networks.items()):
            raise CaptureError(f"container network identity is invalid: {service}")
        for name, details in networks.items():
            previous = network_references.setdefault(name, details["NetworkID"])
            if previous != details["NetworkID"]:
                raise CaptureError("services disagree about Docker network identity")
        if not isinstance(image, str) or IMAGE.fullmatch(image) is None \
                or state.get("Running") is not True or not health_valid \
                or labels.get("com.docker.compose.project") != "openepm-macos-pilot" \
                or labels.get("com.docker.compose.service") != service:
            raise CaptureError(f"container is not exact, healthy, and project-bound: {service}")
        observed[service] = {"containerId": identity, "imageId": image,
                             "running": True, **health_fields,
                             "networks": {name: details["NetworkID"]
                                          for name, details in sorted(networks.items())}}
        if service == "db":
            db_image = image
        else:
            if app_image is not None and image != app_image:
                raise CaptureError("application services use different images")
            app_image = image
            exact_labels = {key: labels.get(key) for key in
                ("org.openepm.qualification", "org.openepm.source.commit",
                 "org.openepm.source.tree")}
            commit = exact_labels["org.openepm.source.commit"]
            tree = exact_labels["org.openepm.source.tree"]
            labels_complete = (
                isinstance(commit, str) and GIT_ID.fullmatch(commit) is not None
                and isinstance(tree, str) and GIT_ID.fullmatch(tree) is not None)
            labels_legacy_empty = commit == "" and tree == ""
            if exact_labels["org.openepm.qualification"] != "schema163-public-parity" \
                    or not (labels_complete or labels_legacy_empty):
                raise CaptureError("application source labels are invalid")
            if app_labels is not None and exact_labels != app_labels:
                raise CaptureError("application services have different source labels")
            app_labels = exact_labels
    network_inventory: dict[str, dict] = {}
    for name, network_id in sorted(network_references.items()):
        try:
            inspected_network = json.loads(run(["docker", "network", "inspect", name]))
            network = inspected_network[0]
            labels = network.get("Labels") or {}
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as failure:
            raise CaptureError("Docker network inspection is invalid") from failure
        if network.get("Id") != network_id or network.get("Name") != name \
                or network.get("Driver") != "bridge" or network.get("Scope") != "local" \
                or not isinstance(network.get("Internal"), bool) \
                or not isinstance(network.get("Attachable"), bool) \
                or not isinstance(labels, dict):
            raise CaptureError("Docker network identity or properties differ")
        network_inventory[name] = {
            "networkId": network_id, "driver": "bridge", "scope": "local",
            "internal": network["Internal"], "attachable": network["Attachable"],
            "composeProject": labels.get("com.docker.compose.project", ""),
            "composeNetwork": labels.get("com.docker.compose.network", ""),
        }
    schema_sql = """SELECT json_build_object(
      'rows',count(*),'minimum',min(version),'maximum',max(version),
      'orderedDigestMd5',md5(string_agg(version::text||':'||checksum,',' ORDER BY version)),
      'sha256Shape',bool_and(checksum ~ '^[0-9a-f]{64}$'))
      FROM epm.schema_migration"""
    count_sql = "SELECT json_build_object('applications',count(*)) FROM epm.application"
    def sql(statement: str) -> dict:
        raw = run([*base, "exec", "-T", "db", "psql", "-U", "postgres",
                   "-d", "postgres", "-AtX", "-v", "ON_ERROR_STOP=1",
                   "-c", statement])
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as failure:
            raise CaptureError("database observation is invalid") from failure
        if not isinstance(value, dict):
            raise CaptureError("database observation is invalid")
        return value
    schema, count = sql(schema_sql), sql(count_sql)
    if schema.get("sha256Shape") is not True:
        raise CaptureError("schema ledger checksum shape is invalid")
    applications = count.get("applications")
    if not isinstance(applications, int) or isinstance(applications, bool) \
            or applications not in (5, 6):
        raise CaptureError("pilot must contain five or six applications")
    pg_dump_version = run([*base, "exec", "-T", "db", "pg_dump", "--version"])
    if not pg_dump_version.startswith("pg_dump (PostgreSQL) ") \
            or len(pg_dump_version) > 128:
        raise CaptureError("pg_dump version identity is invalid")
    logical_raw = run([*base, "exec", "-T", "db", "bash", "-o", "pipefail",
        "-ec", "pg_dump -U postgres -d postgres --data-only --column-inserts "
        "--rows-per-insert=1 --no-owner --no-acl "
        "--restrict-key=openepmpilotcapturev1 | sha256sum"])
    logical_data = logical_raw.split()[0] if logical_raw else ""
    if DIGEST.fullmatch(logical_data) is None:
        raise CaptureError("logical data fingerprint is invalid")
    business_raw = run([*base, "exec", "-T", "db", "bash", "-o", "pipefail",
        "-ec", "pg_dump -U postgres -d postgres --data-only --column-inserts "
        "--rows-per-insert=1 --no-owner --no-acl "
        "--exclude-table-data=epm.schema_migration "
        "--restrict-key=openepmpilotbusinessv1 | sha256sum"])
    business_data = business_raw.split()[0] if business_raw else ""
    if DIGEST.fullmatch(business_data) is None:
        raise CaptureError("business-data fingerprint is invalid")
    ports = {str(port): "listening" if port_probe(port) else "closed"
             for port in (5192, 5193, 5194, 5195)}
    if any(value != "listening" for value in ports.values()):
        raise CaptureError("one or more pilot loopback ports are closed")
    denials = {name: unsigned_probe(*probe) for name, probe in ENDPOINTS.items()}
    if any(status != 401 for status in denials.values()):
        raise CaptureError("one or more unsigned boundaries did not return 401")
    assert app_image is not None and db_image is not None and app_labels is not None
    return {"format": "openepm-macos-pilot-running-state-v1",
            "project": "openepm-macos-pilot", "capturedAtUtc": captured_at,
            "applicationImage": app_image, "databaseImage": db_image,
            "applicationLabels": app_labels,
            "applicationSourceLabelsComplete": bool(
                app_labels["org.openepm.source.commit"]),
            "schema": schema,
            "applicationCount": applications,
            "dataDumpFingerprintSha256": logical_data,
            "dataDumpFingerprintProfile": {
                "kind": "pg_dump-data-only-column-inserts-v1",
                "pgDumpVersion": pg_dump_version,
                "restrictKey": "openepmpilotcapturev1",
                "excludedTables": []},
            "businessDataDumpFingerprintSha256": business_data,
            "businessDataDumpFingerprintProfile": {
                "kind": "pg_dump-data-only-column-inserts-v1",
                "pgDumpVersion": pg_dump_version,
                "restrictKey": "openepmpilotbusinessv1",
                "excludedTables": ["epm.schema_migration"]},
            "captureConsistency": "multi-observation-unquiesced",
            "quiescenceEvidenceSha256": None,
            "networks": network_inventory, "services": observed,
            "pythonBuildBrokerEnabled": broker_enabled,
            "ports": ports, "unsignedDenials": denials, "readOnlyCapture": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--compose-file", type=Path,
                        default=root / "deploy/postgres/compose.yaml")
    parser.add_argument("--env-file", type=Path,
                        default=root / "deploy/macos-pilot/openepm-pilot.env")
    parser.add_argument("--python-compose-file", type=Path,
                        default=root / "deploy/macos-pilot/python-build.compose.yaml")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--captured-at-utc", required=True)
    arguments = parser.parse_args()
    for label, path in (("compose", arguments.compose_file),
                        ("environment", arguments.env_file),
                        ("output", arguments.output)):
        if not path.is_absolute():
            parser.error(f"{label} path must be absolute")
    try:
        enabled = protected_env_value(
            arguments.env_file, "EPM_PILOT_PYTHON_BUILD_ENABLED")
        if enabled not in ("", "0", "1"):
            raise CaptureError("EPM_PILOT_PYTHON_BUILD_ENABLED is invalid")
        base = [*compose_frontend(), "--project-name", "openepm-macos-pilot",
                "--env-file", str(arguments.env_file), "-f",
                str(arguments.compose_file)]
        if enabled == "1":
            if not arguments.python_compose_file.is_absolute() \
                    or not arguments.python_compose_file.is_file():
                raise CaptureError("Python-build Compose override is unavailable")
            base.extend(["-f", str(arguments.python_compose_file)])
        result = capture(base, captured_at=arguments.captured_at_utc)
    except CaptureError as failure:
        parser.error(str(failure))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
