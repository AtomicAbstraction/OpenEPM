#!/usr/bin/env python3
"""Prepare, activate and roll back the retained one-owner writable Mac UAT.

The protected source database is never modified.  ``prepare`` restores its
protected backup into an isolated green project and verifies the complete
schema privately.  ``activate`` moves every public endpoint plus the worker
and Python broker together.  ``rollback`` preserves green data while restoring
the exact database-read-only review that preceded activation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Iterator
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.capture_macos_pilot_running_state import compose_frontend
from scripts import macos_pilot_ui_review as review
from scripts.macos_pilot_active_work import (
    ActiveWorkError, ActiveWorkObserver, FAMILIES, SOURCES,
)
from scripts.qualify_macos_pilot_backup_restore import create_group_roles
from scripts.qualify_macos_pilot_service_switch import (
    BACKUP_ROOT, SOURCE_CONTAINER, application_count, compose,
    compose_override, create_login_roles, docker, file_digest,
    inspect_exact, parse_env, schema_state, wait_broker_ready, wait_health,
    write_phase_environment, write_python_secrets,
)

PROJECT = "openepm-owner-uat-green"
SOURCE_PROJECT = "openepm-macos-pilot"
FORMAT = "openepm-macos-pilot-owner-uat-state-v1"
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
BACKUP = re.compile(r"^pilot-pre-upgrade-[0-9]{8}T[0-9]{6}Z[.]dump$")
APP_SERVICES = ("platform", "workspace", "router", "web", "worker",
                "python-build-broker")
HEALTH_SERVICES = ("platform", "workspace", "router", "web", "worker")
PUBLIC_PORTS = {"workspace": 5192, "platform": 5193,
                "router": 5194, "web": 5195}
PRIVATE_PORTS = {"workspace": 5292, "platform": 5293,
                 "router": 5294, "web": 5295}
MIN_SUSPEND_FREE_KIB = 1024 * 1024
DATABASE_STORAGE_PATH = "/var/lib/postgresql"
MAX_RETAINED_OWNER_UAT_BACKUPS = 5

# The active-work inventory spans lifecycle tables introduced over many
# schema generations.  A retained pre-upgrade generation must not be queried
# for a table that did not exist yet, while a table missing at or after its
# introducing migration must still fail closed.  Keep this fixed allow-list in
# lockstep with ``macos_pilot_active_work.SOURCES``.
SOURCE_INTRODUCED_SCHEMA = {
    "epm.workspace": 1,
    "epm.application": 1,
    "epm.job": 12,
    "epm.source_batch": 15,
    "epm.expression_rule_sequence": 44,
    "epm.full_aggregate_sequence": 54,
    "epm.cube_aggregate_query": 88,
    "epm.python_program_build": 89,
    "epm.python_program_workflow": 89,
    "epm.layout_replacement_request": 107,
    "epm.layout_replacement_activation": 110,
    "epm.fact_export_producer_request": 113,
    "epm.transfer_cleanup_request": 115,
    "epm.python_program_occurrence": 132,
    "epm.python_program_schedule_state": 132,
    "epm.source_import_execution": 151,
    "epm.application_rule_workflow": 217,
    "epm.application_schedule_occurrence": 220,
    "epm.application_schedule_state": 220,
}

# Current-only schedule migrations physically remove the former dispatch-state
# relations after proving admitted work settled. A source is applicable only
# from its introduction through the schema immediately before its retirement.
# Missing any other canonical source continues to fail closed.
SOURCE_RETIRED_SCHEMA = {
    "epm.application_schedule_state": 312,
    "epm.python_program_schedule_state": 315,
}


class OwnerUatError(RuntimeError):
    pass


def safe_root(root: Path) -> None:
    if not root.is_absolute() or root.is_symlink():
        raise OwnerUatError("owner UAT state root is unsafe")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode) \
            or stat.S_IMODE(metadata.st_mode) != 0o700 \
            or metadata.st_uid != os.geteuid():
        raise OwnerUatError("owner UAT state root permissions are unsafe")


@contextmanager
def locked(root: Path) -> Iterator[None]:
    safe_root(root)
    descriptor = os.open(root / "owner-uat.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def state_path(root: Path) -> Path:
    return root / "state.json"


def write_json(path: Path, value: dict) -> None:
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".",
                                        suffix=".partial", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def replace_builder_image(root: Path, old_image: str, new_image: str) -> None:
    path = root / "secrets/epm_python_builder_profiles.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        profiles = value["profiles"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise OwnerUatError("owner UAT builder profile is invalid") from exc
    if (not isinstance(profiles, list) or len(profiles) != 1
            or profiles[0].get("image") != old_image):
        raise OwnerUatError("owner UAT builder image differs")
    profiles[0]["image"] = new_image
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".",
                                        suffix=".partial", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_state(root: Path) -> dict:
    try:
        value = json.loads(state_path(root).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OwnerUatError("owner UAT state is unavailable or invalid") from exc
    if not isinstance(value, dict) or value.get("format") != FORMAT \
            or value.get("project") != PROJECT:
        raise OwnerUatError("owner UAT state differs")
    return value


def exact_inputs(args) -> None:
    if IMAGE.fullmatch(str(args.candidate_image)) is None \
            or IMAGE.fullmatch(str(args.database_image)) is None \
            or BACKUP.fullmatch(str(args.backup_name)) is None \
            or DIGEST.fullmatch(str(args.backup_sha256)) is None \
            or args.expected_schema < 1 \
            or args.expected_applications not in (5, 6):
        raise OwnerUatError("exact owner UAT inputs are required")


def override(application_image: str, database_image: str, *, public: bool) -> str:
    value = compose_override(application_image, database_image)
    web = f"  web:\n    image: {application_image}\n"
    if value.count(web) != 1:
        raise OwnerUatError("owner UAT web image override differs")
    value = value.replace(web, web + "    environment:\n" +
        f"      EPM_RUNTIME_APPLICATION_IMAGE: {application_image}\n")
    ports = PUBLIC_PORTS if public else PRIVATE_PORTS
    for service, private_port in PRIVATE_PORTS.items():
        old = f'127.0.0.1:{private_port}:{5192 if service == "workspace" else 5193 if service == "platform" else 5194 if service == "router" else 5195}'
        internal = PUBLIC_PORTS[service]
        new = f'127.0.0.1:{ports[service]}:{internal}'
        if value.count(old) != 1:
            raise OwnerUatError("owner UAT Compose port shape differs")
        value = value.replace(old, new)
    if "EPM_UI_READ_ONLY_REVIEW" in value:
        raise OwnerUatError("owner UAT override unexpectedly enables review mode")
    return value


def bases(root: Path, *, public: bool) -> tuple[list[str], list[str], dict, dict]:
    compose_file = (ROOT / "deploy/postgres/compose.yaml").resolve()
    python_file = (ROOT / "deploy/macos-pilot/python-build.compose.yaml").resolve()
    source_env = (ROOT / "deploy/macos-pilot/openepm-pilot.env").resolve()
    values = parse_env(root / "compose.env")
    phase_env = {**os.environ, **values}
    # This is a retained owner-UAT project, not one of the disposable
    # ``openepm-pilot-switch-<token>-<phase>`` projects accepted by the
    # service-switch qualifier's deliberately narrow helper.
    target = [*compose_frontend(), "--project-name", PROJECT,
              "--env-file", str(root / "compose.env"),
              "-f", str(compose_file), "-f", str(python_file),
              "-f", str(root / "override.yaml")]
    source_values = parse_env(source_env)
    source = [*compose_frontend(), "--project-name", SOURCE_PROJECT,
              "--env-file", str(source_env), "-f", str(compose_file),
              "-f", str(python_file)]
    return target, source, phase_env, {**os.environ, **source_values}


def all_up(base: list[str], environment: dict, no_deps: bool = False) -> None:
    compose(base, "--profile", "v2", "--profile", "workspace", "--profile",
            "python-build", "up", "--no-build", *(('--no-deps',) if no_deps else ()),
            "-d", "db", *APP_SERVICES,
            environment=environment)


def all_stop(base: list[str], environment: dict) -> None:
    compose(base, "stop", *APP_SERVICES, environment=environment)


def active_work_sources_for_schema(schema: int) -> dict[str, tuple]:
    """Return the canonical work sources that exist in ``schema``.

    This is deliberately schema-history-aware rather than an exception-based
    fallback.  An unexpected missing relation at or after its introducing
    migration therefore remains a hard SQL failure.
    """
    canonical = {
        table for family in FAMILIES
        for table, _status, _active, _terminal in SOURCES[family]
    }
    if (not isinstance(schema, int) or isinstance(schema, bool) or schema < 1
            or set(SOURCE_INTRODUCED_SCHEMA) != canonical
            or not set(SOURCE_RETIRED_SCHEMA).issubset(canonical)
            or any(SOURCE_RETIRED_SCHEMA[table]
                   <= SOURCE_INTRODUCED_SCHEMA[table]
                   for table in SOURCE_RETIRED_SCHEMA)):
        raise ActiveWorkError("active-work schema inventory differs")
    return {
        family: tuple(source for source in SOURCES[family]
                      if SOURCE_INTRODUCED_SCHEMA[source[0]] <= schema
                      and schema < SOURCE_RETIRED_SCHEMA.get(
                          source[0], schema + 1))
        for family in FAMILIES
    }


def verify_no_active_work(base: list[str], environment: dict) -> dict[str, int]:
    """Fail closed before a voluntary owner-UAT service switch.

    The retained database container has no host-published PostgreSQL port.
    Read the canonical native work inventory through local ``psql`` inside that
    exact healthy container, then reuse the same exhaustive classifier as the
    activation runtime. No business row is changed and no credential leaves
    the container.
    """
    database = compose(base, "ps", "-q", "db", environment=environment)
    if not database:
        raise OwnerUatError("owner UAT database is unavailable")
    wait_health(database, PROJECT + ":db")
    rows = {family: [] for family in FAMILIES}
    try:
        identity = schema_state(database)
        schema = identity.get("maximum")
        applicable = active_work_sources_for_schema(schema)
        for family in FAMILIES:
            for table, status_sql, _active, _terminal in applicable[family]:
                query = ("SELECT " + status_sql + "::text,count(*)::bigint "
                         "FROM " + table + " GROUP BY " + status_sql +
                         " ORDER BY 1")
                output = docker(
                    "exec", database, "psql", "-U", "postgres", "-d",
                    "postgres", "-AtX", "-v", "ON_ERROR_STOP=1",
                    "-F", "\t", "-c", query)
                if not output:
                    continue
                for line in output.splitlines():
                    fields = line.split("\t")
                    if len(fields) != 2 or not fields[1].isdecimal():
                        raise ActiveWorkError("active-work row is invalid")
                    rows[family].append({
                        "table_name": table,
                        "status": fields[0],
                        "count": int(fields[1]),
                    })
        counts = ActiveWorkObserver.classify(rows)
    except (ActiveWorkError, KeyError, RuntimeError, TypeError,
            ValueError) as exc:
        raise OwnerUatError(
            "owner UAT active-work inventory failed closed") from exc
    if set(counts) != set(FAMILIES) or any(counts.values()):
        raise OwnerUatError("owner UAT has active work")
    return counts


def verify_suspend_storage_headroom(base: list[str], environment: dict) -> dict:
    """Refuse an orderly database stop when its filesystem is nearly full."""
    database = compose(base, "ps", "-q", "db", environment=environment)
    if not database:
        raise OwnerUatError("owner UAT database is unavailable")
    wait_health(database, PROJECT + ":db")
    output = docker("exec", database, "df", "-Pk", DATABASE_STORAGE_PATH)
    lines = [line.split() for line in output.splitlines() if line.strip()]
    if len(lines) < 2 or len(lines[-1]) < 6:
        raise OwnerUatError("owner UAT storage-headroom inventory failed closed")
    fields = lines[-1]
    try:
        available_kib = int(fields[3])
    except (ValueError, IndexError) as exc:
        raise OwnerUatError(
            "owner UAT storage-headroom inventory failed closed") from exc
    if available_kib < MIN_SUSPEND_FREE_KIB:
        raise OwnerUatError(
            "owner UAT storage headroom is too low for safe suspension")
    return {"availableKiB": available_kib,
            "minimumRequiredKiB": MIN_SUSPEND_FREE_KIB,
            "mountPoint": fields[-1]}


def verify_private_sequential(base: list[str], environment: dict, image: str,
                              database_image: str, expected_schema: int,
                              expected_applications: int) -> dict:
    """Verify the retained generation without running two complete stacks.

    The protected source and read-only review remain available during
    preparation.  Starting each candidate role separately bounds Mac memory;
    activation later runs the whole green generation only after stopping the
    old public generation.
    """
    db = compose(base, "ps", "-q", "db", environment=environment)
    wait_health(db, PROJECT + ":db")
    inspect_exact(db, database_image, health=True)
    if schema_state(db).get("maximum") != expected_schema \
            or application_count(db) != expected_applications:
        raise OwnerUatError("owner UAT database identity differs")
    writable = docker("exec", db, "psql", "-U", "postgres", "-d", "postgres",
                      "-AtX", "-c", "SHOW default_transaction_read_only")
    if writable != "off":
        raise OwnerUatError("owner UAT database is not writable")
    services = {}
    for service in HEALTH_SERVICES:
        profiles = ("--profile", "workspace") if service == "workspace" \
            else ("--profile", "v2")
        compose(base, *profiles, "up", "--no-build", "-d", service,
                environment=environment)
        container = compose(base, "ps", "-q", service,
                            environment=environment)
        wait_health(container, PROJECT + ":" + service)
        services[service] = inspect_exact(container, image, health=True)
        compose(base, "stop", service, environment=environment)
        compose(base, "rm", "-f", service, environment=environment)
    compose(base, "--profile", "python-build", "up", "--no-build", "-d",
            "python-build-broker", environment=environment)
    broker = compose(base, "ps", "-q", "python-build-broker",
                     environment=environment)
    denied = wait_broker_ready(broker)
    services["python-build-broker"] = inspect_exact(
        broker, image, health=False)
    services["python-build-broker"]["invalidCapabilityStatus"] = denied
    compose(base, "stop", "python-build-broker", environment=environment)
    compose(base, "rm", "-f", "python-build-broker", environment=environment)
    return {"databaseContainer": db, "services": services,
            "databaseWritable": True, "publicPorts": False,
            "sequentialVerification": True}


def verify_generation(base: list[str], environment: dict, image: str,
                      database_image: str, expected_schema: int,
                      expected_applications: int, *, public: bool) -> dict:
    db = compose(base, "ps", "-q", "db", environment=environment)
    wait_health(db, PROJECT + ":db")
    inspect_exact(db, database_image, health=True)
    if schema_state(db).get("maximum") != expected_schema \
            or application_count(db) != expected_applications:
        raise OwnerUatError("owner UAT database identity differs")
    writable = docker("exec", db, "psql", "-U", "postgres", "-d", "postgres",
                      "-AtX", "-c", "SHOW default_transaction_read_only")
    if writable != "off":
        raise OwnerUatError("owner UAT database is not writable")
    services = {}
    for service in HEALTH_SERVICES:
        container = compose(base, "ps", "-q", service, environment=environment)
        wait_health(container, PROJECT + ":" + service)
        services[service] = inspect_exact(container, image, health=True)
        if service == "web":
            review_mode = docker(
                "inspect", "-f",
                "{{range .Config.Env}}{{println .}}{{end}}", container)
            if any(line.startswith("EPM_UI_READ_ONLY_REVIEW=")
                   for line in review_mode.splitlines()):
                raise OwnerUatError(
                    "owner UAT web unexpectedly runs in read-only review mode")
    broker = compose(base, "ps", "-q", "python-build-broker",
                     environment=environment)
    denied = wait_broker_ready(broker)
    services["python-build-broker"] = inspect_exact(broker, image, health=False)
    services["python-build-broker"]["invalidCapabilityStatus"] = denied
    unsigned_boundary = {}
    if public:
        for service, port in PUBLIC_PORTS.items():
            if service == "web":
                shell_status = unsigned_status(
                    "GET", f"http://127.0.0.1:{port}/")
                api_status = unsigned_status(
                    "GET", f"http://127.0.0.1:{port}/api/session-identity")
                unsigned_boundary[service] = {
                    "shellStatus": shell_status, "apiStatus": api_status}
                if shell_status != 200 or api_status != 401:
                    raise OwnerUatError(service + " unsigned boundary differs")
            else:
                status = unsigned_status(
                    "POST", f"http://127.0.0.1:{port}/mcp")
                unsigned_boundary[service] = {"apiStatus": status}
                if status != 401:
                    raise OwnerUatError(service + " unsigned boundary differs")
    return {"databaseContainer": db, "services": services,
            "databaseWritable": True, "publicPorts": public,
            "unsignedBoundary": unsigned_boundary}


def unsigned_status(method: str, url: str) -> int:
    query = request.Request(
        url, data=None if method == "GET" else b"{}", method=method,
        headers={} if method == "GET" else {"content-type": "application/json"})
    try:
        with request.build_opener(request.ProxyHandler({})).open(
                query, timeout=5) as response:
            return response.status
    except error.HTTPError as exc:
        return exc.code


def prepare(args) -> dict:
    exact_inputs(args); root = args.state_root.resolve()
    with locked(root):
        if state_path(root).exists():
            raise OwnerUatError("owner UAT already has durable state")
        current_review = review.status(argparse.Namespace(
            state_root=args.review_state_root.resolve()))
        if current_review.get("candidateImage") != args.candidate_image \
                or current_review.get("databaseImage") != args.database_image \
                or current_review.get("backupName") != args.backup_name \
                or current_review.get("backupSha256") != args.backup_sha256 \
                or current_review.get("expectedSchema") != args.expected_schema \
                or current_review.get("expectedApplications") != args.expected_applications:
            raise OwnerUatError("active read-only review differs from UAT inputs")
        source_values = parse_env(
            ROOT / "deploy/macos-pilot/openepm-pilot.env")
        values = write_phase_environment(source_values, root / "compose.env",
                                         root / "secrets")
        values.update(EPM_APPLICATION_IMAGE=args.candidate_image,
                      EPM_DATABASE_IMAGE=args.database_image)
        write_python_secrets(root / "secrets", values,
                             args.candidate_image, PROJECT)
        (root / "override.yaml").write_text(
            override(args.candidate_image, args.database_image, public=False),
            encoding="utf-8")
        (root / "override.yaml").chmod(0o600)
        base, _, environment, _ = bases(root, public=False)
        archive = root / args.backup_name
        state = {"format": FORMAT, "project": PROJECT, "state": "preparing",
                 "candidateImage": args.candidate_image,
                 "databaseImage": args.database_image,
                 "backupName": args.backup_name,
                 "backupSha256": args.backup_sha256,
                 "expectedSchema": args.expected_schema,
                 "expectedApplications": args.expected_applications,
                 "reviewStateRoot": str(args.review_state_root.resolve()),
                 "protectedSourceMutation": False,
                 "ownerActionTimeAuthorized": True,
                 "publicWritable": False}
        write_json(state_path(root), state)
        try:
            docker("cp", SOURCE_CONTAINER + ":" + BACKUP_ROOT + "/" +
                   args.backup_name, str(archive))
            if file_digest(archive) != args.backup_sha256:
                raise OwnerUatError("protected backup digest differs")
            compose(base, "--profile", "setup", "up", "--no-build", "-d", "db",
                    environment=environment)
            db = compose(base, "ps", "-q", "db", environment=environment)
            wait_health(db, PROJECT + ":db")
            inspect_exact(db, args.database_image, health=True)
            docker("cp", str(archive), db + ":/tmp/pilot.dump")
            docker("exec", "-u", "0:0", db, "chmod", "0444", "/tmp/pilot.dump")
            create_group_roles(db)
            docker("exec", db, "pg_restore", "-U", "postgres", "-d", "postgres",
                   "--exit-on-error", "--no-owner", "/tmp/pilot.dump")
            create_login_roles(db, values)
            compose(base, "--profile", "setup", "run", "--rm", "migrate",
                    environment=environment)
            compose(base, "--profile", "python-build-setup", "run", "--rm",
                    "python-build-secret-init", environment=environment)
            evidence = verify_private_sequential(
                base, environment, args.candidate_image, args.database_image,
                args.expected_schema, args.expected_applications)
            compose(base, "stop", "db", environment=environment)
            state.update(state="prepared", privateVerification=evidence)
            write_json(state_path(root), state)
            archive.unlink(missing_ok=True)
            return state
        except BaseException:
            state.update(state="prepare-failed")
            write_json(state_path(root), state)
            raise


def _restore_review(state: dict) -> None:
    review.start(argparse.Namespace(
        state_root=Path(state["reviewStateRoot"]),
        candidate_image=state["candidateImage"],
        database_image=state["databaseImage"],
        backup_name=state["backupName"],
        backup_sha256=state["backupSha256"],
        expected_schema=state["expectedSchema"],
        expected_applications=state["expectedApplications"]))


def activate(args) -> dict:
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") not in ("prepared", "rolled-back"):
            raise OwnerUatError("owner UAT is not prepared for activation")
        review_root = Path(state["reviewStateRoot"])
        review.status(argparse.Namespace(state_root=review_root))
        base, source, environment, source_environment = bases(root, public=True)
        source_stopped = False
        try:
            review.stop(argparse.Namespace(state_root=review_root))
            all_stop(source, source_environment); source_stopped = True
            (root / "override.yaml").write_text(
                override(state["candidateImage"], state["databaseImage"],
                         public=True), encoding="utf-8")
            (root / "override.yaml").chmod(0o600)
            base, _, environment, _ = bases(root, public=True)
            all_up(base, environment)
            evidence = verify_generation(
                base, environment, state["candidateImage"],
                state["databaseImage"], state["expectedSchema"],
                state["expectedApplications"], public=True)
            state.update(state="active", publicWritable=True,
                         activationVerification=evidence)
            write_json(state_path(root), state)
            return state
        except BaseException:
            try:
                all_stop(base, environment)
                compose(base, "stop", "db", environment=environment)
            finally:
                if source_stopped:
                    all_up(source, source_environment)
                if not review.state_path(review_root).exists():
                    _restore_review(state)
            state.update(state="activation-failed", publicWritable=False)
            write_json(state_path(root), state)
            raise


def status(args) -> dict:
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            return {**state, "verified": state.get("state") in
                    ("prepared", "rolled-back", "suspended")}
        base, _, environment, _ = bases(root, public=True)
        evidence = verify_generation(
            base, environment, state["candidateImage"], state["databaseImage"],
            state["expectedSchema"], state["expectedApplications"], public=True)
        return {**state, "verified": True,
                "activationVerification": evidence}


def backup(args) -> dict:
    """Capture the current active database into protected owner-only storage."""
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        if state.get("stableContractAccepted") is not True:
            raise OwnerUatError(
                "backups are disabled until stable-contract owner UAT passes")
        history = list(state.get("backupHistory", []))
        if len(history) >= MAX_RETAINED_OWNER_UAT_BACKUPS:
            raise OwnerUatError("owner UAT backup retention limit reached")
        base, _, environment, _ = bases(root, public=True)
        verify_generation(
            base, environment, state["candidateImage"], state["databaseImage"],
            state["expectedSchema"], state["expectedApplications"], public=True)
        active_work = verify_no_active_work(base, environment)
        database = compose(base, "ps", "-q", "db", environment=environment)
        if not database:
            raise OwnerUatError("owner UAT database is unavailable")
        wait_health(database, PROJECT + ":db")
        backups = root / "backups"
        if backups.exists() and (backups.is_symlink() or not backups.is_dir()):
            raise OwnerUatError("owner UAT backup directory is unsafe")
        backups.mkdir(mode=0o700, exist_ok=True)
        metadata = backups.stat()
        if (stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()):
            raise OwnerUatError("owner UAT backup directory permissions are unsafe")
        created = datetime.now(timezone.utc)
        name = "owner-uat-" + created.strftime("%Y%m%dT%H%M%SZ") + ".dump"
        destination = backups / name
        manifest = backups / (name + ".json")
        if destination.exists() or manifest.exists():
            raise OwnerUatError("owner UAT backup identity already exists")
        container_path = "/tmp/" + name
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="." + name + ".", suffix=".partial", dir=backups)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            docker("exec", database, "pg_dump", "-U", "postgres", "-d",
                   "postgres", "--format=custom", "--file=" + container_path)
            listing = docker("exec", database, "pg_restore", "--list",
                             container_path)
            entries = sum(1 for line in listing.splitlines()
                          if line and not line.startswith(";"))
            if entries < 1:
                raise OwnerUatError("owner UAT backup catalogue is empty")
            docker("cp", database + ":" + container_path, str(temporary))
            temporary.chmod(0o600)
            with temporary.open("rb") as stream:
                os.fsync(stream.fileno())
            size = temporary.stat().st_size
            if size < 1:
                raise OwnerUatError("owner UAT backup is empty")
            digest = file_digest(temporary)
            os.replace(temporary, destination)
            record = {
                "createdAt": created.isoformat(), "name": name,
                "sha256": digest, "bytes": size, "catalogEntries": entries,
                "schema": state["expectedSchema"],
                "applications": state["expectedApplications"],
                "applicationImage": state["candidateImage"],
                "databaseImage": state["databaseImage"],
                "activeWork": active_work,
            }
            write_json(manifest, record)
            history.append(record)
            state.update(backupHistory=history, lastBackup=record)
            write_json(state_path(root), state)
            return record
        finally:
            temporary.unlink(missing_ok=True)
            docker("exec", database, "rm", "-f", container_path)


def backups(args) -> dict:
    """Verify and list every retained current-state owner-UAT backup."""
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        history = state.get("backupHistory", [])
        if not isinstance(history, list) or len(history) > MAX_RETAINED_OWNER_UAT_BACKUPS:
            raise OwnerUatError("owner UAT backup history is invalid")
        directory = root / "backups"
        if history and (not directory.is_dir() or directory.is_symlink()):
            raise OwnerUatError("owner UAT backup directory is unsafe")
        verified = []
        for record in history:
            if not isinstance(record, dict):
                raise OwnerUatError("owner UAT backup record is invalid")
            name = record.get("name")
            if (not isinstance(name, str)
                    or re.fullmatch(r"owner-uat-[0-9]{8}T[0-9]{6}Z[.]dump",
                                    name) is None):
                raise OwnerUatError("owner UAT backup name is invalid")
            archive = directory / name
            manifest = directory / (name + ".json")
            for path in (archive, manifest):
                metadata = path.stat(follow_symlinks=False)
                if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or metadata.st_uid != os.geteuid()):
                    raise OwnerUatError("owner UAT backup artifact is unsafe")
            try:
                manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise OwnerUatError("owner UAT backup manifest is invalid") from exc
            if (manifest_value != record or archive.stat().st_size != record.get("bytes")
                    or file_digest(archive) != record.get("sha256")):
                raise OwnerUatError("owner UAT backup artifact differs")
            verified.append(record)
        return {"format": "openepm-owner-uat-backup-list-v1",
                "count": len(verified),
                "maximum": MAX_RETAINED_OWNER_UAT_BACKUPS,
                "items": verified}


def reconcile_build_recovery_state(args) -> dict:
    """Remove stale snapshot references while the data contract is unstable."""
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("stableContractAccepted") is True:
            raise OwnerUatError(
                "stable-contract recovery state cannot be build-reconciled")
        directory = root / "backups"
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise OwnerUatError("owner UAT backup directory is unsafe")
            if any(directory.iterdir()):
                raise OwnerUatError(
                    "backup artifacts remain; exact-target cleanup is required")
        state.pop("backupHistory", None)
        state.pop("lastBackup", None)
        state.pop("backupName", None)
        state.pop("backupSha256", None)
        state.update(
            recoveryPolicy="build-phase-no-snapshots",
            buildRecoveryStateReconciledAt=
            datetime.now(timezone.utc).isoformat(),
        )
        write_json(state_path(root), state)
        return state


def restart(args) -> dict:
    """Restart and re-qualify the exact active owner-UAT generation.

    The durable state remains ``active`` only when the complete application
    generation and authoritative database return with their pinned identities,
    schema, application count, write mode and public unsigned boundaries.
    A failed first start gets one bounded recovery attempt using the same exact
    artifacts; the controller never silently substitutes another generation.
    """
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        base, _, environment, _ = bases(root, public=True)
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            all_stop(base, environment)
            compose(base, "stop", "db", environment=environment)
            all_up(base, environment)
            evidence = verify_generation(
                base, environment, state["candidateImage"],
                state["databaseImage"], state["expectedSchema"],
                state["expectedApplications"], public=True)
        except BaseException as first_error:
            try:
                all_up(base, environment)
                recovery = verify_generation(
                    base, environment, state["candidateImage"],
                    state["databaseImage"], state["expectedSchema"],
                    state["expectedApplications"], public=True)
            except BaseException:
                state.update(state="restart-failed", publicWritable=False,
                             lastRestartFailedAt=started_at)
                write_json(state_path(root), state)
                raise first_error
            state.update(activationVerification=recovery,
                         lastRestartRecoveredAt=started_at,
                         lastRestartFailure=type(first_error).__name__)
            write_json(state_path(root), state)
            raise first_error
        history = list(state.get("restartHistory", []))
        history.append({
            "startedAt": started_at,
            "candidateImage": state["candidateImage"],
            "databaseImage": state["databaseImage"],
            "expectedSchema": state["expectedSchema"],
            "expectedApplications": state["expectedApplications"],
            "verified": True,
        })
        state.update(activationVerification=evidence,
                     restartHistory=history, publicWritable=True)
        write_json(state_path(root), state)
        return state


def recover(args) -> dict:
    """Converge the exact active generation after Docker or host startup.

    Unlike ``restart``, recovery never stops a healthy generation first.  It
    idempotently asks Compose to start the already sealed services, then
    re-verifies every pinned image, database identity, schema, application
    count, write mode and public endpoint before recording success.
    """
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") not in ("active", "suspended"):
            raise OwnerUatError("owner UAT is not recoverable")
        base, _, environment, _ = bases(root, public=True)
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            all_up(base, environment)
            evidence = verify_generation(
                base, environment, state["candidateImage"],
                state["databaseImage"], state["expectedSchema"],
                state["expectedApplications"], public=True)
        except BaseException:
            state.update(publicWritable=False,
                         lastRecoveryFailedAt=started_at)
            write_json(state_path(root), state)
            raise
        history = list(state.get("recoveryHistory", []))
        history.append({
            "startedAt": started_at,
            "candidateImage": state["candidateImage"],
            "databaseImage": state["databaseImage"],
            "expectedSchema": state["expectedSchema"],
            "expectedApplications": state["expectedApplications"],
            "verified": True,
        })
        state.update(state="active", activationVerification=evidence,
                     recoveryHistory=history, publicWritable=True)
        write_json(state_path(root), state)
        return state


def suspend(args) -> dict:
    """Quiesce and stop the active generation while preserving all volumes."""
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") == "suspended":
            return state
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        base, _, environment, _ = bases(root, public=True)
        active_work = verify_no_active_work(base, environment)
        storage_headroom = verify_suspend_storage_headroom(base, environment)
        all_stop(base, environment)
        compose(base, "stop", "db", environment=environment)
        state.update(state="suspended", publicWritable=False,
                     suspendedAt=datetime.now(timezone.utc).isoformat(),
                     suspendedActiveWork=active_work,
                     suspendedStorageHeadroom=storage_headroom)
        write_json(state_path(root), state)
        return state


def rollback(args) -> dict:
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        base, source, environment, source_environment = bases(root, public=True)
        active_work = verify_no_active_work(base, environment)
        all_stop(base, environment)
        compose(base, "stop", "db", environment=environment)
        all_up(source, source_environment)
        _restore_review(state)
        state.update(state="rolled-back", publicWritable=False,
                     greenDataPreserved=True,
                     rollbackActiveWork=active_work,
                     rolledBackAt=datetime.now(timezone.utc).isoformat())
        write_json(state_path(root), state)
        return state


def upgrade_image(args) -> dict:
    root = args.state_root.resolve()
    if IMAGE.fullmatch(str(args.candidate_image)) is None:
        raise OwnerUatError("upgrade-image requires an exact candidate image")
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        old_image = state["candidateImage"]
        if args.candidate_image == old_image:
            if state.get("lastImageUpgradeFailed") == old_image:
                base, _, environment, _ = bases(root, public=True)
                evidence = verify_generation(
                    base, environment, old_image,
                    state["databaseImage"], state["expectedSchema"],
                    state["expectedApplications"], public=True)
                state.pop("lastImageUpgradeFailed", None)
                state.update(activationVerification=evidence)
                write_json(state_path(root), state)
                return state
            raise OwnerUatError("owner UAT already uses that image")
        base, _, environment, _ = bases(root, public=True)
        old_override = (root / "override.yaml").read_text(encoding="utf-8")
        profile_changed = False
        verify_no_active_work(base, environment)
        try:
            all_stop(base, environment)
            replace_builder_image(root, old_image, args.candidate_image)
            profile_changed = True
            (root / "override.yaml").write_text(
                override(args.candidate_image, state["databaseImage"],
                         public=True), encoding="utf-8")
            (root / "override.yaml").chmod(0o600)
            base, _, environment, _ = bases(root, public=True)
            all_up(base, environment)
            evidence = verify_generation(
                base, environment, args.candidate_image,
                state["databaseImage"], state["expectedSchema"],
                state["expectedApplications"], public=True)
            history = list(state.get("imageUpgradeHistory", []))
            history.append({"from": old_image, "to": args.candidate_image})
            state.pop("lastImageUpgradeFailed", None)
            state.update(candidateImage=args.candidate_image,
                         activationVerification=evidence,
                         imageUpgradeHistory=history)
            write_json(state_path(root), state)
            return state
        except BaseException:
            try:
                all_stop(base, environment)
                (root / "override.yaml").write_text(old_override,
                                                     encoding="utf-8")
                (root / "override.yaml").chmod(0o600)
                if profile_changed:
                    replace_builder_image(root, args.candidate_image, old_image)
                old_base, _, old_environment, _ = bases(root, public=True)
                all_up(old_base, old_environment)
                verify_generation(
                    old_base, old_environment, old_image,
                    state["databaseImage"], state["expectedSchema"],
                    state["expectedApplications"], public=True)
            finally:
                state.update(lastImageUpgradeFailed=args.candidate_image)
                write_json(state_path(root), state)
            raise


def reconcile_image_state(args) -> dict:
    """Adopt an already-running coherent image after exact verification.

    This is recovery for an interrupted/out-of-band image upgrade, not a way
    to select or start a different image. The current override and every live
    service must already name the requested digest. No active durable work may
    exist while the builder profile is brought back into the same generation.
    """
    root = args.state_root.resolve()
    image = str(args.candidate_image)
    if IMAGE.fullmatch(image) is None:
        raise OwnerUatError(
            "reconcile-image-state requires an exact candidate image")
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        old_image = state["candidateImage"]
        if image == old_image:
            raise OwnerUatError("owner UAT state already uses that image")
        expected_override = override(
            image, state["databaseImage"], public=True)
        try:
            current_override = (root / "override.yaml").read_text(
                encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise OwnerUatError("owner UAT override is unavailable") from exc
        if current_override != expected_override:
            raise OwnerUatError(
                "owner UAT override does not select the reconciliation image")
        base, _, environment, _ = bases(root, public=True)
        active_work = verify_no_active_work(base, environment)
        evidence = verify_generation(
            base, environment, image, state["databaseImage"],
            state["expectedSchema"], state["expectedApplications"],
            public=True)
        replace_builder_image(root, old_image, image)
        try:
            history = list(state.get("imageStateReconciliationHistory", []))
            history.append({
                "fromRecorded": old_image,
                "toVerifiedRunning": image,
                "reconciledAt": datetime.now(timezone.utc).isoformat(),
                "activeWork": active_work,
            })
            state.pop("lastImageUpgradeFailed", None)
            state.update(
                candidateImage=image,
                activationVerification=evidence,
                imageStateReconciliationHistory=history)
            write_json(state_path(root), state)
        except BaseException:
            replace_builder_image(root, image, old_image)
            raise
        return state


def refresh_runtime_identity(args) -> dict:
    """Regenerate and verify the active override for its recorded image.

    This bounded restart exists for deployment-contract changes that do not
    select a new application image. It drains durable work, keeps the exact
    recorded image/database generation, and restores the previous override if
    the regenerated generation cannot be verified.
    """
    root = args.state_root.resolve()
    with locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise OwnerUatError("owner UAT is not active")
        image = state["candidateImage"]
        base, _, environment, _ = bases(root, public=True)
        active_work = verify_no_active_work(base, environment)
        path = root / "override.yaml"
        old_override = path.read_text(encoding="utf-8")
        refreshed = override(image, state["databaseImage"], public=True)
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            all_stop(base, environment)
            path.write_text(refreshed, encoding="utf-8")
            path.chmod(0o600)
            base, _, environment, _ = bases(root, public=True)
            all_up(base, environment)
            evidence = verify_generation(
                base, environment, image, state["databaseImage"],
                state["expectedSchema"], state["expectedApplications"],
                public=True)
        except BaseException:
            all_stop(base, environment)
            path.write_text(old_override, encoding="utf-8")
            path.chmod(0o600)
            old_base, _, old_environment, _ = bases(root, public=True)
            all_up(old_base, old_environment)
            verify_generation(
                old_base, old_environment, image, state["databaseImage"],
                state["expectedSchema"], state["expectedApplications"],
                public=True)
            raise
        history = list(state.get("runtimeIdentityRefreshHistory", []))
        history.append({
            "refreshedAt": started_at,
            "candidateImage": image,
            "activeWork": active_work,
            "verified": True,
        })
        state.update(activationVerification=evidence,
                     runtimeIdentityRefreshHistory=history)
        write_json(state_path(root), state)
        return state


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("command", choices=(
        "prepare", "activate", "status", "backup", "backups", "recover", "suspend", "restart", "rollback",
        "upgrade-image", "reconcile-image-state",
        "reconcile-build-recovery-state", "refresh-runtime-identity"))
    value.add_argument("--state-root", type=Path, default=
                       ROOT / "deploy/macos-pilot/.runtime/owner-uat")
    value.add_argument("--review-state-root", type=Path, default=
                       ROOT / "deploy/macos-pilot/.runtime/ui-review")
    value.add_argument("--candidate-image")
    value.add_argument("--database-image")
    value.add_argument("--backup-name")
    value.add_argument("--backup-sha256")
    value.add_argument("--expected-schema", type=int)
    value.add_argument("--expected-applications", type=int)
    return value


def main() -> int:
    command = parser(); args = command.parse_args()
    try:
        if args.command == "prepare":
            required = (args.candidate_image, args.database_image,
                        args.backup_name, args.backup_sha256,
                        args.expected_schema, args.expected_applications)
            if any(item is None for item in required):
                raise OwnerUatError("prepare requires exact candidate inputs")
            result = prepare(args)
        elif args.command == "activate": result = activate(args)
        elif args.command == "status": result = status(args)
        elif args.command == "backup": result = backup(args)
        elif args.command == "backups": result = backups(args)
        elif args.command == "recover": result = recover(args)
        elif args.command == "suspend": result = suspend(args)
        elif args.command == "restart": result = restart(args)
        elif args.command == "rollback": result = rollback(args)
        elif args.command == "upgrade-image": result = upgrade_image(args)
        elif args.command == "reconcile-image-state":
            result = reconcile_image_state(args)
        elif args.command == "reconcile-build-recovery-state":
            result = reconcile_build_recovery_state(args)
        else: result = refresh_runtime_identity(args)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        command.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

