#!/usr/bin/env python3
"""Reversibly expose the qualified UI against a read-only restored pilot copy.

Only the public web listener is switched.  The authoritative pilot database,
MCP services, workers, volumes and Cloudflare configuration are never changed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterator

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.capture_macos_pilot_running_state import compose_frontend
from scripts.qualify_macos_pilot_backup_restore import create_group_roles
from scripts.qualify_macos_pilot_service_switch import (
    BACKUP_ROOT, SOURCE_CONTAINER, application_count, compose_override,
    create_login_roles, docker, file_digest, inspect_exact, parse_env,
    schema_state, wait_health, write_phase_environment,
)

PROJECT = "openepm-ui-review"
SOURCE_PROJECT = "openepm-macos-pilot"
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
BACKUP = re.compile(r"pilot-pre-upgrade-[0-9]{8}T[0-9]{6}Z[.]dump\Z")
FORMAT = "openepm-macos-pilot-ui-review-state-v1"


class ReviewError(RuntimeError):
    pass


def run(arguments: list[str], *, environment: dict[str, str] | None = None) -> str:
    result = subprocess.run(arguments, cwd=ROOT, env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
    if result.returncode:
        raise ReviewError((result.stderr or result.stdout).strip()
                          or "command failed")
    return result.stdout.strip()


def compose(base: list[str], *arguments: str,
            environment: dict[str, str]) -> str:
    return run([*base, *arguments], environment=environment)


def bases(frontend: list[str], env: Path, compose_file: Path,
          python_compose: Path, override: Path) -> tuple[list[str], list[str]]:
    review = [*frontend, "--project-name", PROJECT, "--env-file", str(env),
              "-f", str(compose_file), "-f", str(python_compose),
              "-f", str(override)]
    source = [*frontend, "--project-name", SOURCE_PROJECT, "--env-file",
              str(ROOT / "deploy/macos-pilot/openepm-pilot.env"),
              "-f", str(compose_file), "-f", str(python_compose)]
    return review, source


def review_compose_override(candidate: str, database: str) -> str:
    content = compose_override(candidate, database)
    old = '    ports: !override ["127.0.0.1:5295:5195"]'
    replacement = ('    ports: !override ["127.0.0.1:5195:5195"]\n'
                   "    environment:\n"
                   "      EPM_UI_READ_ONLY_REVIEW: '1'")
    if content.count(old) != 1:
        raise ReviewError("review web override shape differs")
    return content.replace(old, replacement)


def validate_inputs(*, candidate: str, database: str, backup: str,
                    backup_sha256: str, expected_schema: int,
                    expected_applications: int) -> None:
    if IMAGE.fullmatch(candidate) is None or IMAGE.fullmatch(database) is None:
        raise ReviewError("candidate and database images must be exact digests")
    if BACKUP.fullmatch(backup) is None or DIGEST.fullmatch(backup_sha256) is None:
        raise ReviewError("protected backup identity is invalid")
    if expected_schema < 1 or expected_applications not in (5, 6):
        raise ReviewError("review schema/application expectation is invalid")


def safe_root(root: Path) -> None:
    if not root.is_absolute() or root.is_symlink():
        raise ReviewError("review state root is unsafe")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700 \
            or metadata.st_uid != os.geteuid():
        raise ReviewError("review state root permissions are unsafe")


@contextmanager
def locked(root: Path) -> Iterator[None]:
    safe_root(root)
    descriptor = os.open(root / "review.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def state_path(root: Path) -> Path:
    return root / "state.json"


def write_json(path: Path, value: dict) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="." + path.name + ".", suffix=".partial", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_state(root: Path) -> dict:
    try:
        value = json.loads(state_path(root).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReviewError("UI review state is unavailable or invalid") from error
    if not isinstance(value, dict) or value.get("format") != FORMAT \
            or value.get("project") != PROJECT:
        raise ReviewError("UI review state differs")
    return value


def project_resources() -> list[str]:
    label = "label=com.docker.compose.project=" + PROJECT
    return [item for item in docker("ps", "-aq", "--filter", label).splitlines()
            if item]


def cleanup_project() -> None:
    label = "label=com.docker.compose.project=" + PROJECT
    containers = docker("ps", "-aq", "--filter", label).splitlines()
    if containers:
        docker("rm", "-f", *containers)
    for volume in docker("volume", "ls", "-q", "--filter", label).splitlines():
        docker("volume", "rm", volume)
    for network in docker("network", "ls", "-q", "--filter", label).splitlines():
        docker("network", "rm", network)


def start(args) -> dict:
    root = args.state_root.resolve()
    with locked(root):
        if state_path(root).exists() or project_resources():
            raise ReviewError("UI review is already present; inspect or stop it first")
        validate_inputs(candidate=args.candidate_image,
                        database=args.database_image, backup=args.backup_name,
                        backup_sha256=args.backup_sha256,
                        expected_schema=args.expected_schema,
                        expected_applications=args.expected_applications)
        compose_file = (ROOT / "deploy/postgres/compose.yaml").resolve()
        python_compose = (ROOT / "deploy/macos-pilot/python-build.compose.yaml").resolve()
        source_env = (ROOT / "deploy/macos-pilot/openepm-pilot.env").resolve()
        source_values = parse_env(source_env)
        phase_env = root / "compose.env"
        secret_dir = root / "secrets"
        values = write_phase_environment(source_values, phase_env, secret_dir)
        values.update(EPM_APPLICATION_IMAGE=args.candidate_image,
                      EPM_DATABASE_IMAGE=args.database_image)
        override = root / "override.yaml"
        content = review_compose_override(args.candidate_image,
                                          args.database_image)
        override.write_text(content, encoding="utf-8"); override.chmod(0o600)
        frontend = compose_frontend()
        review, source = bases(frontend, phase_env, compose_file,
                               python_compose, override)
        process_env = os.environ.copy(); process_env.update(values)
        source_process_env = os.environ.copy(); source_process_env.update(source_values)
        archive = root / args.backup_name
        record = {"format": FORMAT, "state": "preparing", "project": PROJECT,
                  "candidateImage": args.candidate_image,
                  "databaseImage": args.database_image,
                  "backupName": args.backup_name,
                  "backupSha256": args.backup_sha256,
                  "expectedSchema": args.expected_schema,
                  "expectedApplications": args.expected_applications,
                  "authoritativePilotMutation": False,
                  "publicWebOnly": True, "databaseReadOnly": True}
        write_json(state_path(root), record)
        source_stopped = False
        try:
            docker("cp", SOURCE_CONTAINER + ":" + BACKUP_ROOT + "/" +
                   args.backup_name, str(archive))
            if file_digest(archive) != args.backup_sha256:
                raise ReviewError("protected backup digest differs")
            compose(review, "--profile", "setup", "up", "--no-build", "-d", "db",
                    environment=process_env)
            database = compose(review, "ps", "-q", "db", environment=process_env)
            wait_health(database, "ui-review:db")
            inspect_exact(database, args.database_image, health=True)
            docker("cp", str(archive), database + ":/tmp/pilot.dump")
            docker("exec", "-u", "0:0", database, "chmod", "0444", "/tmp/pilot.dump")
            create_group_roles(database)
            docker("exec", database, "pg_restore", "-U", "postgres", "-d",
                   "postgres", "--exit-on-error", "--no-owner", "/tmp/pilot.dump")
            create_login_roles(database, values)
            compose(review, "--profile", "setup", "run", "--rm", "migrate",
                    environment=process_env)
            if schema_state(database).get("maximum") != args.expected_schema \
                    or application_count(database) != args.expected_applications:
                raise ReviewError("restored review state differs")
            docker("exec", database, "psql", "-U", "postgres", "-d", "postgres",
                   "-v", "ON_ERROR_STOP=1", "-c",
                   "ALTER DATABASE postgres SET default_transaction_read_only=on")
            compose(source, "stop", "web", environment=source_process_env)
            source_stopped = True
            compose(review, "--profile", "v2", "up", "--no-build", "-d", "web",
                    environment=process_env)
            web = compose(review, "ps", "-q", "web", environment=process_env)
            wait_health(web, "ui-review:web")
            inspect_exact(web, args.candidate_image, health=True)
            record.update(state="active", databaseContainer=database,
                          webContainer=web, publicUrl="https://app.openepm.dev/")
            write_json(state_path(root), record)
            archive.unlink(missing_ok=True)
            return record
        except BaseException:
            try:
                cleanup_project()
            finally:
                if source_stopped:
                    compose(source, "--profile", "v2", "up", "--no-build", "-d",
                            "web", environment=source_process_env)
                state_path(root).unlink(missing_ok=True)
                archive.unlink(missing_ok=True)
            raise


def status(args) -> dict:
    root = args.state_root.resolve()
    with locked(root):
        value = load_state(root)
        if value.get("state") != "active":
            raise ReviewError("UI review is not active")
        web = str(value.get("webContainer", ""))
        database = str(value.get("databaseContainer", ""))
        inspect_exact(web, str(value["candidateImage"]), health=True)
        inspect_exact(database, str(value["databaseImage"]), health=True)
        readonly = docker("exec", database, "psql", "-U", "postgres", "-d",
                          "postgres", "-AtX", "-c",
                          "SHOW default_transaction_read_only")
        if readonly != "on":
            raise ReviewError("review database is not read-only")
        return {**value, "verified": True}


def stop(args) -> dict:
    root = args.state_root.resolve()
    with locked(root):
        value = load_state(root)
        source_env = (ROOT / "deploy/macos-pilot/openepm-pilot.env").resolve()
        source_values = parse_env(source_env)
        source = [*compose_frontend(), "--project-name", SOURCE_PROJECT,
                  "--env-file", str(source_env), "-f",
                  str((ROOT / "deploy/postgres/compose.yaml").resolve()), "-f",
                  str((ROOT / "deploy/macos-pilot/python-build.compose.yaml").resolve())]
        cleanup_project()
        compose(source, "--profile", "v2", "up", "--no-build", "-d", "web",
                environment={**os.environ, **source_values})
        shutil.rmtree(root / "secrets", ignore_errors=True)
        for name in ("compose.env", "override.yaml", "state.json"):
            (root / name).unlink(missing_ok=True)
        return {"format": FORMAT, "state": "stopped",
                "restoredPublicWeb": True,
                "authoritativePilotMutation": False,
                "removedProject": value["project"]}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", choices=("start", "status", "stop"))
    result.add_argument("--state-root", type=Path, default=
                        ROOT / "deploy/macos-pilot/.runtime/ui-review")
    result.add_argument("--candidate-image")
    result.add_argument("--database-image")
    result.add_argument("--backup-name")
    result.add_argument("--backup-sha256")
    result.add_argument("--expected-schema", type=int)
    result.add_argument("--expected-applications", type=int)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "start":
            required=(args.candidate_image,args.database_image,args.backup_name,
                      args.backup_sha256,args.expected_schema,
                      args.expected_applications)
            if any(value is None for value in required):
                raise ReviewError("start requires exact image, backup, schema and application inputs")
            value=start(args)
        elif args.command == "status": value=status(args)
        else: value=stop(args)
    except (OSError, ReviewError, RuntimeError, json.JSONDecodeError) as error:
        parser().error(str(error))
    print(json.dumps(value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
