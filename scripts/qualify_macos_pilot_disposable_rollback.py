#!/usr/bin/env python3
"""Prove candidate migration and replacement-database rollback disposably.

The shared pilot is read only: execution copies one exact protected archive.
All restore, migration, database-name switching and old-image validation occur
inside one uniquely owned PostgreSQL container and volume that are removed.
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
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
SOURCE_CONTAINER = "openepm-macos-pilot-db-1"
BACKUP_ROOT = "/var/lib/postgresql/base_backups"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
BACKUP_NAME = re.compile(
    r"^pilot-(?:pre-schema[0-9]+|pre-upgrade|pre-fpna-data|"
    r"post-fpna-foundation|post-fpna-planning|post-fpna-forecast|"
    r"post-fpna-retry)-[0-9]{8}T[0-9]{6}Z[.]dump$")
GROUP_ROLES = (
    "epm_access", "epm_analyst", "epm_lifecycle", "epm_provision",
    "epm_python_coordinator", "epm_runtime", "epm_security", "epm_worker",
)


class RollbackError(ValueError):
    pass


def plan(*, backup_name: str, expected_sha256: str, old_application_image: str,
         candidate_application_image: str, database_image: str,
         expected_source_schema: int, expected_application_count: int,
         output: Path) -> dict[str, object]:
    if BACKUP_NAME.fullmatch(backup_name) is None:
        raise RollbackError("backup name is not an exact pilot backup identity")
    if DIGEST.fullmatch(expected_sha256) is None:
        raise RollbackError("expected backup SHA-256 is invalid")
    for label, value in (
            ("old application", old_application_image),
            ("candidate application", candidate_application_image),
            ("database", database_image)):
        if IMAGE.fullmatch(value) is None:
            raise RollbackError(label + " image must be an exact sha256 identity")
    if old_application_image == candidate_application_image:
        raise RollbackError("old and candidate application images must differ")
    if isinstance(expected_source_schema, bool) \
            or not isinstance(expected_source_schema, int) \
            or expected_source_schema <= 0:
        raise RollbackError("expected source schema must be a positive integer")
    if isinstance(expected_application_count, bool) \
            or not isinstance(expected_application_count, int) \
            or expected_application_count < 0:
        raise RollbackError("expected application count must be nonnegative")
    if not output.is_absolute():
        raise RollbackError("qualification output must be absolute")
    if output.exists():
        raise RollbackError("qualification output already exists")
    return {
        "format": "openepm-macos-pilot-disposable-rollback-plan-v1",
        "disposable": True,
        "sharedPilotMutation": False,
        "liveServiceRollbackClaimed": False,
        "sourceContainer": SOURCE_CONTAINER,
        "backupName": backup_name,
        "expectedBackupSha256": expected_sha256,
        "oldApplicationImage": old_application_image,
        "candidateApplicationImage": candidate_application_image,
        "databaseImage": database_image,
        "expectedSourceSchema": expected_source_schema,
        "expectedApplicationCount": expected_application_count,
        "output": str(output),
    }


def docker(*arguments: str, output: bool = True) -> str:
    completed = subprocess.run(
        ["docker", *arguments], text=True,
        stdout=subprocess.PIPE if output else subprocess.DEVNULL,
        stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "docker command failed")
    return completed.stdout.strip() if output else ""


def file_digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def wait_ready(container: str) -> None:
    for _ in range(100):
        completed = subprocess.run(
            ["docker", "exec", container, "pg_isready", "-U", "postgres",
             "-d", "postgres"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False)
        if completed.returncode == 0:
            return
        time.sleep(.2)
    raise RuntimeError("disposable rollback database did not become ready")


def psql(container: str, database: str, statement: str) -> str:
    return docker("exec", container, "psql", "-U", "postgres", "-d",
                  database, "-AtX", "-v", "ON_ERROR_STOP=1", "-c", statement)


def quote_identifier(value: str) -> str:
    if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value) is None:
        raise RollbackError("internal database identity is unsafe")
    return '"' + value + '"'


def create_policy_roles(container: str) -> None:
    roles = ",".join("'%s'" % role for role in GROUP_ROLES)
    psql(container, "postgres", f"""DO $roles$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[{roles}] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      RAISE EXCEPTION 'ROLLBACK_ROLE_ALREADY_EXISTS: %', role_name;
    END IF;
    EXECUTE format('CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER '
                   'NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                   role_name);
  END LOOP;
END $roles$;""")


def create_database(container: str, database: str) -> None:
    psql(container, "postgres", "CREATE DATABASE " + quote_identifier(database) +
         " TEMPLATE template0")


def restore_archive(container: str, database: str) -> None:
    docker("exec", container, "pg_restore", "-U", "postgres", "-d", database,
           "--exit-on-error", "--no-owner", "/tmp/pilot.dump")


def schema_state(container: str, database: str) -> dict[str, object]:
    raw = psql(container, database, """
        SELECT json_build_object(
          'migrationRows',count(*),'minimum',min(version),'maximum',max(version),
          'orderedDigestMd5',md5(string_agg(
            version::text||':'||checksum,',' ORDER BY version)),
          'sha256Shape',bool_and(checksum ~ '^[0-9a-f]{64}$'))
        FROM epm.schema_migration""")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("schema-state response is invalid") from error
    if not isinstance(value, dict):
        raise RuntimeError("schema-state response is invalid")
    return value


def application_count(container: str, database: str) -> int:
    value = psql(container, database, "SELECT count(*) FROM epm.application")
    if not value.isdecimal():
        raise RuntimeError("application count is invalid")
    return int(value)


def logical_data_digest(container: str, database: str) -> str:
    value = docker(
        "exec", container, "bash", "-o", "pipefail", "-ec",
        "pg_dump -U postgres -d \"$1\" --data-only --column-inserts "
        "--rows-per-insert=1 --no-owner --no-acl "
        "--restrict-key=openepmpilotrollbackv1 | sha256sum", "--", database)
    digest = value.split()[0] if value else ""
    if DIGEST.fullmatch(digest) is None:
        raise RuntimeError("logical data digest is invalid")
    return digest


def initialize_release(container: str, database: str, password: str,
                       image: str) -> None:
    admin_dsn = ("host=127.0.0.1 port=5432 user=postgres password=" + password +
                 " dbname=" + database)
    docker("run", "--rm", "--network", "container:" + container,
           "-e", "EPM_POSTGRES_ADMIN_DSN=" + admin_dsn, image, "python", "-m",
           "scripts.initialize_postgres_release")


def terminate_connections(container: str, database: str) -> None:
    quote_identifier(database)
    psql(container, "postgres",
         "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
         "WHERE datname=" + "'" + database + "'" +
         " AND pid<>pg_backend_pid()")


def switch_to_replacement(container: str, *, active: str, replacement: str,
                          displaced: str) -> dict[str, object]:
    """Bounded two-rename switch, restoring the old name after step-two failure."""
    for database in (active, replacement):
        terminate_connections(container, database)
    psql(container, "postgres", "ALTER DATABASE " + quote_identifier(active) +
         " RENAME TO " + quote_identifier(displaced))
    try:
        psql(container, "postgres", "ALTER DATABASE " +
             quote_identifier(replacement) + " RENAME TO " +
             quote_identifier(active))
    except Exception as switch_error:
        try:
            psql(container, "postgres", "ALTER DATABASE " +
                 quote_identifier(displaced) + " RENAME TO " +
                 quote_identifier(active))
        except Exception as recovery_error:
            raise RuntimeError(
                "replacement switch failed and active-name recovery failed: " +
                str(recovery_error)) from switch_error
        raise RuntimeError(
            "replacement switch failed; original active name was recovered") \
            from switch_error
    return {
        "kind": "bounded-two-rename-with-recovery",
        "candidateDisplaced": True,
        "replacementActivated": True,
        "failedSecondRenameRecoveryImplemented": True,
    }


def require_source(value: dict[str, object], container: str, database: str,
                   expected_digest: str | None = None) -> dict[str, object]:
    schema = schema_state(container, database)
    if schema.get("maximum") != value["expectedSourceSchema"]:
        raise RollbackError("restored source schema differs from expectation")
    count = application_count(container, database)
    if count != value["expectedApplicationCount"]:
        raise RollbackError("restored application count differs from expectation")
    digest = logical_data_digest(container, database)
    if expected_digest is not None and digest != expected_digest:
        raise RollbackError("restored source logical data differs")
    return {"schema": schema, "applicationCount": count,
            "logicalDataSha256": digest}


def execute(value: dict[str, object]) -> dict[str, object]:
    if os.environ.get("EPM_PILOT_ROLLBACK_DISPOSABLE") != "1":
        raise RollbackError("owned disposable rollback opt-in is required")
    token = uuid.uuid4().hex[:10]
    container = "openepm_pilot_rollback_" + token
    volume = container + "_data"
    active = "pilot_active_" + token
    replacement = "pilot_replacement_" + token
    displaced = "pilot_candidate_" + token
    password = secrets.token_urlsafe(24)
    source = f"{BACKUP_ROOT}/{value['backupName']}"
    cleanup_errors: list[str] = []
    volume_created = False
    container_created = False
    with tempfile.TemporaryDirectory(
            prefix=".epm-pilot-rollback-", dir=ROOT) as temporary:
        local = Path(temporary) / str(value["backupName"])
        try:
            docker("cp", SOURCE_CONTAINER + ":" + source, str(local))
            actual_digest = file_digest(local)
            if actual_digest != value["expectedBackupSha256"]:
                raise RollbackError("protected backup SHA-256 mismatch")
            docker("volume", "create", volume)
            volume_created = True
            docker("run", "-d", "--name", container,
                   "-v", volume + ":/var/lib/postgresql",
                   "-e", "POSTGRES_PASSWORD=" + password,
                   str(value["databaseImage"]))
            container_created = True
            wait_ready(container)
            docker("cp", str(local), container + ":/tmp/pilot.dump")
            docker("exec", "-u", "0:0", container, "chmod", "0444",
                   "/tmp/pilot.dump")
            catalog_text = docker(
                "exec", container, "bash", "-o", "pipefail", "-ec",
                "pg_restore --list /tmp/pilot.dump | wc -l | "
                "tr -d '[:space:]'")
            if not catalog_text.isdecimal() or int(catalog_text) <= 0:
                raise RollbackError("protected backup catalogue is unreadable")
            acl_text = docker(
                "exec", container, "bash", "-o", "pipefail", "-ec",
                "pg_restore --list /tmp/pilot.dump | "
                "awk '/ ACL | DEFAULT ACL / {n++} END {print n+0}'")
            if not acl_text.isdecimal() or int(acl_text) <= 0:
                raise RollbackError(
                    "protected backup contains no PostgreSQL privilege ACL entries")
            create_policy_roles(container)

            create_database(container, active)
            restore_archive(container, active)
            source_state = require_source(value, container, active)

            initialize_release(
                container, active, password,
                str(value["candidateApplicationImage"]))
            candidate_state = {
                "schema": schema_state(container, active),
                "applicationCount": application_count(container, active),
            }
            if candidate_state["schema"].get("maximum", 0) \
                    < value["expectedSourceSchema"]:
                raise RollbackError("candidate migration regressed schema")
            if candidate_state["applicationCount"] \
                    != value["expectedApplicationCount"]:
                raise RollbackError("candidate migration changed application count")

            create_database(container, replacement)
            restore_archive(container, replacement)
            replacement_state = require_source(
                value, container, replacement,
                str(source_state["logicalDataSha256"]))
            switch = switch_to_replacement(
                container, active=active, replacement=replacement,
                displaced=displaced)

            initialize_release(
                container, active, password, str(value["oldApplicationImage"]))
            final_state = require_source(
                value, container, active,
                str(source_state["logicalDataSha256"]))
            result = {
                **value,
                "format": "openepm-macos-pilot-disposable-rollback-v1",
                "planFormat": value["format"],
                "status": "verified-for-owned-disposable-database-rollback-scope",
                "backup": {
                    "bytes": local.stat().st_size,
                    "sha256": actual_digest,
                    "catalogEntries": int(catalog_text),
                    "aclEntries": int(acl_text),
                    "catalogReadable": True,
                },
                "sourceState": source_state,
                "candidateState": candidate_state,
                "replacementStateBeforeSwitch": replacement_state,
                "switch": switch,
                "rollback": {
                    "oldApplicationInitializerPassed": True,
                    "sourceStateRestored": True,
                    "finalSourceState": final_state,
                    "oldApplicationImage": value["oldApplicationImage"],
                    "databaseImage": value["databaseImage"],
                },
                "liveLikeMutationTestedInDisposableScope": True,
                "secretsRetained": False,
                "limitations": [
                    "No shared pilot database, image tag or service was changed.",
                    "This does not prove service health, browser/MCP routing, "
                    "unsigned denial or automatic live-stack rollback.",
                    "Live activation still requires a bounded image switch, "
                    "service recreation and post-activation checks.",
                ],
            }
        finally:
            if container_created:
                try:
                    docker("rm", "-f", container)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if volume_created:
                try:
                    docker("volume", "rm", volume)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if cleanup_errors:
                raise RuntimeError(
                    "disposable rollback cleanup failed: " +
                    "; ".join(cleanup_errors))
    result["cleanup"] = {
        "disposableContainerRemoved": True,
        "disposableVolumeRemoved": True,
        "temporaryBackupCopyRemoved": True,
        "cleanupErrors": [],
    }
    return result


def write_evidence(output: Path, value: dict[str, object]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix="." + output.name + ".", suffix=".partial", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-name", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--old-application-image", required=True)
    parser.add_argument("--candidate-application-image", required=True)
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--expected-source-schema", required=True, type=int)
    parser.add_argument("--expected-application-count", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        value = plan(
            backup_name=arguments.backup_name,
            expected_sha256=arguments.expected_sha256,
            old_application_image=arguments.old_application_image,
            candidate_application_image=arguments.candidate_application_image,
            database_image=arguments.database_image,
            expected_source_schema=arguments.expected_source_schema,
            expected_application_count=arguments.expected_application_count,
            output=arguments.output)
        if not arguments.execute:
            print(json.dumps(value, sort_keys=True))
            return 0
        result = execute(value)
        write_evidence(arguments.output, result)
    except (OSError, RollbackError, RuntimeError) as error:
        parser.error(str(error))
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
