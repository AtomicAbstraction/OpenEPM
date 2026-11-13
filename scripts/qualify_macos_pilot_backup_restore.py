#!/usr/bin/env python3
"""Restore one protected Mac-pilot dump into an owned disposable database."""
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
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
BACKUP_NAME = re.compile(
    r"^pilot-(?:pre-schema[0-9]+|pre-upgrade|pre-fpna-data|post-fpna-foundation|"
    r"post-fpna-planning|post-fpna-forecast|post-fpna-retry|owner-uat)-"
    r"[0-9]{8}T[0-9]{6}Z[.]dump$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
GROUP_ROLES = (
    "epm_access", "epm_analyst", "epm_lifecycle", "epm_provision",
    "epm_python_coordinator", "epm_runtime", "epm_security", "epm_worker",
)


class QualificationError(ValueError):
    pass


def validate(backup_name: str, expected_sha256: str, database_image: str,
             application_image: str, output: Path) -> dict[str, object]:
    if BACKUP_NAME.fullmatch(backup_name) is None:
        raise QualificationError("backup name is not an exact pilot backup identity")
    if DIGEST.fullmatch(expected_sha256) is None:
        raise QualificationError("expected backup SHA-256 is invalid")
    if IMAGE.fullmatch(database_image) is None:
        raise QualificationError("database image must be an exact sha256 identity")
    if IMAGE.fullmatch(application_image) is None:
        raise QualificationError("application image must be an exact sha256 identity")
    if not output.is_absolute():
        raise QualificationError("qualification output must be an absolute path")
    return {
        "format": "openepm-macos-pilot-backup-restore-plan-v1",
        "disposable": True,
        "sharedPilotMutation": False,
        "backupName": backup_name,
        "expectedBackupSha256": expected_sha256,
        "databaseImage": database_image,
        "applicationImage": application_image,
        "output": str(output),
    }


def docker(*arguments: str, output: bool = True) -> str:
    completed = subprocess.run(
        ["docker", *arguments], text=True,
        stdout=subprocess.PIPE if output else subprocess.DEVNULL,
        stderr=subprocess.PIPE, check=False)
    if completed.returncode:
        raise RuntimeError("docker command failed: " + completed.stderr.strip())
    return completed.stdout.strip() if output else ""


def file_digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            value.update(block)
    return value.hexdigest()


def wait_ready(container: str) -> None:
    for _ in range(100):
        if subprocess.run(
                ["docker", "exec", container, "pg_isready", "-U", "postgres",
                 "-d", "postgres"], stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False).returncode == 0:
            return
        time.sleep(.2)
    raise RuntimeError("disposable PostgreSQL did not become ready")


def scalar(container: str, statement: str) -> str:
    return docker("exec", container, "psql", "-U", "postgres", "-d",
                  "postgres", "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
                  statement)


def epm_base_table_names(container: str) -> tuple[str, ...]:
    """Return one exact, validated EPM base-table inventory."""
    raw = scalar(container, """
        SELECT coalesce(json_agg(table_name ORDER BY table_name),'[]'::json)
        FROM information_schema.tables
        WHERE table_schema='epm' AND table_type='BASE TABLE'""")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("EPM base-table inventory is invalid") from error
    if not isinstance(value, list) or not value or len(value) > 512:
        raise RuntimeError("EPM base-table inventory is empty or unbounded")
    if any(not isinstance(name, str) or TABLE_NAME.fullmatch(name) is None
           for name in value):
        raise RuntimeError("EPM base-table inventory contains an unsafe name")
    names = tuple(value)
    if names != tuple(sorted(set(names))):
        raise RuntimeError("EPM base-table inventory is not unique and ordered")
    if "schema_migration" not in names:
        raise RuntimeError("EPM base-table inventory omits schema_migration")
    return names


def logical_data_digest(
        container: str, *, table_names: tuple[str, ...] | None = None,
        exclude_schema_migration: bool = False) -> str:
    """Hash a deterministic data-only dump without exposing any row.

    ``schema_migration`` is excluded only for the post-upgrade business-data
    comparison.  Applying a newer release necessarily adds rows to that ledger,
    while an exact pre-upgrade archive comparison must continue to include it.
    """
    selection = ""
    if table_names is not None:
        if (not table_names or len(table_names) > 512 or
                table_names != tuple(sorted(set(table_names))) or
                any(TABLE_NAME.fullmatch(name) is None for name in table_names)):
            raise QualificationError("logical digest table inventory is invalid")
        selected = tuple(
            name for name in table_names
            if not (exclude_schema_migration and name == "schema_migration"))
        if not selected:
            raise QualificationError("logical digest has no selected tables")
        selection = "".join(
            "--table=epm." + name + " " for name in selected)
    elif exclude_schema_migration:
        selection = "--exclude-table-data=epm.schema_migration "
    value = docker(
        "exec", container, "bash", "-o", "pipefail", "-ec",
        "pg_dump -U postgres -d postgres --data-only --column-inserts "
        "--rows-per-insert=1 --no-owner --no-acl " + selection +
        "--restrict-key=openepmpilotrestorev1 | sha256sum")
    digest = value.split()[0] if value else ""
    if DIGEST.fullmatch(digest) is None:
        raise RuntimeError("logical data fingerprint is invalid")
    return digest


def create_group_roles(container: str) -> None:
    roles = ",".join("'%s'" % role for role in GROUP_ROLES)
    statement = f"""DO $restore_roles$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[{roles}] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      RAISE EXCEPTION 'RESTORE_ROLE_ALREADY_EXISTS: %', role_name;
    END IF;
    EXECUTE format('CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER '
                   'NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                   role_name);
  END LOOP;
END $restore_roles$;"""
    scalar(container, statement)


def execute(plan: dict[str, object], source_container: str) -> dict[str, object]:
    if os.environ.get("EPM_PILOT_RESTORE_DISPOSABLE") != "1":
        raise QualificationError("owned disposable restore opt-in is required")
    token = uuid.uuid4().hex[:10]
    container = "openepm_pilot_restore_" + token
    volume = container + "_data"
    password = secrets.token_urlsafe(24)
    backup_name = str(plan["backupName"])
    source = "/var/lib/postgresql/base_backups/" + backup_name
    cleanup_errors: list[str] = []
    container_created = False
    volume_created = False
    with tempfile.TemporaryDirectory(
            prefix=".epm-pilot-restore-", dir=ROOT) as temporary:
        local = Path(temporary) / backup_name
        try:
            source_base_tables = epm_base_table_names(source_container)
            source_data_digest = logical_data_digest(source_container)
            source_business_data_digest = logical_data_digest(
                source_container, table_names=source_base_tables,
                exclude_schema_migration=True)
            docker("cp", source_container + ":" + source, str(local))
            actual_digest = file_digest(local)
            if actual_digest != plan["expectedBackupSha256"]:
                raise QualificationError("protected backup SHA-256 mismatch")
            database_image = str(plan["databaseImage"])
            docker("volume", "create", volume)
            volume_created = True
            docker("run", "-d", "--name", container,
                   "-v", volume + ":/var/lib/postgresql",
                   "-e", "POSTGRES_PASSWORD=" + password,
                   database_image)
            container_created = True
            wait_ready(container)
            docker("cp", str(local), container + ":/tmp/pilot.dump")
            # ``docker cp`` preserves the protected source's owner-only mode.
            # Normalize only the disposable copy so the PostgreSQL user can
            # read it; the source backup remains mode 600 in its volume.
            docker("exec", "-u", "0:0", container, "chmod", "0444",
                   "/tmp/pilot.dump")
            acl_entries_text = docker(
                "exec", container, "sh", "-ec",
                "pg_restore --list /tmp/pilot.dump | "
                "awk '/ ACL | DEFAULT ACL / {n++} END {print n+0}'")
            if not acl_entries_text.isdecimal() or int(acl_entries_text) <= 0:
                raise QualificationError(
                    "protected backup contains no PostgreSQL privilege ACL entries")
            create_group_roles(container)
            docker("exec", container, "pg_restore", "-U", "postgres", "-d",
                   "postgres", "--exit-on-error", "--no-owner",
                   "/tmp/pilot.dump")
            restored_archive_data_digest = logical_data_digest(container)
            if restored_archive_data_digest != source_data_digest:
                raise QualificationError(
                    "restored archive differs from current source before migration")
            restored_archive_base_tables = epm_base_table_names(container)
            if restored_archive_base_tables != source_base_tables:
                raise QualificationError(
                    "restored archive base-table inventory differs from source")
            restored_migrations = json.loads(scalar(container, """
                SELECT json_build_object(
                  'rows',count(*),'minimum',min(version),'maximum',max(version),
                  'orderedDigestMd5',md5(string_agg(
                    version::text||':'||checksum,',' ORDER BY version)),
                  'sha256Shape',bool_and(checksum ~ '^[0-9a-f]{64}$'))
                FROM epm.schema_migration"""))
            admin_dsn = ("host=127.0.0.1 port=5432 user=postgres password="
                         + password + " dbname=postgres")
            docker("run", "--rm", "--network", "container:" + container,
                   "-e", "EPM_POSTGRES_ADMIN_DSN=" + admin_dsn,
                   str(plan["applicationImage"]), "python", "-m",
                   "scripts.initialize_postgres_release")
            migrations = json.loads(scalar(container, """
                SELECT json_build_object(
                  'rows',count(*),'minimum',min(version),'maximum',max(version),
                  'orderedDigestMd5',md5(string_agg(
                    version::text||':'||checksum,',' ORDER BY version)),
                  'sha256Shape',bool_and(checksum ~ '^[0-9a-f]{64}$'))
                FROM epm.schema_migration"""))
            row_counts = json.loads(scalar(container, """
                SELECT json_build_object(
                  'workspaces',(SELECT count(*) FROM epm.workspace),
                  'applications',(SELECT count(*) FROM epm.application),
                  'dimensions',(SELECT count(*) FROM epm.dimension),
                  'members',(SELECT count(*) FROM epm.member),
                  'numericFacts',(SELECT count(*) FROM epm.numeric_fact_event),
                  'textFacts',(SELECT count(*) FROM epm.text_fact_event),
                  'detailFacts',(SELECT count(*) FROM epm.line_detail_event),
                  'jobs',(SELECT count(*) FROM epm.job),
                  'receipts',(SELECT count(*) FROM epm.operation_receipt),
                  'pythonEnvironments',(SELECT count(*) FROM epm.python_environment_version),
                  'pythonPrograms',(SELECT count(*) FROM epm.python_program_definition),
                  'pythonBuilds',(SELECT count(*) FROM epm.python_program_build),
                  'pythonPlans',(SELECT count(*) FROM epm.python_plan_artifact),
                  'pythonWorkflows',(SELECT count(*) FROM epm.python_program_workflow),
                  'pythonWorkflowChildren',(SELECT count(*) FROM epm.python_program_workflow_child),
                  'executionDelegations',(SELECT count(*) FROM epm.execution_delegation_version))"""))
            restored_data_digest = logical_data_digest(container)
            target_base_tables = epm_base_table_names(container)
            missing_tables = sorted(
                set(source_base_tables) - set(target_base_tables))
            if missing_tables:
                raise QualificationError(
                    "post-migration target removed source base tables")
            new_tables = tuple(sorted(
                set(target_base_tables) - set(source_base_tables)))
            new_table_row_counts: dict[str, int] = {}
            for table_name in new_tables:
                row_count = int(scalar(
                    container, "SELECT count(*) FROM epm." + table_name))
                if row_count < 0:
                    raise RuntimeError("new-table row count is invalid")
                new_table_row_counts[table_name] = row_count
            populated_new_tables = {
                name: count for name, count in new_table_row_counts.items()
                if count != 0}
            if populated_new_tables:
                raise QualificationError(
                    "post-migration target-only base table contains data")
            restored_business_data_digest = logical_data_digest(
                container, table_names=source_base_tables,
                exclude_schema_migration=True)
            if restored_business_data_digest != source_business_data_digest:
                raise QualificationError(
                    "post-migration business data fingerprint differs from source")
            extensions = json.loads(scalar(container, """
                SELECT json_agg(extname||':'||extversion ORDER BY extname)
                FROM pg_extension"""))
            base_tables = int(scalar(container, """
                SELECT count(*) FROM information_schema.tables
                WHERE table_schema='epm' AND table_type='BASE TABLE'"""))
            result = {
                **plan,
                "format": "openepm-macos-pilot-backup-restore-v1",
                "planFormat": plan["format"],
                "status": "verified-for-distinct-restore-scope",
                "backup": {
                    "bytes": local.stat().st_size,
                    "sha256": actual_digest,
                    "catalogEntries": int(docker(
                        "exec", container, "sh", "-c",
                        "pg_restore -l /tmp/pilot.dump | wc -l")),
                    "aclEntries": int(acl_entries_text),
                    "catalogReadable": True,
                },
                "restore": {
                    "container": "owned-disposable-removed-after-verification",
                    "ownerReplayDisabled": True,
                    "databasePrivilegeAclReplayEnabled": True,
                    "policyRoles": list(GROUP_ROLES),
                    "sourceMigrations": restored_migrations,
                    "currentReleaseMigrations": migrations,
                    "epmBaseTables": base_tables,
                    "extensions": extensions,
                    "rowCounts": row_counts,
                    "sourceLogicalDataSha256": source_data_digest,
                    "restoredLogicalDataSha256": restored_data_digest,
                    "logicalDataIdentical": (
                        restored_data_digest == source_data_digest),
                    "archiveRestoredLogicalDataSha256": (
                        restored_archive_data_digest),
                    "archiveRestoredLogicalDataIdentical": True,
                    "businessDataDigestExcludes": [
                        "epm.schema_migration"],
                    "sourceBaseTables": list(source_base_tables),
                    "archiveRestoredBaseTables": list(
                        restored_archive_base_tables),
                    "targetBaseTables": list(target_base_tables),
                    "targetOnlyNewTableRowCounts": new_table_row_counts,
                    "targetOnlyNewTablesEmpty": True,
                    "sourceBusinessDataSha256": (
                        source_business_data_digest),
                    "restoredBusinessDataSha256": (
                        restored_business_data_digest),
                    "businessDataIdenticalAfterMigration": True,
                },
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
                    "disposable cleanup failed: " + "; ".join(cleanup_errors))
    result["cleanup"] = {
        "disposableContainerRemoved": True,
        "disposableVolumeRemoved": True,
        "temporaryBackupCopyRemoved": True,
        "cleanupErrors": [],
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-container",
                        default="openepm-macos-pilot-db-1")
    parser.add_argument("--backup-name", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--application-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        plan = validate(arguments.backup_name, arguments.expected_sha256,
                        arguments.database_image, arguments.application_image,
                        arguments.output)
        if not arguments.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        result = execute(plan, arguments.source_container)
    except (QualificationError, RuntimeError) as error:
        parser.error(str(error))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
