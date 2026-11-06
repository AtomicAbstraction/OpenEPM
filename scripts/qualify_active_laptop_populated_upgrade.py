#!/usr/bin/env python3
"""Qualify the active laptop's populated schema upgrade on an owned clone.

The active database is only read through one PostgreSQL consistent dump.  The
archive, target container and target volume are run-owned and are removed even
after failure.  No backup is retained and no active service is reconfigured.
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
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_CONTAINER = re.compile(r"^openepm-[a-z0-9-]{1,90}-db-1$")
SAFE_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
GROUP_ROLES = (
    "epm_access", "epm_analyst", "epm_lifecycle", "epm_provision",
    "epm_python_coordinator", "epm_runtime", "epm_security", "epm_worker",
)
# These tables are the owner-created programmable application contract.  An
# upgrade may add or reconcile technical control rows, but it may not alter
# these identities, metadata, facts, layouts, rules, workflows or evidence.
PROTECTED_TABLES = (
    "application", "application_state", "attribute_definition", "coordinate",
    "coordinate_layout", "dimension", "generic_fact_event",
    "generic_fact_projection", "generic_fact_table", "hierarchy_active",
    "hierarchy_closure", "hierarchy_version", "member",
    "member_list_publication", "member_list_version", "numeric_cell_projection",
    "numeric_fact_event", "operation_receipt", "python_program_publication",
    "python_program_version", "relationship", "saved_grid_definition",
    "sealed_cube_selection", "semantic_column", "source_batch",
    "source_batch_chunk", "source_batch_row", "task", "task_event",
    "text_cell_projection", "text_fact_event", "workspace",
)


class QualificationError(RuntimeError):
    pass


def docker(*arguments: str, stdout=None) -> str:
    completed = subprocess.run(
        ["docker", *arguments], stdout=(subprocess.PIPE if stdout is None else stdout),
        stderr=subprocess.PIPE, text=stdout is None, check=False)
    if completed.returncode:
        error = completed.stderr if isinstance(completed.stderr, str) else ""
        raise QualificationError(error.strip() or "docker command failed")
    return completed.stdout.strip() if stdout is None else ""


def docker_stdout_sha256(*arguments: str) -> str:
    """Hash command stdout without retaining or displaying business rows."""
    process = subprocess.Popen(
        ["docker", *arguments], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    digest = sha256()
    assert process.stdout is not None
    while block := process.stdout.read(1024 * 1024):
        digest.update(block)
    stderr = process.stderr.read() if process.stderr is not None else b""
    if process.wait() != 0:
        raise QualificationError(
            stderr.decode("utf-8", errors="replace").strip()
            or "docker streaming command failed")
    return digest.hexdigest()


def wait_ready(container: str) -> None:
    for _ in range(150):
        result = subprocess.run(
            ["docker", "exec", container, "pg_isready", "-U", "postgres",
             "-d", "postgres"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, check=False)
        if result.returncode == 0:
            return
        time.sleep(.2)
    raise QualificationError("disposable database did not become ready")


def psql(container: str, database: str, statement: str) -> str:
    return docker("exec", container, "psql", "-U", "postgres", "-d", database,
                  "-AtX", "-v", "ON_ERROR_STOP=1", "-c", statement)


def create_roles(container: str) -> None:
    values = ",".join("'%s'" % role for role in GROUP_ROLES)
    psql(container, "postgres", f"""DO $roles$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[{values}] LOOP
    EXECUTE format('CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER '
                   'NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                   role_name);
  END LOOP;
END $roles$;""")


def schema_state(container: str, database: str = "postgres") -> dict[str, object]:
    raw = psql(container, database, """
      SELECT json_build_object(
        'rows',count(*),'minimum',min(version),'maximum',max(version),
        'digest',md5(string_agg(version::text||':'||checksum,',' ORDER BY version)),
        'checksumsValid',bool_and(checksum ~ '^[0-9a-f]{64}$'))
      FROM epm.schema_migration""")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise QualificationError("schema identity response is invalid")
    return value


def application_count(container: str, database: str = "postgres") -> int:
    raw = psql(container, database, "SELECT count(*) FROM epm.application")
    if not raw.isdecimal():
        raise QualificationError("application count response is invalid")
    return int(raw)


def owner_reset_fk_order_violations(container: str) -> list[dict[str, object]]:
    """Return non-self FK edges whose reset child is not before its parent."""
    raw = psql(container, "postgres", """
      WITH definition AS (
        SELECT pg_get_functiondef(
          'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'
          ::regprocedure) AS source
      ), edges AS (
        SELECT child.relname AS child, parent.relname AS parent,
          CASE child.relname
            WHEN 'numeric_cell_projection' THEN 'numeric_cell_current'
            WHEN 'text_cell_projection' THEN 'text_cell_current'
            WHEN 'line_detail_projection' THEN 'line_detail_current'
            WHEN 'generic_fact_projection' THEN 'generic_fact_current'
            WHEN 'coordinate_member_projection' THEN 'coordinate_member'
            WHEN 'coordinate_projection_state' THEN 'coordinate_projection'
            ELSE child.relname END AS child_key,
          CASE parent.relname
            WHEN 'numeric_cell_projection' THEN 'numeric_cell_current'
            WHEN 'text_cell_projection' THEN 'text_cell_current'
            WHEN 'line_detail_projection' THEN 'line_detail_current'
            WHEN 'generic_fact_projection' THEN 'generic_fact_current'
            WHEN 'coordinate_member_projection' THEN 'coordinate_member'
            WHEN 'coordinate_projection_state' THEN 'coordinate_projection'
            ELSE parent.relname END AS parent_key,
          constraint_row.conname, definition.source
        FROM pg_constraint AS constraint_row
        JOIN pg_class AS child ON child.oid=constraint_row.conrelid
        JOIN pg_namespace AS child_namespace
          ON child_namespace.oid=child.relnamespace
        JOIN pg_class AS parent ON parent.oid=constraint_row.confrelid
        JOIN pg_namespace AS parent_namespace
          ON parent_namespace.oid=parent.relnamespace
        CROSS JOIN definition
        WHERE constraint_row.contype='f'
          AND child_namespace.nspname='epm'
          AND parent_namespace.nspname='epm'
          AND child.oid<>parent.oid
      ), positioned AS (
        SELECT *,position(quote_literal(child_key) IN source) AS child_position,
          position(quote_literal(parent_key) IN source) AS parent_position
        FROM edges
      )
      SELECT coalesce(json_agg(json_build_object(
        'child',child,'parent',parent,'constraint',conname,
        'childPosition',child_position,'parentPosition',parent_position)
        ORDER BY parent_position,child_position,child,parent),'[]'::json)
      FROM positioned
      WHERE child_position=0 OR parent_position=0
         OR child_position>parent_position""")
    value = json.loads(raw)
    if not isinstance(value, list) or any(not isinstance(item, dict)
                                          for item in value):
        raise QualificationError("owner-reset FK order response is invalid")
    return value


def table_fingerprint(container: str, table: str) -> dict[str, object]:
    if SAFE_IDENTIFIER.fullmatch(table) is None:
        raise QualificationError("unsafe table identity")
    count = psql(container, "postgres", f'SELECT count(*) FROM epm."{table}"')
    if not count.isdecimal():
        raise QualificationError("table count response is invalid")
    digest = docker_stdout_sha256(
        "exec", container, "psql", "-U", "postgres", "-d", "postgres",
        "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        f'COPY (SELECT payload FROM (SELECT row_to_json(t)::text AS payload '
        f'FROM epm."{table}" AS t) AS canonical ORDER BY payload) TO STDOUT')
    return {"rows": int(count), "sha256": digest}


def fingerprints(container: str) -> dict[str, dict[str, object]]:
    available = set(psql(
        container, "postgres",
        "SELECT tablename FROM pg_tables WHERE schemaname='epm' ORDER BY tablename"
    ).splitlines())
    missing = sorted(set(PROTECTED_TABLES) - available)
    if missing:
        raise QualificationError("protected source tables are absent: " + ",".join(missing))
    return {table: table_fingerprint(container, table) for table in PROTECTED_TABLES}


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def qualify(args: argparse.Namespace) -> dict[str, object]:
    if os.environ.get("EPM_LAPTOP_POPULATED_UPGRADE_DISPOSABLE") != "1":
        raise QualificationError("explicit disposable qualification opt-in is required")
    if SAFE_CONTAINER.fullmatch(args.source_container) is None:
        raise QualificationError("source container identity is invalid")
    for label, value in (("candidate", args.application_image),
                         ("database", args.database_image)):
        if IMAGE.fullmatch(value) is None:
            raise QualificationError(label + " image must be an exact digest")
    if args.expected_source_schema < 1 or args.expected_target_schema < args.expected_source_schema:
        raise QualificationError("schema bounds are invalid")
    if args.output.exists() or not args.output.is_absolute():
        raise QualificationError("output must be a new absolute path")

    token = uuid.uuid4().hex[:12]
    container = "openepm_laptop_upgrade_" + token
    volume = container + "_data"
    password = secrets.token_urlsafe(32)
    cleanup: list[str] = []
    volume_created = container_created = False
    result: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(prefix="openepm-laptop-upgrade-") as directory:
        archive = Path(directory) / "source.dump"
        try:
            with archive.open("wb") as stream:
                docker("exec", args.source_container, "pg_dump", "-U", "postgres",
                       "-d", "postgres", "--format=custom", "--no-owner",
                       "--no-comments", stdout=stream)
            if archive.stat().st_size <= 0:
                raise QualificationError("source archive is empty")
            archive_digest = file_sha256(archive)

            docker("volume", "create", volume)
            volume_created = True
            docker("run", "-d", "--name", container,
                   "--label", "openepm.laptop-upgrade-disposable=true",
                   "-v", volume + ":/var/lib/postgresql",
                   "-e", "POSTGRES_PASSWORD=" + password, args.database_image)
            container_created = True
            wait_ready(container)
            create_roles(container)
            docker("cp", str(archive), container + ":/tmp/source.dump")
            docker("exec", container, "pg_restore", "-U", "postgres", "-d",
                   "postgres", "--exit-on-error", "--no-owner", "/tmp/source.dump")
            before_schema = schema_state(container)
            before_count = application_count(container)
            if before_schema.get("maximum") != args.expected_source_schema:
                raise QualificationError("restored source schema differs")
            if before_count != args.expected_applications:
                raise QualificationError("restored application count differs")
            before = fingerprints(container)

            admin_dsn = ("host=127.0.0.1 port=5432 user=postgres password="
                         + password + " dbname=postgres")
            docker("run", "--rm", "--network", "container:" + container,
                   "-e", "EPM_POSTGRES_ADMIN_DSN=" + admin_dsn,
                   args.application_image, "python", "-m",
                   "scripts.initialize_postgres_release")
            after_schema = schema_state(container)
            after_count = application_count(container)
            reset_order_violations = owner_reset_fk_order_violations(container)
            if reset_order_violations:
                raise QualificationError(
                    "candidate owner-reset FK order differs: "
                    + ",".join(str(item.get("constraint"))
                               for item in reset_order_violations))
            after = fingerprints(container)
            changed = sorted(table for table in PROTECTED_TABLES
                             if before[table] != after[table])
            if after_schema.get("maximum") != args.expected_target_schema:
                raise QualificationError("candidate schema maximum differs")
            if after_count != before_count:
                raise QualificationError("candidate migration changed application count")
            if changed:
                raise QualificationError(
                    "candidate migration changed protected tables: " + ",".join(changed))
            result = {
                "format": "openepm-active-laptop-populated-upgrade-v1",
                "status": "passed", "sharedDatabaseMutation": False,
                "sourceContainer": args.source_container,
                "applicationImage": args.application_image,
                "databaseImage": args.database_image,
                "archive": {"bytes": archive.stat().st_size,
                            "sha256": archive_digest, "retained": False},
                "before": {"schema": before_schema, "applications": before_count,
                           "protectedTables": before},
                "after": {"schema": after_schema, "applications": after_count,
                          "protectedTables": after},
                "protectedTablesUnchanged": True,
                "ownerResetFkOrderViolations": reset_order_violations,
                "ownerResetFkOrderVerified": True,
                "cleanup": {"containerRemoved": True, "volumeRemoved": True,
                            "archiveRemoved": True},
            }
        finally:
            if container_created:
                try:
                    docker("rm", "-f", container)
                except Exception as error:  # cleanup must remain visible
                    cleanup.append(str(error))
            if volume_created:
                try:
                    docker("volume", "rm", volume)
                except Exception as error:
                    cleanup.append(str(error))
            if cleanup:
                raise QualificationError("disposable cleanup failed: " + "; ".join(cleanup))
    if result is None:
        raise QualificationError("qualification produced no result")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-container", required=True)
    parser.add_argument("--application-image", required=True)
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--expected-source-schema", type=int, required=True)
    parser.add_argument("--expected-target-schema", type=int, required=True)
    parser.add_argument("--expected-applications", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = qualify(arguments)
    except QualificationError as error:
        parser.error(str(error))
    print(json.dumps({"status": result["status"],
                      "format": result["format"],
                      "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
