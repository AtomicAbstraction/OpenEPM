#!/usr/bin/env python3
"""Qualify the active laptop's populated schema upgrade on an owned clone.

The active database is only read through one PostgreSQL consistent dump.  The
archive, target container and target volume are run-owned and are removed even
after failure.  No backup is retained and no active service is reconfigured.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from contextvars import ContextVar
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
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from scripts.audit_disposable_docker_cleanup_candidates import OwnedDockerRun
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
    "generic_fact_projection", "generic_fact_table", "hierarchy_definition",
    "hierarchy_closure", "hierarchy_state", "member",
    "member_list_definition", "numeric_cell_projection",
    "numeric_fact_event", "operation_receipt", "python_program_definition",
    "relationship", "saved_grid_definition",
    "sealed_cube_selection", "semantic_column", "source_batch",
    "source_batch_chunk", "source_batch_row", "task", "task_event",
    "text_cell_projection", "text_fact_event", "workspace",
)
TRANSFORMED_PROTECTED_TABLE_COLUMNS = {
    "application_state": (
        "workspace_id", "application_id", "schema_epoch", "metadata_revision",
        "data_revision", "policy_revision", "commit_revision", "processing_mode",
        "currency_settings", "enabled_capabilities", "capability_revision",
        "commit_open", "active_projection_generation", "security_revision",
    ),
    "attribute_definition": (
        "workspace_id", "application_id", "scope", "dimension_id",
        "attribute_id", "default_name", "display_name", "short_description",
        "semantic_description", "value_type", "validation_constraints", "status",
        "created_at", "updated_at",
    ),
    "hierarchy_closure": (
        "workspace_id", "application_id", "dimension_id", "hierarchy_id",
        "ancestor_member_id", "descendant_member_id", "min_depth", "path_count",
    ),
    "operation_receipt": (
        "workspace_id", "application_id", "operation_id", "command_digest",
        "actor_id", "committed_revision", "committed_at", "sealed", "provenance",
    ),
    "saved_grid_definition": (
        "workspace_id", "application_id", "grid_id", "name", "definition",
        "canonical_digest", "metadata_revision", "creator_issuer",
        "creator_subject_id",
    ),
}
INTRODUCED_CURRENT_TABLES = {
    "hierarchy_state", "member_list_definition", "python_program_definition",
}


class QualificationError(RuntimeError):
    pass


_DOCKER_CONTEXT = ContextVar("populated_upgrade_docker_context", default=None)


@contextmanager
def selected_docker_context(context):
    token = _DOCKER_CONTEXT.set(context)
    try:
        yield
    finally:
        _DOCKER_CONTEXT.reset(token)


def docker_arguments(arguments):
    context = _DOCKER_CONTEXT.get()
    prefix = ["--context", context] if context and arguments[:1] != ("--context",) else []
    return ["docker", *prefix, *arguments]


def docker(*arguments: str, stdout=None) -> str:
    completed = subprocess.run(
        docker_arguments(arguments), stdout=(subprocess.PIPE if stdout is None else stdout),
        stderr=subprocess.PIPE, text=stdout is None, check=False)
    if completed.returncode:
        error = completed.stderr if isinstance(completed.stderr, str) else ""
        diagnostic = completed.stdout if isinstance(completed.stdout, str) else ""
        details = "\n".join(
            value.strip() for value in (error, diagnostic) if value.strip())
        raise QualificationError(details or "docker command failed")
    return completed.stdout.strip() if stdout is None else ""


def docker_stdout_sha256(*arguments: str) -> str:
    """Hash command stdout without retaining or displaying business rows."""
    process = subprocess.Popen(
        docker_arguments(arguments), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            docker_arguments(("exec", container, "pg_isready", "-U", "postgres",
                              "-d", "postgres")), stdout=subprocess.DEVNULL,
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


def table_projection_fingerprint(
        container: str, table: str, columns: tuple[str, ...]) -> dict[str, object]:
    if SAFE_IDENTIFIER.fullmatch(table) is None or not columns or any(
            SAFE_IDENTIFIER.fullmatch(column) is None for column in columns):
        raise QualificationError("unsafe projected table identity")
    count = psql(container, "postgres", f'SELECT count(*) FROM epm."{table}"')
    if not count.isdecimal():
        raise QualificationError("projected table count response is invalid")
    projection = ",".join(f'"{column}"' for column in columns)
    digest = docker_stdout_sha256(
        "exec", container, "psql", "-U", "postgres", "-d", "postgres",
        "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        f'COPY (SELECT payload FROM (SELECT row_to_json(projected)::text AS payload '
        f'FROM (SELECT {projection} FROM epm."{table}") AS projected) AS canonical '
        f'ORDER BY payload) TO STDOUT')
    return {"rows": int(count), "sha256": digest}


def query_fingerprint(container: str, query: str) -> dict[str, object]:
    count = psql(container, "postgres", f"SELECT count(*) FROM ({query}) AS projected")
    if not count.isdecimal():
        raise QualificationError("projected query count response is invalid")
    digest = docker_stdout_sha256(
        "exec", container, "psql", "-U", "postgres", "-d", "postgres",
        "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
        f"COPY (SELECT row_to_json(projected)::text AS payload FROM ({query}) "
        "AS projected ORDER BY payload) TO STDOUT")
    return {"rows": int(count), "sha256": digest}


def transformed_fingerprints(
        container: str, *, source_schema: bool,
        reconcile_legacy_member_lists: bool = False) -> dict[str, dict[str, object]]:
    # The installed laptop baseline is schema 364.  Hierarchies, saved views,
    # member lists and Python programs were converted to their stable current
    # tables by migrations 0320, 0306, 0307 and 0314 respectively.  Older
    # qualification code reconstructed those objects from the pre-current
    # version/publication tables; querying that retired shape made a real
    # 364->current rehearsal fail before it could measure preservation.
    # Compare only the stable business projection on both sides.  The
    # source_schema argument remains explicit so callers cannot accidentally
    # stop declaring which side they are fingerprinting.
    if type(source_schema) is not bool:
        raise QualificationError("source schema selector must be boolean")
    result = {
        table: table_projection_fingerprint(container, table, columns)
        for table, columns in sorted(TRANSFORMED_PROTECTED_TABLE_COLUMNS.items())
        if table not in {"application_state", "saved_grid_definition"}
    }
    legacy_revision = ("CASE WHEN EXISTS(SELECT 1 FROM epm.member_list_definition l "
        "JOIN epm.python_program_build b ON (b.workspace_id,b.application_id,b.build_id)="
        "(l.workspace_id,l.application_id,l.source_build_id) "
        "JOIN epm.python_program_definition d ON "
        "(d.workspace_id,d.application_id,d.program_id,d.source_token)="
        "(b.workspace_id,b.application_id,b.program_id,b.program_source_token) "
        "LEFT JOIN epm.python_plan_artifact p ON (p.workspace_id,p.application_id,p.build_id)="
        "(b.workspace_id,b.application_id,b.build_id) "
        "WHERE (l.workspace_id,l.application_id)=(s.workspace_id,s.application_id) "
        "AND l.ownership_state='Unresolved' AND l.status='Inactive' "
        "AND d.status='Inactive' AND d.declared_output IS NULL AND "
        "((p.build_id IS NOT NULL AND p.canonical_plan#>>'{units,0,operations,0,function}'="
        "'metadata.member_list.version.save') OR (p.build_id IS NULL "
        "AND b.purpose='ImpactTest' AND b.status='expired' "
        "AND b.expected_metadata_revision=l.metadata_revision))) THEN 1 ELSE 0 END"
        if source_schema and reconcile_legacy_member_lists else "0")
    definition_owner_revision = ("CASE WHEN EXISTS(SELECT 1 FROM epm.expression_rule_definition r "
        "WHERE (r.workspace_id,r.application_id)=(s.workspace_id,s.application_id)) "
        "OR EXISTS(SELECT 1 FROM epm.member_list_definition l WHERE "
        "(l.workspace_id,l.application_id)=(s.workspace_id,s.application_id)) "
        "THEN 1 ELSE 0 END" if source_schema and not reconcile_legacy_member_lists else "0")
    revision_offset=(legacy_revision if reconcile_legacy_member_lists
                     else definition_owner_revision)
    result["application_state"] = query_fingerprint(container, f"""
      SELECT workspace_id,application_id,schema_epoch,metadata_revision,data_revision,
        policy_revision+({revision_offset}) AS policy_revision,
        commit_revision+({revision_offset}) AS commit_revision,processing_mode,
        currency_settings,enabled_capabilities,capability_revision,commit_open,
        active_projection_generation,security_revision
      FROM epm.application_state s""")
    result["saved_grid_definition"] = query_fingerprint(container, """
      SELECT workspace_id,application_id,grid_id,name,metadata_revision,
        creator_issuer,creator_subject_id FROM epm.saved_grid_definition""")
    return result


def legacy_member_list_reconciliation_fingerprint(
        container: str, *, reconciled: bool) -> dict[str, object]:
    owner_predicate = ("l.ownership_state='Source' AND l.source_program_id=s.program_id "
        "AND l.source_token=s.source_token AND l.source_digest=s.source_digest "
        "AND s.declared_output=jsonb_build_object('kind','MemberList',"
        "'definitionId',l.list_id,'dimensionId',l.dimension_id) "
        "AND s.state_token=l.state_token" if reconciled else
        "l.ownership_state='Unresolved' AND s.declared_output IS NULL")
    return query_fingerprint(container, f"""
      SELECT l.workspace_id,l.application_id,l.list_id,l.dimension_id,
        l.source_build_id,s.program_id,s.source_token,s.source_digest
      FROM epm.member_list_definition l
      JOIN epm.python_program_build b
        ON (b.workspace_id,b.application_id,b.build_id)=
           (l.workspace_id,l.application_id,l.source_build_id)
      JOIN epm.python_program_definition s
        ON (s.workspace_id,s.application_id,s.program_id,s.source_token)=
           (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
      LEFT JOIN epm.python_plan_artifact a
        ON (a.workspace_id,a.application_id,a.build_id)=
           (b.workspace_id,b.application_id,b.build_id)
      WHERE {owner_predicate}
        AND l.status='Inactive' AND l.current_certificate IS NULL
        AND s.status='Inactive'
        AND ((a.build_id IS NOT NULL
          AND jsonb_typeof(a.canonical_plan->'units')='array'
          AND jsonb_array_length(a.canonical_plan->'units')=1
          AND jsonb_typeof(a.canonical_plan#>'{{units,0,operations}}')='array'
          AND jsonb_array_length(a.canonical_plan#>'{{units,0,operations}}')=1
          AND a.canonical_plan#>>'{{units,0,operations,0,function}}'=
            'metadata.member_list.version.save'
          AND a.canonical_plan#>>'{{units,0,operations,0,arguments,definition,listId}}'=l.list_id
          AND a.canonical_plan#>>'{{units,0,operations,0,arguments,definition,dimensionId}}'=l.dimension_id
          AND jsonb_typeof(a.canonical_plan#>'{{units,0,operations,0,arguments,definition,version}}')='number'
          AND a.canonical_plan#>>'{{units,0,operations,0,arguments,definition,version}}' ~ '^[1-9][0-9]*$'
          AND ((a.canonical_plan#>'{{units,0,operations,0,arguments,definition}}')-'version')=l.definition)
          OR (a.build_id IS NULL AND b.purpose='ImpactTest' AND b.status='expired'
            AND b.expected_metadata_revision=l.metadata_revision))
    """)


def saved_grid_semantic_mismatches(container: str) -> int:
    value = psql(container, "postgres", """
      SELECT count(*) FROM public.saved_grid_0374_before b
      FULL JOIN epm.saved_grid_definition g USING(workspace_id,application_id,grid_id)
      WHERE b.grid_id IS NULL OR g.grid_id IS NULL OR g.name<>b.name
        OR g.metadata_revision<>b.metadata_revision
        OR g.definition->>'format'<>'openepm-cube-view-v1'
        OR g.definition->>'viewId'<>b.grid_id OR g.definition->>'name'<>b.name
        OR g.definition->'layout'->'rows'<>b.definition->'rowDimensions'
        OR g.definition->'layout'->'columns'<>b.definition->'columnDimensions'
        OR g.definition->'layout'->'pages'<>'[]'::jsonb
        OR g.definition->'layout'->'filters'<>(SELECT coalesce(
          jsonb_agg(key ORDER BY key),'[]'::jsonb)
          FROM jsonb_object_keys(b.definition->'pov') AS p(key))
        OR g.definition->'dataSource'->>'kind'<>b.definition->>'dataLayer'
        OR g.definition->'pageSize'<>b.definition->'pageSize'
        OR g.definition->'suppression'<>'{"missing":false,"zero":false}'::jsonb
        OR EXISTS(SELECT 1 FROM jsonb_each_text(b.definition->'pov') p
          WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(
            g.definition->'selection'->'dimensions') selected
            WHERE selected->>'dimensionId'=p.key
              AND selected->'include'=jsonb_build_object(
                'kind','member','memberId',p.value)))
        OR EXISTS(SELECT 1 FROM epm.dimension d
          WHERE d.workspace_id=g.workspace_id AND d.application_id=g.application_id
            AND d.status='Active' AND NOT b.definition->'pov' ? d.dimension_id
            AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(
              g.definition->'selection'->'dimensions') selected
              WHERE selected->>'dimensionId'=d.dimension_id
                AND selected->'include'=jsonb_build_object('kind','members','memberIds',
                  (SELECT jsonb_agg(m.member_id ORDER BY m.member_id)
                   FROM epm.member m WHERE m.workspace_id=d.workspace_id
                     AND m.application_id=d.application_id
                     AND m.dimension_id=d.dimension_id AND m.status='Active'))))""")
    if not value.isdecimal():
        raise QualificationError("saved-view semantic mismatch count is invalid")
    return int(value)


def introduced_current_fingerprints(
        container: str, *, normalize_pre_366_statuses: bool
        ) -> dict[str, dict[str, object]]:
    if type(normalize_pre_366_statuses) is not bool:
        raise QualificationError("pre-366 status selector must be boolean")
    member_status = ("'Inactive'" if normalize_pre_366_statuses else "status")
    python_status = ("""CASE WHEN EXISTS(
          SELECT 1 FROM epm.python_program_build b
          WHERE (b.workspace_id,b.application_id,b.program_id,b.program_source_token)=
            (s.workspace_id,s.application_id,s.program_id,s.source_token)
          AND (EXISTS(SELECT 1 FROM epm.expression_rule_definition r WHERE
            (r.workspace_id,r.application_id,r.source_build_id)=
            (b.workspace_id,b.application_id,b.build_id))
           OR EXISTS(SELECT 1 FROM epm.member_list_definition l WHERE
            (l.workspace_id,l.application_id,l.source_build_id)=
            (b.workspace_id,b.application_id,b.build_id))))
          THEN 'Inactive' ELSE s.status END""" if normalize_pre_366_statuses
        else "s.status")
    # Migration 0366 deliberately invalidates every compiled member list and
    # every Python source implicated in an authored rule/list.  Normalize only
    # a source older than 0366 to that exact deterministic result.  A source
    # already at 0366 or later can contain subsequently adopted current
    # definitions, so its real status is protected business state and must be
    # compared exactly rather than rewritten by the qualifier.
    return {
        "hierarchy_state": query_fingerprint(container, """
          SELECT workspace_id,application_id,dimension_id,hierarchy_id,
            metadata_revision,membership_semantics,operation_id,built_at
          FROM epm.hierarchy_state"""),
        "member_list_definition": query_fingerprint(container, """
          SELECT workspace_id,application_id,list_id,dimension_id,name,definition,
            %s AS status,metadata_revision,creator_issuer,creator_subject_id,source_build_id
          FROM epm.member_list_definition""" % member_status),
        "python_program_definition": query_fingerprint(container, """
          SELECT s.workspace_id,s.application_id,s.program_id,%s AS status,s.source_text,
            source_digest,entry_point,parameter_schema,environment_id
          FROM epm.python_program_definition s""" % python_status),
    }


def available_protected_tables(container: str) -> set[str]:
    available = set(psql(
        container, "postgres",
        "SELECT tablename FROM pg_tables WHERE schemaname='epm' ORDER BY tablename"
    ).splitlines())
    return set(PROTECTED_TABLES) & available


def fingerprints(container: str, tables: set[str]) -> dict[str, dict[str, object]]:
    unknown = sorted(tables - set(PROTECTED_TABLES))
    if unknown:
        raise QualificationError("unknown protected tables: " + ",".join(unknown))
    return {table: table_fingerprint(container, table) for table in sorted(tables)}


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
    result: dict[str, object] | None = None
    with OwnedDockerRun(
            args.output.with_suffix(args.output.suffix + ".run.json"),
            purpose="laptop-populated-upgrade", command=docker) as owned, \
            selected_docker_context(owned.manifest["context"]):
        owned.protect_container(args.source_container)
        with tempfile.TemporaryDirectory(prefix="openepm-laptop-upgrade-") as directory:
            archive = Path(directory) / "source.dump"
            with archive.open("wb") as stream:
                docker("exec", args.source_container, "pg_dump", "-U", "postgres",
                       "-d", "postgres", "--format=custom", "--no-owner",
                       "--no-comments", stdout=stream)
            if archive.stat().st_size <= 0:
                raise QualificationError("source archive is empty")
            archive_digest = file_sha256(archive)

            owned.volume(volume)
            container = owned.container(container,
                   "-v", volume + ":/var/lib/postgresql",
                   "-e", "POSTGRES_PASSWORD=" + password, args.database_image)
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
            source_protected_tables = available_protected_tables(container)
            if not source_protected_tables:
                raise QualificationError("source has no protected application tables")
            before = fingerprints(container, source_protected_tables)
            reconcile_legacy_member_lists=(
                args.expected_source_schema>=366 and args.expected_target_schema>=377)
            before_transformed = transformed_fingerprints(
                container, source_schema=True,
                reconcile_legacy_member_lists=reconcile_legacy_member_lists)
            before_introduced = introduced_current_fingerprints(
                container,
                normalize_pre_366_statuses=args.expected_source_schema < 366)
            before_legacy=(legacy_member_list_reconciliation_fingerprint(
                container,reconciled=False) if reconcile_legacy_member_lists else
                {"rows":0,"sha256":sha256(b"").hexdigest()})
            if before_legacy["rows"] != args.expected_legacy_member_list_reconciliations:
                raise QualificationError(
                    "legacy member-list reconciliation count differs")
            psql(container, "postgres", """CREATE TABLE public.saved_grid_0374_before AS
              SELECT workspace_id,application_id,grid_id,name,definition,
                metadata_revision FROM epm.saved_grid_definition""")

            admin_dsn = ("host=127.0.0.1 port=5432 user=postgres password="
                         + password + " dbname=postgres")
            try:
                owned.container("openepm-upgrade-init-" + token,
                       "--network", "container:" + container,
                       "-e", "EPM_POSTGRES_ADMIN_DSN=" + admin_dsn,
                       args.application_image, "python", "-m",
                       "scripts.initialize_postgres_release", attach=True)
            except QualificationError as initialize_error:
                failed_schema = schema_state(container)
                diagnostic_program = (
                    "import os\n"
                    "from pathlib import Path\n"
                    "from scripts.apply_postgres_migrations import apply_migrations\n"
                    "apply_migrations(os.environ['EPM_POSTGRES_ADMIN_DSN'], "
                    "Path('/srv/openepm/schema/postgres'))\n")
                try:
                    owned.container("openepm-upgrade-diagnostic-" + token,
                           "--network", "container:" + container,
                           "-e", "EPM_POSTGRES_ADMIN_DSN=" + admin_dsn,
                           args.application_image, "python", "-c", diagnostic_program,
                           attach=True)
                except QualificationError as diagnostic_error:
                    raise QualificationError(
                        f"initializer failed after schema {failed_schema.get('maximum')}: "
                        f"{initialize_error}; direct migration diagnostic: "
                        f"{diagnostic_error}") from initialize_error
                raise QualificationError(
                    f"initializer failed after schema {failed_schema.get('maximum')}: "
                    f"{initialize_error}; direct retry unexpectedly succeeded") \
                    from initialize_error
            after_schema = schema_state(container)
            after_count = application_count(container)
            reset_order_violations = owner_reset_fk_order_violations(container)
            if reset_order_violations:
                raise QualificationError(
                    "candidate owner-reset FK order differs: "
                    + ",".join(
                        f"{item.get('child')}->{item.get('parent')}"
                        f"[{item.get('constraint')};"
                        f"{item.get('childPosition')}>{item.get('parentPosition')}]"
                        for item in reset_order_violations))
            target_protected_tables = available_protected_tables(container)
            missing_after = sorted(source_protected_tables - target_protected_tables)
            if missing_after:
                raise QualificationError(
                    "candidate migration removed protected tables: "
                    + ",".join(missing_after))
            after = fingerprints(container, target_protected_tables)
            after_transformed = transformed_fingerprints(
                container, source_schema=False,
                reconcile_legacy_member_lists=reconcile_legacy_member_lists)
            after_introduced = introduced_current_fingerprints(
                container, normalize_pre_366_statuses=False)
            after_legacy=(legacy_member_list_reconciliation_fingerprint(
                container,reconciled=True) if reconcile_legacy_member_lists else
                {"rows":0,"sha256":sha256(b"").hexdigest()})
            saved_grid_mismatches = (saved_grid_semantic_mismatches(container)
                if args.expected_source_schema < 374 <= args.expected_target_schema else 0)
            current_saved_grids_exact = (True if args.expected_source_schema < 374
                else before["saved_grid_definition"] == after["saved_grid_definition"])
            introduced_changed = sorted(
                table for table in INTRODUCED_CURRENT_TABLES
                if before_introduced[table] != after_introduced[table])
            transformed_changed = sorted(
                table for table in TRANSFORMED_PROTECTED_TABLE_COLUMNS
                if before_transformed[table] != after_transformed[table])
            changed = sorted(table for table in source_protected_tables
                             if table not in TRANSFORMED_PROTECTED_TABLE_COLUMNS
                             if table not in INTRODUCED_CURRENT_TABLES
                             if before[table] != after[table])
            introduced = sorted(target_protected_tables - source_protected_tables)
            populated_introduced = sorted(
                table for table in introduced
                if table not in INTRODUCED_CURRENT_TABLES
                and after[table]["rows"] != 0)
            if after_schema.get("maximum") != args.expected_target_schema:
                raise QualificationError("candidate schema maximum differs")
            if after_count != before_count:
                raise QualificationError("candidate migration changed application count")
            if changed:
                raise QualificationError(
                    "candidate migration changed protected tables: " + ",".join(changed))
            if transformed_changed:
                raise QualificationError(
                    "candidate migration changed protected business columns: "
                    + ",".join(
                        f"{table}[before={before_transformed[table]};"
                        f"after={after_transformed[table]}]"
                        for table in transformed_changed))
            if introduced_changed:
                raise QualificationError(
                    "candidate migration changed currentized business definitions: "
                    + ",".join(
                        f"{table}[before={before_introduced[table]};"
                        f"after={after_introduced[table]}]"
                        for table in introduced_changed))
            if before_legacy != after_legacy:
                raise QualificationError(
                    "legacy member-list ownership reconciliation differs: "
                    f"before={before_legacy};after={after_legacy}")
            if saved_grid_mismatches:
                raise QualificationError("saved-view semantic reconciliation failed")
            if not current_saved_grids_exact:
                raise QualificationError("current saved views changed during upgrade")
            if populated_introduced:
                raise QualificationError(
                    "candidate migration populated new protected tables: "
                    + ",".join(populated_introduced))
            result = {
                "format": "openepm-active-laptop-populated-upgrade-v2",
                "status": "passed", "sharedDatabaseMutation": False,
                "qualifierSourceSha256": file_sha256(Path(__file__).resolve()),
                "sourceContainer": args.source_container,
                "applicationImage": args.application_image,
                "databaseImage": args.database_image,
                "archive": {"bytes": archive.stat().st_size,
                            "sha256": archive_digest, "retained": False},
                "before": {"schema": before_schema, "applications": before_count,
                           "protectedTables": before,
                           "protectedTableNames": sorted(source_protected_tables)},
                "after": {"schema": after_schema, "applications": after_count,
                          "protectedTables": after,
                          "protectedTableNames": sorted(target_protected_tables)},
                "untransformedProtectedTablesExact": True,
                "transformedProtectedTables": sorted(
                    TRANSFORMED_PROTECTED_TABLE_COLUMNS),
                "transformedBusinessFingerprints": {
                    "before": before_transformed, "after": after_transformed},
                "protectedBusinessSemanticsUnchanged": True,
                "introducedProtectedTables": introduced,
                "unmappedIntroducedProtectedTablesEmpty": True,
                "introducedCurrentTables": sorted(INTRODUCED_CURRENT_TABLES),
                "introducedCurrentBusinessFingerprints": {
                    "before": before_introduced, "after": after_introduced},
                "introducedCurrentBusinessSemanticsUnchanged": True,
                "legacyMemberListOwnershipReconciliation": {
                    "expected": args.expected_legacy_member_list_reconciliations,
                    "before": before_legacy,"after": after_legacy,
                    "exactIdentitiesPreserved": before_legacy==after_legacy,
                    "inactiveWithoutFabricatedAcceptance": True},
                "savedViewSemanticMismatches": saved_grid_mismatches,
                "savedViewSemanticReconciliationPassed": True,
                "currentSavedViewsExact": current_saved_grids_exact,
                "ownerResetFkOrderViolations": reset_order_violations,
                "ownerResetFkOrderVerified": True,
            }
    if result is None:
        raise QualificationError("qualification produced no result")
    result["cleanup"] = {**owned.report, "archiveRemoved": not archive.exists()}
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
    parser.add_argument("--expected-legacy-member-list-reconciliations",
                        type=int, default=0)
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
