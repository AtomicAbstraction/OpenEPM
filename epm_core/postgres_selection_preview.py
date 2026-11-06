"""Authorized, revision-pinned preview of generic cube selections."""

from __future__ import annotations

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout
from .selection_contract import canonical_selection
from .selection_resolver import resolve_selection


PREVIEW = "cube.selection.preview"


def catalog() -> dict:
    return {PREVIEW: {
        "mode": "read", "permission": "read", "workClass": "short",
        "previewRequired": False, "idempotencyRequired": False,
        "arguments": {
            "selection": "complete-grain openepm-cube-selection-v1",
            "expectedPolicyRevision": "current authorization policy revision",
        },
        "result": "resolved member IDs, reusable-list pins and resolution digest",
    }}


def _program(raw: object) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") != PREVIEW
            or not isinstance(raw.get("arguments"), dict)
            or set(raw["arguments"]) != {"selection", "expectedPolicyRevision"}
            or type(raw["arguments"]["expectedPolicyRevision"]) is not int
            or raw["arguments"]["expectedPolicyRevision"] < 0):
        raise ValueError("CUBE_SELECTION_PREVIEW_PROGRAM_INVALID")
    return raw["arguments"]


def resolve_selection_in_transaction(db, scope: ApplicationScope,
                                     selection: object,
                                     metadata_revision: int) -> dict:
    """Resolve one canonical selection inside the caller's pinned transaction.

    The caller owns authorization, scope setup and locking.  Keeping this
    storage adapter shared prevents workflow persistence from implementing a
    weaker member-list or metadata interpretation than the public preview.
    """
    dimensions = [row["dimension_id"] for row in db.execute("""
        SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s
        AND application_id=%s AND status='Active'
        ORDER BY dimension_id""", (scope.workspace_id,
        scope.application_id)).fetchall()]
    canonical = canonical_selection(selection, active_dimensions=dimensions)
    member_rows = db.execute("""SELECT dimension_id,member_id,name,
        custom_values FROM epm.member WHERE workspace_id=%s
        AND application_id=%s AND status='Active'
        ORDER BY dimension_id,member_id""", (scope.workspace_id,
        scope.application_id)).fetchall()
    relationship_rows = db.execute("""SELECT dimension_id,
        relationship_id,parent_member_id,child_member_id
        FROM epm.relationship
        WHERE workspace_id=%s AND application_id=%s
        AND status='Active' ORDER BY dimension_id,parent_member_id,
        child_member_id""", (scope.workspace_id,
        scope.application_id)).fetchall()
    columns = db.execute("""SELECT dimension_id,slot,display_name,
        properties FROM epm.semantic_column WHERE workspace_id=%s
        AND application_id=%s AND scope='Member'
        ORDER BY dimension_id,slot""", (scope.workspace_id,
        scope.application_id)).fetchall()
    members = {dimension: {} for dimension in dimensions}
    relationships = {dimension: [] for dimension in dimensions}
    placement_relationships = {dimension: [] for dimension in dimensions}
    attributes = {dimension: {} for dimension in dimensions}
    attribute_types = {dimension: {} for dimension in dimensions}
    columns_by_dimension = {dimension: [] for dimension in dimensions}
    for column in columns:
        if column["dimension_id"] in columns_by_dimension:
            columns_by_dimension[column["dimension_id"]].append(column)
    for row in member_rows:
        dimension = row["dimension_id"]
        if dimension not in members:
            continue
        members[dimension][row["member_id"]] = row["name"]
        values = dict(row["custom_values"])
        for column in columns_by_dimension[dimension]:
            slot = f"Custom{column['slot']:02d}"
            values[column["display_name"]] = values.get(slot)
        attributes[dimension][row["member_id"]] = values
    for row in relationship_rows:
        if row["dimension_id"] in relationships:
            relationships[row["dimension_id"]].append(
                (row["parent_member_id"], row["child_member_id"]))
            placement_relationships[row["dimension_id"]].append({
                "relationshipId": row["relationship_id"],
                "parentMemberId": row["parent_member_id"],
                "childMemberId": row["child_member_id"]})
    for dimension, dimension_columns in columns_by_dimension.items():
        for column in dimension_columns:
            value_type = column["properties"]["valueType"]
            attribute_types[dimension][f"Custom{column['slot']:02d}"] = value_type
            attribute_types[dimension][column["display_name"]] = value_type
    references = {(selector["listId"], selector["version"])
        for dimension in canonical["dimensions"]
        for selector in (dimension["include"], dimension["exclude"])
        if selector is not None and selector["kind"] == "member_list"}
    member_lists = {}
    for list_id, version in sorted(references):
        row = db.execute("""SELECT v.definition FROM
            epm.member_list_version v JOIN epm.member_list_publication p
            USING(workspace_id,application_id,list_id)
            WHERE v.workspace_id=%s AND v.application_id=%s
            AND v.list_id=%s AND v.version=%s AND p.status='Published'
            AND p.version=v.version""", (scope.workspace_id,
            scope.application_id, list_id, version)).fetchone()
        if row is None:
            raise ValueError("CUBE_SELECTION_MEMBER_LIST_UNPUBLISHED")
        member_lists[(list_id, version)] = row["definition"]
    return resolve_selection(canonical, metadata_revision=metadata_revision,
        active_dimensions=dimensions, members=members,
        relationships=relationships, attributes=attributes,
        placement_relationships=placement_relationships,
        attribute_types=attribute_types, member_lists=member_lists)


class PostgresSelectionPreview:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime",
            ("dimension", "member", "relationship", "semantic_column",
             "member_list_version", "member_list_publication"))
        self.dsn, self.identity = dsn, identity

    @staticmethod
    def _scope(db, scope: ApplicationScope) -> None:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("CUBE_SELECTION_SCOPE_INVALID")
        configure_lock_wait(db)
        configure_statement_timeout(db, 5000)
        PostgresNumericFactStore._set_scope(db, scope)

    def read(self, scope: ApplicationScope, raw: dict) -> dict:
        args = _program(raw)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read", function=PREVIEW)
                state = db.execute("""SELECT metadata_revision,policy_revision,
                    commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if state["policy_revision"] != args["expectedPolicyRevision"]:
                    raise ValueError("STALE_POLICY_REVISION")
                resolved = resolve_selection_in_transaction(
                    db, scope, args["selection"], state["metadata_revision"])
                end = db.execute("""SELECT metadata_revision,policy_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""", (scope.workspace_id,
                    scope.application_id)).fetchone()
                if (end is None or end["metadata_revision"] != state["metadata_revision"]
                        or end["policy_revision"] != state["policy_revision"]):
                    raise ValueError("CUBE_SELECTION_STATE_CHANGED_DURING_PREVIEW")
                return {**resolved, "policyRevision": state["policy_revision"],
                        "commitRevision": state["commit_revision"]}
