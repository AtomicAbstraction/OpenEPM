"""Authorized, revision-pinned preview of generic cube selections."""

from __future__ import annotations

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_member_selection import load_selection_context, SelectionReadBudget
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout
from .selection_contract import canonical_selection
from .selection_resolver import resolve_selection, selector_definition, MAX_RESOLVED_MEMBERS


PREVIEW = "cube.selection.preview"


def catalog() -> dict:
    return {PREVIEW: {
        "mode": "read", "permission": "read", "workClass": "short",
        "previewRequired": False, "idempotencyRequired": False,
        "arguments": {
            "selection": "complete-grain openepm-cube-selection-v1",
            "expectedPolicyRevision": "current authorization policy revision",
        },
        "result": "resolved authorized member IDs, reusable-list pins and resolution digest; requested scopes bounded to 100000 members/edges",
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


def load_current_member_lists(db, scope, selection):
    """Load exactly the current reusable lists required by a canonical selection."""
    references = {selector["listId"]
        for dimension in selection["dimensions"]
        for selector in (dimension["include"], dimension["exclude"])
        if selector is not None and selector["kind"] == "member_list"}
    member_lists = {}
    for list_id in sorted(references):
        row = db.execute("""SELECT * FROM
            epm.member_list_definition WHERE workspace_id=%s AND application_id=%s
            AND list_id=%s AND status='Published'""", (scope.workspace_id,
            scope.application_id, list_id)).fetchone()
        if row is None:
            raise ValueError("CUBE_SELECTION_MEMBER_LIST_UNPUBLISHED")
        from .postgres_python_definitions import assert_source_active
        assert_source_active(db, scope, row)
        member_lists[list_id] = {"definition":row["definition"],
                                 "stateToken":row["state_token"]}
    return member_lists


def selection_semantic_references_in_transaction(db, scope, selection):
    """Resolve compiler references through current native metadata, not members returned.

    The caller owns scope/authority and the same transaction as activation.
    This structural read never exposes descriptors to a public read response.
    """
    from .selection_resolver import selection_semantic_references
    from .postgres_hierarchies import resolve_hierarchy_reference
    from .postgres_member_attributes import load_member_attribute_snapshot
    canonical = canonical_selection(selection)
    references = selection_semantic_references(canonical,
        member_lists=load_current_member_lists(db, scope, canonical))
    dimensions = sorted({item[0] for item in references})
    known_dimensions = db.execute("""SELECT dimension_id FROM epm.dimension
        WHERE workspace_id=%s AND application_id=%s AND dimension_id=ANY(%s::text[])
          AND status='Active'""", (scope.workspace_id, scope.application_id, dimensions)).fetchall()
    if {row['dimension_id'] for row in known_dimensions} != set(dimensions):
        raise ValueError('CUBE_SELECTION_DIMENSION_UNAVAILABLE')
    attribute_dimensions = sorted({dimension for dimension, kind, _ in references if kind == 'attribute'})
    attributes = (load_member_attribute_snapshot(db, scope, attribute_dimensions, [])
                  if attribute_dimensions else None)
    resolved = set()
    for dimension, kind, identity in references:
        if kind == 'hierarchy':
            hierarchy, default = resolve_hierarchy_reference(db, scope, dimension, identity, allow_alias=True)
            resolved.add((dimension, kind, hierarchy['hierarchy_id']))
            if default:
                # An exact ID can later shadow the admitted fallback alias.
                resolved.add((dimension, kind, identity))
                resolved.add((dimension, 'hierarchy-default', dimension))
        elif kind == 'attribute':
            descriptor = attributes.definitions[dimension].get(identity)
            if descriptor is None:
                raise ValueError('MEMBER_LIST_ATTRIBUTE_UNAVAILABLE')
            resolved.add((dimension, kind, descriptor['attributeId']))
        else:
            resolved.add((dimension, kind, identity))
    for dimension in dimensions:
        members = sorted(identity for axis, kind, identity in references
                         if axis == dimension and kind == 'member')
        if members:
            known = db.execute("""SELECT member_id FROM epm.member WHERE workspace_id=%s
                AND application_id=%s AND dimension_id=%s AND member_id=ANY(%s::text[])
                AND status='Active'""", (scope.workspace_id, scope.application_id, dimension, members)).fetchall()
            if {row['member_id'] for row in known} != set(members):
                raise ValueError('MEMBER_LIST_MEMBER_UNAVAILABLE')
    return tuple(sorted(resolved))


def resolve_selection_in_transaction(db, scope: ApplicationScope,
                                     selection: object,
                                     metadata_revision: int, *, authority=None) -> dict:
    """Resolve one canonical selection inside the caller's pinned transaction.

    The caller owns authorization, scope setup and locking.  Keeping this
    storage adapter shared prevents workflow persistence from implementing a
    weaker member-list or metadata interpretation than the public preview.
    """
    layout = db.execute("""SELECT l.dimensions
        FROM epm.application_state s JOIN epm.coordinate_layout l
          USING(workspace_id,application_id,schema_epoch)
        WHERE s.workspace_id=%s AND s.application_id=%s""", (
        scope.workspace_id, scope.application_id)).fetchone()
    if layout is None:
        raise ValueError("COORDINATE_LAYOUT_UNAVAILABLE")
    dimensions = list(layout["dimensions"])
    canonical = canonical_selection(selection, active_dimensions=dimensions)
    member_lists = load_current_member_lists(db, scope, canonical)
    members = {dimension: {} for dimension in dimensions}
    attributes = {dimension: {} for dimension in dimensions}
    attribute_types = {dimension: {} for dimension in dimensions}
    graphs = {dimension: {} for dimension in dimensions}
    budget = SelectionReadBudget(max_members=MAX_RESOLVED_MEMBERS,
                                 max_edges=MAX_RESOLVED_MEMBERS)
    for dimension in canonical["dimensions"]:
        key = dimension["dimensionId"]
        for selector in (dimension["include"], dimension["exclude"]):
            if selector is None:
                continue
            definition, parameters, _ = selector_definition(key, selector, member_lists)
            context = load_selection_context(db, scope, authority, definition,
                parameters=parameters, budget=budget)
            members[key].update(context["members"])
            attributes[key].update(context["attributes"].values[key])
            attribute_types[key].update(context["attributes"].types[key])
            for graph_key, graph in context["hierarchyGraphs"].items():
                merged = graphs[key].setdefault(graph_key, {
                    "hierarchyId": graph["hierarchyId"], "members": set(), "relationships": {}})
                merged["members"].update(graph["members"])
                merged["relationships"].update({edge["relationshipId"]: edge
                                               for edge in graph["relationships"]})
    graphs = {dimension: {key: {"hierarchyId": graph["hierarchyId"],
        "members": sorted(graph["members"]),
        "relationships": list(graph["relationships"].values())}
        for key, graph in values.items()} for dimension, values in graphs.items()}
    # Every graph expression names its hierarchy. No default whole-app graph is
    # needed for direct member and typed attribute selectors.
    relationships = {dimension: [] for dimension in dimensions}
    placement_relationships = {dimension: [] for dimension in dimensions}
    return resolve_selection(canonical, metadata_revision=metadata_revision,
        active_dimensions=dimensions, members=members,
        relationships=relationships, attributes=attributes,
        placement_relationships=placement_relationships,
        attribute_types=attribute_types, member_lists=member_lists, hierarchy_graphs=graphs)


class PostgresSelectionPreview:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn, "epm_runtime",
            ("dimension", "member", "relationship", "semantic_column",
             "attribute_definition",
             "member_list_definition"))
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
                    commit_revision,security_revision,schema_epoch FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if state["policy_revision"] != args["expectedPolicyRevision"]:
                    raise ValueError("STALE_POLICY_REVISION")
                authority = resolve_effective_dimensional_scope(
                    db, self.identity, scope, function=PREVIEW)
                resolved = resolve_selection_in_transaction(
                    db, scope, args["selection"], state["metadata_revision"], authority=authority)
                final_authority = resolve_effective_dimensional_scope(
                    db, self.identity, scope, function=PREVIEW)
                end = db.execute("""SELECT metadata_revision,policy_revision,security_revision,schema_epoch
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""", (scope.workspace_id,
                    scope.application_id)).fetchone()
                if (end is None or end["metadata_revision"] != state["metadata_revision"]
                        or end["policy_revision"] != state["policy_revision"]
                        or end["security_revision"] != state["security_revision"]
                        or end["schema_epoch"] != state["schema_epoch"]
                        or final_authority.scope_digest != authority.scope_digest):
                    raise ValueError("CUBE_SELECTION_STATE_CHANGED_DURING_PREVIEW")
                return {**resolved, "policyRevision": state["policy_revision"],
                        "commitRevision": state["commit_revision"]}
