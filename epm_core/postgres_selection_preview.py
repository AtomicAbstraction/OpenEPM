"""Authorized, revision-pinned preview of generic cube selections."""

from __future__ import annotations

from psycopg import sql
from psycopg.rows import dict_row

from .member_list_evaluator import MAX_EVALUATED_PLACEMENTS, MAX_PLACEMENT_DEPTH
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_member_selection import load_selection_context, SelectionReadBudget
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout
from .selection_contract import (
    FORMAT as SELECTION_FORMAT, INLINE_EXPRESSION_FORMAT, MAX_DIMENSIONS,
    SELECTION_METADATA_STALE, canonical_selection,
    selection_identifier_schema, selection_parameters_schema, structural_schema_definitions)
from .selection_resolver import (
    MAX_RESOLVED_MEMBERS, RESOLVED_FORMAT, resolve_selection, selector_definition)


PREVIEW = "cube.selection.preview"


def resolved_selection_schema(*, retained=False) -> dict:
    from .metadata_read_contract import obj

    revision = {"type": "integer", "minimum": 0}
    dimension_id = selection_identifier_schema()
    stable_id = {"type": "string", "minLength": 1}
    token = {"type": "string", "pattern": r"^[0-9a-f]{64}(?![\s\S])"}
    placement = obj({"memberId": stable_id, "pathRelationshipIds": {
        "type": "array", "maxItems": MAX_PLACEMENT_DEPTH, "items": stable_id}})
    pin = obj({"listId": dimension_id, "stateToken": token, "canonicalDigest": token,
        "parameters": selection_parameters_schema()})

    def dimension_arrays(item, limit, *, unique=False):
        return {"type": "object", "minProperties": 1, "maxProperties": MAX_DIMENSIONS,
            "propertyNames": dimension_id, "additionalProperties": {
                "type": "array", "maxItems": limit, "items": item, "uniqueItems": unique}}

    fields = {"format": {"const": RESOLVED_FORMAT},
        "metadataRevision": {**revision, "minimum": 1}, "policyRevision": revision,
        "schemaEpoch": revision, "securityRevision": revision, "commitRevision": revision,
        "members": dimension_arrays(stable_id, MAX_RESOLVED_MEMBERS, unique=True),
        "placements": dimension_arrays(placement, MAX_EVALUATED_PLACEMENTS),
        "placementUnavailableDimensions": {"type": "array", "minItems": 1,
            "maxItems": MAX_DIMENSIONS, "uniqueItems": True, "items": dimension_id},
        "memberListPins": {"type": "array", "maxItems": 2 * MAX_DIMENSIONS, "items": pin},
        "resolutionDigest": token}
    optional = {"placementUnavailableDimensions"}
    if retained:
        # Earlier sealed results omit these observations. Replay returns the
        # original bytes instead of assigning them modern revision values.
        optional.update(("schemaEpoch", "securityRevision"))
    return obj(fields, [name for name in fields if name not in optional])


def read_program_contract() -> dict:
    from .metadata_read_contract import obj, read_contract, read_example

    arguments = obj({"selection": {"$ref": "#/$defs/cubeSelection"},
                     "expectedPolicyRevision": {"type": "integer", "minimum": 0}})

    def example(include, exclude, *, name, binding):
        return read_example(PREVIEW, {"expectedPolicyRevision": 1, "selection": {
            "format": SELECTION_FORMAT, "metadataRevision": 1, "dimensions": [{
                "dimensionId": "custom-axis", "include": include, "exclude": exclude}]}},
            name=name, binding="Use current metadata and policy revisions from application.state.read. "
                "Use the full authorized grain described by metadata.authoring.context when available. " + binding)

    examples = [
        example({"kind": "member", "memberId": "member-a"}, None,
            name="Preview a complete exact coordinate",
            binding="Use member and axis IDs from authorized application metadata."),
        example({"kind": "member_list", "listId": "current-business-list", "parameters": {}},
            {"kind": "member", "memberId": "member-b"},
            name="Preview a reusable business selection with an exclusion",
            binding="Bind a current executable Member List on the chosen axis. Supply its declared parameters."),
        example({"kind": "inline_expression", "expressionFormat": INLINE_EXPRESSION_FORMAT,
            "expression": {"kind": "navigation", "operation": "leaf_descendants",
                "scope": "hierarchy", "hierarchyId": "main", "anchor": {
                    "memberId": "parent", "pathRelationshipIds": None}, "includeSelf": False,
                "allParents": False}}, None,
            name="Preview strict leaf descendants without a saved Member List",
            binding="Bind the current hierarchy and anchor. Use an exact relationship path where needed."),
    ]
    result_contract = read_contract(PREVIEW, arguments, resolved_selection_schema(), owner="PostgresSelectionPreview.read",
        examples=examples, definitions=structural_schema_definitions(), semantic_rules=[
            "This read evaluates all active fact axes at the current authorized metadata, policy, security and schema revisions. It produces a complete result within the fixed bounds or refuses the request.",
            "A dimension with an empty member array stays empty. An unavailable or denied scope returns an error.",
            "Inline selectors compare and order current authorized attribute values. Unreadable MemberReference values are absent. A named selector also requires current READ on the typed references in its definition.",
            "Placements preserve certified relationship paths. An empty path belongs to a direct member. Dimensions listed in placementUnavailableDimensions have member results without contribution paths.",
            "Member List pins identify the inputs used in resolution. The resolution digest describes this result and conveys no authority to perform an effect.",
        ])
    result_contract["resultSchema"].pop("$defs")
    result_contract["programContract"]["recovery"] = (
        "For stale metadata or policy, or a changed preview state, refresh application.state.read and review the "
        "complete selection under current authority before asking for another preview. On unavailable scope, "
        "rediscover only currently authorized references.")
    return result_contract


def catalog() -> dict:
    return {PREVIEW: {
        "mode": "read", "permission": "read", "workClass": "short",
        "previewRequired": False, "idempotencyRequired": False,
        "arguments": {
            "selection": "complete-grain openepm-cube-selection-v1",
            "expectedPolicyRevision": "current authorization policy revision",
        },
        "result": "resolved authorized member IDs, reusable-list pins and resolution digest; requested scopes bounded to 100000 members/edges",
        **read_program_contract(),
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


def load_current_member_lists(db, scope, selection, *, authority=None):
    """Load current reusable definitions under the caller's selection authority."""
    from .postgres_member_lists import member_list_definition_visible_sql
    from .postgres_python_definitions import assert_source_active

    references = {selector["listId"]
        for dimension in selection["dimensions"]
        for selector in (dimension["include"], dimension["exclude"])
        if selector is not None and selector["kind"] == "member_list"}
    member_lists = {}
    for list_id in sorted(references):
        row = db.execute(sql.SQL("""SELECT d.* FROM
            epm.member_list_definition d WHERE workspace_id=%s AND application_id=%s
            AND list_id=%s AND status='Published' AND {}""").format(
                member_list_definition_visible_sql(authority)), (scope.workspace_id,
            scope.application_id, list_id)).fetchone()
        if row is None:
            if authority is not None and authority.policy is not None:
                raise AccessDenied('METADATA_SELECTION_SCOPE_UNAVAILABLE')
            raise ValueError("CUBE_SELECTION_MEMBER_LIST_UNPUBLISHED")
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
                                     metadata_revision: int, *, authority=None,
                                     require_current_layout: bool = False) -> dict:
    """Resolve one canonical selection inside the caller's pinned transaction.

    The caller owns authorization, scope setup and locking.  Keeping this
    storage adapter shared prevents workflow persistence from implementing a
    weaker member-list or metadata interpretation than the public preview.
    """
    layout = db.execute("""SELECT l.dimensions,s.metadata_revision
        FROM epm.application_state s JOIN epm.coordinate_layout l
          USING(workspace_id,application_id,schema_epoch)
        WHERE s.workspace_id=%s AND s.application_id=%s""", (
        scope.workspace_id, scope.application_id)).fetchone()
    if layout is None:
        raise ValueError("COORDINATE_LAYOUT_UNAVAILABLE")
    if require_current_layout and layout["metadata_revision"] != metadata_revision:
        raise ValueError(SELECTION_METADATA_STALE)
    dimensions = list(layout["dimensions"])
    canonical = canonical_selection(selection, active_dimensions=dimensions,
        expected_metadata_revision=metadata_revision)
    member_lists = load_current_member_lists(db, scope, canonical, authority=authority)
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
        result, _ = self.read_with_authority(scope, raw)
        return result

    def read_with_authority(self, scope: ApplicationScope, raw: dict) -> tuple[dict, str]:
        """Return the preview and its internal authorization binding to the seal owner."""
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
                result = {**resolved, "policyRevision": state["policy_revision"],
                        "schemaEpoch": state["schema_epoch"], "securityRevision": state["security_revision"],
                        "commitRevision": state["commit_revision"]}
                return result, authority.scope_digest
