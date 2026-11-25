"""Native authorized member selection; no stored source or business artifact.

This storage adapter feeds the same selection evaluator used by rules. Graph
loading follows the requested roots, rather than materializing an application.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time

from psycopg import sql
from psycopg.rows import dict_row

from .current_object_contract import require_state_token
from .dimensional_security_policy import ResolvedMemberSecurity
from .member_list_contract import (
    NAVIGATION_OPERATIONS, canonical_member_list_definition, iter_member_list_nodes as _nodes,
)
from .member_list_evaluator import (
    MAX_EVALUATED_PLACEMENTS, evaluate_member_list, evaluate_member_list_placements,
    navigation_graph_key, resolve_member_list_parameters,
)
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import (
    metadata_reference_read_allowed, metadata_visible_attributes_sql, resolve_effective_dimensional_scope,
)
from .postgres_hierarchies import resolve_hierarchy
from .postgres_member_attributes import load_member_attribute_snapshot
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout

SELECT = "metadata.member.select"
MAX_MEMBERS = 5000
MAX_EDGES = 10000
CURSOR_TTL = 900
_HIERARCHY = {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}
_CONTEXT_PINS = {"expectedMetadataRevision": "metadata_revision",
                 "expectedPolicyRevision": "policy_revision",
                 "expectedSecurityRevision": "security_revision",
                 "expectedSchemaEpoch": "schema_epoch"}



class SelectionReadBudget:
    """One request's authorized metadata budget, shared by every selector."""

    def __init__(self, *, max_members=MAX_MEMBERS, max_edges=MAX_EDGES):
        if (type(max_members) is not int or max_members < 1
                or type(max_edges) is not int or max_edges < 1):
            raise ValueError("METADATA_SELECTION_BUDGET_INVALID")
        self.max_members, self.max_edges = max_members, max_edges
        self.members, self.edges = set(), set()
        self.graph_cache, self.context_cache = {}, {}
        self._binding = None

    def bind(self, db, scope, authority):
        binding = (id(db), scope.workspace_id, scope.application_id,
                   authority.scope_digest if authority is not None else None)
        if self._binding is not None and self._binding != binding:
            raise ValueError("METADATA_SELECTION_BUDGET_SCOPE_CHANGED")
        self._binding = binding

    def include_graph(self, dimension, graph):
        edges = {(dimension, graph["hierarchyId"], row["relationshipId"])
                 for row in graph["relationships"]}
        combined = self.edges | edges
        if len(combined) > self.max_edges:
            raise ValueError("METADATA_SELECTION_EDGE_BUDGET")
        self.edges = combined

    def include_members(self, dimension, rows):
        combined = self.members | {(dimension, row["member_id"]) for row in rows}
        if len(combined) > self.max_members:
            raise ValueError("METADATA_SELECTION_MEMBER_BUDGET")
        self.members = combined


def catalog():
    return {SELECT: {"mode": "read", "permission": "read",
        "arguments": {"dimensionId": "active stable dimension ID",
            "expression": "native member selection expression; no saved program"},
        "optionalArguments": {"limit": "optional 1-500, default 100",
            "resultMode": "unique_member (default) or placements for a native navigation expression",
            **dict.fromkeys(_CONTEXT_PINS, "current application revision observed before starting this read"),
            "selectionContext": "empty object to open a context, or expectedToken from an earlier authorized read",
            "cursor": "signed sole continuation argument; current state and authority bound"},
        "argumentForms": ["dimensionId + expression + optional limit/resultMode", "cursor only"],
        "navigationOperations": list(NAVIGATION_OPERATIONS),
        "result": "current member objects, typed attributes, and bounded continuation; native navigation also returns a typed scope and result kind; no persistent effects",
        "previewRequired": False, "idempotencyRequired": False, "workClass": "bounded_read"}}


def _canonical(dimension, expression):
    # The definition is only the existing evaluator's in-memory input envelope.
    # No source, member list, build or definition is written by this operation.
    return canonical_member_list_definition({"format": "openepm-member-list-v1",
        "listId": "native-query", "dimensionId": dimension, "name": "Native query",
        "parameters": [], "expression": expression})


def authorize_hierarchy_selection(db, scope, authority, dimension, selector, *, budget):
    """Authorize the named root and every traversed edge and endpoint for a cube selector."""
    budget.bind(db, scope, authority)
    _dimension_scope_row(db, scope, dimension, authority)
    hierarchy = resolve_hierarchy(db, scope, dimension, selector.get("hierarchyId"))
    node = {"kind": selector["kind"].lower(),
        "hierarchyId": hierarchy["hierarchy_id"], "memberId": selector["rootMemberId"],
        "includeSelf": selector["includeSelf"]}
    graph, _ = _load_graph(db, scope, dimension, node, authority, max_edges=budget.max_edges)
    budget.include_graph(dimension, graph)
    budget.include_members(dimension, ({"member_id": member} for member in graph["members"]))


def _state(db, scope):
    row = db.execute("""SELECT metadata_revision,policy_revision,
        security_revision,schema_epoch FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise ValueError("APPLICATION_UNAVAILABLE")
    return dict(row)


def _authorize_rows(authority, dimension, rows):
    if authority is None or authority.policy is None:
        return
    for row in rows:
        reference = ResolvedMemberSecurity(dimension,
            row.get("member_id", row.get("relationship_id", dimension)),
            tuple(row["read_security_tags"]), tuple(row["write_security_tags"]))
        if not metadata_reference_read_allowed(authority, reference):
            # Do not expose which hidden node/edge, its name, count or tags.
            raise AccessDenied("METADATA_SELECTION_SCOPE_UNAVAILABLE")


_ELIGIBLE_EDGES = """SELECT r.relationship_id,r.parent_member_id,r.child_member_id,
        r.read_security_tags,r.write_security_tags FROM epm.relationship r
        JOIN epm.member p ON p.workspace_id=r.workspace_id AND p.application_id=r.application_id
          AND p.dimension_id=r.dimension_id AND p.member_id=r.parent_member_id AND p.status='Active'
        JOIN epm.member c ON c.workspace_id=r.workspace_id AND c.application_id=r.application_id
          AND c.dimension_id=r.dimension_id AND c.member_id=r.child_member_id AND c.status='Active'
        WHERE r.workspace_id=%s AND r.application_id=%s AND r.dimension_id=%s
          AND r.hierarchy_id=%s AND r.status='Active'
          AND (%s='all_active' OR (EXISTS(SELECT 1 FROM epm.hierarchy_member h
            WHERE h.workspace_id=r.workspace_id AND h.application_id=r.application_id
              AND h.dimension_id=r.dimension_id AND h.hierarchy_id=r.hierarchy_id
              AND h.member_id=r.parent_member_id AND h.status='Active')
            AND EXISTS(SELECT 1 FROM epm.hierarchy_member h
            WHERE h.workspace_id=r.workspace_id AND h.application_id=r.application_id
              AND h.dimension_id=r.dimension_id AND h.hierarchy_id=r.hierarchy_id
              AND h.member_id=r.child_member_id AND h.status='Active')))"""


def _load_graph(db, scope, dimension, node, authority, *, max_edges=MAX_EDGES):
    hierarchy = resolve_hierarchy(db, scope, dimension, node["hierarchyId"], allow_alias=True)
    keys = (scope.workspace_id, scope.application_id, dimension)
    root = node["memberId"]
    included = db.execute("""SELECT m.member_id FROM epm.member m
        WHERE m.workspace_id=%s AND m.application_id=%s AND m.dimension_id=%s
          AND m.member_id=%s AND m.status='Active'
          AND (%s='all_active' OR EXISTS(SELECT 1 FROM epm.hierarchy_member h
            WHERE h.workspace_id=m.workspace_id AND h.application_id=m.application_id
              AND h.dimension_id=m.dimension_id AND h.member_id=m.member_id
              AND h.hierarchy_id=%s AND h.status='Active'))""",
        (*keys, root, hierarchy["membership_mode"], hierarchy["hierarchy_id"])).fetchone()
    if included is None:
        if node["kind"] == "base":
            return {"hierarchyId": hierarchy["hierarchy_id"], "members": [], "relationships": []}, []
        raise ValueError("MEMBER_LIST_HIERARCHY_MEMBER_UNAVAILABLE")
    # Only fixed fragments select traversal direction. Caller values remain bound.
    eligible = _ELIGIBLE_EDGES
    kind = node["kind"]
    args = (*keys, hierarchy["hierarchy_id"], hierarchy["membership_mode"])
    if kind == "self":
        query = f"SELECT * FROM ({eligible}) AS edges WHERE FALSE LIMIT %s"
        args += (max_edges + 1,)
    elif kind in {"children", "base", "parents"}:
        field = "child_member_id" if kind == "parents" else "parent_member_id"
        query = f"WITH edges AS NOT MATERIALIZED ({eligible}) SELECT * FROM edges WHERE {field}=%s ORDER BY relationship_id LIMIT %s"
        args += (root, max_edges + 1)
    elif kind == "siblings":
        query = f"""WITH edges AS NOT MATERIALIZED ({eligible}) SELECT * FROM edges
            WHERE parent_member_id IN (SELECT parent_member_id FROM edges WHERE child_member_id=%s)
            ORDER BY relationship_id LIMIT %s"""
        args += (root, max_edges + 1)
    else:
        origin, target = ("child_member_id", "parent_member_id") if kind == "ancestors" else ("parent_member_id", "child_member_id")
        query = f"""WITH RECURSIVE edges AS NOT MATERIALIZED ({eligible}),
            reach(member_id) AS (SELECT %s::text UNION
              SELECT e.{target} FROM edges e JOIN reach n ON e.{origin}=n.member_id)
            SELECT e.* FROM edges e JOIN reach n ON e.{origin}=n.member_id
            ORDER BY e.relationship_id LIMIT %s"""
        args += (root, max_edges + 1)
    rows = [dict(row) for row in db.execute(query, args).fetchall()]
    _authorize_rows(authority, dimension, rows)
    endpoints = sorted({root} | {row[field] for row in rows
        for field in ("parent_member_id", "child_member_id")})
    visibility = db.execute("""SELECT member_id,read_security_tags,write_security_tags
        FROM epm.member WHERE workspace_id=%s AND application_id=%s
          AND dimension_id=%s AND status='Active' AND member_id=ANY(%s::text[])""",
        (*keys, endpoints)).fetchall()
    _authorize_rows(authority, dimension, visibility)
    if {row["member_id"] for row in visibility} != set(endpoints):
        raise AccessDenied("METADATA_SELECTION_SCOPE_UNAVAILABLE")
    if len(rows) > max_edges:
        raise ValueError("METADATA_SELECTION_EDGE_BUDGET")
    members = {root}
    relationships = []
    for row in rows:
        members.update((row["parent_member_id"], row["child_member_id"]))
        relationships.append({"relationshipId": row["relationship_id"],
            "parentMemberId": row["parent_member_id"], "childMemberId": row["child_member_id"]})
    return {"hierarchyId": hierarchy["hierarchy_id"], "members": sorted(members),
            "relationships": relationships}, rows


def _load_navigation_graph(db, scope, dimension, hierarchy, authority, budget):
    """Load one bounded operative hierarchy, including isolated active members."""
    hierarchy_id = hierarchy["hierarchy_id"]
    key = (dimension, "navigation", hierarchy_id)
    if key in budget.graph_cache:
        return budget.graph_cache[key]
    keys = (scope.workspace_id, scope.application_id, dimension)
    member_rows = db.execute("""SELECT m.member_id,m.read_security_tags,m.write_security_tags
        FROM epm.member m
        WHERE m.workspace_id=%s AND m.application_id=%s AND m.dimension_id=%s
          AND m.status='Active'
          AND (%s='all_active' OR EXISTS(SELECT 1 FROM epm.hierarchy_member h
            WHERE h.workspace_id=m.workspace_id AND h.application_id=m.application_id
              AND h.dimension_id=m.dimension_id AND h.member_id=m.member_id
              AND h.hierarchy_id=%s AND h.status='Active'))
        ORDER BY m.member_id LIMIT %s""",
        (*keys, hierarchy["membership_mode"], hierarchy_id, budget.max_members + 1)).fetchall()
    _authorize_rows(authority, dimension, member_rows)
    budget.include_members(dimension, member_rows)
    edge_rows = db.execute(_ELIGIBLE_EDGES + " ORDER BY relationship_id LIMIT %s",
        (*keys, hierarchy_id, hierarchy["membership_mode"], budget.max_edges + 1)).fetchall()
    _authorize_rows(authority, dimension, edge_rows)
    graph = {"hierarchyId": hierarchy_id,
        "members": [row["member_id"] for row in member_rows],
        "relationships": [{"relationshipId": row["relationship_id"],
            "parentMemberId": row["parent_member_id"], "childMemberId": row["child_member_id"]}
            for row in edge_rows]}
    budget.include_graph(dimension, graph)
    budget.graph_cache[key] = graph
    return graph


def _load_navigation_subgraph(db, scope, dimension, node, authority, budget, hierarchy):
    """Read only the relevant anchored graph and any explicit context path."""
    anchor = node["anchor"]
    path = anchor["pathRelationshipIds"]
    operation = node["operation"]
    kind = ("leaves" if operation == "leaf_descendants" else
            "children" if operation == "is_base" else
            "self" if path is not None and operation in {"parents", "ancestors"} else operation)
    hierarchy_id = hierarchy["hierarchy_id"]
    member_id = anchor["memberId"]
    graph, _ = _load_graph(db, scope, dimension, {
        "memberId": member_id, "hierarchyId": hierarchy_id, "kind": kind,
    }, authority, max_edges=budget.max_edges)
    if path is None:
        return graph

    path_edges = {}
    if path:
        keys = (scope.workspace_id, scope.application_id, dimension)
        rows = db.execute(f"SELECT * FROM ({_ELIGIBLE_EDGES}) AS edges WHERE relationship_id=ANY(%s)",
            (*keys, hierarchy_id, hierarchy["membership_mode"], path)).fetchall()
        _authorize_rows(authority, dimension, rows)
        path_edges = {row["relationship_id"]: row for row in rows}
        if set(path_edges) != set(path):
            raise ValueError("MEMBER_LIST_NAVIGATION_PATH_STALE")
    root = path_edges[path[0]]["parent_member_id"] if path else member_id
    # Root status cannot be inferred from the anchored subgraph, or from
    # filtered/visible edges. Read the real incoming edges before accepting it.
    _, incoming = _load_graph(db, scope, dimension, {
        "memberId": root, "hierarchyId": hierarchy_id, "kind": "parents",
    }, authority, max_edges=budget.max_edges)
    if incoming:
        raise ValueError("MEMBER_LIST_NAVIGATION_PATH_STALE")
    members = set(graph["members"])
    edges = {edge["relationshipId"]: edge for edge in graph["relationships"]}
    for key, row in path_edges.items():
        parent, child = row["parent_member_id"], row["child_member_id"]
        members.update((parent, child))
        edges[key] = {"relationshipId": key, "parentMemberId": parent, "childMemberId": child}
    graph["members"] = sorted(members)
    graph["relationships"] = list(edges.values())
    return graph


def _dimension_scope_row(db, scope, dimension, authority):
    row = db.execute("""SELECT dimension_id,name,short_description,detailed_description,
        read_security_tags,write_security_tags
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
          AND dimension_id=%s AND status='Active'""",
        (scope.workspace_id, scope.application_id, dimension)).fetchone()
    if row is None:
        raise AccessDenied("METADATA_SELECTION_SCOPE_UNAVAILABLE")
    _authorize_rows(authority, dimension, [row])
    return row


def _finite_bound(node, selectors, parameters):
    kind = node["kind"]
    if kind == "explicit":
        return set(node["memberIds"])
    if kind == "parameter":
        return {parameters[node["name"]]} if node["name"] in parameters else set()
    if kind in _HIERARCHY or kind == "navigation" and node["scope"] == "hierarchy":
        return selectors[json.dumps(node, sort_keys=True)]
    if kind == "order" or kind == "difference":
        return _finite_bound(node["source"], selectors, parameters)
    if kind in {"union", "intersection"}:
        values = [_finite_bound(child, selectors, parameters) for child in node["items"]]
        if kind == "union":
            return None if any(value is None for value in values) else set().union(*values)
        finite = [value for value in values if value is not None]
        return None if not finite else set.intersection(*finite)
    return None


def load_selection_context(db, scope, authority, definition, *, parameters=None, budget=None,
                           browsing=False):
    """Load the complete relevant scope for the shared pure evaluators.

    Public reads pass current dimensional authority. Trusted structural callers
    may pass None while enforcing coordinate authority at their existing effect
    boundary; they must never return this metadata directly to a client.
    """
    definition = canonical_member_list_definition(definition)
    budget = budget if budget is not None else SelectionReadBudget()
    budget.bind(db, scope, authority)
    declarations, supplied = resolve_member_list_parameters(definition, parameters)
    for node in _nodes(definition["expression"]):
        if node["kind"] == "parameter" and declarations[node["name"]]["type"] != "Member":
            raise ValueError("MEMBER_LIST_PARAMETER_NOT_MEMBER")
    dimension = definition["dimensionId"]
    cache_key = json.dumps([dimension, definition["expression"], definition["parameters"], supplied, browsing],
                           sort_keys=True, separators=(",", ":"))
    if cache_key in budget.context_cache:
        return budget.context_cache[cache_key]
    keys = (scope.workspace_id, scope.application_id, dimension)
    _dimension_scope_row(db, scope, dimension, authority)
    graphs, selectors = {}, {}
    required = {supplied[name] for name, declaration in declarations.items()
                if declaration["type"] == "Member" and name in supplied}
    for node in _nodes(definition["expression"]):
        if node["kind"] == "explicit":
            required.update(node["memberIds"])
        elif node["kind"] in _HIERARCHY:
            required.add(node["memberId"])
        elif node["kind"] == "navigation" and node["anchor"] is not None:
            required.add(node["anchor"]["memberId"])
    if required:
        roots = db.execute("""SELECT member_id,read_security_tags,write_security_tags
            FROM epm.member WHERE workspace_id=%s AND application_id=%s
              AND dimension_id=%s AND status='Active' AND member_id=ANY(%s::text[])""",
            (*keys, sorted(required))).fetchall()
        _authorize_rows(authority, dimension, roots)
        if {row["member_id"] for row in roots} != required:
            raise AccessDenied("METADATA_SELECTION_SCOPE_UNAVAILABLE")
    for node in _nodes(definition["expression"]):
        if node["kind"] == "explicit":
            required.update(node["memberIds"])
        elif node["kind"] in _HIERARCHY or node["kind"] == "navigation":
            if node["kind"] == "navigation":
                if node["operation"] == "top":
                    raise ValueError("MEMBER_LIST_SCOPE_TOP_NOT_COORDINATE")
                if node["hierarchyId"] is None:
                    continue
                hierarchy = resolve_hierarchy(db, scope, dimension, node["hierarchyId"], allow_alias=True)
                context_key = navigation_graph_key(node)
                if (not browsing and node["anchor"] is not None and node["operation"] in {
                        "self", "is_base", "children", "descendants", "leaf_descendants", "parents", "ancestors"}):
                    graph_key = (dimension, context_key)
                    if graph_key not in budget.graph_cache:
                        graph = _load_navigation_subgraph(db, scope, dimension, node, authority,
                                                          budget, hierarchy)
                        budget.include_graph(dimension, graph)
                        budget.graph_cache[graph_key] = graph
                    graph = budget.graph_cache[graph_key]
                else:
                    graph = _load_navigation_graph(db, scope, dimension, hierarchy, authority, budget)
            else:
                context_key = node["hierarchyId"]
                graph_key = (dimension, json.dumps(node, sort_keys=True))
                if graph_key not in budget.graph_cache:
                    graph, _ = _load_graph(db, scope, dimension, node, authority,
                                          max_edges=budget.max_edges)
                    # Graph loader has authorized every inspected edge and endpoint.
                    budget.include_graph(dimension, graph)
                    budget.graph_cache[graph_key] = graph
                graph = budget.graph_cache[graph_key]
                required.add(node["memberId"])
            required.update(graph["members"])
            # Evaluate the selector in its complete relevant subgraph; merge
            # contexts afterward so sibling/ancestor navigation stays exact.
            if node["kind"] != "navigation" or node["scope"] == "hierarchy":
                names = {member: member for member in required}
                selectors[json.dumps(node, sort_keys=True)] = set(evaluate_member_list(
                    _canonical(dimension, node), members=names, relationships=[],
                    attributes={}, attribute_types={}, hierarchy_graphs={context_key: graph}))
            merged = graphs.setdefault(context_key, {"hierarchyId": graph["hierarchyId"],
                "members": set(), "relationships": {}})
            merged["members"].update(graph["members"])
            merged["relationships"].update({edge["relationshipId"]: edge for edge in graph["relationships"]})
    bound = _finite_bound(definition["expression"], selectors, supplied)
    if bound is not None:
        required.update(bound)
    rows = [dict(row) for row in db.execute(sql.SQL("""SELECT dimension_id,member_id,name,status,
        short_description,detailed_description,{} AS custom_values,read_security_tags,write_security_tags
        FROM epm.member m WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
          AND status='Active' AND (%s::boolean OR member_id=ANY(%s::text[]))
        ORDER BY member_id LIMIT %s""").format(metadata_visible_attributes_sql(authority, 'Member')),
        (*keys, bound is None, sorted(required), budget.max_members + 1)).fetchall()]
    _authorize_rows(authority, dimension, rows)
    budget.include_members(dimension, rows)
    members = {row["member_id"]: row["name"] for row in rows}
    if not required <= set(members):
        raise ValueError("MEMBER_LIST_MEMBER_UNAVAILABLE")
    graph_values = {key: {**value, "members": sorted(value["members"]),
        "relationships": list(value["relationships"].values())} for key, value in graphs.items()}
    attributes = load_member_attribute_snapshot(db, scope, (dimension,), rows)
    context = {"rows": rows, "members": members, "attributes": attributes,
               "hierarchyGraphs": graph_values}
    budget.context_cache[cache_key] = context
    return context


def _evaluate_in_transaction(db,scope,authority,definition,parameters=None):
    """One evaluator/authorization context for one-off and named selections."""
    context=load_selection_context(db,scope,authority,definition,
                                   parameters=parameters)
    dimension=definition["dimensionId"]
    attributes=context["attributes"]
    selected=evaluate_member_list(definition,members=context["members"],
        relationships=[],attributes=attributes.values[dimension],
        attribute_types=attributes.types[dimension],parameters=parameters,
        hierarchy_graphs=context["hierarchyGraphs"])
    return selected,context


def evaluate_member_ids_in_transaction(db,scope,authority,definition,
                                       parameters=None):
    """Return authorized stable IDs through the shared fixed-core evaluator."""
    selected,_=_evaluate_in_transaction(db,scope,authority,definition,parameters)
    return selected


def resolve_in_transaction(db, scope, authority, definition, *, placements=False):
    dimension = definition["dimensionId"]
    if placements:
        context = load_selection_context(db, scope, authority, definition, browsing=True)
        attributes = context["attributes"]
        selected = evaluate_member_list_placements(definition, members=context["members"],
            relationships=[], attributes=attributes.values[dimension],
            attribute_types=attributes.types[dimension], hierarchy_graphs=context["hierarchyGraphs"],
            browsing=True)
    else:
        selected, context = _evaluate_in_transaction(db, scope, authority, definition)
        selected = [{"memberId": key} for key in selected]
    rows, attributes = context["rows"], context["attributes"]
    by_id = {row["member_id"]: row for row in rows}
    return [{**result, "name": by_id[key]["name"], "status": by_id[key]["status"],
        "shortDescription": by_id[key]["short_description"],
        "semanticDescription": by_id[key]["detailed_description"],
        "attributes": {attribute: {"valueType": descriptor["valueType"],
            "present": attribute in (by_id[key]["custom_values"] or {}),
            "value": (by_id[key]["custom_values"] or {}).get(attribute)}
            for attribute, descriptor in attributes.definitions[dimension].items()
            if attribute == descriptor["attributeId"]}} for result in selected
        for key in (result["memberId"],)]


def _scope_descriptor(db, scope, dimension, authority, node):
    row = _dimension_scope_row(db, scope, dimension, authority)
    hierarchy_id = node["hierarchyId"]
    if hierarchy_id is not None:
        hierarchy_id = resolve_hierarchy(db, scope, dimension, hierarchy_id,
                                         allow_alias=True)["hierarchy_id"]
    operations = (list(NAVIGATION_OPERATIONS) if node["scope"] == "hierarchy"
                  else ["top", "all", "leaves", "unplaced"])
    return {"kind": "scope", "scope": node["scope"], "dimensionId": dimension,
        "hierarchyId": hierarchy_id, "name": row["name"],
        "shortDescription": row["short_description"],
        "semanticDescription": row["detailed_description"],
        "businessCoordinate": False, "supportedOperations": operations}


class PostgresMemberSelection:
    def __init__(self, dsn, *, identity, cursor_secret):
        if not isinstance(identity, VerifiedIdentity) or not isinstance(cursor_secret, bytes) or len(cursor_secret) < 32:
            raise ValueError("METADATA_SELECTION_TRUSTED_INPUT_REQUIRED")
        assert_nonowner_role(dsn, "epm_runtime", ("dimension", "member", "relationship", "attribute_definition"))
        self.dsn, self.identity, self.cursor_secret = dsn, identity, cursor_secret

    def _pack(self, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return base64.urlsafe_b64encode(raw + hmac.new(self.cursor_secret, raw, hashlib.sha256).digest()).decode()

    def _context_token(self, scope, state, authority):
        material = json.dumps({"format": "openepm-member-selection-context-v1",
            "scope": [scope.workspace_id, scope.application_id],
            "identity": [self.identity.issuer, self.identity.subject_id],
            "state": state, "authority": authority.scope_digest},
            sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        return hmac.new(self.cursor_secret, material, hashlib.sha256).hexdigest()

    def _unpack(self, token, scope):
        try:
            if not isinstance(token, str) or len(token) > 32768:
                raise ValueError()
            packed = base64.b64decode(token, altchars=b'-_', validate=True)
            raw, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(signature, hmac.new(self.cursor_secret, raw, hashlib.sha256).digest()):
                raise ValueError()
            value = json.loads(raw)
            if (set(value) != {"query", "offset", "state", "scope", "identity", "authority", "expires"}
                    or value["scope"] != [scope.workspace_id, scope.application_id]
                    or value["identity"] != [self.identity.issuer, self.identity.subject_id]
                    or type(value["offset"]) is not int or not 0 < value["offset"] <= (
                        MAX_EVALUATED_PLACEMENTS if value["query"].get("resultMode") == "placements" else MAX_MEMBERS)
                    or type(value["expires"]) is not int or value["expires"] <= time.time()):
                raise ValueError()
            return value
        except (ValueError, TypeError, KeyError, binascii.Error, UnicodeError) as error:
            raise ValueError("METADATA_SELECTION_CURSOR_INVALID") from error

    def read(self, scope, raw):
        if (type(raw) is not dict or set(raw) != {"languageVersion", "function", "arguments"}
                or type(raw["languageVersion"]) is not int or raw["languageVersion"] != 2
                or raw["function"] != SELECT or type(raw["arguments"]) is not dict):
            raise ValueError("METADATA_SELECTION_PROGRAM_INVALID")
        args = raw["arguments"]
        cursor = self._unpack(args["cursor"], scope) if set(args) == {"cursor"} else None
        query = cursor["query"] if cursor else args
        if (type(query) is not dict or not {"dimensionId", "expression"} <= set(query)
                or set(query) - {"dimensionId", "expression", "limit", "resultMode",
                                 "selectionContext", *_CONTEXT_PINS}
                or len(json.dumps(query)) > 16384):
            raise ValueError("METADATA_SELECTION_ARGUMENTS_INVALID")
        pins = {name: query[name] for name in _CONTEXT_PINS if name in query}
        if any(type(value) is not int or not 0 <= value <= 2**63 - 1 for value in pins.values()):
            raise ValueError("METADATA_SELECTION_CONTEXT_PIN_INVALID")
        expected_token = context = None
        if "selectionContext" in query:
            context = query["selectionContext"]
            if type(context) is not dict or set(context) - {"expectedToken"}:
                raise ValueError("METADATA_SELECTION_CONTEXT_INVALID")
            if "expectedToken" in context:
                expected_token = require_state_token(
                    context["expectedToken"], error="METADATA_SELECTION_CONTEXT_INVALID")
        definition = _canonical(query["dimensionId"], query["expression"])
        limit = query.get("limit", 100)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("METADATA_SELECTION_PAGE_INVALID")
        node = definition["expression"]
        native = node["kind"] == "navigation"
        mode = query.get("resultMode", "unique_member")
        if mode not in ("unique_member", "placements") or mode == "placements" and (
                not native or node["operation"] == "top"):
            raise ValueError("METADATA_SELECTION_RESULT_MODE_INVALID")
        query = {"dimensionId": definition["dimensionId"], "expression": node, "limit": limit, **pins}
        if context is not None:
            query["selectionContext"] = context
        if mode == "placements":
            query["resultMode"] = mode
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
                configure_lock_wait(db)
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                authority = resolve_effective_dimensional_scope(db, self.identity, scope, function=SELECT)
                state = _state(db, scope)
                if cursor and (cursor["state"] != state or cursor["authority"] != authority.scope_digest):
                    raise ValueError("METADATA_SELECTION_CURSOR_STALE")
                if any(state[_CONTEXT_PINS[name]] != value for name, value in pins.items()):
                    raise ValueError("METADATA_SELECTION_CONTEXT_STALE")
                context_token = (self._context_token(scope, state, authority)
                                 if context is not None else None)
                if expected_token is not None and not hmac.compare_digest(expected_token, context_token):
                    raise ValueError("METADATA_SELECTION_CONTEXT_STALE")
                descriptor = (_scope_descriptor(db, scope, definition["dimensionId"], authority, node)
                              if native else None)
                top = native and node["operation"] == "top"
                rows = ([] if top else resolve_in_transaction(db, scope, authority, definition,
                        placements=True) if mode == "placements"
                        else resolve_in_transaction(db, scope, authority, definition))
                final_authority = resolve_effective_dimensional_scope(db, self.identity, scope, function=SELECT)
                if _state(db, scope) != state or final_authority.scope_digest != authority.scope_digest:
                    raise ValueError("METADATA_SELECTION_CHANGED_DURING_READ")
                offset = cursor["offset"] if cursor else 0
                if offset > len(rows):
                    raise ValueError("METADATA_SELECTION_CURSOR_STALE")
                next_cursor = None
                if offset + limit < len(rows):
                    next_cursor = self._pack({"query": query, "offset": offset + limit, "state": state,
                        "scope": [scope.workspace_id, scope.application_id],
                        "identity": [self.identity.issuer, self.identity.subject_id],
                        "authority": authority.scope_digest,
                        "expires": cursor["expires"] if cursor else int(time.time()) + CURSOR_TTL})
                return {"dimensionId": definition["dimensionId"], "rows": rows[offset:offset + limit],
                    "metadataRevision": state["metadata_revision"], "nextCursor": next_cursor,
                    **({"selectionContextToken": context_token} if context_token is not None else {}),
                    "hasMore": next_cursor is not None, **(
                        {"resultKind": "scope" if top else mode, "scope": descriptor}
                        if descriptor is not None else {})}


def read_program_contract(function):
    if function != SELECT:
        return None
    from .metadata_read_contract import read_contract, read_example, obj
    from .member_list_contract import structural_schema_definitions
    identifier = {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'}
    revision = {'type': 'integer', 'minimum': 0}
    token = {'type': 'string', 'pattern': r'^[0-9a-f]{64}(?![\s\S])'}
    query = obj({'dimensionId': identifier,
        'expression': {'$ref': '#/$defs/memberListExpression'},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500},
        **dict.fromkeys(_CONTEXT_PINS, {**revision, 'maximum': 2**63 - 1}),
        'selectionContext': obj({'expectedToken': token}, []),
        'resultMode': {'enum': ['unique_member', 'placements']}}, ['dimensionId', 'expression'])
    query['allOf'] = [{'if': {'required': ['resultMode'],
        'properties': {'resultMode': {'const': 'placements'}}},
        'then': {'properties': {'expression': {'type': 'object', 'properties': {
            'kind': {'const': 'navigation'}, 'operation': {'not': {'const': 'top'}}}}}}}]
    arguments = {'oneOf': [query, obj({'cursor': {'type': 'string',
        'minLength': 1, 'maxLength': 32768}})]}
    attribute = obj({'valueType': {'enum': ['Text', 'Decimal', 'Boolean', 'MemberReference']},
        'present': {'type': 'boolean'}, 'value': {'type': ['string', 'boolean', 'null']}})
    base_row = {'memberId': identifier, 'name': {'type': 'string'},
        'status': {'enum': ['Active', 'Inactive']},
        'shortDescription': {'type': 'string'}, 'semanticDescription': {'type': 'string'},
        'attributes': {'type': 'object', 'additionalProperties': attribute}}
    member_row = obj(base_row)
    placement_row = obj({**base_row,
        'pathRelationshipIds': {'type': 'array', 'maxItems': 32, 'items': identifier},
        'pathMemberIds': {'type': 'array', 'minItems': 1, 'maxItems': 33, 'items': identifier},
        'generation': {'anyOf': [{'type': 'integer', 'minimum': 2, 'maximum': 34}, {'type': 'null'}]},
        'level': {'anyOf': [revision, {'type': 'null'}]}})
    scope = obj({'kind': {'const': 'scope'}, 'scope': {'enum': ['dimension', 'hierarchy']},
        'dimensionId': identifier, 'hierarchyId': {'anyOf': [identifier, {'type': 'null'}]},
        'name': {'type': 'string'}, 'shortDescription': {'type': 'string'},
        'semanticDescription': {'type': 'string'}, 'businessCoordinate': {'const': False},
        'supportedOperations': {'type': 'array', 'items': {'enum': list(NAVIGATION_OPERATIONS)}, 'uniqueItems': True}})
    base = {'dimensionId': identifier, 'metadataRevision': revision,
        'nextCursor': {'type': ['string', 'null']}, 'hasMore': {'type': 'boolean'}}
    def page_schema(fields):
        return obj({**fields, 'selectionContextToken': token}, list(fields))

    results = [page_schema({**base, 'rows': {'type': 'array', 'maxItems': 500, 'items': member_row}})]
    for kind, row in [('unique_member', member_row), ('placements', placement_row)]:
        results.append(page_schema({**base, 'resultKind': {'const': kind}, 'scope': scope,
            'rows': {'type': 'array', 'maxItems': 500, 'items': row}}))
    results.append(page_schema({**base, 'resultKind': {'const': 'scope'}, 'scope': scope,
        'rows': {'type': 'array', 'maxItems': 0}, 'nextCursor': {'type': 'null'},
        'hasMore': {'const': False}}))
    examples = [read_example(function, {'dimensionId': 'custom-axis',
        'expression': {'kind': 'explicit', 'memberIds': ['member-a']}},
        name='Read explicit current members', binding='Use IDs from current authorized metadata discovery.'),
        read_example(function, {'dimensionId': 'custom-axis', 'expression': {
            'kind': 'navigation', 'operation': 'top', 'scope': 'dimension',
            'hierarchyId': None, 'anchor': None, 'includeSelf': False, 'allParents': False},
            'selectionContext': {}},
            name='Read the current dimension scope without inventing a member',
            binding='Use the dimensionId from the current authorized dimension list. Keep the returned selectionContextToken for related reads.'),
        read_example(function, {'dimensionId': 'custom-axis', 'limit': 1, 'resultMode': 'placements',
            'expression': {'kind': 'navigation', 'operation': 'all', 'scope': 'hierarchy',
                'hierarchyId': 'example-hierarchy', 'anchor': None, 'includeSelf': False, 'allParents': False},
            **dict.fromkeys(_CONTEXT_PINS, 0), 'selectionContext': {'expectedToken': 'a' * 64}},
            name='Read the first page of a reviewed hierarchy',
            binding='Bind the current dimension and hierarchy IDs and current revision pins. Copy the preceding top read’s selectionContextToken into selectionContext.expectedToken.'),
        read_example(function, {'cursor': 'example-current-cursor'}, name='Read the next page of the same hierarchy',
            binding='Use the exact nextCursor returned by the preceding page in this application with the same identity.')]
    contract = read_contract(function, arguments, {'oneOf': results}, owner='PostgresMemberSelection.read',
        examples=examples, definitions=structural_schema_definitions(parameters=False),
        semantic_rules=['The canonical member-list compiler and evaluator remain the sole expression grammar, including depth/node/reference budgets and typed comparisons.',
            'Unreadable MemberReference values are absent before comparison, ordering and result projection. The same projected attribute values are used throughout the selection.',
            'Pin the current application revisions on each independent read when assembling a selection from several results. A stale first read refuses before returning member or placement information.',
            'Open a selection context with an empty selectionContext. Pass its token to each related independent read. It binds the same caller, application, revision vector and effective dimensional access. Every read still checks current authorization.',
            'Signed continuation is cursor-only and binds original query, actor, scope, current metadata/security/schema/policy and expiry. Do not reconstruct a cursor.',
            'Native scope top is not a business coordinate. Placements retain each path; unique-member results collapse only according to the requested native semantics.',
            'An empty complete result remains empty; native current authority never substitutes the whole dimension or reveals a denied branch.'])
    contract['programContract']['recovery'] = (
        'On METADATA_SELECTION_CONTEXT_STALE, METADATA_SELECTION_CURSOR_STALE or '
        'METADATA_SELECTION_CHANGED_DURING_READ, read the current application state, '
        'rediscover authorized references and restart the selection without a cursor.')
    return contract
