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

from psycopg.rows import dict_row

from .dimensional_security_policy import AccessKind, ResolvedMemberSecurity, evaluate_coordinate
from .member_list_contract import canonical_member_list_definition
from .member_list_evaluator import evaluate_member_list, resolve_member_list_parameters
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDenied, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_hierarchies import resolve_hierarchy
from .postgres_member_attributes import load_member_attribute_snapshot
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout

SELECT = "metadata.member.select"
MAX_MEMBERS = 5000
MAX_EDGES = 10000
CURSOR_TTL = 900
_HIERARCHY = {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}



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
            "cursor": "signed sole continuation argument; current state and authority bound"},
        "argumentForms": ["dimensionId + expression + optional limit", "cursor only"],
        "result": "current member objects, typed attributes and bounded continuation; no persistent effects",
        "previewRequired": False, "idempotencyRequired": False, "workClass": "bounded_read"}}


def _canonical(dimension, expression):
    # The definition is only the existing evaluator's in-memory input envelope.
    # No source, member list, build or definition is written by this operation.
    return canonical_member_list_definition({"format": "openepm-member-list-v1",
        "listId": "native-query", "dimensionId": dimension, "name": "Native query",
        "parameters": [], "expression": expression})


from .member_list_contract import iter_member_list_nodes as _nodes

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
        decision = evaluate_coordinate((ResolvedMemberSecurity(dimension,
            row.get("member_id", row.get("relationship_id", dimension)),
            tuple(row["read_security_tags"]), tuple(row["write_security_tags"])),),
            kind=AccessKind.READ, expected_dimensions=(dimension,),
            policy=authority.policy, read_assignments=authority.read_assignments,
            write_assignments=authority.write_assignments,
            application_administrator=authority.access.role == "Administrator",
            workspace_administrator=authority.access.workspace_administrator)
        if not decision.allowed:
            # Do not expose which hidden node/edge, its name, count or tags.
            raise AccessDenied("METADATA_SELECTION_SCOPE_UNAVAILABLE")


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
    eligible = """SELECT r.relationship_id,r.parent_member_id,r.child_member_id,
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
    kind = node["kind"]
    args = (*keys, hierarchy["hierarchy_id"], hierarchy["membership_mode"])
    if kind in {"children", "base", "parents"}:
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


def _finite_bound(node, selectors, parameters):
    kind = node["kind"]
    if kind == "explicit":
        return set(node["memberIds"])
    if kind == "parameter":
        return {parameters[node["name"]]} if node["name"] in parameters else set()
    if kind in _HIERARCHY:
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


def load_selection_context(db, scope, authority, definition, *, parameters=None, budget=None):
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
    cache_key = json.dumps([dimension, definition["expression"], definition["parameters"], supplied],
                           sort_keys=True, separators=(",", ":"))
    if cache_key in budget.context_cache:
        return budget.context_cache[cache_key]
    keys = (scope.workspace_id, scope.application_id, dimension)
    dimension_row = db.execute("""SELECT dimension_id,read_security_tags,write_security_tags
        FROM epm.dimension WHERE workspace_id=%s AND application_id=%s
          AND dimension_id=%s AND status='Active'""", keys).fetchone()
    if dimension_row is None:
        raise AccessDenied("METADATA_SELECTION_SCOPE_UNAVAILABLE")
    _authorize_rows(authority, dimension, [dimension_row])
    graphs, selectors = {}, {}
    required = {supplied[name] for name, declaration in declarations.items()
                if declaration["type"] == "Member" and name in supplied}
    for node in _nodes(definition["expression"]):
        if node["kind"] == "explicit":
            required.update(node["memberIds"])
        elif node["kind"] in _HIERARCHY:
            required.add(node["memberId"])
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
        elif node["kind"] in _HIERARCHY:
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
            names = {member: member for member in required}
            selectors[json.dumps(node, sort_keys=True)] = set(evaluate_member_list(
                _canonical(dimension, node), members=names, relationships=[],
                attributes={}, attribute_types={}, hierarchy_graphs={node["hierarchyId"]: graph}))
            merged = graphs.setdefault(node["hierarchyId"], {"hierarchyId": graph["hierarchyId"],
                "members": set(), "relationships": {}})
            merged["members"].update(graph["members"])
            merged["relationships"].update({edge["relationshipId"]: edge for edge in graph["relationships"]})
    bound = _finite_bound(definition["expression"], selectors, supplied)
    if bound is not None:
        required.update(bound)
    rows = [dict(row) for row in db.execute("""SELECT dimension_id,member_id,name,status,
        short_description,detailed_description,custom_values,read_security_tags,write_security_tags
        FROM epm.member WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
          AND status='Active' AND (%s::boolean OR member_id=ANY(%s::text[]))
        ORDER BY member_id LIMIT %s""", (*keys, bound is None, sorted(required), budget.max_members + 1)).fetchall()]
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


def resolve_in_transaction(db, scope, authority, definition):
    selected,context = _evaluate_in_transaction(
        db,scope,authority,definition)
    dimension = definition["dimensionId"]
    rows, attributes = context["rows"], context["attributes"]
    by_id = {row["member_id"]: row for row in rows}
    return [{"memberId": key, "name": by_id[key]["name"], "status": by_id[key]["status"],
        "shortDescription": by_id[key]["short_description"],
        "semanticDescription": by_id[key]["detailed_description"],
        "attributes": {attribute: {"valueType": descriptor["valueType"],
            "present": attribute in (by_id[key]["custom_values"] or {}),
            "value": (by_id[key]["custom_values"] or {}).get(attribute)}
            for attribute, descriptor in attributes.definitions[dimension].items()
            if attribute == descriptor["attributeId"]}} for key in selected]


class PostgresMemberSelection:
    def __init__(self, dsn, *, identity, cursor_secret):
        if not isinstance(identity, VerifiedIdentity) or not isinstance(cursor_secret, bytes) or len(cursor_secret) < 32:
            raise ValueError("METADATA_SELECTION_TRUSTED_INPUT_REQUIRED")
        assert_nonowner_role(dsn, "epm_runtime", ("dimension", "member", "relationship", "attribute_definition"))
        self.dsn, self.identity, self.cursor_secret = dsn, identity, cursor_secret

    def _pack(self, value):
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return base64.urlsafe_b64encode(raw + hmac.new(self.cursor_secret, raw, hashlib.sha256).digest()).decode()

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
                    or type(value["offset"]) is not int or not 0 < value["offset"] <= MAX_MEMBERS
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
                or set(query) - {"dimensionId", "expression", "limit"}
                or len(json.dumps(query)) > 16384):
            raise ValueError("METADATA_SELECTION_ARGUMENTS_INVALID")
        definition = _canonical(query["dimensionId"], query["expression"])
        limit = query.get("limit", 100)
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ValueError("METADATA_SELECTION_PAGE_INVALID")
        query = {"dimensionId": definition["dimensionId"], "expression": definition["expression"], "limit": limit}
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
                rows = resolve_in_transaction(db, scope, authority, definition)
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
                    "hasMore": next_cursor is not None}
