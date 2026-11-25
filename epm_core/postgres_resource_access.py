"""Reverse a protected coordinate or saved-view read into grants and admitted people."""

from __future__ import annotations

import base64
from collections import defaultdict
from dataclasses import replace
from functools import lru_cache
from hashlib import sha256
import hmac
import json

from cryptography.fernet import Fernet, InvalidToken
from jsonschema import Draft202012Validator
from psycopg import sql
from psycopg.rows import dict_row

from .dimensional_privileges import DimensionalPrivileges, dimensional_privileges_for_groups
from .metadata_read_contract import read_contract, read_example
from .persistence_contract import Coordinate
from .postgres_access import PostgresAccessChecker, SECURITY_READ_AUTHORIZATION_STALE
from .postgres_access_explanation import _visible_point, _state as explanation_state, planning_set_failure
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_jobs import _canonical_digest
from .postgres_numeric_catalog import obj, program_schema
from .postgres_planning_write_guard import load_planning_write_context
from .postgres_saved_grids import _object_visible_sql, _view_visible_sql

FUNCTION = "security.application.resource-access.list"
INVALID = "APPLICATION_RESOURCE_ACCESS_ARGUMENTS_INVALID"
STALE = "APPLICATION_RESOURCE_ACCESS_CURSOR_STALE"
MAX_GROUPS = 512
_MAX_ORIGINS = 8
_MAX_VIEW_CANDIDATES = 2048
_TEXT = {"type": "string", "minLength": 1, "maxLength": 300}
_MEMBER = {
    "type": "string",
    "minLength": 1,
    "maxLength": 200,
    "pattern": r"^[^\u0000\uD800-\uDFFF]+$",
}
_POINT = {
    "type": "object",
    "minProperties": 1,
    "maxProperties": 128,
    "propertyNames": _MEMBER,
    "additionalProperties": _MEMBER,
}
_VIEW = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}(?![\s\S])"}
_ACTION = {"enum": ["facts.read", "facts.write", "views.read"]}
_ARGS = obj(
    {
        "action": _ACTION,
        "coordinate": _POINT,
        "savedViewId": _VIEW,
        "collection": {"enum": ["people", "groups", "origins"]},
        "groupId": _TEXT,
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "expectedMetadataRevision": {"type": "integer", "minimum": 0},
        "cursor": {"type": "string", "minLength": 1, "maxLength": 8192},
    },
    ["action", "collection"],
)
_ARGS["allOf"] = [
    {
        "if": {"properties": {"action": {"const": "views.read"}}},
        "then": {"required": ["savedViewId"], "not": {"required": ["coordinate"]}},
        "else": {"required": ["coordinate"], "not": {"required": ["savedViewId"]}},
    },
    {
        "if": {"properties": {"collection": {"const": "origins"}}},
        "then": {"required": ["groupId"]},
        "else": {"not": {"required": ["groupId"]}},
    },
]


def catalog_entry():
    rev = {"type": "integer", "minimum": 0}
    status = {"enum": ["open", "locked", "blocked", "unknown", "workflow_role_unbound", "not_applicable"]}
    origin = obj(
        {
            "assignmentId": _TEXT,
            "assignmentRevision": rev,
            "groupId": _TEXT,
            "roleId": _TEXT,
            "roleRevision": rev,
            "scopeId": _TEXT,
            "scopeRevision": rev,
            "action": _ACTION,
        }
    )
    from .application_authorization_config import WORKFLOW_DUTIES
    origin["properties"]["workflowDuties"] = WORKFLOW_DUTIES
    group = obj(
        {
            "groupId": _TEXT,
            "groupName": {"type": ["string", "null"]},
            "hasActiveMembers": {"type": "boolean"},
            "origins": {"type": "array", "items": origin, "maxItems": _MAX_ORIGINS},
            "originsComplete": {"type": "boolean"},
        }
    )
    person = obj(
        {
            "subjectId": _TEXT,
            "username": {"type": ["string", "null"]},
            "displayName": {"type": ["string", "null"]},
            "grantingGroupIds": {"type": "array", "items": _TEXT, "maxItems": MAX_GROUPS},
            "entryGroupIds": {"type": "array", "items": _TEXT, "maxItems": MAX_GROUPS},
        }
    )
    group["properties"]["businessState"] = status
    person["properties"]["businessState"] = status
    result = obj(
        {
            "workspaceId": _TEXT,
            "applicationId": _TEXT,
            "action": _ACTION,
            "collection": _ARGS["properties"]["collection"],
            "coordinate": _POINT,
            "savedViewId": _VIEW,
            "groupId": _TEXT,
            "coverage": {"enum": ["complete_in_application", "partial", "unavailable"]},
            "coverageReasons": {"type": "array", "items": _TEXT},
            "businessState": {"enum": [*status["enum"], "per_assignment"]},
            "asOf": {"type": "string", "format": "date-time"},
            "nextCursor": {"type": ["string", "null"]},
            "groups": {"type": "array", "maxItems": 100, "items": group},
            "people": {"type": "array", "maxItems": 100, "items": person},
            "origins": {"type": "array", "maxItems": 100, "items": origin},
        },
        [
            "workspaceId",
            "applicationId",
            "action",
            "collection",
            "coverage",
            "coverageReasons",
            "businessState",
            "asOf",
            "nextCursor",
            "groups",
            "people",
            "origins",
        ],
    )
    return {
        "mode": "read",
        "permission": "admin",
        "previewRequired": False,
        "idempotencyRequired": False,
        "workClass": "short",
        "arguments": list(_ARGS["properties"]),
        "result": "Resource-scoped effective people and granting groups",
        **read_contract(
            FUNCTION,
            _ARGS,
            result,
            owner="ResourceAccessReview",
            examples=[
                read_example(
                    FUNCTION,
                    {
                        "collection": "people",
                        "action": "facts.read",
                        "coordinate": {"Entity": "India", "Account": "Expenses"},
                    },
                    name="Who can read this coordinate?",
                    binding="Choose one visible member of every active fact dimension.",
                ),
                read_example(
                    FUNCTION,
                    {
                        "collection": "groups",
                        "action": "views.read",
                        "savedViewId": "quarterly-plan",
                    },
                    name="Which groups have an object grant?",
                    binding="Select a saved view visible to the reviewer.",
                ),
            ],
            semantic_rules=[
                "A group row describes a matching assignment even when its group is empty. A person also needs active directory membership and application entry.",
                "Write requires read and write on the same assignment. Inspect businessState separately for planning write locks.",
                "When businessState is per_assignment, inspect each returned person's numeric Set state. Group states evaluate only that group's matching assignments. Origins show linked duties; combining memberships can change the outcome.",
                "People listed for views.read can also see the referenced metadata under their own current assignments.",
                "Use collection origins with one granting groupId to page every independent binding.",
            ],
        ),
    }


@lru_cache(maxsize=1)
def _validator():
    return Draft202012Validator(program_schema(FUNCTION, _ARGS))


def _source(row):
    return {
        "assignmentId": row.assignment_id,
        "assignmentRevision": row.assignment_revision,
        "groupId": row.group_id,
        "roleId": row.role_id,
        "roleRevision": row.role_revision,
        "scopeId": row.scope_id,
        "scopeRevision": row.scope_revision,
        "action": row.action,
        **({"workflowDuties": list(row.workflow_duties)} if row.action == "facts.write" else {}),
    }


def _state(db, scope):
    state = explanation_state(db, scope)
    if state:
        state.update(
            db.execute(
                """SELECT commit_revision,CURRENT_DATE::text AS planning_evaluation_date,
            epm.resource_review_directory_fence() AS directory_revision
            FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id, scope.application_id),
            ).fetchone()
        )
        state["created_at"] = state["created_at"].isoformat()
    return state


def _view_token(db, scope, authority, view):
    # The first predicate protects object identity; the second protects every
    # referenced selection, just as the normal grid.definition.read does.
    query = sql.SQL("""SELECT g.state_token FROM epm.saved_grid_definition g WHERE g.workspace_id=%s AND
        g.application_id=%s AND g.grid_id=%s AND {} AND {}""").format(
        _object_visible_sql(authority, "views.read"), _view_visible_sql(authority)
    )
    row = db.execute(query, (scope.workspace_id, scope.application_id, view)).fetchone()
    return row["state_token"] if row else None


def _resource(db, scope, actor, access, state, args):
    unknown = "unavailable_or_outside_review_scope"
    if state["authorization_model"] != "group_assignments":
        return None, "unknown", "unsupported_authorization_model"
    authority = resolve_effective_dimensional_scope(db, actor, scope, access=access)
    if args["action"] == "views.read":
        if "views.read" not in access.actions or not _view_token(
            db, scope, authority, args["savedViewId"]
        ):
            return None, "unknown", unknown
        return (authority, None, None, None), "not_applicable", None
    if "metadata.browse" not in access.actions:
        return None, "unknown", unknown
    point = Coordinate.from_mapping(args["coordinate"])
    members = _visible_point(db, scope, authority, point)
    if not members:
        return None, "unknown", unknown
    status = "not_applicable"
    planning = None
    if args["action"] == "facts.write":
        if any(
            state[key] != "Active" for key in ("app_status", "workspace_status", "processing_mode")
        ):
            status = "blocked"
        else:
            try:
                planning = load_planning_write_context(db, scope, (point,))
                if planning.lock_states[point] != "Open":
                    status = "locked"
                else:
                    status = "per_assignment" if planning.policy else "open"
            except ValueError as error:
                status, _ = planning_set_failure(error)
                if status == "planning_policy_blocked":
                    status = "blocked"
    return (authority, members, planning, point), status, None


def _match(rows, action, view, members, policy):
    if action == "views.read":
        # Use the same exact/per-application object evaluator per binding;
        # unioning the surviving rows also preserves every independent origin.
        return tuple(
            r
            for r in rows
            if r.action == action
            and (DimensionalPrivileges((r,)).object_targets(action, "saved_view") in (None, {view}))
        )
    return DimensionalPrivileges(rows).matching_rows(members, action, policy)


def _page(db, scope, actor, resource, args, after, limit, result):
    authority, members, planning, point = resource
    groups = db.execute("SELECT * FROM epm.resource_review_groups(%s)", (actor.issuer,)).fetchall()
    if len(groups) > MAX_GROUPS:
        raise ValueError("DIMENSIONAL_PRIVILEGE_REVIEW_LIMIT")
    gap = any(g["directory_gap"] for g in groups)
    active = {g["group_id"]: g for g in groups if g["active"]}
    rows = dimensional_privileges_for_groups(
        db, scope, actor.issuer, active, maximum_rows=4096
    ).rows
    view = args.get("savedViewId")
    matches = _match(rows, args["action"], view, members, authority.policy)
    origins = defaultdict(list)
    write_rows = defaultdict(list)
    for row in matches:
        origins[row.group_id].append(_source(row))
        if row.action == "facts.write":
            write_rows[row.group_id].append(row)
    if result["businessState"] == "per_assignment" and not any(
        r.workflow_duties for group in write_rows.values() for r in group
    ):
        result["businessState"] = "workflow_role_unbound"

    @lru_cache(maxsize=128)
    def write_outcome(group_ids):
        if result["businessState"] != "per_assignment":
            return result["businessState"]
        matched = tuple(row for gid in group_ids for row in write_rows.get(gid, ()))
        try:
            planning.evaluate(((point, "Set"),), workflow_role="Assigned", matched_write_rows=matched)
            return "open"
        except ValueError as error:
            status, _ = planning_set_failure(error)
            return "blocked" if status == "planning_policy_blocked" else status
    collection = args["collection"]
    anchor = None
    if collection == "groups":
        keys = sorted(group for group in origins if after is None or group > after)
        for key in keys[:limit]:
            group = active[key]
            result["groups"].append(
                {
                    "groupId": key,
                    "groupName": group["group_name"],
                    "hasActiveMembers": group["has_active_members"],
                    "origins": origins[key][:_MAX_ORIGINS],
                    "originsComplete": len(origins[key]) <= _MAX_ORIGINS,
                    **({"businessState": write_outcome((key,))} if args["action"] == "facts.write" else {}),
                }
            )
        if len(keys) > limit:
            anchor = keys[limit - 1]
    elif collection == "origins":
        options = origins.get(args["groupId"], [])
        keyed = sorted(
            (json.dumps([o["assignmentId"], o["action"], o["scopeId"]], separators=(",", ":")), o)
            for o in options
        )
        page = [(k, o) for k, o in keyed if after is None or k > after][: limit + 1]
        result["origins"] = [o for _, o in page[:limit]]
        if len(page) > limit:
            anchor = page[limit - 1][0]
    elif origins:
        # Never let an invisible candidate influence a returned page or cursor.
        # One bounded scan collects a full visible page and its visible lookahead.
        people = []
        visible_for_groups = {}
        examined = 0
        candidate_after = after
        while len(people) <= limit:
            batch = min(128, _MAX_VIEW_CANDIDATES - examined + 1) if view else limit + 1
            candidates = db.execute(
                "SELECT * FROM epm.resource_review_people(%s,%s::text[],%s,%s)",
                (actor.issuer, list(origins), candidate_after, batch),
            ).fetchall()
            for person in candidates:
                examined += 1
                if view and examined > _MAX_VIEW_CANDIDATES:
                    raise ValueError("DIMENSIONAL_PRIVILEGE_REVIEW_LIMIT")
                group_ids = tuple(person["group_ids"])
                if view:
                    if group_ids not in visible_for_groups:
                        chosen = frozenset(group_ids)
                        subject_rows = tuple(row for row in rows if row.group_id in chosen)
                        projected = replace(
                            authority, privileges=DimensionalPrivileges(subject_rows)
                        )
                        visible_for_groups[group_ids] = bool(
                            _view_token(db, scope, projected, view)
                        )
                    if not visible_for_groups[group_ids]:
                        continue
                people.append(
                    {
                        "subjectId": person["subject_id"],
                        "username": person["username"],
                        "displayName": person["display_name"],
                        "grantingGroupIds": sorted(set(group_ids) & origins.keys()),
                        "entryGroupIds": person["entry_ids"],
                        **({"businessState": write_outcome(group_ids)} if args["action"] == "facts.write" else {}),
                    }
                )
                if len(people) > limit:
                    break
            if not view or len(people) > limit or len(candidates) < batch:
                break
            candidate_after = candidates[-1]["subject_id"]
        result["people"] = people[:limit]
        if len(people) > limit:
            anchor = people[limit - 1]["subjectId"]
    if gap:
        result.update(coverage="partial", coverageReasons=["directory_identity_unresolved"])
    return anchor


def compile_resource_review(program):
    if not _validator().is_valid(program) or type(program["languageVersion"]) is not int:
        raise ValueError(INVALID)
    args = program["arguments"]
    if any(type(args[k]) is not int for k in ("limit", "expectedMetadataRevision") if k in args):
        raise ValueError(INVALID)
    return args


def read(dsn, scope, actor, program, *, secret):
    args = compile_resource_review(program)
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("RESOURCE_ACCESS_KEY_REQUIRED")
    limit = args.get("limit", 25)
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with PostgresAccessChecker.application_security_read(
            db, actor, scope, function=FUNCTION, fence_directory=True
        ) as access:
            state = _state(db, scope)
            if (
                not state
                or args.get("expectedMetadataRevision", state["metadata_revision"])
                != state["metadata_revision"]
            ):
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
            bound = _canonical_digest(
                [
                    FUNCTION,
                    scope.workspace_id,
                    scope.application_id,
                    actor.issuer,
                    actor.subject_id,
                    sorted(actor.groups),
                    state,
                    {k: v for k, v in args.items() if k != "cursor"},
                ]
            )
            # Bind the continuation to the exact resource, review authority and
            # observed state. Keep the anchor opaque outside the server.
            cipher = Fernet(
                base64.urlsafe_b64encode(
                    hmac.digest(secret, ("resource-review-v1:" + bound).encode(), sha256)
                )
            )
            try:
                after = (
                    cipher.decrypt(args["cursor"].encode(), ttl=900).decode()
                    if "cursor" in args
                    else None
                )
            except (InvalidToken, UnicodeError, ValueError):
                raise ValueError(STALE) from None
            result = {
                "workspaceId": scope.workspace_id,
                "applicationId": scope.application_id,
                **{
                    k: args[k]
                    for k in ("coordinate", "savedViewId", "action", "groupId", "collection")
                    if k in args
                },
                "groups": [],
                "people": [],
                "origins": [],
                "coverage": "complete_in_application",
                "coverageReasons": [],
                "nextCursor": None,
            }
            try:
                resolved, status, reason = _resource(db, scope, actor, access, state, args)
                result["businessState"] = status
                if resolved is None:
                    result.update(coverage="unavailable", coverageReasons=[reason])
                else:
                    anchor = _page(db, scope, actor, resolved, args, after, limit, result)
                    if anchor:
                        result["nextCursor"] = cipher.encrypt(anchor.encode()).decode()
            except ValueError as e:
                if str(e) not in (
                    "DIMENSIONAL_PRIVILEGE_REVIEW_LIMIT",
                    "MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION",
                    "GROUP_ASSIGNMENT_DIMENSIONAL_POLICY_REQUIRED",
                    "DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT",
                ):
                    raise
                result.update(
                    coverage="unavailable",
                    coverageReasons=["review_unavailable"],
                    groups=[],
                    people=[],
                    origins=[],
                    nextCursor=None,
                    businessState="unknown",
                )
            if _state(db, scope) != state:
                raise ValueError(SECURITY_READ_AUTHORIZATION_STALE)
            result["asOf"] = (
                db.execute("SELECT statement_timestamp() AS observed")
                .fetchone()["observed"]
                .isoformat()
            )
            return {"languageVersion": 2, "function": FUNCTION, "result": result}
