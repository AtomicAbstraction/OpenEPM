"""Authorize named aggregate inputs before admission and again on the worker snapshot."""
from psycopg.types.json import Jsonb

from .dimensional_security_policy import ResolvedMemberSecurity
from .postgres_access import AccessDenied
from .postgres_member_selection import SelectionReadBudget, authorize_hierarchy_selection


def authorize_aggregate_selection(db, scope, authority, query):
    if authority.privileges is None:
        return
    # These operations take every contribution from authorized numeric coordinates.
    # Weighted/placement reducers also depend on an authorized external source of weights.
    if query["aggregation"] not in ("unique_coordinate_sum", "unique_coordinate_reduction"):
        raise AccessDenied("CUBE_AGGREGATE_SOURCE_PRIVILEGE_REQUIRED")
    names = []
    budget = SelectionReadBudget()
    for dimension, selector in query["selectors"].items():
        if selector["kind"] == "Members":
            names.extend({"dimension_id": dimension, "member_id": member} for member in selector["memberIds"])
        else:
            try:
                authorize_hierarchy_selection(db, scope, authority, dimension, selector, budget=budget)
            except (ValueError, AccessDenied):
                raise AccessDenied("CUBE_SELECTION_MEMBER_UNAVAILABLE") from None
    if not names:
        return
    rows = db.execute("""SELECT m.dimension_id,m.member_id,m.read_security_tags,m.write_security_tags
        FROM jsonb_to_recordset(%s::jsonb) input(dimension_id text,member_id text)
        JOIN epm.member m USING(dimension_id,member_id) WHERE m.workspace_id=%s AND m.application_id=%s
          AND m.status='Active'""", (Jsonb(names), scope.workspace_id, scope.application_id)).fetchall()
    if len(rows) != len(names):
        raise AccessDenied("CUBE_SELECTION_MEMBER_UNAVAILABLE")
    for row in rows:
        member = ResolvedMemberSecurity(row["dimension_id"], row["member_id"],
            tuple(row["read_security_tags"]), tuple(row["write_security_tags"]))
        if not authority.privileges.covers_read_filter((member,), authority.policy):
            raise AccessDenied("CUBE_SELECTION_MEMBER_UNAVAILABLE")
