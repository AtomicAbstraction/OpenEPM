"""Current, owner-only visibility of ordinary numeric jobs in a group-assigned application."""

from psycopg import sql
from psycopg.types.json import Jsonb

from .dimensional_privileges import _axis_matches_sql
from .dimensional_security_policy import MemberTagCardinality
from .postgres_dimensional_scope import resolve_effective_dimensional_scope


def numeric_job_visibility(db, scope, identity, access, *, lock_state=False):
    """A predicate over job alias j, shared before reading, paging or cancelling."""
    # Take the same workspace, state, job lock order as a numeric publisher.
    # For read-only transactions the statement that reads the job verifies this revision cut.
    layout_query = """SELECT l.dimensions,s.schema_epoch,s.metadata_revision,s.security_revision
        FROM epm.coordinate_layout l JOIN epm.application_state s USING(workspace_id,application_id,schema_epoch)
        WHERE l.workspace_id=%s AND l.application_id=%s"""
    if lock_state:
        layout_query += " FOR SHARE OF s"
    layout = db.execute(layout_query, (scope.workspace_id, scope.application_id)).fetchone()
    if not layout or not layout["dimensions"]:
        return sql.SQL("FALSE"), ()
    authority = resolve_effective_dimensional_scope(db, identity, scope, access=access)
    bindings = [
        {"assignment": row.assignment_id, "action": row.action, "kind": row.scope_kind, "selector": row.selector}
        for row in authority.privileges.rows
        if row.action in ("facts.read", "facts.write")
        and row.scope_kind in ("entire_application", "dimension_tags")
    ]
    if not bindings:
        return sql.SQL("FALSE"), ()
    # A complete write requires matching read and write on every protected axis
    # in one assignment. Different bindings of that assignment may supply them.
    tags = sql.SQL("CASE WHEN b.action='facts.read' THEN m.read_security_tags ELSE m.write_security_tags END")
    matches = _axis_matches_sql(
        authority.policy, sql.SQL("b.kind"), sql.SQL("b.selector"), sql.SQL("axis.id"), tags
    )
    valid = sql.SQL("m.member_id IS NOT NULL")
    if authority.policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED:
        valid += sql.SQL(" AND cardinality(m.read_security_tags)<=1 AND cardinality(m.write_security_tags)<=1")
    condition = sql.SQL("""j.issuer=%s AND j.subject_id=%s AND j.function_name='facts.numeric.batch'
        AND j.admission_origin_kind='ordinary' AND j.python_workflow_id IS NULL
        AND j.execution_schedule_id IS NULL AND j.authority_kind='HumanToken' AND j.token_issued_at IS NOT NULL
        AND epm.identity_subject_session_valid(j.issuer,j.subject_id,j.token_issued_at)
        AND j.verified_groups=%s::text[] AND j.authorization_scope_digest=%s
        AND EXISTS (SELECT 1 FROM epm.application_state s WHERE s.workspace_id=j.workspace_id
          AND s.application_id=j.application_id AND s.schema_epoch=%s AND s.metadata_revision=%s
          AND s.security_revision=%s)
        AND j.normalized_program @> '{{"version":1,"function":"facts.numeric.batch"}}'::jsonb
        AND CASE WHEN jsonb_typeof(j.normalized_program->'mutations')='array' THEN
          jsonb_array_length(j.normalized_program->'mutations') BETWEEN 1 AND 500 AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(j.normalized_program->'mutations') mutation
            CROSS JOIN LATERAL (SELECT CASE WHEN jsonb_typeof(mutation->'members')='object'
                THEN mutation->'members' ELSE '{{}}'::jsonb END AS members) pt
            WHERE NOT (pt.members ?& %s::text[])
               OR (SELECT count(*) FROM jsonb_object_keys(pt.members))<>%s
               OR EXISTS (SELECT 1 FROM jsonb_each(pt.members) v WHERE jsonb_typeof(v.value)<>'string')
               OR NOT EXISTS (
                  SELECT b.assignment FROM jsonb_to_recordset(%s::jsonb)
                    b(assignment text,action text,kind text,selector jsonb)
                  WHERE (b.kind='entire_application' OR (b.selector<>'{{}}'::jsonb AND NOT EXISTS (
                      SELECT 1 FROM jsonb_object_keys(b.selector) k(id) WHERE NOT (pt.members ? k.id))))
                    AND NOT EXISTS (SELECT 1 FROM jsonb_each_text(pt.members) axis(id,member)
                      LEFT JOIN epm.member m ON m.workspace_id=j.workspace_id AND m.application_id=j.application_id
                        AND m.dimension_id=axis.id AND m.member_id=axis.member AND m.status='Active'
                      WHERE NOT coalesce(({valid} AND {matches}),false))
                  GROUP BY b.assignment HAVING bool_or(b.action='facts.read') AND bool_or(b.action='facts.write')
              )
          ) ELSE false END""").format(valid=valid, matches=matches)
    parameters = (
        identity.issuer,
        identity.subject_id,
        list(access.groups),
        authority.scope_digest,
        layout["schema_epoch"],
        layout["metadata_revision"],
        layout["security_revision"],
        list(layout["dimensions"]),
        len(layout["dimensions"]),
        Jsonb(bindings),
    )
    return condition, parameters
