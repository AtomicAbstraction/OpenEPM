"""Coordinate and metadata authorization by complete, current group assignments."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from psycopg import sql
from psycopg.types.json import Jsonb
from .application_authorization_actions import SAME_ASSIGNMENT_PREREQUISITE

from .dimensional_security_policy import (
    AccessKind, AcrossDimensions, AdministratorTreatment, CoordinateSecurityDecision,
    HierarchyTags, MemberTagCardinality, MixedSelection, UntaggedMember,
    WithinDimension, WriteReadRelationship,
)


def legacy_dimensional_ctes(access, scope, identity):
    """Provide flattened tags only while the application uses the legacy model."""
    if access.authorization_model == "group_assignments":
        return ("WITH read_by_dimension(dimension_id,tags) AS "
                "(SELECT NULL::text,NULL::jsonb WHERE false), "
                "write_by_dimension AS (SELECT * FROM read_by_dimension) ", ())
    if access.authorization_model != "legacy":
        raise ValueError("APPLICATION_AUTHORIZATION_MODEL_INVALID")
    return ("""WITH effective_grants AS (
            SELECT g.read_security_tags,g.write_security_tags
            FROM epm.application_access_grant g
            WHERE g.workspace_id=%s AND g.application_id=%s
              AND g.issuer=%s AND g.subject_id=%s
            UNION ALL
            SELECT g.read_security_tags,g.write_security_tags
            FROM epm.application_group_access_grant g
            WHERE g.workspace_id=%s AND g.application_id=%s
              AND g.issuer=%s AND g.group_id=ANY(%s::text[])
        ), read_by_dimension AS (
            SELECT assignment.key AS dimension_id,
                   jsonb_agg(DISTINCT tag.value ORDER BY tag.value) AS tags
            FROM effective_grants grant_row
            CROSS JOIN LATERAL jsonb_each(
                grant_row.read_security_tags) assignment
            CROSS JOIN LATERAL jsonb_array_elements_text(
                assignment.value) tag(value)
            GROUP BY assignment.key
        ), write_by_dimension AS (
            SELECT assignment.key AS dimension_id,
                   jsonb_agg(DISTINCT tag.value ORDER BY tag.value) AS tags
            FROM effective_grants grant_row
            CROSS JOIN LATERAL jsonb_each(
                grant_row.write_security_tags) assignment
            CROSS JOIN LATERAL jsonb_array_elements_text(
                assignment.value) tag(value)
            GROUP BY assignment.key
        )
""", (
        scope.workspace_id, scope.application_id, identity.issuer, identity.subject_id,
        scope.workspace_id, scope.application_id, identity.issuer, list(access.groups)))


def require_assignment_policy(policy):
    if (policy is None
            or policy.across_dimensions is not AcrossDimensions.EVERY_PROTECTED
            or policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY
            or policy.administrator_treatment is not AdministratorTreatment.REQUIRE_ASSIGNMENT
            or policy.write_read_relationship is not WriteReadRelationship.REQUIRE_READ
            or policy.mixed_selection is MixedSelection.FILTER_READS_AND_WRITES):
        raise ValueError("GROUP_ASSIGNMENT_DIMENSIONAL_POLICY_REQUIRED")


@dataclass(frozen=True, slots=True)
class DimensionalPrivilege:
    assignment_id: str
    assignment_revision: int
    group_id: str
    role_id: str
    role_revision: int
    scope_id: str
    scope_revision: int
    action: str
    scope_kind: str
    selector: dict
    workflow_duties: tuple[str, ...] = ()

    def matches(self, members, *, policy, metadata=False, partial=False):
        if self.scope_kind not in ("entire_application", "dimension_tags"):
            return False
        constrained = self.scope_kind == "dimension_tags"
        if constrained:
            if not self.selector:
                return False
            if metadata:
                if members[0].dimension_id not in self.selector:
                    return False
            elif not partial and not self.selector.keys() <= {m.dimension_id for m in members}:
                return False
        for member in members:
            tags = member.write_tags if self.action == "facts.write" else member.read_tags
            assigned = self.selector.get(member.dimension_id)
            if not tags:
                if policy.untagged_member is UntaggedMember.DENY or (constrained and assigned is not None):
                    return False
            elif constrained:
                if not assigned:
                    return False
                if policy.within_dimension is WithinDimension.ALL_TAGS:
                    if not set(tags).issubset(assigned):
                        return False
                elif set(tags).isdisjoint(assigned):
                    return False
        return True


@dataclass(frozen=True, slots=True)
class DimensionalPrivileges:
    """The server-resolved rows for one subject in one application."""
    rows: tuple[DimensionalPrivilege, ...]

    def digest_input(self):
        result = []
        for row in self.rows:
            item = asdict(row)
            if not row.workflow_duties:
                # Preserve authority seals created before explicit duties existed.
                del item['workflow_duties']
            result.append(item)
        return result

    def scopes_for_action(self, action):
        return [{"kind": row.scope_kind, "selector": row.selector} for row in self.rows
                if row.action == action and row.scope_kind in ("entire_application", "dimension_tags")]

    def object_targets(self, action, object_type):
        """None represents the whole application, an empty set represents no target."""
        selected = [row for row in self.rows if row.action == action]
        if any(row.scope_kind == "entire_application" for row in selected):
            return None
        return {row.selector["objectId"] for row in selected if row.scope_kind == "exact_object"
                and row.selector.get("objectType") == object_type}

    def matching_rows(self, members, action, policy):
        """Return the complete bindings that establish this action on this point."""
        require_assignment_policy(policy)
        if not members or action not in ("metadata.browse", "facts.read", "facts.write"):
            raise ValueError("DIMENSIONAL_PRIVILEGE_INPUT_INVALID")
        if policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED:
            if any(len(m.read_tags) > 1 or (action == "facts.write" and len(m.write_tags) > 1)
                   for m in members):
                raise ValueError("MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION")
        metadata = action == "metadata.browse"
        if metadata and len(members) != 1:
            raise ValueError("DIMENSIONAL_PRIVILEGE_INPUT_INVALID")
        matching = tuple(r for r in self.rows if r.action == action
                         and r.matches(members, policy=policy, metadata=metadata))
        if action != "facts.write":
            return matching
        allowed_ids = {r.assignment_id for r in matching}
        reads = tuple(r for r in self.rows if r.assignment_id in allowed_ids and r.action == SAME_ASSIGNMENT_PREREQUISITE[action]
                      and r.matches(members, policy=policy))
        read_ids = {r.assignment_id for r in reads}
        return tuple(r for r in matching if r.assignment_id in read_ids) + reads

    def permits(self, members, action, policy):
        return bool(self.matching_rows(members, action, policy))

    def permits_structure_edit(self, references, policy):
        """One assignment must cover both browsing and editing the dimension and target."""
        require_assignment_policy(policy)
        if not references or (policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                              and any(len(ref.read_tags) > 1 for ref in references)):
            return False
        matching = {}
        for row in self.rows:
            if row.action in ('metadata.structure.edit', SAME_ASSIGNMENT_PREREQUISITE['metadata.structure.edit']) and all(
                    row.matches((ref,), policy=policy, metadata=True) for ref in references):
                matching.setdefault(row.assignment_id, set()).add(row.action)
        return any(len(actions) == 2 for actions in matching.values())

    def coordinate_decision(self, members, kind, dimensions, policy):
        return self.coordinate_decision_and_duties(members, kind, dimensions, policy)[0]

    def coordinate_decision_and_duties(self, members, kind, dimensions, policy):
        if not isinstance(kind, AccessKind) or tuple(m.dimension_id for m in members) != dimensions:
            raise ValueError("DIMENSIONAL_COORDINATE_LAYOUT_MISMATCH")
        action = "facts.write" if kind is AccessKind.WRITE else "facts.read"
        rows = self.matching_rows(members, action, policy)
        allowed = bool(rows)
        decision = CoordinateSecurityDecision(allowed,
            "DIMENSIONAL_SCOPE_ALLOWED" if allowed else "DIMENSIONAL_SCOPE_DENIED",
            dimensions, dimensions if allowed else ())
        duties = tuple(sorted({duty for row in rows for duty in row.workflow_duties})) if kind is AccessKind.WRITE else ()
        return decision, duties

    def covers_read_filter(self, members, policy):
        """Admit visible filter names together; each resulting full cell is checked separately."""
        require_assignment_policy(policy)
        if (not members or policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                and any(len(member.read_tags) > 1 for member in members)):
            return False
        return any(row.action == 'facts.read' and row.matches(members, policy=policy, partial=True)
                   for row in self.rows)


def read_dimensional_privileges(db, scope, identity, groups):
    return dimensional_privileges_for_groups(db, scope, identity.issuer, groups)


def dimensional_privileges_for_groups(db, scope, issuer, groups, *, maximum_rows=None):
    statement = """SELECT assignment_id,assignment_revision,group_id,role_id,role_revision,
            scope_id,scope_revision,action,scope_kind,selector,workflow_duties
        FROM epm.application_authorization_privilege
        WHERE workspace_id=%s AND application_id=%s AND issuer=%s
          AND group_id=ANY(%s::text[])
          AND action IN ('metadata.browse','metadata.structure.edit','rules.design','rules.test','rules.publish','rules.run','facts.read','facts.write','views.read','views.save','views.delete','views.run')
        ORDER BY assignment_id COLLATE "C",action COLLATE "C",scope_id COLLATE "C" """
    params = (scope.workspace_id, scope.application_id, issuer, list(groups))
    if maximum_rows is not None:
        statement += ' LIMIT %s'
        params += (maximum_rows + 1,)
    rows = db.execute(statement, params).fetchall()
    if maximum_rows is not None and len(rows) > maximum_rows:
        raise ValueError('DIMENSIONAL_PRIVILEGE_REVIEW_LIMIT')
    return DimensionalPrivileges(tuple(DimensionalPrivilege(**{
        **row, 'workflow_duties': tuple(row['workflow_duties'])
    }) for row in rows))


def _axis_matches_sql(policy, kind, selector, dimension, tags):
    """The set-based form of DimensionalPrivilege.matches for one axis."""
    assigned = sql.SQL("""ARRAY(SELECT jsonb_array_elements_text(
        coalesce(({selector})->({dimension}),'[]'::jsonb)))""").format(
            selector=selector, dimension=dimension)
    return sql.SQL("""(CASE WHEN cardinality({tags})=0 THEN
            ({untagged} AND ({kind}='entire_application' OR NOT ({selector} ? {dimension})))
        ELSE ({kind}='entire_application' OR {tags} {operator} {assigned}) END)""").format(
            tags=tags, untagged=sql.Literal(policy.untagged_member is UntaggedMember.ALLOW),
            kind=kind, selector=selector, dimension=dimension,
            operator=sql.SQL('&&' if policy.within_dimension is WithinDimension.ANY_TAG else '<@'),
            assigned=assigned)


def metadata_privilege_sql(privileges, policy, dimension, tags):
    scopes = privileges.scopes_for_action("metadata.browse")
    if not scopes:
        return sql.SQL("FALSE")
    axis_matches = _axis_matches_sql(policy, sql.SQL("b.kind"), sql.SQL("b.selector"), dimension, tags)
    cardinality = (sql.SQL(" AND cardinality({})<=1").format(tags)
                   if policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                   else sql.SQL(""))
    return sql.SQL("""EXISTS (SELECT 1 FROM jsonb_to_recordset({scopes}::jsonb)
        b(kind text, selector jsonb)
        WHERE (b.kind='entire_application' OR b.selector ? {axis})
          AND {axis_matches}{cardinality})""").format(
            scopes=sql.Literal(Jsonb(scopes)), axis=dimension,
            axis_matches=axis_matches, cardinality=cardinality)


def coordinate_write_assignment_sql(policy):
    """Match both sides of a write on one assignment and every axis of a literal target.

    The calling query supplies target.members, layout.dimensions, its axes
    with read and write tags, and the actor's write_scopes relation. An axis
    marked needs_binding is left for the canonical point evaluator.
    """
    require_assignment_policy(policy)
    tags = sql.SQL("CASE WHEN b.action='facts.write' THEN a.write_tags ELSE a.read_tags END")
    axis = _axis_matches_sql(policy, sql.SQL("b.kind"), sql.SQL("b.selector"), sql.SQL("a.dimension_id"), tags)
    cardinality = (sql.SQL(' AND cardinality(a.read_tags)<=1 AND cardinality(a.write_tags)<=1')
                   if policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                   else sql.SQL(''))
    return sql.SQL("""EXISTS (
        SELECT 1 FROM write_scopes b
        WHERE cardinality(layout.dimensions)>0 AND target.members ?& layout.dimensions
          AND (SELECT count(*) FROM axes)=cardinality(layout.dimensions)
          AND (b.kind='entire_application' OR NOT EXISTS (
            SELECT 1 FROM jsonb_object_keys(b.selector) k(dimension_id)
            WHERE NOT (target.members ? k.dimension_id)))
          AND NOT EXISTS (SELECT 1 FROM axes a WHERE a.needs_binding IS NOT TRUE
                          AND (a.member_id IS NULL OR NOT ({matches}{cardinality})))
        GROUP BY b.assignment HAVING bool_or(b.action='facts.read') AND bool_or(b.action='facts.write')
    )""").format(matches=axis, cardinality=cardinality)


def _coordinate_scope_sql(policy, dimension_count, scopes):
    summary = sql.SQL("""LATERAL (SELECT count(*) AS axis_count, count(m.member_id) AS found_count,
            coalesce(bool_or(cardinality(m.read_security_tags)>1),false) AS cardinality_violation,
            coalesce(jsonb_object_agg(axis.dimension_id,m.read_security_tags)
                FILTER (WHERE m.member_id IS NOT NULL),'{}'::jsonb) AS member_tags
          FROM jsonb_each_text(c.members) axis(dimension_id,member_id)
          LEFT JOIN epm.member m ON m.workspace_id=c.workspace_id
            AND m.application_id=c.application_id AND m.dimension_id=axis.dimension_id
            AND m.member_id=axis.member_id AND m.status='Active') security""")
    matches = _axis_matches_sql(policy, sql.SQL("b.kind"), sql.SQL("b.selector"),
        sql.SQL("a.dimension_id"), sql.SQL("ARRAY(SELECT jsonb_array_elements_text(a.tags))"))
    cardinality = (sql.SQL(" AND NOT security.cardinality_violation")
                   if policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                   else sql.SQL(""))
    allowed = sql.SQL("""(security.axis_count={count} AND security.found_count={count}{cardinality}
        AND EXISTS (SELECT 1 FROM jsonb_to_recordset({scopes}::jsonb) b(kind text,selector jsonb)
            WHERE (b.kind='entire_application' OR (b.selector<>'{{}}'::jsonb AND
                NOT EXISTS (SELECT 1 FROM jsonb_object_keys(b.selector) AS k(dimension_id)
                    WHERE NOT (security.member_tags ? k.dimension_id))))
              AND NOT EXISTS (SELECT 1 FROM jsonb_each(security.member_tags) a(dimension_id,tags)
                  WHERE NOT {axis_matches})))""").format(count=sql.Literal(dimension_count),
            cardinality=cardinality, scopes=scopes,
            axis_matches=matches)
    return summary, allowed


def coordinate_read_filter_sql(policy, dimensions):
    """Discard known denials early; leave malformed rows for the shared evaluator to reject."""
    summary, allowed = _coordinate_scope_sql(policy, len(dimensions), sql.Placeholder())
    invalid = sql.SQL("""security.axis_count<>{count} OR security.found_count<>{count}
        OR NOT (c.members ?& {dimensions}::text[])""").format(
            count=sql.Literal(len(dimensions)), dimensions=sql.Literal(list(dimensions)))
    if policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED:
        invalid += sql.SQL(" OR security.cardinality_violation")
    return sql.SQL(" AND EXISTS (SELECT 1 FROM {} WHERE ({}) OR {})").format(
        summary, invalid, allowed)


def aggregate_privilege_sql(privileges, policy, dimension_count):
    """Bind one scope across all axes before reducing any source facts."""
    summary, allowed = _coordinate_scope_sql(policy, dimension_count,
        sql.Literal(Jsonb(privileges.scopes_for_action("facts.read"))))
    join = sql.SQL("""JOIN epm.coordinate c ON c.workspace_id=n.workspace_id
        AND c.application_id=n.application_id AND c.coordinate_id=n.coordinate_id
        JOIN {} ON true""").format(summary)
    return join, sql.SQL(" AND {}").format(allowed), [], allowed
