"""Trusted PostgreSQL input resolver for dimensional authorization.

The public language, MCP clients, Python programs, and fact payloads never
provide layout, tags, assignments, revisions, or administrator status to this
resolver.  It obtains all of them inside the current READ COMMITTED database
transaction and passes only server-resolved values to the pure policy contract.

The active-policy path re-runs this resolver immediately before publication
under the existing security fence.  Effective assignments are the deterministic
union of the verified user principal and verified Keycloak group principals;
clients never submit an authoritative group list.
"""
from __future__ import annotations

from dataclasses import dataclass
from psycopg.types.json import Jsonb

from .dimensional_security_policy import (
    AccessKind, CoordinateSecurityDecision, DimensionalSecurityPolicy,
    HierarchyTags, MixedSelection, ResolvedMemberSecurity,
    dimensional_security_policy_digest, evaluate_coordinate,
)
from .postgres_dimensional_security_policies import policy_from_values
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_processing_limits import configure_statement_timeout


@dataclass(frozen=True, slots=True)
class DimensionalAuthorization:
    decision: CoordinateSecurityDecision
    metadata_revision: int
    security_revision: int
    schema_epoch: int
    dimensions: tuple[str, ...]
    policy_state_token: str | None = None
    policy_digest: str | None = None
    mixed_selection: MixedSelection | None = None


class PostgresDimensionalSecurityResolver:
    """Resolve one exact coordinate from authoritative current state."""

    @staticmethod
    def resolve_active_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind,
            coordinate: dict[str, str]) -> DimensionalAuthorization | None:
        """Resolve the explicitly active policy, or return unrestricted.

        The absence of an active pointer preserves existing application
        behavior.  A pointer is never treated as valid without reconstituting
        every typed choice and verifying its canonical scoped digest.  The
        shared workspace fence prevents activation from changing between this
        lookup and the coordinate resolution below.
        """
        if (not isinstance(identity, VerifiedIdentity)
                or not isinstance(scope, ApplicationScope)
                or not isinstance(kind, AccessKind)
                or type(coordinate) is not dict):
            raise ValueError("Trusted dimensional-security inputs are required")
        configure_statement_timeout(db, 5000)
        db.execute("SELECT set_config('epm.workspace_id',%s,true),"
                   "set_config('epm.application_id',%s,true)",
                   (scope.workspace_id, scope.application_id))
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        row = db.execute('''SELECT s.security_revision,p.state_token,
                p.policy_digest,p.across_dimensions,p.within_dimension,
                p.untagged_member,p.untagged_deny_precedence,
                p.member_tag_cardinality,p.hierarchy_tags,
                p.write_read_relationship,p.mixed_selection,
                p.administrator_treatment,p.fact_side_authority
            FROM epm.application_state s
            LEFT JOIN epm.dimensional_security_policy_definition p
              ON p.workspace_id=s.workspace_id
             AND p.application_id=s.application_id
             AND p.status='Active'
            WHERE s.workspace_id=%s AND s.application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_UNAVAILABLE")
        token = row["state_token"]
        if token is None:
            return None
        if row["policy_digest"] is None:
            raise ValueError("DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT")
        policy = policy_from_values({
            "acrossDimensions": row["across_dimensions"],
            "withinDimension": row["within_dimension"],
            "untaggedMember": row["untagged_member"],
            "untaggedDenyPrecedence": row["untagged_deny_precedence"],
            "memberTagCardinality": row["member_tag_cardinality"],
            "hierarchyTags": row["hierarchy_tags"],
            "writeReadRelationship": row["write_read_relationship"],
            "mixedSelection": row["mixed_selection"],
            "administratorTreatment": row["administrator_treatment"],
            "factSideAuthority": row["fact_side_authority"],
        })
        expected_digest = dimensional_security_policy_digest(
            scope.workspace_id, scope.application_id, policy)
        if row["policy_digest"] != expected_digest:
            raise ValueError("DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT")
        resolved = PostgresDimensionalSecurityResolver.resolve_in_transaction(
            db, identity, scope, kind=kind, coordinate=coordinate,
            policy=policy)
        if resolved.security_revision != row["security_revision"]:
            raise ValueError("DIMENSIONAL_SECURITY_REVISION_CHANGED")
        return DimensionalAuthorization(
            decision=resolved.decision,
            metadata_revision=resolved.metadata_revision,
            security_revision=resolved.security_revision,
            schema_epoch=resolved.schema_epoch,
            dimensions=resolved.dimensions,
            policy_state_token=token,
            policy_digest=expected_digest,
            mixed_selection=policy.mixed_selection)

    @staticmethod
    def resolve_many_active_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind, coordinates: tuple[dict[str, str], ...]
            ) -> tuple[DimensionalAuthorization, ...] | None:
        """Resolve a bounded coordinate collection from one current snapshot.

        Relation-backed rules routinely authorize hundreds of coordinates.
        Re-reading the active policy, grant assignments, layout and member tags
        once per coordinate makes security work dominate the calculation.  The
        workspace fence protects one policy snapshot while the fixed core loads
        the shared inputs once and evaluates each exact coordinate locally.
        """
        if (not isinstance(identity, VerifiedIdentity)
                or not isinstance(scope, ApplicationScope)
                or not isinstance(kind, AccessKind)
                or not isinstance(coordinates, tuple)
                or len(coordinates) > 1000
                or any(type(coordinate) is not dict for coordinate in coordinates)):
            raise ValueError("Trusted dimensional-security inputs are required")
        if not coordinates:
            return ()
        configure_statement_timeout(db, 5000)
        db.execute("SELECT set_config('epm.workspace_id',%s,true),"
                   "set_config('epm.application_id',%s,true)",
                   (scope.workspace_id, scope.application_id))
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        row = db.execute('''SELECT s.security_revision,p.state_token,
                p.policy_digest,p.across_dimensions,p.within_dimension,
                p.untagged_member,p.untagged_deny_precedence,
                p.member_tag_cardinality,p.hierarchy_tags,
                p.write_read_relationship,p.mixed_selection,
                p.administrator_treatment,p.fact_side_authority
            FROM epm.application_state s
            LEFT JOIN epm.dimensional_security_policy_definition p
              ON p.workspace_id=s.workspace_id
             AND p.application_id=s.application_id AND p.status='Active'
            WHERE s.workspace_id=%s AND s.application_id=%s''',
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_UNAVAILABLE")
        if row["state_token"] is None:
            return None
        policy = policy_from_values({
            "acrossDimensions": row["across_dimensions"],
            "withinDimension": row["within_dimension"],
            "untaggedMember": row["untagged_member"],
            "untaggedDenyPrecedence": row["untagged_deny_precedence"],
            "memberTagCardinality": row["member_tag_cardinality"],
            "hierarchyTags": row["hierarchy_tags"],
            "writeReadRelationship": row["write_read_relationship"],
            "mixedSelection": row["mixed_selection"],
            "administratorTreatment": row["administrator_treatment"],
            "factSideAuthority": row["fact_side_authority"],
        })
        digest = dimensional_security_policy_digest(
            scope.workspace_id, scope.application_id, policy)
        if row["policy_digest"] != digest:
            raise ValueError("DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT")
        resolved = PostgresDimensionalSecurityResolver.resolve_many_in_transaction(
            db, identity, scope, kind=kind, coordinates=coordinates,
            policy=policy)
        if any(item.security_revision != row["security_revision"]
               for item in resolved):
            raise ValueError("DIMENSIONAL_SECURITY_REVISION_CHANGED")
        return tuple(DimensionalAuthorization(
            decision=item.decision,
            metadata_revision=item.metadata_revision,
            security_revision=item.security_revision,
            schema_epoch=item.schema_epoch,
            dimensions=item.dimensions,
            policy_state_token=row["state_token"],
            policy_digest=digest,
            mixed_selection=policy.mixed_selection) for item in resolved)

    @staticmethod
    def resolve_many_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind, coordinates: tuple[dict[str, str], ...],
            policy: DimensionalSecurityPolicy
            ) -> tuple[DimensionalAuthorization, ...]:
        if (not isinstance(identity, VerifiedIdentity)
                or not isinstance(scope, ApplicationScope)
                or not isinstance(kind, AccessKind)
                or not isinstance(policy, DimensionalSecurityPolicy)
                or not isinstance(coordinates, tuple)
                or not 1 <= len(coordinates) <= 1000
                or any(type(coordinate) is not dict or any(
                    not isinstance(dimension_id, str) or not dimension_id
                    or not isinstance(member_id, str) or not member_id
                    for dimension_id, member_id in coordinate.items())
                    for coordinate in coordinates)):
            raise ValueError("Trusted dimensional-security inputs are required")
        if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
            raise ValueError("DIMENSIONAL_HIERARCHY_POLICY_NOT_INTEGRATED")
        access = PostgresAccessChecker.check_in_transaction(
            db, identity, scope,
            "read" if kind is AccessKind.READ else "write")
        requested = sorted({(dimension_id, member_id)
            for coordinate in coordinates
            for dimension_id, member_id in coordinate.items()})
        state = db.execute('''WITH effective_grants AS (
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
                SELECT assignment.key dimension_id,
                  jsonb_agg(DISTINCT tag.value ORDER BY tag.value) tags
                FROM effective_grants grant_row CROSS JOIN LATERAL
                  jsonb_each(grant_row.read_security_tags) assignment
                CROSS JOIN LATERAL
                  jsonb_array_elements_text(assignment.value) tag(value)
                GROUP BY assignment.key
            ), write_by_dimension AS (
                SELECT assignment.key dimension_id,
                  jsonb_agg(DISTINCT tag.value ORDER BY tag.value) tags
                FROM effective_grants grant_row CROSS JOIN LATERAL
                  jsonb_each(grant_row.write_security_tags) assignment
                CROSS JOIN LATERAL
                  jsonb_array_elements_text(assignment.value) tag(value)
                GROUP BY assignment.key
            )
            SELECT s.metadata_revision,s.security_revision,s.schema_epoch,
              l.dimensions,
              coalesce((SELECT jsonb_object_agg(dimension_id,tags
                ORDER BY dimension_id COLLATE "C") FROM read_by_dimension),
                '{}'::jsonb) assigned_read_tags,
              coalesce((SELECT jsonb_object_agg(dimension_id,tags
                ORDER BY dimension_id COLLATE "C") FROM write_by_dimension),
                '{}'::jsonb) assigned_write_tags,
              coalesce((SELECT jsonb_agg(jsonb_build_object(
                'dimension_id',requested.dimension_id,
                'member_id',requested.member_id,
                'read_security_tags',m.read_security_tags,
                'write_security_tags',m.write_security_tags)
                ORDER BY requested.dimension_id COLLATE "C",
                  requested.member_id COLLATE "C")
                FROM jsonb_to_recordset(%s::jsonb)
                  requested(dimension_id text,member_id text)
                LEFT JOIN epm.member m ON m.workspace_id=s.workspace_id
                 AND m.application_id=s.application_id
                 AND m.dimension_id=requested.dimension_id
                 AND m.member_id=requested.member_id AND m.status='Active'),
                '[]'::jsonb) requested_members
            FROM epm.application_state s JOIN epm.coordinate_layout l
              ON l.workspace_id=s.workspace_id
             AND l.application_id=s.application_id
             AND l.schema_epoch=s.schema_epoch
            WHERE s.workspace_id=%s AND s.application_id=%s''',(
            scope.workspace_id,scope.application_id,identity.issuer,
            identity.subject_id,scope.workspace_id,scope.application_id,
            identity.issuer,list(access.groups),Jsonb([
                {"dimension_id":dimension_id,"member_id":member_id}
                for dimension_id,member_id in requested]),
            scope.workspace_id,scope.application_id)).fetchone()
        if state is None:
            raise ValueError("APPLICATION_LAYOUT_UNAVAILABLE")
        dimensions=tuple(state["dimensions"])
        if any(tuple(sorted(coordinate)) != dimensions
               for coordinate in coordinates):
            raise ValueError("DIMENSIONAL_COORDINATE_LAYOUT_MISMATCH")
        rows=state["requested_members"]
        if (len(rows) != len(requested)
                or any(row["read_security_tags"] is None
                       or row["write_security_tags"] is None for row in rows)):
            raise ValueError("DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE")
        members={(row["dimension_id"],row["member_id"]):
            ResolvedMemberSecurity(row["dimension_id"],row["member_id"],
                tuple(row["read_security_tags"]),
                tuple(row["write_security_tags"])) for row in rows}
        return tuple(DimensionalAuthorization(
            decision=evaluate_coordinate(tuple(members[(dimension_id,
                coordinate[dimension_id])] for dimension_id in dimensions),
                kind=kind,expected_dimensions=dimensions,
                read_assignments=state["assigned_read_tags"],
                write_assignments=state["assigned_write_tags"],policy=policy,
                application_administrator=access.role=="Administrator",
                workspace_administrator=access.workspace_administrator),
            metadata_revision=state["metadata_revision"],
            security_revision=state["security_revision"],
            schema_epoch=state["schema_epoch"],dimensions=dimensions)
            for coordinate in coordinates)

    @staticmethod
    def resolve_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind, coordinate: dict[str, str],
            policy: DimensionalSecurityPolicy) -> DimensionalAuthorization:
        if (not isinstance(identity, VerifiedIdentity)
                or not isinstance(scope, ApplicationScope)
                or not isinstance(kind, AccessKind)
                or not isinstance(policy, DimensionalSecurityPolicy)
                or type(coordinate) is not dict
                or any(not isinstance(dimension_id, str) or not dimension_id
                       or not isinstance(member_id, str) or not member_id
                       for dimension_id, member_id in coordinate.items())):
            raise ValueError("Trusted dimensional-security inputs are required")
        if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
            raise ValueError("DIMENSIONAL_HIERARCHY_POLICY_NOT_INTEGRATED")

        configure_statement_timeout(db, 5000)
        db.execute("SELECT set_config('epm.workspace_id',%s,true),"
                   "set_config('epm.application_id',%s,true)",
                   (scope.workspace_id, scope.application_id))
        access = PostgresAccessChecker.check_in_transaction(
            db, identity, scope,
            "read" if kind is AccessKind.READ else "write")
        requested = [{"dimension_id": dimension_id,
                      "member_id": member_id}
                     for dimension_id, member_id in coordinate.items()]
        state = db.execute('''WITH effective_grants AS (
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
                CROSS JOIN LATERAL
                    jsonb_each(grant_row.read_security_tags) assignment
                CROSS JOIN LATERAL
                    jsonb_array_elements_text(assignment.value) tag(value)
                GROUP BY assignment.key
            ), write_by_dimension AS (
                SELECT assignment.key AS dimension_id,
                       jsonb_agg(DISTINCT tag.value ORDER BY tag.value) AS tags
                FROM effective_grants grant_row
                CROSS JOIN LATERAL
                    jsonb_each(grant_row.write_security_tags) assignment
                CROSS JOIN LATERAL
                    jsonb_array_elements_text(assignment.value) tag(value)
                GROUP BY assignment.key
            )
            SELECT s.metadata_revision,s.security_revision,
                s.schema_epoch,l.dimensions,
                coalesce((SELECT jsonb_object_agg(
                    dimension_id,tags ORDER BY dimension_id COLLATE "C")
                    FROM read_by_dimension),'{}'::jsonb)
                    AS assigned_read_tags,
                coalesce((SELECT jsonb_object_agg(
                    dimension_id,tags ORDER BY dimension_id COLLATE "C")
                    FROM write_by_dimension),'{}'::jsonb)
                    AS assigned_write_tags,
                coalesce((SELECT jsonb_agg(jsonb_build_object(
                    'dimension_id',requested.dimension_id,
                    'member_id',requested.member_id,
                    'read_security_tags',m.read_security_tags,
                    'write_security_tags',m.write_security_tags)
                    ORDER BY requested.dimension_id COLLATE "C")
                  FROM jsonb_to_recordset(%s::jsonb)
                    AS requested(dimension_id text,member_id text)
                  LEFT JOIN epm.member m ON m.workspace_id=s.workspace_id
                   AND m.application_id=s.application_id
                   AND m.dimension_id=requested.dimension_id
                   AND m.member_id=requested.member_id
                   AND m.status='Active'),'[]'::jsonb) AS requested_members
            FROM epm.application_state s
            JOIN epm.coordinate_layout l ON l.workspace_id=s.workspace_id
             AND l.application_id=s.application_id
             AND l.schema_epoch=s.schema_epoch
            WHERE s.workspace_id=%s AND s.application_id=%s''',
            (scope.workspace_id, scope.application_id, identity.issuer,
             identity.subject_id, scope.workspace_id, scope.application_id,
             identity.issuer, list(access.groups), Jsonb(requested),
             scope.workspace_id, scope.application_id)).fetchone()
        if state is None:
            raise ValueError("APPLICATION_LAYOUT_UNAVAILABLE")
        dimensions = tuple(state["dimensions"])
        if tuple(sorted(coordinate)) != dimensions:
            raise ValueError("DIMENSIONAL_COORDINATE_LAYOUT_MISMATCH")

        rows = state["requested_members"]
        if (len(rows) != len(dimensions)
                or any(row["read_security_tags"] is None
                       or row["write_security_tags"] is None for row in rows)
                or tuple(row["dimension_id"] for row in rows) != dimensions):
            raise ValueError("DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE")

        read_assignments = state["assigned_read_tags"]
        write_assignments = state["assigned_write_tags"]
        members = tuple(ResolvedMemberSecurity(
            row["dimension_id"], row["member_id"],
            tuple(row["read_security_tags"]),
            tuple(row["write_security_tags"])) for row in rows)
        decision = evaluate_coordinate(
            members, kind=kind, expected_dimensions=dimensions,
            read_assignments=read_assignments,
            write_assignments=write_assignments, policy=policy,
            application_administrator=access.role == "Administrator",
            workspace_administrator=access.workspace_administrator)
        return DimensionalAuthorization(
            decision=decision,
            metadata_revision=state["metadata_revision"],
            security_revision=state["security_revision"],
            schema_epoch=state["schema_epoch"], dimensions=dimensions)
