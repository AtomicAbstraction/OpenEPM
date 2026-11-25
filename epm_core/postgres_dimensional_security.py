"""Trusted PostgreSQL input resolver for dimensional authorization.

The public language, MCP clients, Python programs, and fact payloads never
provide layout, tags, assignments, revisions, or administrator status to this
resolver.  It obtains all of them inside the current READ COMMITTED database
transaction and passes only server-resolved values to the pure policy contract.

The active-policy path re-runs this resolver immediately before publication
under the existing security fence.  Effective assignments are the deterministic
union for legacy applications or complete group assignments for migrated applications;
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
from .dimensional_privileges import (
    legacy_dimensional_ctes, read_dimensional_privileges, require_assignment_policy,
)
from .postgres_dimensional_security_policies import policy_from_values
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDecision, PostgresAccessChecker, VerifiedIdentity
from .postgres_processing_limits import configure_statement_timeout


CUBE_READ_AUTHORIZATION_STALE = 'CUBE_READ_AUTHORIZATION_STALE'


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
    workflow_duties: tuple[str, ...] = ()


class PostgresDimensionalSecurityResolver:
    """Resolve one exact coordinate from authoritative current state."""

    @staticmethod
    def active_policy_in_transaction(db, identity: VerifiedIdentity,
                                     scope: ApplicationScope):
        """Return the verified current policy snapshot, or unrestricted absence.

        Explanation readers sometimes have no complete source coordinate to
        authorize. They may distinguish policy absence through this same owner
        and workspace fence, never by inventing a coordinate or duplicating
        policy lookup/validation. The caller's transaction retains the fence.
        """
        if (not isinstance(identity, VerifiedIdentity)
                or not isinstance(scope, ApplicationScope)):
            raise ValueError("Trusted dimensional-security inputs are required")
        configure_statement_timeout(db, 5000)
        db.execute("SELECT set_config('epm.workspace_id',%s,true),"
                   "set_config('epm.application_id',%s,true)",
                   (scope.workspace_id, scope.application_id))
        PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
        row = db.execute('''SELECT s.security_revision,a.authorization_model,p.state_token,
                p.policy_digest,p.across_dimensions,p.within_dimension,
                p.untagged_member,p.untagged_deny_precedence,
                p.member_tag_cardinality,p.hierarchy_tags,
                p.write_read_relationship,p.mixed_selection,
                p.administrator_treatment,p.fact_side_authority
            FROM epm.application_state s
            JOIN epm.application a USING (workspace_id,application_id)
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
            if row.get("authorization_model") == "group_assignments":
                require_assignment_policy(None)
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
        if row.get("authorization_model") == "group_assignments":
            require_assignment_policy(policy)
        return policy, token, expected_digest, row["security_revision"]

    @staticmethod
    def resolve_active_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind,
            coordinate: dict[str, str],
            expected_access: AccessDecision | None = None) -> DimensionalAuthorization | None:
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
        active = PostgresDimensionalSecurityResolver.active_policy_in_transaction(
            db, identity, scope)
        if active is None:
            return None
        policy, token, expected_digest, security_revision = active
        resolved = PostgresDimensionalSecurityResolver.resolve_in_transaction(
            db, identity, scope, kind=kind, coordinate=coordinate,
            policy=policy, expected_access=expected_access)
        if resolved.security_revision != security_revision:
            raise ValueError("DIMENSIONAL_SECURITY_REVISION_CHANGED")
        return DimensionalAuthorization(
            decision=resolved.decision,
            metadata_revision=resolved.metadata_revision,
            security_revision=resolved.security_revision,
            schema_epoch=resolved.schema_epoch,
            dimensions=resolved.dimensions,
            policy_state_token=token,
            policy_digest=expected_digest,
            mixed_selection=policy.mixed_selection, workflow_duties=resolved.workflow_duties)

    @staticmethod
    def resolve_many_active_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind, coordinates: tuple[dict[str, str], ...],
            expected_access: AccessDecision | None = None,
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
        active = PostgresDimensionalSecurityResolver.active_policy_in_transaction(
            db, identity, scope)
        if active is None:
            return None
        policy, token, digest, security_revision = active
        resolved = PostgresDimensionalSecurityResolver.resolve_many_in_transaction(
            db, identity, scope, kind=kind, coordinates=coordinates,
            policy=policy, expected_access=expected_access)
        if any(item.security_revision != security_revision
               for item in resolved):
            raise ValueError("DIMENSIONAL_SECURITY_REVISION_CHANGED")
        return tuple(DimensionalAuthorization(
            decision=item.decision,
            metadata_revision=item.metadata_revision,
            security_revision=item.security_revision,
            schema_epoch=item.schema_epoch,
            dimensions=item.dimensions,
            policy_state_token=token,
            policy_digest=digest,
            mixed_selection=policy.mixed_selection, workflow_duties=item.workflow_duties) for item in resolved)

    @staticmethod
    def resolve_many_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind, coordinates: tuple[dict[str, str], ...],
            policy: DimensionalSecurityPolicy,
            expected_access: AccessDecision | None = None,
            deny_unavailable_points: bool = False,
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
            "read" if kind is AccessKind.READ else "write",
            action="facts.read" if kind is AccessKind.READ else "facts.write")
        # A pinned reader compares the decision this batch will actually use.
        # A final group check alone would miss a temporary directory change.
        if expected_access is not None and access != expected_access:
            raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
        requested = sorted({(dimension_id, member_id)
            for coordinate in coordinates
            for dimension_id, member_id in coordinate.items()})
        ctes, grant_parameters = legacy_dimensional_ctes(access, scope, identity)
        state = db.execute(ctes + '''
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
            *grant_parameters, Jsonb([
                {"dimension_id":dimension_id,"member_id":member_id}
                for dimension_id,member_id in requested]),
            scope.workspace_id,scope.application_id)).fetchone()
        if state is None:
            raise ValueError("APPLICATION_LAYOUT_UNAVAILABLE")
        dimensions=tuple(state["dimensions"])
        if not deny_unavailable_points and any(tuple(sorted(coordinate)) != dimensions
               for coordinate in coordinates):
            raise ValueError("DIMENSIONAL_COORDINATE_LAYOUT_MISMATCH")
        rows=state["requested_members"]
        if not deny_unavailable_points and (len(rows) != len(requested)
                or any(row["read_security_tags"] is None
                       or row["write_security_tags"] is None for row in rows)):
            raise ValueError("DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE")
        members={(row["dimension_id"],row["member_id"]):
            ResolvedMemberSecurity(row["dimension_id"],row["member_id"],
                tuple(row["read_security_tags"]),
                tuple(row["write_security_tags"])) for row in rows
                if row["read_security_tags"] is not None and row["write_security_tags"] is not None}
        privileges = None
        if access.authorization_model == "group_assignments":
            require_assignment_policy(policy)
            privileges = read_dimensional_privileges(db, scope, identity, access.groups)

        def decide(coordinate):
            duties = ()
            if deny_unavailable_points and (tuple(sorted(coordinate)) != dimensions
                    or any(pair not in members for pair in coordinate.items())):
                decision = CoordinateSecurityDecision(False, 'DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE', dimensions, ())
            else:
                point = tuple(members[(axis, coordinate[axis])] for axis in dimensions)
                if privileges is None:
                    decision = evaluate_coordinate(point, kind=kind, expected_dimensions=dimensions,
                        read_assignments=state["assigned_read_tags"], write_assignments=state["assigned_write_tags"],
                        policy=policy, application_administrator=access.role == "Administrator",
                        workspace_administrator=access.workspace_administrator)
                else:
                    try:
                        decision, duties = privileges.coordinate_decision_and_duties(point, kind, dimensions, policy)
                    except ValueError as exc:
                        if not deny_unavailable_points or str(exc) != 'MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION':
                            raise
                        decision = CoordinateSecurityDecision(False, str(exc), dimensions, ())
            return DimensionalAuthorization(decision=decision, workflow_duties=duties,
                metadata_revision=state["metadata_revision"], security_revision=state["security_revision"],
                schema_epoch=state["schema_epoch"], dimensions=dimensions)

        return tuple(decide(coordinate) for coordinate in coordinates)

    @staticmethod
    def resolve_in_transaction(
            db, identity: VerifiedIdentity, scope: ApplicationScope, *,
            kind: AccessKind, coordinate: dict[str, str],
            policy: DimensionalSecurityPolicy,
            expected_access: AccessDecision | None = None) -> DimensionalAuthorization:
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
        return PostgresDimensionalSecurityResolver.resolve_many_in_transaction(
            db, identity, scope, kind=kind, coordinates=(coordinate,),
            policy=policy, expected_access=expected_access)[0]
