"""Current effective dimensional authorization scope for set-oriented reads.

The digest produced here is server-derived.  It binds durable analytical
results to the effective direct-plus-current-Keycloak-group authorization
scope without trusting a caller-authored group list or caching business truth.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256

from .dimensional_security_policy import (
    AdministratorTreatment, DimensionalSecurityPolicy,
    dimensional_security_policy_digest)
from .persistence_contract import ApplicationScope
from .postgres_access import AccessDecision, PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security_policies import policy_from_values


def _canonical_digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


@dataclass(frozen=True, slots=True)
class EffectiveDimensionalScope:
    access: AccessDecision
    policy: DimensionalSecurityPolicy | None
    policy_state_token: str | None
    policy_digest: str | None
    read_assignments: dict
    write_assignments: dict
    scope_digest: str

    @property
    def administrator_bypass(self) -> bool:
        return bool(self.policy is not None
            and self.policy.administrator_treatment
                is AdministratorTreatment.BYPASS
            and (self.access.workspace_administrator
                 or self.access.role == "Administrator"))


def resolve_effective_dimensional_scope(db, identity: VerifiedIdentity,
        scope: ApplicationScope, *, access: AccessDecision | None = None,
        function: str | None = None) -> EffectiveDimensionalScope:
    """Resolve the current direct-plus-group dimensional authorization scope.

    Callers must use a READ COMMITTED transaction.  The shared access checker
    both validates the current Keycloak-derived membership projection and
    establishes the workspace security fence before assignments are read.
    """
    if not isinstance(identity, VerifiedIdentity) or not isinstance(
            scope, ApplicationScope):
        raise ValueError("Trusted dimensional-scope inputs are required")
    if access is None:
        access = PostgresAccessChecker.check_in_transaction(
            db, identity, scope, "read", function=function)
    elif not isinstance(access, AccessDecision):
        raise ValueError("Trusted dimensional-scope access is required")
    row = db.execute('''WITH effective_grants AS (
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
        SELECT p.state_token AS policy_state_token,
            p.policy_digest,p.across_dimensions,p.within_dimension,
            p.untagged_member,p.untagged_deny_precedence,
            p.member_tag_cardinality,p.hierarchy_tags,
            p.write_read_relationship,p.mixed_selection,
            p.administrator_treatment,p.fact_side_authority,
            coalesce((SELECT jsonb_object_agg(dimension_id,tags
                ORDER BY dimension_id COLLATE "C") FROM read_by_dimension),
                '{}'::jsonb) AS read_assignments,
            coalesce((SELECT jsonb_object_agg(dimension_id,tags
                ORDER BY dimension_id COLLATE "C") FROM write_by_dimension),
                '{}'::jsonb) AS write_assignments
        FROM epm.application_state s
        LEFT JOIN epm.dimensional_security_policy_definition p
          ON p.workspace_id=s.workspace_id
         AND p.application_id=s.application_id
         AND p.status='Active'
        WHERE s.workspace_id=%s AND s.application_id=%s''',
        (scope.workspace_id, scope.application_id, identity.issuer,
         identity.subject_id, scope.workspace_id, scope.application_id,
         identity.issuer, list(access.groups), scope.workspace_id,
         scope.application_id)).fetchone()
    if row is None:
        raise ValueError("APPLICATION_UNAVAILABLE")
    token = row["policy_state_token"]
    policy = None
    policy_digest = None
    if token is not None:
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
        policy_digest = dimensional_security_policy_digest(
            scope.workspace_id, scope.application_id, policy)
        if row["policy_digest"] != policy_digest:
            raise ValueError("DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT")
    read_assignments = row["read_assignments"]
    write_assignments = row["write_assignments"]
    digest = _canonical_digest({
        "format": "openepm-effective-dimensional-scope-v1",
        "policyStateToken": token,
        "policyDigest": policy_digest,
        "readAssignments": read_assignments,
        "writeAssignments": write_assignments,
        "applicationRole": access.role,
        "workspaceAdministrator": access.workspace_administrator,
    })
    return EffectiveDimensionalScope(access, policy, token, policy_digest,
        read_assignments, write_assignments, digest)
