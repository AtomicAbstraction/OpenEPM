"""Current effective dimensional authorization scope for set-oriented reads.

The digest produced here is server-derived.  It binds durable analytical
results to the effective direct-plus-current-Keycloak-group authorization
scope without trusting a caller-authored group list or caching business truth.
"""
from __future__ import annotations

import json
import hmac
import re
import time
from dataclasses import dataclass
from hashlib import sha256
from psycopg import sql
from psycopg.types.json import Jsonb

from .dimensional_privileges import (
    DimensionalPrivileges, legacy_dimensional_ctes, metadata_privilege_sql, read_dimensional_privileges,
    require_assignment_policy,
)
from .dimensional_security_policy import (
    AccessKind, AdministratorTreatment, DimensionalSecurityPolicy, HierarchyTags,
    MemberTagCardinality, MixedSelection, ResolvedMemberSecurity, UntaggedMember,
    WithinDimension, dimensional_security_policy_digest, evaluate_coordinate)
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
    privileges: DimensionalPrivileges | None = None

    @property
    def administrator_bypass(self) -> bool:
        return bool(self.privileges is None and self.policy is not None
            and self.policy.administrator_treatment
                is AdministratorTreatment.BYPASS
            and (self.access.workspace_administrator
                 or self.access.role == "Administrator"))


def metadata_reference_read_allowed(authority: EffectiveDimensionalScope,
                                    reference: ResolvedMemberSecurity) -> bool:
    """Evaluate a single typed metadata reference under the active read policy."""
    if authority.policy is None:
        return True
    if getattr(authority, 'privileges', None) is not None:
        return authority.privileges.permits((reference,), 'metadata.browse', authority.policy)
    return evaluate_coordinate((reference,), kind=AccessKind.READ,
        expected_dimensions=(reference.dimension_id,), policy=authority.policy,
        read_assignments=authority.read_assignments, write_assignments=authority.write_assignments,
        application_administrator=authority.access.role == 'Administrator',
        workspace_administrator=authority.access.workspace_administrator).allowed


def metadata_reference_read_sql(authority: EffectiveDimensionalScope,
                                alias: str, dimension: str | None = None) -> sql.Composable:
    """Project the single-reference READ decision over a fixed metadata query."""
    policy = authority.policy
    if policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
        raise ValueError('DIMENSIONAL_SECURITY_HIERARCHY_POLICY_NOT_ACTIVATABLE')
    tags = sql.Identifier(alias, 'read_security_tags')
    if getattr(authority, 'privileges', None) is not None:
        axis = sql.Literal(dimension) if dimension is not None else sql.Identifier(alias, 'dimension_id')
        return metadata_privilege_sql(authority.privileges, policy, axis, tags)
    if dimension is None:
        assigned = sql.SQL("""ARRAY(SELECT jsonb_array_elements_text(
            coalesce({}::jsonb->{}.dimension_id,'[]'::jsonb)))""").format(
                sql.Literal(Jsonb(authority.read_assignments)), sql.Identifier(alias))
    else:
        assigned = sql.SQL('{}::text[]').format(
            sql.Literal(authority.read_assignments.get(dimension, [])))
    operator = sql.SQL('&&' if policy.within_dimension is WithinDimension.ANY_TAG else '<@')
    cardinality = (sql.SQL(' AND cardinality({})<=1').format(tags)
                   if policy.member_tag_cardinality is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                   else sql.SQL(''))
    return sql.SQL("""((CASE WHEN cardinality({tags})=0 THEN {untagged}
                            ELSE {tags} {operator} {assigned} END){cardinality})""").format(
        tags=tags, untagged=sql.Literal(policy.untagged_member is UntaggedMember.ALLOW),
        operator=operator, assigned=assigned, cardinality=cardinality)


def reject_mixed_metadata_reads(authority: EffectiveDimensionalScope) -> bool:
    return (authority.policy is not None and not authority.administrator_bypass
            and authority.policy.mixed_selection is MixedSelection.REJECT_ALL)


def metadata_relationship_read_sql(authority, alias: str, dimension: str | None = None) -> sql.Composable:
    """A placement is visible only with authority over the edge and both endpoints."""
    if authority.policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    root = sql.Identifier(alias)
    endpoint = sql.SQL('''EXISTS(SELECT 1 FROM epm.member e
        WHERE e.workspace_id={root}.workspace_id AND e.application_id={root}.application_id
          AND e.dimension_id={root}.dimension_id AND e.member_id={column} AND {visible})''')
    visible = metadata_reference_read_sql(authority, 'e', dimension)
    parent, child = (endpoint.format(root=root, column=sql.Identifier(alias, key), visible=visible)
                     for key in ('parent_member_id', 'child_member_id'))
    return sql.SQL('({} AND {} AND {})').format(
        metadata_reference_read_sql(authority, alias, dimension), parent, child)


def metadata_dimension_visible(db, scope, authority, dimension: str) -> bool:
    if authority.policy is None or authority.administrator_bypass:
        return True
    return db.execute(sql.SQL('''SELECT 1 FROM epm.dimension d
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.dimension_id=%s AND {}''').format(
            metadata_reference_read_sql(authority, 'd', dimension)),
        (scope.workspace_id, scope.application_id, dimension)).fetchone() is not None


def metadata_dimension_reference_read_sql(authority, alias: str, dimension) -> sql.Composable:
    if authority.policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    return sql.SQL('''EXISTS(SELECT 1 FROM epm.dimension linked_d
        WHERE linked_d.workspace_id={owner}.workspace_id
          AND linked_d.application_id={owner}.application_id
          AND linked_d.dimension_id={dimension} AND {visible})''').format(
            owner=sql.Identifier(alias), dimension=dimension,
            visible=metadata_reference_read_sql(authority, 'linked_d'))


def metadata_linked_member_read_sql(authority, alias: str, dimension, member) -> sql.Composable:
    """Compile a declared MemberReference within the row's own application."""
    if authority.policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    return sql.SQL('''EXISTS(SELECT 1 FROM epm.dimension linked_d JOIN epm.member linked_m
        USING (workspace_id,application_id,dimension_id)
        WHERE linked_d.workspace_id={owner}.workspace_id
          AND linked_d.application_id={owner}.application_id
          AND linked_d.dimension_id={dimension} AND linked_m.member_id={member}
          AND {dimension_access} AND {member_access})''').format(
            owner=sql.Identifier(alias), dimension=dimension, member=member,
            dimension_access=metadata_reference_read_sql(authority, 'linked_d'),
            member_access=metadata_reference_read_sql(authority, 'linked_m'))


def metadata_expression_visible_sql(authority, alias, dimension, expression) -> sql.Composable:
    """Check typed literals in the complete canonical definition without evaluating it."""
    if authority is None or authority.policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    source = sql.SQL('''SELECT a.validation_constraints->>'referenceDimensionId' AS dimension_id
        FROM epm.attribute_definition a
        WHERE a.workspace_id={owner}.workspace_id AND a.application_id={owner}.application_id
          AND a.dimension_id={axis} AND a.scope='Member'
          AND a.attribute_id=n.node->>'attributeId' AND a.value_type='MemberReference'
        UNION ALL
        SELECT c.properties->>'referenceDimensionId' AS dimension_id
        FROM epm.semantic_column c
        WHERE c.workspace_id={owner}.workspace_id AND c.application_id={owner}.application_id
          AND c.dimension_id={axis} AND c.scope='Member'
          AND (c.display_name=n.node->>'attributeId'
               OR ('Custom'||lpad(c.slot::text,2,'0'))=n.node->>'attributeId')
          AND c.properties->>'valueType'='MemberReference' ''').format(
            owner=sql.Identifier(alias), axis=dimension)
    return sql.SQL('''({dimension} AND jsonb_typeof({expression})='object'
         AND ({expression})->>'kind' IS NOT NULL
         AND NOT EXISTS (
            SELECT 1 FROM jsonb_path_query({expression},
                'strict $.** ? (@.type() == "object" && exists(@.kind))') n(node)
            WHERE CASE n.node->>'kind'
                WHEN 'explicit' THEN
                    jsonb_typeof(n.node->'memberIds') IS DISTINCT FROM 'array'
                    OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(n.node->'memberIds') ref(member_id)
                        WHERE NOT {explicit})
                WHEN 'navigation' THEN
                    (n.node#>>'{{anchor,memberId}}' IS NOT NULL AND NOT {anchor})
                    OR EXISTS (
                        SELECT 1 FROM jsonb_array_elements_text(CASE
                            WHEN jsonb_typeof(n.node#>'{{anchor,pathRelationshipIds}}')='array'
                            THEN n.node#>'{{anchor,pathRelationshipIds}}' ELSE '[]'::jsonb END) path(edge_id)
                        WHERE NOT EXISTS (SELECT 1 FROM epm.relationship r
                            WHERE r.workspace_id={owner}.workspace_id AND r.application_id={owner}.application_id
                              AND r.dimension_id={axis} AND r.relationship_id=path.edge_id AND {edge}))
                WHEN 'attribute' THEN EXISTS(
                    SELECT 1 FROM ({attribute_axes}) target
                    WHERE NOT {attribute_axis} OR (n.node->>'operator'<>'exists'
                        AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(CASE
                            WHEN jsonb_typeof(n.node->'value')='array' THEN n.node->'value'
                            ELSE jsonb_build_array(n.node->'value') END) ref(member_id)
                            WHERE ref.member_id IS NOT NULL AND NOT {attribute_member})))
                WHEN 'order' THEN EXISTS(
                    SELECT 1 FROM ({attribute_axes}) target WHERE NOT {attribute_axis})
                ELSE CASE WHEN n.node->>'kind' IN
                    ('children','parents','descendants','ancestors','siblings','leaves','base')
                    THEN NOT {hierarchy_member}
                    ELSE n.node->>'kind' NOT IN ('parameter','union','intersection','difference') END
            END))''').format(
        owner=sql.Identifier(alias), axis=dimension, expression=expression,
        dimension=metadata_dimension_reference_read_sql(authority, alias, dimension),
        explicit=metadata_linked_member_read_sql(authority, alias, dimension, sql.SQL('ref.member_id')),
        anchor=metadata_linked_member_read_sql(authority, alias, dimension, sql.SQL("n.node#>>'{anchor,memberId}'")),
        hierarchy_member=metadata_linked_member_read_sql(authority, alias, dimension, sql.SQL("n.node->>'memberId'")),
        edge=metadata_relationship_read_sql(authority, 'r'),
        attribute_axes=source,
        attribute_axis=metadata_dimension_reference_read_sql(authority, alias, sql.SQL('target.dimension_id')),
        attribute_member=metadata_linked_member_read_sql(authority, alias,
            sql.SQL('target.dimension_id'), sql.SQL('ref.member_id')))


def metadata_selection_visible_sql(authority, alias, selection) -> sql.Composable:
    """Check the typed references in both sides of a canonical cube selection."""
    if authority is None or authority.policy is None or authority.administrator_bypass:
        return sql.SQL('TRUE')
    from .postgres_member_lists import member_list_definition_visible_sql

    axis = sql.SQL("view_axis.axis->>'dimensionId'")
    expression = sql.SQL("""CASE view_selector.selector->>'kind'
        WHEN 'member' THEN jsonb_build_object('kind','explicit','memberIds',
                                              jsonb_build_array(view_selector.selector->'memberId'))
        WHEN 'members' THEN view_selector.selector || jsonb_build_object('kind','explicit')
        WHEN 'hierarchy' THEN view_selector.selector || jsonb_build_object('kind',view_selector.selector->'operator')
        WHEN 'attribute' THEN view_selector.selector
        WHEN 'inline_expression' THEN view_selector.selector->'expression'
        ELSE NULL END""")
    return sql.SQL("""(CASE WHEN jsonb_typeof(({selection})->'dimensions')='array'
        THEN jsonb_array_length(({selection})->'dimensions')>0 AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(({selection})->'dimensions') view_axis(axis)
            CROSS JOIN LATERAL (VALUES (view_axis.axis->'include'),(view_axis.axis->'exclude')) view_selector(selector)
            WHERE view_selector.selector IS DISTINCT FROM 'null'::jsonb
              AND (CASE WHEN view_selector.selector->>'kind'='member_list' THEN EXISTS (
                    SELECT 1 FROM epm.member_list_definition d
                    WHERE d.workspace_id={owner}.workspace_id AND d.application_id={owner}.application_id
                      AND d.dimension_id={axis} AND d.list_id=view_selector.selector->>'listId'
                      AND d.definition IS NOT NULL AND {named}
                      AND NOT EXISTS (
                          SELECT 1 FROM jsonb_each(view_selector.selector->'parameters') p(name,value)
                          WHERE NOT EXISTS (
                              SELECT 1 FROM jsonb_array_elements(d.definition->'parameters') t(declaration)
                              WHERE t.declaration->>'name'=p.name AND
                                  (t.declaration->>'type'<>'Member' OR {member_parameter})
                          )
                      )
                ) ELSE {expression_visible} END) IS DISTINCT FROM TRUE
        ) ELSE FALSE END)""").format(
        owner=sql.Identifier(alias), selection=selection, axis=axis,
        named=member_list_definition_visible_sql(authority),
        member_parameter=metadata_linked_member_read_sql(authority, alias, axis, sql.SQL("p.value#>>'{}'")),
        expression_visible=metadata_expression_visible_sql(authority, alias, axis, expression))


def metadata_visible_attributes_sql(authority, attribute_scope) -> sql.Composable:
    """Project unreadable linked members as absent before evaluating or displaying values."""
    if authority is None or authority.policy is None or authority.administrator_bypass:
        return sql.SQL('m.custom_values')
    return sql.SQL('''m.custom_values - ARRAY(
        SELECT linked.attribute_id FROM (
            SELECT a.attribute_id, a.validation_constraints->>'referenceDimensionId' AS dimension_id
            FROM epm.attribute_definition a
            WHERE a.workspace_id=m.workspace_id AND a.application_id=m.application_id
              AND a.dimension_id=m.dimension_id AND a.scope={scope}
              AND a.value_type='MemberReference'
            UNION ALL
            SELECT 'Custom'||lpad(c.slot::text,2,'0'), c.properties->>'referenceDimensionId'
            FROM epm.semantic_column c
            WHERE c.workspace_id=m.workspace_id AND c.application_id=m.application_id
              AND c.dimension_id=m.dimension_id AND c.scope={scope}
              AND c.properties->>'valueType'='MemberReference'
        ) linked
        WHERE m.custom_values ? linked.attribute_id AND NOT {target})''').format(
            scope=sql.Literal(attribute_scope),
            target=metadata_linked_member_read_sql(authority, 'm', sql.SQL('linked.dimension_id'),
                                                   sql.SQL('m.custom_values->>linked.attribute_id')))


def metadata_page_token(secret, context, after, *, expires=None):
    if secret is None:
        raise ValueError('METADATA_DIRECTORY_CURSOR_UNAVAILABLE')
    if expires is None:
        expires = int(time.time()) + 900
    payload = json.dumps(['openepm-directory-page-v1', context, after, expires],
                         separators=(',', ':'), ensure_ascii=True).encode()
    return f'{expires}.{hmac.new(secret, payload, sha256).hexdigest()}'


def require_metadata_page_token(authority, secret, context, after, token):
    if token is None:
        if after is not None and authority.policy is not None:
            raise ValueError('METADATA_DIRECTORY_CURSOR_REQUIRED')
        return
    if (authority.policy is None or after is None or not isinstance(token, str)
            or re.fullmatch(r'[0-9]{1,12}\.[0-9a-f]{64}', token) is None):
        raise ValueError('METADATA_DIRECTORY_CURSOR_STALE')
    expires = int(token.split('.', 1)[0])
    if expires <= time.time() or not hmac.compare_digest(
            token, metadata_page_token(secret, context, after, expires=expires)):
        raise ValueError('METADATA_DIRECTORY_CURSOR_STALE')


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
            db, identity, scope, "read", function=function,
            action="application.enter" if function is None else None)
    elif not isinstance(access, AccessDecision):
        raise ValueError("Trusted dimensional-scope access is required")
    ctes, grant_parameters = legacy_dimensional_ctes(access, scope, identity)
    row = db.execute(ctes + '''
        SELECT p.state_token AS policy_state_token,s.schema_epoch,s.metadata_revision,s.security_revision,
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
        (*grant_parameters, scope.workspace_id, scope.application_id)).fetchone()
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
    if access.authorization_model == 'group_assignments':
        require_assignment_policy(policy)
        privileges = read_dimensional_privileges(db, scope, identity, access.groups)
        digest = _canonical_digest({
            'format': 'openepm-effective-dimensional-scope-v2',
            'workspaceId': scope.workspace_id, 'applicationId': scope.application_id,
            'schemaEpoch': row['schema_epoch'], 'policyStateToken': token,
            'metadataRevision': row['metadata_revision'], 'securityRevision': row['security_revision'],
            'policyDigest': policy_digest, 'privileges': privileges.digest_input(),
        })
        return EffectiveDimensionalScope(access, policy, token, policy_digest, {}, {}, digest, privileges)
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
