"""Immutable dimensional-security policies and their explicit active pointer.

Saving a version has no authorization effect.  An administrator must separately
activate one exact integrity-checked version against the current security
revision.  Runtime enforcement consumes that pointer; it never guesses a
default or treats the newest draft as active.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .dimensional_security_policy import (
    AdministratorTreatment, AcrossDimensions, DimensionalSecurityPolicy,
    FactSideAuthority, HierarchyTags, MemberTagCardinality, MixedSelection,
    UntaggedDenyPrecedence, UntaggedMember, WithinDimension,
    WriteReadRelationship, dimensional_security_policy_digest)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def policy_from_values(values: dict[str, object]) -> DimensionalSecurityPolicy:
    """Construct the complete typed contract, rejecting unknown alternatives."""
    try:
        return DimensionalSecurityPolicy(
            across_dimensions=AcrossDimensions(values["acrossDimensions"]),
            within_dimension=WithinDimension(values["withinDimension"]),
            untagged_member=UntaggedMember(values["untaggedMember"]),
            untagged_deny_precedence=UntaggedDenyPrecedence(
                values["untaggedDenyPrecedence"]),
            member_tag_cardinality=MemberTagCardinality(
                values["memberTagCardinality"]),
            hierarchy_tags=HierarchyTags(values["hierarchyTags"]),
            write_read_relationship=WriteReadRelationship(
                values["writeReadRelationship"]),
            mixed_selection=MixedSelection(values["mixedSelection"]),
            administrator_treatment=AdministratorTreatment(
                values["administratorTreatment"]),
            fact_side_authority=FactSideAuthority(values["factSideAuthority"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("DIMENSIONAL_SECURITY_POLICY_INVALID") from exc


def policy_values(policy: DimensionalSecurityPolicy) -> dict[str, str]:
    return {
        "acrossDimensions": policy.across_dimensions.value,
        "withinDimension": policy.within_dimension.value,
        "untaggedMember": policy.untagged_member.value,
        "untaggedDenyPrecedence": policy.untagged_deny_precedence.value,
        "memberTagCardinality": policy.member_tag_cardinality.value,
        "hierarchyTags": policy.hierarchy_tags.value,
        "writeReadRelationship": policy.write_read_relationship.value,
        "mixedSelection": policy.mixed_selection.value,
        "administratorTreatment": policy.administrator_treatment.value,
        "factSideAuthority": policy.fact_side_authority.value,
    }


def validate_policy_activation_supported(
        policy: DimensionalSecurityPolicy) -> None:
    """Reject a saved policy whose runtime semantics are not implemented.

    Immutable drafts retain every typed alternative so a future migration can
    add hierarchy-effective semantics without reinterpreting old source.  An
    active pointer, however, must never select a policy the trusted resolver
    cannot execute.  Selected-member-only is the sole currently qualified
    hierarchy policy; no inheritance direction or shared-placement rule is
    inferred here.
    """
    if not isinstance(policy, DimensionalSecurityPolicy):
        raise ValueError("DIMENSIONAL_SECURITY_POLICY_INVALID")
    if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
        raise ValueError(
            "DIMENSIONAL_SECURITY_HIERARCHY_POLICY_NOT_ACTIVATABLE")


def _row_policy(row: dict) -> DimensionalSecurityPolicy:
    return policy_from_values({
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


class PostgresDimensionalSecurityPolicyStore:
    """Application-admin authoring API for inert immutable policy versions."""

    _COLUMNS = """policy_version,policy_digest,across_dimensions,
        within_dimension,untagged_member,untagged_deny_precedence,
        member_tag_cardinality,hierarchy_tags,write_read_relationship,
        mixed_selection,administrator_treatment,fact_side_authority,created_at"""

    def __init__(self, dsn: str):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL security-writer DSN is required")
        self.dsn = dsn

    @staticmethod
    def _scope(db, scope: ApplicationScope) -> None:
        db.execute("SELECT set_config('epm.workspace_id',%s,true)",
                   (scope.workspace_id,))
        db.execute("SELECT set_config('epm.application_id',%s,true)",
                   (scope.application_id,))

    @staticmethod
    def _verified(scope: ApplicationScope, row: dict, *,
                  active_version: int | None = None) -> dict:
        policy = _row_policy(row)
        expected = dimensional_security_policy_digest(
            scope.workspace_id, scope.application_id,
            row["policy_version"], policy)
        if row["policy_digest"] != expected:
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_CORRUPT")
        return {
            "policyVersion": row["policy_version"],
            "policyDigest": row["policy_digest"],
            "policy": policy_values(policy),
            "createdAt": row["created_at"].isoformat(),
            "authorizationEffect": row["policy_version"] == active_version,
        }

    def save(self, scope: ApplicationScope, *, actor: VerifiedIdentity,
             policy_version: int, policy: DimensionalSecurityPolicy,
             operation_id: str, command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or isinstance(policy_version, bool)
                or not isinstance(policy_version, int) or policy_version < 1
                or not isinstance(policy, DimensionalSecurityPolicy)
                or not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not _SHA256.fullmatch(command_digest)):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_SAVE_INVALID")
        values = policy_values(policy)
        payload = {
            "workspaceId": scope.workspace_id,
            "applicationId": scope.application_id,
            "actor": [actor.issuer, actor.subject_id],
            "policyVersion": policy_version,
            "policy": values,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        actor_digest = sha256(
            (actor.issuer + "\0" + actor.subject_id).encode("utf-8")).hexdigest()
        policy_digest = dimensional_security_policy_digest(
            scope.workspace_id, scope.application_id, policy_version, policy)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, "admin")
                previous = db.execute("""SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s""",
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous["command_digest"] != command_digest:
                        raise ValueError("IDEMPOTENCY_KEY_REUSED")
                    if previous["payload_digest"] != payload_digest:
                        raise ValueError("IDEMPOTENCY_PAYLOAD_CHANGED")
                    return previous["result"]
                state = db.execute("""SELECT security_revision,
                    active_dimensional_security_policy_version
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR SHARE""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                latest = db.execute("""SELECT max(policy_version) AS version
                    FROM epm.dimensional_security_policy_version
                    WHERE workspace_id=%s AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if policy_version != (latest["version"] or 0) + 1:
                    raise ValueError("DIMENSIONAL_SECURITY_POLICY_VERSION_NOT_NEXT")
                result = {
                    "workspaceId": scope.workspace_id,
                    "applicationId": scope.application_id,
                    "policyVersion": policy_version,
                    "policyDigest": policy_digest,
                    "securityRevision": state["security_revision"],
                    "authorizationEffect": False,
                    "status": "Saved",
                }
                db.execute("""INSERT INTO epm.dimensional_security_policy_version
                    (workspace_id,application_id,policy_version,policy_digest,
                     across_dimensions,within_dimension,untagged_member,
                     untagged_deny_precedence,member_tag_cardinality,
                     hierarchy_tags,write_read_relationship,mixed_selection,
                     administrator_treatment,fact_side_authority,
                     created_by_digest)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (scope.workspace_id, scope.application_id, policy_version,
                     policy_digest, values["acrossDimensions"],
                     values["withinDimension"], values["untaggedMember"],
                     values["untaggedDenyPrecedence"],
                     values["memberTagCardinality"], values["hierarchyTags"],
                     values["writeReadRelationship"], values["mixedSelection"],
                     values["administratorTreatment"],
                     values["factSideAuthority"], actor_digest))
                db.execute("""INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,'dimension-policy.version.save',%s)""",
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest, Jsonb(result)))
                db.execute("""INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,target_digest,
                     outcome,detail) VALUES (%s,'dimension-policy.version.save',
                     %s,%s,%s,'Accepted',%s)""",
                    (actor_digest, scope.workspace_id, scope.application_id,
                     policy_digest, Jsonb({"operationId": operation_id,
                                           "policyVersion": policy_version,
                                           "authorizationEffect": False})))
                return result

    def read(self, scope: ApplicationScope, *, actor: VerifiedIdentity,
             policy_version: int) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or isinstance(policy_version, bool)
                or not isinstance(policy_version, int) or policy_version < 1):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_READ_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, "admin")
                state = db.execute("""SELECT security_revision,
                    active_dimensional_security_policy_version
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                row = db.execute(f"""SELECT {self._COLUMNS}
                    FROM epm.dimensional_security_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND policy_version=%s""",
                    (scope.workspace_id, scope.application_id,
                     policy_version)).fetchone()
                if row is None:
                    raise ValueError("DIMENSIONAL_SECURITY_POLICY_VERSION_UNAVAILABLE")
                return {**self._verified(
                            scope, row,
                            active_version=state[
                                "active_dimensional_security_policy_version"]),
                        "securityRevision": state["security_revision"]}

    def list(self, scope: ApplicationScope, *, actor: VerifiedIdentity,
             after_version: int | None, limit: int) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or (after_version is not None and (
                    isinstance(after_version, bool)
                    or not isinstance(after_version, int)
                    or after_version < 0))
                or isinstance(limit, bool) or not isinstance(limit, int)
                or not 1 <= limit <= 100):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_LIST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, "admin")
                state = db.execute("""SELECT security_revision,
                    active_dimensional_security_policy_version
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                rows = db.execute(f"""SELECT {self._COLUMNS}
                    FROM epm.dimensional_security_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND (%s::bigint IS NULL OR policy_version>%s)
                    ORDER BY policy_version LIMIT %s""",
                    (scope.workspace_id, scope.application_id,
                     after_version, after_version, limit + 1)).fetchall()
                items = [self._verified(
                    scope, row,
                    active_version=state[
                        "active_dimensional_security_policy_version"])
                    for row in rows[:limit]]
                return {
                    "items": items,
                    "nextAfterVersion": (items[-1]["policyVersion"]
                                         if len(rows) > limit and items
                                         else None),
                    "securityRevision": state["security_revision"],
                    "activePolicyVersion": state[
                        "active_dimensional_security_policy_version"],
                    "authorizationEffect": state[
                        "active_dimensional_security_policy_version"] is not None,
                }

    def set_active(self, scope: ApplicationScope, *, actor: VerifiedIdentity,
                   policy_version: int | None,
                   expected_security_revision: int, operation_id: str,
                   command_digest: str) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)
                or (policy_version is not None and (
                    isinstance(policy_version, bool)
                    or not isinstance(policy_version, int)
                    or policy_version < 1))
                or isinstance(expected_security_revision, bool)
                or not isinstance(expected_security_revision, int)
                or expected_security_revision < 0
                or not isinstance(operation_id, str)
                or not 1 <= len(operation_id) <= 200
                or not isinstance(command_digest, str)
                or not _SHA256.fullmatch(command_digest)):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_ACTIVATION_INVALID")
        action = ("dimension-policy.activate" if policy_version is not None
                  else "dimension-policy.deactivate")
        payload = {
            "workspaceId": scope.workspace_id,
            "applicationId": scope.application_id,
            "actor": [actor.issuer, actor.subject_id],
            "policyVersion": policy_version,
            "expectedSecurityRevision": expected_security_revision,
        }
        payload_digest = sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()
        actor_digest = sha256(
            (actor.issuer + "\0" + actor.subject_id).encode("utf-8")).hexdigest()
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(
                    db, scope.workspace_id, exclusive=True)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, "admin")
                previous = db.execute("""SELECT command_digest,payload_digest,
                    result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s""",
                    (scope.workspace_id, operation_id)).fetchone()
                if previous:
                    if previous["command_digest"] != command_digest:
                        raise ValueError("IDEMPOTENCY_KEY_REUSED")
                    if previous["payload_digest"] != payload_digest:
                        raise ValueError("IDEMPOTENCY_PAYLOAD_CHANGED")
                    return previous["result"]
                state = db.execute("""SELECT security_revision,
                    active_dimensional_security_policy_version
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s FOR UPDATE""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                if state["security_revision"] != expected_security_revision:
                    raise ValueError("SECURITY_REVISION_CHANGED")
                policy_digest = None
                if policy_version is not None:
                    row = db.execute(f"""SELECT {self._COLUMNS}
                        FROM epm.dimensional_security_policy_version
                        WHERE workspace_id=%s AND application_id=%s
                          AND policy_version=%s""",
                        (scope.workspace_id, scope.application_id,
                         policy_version)).fetchone()
                    if row is None:
                        raise ValueError(
                            "DIMENSIONAL_SECURITY_POLICY_VERSION_UNAVAILABLE")
                    validate_policy_activation_supported(_row_policy(row))
                    verified = self._verified(scope, row)
                    policy_digest = verified["policyDigest"]
                next_revision = state["security_revision"] + 1
                db.execute("""UPDATE epm.application_state SET
                    active_dimensional_security_policy_version=%s,
                    security_revision=%s WHERE workspace_id=%s
                    AND application_id=%s""",
                    (policy_version, next_revision, scope.workspace_id,
                     scope.application_id))
                result = {
                    "workspaceId": scope.workspace_id,
                    "applicationId": scope.application_id,
                    "policyVersion": policy_version,
                    "policyDigest": policy_digest,
                    "securityRevision": next_revision,
                    "authorizationEffect": policy_version is not None,
                    "status": "Activated" if policy_version is not None
                              else "Deactivated",
                }
                db.execute("""INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,
                     actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (scope.workspace_id, operation_id, command_digest,
                     payload_digest, actor_digest, action, Jsonb(result)))
                db.execute("""INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,target_digest,
                     outcome,detail) VALUES (%s,%s,%s,%s,%s,'Accepted',%s)""",
                    (actor_digest, action, scope.workspace_id,
                     scope.application_id, policy_digest,
                     Jsonb({"operationId": operation_id,
                            "policyVersion": policy_version,
                            "securityRevision": next_revision,
                            "authorizationEffect": policy_version is not None})))
                return result

    def read_active(self, scope: ApplicationScope, *,
                    actor: VerifiedIdentity) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(actor, VerifiedIdentity)):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_ACTIVE_READ_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, actor, scope, "admin")
                state = db.execute("""SELECT security_revision,
                    active_dimensional_security_policy_version
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""",
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                active = state["active_dimensional_security_policy_version"]
                if active is None:
                    return {"workspaceId": scope.workspace_id,
                            "applicationId": scope.application_id,
                            "policyVersion": None, "policy": None,
                            "securityRevision": state["security_revision"],
                            "authorizationEffect": False,
                            "status": "Inactive"}
                row = db.execute(f"""SELECT {self._COLUMNS}
                    FROM epm.dimensional_security_policy_version
                    WHERE workspace_id=%s AND application_id=%s
                      AND policy_version=%s""",
                    (scope.workspace_id, scope.application_id,
                     active)).fetchone()
                if row is None:
                    raise ValueError("DIMENSIONAL_SECURITY_ACTIVE_POLICY_CORRUPT")
                return {**self._verified(
                            scope, row, active_version=active),
                        "workspaceId": scope.workspace_id,
                        "applicationId": scope.application_id,
                        "securityRevision": state["security_revision"],
                        "status": "Active"}
