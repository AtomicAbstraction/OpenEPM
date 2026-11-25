"""Workspace-admin reviewed transition for a single existing application."""

from __future__ import annotations

import hmac
from hashlib import sha256
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from . import application_authorization_migration as contract
from .current_object_contract import new_state_token
from .dimensional_privileges import require_assignment_policy
from .dimensional_security_policy import dimensional_security_policy_digest
from .postgres_access import AccessDenied, _ROLE_RANK
from .postgres_authorization_config import configuration_state
from .postgres_capability_contract import filter_catalog
from .postgres_connection import connect_postgres
from .postgres_dimensional_security_policies import (
    assignment_policy_values,
    policy_from_values,
    _row_policy,
)
from .postgres_grants import PostgresGrantStore

STALE = "APPLICATION_AUTHORIZATION_MIGRATION_STALE"
BLOCKED = "APPLICATION_AUTHORIZATION_MIGRATION_BLOCKED"
DISPOSITIONS = "APPLICATION_AUTHORIZATION_MIGRATION_DISPOSITIONS_REQUIRED"
RECEIPT = "application-authorization.activate"


def _state(db, p):
    state = configuration_state(db, p)
    state.update(
        db.execute(
            """SELECT a.status,s.policy_revision,s.capability_revision,
        s.enabled_capabilities FROM epm.application a JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE a.workspace_id=%(workspace)s AND a.application_id=%(app)s""",
            p,
        ).fetchone()
    )
    if state["status"] != "Active":
        raise AccessDenied("APPLICATION_NOT_WRITABLE")
    return state


def _review(db, p, state, secret, actor, target):
    from .postgres_language_v2 import PostgresLanguageV2
    from .postgres_security_language import PostgresSecurityLanguage

    blockers = set()
    if target == state["authorization_model"]:
        blockers.add("MODE_ALREADY_ACTIVE")
    if not state["directory_revision"]:
        blockers.add("DIRECTORY_UNAVAILABLE")
    dependencies = db.execute("SELECT * FROM epm.authorization_migration_dependencies()").fetchone()
    blockers.update(name.upper() for name, exists in dependencies.items() if exists)
    outstanding_work = [
        row["family"]
        for row in db.execute(
            "SELECT family FROM epm.authorization_migration_active_work()"
        ).fetchall()
    ]
    if outstanding_work:
        blockers.add("IN_FLIGHT")
    if (
        target == "group_assignments"
        and not db.execute(
            "SELECT epm.authorization_has_reachable_admin(%(workspace)s,%(app)s) AS reachable", p
        ).fetchone()["reachable"]
    ):
        blockers.add("NO_REACHABLE_ASSIGNMENT_ADMINISTRATOR")
    policy = db.execute(
        """SELECT * FROM epm.dimensional_security_policy_definition
        WHERE workspace_id=%(workspace)s AND application_id=%(app)s""",
        p,
    ).fetchone()
    disposition = "retain_current_policy"
    if policy:
        if policy["status"] != "Active":
            blockers.add("DRAFT_DIMENSIONAL_POLICY_REQUIRES_DISPOSITION")
        else:
            try:
                resolved = _row_policy(policy)
                require_assignment_policy(resolved)
                if (
                    dimensional_security_policy_digest(p["workspace"], p["app"], resolved)
                    != policy["policy_digest"]
                ):
                    blockers.add("DIMENSIONAL_POLICY_UNVERIFIED")
            except ValueError:
                blockers.add("DIMENSIONAL_POLICY_NOT_COMPATIBLE")
    else:
        disposition = "install_assignment_policy_atomically"
    origins = [
        r["origin"]
        for r in db.execute("SELECT origin FROM epm.authorization_migration_origins()").fetchall()
    ]
    specs = filter_catalog(PostgresLanguageV2.catalog(), state["enabled_capabilities"])["functions"]
    specs.update(PostgresSecurityLanguage.catalog()["functions"])
    functions = {
        name: s["permission"]
        for name, s in specs.items()
        if s.get("availability", {}).get("status") != "unsupported"
    }
    reverse = target == "legacy"
    details = contract.compare(
        actor.issuer,
        origins,
        functions,
        reverse=reverse,
        old_policy=policy is not None,
        blockers=blockers,
        changing_model=target != state["authorization_model"],
    )
    if target != state["authorization_model"]:
        if db.execute("SELECT epm.authorization_migration_has_pending_planning_draft() AS pending").fetchone()["pending"]:
            blockers.add("PENDING_PLANNING_POLICY_DRAFT_REQUIRES_DISPOSITION")
        # Every legacy writer supplies a server-derived role from the access
        # check, including a Reader with separate rule-run permission.
        planning = db.execute(
            "SELECT * FROM epm.authorization_migration_planning_candidates(%s::text[])",
            (list(_ROLE_RANK),),
        ).fetchone()
        if planning["group_allow_possible"] or (reverse and planning["legacy_allow_possible"]):
            blockers.add("PLANNING_DUTY_EQUIVALENCE_UNPROVEN")
        elif planning["active_policy"] and not reverse:
            consequence = "planning_writes_closed_until_scoped_duties_are_linked"
            disposition_id = contract.digest([p["workspace"], p["app"], state["created_at"],
                state["policy_revision"], state["security_revision"], consequence])
            details["planningWriteChange"] = {"effect": consequence, "dispositionId": disposition_id}
            details["requiredDispositions"].append(disposition_id)
            if len(details["requiredDispositions"]) > contract.DISPOSITION_LIMIT:
                blockers.add("INVENTORY_BOUND_EXCEEDED")
    if reverse:
        latest = db.execute(
            """SELECT result FROM epm.security_operation_receipt
            WHERE workspace_id=%(workspace)s AND action='application-authorization.activate'
              AND result->>'applicationId'=%(app)s AND result->>'incarnation'=%(created)s
            ORDER BY committed_at DESC,operation_id DESC LIMIT 1""",
            {**p, "created": state["created_at"]},
        ).fetchone()
        if (
            latest is None
            or latest["result"]["targetMode"] != "group_assignments"
            or latest["result"].get("postAuthorityDigest") != contract.digest(state)
        ):
            blockers.add("RESTORE_AUTHORITY_FENCE_CHANGED")
        if (
            not policy
            or latest
            and latest["result"].get("policyDisposition") != "retain_current_policy"
        ):
            blockers.add("RESTORE_POLICY_NOT_IDENTICAL")
    result = {
        "workspaceId": p["workspace"],
        "applicationId": p["app"],
        "incarnation": state["created_at"],
        "sourceMode": state["authorization_model"],
        "targetMode": target,
        "revision": state["security_revision"],
        "blockers": sorted(blockers),
        "outstandingWorkFamilies": outstanding_work,
        "policyDisposition": disposition,
        "changed": False,
        **details,
    }
    # The checkout contract, complete current directory and application epochs are
    # part of the review, including differences invisible in the display fields.
    key = contract.digest([result, state, actor.issuer, actor.subject_id, actor.groups])
    result["reviewDigest"] = (
        None if blockers else hmac.new(secret, key.encode(), sha256).hexdigest()
    )
    return result


def _install_policy(db, p, actor_hash, operation):
    values = assignment_policy_values()
    digest = dimensional_security_policy_digest(
        p["workspace"], p["app"], policy_from_values(values)
    )
    db.execute(
        """INSERT INTO epm.dimensional_security_policy_definition
        (workspace_id,application_id,state_token,status,policy_digest,across_dimensions,within_dimension,
         untagged_member,untagged_deny_precedence,member_tag_cardinality,hierarchy_tags,write_read_relationship,
         mixed_selection,administrator_treatment,fact_side_authority,updated_operation_id,updated_by_digest)
        VALUES (%(workspace)s,%(app)s,%(token)s,'Active',%(digest)s,%(acrossDimensions)s,%(withinDimension)s,
        %(untaggedMember)s,%(untaggedDenyPrecedence)s,%(memberTagCardinality)s,%(hierarchyTags)s,
        %(writeReadRelationship)s,%(mixedSelection)s,%(administratorTreatment)s,%(factSideAuthority)s,%(operation)s,%(actor)s)""",
        {
            **p,
            **values,
            "token": new_state_token(),
            "digest": digest,
            "operation": operation,
            "actor": actor_hash,
        },
    )


def execute(dsn, workspace, actor, program, *, secret, operation_id=None):
    args = contract.compile_program(program)
    write = program["function"] == contract.ACTIVATE
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("AUTHORIZATION_MIGRATION_KEY_REQUIRED")
    if write and (
        not isinstance(operation_id, str)
        or not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", operation_id)
    ):
        raise ValueError(contract.INVALID)
    p = {"workspace": workspace, "app": args["applicationId"]}
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with PostgresGrantStore._workspace_security_transaction(
            db, workspace, actor, write=write, fence_directory=True
        ):
            db.execute("SELECT set_config('epm.application_id',%(app)s,true)", p)
            if write:
                db.execute(
                    """SELECT security_revision FROM epm.application_state WHERE workspace_id=%(workspace)s
                    AND application_id=%(app)s FOR UPDATE""",
                    p,
                )
            state = _state(db, p)
            actor_hash = sha256((actor.issuer + "\0" + actor.subject_id).encode()).hexdigest()
            command = contract.digest([p, state["created_at"], actor_hash, program])
            if write:
                prior = db.execute(
                    """SELECT command_digest,action,result FROM epm.security_operation_receipt
                    WHERE workspace_id=%s AND operation_id=%s""",
                    (workspace, operation_id),
                ).fetchone()
                if prior:
                    if prior["command_digest"] != command or prior["action"] != RECEIPT:
                        raise ValueError("IDEMPOTENCY_KEY_REUSED")
                    return {
                        "languageVersion": 2,
                        "function": program["function"],
                        "result": prior["result"],
                    }
            result = _review(db, p, state, secret, actor, args["targetMode"])
            if _state(db, p) != state:
                raise ValueError(STALE)
            if write:
                if result["blockers"]:
                    raise ValueError(BLOCKED + ":" + ",".join(result["blockers"]))
                if not hmac.compare_digest(args["reviewDigest"], result["reviewDigest"]):
                    raise ValueError(STALE)
                if sorted(args["acceptedDispositions"]) != sorted(result["requiredDispositions"]):
                    raise ValueError(DISPOSITIONS)
                if result["policyDisposition"] == "install_assignment_policy_atomically":
                    _install_policy(db, p, actor_hash, operation_id)
                db.execute(
                    "SELECT epm.switch_application_authorization_model(%s,%s,%s)",
                    (result["sourceMode"], result["targetMode"], state["created_at"]),
                )
                committed = _state(db, p)
                result.update(
                    changed=True,
                    revision=committed["security_revision"],
                    postAuthorityDigest=contract.digest(committed),
                )
                db.execute(
                    """INSERT INTO epm.security_operation_receipt
                    (workspace_id,operation_id,command_digest,payload_digest,actor_digest,action,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        workspace,
                        operation_id,
                        command,
                        contract.digest(args),
                        actor_hash,
                        RECEIPT,
                        Jsonb(result),
                    ),
                )
                db.execute(
                    """INSERT INTO epm.security_audit
                    (actor_id,action,workspace_id,application_id,target_digest,outcome,detail)
                    VALUES (%s,%s,%s,%s,%s,'Accepted',%s)""",
                    (
                        actor_hash,
                        RECEIPT,
                        workspace,
                        p["app"],
                        result["reviewDigest"],
                        Jsonb(
                            {
                                "operationId": operation_id,
                                "targetMode": result["targetMode"],
                                "revision": result["revision"],
                            }
                        ),
                    ),
                )
            return {"languageVersion": 2, "function": program["function"], "result": result}
