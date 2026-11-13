"""PostgreSQL repository for one-current W08 resolved-read bindings."""
from __future__ import annotations

from psycopg.types.json import Jsonb

from .current_object_contract import new_state_token, require_state_token
from .hierarchy_node_contract import compile_hierarchy_node
from .persistence_contract import ApplicationScope
from .resolved_read_binding_contract import (
    ResolvedReadBinding, compile_resolved_read_binding)


def _dimensions(db, scope: ApplicationScope) -> list[str]:
    row = db.execute("""SELECT l.dimensions FROM epm.application_state s
        JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
        WHERE s.workspace_id=%s AND s.application_id=%s""", (
        scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise ValueError("COORDINATE_LAYOUT_UNAVAILABLE")
    return list(row["dimensions"])


def save_resolved_read_binding(db, scope: ApplicationScope, *,
        binding: ResolvedReadBinding, metadata_revision: int,
        policy_revision: int, expected_state_token: str | None = None
        ) -> dict[str, object]:
    """Create or replace the sole current binding and leave it inactive."""
    if (not isinstance(scope, ApplicationScope)
            or not isinstance(binding, ResolvedReadBinding)
            or type(metadata_revision) is not int or metadata_revision < 0
            or type(policy_revision) is not int or policy_revision < 0):
        raise ValueError("RESOLVED_READ_BINDING_SAVE_INVALID")
    if expected_state_token is not None:
        require_state_token(expected_state_token,
            error="RESOLVED_READ_BINDING_SAVE_INVALID")
    canonical = compile_resolved_read_binding(binding.normalized,
        active_dimensions=_dimensions(db, scope))
    if canonical.digest != binding.digest:
        raise ValueError("RESOLVED_READ_BINDING_NONCANONICAL")
    state = db.execute("""SELECT metadata_revision,policy_revision FROM
        epm.application_state WHERE workspace_id=%s AND application_id=%s
        FOR SHARE""", (scope.workspace_id, scope.application_id)).fetchone()
    if (state is None or state["metadata_revision"] != metadata_revision
            or state["policy_revision"] != policy_revision):
        raise ValueError("RESOLVED_READ_BINDING_REVISION_MISMATCH")
    current = db.execute("""SELECT state_token FROM
        epm.resolved_read_binding_definition WHERE workspace_id=%s
        AND application_id=%s AND binding_id=%s FOR UPDATE""", (
        scope.workspace_id, scope.application_id,
        binding.normalized["bindingId"])).fetchone()
    if ((current is None) != (expected_state_token is None)
            or (current is not None
                and current["state_token"] != expected_state_token)):
        raise ValueError("RESOLVED_READ_BINDING_STATE_CONFLICT")
    state_token = new_state_token()
    row = db.execute("""INSERT INTO epm.resolved_read_binding_definition(
        workspace_id,application_id,binding_id,state_token,binding_digest,
        binding,status,metadata_revision,policy_revision)
        VALUES(%s,%s,%s,%s,%s,%s,'Saved',%s,%s)
        ON CONFLICT(workspace_id,application_id,binding_id) DO UPDATE SET
          state_token=EXCLUDED.state_token,
          binding_digest=EXCLUDED.binding_digest,binding=EXCLUDED.binding,
          status='Saved',metadata_revision=EXCLUDED.metadata_revision,
          policy_revision=EXCLUDED.policy_revision,
          activation_operation_id=NULL,updated_at=transaction_timestamp()
        RETURNING binding_id,state_token,binding_digest,status""", (
        scope.workspace_id, scope.application_id,
        binding.normalized["bindingId"], state_token, binding.digest,
        Jsonb(binding.normalized), metadata_revision,
        policy_revision)).fetchone()
    return {"bindingId": row["binding_id"],
            "stateToken": row["state_token"],
            "bindingDigest": row["binding_digest"],
            "status": row["status"]}


def _validate_references(db, scope: ApplicationScope,
        binding: ResolvedReadBinding) -> None:
    for stage in binding.normalized["stages"]:
        if stage["kind"] == "calculated_member":
            row = db.execute("""SELECT state_token,program,program_digest
                FROM epm.expression_rule_definition
                WHERE workspace_id=%s AND application_id=%s AND rule_id=%s
                  AND status='Active'""", (scope.workspace_id,
                scope.application_id, stage["definitionId"])).fetchone()
            if (row is None
                    or row["state_token"] != stage["definitionStateToken"]
                    or row["program"].get("function") !=
                       "calculated.member.definition"
                    or row["program"]["arguments"].get("evaluation") !=
                       stage["evaluation"]
                    or row["program"]["arguments"].get("resultUnit") !=
                       stage["resultUnit"]):
                raise ValueError("RESOLVED_READ_CALCULATION_UNAVAILABLE")
        else:
            definition = compile_hierarchy_node(stage["definition"])
            row = db.execute("""SELECT membership_semantics FROM
                epm.hierarchy_state WHERE workspace_id=%s
                AND application_id=%s AND dimension_id=%s
                AND hierarchy_id=%s AND state_token=%s""", (
                scope.workspace_id, scope.application_id,
                definition.normalized["dimensionId"],
                definition.normalized["hierarchyId"],
                definition.normalized["hierarchyStateToken"])).fetchone()
            if (row is None or row["membership_semantics"] !=
                       definition.normalized["membershipSemantics"]):
                raise ValueError("RESOLVED_READ_HIERARCHY_UNAVAILABLE")
            override_ids = sorted(
                definition.normalized.get("ruleOperatorOverrides", {}))
            if override_ids:
                targets = db.execute("""SELECT relationship_id FROM
                    epm.relationship WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND hierarchy_id=%s AND status='Active'
                    AND relationship_id=ANY(%s::text[])""", (
                    scope.workspace_id, scope.application_id,
                    definition.normalized["dimensionId"],
                    definition.normalized["hierarchyId"],
                    override_ids)).fetchall()
                if {item["relationship_id"] for item in targets} != set(override_ids):
                    raise ValueError(
                        "RESOLVED_READ_RULE_OVERRIDE_UNAVAILABLE")


def activate_resolved_read_binding(db, scope: ApplicationScope, *,
        binding_id: str, expected_state_token: str,
        expected_metadata_revision: int, expected_policy_revision: int,
        operation_id: str, command_digest: str,
        actor_id: str) -> dict[str, object]:
    """Validate and activate the exact current binding state."""
    if (not isinstance(binding_id, str) or not binding_id
            or type(expected_metadata_revision) is not int
            or expected_metadata_revision < 0
            or type(expected_policy_revision) is not int
            or expected_policy_revision < 0
            or not isinstance(operation_id, str) or not operation_id
            or not isinstance(command_digest, str)
            or len(command_digest) != 64
            or any(character not in "0123456789abcdef"
                   for character in command_digest)
            or not isinstance(actor_id, str) or not actor_id):
        raise ValueError("RESOLVED_READ_BINDING_ACTIVATION_INVALID")
    require_state_token(expected_state_token,
        error="RESOLVED_READ_BINDING_ACTIVATION_INVALID")
    replay = db.execute("""SELECT r.command_digest,r.actor_id,r.result,
        d.binding_id,d.state_token,d.binding_digest,e.impact_epoch
        FROM epm.operation_receipt r
        LEFT JOIN epm.resolved_read_binding_definition d
          ON d.workspace_id=r.workspace_id AND d.application_id=r.application_id
         AND d.activation_operation_id=r.operation_id
        LEFT JOIN epm.calculation_impact_event e
          ON e.workspace_id=r.workspace_id AND e.application_id=r.application_id
         AND e.operation_id=r.operation_id
        WHERE r.workspace_id=%s AND r.application_id=%s
          AND r.operation_id=%s""", (scope.workspace_id,
        scope.application_id, operation_id)).fetchone()
    if replay is not None:
        if (replay["command_digest"] != command_digest
                or replay["actor_id"] != actor_id
                or replay["binding_id"] != binding_id):
            raise ValueError("RESOLVED_READ_BINDING_REPLAY_CONFLICT")
        if replay["impact_epoch"] is None:
            raise ValueError("CALCULATION_IMPACT_REPLAY_MISMATCH")
        return {**replay["result"], "impactEpoch": replay["impact_epoch"],
                "duplicate": True}
    state = db.execute("""SELECT metadata_revision,policy_revision,
        commit_revision FROM epm.application_state WHERE workspace_id=%s
        AND application_id=%s FOR UPDATE""", (
        scope.workspace_id, scope.application_id)).fetchone()
    if (state is None or state["metadata_revision"] !=
            expected_metadata_revision or state["policy_revision"] !=
            expected_policy_revision):
        raise ValueError("RESOLVED_READ_BINDING_REVISION_MISMATCH")
    row = db.execute("""SELECT binding,binding_digest,state_token,
        metadata_revision,policy_revision,status FROM
        epm.resolved_read_binding_definition WHERE workspace_id=%s
        AND application_id=%s AND binding_id=%s FOR UPDATE""", (
        scope.workspace_id, scope.application_id, binding_id)).fetchone()
    if (row is None or row["state_token"] != expected_state_token
            or row["metadata_revision"] != expected_metadata_revision
            or row["policy_revision"] != expected_policy_revision):
        raise ValueError("RESOLVED_READ_BINDING_STATE_CONFLICT")
    binding = compile_resolved_read_binding(row["binding"],
        active_dimensions=_dimensions(db, scope))
    if binding.digest != row["binding_digest"]:
        raise ValueError("RESOLVED_READ_BINDING_CORRUPT")
    _validate_references(db, scope, binding)
    committed_revision = state["commit_revision"] + 1
    policy_revision = state["policy_revision"] + 1
    state_token = new_state_token()
    result = {"bindingId": binding_id, "stateToken": state_token,
        "bindingDigest": binding.digest,
        "policyRevision": policy_revision,
        "operationId": operation_id, "status": "Active"}
    db.execute("""INSERT INTO epm.operation_receipt(workspace_id,
        application_id,operation_id,command_digest,actor_id,
        committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""", (
        scope.workspace_id, scope.application_id, operation_id,
        command_digest, actor_id, committed_revision, Jsonb(result)))
    db.execute("""UPDATE epm.resolved_read_binding_definition SET
        state_token=%s,status='Active',activation_operation_id=%s,
        updated_at=transaction_timestamp() WHERE workspace_id=%s
        AND application_id=%s AND binding_id=%s""", (
        state_token, operation_id,
        scope.workspace_id, scope.application_id, binding_id))
    from .postgres_calculation_impact import (
        object_impact, record_calculation_impact)
    impact = object_impact(source_kind="definition", operation_id=operation_id,
        causal_revision=committed_revision, domain="definition",
        object_type="resolved-read-binding", object_id=binding_id,
        change="activate", reason="definition_changed")
    impact_epoch = record_calculation_impact(db, scope,
        operation_id=operation_id, impact=impact)
    db.execute("""UPDATE epm.application_state SET commit_revision=%s,
        policy_revision=%s WHERE workspace_id=%s
        AND application_id=%s""", (committed_revision, policy_revision,
        scope.workspace_id, scope.application_id))
    return {**result, "impactEpoch": impact_epoch, "duplicate": False}


def read_current_resolved_read_binding(db, scope: ApplicationScope, *,
        binding_id: str, expected_state_token: str | None = None,
        require_active: bool = True) -> dict[str, object]:
    if expected_state_token is not None:
        require_state_token(expected_state_token,
            error="RESOLVED_READ_BINDING_READ_INVALID")
    row = db.execute("""SELECT state_token,binding_digest,binding,status,
        metadata_revision,policy_revision
        FROM epm.resolved_read_binding_definition
        WHERE workspace_id=%s AND application_id=%s AND binding_id=%s""",
        (scope.workspace_id, scope.application_id, binding_id)).fetchone()
    if (row is None or (require_active and row["status"] != "Active")
            or (expected_state_token is not None
                and row["state_token"] != expected_state_token)):
        raise ValueError("RESOLVED_READ_BINDING_UNAVAILABLE")
    binding = compile_resolved_read_binding(row["binding"],
        active_dimensions=_dimensions(db, scope))
    if binding.digest != row["binding_digest"]:
        raise ValueError("RESOLVED_READ_BINDING_CORRUPT")
    return {"binding": binding, "stateToken": row["state_token"],
        "bindingDigest": binding.digest, "status": row["status"],
        "metadataRevision": row["metadata_revision"],
        "policyRevision": row["policy_revision"]}
