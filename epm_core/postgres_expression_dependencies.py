"""W05 dependency state for relation-driven expression results."""
from __future__ import annotations


def prepare_applicability_dependency_state(db, scope, plan, *,
        job_id: str, state: dict) -> dict:
    from .calculation_dependency_compiler import (
        compile_applicability_expression_dependency_template)
    from .calculation_dependency_contract import (
        calculation_instance_binding, compile_execution_manifest, digest)
    from .postgres_calculation_dependencies import (
        initialize_scope_state, register_dependency_template,
        register_instance_binding, seal_execution_manifest)
    from .postgres_expression import compiler_for

    required = {"schema_epoch", "commit_revision", "metadata_revision",
                "data_revision", "policy_revision"}
    if not required <= set(state):
        raise ValueError("CALCULATION_DEPENDENCY_READ_CUT_INVALID")
    domain = plan.applicability_domain
    template = compile_applicability_expression_dependency_template(
        plan, compiler_version=compiler_for(plan)[0])
    register_dependency_template(db, scope, template,
                                 schema_epoch=state["schema_epoch"])
    binding = calculation_instance_binding(
        template_digest=template.digest,
        definition_id=template.normalized["definitionId"],
        definition_state_token=domain["relationStateToken"],
        stage="calculate", parameters={
            "relationId": domain["relationId"],
            "relationDigest": domain["relationDigest"],
            "resultKey": plan.result_key,
        }, partition_policy_version=1)
    register_instance_binding(db, scope, binding)
    partitions = [item["partitionKey"]
                  for item in template.normalized["targets"]]
    read_cut = {"commit": state["commit_revision"],
                "metadata": state["metadata_revision"],
                "data": state["data_revision"],
                "policy": state["policy_revision"]}
    resolved = []
    for ordinal, dependency in enumerate(template.normalized["dependencies"]):
        if (dependency["objectType"] == "applicability-relation"
                and dependency["objectId"] == domain["relationId"]):
            token = {"kind": dependency["kind"],
                "objectType": dependency["objectType"],
                "objectId": dependency["objectId"],
                "stateToken": domain["relationStateToken"],
                "contentDigest": domain["relationDigest"]}
        else:
            kind = dependency["kind"]
            token = {"kind": kind,
                "objectType": dependency["objectType"],
                "objectId": dependency["objectId"],
                "scope": dependency["scope"],
                "readCut": ({"data": state["data_revision"]}
                    if kind in {"raw", "absence_range"}
                    else {"metadata": state["metadata_revision"]}
                    if kind in {"selector", "hierarchy", "calendar",
                                "unit_policy"}
                    else {"commit": state["commit_revision"],
                          "data": state["data_revision"]})}
        resolved.append({"templateOrdinal": ordinal,
            "tokenDigest": digest(token), "token": token,
            "outputPartitions": partitions})
    manifest = compile_execution_manifest({
        "format": "openepm-calculation-execution-manifest-v1",
        "templateDigest": template.digest,
        "bindingDigest": binding["bindingDigest"],
        "schemaEpoch": state["schema_epoch"], "readCut": read_cut,
        "resolvedDependencies": resolved,
        "targetPartitions": partitions, "coverage": "complete"})
    seal_execution_manifest(db, scope, template=template, binding=binding,
                            manifest=manifest, job_id=job_id)
    initialize_scope_state(db, scope, template=template, binding=binding)
    epochs = db.execute('''SELECT partition_key,required_epoch FROM
        epm.calculation_scope_state WHERE workspace_id=%s
        AND application_id=%s AND binding_digest=%s AND stage=%s
        ORDER BY partition_key''', (scope.workspace_id, scope.application_id,
        binding["bindingDigest"], binding["stage"])).fetchall()
    if [row["partition_key"] for row in epochs] != partitions:
        raise ValueError("CALCULATION_SCOPE_STATE_INCOMPLETE")
    return {"template": template, "binding": binding,
            "manifest": manifest,
            "requiredEpochs": {row["partition_key"]: row["required_epoch"]
                               for row in epochs}}


def prepare_relation_apportionment_dependency_state(db, scope, request, *,
        job_id: str, state: dict, compiler_version: str) -> dict:
    """Seal the current business relation and raw-data cut for one rule run."""
    from .calculation_dependency_compiler import (
        compile_relation_apportionment_dependency_template)
    from .calculation_dependency_contract import (
        calculation_instance_binding, compile_execution_manifest, digest)
    from .postgres_calculation_dependencies import (
        initialize_scope_state, register_dependency_template,
        register_instance_binding, seal_execution_manifest)

    required = {"schema_epoch", "commit_revision", "metadata_revision",
                "data_revision", "policy_revision"}
    if not required <= set(state):
        raise ValueError("CALCULATION_DEPENDENCY_READ_CUT_INVALID")
    template = compile_relation_apportionment_dependency_template(
        request, compiler_version=compiler_version)
    domain = request["apportionmentDomain"]
    register_dependency_template(db, scope, template,
                                 schema_epoch=state["schema_epoch"])
    binding = calculation_instance_binding(
        template_digest=template.digest,
        definition_id=template.normalized["definitionId"],
        definition_state_token=domain["relationStateToken"],
        stage="calculate", parameters={
            "relationId": domain["relationId"],
            "relationDigest": domain["relationDigest"],
            "resultKey": request["resultKey"],
        }, partition_policy_version=1)
    register_instance_binding(db, scope, binding)
    partitions = [item["partitionKey"]
                  for item in template.normalized["targets"]]
    read_cut = {"commit": state["commit_revision"],
                "metadata": state["metadata_revision"],
                "data": state["data_revision"],
                "policy": state["policy_revision"]}
    resolved = []
    for ordinal, dependency in enumerate(template.normalized["dependencies"]):
        token = ({"kind": dependency["kind"],
                  "objectType": dependency["objectType"],
                  "objectId": dependency["objectId"],
                  "stateToken": domain["relationStateToken"],
                  "contentDigest": domain["relationDigest"]}
            if dependency["objectType"] == "applicability-relation"
            else {"kind": dependency["kind"],
                  "objectType": dependency["objectType"],
                  "objectId": dependency["objectId"],
                  "scope": dependency["scope"],
                  "readCut": {"data": state["data_revision"]}})
        resolved.append({"templateOrdinal": ordinal,
            "tokenDigest": digest(token), "token": token,
            "outputPartitions": partitions})
    manifest = compile_execution_manifest({
        "format": "openepm-calculation-execution-manifest-v1",
        "templateDigest": template.digest,
        "bindingDigest": binding["bindingDigest"],
        "schemaEpoch": state["schema_epoch"], "readCut": read_cut,
        "resolvedDependencies": resolved,
        "targetPartitions": partitions, "coverage": "complete"})
    seal_execution_manifest(db, scope, template=template, binding=binding,
                            manifest=manifest, job_id=job_id)
    initialize_scope_state(db, scope, template=template, binding=binding)
    epochs = db.execute('''SELECT partition_key,required_epoch FROM
        epm.calculation_scope_state WHERE workspace_id=%s
        AND application_id=%s AND binding_digest=%s AND stage=%s
        ORDER BY partition_key''', (scope.workspace_id, scope.application_id,
        binding["bindingDigest"], binding["stage"])).fetchall()
    if [row["partition_key"] for row in epochs] != partitions:
        raise ValueError("CALCULATION_SCOPE_STATE_INCOMPLETE")
    return {"template": template, "binding": binding,
            "manifest": manifest,
            "requiredEpochs": {row["partition_key"]: row["required_epoch"]
                               for row in epochs}}
