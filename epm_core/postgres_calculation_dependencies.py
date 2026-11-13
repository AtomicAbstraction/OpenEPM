"""PostgreSQL persistence for W05 calculation dependency artifacts.

Callers own the surrounding transaction and application authorization.  This
module stores only fixed-core compiled contracts; it never accepts client SQL.
"""
from __future__ import annotations

from psycopg.types.json import Jsonb

from .calculation_dependency_contract import (
    REASONS,
    DependencyTemplate,
    ExecutionManifest,
    freshness_status,
    validate_manifest_against_template,
)
from .calculation_partition_manifest_contract import PartitionManifest
from .persistence_contract import ApplicationScope


_GENERATION_UNSPECIFIED = object()


def _state(db, scope: ApplicationScope) -> dict:
    row = db.execute("""SELECT schema_epoch FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if row is None:
        raise ValueError("CALCULATION_DEPENDENCY_APPLICATION_UNAVAILABLE")
    return row


def register_dependency_template(db, scope: ApplicationScope,
        template: DependencyTemplate, *, schema_epoch: int) -> str:
    if type(schema_epoch) is not int or schema_epoch < 0:
        raise ValueError("CALCULATION_DEPENDENCY_SCHEMA_EPOCH_INVALID")
    value = template.normalized
    if _state(db, scope)["schema_epoch"] != schema_epoch:
        raise ValueError("CALCULATION_DEPENDENCY_SCHEMA_STALE")
    db.execute("""INSERT INTO epm.calculation_dependency_template(
        workspace_id,application_id,template_digest,definition_id,
        definition_digest,compiler_version,schema_epoch,
        coverage,template) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,application_id,template_digest) DO NOTHING""",
        (scope.workspace_id, scope.application_id, template.digest,
         value["definitionId"], value["definitionDigest"],
         value["compilerVersion"], schema_epoch,
         value["coverage"], Jsonb(value)))
    row = db.execute("""SELECT definition_id,
        definition_digest,compiler_version,schema_epoch,coverage,template
        FROM epm.calculation_dependency_template
        WHERE workspace_id=%s AND application_id=%s AND template_digest=%s""",
        (scope.workspace_id, scope.application_id, template.digest)).fetchone()
    expected = (value["definitionId"],
        value["definitionDigest"], value["compilerVersion"], schema_epoch,
        value["coverage"], value)
    observed = (row["definition_id"],
        row["definition_digest"], row["compiler_version"],
        row["schema_epoch"], row["coverage"], row["template"])
    if observed != expected:
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_CONFLICT")
    return template.digest


def register_instance_binding(db, scope: ApplicationScope,
        binding: dict[str, object]) -> str:
    required = {"format", "templateDigest", "definitionId",
        "definitionStateToken", "stage", "parameters",
        "partitionPolicyVersion", "bindingDigest"}
    if not isinstance(binding, dict) or set(binding) != required:
        raise ValueError("CALCULATION_INSTANCE_BINDING_INVALID")
    digest = binding["bindingDigest"]
    db.execute("""INSERT INTO epm.calculation_instance_binding(
        workspace_id,application_id,binding_digest,template_digest,
        definition_id,definition_state_token,stage,partition_policy_version,
        parameters,binding) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,application_id,binding_digest) DO NOTHING""",
        (scope.workspace_id, scope.application_id, digest,
         binding["templateDigest"], binding["definitionId"],
         binding["definitionStateToken"], binding["stage"],
         binding["partitionPolicyVersion"], Jsonb(binding["parameters"]),
         Jsonb(binding)))
    row = db.execute("""SELECT binding FROM epm.calculation_instance_binding
        WHERE workspace_id=%s AND application_id=%s AND binding_digest=%s""",
        (scope.workspace_id, scope.application_id, digest)).fetchone()
    if row is None or row["binding"] != binding:
        raise ValueError("CALCULATION_INSTANCE_BINDING_CONFLICT")
    return str(digest)


def seal_execution_manifest(db, scope: ApplicationScope, *,
        template: DependencyTemplate, binding: dict[str, object],
        manifest: ExecutionManifest, job_id: str) -> str:
    validate_manifest_against_template(template, manifest)
    value = manifest.normalized
    if (binding.get("bindingDigest") != value["bindingDigest"]
            or binding.get("templateDigest") != template.digest):
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_BINDING_INVALID")
    if _state(db, scope)["schema_epoch"] != value["schemaEpoch"]:
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_SCHEMA_STALE")
    read_cut = value["readCut"]
    db.execute("""INSERT INTO epm.calculation_execution_manifest(
        workspace_id,application_id,manifest_digest,template_digest,
        binding_digest,job_id,schema_epoch,read_commit_revision,
        read_metadata_revision,read_data_revision,read_policy_revision,
        coverage,manifest) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,application_id,manifest_digest) DO NOTHING""",
        (scope.workspace_id, scope.application_id, manifest.digest,
         template.digest, binding["bindingDigest"], job_id,
         value["schemaEpoch"], read_cut["commit"], read_cut["metadata"],
         read_cut["data"], read_cut["policy"], value["coverage"],
         Jsonb(value)))
    row = db.execute("""SELECT manifest,job_id FROM
        epm.calculation_execution_manifest WHERE workspace_id=%s
        AND application_id=%s AND manifest_digest=%s""",
        (scope.workspace_id, scope.application_id, manifest.digest)).fetchone()
    if row is None or row["manifest"] != value or row["job_id"] != job_id:
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_CONFLICT")
    dependencies = template.normalized["dependencies"]
    for resolved in value["resolvedDependencies"]:
        symbolic = dependencies[resolved["templateOrdinal"]]
        matcher = {"scope": symbolic["scope"],
            "absenceWatch": symbolic["absenceWatch"],
            "fanout": symbolic["fanout"]}
        for partition in resolved["outputPartitions"]:
            db.execute("""INSERT INTO epm.calculation_dependency_index(
                workspace_id,application_id,manifest_digest,
                dependency_ordinal,dependency_kind,object_type,object_id,
                token_digest,scope_matcher,output_partition)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING""", (scope.workspace_id,
                scope.application_id, manifest.digest,
                resolved["templateOrdinal"], symbolic["kind"],
                symbolic["objectType"], symbolic["objectId"],
                resolved["tokenDigest"], Jsonb(matcher), partition))
    expected_rows = sum(len(item["outputPartitions"])
                        for item in value["resolvedDependencies"])
    observed_rows = db.execute("""SELECT count(*) n FROM
        epm.calculation_dependency_index WHERE workspace_id=%s
        AND application_id=%s AND manifest_digest=%s""",
        (scope.workspace_id, scope.application_id,
         manifest.digest)).fetchone()["n"]
    if observed_rows != expected_rows:
        raise ValueError("CALCULATION_DEPENDENCY_INDEX_CONFLICT")
    return manifest.digest


def read_scope_freshness(db, scope: ApplicationScope, *, binding_digest: str,
        stage: str, partition_key: str, activity: str = "idle",
        expected_definition_digest: str | None = None,
        impact_barrier: dict | None = None) -> dict:
    row = db.execute("""SELECT scope_state.current_result_state_token,
        scope_state.required_epoch,scope_state.published_epoch,
        scope_state.definition_digest,scope_state.coverage,
        scope_state.presence,scope_state.reasons,scope_state.dependency_token_digest
        FROM epm.calculation_scope_state AS scope_state
        WHERE scope_state.workspace_id=%s
        AND scope_state.application_id=%s AND binding_digest=%s AND stage=%s
        AND partition_key=%s""", (scope.workspace_id, scope.application_id,
        binding_digest, stage, partition_key)).fetchone()
    if row is None:
        result = freshness_status(current_result_state_token=None,
            required_epoch=0, published_epoch=0, definition_valid=True,
            coverage_complete=False, reasons=["coverage_unknown"],
            presence="unknown", activity=activity)
    else:
        definition_valid = (expected_definition_digest is None
            or expected_definition_digest == row["definition_digest"])
        reasons = list(row["reasons"])
        if not definition_valid and "definition_changed" not in reasons:
            reasons.append("definition_changed")
        result = {**freshness_status(
            current_result_state_token=row["current_result_state_token"],
            required_epoch=row["required_epoch"],
            published_epoch=row["published_epoch"],
            definition_valid=definition_valid,
            coverage_complete=row["coverage"] == "complete",
            reasons=reasons, presence=row["presence"], activity=activity),
            "definitionDigest": row["definition_digest"],
            "coverage": row["coverage"],
            "dependencyTokenDigest": row["dependency_token_digest"]}
    from .postgres_calculation_impact import impact_processing_barrier
    barrier = impact_barrier if impact_barrier is not None else impact_processing_barrier(db, scope)
    if barrier["pending"]:
        result = {**result, "freshness": "impact_coverage_pending",
            "requiredAction": "process_impact", "impactBarrier": barrier}
    else:
        result = {**result, "impactBarrier": barrier}
    return result


def initialize_scope_state(db, scope: ApplicationScope, *,
        template: DependencyTemplate, binding: dict[str, object]) -> None:
    if (binding.get("templateDigest") != template.digest
            or binding.get("definitionId") !=
                template.normalized["definitionId"]
            or not isinstance(binding.get("definitionStateToken"),str)):
        raise ValueError("CALCULATION_SCOPE_BINDING_INVALID")
    reasons = ([] if template.normalized["coverage"] == "complete"
               else ["coverage_unknown"])
    for target in template.normalized["targets"]:
        db.execute("""INSERT INTO epm.calculation_scope_state(
            workspace_id,application_id,binding_digest,stage,partition_key,
            required_epoch,published_epoch,definition_digest,coverage,
            presence,reasons) VALUES(%s,%s,%s,%s,%s,0,0,%s,%s,'unknown',%s)
            ON CONFLICT(workspace_id,application_id,binding_digest,stage,
              partition_key) DO NOTHING""", (scope.workspace_id,
            scope.application_id, binding["bindingDigest"], binding["stage"],
            target["partitionKey"], template.normalized["definitionDigest"],
            template.normalized["coverage"], reasons))
        row = db.execute("""SELECT definition_digest,coverage FROM
            epm.calculation_scope_state WHERE workspace_id=%s
            AND application_id=%s AND binding_digest=%s AND stage=%s
            AND partition_key=%s""", (scope.workspace_id,
            scope.application_id, binding["bindingDigest"], binding["stage"],
            target["partitionKey"])).fetchone()
        if (row is None or row["definition_digest"] !=
                template.normalized["definitionDigest"]
                or row["coverage"] != template.normalized["coverage"]):
            raise ValueError("CALCULATION_SCOPE_STATE_CONFLICT")


def mark_scope_required(db, scope: ApplicationScope, *,
        binding_digest: str, stage: str, partition_key: str,
        required_epoch: int, reason: str) -> None:
    if type(required_epoch) is not int or required_epoch < 1 or reason not in REASONS:
        raise ValueError("CALCULATION_SCOPE_IMPACT_INVALID")
    row = db.execute("""SELECT required_epoch,reasons FROM
        epm.calculation_scope_state WHERE workspace_id=%s
        AND application_id=%s AND binding_digest=%s AND stage=%s
        AND partition_key=%s FOR UPDATE""", (scope.workspace_id,
        scope.application_id, binding_digest, stage, partition_key)).fetchone()
    if row is None:
        raise ValueError("CALCULATION_SCOPE_STATE_UNAVAILABLE")
    if required_epoch < row["required_epoch"]:
        raise ValueError("CALCULATION_SCOPE_IMPACT_EPOCH_STALE")
    reasons = sorted(set(row["reasons"]) | {reason})
    db.execute("""UPDATE epm.calculation_scope_state SET required_epoch=%s,
        reasons=%s,updated_at=transaction_timestamp() WHERE workspace_id=%s
        AND application_id=%s AND binding_digest=%s AND stage=%s
        AND partition_key=%s""", (required_epoch, reasons,
        scope.workspace_id, scope.application_id, binding_digest, stage,
        partition_key))


def publish_scope_current(db, scope: ApplicationScope, *,
        binding_digest: str, stage: str, partition_key: str,
        expected_required_epoch: int, result_state_token: str,
        dependency_token_digest: str, presence: str,
        definition_digest: str,
        expected_result_state_token: str | None | object =
            _GENERATION_UNSPECIFIED) -> None:
    if presence not in {"empty", "present"}:
        raise ValueError("CALCULATION_SCOPE_PUBLICATION_INVALID")
    row = db.execute("""UPDATE epm.calculation_scope_state AS target SET
        current_result_state_token=%s,published_epoch=required_epoch,
        dependency_token_digest=%s,presence=%s,reasons='{}'::text[],
        updated_at=transaction_timestamp()
        FROM epm.application_state AS app
        WHERE target.workspace_id=%s AND target.application_id=%s
          AND target.binding_digest=%s AND target.stage=%s
          AND target.partition_key=%s AND target.required_epoch=%s
          AND target.definition_digest=%s AND target.coverage='complete'
          AND (%s OR target.current_result_state_token IS NOT DISTINCT FROM %s)
          AND app.workspace_id=target.workspace_id
          AND app.application_id=target.application_id
          AND app.impact_epoch=app.processed_impact_epoch
        RETURNING target.required_epoch""", (result_state_token,
        dependency_token_digest, presence, scope.workspace_id,
        scope.application_id, binding_digest, stage, partition_key,
        expected_required_epoch, definition_digest,
        expected_result_state_token is _GENERATION_UNSPECIFIED,
        None if expected_result_state_token is _GENERATION_UNSPECIFIED
             else expected_result_state_token,
        )).fetchone()
    if row is None:
        from .postgres_calculation_impact import impact_processing_barrier
        if impact_processing_barrier(db, scope)["pending"]:
            raise ValueError("IMPACT_COVERAGE_PENDING")
        raise ValueError("STALE_CALCULATION_SCOPE_PUBLICATION")


def store_partition_manifest(db, scope: ApplicationScope, *,
        generation_id: str, manifest: PartitionManifest) -> str:
    value = manifest.normalized
    generation = db.execute('''SELECT generation_kind FROM
        epm.calculation_operation_staging WHERE workspace_id=%s
        AND application_id=%s AND generation_id=%s''',(
        scope.workspace_id, scope.application_id, generation_id)).fetchone()
    if generation is None or generation["generation_kind"] != "partition_manifest":
        raise ValueError("CALCULATION_PARTITION_GENERATION_KIND_INVALID")
    db.execute("""INSERT INTO epm.calculation_partition_manifest_staging(
        workspace_id,application_id,operation_id,binding_digest,
        execution_manifest_digest,partition_policy_version,
        partition_map_digest,partition_map)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,application_id,operation_id) DO NOTHING""",
        (scope.workspace_id, scope.application_id, generation_id,
         value["bindingDigest"], value["executionManifestDigest"],
         value["partitionPolicyVersion"], manifest.digest, Jsonb(value)))
    row = db.execute("""SELECT partition_map_digest,partition_map FROM
        epm.calculation_partition_manifest_staging WHERE workspace_id=%s
        AND application_id=%s AND operation_id=%s""",
        (scope.workspace_id, scope.application_id, generation_id)).fetchone()
    if (row is None or row["partition_map_digest"] != manifest.digest
            or row["partition_map"] != value):
        raise ValueError("CALCULATION_PARTITION_MANIFEST_CONFLICT")
    for partition in value["partitions"]:
        db.execute("""INSERT INTO epm.calculation_partition_staging(
            workspace_id,application_id,operation_id,partition_key,
            certificate_digest,presence,row_count)
            VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (scope.workspace_id, scope.application_id, generation_id,
             partition["partitionKey"],partition["certificateDigest"],partition["presence"],
             partition["rowCount"]))
    observed = db.execute("""SELECT partition_key,certificate_digest,presence,row_count FROM
        epm.calculation_partition_staging WHERE workspace_id=%s
        AND application_id=%s AND operation_id=%s ORDER BY partition_key""",
        (scope.workspace_id, scope.application_id, generation_id)).fetchall()
    expected = [{"partition_key": item["partitionKey"],
        "certificate_digest": item["certificateDigest"],
        "presence": item["presence"], "row_count": item["rowCount"]}
        for item in value["partitions"]]
    if [dict(item) for item in observed] != expected:
        raise ValueError("CALCULATION_PARTITION_INDEX_CONFLICT")
    return manifest.digest
