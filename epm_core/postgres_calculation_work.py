"""PostgreSQL adapter for deterministic affected-work requests.

The adapter persists planning identities and maps already-authorized durable
jobs to plan tasks.  It does not execute calculations and cannot publish a
result; existing job claims, leases, cancellation, receipts and final fences
remain authoritative.
"""
from __future__ import annotations

from hashlib import sha256

from psycopg.types.json import Jsonb

from .calculation_work_contract import (
    CalculationWorkPlan,
    compile_calculation_work_plan,
)
from .calculation_partition_manifest_contract import (
    PartitionManifest,
    compile_partition_manifest,
    merge_coordinate_partitions,
)
from .calculation_coordinate_partition_contract import (
    compile_coordinate_partition_profile,
)
from .calculation_dependency_contract import (
    compile_dependency_template,
    compile_execution_manifest,
    validate_manifest_against_template,
)
from .persistence_contract import ApplicationScope


def _request_id(scope: ApplicationScope, issuer: str, subject_id: str,
                idempotency_key: str) -> str:
    material = "\x1f".join((scope.workspace_id, scope.application_id,
                              issuer, subject_id, idempotency_key))
    return sha256(material.encode("utf-8")).hexdigest()[:32]


def _validate_actor(issuer: object, subject_id: object,
                    idempotency_key: object) -> tuple[str, str, str]:
    import re
    if (not isinstance(issuer, str) or not 1 <= len(issuer) <= 300
            or not isinstance(subject_id, str) or not 1 <= len(subject_id) <= 300
            or not isinstance(idempotency_key, str)
            or re.fullmatch(r"[A-Za-z0-9._-]{8,128}", idempotency_key) is None):
        raise ValueError("CALCULATION_WORK_IDENTITY_INVALID")
    return issuer, subject_id, idempotency_key


def load_calculation_scope_states(db, scope: ApplicationScope
                                  ) -> list[dict[str, object]]:
    rows = db.execute("""SELECT state.binding_digest,state.stage,
        state.partition_key,state.required_epoch,state.published_epoch,
        state.coverage,state.presence,state.definition_digest,
        state.current_result_state_token,state.reasons,
        part.certificate_digest AS current_partition_certificate_digest,
        manifest.partition_map_digest AS current_manifest_digest,
        binding.partition_policy_version
        FROM epm.calculation_scope_state AS state
        JOIN epm.calculation_instance_binding AS binding
          ON binding.workspace_id=state.workspace_id
         AND binding.application_id=state.application_id
         AND binding.binding_digest=state.binding_digest
        LEFT JOIN epm.calculation_partition_manifest_current AS manifest
          ON manifest.workspace_id=state.workspace_id
         AND manifest.application_id=state.application_id
         AND manifest.result_state_token=state.current_result_state_token
        LEFT JOIN epm.calculation_partition_current AS part
          ON part.workspace_id=manifest.workspace_id
         AND part.application_id=manifest.application_id
         AND part.result_key=manifest.result_key
         AND part.partition_key=state.partition_key
        WHERE state.workspace_id=%s AND state.application_id=%s
        ORDER BY state.binding_digest,state.stage,state.partition_key""",
        (scope.workspace_id, scope.application_id)).fetchall()
    return [{
        "bindingDigest": row["binding_digest"], "stage": row["stage"],
        "partitionKey": row["partition_key"],
        "requiredEpoch": row["required_epoch"],
        "publishedEpoch": row["published_epoch"],
        "coverage": row["coverage"], "presence": row["presence"],
        "definitionDigest": row["definition_digest"],
        "currentResultStateToken": row["current_result_state_token"],
        "currentPartitionCertificateDigest":
            row["current_partition_certificate_digest"],
        "currentManifestDigest": row["current_manifest_digest"],
        "partitionPolicyVersion": row["partition_policy_version"],
        "reasons": list(row["reasons"]),
    } for row in rows]


def persist_calculation_work_request(db, scope: ApplicationScope, *,
        plan: CalculationWorkPlan, issuer: str, subject_id: str,
        idempotency_key: str) -> dict[str, object]:
    """Persist one exact request or reconcile an exact/compatible replay."""
    issuer, subject_id, idempotency_key = _validate_actor(
        issuer, subject_id, idempotency_key)
    if plan.normalized["status"] == "blocked":
        raise ValueError("IMPACT_COVERAGE_PENDING")
    request_id = _request_id(scope, issuer, subject_id, idempotency_key)
    previous = db.execute("""SELECT key.request_id,key.plan_digest,
        request.status FROM epm.calculation_work_request_key AS key
        JOIN epm.calculation_work_request AS request
          ON request.workspace_id=key.workspace_id
         AND request.application_id=key.application_id
         AND request.request_id=key.request_id
        WHERE key.workspace_id=%s AND key.application_id=%s
        AND key.issuer=%s AND key.subject_id=%s
        AND key.idempotency_key=%s FOR UPDATE OF key,request""", (
        scope.workspace_id,
        scope.application_id, issuer, subject_id, idempotency_key)).fetchone()
    if previous is not None:
        if previous["plan_digest"] != plan.digest:
            raise ValueError("CALCULATION_WORK_IDEMPOTENCY_CONFLICT")
        return {"requestId": previous["request_id"],
                "status": previous["status"], "duplicate": True,
                "compatible": False, "taskCount": plan.task_count}
    compatible = db.execute("""SELECT request_id,status FROM
        epm.calculation_work_request WHERE workspace_id=%s
        AND application_id=%s AND plan_digest=%s
        AND status IN('planned','running') ORDER BY created_at,request_id
        LIMIT 1 FOR UPDATE""", (scope.workspace_id, scope.application_id,
                                plan.digest)).fetchone()
    if compatible is not None:
        db.execute("""INSERT INTO epm.calculation_work_request_key(
            workspace_id,application_id,issuer,subject_id,idempotency_key,
            request_id,plan_digest) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
            (scope.workspace_id, scope.application_id, issuer, subject_id,
             idempotency_key, compatible["request_id"], plan.digest))
        return {"requestId": compatible["request_id"],
                "status": compatible["status"], "duplicate": True,
                "compatible": True, "taskCount": plan.task_count}
    status = "no_change" if plan.normalized["status"] == "no_change" else "planned"
    db.execute("""INSERT INTO epm.calculation_work_request(
        workspace_id,application_id,request_id,issuer,subject_id,
        idempotency_key,mode,plan_digest,plan,status)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", (
        scope.workspace_id, scope.application_id, request_id, issuer,
        subject_id, idempotency_key, plan.normalized["mode"], plan.digest,
        Jsonb(plan.normalized), status))
    db.execute("""INSERT INTO epm.calculation_work_request_key(
        workspace_id,application_id,issuer,subject_id,idempotency_key,
        request_id,plan_digest) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
        (scope.workspace_id, scope.application_id, issuer, subject_id,
         idempotency_key, request_id, plan.digest))
    for task in plan.normalized["tasks"]:
        db.execute("""INSERT INTO epm.calculation_work_task(
            workspace_id,application_id,request_id,task_ordinal,
            binding_digest,stage,partition_key,expected_required_epoch,
            definition_digest,expected_result_state_token,
            expected_partition_certificate_digest,expected_manifest_digest,
            partition_policy_version,reason_codes,predecessor_pins)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (scope.workspace_id, scope.application_id, request_id,
             task["ordinal"], task["bindingDigest"], task["stage"],
             task["partitionKey"], task["expectedRequiredEpoch"],
             task["definitionDigest"], task["expectedResultStateToken"],
             task["expectedPartitionCertificateDigest"],
             task["expectedManifestDigest"], task["partitionPolicyVersion"],
             task["reasonCodes"], Jsonb(task["predecessorPins"])))
    return {"requestId": request_id, "status": status, "duplicate": False,
            "compatible": False, "taskCount": plan.task_count}


def plan_and_persist_calculation_work(db, scope: ApplicationScope, *,
        mode: str, dependencies=(), issuer: str, subject_id: str,
        idempotency_key: str, max_tasks: int = 10_000) -> dict[str, object]:
    from .postgres_calculation_impact import impact_processing_barrier
    barrier = impact_processing_barrier(db, scope)
    plan = compile_calculation_work_plan(mode=mode,
        states=load_calculation_scope_states(db, scope),
        dependencies=dependencies, impact_barrier_pending=barrier["pending"],
        max_tasks=max_tasks)
    result = persist_calculation_work_request(db, scope, plan=plan,
        issuer=issuer, subject_id=subject_id, idempotency_key=idempotency_key)
    return {**result, "planDigest": plan.digest,
            "impactBarrier": barrier, "plan": plan.normalized}


def attach_work_task_job(db, scope: ApplicationScope, *, request_id: str,
        task_ordinal: int, job_id: str) -> dict[str, object]:
    """Attach one admitted job and materialize its exact queue predecessors.

    Selected predecessor scopes use their new task job.  An unchanged
    predecessor must still have the exact published receipt/generation/manifest
    named by the plan.  This prevents a healthy-looking downstream stage from
    binding to a different generation after planning.
    """
    if type(task_ordinal) is not int or not 0 <= task_ordinal <= 99_999:
        raise ValueError("CALCULATION_WORK_TASK_INVALID")
    task = db.execute("""SELECT status,job_id,predecessor_pins FROM
        epm.calculation_work_task WHERE workspace_id=%s AND application_id=%s
        AND request_id=%s AND task_ordinal=%s FOR UPDATE""",
        (scope.workspace_id, scope.application_id, request_id,
         task_ordinal)).fetchone()
    if task is None:
        raise ValueError("CALCULATION_WORK_TASK_UNAVAILABLE")
    if task["status"] != "pending":
        if task["job_id"] != job_id:
            raise ValueError("CALCULATION_WORK_TASK_JOB_CONFLICT")
        return {"jobId": job_id, "status": task["status"],
                "duplicate": True}
    job = db.execute("""SELECT status FROM epm.job WHERE workspace_id=%s
        AND application_id=%s AND job_id=%s FOR UPDATE""",
        (scope.workspace_id, scope.application_id, job_id)).fetchone()
    if job is None or job["status"] not in {"accepted", "ready"}:
        raise ValueError("CALCULATION_WORK_JOB_NOT_ADMITTED")
    predecessors = []
    for pin in task["predecessor_pins"]:
        selected = db.execute("""SELECT job_id,status FROM
            epm.calculation_work_task WHERE workspace_id=%s
            AND application_id=%s AND request_id=%s AND binding_digest=%s
            AND stage=%s AND partition_key=%s""", (scope.workspace_id,
            scope.application_id, request_id, pin["bindingDigest"],
            pin["stage"], pin["partitionKey"])).fetchone()
        if selected is not None:
            if selected["job_id"] is None or selected["status"] == "pending":
                raise ValueError("CALCULATION_WORK_PREDECESSOR_NOT_QUEUED")
            predecessor_job = selected["job_id"]
        else:
            if pin["receiptId"] is None or pin["resultStateToken"] is None:
                raise ValueError("STALE_DEPENDENCY")
            proof = db.execute("""SELECT j.status,current_result.state_token,
                manifest.partition_map_digest FROM epm.job j
                JOIN epm.operation_receipt r ON r.workspace_id=j.workspace_id
                  AND r.application_id=j.application_id
                  AND r.operation_id=j.job_id
                JOIN epm.calculation_result_state current_result ON
                  current_result.workspace_id=j.workspace_id
                  AND current_result.application_id=j.application_id
                  AND current_result.source_operation_id=j.job_id
                LEFT JOIN epm.calculation_partition_manifest_current manifest ON
                  manifest.workspace_id=current_result.workspace_id
                  AND manifest.application_id=current_result.application_id
                  AND manifest.result_state_token=current_result.state_token
                WHERE j.workspace_id=%s AND j.application_id=%s
                  AND j.job_id=%s AND current_result.state_token=%s""",
                (scope.workspace_id, scope.application_id, pin["receiptId"],
                 pin["resultStateToken"])).fetchone()
            if (proof is None or proof["status"] != "published"
                    or (pin["manifestDigest"] is not None
                        and proof["partition_map_digest"] !=
                            pin["manifestDigest"])):
                raise ValueError("STALE_DEPENDENCY")
            predecessor_job = pin["receiptId"]
        if predecessor_job == job_id:
            raise ValueError("DEPENDENCY_CYCLE")
        predecessors.append(predecessor_job)
    for predecessor in sorted(set(predecessors)):
        db.execute("""INSERT INTO epm.job_dependency(
            workspace_id,application_id,job_id,depends_on_job_id)
            VALUES(%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (scope.workspace_id, scope.application_id, job_id, predecessor))
    updated = db.execute("""UPDATE epm.calculation_work_task SET
        job_id=%s,status='queued',updated_at=transaction_timestamp()
        WHERE workspace_id=%s AND application_id=%s AND request_id=%s
        AND task_ordinal=%s AND status='pending'""", (job_id,
        scope.workspace_id, scope.application_id, request_id,
        task_ordinal)).rowcount
    if updated != 1:
        raise ValueError("CALCULATION_WORK_TASK_ATTACH_RACE")
    db.execute("""UPDATE epm.calculation_work_request SET status='running',
        updated_at=transaction_timestamp() WHERE workspace_id=%s
        AND application_id=%s AND request_id=%s AND status='planned'""",
        (scope.workspace_id, scope.application_id, request_id))
    return {"jobId": job_id, "status": "queued", "duplicate": False,
            "predecessorJobIds": sorted(set(predecessors))}


def _current_partition_manifest(db, scope: ApplicationScope, *,
        result_state_token: str) -> PartitionManifest:
    row = db.execute("""SELECT manifest.partition_map FROM
        epm.calculation_partition_manifest_current manifest
        WHERE manifest.workspace_id=%s
          AND manifest.application_id=%s
          AND manifest.result_state_token=%s""",
        (scope.workspace_id,scope.application_id,result_state_token)).fetchone()
    if row is None:
        raise ValueError("CALCULATION_WORK_MANIFEST_UNAVAILABLE")
    return compile_partition_manifest(row["partition_map"])


def _qualified_coordinate_partition_profile(db, scope: ApplicationScope, *,
        binding_digest: str, stage: str, definition_digest: str,
        partition_policy_version: int):
    row = db.execute("""SELECT binding.template_digest,binding.stage,
        binding.partition_policy_version,template.template,
        template.schema_epoch,state.schema_epoch AS current_schema_epoch
        FROM epm.calculation_instance_binding binding
        JOIN epm.calculation_dependency_template template ON
          template.workspace_id=binding.workspace_id
          AND template.application_id=binding.application_id
          AND template.template_digest=binding.template_digest
        JOIN epm.application_state state ON
          state.workspace_id=binding.workspace_id
          AND state.application_id=binding.application_id
        WHERE binding.workspace_id=%s AND binding.application_id=%s
          AND binding.binding_digest=%s""", (scope.workspace_id,
        scope.application_id, binding_digest)).fetchone()
    if row is None:
        raise ValueError("CALCULATION_COORDINATE_PARTITION_UNQUALIFIED")
    template = compile_dependency_template(row["template"])
    if (template.digest != row["template_digest"]
            or template.normalized["definitionDigest"] != definition_digest
            or row["stage"] != stage
            or row["partition_policy_version"] != partition_policy_version
            or row["schema_epoch"] != row["current_schema_epoch"]):
        raise ValueError("CALCULATION_COORDINATE_PARTITION_UNQUALIFIED")
    return template, compile_coordinate_partition_profile(template,
        binding_digest=binding_digest, stage=stage,
        partition_policy_version=partition_policy_version)


def _validate_execution_and_carried_certificates(db,
        scope: ApplicationScope, *, template, binding_digest: str,
        replacement_partition: str, execution_manifest_digest: str,
        job_id: str, current: PartitionManifest | None) -> None:
    digests = [execution_manifest_digest]
    if current is not None:
        digests.extend(item["certificateDigest"]
                       for item in current.partitions.values())
    rows = db.execute("""SELECT execution.manifest_digest,
        execution.binding_digest,execution.template_digest,
        execution.job_id,execution.manifest,job.status
        FROM epm.calculation_execution_manifest execution
        JOIN epm.job job ON job.workspace_id=execution.workspace_id
          AND job.application_id=execution.application_id
          AND job.job_id=execution.job_id
        WHERE execution.workspace_id=%s AND execution.application_id=%s
          AND execution.manifest_digest=ANY(%s::text[])""", (
        scope.workspace_id, scope.application_id, sorted(set(digests))
    )).fetchall()
    by_digest = {row["manifest_digest"]: row for row in rows}
    if set(by_digest) != set(digests):
        raise ValueError("CALCULATION_PARTITION_CERTIFICATE_INVALID")
    for digest_value in sorted(set(digests)):
        row = by_digest[digest_value]
        manifest = compile_execution_manifest(row["manifest"])
        validate_manifest_against_template(template, manifest)
        if (manifest.digest != digest_value
                or row["binding_digest"] != binding_digest
                or row["template_digest"] != template.digest
                or (digest_value == execution_manifest_digest
                    and (row["job_id"] != job_id
                         or manifest.normalized["targetPartitions"] !=
                            [replacement_partition]))
                or (digest_value != execution_manifest_digest
                    and row["status"] != "published")):
            raise ValueError("CALCULATION_PARTITION_CERTIFICATE_INVALID")
    if current is not None:
        for key, partition in current.partitions.items():
            certificate = by_digest[partition["certificateDigest"]]
            manifest = compile_execution_manifest(certificate["manifest"])
            if key not in manifest.normalized["targetPartitions"]:
                raise ValueError("CALCULATION_PARTITION_CERTIFICATE_INVALID")


def reconcile_calculation_work_request(db, scope: ApplicationScope, *,
        request_id: str) -> dict[str, object]:
    """Derive one request status from its durable task and job states."""
    request = db.execute("""SELECT status FROM epm.calculation_work_request
        WHERE workspace_id=%s AND application_id=%s AND request_id=%s
        FOR UPDATE""", (scope.workspace_id, scope.application_id,
                         request_id)).fetchone()
    if request is None:
        raise ValueError("CALCULATION_WORK_REQUEST_UNAVAILABLE")
    if request["status"] == "no_change":
        return {"requestId": request_id, "status": "no_change",
                "errorCode": None, "taskCounts": {}}
    db.execute("""UPDATE epm.calculation_work_task AS work SET
          status=CASE
            WHEN job.status IN('failed','needs_inspection','published')
              THEN 'failed'
            WHEN job.status='cancelled' THEN 'cancelled'
            WHEN job.status IN('running','staged','cancel_requested')
              THEN 'running'
            ELSE 'queued' END,
          error_code=CASE
            WHEN job.status='published'
              THEN 'CALCULATION_WORK_PUBLICATION_UNRECONCILED'
            WHEN job.status IN('failed','needs_inspection')
              THEN coalesce(job.error_code,'CALCULATION_WORK_JOB_FAILED')
            WHEN job.status='cancelled' THEN coalesce(job.error_code,'INTERRUPTED')
            ELSE NULL END,
          updated_at=transaction_timestamp()
        FROM epm.job AS job WHERE work.workspace_id=%s
          AND work.application_id=%s AND work.request_id=%s
          AND work.status IN('queued','running')
          AND job.workspace_id=work.workspace_id
          AND job.application_id=work.application_id
          AND job.job_id=work.job_id""", (scope.workspace_id,
          scope.application_id, request_id))
    rows = db.execute("""SELECT status,count(*) AS total FROM
        epm.calculation_work_task WHERE workspace_id=%s
        AND application_id=%s AND request_id=%s
        GROUP BY status ORDER BY status""",
        (scope.workspace_id, scope.application_id, request_id)).fetchall()
    counts = {row["status"]: row["total"] for row in rows}
    if counts.get("failed"):
        status = "failed"
    elif counts.get("cancelled"):
        status = "cancelled"
    elif counts and counts.get("published") == sum(counts.values()):
        status = "published"
    elif counts.get("running") or counts.get("queued"):
        status = "running"
    else:
        status = "planned"
    failure = db.execute("""SELECT error_code FROM
        epm.calculation_work_task WHERE workspace_id=%s
        AND application_id=%s AND request_id=%s AND error_code IS NOT NULL
        ORDER BY task_ordinal LIMIT 1""", (scope.workspace_id,
        scope.application_id, request_id)).fetchone()
    error_code = (failure["error_code"] if failure is not None
                  and status in {"failed", "cancelled"} else None)
    db.execute("""UPDATE epm.calculation_work_request SET status=%s,
        error_code=%s,
        updated_at=transaction_timestamp() WHERE workspace_id=%s
        AND application_id=%s AND request_id=%s""", (status, error_code,
        scope.workspace_id, scope.application_id, request_id))
    return {"requestId": request_id, "status": status,
            "errorCode": error_code, "taskCounts": counts}


def publish_calculation_work_task(db, scope: ApplicationScope, *,
        request_id: str, task_ordinal: int, claim: dict[str, object],
        generation_id: str, execution_manifest_digest: str,
        replacement: dict[str, object], dependency_token_digest: str,
        revision: int) -> dict[str, object]:
    """Atomically replace one partition and finish its exact claimed job.

    The worker supplies one already-computed immutable generation and one
    partition result.  This function rechecks the planned epoch, definition,
    prior logical generation and prior partition fragment under row locks.
    A disjoint task may merge over a newer manifest only when this partition's
    exact fragment is unchanged.  Every mutation rolls back if the existing
    job claim/lease final fence fails.
    """
    if (type(task_ordinal) is not int or not 0 <= task_ordinal <= 99_999
            or type(revision) is not int or revision < 1
            or not isinstance(claim, dict)
            or claim.get("job_id") is None):
        raise ValueError("CALCULATION_WORK_PUBLICATION_INVALID")
    task = db.execute("""SELECT binding_digest,stage,partition_key,
        expected_required_epoch,definition_digest,expected_result_state_token,
        expected_partition_certificate_digest,expected_manifest_digest,
        partition_policy_version,job_id,status
        FROM epm.calculation_work_task WHERE workspace_id=%s
        AND application_id=%s AND request_id=%s AND task_ordinal=%s
        FOR UPDATE""", (scope.workspace_id, scope.application_id,
        request_id, task_ordinal)).fetchone()
    if task is None or task["job_id"] != claim["job_id"]:
        raise ValueError("CALCULATION_WORK_TASK_UNAVAILABLE")
    if task["status"] == "published":
        proof = db.execute("""SELECT job.status,receipt.committed_revision,
            receipt.result FROM epm.job AS job
            JOIN epm.operation_receipt AS receipt
              ON receipt.workspace_id=job.workspace_id
             AND receipt.application_id=job.application_id
             AND receipt.operation_id=job.job_id
            WHERE job.workspace_id=%s AND job.application_id=%s
              AND job.job_id=%s""", (scope.workspace_id,
              scope.application_id, claim["job_id"])).fetchone()
        result = None if proof is None else proof["result"]
        if (proof is None or proof["status"] != "published"
                or proof["committed_revision"] != revision
                or generation_id != claim["job_id"]
                or not isinstance(result, dict)
                or result.get("requestId") != request_id
                or result.get("taskOrdinal") != task_ordinal
                or result.get("partitionKey") != task["partition_key"]
                or result.get("jobId") != claim["job_id"]
                or result.get("generationId") != generation_id
                or not isinstance(result.get("resultStateToken"), str)):
            raise ValueError("CALCULATION_WORK_PUBLICATION_REPLAY_MISMATCH")
        request = reconcile_calculation_work_request(
            db, scope, request_id=request_id)
        return {"requestId": request_id, "taskOrdinal": task_ordinal,
                "jobId": claim["job_id"],
                "resultStateToken":result["resultStateToken"],
                "status": "published", "duplicate": True,
                "requestStatus": request["status"]}
    if task["status"] not in {"queued", "running"}:
        raise ValueError("CALCULATION_WORK_TASK_NOT_PUBLISHABLE")
    state = db.execute("""SELECT commit_revision,impact_epoch,
        processed_impact_epoch FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s FOR UPDATE""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None or revision != state["commit_revision"] + 1:
        raise ValueError("STALE_CALCULATION_WORK_REVISION")
    if state["impact_epoch"] != state["processed_impact_epoch"]:
        raise ValueError("IMPACT_COVERAGE_PENDING")
    generation = db.execute("""SELECT generation.job_id,
        generation.generation_kind,generation.result_key,job.program_digest,
        job.subject_id FROM epm.calculation_operation_staging AS generation
        JOIN epm.job AS job ON job.workspace_id=generation.workspace_id
          AND job.application_id=generation.application_id
          AND job.job_id=generation.job_id
        WHERE generation.workspace_id=%s
          AND generation.application_id=%s
          AND generation.generation_id=%s FOR SHARE OF generation,job""",
        (scope.workspace_id, scope.application_id, generation_id)).fetchone()
    if (generation is None or generation["job_id"] != claim["job_id"]
            or generation["generation_kind"] != "partition_manifest"):
        raise ValueError("CALCULATION_WORK_GENERATION_INVALID")
    scope_state = db.execute("""SELECT current_result_state_token,required_epoch,
        published_epoch,definition_digest,coverage,presence,
        dependency_token_digest FROM epm.calculation_scope_state
        WHERE workspace_id=%s AND application_id=%s AND binding_digest=%s
        AND stage=%s AND partition_key=%s FOR UPDATE""",
        (scope.workspace_id, scope.application_id, task["binding_digest"],
         task["stage"], task["partition_key"])).fetchone()
    if (scope_state is None
            or scope_state["required_epoch"] !=
                task["expected_required_epoch"]
            or scope_state["definition_digest"] != task["definition_digest"]
            or scope_state["coverage"] != "complete"):
        raise ValueError("STALE_CALCULATION_SCOPE_PUBLICATION")
    replacement = dict(replacement)
    if (replacement.get("partitionKey") != task["partition_key"]
            or replacement.get("certificateDigest") !=
                execution_manifest_digest):
        raise ValueError("CALCULATION_WORK_PARTITION_INVALID")
    policy_version = task["partition_policy_version"] or 1
    template, profile = _qualified_coordinate_partition_profile(db, scope,
        binding_digest=task["binding_digest"], stage=task["stage"],
        definition_digest=task["definition_digest"],
        partition_policy_version=policy_version)
    previous = db.execute("""SELECT state_token FROM
        epm.calculation_result_state WHERE workspace_id=%s
        AND application_id=%s AND result_key=%s FOR UPDATE""",
        (scope.workspace_id, scope.application_id,
         generation["result_key"])).fetchone()
    current_token = None if previous is None else previous["state_token"]
    current = (None if current_token is None else
               _current_partition_manifest(db, scope,
                   result_state_token=current_token))
    _validate_execution_and_carried_certificates(db, scope,
        template=template, binding_digest=task["binding_digest"],
        replacement_partition=task["partition_key"],
        execution_manifest_digest=execution_manifest_digest,
        job_id=claim["job_id"], current=current)
    if ((task["expected_partition_certificate_digest"] is None) !=
            (task["expected_result_state_token"] is None)
            or (task["expected_result_state_token"] is None) !=
            (task["expected_manifest_digest"] is None)):
        raise ValueError("CALCULATION_WORK_EXPECTATION_INVALID")
    if (task["expected_result_state_token"] == current_token
            and current is not None
            and current.digest != task["expected_manifest_digest"]):
        raise ValueError("CALCULATION_WORK_EXPECTATION_INVALID")
    current_partition = (None if current is None else
                         current.partitions.get(task["partition_key"]))
    if current_partition is None:
        if (scope_state["current_result_state_token"] is not None
                or scope_state["dependency_token_digest"] is not None):
            raise ValueError("STALE_CALCULATION_SCOPE_PUBLICATION")
    elif (scope_state["current_result_state_token"] != current_token
            or scope_state["dependency_token_digest"] !=
                current_partition["certificateDigest"]
            or scope_state["presence"] != current_partition["presence"]):
        raise ValueError("STALE_CALCULATION_SCOPE_PUBLICATION")
    manifest = merge_coordinate_partitions(current,
        binding_digest=task["binding_digest"],
        partition_policy_version=policy_version,
        declared_partitions=profile.partition_keys,
        expected_certificates={task["partition_key"]:
            task["expected_partition_certificate_digest"]},
        replacements=[replacement],
        execution_manifest_digest=execution_manifest_digest)
    from .postgres_calculation_dependencies import (
        publish_scope_current, store_partition_manifest)
    store_partition_manifest(db, scope, generation_id=generation_id,
                             manifest=manifest)
    from .postgres_current_result_publication import (
        CurrentPartitionMergeIntent,
        advance_result_head_during_conversion,
    )
    current_result=advance_result_head_during_conversion(db,scope,
        result_key=generation["result_key"],operation_id=generation_id,
        committed_revision=revision,
        partition_merge=CurrentPartitionMergeIntent(profile=profile,
            replacement_partition=task["partition_key"],
            prior_manifest=current,next_manifest=manifest))
    if current is not None:
        for key, partition in current.partitions.items():
            if key == task["partition_key"]:
                continue
            rotated = db.execute("""UPDATE epm.calculation_scope_state SET
                current_result_state_token=%s,
                updated_at=transaction_timestamp()
                WHERE workspace_id=%s AND application_id=%s
                  AND binding_digest=%s AND stage=%s AND partition_key=%s
                  AND current_result_state_token=%s
                  AND dependency_token_digest=%s
                  AND definition_digest=%s""", (
                current_result["state_token"], scope.workspace_id,
                scope.application_id, task["binding_digest"], task["stage"],
                key, current_token, partition["certificateDigest"],
                task["definition_digest"])).rowcount
            if rotated != 1:
                raise ValueError("STALE_CALCULATION_CARRIED_PARTITION")
    publish_scope_current(db,scope,
        binding_digest=task["binding_digest"],stage=task["stage"],
        partition_key=task["partition_key"],
        expected_required_epoch=task["expected_required_epoch"],
        result_state_token=current_result["state_token"],
        dependency_token_digest=dependency_token_digest,
        presence=replacement["presence"],
        definition_digest=task["definition_digest"],
        expected_result_state_token=scope_state[
            "current_result_state_token"])
    updated = db.execute("""UPDATE epm.calculation_work_task SET
        status='published',error_code=NULL,updated_at=transaction_timestamp()
        WHERE workspace_id=%s AND application_id=%s AND request_id=%s
        AND task_ordinal=%s AND job_id=%s AND status IN('queued','running')""",
        (scope.workspace_id, scope.application_id, request_id, task_ordinal,
         claim["job_id"])).rowcount
    if updated != 1:
        raise ValueError("CALCULATION_WORK_TASK_PUBLICATION_RACE")
    request = reconcile_calculation_work_request(
        db, scope, request_id=request_id)
    result = {"requestId": request_id, "taskOrdinal": task_ordinal,
        "jobId": claim["job_id"], "generationId": generation_id,
        "resultStateToken":current_result["state_token"],
        "resultKey": generation["result_key"],
        "partitionManifestDigest": manifest.digest,
        "partitionKey": task["partition_key"],
        "requestStatus": request["status"]}
    db.execute("""UPDATE epm.application_state SET commit_revision=%s
        WHERE workspace_id=%s AND application_id=%s""", (revision,
        scope.workspace_id, scope.application_id))
    db.execute("""INSERT INTO epm.operation_receipt(
        workspace_id,application_id,operation_id,command_digest,actor_id,
        committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
        (scope.workspace_id, scope.application_id, claim["job_id"],
         generation["program_digest"], generation["subject_id"], revision,
         Jsonb(result)))
    from .postgres_calculation_impact import (
        calculation_publication_impact, record_calculation_impact)
    impact = calculation_publication_impact(operation_id=claim["job_id"],
        causal_revision=revision, result_key=generation["result_key"],
        existed=previous is not None)
    record_calculation_impact(db, scope, operation_id=claim["job_id"],
                              impact=impact)
    from .postgres_job_final_fence import finish_published_job
    finish_published_job(db, scope, claim, revision=revision, result=result)
    return {**result, "jobId": claim["job_id"], "status": "published",
            "duplicate": False}
