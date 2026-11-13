"""Single publication boundary for authoritative current calculation results.

Legacy generation-keyed relations are private writer staging while publishers
are converted. The authoritative result and its exact provenance are owned by
the current-result relations and never use a retained generation as history.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from .calculation_coordinate_partition_contract import (
    CoordinatePartitionProfile,
)
from .calculation_partition_manifest_contract import PartitionManifest
from .current_object_contract import new_state_token
from .persistence_contract import ApplicationScope


_RESULT_KEY = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")


@dataclass(frozen=True, slots=True)
class CurrentPartitionMergeIntent:
    profile: CoordinatePartitionProfile
    replacement_partition: str
    prior_manifest: PartitionManifest | None
    next_manifest: PartitionManifest


def _install_partition_profile(db, profile: CoordinatePartitionProfile) -> None:
    db.execute("""CREATE TEMP TABLE IF NOT EXISTS
        epm_result_partition_scope(
          partition_key text NOT NULL,
          dimension_id text NOT NULL,
          member_ids text[] NOT NULL,
          PRIMARY KEY(partition_key,dimension_id)
        ) ON COMMIT DROP""")
    db.execute("TRUNCATE pg_temp.epm_result_partition_scope")
    for partition, dimensions in sorted(profile.scopes.items()):
        for dimension, members in sorted(dimensions.items()):
            db.execute("""INSERT INTO pg_temp.epm_result_partition_scope(
                partition_key,dimension_id,member_ids) VALUES(%s,%s,%s)""",
                (partition, dimension, sorted(members)))


def _partition_payload_counts(db, scope: ApplicationScope, *,
        result_key: str | None = None,
        operation_id: str | None = None) -> tuple[dict[str, int], str | None]:
    """Classify each actual payload row by one installed coordinate scope."""
    if (result_key is None) == (operation_id is None):
        raise ValueError("CURRENT_RESULT_PARTITION_CLASSIFICATION_INVALID")
    if result_key is not None:
        key = result_key
        branches = [f"""SELECT coordinate_id,'{kind}' kind FROM epm.{table}
            WHERE workspace_id=%s AND application_id=%s AND result_key=%s"""
            for table, kind in (("calculation_result_current", "numeric"),
                ("calculation_unit_result_current", "typed_currency"),
                ("calculation_ratio_result_current", "ratio"))]
    else:
        key = operation_id
        branches = [f"""SELECT coordinate_id,'{kind}' kind FROM epm.{table}
            WHERE workspace_id=%s AND application_id=%s AND generation_id=%s"""
            for table, kind in (("calculation_result_staging", "numeric"),
                ("calculation_unit_result_staging", "typed_currency"),
                ("calculation_ratio_result_staging", "ratio"))]
    payload = " UNION ALL ".join(branches)
    parameters = tuple(value for _ in branches for value in (
        scope.workspace_id, scope.application_id, key))
    row = db.execute(f"""WITH payload AS ({payload}), coordinate_payload AS (
          SELECT coordinate_id,kind,count(*)::bigint row_count
          FROM payload GROUP BY coordinate_id,kind
        ), owners AS (
          SELECT payload.coordinate_id,payload.kind,payload.row_count,
            candidate.partition_key
          FROM coordinate_payload payload
          JOIN epm.coordinate coordinate ON
            coordinate.workspace_id=%s AND coordinate.application_id=%s
            AND coordinate.coordinate_id=payload.coordinate_id
          CROSS JOIN (SELECT DISTINCT partition_key
            FROM pg_temp.epm_result_partition_scope) candidate
          WHERE NOT EXISTS(
            SELECT 1 FROM pg_temp.epm_result_partition_scope required
            WHERE required.partition_key=candidate.partition_key
              AND NOT (coordinate.members->>required.dimension_id
                       = ANY(required.member_ids)))
        ), classified AS (
          SELECT payload.coordinate_id,payload.kind,payload.row_count,
            count(owner.partition_key) owner_count,
            min(owner.partition_key) partition_key
          FROM coordinate_payload payload LEFT JOIN owners owner
            USING(coordinate_id,kind,row_count)
          GROUP BY payload.coordinate_id,payload.kind,payload.row_count
        ), partition_counts AS (
          SELECT partition_key,sum(row_count)::bigint row_count
          FROM classified WHERE owner_count=1 GROUP BY partition_key
        ) SELECT
          (SELECT count(*) FROM classified WHERE owner_count<>1) invalid_rows,
          (SELECT count(DISTINCT kind) FROM classified) kind_count,
          (SELECT min(kind) FROM classified) payload_kind,
          coalesce((SELECT jsonb_object_agg(partition_key,row_count)
                    FROM partition_counts),'{{}}'::jsonb) partition_counts""",
        (*parameters, scope.workspace_id, scope.application_id)).fetchone()
    if row is None or row["invalid_rows"] != 0 or row["kind_count"] > 1:
        raise ValueError("CURRENT_RESULT_PARTITION_OWNERSHIP_INVALID")
    return ({str(key): int(value)
             for key, value in row["partition_counts"].items()},
            row["payload_kind"])


def _manifest_counts(manifest: PartitionManifest | None) -> dict[str, int]:
    return ({} if manifest is None else
            {key: int(value["rowCount"])
             for key, value in manifest.partitions.items()})


def _delete_replacement_partition(db, scope: ApplicationScope, *,
        result_key: str, partition_key: str) -> None:
    coordinate_ids = """SELECT coordinate.coordinate_id
        FROM epm.coordinate coordinate
        WHERE coordinate.workspace_id=%s AND coordinate.application_id=%s
          AND NOT EXISTS(
            SELECT 1 FROM pg_temp.epm_result_partition_scope required
            WHERE required.partition_key=%s
              AND NOT (coordinate.members->>required.dimension_id
                       = ANY(required.member_ids)))"""
    parameters = (scope.workspace_id, scope.application_id, partition_key)
    for relation in ("rollup_placement_path_edge_current",
            "rollup_source_lineage_current", "rollup_placement_path_current",
            "allocation_basis_lineage_current",
            "calculation_ratio_result_current",
            "calculation_unit_result_current", "calculation_result_current"):
        db.execute(f"""DELETE FROM epm.{relation} WHERE workspace_id=%s
            AND application_id=%s AND result_key=%s
            AND coordinate_id IN ({coordinate_ids})""", (
            scope.workspace_id, scope.application_id, result_key,
            *parameters))


def _replace_current_payload(db, scope: ApplicationScope, *,
        result_key: str, operation_id: str, state_token: str,
        partition_merge: CurrentPartitionMergeIntent | None = None) -> dict:
    """Replace all three typed current payloads from one private worker result."""
    keys=(scope.workspace_id,scope.application_id,result_key)
    if partition_merge is None:
        for relation in ("calculation_partition_current",
                         "calculation_partition_manifest_current",
                         "rollup_source_lineage_current",
                         "rollup_placement_path_edge_current",
                         "rollup_placement_path_current",
                         "allocation_basis_lineage_current",
                         "calculation_ratio_result_current",
                         "calculation_unit_result_current",
                         "calculation_result_current"):
            db.execute(f"""DELETE FROM epm.{relation} WHERE workspace_id=%s
                AND application_id=%s AND result_key=%s""",keys)
    else:
        intent = partition_merge
        profile = intent.profile
        if (intent.replacement_partition not in profile.scopes
                or intent.next_manifest.normalized["bindingDigest"] !=
                    profile.binding_digest
                or intent.next_manifest.normalized["partitionPolicyVersion"] !=
                    profile.partition_policy_version
                or (intent.prior_manifest is not None and
                    (intent.prior_manifest.normalized["bindingDigest"] !=
                        profile.binding_digest
                     or intent.prior_manifest.normalized[
                        "partitionPolicyVersion"] !=
                        profile.partition_policy_version))):
            raise ValueError("CURRENT_RESULT_PARTITION_INTENT_INVALID")
        _install_partition_profile(db, profile)
        current_counts, current_kind = _partition_payload_counts(
            db, scope, result_key=result_key)
        staged_counts, staged_kind = _partition_payload_counts(
            db, scope, operation_id=operation_id)
        expected_current = {key: value for key, value in
            _manifest_counts(intent.prior_manifest).items() if value}
        expected_staged_count = int(intent.next_manifest.partitions[
            intent.replacement_partition]["rowCount"])
        expected_staged = ({intent.replacement_partition:
                            expected_staged_count}
                           if expected_staged_count else {})
        if (current_counts != expected_current
                or staged_counts != expected_staged
                or (current_kind and staged_kind
                    and current_kind != staged_kind)):
            raise ValueError("CURRENT_RESULT_PARTITION_PAYLOAD_MISMATCH")
        for relation in ("calculation_partition_current",
                         "calculation_partition_manifest_current"):
            db.execute(f"""DELETE FROM epm.{relation} WHERE workspace_id=%s
                AND application_id=%s AND result_key=%s""",keys)
        _delete_replacement_partition(db, scope, result_key=result_key,
                                      partition_key=intent.replacement_partition)
    db.execute("""INSERT INTO epm.calculation_result_current(
        workspace_id,application_id,result_key,coordinate_id,source_amount,
        source_change_id,source_present,amount,source_lookup_lineage)
        SELECT workspace_id,application_id,%s,coordinate_id,source_amount,
          source_change_id,source_present,amount,source_lookup_lineage
        FROM epm.calculation_result_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.calculation_unit_result_current(
        workspace_id,application_id,result_key,coordinate_id,
        output_unit_currency_dimension_id,output_unit_currency_member_id,
        source_amount,source_change_id,source_evidence_digest,amount,
        rate_strategy,rate_numerator,rate_denominator,rate_sources,
        source_lookup_lineage)
        SELECT workspace_id,application_id,%s,coordinate_id,
          output_unit_currency_dimension_id,output_unit_currency_member_id,
          source_amount,source_change_id,source_evidence_digest,amount,
          rate_strategy,rate_numerator,rate_denominator,rate_sources,
          source_lookup_lineage
        FROM epm.calculation_unit_result_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.calculation_ratio_result_current(
        workspace_id,application_id,result_key,coordinate_id,source_amount,
        source_change_id,source_present,ratio,source_lookup_lineage)
        SELECT workspace_id,application_id,%s,coordinate_id,source_amount,
          source_change_id,source_present,ratio,source_lookup_lineage
        FROM epm.calculation_ratio_result_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.allocation_basis_lineage_current
        SELECT workspace_id,application_id,%s,coordinate_id,
          basis_coordinate_id,basis_amount,basis_change_id,total_basis,
          base_units,remainder_numerator,extra_unit
        FROM epm.allocation_basis_lineage_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.rollup_placement_path_current
        SELECT workspace_id,application_id,%s,coordinate_id,
          placement_path_id,path_ordinal,hierarchy_dimension_id,
          root_member_id,leaf_member_id,relationship_count,
          hierarchy_state_token
        FROM epm.rollup_placement_path_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.rollup_placement_path_edge_current
        SELECT workspace_id,application_id,%s,coordinate_id,
          placement_path_id,edge_ordinal,relationship_id,
          hierarchy_dimension_id,parent_member_id,child_member_id
        FROM epm.rollup_placement_path_edge_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.rollup_source_lineage_current(
        workspace_id,application_id,result_key,coordinate_id,
        source_coordinate_id,source_amount,source_change_id,
        hierarchy_dimension_id,source_selection,placement_relationship_id,
        placement_parent_member_id,placement_child_member_id,lineage_ordinal,
        placement_path_id,placement_path_ordinal,hierarchy_state_token)
        SELECT workspace_id,application_id,%s,coordinate_id,
          source_coordinate_id,source_amount,source_change_id,
          hierarchy_dimension_id,source_selection,placement_relationship_id,
          placement_parent_member_id,placement_child_member_id,lineage_ordinal,
          placement_path_id,placement_path_ordinal,hierarchy_state_token
        FROM epm.rollup_source_lineage_staging WHERE workspace_id=%s
          AND application_id=%s AND generation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""INSERT INTO epm.calculation_partition_manifest_current(
        workspace_id,application_id,result_key,result_state_token,
        binding_digest,execution_manifest_digest,partition_policy_version,
        partition_map_digest,partition_map)
        SELECT workspace_id,application_id,%s,%s,binding_digest,
          execution_manifest_digest,partition_policy_version,
          partition_map_digest,partition_map
        FROM epm.calculation_partition_manifest_staging WHERE workspace_id=%s
          AND application_id=%s AND operation_id=%s""",(
        result_key,state_token,scope.workspace_id,scope.application_id,
        operation_id))
    db.execute("""INSERT INTO epm.calculation_partition_current(
        workspace_id,application_id,result_key,partition_key,
        certificate_digest,presence,row_count)
        SELECT workspace_id,application_id,%s,partition_key,
          certificate_digest,presence,row_count
        FROM epm.calculation_partition_staging WHERE workspace_id=%s
          AND application_id=%s AND operation_id=%s""",(
        result_key,scope.workspace_id,scope.application_id,operation_id))
    db.execute("""DELETE FROM epm.calculation_partition_manifest_staging
        WHERE workspace_id=%s AND application_id=%s AND operation_id=%s""",
        (scope.workspace_id,scope.application_id,operation_id))
    if partition_merge is not None:
        assembled_counts, _ = _partition_payload_counts(
            db, scope, result_key=result_key)
        expected_assembled = {key: value for key, value in
            _manifest_counts(partition_merge.next_manifest).items() if value}
        if assembled_counts != expected_assembled:
            raise ValueError("CURRENT_RESULT_PARTITION_ASSEMBLY_MISMATCH")
    summary=db.execute("""WITH payload AS (
      SELECT jsonb_build_object('kind','numeric','coordinateId',coordinate_id,
        'sourceAmount',source_amount,'sourceChangeId',source_change_id,
        'sourcePresent',source_present,'amount',amount,
        'sourceLookupLineage',source_lookup_lineage) value
        FROM epm.calculation_result_current WHERE workspace_id=%s
         AND application_id=%s AND result_key=%s
      UNION ALL SELECT jsonb_build_object('kind','typed_currency',
        'coordinateId',coordinate_id,'unitDimensionId',output_unit_currency_dimension_id,
        'unitMemberId',output_unit_currency_member_id,'sourceAmount',source_amount,
        'sourceChangeId',source_change_id,'sourceEvidenceDigest',source_evidence_digest,
        'amount',amount,'rateStrategy',rate_strategy,'rateNumerator',rate_numerator,
        'rateDenominator',rate_denominator,'rateSources',rate_sources,
        'sourceLookupLineage',source_lookup_lineage)
        FROM epm.calculation_unit_result_current WHERE workspace_id=%s
         AND application_id=%s AND result_key=%s
      UNION ALL SELECT jsonb_build_object('kind','ratio','coordinateId',coordinate_id,
        'sourceAmount',source_amount,'sourceChangeId',source_change_id,
        'sourcePresent',source_present,'ratio',ratio,
        'sourceLookupLineage',source_lookup_lineage)
        FROM epm.calculation_ratio_result_current WHERE workspace_id=%s
         AND application_id=%s AND result_key=%s), kinds AS (
      SELECT count(*) row_count,count(DISTINCT value->>'kind') kind_count,
        min(value->>'kind') payload_kind FROM payload)
      SELECT CASE WHEN row_count=0 THEN 'empty' ELSE payload_kind END payload_kind,
        row_count,encode(sha256(convert_to(coalesce((SELECT jsonb_agg(value
          ORDER BY value->>'kind',value->>'coordinateId',
          value->>'unitDimensionId',value->>'unitMemberId')::text FROM payload),
          '[]'),'UTF8')),'hex') content_digest,kind_count
      FROM kinds""",(*keys,*keys,*keys)).fetchone()
    if summary is None or summary["kind_count"] > 1:
        raise ValueError("CURRENT_RESULT_PAYLOAD_KIND_INVALID")
    # A writer operation is scratch state, never product history.  Delete the
    # exact operation after its current payload and content certificate have
    # been materialized.  Any later failure rolls these deletes back with the
    # publication transaction.
    for relation in (
            "rollup_placement_path_edge_staging",
            "rollup_source_lineage_staging",
            "rollup_placement_path_staging",
            "allocation_basis_lineage_staging",
            "calculation_ratio_result_staging",
            "calculation_unit_result_staging",
            "calculation_result_staging"):
        db.execute(f"""DELETE FROM epm.{relation} WHERE workspace_id=%s
            AND application_id=%s AND generation_id=%s""",(
            scope.workspace_id,scope.application_id,operation_id))
    deleted=db.execute("""DELETE FROM epm.calculation_operation_staging
        WHERE workspace_id=%s AND application_id=%s AND generation_id=%s
        RETURNING generation_id""",(
        scope.workspace_id,scope.application_id,operation_id)).fetchone()
    if deleted is None:
        raise ValueError("CURRENT_RESULT_SOURCE_CLEANUP_MISSING")
    return dict(summary)


def advance_result_head_during_conversion(
        db, scope: ApplicationScope, *, result_key: str,
        operation_id: str, committed_revision: int,
        partition_merge: CurrentPartitionMergeIntent | None = None) -> dict:
    """Advance the legacy payload head and rotate its sole current-state fence."""
    if (not isinstance(result_key, str) or _RESULT_KEY.fullmatch(result_key) is None
            or not isinstance(operation_id, str)
            or _OPERATION_ID.fullmatch(operation_id) is None
            or type(committed_revision) is not int or committed_revision < 1):
        raise ValueError("CURRENT_RESULT_PUBLICATION_ARGUMENT_INVALID")
    prior = db.execute("""SELECT source_operation_id,
        committed_revision AS published_revision,state_token
        FROM epm.calculation_result_state
        WHERE workspace_id=%s AND application_id=%s AND result_key=%s
        FOR UPDATE""", (scope.workspace_id, scope.application_id,
                         result_key)).fetchone()
    prior_revision = (None if prior is None else
                      (prior["published_revision"] if hasattr(prior, "keys")
                       else prior[1]))
    if prior_revision is not None and prior_revision >= committed_revision:
        raise ValueError("CURRENT_RESULT_PUBLICATION_REVISION_STALE")
    provenance=db.execute("""SELECT job.job_id AS source_job_id,generation.function_name,
        generation.source_commit_revision,
        generation.source_metadata_revision,generation.generation_kind,
        job.expected_data_revision AS source_data_revision,
        generation.source_policy_revision,job.compiler_version,
        job.program_digest
        FROM epm.calculation_operation_staging generation JOIN epm.job job
          ON job.workspace_id=generation.workspace_id
         AND job.application_id=generation.application_id
         AND job.job_id=generation.job_id
        WHERE generation.workspace_id=%s AND generation.application_id=%s
          AND generation.generation_id=%s AND generation.result_key=%s""",(
        scope.workspace_id,scope.application_id,operation_id,
        result_key)).fetchone()
    if provenance is None:
        raise ValueError("CURRENT_RESULT_SOURCE_UNAVAILABLE")
    if provenance.get('source_job_id') != operation_id:
        raise ValueError("CURRENT_RESULT_SOURCE_IDENTITY_MISMATCH")
    state_token = new_state_token()
    if prior is not None:
        prior_token = prior['state_token'] if hasattr(prior, 'keys') else prior[2]
        # A replacement binding cannot leave an obsolete current reference to
        # the head token being retired. Keep incoming-binding references for
        # publish_scope_current's existing required-epoch/old-token CAS. Other
        # work retains its old expectation and therefore fails that same CAS.
        # Do not rebind old certificates or reset their impact epochs.
        db.execute("""UPDATE epm.calculation_scope_state AS target
            SET current_result_state_token=NULL,dependency_token_digest=NULL,
                presence='unknown',updated_at=transaction_timestamp()
            WHERE target.workspace_id=%s AND target.application_id=%s
              AND target.current_result_state_token=%s
              AND NOT EXISTS(SELECT 1 FROM epm.calculation_partition_manifest_staging incoming
                WHERE incoming.workspace_id=target.workspace_id
                  AND incoming.application_id=target.application_id
                  AND incoming.operation_id=%s
                  AND incoming.binding_digest=target.binding_digest)""",
            (scope.workspace_id,scope.application_id,prior_token,operation_id))
    payload=_replace_current_payload(db,scope,result_key=result_key,
        operation_id=operation_id,state_token=state_token,
        partition_merge=partition_merge)
    db.execute("""INSERT INTO epm.calculation_result_state(
        workspace_id,application_id,result_key,state_token,
        source_operation_id,committed_revision,payload_kind,row_count,
        content_digest,source_function,source_commit_revision,
        source_metadata_revision,source_data_revision,source_policy_revision,
        source_compiler_version,source_program_digest,payload_layout)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(workspace_id,application_id,result_key) DO UPDATE SET
          state_token=EXCLUDED.state_token,
          source_operation_id=EXCLUDED.source_operation_id,
          committed_revision=EXCLUDED.committed_revision,
          payload_kind=EXCLUDED.payload_kind,row_count=EXCLUDED.row_count,
          content_digest=EXCLUDED.content_digest,
          source_function=EXCLUDED.source_function,
          source_commit_revision=EXCLUDED.source_commit_revision,
          source_metadata_revision=EXCLUDED.source_metadata_revision,
          source_data_revision=EXCLUDED.source_data_revision,
          source_policy_revision=EXCLUDED.source_policy_revision,
          source_compiler_version=EXCLUDED.source_compiler_version,
          source_program_digest=EXCLUDED.source_program_digest,
          payload_layout=EXCLUDED.payload_layout,
          updated_at=transaction_timestamp()""", (
        scope.workspace_id, scope.application_id, result_key, state_token,
        operation_id, committed_revision,payload["payload_kind"],
        payload["row_count"],payload["content_digest"],
        provenance["function_name"],provenance["source_commit_revision"],
        provenance["source_metadata_revision"],
        provenance["source_data_revision"],
        provenance["source_policy_revision"],provenance["compiler_version"],
        provenance["program_digest"],provenance["generation_kind"]))
    result = {"result_key": result_key, "state_token": state_token,
              "source_operation_id": operation_id,
              "committed_revision": committed_revision,
              "payload_kind":payload["payload_kind"],
              "row_count":payload["row_count"],
              "content_digest":payload["content_digest"]}
    if prior is not None:
        result["prior"] = (dict(prior) if hasattr(prior, "keys") else
                           {"source_operation_id": prior[0],
                            "published_revision": prior[1]})
    return result
