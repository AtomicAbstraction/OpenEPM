-- Extend typed period-NCI sealing to the explicitly versioned IC-adjusted
-- typed Full source.  Admitted v7 rows retain their exact contract.
DO $$BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=160) THEN
  RAISE EXCEPTION 'MIGRATION_0161_PREDECESSOR_0160_REQUIRED';
 END IF;
END$$;

CREATE OR REPLACE FUNCTION epm.period_attribution_line_open()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM period_inserted i
  JOIN epm.calculation_generation g USING(workspace_id,application_id,generation_id)
  JOIN epm.job j ON j.workspace_id=g.workspace_id
   AND j.application_id=g.application_id AND j.job_id=g.job_id
  WHERE g.function_name IN ('consolidation.nci.period.publish',
                            'consolidation.nci.period.withdraw')
   AND (j.compiler_version IN ('period-nci-attribution-v7-typed-unit',
        'period-nci-attribution-v8-ic-adjusted-typed-unit')
        OR g.function_name<>'consolidation.nci.period.publish'
        OR j.status<>'running')) THEN
  RAISE EXCEPTION 'PERIOD_ATTRIBUTION_GENERATION_SEALED' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.period_attribution_line_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.period_attribution_line_open() TO epm_runtime;

CREATE OR REPLACE FUNCTION epm.period_attribution_unit_line_open()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM typed_period_inserted i
  JOIN epm.calculation_generation g USING(workspace_id,application_id,generation_id)
  JOIN epm.job j ON j.workspace_id=g.workspace_id
   AND j.application_id=g.application_id AND j.job_id=g.job_id
  WHERE g.function_name IN ('consolidation.nci.period.publish',
                            'consolidation.nci.period.withdraw')
   AND (g.function_name<>'consolidation.nci.period.publish'
        OR j.compiler_version NOT IN ('period-nci-attribution-v7-typed-unit',
             'period-nci-attribution-v8-ic-adjusted-typed-unit')
        OR j.status<>'running')) THEN
  RAISE EXCEPTION 'PERIOD_ATTRIBUTION_GENERATION_SEALED' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.period_attribution_unit_line_open() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.period_attribution_unit_line_open() TO epm_runtime;

CREATE OR REPLACE FUNCTION epm.period_attribution_pointer_complete()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE kind text; compiler text; expected_rows integer; actual_rows bigint;
 generation_key text; generation_revision bigint; basis_min numeric;
 basis_max numeric; attributed numeric; evidence_min text; evidence_max text;
 unit_count bigint; lineage_count bigint; invalid_currency_rows bigint;
 legacy_rows bigint; expected_contract text;
 receipt jsonb; lineage_min jsonb; expected_source_digest text;
BEGIN
 SELECT g.function_name,g.row_count,g.result_key,g.published_revision,
        j.compiler_version,j.normalized_program->>'expectedSourceDigest'
 INTO kind,expected_rows,generation_key,generation_revision,compiler,
      expected_source_digest
 FROM epm.calculation_generation g JOIN epm.job j
  ON j.workspace_id=g.workspace_id AND j.application_id=g.application_id
  AND j.job_id=g.job_id
 WHERE g.workspace_id=NEW.workspace_id AND g.application_id=NEW.application_id
  AND g.generation_id=NEW.generation_id;
 IF kind IN ('consolidation.nci.period.publish',
             'consolidation.nci.period.withdraw') THEN
  SELECT o.result INTO receipt FROM epm.operation_receipt o
   WHERE o.workspace_id=NEW.workspace_id
    AND o.application_id=NEW.application_id
    AND o.operation_id=NEW.generation_id
    AND o.committed_revision=NEW.published_revision
    AND o.result->>'function'=kind;
  IF compiler IN ('period-nci-attribution-v7-typed-unit',
                  'period-nci-attribution-v8-ic-adjusted-typed-unit') THEN
   expected_contract := CASE compiler
    WHEN 'period-nci-attribution-v7-typed-unit'
     THEN 'owner_declared_typed_full_contribution_v1'
    ELSE 'owner_declared_ic_adjusted_typed_full_contribution_v1' END;
   SELECT count(*) INTO legacy_rows FROM epm.calculation_result
    WHERE workspace_id=NEW.workspace_id
     AND application_id=NEW.application_id
     AND generation_id=NEW.generation_id;
   SELECT count(*),min(r.source_amount),max(r.source_amount),sum(r.amount),
    min(r.source_evidence_digest),max(r.source_evidence_digest),
    count(DISTINCT (r.output_unit_currency_dimension_id,
                    r.output_unit_currency_member_id)),
    count(DISTINCT r.source_lookup_lineage),
    min(r.source_lookup_lineage::text)::jsonb,
    count(*) FILTER(WHERE EXISTS(SELECT 1 FROM epm.dimension d
      WHERE d.workspace_id=r.workspace_id AND d.application_id=r.application_id
       AND d.model_role='Currency' AND d.status='Active'
       AND c.members ? d.dimension_id))
   INTO actual_rows,basis_min,basis_max,attributed,evidence_min,evidence_max,
        unit_count,lineage_count,lineage_min,invalid_currency_rows
   FROM epm.calculation_unit_result r JOIN epm.coordinate c
    USING(workspace_id,application_id,coordinate_id)
   WHERE r.workspace_id=NEW.workspace_id
    AND r.application_id=NEW.application_id
    AND r.generation_id=NEW.generation_id;
   IF expected_source_digest IS NULL OR legacy_rows<>0
      OR generation_key<>NEW.result_key
      OR generation_revision<>NEW.published_revision OR expected_rows<>2
      OR actual_rows<>2 OR basis_min IS NULL OR basis_min<>basis_max
      OR attributed<>basis_min OR evidence_min IS NULL
      OR evidence_min<>evidence_max OR unit_count<>1
      OR invalid_currency_rows<>0 OR lineage_count<>1
      OR receipt IS NULL
      OR receipt->>'generationId' IS DISTINCT FROM NEW.generation_id
      OR receipt->>'resultKey' IS DISTINCT FROM NEW.result_key
      OR (receipt->>'publishedRevision')::bigint IS DISTINCT FROM NEW.published_revision
      OR receipt->>'sourceContract' IS DISTINCT FROM expected_contract
      OR receipt->>'sourceDigest' IS DISTINCT FROM expected_source_digest
      OR receipt->>'sourceEvidenceDigest' IS DISTINCT FROM evidence_min
      OR receipt->'sourceLookupLineage' IS DISTINCT FROM lineage_min
      OR (receipt->'sourceEvidence'->>'basisAmount')::numeric IS DISTINCT FROM basis_min
      OR receipt->'outputUnit' IS DISTINCT FROM jsonb_build_object(
         'dimensionId',(SELECT output_unit_currency_dimension_id
           FROM epm.calculation_unit_result WHERE workspace_id=NEW.workspace_id
           AND application_id=NEW.application_id
           AND generation_id=NEW.generation_id LIMIT 1),
         'memberId',(SELECT output_unit_currency_member_id
           FROM epm.calculation_unit_result WHERE workspace_id=NEW.workspace_id
           AND application_id=NEW.application_id
           AND generation_id=NEW.generation_id LIMIT 1))
      OR lineage_min->0->>'sourceDigest' IS DISTINCT FROM expected_source_digest
   THEN
    RAISE EXCEPTION 'PERIOD_ATTRIBUTION_PUBLICATION_INCOMPLETE'
      USING ERRCODE='23514';
   END IF;
  ELSE
   SELECT count(*),min(source_amount),max(source_amount),sum(amount)
    INTO actual_rows,basis_min,basis_max,attributed
   FROM epm.calculation_result WHERE workspace_id=NEW.workspace_id
    AND application_id=NEW.application_id
    AND generation_id=NEW.generation_id;
   IF generation_key<>NEW.result_key
      OR generation_revision<>NEW.published_revision
      OR expected_rows<>actual_rows OR receipt IS NULL
      OR (kind='consolidation.nci.period.publish' AND
          (actual_rows<>2 OR basis_min<>basis_max OR attributed<>basis_min))
      OR (kind='consolidation.nci.period.withdraw' AND actual_rows<>0) THEN
    RAISE EXCEPTION 'PERIOD_ATTRIBUTION_PUBLICATION_INCOMPLETE'
      USING ERRCODE='23514';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.period_attribution_pointer_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.period_attribution_pointer_complete() TO epm_runtime;
