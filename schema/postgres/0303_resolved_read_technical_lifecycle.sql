-- Generalize the qualified durable aggregate-query lifecycle for resolved
-- reads without introducing a second queue, cursor, lease or cleanup model.

ALTER TABLE epm.cube_aggregate_query
    ADD COLUMN request_family text NOT NULL DEFAULT 'aggregate'
    CHECK(request_family IN ('aggregate','resolved_read'));

ALTER TABLE epm.cube_aggregate_result
    ADD COLUMN resolved_row jsonb;

ALTER TABLE epm.cube_aggregate_result
    DROP CONSTRAINT cube_aggregate_result_measure_shape_check;
ALTER TABLE epm.cube_aggregate_result
    ADD CONSTRAINT cube_aggregate_result_measure_shape_check CHECK(
      (resolved_row IS NULL AND
       (sum_amount IS NOT NULL OR count_present IS NOT NULL
        OR min_amount IS NOT NULL OR max_amount IS NOT NULL
        OR (empty_scalar AND members='{}'::jsonb)))
      OR
      (resolved_row IS NOT NULL AND jsonb_typeof(resolved_row)='object'
       AND sum_amount IS NULL AND count_present IS NULL
       AND min_amount IS NULL AND max_amount IS NULL AND NOT empty_scalar));

CREATE FUNCTION epm.cube_technical_result_family_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE family text;
BEGIN
  IF current_setting('epm.workspace_id',true) IS DISTINCT FROM NEW.workspace_id
     OR current_setting('epm.application_id',true) IS DISTINCT FROM NEW.application_id THEN
    RAISE EXCEPTION 'CUBE_TECHNICAL_RESULT_SCOPE_CHANGED' USING ERRCODE='23514';
  END IF;
  SELECT request_family INTO family FROM epm.cube_aggregate_query
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
     AND query_id=NEW.query_id;
  IF family IS NULL
     OR (family='aggregate' AND NEW.resolved_row IS NOT NULL)
     OR (family='resolved_read' AND NEW.resolved_row IS NULL) THEN
    RAISE EXCEPTION 'CUBE_TECHNICAL_RESULT_FAMILY_MISMATCH' USING ERRCODE='23514';
  END IF;
  IF family='resolved_read' AND (
       NEW.resolved_row->>'format' IS DISTINCT FROM
          'openepm-resolved-cube-read-row-v1'
       OR jsonb_typeof(NEW.resolved_row->'members') IS DISTINCT FROM 'object'
       OR jsonb_typeof(NEW.resolved_row->'lineage') IS DISTINCT FROM 'array'
       OR coalesce(NEW.resolved_row->>'origin','') NOT IN
          ('input','materialized','dynamic','hierarchy')
       OR coalesce(NEW.resolved_row->>'currentness','') NOT IN
          ('current','stale')) THEN
    RAISE EXCEPTION 'CUBE_TECHNICAL_RESOLVED_ROW_INVALID' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.cube_technical_result_family_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.cube_technical_result_family_guard()
    TO epm_runtime;
CREATE TRIGGER cube_technical_result_family_guard
BEFORE INSERT OR UPDATE ON epm.cube_aggregate_result
FOR EACH ROW EXECUTE FUNCTION epm.cube_technical_result_family_guard();

COMMENT ON COLUMN epm.cube_aggregate_query.request_family IS
'Discriminator for the one qualified durable technical-query lifecycle.';
COMMENT ON COLUMN epm.cube_aggregate_result.resolved_row IS
'Canonical resolved-read row; mutually exclusive with aggregate measures.';
