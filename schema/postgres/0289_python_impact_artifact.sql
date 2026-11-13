BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=288) THEN
    RAISE EXCEPTION 'MIGRATION_0289_REQUIRES_0288';
  END IF;
END $migration$;

-- A Test is existing durable technical build work. Its bounded private result
-- is sealed atomically with its plan, not published as business fact history.
ALTER TABLE epm.python_plan_artifact ADD COLUMN impact jsonb;
ALTER TABLE epm.python_plan_artifact ADD CONSTRAINT python_impact_artifact_shape CHECK (
  impact IS NULL OR (
    jsonb_typeof(impact)='object'
    AND impact->>'format'='openepm-python-impact-v1'
    AND impact->>'status'='complete'
    AND impact->>'planDigest'=plan_digest
    AND impact->>'compilerVersion'=compiler_version
    AND impact->>'sourceDigest' ~ '^[0-9a-f]{64}$'
    AND impact->'businessDataChanged'='false'::jsonb
    AND jsonb_typeof(impact->'rows')='array'
    AND jsonb_array_length(impact->'rows')<=10000
    AND jsonb_typeof(impact->'units')='array'
    AND jsonb_array_length(impact->'units') BETWEEN 1 AND 500
    AND octet_length(impact::text)<=16777216
  ) IS TRUE
);
CREATE FUNCTION epm.python_impact_artifact_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
DECLARE purpose text; source_digest text;
BEGIN
  SELECT b.purpose,v.source_digest INTO purpose,source_digest
    FROM epm.python_program_build b JOIN epm.python_program_version v
      ON v.workspace_id=b.workspace_id AND v.application_id=b.application_id
      AND v.program_id=b.program_id AND v.version=b.program_version
    WHERE b.workspace_id=NEW.workspace_id AND b.application_id=NEW.application_id
      AND b.build_id=NEW.build_id;
  IF purpose IS NULL OR (purpose='ImpactTest') IS DISTINCT FROM (NEW.impact IS NOT NULL)
      OR (NEW.impact IS NOT NULL AND NEW.impact->>'sourceDigest' IS DISTINCT FROM source_digest) THEN
    RAISE EXCEPTION 'PYTHON_IMPACT_ARTIFACT_SOURCE_OR_PURPOSE_MISMATCH' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION epm.python_impact_artifact_guard() FROM PUBLIC;
CREATE TRIGGER python_impact_artifact_guard BEFORE INSERT ON epm.python_plan_artifact
  FOR EACH ROW EXECUTE FUNCTION epm.python_impact_artifact_guard();
COMMENT ON COLUMN epm.python_plan_artifact.impact IS
  'Bounded private numeric Test result. No business publication; expires with technical build artifacts.';
COMMIT;
