BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=283) THEN
    RAISE EXCEPTION 'MIGRATION_0284_REQUIRES_0283';
  END IF;
END $migration$;

-- Technical build failures retain bounded repair diagnostics on their existing
-- task. They create no new event stream, history table, or business revision.
ALTER TABLE epm.python_program_build ADD COLUMN diagnostics jsonb;
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_build_diagnostics_shape CHECK (
    diagnostics IS NULL OR (
      status='failed' AND error_code='PYTHON_SOURCE_VALIDATION_FAILED'
      AND jsonb_typeof(diagnostics)='object'
      AND diagnostics->>'format'='openepm-diagnostics-v1'
      AND diagnostics->>'positionEncoding'='utf-16'
      AND diagnostics->>'sourceDigest' ~ '^[0-9a-f]{64}$'
      AND jsonb_typeof(diagnostics->'diagnostics')='array'
      AND jsonb_array_length(diagnostics->'diagnostics') BETWEEN 1 AND 100
      AND octet_length(diagnostics::text)<=262144
    ) IS TRUE
);

COMMENT ON COLUMN epm.python_program_build.diagnostics IS
  'Bounded author repair diagnostics; source/parameters/tracebacks are not copied here. Purged with the build.';

CREATE FUNCTION epm.python_build_diagnostics_source_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF NEW.diagnostics IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM epm.python_program_version v
    WHERE v.workspace_id=NEW.workspace_id AND v.application_id=NEW.application_id
      AND v.program_id=NEW.program_id AND v.version=NEW.program_version
      AND v.source_digest=NEW.diagnostics->>'sourceDigest'
  ) THEN
    RAISE EXCEPTION 'PYTHON_BUILD_DIAGNOSTIC_SOURCE_MISMATCH' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION epm.python_build_diagnostics_source_guard() FROM PUBLIC;
CREATE TRIGGER python_build_diagnostics_source_guard
  BEFORE INSERT OR UPDATE OF diagnostics ON epm.python_program_build
  FOR EACH ROW EXECUTE FUNCTION epm.python_build_diagnostics_source_guard();

COMMIT;
