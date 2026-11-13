BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=287) THEN
    RAISE EXCEPTION 'MIGRATION_0288_REQUIRES_0287';
  END IF;
END $migration$;

ALTER TABLE epm.python_program_build ADD COLUMN purpose text NOT NULL DEFAULT 'Plan';
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_build_purpose_check
  CHECK (purpose IN ('Plan','Validation','ImpactTest'));
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_build_design_authority_check
  CHECK (purpose='Plan' OR (delegation_id IS NULL AND delegation_version IS NULL
      AND schedule_id IS NULL AND schedule_version IS NULL));

CREATE FUNCTION epm.python_build_purpose_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF NEW.purpose IS DISTINCT FROM OLD.purpose THEN
    RAISE EXCEPTION 'PYTHON_BUILD_PURPOSE_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION epm.python_build_purpose_immutable() FROM PUBLIC;
CREATE TRIGGER python_build_purpose_immutable
  BEFORE UPDATE OF purpose ON epm.python_program_build FOR EACH ROW
  EXECUTE FUNCTION epm.python_build_purpose_immutable();

COMMENT ON COLUMN epm.python_program_build.purpose IS
  'Plan uses execution delegation; Validation and ImpactTest are design-authorized technical work and never authorize business publication.';
COMMIT;
