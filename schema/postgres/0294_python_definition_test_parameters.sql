BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=293) THEN
    RAISE EXCEPTION 'MIGRATION_0294_REQUIRES_0293';
  END IF;
END $migration$;

ALTER TABLE epm.python_program_build ADD COLUMN definition_parameters jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_definition_parameters_check
  CHECK(jsonb_typeof(definition_parameters)='object'
    AND octet_length(definition_parameters::text)<=1048576
    AND (purpose='ImpactTest' OR definition_parameters='{}'::jsonb));
CREATE FUNCTION epm.python_definition_parameters_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF NEW.definition_parameters IS DISTINCT FROM OLD.definition_parameters THEN
    RAISE EXCEPTION 'PYTHON_DEFINITION_PARAMETERS_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION epm.python_definition_parameters_immutable() FROM PUBLIC;
CREATE TRIGGER python_definition_parameters_immutable
  BEFORE UPDATE OF definition_parameters ON epm.python_program_build FOR EACH ROW
  EXECUTE FUNCTION epm.python_definition_parameters_immutable();
COMMENT ON COLUMN epm.python_program_build.definition_parameters IS
  'Explicit runtime bindings for returned definitions during private Test; distinct from parameters passed to the authored builder.';
COMMIT;
