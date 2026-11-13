BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=346) THEN
    RAISE EXCEPTION 'MIGRATION_0347_REQUIRES_0346';
  END IF;
END $migration$;

-- Environment and schedule definitions retain one current row. Runtime image
-- and dependency profile pins remain; copied application commit revisions do
-- not form part of either product object's identity.
ALTER TABLE epm.python_environment_definition DROP COLUMN updated_revision;
ALTER TABLE epm.python_program_definition DROP COLUMN updated_revision;
ALTER TABLE epm.python_program_schedule_definition DROP COLUMN updated_revision;

COMMIT;
