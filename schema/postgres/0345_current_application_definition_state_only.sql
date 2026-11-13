BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=344) THEN
    RAISE EXCEPTION 'MIGRATION_0345_REQUIRES_0344';
  END IF;
END $migration$;

-- Workflows, schedules and assignments each retain one current definition.
-- Their opaque state tokens fence replacement; commit chronology belongs only
-- to operation receipts and is not copied into product objects.
ALTER TABLE epm.application_workflow_definition DROP COLUMN updated_revision;
ALTER TABLE epm.application_schedule_definition DROP COLUMN updated_revision;
ALTER TABLE epm.application_assignment_definition DROP COLUMN updated_revision;

COMMIT;
