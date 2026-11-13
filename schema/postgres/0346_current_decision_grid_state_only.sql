BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=345) THEN
    RAISE EXCEPTION 'MIGRATION_0346_REQUIRES_0345';
  END IF;
END $migration$;

-- Decisions and grids are current objects. Their state tokens fence edits;
-- actor commit chronology remains in operation receipts only.
ALTER TABLE epm.application_decision DROP COLUMN updated_revision;
ALTER TABLE epm.saved_grid_definition DROP COLUMN updated_revision;

COMMIT;
