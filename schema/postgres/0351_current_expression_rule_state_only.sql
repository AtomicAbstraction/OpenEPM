BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=350) THEN
    RAISE EXCEPTION 'MIGRATION_0351_REQUIRES_0350';
  END IF;
END $migration$;

-- Saved rules use their opaque state token and program digest. The operation
-- receipt remains the sole owner of commit chronology.
ALTER TABLE epm.expression_rule_definition DROP COLUMN updated_revision;

COMMIT;
