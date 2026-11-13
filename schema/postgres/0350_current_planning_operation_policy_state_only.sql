BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=349) THEN
    RAISE EXCEPTION 'MIGRATION_0350_REQUIRES_0349';
  END IF;
END $migration$;

-- The exact current policy is fenced by its opaque state token and canonical
-- digest. Operation commit chronology remains solely in the receipt.
ALTER TABLE epm.planning_operation_policy DROP COLUMN updated_revision;

COMMIT;
