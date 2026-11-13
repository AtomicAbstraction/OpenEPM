BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=348) THEN
    RAISE EXCEPTION 'MIGRATION_0349_REQUIRES_0348';
  END IF;
END $migration$;

-- These definitions already use opaque state tokens and exact digests. Commit
-- chronology remains in operation receipts instead of being copied into the
-- current product row.
ALTER TABLE epm.cube_write_policy_definition DROP COLUMN updated_revision;
ALTER TABLE epm.inventory_unrealized_schedule_definition DROP COLUMN updated_revision;
ALTER TABLE epm.consolidation_layout DROP COLUMN updated_revision;

COMMIT;
