BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=351) THEN
    RAISE EXCEPTION 'MIGRATION_0352_REQUIRES_0351';
  END IF;
END $migration$;

-- The current accounting-policy definition is identified by stable policy id,
-- opaque state token and definition digest. Creation chronology remains in the
-- referenced operation receipt instead of being copied into the product row.
ALTER TABLE epm.policy_pack_draft DROP COLUMN created_revision;

COMMIT;
