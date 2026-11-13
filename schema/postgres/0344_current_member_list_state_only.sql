BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=343) THEN
    RAISE EXCEPTION 'MIGRATION_0344_REQUIRES_0343';
  END IF;
END $migration$;

-- Member lists expose one current definition fenced by its opaque state
-- token. Commit chronology remains in the actor operation receipt and is not
-- copied into the product object.
ALTER TABLE epm.member_list_definition DROP COLUMN updated_revision;

COMMIT;
