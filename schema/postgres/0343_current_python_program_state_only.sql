BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=342) THEN
    RAISE EXCEPTION 'MIGRATION_0343_REQUIRES_0342';
  END IF;
END $migration$;

-- Program activation is represented by the current status and rotated opaque
-- state token.  The application commit chronology remains only in the actor
-- operation receipt and is not copied into the product object.
ALTER TABLE epm.python_program_definition DROP COLUMN activated_revision;

COMMIT;
