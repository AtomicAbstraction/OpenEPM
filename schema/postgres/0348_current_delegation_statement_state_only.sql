BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=347) THEN
    RAISE EXCEPTION 'MIGRATION_0348_REQUIRES_0347';
  END IF;
END $migration$;

-- Delegations and statement definitions retain one current row identified by
-- an opaque state token. The operation receipt owns commit chronology; current
-- product objects do not copy that revision into their definitions.
ALTER TABLE epm.execution_delegation_definition DROP COLUMN updated_revision;
ALTER TABLE epm.statement_definition DROP COLUMN updated_revision;

COMMIT;
