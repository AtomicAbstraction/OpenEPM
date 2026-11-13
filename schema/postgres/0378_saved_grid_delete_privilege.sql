BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=377) THEN
    RAISE EXCEPTION 'MIGRATION_0378_REQUIRES_0377';
  END IF;
END $migration$;

-- grid.definition.delete is a fixed-core current-object operation executed by
-- epm_runtime.  The current-table migration granted insert and column updates
-- but omitted the DELETE privilege, making the published lifecycle contract
-- impossible to execute even for an authorized writer.
GRANT DELETE ON epm.saved_grid_definition TO epm_runtime;

COMMIT;
SELECT '0378 applied' AS migration;
