BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=380) THEN
    RAISE EXCEPTION 'MIGRATION_0381_REQUIRES_0380';
  END IF;
END $migration$;

-- The fixed public schedule-run catalogue is scoped to one application and
-- ordered newest first.  Back that contract with its exact keyset order so a
-- user-facing history page never degrades into a growing occurrence-table
-- sort.  Schedule and status are safe catalogue fields and permit an
-- index-only projection when PostgreSQL visibility permits it; opaque build,
-- workflow and worker identifiers remain outside the public result.
CREATE INDEX python_occurrence_catalogue_recent
  ON epm.python_program_occurrence(
    workspace_id,application_id,due_at DESC,occurrence_id DESC)
  INCLUDE(schedule_id,status);

COMMENT ON INDEX epm.python_occurrence_catalogue_recent IS
  'Scoped recent-first backing index for the fixed public Python schedule occurrence catalogue';

COMMIT;
SELECT '0381 applied' AS migration;
