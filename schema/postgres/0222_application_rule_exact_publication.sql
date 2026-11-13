-- Preserve the exact publication proof used to admit a scheduled historical
-- application-rule version.  Ordinary interactive workflows keep NULL and
-- continue following the current publication pointer.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=221) THEN
    RAISE EXCEPTION 'MIGRATION_0222_PREDECESSOR_0221_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.application_rule_workflow
  ADD COLUMN publication_operation_id text
    CHECK(publication_operation_id IS NULL
      OR publication_operation_id ~ '^[A-Za-z0-9._-]{8,128}$');

-- The operation receipt is immutable and validated transactionally by fixed
-- core at admission and every continuation.  No new FK is introduced here so
-- the already reviewed reset dependency graph remains unchanged.

