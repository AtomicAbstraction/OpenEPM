BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=366) THEN
    RAISE EXCEPTION 'MIGRATION_0367_REQUIRES_0366';
  END IF;
END $migration$;

-- A current calculated definition can acquire different semantic dependencies
-- when a referenced native member list changes without changing its source.
-- The full template digest remains its identity and every binding/manifest FK
-- already uses that digest. Preserve all rows and immutable-artifact guards;
-- callers must resolve the exact registered current digest, never a latest row.
ALTER TABLE epm.calculation_dependency_template
  DROP CONSTRAINT calculation_dependency_template_current_unique RESTRICT;

COMMIT;
