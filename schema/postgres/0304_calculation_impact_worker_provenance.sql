BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=303) THEN
    RAISE EXCEPTION 'MIGRATION_0304_REQUIRES_0303';
  END IF;
END $migration$;

-- Source-replacement impact expansion resolves an operation's durable source
-- coordinates under the worker role.  Grant only the immutable provenance
-- reads required by that resolver; mutation remains unavailable.
GRANT SELECT ON epm.numeric_fact_event,epm.text_fact_event,
  epm.line_detail_event,epm.coordinate TO epm_worker;

COMMIT;
