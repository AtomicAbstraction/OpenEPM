BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=361) THEN
    RAISE EXCEPTION 'MIGRATION_0362_REQUIRES_0361';
  END IF;
END $migration$;

-- Workspace and application purge already run through the fenced
-- SECURITY DEFINER lifecycle functions.  The service login must not retain a
-- general-purpose DELETE capability on an individual business definition.
REVOKE DELETE ON epm.inventory_unrealized_schedule_definition
  FROM epm_lifecycle;

DO $migration$ BEGIN
  IF has_table_privilege('epm_lifecycle',
      'epm.inventory_unrealized_schedule_definition','DELETE') THEN
    RAISE EXCEPTION 'INVENTORY_SCHEDULE_LIFECYCLE_DELETE_TOO_BROAD';
  END IF;
END $migration$;
COMMIT;
