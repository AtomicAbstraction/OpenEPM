BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=341) THEN
    RAISE EXCEPTION 'MIGRATION_0342_REQUIRES_0341';
  END IF;
END $migration$;

-- The current binding state token is the sole activation/currentness fence.
-- Application commit/policy counters remain application concurrency state and
-- are not copied into the binding as product object identities.
DO $migration$ DECLARE item record; BEGIN
  FOR item IN
    SELECT constraint_record.conname
    FROM pg_constraint constraint_record
    WHERE constraint_record.contype='c'
      AND constraint_record.conrelid=
          'epm.resolved_read_binding_definition'::regclass
      AND pg_get_constraintdef(constraint_record.oid) ~
          '(activated_revision|activation_policy_revision)'
  LOOP
    EXECUTE format(
      'ALTER TABLE epm.resolved_read_binding_definition DROP CONSTRAINT %I',
      item.conname);
  END LOOP;
END $migration$;

ALTER TABLE epm.resolved_read_binding_definition
  DROP COLUMN activated_revision,
  DROP COLUMN activation_policy_revision,
  ADD CONSTRAINT resolved_read_binding_current_activation
    CHECK((status='Active')=(activation_operation_id IS NOT NULL));

COMMIT;
