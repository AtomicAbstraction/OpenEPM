BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=308) THEN
    RAISE EXCEPTION 'MIGRATION_0309_REQUIRES_0308';
  END IF;
END $migration$;

-- These are derived execution artifacts, not business definitions. Old
-- bindings name retired definition versions and cannot be replayed against the
-- one-current-definition contract. Remove them child-first; the current
-- definition's next activation/materialization rebuilds exact artifacts.
DO $migration$ DECLARE relation text;
BEGIN
  FOREACH relation IN ARRAY ARRAY['calculation_dependency_template',
    'calculation_instance_binding','calculation_execution_manifest',
    'calculation_dependency_index','calculation_generation_manifest',
    'calculation_generation_partition'] LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I_immutable ON epm.%I',
      relation,relation);
  END LOOP;
END $migration$;

DELETE FROM epm.calculation_generation_partition;
DELETE FROM epm.calculation_generation_manifest;
DELETE FROM epm.calculation_scope_state;
DELETE FROM epm.calculation_dependency_index;
DELETE FROM epm.calculation_execution_manifest;
DELETE FROM epm.calculation_instance_binding;
DELETE FROM epm.calculation_dependency_template;

DO $migration$ DECLARE constraint_row record;
BEGIN
  FOR constraint_row IN
    SELECT conrelid::regclass relation,conname
    FROM pg_constraint
    WHERE conrelid='epm.calculation_dependency_template'::regclass
      AND pg_get_constraintdef(oid) LIKE '%definition_version%'
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',
      constraint_row.relation,constraint_row.conname);
  END LOOP;
END $migration$;
ALTER TABLE epm.calculation_dependency_template DROP COLUMN definition_version;
ALTER TABLE epm.calculation_dependency_template ADD CONSTRAINT
  calculation_dependency_template_current_unique UNIQUE(
    workspace_id,application_id,definition_id,definition_digest,
    compiler_version);

ALTER TABLE epm.calculation_instance_binding
  ADD COLUMN definition_state_token text;
ALTER TABLE epm.calculation_instance_binding
  ALTER COLUMN definition_state_token SET NOT NULL;
ALTER TABLE epm.calculation_instance_binding ADD CONSTRAINT
  calculation_instance_binding_state_token_check
  CHECK(definition_state_token~'^[0-9a-f]{64}$');
ALTER TABLE epm.calculation_instance_binding DROP COLUMN definition_version;

DO $migration$ DECLARE relation text;
BEGIN
  FOREACH relation IN ARRAY ARRAY['calculation_dependency_template',
    'calculation_instance_binding','calculation_execution_manifest',
    'calculation_dependency_index','calculation_generation_manifest',
    'calculation_generation_partition'] LOOP
    EXECUTE format('CREATE TRIGGER %I_immutable BEFORE UPDATE OR DELETE ON epm.%I '
      'FOR EACH ROW EXECUTE FUNCTION epm.calculation_dependency_immutable()',
      relation,relation);
  END LOOP;
END $migration$;

COMMIT;
