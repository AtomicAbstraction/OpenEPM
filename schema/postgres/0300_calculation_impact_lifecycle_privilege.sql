BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=299) THEN
    RAISE EXCEPTION 'MIGRATION_0300_REQUIRES_0299';
  END IF;
END $migration$;

-- Application purge is executed only by the existing SECURITY DEFINER purge
-- function after its exact lifecycle context and incarnation fences pass.
-- The lifecycle login must not gain a general-purpose table DELETE path.
REVOKE DELETE ON epm.calculation_impact_event,
  epm.calculation_impact_progress,epm.calculation_impact_fanout
  FROM epm_lifecycle;
REVOKE DELETE ON epm.calculation_dependency_template,
  epm.calculation_instance_binding,epm.calculation_execution_manifest,
  epm.calculation_dependency_index,epm.calculation_scope_state,
  epm.calculation_generation_manifest,epm.calculation_generation_partition
  FROM epm_lifecycle;

DO $migration$ DECLARE relation text;
BEGIN
  FOREACH relation IN ARRAY ARRAY['calculation_impact_event',
    'calculation_impact_progress','calculation_impact_fanout',
    'calculation_dependency_template','calculation_instance_binding',
    'calculation_execution_manifest','calculation_dependency_index',
    'calculation_scope_state','calculation_generation_manifest',
    'calculation_generation_partition'] LOOP
    IF has_table_privilege('epm_lifecycle',format('epm.%I',relation),'DELETE') THEN
      RAISE EXCEPTION 'CALCULATION_IMPACT_LIFECYCLE_DELETE_TOO_BROAD';
    END IF;
  END LOOP;
END $migration$;
COMMIT;
