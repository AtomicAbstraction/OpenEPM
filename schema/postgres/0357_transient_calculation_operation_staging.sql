BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=356) THEN
    RAISE EXCEPTION 'MIGRATION_0357_REQUIRES_0356';
  END IF;
  IF EXISTS(
    SELECT 1 FROM epm.calculation_generation generation
    JOIN epm.job job ON job.workspace_id=generation.workspace_id
      AND job.application_id=generation.application_id
      AND job.job_id=generation.job_id
    WHERE job.status IN(
      'accepted','ready','running','staged','cancel_requested',
      'needs_inspection')
  ) THEN
    RAISE EXCEPTION 'MIGRATION_0357_ACTIVE_CALCULATION_OPERATION';
  END IF;
END $migration$;

-- The current result owns the durable payload and provenance after 0356.
-- These rows are therefore stale private writer artifacts, not application
-- history.  Remove them rather than carrying old operations into the renamed
-- staging contract.
DO $migration$ DECLARE item record; BEGIN
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='epm.calculation_scope_state'::regclass
      AND pg_get_constraintdef(oid) LIKE '%current_generation_id%'
  LOOP
    EXECUTE format('ALTER TABLE epm.calculation_scope_state DROP CONSTRAINT %I',
                   item.conname);
  END LOOP;
END $migration$;
ALTER TABLE epm.calculation_scope_state DROP COLUMN current_generation_id;

DELETE FROM epm.rollup_placement_path_edge;
DELETE FROM epm.rollup_source_lineage;
DELETE FROM epm.rollup_placement_path;
DELETE FROM epm.allocation_basis_lineage;
DELETE FROM epm.calculation_ratio_result;
DELETE FROM epm.calculation_unit_result;
DELETE FROM epm.calculation_result;
DELETE FROM epm.calculation_generation;

ALTER TABLE epm.calculation_generation
  RENAME TO calculation_operation_staging;
ALTER TABLE epm.calculation_result
  RENAME TO calculation_result_staging;
ALTER TABLE epm.calculation_unit_result
  RENAME TO calculation_unit_result_staging;
ALTER TABLE epm.calculation_ratio_result
  RENAME TO calculation_ratio_result_staging;
ALTER TABLE epm.allocation_basis_lineage
  RENAME TO allocation_basis_lineage_staging;
ALTER TABLE epm.rollup_placement_path
  RENAME TO rollup_placement_path_staging;
ALTER TABLE epm.rollup_placement_path_edge
  RENAME TO rollup_placement_path_edge_staging;
ALTER TABLE epm.rollup_source_lineage
  RENAME TO rollup_source_lineage_staging;

-- Publication now consumes and removes its own private scratch rows in the
-- same runtime transaction.  The old durable-generation contract only needed
-- INSERT/SELECT; grant the fixed runtime role the narrow additional DELETE
-- privilege required by the transient contract.
GRANT DELETE ON
  epm.calculation_operation_staging,
  epm.calculation_result_staging,
  epm.calculation_unit_result_staging,
  epm.calculation_ratio_result_staging,
  epm.allocation_basis_lineage_staging,
  epm.rollup_placement_path_staging,
  epm.rollup_placement_path_edge_staging,
  epm.rollup_source_lineage_staging
TO epm_runtime;

-- Deferred integrity triggers and lifecycle inventories contain constant
-- relation names inside PL/pgSQL bodies.  ALTER TABLE RENAME cannot rewrite
-- those bodies.  Rewrite every affected EPM function by exact identifier word
-- so result-keyed *_current relations remain untouched.
DO $migration$
DECLARE
  function_id regprocedure;
  definition text;
  revised text;
  old_name text;
  new_name text;
  index integer;
  names constant text[][] := ARRAY[
    ['calculation_generation','calculation_operation_staging'],
    ['calculation_result','calculation_result_staging'],
    ['calculation_unit_result','calculation_unit_result_staging'],
    ['calculation_ratio_result','calculation_ratio_result_staging'],
    ['allocation_basis_lineage','allocation_basis_lineage_staging'],
    ['rollup_placement_path','rollup_placement_path_staging'],
    ['rollup_placement_path_edge','rollup_placement_path_edge_staging'],
    ['rollup_source_lineage','rollup_source_lineage_staging']
  ];
BEGIN
  FOR function_id IN
    SELECT function.oid::regprocedure
    FROM pg_proc function
    JOIN pg_namespace namespace ON namespace.oid=function.pronamespace
    WHERE namespace.nspname='epm' AND function.prokind IN('f','p')
    ORDER BY function.oid
  LOOP
    SELECT pg_get_functiondef(function_id) INTO definition;
    revised := definition;
    FOR index IN 1..array_length(names,1) LOOP
      old_name := names[index][1];
      new_name := names[index][2];
      revised := regexp_replace(revised,
        E'\\m' || old_name || E'\\M',new_name,'g');
    END LOOP;
    IF revised<>definition THEN
      EXECUTE revised;
    END IF;
  END LOOP;

  -- The graph changed because the retained relations became explicit staging
  -- and the obsolete scope FK/column disappeared.  Both destructive lifecycle
  -- gates must require the reviewed new graph.
  FOREACH function_id IN ARRAY ARRAY[
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure,
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(function_id) INTO definition;
    revised := replace(definition,
      'c78ce1a60b27151397911fa1758fe74e1c3ba867de8416ab409a9a266efa6f7d',
      '1806a173f9db6dd9a3ceb6cd24bcf772fa6d01f812914706581b5f4da017244e');
    IF revised=definition THEN
      RAISE EXCEPTION 'MIGRATION_0357_FINGERPRINT_PREDECESSOR_MISSING: %',
                      function_id::text;
    END IF;
    EXECUTE revised;
  END LOOP;
  IF NOT epm.application_purge_relations() @> ARRAY[
      'calculation_operation_staging','calculation_result_staging',
      'calculation_unit_result_staging','calculation_ratio_result_staging',
      'allocation_basis_lineage_staging','rollup_placement_path_staging',
      'rollup_placement_path_edge_staging','rollup_source_lineage_staging'
    ]::text[] THEN
    RAISE EXCEPTION 'MIGRATION_0357_APPLICATION_PURGE_INVENTORY_INCOMPLETE';
  END IF;
END $migration$;

COMMIT;
