BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=363) THEN
    RAISE EXCEPTION 'MIGRATION_0364_REQUIRES_0363';
  END IF;
END $migration$;

-- The current partition manifest and expression staging relations were added
-- to lifecycle inventories after their referenced parents.  Reset/purge must
-- always delete every child before its parent; otherwise a populated
-- development application cannot be removed without violating its FKs.
DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:=
  'ec134ab6a03db5d6b8ddc11e0867acc9c1749c8fb339d8677b7ff702647763b0';
DECLARE current_graph constant text:=
  '2e8767f44870298dacdb34265d459cea5017d699ada909c682d59fba1e0a46ac';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0
     OR position('''calculation_partition_current'',''calculation_partition_manifest_current'',''calculation_result_state''' IN definition)=0
     OR position('''calculation_execution_manifest''' IN definition)=0
     OR position('''calculation_partition_staging''' IN definition)=0
     OR position('''expression_result_staging''' IN definition)>0
     OR position('''expression_result_staging_row''' IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0364_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''calculation_partition_current'',''calculation_partition_manifest_current'',''calculation_result_state''',
    '''calculation_result_state''');
  revised:=replace(revised,'''calculation_execution_manifest''',
    '''calculation_partition_current'',''calculation_partition_manifest_current'',''calculation_execution_manifest''');
  revised:=replace(revised,'''calculation_partition_staging''',
    '''expression_result_staging_row'',''expression_result_staging'',''calculation_partition_staging''');
  revised:=replace(revised,previous,current_graph);
  EXECUTE revised;

  inventory:=epm.application_purge_relations();
  IF NOT inventory @> ARRAY['calculation_partition_current',
      'calculation_partition_manifest_current','calculation_execution_manifest',
      'expression_result_staging_row','expression_result_staging']::text[] THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0364_INVENTORY_INCOMPLETE';
  END IF;
  inventory:=array_remove(array_remove(inventory,
    'calculation_partition_current'),'calculation_partition_manifest_current');
  idx:=array_position(inventory,'calculation_execution_manifest');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0364_PARENT_MISSING';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['calculation_partition_current',
    'calculation_partition_manifest_current']||inventory[idx:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0364_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
