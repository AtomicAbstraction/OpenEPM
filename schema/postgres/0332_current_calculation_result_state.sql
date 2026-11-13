BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=331) THEN
    RAISE EXCEPTION 'MIGRATION_0332_REQUIRES_0331';
  END IF;
END $migration$;

-- First bounded slice of the generation-to-current-result conversion.  This
-- row is the sole currentness fence for a logical result key.  The generation
-- reference remains an explicitly internal bridge while payload tables and
-- readers are converted; it is not a public or historical lookup contract.
CREATE TABLE epm.calculation_result_state(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  result_key text NOT NULL CHECK(result_key~'^[A-Za-z0-9._-]{8,128}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  bridge_generation_id text NOT NULL,
  committed_revision bigint NOT NULL CHECK(committed_revision>0),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,result_key),
  UNIQUE(workspace_id,application_id,result_key,state_token),
  FOREIGN KEY(workspace_id,application_id,bridge_generation_id)
    REFERENCES epm.calculation_generation(
      workspace_id,application_id,generation_id) ON DELETE RESTRICT
);

INSERT INTO epm.calculation_result_state(
  workspace_id,application_id,result_key,state_token,bridge_generation_id,
  committed_revision,updated_at)
SELECT workspace_id,application_id,result_key,
  encode(sha256(convert_to(concat_ws(chr(31),'current-result',workspace_id,
    application_id,result_key,generation_id,published_revision::text),
    'UTF8')),'hex'),generation_id,published_revision,updated_at
FROM epm.calculation_publication;

CREATE FUNCTION epm.calculation_result_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
  IF (NEW.workspace_id,NEW.application_id,NEW.result_key) IS DISTINCT FROM
     (OLD.workspace_id,OLD.application_id,OLD.result_key) THEN
    RAISE EXCEPTION 'CALCULATION_RESULT_STATE_IDENTITY_IMMUTABLE';
  END IF;
  IF NEW.state_token=OLD.state_token THEN
    RAISE EXCEPTION 'CALCULATION_RESULT_STATE_TOKEN_NOT_ROTATED';
  END IF;
  IF NEW.committed_revision<=OLD.committed_revision THEN
    RAISE EXCEPTION 'CALCULATION_RESULT_STATE_REVISION_STALE';
  END IF;
  RETURN NEW;
END $guard$;
CREATE TRIGGER calculation_result_state_guard
BEFORE UPDATE ON epm.calculation_result_state FOR EACH ROW
EXECUTE FUNCTION epm.calculation_result_state_guard();

ALTER TABLE epm.calculation_result_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY calculation_result_state_scope ON epm.calculation_result_state
  TO epm_runtime,epm_worker,epm_analyst
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY calculation_result_state_lifecycle ON epm.calculation_result_state
  FOR SELECT TO epm_lifecycle
  USING(current_setting('epm.lifecycle_context',true)='workspace_reset');
REVOKE ALL ON epm.calculation_result_state
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.calculation_result_state TO epm_runtime;
GRANT SELECT ON epm.calculation_result_state TO epm_worker,epm_analyst,epm_lifecycle;

-- Add the current row to both qualified child-first deletion inventories.  It
-- precedes the generation parent and advances the common graph pin.  The pin
-- is replaced with the measured pristine-0332 fingerprint during qualification.
DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
DECLARE previous constant text:='e11667d7ab45f381db9f94f37159b3a84f72d1ac83f24e56756d40d4f8779eb7';
DECLARE current_graph constant text:='c3fe1ab97eae85f70e13abcd17afaa41f0663bd43468864a7923655258c72596';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
  IF position(previous IN definition)=0
     OR position('''calculation_result'',''calculation_publication''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0332_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''calculation_result'',''calculation_publication''',
    '''calculation_result'',''calculation_result_state'',''calculation_publication''');
  revised:=replace(revised,
    '''hierarchy_state'',''expression_rule_definition''',
    '''hierarchy_state'',''application_rule_workflow_child'',''task_event'',''task'',''application_schedule_occurrence'',''application_schedule_definition'',''application_rule_workflow'',''expression_rule_definition''');
  revised:=replace(revised,
    '''calculation_generation'',''application_rule_workflow_child'',''raw_operation_membership''',
    '''calculation_generation'',''raw_operation_membership''');
  revised:=replace(revised,
    '''transfer_cleanup_request'',''task_event'',''task'',',
    '''transfer_cleanup_request'',');
  revised:=replace(revised,
    '''source_import_execution'',''source_batch'',''application_schedule_occurrence'',''application_schedule_definition'',''application_rule_workflow'',',
    '''source_import_execution'',''source_batch'',');
  revised:=replace(revised,
    '''operation_receipt'',''generic_fact_table''',
    '''saved_grid_definition'',''operation_receipt'',''generic_fact_table''');
  revised:=replace(revised,
    '''sealed_cube_selection'',''saved_grid_definition'',',
    '''sealed_cube_selection'',');
  IF position('''source_batch'',''application_schedule_occurrence''' IN revised)>0
     OR position('''sealed_cube_selection'',''saved_grid_definition''' IN revised)>0 THEN
    RAISE EXCEPTION 'RESET_0332_EXISTING_ORDER_REPAIR_MISMATCH';
  END IF;
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  inventory:=array_remove(array_remove(array_remove(array_remove(array_remove(
    array_remove(array_remove(inventory,'application_rule_workflow_child'),
    'task_event'),'task'),'application_schedule_occurrence'),
    'application_schedule_definition'),'application_rule_workflow'),
    'saved_grid_definition');
  idx:=array_position(inventory,'expression_rule_definition');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0332_RULE_ORDER_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['application_rule_workflow_child',
    'task_event','task','application_schedule_occurrence',
    'application_schedule_definition','application_rule_workflow']||inventory[idx:];
  idx:=array_position(inventory,'operation_receipt');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0332_RECEIPT_ORDER_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['saved_grid_definition']||inventory[idx:];
  idx:=array_position(inventory,'calculation_publication');
  IF idx IS NULL OR 'calculation_result_state'=ANY(inventory) THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0332_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['calculation_result_state']||inventory[idx:];
  FOR edge IN SELECT child.relname child,parent.relname parent
    FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid
    JOIN pg_namespace cn ON cn.oid=child.relnamespace
    JOIN pg_class parent ON parent.oid=c.confrelid
    JOIN pg_namespace pn ON pn.oid=parent.relnamespace
    WHERE c.contype='f' AND cn.nspname='epm' AND pn.nspname='epm'
      AND child.oid<>parent.oid
  LOOP
    IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
       AND array_position(inventory,edge.child)>array_position(inventory,edge.parent) THEN
      RAISE EXCEPTION 'APPLICATION_PURGE_0332_FK_ORDER_INVALID:%:%:%:%',
        edge.child,edge.parent,array_position(inventory,edge.child),
        array_position(inventory,edge.parent);
    END IF;
  END LOOP;
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
  INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0332_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
