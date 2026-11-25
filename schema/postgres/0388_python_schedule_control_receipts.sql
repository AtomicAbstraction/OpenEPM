BEGIN;

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=387) THEN
  RAISE EXCEPTION 'MIGRATION_0388_REQUIRES_0387';
 END IF;
END $migration$;

-- Manual materialization and stop intent are operational effects. Their exact
-- outcomes do not claim a business commit revision or a fact publication.
CREATE TABLE epm.python_schedule_control_receipt (
 workspace_id text NOT NULL,
 application_id text NOT NULL,
 operation_id text NOT NULL CHECK(operation_id ~ '^[A-Za-z0-9._-]{8,128}$'),
 command_digest text NOT NULL CHECK(command_digest ~ '^[0-9a-f]{64}$'),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object' AND octet_length(result::text)<=4096),
 PRIMARY KEY(workspace_id,application_id,operation_id),
 CONSTRAINT python_schedule_control_receipt_state_fk
  FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id)
  ON DELETE RESTRICT
);
ALTER TABLE epm.python_schedule_control_receipt ENABLE ROW LEVEL SECURITY;
CREATE POLICY python_schedule_control_receipt_scope ON epm.python_schedule_control_receipt TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
GRANT SELECT,INSERT ON epm.python_schedule_control_receipt TO epm_runtime;

DO $lifecycle$
DECLARE definition text;inventory text[];idx integer;
DECLARE previous constant text:=
 '090c87c423ce39f0233ea03dc9db290f2305fae43668f413ad657929c4b94fa1';
DECLARE current_graph constant text:=
 '880f4a68a58684ff0da54c1d4c9d2bcd4784ffe1e20adace2e471de00734a532';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 OR position('''python_program_occurrence''' IN definition)=0
    OR position('''python_schedule_control_receipt''' IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0388_PREDECESSOR_MISMATCH';
 END IF;
 definition:=replace(definition,'''python_program_occurrence''',
  '''python_schedule_control_receipt'',''python_program_occurrence''');
 EXECUTE replace(definition,previous,current_graph);

 inventory:=epm.application_purge_relations();
 idx:=array_position(inventory,'python_program_occurrence');
 IF idx IS NULL OR 'python_schedule_control_receipt'=ANY(inventory) THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0388_INVENTORY_MISMATCH';
 END IF;
 inventory:=inventory[1:idx-1]||ARRAY['python_schedule_control_receipt']||inventory[idx:];
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
  'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
  'SELECT '||quote_literal(inventory::text)||'::text[]');
 SELECT pg_get_functiondef(
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0388_PREDECESSOR_MISMATCH';
 END IF;
 EXECUTE replace(definition,previous,current_graph);
END $lifecycle$;

COMMIT;
SELECT '0388 applied' AS migration;
