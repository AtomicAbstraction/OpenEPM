-- Preserve exact retired product rows in one generic immutable archive before
-- their operational relations and executable consumers are removed. This
-- migration refuses to archive unsettled work; operators must first run the
-- isolated historical recovery worker and repeat the migration.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=233) THEN
    RAISE EXCEPTION 'MIGRATION_0234_PREDECESSOR_0233_REQUIRED';
  END IF;
END $migration$;

DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.planning_forecast_occurrence
      WHERE status NOT IN ('cancelled','progress_committed','failed'))
     OR EXISTS(SELECT 1 FROM epm.planning_forecast_schedule_state
      WHERE active_version IS NOT NULL)
     OR EXISTS(SELECT 1 FROM epm.planning_assignment_due_occurrence
      WHERE status<>'Completed')
     OR EXISTS(SELECT 1 FROM epm.application_task_flow_occurrence
      WHERE status NOT IN ('Completed','Cancelled'))
     OR EXISTS(SELECT 1 FROM epm.application_task_flow_activity
      WHERE status NOT IN ('Completed','Cancelled')) THEN
    RAISE EXCEPTION 'RETIRED_PRODUCT_HISTORY_UNSETTLED_WORK';
  END IF;
END $migration$;

CREATE TABLE epm.retired_product_history (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  source_relation text NOT NULL CHECK(source_relation IN (
    'application_task_flow_activity','application_task_flow_event',
    'application_task_flow_occurrence','application_task_flow_state',
    'application_task_flow_version','planning_assignment_control_current',
    'planning_assignment_control_event','planning_assignment_due_occurrence',
    'planning_assignment_state','planning_assignment_version',
    'planning_forecast_definition_state',
    'planning_forecast_definition_version','planning_forecast_occurrence',
    'planning_forecast_progress','planning_forecast_schedule_event',
    'planning_forecast_schedule_state','planning_forecast_schedule_version')),
  row_digest text NOT NULL CHECK(row_digest ~ '^[0-9a-f]{64}$'),
  payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object'
    AND octet_length(payload::text)<=4194304
    AND payload->>'workspace_id'=workspace_id
    AND payload->>'application_id'=application_id
    AND row_digest=encode(pg_catalog.sha256(
      convert_to(payload::text,'UTF8')),'hex')),
  archived_by_migration bigint NOT NULL DEFAULT 234
    CHECK(archived_by_migration=234),
  archived_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,source_relation,row_digest),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application(workspace_id,application_id)
    ON DELETE RESTRICT
);

DO $migration$
DECLARE relation_name text; archived bigint; source_count bigint;
DECLARE relations constant text[] := ARRAY[
  'application_task_flow_activity','application_task_flow_event',
  'application_task_flow_occurrence','application_task_flow_state',
  'application_task_flow_version','planning_assignment_control_current',
  'planning_assignment_control_event','planning_assignment_due_occurrence',
  'planning_assignment_state','planning_assignment_version',
  'planning_forecast_definition_state',
  'planning_forecast_definition_version','planning_forecast_occurrence',
  'planning_forecast_progress','planning_forecast_schedule_event',
  'planning_forecast_schedule_state','planning_forecast_schedule_version'];
BEGIN
  FOREACH relation_name IN ARRAY relations LOOP
    EXECUTE format($sql$
      INSERT INTO epm.retired_product_history(
        workspace_id,application_id,source_relation,row_digest,payload)
      SELECT workspace_id,application_id,%L,
        encode(pg_catalog.sha256(convert_to(to_jsonb(source_row)::text,
          'UTF8')),'hex'),to_jsonb(source_row)
      FROM epm.%I source_row ON CONFLICT DO NOTHING$sql$,
      relation_name,relation_name);
    EXECUTE format('SELECT count(*) FROM epm.%I',relation_name)
      INTO source_count;
    SELECT count(*) INTO archived FROM epm.retired_product_history
      WHERE source_relation=relation_name;
    IF archived<>source_count THEN
      RAISE EXCEPTION 'RETIRED_PRODUCT_HISTORY_COUNT_MISMATCH: %',
        relation_name;
    END IF;
  END LOOP;
END $migration$;

CREATE FUNCTION epm.retired_product_history_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' AND
     current_setting('epm.projection_cleanup_reset_context',true)=
       jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                         pg_backend_pid())::text THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'RETIRED_PRODUCT_HISTORY_IMMUTABLE'
    USING ERRCODE='23514';
END$$;
CREATE TRIGGER retired_product_history_immutable
  BEFORE UPDATE OR DELETE ON epm.retired_product_history
  FOR EACH ROW EXECUTE FUNCTION epm.retired_product_history_immutable();
REVOKE ALL ON FUNCTION epm.retired_product_history_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

ALTER TABLE epm.retired_product_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY retired_product_history_lifecycle_scope
  ON epm.retired_product_history FOR SELECT TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.retired_product_history
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT ON epm.retired_product_history TO epm_lifecycle;

-- Reset remains exact and child-first. The archive has only an application
-- parent and is deleted before every retained historical source relation.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_group text :=
  $pattern$'application_workflow_evidence_link','application_workflow_event',$pattern$;
DECLARE new_group text :=
  $pattern$'retired_product_history','application_workflow_evidence_link','application_workflow_event',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_group IN definition)=0 OR position(new_group IN definition)>0
  THEN RAISE EXCEPTION 'RESET_0234_DEFINITION_MISMATCH';END IF;
  revised:=replace(definition,old_group,new_group);
  IF revised=definition OR position(new_group IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0234_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

-- Replaced after isolated canonical graph inspection.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '29e581d280aed9d5452a756fcf1dff6a21d8f2fe9fae81e929eaf391e132c75e';
DECLARE new_fingerprint constant text :=
  'e3c5a39b0afe8b8b2d7021407a0d9d9f66a27e868980b5c6e5ccd2739461312f';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0234_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0234_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;
