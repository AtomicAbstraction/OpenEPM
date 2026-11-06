-- Remove the operational storage and database execution paths for the product
-- families retired by the programmable multidimensional redesign. Migration
-- 0234 remains the immutable historical authority for every removed row.
-- Dependencies are removed explicitly; DROP ... CASCADE is intentionally
-- prohibited so an unreviewed dependency fails this migration.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=234) THEN
    RAISE EXCEPTION 'MIGRATION_0235_PREDECESSOR_0234_REQUIRED';
  END IF;
END $migration$;

-- Recheck the recovery boundary and prove that the archive contains the exact
-- current form of every source row. This also catches rows changed after 0234.
DO $migration$
DECLARE relation_name text; missing_current bigint;
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
    RAISE EXCEPTION 'RETIRED_PRODUCT_STORAGE_UNSETTLED_WORK';
  END IF;
  FOREACH relation_name IN ARRAY relations LOOP
    EXECUTE format($sql$
      SELECT count(*) FROM epm.%I source_row
      WHERE NOT EXISTS(
        SELECT 1 FROM epm.retired_product_history archived
        WHERE archived.workspace_id=source_row.workspace_id
          AND archived.application_id=source_row.application_id
          AND archived.source_relation=%L
          AND archived.row_digest=encode(pg_catalog.sha256(convert_to(
            to_jsonb(source_row)::text,'UTF8')),'hex'))$sql$,
      relation_name,relation_name) INTO missing_current;
    IF missing_current<>0 THEN
      RAISE EXCEPTION 'RETIRED_PRODUCT_HISTORY_CURRENT_ROW_MISSING: %',
        relation_name;
    END IF;
  END LOOP;
END $migration$;

-- Retained universal-task rows and assigned-submission history keep their
-- immutable source identifiers, while source-table referential enforcement is
-- replaced by the digest-bound archive. No historical row is deleted here.
ALTER TABLE epm.cube_write_scope_assigned_submission DROP CONSTRAINT
  cube_write_scope_assigned_submission_workspace_id_appl_32b99379;
ALTER TABLE epm.task DROP CONSTRAINT task_human_activity_fkey;
ALTER TABLE epm.task DROP CONSTRAINT task_source_forecast_occurrence_fkey;
UPDATE epm.task SET interruptible=false,rerun_supported=false
  WHERE source_family IN ('HumanActivity','ForecastOccurrence',
    'AssignmentEscalation','ApplicationTaskFlowOccurrence')
    AND (interruptible OR rerun_supported);

-- Remove trigger dependencies before their functions. Generic queue-claim
-- capture remains because active generic operation families use it.
DROP TRIGGER aa_application_task_flow_task_projection
  ON epm.application_task_flow_event;
DROP TRIGGER aa_application_taskflow_occurrence_task_projection
  ON epm.application_task_flow_event;
DROP TRIGGER application_task_flow_event_immutable
  ON epm.application_task_flow_event;
DROP TRIGGER application_task_flow_version_immutable
  ON epm.application_task_flow_version;
DROP TRIGGER aa_assignment_escalation_task_projection
  ON epm.planning_assignment_due_occurrence;
DROP TRIGGER planning_assignment_capture_first_queue_claim
  ON epm.planning_assignment_due_occurrence;
DROP TRIGGER planning_assignment_version_immutable
  ON epm.planning_assignment_version;
DROP TRIGGER forecast_definition_state_guard
  ON epm.planning_forecast_definition_state;
DROP TRIGGER forecast_definition_version_guard
  ON epm.planning_forecast_definition_version;
DROP TRIGGER aa_forecast_occurrence_task_projection
  ON epm.planning_forecast_occurrence;
DROP TRIGGER planning_forecast_capture_first_queue_claim
  ON epm.planning_forecast_occurrence;

DROP FUNCTION epm.application_task_flow_immutable();
DROP FUNCTION epm.assignment_escalation_materialize_due(integer);
DROP FUNCTION epm.assignment_escalation_worker_cancel(
  text,text,text,bigint,text,timestamptz,bigint,text);
DROP FUNCTION epm.assignment_escalation_worker_claim(text,integer);
DROP FUNCTION epm.assignment_escalation_worker_renew(
  text,text,text,bigint,text,timestamptz,bigint,text,integer);
DROP FUNCTION epm.assignment_escalation_worker_settle(
  text,text,text,bigint,text,timestamptz,bigint,text);
DROP FUNCTION epm.forecast_definition_state_guard();
DROP FUNCTION epm.forecast_definition_version_guard();
DROP FUNCTION epm.forecast_occurrence_worker_claim(
  text,integer,integer,integer,integer);
DROP FUNCTION epm.forecast_occurrence_worker_settle_failed(
  text,text,text,bigint,text);
DROP FUNCTION epm.forecast_occurrence_worker_settle_rejected(
  text,text,text,bigint,text,text);
DROP FUNCTION epm.forecast_schedule_worker_block_revoked();
DROP FUNCTION epm.forecast_schedule_worker_claim(text,integer);
DROP FUNCTION epm.forecast_schedule_worker_release(
  text,text,text,bigint,text);
DROP FUNCTION epm.planning_assignment_version_immutable();
DROP FUNCTION epm.project_application_taskflow_occurrence_task();
DROP FUNCTION epm.project_assignment_escalation_task();
DROP FUNCTION epm.project_forecast_occurrence_task();
DROP FUNCTION epm.project_human_activity_tasks();
DROP FUNCTION epm.assignment_escalation_task_source_id(
  text,bigint,text,timestamptz);
DROP FUNCTION epm.normalized_assignment_escalation_task_status(text);
DROP FUNCTION epm.normalized_forecast_occurrence_task_status(text);
DROP FUNCTION epm.normalized_application_taskflow_task_status(text);
DROP FUNCTION epm.normalized_human_activity_task_status(text);

-- Rewrite reset before removing the named relations. Exact old guards and all
-- 17 inventory entries must be present; otherwise fail rather than weakening
-- the lifecycle primitive silently.
DO $migration$
DECLARE definition text; revised text; relation_name text;
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
DECLARE forecast_guard constant text :=
  $guard$    IF EXISTS (SELECT 1 FROM epm.planning_forecast_occurrence WHERE workspace_id=p_workspace_id AND status IN ('accepted','ready','running','cancel_requested','business_published','needs_inspection')) THEN RAISE EXCEPTION 'UNSETTLED_FORECAST_OCCURRENCES'; END IF;
    IF EXISTS (SELECT 1 FROM epm.planning_forecast_schedule_state WHERE workspace_id=p_workspace_id AND dispatch_claimant IS NOT NULL AND dispatch_lease_until IS NOT NULL) THEN RAISE EXCEPTION 'UNSETTLED_FORECAST_SCHEDULE_DISPATCH'; END IF;
$guard$;
DECLARE assignment_guard constant text :=
  $guard$    IF EXISTS (SELECT 1 FROM epm.planning_assignment_due_occurrence WHERE workspace_id=p_workspace_id AND status='Running' AND claimant IS NOT NULL AND lease_until IS NOT NULL) THEN RAISE EXCEPTION 'UNSETTLED_ASSIGNMENT_ESCALATION_CLAIMS'; END IF;
$guard$;
DECLARE taskflow_guard constant text :=
  $guard$    IF EXISTS (SELECT 1 FROM epm.application_task_flow_occurrence
        WHERE workspace_id=p_workspace_id AND status='Active') THEN
        RAISE EXCEPTION 'UNSETTLED_APPLICATION_TASK_FLOW_OCCURRENCES';
    END IF;
$guard$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  revised:=replace(replace(replace(definition,forecast_guard,''),
    assignment_guard,''),taskflow_guard,'');
  IF revised=definition THEN
    RAISE EXCEPTION 'RESET_0235_GUARD_DEFINITION_MISMATCH';
  END IF;
  FOREACH relation_name IN ARRAY relations LOOP
    IF position(quote_literal(relation_name)||',' IN revised)>0 THEN
      revised:=replace(revised,quote_literal(relation_name)||',','');
    END IF;
  END LOOP;
  FOREACH relation_name IN ARRAY relations LOOP
    IF position(relation_name IN revised)>0 THEN
      RAISE EXCEPTION 'RESET_0235_REFERENCE_REMAINS: %',relation_name;
    END IF;
  END LOOP;
  EXECUTE revised;
END $migration$;

DROP TABLE epm.application_task_flow_event;
DROP TABLE epm.application_task_flow_activity;
DROP TABLE epm.application_task_flow_occurrence;
DROP TABLE epm.application_task_flow_state;
DROP TABLE epm.application_task_flow_version;
DROP TABLE epm.planning_assignment_control_current;
DROP TABLE epm.planning_assignment_control_event;
DROP TABLE epm.planning_assignment_due_occurrence;
DROP TABLE epm.planning_assignment_state;
DROP TABLE epm.planning_assignment_version;
DROP TABLE epm.planning_forecast_schedule_event;
DROP TABLE epm.planning_forecast_schedule_state;
DROP TABLE epm.planning_forecast_occurrence;
DROP TABLE epm.planning_forecast_progress;
DROP TABLE epm.planning_forecast_schedule_version;
DROP TABLE epm.planning_forecast_definition_state;
DROP TABLE epm.planning_forecast_definition_version;

-- Replaced after isolated canonical graph inspection.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'e3c5a39b0afe8b8b2d7021407a0d9d9f66a27e868980b5c6e5ccd2739461312f';
DECLARE new_fingerprint constant text :=
  'ff52ba439b4eaaf4ffaeece6fb18917581ebc35b43370befa11371440fd1c6b9';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0235_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0235_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;
