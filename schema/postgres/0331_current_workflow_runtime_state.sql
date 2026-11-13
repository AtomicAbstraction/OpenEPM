BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=330) THEN
    RAISE EXCEPTION 'MIGRATION_0331_REQUIRES_0330';
  END IF;
END $migration$;

-- Workflow event ordinals remain audit chronology.  They are not concurrency
-- locators.  Current occurrence/activity mutation state is fenced by opaque
-- tokens, and no prior state payload is retained.
ALTER TABLE epm.application_workflow_occurrence
  RENAME COLUMN occurrence_version TO last_event_ordinal;
ALTER TABLE epm.application_workflow_activity
  RENAME COLUMN activity_version TO transition_ordinal;

ALTER TABLE epm.application_workflow_occurrence ADD COLUMN state_token text;
ALTER TABLE epm.application_workflow_activity ADD COLUMN state_token text;

UPDATE epm.application_workflow_occurrence
SET state_token=encode(sha256(convert_to(
  workspace_id||E'\n'||application_id||E'\n'||occurrence_id||E'\n'||
  last_event_ordinal::text||E'\n'||last_operation_id,'UTF8')),'hex');
UPDATE epm.application_workflow_activity
SET state_token=encode(sha256(convert_to(
  workspace_id||E'\n'||application_id||E'\n'||occurrence_id||E'\n'||
  activity_id||E'\n'||transition_ordinal::text||E'\n'||coalesce(operation_id,''),
  'UTF8')),'hex');

ALTER TABLE epm.application_workflow_occurrence
  ALTER COLUMN state_token SET NOT NULL,
  ADD CONSTRAINT application_workflow_occurrence_state_token_check
    CHECK(state_token~'^[0-9a-f]{64}$');
ALTER TABLE epm.application_workflow_activity
  ALTER COLUMN state_token SET NOT NULL,
  ADD CONSTRAINT application_workflow_activity_state_token_check
    CHECK(state_token~'^[0-9a-f]{64}$');

GRANT UPDATE(status,last_event_ordinal,state_token,last_operation_id,
  completed_at,cancelled_at) ON epm.application_workflow_occurrence TO epm_runtime;
GRANT UPDATE(status,transition_ordinal,state_token,operation_id,
  completed_by_issuer,completed_by_subject_id,completed_at,
  returned_to_activity_id) ON epm.application_workflow_activity TO epm_runtime;

-- Universal task projection uses transition/event ordinals only as append-only
-- audit ordering.  Rewrite its stored definition after the physical renames.
DO $migration$
DECLARE definition text; revised text;
BEGIN
  SELECT pg_get_functiondef(
    'epm.project_application_workflow_tasks()'::regprocedure)
  INTO definition;
  IF position('occurrence.occurrence_version' IN definition)=0
     OR position('activity.activity_version' IN definition)=0 THEN
    RAISE EXCEPTION 'WORKFLOW_RUNTIME_0331_PROJECTION_MISMATCH';
  END IF;
  revised:=replace(replace(definition,
    'occurrence.occurrence_version','occurrence.last_event_ordinal'),
    'activity.activity_version','activity.transition_ordinal');
  EXECUTE revised;
END $migration$;

COMMIT;
