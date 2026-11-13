BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=328) THEN
    RAISE EXCEPTION 'MIGRATION_0329_REQUIRES_0328';
  END IF;
END $migration$;

-- Durable Python child jobs bind the exact current schedule state carried by
-- their sealed build.  A numeric schedule version was left behind when
-- schedules/builds moved to current tokens in 0315; remove that last locator.
ALTER TABLE epm.job ADD COLUMN execution_schedule_state_token text;
UPDATE epm.job j SET execution_schedule_state_token=b.schedule_state_token
FROM epm.python_program_workflow w
JOIN epm.python_program_build b
  ON (b.workspace_id,b.application_id,b.build_id)=
     (w.workspace_id,w.application_id,w.build_id)
WHERE (j.workspace_id,j.application_id,j.python_workflow_id)=
      (w.workspace_id,w.application_id,w.workflow_id)
  AND j.execution_schedule_id IS NOT NULL;

DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.job
      WHERE (execution_schedule_id IS NULL)<>(execution_schedule_state_token IS NULL)) THEN
    RAISE EXCEPTION 'JOB_SCHEDULE_0329_BINDING_UNRESOLVED';
  END IF;
END $migration$;

DO $migration$ DECLARE item record;
BEGIN
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='epm.job'::regclass
      AND pg_get_constraintdef(oid) LIKE '%execution_schedule_version%'
  LOOP
    EXECUTE format('ALTER TABLE epm.job DROP CONSTRAINT %I',item.conname);
  END LOOP;
END $migration$;

ALTER TABLE epm.job
  DROP COLUMN execution_schedule_version,
  ADD CONSTRAINT job_execution_schedule_state_token_format CHECK(
    execution_schedule_state_token IS NULL
    OR execution_schedule_state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT job_execution_schedule_binding_complete CHECK(
    (execution_schedule_id IS NULL)=(execution_schedule_state_token IS NULL)
    AND (python_workflow_id IS NOT NULL OR execution_schedule_id IS NULL));
COMMIT;
