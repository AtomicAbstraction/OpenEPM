-- Server-owned authority pinned to asynchronously published Python child jobs.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='epm'
   AND table_name='job' AND column_name='python_workflow_id')
 THEN RAISE EXCEPTION 'RESET_0131_DEFINITION_MISMATCH'; END IF;
END $$;

ALTER TABLE epm.job
 ADD COLUMN python_workflow_id text,
 ADD COLUMN execution_delegation_id text,
 ADD COLUMN execution_delegation_version bigint,
 ADD COLUMN execution_schedule_id text,
 ADD COLUMN execution_schedule_version bigint,
 ADD CONSTRAINT job_python_authority_all_or_none CHECK (
   (python_workflow_id IS NULL) = (execution_delegation_id IS NULL)
   AND (execution_delegation_id IS NULL) = (execution_delegation_version IS NULL)),
 ADD CONSTRAINT job_python_schedule_pair CHECK (
   (execution_schedule_id IS NULL) = (execution_schedule_version IS NULL)
   AND (python_workflow_id IS NOT NULL OR execution_schedule_id IS NULL)),
 ADD CONSTRAINT job_python_authority_shapes CHECK (
   (execution_delegation_id IS NULL OR
      execution_delegation_id ~ '^[A-Za-z0-9._-]{1,200}$')
   AND (execution_delegation_version IS NULL OR
      execution_delegation_version > 0)
   AND (execution_schedule_id IS NULL OR
      execution_schedule_id ~ '^[A-Za-z0-9._-]{1,200}$')
   AND (execution_schedule_version IS NULL OR execution_schedule_version > 0)),
 ADD CONSTRAINT job_python_workflow_fkey FOREIGN KEY
   (workspace_id,application_id,python_workflow_id)
   REFERENCES epm.python_program_workflow(workspace_id,application_id,workflow_id)
   ON DELETE RESTRICT,
 ADD CONSTRAINT job_python_delegation_fkey FOREIGN KEY
   (workspace_id,application_id,execution_delegation_id,
    execution_delegation_version)
   REFERENCES epm.execution_delegation_version
     (workspace_id,application_id,delegation_id,version) ON DELETE RESTRICT;

CREATE INDEX job_python_workflow_authority ON epm.job
 (workspace_id,application_id,python_workflow_id,
  execution_delegation_id,execution_delegation_version)
 WHERE python_workflow_id IS NOT NULL;
