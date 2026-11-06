-- Bind new Python builds to immutable, revocable unattended-execution authority.
-- Columns stay nullable so an upgrade preserves historical technical records;
-- fixed-core admission rejects an unbound legacy row before any new effect.
DO $$
BEGIN
  IF EXISTS(SELECT 1 FROM information_schema.columns
      WHERE table_schema='epm' AND table_name='python_program_build'
        AND column_name IN ('delegation_id','delegation_version','schedule_id',
                            'schedule_version'))
  THEN RAISE EXCEPTION 'RESET_0130_DEFINITION_MISMATCH'; END IF;
END $$;

ALTER TABLE epm.python_program_build
  ADD COLUMN delegation_id text,
  ADD COLUMN delegation_version bigint,
  ADD COLUMN schedule_id text,
  ADD COLUMN schedule_version bigint,
  ADD CONSTRAINT python_build_delegation_pair CHECK
    ((delegation_id IS NULL) = (delegation_version IS NULL)),
  ADD CONSTRAINT python_build_schedule_pair CHECK
    ((schedule_id IS NULL) = (schedule_version IS NULL)),
  ADD CONSTRAINT python_build_delegation_id_shape CHECK
    (delegation_id IS NULL OR delegation_id ~ '^[A-Za-z0-9._-]{1,200}$'),
  ADD CONSTRAINT python_build_delegation_version_positive CHECK
    (delegation_version IS NULL OR delegation_version > 0),
  ADD CONSTRAINT python_build_schedule_shape CHECK
    (schedule_id IS NULL OR schedule_id ~ '^[A-Za-z0-9._-]{1,200}$'),
  ADD CONSTRAINT python_build_schedule_version_positive CHECK
    (schedule_version IS NULL OR schedule_version > 0),
  ADD CONSTRAINT python_build_execution_delegation_fkey FOREIGN KEY
    (workspace_id,application_id,delegation_id,delegation_version)
    REFERENCES epm.execution_delegation_version
      (workspace_id,application_id,delegation_id,version) ON DELETE RESTRICT;

CREATE INDEX python_build_execution_delegation
  ON epm.python_program_build
    (workspace_id,application_id,delegation_id,delegation_version)
  WHERE delegation_id IS NOT NULL;
