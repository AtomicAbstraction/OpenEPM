BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=355) THEN
    RAISE EXCEPTION 'MIGRATION_0356_REQUIRES_0355';
  END IF;
END $migration$;

-- A current result owns the provenance required to validate and explain that
-- result.  It must not depend on a retained generation row.  The old
-- generation-keyed relations remain temporarily as private writer staging;
-- later migrations remove them after every publisher writes current payloads
-- directly.
DO $migration$ DECLARE constraint_name text; BEGIN
  SELECT con.conname INTO constraint_name
  FROM pg_constraint con
  WHERE con.conrelid='epm.calculation_result_state'::regclass
    AND con.contype='f'
    AND con.confrelid='epm.calculation_generation'::regclass;
  IF constraint_name IS NULL THEN
    RAISE EXCEPTION 'CURRENT_RESULT_GENERATION_BRIDGE_FK_MISSING';
  END IF;
  EXECUTE format('ALTER TABLE epm.calculation_result_state DROP CONSTRAINT %I',
                 constraint_name);
END $migration$;

ALTER TABLE epm.calculation_result_state
  RENAME COLUMN bridge_generation_id TO source_operation_id;
ALTER TABLE epm.calculation_result_state
  ADD COLUMN source_function text,
  ADD COLUMN source_commit_revision bigint,
  ADD COLUMN source_metadata_revision bigint,
  ADD COLUMN source_data_revision bigint,
  ADD COLUMN source_policy_revision bigint,
  ADD COLUMN source_compiler_version text,
  ADD COLUMN source_program_digest text,
  ADD COLUMN payload_layout text;

ALTER TABLE epm.calculation_result_state DISABLE TRIGGER USER;
UPDATE epm.calculation_result_state state SET
  source_function=generation.function_name,
  source_commit_revision=generation.source_commit_revision,
  source_metadata_revision=generation.source_metadata_revision,
  source_data_revision=job.expected_data_revision,
  source_policy_revision=generation.source_policy_revision,
  source_compiler_version=job.compiler_version,
  source_program_digest=job.program_digest,
  payload_layout=generation.generation_kind
FROM epm.calculation_generation generation
JOIN epm.job job
  ON job.workspace_id=generation.workspace_id
 AND job.application_id=generation.application_id
 AND job.job_id=generation.job_id
WHERE generation.workspace_id=state.workspace_id
  AND generation.application_id=state.application_id
  AND generation.generation_id=state.source_operation_id;
ALTER TABLE epm.calculation_result_state ENABLE TRIGGER USER;

DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.calculation_result_state
    WHERE source_function IS NULL OR source_commit_revision IS NULL
       OR source_metadata_revision IS NULL OR source_data_revision IS NULL
       OR source_policy_revision IS NULL OR source_compiler_version IS NULL
       OR source_program_digest IS NULL OR payload_layout IS NULL) THEN
    RAISE EXCEPTION 'CURRENT_RESULT_PROVENANCE_BACKFILL_INCOMPLETE';
  END IF;
END $migration$;

ALTER TABLE epm.calculation_result_state
  ALTER COLUMN source_function SET NOT NULL,
  ALTER COLUMN source_commit_revision SET NOT NULL,
  ALTER COLUMN source_metadata_revision SET NOT NULL,
  ALTER COLUMN source_data_revision SET NOT NULL,
  ALTER COLUMN source_policy_revision SET NOT NULL,
  ALTER COLUMN source_compiler_version SET NOT NULL,
  ALTER COLUMN source_program_digest SET NOT NULL,
  ALTER COLUMN payload_layout SET NOT NULL,
  ADD CONSTRAINT calculation_result_state_source_operation_id_check CHECK(
    source_operation_id~'^[0-9a-f]{32}$'),
  ADD CONSTRAINT calculation_result_state_source_function_check CHECK(
    length(source_function) BETWEEN 1 AND 200),
  ADD CONSTRAINT calculation_result_state_source_revisions_check CHECK(
    source_commit_revision>=0 AND source_metadata_revision>=0
    AND source_data_revision>=0 AND source_policy_revision>=0),
  ADD CONSTRAINT calculation_result_state_source_compiler_check CHECK(
    length(source_compiler_version) BETWEEN 1 AND 200),
  ADD CONSTRAINT calculation_result_state_source_program_digest_check CHECK(
    source_program_digest~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT calculation_result_state_payload_layout_check CHECK(
    payload_layout IN('flat','partition_manifest'));

-- Removing the generation FK changes the reviewed reset graph even though the
-- deletion inventory itself is unchanged.
DO $migration$
DECLARE definition text;
DECLARE previous constant text:=
  'cde87b63a665e9e1d6f42af4c322521e1fc1ef014fbfd7c4698ef5f6936ddeda';
DECLARE current_graph constant text:=
  'c78ce1a60b27151397911fa1758fe74e1c3ba867de8416ab409a9a266efa6f7d';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0356_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0356_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
