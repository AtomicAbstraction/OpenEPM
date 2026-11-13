BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=338) THEN
    RAISE EXCEPTION 'MIGRATION_0339_REQUIRES_0338';
  END IF;
  IF EXISTS(
    SELECT 1 FROM epm.job job
    JOIN epm.calculation_generation generation
      ON generation.workspace_id=job.workspace_id
     AND generation.application_id=job.application_id
     AND generation.job_id=job.job_id
    WHERE job.status IN('accepted','ready','running','staged','cancel_requested')
  ) THEN
    RAISE EXCEPTION 'MIGRATION_0339_ACTIVE_CALCULATION_WORK';
  END IF;
END $migration$;

-- Posted journals are accounting evidence, not live pointers into the current
-- calculation payload.  Copy the exact result identity and typed amount before
-- retiring the legacy publication/payload foreign keys.
ALTER TABLE epm.manual_journal_calculation_source
  ADD COLUMN result_state_token text,
  ADD COLUMN result_content_digest text,
  ADD COLUMN source_amount numeric(38,8);

UPDATE epm.manual_journal_calculation_source journal_source
SET result_state_token=state.state_token,
    result_content_digest=state.content_digest,
    source_amount=result.amount
FROM epm.calculation_result_state state,
     epm.calculation_unit_result result
WHERE state.workspace_id=journal_source.workspace_id
  AND state.application_id=journal_source.application_id
  AND state.result_key=journal_source.result_key
  AND state.bridge_generation_id=journal_source.generation_id
  AND state.committed_revision=journal_source.published_revision
  AND result.workspace_id=journal_source.workspace_id
  AND result.application_id=journal_source.application_id
  AND result.generation_id=journal_source.generation_id
  AND result.coordinate_id=journal_source.source_coordinate_id
  AND result.output_unit_currency_dimension_id=journal_source.unit_dimension_id
  AND result.output_unit_currency_member_id=journal_source.unit_member_id;

DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.manual_journal_calculation_source
      WHERE result_state_token IS NULL OR result_content_digest IS NULL
         OR source_amount IS NULL) THEN
    RAISE EXCEPTION 'MIGRATION_0339_STALE_JOURNAL_SOURCE';
  END IF;
END $migration$;

DO $migration$ DECLARE constraint_name text; BEGIN
  FOR constraint_name IN
    SELECT constraint_record.conname
    FROM pg_constraint constraint_record
    WHERE constraint_record.conrelid=
            'epm.manual_journal_calculation_source'::regclass
      AND constraint_record.contype='f'
      AND constraint_record.confrelid IN(
            'epm.calculation_publication'::regclass,
            'epm.calculation_unit_result'::regclass)
  LOOP
    EXECUTE format('ALTER TABLE epm.manual_journal_calculation_source '
      'DROP CONSTRAINT %I',constraint_name);
  END LOOP;
END $migration$;

DROP INDEX epm.manual_journal_calculation_source_generation;
ALTER TABLE epm.manual_journal_calculation_source
  RENAME COLUMN generation_id TO source_operation_id;
ALTER TABLE epm.manual_journal_calculation_source
  RENAME COLUMN published_revision TO source_committed_revision;
ALTER TABLE epm.manual_journal_calculation_source
  ALTER COLUMN result_state_token SET NOT NULL,
  ALTER COLUMN result_content_digest SET NOT NULL,
  ALTER COLUMN source_amount SET NOT NULL,
  ADD CONSTRAINT manual_journal_calculation_source_state_token_valid
    CHECK(result_state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT manual_journal_calculation_source_content_digest_valid
    CHECK(result_content_digest~'^[0-9a-f]{64}$');
CREATE INDEX manual_journal_calculation_source_evidence
  ON epm.manual_journal_calculation_source(
    workspace_id,application_id,result_key,result_state_token);

DROP TABLE epm.calculation_publication;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:='490f437ceebeacee7874c8e95d8491a50830a4e60b72503138b8d19703f26ae5';
DECLARE current_graph constant text:='9a32b3512b933f4d87df96b22104ab7fb3f7467e25072b92804698e36d7a0f91';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 OR
     position('''calculation_result_state'',''calculation_publication''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0339_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''calculation_result_state'',''calculation_publication''',
    '''calculation_result_state''');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'calculation_publication');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0339_INVENTORY_MISMATCH';
  END IF;
  inventory:=array_remove(inventory,'calculation_publication');
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
