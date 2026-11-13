BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=339) THEN
    RAISE EXCEPTION 'MIGRATION_0340_REQUIRES_0339';
  END IF;
END $migration$;

ALTER TABLE epm.cta_bridge_source
  ADD COLUMN result_state_token text,
  ADD COLUMN result_content_digest text;

UPDATE epm.cta_bridge_source source
SET result_state_token=state.state_token,
    result_content_digest=state.content_digest
FROM epm.calculation_result_state state
WHERE state.workspace_id=source.workspace_id
  AND state.application_id=source.application_id
  AND state.result_key=source.result_key
  AND state.bridge_generation_id=source.generation_id
  AND state.committed_revision=source.published_revision;

DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.cta_bridge_source
      WHERE result_state_token IS NULL OR result_content_digest IS NULL) THEN
    RAISE EXCEPTION 'MIGRATION_0340_STALE_CTA_SOURCE';
  END IF;
END $migration$;

DO $migration$ DECLARE constraint_name text; BEGIN
  FOR constraint_name IN
    SELECT constraint_record.conname FROM pg_constraint constraint_record
    WHERE constraint_record.conrelid='epm.cta_bridge_source'::regclass
      AND constraint_record.contype='f'
      AND constraint_record.confrelid='epm.calculation_generation'::regclass
  LOOP
    EXECUTE format('ALTER TABLE epm.cta_bridge_source DROP CONSTRAINT %I',
      constraint_name);
  END LOOP;
END $migration$;

ALTER TABLE epm.cta_bridge_source
  RENAME COLUMN generation_id TO source_operation_id;
ALTER TABLE epm.cta_bridge_source
  RENAME COLUMN published_revision TO source_committed_revision;
ALTER TABLE epm.cta_bridge_source
  ALTER COLUMN result_state_token SET NOT NULL,
  ALTER COLUMN result_content_digest SET NOT NULL,
  ADD CONSTRAINT cta_bridge_source_state_token_valid
    CHECK(result_state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT cta_bridge_source_content_digest_valid
    CHECK(result_content_digest~'^[0-9a-f]{64}$');
CREATE INDEX cta_bridge_source_result_evidence
  ON epm.cta_bridge_source(
    workspace_id,application_id,result_key,result_state_token);

DO $migration$
DECLARE definition text; revised text;
DECLARE previous constant text:='9a32b3512b933f4d87df96b22104ab7fb3f7467e25072b92804698e36d7a0f91';
DECLARE current_graph constant text:='e68626c544dd0a6f53cfa8b97ab9797656a28b50663cebfe40da15843afd6a70';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0340_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,previous,current_graph);
  IF revised=definition THEN RAISE EXCEPTION 'RESET_0340_DEFINITION_MISMATCH'; END IF;
  EXECUTE revised;

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0340_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
