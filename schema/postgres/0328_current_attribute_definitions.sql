BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=327) THEN
    RAISE EXCEPTION 'MIGRATION_0328_REQUIRES_0327';
  END IF;
END $migration$;

-- Attribute definitions are one current application object.  Metadata and
-- values remain in place; numeric mutation history is replaced with an opaque
-- current-state fence that cannot address an older definition.
DROP TRIGGER attribute_definition_guard ON epm.attribute_definition;
ALTER TABLE epm.attribute_definition ADD COLUMN state_token text;
UPDATE epm.attribute_definition SET state_token=encode(pg_catalog.sha256(
  convert_to(concat_ws(chr(31),'attribute-definition',workspace_id,
    application_id,scope,dimension_id,attribute_id,definition_version::text,
    clock_timestamp()::text,random()::text),'UTF8')),'hex');
ALTER TABLE epm.attribute_definition
  ALTER COLUMN state_token SET NOT NULL,
  ALTER COLUMN state_token SET DEFAULT encode(pg_catalog.sha256(
    convert_to(gen_random_uuid()::text,'UTF8')),'hex'),
  DROP COLUMN definition_version,
  ADD CONSTRAINT attribute_definition_state_token_check
    CHECK(state_token~'^[0-9a-f]{64}$'),
  ADD CONSTRAINT attribute_definition_state_token_unique UNIQUE(
    workspace_id,application_id,state_token);

CREATE OR REPLACE FUNCTION epm.attribute_definition_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='UPDATE' THEN
    IF (NEW.workspace_id,NEW.application_id,NEW.scope,NEW.dimension_id,
        NEW.attribute_id,NEW.default_name) IS DISTINCT FROM
       (OLD.workspace_id,OLD.application_id,OLD.scope,OLD.dimension_id,
        OLD.attribute_id,OLD.default_name) THEN
      RAISE EXCEPTION 'ATTRIBUTE_DEFINITION_IDENTITY_IMMUTABLE';
    END IF;
    IF NEW.state_token=OLD.state_token THEN
      RAISE EXCEPTION 'ATTRIBUTE_DEFINITION_STATE_TOKEN_NOT_ROTATED';
    END IF;
    NEW.updated_at=transaction_timestamp();
  END IF;
  IF NEW.scope<>'Dimension' AND NOT EXISTS (
      SELECT 1 FROM epm.dimension d
       WHERE d.workspace_id=NEW.workspace_id
         AND d.application_id=NEW.application_id
         AND d.dimension_id=NEW.dimension_id) THEN
    RAISE EXCEPTION 'ATTRIBUTE_DEFINITION_DIMENSION_UNAVAILABLE';
  END IF;
  RETURN NEW;
END $function$;
CREATE TRIGGER attribute_definition_guard BEFORE INSERT OR UPDATE
  ON epm.attribute_definition FOR EACH ROW
  EXECUTE FUNCTION epm.attribute_definition_guard();

GRANT UPDATE(state_token) ON epm.attribute_definition TO epm_runtime;
ALTER TABLE epm.operation_receipt DISABLE TRIGGER USER;
UPDATE epm.operation_receipt SET result=result-'definitionVersion'
 WHERE result ? 'definitionVersion';
ALTER TABLE epm.operation_receipt ENABLE TRIGGER USER;
COMMIT;
