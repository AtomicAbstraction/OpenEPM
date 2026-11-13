BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=340) THEN
    RAISE EXCEPTION 'MIGRATION_0341_REQUIRES_0340';
  END IF;
END $migration$;

-- A saved rule has one current definition.  State tokens fence replacement and
-- activation; activation/commit counters are not object identities.
CREATE FUNCTION epm.current_rule_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_rule_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_rule_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_rule_canonical_json(jsonb)
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

UPDATE epm.application_schedule_definition
SET definition=definition#-'{target,activatedRevision}',
    definition_digest=encode(sha256(convert_to(
      epm.current_rule_canonical_json(
        definition#-'{target,activatedRevision}'),'UTF8')),'hex');

DO $migration$ DECLARE item record; BEGIN
  FOR item IN
    SELECT constraint_record.conrelid::regclass AS relation,
           constraint_record.conname
    FROM pg_constraint constraint_record
    WHERE constraint_record.contype='c'
      AND constraint_record.conrelid IN (
        'epm.expression_rule_definition'::regclass,
        'epm.application_schedule_definition'::regclass,
        'epm.application_rule_workflow'::regclass)
      AND pg_get_constraintdef(constraint_record.oid) ~
          '(activated_revision|published_revision)'
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',
      item.relation,item.conname);
  END LOOP;
END $migration$;

ALTER TABLE epm.expression_rule_definition DROP COLUMN activated_revision;
ALTER TABLE epm.application_schedule_definition DROP COLUMN activated_revision;
ALTER TABLE epm.application_rule_workflow DROP COLUMN published_revision;

REVOKE UPDATE ON epm.expression_rule_definition FROM epm_runtime;
GRANT UPDATE(program,program_digest,state_token,status,metadata_revision,
  source_build_id,updated_operation_id,updated_revision,updated_issuer,
  updated_subject_id,updated_at)
  ON epm.expression_rule_definition TO epm_runtime;

DROP FUNCTION epm.current_rule_canonical_json(jsonb);

COMMIT;
