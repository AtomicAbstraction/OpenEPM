BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=284) THEN
    RAISE EXCEPTION 'MIGRATION_0285_REQUIRES_0284';
  END IF;
END $migration$;

-- Private calculated work is attached to its durable job, never a business
-- snapshot or independently publishable artifact. Job retention/purge owns it.
CREATE TABLE epm.numeric_transform_candidate (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    job_id text NOT NULL,
    program_digest text NOT NULL CHECK (program_digest ~ '^[0-9a-f]{64}$'),
    candidate_digest text NOT NULL CHECK (candidate_digest ~ '^[0-9a-f]{64}$'),
    candidate jsonb NOT NULL CHECK (jsonb_typeof(candidate)='object'
        AND octet_length(candidate::text)<=16777216),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,job_id),
    FOREIGN KEY (workspace_id,application_id,job_id)
        REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE CASCADE
);
GRANT SELECT,INSERT,DELETE ON epm.numeric_transform_candidate TO epm_runtime;
GRANT SELECT ON epm.numeric_transform_candidate TO epm_lifecycle;
ALTER TABLE epm.numeric_transform_candidate ENABLE ROW LEVEL SECURITY;
CREATE POLICY numeric_transform_candidate_scope ON epm.numeric_transform_candidate
    TO epm_runtime USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY numeric_transform_candidate_lifecycle ON epm.numeric_transform_candidate
    FOR SELECT TO epm_lifecycle USING (workspace_id=current_setting('epm.workspace_id',true));

-- Every terminal job path (publication, cancellation, definitive failure)
-- retires its private work, including paths owned by the worker role.
CREATE FUNCTION epm.retire_numeric_transform_candidate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
  IF NEW.status IN ('published','failed','cancelled') THEN
    DELETE FROM epm.numeric_transform_candidate
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND job_id=NEW.job_id;
  END IF;
  RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION epm.retire_numeric_transform_candidate() FROM PUBLIC;
CREATE TRIGGER retire_numeric_transform_candidate
  AFTER UPDATE OF status ON epm.job FOR EACH ROW
  WHEN (NEW.function_name='facts.numeric.transform')
  EXECUTE FUNCTION epm.retire_numeric_transform_candidate();

DO $migration$
DECLARE definition text; revised text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position('c6b19e7612e2b7d2c536bf2326f9987e74ef01091ea1f0516f5d92f33c158379' IN definition)=0
     OR position('''job_event'',''job_dependency''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0285_PREDECESSOR_MISMATCH';
  END IF;
  revised := replace(definition, '''job_event'',''job_dependency''',
      '''numeric_transform_candidate'',''job_event'',''job_dependency''');
  revised := replace(revised,
      'c6b19e7612e2b7d2c536bf2326f9987e74ef01091ea1f0516f5d92f33c158379',
      '390b2aa5ee922a4a76eb73158fd2ef0c6130c21d55bab95dcb19df77a597cefb');
  EXECUTE revised;
END $migration$;

COMMIT;
