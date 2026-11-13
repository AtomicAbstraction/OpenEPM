-- Project durable sealed-source import executions into the universal task log.
-- The native import record and source-batch publisher remain authoritative.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=180) THEN
    RAISE EXCEPTION 'MIGRATION_0181_PREDECESSOR_0180_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','f:','i:','p:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK(source_family IN
    ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
     'ForecastOccurrence','ImportExecution')),
  ADD COLUMN source_import_execution_id text GENERATED ALWAYS AS
    (CASE WHEN source_family='ImportExecution' THEN source_id END) STORED,
  ADD CONSTRAINT task_source_import_execution_fkey FOREIGN KEY
    (workspace_id,application_id,source_import_execution_id)
    REFERENCES epm.source_import_execution
      (workspace_id,application_id,request_id) ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_import_execution_task_status(
  native text,cancel_requested boolean)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE WHEN cancel_requested AND native='Claimed' THEN 'InterruptRequested'
ELSE CASE native
  WHEN 'Accepted' THEN 'Accepted'
  WHEN 'Claimed' THEN 'Running'
  WHEN 'Publishing' THEN 'Running'
  WHEN 'Completed' THEN 'Succeeded'
  WHEN 'Failed' THEN 'Failed'
  WHEN 'Cancelled' THEN 'Interrupted'
END END;

CREATE FUNCTION epm.project_import_execution_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'i:'||NEW.request_id;
BEGIN
  normalized := epm.normalized_import_execution_task_status(
    NEW.status,NEW.cancel_requested);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_IMPORT_EXECUTION_TASK_STATUS'; END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.cancel_requested=OLD.cancel_requested
      AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW; END IF;
  IF TG_OP='INSERT' THEN
    INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
      VALUES(NEW.workspace_id,NEW.application_id,1)
      ON CONFLICT(workspace_id,application_id) DO UPDATE
        SET last_sequence=epm.task_cursor.last_sequence+1
      RETURNING last_sequence INTO task_sequence;
    INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,
      task_class,source_family,source_id,issuer,subject_id,function_name,
      resource_class,status,native_status,interruptible,rerun_supported,
      created_at,updated_at)
    VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
      'BusinessExecution','ImportExecution',NEW.request_id,NEW.issuer,
      NEW.subject_id,'facts.transfer.import.request','long',normalized,NEW.status,
      NEW.status IN ('Accepted','Claimed'),false,NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN ('Accepted','Claimed'),
      updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id
      AND source_family='ImportExecution' AND source_id=NEW.request_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND task_id=projected_task_id;
  END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
    status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
    NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_import_execution_task_status(text,boolean)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_import_execution_task() FROM PUBLIC;

WITH numbered AS (
  SELECT e.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY e.workspace_id,e.application_id
    ORDER BY e.created_at,e.request_id) AS task_sequence
  FROM epm.source_import_execution e
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'i:'||request_id,task_sequence,
  'BusinessExecution','ImportExecution',request_id,issuer,subject_id,
  'facts.transfer.import.request','long',
  epm.normalized_import_execution_task_status(status,cancel_requested),status,
  status IN ('Accepted','Claimed'),false,created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'i:'||request_id,1,
  epm.normalized_import_execution_task_status(status,cancel_requested),status,
  claim_generation,NULL,error_code,updated_at FROM epm.source_import_execution;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_import_execution_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation,cancel_requested
ON epm.source_import_execution
FOR EACH ROW EXECUTE FUNCTION epm.project_import_execution_task();

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '2d6b296c095881faf427191d8f09a7d2383b81ef4454c439ee2b04f6b4223afc';
DECLARE new_fingerprint constant text :=
  'a4e4f22168ff3aa521c25d486a530b37f5fb189739ff588e11db811d043d1bb3';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0181_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
