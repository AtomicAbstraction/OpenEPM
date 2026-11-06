-- Project durable rolling-forecast occurrences into the universal task log.
-- Native occurrence rows remain authoritative for cancellation and recovery.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=179) THEN
    RAISE EXCEPTION 'MIGRATION_0180_PREDECESSOR_0179_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','f:','p:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK(source_family IN
    ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
     'ForecastOccurrence')),
  ADD COLUMN source_forecast_occurrence_id text GENERATED ALWAYS AS
    (CASE WHEN source_family='ForecastOccurrence' THEN source_id END) STORED,
  ADD CONSTRAINT task_source_forecast_occurrence_fkey FOREIGN KEY
    (workspace_id,application_id,source_forecast_occurrence_id)
    REFERENCES epm.planning_forecast_occurrence
      (workspace_id,application_id,occurrence_id) ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_forecast_occurrence_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'accepted' THEN 'Accepted'
  WHEN 'ready' THEN 'Waiting'
  WHEN 'running' THEN 'Running'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'business_published' THEN 'Running'
  WHEN 'progress_committed' THEN 'Succeeded'
  WHEN 'needs_inspection' THEN 'NeedsInspection'
  WHEN 'failed' THEN 'Failed'
END;

CREATE FUNCTION epm.project_forecast_occurrence_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'f:'||NEW.occurrence_id;
BEGIN
  normalized := epm.normalized_forecast_occurrence_task_status(NEW.status);
  IF normalized IS NULL THEN
    RAISE EXCEPTION 'UNKNOWN_FORECAST_OCCURRENCE_TASK_STATUS';
  END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
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
      'BusinessExecution','ForecastOccurrence',NEW.occurrence_id,
      NEW.execution_issuer,NEW.execution_subject,
      'facts.planning.forecast.occurrence.request','long',normalized,NEW.status,
      NEW.status IN ('accepted','ready','running','cancel_requested'),false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN
        ('accepted','ready','running','cancel_requested'),
      updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id
      AND source_family='ForecastOccurrence'
      AND source_id=NEW.occurrence_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND task_id=projected_task_id;
  END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
    status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
    NEW.status,NEW.claim_generation,NEW.committed_revision,NEW.error_code,
    transaction_timestamp());
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_forecast_occurrence_task_status(text)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_forecast_occurrence_task() FROM PUBLIC;

WITH numbered AS (
  SELECT o.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY o.workspace_id,o.application_id
    ORDER BY o.created_at,o.occurrence_id) AS task_sequence
  FROM epm.planning_forecast_occurrence o
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'f:'||occurrence_id,task_sequence,
  'BusinessExecution','ForecastOccurrence',occurrence_id,execution_issuer,
  execution_subject,'facts.planning.forecast.occurrence.request','long',
  epm.normalized_forecast_occurrence_task_status(status),status,
  status IN ('accepted','ready','running','cancel_requested'),false,
  created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'f:'||occurrence_id,1,
  epm.normalized_forecast_occurrence_task_status(status),status,
  claim_generation,committed_revision,error_code,updated_at
FROM epm.planning_forecast_occurrence;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_forecast_occurrence_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation
ON epm.planning_forecast_occurrence
FOR EACH ROW EXECUTE FUNCTION epm.project_forecast_occurrence_task();

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '154e572598c6bdc8db98c6a37896713e5ad37826c4f0d0d01af083129052b1f0';
DECLARE new_fingerprint constant text :=
  '2d6b296c095881faf427191d8f09a7d2383b81ef4454c439ee2b04f6b4223afc';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0180_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
