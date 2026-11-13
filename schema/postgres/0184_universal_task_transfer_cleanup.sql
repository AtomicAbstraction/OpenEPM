-- Project administrator-requested transfer-retention cleanup into the
-- universal task log.  The native lease-fenced cleanup and immutable cleanup
-- certificate remain authoritative.  The task log has no source foreign key,
-- preserving its independent history if a future bounded native-retention
-- policy removes old cleanup control records.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=183) THEN
    RAISE EXCEPTION 'MIGRATION_0184_PREDECESSOR_0183_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','e:','f:','i:','p:','r:','s:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK(source_family IN
    ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
     'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
     'ExportProducer','TransferCleanup'));

CREATE FUNCTION epm.normalized_transfer_cleanup_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'Accepted' THEN 'Accepted'
  WHEN 'Running' THEN 'Running'
  WHEN 'Completed' THEN 'Succeeded'
  WHEN 'Cancelled' THEN 'Interrupted'
  WHEN 'Failed' THEN 'Failed'
END;

CREATE FUNCTION epm.project_transfer_cleanup_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'r:'||NEW.request_id;
BEGIN
  normalized := epm.normalized_transfer_cleanup_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_TRANSFER_CLEANUP_TASK_STATUS'; END IF;
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
      'TechnicalExecution','TransferCleanup',NEW.request_id,NEW.issuer,
      NEW.subject_id,'system.transfer.retention.cleanup','long',normalized,
      NEW.status,NEW.status IN ('Accepted','Running'),false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN ('Accepted','Running'),
      updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id
      AND source_family='TransferCleanup' AND source_id=NEW.request_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND task_id=projected_task_id;
  END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
    status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
    NEW.status,NEW.claim_generation,NULL,NULL,transaction_timestamp());
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_transfer_cleanup_task_status(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_transfer_cleanup_task() FROM PUBLIC;

WITH numbered AS (
  SELECT r.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY r.workspace_id,r.application_id
    ORDER BY r.created_at,r.request_id) AS task_sequence
  FROM epm.transfer_cleanup_request r
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'r:'||request_id,task_sequence,
  'TechnicalExecution','TransferCleanup',request_id,issuer,subject_id,
  'system.transfer.retention.cleanup','long',
  epm.normalized_transfer_cleanup_task_status(status),status,
  status IN ('Accepted','Running'),false,created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'r:'||request_id,1,
  epm.normalized_transfer_cleanup_task_status(status),status,
  claim_generation,NULL,NULL,updated_at FROM epm.transfer_cleanup_request;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_transfer_cleanup_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation
ON epm.transfer_cleanup_request
FOR EACH ROW EXECUTE FUNCTION epm.project_transfer_cleanup_task();

-- Reviewed reset impact: this migration adds only constraints, functions and a
-- trigger over already-inventoried relations.  It introduces no relation,
-- foreign key or view, so the reviewed 0182 reset fingerprint remains exact.
