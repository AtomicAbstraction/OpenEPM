-- Project populated-layout build/validation and atomic activation as two
-- distinct universal tasks.  The private build is technical work and does
-- not become successful merely because coordinates were staged.  Activation
-- is business work and carries the revision committed by its native receipt.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=184) THEN
    RAISE EXCEPTION 'MIGRATION_0185_PREDECESSOR_0184_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('a:','c:','e:','f:','i:','l:','p:','r:','s:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK(source_family IN
    ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
     'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
     'ExportProducer','TransferCleanup','LayoutReplacementBuild',
     'LayoutActivation'));

CREATE FUNCTION epm.normalized_layout_replacement_build_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'Accepted' THEN 'Accepted'
  WHEN 'Staging' THEN 'Running'
  WHEN 'Staged' THEN 'Running'
  WHEN 'Validated' THEN 'Succeeded'
  WHEN 'ValidationFailed' THEN 'Failed'
  WHEN 'Failed' THEN 'Failed'
  WHEN 'Cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.normalized_layout_activation_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'Requested' THEN 'Accepted'
  WHEN 'Activating' THEN 'Running'
  WHEN 'Activated' THEN 'Succeeded'
  WHEN 'Failed' THEN 'Failed'
  WHEN 'Cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.project_layout_replacement_build_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'l:'||NEW.request_id;
BEGIN
  normalized := epm.normalized_layout_replacement_build_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_LAYOUT_BUILD_TASK_STATUS'; END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.claim_generation=OLD.claim_generation
      AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code THEN RETURN NEW; END IF;
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
      'TechnicalExecution','LayoutReplacementBuild',NEW.request_id,NEW.issuer,
      NEW.subject_id,'metadata.layout.populated.replace.request','long',
      normalized,NEW.status,NEW.status IN ('Accepted','Staging'),false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN ('Accepted','Staging'),updated_at=NEW.updated_at
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND source_family='LayoutReplacementBuild' AND source_id=NEW.request_id;
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

CREATE FUNCTION epm.project_layout_activation_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'a:'||NEW.activation_id;
DECLARE committed_revision bigint;
BEGIN
  normalized := epm.normalized_layout_activation_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_LAYOUT_ACTIVATION_TASK_STATUS'; END IF;
  IF NEW.status='Activated' THEN
    committed_revision := (NEW.result->>'committedRevision')::bigint;
    IF committed_revision IS NULL OR committed_revision<=0 THEN
      RAISE EXCEPTION 'LAYOUT_ACTIVATION_TASK_RECEIPT_INVALID';
    END IF;
  END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.claim_generation=OLD.claim_generation
      AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code
      AND NEW.result IS NOT DISTINCT FROM OLD.result THEN RETURN NEW; END IF;
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
      'BusinessExecution','LayoutActivation',NEW.activation_id,NEW.issuer,
      NEW.subject_id,'metadata.layout.populated.activate.request','long',
      normalized,NEW.status,NEW.status='Requested',false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status='Requested',updated_at=NEW.updated_at
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND source_family='LayoutActivation' AND source_id=NEW.activation_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      AND task_id=projected_task_id;
  END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
    status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
    NEW.status,NEW.claim_generation,committed_revision,NEW.error_code,
    transaction_timestamp());
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION epm.normalized_layout_replacement_build_task_status(text),
 epm.normalized_layout_activation_task_status(text),
 epm.project_layout_replacement_build_task(),epm.project_layout_activation_task()
 FROM PUBLIC;

WITH numbered AS (
  SELECT r.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY r.workspace_id,r.application_id
    ORDER BY r.created_at,r.request_id) AS task_sequence
  FROM epm.layout_replacement_request r
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'l:'||request_id,task_sequence,
 'TechnicalExecution','LayoutReplacementBuild',request_id,issuer,subject_id,
 'metadata.layout.populated.replace.request','long',
 epm.normalized_layout_replacement_build_task_status(status),status,
 status IN ('Accepted','Staging'),false,created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'l:'||request_id,1,
 epm.normalized_layout_replacement_build_task_status(status),status,
 claim_generation,NULL,error_code,updated_at FROM epm.layout_replacement_request;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

WITH numbered AS (
  SELECT x.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY x.workspace_id,x.application_id
    ORDER BY x.created_at,x.activation_id) AS task_sequence
  FROM epm.layout_replacement_activation x
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'a:'||activation_id,task_sequence,
 'BusinessExecution','LayoutActivation',activation_id,issuer,subject_id,
 'metadata.layout.populated.activate.request','long',
 epm.normalized_layout_activation_task_status(status),status,
 status='Requested',false,created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'a:'||activation_id,1,
 epm.normalized_layout_activation_task_status(status),status,claim_generation,
 CASE WHEN status='Activated' THEN (result->>'committedRevision')::bigint END,
 error_code,updated_at FROM epm.layout_replacement_activation;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_layout_replacement_build_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation,error_code
ON epm.layout_replacement_request
FOR EACH ROW EXECUTE FUNCTION epm.project_layout_replacement_build_task();

CREATE TRIGGER aa_layout_activation_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation,error_code,result
ON epm.layout_replacement_activation
FOR EACH ROW EXECUTE FUNCTION epm.project_layout_activation_task();

-- Both native rows and their certificates/receipts are retained.  Omitting a
-- source foreign key keeps the universal audit usable even if a later bounded
-- retention policy is introduced.  This migration adds no relation, foreign
-- key or view, so the reviewed 0182 reset fingerprint remains exact.
