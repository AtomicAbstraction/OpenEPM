-- Project durable export production into the universal task log.  The native
-- producer and publication fence remain authoritative.  No foreign key is
-- used because retention cleanup may remove the producer/artifact while its
-- persistent task and immutable events must remain available.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=182) THEN
    RAISE EXCEPTION 'MIGRATION_0183_PREDECESSOR_0182_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','e:','f:','i:','p:','s:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK(source_family IN
    ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
     'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
     'ExportProducer'));

CREATE FUNCTION epm.normalized_export_producer_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'Accepted' THEN 'Accepted'
  WHEN 'Reading' THEN 'Running'
  WHEN 'Prepared' THEN 'Running'
  WHEN 'Publishing' THEN 'Running'
  WHEN 'Completed' THEN 'Succeeded'
  WHEN 'Cancelled' THEN 'Interrupted'
  WHEN 'Failed' THEN 'Failed'
END;

CREATE FUNCTION epm.project_export_producer_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'e:'||NEW.request_id;
BEGIN
  normalized := epm.normalized_export_producer_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_EXPORT_PRODUCER_TASK_STATUS'; END IF;
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
      'TechnicalExecution','ExportProducer',NEW.request_id,NEW.issuer,
      NEW.subject_id,'facts.transfer.export.request','long',normalized,NEW.status,
      NEW.status IN ('Accepted','Reading','Prepared','Publishing'),false,
      NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN
        ('Accepted','Reading','Prepared','Publishing'),
      updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
      AND application_id=NEW.application_id
      AND source_family='ExportProducer' AND source_id=NEW.request_id;
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
REVOKE ALL ON FUNCTION epm.normalized_export_producer_task_status(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_export_producer_task() FROM PUBLIC;

-- The runtime table policy is deliberately owner-scoped.  This narrow
-- controller lets the fixed task service interrupt another owner's producer
-- only when the verified caller is a current application Administrator.  It
-- never publishes an artifact and returns no row for an unavailable request.
CREATE FUNCTION epm.export_producer_cancel_control(
  w text,a text,rid text,actor_issuer text,actor_subject text,
  allow_application_admin boolean)
RETURNS TABLE(request_id text,status text,cancel_requested boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE producer epm.fact_export_producer_request%ROWTYPE;
DECLARE owner boolean;
DECLARE administrator boolean;
BEGIN
  IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w OR
     current_setting('epm.application_id',true) IS DISTINCT FROM a THEN
    RETURN;
  END IF;
  SELECT * INTO producer FROM epm.fact_export_producer_request
    WHERE workspace_id=w AND application_id=a AND
      epm.fact_export_producer_request.request_id=rid FOR UPDATE;
  IF NOT FOUND THEN RETURN; END IF;
  owner := (producer.issuer,producer.subject_id)=(actor_issuer,actor_subject);
  administrator := allow_application_admin AND EXISTS(
    SELECT 1 FROM epm.application_access_grant g
    WHERE g.workspace_id=w AND g.application_id=a
      AND g.issuer=actor_issuer AND g.subject_id=actor_subject
      AND g.role='Administrator');
  IF NOT (owner OR administrator) THEN RETURN; END IF;
  PERFORM epm.export_producer_cancel(w,a,rid);
  RETURN QUERY SELECT p.request_id,p.status,p.cancel_requested
    FROM epm.fact_export_producer_request p
    WHERE p.workspace_id=w AND p.application_id=a AND p.request_id=rid;
END $$;
REVOKE ALL ON FUNCTION epm.export_producer_cancel_control(
  text,text,text,text,text,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_cancel_control(
  text,text,text,text,text,boolean) TO epm_runtime;

WITH numbered AS (
  SELECT p.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY p.workspace_id,p.application_id
    ORDER BY p.created_at,p.request_id) AS task_sequence
  FROM epm.fact_export_producer_request p
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'e:'||request_id,task_sequence,
  'TechnicalExecution','ExportProducer',request_id,issuer,subject_id,
  'facts.transfer.export.request','long',
  epm.normalized_export_producer_task_status(status),status,
  status IN ('Accepted','Reading','Prepared','Publishing'),false,
  created_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'e:'||request_id,1,
  epm.normalized_export_producer_task_status(status),status,
  claim_generation,NULL,error_code,updated_at
FROM epm.fact_export_producer_request;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_export_producer_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation
ON epm.fact_export_producer_request
FOR EACH ROW EXECUTE FUNCTION epm.project_export_producer_task();

-- Reviewed reset impact: this migration adds only constraints, functions and a
-- trigger over already-inventoried relations.  It introduces no relation,
-- foreign key or view, so the reviewed 0182 reset fingerprint remains exact.
