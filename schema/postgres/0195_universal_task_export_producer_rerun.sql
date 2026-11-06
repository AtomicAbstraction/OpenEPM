-- Retained failed/cancelled export producers may create a distinct owner-only
-- request.  The task remains after retention cleanup, but cleanup explicitly
-- removes rerun eligibility when the authoritative request is deleted.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=194) THEN
  RAISE EXCEPTION 'MIGRATION_0195_PREDECESSOR_0194_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.fact_export_producer_request
 ADD COLUMN rerun_of_request_id text,
 ADD CONSTRAINT fact_export_producer_rerun_not_self CHECK(
  rerun_of_request_id IS NULL OR rerun_of_request_id<>request_id);
CREATE INDEX fact_export_producer_rerun_source ON
 epm.fact_export_producer_request(workspace_id,application_id,
  rerun_of_request_id) WHERE rerun_of_request_id IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.project_export_producer_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE projected_task_id text:='e:'||NEW.request_id;
BEGIN
 normalized:=epm.normalized_export_producer_task_status(NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_EXPORT_PRODUCER_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,
   task_class,source_family,source_id,issuer,subject_id,function_name,
   resource_class,status,native_status,interruptible,rerun_supported,
   created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'TechnicalExecution','ExportProducer',NEW.request_id,NEW.issuer,
   NEW.subject_id,'facts.transfer.export.request','long',normalized,NEW.status,
   NEW.status IN('Accepted','Reading','Prepared','Publishing'),
   NEW.status IN('Cancelled','Failed'),NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('Accepted','Reading','Prepared','Publishing'),
   rerun_supported=NEW.status IN('Cancelled','Failed'),updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='ExportProducer' AND source_id=NEW.request_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.project_export_producer_task() FROM PUBLIC;

UPDATE epm.task t SET rerun_supported=p.status IN('Cancelled','Failed')
FROM epm.fact_export_producer_request p
WHERE t.workspace_id=p.workspace_id AND t.application_id=p.application_id
 AND t.source_family='ExportProducer' AND t.source_id=p.request_id;

CREATE FUNCTION epm.export_producer_task_before_delete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN
 UPDATE epm.task SET rerun_supported=false,updated_at=transaction_timestamp()
 WHERE workspace_id=OLD.workspace_id AND application_id=OLD.application_id
  AND source_family='ExportProducer' AND source_id=OLD.request_id;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION epm.export_producer_task_before_delete() FROM PUBLIC;
CREATE TRIGGER aa_export_producer_task_retention
 BEFORE DELETE ON epm.fact_export_producer_request FOR EACH ROW
 EXECUTE FUNCTION epm.export_producer_task_before_delete();

-- No relation or foreign-key inventory changes: the reviewed reset graph and
-- its fingerprint remain unchanged.  Lineage intentionally has no FK because
-- retention may remove the source before the newer request.
