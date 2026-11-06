-- Project generic application-rule schedule occurrences into the universal
-- task log.  The occurrence, its immutable schedule version and its linked
-- application-rule workflow remain authoritative; this creates no second
-- scheduler or receipt system.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=222) THEN
  RAISE EXCEPTION 'MIGRATION_0223_PREDECESSOR_0222_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
 ADD CONSTRAINT task_task_id_check CHECK(
  task_id~'^[0-9a-f]{32}$'
  OR(left(task_id,2)IN('a:','b:','c:','e:','f:','g:','i:','l:','p:','q:','r:','s:','t:','u:','v:','w:')
    AND substring(task_id from 3)~'^[0-9a-f]{32}$')
  OR task_id~'^d:[0-9a-f]{64}$'
  OR(task_id~'^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
  'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
  'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
  'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
  'ExpressionRuleSequence','FullAggregateSequence','SourceBatch',
  'AssignmentEscalation','ApplicationTaskFlowOccurrence','ApplicationRuleWorkflow',
  'ApplicationScheduleOccurrence')),
 ADD COLUMN source_application_schedule_occurrence_id text
  GENERATED ALWAYS AS(CASE WHEN source_family='ApplicationScheduleOccurrence'
                            THEN source_id END) STORED,
 ADD CONSTRAINT task_source_application_schedule_occurrence_fkey FOREIGN KEY(
  workspace_id,application_id,source_application_schedule_occurrence_id)
  REFERENCES epm.application_schedule_occurrence(
   workspace_id,application_id,occurrence_id) ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_application_schedule_occurrence_task_status(
 native text) RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
 WHEN 'ready' THEN 'Waiting' WHEN 'running' THEN 'Running'
 WHEN 'submitted' THEN 'Running'
 WHEN 'cancel_requested' THEN 'InterruptRequested'
 WHEN 'cancelled' THEN 'Interrupted' WHEN 'published' THEN 'Succeeded'
 WHEN 'partially_published' THEN 'PartiallySucceeded'
 WHEN 'failed' THEN 'Failed' WHEN 'needs_inspection' THEN 'NeedsInspection' END;

CREATE FUNCTION epm.project_application_schedule_occurrence_task()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE authority record;DECLARE projected text:='v:'||NEW.occurrence_id;
BEGIN
 normalized:=epm.normalized_application_schedule_occurrence_task_status(
  NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_APPLICATION_SCHEDULE_OCCURRENCE_TASK_STATUS';
 END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  SELECT execution_issuer,execution_subject INTO STRICT authority
  FROM epm.application_schedule_version WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND schedule_id=NEW.schedule_id
   AND version=NEW.schedule_version;
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected,task_sequence,
   'BusinessExecution','ApplicationScheduleOccurrence',NEW.occurrence_id,
   authority.execution_issuer,authority.execution_subject,
   'schedule.occurrence.run','long',normalized,NEW.status,
   NEW.status IN('ready','running','submitted','cancel_requested'),false,
   NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN(
    'ready','running','submitted','cancel_requested'),updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='ApplicationScheduleOccurrence'
   AND source_id=NEW.occurrence_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,
  transaction_timestamp());RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION
 epm.normalized_application_schedule_occurrence_task_status(text),
 epm.project_application_schedule_occurrence_task() FROM PUBLIC;

WITH numbered AS(
 SELECT o.*,v.execution_issuer,v.execution_subject,
  coalesce(c.last_sequence,0)+row_number()OVER(PARTITION BY o.workspace_id,
   o.application_id ORDER BY o.created_at,o.occurrence_id) AS task_sequence
 FROM epm.application_schedule_occurrence o
 JOIN epm.application_schedule_version v ON
  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
 LEFT JOIN epm.task_cursor c ON c.workspace_id=o.workspace_id
  AND c.application_id=o.application_id)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'v:'||occurrence_id,task_sequence,
 'BusinessExecution','ApplicationScheduleOccurrence',occurrence_id,
 execution_issuer,execution_subject,'schedule.occurrence.run','long',
 epm.normalized_application_schedule_occurrence_task_status(status),status,
 status IN('ready','running','submitted','cancel_requested'),false,
 created_at,updated_at FROM numbered;
INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'v:'||occurrence_id,1,
 epm.normalized_application_schedule_occurrence_task_status(status),status,
 claim_generation,NULL,error_code,updated_at
FROM epm.application_schedule_occurrence;
INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;
CREATE TRIGGER aa_application_schedule_occurrence_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation
ON epm.application_schedule_occurrence FOR EACH ROW
EXECUTE FUNCTION epm.project_application_schedule_occurrence_task();

-- The task projection FK changes the reviewed reset graph.  The final
-- fingerprint was derived from a clean disposable 0001-0223 installation.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
 '20733f9787bc8eb9930a34cbd1a5868cfd1a0b474247ef4b3d624d8cd4ac9b24';
DECLARE new_fingerprint constant text:=
 '10c0c68ca83b1448cb3fe45dcf2245c0900eff805c0d8f8617b13efa6ce209d6';
BEGIN
 definition:=pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
 IF position(old_fingerprint IN definition)=0
    OR position(new_fingerprint IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0223_FINGERPRINT_DEFINITION_MISMATCH';END IF;
 revised:=replace(definition,old_fingerprint,new_fingerprint);
 IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
  RAISE EXCEPTION 'RESET_0223_FINGERPRINT_UPDATE_FAILED';END IF;
 EXECUTE revised;
END $migration$;
