-- Admit explicit manual rerun only where a native family can create distinct
-- new work safely.  A rerun never mutates, resumes or undoes the source task.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=189) THEN
  RAISE EXCEPTION 'MIGRATION_0190_PREDECESSOR_0189_REQUIRED';
 END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.project_application_taskflow_occurrence_task()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE occurrence epm.application_task_flow_occurrence%ROWTYPE;
DECLARE task_sequence bigint;DECLARE normalized text;DECLARE event_status text;
BEGIN
 SELECT * INTO occurrence FROM epm.application_task_flow_occurrence
 WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
  AND occurrence_id=NEW.occurrence_id;
 IF occurrence.occurrence_id IS NULL THEN
  RAISE EXCEPTION 'APPLICATION_TASKFLOW_TASK_OCCURRENCE_UNAVAILABLE';END IF;
 normalized:=epm.normalized_application_taskflow_task_status(occurrence.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_APPLICATION_TASKFLOW_TASK_STATUS';END IF;
 event_status:=CASE
  WHEN NEW.event_ordinal=occurrence.occurrence_version THEN normalized
  ELSE 'Running' END;
 IF NEW.event_ordinal=1 THEN
  IF NEW.event_type<>'OccurrenceStarted' THEN
   RAISE EXCEPTION 'APPLICATION_TASKFLOW_TASK_START_EVENT_INVALID';END IF;
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,'t:'||NEW.occurrence_id,
   task_sequence,'BusinessExecution','ApplicationTaskFlowOccurrence',
   NEW.occurrence_id,occurrence.started_by_issuer,
   occurrence.started_by_subject_id,'application.taskflow.occurrence.start',
   'long',normalized,occurrence.status,occurrence.status='Active',
   occurrence.status IN('Completed','Cancelled'),
   occurrence.started_at,NEW.created_at);
 ELSE
  UPDATE epm.task SET status=normalized,native_status=occurrence.status,
   interruptible=occurrence.status='Active',
   rerun_supported=occurrence.status IN('Completed','Cancelled'),
   updated_at=NEW.created_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='ApplicationTaskFlowOccurrence'
   AND source_id=NEW.occurrence_id;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'APPLICATION_TASKFLOW_TASK_PROJECTION_UNAVAILABLE';END IF;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,'t:'||NEW.occurrence_id,
  NEW.event_ordinal,event_status,NEW.event_type,occurrence.occurrence_version,
  NEW.committed_revision,NULL,NEW.created_at);
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.project_application_taskflow_occurrence_task()
 FROM PUBLIC;

UPDATE epm.task t SET
 rerun_supported=o.status IN('Completed','Cancelled')
FROM epm.application_task_flow_occurrence o
WHERE t.workspace_id=o.workspace_id AND t.application_id=o.application_id
 AND t.source_family='ApplicationTaskFlowOccurrence'
 AND t.source_id=o.occurrence_id
 AND t.rerun_supported IS DISTINCT FROM
     (o.status IN('Completed','Cancelled'));

-- No relation, key or reset inventory changes are introduced.
