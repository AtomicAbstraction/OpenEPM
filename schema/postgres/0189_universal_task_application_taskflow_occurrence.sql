-- Project durable application task-flow occurrences into the universal task
-- surface.  The task-flow occurrence and its event stream remain authoritative;
-- this retained projection neither executes activities nor creates a new queue.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=188) THEN
  RAISE EXCEPTION 'MIGRATION_0189_PREDECESSOR_0188_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task ADD CONSTRAINT task_task_id_check CHECK(
 task_id~'^[0-9a-f]{32}$'
 OR(left(task_id,2)IN('a:','b:','c:','e:','f:','g:','i:','l:','p:','q:','r:','s:','t:','w:')
   AND substring(task_id from 3)~'^[0-9a-f]{32}$')
 OR(task_id~'^d:[0-9a-f]{64}$')
 OR(task_id~'^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
   AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
 'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
 'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
 'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
 'ExpressionRuleSequence','FullAggregateSequence','SourceBatch',
 'AssignmentEscalation','ApplicationTaskFlowOccurrence'));

CREATE FUNCTION epm.normalized_application_taskflow_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
 WHEN 'Active' THEN 'Running'
 WHEN 'Completed' THEN 'Succeeded'
 WHEN 'Cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.project_application_taskflow_occurrence_task()
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
   'long',normalized,occurrence.status,occurrence.status='Active',false,
   occurrence.started_at,NEW.created_at);
 ELSE
  UPDATE epm.task SET status=normalized,native_status=occurrence.status,
   interruptible=occurrence.status='Active',updated_at=NEW.created_at
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
REVOKE ALL ON FUNCTION
 epm.normalized_application_taskflow_task_status(text),
 epm.project_application_taskflow_occurrence_task() FROM PUBLIC;

WITH numbered AS(
 SELECT o.*,coalesce(c.last_sequence,0)+row_number()OVER(
  PARTITION BY o.workspace_id,o.application_id
  ORDER BY o.started_at,o.occurrence_id)task_sequence
 FROM epm.application_task_flow_occurrence o
 LEFT JOIN epm.task_cursor c USING(workspace_id,application_id))
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'t:'||occurrence_id,task_sequence,
 'BusinessExecution','ApplicationTaskFlowOccurrence',occurrence_id,
 started_by_issuer,started_by_subject_id,'application.taskflow.occurrence.start',
 'long',epm.normalized_application_taskflow_task_status(status),status,
 status='Active',false,started_at,coalesce(completed_at,cancelled_at,started_at)
FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT e.workspace_id,e.application_id,'t:'||e.occurrence_id,e.event_ordinal,
 CASE WHEN e.event_ordinal=o.occurrence_version
   THEN epm.normalized_application_taskflow_task_status(o.status)
   ELSE 'Running' END,
 e.event_type,o.occurrence_version,e.committed_revision,NULL,e.created_at
FROM epm.application_task_flow_event e
JOIN epm.application_task_flow_occurrence o
 USING(workspace_id,application_id,occurrence_id);

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence)FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_application_taskflow_occurrence_task_projection
AFTER INSERT ON epm.application_task_flow_event FOR EACH ROW
EXECUTE FUNCTION epm.project_application_taskflow_occurrence_task();

-- The retained projection introduces no new relation or foreign key, so the
-- reviewed reset fingerprint remains unchanged.
