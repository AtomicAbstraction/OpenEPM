-- Project domain-neutral application workflow occurrences and assigned
-- activities into the universal task surface.  The workflow occurrence,
-- activity and immutable event stores remain authoritative; this projection
-- neither executes destinations nor creates a second workflow engine.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=230) THEN
  RAISE EXCEPTION 'MIGRATION_0231_PREDECESSOR_0230_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
 ADD CONSTRAINT task_task_id_check CHECK(
  task_id~'^[0-9a-f]{32}$'
  OR(left(task_id,2)IN('a:','b:','c:','e:','f:','g:','i:','l:','p:','q:',
      'r:','s:','t:','u:','v:','w:','x:')
    AND substring(task_id from 3)~'^[0-9a-f]{32}$')
  OR task_id~'^d:[0-9a-f]{64}$'
  OR(task_id~'^[hy]:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
  'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
  'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
  'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
  'ExpressionRuleSequence','FullAggregateSequence','SourceBatch',
  'AssignmentEscalation','ApplicationTaskFlowOccurrence',
  'ApplicationRuleWorkflow','ApplicationScheduleOccurrence',
  'ApplicationWorkflowOccurrence','ApplicationWorkflowActivity')),
 ADD COLUMN workflow_occurrence_id text,
 ADD COLUMN workflow_activity_id text,
 ADD CONSTRAINT task_application_workflow_source_shape CHECK(
  (source_family='ApplicationWorkflowOccurrence')=
    (workflow_occurrence_id IS NOT NULL AND workflow_activity_id IS NULL)
  OR (source_family='ApplicationWorkflowActivity')=
    (workflow_occurrence_id IS NOT NULL AND workflow_activity_id IS NOT NULL)
  OR (source_family NOT IN(
      'ApplicationWorkflowOccurrence','ApplicationWorkflowActivity')
    AND workflow_occurrence_id IS NULL AND workflow_activity_id IS NULL));

CREATE FUNCTION epm.normalized_application_workflow_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
 WHEN 'Active' THEN 'Running' WHEN 'Completed' THEN 'Succeeded'
 WHEN 'Cancelled' THEN 'Interrupted'
 WHEN 'Blocked' THEN 'Waiting' WHEN 'Ready' THEN 'Waiting'
 WHEN 'Returned' THEN 'Waiting'
END;

CREATE FUNCTION epm.project_application_workflow_tasks()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE occurrence epm.application_workflow_occurrence%ROWTYPE;
DECLARE activity record;DECLARE task_sequence bigint;DECLARE ordinal bigint;
DECLARE normalized text;DECLARE projected text;DECLARE prior_native text;
BEGIN
 SELECT * INTO occurrence FROM epm.application_workflow_occurrence
 WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
  AND occurrence_id=NEW.occurrence_id;
 IF occurrence.occurrence_id IS NULL THEN
  RAISE EXCEPTION 'APPLICATION_WORKFLOW_TASK_OCCURRENCE_UNAVAILABLE';END IF;

 normalized:=epm.normalized_application_workflow_task_status(occurrence.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_APPLICATION_WORKFLOW_TASK_STATUS';END IF;
 projected:='x:'||NEW.occurrence_id;
 IF NEW.event_ordinal=1 THEN
  IF NEW.event_type<>'OccurrenceStarted' THEN
   RAISE EXCEPTION 'APPLICATION_WORKFLOW_TASK_START_EVENT_INVALID';END IF;
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,workflow_occurrence_id,
   created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected,task_sequence,
   'BusinessExecution','ApplicationWorkflowOccurrence',NEW.occurrence_id,
   occurrence.started_by_issuer,occurrence.started_by_subject_id,
   'application.workflow.occurrence.start','long',normalized,occurrence.status,
   occurrence.status='Active',false,NEW.occurrence_id,occurrence.started_at,
   NEW.created_at);
 ELSE
  UPDATE epm.task SET status=normalized,native_status=occurrence.status,
   interruptible=occurrence.status='Active',updated_at=NEW.created_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='ApplicationWorkflowOccurrence'
   AND source_id=NEW.occurrence_id;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'APPLICATION_WORKFLOW_TASK_PROJECTION_UNAVAILABLE';END IF;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected,NEW.event_ordinal,
  normalized,NEW.event_type,occurrence.occurrence_version,
  NEW.committed_revision,NULL,NEW.created_at);

 FOR activity IN SELECT a.* FROM epm.application_workflow_activity a
  WHERE a.workspace_id=NEW.workspace_id AND a.application_id=NEW.application_id
   AND a.occurrence_id=NEW.occurrence_id ORDER BY a.activity_id
 LOOP
  normalized:=epm.normalized_application_workflow_task_status(activity.status);
  IF normalized IS NULL THEN
   RAISE EXCEPTION 'UNKNOWN_APPLICATION_WORKFLOW_ACTIVITY_TASK_STATUS';END IF;
  projected:='y:'||activity.occurrence_id||'/'||activity.activity_id;
  SELECT native_status INTO prior_native FROM epm.task
   WHERE workspace_id=activity.workspace_id
    AND application_id=activity.application_id AND task_id=projected;
  IF NOT FOUND THEN
   INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
    VALUES(activity.workspace_id,activity.application_id,1)
    ON CONFLICT(workspace_id,application_id)DO UPDATE
     SET last_sequence=epm.task_cursor.last_sequence+1
    RETURNING last_sequence INTO task_sequence;
   INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
    source_family,source_id,issuer,subject_id,function_name,resource_class,status,
    native_status,interruptible,rerun_supported,workflow_occurrence_id,
    workflow_activity_id,created_at,updated_at)
   VALUES(activity.workspace_id,activity.application_id,projected,task_sequence,
    'HumanActivity','ApplicationWorkflowActivity',
    activity.occurrence_id||'/'||activity.activity_id,
    occurrence.started_by_issuer,occurrence.started_by_subject_id,
    'application.workflow.activity.complete','short',normalized,activity.status,
    false,false,activity.occurrence_id,activity.activity_id,
    occurrence.started_at,NEW.created_at);
   ordinal:=1;
  ELSIF prior_native IS DISTINCT FROM activity.status THEN
   UPDATE epm.task SET status=normalized,native_status=activity.status,
    updated_at=NEW.created_at WHERE workspace_id=activity.workspace_id
     AND application_id=activity.application_id AND task_id=projected;
   SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
    WHERE workspace_id=activity.workspace_id
     AND application_id=activity.application_id AND task_id=projected;
  ELSE CONTINUE;END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
   status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(activity.workspace_id,activity.application_id,projected,ordinal,
   normalized,activity.status,activity.activity_version,
   NEW.committed_revision,NULL,NEW.created_at);
 END LOOP;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_application_workflow_task_status(text),
 epm.project_application_workflow_tasks() FROM PUBLIC;

-- Backfill one truthful current-state projection.  The immutable authoritative
-- workflow event stream retains the complete history before this migration.
WITH numbered AS(
 SELECT o.*,e.created_at updated_at,e.committed_revision,
  coalesce(c.last_sequence,0)+row_number()OVER(PARTITION BY o.workspace_id,
   o.application_id ORDER BY o.started_at,o.occurrence_id) task_sequence
 FROM epm.application_workflow_occurrence o
 JOIN LATERAL(SELECT created_at,committed_revision
  FROM epm.application_workflow_event e WHERE e.workspace_id=o.workspace_id
   AND e.application_id=o.application_id AND e.occurrence_id=o.occurrence_id
  ORDER BY event_ordinal DESC LIMIT 1)e ON true
 LEFT JOIN epm.task_cursor c USING(workspace_id,application_id))
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,workflow_occurrence_id,
 created_at,updated_at)
SELECT workspace_id,application_id,'x:'||occurrence_id,task_sequence,
 'BusinessExecution','ApplicationWorkflowOccurrence',occurrence_id,
 started_by_issuer,started_by_subject_id,'application.workflow.occurrence.start',
 'long',epm.normalized_application_workflow_task_status(status),status,
 status='Active',false,occurrence_id,started_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT o.workspace_id,o.application_id,'x:'||o.occurrence_id,1,
 epm.normalized_application_workflow_task_status(o.status),'Backfilled',
 o.occurrence_version,e.committed_revision,NULL,e.created_at
FROM epm.application_workflow_occurrence o
JOIN LATERAL(SELECT committed_revision,created_at
 FROM epm.application_workflow_event e WHERE e.workspace_id=o.workspace_id
  AND e.application_id=o.application_id AND e.occurrence_id=o.occurrence_id
 ORDER BY event_ordinal DESC LIMIT 1)e ON true;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

WITH numbered AS(
 SELECT a.*,o.started_by_issuer,o.started_by_subject_id,o.started_at,
  e.created_at updated_at,e.committed_revision,
  coalesce(c.last_sequence,0)+row_number()OVER(PARTITION BY a.workspace_id,
   a.application_id ORDER BY o.started_at,a.occurrence_id,a.activity_id)
   task_sequence
 FROM epm.application_workflow_activity a
 JOIN epm.application_workflow_occurrence o USING(
  workspace_id,application_id,occurrence_id,flow_id,flow_version)
 JOIN LATERAL(SELECT created_at,committed_revision
  FROM epm.application_workflow_event e WHERE e.workspace_id=a.workspace_id
   AND e.application_id=a.application_id AND e.occurrence_id=a.occurrence_id
  ORDER BY event_ordinal DESC LIMIT 1)e ON true
 LEFT JOIN epm.task_cursor c ON c.workspace_id=a.workspace_id
  AND c.application_id=a.application_id)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,workflow_occurrence_id,
 workflow_activity_id,created_at,updated_at)
SELECT workspace_id,application_id,'y:'||occurrence_id||'/'||activity_id,
 task_sequence,'HumanActivity','ApplicationWorkflowActivity',
 occurrence_id||'/'||activity_id,started_by_issuer,started_by_subject_id,
 'application.workflow.activity.complete','short',
 epm.normalized_application_workflow_task_status(status),status,false,false,
 occurrence_id,activity_id,started_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT a.workspace_id,a.application_id,
 'y:'||a.occurrence_id||'/'||a.activity_id,1,
 epm.normalized_application_workflow_task_status(a.status),a.status,
 a.activity_version,e.committed_revision,NULL,e.created_at
FROM epm.application_workflow_activity a
JOIN LATERAL(SELECT committed_revision,created_at
 FROM epm.application_workflow_event e WHERE e.workspace_id=a.workspace_id
  AND e.application_id=a.application_id AND e.occurrence_id=a.occurrence_id
 ORDER BY event_ordinal DESC LIMIT 1)e ON true;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_application_workflow_task_projection
AFTER INSERT ON epm.application_workflow_event FOR EACH ROW
EXECUTE FUNCTION epm.project_application_workflow_tasks();

-- No relation or foreign key is introduced.  Universal tasks are already
-- deleted before native workflow records by the reviewed reset inventory, so
-- the schema-0230 reset fingerprint remains exact.
