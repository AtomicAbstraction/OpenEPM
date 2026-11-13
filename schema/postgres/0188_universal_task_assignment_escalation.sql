-- Project server-owned assignment escalations into universal business tasks.
-- The due-occurrence store and its lease-fenced worker remain authoritative.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=187) THEN
  RAISE EXCEPTION 'MIGRATION_0188_PREDECESSOR_0187_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task ADD CONSTRAINT task_task_id_check CHECK(
 task_id~'^[0-9a-f]{32}$'
 OR(left(task_id,2)IN('a:','b:','c:','e:','f:','g:','i:','l:','p:','q:','r:','s:','w:')
   AND substring(task_id from 3)~'^[0-9a-f]{32}$')
 OR(task_id~'^d:[0-9a-f]{64}$')
 OR(task_id~'^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
   AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
 'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
 'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
 'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
 'ExpressionRuleSequence','FullAggregateSequence','SourceBatch',
 'AssignmentEscalation'));

CREATE FUNCTION epm.assignment_escalation_task_source_id(
 p_set text,p_version bigint,p_assignment text,p_due timestamptz)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN encode(sha256(convert_to(jsonb_build_array(
 p_set,p_version,p_assignment,p_due)::text,'UTF8')),'hex');

CREATE FUNCTION epm.normalized_assignment_escalation_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
 WHEN 'Pending' THEN 'Waiting'
 WHEN 'Running' THEN 'Running'
 WHEN 'Completed' THEN 'Succeeded'
 WHEN 'Cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.project_assignment_escalation_task()RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE source_digest text;DECLARE owner_issuer text;DECLARE owner_subject text;
DECLARE receipt bigint;DECLARE operation text;DECLARE event_at timestamptz;
BEGIN
 source_digest:=epm.assignment_escalation_task_source_id(
  NEW.assignment_set_id,NEW.assignment_version,NEW.assignment_id,NEW.due_at);
 normalized:=epm.normalized_assignment_escalation_task_status(NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_ASSIGNMENT_ESCALATION_TASK_STATUS';END IF;
 SELECT v.creator_issuer,v.creator_subject_id INTO owner_issuer,owner_subject
 FROM epm.planning_assignment_version v WHERE v.workspace_id=NEW.workspace_id
  AND v.application_id=NEW.application_id
  AND v.assignment_set_id=NEW.assignment_set_id
  AND v.version=NEW.assignment_version;
 IF owner_subject IS NULL THEN
  RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_TASK_OWNER_INVALID';END IF;
 IF NEW.status='Completed' THEN
  operation:='assignment-escalation:'||NEW.assignment_set_id||':'||
   NEW.assignment_version||':'||NEW.assignment_id||':'||
   extract(epoch from NEW.due_at)::bigint;
  SELECT committed_revision INTO receipt FROM epm.operation_receipt
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND operation_id=operation;
  IF receipt IS NULL OR receipt<=0 THEN
   RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_TASK_RECEIPT_INVALID';END IF;
 END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
  AND NEW.claim_generation=OLD.claim_generation
  AND NEW.result_event_ordinal IS NOT DISTINCT FROM OLD.result_event_ordinal
  THEN RETURN NEW;END IF;
 event_at:=coalesce(NEW.completed_at,transaction_timestamp());
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,'d:'||source_digest,task_sequence,
   'BusinessExecution','AssignmentEscalation',source_digest,owner_issuer,
   owner_subject,'planning.assignment.escalation.process','short',normalized,
   NEW.status,false,false,NEW.created_at,event_at);
  ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=false,updated_at=event_at
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='AssignmentEscalation' AND source_id=source_digest;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id='d:'||source_digest;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,'d:'||source_digest,ordinal,
  normalized,NEW.status,NEW.claim_generation,receipt,NULL,event_at);
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION
 epm.assignment_escalation_task_source_id(text,bigint,text,timestamptz),
 epm.normalized_assignment_escalation_task_status(text),
 epm.project_assignment_escalation_task()FROM PUBLIC;

DO $migration$ BEGIN
 IF EXISTS(SELECT 1 FROM epm.planning_assignment_due_occurrence o
  WHERE o.status='Completed' AND NOT EXISTS(
   SELECT 1 FROM epm.operation_receipt r WHERE r.workspace_id=o.workspace_id
    AND r.application_id=o.application_id AND r.sealed
    AND r.operation_id='assignment-escalation:'||o.assignment_set_id||':'||
     o.assignment_version||':'||o.assignment_id||':'||
     extract(epoch from o.due_at)::bigint))THEN
  RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_TASK_BACKFILL_RECEIPT_INVALID';
 END IF;
END $migration$;

WITH numbered AS(
 SELECT o.*,v.creator_issuer,v.creator_subject_id,
  epm.assignment_escalation_task_source_id(o.assignment_set_id,
   o.assignment_version,o.assignment_id,o.due_at)source_digest,
  coalesce(c.last_sequence,0)+row_number()OVER(
   PARTITION BY o.workspace_id,o.application_id
   ORDER BY o.created_at,o.assignment_set_id,o.assignment_version,
    o.assignment_id,o.due_at)task_sequence
 FROM epm.planning_assignment_due_occurrence o
 JOIN epm.planning_assignment_version v USING(
  workspace_id,application_id,assignment_set_id)
 LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
 WHERE v.version=o.assignment_version)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'d:'||source_digest,task_sequence,
 'BusinessExecution','AssignmentEscalation',source_digest,creator_issuer,
 creator_subject_id,'planning.assignment.escalation.process','short',
 epm.normalized_assignment_escalation_task_status(status),status,false,false,
 created_at,coalesce(completed_at,created_at)FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT o.workspace_id,o.application_id,'d:'||
 epm.assignment_escalation_task_source_id(o.assignment_set_id,
  o.assignment_version,o.assignment_id,o.due_at),1,
 epm.normalized_assignment_escalation_task_status(o.status),o.status,
 o.claim_generation,r.committed_revision,NULL,coalesce(o.completed_at,o.created_at)
FROM epm.planning_assignment_due_occurrence o LEFT JOIN epm.operation_receipt r
 ON r.workspace_id=o.workspace_id AND r.application_id=o.application_id
 AND r.operation_id='assignment-escalation:'||o.assignment_set_id||':'||
  o.assignment_version||':'||o.assignment_id||':'||
  extract(epoch from o.due_at)::bigint AND r.sealed;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence)FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_assignment_escalation_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation,result_event_ordinal
ON epm.planning_assignment_due_occurrence FOR EACH ROW
EXECUTE FUNCTION epm.project_assignment_escalation_task();

-- No new relation or foreign key is added, so the reviewed reset fingerprint
-- remains unchanged.  The task is a retained projection, not a second queue.
