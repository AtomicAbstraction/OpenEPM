-- Project the two durable ordered parent sequences into universal tasks.
-- Each child calculation remains an independent receipted Job task.  The
-- parent reports ordering, interruption and the final child's receipt without
-- pretending that cancellation reverses already-published child units.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=185) THEN
  RAISE EXCEPTION 'MIGRATION_0186_PREDECESSOR_0185_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task ADD CONSTRAINT task_task_id_check CHECK(
 task_id~'^[0-9a-f]{32}$'
 OR(left(task_id,2)IN('a:','c:','e:','f:','g:','i:','l:','p:','q:','r:','s:','w:')
    AND substring(task_id from 3)~'^[0-9a-f]{32}$')
 OR(task_id~'^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    AND length(task_id)<=335)),
 ADD CONSTRAINT task_source_family_check CHECK(source_family IN(
 'Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity',
 'ForecastOccurrence','ImportExecution','PythonScheduleOccurrence',
 'ExportProducer','TransferCleanup','LayoutReplacementBuild','LayoutActivation',
 'ExpressionRuleSequence','FullAggregateSequence'));

CREATE FUNCTION epm.normalized_ordered_sequence_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
 WHEN 'accepted' THEN 'Accepted'
 WHEN 'running' THEN 'Running'
 WHEN 'published' THEN 'Succeeded'
 WHEN 'failed' THEN 'Failed'
 WHEN 'cancel_requested' THEN 'InterruptRequested'
 WHEN 'cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.project_ordered_sequence_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE family text;DECLARE task_prefix text;DECLARE public_function text;
DECLARE projected_task_id text;DECLARE committed_revision bigint;
BEGIN
 IF TG_TABLE_NAME='expression_rule_sequence' THEN
  family:='ExpressionRuleSequence';task_prefix:='q:';
  public_function:='rules.expression.sequence.run';
 ELSIF TG_TABLE_NAME='full_aggregate_sequence' THEN
  family:='FullAggregateSequence';task_prefix:='g:';
  public_function:='consolidation.full.sequence.run';
 ELSE RAISE EXCEPTION 'UNKNOWN_ORDERED_SEQUENCE_TASK_SOURCE';END IF;
 projected_task_id:=task_prefix||NEW.sequence_id;
 normalized:=epm.normalized_ordered_sequence_task_status(NEW.status);
 IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_ORDERED_SEQUENCE_TASK_STATUS';END IF;
 IF NEW.status='published' THEN
  IF jsonb_array_length(NEW.job_ids)=0 THEN
   RAISE EXCEPTION 'ORDERED_SEQUENCE_TASK_RECEIPT_INVALID';
  END IF;
  SELECT receipt_revision INTO committed_revision FROM epm.job
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND job_id=NEW.job_ids->>(jsonb_array_length(NEW.job_ids)-1);
  IF committed_revision IS NULL OR committed_revision<=0 THEN
   RAISE EXCEPTION 'ORDERED_SEQUENCE_TASK_RECEIPT_INVALID';
  END IF;
 END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
  AND NEW.current_step=OLD.current_step
  AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'BusinessExecution',family,NEW.sequence_id,NEW.issuer,NEW.subject_id,
   public_function,'long',normalized,NEW.status,
   NEW.status IN('accepted','running'),false,NEW.created_at,NEW.updated_at);
  ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('accepted','running'),updated_at=NEW.updated_at
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family=family AND source_id=NEW.sequence_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.current_step,committed_revision,NEW.error_code,
  transaction_timestamp());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_ordered_sequence_task_status(text),
 epm.project_ordered_sequence_task() FROM PUBLIC;

DO $migration$ BEGIN
 IF EXISTS(
  SELECT 1 FROM(
   SELECT workspace_id,application_id,status,job_ids
   FROM epm.expression_rule_sequence UNION ALL
   SELECT workspace_id,application_id,status,job_ids
   FROM epm.full_aggregate_sequence)x
  LEFT JOIN epm.job j ON j.workspace_id=x.workspace_id
   AND j.application_id=x.application_id
   AND jsonb_array_length(x.job_ids)>0
   AND j.job_id=x.job_ids->>(jsonb_array_length(x.job_ids)-1)
  WHERE x.status='published' AND j.receipt_revision IS NULL) THEN
  RAISE EXCEPTION 'ORDERED_SEQUENCE_TASK_BACKFILL_RECEIPT_INVALID';
 END IF;
END $migration$;

WITH combined AS(
 SELECT workspace_id,application_id,sequence_id,issuer,subject_id,status,
  current_step,error_code,created_at,updated_at,'q:' prefix,
  'ExpressionRuleSequence' family,'rules.expression.sequence.run' public_function,
  job_ids FROM epm.expression_rule_sequence
 UNION ALL
 SELECT workspace_id,application_id,sequence_id,issuer,subject_id,status,
  current_step,error_code,created_at,updated_at,'g:',
  'FullAggregateSequence','consolidation.full.sequence.run',job_ids
  FROM epm.full_aggregate_sequence
),numbered AS(
 SELECT x.*,coalesce(c.last_sequence,0)+row_number()OVER(
  PARTITION BY x.workspace_id,x.application_id
  ORDER BY x.created_at,x.prefix,x.sequence_id) task_sequence
 FROM combined x LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
 source_family,source_id,issuer,subject_id,function_name,resource_class,status,
 native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,prefix||sequence_id,task_sequence,
 'BusinessExecution',family,sequence_id,issuer,subject_id,public_function,'long',
 epm.normalized_ordered_sequence_task_status(status),status,
 status IN('accepted','running'),false,created_at,updated_at FROM numbered;

WITH combined AS(
 SELECT workspace_id,application_id,sequence_id,status,current_step,error_code,
  updated_at,'q:' prefix,job_ids FROM epm.expression_rule_sequence
 UNION ALL
 SELECT workspace_id,application_id,sequence_id,status,current_step,error_code,
  updated_at,'g:',job_ids FROM epm.full_aggregate_sequence
)
INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
 status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT x.workspace_id,x.application_id,x.prefix||x.sequence_id,1,
 epm.normalized_ordered_sequence_task_status(x.status),x.status,x.current_step,
 CASE WHEN x.status='published' THEN j.receipt_revision END,x.error_code,x.updated_at
FROM combined x LEFT JOIN epm.job j ON j.workspace_id=x.workspace_id
 AND j.application_id=x.application_id
 AND j.job_id=x.job_ids->>(jsonb_array_length(x.job_ids)-1);

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence)FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_expression_rule_sequence_task_projection
AFTER INSERT OR UPDATE OF status,current_step,error_code
ON epm.expression_rule_sequence FOR EACH ROW
EXECUTE FUNCTION epm.project_ordered_sequence_task();
CREATE TRIGGER aa_full_aggregate_sequence_task_projection
AFTER INSERT OR UPDATE OF status,current_step,error_code
ON epm.full_aggregate_sequence FOR EACH ROW
EXECUTE FUNCTION epm.project_ordered_sequence_task();

-- Existing sequence rows and child Job receipts remain authoritative.  No new
-- relation, view or foreign key is introduced, so the reviewed 0182 reset
-- fingerprint remains exact.
