-- Project durable cube-aggregate technical queries into the universal task log.
-- The native query remains authoritative.  Its task and immutable events are
-- intentionally retained after expired technical results are cleaned up.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=175) THEN
    RAISE EXCEPTION 'MIGRATION_0176_PREDECESSOR_0175_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_workspace_id_application_id_source_id_fkey;
ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2)='c:' AND length(task_id) BETWEEN 3 AND 202)),
  ADD CONSTRAINT task_source_family_check CHECK
    (source_family IN ('Job','CubeAggregate')),
  ADD COLUMN source_job_id text GENERATED ALWAYS AS
    (CASE WHEN source_family='Job' THEN source_id END) STORED,
  ADD CONSTRAINT task_source_job_fkey
    FOREIGN KEY(workspace_id,application_id,source_job_id)
    REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_cube_aggregate_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'accepted' THEN 'Accepted'
  WHEN 'ready' THEN 'Waiting'
  WHEN 'running' THEN 'Running'
  WHEN 'computed' THEN 'Running'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'sealed' THEN 'Succeeded'
  WHEN 'expired' THEN 'Succeeded'
  WHEN 'failed' THEN 'Failed'
END;

CREATE FUNCTION epm.project_cube_aggregate_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text := 'c:'||NEW.query_id;
BEGIN
  normalized := epm.normalized_cube_aggregate_task_status(NEW.status);
  IF normalized IS NULL THEN
    RAISE EXCEPTION 'UNKNOWN_CUBE_AGGREGATE_TASK_STATUS';
  END IF;
  IF TG_OP='UPDATE' AND NEW.status=OLD.status
      AND NEW.claim_generation=OLD.claim_generation THEN
    RETURN NEW;
  END IF;
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
      'TechnicalExecution','CubeAggregate',NEW.query_id,NEW.issuer,NEW.subject_id,
      'facts.cube.aggregate.request','long',normalized,NEW.status,
      NEW.status IN ('accepted','ready','running','computed','cancel_requested'),
      false,NEW.accepted_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN
        ('accepted','ready','running','computed','cancel_requested'),
      updated_at=NEW.updated_at
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND source_family='CubeAggregate' AND source_id=NEW.query_id;
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
REVOKE ALL ON FUNCTION epm.normalized_cube_aggregate_task_status(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_cube_aggregate_task() FROM PUBLIC;

WITH numbered AS (
  SELECT q.*,COALESCE(c.last_sequence,0)+row_number() OVER(
    PARTITION BY q.workspace_id,q.application_id
    ORDER BY q.accepted_at,q.query_id) AS task_sequence
  FROM epm.cube_aggregate_query q
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,'c:'||query_id,task_sequence,
  'TechnicalExecution','CubeAggregate',query_id,issuer,subject_id,
  'facts.cube.aggregate.request','long',
  epm.normalized_cube_aggregate_task_status(status),status,
  status IN ('accepted','ready','running','computed','cancel_requested'),false,
  accepted_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,'c:'||query_id,1,
  epm.normalized_cube_aggregate_task_status(status),status,claim_generation,
  NULL,error_code,updated_at FROM epm.cube_aggregate_query;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id
ON CONFLICT(workspace_id,application_id) DO UPDATE
SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_cube_aggregate_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation ON epm.cube_aggregate_query
FOR EACH ROW EXECUTE FUNCTION epm.project_cube_aggregate_task();

-- The reset inventory already deletes task_event/task/task_cursor before all
-- native work tables.  Only its structural fingerprint changes here.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '29fff18920ae4581e6ae715a5edfb3d95ba776e453a9ea09aee5caaf8407114b';
DECLARE new_fingerprint constant text :=
  '82b7b16966f420a3db8c033f34f02cc9f4334ad6c74b96e0c211a661948bbb6d';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0176_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
