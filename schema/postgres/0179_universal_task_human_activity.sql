-- Project assigned application-task-flow activities into the universal task
-- surface. The task-flow tables remain authoritative.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=178) THEN
    RAISE EXCEPTION 'MIGRATION_0179_PREDECESSOR_0178_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.task DROP CONSTRAINT task_source_family_check;
ALTER TABLE epm.task DROP CONSTRAINT task_task_id_check;
ALTER TABLE epm.task DROP CONSTRAINT task_source_id_check;
ALTER TABLE epm.task
  ADD CONSTRAINT task_task_id_check CHECK
    (task_id ~ '^[0-9a-f]{32}$'
     OR (left(task_id,2) IN ('c:','p:','w:')
         AND substring(task_id from 3) ~ '^[0-9a-f]{32}$')
     OR (task_id ~ '^h:[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
         AND length(task_id)<=335)),
  ADD CONSTRAINT task_source_family_check CHECK
    (source_family IN
      ('Job','CubeAggregate','PythonBuild','PythonWorkflow','HumanActivity')),
  ADD CONSTRAINT task_source_id_check CHECK(length(source_id) BETWEEN 1 AND 400),
  ADD COLUMN human_occurrence_id text,
  ADD COLUMN human_activity_id text,
  ADD CONSTRAINT task_human_source_shape CHECK
    ((source_family='HumanActivity')=
      (human_occurrence_id IS NOT NULL AND human_activity_id IS NOT NULL)),
  ADD CONSTRAINT task_human_activity_fkey FOREIGN KEY
    (workspace_id,application_id,human_occurrence_id,human_activity_id)
    REFERENCES epm.application_task_flow_activity
      (workspace_id,application_id,occurrence_id,activity_id)
    ON DELETE CASCADE;

CREATE FUNCTION epm.normalized_human_activity_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'Blocked' THEN 'Waiting'
  WHEN 'Ready' THEN 'Waiting'
  WHEN 'Completed' THEN 'Succeeded'
  WHEN 'Cancelled' THEN 'Interrupted'
END;

CREATE FUNCTION epm.project_human_activity_tasks() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE activity record;
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
DECLARE projected_task_id text;
DECLARE prior_native text;
BEGIN
  FOR activity IN
    SELECT a.*,o.started_by_issuer,o.started_by_subject_id,o.started_at,
      NEW.committed_revision,NEW.created_at AS event_at
    FROM epm.application_task_flow_activity a
    JOIN epm.application_task_flow_occurrence o
      USING(workspace_id,application_id,occurrence_id)
    WHERE a.workspace_id=NEW.workspace_id
      AND a.application_id=NEW.application_id
      AND a.occurrence_id=NEW.occurrence_id
    ORDER BY a.activity_id
  LOOP
    normalized := epm.normalized_human_activity_task_status(activity.status);
    IF normalized IS NULL THEN
      RAISE EXCEPTION 'UNKNOWN_HUMAN_ACTIVITY_TASK_STATUS';
    END IF;
    projected_task_id := 'h:'||activity.occurrence_id||'/'||activity.activity_id;
    SELECT native_status INTO prior_native FROM epm.task
      WHERE workspace_id=activity.workspace_id
        AND application_id=activity.application_id
        AND task_id=projected_task_id;
    IF NOT FOUND THEN
      INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
        VALUES(activity.workspace_id,activity.application_id,1)
        ON CONFLICT(workspace_id,application_id) DO UPDATE
          SET last_sequence=epm.task_cursor.last_sequence+1
        RETURNING last_sequence INTO task_sequence;
      INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,
        task_class,source_family,source_id,issuer,subject_id,function_name,
        resource_class,status,native_status,interruptible,rerun_supported,
        human_occurrence_id,human_activity_id,created_at,updated_at)
      VALUES(activity.workspace_id,activity.application_id,projected_task_id,
        task_sequence,'HumanActivity','HumanActivity',
        activity.occurrence_id||'/'||activity.activity_id,
        activity.started_by_issuer,activity.started_by_subject_id,
        'application.taskflow.activity.complete','short',normalized,
        activity.status,false,false,activity.occurrence_id,activity.activity_id,
        activity.started_at,activity.event_at);
      ordinal := 1;
    ELSIF prior_native IS DISTINCT FROM activity.status THEN
      UPDATE epm.task SET status=normalized,native_status=activity.status,
        updated_at=activity.event_at
        WHERE workspace_id=activity.workspace_id
          AND application_id=activity.application_id
          AND task_id=projected_task_id;
      SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal
        FROM epm.task_event WHERE workspace_id=activity.workspace_id
          AND application_id=activity.application_id
          AND task_id=projected_task_id;
    ELSE
      CONTINUE;
    END IF;
    INSERT INTO epm.task_event(workspace_id,application_id,task_id,
      event_ordinal,status,native_status,claim_generation,receipt_revision,
      error_code,occurred_at)
    VALUES(activity.workspace_id,activity.application_id,projected_task_id,
      ordinal,normalized,activity.status,0,activity.committed_revision,NULL,
      activity.event_at);
  END LOOP;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_human_activity_task_status(text)
  FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_human_activity_tasks() FROM PUBLIC;

-- Retain pre-0179 source audit in application_task_flow_event and backfill one
-- truthful current-state event per activity. Future changes append transitions.
WITH numbered AS (
  SELECT a.*,o.started_by_issuer,o.started_by_subject_id,o.started_at,
    e.created_at AS updated_at,
    COALESCE(c.last_sequence,0)+row_number() OVER(
      PARTITION BY a.workspace_id,a.application_id
      ORDER BY o.started_at,a.occurrence_id,a.activity_id) AS task_sequence
  FROM epm.application_task_flow_activity a
  JOIN epm.application_task_flow_occurrence o
    USING(workspace_id,application_id,occurrence_id)
  JOIN LATERAL (
    SELECT created_at FROM epm.application_task_flow_event e
    WHERE e.workspace_id=a.workspace_id AND e.application_id=a.application_id
      AND e.occurrence_id=a.occurrence_id
    ORDER BY event_ordinal DESC LIMIT 1
  ) e ON true
  LEFT JOIN epm.task_cursor c USING(workspace_id,application_id)
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,human_occurrence_id,
  human_activity_id,created_at,updated_at)
SELECT workspace_id,application_id,'h:'||occurrence_id||'/'||activity_id,
  task_sequence,'HumanActivity','HumanActivity',occurrence_id||'/'||activity_id,
  started_by_issuer,started_by_subject_id,
  'application.taskflow.activity.complete','short',
  epm.normalized_human_activity_task_status(status),status,false,false,
  occurrence_id,activity_id,started_at,updated_at FROM numbered;

INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT a.workspace_id,a.application_id,
  'h:'||a.occurrence_id||'/'||a.activity_id,1,
  epm.normalized_human_activity_task_status(a.status),a.status,0,
  e.committed_revision,NULL,e.created_at
FROM epm.application_task_flow_activity a
JOIN LATERAL (
  SELECT committed_revision,created_at
  FROM epm.application_task_flow_event e
  WHERE e.workspace_id=a.workspace_id AND e.application_id=a.application_id
    AND e.occurrence_id=a.occurrence_id
  ORDER BY event_ordinal DESC LIMIT 1
) e ON true;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id ON CONFLICT(workspace_id,application_id)
DO UPDATE SET last_sequence=EXCLUDED.last_sequence;

CREATE TRIGGER aa_application_task_flow_task_projection
AFTER INSERT ON epm.application_task_flow_event
FOR EACH ROW EXECUTE FUNCTION epm.project_human_activity_tasks();

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'c60d12f083dc86e7bce3f0e8d894289ee20694f33a9fbcdd19ae08409b151ca4';
DECLARE new_fingerprint constant text :=
  '154e572598c6bdc8db98c6a37896713e5ad37826c4f0d0d01af083129052b1f0';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0179_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  EXECUTE revised;
END $migration$;
