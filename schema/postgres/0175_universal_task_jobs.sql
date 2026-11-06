-- Universal task projection, first complete family: ordinary durable jobs.
-- Native job rows remain authoritative.  The projection is maintained only by
-- a security-definer trigger and never resumes, reruns or undoes business work.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=174) THEN
    RAISE EXCEPTION 'MIGRATION_0175_PREDECESSOR_0174_REQUIRED';
  END IF;
END $migration$;

-- Pin the reset graph observed after the clean schema-163 baseline upgrade
-- through this migration.  Fixed reset code carries the same reviewed pin.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '9997f508a4670a8879d7745d0ac8076bc4fe578aa94f58ef3f3f4526f1bbd946';
DECLARE new_fingerprint constant text :=
  '29fff18920ae4581e6ae715a5edfb3d95ba776e453a9ea09aee5caaf8407114b';
BEGIN
  definition := pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0175_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0175_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

CREATE TABLE epm.task_cursor (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    last_sequence bigint NOT NULL CHECK (last_sequence > 0),
    PRIMARY KEY (workspace_id,application_id),
    FOREIGN KEY (workspace_id,application_id)
      REFERENCES epm.application_state(workspace_id,application_id)
      ON DELETE CASCADE
);

CREATE TABLE epm.task (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    task_id text NOT NULL CHECK (task_id ~ '^[0-9a-f]{32}$'),
    sequence bigint NOT NULL CHECK (sequence > 0),
    task_class text NOT NULL CHECK (task_class IN
      ('BusinessExecution','TechnicalExecution','HumanActivity')),
    source_family text NOT NULL CHECK (source_family IN ('Job')),
    source_id text NOT NULL CHECK (length(source_id) BETWEEN 1 AND 200),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    function_name text NOT NULL CHECK (length(function_name) BETWEEN 1 AND 200),
    resource_class text NOT NULL CHECK (resource_class IN ('short','medium','long')),
    status text NOT NULL CHECK (status IN
      ('Accepted','Waiting','Running','InterruptRequested','Interrupted',
       'Succeeded','Failed','NeedsInspection')),
    native_status text NOT NULL CHECK (length(native_status) BETWEEN 1 AND 80),
    interruptible boolean NOT NULL,
    rerun_supported boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id,application_id,task_id),
    UNIQUE (workspace_id,application_id,sequence),
    UNIQUE (workspace_id,application_id,source_family,source_id),
    FOREIGN KEY (workspace_id,application_id,source_id)
      REFERENCES epm.job(workspace_id,application_id,job_id)
      ON DELETE CASCADE
);

CREATE TABLE epm.task_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    task_id text NOT NULL,
    event_ordinal bigint NOT NULL CHECK (event_ordinal > 0),
    status text NOT NULL CHECK (status IN
      ('Accepted','Waiting','Running','InterruptRequested','Interrupted',
       'Succeeded','Failed','NeedsInspection')),
    native_status text NOT NULL CHECK (length(native_status) BETWEEN 1 AND 80),
    claim_generation bigint NOT NULL CHECK (claim_generation >= 0),
    receipt_revision bigint CHECK (receipt_revision IS NULL OR receipt_revision > 0),
    error_code text CHECK (error_code IS NULL OR length(error_code) <= 200),
    occurred_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id,application_id,task_id,event_ordinal),
    FOREIGN KEY (workspace_id,application_id,task_id)
      REFERENCES epm.task(workspace_id,application_id,task_id)
      ON DELETE CASCADE
);

CREATE INDEX task_owner_page ON epm.task
  (workspace_id,application_id,issuer,subject_id,sequence);
CREATE INDEX task_application_page ON epm.task
  (workspace_id,application_id,sequence);

CREATE FUNCTION epm.task_event_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' AND
     current_setting('epm.projection_cleanup_reset_context',true)=
       jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                         pg_backend_pid())::text THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'TASK_EVENT_IMMUTABLE' USING ERRCODE='23514';
END $$;
CREATE TRIGGER task_event_immutable
  BEFORE UPDATE OR DELETE ON epm.task_event
  FOR EACH ROW EXECUTE FUNCTION epm.task_event_immutable();
REVOKE ALL ON FUNCTION epm.task_event_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

CREATE FUNCTION epm.normalized_job_task_status(native text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'accepted' THEN 'Accepted'
  WHEN 'ready' THEN 'Waiting'
  WHEN 'running' THEN 'Running'
  WHEN 'staged' THEN 'Running'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'published' THEN 'Succeeded'
  WHEN 'failed' THEN 'Failed'
  WHEN 'needs_inspection' THEN 'NeedsInspection'
END;

CREATE FUNCTION epm.project_job_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;
DECLARE ordinal bigint;
DECLARE normalized text;
BEGIN
  normalized := epm.normalized_job_task_status(NEW.status);
  IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_JOB_TASK_STATUS'; END IF;
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
    VALUES(NEW.workspace_id,NEW.application_id,NEW.job_id,task_sequence,
      'BusinessExecution','Job',NEW.job_id,NEW.issuer,NEW.subject_id,
      NEW.function_name,NEW.resource_class,normalized,NEW.status,
      NEW.status IN ('accepted','ready','running','staged','cancel_requested'),
      false,NEW.created_at,NEW.updated_at);
    ordinal := 1;
  ELSE
    UPDATE epm.task SET status=normalized,native_status=NEW.status,
      interruptible=NEW.status IN
        ('accepted','ready','running','staged','cancel_requested'),
      updated_at=NEW.updated_at
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND source_family='Job' AND source_id=NEW.job_id;
    SELECT COALESCE(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND task_id=NEW.job_id;
  END IF;
  INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
    status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
  VALUES(NEW.workspace_id,NEW.application_id,NEW.job_id,ordinal,normalized,
    NEW.status,NEW.claim_generation,NEW.receipt_revision,NEW.error_code,
    transaction_timestamp());
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.normalized_job_task_status(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.project_job_task() FROM PUBLIC;

-- Backfill existing jobs and their retained event history before enabling the
-- trigger.  Stable per-application ordering uses creation time and job ID.
WITH numbered AS (
  SELECT j.*,row_number() OVER(PARTITION BY workspace_id,application_id
    ORDER BY created_at,job_id) AS task_sequence
  FROM epm.job j
)
INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
  source_family,source_id,issuer,subject_id,function_name,resource_class,status,
  native_status,interruptible,rerun_supported,created_at,updated_at)
SELECT workspace_id,application_id,job_id,task_sequence,'BusinessExecution',
  'Job',job_id,issuer,subject_id,function_name,resource_class,
  epm.normalized_job_task_status(status),status,
  status IN ('accepted','ready','running','staged','cancel_requested'),false,
  created_at,updated_at FROM numbered;

INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
SELECT workspace_id,application_id,max(sequence) FROM epm.task
GROUP BY workspace_id,application_id;

WITH numbered AS (
  SELECT e.*,row_number() OVER(PARTITION BY e.workspace_id,e.application_id,e.job_id
    ORDER BY e.sequence) AS ordinal
  FROM epm.job_event e
)
INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
SELECT workspace_id,application_id,job_id,ordinal,
  epm.normalized_job_task_status(status),status,claim_generation,
  receipt_revision,error_code,occurred_at FROM numbered;

CREATE TRIGGER aa_job_task_projection
AFTER INSERT OR UPDATE OF status,claim_generation ON epm.job
FOR EACH ROW EXECUTE FUNCTION epm.project_job_task();

REVOKE ALL ON epm.task_cursor,epm.task,epm.task_event FROM PUBLIC;
GRANT SELECT ON epm.task,epm.task_event TO epm_runtime;
GRANT SELECT ON epm.task_cursor,epm.task,epm.task_event TO epm_lifecycle;

ALTER TABLE epm.task_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.task ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.task_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY task_cursor_runtime_scope ON epm.task_cursor TO epm_runtime
  USING (workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY task_runtime_scope ON epm.task TO epm_runtime
  USING (workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY task_event_runtime_scope ON epm.task_event TO epm_runtime
  USING (workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY task_cursor_lifecycle_scope ON epm.task_cursor TO epm_lifecycle
  USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY task_lifecycle_scope ON epm.task TO epm_lifecycle
  USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY task_event_lifecycle_scope ON epm.task_event TO epm_lifecycle
  USING (workspace_id=current_setting('epm.workspace_id',true));

-- Extend exact owner-reset inventory in child-first order.  The immutable
-- event trigger permits deletion only inside the established reset context.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_prefix text := $pattern$'statement_definition_event','statement_definition_state','statement_definition_version',$pattern$;
DECLARE new_prefix text := $pattern$'task_event','task','task_cursor','statement_definition_event','statement_definition_state','statement_definition_version',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_prefix IN definition)=0 OR
     position(new_prefix IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0175_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_prefix,new_prefix);
  IF revised=definition OR position(new_prefix IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0175_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;
