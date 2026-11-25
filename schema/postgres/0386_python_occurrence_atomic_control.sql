-- Atomic Python occurrence admission and current-controller cancellation.
-- Existing rows retain legacy provenance; a missing link is never backfilled
-- from an idempotency-key guess. Stop old writers before this migration.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=385) THEN
  RAISE EXCEPTION 'MIGRATION_0386_REQUIRES_0385'; END IF;
END $$;
ALTER TABLE epm.python_program_occurrence
 ADD COLUMN admission_protocol integer NOT NULL DEFAULT 0 CHECK(admission_protocol IN(0,1)),
 ADD COLUMN control_authority jsonb,
 ADD CONSTRAINT python_occurrence_control_shape CHECK(control_authority IS NULL OR (
   jsonb_typeof(control_authority)='object'
   AND control_authority->>'format'='python-occurrence-control-v1'
   AND control_authority->>'cause' IN('ExplicitCancel','ScheduleRotation')
   AND jsonb_typeof(control_authority->'requestGeneration')='number'
   AND (control_authority->>'requestGeneration')::bigint>0
   AND octet_length(control_authority::text)<=131072));
CREATE UNIQUE INDEX python_occurrence_atomic_build_link ON epm.python_program_occurrence
 (workspace_id,application_id,build_id) WHERE admission_protocol=1 AND build_id IS NOT NULL;
CREATE UNIQUE INDEX python_occurrence_atomic_parent_link ON epm.python_program_occurrence
 (workspace_id,application_id,workflow_id) WHERE admission_protocol=1 AND workflow_id IS NOT NULL;
CREATE FUNCTION epm.python_occurrence_link_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='UPDATE' AND (NEW.admission_protocol<>OLD.admission_protocol
   OR (OLD.build_id IS NOT NULL AND NEW.build_id IS DISTINCT FROM OLD.build_id)
   OR (OLD.workflow_id IS NOT NULL AND NEW.workflow_id IS DISTINCT FROM OLD.workflow_id)) THEN
  RAISE EXCEPTION 'PYTHON_SCHEDULE_LINK_IMMUTABLE'; END IF;
 IF NEW.admission_protocol=1 AND (TG_OP='INSERT' OR
    NEW.build_id IS DISTINCT FROM OLD.build_id OR NEW.workflow_id IS DISTINCT FROM OLD.workflow_id) THEN
  IF NEW.build_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM epm.python_program_build b
    JOIN epm.task t ON (t.workspace_id,t.application_id,t.source_id)=
      (NEW.workspace_id,NEW.application_id,NEW.occurrence_id)
      AND t.source_family='PythonScheduleOccurrence' AND t.task_id='s:'||NEW.occurrence_id
    WHERE (b.workspace_id,b.application_id,b.build_id)=(NEW.workspace_id,NEW.application_id,NEW.build_id)
     AND (b.issuer,b.subject_id)=(t.issuer,t.subject_id)
     AND (b.schedule_id,b.schedule_state_token)=(NEW.schedule_id,NEW.schedule_state_token)
     AND b.idempotency_key='py-schedule-build-'||NEW.occurrence_id) THEN
   RAISE EXCEPTION 'PYTHON_SCHEDULE_ADMISSION_INVALID'; END IF;
  IF NEW.workflow_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM epm.python_program_workflow w
    JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
    WHERE (w.workspace_id,w.application_id,w.workflow_id)=
      (NEW.workspace_id,NEW.application_id,NEW.workflow_id)
      AND w.build_id=NEW.build_id AND (w.issuer,w.subject_id)=(b.issuer,b.subject_id)
      AND w.idempotency_key='py-schedule-run-'||NEW.occurrence_id) THEN
   RAISE EXCEPTION 'PYTHON_SCHEDULE_ADMISSION_INVALID'; END IF;
 END IF;
 IF TG_OP='UPDATE' AND NEW.control_authority IS DISTINCT FROM OLD.control_authority THEN
  IF NEW.control_authority IS NULL OR NEW.status NOT IN('cancel_requested','cancelled')
    OR (NEW.control_authority->>'requestGeneration')::bigint<>NEW.claim_generation
    OR NEW.claim_generation<=OLD.claim_generation THEN
   RAISE EXCEPTION 'PYTHON_SCHEDULE_CONTROL_INVALID'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER python_occurrence_immutable_links BEFORE INSERT OR UPDATE
 ON epm.python_program_occurrence FOR EACH ROW EXECUTE FUNCTION epm.python_occurrence_link_guard();
COMMENT ON COLUMN epm.python_program_occurrence.admission_protocol IS
 '0 retains legacy uncertainty; 1 means each scheduled build/workflow insertion and link commit atomically. Never infer provenance from a null ID.';
COMMENT ON COLUMN epm.python_program_occurrence.control_authority IS
 'Private verified current controller for cancellation only. Original execution identity is unchanged; every retry rechecks current admin/session/groups/scope. Not public output.';

CREATE OR REPLACE FUNCTION epm.python_occurrence_worker_claim(
 p_claimant text,p_lease integer,p_global integer,p_workspace integer,p_application integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,status text,
 claim_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease NOT BETWEEN 5 AND 300 OR p_application NOT BETWEEN 1 AND p_workspace
  OR p_workspace NOT BETWEEN 1 AND p_global THEN RAISE EXCEPTION 'PYTHON_OCCURRENCE_CLAIM_INVALID'
  USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.occurrence.dispatch',0));
 IF(SELECT count(*) FROM epm.python_program_occurrence WHERE claimant IS NOT NULL
  AND lease_until>clock_timestamp())>=p_global THEN RETURN;END IF;
 SELECT o.*,state.schema_epoch INTO c FROM epm.python_program_occurrence o
 LEFT JOIN epm.python_program_schedule_definition schedule
  ON(schedule.workspace_id,schedule.application_id,schedule.schedule_id,schedule.state_token)=
   (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
  AND schedule.status='Active'
 JOIN epm.application_state state ON(state.workspace_id,state.application_id)=
  (o.workspace_id,o.application_id)
 JOIN epm.application app ON(app.workspace_id,app.application_id)=
  (o.workspace_id,o.application_id)
 JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE state.processing_mode='Active' AND app.status='Active' AND ws.status='Active'
  AND o.status IN('ready','running','building','running_program','cancel_requested')
  AND o.worker_failures<3
  AND (o.status='cancel_requested' OR schedule.status='Active')
  AND(o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
  AND(o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
  AND(SELECT count(*) FROM epm.python_program_occurrence x
   WHERE x.workspace_id=o.workspace_id AND x.claimant IS NOT NULL
    AND x.lease_until>clock_timestamp())<p_workspace
  AND(SELECT count(*) FROM epm.python_program_occurrence x
   WHERE x.workspace_id=o.workspace_id AND x.application_id=o.application_id
    AND x.claimant IS NOT NULL AND x.lease_until>clock_timestamp())<p_application
 ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id
 FOR UPDATE OF o SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 IF c.claimant IS NOT NULL THEN
  UPDATE epm.python_program_occurrence target SET
   worker_failures=LEAST(3,target.worker_failures+1),
   status=CASE WHEN target.status='cancel_requested' THEN target.status
    WHEN target.worker_failures+1>=3 THEN 'needs_inspection' ELSE target.status END,
   error_code=CASE WHEN target.worker_failures+1>=3 THEN
    CASE WHEN target.status='cancel_requested' THEN 'PYTHON_SCHEDULE_CANCELLATION_RECOVERY_PARKED'
      ELSE 'PYTHON_SCHEDULE_WORKER_RETRY_LIMIT' END ELSE target.error_code END,
   next_attempt_at=CASE WHEN target.worker_failures+1>=3 THEN NULL ELSE
    clock_timestamp()+make_interval(secs=>CASE target.worker_failures WHEN 0 THEN 1 ELSE 5 END)END,
   claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE(target.workspace_id,target.application_id,target.occurrence_id,target.claim_generation)=
   (c.workspace_id,c.application_id,c.occurrence_id,c.claim_generation)
   AND target.claimant=c.claimant AND target.lease_until<=clock_timestamp();RETURN;END IF;
 UPDATE epm.python_program_occurrence target SET
  status=CASE WHEN target.status='ready' THEN 'running' ELSE target.status END,
  claim_generation=target.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease),next_attempt_at=NULL,
  updated_at=transaction_timestamp()
 WHERE(target.workspace_id,target.application_id,target.occurrence_id)=
  (c.workspace_id,c.application_id,c.occurrence_id);
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(c.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.occurrence_id,
  CASE WHEN c.status='ready' THEN 'running' ELSE c.status END,c.claim_generation+1,c.schema_epoch;
END $$;


CREATE OR REPLACE FUNCTION epm.python_occurrence_worker_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,p_generation bigint,
 p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;BEGIN
 IF p_error NOT IN ('PYTHON_SCHEDULE_WORKER_FAILED',
                    'PYTHON_SCHEDULE_INFRASTRUCTURE_FAILURE')
 THEN RAISE EXCEPTION 'PYTHON_SCHEDULE_WORKER_ERROR_INVALID'
   USING ERRCODE='22023';END IF;
 UPDATE epm.python_program_occurrence SET
   worker_failures=LEAST(3,worker_failures+1),
   status=CASE WHEN status='cancel_requested' THEN status
     WHEN worker_failures+1>=3 THEN 'needs_inspection' ELSE status END,
   error_code=CASE WHEN worker_failures+1>=3 THEN CASE WHEN status='cancel_requested'
     THEN 'PYTHON_SCHEDULE_CANCELLATION_RECOVERY_PARKED' ELSE p_error END ELSE error_code END,
   next_attempt_at=CASE WHEN worker_failures+1>=3 THEN NULL ELSE
     clock_timestamp()+make_interval(secs=>
       CASE worker_failures WHEN 0 THEN 1 ELSE 5 END) END,
   claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active') AND workspace_id=p_workspace AND application_id=p_application
   AND occurrence_id=p_occurrence AND claim_generation=p_generation
   AND claimant=p_claimant AND lease_until>clock_timestamp()
   AND status IN
     ('running','building','running_program','cancel_requested')
 RETURNING CASE WHEN worker_failures>=3 THEN
   CASE WHEN status='cancel_requested' THEN 'cancel_requested' ELSE 'needs_inspection' END
   ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;


CREATE OR REPLACE FUNCTION epm.project_python_schedule_occurrence_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE authority record;DECLARE projected_task_id text:='s:'||NEW.occurrence_id;
BEGIN
 normalized:=epm.normalized_python_schedule_occurrence_task_status(NEW.status);
 IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_PYTHON_SCHEDULE_OCCURRENCE_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status AND NEW.claim_generation=OLD.claim_generation
  AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  SELECT execution_issuer,execution_subject INTO STRICT authority
  FROM epm.python_program_schedule_definition WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND schedule_id=NEW.schedule_id
   AND state_token=NEW.schedule_state_token;
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
   SET last_sequence=epm.task_cursor.last_sequence+1 RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'BusinessExecution','PythonScheduleOccurrence',NEW.occurrence_id,
   authority.execution_issuer,authority.execution_subject,'python.schedule.run','long',
   normalized,NEW.status,NEW.status IN('ready','running','building','running_program',
   'cancel_requested'),false,NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('ready','running','building','running_program','cancel_requested'),
   updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND source_family='PythonScheduleOccurrence'
   AND source_id=NEW.occurrence_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,status,
  native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());RETURN NEW;
END $$;


-- Parking can change only the diagnostic, without a new status/generation.
-- Keep the existing task/event owner responsive to that authoritative change.
DROP TRIGGER aa_python_schedule_occurrence_task_projection
 ON epm.python_program_occurrence;
CREATE TRIGGER aa_python_schedule_occurrence_task_projection
 AFTER INSERT OR UPDATE OF status,claim_generation,error_code
 ON epm.python_program_occurrence FOR EACH ROW
 EXECUTE FUNCTION epm.project_python_schedule_occurrence_task();
REVOKE ALL ON FUNCTION epm.python_occurrence_link_guard() FROM PUBLIC;

COMMIT;
