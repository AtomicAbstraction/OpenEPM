-- Recover a forecast definition after a terminal, effect-free occurrence and
-- make revoked schedules durably visible instead of silently polling forever.
ALTER TABLE epm.planning_forecast_occurrence
  ADD COLUMN attempt_no bigint NOT NULL DEFAULT 1 CHECK(attempt_no>0),
  ADD COLUMN supersedes_attempt_no bigint,
  ADD COLUMN supersedes_occurrence_id text;

DO $$ DECLARE n text;
BEGIN
 SELECT c.conname INTO n FROM pg_constraint c
 JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace s ON s.oid=t.relnamespace
 WHERE s.nspname='epm' AND t.relname='planning_forecast_occurrence'
   AND c.contype='u' AND pg_get_constraintdef(c.oid)=
     'UNIQUE (workspace_id, application_id, definition_id, progress_sequence)';
 IF n IS NULL THEN RAISE EXCEPTION 'FORECAST_PROGRESS_UNIQUE_CONSTRAINT_UNAVAILABLE'; END IF;
 EXECUTE format('ALTER TABLE epm.planning_forecast_occurrence DROP CONSTRAINT %I',n);
END $$;

ALTER TABLE epm.planning_forecast_occurrence
  ADD CONSTRAINT forecast_occurrence_attempt_unique UNIQUE
    (workspace_id,application_id,definition_id,progress_sequence,attempt_no),
  ADD CONSTRAINT forecast_occurrence_attempt_identity_unique UNIQUE
    (workspace_id,application_id,definition_id,progress_sequence,attempt_no,
     occurrence_id),
  ADD CONSTRAINT forecast_occurrence_supersedes_fkey FOREIGN KEY
    (workspace_id,application_id,definition_id,progress_sequence,
     supersedes_attempt_no,supersedes_occurrence_id)
    REFERENCES epm.planning_forecast_occurrence
      (workspace_id,application_id,definition_id,progress_sequence,
       attempt_no,occurrence_id) ON DELETE RESTRICT,
  ADD CONSTRAINT forecast_occurrence_supersession_shape CHECK(
    (attempt_no=1 AND supersedes_attempt_no IS NULL
                  AND supersedes_occurrence_id IS NULL) OR
    (attempt_no>1 AND supersedes_attempt_no=attempt_no-1
                  AND supersedes_occurrence_id IS NOT NULL));
CREATE UNIQUE INDEX forecast_occurrence_one_live_progress
  ON epm.planning_forecast_occurrence
    (workspace_id,application_id,definition_id,progress_sequence)
  WHERE status NOT IN ('cancelled','failed');

ALTER TABLE epm.planning_forecast_schedule_state
  ADD COLUMN dispatch_status text NOT NULL DEFAULT 'Active'
    CHECK(dispatch_status IN ('Active','Blocked')),
  ADD COLUMN blocked_code text,
  ADD COLUMN blocked_at timestamptz,
  ADD CONSTRAINT forecast_schedule_block_shape CHECK(
    (dispatch_status='Active' AND blocked_code IS NULL AND blocked_at IS NULL) OR
    (dispatch_status='Blocked' AND blocked_code IS NOT NULL AND blocked_at IS NOT NULL));

CREATE TABLE epm.planning_forecast_schedule_event(
 workspace_id text NOT NULL, application_id text NOT NULL, schedule_id text NOT NULL,
 event_sequence bigint GENERATED ALWAYS AS IDENTITY,
 event_type text NOT NULL CHECK(event_type IN ('Blocked','Resumed')),
 schedule_version bigint NOT NULL CHECK(schedule_version>0),
 prior_last_due_at timestamptz, reason_code text NOT NULL,
 operation_id text, created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,schedule_id,event_sequence),
 FOREIGN KEY(workspace_id,application_id,schedule_id)
   REFERENCES epm.planning_forecast_schedule_state
   (workspace_id,application_id,schedule_id) ON DELETE CASCADE,
 FOREIGN KEY(workspace_id,application_id,schedule_id,schedule_version)
   REFERENCES epm.planning_forecast_schedule_version
   (workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,operation_id)
   REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
   ON DELETE RESTRICT
);
ALTER TABLE epm.planning_forecast_schedule_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY forecast_schedule_event_runtime_scope ON epm.planning_forecast_schedule_event
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY forecast_schedule_event_lifecycle_inventory ON epm.planning_forecast_schedule_event
 TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.planning_forecast_schedule_event FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_forecast_schedule_event TO epm_runtime;
GRANT SELECT(workspace_id,application_id,schedule_id,event_sequence)
 ON epm.planning_forecast_schedule_event TO epm_lifecycle;
GRANT USAGE,SELECT ON SEQUENCE epm.planning_forecast_schedule_event_event_sequence_seq TO epm_runtime;
GRANT SELECT(attempt_no,supersedes_attempt_no,supersedes_occurrence_id)
 ON epm.planning_forecast_occurrence TO epm_lifecycle;
GRANT SELECT(dispatch_status,blocked_code,blocked_at) ON epm.planning_forecast_schedule_state TO epm_lifecycle;

CREATE FUNCTION epm.forecast_schedule_worker_block_revoked()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 SELECT s.*,v.delegation_id,v.delegation_version,v.execution_issuer,v.execution_subject
 INTO candidate FROM epm.planning_forecast_schedule_state s
 JOIN epm.planning_forecast_schedule_version v ON
  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 WHERE s.active_version IS NOT NULL AND s.dispatch_status='Active'
  AND v.first_due_at<=clock_timestamp()
  AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>v.interval_seconds)<=clock_timestamp())
  AND NOT epm.execution_delegation_is_current(s.workspace_id,s.application_id,
   v.delegation_id,v.delegation_version,v.execution_issuer,v.execution_subject,
   'facts.planning.forecast.occurrence.request',s.schedule_id,s.active_version)
 ORDER BY s.workspace_id,s.application_id,s.schedule_id FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE epm.planning_forecast_schedule_state SET dispatch_status='Blocked',
  blocked_code='FORECAST_EXECUTION_DELEGATION_REVOKED',blocked_at=clock_timestamp(),
  dispatch_claimant=NULL,dispatch_lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=candidate.workspace_id AND application_id=candidate.application_id
  AND schedule_id=candidate.schedule_id;
 INSERT INTO epm.planning_forecast_schedule_event(workspace_id,application_id,schedule_id,
  event_type,schedule_version,prior_last_due_at,reason_code)
 VALUES(candidate.workspace_id,candidate.application_id,candidate.schedule_id,'Blocked',
  candidate.active_version,candidate.last_due_at,'FORECAST_EXECUTION_DELEGATION_REVOKED');
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION epm.forecast_schedule_worker_block_revoked() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.forecast_schedule_worker_block_revoked() TO epm_worker;

-- Retain the qualified claim body while excluding durable blocked schedules.
CREATE OR REPLACE FUNCTION epm.forecast_schedule_worker_claim(
  p_claimant text,p_lease_seconds integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,dispatch_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN RAISE EXCEPTION 'FORECAST_WORKER_CLAIM_INVALID'; END IF;
 SELECT s.* INTO candidate FROM epm.planning_forecast_schedule_state s
 JOIN epm.planning_forecast_schedule_version v ON
  (v.workspace_id,v.application_id,v.schedule_id,v.version)=
  (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 JOIN epm.application a ON a.workspace_id=s.workspace_id AND a.application_id=s.application_id
 JOIN epm.application_state ast ON ast.workspace_id=s.workspace_id AND ast.application_id=s.application_id
 JOIN epm.workspace w ON w.workspace_id=s.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
 WHERE s.active_version IS NOT NULL AND s.dispatch_status='Active'
  AND (s.dispatch_lease_until IS NULL OR s.dispatch_lease_until<=clock_timestamp())
  AND v.first_due_at<=clock_timestamp()
  AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>v.interval_seconds)<=clock_timestamp())
  AND a.status='Active' AND w.status='Active' AND ast.processing_mode='Active'
  AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,v.delegation_id,
   v.delegation_version,v.execution_issuer,v.execution_subject,
   'facts.planning.forecast.occurrence.request',s.schedule_id,s.active_version)
 ORDER BY d.last_claim_sequence NULLS FIRST,COALESCE(s.last_due_at,v.first_due_at),
  s.workspace_id,s.application_id,s.schedule_id FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE epm.planning_forecast_schedule_state s SET dispatch_generation=s.dispatch_generation+1,
  dispatch_claimant=p_claimant,dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp() WHERE s.workspace_id=candidate.workspace_id
  AND s.application_id=candidate.application_id AND s.schedule_id=candidate.schedule_id;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,candidate.schedule_id,
  candidate.dispatch_generation+1;
END $$;
REVOKE ALL ON FUNCTION epm.forecast_schedule_worker_claim(text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.forecast_schedule_worker_claim(text,integer) TO epm_worker;
