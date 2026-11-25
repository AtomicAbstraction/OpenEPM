-- Existing pending origins are never guessed or rebased.
BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=382) THEN
  RAISE EXCEPTION 'MIGRATION_0383_REQUIRES_0382';
 END IF;
END $migration$;

ALTER TABLE epm.application_rule_workflow
 ADD COLUMN execution_origin_kind text NOT NULL DEFAULT 'legacy_unresolved'
  CHECK(execution_origin_kind IN ('direct','scheduled','legacy_unresolved')),
 ADD COLUMN schedule_authority jsonb;
-- Only the migration assigns the unresolved default to retained rows. Every
-- new trusted entry must supply its direct/scheduled origin explicitly.
ALTER TABLE epm.application_rule_workflow ALTER COLUMN execution_origin_kind DROP DEFAULT;
ALTER TABLE epm.application_rule_workflow ADD CONSTRAINT application_rule_schedule_authority_shape CHECK(
 (execution_origin_kind IN ('direct','legacy_unresolved') AND schedule_authority IS NULL)
 OR (execution_origin_kind='scheduled' AND schedule_authority IS NOT NULL
  AND coalesce(jsonb_typeof(schedule_authority)='object'
   AND schedule_authority ?& ARRAY['occurrenceId','scheduleId','scheduleStateToken','delegationId','delegationStateToken']
   AND schedule_authority-ARRAY['occurrenceId','scheduleId','scheduleStateToken','delegationId','delegationStateToken']='{}'::jsonb
   AND jsonb_typeof(schedule_authority->'occurrenceId')='string'
   AND schedule_authority->>'occurrenceId'~'^[0-9a-f]{32}$'
   AND jsonb_typeof(schedule_authority->'scheduleId')='string'
   AND schedule_authority->>'scheduleId'~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
   AND jsonb_typeof(schedule_authority->'scheduleStateToken')='string'
   AND schedule_authority->>'scheduleStateToken'~'^[0-9a-f]{64}$'
   AND jsonb_typeof(schedule_authority->'delegationId')='string'
   AND schedule_authority->>'delegationId'~'^[A-Za-z0-9._-]{1,200}$'
   AND jsonb_typeof(schedule_authority->'delegationStateToken')='string'
   AND schedule_authority->>'delegationStateToken'~'^[0-9a-f]{64}$',false)));

CREATE INDEX application_schedule_occurrence_rule_origin
 ON epm.application_schedule_occurrence(workspace_id,application_id,application_rule_workflow_id,occurrence_id)
 WHERE application_rule_workflow_id IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.application_rule_owner_certificate_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE owner_row epm.expression_rule_definition%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW.workspace_id,NEW.application_id,NEW.workflow_id,NEW.rule_id,NEW.rule_state_token,
      NEW.program_digest,NEW.owner_certificate_digest,NEW.sealed_plan,NEW.plan_digest,NEW.compiler_version,
      NEW.expected_metadata_revision,NEW.expected_policy_revision,NEW.expected_schema_epoch,
      NEW.issuer,NEW.subject_id,NEW.verified_groups,NEW.authorization_scope_digest,
      NEW.execution_origin_kind,NEW.schedule_authority)
   IS DISTINCT FROM
     (OLD.workspace_id,OLD.application_id,OLD.workflow_id,OLD.rule_id,OLD.rule_state_token,
      OLD.program_digest,OLD.owner_certificate_digest,OLD.sealed_plan,OLD.plan_digest,OLD.compiler_version,
      OLD.expected_metadata_revision,OLD.expected_policy_revision,OLD.expected_schema_epoch,
      OLD.issuer,OLD.subject_id,OLD.verified_groups,OLD.authorization_scope_digest,
      OLD.execution_origin_kind,OLD.schedule_authority) THEN
   RAISE EXCEPTION 'APPLICATION_RULE_OWNER_CERTIFICATE_IMMUTABLE' USING ERRCODE='23514';
  END IF;
 ELSE
  IF NEW.execution_origin_kind NOT IN ('direct','scheduled') THEN
   RAISE EXCEPTION 'APPLICATION_RULE_EXECUTION_ORIGIN_REQUIRED' USING ERRCODE='23514';
  END IF;
  SELECT * INTO owner_row FROM epm.expression_rule_definition
   WHERE(workspace_id,application_id,rule_id)=(NEW.workspace_id,NEW.application_id,NEW.rule_id);
  IF NEW.owner_certificate_digest IS NULL OR owner_row.current_certificate IS NULL
   OR owner_row.definition_kind IS DISTINCT FROM 'ApplicationRule' OR owner_row.status IS DISTINCT FROM 'Active'
   OR (owner_row.state_token,owner_row.program_digest) IS DISTINCT FROM (NEW.rule_state_token,NEW.program_digest)
   OR NEW.owner_certificate_digest IS DISTINCT FROM encode(sha256(convert_to(
        epm.definition_canonical_json(owner_row.current_certificate),'UTF8')),'hex') THEN
   RAISE EXCEPTION 'APPLICATION_RULE_OWNER_CERTIFICATE_REQUIRED' USING ERRCODE='23514';
  END IF;
  IF NEW.sealed_plan->>'format' IS DISTINCT FROM 'openepm-python-plan-v1'
   OR jsonb_typeof(NEW.sealed_plan->'units') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'APPLICATION_RULE_SEALED_PLAN_SHAPE_INVALID' USING ERRCODE='23514';
  END IF;
  IF jsonb_array_length(NEW.sealed_plan->'units') NOT BETWEEN 1 AND 500 THEN
   RAISE EXCEPTION 'APPLICATION_RULE_SEALED_PLAN_SHAPE_INVALID' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;

-- Current-target eligibility applies to new execution. A known linked
-- cancellation remains recoverable after schedule deactivation/replacement.
CREATE OR REPLACE FUNCTION epm.application_schedule_occurrence_worker_claim(
 p_claimant text,p_lease_seconds integer,p_global_limit integer,
 p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
 status text,claim_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 30 AND 300 OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(
  hashtextextended('epm.application.schedule.occurrence.dispatch',0));
 IF (SELECT count(*) FROM epm.application_schedule_occurrence
  WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global_limit
 THEN RETURN;END IF;
 SELECT o.*,state.schema_epoch INTO candidate
 FROM epm.application_schedule_occurrence o
 LEFT JOIN epm.application_schedule_definition schedule
  ON (schedule.workspace_id,schedule.application_id,schedule.schedule_id,
      schedule.state_token)=(o.workspace_id,o.application_id,o.schedule_id,
      o.schedule_state_token) AND schedule.status='Active'
 JOIN epm.application a
  ON (a.workspace_id,a.application_id)=(o.workspace_id,o.application_id)
 JOIN epm.application_state state
  ON (state.workspace_id,state.application_id)=(o.workspace_id,o.application_id)
 JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE o.status IN('ready','running','submitted','cancel_requested')
  AND (schedule.schedule_id IS NOT NULL
    OR (o.status='cancel_requested' AND o.application_rule_workflow_id IS NOT NULL))
  AND o.claimant IS NULL
  AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
  AND a.status='Active' AND ws.status='Active' AND state.processing_mode='Active'
  AND (SELECT count(*) FROM epm.application_schedule_occurrence active
    WHERE active.workspace_id=o.workspace_id AND active.claimant IS NOT NULL
      AND active.lease_until>clock_timestamp())<p_workspace_limit
  AND (SELECT count(*) FROM epm.application_schedule_occurrence active
    WHERE active.workspace_id=o.workspace_id AND active.application_id=o.application_id
      AND active.claimant IS NOT NULL
      AND active.lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id
 FOR UPDATE OF o SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.application_schedule_occurrence target SET
  status=CASE WHEN target.status='ready' THEN 'running' ELSE target.status END,
  claim_generation=target.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE target.workspace_id=candidate.workspace_id
  AND target.application_id=candidate.application_id
  AND target.occurrence_id=candidate.occurrence_id;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
  candidate.occurrence_id,
  CASE WHEN candidate.status='ready' THEN 'running' ELSE candidate.status END,
  candidate.claim_generation+1,candidate.schema_epoch;
END $$;


-- The exact old schedule may no longer exist after definition rotation. A
-- linked cancellation still needs a fenced settlement, but must not borrow
-- the replacement definition's retry policy. Park such uncertainty directly.
CREATE OR REPLACE FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,
 p_generation bigint,p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('APPLICATION_SCHEDULE_WORKER_FAILED',
                   'APPLICATION_SCHEDULE_LEASE_EXPIRED') THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_ERROR_INVALID' USING ERRCODE='22023';
 END IF;
 WITH retry AS (
  SELECT observed.workspace_id,observed.application_id,observed.occurrence_id,
   coalesce((v.definition#>>'{retryPolicy,maxAttempts}')::integer,1) AS max_attempts,
   coalesce((v.definition#>>'{retryPolicy,backoffSeconds}')::integer,0) AS backoff_seconds
  FROM epm.application_schedule_occurrence observed
  LEFT JOIN epm.application_schedule_definition v
    ON (v.workspace_id,v.application_id,v.schedule_id,v.state_token)=
       (observed.workspace_id,observed.application_id,observed.schedule_id,observed.schedule_state_token)
  WHERE observed.workspace_id=p_workspace AND observed.application_id=p_application
   AND observed.occurrence_id=p_occurrence
   AND (v.schedule_id IS NOT NULL OR
       (observed.status='cancel_requested' AND observed.application_rule_workflow_id IS NOT NULL))
 )
 UPDATE epm.application_schedule_occurrence o SET
  attempt_count=o.attempt_count+1,
  inspection_origin_status=CASE WHEN o.attempt_count+1>=retry.max_attempts
   THEN o.status ELSE o.inspection_origin_status END,
  status=CASE WHEN o.attempt_count+1>=retry.max_attempts
   THEN 'needs_inspection' ELSE o.status END,
  next_attempt_at=CASE WHEN o.attempt_count+1>=retry.max_attempts THEN NULL
   ELSE clock_timestamp()+make_interval(secs=>retry.backoff_seconds) END,
  claim_generation=o.claim_generation+1,claimant=NULL,lease_until=NULL,
  error_code=p_error,updated_at=transaction_timestamp()
 FROM retry
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active')
  AND (retry.workspace_id,retry.application_id,retry.occurrence_id)=
      (o.workspace_id,o.application_id,o.occurrence_id)
  AND o.workspace_id=p_workspace AND o.application_id=p_application
  AND o.occurrence_id=p_occurrence AND o.claim_generation=p_generation
  AND o.claimant=p_claimant
  AND o.status IN('running','submitted','cancel_requested')
 RETURNING CASE WHEN o.status='needs_inspection'
  THEN 'needs_inspection' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

COMMENT ON COLUMN epm.application_rule_workflow.execution_origin_kind IS
 'Trusted direct/scheduled origin for new work; retained unknown origin requires exact proof before effects';
COMMENT ON COLUMN epm.application_rule_workflow.schedule_authority IS
 'Immutable original occurrence, schedule and delegation identity; current authority is rechecked at each effect boundary';
COMMIT;
SELECT '0383 applied' AS migration;
