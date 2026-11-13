-- Fair, lease-fenced dispatch for generic application-rule schedules and
-- their durable occurrences.  Workers receive identities only; authoritative
-- schedule definitions and execution authority remain in scoped runtime code.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=220) THEN
    RAISE EXCEPTION 'MIGRATION_0221_PREDECESSOR_0220_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.application_schedule_state
  ADD COLUMN dispatch_error_code text
    CHECK(dispatch_error_code IS NULL OR length(dispatch_error_code) BETWEEN 1 AND 200);

CREATE UNIQUE INDEX application_schedule_occurrence_workflow_unique
  ON epm.application_schedule_occurrence(
    workspace_id,application_id,application_rule_workflow_id)
  WHERE application_rule_workflow_id IS NOT NULL;

CREATE FUNCTION epm.application_schedule_dispatch_recover()
RETURNS TABLE(schedule_claims integer,occurrence_claims integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE schedules integer;DECLARE occurrences integer;
BEGIN
  UPDATE epm.application_schedule_state SET
    dispatch_generation=dispatch_generation+1,dispatch_claimant=NULL,
    dispatch_lease_until=NULL,updated_at=transaction_timestamp()
  WHERE dispatch_claimant IS NOT NULL
    AND dispatch_lease_until<=clock_timestamp();
  GET DIAGNOSTICS schedules=ROW_COUNT;

  UPDATE epm.application_schedule_occurrence o SET
    attempt_count=o.attempt_count+1,
    status=CASE WHEN o.attempt_count+1 >=
      ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
      THEN 'needs_inspection' ELSE o.status END,
    next_attempt_at=CASE WHEN o.attempt_count+1 >=
      ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
      THEN NULL ELSE clock_timestamp()+make_interval(secs=>
        ((v.definition#>>'{retryPolicy,backoffSeconds}')::integer)) END,
    claim_generation=o.claim_generation+1,claimant=NULL,lease_until=NULL,
    error_code='APPLICATION_SCHEDULE_LEASE_EXPIRED',
    updated_at=transaction_timestamp()
  FROM epm.application_schedule_version v
  WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
    (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
    AND o.claimant IS NOT NULL AND o.lease_until<=clock_timestamp()
    AND o.status IN('running','submitted','cancel_requested');
  GET DIAGNOSTICS occurrences=ROW_COUNT;
  RETURN QUERY SELECT schedules,occurrences;
END $$;

CREATE FUNCTION epm.application_schedule_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
  dispatch_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 30 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_CLAIM_INVALID'
      USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('epm.application.schedule.dispatch',0));
  IF (SELECT count(*) FROM epm.application_schedule_state
      WHERE dispatch_claimant IS NOT NULL
        AND dispatch_lease_until>clock_timestamp())>=p_global_limit THEN
    RETURN;
  END IF;
  SELECT s.* INTO candidate FROM epm.application_schedule_state s
  JOIN epm.application_schedule_version v ON
    (v.workspace_id,v.application_id,v.schedule_id,v.version)=
    (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
  JOIN epm.application a ON a.workspace_id=s.workspace_id
    AND a.application_id=s.application_id
  JOIN epm.application_state state ON state.workspace_id=s.workspace_id
    AND state.application_id=s.application_id
  JOIN epm.workspace ws ON ws.workspace_id=s.workspace_id
  LEFT JOIN epm.worker_workspace_dispatch d
    ON d.workspace_id=s.workspace_id
  WHERE s.active_version IS NOT NULL AND s.dispatch_error_code IS NULL
    AND s.dispatch_claimant IS NULL AND a.status='Active'
    AND ws.status='Active' AND state.processing_mode='Active'
    AND (v.definition#>>'{recurrence,firstDueAt}')::timestamptz
        <=clock_timestamp()
    AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>
        (v.definition#>>'{recurrence,intervalSeconds}')::integer)
        <=clock_timestamp())
    AND (SELECT count(*) FROM epm.application_schedule_state active
      WHERE active.workspace_id=s.workspace_id
        AND active.dispatch_claimant IS NOT NULL
        AND active.dispatch_lease_until>clock_timestamp())<p_workspace_limit
    AND (SELECT count(*) FROM epm.application_schedule_state active
      WHERE active.workspace_id=s.workspace_id
        AND active.application_id=s.application_id
        AND active.dispatch_claimant IS NOT NULL
        AND active.dispatch_lease_until>clock_timestamp())<p_application_limit
  ORDER BY d.last_claim_sequence NULLS FIRST,
    COALESCE(s.last_due_at,
      (v.definition#>>'{recurrence,firstDueAt}')::timestamptz),s.schedule_id
  FOR UPDATE OF s SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN;END IF;
  UPDATE epm.application_schedule_state target SET
    dispatch_generation=target.dispatch_generation+1,
    dispatch_claimant=p_claimant,
    dispatch_lease_until=clock_timestamp()+
      make_interval(secs=>p_lease_seconds),updated_at=transaction_timestamp()
  WHERE target.workspace_id=candidate.workspace_id
    AND target.application_id=candidate.application_id
    AND target.schedule_id=candidate.schedule_id;
  INSERT INTO epm.worker_workspace_dispatch(
    workspace_id,last_claim_sequence,claim_count)
  VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
  ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
    last_claim_sequence=EXCLUDED.last_claim_sequence,
    claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.schedule_id,candidate.dispatch_generation+1;
END $$;

CREATE FUNCTION epm.application_schedule_worker_renew(
  p_workspace text,p_application text,p_schedule text,p_generation bigint,
  p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_RENEW_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_state SET
    dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND schedule_id=p_schedule AND dispatch_generation=p_generation
    AND dispatch_claimant=p_claimant
    AND dispatch_lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

CREATE FUNCTION epm.application_schedule_worker_release(
  p_workspace text,p_application text,p_schedule text,p_generation bigint,
  p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  UPDATE epm.application_schedule_state SET dispatch_claimant=NULL,
    dispatch_lease_until=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND schedule_id=p_schedule AND dispatch_generation=p_generation
    AND dispatch_claimant=p_claimant
    AND dispatch_lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

CREATE FUNCTION epm.application_schedule_worker_block(
  p_workspace text,p_application text,p_schedule text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_error NOT IN('APPLICATION_SCHEDULE_AUTHORITY_INVALID',
                    'APPLICATION_SCHEDULE_DEFINITION_CORRUPT') THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_BLOCK_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_state SET dispatch_error_code=p_error,
    dispatch_claimant=NULL,dispatch_lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND schedule_id=p_schedule AND dispatch_generation=p_generation
    AND dispatch_claimant=p_claimant
    AND dispatch_lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

CREATE FUNCTION epm.application_schedule_occurrence_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
  status text,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
     OR p_lease_seconds NOT BETWEEN 30 AND 300
     OR p_global_limit NOT BETWEEN 1 AND 10000
     OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
     OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_CLAIM_INVALID'
      USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('epm.application.schedule.occurrence.dispatch',0));
  IF (SELECT count(*) FROM epm.application_schedule_occurrence
      WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())
      >=p_global_limit THEN RETURN;END IF;
  SELECT o.* INTO candidate FROM epm.application_schedule_occurrence o
  JOIN epm.application a ON a.workspace_id=o.workspace_id
    AND a.application_id=o.application_id
  JOIN epm.application_state state ON state.workspace_id=o.workspace_id
    AND state.application_id=o.application_id
  JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
  LEFT JOIN epm.worker_workspace_dispatch d
    ON d.workspace_id=o.workspace_id
  WHERE o.status IN('ready','running','submitted','cancel_requested')
    AND o.claimant IS NULL
    AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
    AND a.status='Active' AND ws.status='Active'
    AND state.processing_mode='Active'
    AND (SELECT count(*) FROM epm.application_schedule_occurrence active
      WHERE active.workspace_id=o.workspace_id AND active.claimant IS NOT NULL
        AND active.lease_until>clock_timestamp())<p_workspace_limit
    AND (SELECT count(*) FROM epm.application_schedule_occurrence active
      WHERE active.workspace_id=o.workspace_id
        AND active.application_id=o.application_id
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
  INSERT INTO epm.worker_workspace_dispatch(
    workspace_id,last_claim_sequence,claim_count)
  VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
  ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
    last_claim_sequence=EXCLUDED.last_claim_sequence,
    claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.occurrence_id,
    CASE WHEN candidate.status='ready' THEN 'running' ELSE candidate.status END,
    candidate.claim_generation+1;
END $$;

CREATE FUNCTION epm.application_schedule_occurrence_worker_renew(
  p_workspace text,p_application text,p_occurrence text,p_generation bigint,
  p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_RENEW_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_occurrence SET
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND occurrence_id=p_occurrence AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp()
    AND status IN('running','submitted','cancel_requested');
  RETURN FOUND;
END $$;

CREATE FUNCTION epm.application_schedule_occurrence_worker_release(
  p_workspace text,p_application text,p_occurrence text,p_generation bigint,
  p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  UPDATE epm.application_schedule_occurrence SET claimant=NULL,
    lease_until=NULL,error_code=NULL,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND occurrence_id=p_occurrence AND claim_generation=p_generation
    AND claimant=p_claimant AND lease_until>clock_timestamp();
  RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.application_schedule_dispatch_recover(),
  epm.application_schedule_worker_claim(text,integer,integer,integer,integer),
  epm.application_schedule_worker_renew(text,text,text,bigint,text,integer),
  epm.application_schedule_worker_release(text,text,text,bigint,text),
  epm.application_schedule_worker_block(text,text,text,bigint,text,text),
  epm.application_schedule_occurrence_worker_claim(
    text,integer,integer,integer,integer),
  epm.application_schedule_occurrence_worker_renew(
    text,text,text,bigint,text,integer),
  epm.application_schedule_occurrence_worker_release(
    text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.application_schedule_dispatch_recover(),
  epm.application_schedule_worker_claim(text,integer,integer,integer,integer),
  epm.application_schedule_worker_renew(text,text,text,bigint,text,integer),
  epm.application_schedule_worker_release(text,text,text,bigint,text),
  epm.application_schedule_worker_block(text,text,text,bigint,text,text),
  epm.application_schedule_occurrence_worker_claim(
    text,integer,integer,integer,integer),
  epm.application_schedule_occurrence_worker_renew(
    text,text,text,bigint,text,integer),
  epm.application_schedule_occurrence_worker_release(
    text,text,text,bigint,text) TO epm_worker;

REVOKE UPDATE(dispatch_error_code) ON epm.application_schedule_state
  FROM epm_worker,epm_runtime,epm_lifecycle;
GRANT UPDATE(dispatch_error_code) ON epm.application_schedule_state TO epm_runtime;

