-- Let the fixed worker coordinator discover and execute durable exports.
-- The caller receives only one server-selected request and its persisted
-- actor identity; it cannot choose a workspace, application or request.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=207) THEN
        RAISE EXCEPTION 'MIGRATION_0208_PREDECESSOR_0207_REQUIRED';
    END IF;
END $migration$;

CREATE FUNCTION epm.export_producer_worker_claim(
    p_claimant text,p_lease_seconds integer,p_global_limit integer,
    p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,request_id text,
              issuer text,subject_id text,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
    IF NOT pg_has_role(session_user,'epm_worker','member')
       OR p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
       OR p_lease_seconds NOT BETWEEN 30 AND 300
       OR p_global_limit NOT BETWEEN 1 AND 10000
       OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
       OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
        RAISE EXCEPTION 'EXPORT_PRODUCER_WORKER_CLAIM_INVALID'
            USING ERRCODE='22023';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended('epm.export.producer.dispatch',0));
    SELECT r.* INTO candidate
    FROM epm.fact_export_producer_request r
    JOIN epm.application a USING(workspace_id,application_id)
    JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.workspace w USING(workspace_id)
    LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
    WHERE (r.status='Accepted' OR
           (r.status='Reading' AND r.lease_until<=clock_timestamp()))
      AND NOT r.cancel_requested
      AND r.expires_at_epoch>extract(epoch from clock_timestamp())::bigint
      AND a.status='Active' AND w.status='Active'
      AND s.processing_mode='Active'
      AND (SELECT count(*) FROM epm.fact_export_producer_request x
           WHERE x.status IN('Reading','Publishing')
             AND x.lease_until>clock_timestamp())<p_global_limit
      AND (SELECT count(*) FROM epm.fact_export_producer_request x
           WHERE x.workspace_id=r.workspace_id
             AND x.status IN('Reading','Publishing')
             AND x.lease_until>clock_timestamp())<p_workspace_limit
      AND (SELECT count(*) FROM epm.fact_export_producer_request x
           WHERE x.workspace_id=r.workspace_id
             AND x.application_id=r.application_id
             AND x.status IN('Reading','Publishing')
             AND x.lease_until>clock_timestamp())<p_application_limit
    ORDER BY d.last_claim_sequence NULLS FIRST,r.created_at,
             r.workspace_id,r.application_id,r.request_id
    FOR UPDATE OF r SKIP LOCKED LIMIT 1;
    IF NOT FOUND THEN RETURN; END IF;
    UPDATE epm.fact_export_producer_request r
    SET status='Reading',claim_generation=r.claim_generation+1,
        claimant=p_claimant,
        lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
        error_code=NULL,updated_at=transaction_timestamp()
    WHERE r.workspace_id=candidate.workspace_id
      AND r.application_id=candidate.application_id
      AND r.request_id=candidate.request_id;
    INSERT INTO epm.worker_workspace_dispatch(
        workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
        last_claim_sequence=EXCLUDED.last_claim_sequence,
        claim_count=epm.worker_workspace_dispatch.claim_count+1;
    RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
        candidate.request_id,candidate.issuer,candidate.subject_id,
        candidate.claim_generation+1;
END $$;

CREATE FUNCTION epm.export_producer_worker_settle_failed(
    p_workspace text,p_application text,p_request text,p_generation bigint,
    p_claimant text,p_error_code text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF NOT pg_has_role(session_user,'epm_worker','member')
       OR p_error_code IS NULL OR p_error_code !~ '^[A-Z][A-Z0-9_]{2,127}$'
       OR length(p_claimant) NOT BETWEEN 1 AND 200 THEN
        RAISE EXCEPTION 'EXPORT_PRODUCER_WORKER_SETTLEMENT_INVALID'
            USING ERRCODE='22023';
    END IF;
    UPDATE epm.fact_export_producer_request SET
        status=CASE WHEN cancel_requested THEN 'Cancelled' ELSE 'Failed' END,
        error_code=CASE WHEN cancel_requested THEN NULL ELSE p_error_code END,
        claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
    WHERE workspace_id=p_workspace AND application_id=p_application
      AND request_id=p_request AND status='Reading'
      AND claim_generation=p_generation AND claimant=p_claimant
      AND lease_until>clock_timestamp();
    RETURN FOUND;
END $$;

REVOKE ALL ON FUNCTION epm.export_producer_worker_claim(
    text,integer,integer,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.export_producer_worker_settle_failed(
    text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_worker_claim(
    text,integer,integer,integer,integer) TO epm_worker;
GRANT EXECUTE ON FUNCTION epm.export_producer_worker_settle_failed(
    text,text,text,bigint,text,text) TO epm_worker;
