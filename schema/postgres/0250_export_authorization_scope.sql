-- Bind durable export production and stored export visibility to the exact
-- server-resolved direct-plus-Keycloak-group dimensional authorization scope.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=249) THEN
        RAISE EXCEPTION 'MIGRATION_0250_PREDECESSOR_0249_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.fact_export_producer_request
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.fact_export_producer_request
    ADD CONSTRAINT fact_export_producer_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT fact_export_producer_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

ALTER TABLE epm.fact_export_artifact
    ADD COLUMN authorization_scope_digest text NULL,
    ADD CONSTRAINT fact_export_artifact_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

-- Historical requests and artifacts cannot prove the group-derived scope that
-- produced them.  They remain immutable history but the fixed repositories
-- require a non-null digest before dispatch, continuation, reuse or reading.

DROP FUNCTION epm.export_producer_worker_claim(
    text,integer,integer,integer,integer);

CREATE FUNCTION epm.export_producer_worker_claim(
    p_claimant text,p_lease_seconds integer,p_global_limit integer,
    p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,request_id text,
              issuer text,subject_id text,verified_groups text[],
              claim_generation bigint)
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
      AND r.authorization_scope_digest IS NOT NULL
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
        candidate.verified_groups,candidate.claim_generation+1;
END $$;

REVOKE ALL ON FUNCTION epm.export_producer_worker_claim(
    text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_worker_claim(
    text,integer,integer,integer,integer) TO epm_worker;
