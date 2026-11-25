BEGIN;

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=391) THEN
        RAISE EXCEPTION 'MIGRATION_0392_REQUIRES_0391';
    END IF;
END $migration$;

-- The runtime checker has already refused the admitted identity. The worker
-- can settle only the same generation and admitted scope. A computed result
-- has no live claimant, so match its durable authority and current status.
CREATE FUNCTION epm.cube_aggregate_worker_settle_denied(
    p_workspace text,p_application text,p_query text,p_generation bigint,
    p_claimant text,p_scope_digest text)
RETURNS TABLE(outcome text,error_code text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    current epm.cube_aggregate_query%ROWTYPE;
    next_status text;
    next_error text;
    cutoff timestamptz;
BEGIN
    IF p_workspace IS NULL OR p_application IS NULL OR p_query IS NULL
       OR p_generation IS NULL OR p_generation<1
       OR p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
       OR p_scope_digest IS NULL OR p_scope_digest!~'^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'CUBE_AGGREGATE_WORKER_SETTLEMENT_INVALID' USING ERRCODE='22023';
    END IF;

    SELECT q.* INTO current FROM epm.cube_aggregate_query q
    WHERE q.workspace_id=p_workspace AND q.application_id=p_application AND q.query_id=p_query
      AND q.claim_generation=p_generation AND q.authorization_scope_digest=p_scope_digest
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'stale'::text,NULL::text;
        RETURN;
    END IF;
    IF current.status IN ('sealed','cancelled','failed','expired') THEN
        RETURN QUERY SELECT current.status,current.error_code;
        RETURN;
    END IF;

    cutoff:=clock_timestamp();
    IF current.status<>'computed' AND (
        current.status NOT IN ('running','cancel_requested')
        OR current.claimant IS DISTINCT FROM p_claimant
        OR current.lease_until IS NULL OR current.lease_until<=cutoff) THEN
        RETURN QUERY SELECT 'stale'::text,NULL::text;
        RETURN;
    END IF;

    IF current.status='cancel_requested' THEN
        next_status:='cancelled';
    ELSIF current.status='computed' AND current.expires_at<=cutoff THEN
        next_status:='expired';
    ELSE
        next_status:='failed';
        next_error:='CUBE_AGGREGATE_AUTHORIZATION_REVOKED';
    END IF;

    UPDATE epm.cube_aggregate_query q SET status=next_status,error_code=next_error,
        claimant=NULL,lease_until=NULL,next_attempt_at=NULL,updated_at=cutoff
    WHERE q.workspace_id=p_workspace AND q.application_id=p_application AND q.query_id=p_query;
    IF current.status='computed' THEN
        DELETE FROM epm.cube_aggregate_result r
        WHERE r.workspace_id=p_workspace AND r.application_id=p_application AND r.query_id=p_query;
    END IF;
    RETURN QUERY SELECT next_status,next_error;
END $function$;

REVOKE ALL ON FUNCTION
    epm.cube_aggregate_worker_settle_denied(text,text,text,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    epm.cube_aggregate_worker_settle_denied(text,text,text,bigint,text,text) TO epm_worker;

COMMIT;
