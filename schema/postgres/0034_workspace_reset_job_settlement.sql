-- A narrow fixed operation for a quiesced workspace. The lifecycle login has
-- EXECUTE only: it cannot issue arbitrary job UPDATEs or write business facts.
GRANT SELECT ON epm.operation_receipt TO epm_lifecycle;
CREATE POLICY operation_receipt_lifecycle_read
    ON epm.operation_receipt FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));

CREATE FUNCTION epm.settle_workspace_reset_jobs(p_workspace_id text)
RETURNS TABLE(cancelled_count bigint, inspection_count bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    v_status text;
BEGIN
    IF p_workspace_id IS NULL OR p_workspace_id = '' OR
       p_workspace_id <> current_setting('epm.workspace_id', true) THEN
        RAISE EXCEPTION 'RESET_SCOPE_INVALID';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'RESET_REQUIRES_READ_COMMITTED';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended('epm.security.workspace:' || p_workspace_id,0));
    SELECT status INTO v_status FROM epm.workspace
        WHERE workspace_id=p_workspace_id;
    IF v_status IS DISTINCT FROM 'Maintenance' THEN
        RAISE EXCEPTION 'WORKSPACE_NOT_IN_MAINTENANCE';
    END IF;
    IF (SELECT count(*) FROM epm.job
        WHERE workspace_id=p_workspace_id AND status IN
            ('accepted','ready','running','staged','cancel_requested')) > 1000 THEN
        RAISE EXCEPTION 'RESET_ACTIVE_TARGETS_EXCEED_LIMIT';
    END IF;

    RETURN QUERY
    WITH targets AS MATERIALIZED (
        SELECT j.workspace_id,j.application_id,j.job_id,
            EXISTS (SELECT 1 FROM epm.operation_receipt r
                WHERE r.workspace_id=j.workspace_id
                  AND r.application_id=j.application_id
                  AND r.operation_id=j.job_id) AS has_receipt
        FROM epm.job j WHERE j.workspace_id=p_workspace_id
          AND j.status IN
              ('accepted','ready','running','staged','cancel_requested')
        ORDER BY j.application_id,j.job_id FOR UPDATE OF j
    ), changed AS (
        UPDATE epm.job j SET
            status=CASE WHEN t.has_receipt THEN 'needs_inspection'
                        ELSE 'cancelled' END,
            claim_generation=j.claim_generation+1,
            claimant=NULL,lease_until=NULL,
            error_code=CASE WHEN t.has_receipt
                THEN 'RECEIPT_REQUIRES_PUBLICATION_REVIEW'
                ELSE 'WORKSPACE_RESET_SETTLEMENT' END,
            updated_at=transaction_timestamp()
        FROM targets t WHERE j.workspace_id=t.workspace_id
          AND j.application_id=t.application_id AND j.job_id=t.job_id
        RETURNING j.status
    )
    SELECT count(*) FILTER (WHERE status='cancelled')::bigint,
           count(*) FILTER (WHERE status='needs_inspection')::bigint
    FROM changed;
END $$;
REVOKE ALL ON FUNCTION epm.settle_workspace_reset_jobs(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.settle_workspace_reset_jobs(text)
    TO epm_lifecycle;
