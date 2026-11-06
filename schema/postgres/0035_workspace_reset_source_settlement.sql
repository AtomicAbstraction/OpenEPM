-- Quiesced source batches retain their staged rows for exact-target deletion,
-- but can no longer be appended, sealed or published after settlement. The
-- lifecycle login can execute only this bounded fixed operation.
CREATE FUNCTION epm.settle_workspace_reset_batches(p_workspace_id text)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    v_status text;
    v_count bigint;
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
    IF (SELECT count(*) FROM epm.source_batch
        WHERE workspace_id=p_workspace_id AND status IN ('staging','ready'))
        > 1000 THEN
        RAISE EXCEPTION 'RESET_ACTIVE_TARGETS_EXCEED_LIMIT';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.source_batch b
        JOIN epm.operation_receipt r
          ON r.workspace_id=b.workspace_id
         AND r.application_id=b.application_id
         AND r.operation_id=b.batch_id
        WHERE b.workspace_id=p_workspace_id
          AND b.status IN ('staging','ready')) THEN
        RAISE EXCEPTION 'SOURCE_BATCH_RECEIPT_REQUIRES_INSPECTION';
    END IF;

    UPDATE epm.source_batch SET status='failed',
        result=jsonb_build_object('errorCode','WORKSPACE_RESET_SETTLEMENT'),
        updated_at=transaction_timestamp()
        WHERE workspace_id=p_workspace_id AND status IN ('staging','ready');
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$;
REVOKE ALL ON FUNCTION epm.settle_workspace_reset_batches(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.settle_workspace_reset_batches(text)
    TO epm_lifecycle;
