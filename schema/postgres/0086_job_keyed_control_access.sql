-- Bounded keyed job access; preserve existing constraints and grants.
CREATE INDEX job_keyed_access ON epm.job(job_id,workspace_id,application_id);

-- The manifest's scoped FK already proves job existence. Retain the separate
-- live running/claim/lease check rather than joining scoped terminal history.
CREATE OR REPLACE FUNCTION epm.staged_projection_allowed(w text,a text,target bigint,allowed_phase text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE m epm.projection_recovery_manifest%ROWTYPE;
BEGIN
    IF coalesce(current_setting('epm.staged_projection_context',true),'')='' THEN RETURN false; END IF;
    IF NOT pg_has_role(current_user,(SELECT relowner FROM pg_class
        WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN false; END IF;
    SELECT m0.* INTO m FROM epm.projection_recovery_manifest m0
        WHERE m0.workspace_id=w AND m0.application_id=a AND m0.target_generation=target
        AND m0.target_generation<>m0.original_generation
        AND (allowed_phase IS NULL OR m0.phase=allowed_phase)
        AND m0.context_xid=pg_current_xact_id()::text AND m0.context_pid=pg_backend_pid()
        AND current_setting('epm.staged_projection_context',true)=jsonb_build_array(
            w,a,m0.job_id,target,m0.context_claim,m0.context_xid,m0.context_pid)::text;
    IF NOT FOUND THEN RETURN false; END IF;
    IF NOT EXISTS(SELECT 1 FROM epm.job j WHERE j.workspace_id=w AND j.application_id=a
        AND j.job_id=m.job_id AND j.status='running' AND j.claim_generation=m.context_claim
        AND j.lease_until>clock_timestamp()) THEN
        RAISE EXCEPTION 'STALE_WORKER_FENCE' USING ERRCODE='23514';
    END IF;
    RETURN true;
END $$;
