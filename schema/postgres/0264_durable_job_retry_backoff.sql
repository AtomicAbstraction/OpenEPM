-- Keep retry admission durable so a repeatedly failing job cannot monopolize
-- worker claim cycles. The fixed worker owns this technical schedule; clients
-- cannot supply or modify it.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=263) THEN
        RAISE EXCEPTION 'MIGRATION_0264_PREDECESSOR_0263_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.job
    ADD COLUMN next_attempt_at timestamptz,
    ADD CONSTRAINT job_next_attempt_state_check
        CHECK(next_attempt_at IS NULL OR status='ready');

CREATE INDEX job_ready_retry_queue ON epm.job
    (resource_class,next_attempt_at,created_at,workspace_id,application_id)
    WHERE status='ready';

CREATE FUNCTION epm.clear_job_retry_schedule()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path=pg_catalog
AS $$
BEGIN
    IF NEW.status<>'ready' THEN
        NEW.next_attempt_at:=NULL;
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION epm.clear_job_retry_schedule() FROM PUBLIC;

CREATE TRIGGER job_clear_retry_schedule
    BEFORE UPDATE OF status ON epm.job
    FOR EACH ROW EXECUTE FUNCTION epm.clear_job_retry_schedule();

