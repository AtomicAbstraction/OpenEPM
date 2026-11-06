-- Capture the first authoritative backend claim for every durable queue family.
-- This is technical timing metadata only: it contains no business values and
-- cannot be supplied or changed through a public product operation.

ALTER TABLE epm.job
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT job_first_claim_time_check
        CHECK(first_claimed_at IS NULL OR first_claimed_at >= created_at);

ALTER TABLE epm.cube_aggregate_query
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT cube_aggregate_first_claim_time_check
        CHECK(first_claimed_at IS NULL OR first_claimed_at >= accepted_at);

ALTER TABLE epm.planning_forecast_occurrence
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT planning_forecast_first_claim_time_check
        CHECK(first_claimed_at IS NULL
              OR first_claimed_at >= greatest(created_at,due_at));

ALTER TABLE epm.planning_assignment_due_occurrence
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT planning_assignment_first_claim_time_check
        CHECK(first_claimed_at IS NULL
              OR first_claimed_at >= greatest(created_at,due_at));

ALTER TABLE epm.python_program_build
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT python_build_first_claim_time_check
        CHECK(first_claimed_at IS NULL OR first_claimed_at >= created_at);

ALTER TABLE epm.python_program_workflow
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT python_workflow_first_claim_time_check
        CHECK(first_claimed_at IS NULL OR first_claimed_at >= created_at);

ALTER TABLE epm.python_program_occurrence
    ADD COLUMN first_claimed_at timestamptz,
    ADD CONSTRAINT python_occurrence_first_claim_time_check
        CHECK(first_claimed_at IS NULL
              OR first_claimed_at >= greatest(created_at,due_at));

CREATE FUNCTION epm.capture_first_queue_claim()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path=pg_catalog
AS $$
BEGIN
    IF NEW.first_claimed_at IS NULL AND NEW.status=TG_ARGV[0] THEN
        NEW.first_claimed_at := clock_timestamp();
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION epm.capture_first_queue_claim() FROM PUBLIC;

CREATE TRIGGER job_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.job
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('running');
CREATE TRIGGER cube_aggregate_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.cube_aggregate_query
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('running');
CREATE TRIGGER planning_forecast_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.planning_forecast_occurrence
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('running');
CREATE TRIGGER planning_assignment_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.planning_assignment_due_occurrence
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('Running');
CREATE TRIGGER python_build_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.python_program_build
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('running');
CREATE TRIGGER python_workflow_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.python_program_workflow
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('running');
CREATE TRIGGER python_occurrence_capture_first_queue_claim
    BEFORE UPDATE OF status ON epm.python_program_occurrence
    FOR EACH ROW EXECUTE FUNCTION epm.capture_first_queue_claim('running');
