-- Keep first-claim timing valid if the host wall clock moves backwards.
--
-- The availability timestamp is already durable and is the lower bound used
-- by each table's check constraint.  A wall-clock sample is useful for queue
-- latency, but it must never precede that durable boundary.

CREATE OR REPLACE FUNCTION epm.capture_first_queue_claim()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path=pg_catalog
AS $$
DECLARE
    row_json jsonb := to_jsonb(NEW);
    available_at timestamptz;
    due_at timestamptz;
BEGIN
    IF NEW.first_claimed_at IS NULL AND NEW.status=TG_ARGV[0] THEN
        available_at := coalesce(
            (row_json->>'created_at')::timestamptz,
            (row_json->>'accepted_at')::timestamptz,
            '-infinity'::timestamptz);
        due_at := coalesce((row_json->>'due_at')::timestamptz,
                           '-infinity'::timestamptz);
        NEW.first_claimed_at := greatest(
            clock_timestamp(),available_at,due_at);
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION epm.capture_first_queue_claim() FROM PUBLIC;
