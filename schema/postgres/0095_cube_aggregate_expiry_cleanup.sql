-- Bounded worker-only expiry and payload cleanup for aggregate query results.
-- Query rows and technical certificates remain as durable evidence; only
-- expired result pages are removed after the configured retention delay.
CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_expire(
  p_limit integer,p_payload_retention_seconds integer)
RETURNS TABLE(expired_count integer,payload_query_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE expired_rows integer:=0; payload_queries integer:=0;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 1000
     OR p_payload_retention_seconds NOT BETWEEN 60 AND 604800 THEN
    RAISE EXCEPTION 'CUBE_AGGREGATE_EXPIRY_POLICY_INVALID' USING ERRCODE='22023';
  END IF;
  WITH due AS (
    SELECT q.workspace_id,q.application_id,q.query_id
      FROM epm.cube_aggregate_query q
     WHERE q.status='sealed' AND q.expires_at<=clock_timestamp()
     ORDER BY q.expires_at,q.workspace_id,q.application_id,q.query_id
     FOR UPDATE OF q SKIP LOCKED LIMIT p_limit
  )
  UPDATE epm.cube_aggregate_query q SET status='expired',
    updated_at=transaction_timestamp() FROM due
   WHERE q.workspace_id=due.workspace_id
     AND q.application_id=due.application_id AND q.query_id=due.query_id;
  GET DIAGNOSTICS expired_rows=ROW_COUNT;
  WITH due AS (
    SELECT q.workspace_id,q.application_id,q.query_id
      FROM epm.cube_aggregate_query q
     WHERE q.status='expired'
       AND q.updated_at<=clock_timestamp()
          -make_interval(secs=>p_payload_retention_seconds)
       AND EXISTS (SELECT 1 FROM epm.cube_aggregate_result r
          WHERE r.workspace_id=q.workspace_id
            AND r.application_id=q.application_id AND r.query_id=q.query_id)
     ORDER BY q.updated_at,q.workspace_id,q.application_id,q.query_id
     FOR UPDATE OF q SKIP LOCKED LIMIT p_limit
  ), deleted AS (
    DELETE FROM epm.cube_aggregate_result r USING due
     WHERE r.workspace_id=due.workspace_id
       AND r.application_id=due.application_id AND r.query_id=due.query_id
    RETURNING r.workspace_id,r.application_id,r.query_id
  )
  SELECT count(*)::integer INTO payload_queries FROM (
    SELECT DISTINCT workspace_id,application_id,query_id FROM deleted) removed;
  RETURN QUERY SELECT expired_rows,payload_queries;
END $$;

REVOKE ALL ON FUNCTION epm.cube_aggregate_worker_expire(integer,integer)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.cube_aggregate_worker_expire(integer,integer)
  TO epm_worker;
