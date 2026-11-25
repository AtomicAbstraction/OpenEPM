BEGIN;

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=390) THEN
        RAISE EXCEPTION 'MIGRATION_0391_REQUIRES_0390';
    END IF;
END $migration$;

DROP INDEX epm.cube_aggregate_query_expiry;
CREATE INDEX cube_aggregate_query_expiry
    ON epm.cube_aggregate_query(expires_at,workspace_id,application_id,query_id)
    WHERE status IN ('computed','sealed');

-- Computed results are private and can no longer be sealed after expiry.
-- Discard their payload in the expiry transaction. Retain previously sealed
-- payloads for the configured window, and include historical terminal rows
-- whose private payload may have survived cancellation or failure.
CREATE OR REPLACE FUNCTION epm.cube_aggregate_worker_expire(
    p_limit integer,p_payload_retention_seconds integer)
RETURNS TABLE(expired_count integer,payload_query_count integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE
    cutoff timestamptz:=statement_timestamp();
    expired_rows integer;
    private_queries integer;
    retained_queries integer;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000
       OR p_payload_retention_seconds IS NULL
       OR p_payload_retention_seconds NOT BETWEEN 60 AND 604800 THEN
        RAISE EXCEPTION 'CUBE_AGGREGATE_EXPIRY_POLICY_INVALID' USING ERRCODE='22023';
    END IF;

    WITH due AS (
        SELECT q.workspace_id,q.application_id,q.query_id,q.status
        FROM epm.cube_aggregate_query q
        WHERE q.status IN ('computed','sealed') AND q.expires_at<=cutoff
        ORDER BY q.expires_at,q.workspace_id,q.application_id,q.query_id
        FOR UPDATE OF q SKIP LOCKED LIMIT p_limit
    ), changed AS (
        UPDATE epm.cube_aggregate_query q SET status='expired',updated_at=cutoff
        FROM due
        WHERE (q.workspace_id,q.application_id,q.query_id)=
              (due.workspace_id,due.application_id,due.query_id)
        RETURNING q.workspace_id,q.application_id,q.query_id,due.status AS prior_status
    ), discarded AS (
        DELETE FROM epm.cube_aggregate_result r USING changed
        WHERE changed.prior_status='computed'
          AND (r.workspace_id,r.application_id,r.query_id)=
              (changed.workspace_id,changed.application_id,changed.query_id)
        RETURNING r.workspace_id,r.application_id,r.query_id
    )
    SELECT (SELECT count(*)::integer FROM changed),
           (SELECT count(DISTINCT (workspace_id,application_id,query_id))::integer FROM discarded)
    INTO expired_rows,private_queries;

    WITH due AS (
        SELECT q.workspace_id,q.application_id,q.query_id
        FROM epm.cube_aggregate_query q
        WHERE q.status IN ('expired','cancelled','failed')
          AND q.updated_at<=cutoff-make_interval(secs=>p_payload_retention_seconds)
          AND EXISTS (SELECT 1 FROM epm.cube_aggregate_result r
              WHERE (r.workspace_id,r.application_id,r.query_id)=
                    (q.workspace_id,q.application_id,q.query_id))
        ORDER BY q.updated_at,q.workspace_id,q.application_id,q.query_id
        FOR UPDATE OF q SKIP LOCKED LIMIT (p_limit-private_queries)
    ), discarded AS (
        DELETE FROM epm.cube_aggregate_result r USING due
        WHERE (r.workspace_id,r.application_id,r.query_id)=
              (due.workspace_id,due.application_id,due.query_id)
        RETURNING r.workspace_id,r.application_id,r.query_id
    )
    SELECT count(DISTINCT (workspace_id,application_id,query_id))::integer
    INTO retained_queries FROM discarded;

    RETURN QUERY SELECT expired_rows,private_queries+retained_queries;
END $function$;

REVOKE ALL ON FUNCTION epm.cube_aggregate_worker_expire(integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.cube_aggregate_worker_expire(integer,integer) TO epm_worker;

COMMIT;
