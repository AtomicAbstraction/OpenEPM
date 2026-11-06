-- Lease/fence state for the read-only aggregate technical queue.  This queue
-- has no operation receipt and never changes an application's business revision.
ALTER TABLE epm.cube_aggregate_query
    DROP CONSTRAINT cube_aggregate_query_identity_key,
    ADD COLUMN claim_generation bigint NOT NULL DEFAULT 0,
    ADD COLUMN claimant text,
    ADD COLUMN lease_until timestamptz,
    ADD COLUMN attempts integer NOT NULL DEFAULT 0,
    ADD CONSTRAINT cube_aggregate_query_claim_generation_check
        CHECK(claim_generation>=0),
    ADD CONSTRAINT cube_aggregate_query_attempts_check
        CHECK(attempts BETWEEN 0 AND 3),
    ADD CONSTRAINT cube_aggregate_query_lease_state_check CHECK(
        (status IN ('running','cancel_requested')
         AND claimant IS NOT NULL AND length(claimant) BETWEEN 1 AND 200
         AND lease_until IS NOT NULL)
        OR
        (status NOT IN ('running','cancel_requested')
         AND claimant IS NULL AND lease_until IS NULL));

CREATE INDEX cube_aggregate_query_technical_queue
    ON epm.cube_aggregate_query(accepted_at,workspace_id,application_id,query_id)
    WHERE status='ready';
CREATE INDEX cube_aggregate_query_technical_lease
    ON epm.cube_aggregate_query(lease_until,workspace_id,application_id,query_id)
    WHERE status IN ('running','cancel_requested');

