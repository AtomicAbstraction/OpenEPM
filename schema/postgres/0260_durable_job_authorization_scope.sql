-- Bind every newly admitted durable job to its exact dimensional authority.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=259) THEN
        RAISE EXCEPTION 'MIGRATION_0260_PREDECESSOR_0259_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.job
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.job
    ADD CONSTRAINT job_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.job.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at admission';

-- Historical unsettled jobs cannot prove their admitted dimensional scope.
-- Preserve them for inspection, but never let a current worker publish them.
UPDATE epm.job SET status='needs_inspection',
    error_code='AUTHORIZATION_SCOPE_UNPROVEN',
    claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
WHERE status IN ('accepted','ready','running','staged','cancel_requested')
  AND authorization_scope_digest IS NULL;
