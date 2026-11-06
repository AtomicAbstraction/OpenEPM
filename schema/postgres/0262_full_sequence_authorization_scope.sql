-- Bind the legacy Full aggregate sequence coordinator to exact admitted authority.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=261) THEN
        RAISE EXCEPTION 'MIGRATION_0262_PREDECESSOR_0261_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.full_aggregate_sequence
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.full_aggregate_sequence
    ADD CONSTRAINT full_sequence_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT full_sequence_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL OR
        authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.full_aggregate_sequence.verified_groups IS
    'Exact server-verified Keycloak group tuple at sequence admission';
COMMENT ON COLUMN epm.full_aggregate_sequence.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at sequence admission';

-- Historical unsettled sequences cannot prove their admitted group/scope
-- authority. Preserve their record, but never let a current worker continue.
UPDATE epm.full_aggregate_sequence
SET status='failed',error_code='FULL_SEQUENCE_AUTHORIZATION_SCOPE_UNPROVEN',
    updated_at=transaction_timestamp()
WHERE status IN ('accepted','running','cancel_requested')
  AND authorization_scope_digest IS NULL;
