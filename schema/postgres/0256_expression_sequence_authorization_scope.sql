-- Bind generic expression-rule sequences to the verified group upper bound
-- and exact dimensional authorization scope accepted with the sequence.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=255) THEN
        RAISE EXCEPTION 'MIGRATION_0256_PREDECESSOR_0255_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.expression_rule_sequence
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.expression_rule_sequence
    ADD CONSTRAINT expression_rule_sequence_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT expression_rule_sequence_authorization_scope_digest_check
    CHECK (authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.expression_rule_sequence.verified_groups IS
    'Immutable verified group upper bound admitted with this sequence';
COMMENT ON COLUMN epm.expression_rule_sequence.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at admission';
