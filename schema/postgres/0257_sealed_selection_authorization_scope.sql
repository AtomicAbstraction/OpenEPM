-- Bind durable cube selections to the verified Keycloak-group upper bound
-- and exact dimensional authorization scope under which they were resolved.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=256) THEN
        RAISE EXCEPTION 'MIGRATION_0257_PREDECESSOR_0256_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.sealed_cube_selection
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.sealed_cube_selection
    ADD CONSTRAINT sealed_cube_selection_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT sealed_cube_selection_authorization_scope_digest_check
    CHECK (authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.sealed_cube_selection.verified_groups IS
    'Immutable verified group upper bound admitted with this selection';
COMMENT ON COLUMN epm.sealed_cube_selection.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at resolution';
