-- Bind durable source-import publication to the exact verified groups and
-- dimensional authorization scope admitted with the request.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=254) THEN
        RAISE EXCEPTION 'MIGRATION_0255_PREDECESSOR_0254_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.source_import_execution
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.source_import_execution
    ADD CONSTRAINT source_import_execution_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT source_import_execution_authorization_scope_digest_check
    CHECK (authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

COMMENT ON COLUMN epm.source_import_execution.verified_groups IS
    'Immutable verified group upper bound admitted with this import request';
COMMENT ON COLUMN epm.source_import_execution.authorization_scope_digest IS
    'Exact server-derived dimensional authorization scope at import admission';
