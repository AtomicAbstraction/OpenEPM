-- Permit the narrow security adapter to inspect immutable application-scoped
-- security evidence after the fixed core has rechecked current Administrator
-- authority in the same read-only transaction.  The public service exposes a
-- closed safe projection rather than returning the arbitrary detail document.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=264) THEN
        RAISE EXCEPTION 'MIGRATION_0265_PREDECESSOR_0264_REQUIRED';
    END IF;
END $migration$;

GRANT SELECT ON epm.security_audit TO epm_security;

CREATE INDEX security_audit_application_cursor
    ON epm.security_audit(workspace_id,application_id,audit_id DESC)
    WHERE application_id IS NOT NULL;
