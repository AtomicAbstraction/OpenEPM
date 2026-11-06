-- Principal cutover is complete. Preserve the immutable mapping/audit table
-- for historical interpretation, but remove every executable SQL entry point
-- so the ordinary platform service cannot absorb another principal's grants.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=265) THEN
        RAISE EXCEPTION 'MIGRATION_0266_PREDECESSOR_0265_REQUIRED';
    END IF;
END $migration$;

REVOKE ALL ON FUNCTION epm.identity_principal_migration_preview(
    text,text,text,text,text,text) FROM PUBLIC,epm_provision;
REVOKE ALL ON FUNCTION epm.identity_principal_migration_apply(
    text,text,text,text,text,text,text,jsonb,text,text,text)
    FROM PUBLIC,epm_provision;

DROP FUNCTION epm.identity_principal_migration_apply(
    text,text,text,text,text,text,text,jsonb,text,text,text);
DROP FUNCTION epm.identity_principal_migration_preview(
    text,text,text,text,text,text);

COMMENT ON TABLE epm.identity_principal_migration IS
    'Immutable historical principal-cutover evidence; executable migration capability retired by schema 0266';
