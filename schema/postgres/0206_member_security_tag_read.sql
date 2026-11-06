-- Permit the security plane to read only the member fields required by the
-- authorized member-tag read contract.  The application context remains the
-- database-enforced scope; this does not grant the security role a general
-- member-table read path.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=205) THEN
        RAISE EXCEPTION 'MIGRATION_0206_PREDECESSOR_0205_REQUIRED';
    END IF;
END $migration$;

GRANT SELECT (workspace_id,application_id,dimension_id,member_id,name,status,
              read_security_tags,write_security_tags)
    ON epm.member TO epm_security;

CREATE POLICY member_security_read
    ON epm.member FOR SELECT TO epm_security
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
