-- Permit the security plane to enumerate only the active dimension identity
-- fields required to construct the dimensional-tag administration catalogue.
-- RLS still requires the server-set exact workspace/application context.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=206) THEN
        RAISE EXCEPTION 'MIGRATION_0207_PREDECESSOR_0206_REQUIRED';
    END IF;
END $migration$;

GRANT SELECT (workspace_id,application_id,dimension_id,name,model_role,status,
              created_at)
    ON epm.dimension TO epm_security;

CREATE POLICY dimension_security_read
    ON epm.dimension FOR SELECT TO epm_security
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
