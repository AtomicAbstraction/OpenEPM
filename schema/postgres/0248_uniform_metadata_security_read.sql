-- Narrow security-plane readback for the uniform Dimension and Relationship
-- Security String. RLS still requires exact server-set application scope.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=247) THEN
        RAISE EXCEPTION 'MIGRATION_0248_PREDECESSOR_0247_REQUIRED';
    END IF;
END $migration$;

GRANT SELECT (workspace_id,application_id,dimension_id,name,status,
              read_security_tags,write_security_tags)
    ON epm.dimension TO epm_security;

GRANT SELECT (workspace_id,application_id,relationship_id,dimension_id,name,
              status,read_security_tags,write_security_tags)
    ON epm.relationship TO epm_security;

CREATE POLICY relationship_security_read
    ON epm.relationship FOR SELECT TO epm_security
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
