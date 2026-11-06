-- Deployment trust root and scoped first-workspace provisioning. The owner
-- enrolls the first verified platform operator once during installation.
CREATE TABLE epm.platform_operator_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,subject_id)
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_provision') THEN
        CREATE ROLE epm_provision NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA epm TO epm_provision;
GRANT SELECT ON epm.platform_operator_grant, epm.workspace TO epm_provision;
GRANT INSERT ON epm.workspace, epm.workspace_access_grant,
    epm.security_audit TO epm_provision;
GRANT USAGE ON SEQUENCE epm.security_audit_audit_id_seq TO epm_provision;

ALTER TABLE epm.platform_operator_grant ENABLE ROW LEVEL SECURITY;
CREATE POLICY platform_operator_provision_read ON epm.platform_operator_grant
    FOR SELECT TO epm_provision USING (true);
CREATE POLICY workspace_provision_read ON epm.workspace
    FOR SELECT TO epm_provision
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY workspace_provision_insert ON epm.workspace
    FOR INSERT TO epm_provision
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY workspace_admin_provision_insert ON epm.workspace_access_grant
    FOR INSERT TO epm_provision
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true));

CREATE TABLE epm.platform_workspace_receipt (
    operation_id text PRIMARY KEY CHECK (length(operation_id) BETWEEN 1 AND 200),
    command_digest text NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    actor_digest text NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
    result jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
ALTER TABLE epm.platform_workspace_receipt ENABLE ROW LEVEL SECURITY;
CREATE POLICY platform_workspace_receipt_provision
    ON epm.platform_workspace_receipt TO epm_provision
    USING (true) WITH CHECK (true);
GRANT SELECT, INSERT ON epm.platform_workspace_receipt TO epm_provision;
