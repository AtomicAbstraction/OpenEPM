-- A separate non-owner service may create blank applications only inside an
-- already provisioned workspace. It cannot create workspaces or write facts.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_lifecycle') THEN
        CREATE ROLE epm_lifecycle NOLOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA epm TO epm_lifecycle;
GRANT SELECT ON epm.workspace, epm.workspace_access_grant,
    epm.application TO epm_lifecycle;
GRANT INSERT ON epm.application, epm.application_state,
    epm.application_access_grant, epm.security_audit TO epm_lifecycle;
GRANT USAGE ON SEQUENCE epm.security_audit_audit_id_seq TO epm_lifecycle;

CREATE POLICY workspace_lifecycle_read ON epm.workspace FOR SELECT
    TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY workspace_grant_lifecycle_read ON epm.workspace_access_grant
    FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_lifecycle_read ON epm.application FOR SELECT
    TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_lifecycle_insert ON epm.application FOR INSERT
    TO epm_lifecycle
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_state_lifecycle_insert ON epm.application_state
    FOR INSERT TO epm_lifecycle
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_grant_lifecycle_insert
    ON epm.application_access_grant FOR INSERT TO epm_lifecycle
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));

CREATE TABLE epm.workspace_lifecycle_receipt (
    workspace_id text NOT NULL REFERENCES epm.workspace(workspace_id)
        ON DELETE RESTRICT,
    operation_id text NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 200),
    command_digest text NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    actor_digest text NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
    result jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,operation_id)
);
ALTER TABLE epm.workspace_lifecycle_receipt ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_lifecycle_receipt_scope
    ON epm.workspace_lifecycle_receipt TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true));
GRANT SELECT,INSERT ON epm.workspace_lifecycle_receipt TO epm_lifecycle;
