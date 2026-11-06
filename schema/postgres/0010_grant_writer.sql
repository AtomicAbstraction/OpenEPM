-- Non-owner fixed-core security writer. Admission/effects hold a shared
-- workspace advisory transaction lock; grant changes take it exclusively.
-- The security role has no fact or metadata write privileges.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_security') THEN
        CREATE ROLE epm_security NOLOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA epm TO epm_security;
GRANT SELECT ON epm.workspace, epm.application,
    epm.workspace_access_grant, epm.application_access_grant,
    epm.rule_access_grant TO epm_security;
GRANT INSERT, UPDATE, DELETE ON epm.application_access_grant,
    epm.rule_access_grant TO epm_security;
GRANT INSERT ON epm.security_audit TO epm_security;
GRANT USAGE ON SEQUENCE epm.security_audit_audit_id_seq TO epm_security;

CREATE POLICY workspace_security_lookup ON epm.workspace TO epm_security
    USING (true);
CREATE POLICY application_security_lookup ON epm.application TO epm_security
    USING (true);

CREATE TABLE epm.security_operation_receipt (
    workspace_id text NOT NULL REFERENCES epm.workspace(workspace_id)
        ON DELETE RESTRICT,
    operation_id text NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 200),
    command_digest text NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    actor_digest text NOT NULL CHECK (actor_digest ~ '^[0-9a-f]{64}$'),
    action text NOT NULL CHECK (action IN ('application.grant',
                                           'application.revoke')),
    result jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, operation_id)
);
GRANT SELECT, INSERT ON epm.security_operation_receipt TO epm_security;
