-- PostgreSQL authorization foundation. Identity is a verified issuer/subject
-- pair supplied by the server's authenticator, never an email or role payload.

CREATE TABLE epm.workspace_access_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    workspace_id text NOT NULL REFERENCES epm.workspace(workspace_id)
        ON DELETE RESTRICT,
    role text NOT NULL CHECK (role = 'Administrator'),
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer, subject_id, workspace_id)
);
CREATE INDEX workspace_access_grant_scope
    ON epm.workspace_access_grant(workspace_id, issuer, subject_id);

CREATE TABLE epm.application_access_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('Reader', 'Editor', 'Administrator')),
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer, subject_id, workspace_id, application_id),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application(workspace_id, application_id)
        ON DELETE RESTRICT
);
CREATE INDEX application_access_grant_scope
    ON epm.application_access_grant(workspace_id, application_id, role);

CREATE TABLE epm.rule_access_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    can_design boolean NOT NULL DEFAULT false,
    can_publish boolean NOT NULL DEFAULT false,
    can_run boolean NOT NULL DEFAULT false,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer, subject_id, workspace_id, application_id),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application(workspace_id, application_id)
        ON DELETE RESTRICT
);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_access') THEN
        CREATE ROLE epm_access NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA epm TO epm_access;
GRANT SELECT ON epm.workspace, epm.application,
    epm.workspace_access_grant, epm.application_access_grant,
    epm.rule_access_grant TO epm_access;

-- The access service needs cross-application lookup to authenticate and
-- discover grants. Its credential belongs only to fixed server code.
CREATE POLICY workspace_access_lookup ON epm.workspace TO epm_access
    USING (true);
CREATE POLICY application_access_lookup ON epm.application TO epm_access
    USING (true);
