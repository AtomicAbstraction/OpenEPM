-- Open EPM PostgreSQL foundation. The migration runner supplies the transaction
-- and version/checksum record. Runtime principals must not own these tables.

CREATE SCHEMA epm;

CREATE TABLE epm.schema_migration (
    version integer PRIMARY KEY CHECK (version > 0),
    description text NOT NULL,
    checksum text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE epm.workspace (
    workspace_id text PRIMARY KEY CHECK (length(workspace_id) BETWEEN 1 AND 200),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Maintenance', 'Deleting')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);

CREATE TABLE epm.application (
    workspace_id text NOT NULL,
    application_id text NOT NULL CHECK (length(application_id) BETWEEN 1 AND 200),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind text NOT NULL DEFAULT 'blank' CHECK (length(kind) BETWEEN 1 AND 80),
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active', 'Maintenance', 'Deleting')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id),
    UNIQUE (workspace_id, name),
    FOREIGN KEY (workspace_id) REFERENCES epm.workspace(workspace_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.application_state (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    schema_epoch bigint NOT NULL DEFAULT 0 CHECK (schema_epoch >= 0),
    metadata_revision bigint NOT NULL DEFAULT 0 CHECK (metadata_revision >= 0),
    data_revision bigint NOT NULL DEFAULT 0 CHECK (data_revision >= 0),
    policy_revision bigint NOT NULL DEFAULT 0 CHECK (policy_revision >= 0),
    commit_revision bigint NOT NULL DEFAULT 0 CHECK (commit_revision >= 0),
    processing_mode text NOT NULL DEFAULT 'Active'
        CHECK (processing_mode IN ('Active', 'Maintenance', 'ReadOnly', 'Deleting')),
    PRIMARY KEY (workspace_id, application_id),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application(workspace_id, application_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.operation_receipt (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    operation_id text NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 200),
    command_digest text NOT NULL CHECK (command_digest ~ '^[0-9a-f]{64}$'),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 200),
    committed_revision bigint NOT NULL CHECK (committed_revision > 0),
    result jsonb NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, operation_id),
    UNIQUE (workspace_id, application_id, committed_revision),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application_state(workspace_id, application_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.security_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 200),
    action text NOT NULL CHECK (length(action) BETWEEN 1 AND 200),
    workspace_id text,
    application_id text,
    target_digest text,
    outcome text NOT NULL CHECK (outcome IN ('Accepted', 'Rejected', 'Failed')),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (application_id IS NULL OR workspace_id IS NOT NULL)
);

CREATE INDEX security_audit_scope_time
    ON epm.security_audit(workspace_id, application_id, occurred_at DESC);

