-- Durable application-scoped numeric source staging. Only fixed-core code
-- validates and publishes these rows; staging is never a fact write.

CREATE TABLE epm.source_batch (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    batch_id text NOT NULL CHECK (batch_id ~ '^[0-9a-f]{32}$'),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    idempotency_key text NOT NULL
        CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    mode text NOT NULL CHECK (mode IN ('merge','replace')),
    scope_members jsonb NOT NULL CHECK (jsonb_typeof(scope_members)='object'),
    scope_all boolean NOT NULL,
    expected_metadata_revision bigint NOT NULL CHECK (expected_metadata_revision>=0),
    expected_data_revision bigint NOT NULL CHECK (expected_data_revision>=0),
    status text NOT NULL CHECK (status IN ('staging','ready','published','failed')),
    chunk_count integer NOT NULL DEFAULT 0 CHECK (chunk_count BETWEEN 0 AND 1000),
    row_count integer NOT NULL DEFAULT 0 CHECK (row_count BETWEEN 0 AND 100000),
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    receipt_revision bigint CHECK (receipt_revision IS NULL OR receipt_revision>0),
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,batch_id),
    UNIQUE (workspace_id,application_id,issuer,subject_id,idempotency_key),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id)
        ON DELETE RESTRICT,
    CHECK (scope_all = (scope_members='{}'::jsonb))
);

CREATE TABLE epm.source_batch_chunk (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    batch_id text NOT NULL,
    chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 999),
    row_count integer NOT NULL CHECK (row_count BETWEEN 1 AND 500),
    chunk_digest text NOT NULL CHECK (chunk_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,batch_id,chunk_index),
    FOREIGN KEY (workspace_id,application_id,batch_id)
        REFERENCES epm.source_batch(workspace_id,application_id,batch_id)
        ON DELETE RESTRICT
);

CREATE TABLE epm.source_batch_row (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    batch_id text NOT NULL,
    row_ordinal bigint NOT NULL CHECK (row_ordinal BETWEEN 1 AND 100000),
    series_key text NOT NULL CHECK (series_key ~ '^[0-9a-f]{64}$'),
    members jsonb NOT NULL CHECK (jsonb_typeof(members)='object'),
    amount numeric(28,8) NOT NULL,
    source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 200),
    PRIMARY KEY (workspace_id,application_id,batch_id,row_ordinal),
    UNIQUE (workspace_id,application_id,batch_id,series_key),
    FOREIGN KEY (workspace_id,application_id,batch_id)
        REFERENCES epm.source_batch(workspace_id,application_id,batch_id)
        ON DELETE RESTRICT
);
CREATE INDEX source_batch_ready ON epm.source_batch
    (workspace_id,application_id,status,created_at);

GRANT SELECT,INSERT,UPDATE ON epm.source_batch TO epm_runtime;
GRANT SELECT,INSERT ON epm.source_batch_chunk,
    epm.source_batch_row TO epm_runtime;
ALTER TABLE epm.source_batch ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.source_batch_chunk ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.source_batch_row ENABLE ROW LEVEL SECURITY;
CREATE POLICY source_batch_scope ON epm.source_batch TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY source_batch_chunk_scope ON epm.source_batch_chunk TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY source_batch_row_scope ON epm.source_batch_row TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
