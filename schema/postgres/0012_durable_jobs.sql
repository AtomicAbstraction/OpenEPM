-- Durable application jobs and same-application dependency edges. Publication
-- still requires a future fixed-core effect transaction and pointer contract.

CREATE TABLE epm.job (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    job_id text NOT NULL CHECK (job_id ~ '^[0-9a-f]{32}$'),
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300),
    idempotency_key text NOT NULL
        CHECK (idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    function_name text NOT NULL CHECK (length(function_name) BETWEEN 1 AND 200),
    normalized_program jsonb NOT NULL
        CHECK (jsonb_typeof(normalized_program) = 'object'
           AND octet_length(normalized_program::text) <= 8500000),
    compiler_version text NOT NULL CHECK (length(compiler_version) BETWEEN 1 AND 80),
    program_digest text NOT NULL CHECK (program_digest ~ '^[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    plan_digest text NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    expected_metadata_revision bigint NOT NULL CHECK (expected_metadata_revision >= 0),
    expected_data_revision bigint NOT NULL CHECK (expected_data_revision >= 0),
    expected_policy_revision bigint NOT NULL CHECK (expected_policy_revision >= 0),
    resource_class text NOT NULL CHECK (resource_class IN ('short','medium','long')),
    status text NOT NULL CHECK (status IN
        ('accepted','ready','running','staged','published','failed',
         'cancel_requested','cancelled','needs_inspection')),
    claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claimant text CHECK (claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    receipt_revision bigint CHECK (receipt_revision IS NULL OR receipt_revision > 0),
    error_code text,
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id, application_id, job_id),
    UNIQUE (workspace_id, application_id, issuer, subject_id, idempotency_key),
    FOREIGN KEY (workspace_id, application_id)
        REFERENCES epm.application_state(workspace_id, application_id)
        ON DELETE RESTRICT,
    CHECK ((status = 'running') = (claimant IS NOT NULL AND lease_until IS NOT NULL))
);

CREATE TABLE epm.job_dependency (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    job_id text NOT NULL,
    depends_on_job_id text NOT NULL,
    PRIMARY KEY (workspace_id, application_id, job_id, depends_on_job_id),
    FOREIGN KEY (workspace_id, application_id, job_id)
        REFERENCES epm.job(workspace_id, application_id, job_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, application_id, depends_on_job_id)
        REFERENCES epm.job(workspace_id, application_id, job_id)
        ON DELETE RESTRICT,
    CHECK (job_id <> depends_on_job_id)
);
CREATE INDEX job_ready_queue ON epm.job
    (status, resource_class, created_at, workspace_id, application_id)
    WHERE status IN ('accepted','ready','running','cancel_requested');
CREATE INDEX job_dependency_predecessor ON epm.job_dependency
    (workspace_id, application_id, depends_on_job_id);

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_worker') THEN
        CREATE ROLE epm_worker NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA epm TO epm_worker;
GRANT SELECT, INSERT ON epm.job, epm.job_dependency TO epm_runtime;
GRANT UPDATE ON epm.job TO epm_runtime;
GRANT SELECT, UPDATE ON epm.job TO epm_worker;
GRANT SELECT ON epm.job_dependency, epm.operation_receipt TO epm_worker;

ALTER TABLE epm.job ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.job_dependency ENABLE ROW LEVEL SECURITY;
CREATE POLICY job_runtime_scope ON epm.job TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY dependency_runtime_scope ON epm.job_dependency TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY job_worker_scope ON epm.job TO epm_worker
    USING (true) WITH CHECK (true);
CREATE POLICY dependency_worker_scope ON epm.job_dependency FOR SELECT TO epm_worker
    USING (true);
CREATE POLICY receipt_worker_scope ON epm.operation_receipt FOR SELECT TO epm_worker
    USING (true);
