-- Server-owned rolling-forecast occurrences and progress. Public scheduling
-- remains fail-closed until the coordinator and function catalog are wired.

CREATE TABLE epm.planning_forecast_progress (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    definition_id text NOT NULL,
    definition_version bigint NOT NULL CHECK(definition_version > 0),
    committed_sequence bigint NOT NULL DEFAULT 0 CHECK(committed_sequence >= 0),
    window_start date NOT NULL,
    actual_through date NOT NULL,
    window_end_exclusive date NOT NULL,
    last_operation_id text,
    state_revision bigint NOT NULL CHECK(state_revision > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,definition_id),
    CONSTRAINT forecast_progress_definition_fkey FOREIGN KEY
        (workspace_id,application_id,definition_id,definition_version)
        REFERENCES epm.planning_forecast_definition_version
        (workspace_id,application_id,definition_id,version) ON DELETE RESTRICT,
    CONSTRAINT forecast_progress_receipt_fkey FOREIGN KEY
        (workspace_id,application_id,last_operation_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT,
    CHECK(window_start <= actual_through
      AND actual_through <= window_end_exclusive),
    CHECK((committed_sequence=0 AND last_operation_id IS NULL)
       OR (committed_sequence>0 AND last_operation_id IS NOT NULL))
);

-- The scheduler stores typed, bounded due intent.  It does not store Python,
-- SQL, a cron command, or an authored identity asserted without verification.
CREATE TABLE epm.planning_forecast_schedule_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    schedule_id text NOT NULL
        CHECK(schedule_id ~ '^[A-Za-z0-9._-]{1,100}$'),
    version bigint NOT NULL CHECK(version > 0),
    definition_id text NOT NULL,
    definition_version bigint NOT NULL CHECK(definition_version > 0),
    interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2678400),
    first_due_at timestamptz NOT NULL,
    catch_up_policy text NOT NULL CHECK(catch_up_policy IN ('skip','latest','all')),
    max_catch_up integer NOT NULL CHECK(max_catch_up BETWEEN 1 AND 36),
    execution_issuer text NOT NULL CHECK(length(execution_issuer) BETWEEN 1 AND 300),
    execution_subject text NOT NULL CHECK(length(execution_subject) BETWEEN 1 AND 300),
    delegation_id text NOT NULL CHECK(length(delegation_id) BETWEEN 1 AND 200),
    operation_id text NOT NULL,
    created_revision bigint NOT NULL CHECK(created_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,schedule_id,version),
    CONSTRAINT forecast_schedule_definition_fkey FOREIGN KEY
        (workspace_id,application_id,definition_id,definition_version)
        REFERENCES epm.planning_forecast_definition_version
        (workspace_id,application_id,definition_id,version) ON DELETE RESTRICT,
    CONSTRAINT forecast_schedule_receipt_fkey FOREIGN KEY
        (workspace_id,application_id,operation_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

CREATE TABLE epm.planning_forecast_schedule_state (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    schedule_id text NOT NULL,
    latest_version bigint NOT NULL CHECK(latest_version > 0),
    active_version bigint CHECK(active_version > 0 AND active_version <= latest_version),
    last_due_at timestamptz,
    state_revision bigint NOT NULL CHECK(state_revision > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,schedule_id),
    CONSTRAINT forecast_schedule_latest_fkey FOREIGN KEY
        (workspace_id,application_id,schedule_id,latest_version)
        REFERENCES epm.planning_forecast_schedule_version
        (workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
    CONSTRAINT forecast_schedule_active_fkey FOREIGN KEY
        (workspace_id,application_id,schedule_id,active_version)
        REFERENCES epm.planning_forecast_schedule_version
        (workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT
);

CREATE TABLE epm.planning_forecast_occurrence (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    occurrence_id text NOT NULL CHECK(occurrence_id ~ '^[0-9a-f]{32}$'),
    definition_id text NOT NULL,
    definition_version bigint NOT NULL CHECK(definition_version > 0),
    progress_sequence bigint NOT NULL CHECK(progress_sequence > 0),
    schedule_id text,
    schedule_version bigint,
    due_at timestamptz NOT NULL,
    execution_issuer text NOT NULL CHECK(length(execution_issuer) BETWEEN 1 AND 300),
    execution_subject text NOT NULL CHECK(length(execution_subject) BETWEEN 1 AND 300),
    delegation_id text NOT NULL CHECK(length(delegation_id) BETWEEN 1 AND 200),
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    normalized_program jsonb NOT NULL
        CHECK(jsonb_typeof(normalized_program)='object'
          AND octet_length(normalized_program::text) <= 4194304
          AND normalized_program->>'function'='facts.planning.forecast.roll.apply'
          AND normalized_program->'languageVersion'='2'::jsonb),
    -- Fixed core computes this over the shared compact canonical JSON bytes.
    -- PostgreSQL jsonb::text has a different serialization and must not
    -- manufacture a second, incompatible digest identity.
    program_digest text NOT NULL CHECK(program_digest ~ '^[0-9a-f]{64}$'),
    inner_idempotency_key text NOT NULL
        CHECK(inner_idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    metadata_revision bigint NOT NULL CHECK(metadata_revision >= 0),
    data_revision bigint NOT NULL CHECK(data_revision >= 0),
    policy_revision bigint NOT NULL CHECK(policy_revision >= 0),
    schema_epoch bigint NOT NULL CHECK(schema_epoch >= 0),
    definition_state_revision bigint NOT NULL CHECK(definition_state_revision >= 0),
    calendar_digest text NOT NULL CHECK(calendar_digest ~ '^[0-9a-f]{64}$'),
    calendar_selection jsonb NOT NULL
        CHECK(jsonb_typeof(calendar_selection)='array'
          AND jsonb_array_length(calendar_selection) BETWEEN 1 AND 36
          AND octet_length(calendar_selection::text) <= 262144),
    next_window_start date NOT NULL,
    next_actual_through date NOT NULL,
    next_window_end_exclusive date NOT NULL,
    status text NOT NULL CHECK(status IN
        ('accepted','ready','running','cancel_requested','cancelled',
         'business_published','progress_committed','needs_inspection','failed')),
    claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation >= 0),
    claimant text CHECK(claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
    lease_until timestamptz,
    batch_id text,
    publication_operation_id text,
    publication_command_digest text,
    publication_result_digest text,
    committed_revision bigint,
    error_code text CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,occurrence_id),
    UNIQUE(workspace_id,application_id,definition_id,progress_sequence),
    UNIQUE(workspace_id,application_id,schedule_id,schedule_version,due_at),
    UNIQUE(workspace_id,application_id,execution_issuer,execution_subject,
           inner_idempotency_key),
    CONSTRAINT forecast_occurrence_definition_fkey FOREIGN KEY
        (workspace_id,application_id,definition_id,definition_version)
        REFERENCES epm.planning_forecast_definition_version
        (workspace_id,application_id,definition_id,version) ON DELETE RESTRICT,
    CONSTRAINT forecast_occurrence_schedule_fkey FOREIGN KEY
        (workspace_id,application_id,schedule_id,schedule_version)
        REFERENCES epm.planning_forecast_schedule_version
        (workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
    CONSTRAINT forecast_occurrence_receipt_fkey FOREIGN KEY
        (workspace_id,application_id,publication_operation_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT,
    CHECK((schedule_id IS NULL)=(schedule_version IS NULL)),
    CHECK(next_window_start <= next_actual_through
      AND next_actual_through <= next_window_end_exclusive),
    CHECK((status IN ('running','cancel_requested'))=
          (claimant IS NOT NULL AND lease_until IS NOT NULL)),
    CHECK((status='failed' AND error_code IS NOT NULL)
       OR (status<>'failed' AND error_code IS NULL)),
    CHECK((status IN ('business_published','progress_committed','needs_inspection'))
        = (batch_id IS NOT NULL AND publication_operation_id IS NOT NULL
           AND publication_command_digest ~ '^[0-9a-f]{64}$'
           AND publication_result_digest ~ '^[0-9a-f]{64}$'
           AND committed_revision > 0))
);

CREATE INDEX planning_forecast_occurrence_ready
    ON epm.planning_forecast_occurrence
    (status,due_at,workspace_id,application_id)
    WHERE status IN ('accepted','ready','running','cancel_requested','business_published','needs_inspection');
CREATE INDEX planning_forecast_occurrence_lease
    ON epm.planning_forecast_occurrence(lease_until,workspace_id,application_id)
    WHERE status='running';

ALTER TABLE epm.planning_forecast_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_forecast_schedule_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_forecast_schedule_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_forecast_occurrence ENABLE ROW LEVEL SECURITY;

CREATE POLICY forecast_progress_runtime_scope ON epm.planning_forecast_progress
    TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));
CREATE POLICY forecast_schedule_version_runtime_scope ON epm.planning_forecast_schedule_version
    TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));
CREATE POLICY forecast_schedule_state_runtime_scope ON epm.planning_forecast_schedule_state
    TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));
CREATE POLICY forecast_occurrence_runtime_scope ON epm.planning_forecast_occurrence
    TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));
CREATE POLICY forecast_occurrence_worker_scope ON epm.planning_forecast_occurrence
    TO epm_worker USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));

CREATE POLICY forecast_progress_lifecycle_inventory ON epm.planning_forecast_progress
    TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY forecast_schedule_version_lifecycle_inventory ON epm.planning_forecast_schedule_version
    TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY forecast_schedule_state_lifecycle_inventory ON epm.planning_forecast_schedule_state
    TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY forecast_occurrence_lifecycle_inventory ON epm.planning_forecast_occurrence
    TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.planning_forecast_progress,
    epm.planning_forecast_schedule_version,
    epm.planning_forecast_schedule_state,
    epm.planning_forecast_occurrence
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_forecast_progress,
    epm.planning_forecast_schedule_version,
    epm.planning_forecast_schedule_state,
    epm.planning_forecast_occurrence TO epm_runtime;
GRANT UPDATE ON epm.planning_forecast_progress,
    epm.planning_forecast_schedule_state,
    epm.planning_forecast_occurrence TO epm_runtime;
GRANT SELECT,UPDATE(status,claim_generation,claimant,lease_until,batch_id,
    publication_operation_id,publication_command_digest,
    publication_result_digest,committed_revision,error_code,updated_at)
    ON epm.planning_forecast_occurrence TO epm_worker;
GRANT SELECT(workspace_id,application_id,definition_id,definition_version,
    committed_sequence,state_revision) ON epm.planning_forecast_progress TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,schedule_id,version)
    ON epm.planning_forecast_schedule_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,schedule_id,latest_version,active_version,state_revision)
    ON epm.planning_forecast_schedule_state TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,occurrence_id,status)
    ON epm.planning_forecast_occurrence TO epm_lifecycle;
