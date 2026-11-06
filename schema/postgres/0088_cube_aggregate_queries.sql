-- Durable read-query lifecycle for facts.cube.aggregate.*.  Public routing is
-- integrated separately; schema presence alone exposes no executable function.

CREATE TABLE epm.cube_aggregate_query (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    query_id text NOT NULL CHECK(length(query_id) BETWEEN 1 AND 200),
    issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 200),
    subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 200),
    request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),
    plan_digest text NOT NULL CHECK(plan_digest~'^[0-9a-f]{64}$'),
    normalized_request jsonb NOT NULL CHECK(jsonb_typeof(normalized_request)='object'),
    status text NOT NULL CHECK(status IN
        ('accepted','ready','running','computed','sealed','cancel_requested',
         'cancelled','failed','expired')),
    max_groups integer NOT NULL CHECK(max_groups BETWEEN 1 AND 100000),
    max_result_bytes integer NOT NULL CHECK(max_result_bytes BETWEEN 1 AND 33554432),
    page_size integer NOT NULL CHECK(page_size BETWEEN 1 AND 500),
    ttl_seconds integer NOT NULL CHECK(ttl_seconds BETWEEN 1 AND 900),
    accepted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    source_commit_revision bigint,
    source_data_revision bigint,
    source_metadata_revision bigint,
    source_policy_revision bigint,
    source_schema_epoch bigint,
    source_projection_generation bigint,
    backend_profile text,
    hierarchy_digest text,
    result_digest text,
    result_group_count integer,
    result_bytes integer,
    error_code text,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,query_id),
    CONSTRAINT cube_aggregate_query_application_fkey
        FOREIGN KEY(workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
    CONSTRAINT cube_aggregate_query_identity_key
        UNIQUE(workspace_id,application_id,issuer,subject_id,request_digest),
    CHECK(expires_at=accepted_at+ttl_seconds*interval '1 second'),
    CHECK((status='failed' AND error_code IS NOT NULL AND length(error_code) BETWEEN 1 AND 200)
       OR (status<>'failed' AND error_code IS NULL)),
    CHECK((source_commit_revision IS NULL AND source_data_revision IS NULL
         AND source_metadata_revision IS NULL AND source_policy_revision IS NULL
         AND source_schema_epoch IS NULL AND source_projection_generation IS NULL
         AND backend_profile IS NULL AND hierarchy_digest IS NULL
         AND result_digest IS NULL AND result_group_count IS NULL
         AND result_bytes IS NULL)
       OR (source_commit_revision IS NOT NULL AND source_data_revision IS NOT NULL
         AND source_metadata_revision IS NOT NULL AND source_policy_revision IS NOT NULL
         AND source_schema_epoch IS NOT NULL AND source_projection_generation IS NOT NULL
         AND backend_profile IS NOT NULL AND hierarchy_digest~'^[0-9a-f]{64}$'
         AND result_digest~'^[0-9a-f]{64}$' AND result_group_count IS NOT NULL
         AND result_bytes IS NOT NULL)),
    -- A computed certificate remains useful technical evidence after expiry or
    -- cancellation.  It is not a business receipt and cannot authorize effects.
    CHECK(status NOT IN ('computed','sealed','expired') OR result_digest IS NOT NULL),
    CHECK(source_commit_revision IS NULL OR source_commit_revision>=0),
    CHECK(source_data_revision IS NULL OR source_data_revision>=0),
    CHECK(source_metadata_revision IS NULL OR source_metadata_revision>=0),
    CHECK(source_policy_revision IS NULL OR source_policy_revision>=0),
    CHECK(source_schema_epoch IS NULL OR source_schema_epoch>=0),
    CHECK(source_projection_generation IS NULL OR source_projection_generation>=0),
    CHECK(result_group_count IS NULL OR result_group_count BETWEEN 0 AND max_groups),
    CHECK(result_bytes IS NULL OR result_bytes BETWEEN 0 AND max_result_bytes)
);

CREATE INDEX cube_aggregate_query_ready
    ON epm.cube_aggregate_query(status,accepted_at,workspace_id,application_id)
    WHERE status IN ('accepted','ready','running','cancel_requested','computed');
CREATE INDEX cube_aggregate_query_expiry
    ON epm.cube_aggregate_query(expires_at,workspace_id,application_id)
    WHERE status='sealed';

CREATE TABLE epm.cube_aggregate_result (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    query_id text NOT NULL,
    ordinal integer NOT NULL CHECK(ordinal>=1),
    members jsonb NOT NULL CHECK(jsonb_typeof(members)='object'),
    sum_amount numeric(38,8),
    count_present bigint CHECK(count_present IS NULL OR count_present>=0),
    row_bytes integer NOT NULL CHECK(row_bytes>0),
    PRIMARY KEY(workspace_id,application_id,query_id,ordinal),
    CONSTRAINT cube_aggregate_result_query_fkey
        FOREIGN KEY(workspace_id,application_id,query_id)
        REFERENCES epm.cube_aggregate_query(workspace_id,application_id,query_id)
        ON DELETE CASCADE,
    CHECK(sum_amount IS NOT NULL OR count_present IS NOT NULL)
);

ALTER TABLE epm.cube_aggregate_query ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.cube_aggregate_result ENABLE ROW LEVEL SECURITY;

CREATE POLICY cube_aggregate_query_runtime_scope ON epm.cube_aggregate_query
    TO epm_runtime
    USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));
CREATE POLICY cube_aggregate_result_runtime_scope ON epm.cube_aggregate_result
    TO epm_runtime
    USING(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
      AND application_id=current_setting('epm.application_id',true));

-- Lifecycle can inventory these technical rows for its current workspace.
-- Deletion remains inside the reviewed owner-only reset primitive; ordinary
-- lifecycle credentials must not acquire a parallel destructive path.
CREATE POLICY cube_aggregate_query_lifecycle_scope ON epm.cube_aggregate_query
    TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY cube_aggregate_result_lifecycle_scope ON epm.cube_aggregate_result
    TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.cube_aggregate_query,epm.cube_aggregate_result
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.cube_aggregate_query TO epm_runtime;
GRANT SELECT,INSERT,DELETE ON epm.cube_aggregate_result TO epm_runtime;
GRANT SELECT ON epm.cube_aggregate_query,epm.cube_aggregate_result TO epm_lifecycle;

