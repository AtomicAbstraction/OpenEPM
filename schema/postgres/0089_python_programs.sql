-- Immutable Python-authored program definitions and technical build control.
-- Public routing and the isolated launcher are integrated separately.
-- Untrusted builders never receive this database role or a database credential.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='epm_python_coordinator') THEN
        CREATE ROLE epm_python_coordinator NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA epm TO epm_python_coordinator;

CREATE TABLE epm.python_environment_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL
        CHECK(environment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    version integer NOT NULL CHECK(version > 0),
    manifest jsonb NOT NULL
        CHECK(jsonb_typeof(manifest)='object'
          AND octet_length(manifest::text) <= 1048576),
    manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$'),
    image_digest text NOT NULL CHECK(image_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_operation_id text NOT NULL,
    created_revision bigint NOT NULL CHECK(created_revision > 0),
    created_issuer text NOT NULL CHECK(length(created_issuer) BETWEEN 1 AND 300),
    created_subject_id text NOT NULL CHECK(length(created_subject_id) BETWEEN 1 AND 300),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,environment_id,version),
    FOREIGN KEY(workspace_id,application_id)
      REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,created_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT
);

CREATE TABLE epm.python_environment_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    environment_id text NOT NULL,
    version integer NOT NULL,
    status text NOT NULL CHECK(status IN ('Active','Inactive')),
    operation_id text NOT NULL,
    revision bigint NOT NULL CHECK(revision > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,environment_id),
    FOREIGN KEY(workspace_id,application_id,environment_id,version)
      REFERENCES epm.python_environment_version
        (workspace_id,application_id,environment_id,version) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT
);

CREATE TABLE epm.python_program_version (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    program_id text NOT NULL
        CHECK(program_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
    version integer NOT NULL CHECK(version > 0),
    source_text text NOT NULL
        CHECK(octet_length(source_text) BETWEEN 1 AND 1048576),
    source_digest text NOT NULL CHECK(source_digest ~ '^[0-9a-f]{64}$'),
    entry_point text NOT NULL
        CHECK(entry_point ~ '^[A-Za-z_][A-Za-z0-9_]{0,99}$'),
    parameter_schema jsonb NOT NULL
        CHECK(jsonb_typeof(parameter_schema)='object'
          AND octet_length(parameter_schema::text) <= 262144),
    environment_id text NOT NULL,
    environment_version integer NOT NULL,
    created_operation_id text NOT NULL,
    created_revision bigint NOT NULL CHECK(created_revision > 0),
    created_issuer text NOT NULL CHECK(length(created_issuer) BETWEEN 1 AND 300),
    created_subject_id text NOT NULL CHECK(length(created_subject_id) BETWEEN 1 AND 300),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,program_id,version),
    FOREIGN KEY(workspace_id,application_id,environment_id,environment_version)
      REFERENCES epm.python_environment_version
        (workspace_id,application_id,environment_id,version) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,created_operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT
);

CREATE TABLE epm.python_program_publication (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    program_id text NOT NULL,
    version integer NOT NULL,
    status text NOT NULL CHECK(status IN ('Published','Deactivated')),
    operation_id text NOT NULL,
    revision bigint NOT NULL CHECK(revision > 0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,program_id),
    FOREIGN KEY(workspace_id,application_id,program_id,version)
      REFERENCES epm.python_program_version
        (workspace_id,application_id,program_id,version) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,operation_id)
      REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
      ON DELETE RESTRICT
);

-- A build is technical work.  Its completion is certified by a sealed plan
-- artifact, not by an epm.operation_receipt and not by a business revision.
CREATE TABLE epm.python_program_build (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    build_id text NOT NULL CHECK(build_id ~ '^[0-9a-f]{32}$'),
    issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
    idempotency_key text NOT NULL
        CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    program_id text NOT NULL,
    program_version integer NOT NULL,
    parameter_values jsonb NOT NULL
        CHECK(jsonb_typeof(parameter_values)='object'
          AND octet_length(parameter_values::text) <= 1048576),
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    expected_metadata_revision bigint NOT NULL CHECK(expected_metadata_revision >= 0),
    expected_policy_revision bigint NOT NULL CHECK(expected_policy_revision >= 0),
    expected_schema_epoch bigint NOT NULL CHECK(expected_schema_epoch >= 0),
    status text NOT NULL CHECK(status IN
        ('accepted','ready','running','sealed','failed','cancel_requested','cancelled')),
    claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation >= 0),
    claimant text CHECK(claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
    lease_until timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    error_code text CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,build_id),
    UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
    FOREIGN KEY(workspace_id,application_id,program_id,program_version)
      REFERENCES epm.python_program_version
        (workspace_id,application_id,program_id,version) ON DELETE RESTRICT,
    CHECK((status IN ('running','cancel_requested')) =
          (claimant IS NOT NULL AND lease_until IS NOT NULL))
);

CREATE TABLE epm.python_plan_artifact (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    build_id text NOT NULL,
    format text NOT NULL CHECK(format='openepm-python-plan-v1'),
    canonical_plan jsonb NOT NULL
        CHECK(jsonb_typeof(canonical_plan)='object'
          AND octet_length(canonical_plan::text) <= 4194304),
    plan_digest text NOT NULL CHECK(plan_digest ~ '^[0-9a-f]{64}$'),
    source_map jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK(jsonb_typeof(source_map)='object'
          AND octet_length(source_map::text) <= 1048576),
    build_log text NOT NULL DEFAULT ''
        CHECK(octet_length(build_log) <= 1048576),
    compiler_version text NOT NULL CHECK(length(compiler_version) BETWEEN 1 AND 80),
    sealed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,build_id),
    UNIQUE(workspace_id,application_id,plan_digest),
    FOREIGN KEY(workspace_id,application_id,build_id)
      REFERENCES epm.python_program_build(workspace_id,application_id,build_id)
      ON DELETE RESTRICT
);

-- The workflow records business execution state separately from build state.
-- Child jobs retain their own ordinary receipt/publication contracts.
CREATE TABLE epm.python_program_workflow (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    workflow_id text NOT NULL CHECK(workflow_id ~ '^[0-9a-f]{32}$'),
    build_id text NOT NULL,
    issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
    idempotency_key text NOT NULL
        CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK(status IN
        ('accepted','running','published','partially_published','failed',
         'cancel_requested','cancelled','needs_inspection')),
    result jsonb CHECK(result IS NULL OR jsonb_typeof(result)='object'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,workflow_id),
    UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
    FOREIGN KEY(workspace_id,application_id,build_id)
      REFERENCES epm.python_plan_artifact(workspace_id,application_id,build_id)
      ON DELETE RESTRICT
);

CREATE TABLE epm.python_program_workflow_child (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    workflow_id text NOT NULL,
    unit_ordinal integer NOT NULL CHECK(unit_ordinal BETWEEN 1 AND 10000),
    job_id text NOT NULL,
    PRIMARY KEY(workspace_id,application_id,workflow_id,unit_ordinal),
    UNIQUE(workspace_id,application_id,workflow_id,job_id),
    FOREIGN KEY(workspace_id,application_id,workflow_id)
      REFERENCES epm.python_program_workflow
        (workspace_id,application_id,workflow_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,job_id)
      REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE RESTRICT
);

CREATE INDEX python_build_ready_queue ON epm.python_program_build
    (status,created_at,workspace_id,application_id)
    WHERE status IN ('accepted','ready','running','cancel_requested');
CREATE INDEX python_workflow_child_job ON epm.python_program_workflow_child
    (workspace_id,application_id,job_id);

GRANT SELECT,INSERT ON epm.python_environment_version,
    epm.python_environment_current,epm.python_program_version,
    epm.python_program_publication,epm.python_program_build,
    epm.python_program_workflow,epm.python_program_workflow_child TO epm_runtime;
GRANT UPDATE(status,version,operation_id,revision,updated_at)
    ON epm.python_environment_current TO epm_runtime;
GRANT UPDATE(status,version,operation_id,revision,updated_at)
    ON epm.python_program_publication TO epm_runtime;
GRANT SELECT ON epm.python_plan_artifact TO epm_runtime;
GRANT UPDATE(status,updated_at) ON epm.python_program_build TO epm_runtime;
GRANT UPDATE(status,result,updated_at) ON epm.python_program_workflow TO epm_runtime;

GRANT SELECT ON epm.python_environment_version,epm.python_environment_current,
    epm.python_program_version,epm.python_program_publication TO epm_python_coordinator;
GRANT SELECT,UPDATE ON epm.python_program_build TO epm_python_coordinator;
GRANT SELECT,INSERT ON epm.python_plan_artifact TO epm_python_coordinator;

ALTER TABLE epm.python_environment_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_environment_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_publication ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_build ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_plan_artifact ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_workflow ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_workflow_child ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE v_table text;
BEGIN
    FOREACH v_table IN ARRAY ARRAY[
      'python_environment_version','python_environment_current',
      'python_program_version','python_program_publication','python_program_build',
      'python_plan_artifact','python_program_workflow','python_program_workflow_child']
    LOOP
        EXECUTE format(
          'CREATE POLICY %I ON epm.%I TO epm_runtime USING '
          '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
          'application_id=current_setting(''epm.application_id'',true)) WITH CHECK '
          '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
          'application_id=current_setting(''epm.application_id'',true))',
          v_table || '_runtime_scope',v_table);
    END LOOP;
END $$;

CREATE POLICY python_environment_version_coordinator_scope
  ON epm.python_environment_version FOR SELECT TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_environment_current_coordinator_scope
  ON epm.python_environment_current FOR SELECT TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_program_version_coordinator_scope
  ON epm.python_program_version FOR SELECT TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_program_publication_coordinator_scope
  ON epm.python_program_publication FOR SELECT TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_program_build_coordinator_scope
  ON epm.python_program_build TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_plan_artifact_coordinator_scope
  ON epm.python_plan_artifact TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));

COMMENT ON TABLE epm.python_program_build IS
  'Technical isolated-build state; completion does not imply a business receipt.';
COMMENT ON TABLE epm.python_plan_artifact IS
  'Bounded JSON plan sealed by the trusted coordinator; never executable Python serialization.';
