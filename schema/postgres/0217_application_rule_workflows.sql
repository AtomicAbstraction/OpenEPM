-- Durable execution state for published generic application rules.  The
-- sealed plan is fixed-core JSON, never authored Python or caller SQL.  Each
-- child remains an ordinary governed V2 job with its own business receipt.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=216) THEN
    RAISE EXCEPTION 'MIGRATION_0217_PREDECESSOR_0216_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.application_rule_workflow (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  workflow_id text NOT NULL CHECK(workflow_id ~ '^[0-9a-f]{32}$'),
  rule_id text NOT NULL
    CHECK(rule_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  rule_version bigint NOT NULL CHECK(rule_version > 0),
  program_digest text NOT NULL CHECK(program_digest ~ '^[0-9a-f]{64}$'),
  published_revision bigint NOT NULL CHECK(published_revision > 0),
  sealed_plan jsonb NOT NULL CHECK(jsonb_typeof(sealed_plan)='object'
    AND sealed_plan->>'format'='openepm-python-plan-v1'
    AND jsonb_typeof(sealed_plan->'units')='array'
    AND octet_length(sealed_plan::text) <= 4194304),
  plan_digest text NOT NULL CHECK(plan_digest ~ '^[0-9a-f]{64}$'),
  compiler_version text NOT NULL
    CHECK(length(compiler_version) BETWEEN 1 AND 80),
  expected_metadata_revision bigint NOT NULL CHECK(expected_metadata_revision>=0),
  expected_policy_revision bigint NOT NULL CHECK(expected_policy_revision>=0),
  expected_schema_epoch bigint NOT NULL CHECK(expected_schema_epoch>=0),
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
  subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
  idempotency_key text NOT NULL
    CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
  request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN
    ('accepted','running','published','partially_published','failed',
     'cancel_requested','cancelled','needs_inspection')),
  result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),
  claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),
  claimant text CHECK(claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
  lease_until timestamptz,
  worker_error_code text
    CHECK(worker_error_code IS NULL OR length(worker_error_code) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,workflow_id),
  UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
  FOREIGN KEY(workspace_id,application_id,rule_id,rule_version)
    REFERENCES epm.expression_rule_version(
      workspace_id,application_id,rule_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
      ON DELETE RESTRICT,
  CHECK((claimant IS NULL)=(lease_until IS NULL))
);

CREATE TABLE epm.application_rule_workflow_child (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  workflow_id text NOT NULL,
  unit_ordinal integer NOT NULL CHECK(unit_ordinal BETWEEN 1 AND 500),
  job_id text NOT NULL,
  PRIMARY KEY(workspace_id,application_id,workflow_id,unit_ordinal),
  UNIQUE(workspace_id,application_id,workflow_id,job_id),
  FOREIGN KEY(workspace_id,application_id,workflow_id)
    REFERENCES epm.application_rule_workflow(
      workspace_id,application_id,workflow_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,job_id)
    REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE RESTRICT
);

CREATE INDEX application_rule_workflow_ready
  ON epm.application_rule_workflow(
    status,updated_at,workspace_id,application_id)
  WHERE status IN ('accepted','running','cancel_requested');
CREATE INDEX application_rule_workflow_child_job
  ON epm.application_rule_workflow_child(
    workspace_id,application_id,job_id);

ALTER TABLE epm.application_rule_workflow ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_rule_workflow_child ENABLE ROW LEVEL SECURITY;

CREATE POLICY application_rule_workflow_runtime_scope
  ON epm.application_rule_workflow TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_rule_workflow_child_runtime_scope
  ON epm.application_rule_workflow_child TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_rule_workflow_lifecycle_scope
  ON epm.application_rule_workflow TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_rule_workflow_child_lifecycle_scope
  ON epm.application_rule_workflow_child TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.application_rule_workflow,
  epm.application_rule_workflow_child
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_rule_workflow,
  epm.application_rule_workflow_child TO epm_runtime;
GRANT UPDATE(status,result,updated_at) ON epm.application_rule_workflow
  TO epm_runtime;
GRANT SELECT,DELETE ON epm.application_rule_workflow_child,
  epm.application_rule_workflow TO epm_lifecycle;

-- Owner reset remains child-first and retains immutable job/receipt history
-- ordering.  The final fingerprint is replaced after isolated FK inspection.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_pair text :=
  $pattern$'sealed_cube_selection','member_list_publication',$pattern$;
DECLARE new_pair text :=
  $pattern$'application_rule_workflow_child','application_rule_workflow','sealed_cube_selection','member_list_publication',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0217_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0217_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'ef10c6ad1b520b8ab5c1cbdfba7da632ed06fdf7dbc7e491a06c6e44b50742da';
DECLARE new_fingerprint constant text :=
  'd4c3b3b04a02295c411d1310870df538b83b6a29bf61d8d1a964b48df66ec8c1';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0 OR
     position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0217_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised := replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0217_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
