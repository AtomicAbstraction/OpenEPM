-- Generic schedules for exact published application-rule versions.  These
-- records contain fixed-core definitions and execution authority only; they
-- do not preserve the retired product distinction between planning,
-- consolidation, forecast or Python schedules.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=219) THEN
    RAISE EXCEPTION 'MIGRATION_0220_PREDECESSOR_0219_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.application_schedule_version (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  schedule_id text NOT NULL
    CHECK(schedule_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  version bigint NOT NULL CHECK(version>0),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND definition->>'format'='openepm-application-schedule-v1'
    AND octet_length(definition::text)<=1048576),
  definition_digest text NOT NULL
    CHECK(definition_digest ~ '^[0-9a-f]{64}$'),
  rule_id text NOT NULL,
  rule_version integer NOT NULL CHECK(rule_version>0),
  rule_program_digest text NOT NULL
    CHECK(rule_program_digest ~ '^[0-9a-f]{64}$'),
  publication_operation_id text NOT NULL,
  published_revision bigint NOT NULL CHECK(published_revision>0),
  execution_issuer text NOT NULL CHECK(length(execution_issuer) BETWEEN 1 AND 300),
  execution_subject text NOT NULL CHECK(length(execution_subject) BETWEEN 1 AND 300),
  delegation_id text NOT NULL,
  delegation_version bigint NOT NULL CHECK(delegation_version>0),
  operation_id text NOT NULL,
  created_revision bigint NOT NULL CHECK(created_revision>0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,schedule_id,version),
  FOREIGN KEY(workspace_id,application_id,rule_id,rule_version)
    REFERENCES epm.expression_rule_version(
      workspace_id,application_id,rule_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,publication_operation_id)
    REFERENCES epm.operation_receipt(
      workspace_id,application_id,operation_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,delegation_id,delegation_version)
    REFERENCES epm.execution_delegation_version(
      workspace_id,application_id,delegation_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(
      workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

CREATE TABLE epm.application_schedule_state (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  schedule_id text NOT NULL,
  latest_version bigint NOT NULL CHECK(latest_version>0),
  active_version bigint,
  state_revision bigint NOT NULL CHECK(state_revision>0),
  last_due_at timestamptz,
  dispatch_generation bigint NOT NULL DEFAULT 0 CHECK(dispatch_generation>=0),
  dispatch_claimant text
    CHECK(dispatch_claimant IS NULL OR length(dispatch_claimant) BETWEEN 1 AND 200),
  dispatch_lease_until timestamptz,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,schedule_id),
  FOREIGN KEY(workspace_id,application_id,schedule_id,latest_version)
    REFERENCES epm.application_schedule_version(
      workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,schedule_id,active_version)
    REFERENCES epm.application_schedule_version(
      workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
  CHECK((dispatch_claimant IS NULL)=(dispatch_lease_until IS NULL))
);

CREATE TABLE epm.application_schedule_occurrence (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  occurrence_id text NOT NULL CHECK(occurrence_id ~ '^[0-9a-f]{32}$'),
  schedule_id text NOT NULL,
  schedule_version bigint NOT NULL CHECK(schedule_version>0),
  due_at timestamptz NOT NULL,
  status text NOT NULL CHECK(status IN (
    'ready','running','submitted','published','partially_published','failed',
    'cancel_requested','cancelled','needs_inspection')),
  application_rule_workflow_id text
    CHECK(application_rule_workflow_id IS NULL
      OR application_rule_workflow_id ~ '^[0-9a-f]{32}$'),
  attempt_count integer NOT NULL DEFAULT 0 CHECK(attempt_count BETWEEN 0 AND 10),
  next_attempt_at timestamptz,
  claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),
  claimant text CHECK(claimant IS NULL OR length(claimant) BETWEEN 1 AND 200),
  lease_until timestamptz,
  error_code text CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 200),
  result jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(result)='object'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,occurrence_id),
  UNIQUE(workspace_id,application_id,schedule_id,schedule_version,due_at),
  FOREIGN KEY(workspace_id,application_id,schedule_id,schedule_version)
    REFERENCES epm.application_schedule_version(
      workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,application_rule_workflow_id)
    REFERENCES epm.application_rule_workflow(
      workspace_id,application_id,workflow_id) ON DELETE RESTRICT,
  CHECK((claimant IS NULL)=(lease_until IS NULL)),
  CHECK((status IN ('submitted','published','partially_published')
      AND application_rule_workflow_id IS NOT NULL)
    OR status IN ('ready','running','failed','cancel_requested','cancelled',
                  'needs_inspection'))
);

CREATE INDEX application_schedule_due
  ON epm.application_schedule_state(
    active_version,dispatch_lease_until,workspace_id,application_id,schedule_id)
  WHERE active_version IS NOT NULL;
CREATE INDEX application_schedule_occurrence_ready
  ON epm.application_schedule_occurrence(
    status,next_attempt_at,lease_until,due_at,workspace_id,application_id)
  WHERE status IN ('ready','running','submitted','cancel_requested');

ALTER TABLE epm.application_schedule_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_schedule_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_schedule_occurrence ENABLE ROW LEVEL SECURITY;

DO $migration$ DECLARE relation_name text; BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'application_schedule_version','application_schedule_state',
    'application_schedule_occurrence'] LOOP
    EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) '
      'AND application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) '
      'AND application_id=current_setting(''epm.application_id'',true))',
      relation_name||'_runtime_scope',relation_name);
    EXECUTE format('CREATE POLICY %I ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true))',
      relation_name||'_lifecycle_scope',relation_name);
  END LOOP;
END $migration$;

REVOKE ALL ON epm.application_schedule_version,
  epm.application_schedule_state,epm.application_schedule_occurrence
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_schedule_version,
  epm.application_schedule_state,epm.application_schedule_occurrence
  TO epm_runtime;
GRANT UPDATE(latest_version,active_version,state_revision,last_due_at,
  dispatch_generation,dispatch_claimant,dispatch_lease_until,updated_at)
  ON epm.application_schedule_state TO epm_runtime;
GRANT UPDATE(status,application_rule_workflow_id,attempt_count,next_attempt_at,
  claim_generation,claimant,lease_until,error_code,result,updated_at)
  ON epm.application_schedule_occurrence TO epm_runtime;
GRANT SELECT(workspace_id,application_id,schedule_id,version)
  ON epm.application_schedule_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,schedule_id,latest_version,
  active_version,state_revision,dispatch_claimant,dispatch_lease_until)
  ON epm.application_schedule_state TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,occurrence_id,status,claimant,lease_until)
  ON epm.application_schedule_occurrence TO epm_lifecycle;

-- The owner reset gate rejects active schedule work and deletes the new
-- generic records child-first.  Lifecycle roles retain inventory reads only.
DO $migration$
DECLARE definition text;revised text;
DECLARE marker text :=
  $pattern$    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),$pattern$;
DECLARE gate text :=
  $pattern$    IF EXISTS (SELECT 1 FROM epm.application_schedule_occurrence WHERE workspace_id=p_workspace_id AND status IN ('ready','running','submitted','cancel_requested','needs_inspection')) OR EXISTS (SELECT 1 FROM epm.application_schedule_state WHERE workspace_id=p_workspace_id AND dispatch_claimant IS NOT NULL AND dispatch_lease_until>clock_timestamp()) THEN RAISE EXCEPTION 'UNSETTLED_APPLICATION_SCHEDULE_WORK'; END IF;

$pattern$;
DECLARE old_pair text :=
  $pattern$'application_rule_workflow_child','application_rule_workflow',$pattern$;
DECLARE new_pair text :=
  $pattern$'application_schedule_occurrence','application_schedule_state','application_schedule_version','application_rule_workflow_child','application_rule_workflow',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(marker IN definition)=0 OR position(gate IN definition)>0
     OR position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0220_DEFINITION_MISMATCH';
  END IF;
  revised:=replace(definition,marker,gate||marker);
  revised:=replace(revised,old_pair,new_pair);
  IF revised=definition OR position(gate IN revised)=0
     OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0220_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$
DECLARE definition text;revised text;
DECLARE old_fingerprint constant text :=
  '1358844c2bc77c9d5023f8b0cca542642ca18317c4d586c3984cdd539c9d0bc3';
-- Replaced with the reviewed graph produced by an isolated clean 0001-0220
-- installation before this migration is accepted.
DECLARE new_fingerprint constant text :=
  '20733f9787bc8eb9930a34cbd1a5868cfd1a0b474247ef4b3d624d8cd4ac9b24';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0220_FINGERPRINT_DEFINITION_MISMATCH';
  END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0220_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;

DO $migration$ DECLARE role_name text;relation_name text; BEGIN
  FOREACH role_name IN ARRAY ARRAY['epm_lifecycle','epm_lifecycle_login'] LOOP
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      FOREACH relation_name IN ARRAY ARRAY[
        'epm.application_schedule_version','epm.application_schedule_state',
        'epm.application_schedule_occurrence'] LOOP
        IF has_table_privilege(role_name,relation_name,'DELETE') THEN
          RAISE EXCEPTION 'MIGRATION_0220_LIFECYCLE_DELETE_REMAINS:%:%',
            role_name,relation_name;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END $migration$;
