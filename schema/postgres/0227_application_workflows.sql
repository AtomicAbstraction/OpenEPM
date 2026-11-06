-- Immutable domain-neutral workflow definitions and relational assignment
-- pins.  This persistence owns no execution semantics and grants no cube
-- access; fixed core validates selections, destinations and evidence.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=226) THEN
    RAISE EXCEPTION 'MIGRATION_0227_PREDECESSOR_0226_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.application_workflow_version (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  flow_id text NOT NULL CHECK(length(flow_id) BETWEEN 1 AND 300
    AND flow_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
  version bigint NOT NULL CHECK(version>0),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND octet_length(definition::text)<=4194304
    AND definition->>'format'='openepm-application-task-flow-v2'
    AND definition->>'workspaceId'=workspace_id
    AND definition->>'applicationId'=application_id
    AND definition->>'flowId'=flow_id
    AND (definition->>'version')::bigint=version),
  definition_digest text NOT NULL CHECK(definition_digest ~ '^[0-9a-f]{64}$'),
  operation_id text NOT NULL,
  created_revision bigint NOT NULL CHECK(created_revision>0),
  creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
    AND creator_issuer !~ '[[:cntrl:]]'),
  creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300
    AND creator_subject_id !~ '[[:cntrl:]]'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,flow_id,version),
  UNIQUE(workspace_id,application_id,flow_id,version,definition_digest),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

CREATE INDEX application_workflow_version_latest
  ON epm.application_workflow_version(
    workspace_id,application_id,flow_id,version DESC);

CREATE TABLE epm.application_workflow_state (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  flow_id text NOT NULL CHECK(length(flow_id) BETWEEN 1 AND 300
    AND flow_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
  latest_version bigint NOT NULL CHECK(latest_version>0),
  active_version bigint,
  state_revision bigint NOT NULL CHECK(state_revision>0),
  operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,flow_id),
  FOREIGN KEY(workspace_id,application_id,flow_id,latest_version)
    REFERENCES epm.application_workflow_version(
      workspace_id,application_id,flow_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,flow_id,active_version)
    REFERENCES epm.application_workflow_version(
      workspace_id,application_id,flow_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

CREATE TABLE epm.application_workflow_assignment_pin (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  flow_id text NOT NULL,
  flow_version bigint NOT NULL CHECK(flow_version>0),
  activity_id text NOT NULL CHECK(length(activity_id) BETWEEN 1 AND 300
    AND activity_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
  assignment_set_id text NOT NULL,
  assignment_version bigint NOT NULL CHECK(assignment_version>0),
  assignment_digest text NOT NULL CHECK(assignment_digest ~ '^[0-9a-f]{64}$'),
  assignment_id text NOT NULL CHECK(length(assignment_id) BETWEEN 1 AND 300
    AND assignment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
  PRIMARY KEY(workspace_id,application_id,flow_id,flow_version,activity_id),
  FOREIGN KEY(workspace_id,application_id,flow_id,flow_version)
    REFERENCES epm.application_workflow_version(
      workspace_id,application_id,flow_id,version) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,assignment_set_id,
      assignment_version,assignment_digest)
    REFERENCES epm.application_assignment_version(
      workspace_id,application_id,assignment_set_id,version,definition_digest)
    ON DELETE RESTRICT
);

CREATE INDEX application_workflow_assignment_lookup
  ON epm.application_workflow_assignment_pin(
    workspace_id,application_id,assignment_set_id,assignment_version,
    assignment_id,flow_id,flow_version,activity_id);

CREATE FUNCTION epm.application_workflow_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
  RAISE EXCEPTION 'APPLICATION_WORKFLOW_IMMUTABLE' USING ERRCODE='23514';
END$$;
CREATE TRIGGER application_workflow_version_immutable
  BEFORE UPDATE OR DELETE ON epm.application_workflow_version
  FOR EACH ROW EXECUTE FUNCTION epm.application_workflow_immutable();
CREATE TRIGGER application_workflow_assignment_pin_immutable
  BEFORE UPDATE OR DELETE ON epm.application_workflow_assignment_pin
  FOR EACH ROW EXECUTE FUNCTION epm.application_workflow_immutable();
REVOKE ALL ON FUNCTION epm.application_workflow_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

DO $migration$ DECLARE relation_name text;BEGIN
  FOREACH relation_name IN ARRAY ARRAY['application_workflow_version',
    'application_workflow_state','application_workflow_assignment_pin'] LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation_name);
    EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime USING '
      '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) WITH CHECK '
      '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',
      relation_name||'_runtime_scope',relation_name);
    EXECUTE format('CREATE POLICY %I ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true))',
      relation_name||'_lifecycle_scope',relation_name);
  END LOOP;
END $migration$;

REVOKE ALL ON epm.application_workflow_version,
  epm.application_workflow_state,epm.application_workflow_assignment_pin
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_workflow_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_workflow_state TO epm_runtime;
GRANT UPDATE(latest_version,active_version,state_revision,operation_id,updated_at)
  ON epm.application_workflow_state TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_workflow_assignment_pin TO epm_runtime;
GRANT SELECT(workspace_id,application_id,flow_id,version)
  ON epm.application_workflow_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,flow_id,latest_version,
  active_version,state_revision) ON epm.application_workflow_state
  TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,flow_id,flow_version,activity_id,
  assignment_set_id,assignment_version,assignment_id)
  ON epm.application_workflow_assignment_pin TO epm_lifecycle;

-- New workflow rows are children of exact assignment versions.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_group text:=
  $pattern$'application_task_flow_version','application_assignment_state','application_assignment_version',$pattern$;
DECLARE new_group text:=
  $pattern$'application_task_flow_version','application_workflow_assignment_pin','application_workflow_state','application_workflow_version','application_assignment_state','application_assignment_version',$pattern$;
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_group IN definition)=0 OR position(new_group IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0227_DEFINITION_MISMATCH';END IF;
  revised:=replace(definition,old_group,new_group);
  IF revised=definition OR position(new_group IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0227_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

-- Replaced with the observed canonical fingerprint after a clean disposable
-- 0001--0227 installation and FK-graph inspection.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
  'f615e1a13de8b33be0798fed83cec52d119614679808499cfc361b8afa69ebb9';
DECLARE new_fingerprint constant text:=
  'c422e1cb28cfcb0de4c1993f44f95ad1fc7c802f516c05eaa1f21bef6b01aec3';
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0227_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0227_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

DO $migration$ DECLARE role_name text;DECLARE relation_name text;BEGIN
  FOREACH role_name IN ARRAY ARRAY['epm_lifecycle','epm_lifecycle_login'] LOOP
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      FOREACH relation_name IN ARRAY ARRAY[
        'epm.application_workflow_version','epm.application_workflow_state',
        'epm.application_workflow_assignment_pin'] LOOP
        IF has_table_privilege(role_name,relation_name,'DELETE') THEN
          RAISE EXCEPTION 'MIGRATION_0227_LIFECYCLE_DELETE_REMAINS:%:%',
            role_name,relation_name;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END $migration$;
