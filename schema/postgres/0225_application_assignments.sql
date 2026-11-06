-- Immutable domain-neutral application assignments and one separately fenced
-- publication pointer.  An assignment establishes responsibility over an
-- explicit multidimensional member scope; it grants no cube access, executes
-- no business function and owns no workflow transition.

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=224) THEN
    RAISE EXCEPTION 'MIGRATION_0225_PREDECESSOR_0224_REQUIRED';
  END IF;
END $migration$;

CREATE TABLE epm.application_assignment_version (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  assignment_set_id text NOT NULL CHECK(
    assignment_set_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$'),
  version bigint NOT NULL CHECK(version>0),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND octet_length(definition::text)<=4194304
    AND definition->>'format'='openepm-application-assignment-set-v1'
    AND definition->>'workspaceId'=workspace_id
    AND definition->>'applicationId'=application_id
    AND definition->>'assignmentSetId'=assignment_set_id
    AND (definition->>'version')::bigint=version),
  definition_digest text NOT NULL CHECK(
    definition_digest ~ '^[0-9a-f]{64}$'),
  operation_id text NOT NULL,
  created_revision bigint NOT NULL CHECK(created_revision>0),
  creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
    AND creator_issuer !~ '[[:cntrl:]]'),
  creator_subject_id text NOT NULL CHECK(
    length(creator_subject_id) BETWEEN 1 AND 300
    AND creator_subject_id !~ '[[:cntrl:]]'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,assignment_set_id,version),
  UNIQUE(workspace_id,application_id,assignment_set_id,version,
    definition_digest),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

CREATE INDEX application_assignment_version_latest
  ON epm.application_assignment_version(
    workspace_id,application_id,assignment_set_id,version DESC);

CREATE TABLE epm.application_assignment_state (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  assignment_set_id text NOT NULL CHECK(
    assignment_set_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$'),
  latest_version bigint NOT NULL CHECK(latest_version>0),
  active_version bigint,
  state_revision bigint NOT NULL CHECK(state_revision>0),
  operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,assignment_set_id),
  FOREIGN KEY(workspace_id,application_id,assignment_set_id,latest_version)
    REFERENCES epm.application_assignment_version(
      workspace_id,application_id,assignment_set_id,version)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,assignment_set_id,active_version)
    REFERENCES epm.application_assignment_version(
      workspace_id,application_id,assignment_set_id,version)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

CREATE FUNCTION epm.application_assignment_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
  RAISE EXCEPTION 'APPLICATION_ASSIGNMENT_VERSION_IMMUTABLE'
    USING ERRCODE='23514';
END$$;
CREATE TRIGGER application_assignment_version_immutable
  BEFORE UPDATE OR DELETE ON epm.application_assignment_version
  FOR EACH ROW EXECUTE FUNCTION epm.application_assignment_version_immutable();
REVOKE ALL ON FUNCTION epm.application_assignment_version_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

ALTER TABLE epm.application_assignment_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_assignment_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY application_assignment_version_runtime_scope
  ON epm.application_assignment_version TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_assignment_version_lifecycle_scope
  ON epm.application_assignment_version FOR SELECT TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_assignment_state_runtime_scope
  ON epm.application_assignment_state TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_assignment_state_lifecycle_scope
  ON epm.application_assignment_state FOR SELECT TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.application_assignment_version,
  epm.application_assignment_state
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.application_assignment_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.application_assignment_state TO epm_runtime;
GRANT UPDATE(latest_version,active_version,state_revision,operation_id,updated_at)
  ON epm.application_assignment_state TO epm_runtime;
GRANT SELECT(workspace_id,application_id,assignment_set_id,version)
  ON epm.application_assignment_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,assignment_set_id,latest_version,
  active_version,state_revision)
  ON epm.application_assignment_state TO epm_lifecycle;

-- Application task-flow records remain children of assignment definitions.
-- Insert the generic assignment records between the task-flow and legacy
-- planning-assignment families in the owner reset's child-first inventory.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_pair text:=
  $pattern$'application_task_flow_version','planning_assignment_state',$pattern$;
DECLARE new_pair text:=
  $pattern$'application_task_flow_version','application_assignment_state','application_assignment_version','planning_assignment_state',$pattern$;
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0225_DEFINITION_MISMATCH';END IF;
  revised:=replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0225_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

-- The final fingerprint is replaced after a clean disposable 0001--0225
-- installation and canonical FK-graph inspection.
DO $migration$
DECLARE definition text;DECLARE revised text;
DECLARE old_fingerprint constant text:=
  '10c0c68ca83b1448cb3fe45dcf2245c0900eff805c0d8f8617b13efa6ce209d6';
DECLARE new_fingerprint constant text:=
  'f615e1a13de8b33be0798fed83cec52d119614679808499cfc361b8afa69ebb9';
BEGIN
  definition:=pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0225_FINGERPRINT_PREDECESSOR_MISMATCH';END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0225_FINGERPRINT_UPDATE_FAILED';END IF;
  EXECUTE revised;
END $migration$;

DO $migration$ DECLARE role_name text;DECLARE relation_name text;BEGIN
  FOREACH role_name IN ARRAY ARRAY['epm_lifecycle','epm_lifecycle_login'] LOOP
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name) THEN
      FOREACH relation_name IN ARRAY ARRAY[
        'epm.application_assignment_version',
        'epm.application_assignment_state'] LOOP
        IF has_table_privilege(role_name,relation_name,'DELETE') THEN
          RAISE EXCEPTION 'MIGRATION_0225_LIFECYCLE_DELETE_REMAINS:%:%',
            role_name,relation_name;
        END IF;
      END LOOP;
    END IF;
  END LOOP;
END $migration$;
