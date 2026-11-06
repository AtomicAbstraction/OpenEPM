-- Immutable generic planning assignments and one active pointer per app.
CREATE TABLE epm.planning_assignment_version(
 workspace_id text NOT NULL,application_id text NOT NULL,
 assignment_set_id text NOT NULL,version bigint NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
   AND octet_length(definition::text)<=4194304),
 canonical_digest text NOT NULL CHECK(canonical_digest~'^[0-9a-f]{64}$'),
 policy_id text NOT NULL,policy_version bigint NOT NULL CHECK(policy_version>0),
 policy_digest text NOT NULL CHECK(policy_digest~'^[0-9a-f]{64}$'),
 creator_issuer text NOT NULL,creator_subject_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,assignment_set_id,version),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,policy_id,policy_version)
   REFERENCES epm.planning_workflow_policy_version(workspace_id,application_id,policy_id,version) ON DELETE RESTRICT);
CREATE TABLE epm.planning_assignment_state(
 workspace_id text NOT NULL,application_id text NOT NULL,
 active_assignment_set_id text,active_version bigint,
 pointer_version bigint NOT NULL CHECK(pointer_version>0),
 state_revision bigint NOT NULL CHECK(state_revision>0),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,active_assignment_set_id,active_version)
  REFERENCES epm.planning_assignment_version(workspace_id,application_id,assignment_set_id,version) ON DELETE RESTRICT,
 CHECK((active_assignment_set_id IS NULL)=(active_version IS NULL)));
CREATE FUNCTION epm.planning_assignment_version_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
 RAISE EXCEPTION 'PLANNING_ASSIGNMENT_VERSION_IMMUTABLE' USING ERRCODE='23514';END$$;
CREATE TRIGGER planning_assignment_version_immutable BEFORE UPDATE OR DELETE ON epm.planning_assignment_version
 FOR EACH ROW EXECUTE FUNCTION epm.planning_assignment_version_immutable();
REVOKE ALL ON FUNCTION epm.planning_assignment_version_immutable() FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
ALTER TABLE epm.planning_assignment_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_assignment_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_assignment_version_runtime ON epm.planning_assignment_version TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_assignment_state_runtime ON epm.planning_assignment_state TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_assignment_version_lifecycle ON epm.planning_assignment_version TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY planning_assignment_state_lifecycle ON epm.planning_assignment_state TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.planning_assignment_version,epm.planning_assignment_state FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_assignment_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_assignment_state TO epm_runtime;
GRANT UPDATE(active_assignment_set_id,active_version,pointer_version,state_revision,updated_at) ON epm.planning_assignment_state TO epm_runtime;
GRANT SELECT(workspace_id,application_id,assignment_set_id,version) ON epm.planning_assignment_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,active_assignment_set_id,active_version,pointer_version,state_revision) ON epm.planning_assignment_state TO epm_lifecycle;
DO $$DECLARE old text:='28c6c4b5012de669dad732ac09932c5d5f566097e26adaae65a8612f068064d3';new text:='46fa0ba2e425dc471dd571534e04caf892e2b2f3dd3d0f2b32cd857a3a974734';d text;r text;
 b text:='''planning_workflow_policy_state'',''planning_workflow_policy_version''';
 a text:='''planning_assignment_state'',''planning_assignment_version'',''planning_workflow_policy_state'',''planning_workflow_policy_version''';
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(old in d)=0 OR position(b in d)=0 THEN RAISE EXCEPTION 'RESET_0114_DEFINITION_MISMATCH';END IF;
 r:=replace(replace(d,old,new),b,a);EXECUTE r;END$$;
