-- Immutable reusable Seed/Driver/Rollup/Spread/Allocation policies.
CREATE TABLE epm.planning_operation_policy_version(
 workspace_id text NOT NULL,application_id text NOT NULL,
 policy_id text NOT NULL CHECK(policy_id~'^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$'),
 version bigint NOT NULL CHECK(version>0),
 kind text NOT NULL CHECK(kind IN('Seed','Driver','Rollup','Spread','Allocation')),
 effective_from date NOT NULL,effective_before date NOT NULL,
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
   AND octet_length(definition::text)<=1048576),
 canonical_digest text NOT NULL CHECK(canonical_digest~'^[0-9a-f]{64}$'),
 creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300),
 creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,policy_id,version),
 FOREIGN KEY(workspace_id,application_id) REFERENCES
  epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CHECK(effective_from<effective_before));

CREATE TABLE epm.planning_operation_policy_state(
 workspace_id text NOT NULL,application_id text NOT NULL,policy_id text NOT NULL,
 latest_version bigint NOT NULL CHECK(latest_version>0),
 active_version bigint,pointer_version bigint NOT NULL CHECK(pointer_version>=0),
 state_revision bigint NOT NULL CHECK(state_revision>=0),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,policy_id),
 FOREIGN KEY(workspace_id,application_id,policy_id,latest_version)
  REFERENCES epm.planning_operation_policy_version
   (workspace_id,application_id,policy_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,policy_id,active_version)
  REFERENCES epm.planning_operation_policy_version
   (workspace_id,application_id,policy_id,version) ON DELETE RESTRICT);

CREATE FUNCTION epm.planning_operation_policy_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'PLANNING_OPERATION_POLICY_VERSION_IMMUTABLE'
 USING ERRCODE='23514';END$$;
CREATE TRIGGER planning_operation_policy_version_immutable
 BEFORE UPDATE OR DELETE ON epm.planning_operation_policy_version
 FOR EACH ROW EXECUTE FUNCTION epm.planning_operation_policy_version_immutable();
REVOKE ALL ON FUNCTION epm.planning_operation_policy_version_immutable()
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

ALTER TABLE epm.planning_operation_policy_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_operation_policy_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_operation_policy_version_runtime
 ON epm.planning_operation_policy_version TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_operation_policy_state_runtime
 ON epm.planning_operation_policy_state TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_operation_policy_version_lifecycle
 ON epm.planning_operation_policy_version TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY planning_operation_policy_state_lifecycle
 ON epm.planning_operation_policy_state TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.planning_operation_policy_version,
 epm.planning_operation_policy_state
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_operation_policy_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_operation_policy_state TO epm_runtime;
GRANT UPDATE(latest_version,active_version,pointer_version,state_revision,
 updated_at) ON epm.planning_operation_policy_state TO epm_runtime;
GRANT SELECT(workspace_id,application_id,policy_id,version)
 ON epm.planning_operation_policy_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,policy_id,latest_version,
 active_version,pointer_version,state_revision)
 ON epm.planning_operation_policy_state TO epm_lifecycle;

DO $$DECLARE
 old text:='b0efbf3f98f18add1a80cd1631c9fde9626e2386975d973cf60ca13e122c3b19';
 new text:='30a2efa926fe95d9d21d178d712a77ab8bb987f8ec9b334442aa3ae0981eb1aa';
 d text;r text;
 b text:='''planning_assignment_control_current'',''planning_assignment_control_event'',''planning_assignment_due_occurrence''';
 a text:='''planning_operation_policy_state'',''planning_operation_policy_version'',''planning_assignment_control_current'',''planning_assignment_control_event'',''planning_assignment_due_occurrence''';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(old in d)=0 OR position(b in d)=0 THEN
  RAISE EXCEPTION 'RESET_0119_DEFINITION_MISMATCH';END IF;
 r:=replace(replace(d,old,new),b,a);EXECUTE r;
END$$;
