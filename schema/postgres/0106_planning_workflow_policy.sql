-- Immutable generic-planning editability definitions and one active pointer
-- per application.  Definitions name their own dimensions; no financial or
-- consolidation axis is required by this storage contract.
CREATE TABLE epm.planning_workflow_policy_version(
 workspace_id text NOT NULL,application_id text NOT NULL,
 policy_id text NOT NULL CHECK(policy_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
 version bigint NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND octet_length(definition::text)<=4194304),
 canonical_digest text NOT NULL CHECK(canonical_digest ~ '^[0-9a-f]{64}$'),
 creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
    AND creator_issuer !~ '[[:cntrl:]]'),
 creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300
    AND creator_subject_id !~ '[[:cntrl:]]'),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,policy_id,version),
 CONSTRAINT planning_workflow_policy_application_fkey
   FOREIGN KEY(workspace_id,application_id)
   REFERENCES epm.application_state(workspace_id,application_id)
   ON DELETE RESTRICT
);

CREATE TABLE epm.planning_workflow_policy_state(
 workspace_id text NOT NULL,application_id text NOT NULL,
 active_policy_id text,active_version bigint,
 pointer_version bigint NOT NULL CHECK(pointer_version>0),
 state_revision bigint NOT NULL CHECK(state_revision>0),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id),
 CONSTRAINT planning_workflow_policy_state_application_fkey
   FOREIGN KEY(workspace_id,application_id)
   REFERENCES epm.application_state(workspace_id,application_id)
   ON DELETE RESTRICT,
 CONSTRAINT planning_workflow_policy_active_fkey
   FOREIGN KEY(workspace_id,application_id,active_policy_id,active_version)
   REFERENCES epm.planning_workflow_policy_version
     (workspace_id,application_id,policy_id,version)
   ON DELETE RESTRICT,
 CHECK((active_policy_id IS NULL)=(active_version IS NULL))
);

CREATE FUNCTION epm.planning_workflow_policy_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'PLANNING_WORKFLOW_POLICY_VERSION_IMMUTABLE'
   USING ERRCODE='23514';
END $$;
CREATE TRIGGER planning_workflow_policy_version_immutable
BEFORE UPDATE OR DELETE ON epm.planning_workflow_policy_version
FOR EACH ROW EXECUTE FUNCTION epm.planning_workflow_policy_version_immutable();
REVOKE ALL ON FUNCTION epm.planning_workflow_policy_version_immutable()
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;

ALTER TABLE epm.planning_workflow_policy_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_workflow_policy_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_workflow_policy_version_scope
 ON epm.planning_workflow_policy_version TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_workflow_policy_state_scope
 ON epm.planning_workflow_policy_state TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_workflow_policy_version_lifecycle
 ON epm.planning_workflow_policy_version TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY planning_workflow_policy_state_lifecycle
 ON epm.planning_workflow_policy_state TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.planning_workflow_policy_version,
 epm.planning_workflow_policy_state
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_workflow_policy_version TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_workflow_policy_state TO epm_runtime;
GRANT UPDATE(active_policy_id,active_version,pointer_version,state_revision,
 updated_at) ON epm.planning_workflow_policy_state TO epm_runtime;
GRANT SELECT(workspace_id,application_id,policy_id,version)
 ON epm.planning_workflow_policy_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,active_policy_id,active_version,
 pointer_version,state_revision)
 ON epm.planning_workflow_policy_state TO epm_lifecycle;

-- Extend the exact owner reset in FK-safe order and bind it to the reviewed
-- post-0106 schema fingerprint.  The final digest is generated from a clean
-- disposable PostgreSQL migration run and checked by focused tests.
DO $$
DECLARE
 v_old text := '0d2a3c4cac9b49c4b4585163d628dbc8604050f5cee8ca73d3cf7579710d7430';
 v_new text := '6565519d66059bc8041b4704b72f79fe1baf7e8248d987c99d8ebb03f72a82a4';
 v_before text := '''execution_delegation_state'',''execution_delegation_version'',''operation_receipt''';
 v_after text := '''execution_delegation_state'',''execution_delegation_version'',''planning_workflow_policy_state'',''planning_workflow_policy_version'',''operation_receipt''';
 v_definition text;
 v_replaced text;
BEGIN
 SELECT pg_get_functiondef(
   'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO v_definition;
 IF length(v_definition)-length(replace(v_definition,v_old,''))<>length(v_old)
 OR length(v_definition)-length(replace(v_definition,v_before,''))<>length(v_before)
 THEN RAISE EXCEPTION 'RESET_0106_DEFINITION_MISMATCH'; END IF;
 v_replaced := replace(replace(v_definition,v_old,v_new),v_before,v_after);
 IF v_replaced=v_definition THEN
   RAISE EXCEPTION 'RESET_0106_REPLACEMENT_FAILED';
 END IF;
 EXECUTE v_replaced;
END $$;
