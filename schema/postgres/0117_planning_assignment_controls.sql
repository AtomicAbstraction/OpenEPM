-- Durable delegation, reassignment and due escalation for published assignments.
CREATE TABLE epm.planning_assignment_control_event(
 workspace_id text NOT NULL,application_id text NOT NULL,
 assignment_set_id text NOT NULL,assignment_version bigint NOT NULL,
 assignment_id text NOT NULL,event_ordinal bigint NOT NULL CHECK(event_ordinal>0),
 event_kind text NOT NULL CHECK(event_kind IN('Delegated','DelegationRevoked','Reassigned','Escalated')),
 actor_issuer text NOT NULL,actor_subject_id text NOT NULL,
 target_issuer text,target_subject_id text,target_group_id text,reason text NOT NULL,
 expires_at timestamptz,request_key text NOT NULL,command_digest text NOT NULL CHECK(command_digest~'^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id,event_ordinal),
 UNIQUE(workspace_id,application_id,request_key),
 FOREIGN KEY(workspace_id,application_id,assignment_set_id,assignment_version)
  REFERENCES epm.planning_assignment_version(workspace_id,application_id,assignment_set_id,version) ON DELETE RESTRICT);
CREATE TABLE epm.planning_assignment_control_current(
 workspace_id text NOT NULL,application_id text NOT NULL,
 assignment_set_id text NOT NULL,assignment_version bigint NOT NULL,assignment_id text NOT NULL,
 control_version bigint NOT NULL CHECK(control_version>0),
 assignee_issuer text,assignee_subject_id text,assignee_group_id text,delegator_issuer text,delegator_subject_id text,
 delegation_depth bigint NOT NULL DEFAULT 0 CHECK(delegation_depth>=0),delegation_expires_at timestamptz,
 escalated_reviewer_ordinal bigint,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id),
 FOREIGN KEY(workspace_id,application_id,assignment_set_id,assignment_version)
  REFERENCES epm.planning_assignment_version(workspace_id,application_id,assignment_set_id,version) ON DELETE RESTRICT,
 CHECK((assignee_issuer IS NULL)=(assignee_subject_id IS NULL)),
 CHECK(NOT(assignee_subject_id IS NOT NULL AND assignee_group_id IS NOT NULL)),
 CHECK((delegator_issuer IS NULL)=(delegator_subject_id IS NULL)));
CREATE TABLE epm.planning_assignment_due_occurrence(
 workspace_id text NOT NULL,application_id text NOT NULL,
 assignment_set_id text NOT NULL,assignment_version bigint NOT NULL,assignment_id text NOT NULL,
 due_at timestamptz NOT NULL,status text NOT NULL CHECK(status IN('Pending','Running','Completed')),
 claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),claimant text,lease_until timestamptz,
 result_event_ordinal bigint,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),completed_at timestamptz,
 PRIMARY KEY(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id,due_at),
 FOREIGN KEY(workspace_id,application_id,assignment_set_id,assignment_version)
  REFERENCES epm.planning_assignment_version(workspace_id,application_id,assignment_set_id,version) ON DELETE RESTRICT,
 CHECK((claimant IS NULL)=(lease_until IS NULL)));
CREATE INDEX planning_assignment_due_claim_idx ON epm.planning_assignment_due_occurrence(status,due_at,lease_until);

ALTER TABLE epm.planning_assignment_control_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_assignment_control_current ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.planning_assignment_due_occurrence ENABLE ROW LEVEL SECURITY;
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['planning_assignment_control_event','planning_assignment_control_current','planning_assignment_due_occurrence'] LOOP
 EXECUTE format('CREATE POLICY %I_runtime ON epm.%I TO epm_runtime USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',t,t);
 EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I TO epm_lifecycle USING(workspace_id=current_setting(''epm.workspace_id'',true))',t,t);
END LOOP;END$$;
REVOKE ALL ON epm.planning_assignment_control_event,epm.planning_assignment_control_current,epm.planning_assignment_due_occurrence FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_assignment_control_event TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.planning_assignment_control_current TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.planning_assignment_due_occurrence TO epm_runtime,epm_worker;
GRANT SELECT(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id,event_ordinal) ON epm.planning_assignment_control_event TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id) ON epm.planning_assignment_control_current TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id) ON epm.planning_assignment_due_occurrence TO epm_lifecycle;

DO $$DECLARE old text:='2e2dd822dd240379fd3ee7068d7f2c91d5a95dcf197490a4a52cc9d562e6c386';new text:='b0efbf3f98f18add1a80cd1631c9fde9626e2386975d973cf60ca13e122c3b19';d text;r text;
 b text:='''transfer_cleanup_certificate'',''transfer_cleanup_request'',''planning_assignment_state'',''planning_assignment_version''';
 a text:='''planning_assignment_control_current'',''planning_assignment_control_event'',''planning_assignment_due_occurrence'',''transfer_cleanup_certificate'',''transfer_cleanup_request'',''planning_assignment_state'',''planning_assignment_version''';
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(old in d)=0 OR position(b in d)=0 THEN RAISE EXCEPTION 'RESET_0117_DEFINITION_MISMATCH';END IF;
 r:=replace(replace(d,old,new),b,a);EXECUTE r;END$$;
