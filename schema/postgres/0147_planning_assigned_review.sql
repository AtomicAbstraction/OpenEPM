-- Assignment-bound sequential review.  Legacy planning_submission remains
-- byte-compatible; these additive records make the immutable assignment the
-- authority for new assigned submissions.
-- For a Group first reviewer, planning_submission.reviewer_subject_id contains
-- `__assigned_group_non_authoritative__` solely to satisfy the legacy shape.
-- The assigned tables are authoritative and legacy approve/reopen reject them.
CREATE TABLE epm.planning_assigned_submission(
 workspace_id text NOT NULL,application_id text NOT NULL,lock_id text NOT NULL,
 assignment_set_id text NOT NULL,assignment_version bigint NOT NULL,
 assignment_digest text NOT NULL CHECK(assignment_digest~'^[0-9a-f]{64}$'),
 assignment_id text NOT NULL,policy_id text NOT NULL,policy_version bigint NOT NULL,
 policy_digest text NOT NULL CHECK(policy_digest~'^[0-9a-f]{64}$'),
 control_version bigint NOT NULL CHECK(control_version>=0),chain_digest text NOT NULL CHECK(chain_digest~'^[0-9a-f]{64}$'),
 current_step integer NOT NULL CHECK(current_step>0),step_count integer NOT NULL CHECK(step_count BETWEEN 1 AND 20),
 status text NOT NULL CHECK(status IN('Submitted','InReview','Approved','Returned','Reopened')),
 workflow_version bigint NOT NULL CHECK(workflow_version>0),
 PRIMARY KEY(workspace_id,application_id,lock_id),
 FOREIGN KEY(workspace_id,application_id,lock_id) REFERENCES epm.planning_submission(workspace_id,application_id,lock_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,assignment_set_id,assignment_version) REFERENCES epm.planning_assignment_version(workspace_id,application_id,assignment_set_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,policy_id,policy_version) REFERENCES epm.planning_workflow_policy_version(workspace_id,application_id,policy_id,version) ON DELETE RESTRICT,
 CHECK(current_step<=step_count),
 CHECK((status='Approved' AND current_step=step_count) OR status<>'Approved'));
CREATE TABLE epm.planning_assigned_reviewer(
 workspace_id text NOT NULL,application_id text NOT NULL,lock_id text NOT NULL,
 reviewer_ordinal integer NOT NULL CHECK(reviewer_ordinal BETWEEN 1 AND 20),
 reviewer_kind text NOT NULL CHECK(reviewer_kind IN('Subject','Group')),
 reviewer_issuer text NOT NULL,
 reviewer_id text NOT NULL,
 PRIMARY KEY(workspace_id,application_id,lock_id,reviewer_ordinal),
 FOREIGN KEY(workspace_id,application_id,lock_id) REFERENCES epm.planning_assigned_submission(workspace_id,application_id,lock_id) ON DELETE RESTRICT);
CREATE TABLE epm.planning_assigned_review_event(
 workspace_id text NOT NULL,application_id text NOT NULL,lock_id text NOT NULL,
 event_ordinal bigint NOT NULL CHECK(event_ordinal>0),workflow_version bigint NOT NULL CHECK(workflow_version>0),
 action text NOT NULL CHECK(action IN('Submitted','Advanced','Approved','Returned','Reopened')),
 reviewer_ordinal integer,actor_issuer text NOT NULL,actor_subject_id text NOT NULL,
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),committed_revision bigint NOT NULL CHECK(committed_revision>0),
 occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,lock_id,event_ordinal),
 FOREIGN KEY(workspace_id,application_id,lock_id) REFERENCES epm.planning_assigned_submission(workspace_id,application_id,lock_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,lock_id,reviewer_ordinal) REFERENCES epm.planning_assigned_reviewer(workspace_id,application_id,lock_id,reviewer_ordinal) ON DELETE RESTRICT);

CREATE FUNCTION epm.validate_planning_assigned_chain() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$DECLARE a record;cnt integer;maxord integer;BEGIN
 SELECT * INTO a FROM epm.planning_assigned_submission WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id AND lock_id=NEW.lock_id;
 IF a IS NULL THEN RETURN NEW;END IF;
 SELECT count(*),coalesce(max(reviewer_ordinal),0) INTO cnt,maxord FROM epm.planning_assigned_reviewer WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id AND lock_id=NEW.lock_id;
 IF cnt<>a.step_count OR maxord<>a.step_count OR a.current_step>cnt THEN RAISE EXCEPTION 'PLANNING_ASSIGNED_CHAIN_INVALID';END IF;
 RETURN NEW;END$$;
REVOKE ALL ON FUNCTION epm.validate_planning_assigned_chain() FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
CREATE CONSTRAINT TRIGGER planning_assigned_chain_submission AFTER INSERT OR UPDATE ON epm.planning_assigned_submission DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epm.validate_planning_assigned_chain();
CREATE CONSTRAINT TRIGGER planning_assigned_chain_reviewer AFTER INSERT OR UPDATE ON epm.planning_assigned_reviewer DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION epm.validate_planning_assigned_chain();
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['planning_assigned_submission','planning_assigned_reviewer','planning_assigned_review_event'] LOOP
 EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY %I_runtime ON epm.%I TO epm_runtime USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',t,t);
 EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I TO epm_lifecycle USING(workspace_id=current_setting(''epm.workspace_id'',true))',t,t);
END LOOP;END$$;
REVOKE ALL ON epm.planning_assigned_submission,epm.planning_assigned_reviewer,epm.planning_assigned_review_event FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.planning_assigned_submission TO epm_runtime;
GRANT UPDATE(current_step,status,workflow_version) ON epm.planning_assigned_submission TO epm_runtime;
GRANT SELECT,INSERT ON epm.planning_assigned_reviewer,epm.planning_assigned_review_event TO epm_runtime;
GRANT SELECT(workspace_id,application_id,lock_id) ON epm.planning_assigned_submission,epm.planning_assigned_reviewer,epm.planning_assigned_review_event TO epm_lifecycle;

DO $$DECLARE definition text;revised text;
 old_pair text:=$p$'planning_assignment_control_current','planning_assignment_control_event',$p$;
 new_pair text:=$p$'planning_assigned_review_event','planning_assigned_reviewer','planning_assigned_submission','planning_assignment_control_current','planning_assignment_control_event',$p$;
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN RAISE EXCEPTION 'RESET_0147_DEFINITION_MISMATCH';END IF;
 revised:=replace(definition,old_pair,new_pair);IF revised=definition THEN RAISE EXCEPTION 'RESET_0147_DEFINITION_MISMATCH';END IF;EXECUTE revised;
END$$;
