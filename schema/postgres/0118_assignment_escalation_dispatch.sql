-- Server-owned fair assignment escalation claims and fenced settlement.
ALTER TABLE epm.planning_assignment_due_occurrence DROP CONSTRAINT planning_assignment_due_occurrence_status_check;
ALTER TABLE epm.planning_assignment_due_occurrence ADD CONSTRAINT planning_assignment_due_occurrence_status_check
 CHECK(status IN('Pending','Running','Completed','Cancelled'));

CREATE FUNCTION epm.assignment_escalation_worker_claim(p_claimant text,p_lease_seconds integer)
RETURNS TABLE(workspace_id text,application_id text,assignment_set_id text,
 assignment_version bigint,assignment_id text,due_at timestamptz,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR p_claimant!~'^[A-Za-z0-9][A-Za-z0-9._:@/-]*$' OR length(p_claimant)>300
    OR p_lease_seconds<5 OR p_lease_seconds>300 THEN
   RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_WORKER_ARGUMENT_INVALID';
 END IF;
 INSERT INTO epm.planning_assignment_due_occurrence(
   workspace_id,application_id,assignment_set_id,assignment_version,
   assignment_id,due_at,status)
 SELECT s.workspace_id,s.application_id,s.active_assignment_set_id,s.active_version,
   a->>'assignmentId',(a->>'dueAt')::timestamptz,'Pending'
 FROM epm.planning_assignment_state s
 JOIN epm.planning_assignment_version v ON v.workspace_id=s.workspace_id
  AND v.application_id=s.application_id AND v.assignment_set_id=s.active_assignment_set_id
  AND v.version=s.active_version
 JOIN epm.planning_workflow_policy_state p ON p.workspace_id=s.workspace_id
  AND p.application_id=s.application_id AND p.active_policy_id=v.policy_id
  AND p.active_version=v.policy_version
 CROSS JOIN LATERAL jsonb_array_elements(v.definition->'assignments') a
 WHERE s.active_assignment_set_id IS NOT NULL
  AND clock_timestamp()>=(a->>'dueAt')::timestamptz+
    ((a->'escalation'->>'afterDueMinutes')::integer*interval '1 minute')
 ON CONFLICT DO NOTHING;
 SELECT q.* INTO c FROM (
   SELECT DISTINCT ON (o.workspace_id,o.application_id)
     o.workspace_id,o.application_id,o.assignment_set_id,o.assignment_version,
     o.assignment_id,o.due_at,o.claim_generation
   FROM epm.planning_assignment_due_occurrence o
   WHERE o.status='Pending' OR
     (o.status='Running' AND o.lease_until<clock_timestamp())
   ORDER BY o.workspace_id,o.application_id,o.due_at,o.assignment_id
 ) q ORDER BY q.due_at,q.workspace_id,q.application_id LIMIT 1;
 IF c IS NULL THEN RETURN;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(c.workspace_id,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(c.workspace_id||chr(31)||c.application_id,0));
 RETURN QUERY UPDATE epm.planning_assignment_due_occurrence o
 SET status='Running',claim_generation=o.claim_generation+1,claimant=p_claimant,
   lease_until=clock_timestamp()+p_lease_seconds*interval '1 second'
 WHERE o.workspace_id=c.workspace_id AND o.application_id=c.application_id
  AND o.assignment_set_id=c.assignment_set_id AND o.assignment_version=c.assignment_version
  AND o.assignment_id=c.assignment_id AND o.due_at=c.due_at
  AND (o.status='Pending' OR(o.status='Running' AND o.lease_until<clock_timestamp()))
 RETURNING o.workspace_id,o.application_id,o.assignment_set_id,
   o.assignment_version,o.assignment_id,o.due_at,o.claim_generation;
END$$;

CREATE FUNCTION epm.assignment_escalation_worker_renew(
 p_workspace text,p_application text,p_set text,p_version bigint,p_assignment text,
 p_due timestamptz,p_generation bigint,p_claimant text,p_lease_seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR p_lease_seconds<5 OR p_lease_seconds>300 THEN
  RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_WORKER_ARGUMENT_INVALID';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace||chr(31)||p_application,0));
 UPDATE epm.planning_assignment_due_occurrence SET
  lease_until=clock_timestamp()+p_lease_seconds*interval '1 second'
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND assignment_set_id=p_set AND assignment_version=p_version
  AND assignment_id=p_assignment AND due_at=p_due AND status='Running'
  AND claim_generation=p_generation AND claimant=p_claimant
  AND lease_until>=clock_timestamp();
 RETURN FOUND;
END$$;

CREATE FUNCTION epm.assignment_escalation_worker_cancel(
 p_workspace text,p_application text,p_set text,p_version bigint,p_assignment text,
 p_due timestamptz,p_generation bigint,p_claimant text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_WORKER_REQUIRED';END IF;
 PERFORM set_config('epm.workspace_id',p_workspace,true);
 PERFORM set_config('epm.application_id',p_application,true);
 PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace||chr(31)||p_application,0));
 UPDATE epm.planning_assignment_due_occurrence SET status='Cancelled',claimant=NULL,lease_until=NULL
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND assignment_set_id=p_set AND assignment_version=p_version
  AND assignment_id=p_assignment AND due_at=p_due AND status='Running'
  AND claim_generation=p_generation AND claimant=p_claimant
  AND lease_until>=clock_timestamp();RETURN FOUND;
END$$;

CREATE FUNCTION epm.assignment_escalation_worker_settle(
 p_workspace text,p_application text,p_set text,p_version bigint,p_assignment text,
 p_due timestamptz,p_generation bigint,p_claimant text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE o record;v record;s record;a jsonb;r jsonb;reviewer jsonb;ordinal bigint;
 control_version bigint;revision bigint;data_revision bigint;operation text;command_digest text;result jsonb;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_WORKER_REQUIRED';END IF;
 PERFORM set_config('epm.workspace_id',p_workspace,true);
 PERFORM set_config('epm.application_id',p_application,true);
 PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_workspace||chr(31)||p_application,0));
 SELECT * INTO o FROM epm.planning_assignment_due_occurrence WHERE workspace_id=p_workspace
  AND application_id=p_application AND assignment_set_id=p_set AND assignment_version=p_version
  AND assignment_id=p_assignment AND due_at=p_due FOR UPDATE;
 IF o.status<>'Running' OR o.claim_generation<>p_generation OR o.claimant<>p_claimant
    OR o.lease_until<clock_timestamp() THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_CLAIM_STALE';END IF;
 SELECT av.*,aps.active_assignment_set_id,aps.active_version INTO v
 FROM epm.planning_assignment_version av JOIN epm.planning_assignment_state aps
  ON aps.workspace_id=av.workspace_id AND aps.application_id=av.application_id
 WHERE av.workspace_id=p_workspace AND av.application_id=p_application
  AND av.assignment_set_id=p_set AND av.version=p_version;
 IF v.active_assignment_set_id IS DISTINCT FROM p_set OR v.active_version IS DISTINCT FROM p_version THEN
  RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_ASSIGNMENT_REVOKED';END IF;
 IF NOT EXISTS(SELECT 1 FROM epm.planning_workflow_policy_state ps
  JOIN epm.planning_workflow_policy_version pv ON pv.workspace_id=ps.workspace_id
   AND pv.application_id=ps.application_id AND pv.policy_id=ps.active_policy_id
   AND pv.version=ps.active_version
  WHERE ps.workspace_id=p_workspace AND ps.application_id=p_application
   AND ps.active_policy_id=v.policy_id AND ps.active_version=v.policy_version
   AND pv.canonical_digest=v.policy_digest) THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_POLICY_REVOKED';END IF;
 SELECT value INTO a FROM jsonb_array_elements(v.definition->'assignments') WHERE value->>'assignmentId'=p_assignment;
 IF a IS NULL THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_ITEM_REVOKED';END IF;
 reviewer:=a->'reviewerChain'->((a->'escalation'->>'reviewerOrdinal')::integer-1);
 IF reviewer IS NULL THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_REVIEWER_INVALID';END IF;
 IF reviewer->>'kind'='Subject' AND NOT EXISTS(SELECT 1 FROM epm.application_access_grant g
   WHERE g.issuer=v.creator_issuer AND g.subject_id=reviewer->>'id'
    AND g.workspace_id=p_workspace AND g.application_id=p_application) THEN
   RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_REVIEWER_GRANT_REVOKED';END IF;
 SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.planning_assignment_control_event
  WHERE workspace_id=p_workspace AND application_id=p_application AND assignment_set_id=p_set
   AND assignment_version=p_version AND assignment_id=p_assignment;
 operation:='assignment-escalation:'||p_set||':'||p_version||':'||p_assignment||':'||extract(epoch from p_due)::bigint;
 command_digest:=encode(pg_catalog.sha256(convert_to(operation,'UTF8')),'hex');
 INSERT INTO epm.planning_assignment_control_event(workspace_id,application_id,
  assignment_set_id,assignment_version,assignment_id,event_ordinal,event_kind,
  actor_issuer,actor_subject_id,target_issuer,target_subject_id,target_group_id,
  reason,request_key,command_digest)
 VALUES(p_workspace,p_application,p_set,p_version,p_assignment,ordinal,'Escalated',
  'urn:openepm:worker',p_claimant,CASE WHEN reviewer->>'kind'='Subject' THEN v.creator_issuer END,
  CASE WHEN reviewer->>'kind'='Subject' THEN reviewer->>'id' END,
  CASE WHEN reviewer->>'kind'='Group' THEN reviewer->>'id' END,
  'Server due escalation',operation,command_digest);
 SELECT coalesce(c.control_version,0)+1 INTO control_version
  FROM (SELECT 1) x LEFT JOIN epm.planning_assignment_control_current c
   ON c.workspace_id=p_workspace AND c.application_id=p_application
   AND c.assignment_set_id=p_set AND c.assignment_version=p_version AND c.assignment_id=p_assignment;
 INSERT INTO epm.planning_assignment_control_current(workspace_id,application_id,
  assignment_set_id,assignment_version,assignment_id,control_version,assignee_issuer,
  assignee_subject_id,assignee_group_id,delegation_depth,escalated_reviewer_ordinal)
 VALUES(p_workspace,p_application,p_set,p_version,p_assignment,control_version,
  CASE WHEN reviewer->>'kind'='Subject' THEN v.creator_issuer END,
  CASE WHEN reviewer->>'kind'='Subject' THEN reviewer->>'id' END,
  CASE WHEN reviewer->>'kind'='Group' THEN reviewer->>'id' END,0,
  (a->'escalation'->>'reviewerOrdinal')::integer)
 ON CONFLICT(workspace_id,application_id,assignment_set_id,assignment_version,assignment_id)
 DO UPDATE SET control_version=excluded.control_version,assignee_issuer=excluded.assignee_issuer,
  assignee_subject_id=excluded.assignee_subject_id,assignee_group_id=excluded.assignee_group_id,
  delegator_issuer=NULL,delegator_subject_id=NULL,delegation_depth=0,
  delegation_expires_at=NULL,escalated_reviewer_ordinal=excluded.escalated_reviewer_ordinal,
  updated_at=transaction_timestamp();
 SELECT st.commit_revision+1,st.data_revision INTO revision,data_revision
  FROM epm.application_state st WHERE st.workspace_id=p_workspace
  AND st.application_id=p_application FOR UPDATE;
 UPDATE epm.application_state SET policy_revision=policy_revision+1,commit_revision=revision
  WHERE workspace_id=p_workspace AND application_id=p_application;
 result:=jsonb_build_object('operationId',operation,'assignmentId',p_assignment,
  'event','Escalated','eventOrdinal',ordinal,'controlVersion',control_version,
  'dataRevision',data_revision,'committedRevision',revision);
 INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
  command_digest,actor_id,committed_revision,result)
 VALUES(p_workspace,p_application,operation,command_digest,p_claimant,revision,result)
 ON CONFLICT(workspace_id,application_id,operation_id) DO NOTHING;
 UPDATE epm.planning_assignment_due_occurrence SET status='Completed',claimant=NULL,
  lease_until=NULL,result_event_ordinal=ordinal,completed_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND assignment_set_id=p_set AND assignment_version=p_version
  AND assignment_id=p_assignment AND due_at=p_due AND claim_generation=p_generation
  AND claimant=p_claimant AND lease_until>=clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_CLAIM_STALE';END IF;
 RETURN result;
END$$;

REVOKE ALL ON FUNCTION epm.assignment_escalation_worker_claim(text,integer),
 epm.assignment_escalation_worker_renew(text,text,text,bigint,text,timestamptz,bigint,text,integer),
 epm.assignment_escalation_worker_cancel(text,text,text,bigint,text,timestamptz,bigint,text),
 epm.assignment_escalation_worker_settle(text,text,text,bigint,text,timestamptz,bigint,text)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.assignment_escalation_worker_claim(text,integer),
 epm.assignment_escalation_worker_renew(text,text,text,bigint,text,timestamptz,bigint,text,integer),
 epm.assignment_escalation_worker_cancel(text,text,text,bigint,text,timestamptz,bigint,text),
 epm.assignment_escalation_worker_settle(text,text,text,bigint,text,timestamptz,bigint,text)
 TO epm_worker;

DO $$DECLARE old text:='b0efbf3f98f18add1a80cd1631c9fde9626e2386975d973cf60ca13e122c3b19';new text:='b0efbf3f98f18add1a80cd1631c9fde9626e2386975d973cf60ca13e122c3b19';d text;r text;
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(old in d)=0 THEN RAISE EXCEPTION 'RESET_0118_DEFINITION_MISMATCH';END IF;
 r:=replace(d,old,new);EXECUTE r;END$$;
