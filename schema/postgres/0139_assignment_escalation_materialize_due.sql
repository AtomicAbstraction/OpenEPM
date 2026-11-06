-- Separate bounded due-occurrence discovery from claim/settlement. The
-- scheduler can make assignment work visible without claiming it, while the
-- ordinary claim primitive remains one fair worker quantum.
CREATE FUNCTION epm.assignment_escalation_materialize_due(p_limit integer)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE inserted_count integer;
BEGIN
  IF NOT pg_has_role(session_user,'epm_worker','member') THEN
    RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_WORKER_REQUIRED';
  END IF;
  IF p_limit IS NULL OR p_limit<1 OR p_limit>1000 THEN
    RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_MATERIALIZE_LIMIT_INVALID'
      USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(
    hashtextextended('epm.assignment.escalation.materialize',0));
  WITH due AS MATERIALIZED (
    SELECT s.workspace_id,s.application_id,
      s.active_assignment_set_id assignment_set_id,
      s.active_version assignment_version,a->>'assignmentId' assignment_id,
      (a->>'dueAt')::timestamptz due_at
    FROM epm.planning_assignment_state s
    JOIN epm.planning_assignment_version v
      ON v.workspace_id=s.workspace_id AND v.application_id=s.application_id
     AND v.assignment_set_id=s.active_assignment_set_id
     AND v.version=s.active_version
    JOIN epm.planning_workflow_policy_state ps
      ON ps.workspace_id=s.workspace_id AND ps.application_id=s.application_id
     AND ps.active_policy_id=v.policy_id AND ps.active_version=v.policy_version
    JOIN epm.planning_workflow_policy_version pv
      ON pv.workspace_id=ps.workspace_id AND pv.application_id=ps.application_id
     AND pv.policy_id=ps.active_policy_id AND pv.version=ps.active_version
     AND pv.canonical_digest=v.policy_digest
    JOIN epm.workspace w ON w.workspace_id=s.workspace_id AND w.status='Active'
    JOIN epm.application app
      ON app.workspace_id=s.workspace_id AND app.application_id=s.application_id
     AND app.status='Active'
    JOIN epm.application_state ast
      ON ast.workspace_id=s.workspace_id AND ast.application_id=s.application_id
     AND ast.processing_mode='Active'
    CROSS JOIN LATERAL jsonb_array_elements(v.definition->'assignments') a
    WHERE s.active_assignment_set_id IS NOT NULL
      AND jsonb_typeof(a)='object'
      AND a->>'assignmentId' IS NOT NULL
      AND a->>'dueAt' IS NOT NULL
      AND jsonb_typeof(a->'escalation')='object'
      AND (a->'escalation'->>'afterDueMinutes') IS NOT NULL
      AND clock_timestamp()>=(a->>'dueAt')::timestamptz+
        ((a->'escalation'->>'afterDueMinutes')::integer*interval '1 minute')
      AND (v.definition->>'effectiveFrom' IS NULL OR
           clock_timestamp()>=(v.definition->>'effectiveFrom')::timestamptz)
      AND (v.definition->>'effectiveTo' IS NULL OR
           clock_timestamp()<=(v.definition->>'effectiveTo')::timestamptz)
      AND NOT EXISTS (
        SELECT 1 FROM epm.planning_assignment_due_occurrence existing
        WHERE existing.workspace_id=s.workspace_id
          AND existing.application_id=s.application_id
          AND existing.assignment_set_id=s.active_assignment_set_id
          AND existing.assignment_version=s.active_version
          AND existing.assignment_id=a->>'assignmentId'
          AND existing.due_at=(a->>'dueAt')::timestamptz)
    ORDER BY (a->>'dueAt')::timestamptz,s.workspace_id,s.application_id,
      a->>'assignmentId'
    LIMIT p_limit
  )
  INSERT INTO epm.planning_assignment_due_occurrence(
    workspace_id,application_id,assignment_set_id,assignment_version,
    assignment_id,due_at,status)
  SELECT workspace_id,application_id,assignment_set_id,assignment_version,
    assignment_id,due_at,'Pending' FROM due
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_count=ROW_COUNT;
  RETURN inserted_count;
END $$;

-- Migration 0118 coupled discovery to claim. Preserve the accepted claim
-- signature while making it claim/takeover only.
CREATE OR REPLACE FUNCTION epm.assignment_escalation_worker_claim(
 p_claimant text,p_lease_seconds integer)
RETURNS TABLE(workspace_id text,application_id text,assignment_set_id text,
 assignment_version bigint,assignment_id text,due_at timestamptz,
 claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR
    p_claimant!~'^[A-Za-z0-9][A-Za-z0-9._:@/-]*$' OR
    length(p_claimant)>300 OR p_lease_seconds<5 OR p_lease_seconds>300 THEN
   RAISE EXCEPTION 'ASSIGNMENT_ESCALATION_WORKER_ARGUMENT_INVALID';
 END IF;
 SELECT q.* INTO c FROM (
   SELECT DISTINCT ON (o.workspace_id,o.application_id)
     o.workspace_id,o.application_id,o.assignment_set_id,o.assignment_version,
     o.assignment_id,o.due_at,o.claim_generation
   FROM epm.planning_assignment_due_occurrence o
   JOIN epm.workspace w ON w.workspace_id=o.workspace_id AND w.status='Active'
   JOIN epm.application a ON a.workspace_id=o.workspace_id
    AND a.application_id=o.application_id AND a.status='Active'
   JOIN epm.application_state ast ON ast.workspace_id=o.workspace_id
    AND ast.application_id=o.application_id AND ast.processing_mode='Active'
   WHERE o.status='Pending' OR
     (o.status='Running' AND o.lease_until<clock_timestamp())
   ORDER BY o.workspace_id,o.application_id,o.due_at,o.assignment_id
 ) q ORDER BY q.due_at,q.workspace_id,q.application_id LIMIT 1;
 IF c IS NULL THEN RETURN;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(c.workspace_id,0));
 PERFORM pg_advisory_xact_lock(
   hashtextextended(c.workspace_id||chr(31)||c.application_id,0));
 RETURN QUERY UPDATE epm.planning_assignment_due_occurrence o
 SET status='Running',claim_generation=o.claim_generation+1,
   claimant=p_claimant,
   lease_until=clock_timestamp()+p_lease_seconds*interval '1 second'
 WHERE o.workspace_id=c.workspace_id AND o.application_id=c.application_id
  AND o.assignment_set_id=c.assignment_set_id
  AND o.assignment_version=c.assignment_version
  AND o.assignment_id=c.assignment_id AND o.due_at=c.due_at
  AND (o.status='Pending' OR
       (o.status='Running' AND o.lease_until<clock_timestamp()))
 RETURNING o.workspace_id,o.application_id,o.assignment_set_id,
   o.assignment_version,o.assignment_id,o.due_at,o.claim_generation;
END $$;

REVOKE ALL ON FUNCTION epm.assignment_escalation_materialize_due(integer)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.assignment_escalation_materialize_due(integer)
 TO epm_worker;
