-- Due occurrences are durable duplicate-suppression/audit state. Only a live
-- Running claim conflicts with reset; Pending, Completed and Cancelled do not.
GRANT SELECT(due_at,status,claim_generation,claimant,lease_until,result_event_ordinal,
 completed_at) ON epm.planning_assignment_due_occurrence TO epm_lifecycle;

CREATE OR REPLACE FUNCTION epm.planning_assignment_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' AND current_setting('epm.projection_cleanup_reset_context',true)=
    jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                      pg_backend_pid())::text THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'PLANNING_ASSIGNMENT_VERSION_IMMUTABLE' USING ERRCODE='23514';
END$$;

DO $$DECLARE
 d text;r text;
 marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gate text:='    IF EXISTS (SELECT 1 FROM epm.planning_assignment_due_occurrence WHERE workspace_id=p_workspace_id AND status=''Running'' AND claimant IS NOT NULL AND lease_until IS NOT NULL) THEN RAISE EXCEPTION ''UNSETTLED_ASSIGNMENT_ESCALATION_CLAIMS''; END IF;'||chr(10)||chr(10);
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(marker in d)=0 OR position('UNSETTLED_TRANSFER_CLEANUP' in d)=0
 OR position('UNSETTLED_ASSIGNMENT_ESCALATION_CLAIMS' in d)>0
 THEN RAISE EXCEPTION 'RESET_0125_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gate||marker);EXECUTE r;
END$$;
