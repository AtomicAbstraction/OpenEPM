-- Parent composite workflows are independently durable and may be active
-- between child jobs. Lifecycle sees only reset-blocking inventory columns.
GRANT SELECT(workspace_id,application_id,workflow_id,status,claim_generation,
 claimant,lease_until) ON epm.python_program_workflow TO epm_lifecycle;
CREATE POLICY python_program_workflow_lifecycle_inventory
 ON epm.python_program_workflow FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

DO $$DECLARE
 d text;r text;
 marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gate text:='    IF EXISTS (SELECT 1 FROM epm.python_program_workflow WHERE workspace_id=p_workspace_id AND status IN (''accepted'',''running'',''cancel_requested'',''needs_inspection'')) THEN RAISE EXCEPTION ''UNSETTLED_PYTHON_WORKFLOWS''; END IF;'||chr(10)||chr(10);
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(marker in d)=0
 OR position('UNSETTLED_FORECAST_OCCURRENCES' in d)=0
 OR position('UNSETTLED_PYTHON_WORKFLOWS' in d)>0
 THEN RAISE EXCEPTION 'RESET_0123_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gate||marker);EXECUTE r;
END$$;
