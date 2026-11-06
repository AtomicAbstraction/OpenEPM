-- Reset inventory needs only schedule dispatch control columns added by 0102.
-- Existing lifecycle RLS remains the security boundary; no write privilege is
-- granted and merely configured active schedules are intentionally nonblocking.
GRANT SELECT(dispatch_generation,dispatch_claimant,dispatch_lease_until)
 ON epm.planning_forecast_schedule_state TO epm_lifecycle;

DO $$DECLARE
 d text;r text;
 marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gates text:=
 '    IF EXISTS (SELECT 1 FROM epm.planning_forecast_occurrence WHERE workspace_id=p_workspace_id AND status IN (''accepted'',''ready'',''running'',''cancel_requested'',''business_published'',''needs_inspection'')) THEN RAISE EXCEPTION ''UNSETTLED_FORECAST_OCCURRENCES''; END IF;'||chr(10)||
 '    IF EXISTS (SELECT 1 FROM epm.planning_forecast_schedule_state WHERE workspace_id=p_workspace_id AND dispatch_claimant IS NOT NULL AND dispatch_lease_until IS NOT NULL) THEN RAISE EXCEPTION ''UNSETTLED_FORECAST_SCHEDULE_DISPATCH''; END IF;'||chr(10)||chr(10);
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(marker in d)=0
 OR position('UNSETTLED_CUBE_AGGREGATE_QUERIES' in d)=0
 OR position('UNSETTLED_FORECAST_OCCURRENCES' in d)>0
 OR position('UNSETTLED_FORECAST_SCHEDULE_DISPATCH' in d)>0
 THEN RAISE EXCEPTION 'RESET_0122_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gates||marker);EXECUTE r;
END$$;
