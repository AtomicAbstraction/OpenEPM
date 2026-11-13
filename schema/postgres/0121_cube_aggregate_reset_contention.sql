-- Reject reset/delete while a technical cube query can still compute or seal.
-- Migration 0088 already grants epm_lifecycle workspace-scoped RLS SELECT;
-- this migration intentionally adds no privilege.
DO $$DECLARE
 d text;r text;
 marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gate text:='    IF EXISTS (SELECT 1 FROM epm.cube_aggregate_query WHERE workspace_id=p_workspace_id AND status IN (''accepted'',''ready'',''running'',''computed'',''cancel_requested'')) THEN RAISE EXCEPTION ''UNSETTLED_CUBE_AGGREGATE_QUERIES''; END IF;'||chr(10)||chr(10);
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(marker in d)=0
 OR position('UNSETTLED_CUBE_AGGREGATE_QUERIES' in d)>0
 OR position('UNSETTLED_PYTHON_BUILDS' in d)=0
 THEN RAISE EXCEPTION 'RESET_0121_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gate||marker);EXECUTE r;
END$$;
