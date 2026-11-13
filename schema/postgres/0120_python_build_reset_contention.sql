-- Reject workspace reset/delete while an isolated Python build can still act.
-- The lifecycle role receives only the columns required by the signed reset
-- inventory, scoped to the server-selected workspace through RLS.
CREATE POLICY python_program_build_lifecycle
 ON epm.python_program_build FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

GRANT SELECT(workspace_id,application_id,build_id,status,claim_generation,
 request_digest,program_id,program_version,error_code,updated_at)
 ON epm.python_program_build TO epm_lifecycle;

-- Forward-only patch of the owner credential deletion primitive. Structural
-- schema fingerprint is unchanged: this migration adds a policy, privilege,
-- and an active-work gate, but no relation or foreign key.
DO $$DECLARE
 d text;r text;
 marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gate text:='    IF EXISTS (SELECT 1 FROM epm.python_program_build WHERE workspace_id=p_workspace_id AND status IN (''accepted'',''ready'',''running'',''cancel_requested'')) THEN RAISE EXCEPTION ''UNSETTLED_PYTHON_BUILDS''; END IF;'||chr(10)||chr(10);
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(marker in d)=0 OR position('UNSETTLED_PYTHON_BUILDS' in d)>0
 THEN RAISE EXCEPTION 'RESET_0120_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gate||marker);EXECUTE r;
END$$;
