BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=378) THEN
    RAISE EXCEPTION 'MIGRATION_0379_REQUIRES_0378';
  END IF;
END $migration$;

-- A completed business workflow is durable evidence of what ran, not active
-- ownership of the source forever.  Keep its exact sealed plan and build
-- inputs, while retiring only unreferenced diagnostic payloads from the old
-- source.  Active builds/workflows remain fail-closed in fixed Python.
CREATE OR REPLACE FUNCTION epm.definition_source_payload_retire(
  w text,a text,pid text,token text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE affected integer; BEGIN
 IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
  OR current_setting('epm.application_id',true) IS DISTINCT FROM a
  OR NOT EXISTS(SELECT 1 FROM epm.python_program_definition s WHERE
   (s.workspace_id,s.application_id,s.program_id,s.source_token)=(w,a,pid,token)) THEN
  RAISE EXCEPTION 'DEFINITION_PAYLOAD_RETIREMENT_SCOPE_INVALID' USING ERRCODE='42501';
 END IF;
 IF EXISTS(SELECT 1 FROM epm.python_program_build b WHERE
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token)
  AND b.status IN('accepted','ready','running','cancel_requested')) THEN
  RAISE EXCEPTION 'DEFINITION_PAYLOAD_ACTIVE_WORK_BLOCKER';
 END IF;
 DELETE FROM epm.python_plan_artifact p USING epm.python_program_build b WHERE
  (p.workspace_id,p.application_id,p.build_id)=(b.workspace_id,b.application_id,b.build_id)
  AND(b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token)
  AND NOT EXISTS(SELECT 1 FROM epm.python_program_workflow f WHERE
   (f.workspace_id,f.application_id,f.build_id)=(b.workspace_id,b.application_id,b.build_id));
 GET DIAGNOSTICS affected=ROW_COUNT;
 UPDATE epm.python_program_build b SET
  status=CASE WHEN status='sealed' THEN 'expired' ELSE status END,
  parameter_values='{}'::jsonb,definition_parameters='{}'::jsonb,
  diagnostics=NULL,updated_at=transaction_timestamp()
 WHERE(b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token)
  AND b.status IN('sealed','failed','cancelled','expired')
  AND NOT EXISTS(SELECT 1 FROM epm.python_program_workflow f WHERE
   (f.workspace_id,f.application_id,f.build_id)=(b.workspace_id,b.application_id,b.build_id));
 RETURN affected;
END $$;
REVOKE ALL ON FUNCTION epm.definition_source_payload_retire(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.definition_source_payload_retire(text,text,text,text) TO epm_runtime;

COMMENT ON FUNCTION epm.definition_source_payload_retire(text,text,text,text) IS
 'Retire unreferenced terminal build payloads for a replaced current source; preserve terminal workflow evidence and reject active work.';

COMMIT;
SELECT '0379 applied' AS migration;
