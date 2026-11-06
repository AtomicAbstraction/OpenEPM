-- Immutable workflow definitions and assignment pins remain immutable for
-- every ordinary caller.  Permit deletion only inside the exact owner-reset
-- SECURITY DEFINER transaction, with both the lifecycle role and a local
-- reset context present.
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=237) THEN
  RAISE EXCEPTION 'MIGRATION_0238_PREDECESSOR_0237_REQUIRED';
 END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.application_workflow_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
 IF TG_OP='DELETE'
    AND current_setting('epm.lifecycle_context',true)='workspace_reset'
    AND pg_has_role(session_user,'epm_lifecycle','member') THEN
  RETURN OLD;
 END IF;
 RAISE EXCEPTION 'APPLICATION_WORKFLOW_IMMUTABLE' USING ERRCODE='23514';
END $function$;
REVOKE ALL ON FUNCTION epm.application_workflow_immutable()
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

DO $migration$
DECLARE definition text;revised text;
DECLARE marker text :=
 $pattern$    FOREACH v_table IN ARRAY ARRAY[$pattern$;
DECLARE replacement text :=
 $pattern$    PERFORM set_config('epm.lifecycle_context','workspace_reset',true);
    FOREACH v_table IN ARRAY ARRAY[$pattern$;
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position(marker IN definition)=0 OR position(replacement IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0238_DEFINITION_MISMATCH';
 END IF;
 revised:=replace(definition,marker,replacement);
 IF revised=definition OR position(replacement IN revised)=0 THEN
  RAISE EXCEPTION 'RESET_0238_UPDATE_FAILED';
 END IF;
 EXECUTE revised;
END $migration$;
