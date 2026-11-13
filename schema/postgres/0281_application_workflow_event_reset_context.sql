BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=280) THEN
    RAISE EXCEPTION 'MIGRATION_0281_REQUIRES_0280';
  END IF;
END $migration$;

-- Workflow history is immutable to every ordinary caller. Owner reset is the
-- sole deletion boundary and already establishes both the local lifecycle
-- context and the epm_lifecycle session role. Require both, matching the
-- workflow-definition exception installed by migration 0238.
CREATE OR REPLACE FUNCTION epm.application_workflow_event_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='DELETE'
     AND current_setting('epm.lifecycle_context',true)='workspace_reset'
     AND pg_has_role(session_user,'epm_lifecycle','member') THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'APPLICATION_WORKFLOW_EVENT_IMMUTABLE'
    USING ERRCODE='23514';
END $function$;
REVOKE ALL ON FUNCTION epm.application_workflow_event_immutable()
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

DO $migration$
DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position('set_config' IN definition)=0
     OR position('epm.lifecycle_context' IN definition)=0
     OR position('workspace_reset' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0281_CONTEXT_MISSING';
  END IF;
  IF position('''application_workflow_event''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0281_EVENT_INVENTORY_MISSING';
  END IF;
END $migration$;

COMMIT;
