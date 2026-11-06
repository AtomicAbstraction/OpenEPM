-- Assignment versions remain immutable except inside the same exact
-- owner-reset context used for immutable workflow definitions.
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=238) THEN
  RAISE EXCEPTION 'MIGRATION_0239_PREDECESSOR_0238_REQUIRED';
 END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.application_assignment_version_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
 IF TG_OP='DELETE'
    AND current_setting('epm.lifecycle_context',true)='workspace_reset'
    AND pg_has_role(session_user,'epm_lifecycle','member') THEN
  RETURN OLD;
 END IF;
 RAISE EXCEPTION 'APPLICATION_ASSIGNMENT_VERSION_IMMUTABLE'
  USING ERRCODE='23514';
END $function$;
REVOKE ALL ON FUNCTION epm.application_assignment_version_immutable()
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
