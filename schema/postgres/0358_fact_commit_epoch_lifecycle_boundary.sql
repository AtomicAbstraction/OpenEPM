BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=357) THEN
    RAISE EXCEPTION 'MIGRATION_0358_REQUIRES_0357';
  END IF;
END $migration$;

-- A deferred trigger closes the commit epoch after application_state changes.
-- It is a server invariant, not a lifecycle-role mutation.  Application
-- creation legitimately reaches this trigger while SET ROLE epm_lifecycle is
-- active, so perform only the exact close under the function owner while
-- preserving the original workspace/application scope checks explicitly.
CREATE OR REPLACE FUNCTION epm.fact_commit_epoch_close() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog AS $$
DECLARE
  state_owner oid;
BEGIN
  SELECT relowner INTO state_owner
  FROM pg_catalog.pg_class
  WHERE oid='epm.application_state'::regclass;

  IF NOT pg_has_role(session_user,state_owner,'USAGE') THEN
    IF current_setting('epm.workspace_id',true) IS DISTINCT FROM NEW.workspace_id OR
       (current_setting('epm.application_id',true) IS DISTINCT FROM NEW.application_id AND
        NOT pg_has_role(session_user,'epm_lifecycle','member')) THEN
      RAISE EXCEPTION 'FACT_PUBLICATION_SCOPE_CHANGED' USING ERRCODE='23514';
    END IF;
  END IF;

  UPDATE epm.application_state
  SET commit_open=false
  WHERE workspace_id=NEW.workspace_id
    AND application_id=NEW.application_id
    AND commit_open;
  RETURN NULL;
END $$;

REVOKE ALL ON FUNCTION epm.fact_commit_epoch_close() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.fact_commit_epoch_close()
  TO epm_runtime,epm_lifecycle;

COMMIT;
