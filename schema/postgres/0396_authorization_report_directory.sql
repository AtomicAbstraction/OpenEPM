BEGIN;

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=395) THEN
        RAISE EXCEPTION 'MIGRATION_0396_REQUIRES_0395';
    END IF;
END $migration$;

-- Permit the security reader to expand a group only within the selected
-- application's actual assignments. The full membership table stays private.
CREATE FUNCTION epm.authorization_group_members(requested_issuer text, requested_group text)
RETURNS TABLE(subject_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,epm
AS $body$
    SELECT m.subject_id
    FROM epm.identity_group_membership_state m
    JOIN epm.identity_user_directory_state u USING (issuer,subject_id)
    JOIN epm.identity_group_directory_state g USING (issuer,group_id)
    WHERE m.issuer=requested_issuer AND m.group_id=requested_group
      AND m.active AND u.status='Active' AND g.status='Active'
      AND EXISTS (
        SELECT 1 FROM epm.application a
        WHERE a.workspace_id=current_setting('epm.workspace_id',true)
          AND a.application_id=current_setting('epm.application_id',true)
          AND (
            (a.authorization_model='legacy' AND (
              EXISTS (SELECT 1 FROM epm.application_group_access_grant x
                      WHERE x.workspace_id=a.workspace_id AND x.application_id=a.application_id
                        AND x.issuer=requested_issuer AND x.group_id=requested_group)
              OR EXISTS (SELECT 1 FROM epm.workspace_group_access_grant x
                      WHERE x.workspace_id=a.workspace_id
                        AND x.issuer=requested_issuer AND x.group_id=requested_group)))
            OR (a.authorization_model='group_assignments' AND EXISTS (
              SELECT 1 FROM epm.application_authorization_privilege x
              WHERE x.workspace_id=a.workspace_id AND x.application_id=a.application_id
                AND x.issuer=requested_issuer AND x.group_id=requested_group))))
$body$;

-- A global monotonic fence is bound into an opaque per-observer page token.
-- No directory rows or population counts are exposed by the fence.
CREATE FUNCTION epm.authorization_directory_revision() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,epm
AS $body$
    SELECT revision FROM epm.identity_directory_state WHERE singleton
$body$;
REVOKE ALL ON FUNCTION epm.authorization_group_members(text,text),
    epm.authorization_directory_revision() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_group_members(text,text),
    epm.authorization_directory_revision() TO epm_security;

COMMIT;
