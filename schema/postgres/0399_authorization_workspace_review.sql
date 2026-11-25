BEGIN;
DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=398) THEN
        RAISE EXCEPTION 'MIGRATION_0399_REQUIRES_0398';
    END IF;
END $migration$;

-- Inspect only the current workspace. This joins assignment provenance in
-- the database without granting the scoped application/security login a
-- cross-application privilege on the assignment or raw membership tables.
CREATE FUNCTION epm.workspace_authorization_review_sources(requested_issuer text,requested_subject text)
RETURNS TABLE(person text,group_id text,group_name text,origin text,application_id text,
              application_name text,authorization_model text,role_name text,admits boolean,
              directory_gap boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    WITH apps AS (
        SELECT a.* FROM epm.application a
        WHERE a.workspace_id=current_setting('epm.workspace_id',true) AND a.status<>'Deleting'
    ), bindings(person,gid,origin,app_id,app_name,model,role_name,admits) AS (
        SELECT w.subject_id,NULL::text,'workspace_direct',NULL::text,NULL::text,NULL::text,w.role,true
        FROM epm.workspace_access_grant w WHERE w.workspace_id=current_setting('epm.workspace_id',true)
          AND w.issuer=requested_issuer AND (requested_subject IS NULL OR w.subject_id=requested_subject)
        UNION ALL
        SELECT NULL,w.group_id,'workspace_group',NULL,NULL,NULL,w.role,true FROM epm.workspace_group_access_grant w
        WHERE w.workspace_id=current_setting('epm.workspace_id',true) AND w.issuer=requested_issuer
        UNION ALL
        SELECT g.subject_id,NULL,'application_direct',a.application_id,a.name,a.authorization_model,g.role,true
        FROM apps a JOIN epm.application_access_grant g USING(workspace_id,application_id)
        WHERE a.authorization_model='legacy' AND g.issuer=requested_issuer
          AND (requested_subject IS NULL OR g.subject_id=requested_subject)
        UNION ALL
        SELECT NULL,g.group_id,'application_group',a.application_id,a.name,a.authorization_model,g.role,true
        FROM apps a JOIN epm.application_group_access_grant g USING(workspace_id,application_id)
        WHERE a.authorization_model='legacy' AND g.issuer=requested_issuer
        UNION ALL
        SELECT NULL,p.group_id,'application_group',a.application_id,a.name,a.authorization_model,p.role_name,
               bool_or(p.action='application.enter' AND p.scope_kind='entire_application')
        FROM apps a JOIN epm.application_authorization_privilege p USING(workspace_id,application_id)
        WHERE a.authorization_model='group_assignments' AND p.issuer=requested_issuer
        GROUP BY p.group_id,a.application_id,a.name,a.authorization_model,p.role_name
    )
    SELECT b.person,NULL,NULL,b.origin,b.app_id,b.app_name,b.model,b.role_name,b.admits,
           u.subject_id IS NULL OR u.status='Active' AND
             (u.display_name IS NULL OR u.username IS NULL OR u.principal_digest IS NULL)
    FROM bindings b LEFT JOIN epm.identity_user_directory_state u
      ON u.issuer=requested_issuer AND u.subject_id=b.person WHERE b.person IS NOT NULL
    UNION ALL
    SELECT m.subject_id,b.gid,coalesce(g.display_name,g.group_name),b.origin,b.app_id,b.app_name,b.model,
           b.role_name,b.admits,g.group_name IS NULL OR g.principal_digest IS NULL
           OR u.display_name IS NULL OR u.username IS NULL OR u.principal_digest IS NULL
    FROM bindings b JOIN epm.identity_group_directory_state g ON g.issuer=requested_issuer AND g.group_id=b.gid
    JOIN epm.identity_group_membership_state m ON m.issuer=g.issuer AND m.group_id=g.group_id AND m.active
    JOIN epm.identity_user_directory_state u ON u.issuer=m.issuer AND u.subject_id=m.subject_id
    WHERE g.status='Active' AND u.status='Active' AND (requested_subject IS NULL OR m.subject_id=requested_subject)
    UNION ALL
    SELECT NULL,b.gid,NULL,b.origin,b.app_id,b.app_name,b.model,b.role_name,false,true
    FROM bindings b LEFT JOIN epm.identity_group_directory_state g ON g.issuer=requested_issuer AND g.group_id=b.gid
    WHERE b.gid IS NOT NULL AND (g.group_id IS NULL OR
        g.status='Active' AND (g.group_name IS NULL OR g.principal_digest IS NULL))
$body$;

-- Changes anywhere in this workspace's authority or directory invalidate the
-- reviewer's continuation; no other workspace's inventory or count is exposed.
CREATE FUNCTION epm.workspace_authorization_review_state()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    SELECT encode(sha256(convert_to(jsonb_build_array(
        (SELECT jsonb_agg(jsonb_build_array(a.application_id,a.name,a.created_at,a.status,a.authorization_model,
                     s.schema_epoch,s.security_revision) ORDER BY a.application_id COLLATE "C")
           FROM epm.application a JOIN epm.application_state s USING(workspace_id,application_id)
           WHERE a.workspace_id=current_setting('epm.workspace_id',true)),
        (SELECT max(audit_id) FROM epm.security_audit WHERE workspace_id=current_setting('epm.workspace_id',true)
           AND application_id IS NULL AND outcome='Accepted'),
        epm.authorization_directory_revision())::text,'UTF8')),'hex')
$body$;

CREATE FUNCTION epm.workspace_authorization_legacy_applications()
RETURNS TABLE(application_id text,application_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    SELECT a.application_id,a.name FROM epm.application a WHERE a.workspace_id=current_setting('epm.workspace_id',true)
      AND a.authorization_model='legacy' AND a.status<>'Deleting'
$body$;
CREATE FUNCTION epm.workspace_bootstrap_groups(requested_issuer text, requested_subject text, signed_groups text[])
RETURNS TABLE(group_id text,group_name text,display_name text,actor_member boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    WITH actor AS (
        SELECT epm.current_identity_groups(requested_issuer,requested_subject,signed_groups) AS groups
        WHERE epm.identity_subject_active(requested_issuer,requested_subject)
    ), workspace_groups AS (
        SELECT w.group_id FROM epm.workspace_group_access_grant w
        WHERE w.workspace_id=current_setting('epm.workspace_id',true) AND w.issuer=requested_issuer
          AND w.role='Administrator'
    )
    SELECT g.group_id,g.group_name,g.display_name,g.group_id=ANY(actor.groups)
    FROM epm.identity_group_directory_state g CROSS JOIN actor
    WHERE g.issuer=requested_issuer AND g.status='Active' AND (
        EXISTS(SELECT 1 FROM epm.workspace_access_grant w WHERE w.workspace_id=current_setting('epm.workspace_id',true)
               AND w.issuer=requested_issuer AND w.subject_id=requested_subject AND w.role='Administrator')
        OR EXISTS(SELECT 1 FROM workspace_groups wg WHERE wg.group_id=ANY(actor.groups)))
      AND (g.group_id=ANY(actor.groups) OR EXISTS(SELECT 1 FROM workspace_groups wg WHERE wg.group_id=g.group_id))
      AND EXISTS(SELECT 1 FROM epm.identity_group_membership_state m JOIN epm.identity_user_directory_state u
                   USING(issuer,subject_id) WHERE m.issuer=g.issuer AND m.group_id=g.group_id
                   AND m.active AND u.status='Active')
$body$;
REVOKE ALL ON FUNCTION epm.workspace_bootstrap_groups(text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.workspace_bootstrap_groups(text,text,text[]) TO epm_security,epm_lifecycle;

REVOKE ALL ON FUNCTION epm.workspace_authorization_review_sources(text,text),
    epm.workspace_authorization_review_state(),epm.workspace_authorization_legacy_applications() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.workspace_authorization_review_sources(text,text),
    epm.workspace_authorization_review_state(),epm.workspace_authorization_legacy_applications() TO epm_security;
COMMIT;
