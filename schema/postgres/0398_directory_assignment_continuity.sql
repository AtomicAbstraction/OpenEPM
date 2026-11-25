DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=397) THEN
        RAISE EXCEPTION 'MIGRATION_0398_REQUIRES_0397';
    END IF;
END $migration$;

-- Internal predicate for both configuration changes and preflighting a
-- directory removal. The optional exclusion describes a user, group or pair.
CREATE FUNCTION epm.assignment_admin_remains(
    p_workspace text,p_application text,p_issuer text,p_subject text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog
AS $body$
 SELECT EXISTS (
   SELECT 1 FROM epm.application_authorization_privilege p
   JOIN epm.identity_group_directory_state g USING (issuer,group_id)
   JOIN epm.identity_group_membership_state m USING (issuer,group_id)
   JOIN epm.identity_user_directory_state u USING (issuer,subject_id)
   WHERE p.workspace_id=p_workspace AND p.application_id=p_application
     AND p.scope_kind='entire_application'
     AND p.action IN ('application.enter','access.manage','roles.manage')
     AND m.active AND u.status='Active' AND g.status='Active'
     AND (p_issuer IS NULL OR m.issuer<>p_issuer
          OR (p_subject IS NOT NULL AND m.subject_id<>p_subject)
          OR (p_group IS NOT NULL AND m.group_id<>p_group))
   GROUP BY m.issuer,m.subject_id HAVING count(DISTINCT p.action)=3)
$body$;
REVOKE ALL ON FUNCTION epm.assignment_admin_remains(text,text,text,text,text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION epm.authorization_has_reachable_admin(p_workspace text,p_application text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
 SELECT p_workspace=current_setting('epm.workspace_id',true)
    AND p_application=current_setting('epm.application_id',true)
    AND epm.assignment_admin_remains(p_workspace,p_application,NULL,NULL,NULL)
$body$;

CREATE FUNCTION epm.directory_removal_preserves_assignment_admins(
    p_issuer text,p_subject text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
 SELECT p_issuer IS NOT NULL AND (p_group IS NOT NULL OR p_subject IS NOT NULL)
    AND NOT EXISTS (
      SELECT 1 FROM epm.application a
      WHERE a.authorization_model='group_assignments' AND a.status<>'Deleting'
        AND EXISTS (
            SELECT 1 FROM epm.application_authorization_privilege p
            JOIN epm.identity_group_membership_state m USING (issuer,group_id)
            WHERE p.workspace_id=a.workspace_id AND p.application_id=a.application_id
              AND p.issuer=p_issuer AND m.active
              AND (p_subject IS NULL OR m.subject_id=p_subject)
              AND (p_group IS NULL OR m.group_id=p_group)
              AND p.action IN ('application.enter','access.manage','roles.manage'))
        AND epm.assignment_admin_remains(a.workspace_id,a.application_id,NULL,NULL,NULL)
        AND NOT epm.assignment_admin_remains(a.workspace_id,a.application_id,p_issuer,p_subject,p_group))
$body$;
REVOKE ALL ON FUNCTION epm.directory_removal_preserves_assignment_admins(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.directory_removal_preserves_assignment_admins(text,text,text) TO epm_provision;
