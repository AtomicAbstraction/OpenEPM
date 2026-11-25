DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=396) THEN
        RAISE EXCEPTION 'MIGRATION_0397_REQUIRES_0396';
    END IF;
END $migration$;

-- The observable answer is one boolean for the selected application. Multiple
-- people, multiple groups and equivalent grant rows must never be confused.
CREATE FUNCTION epm.authorization_has_reachable_admin(p_workspace text,p_application text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
 SELECT p_workspace=current_setting('epm.workspace_id',true)
    AND p_application=current_setting('epm.application_id',true)
    AND EXISTS (
        SELECT 1 FROM epm.application_authorization_privilege p
        JOIN epm.identity_group_directory_state g USING (issuer,group_id)
        JOIN epm.identity_group_membership_state m USING (issuer,group_id)
        JOIN epm.identity_user_directory_state u USING (issuer,subject_id)
        WHERE p.workspace_id=p_workspace AND p.application_id=p_application
          AND p.scope_kind='entire_application'
          AND p.action IN ('application.enter','access.manage','roles.manage')
          AND m.active AND g.status='Active' AND u.status='Active'
        GROUP BY m.issuer,m.subject_id HAVING count(DISTINCT p.action)=3
    )
$body$;
REVOKE ALL ON FUNCTION epm.authorization_has_reachable_admin(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_has_reachable_admin(text,text) TO epm_security;

ALTER TABLE epm.security_operation_receipt DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt ADD CONSTRAINT security_operation_receipt_action_check
    CHECK (action=ANY(ARRAY['application.grant','application.revoke','workspace.grant','workspace.revoke',
    'rule.set','rule.revoke','dimension-access.set','dimension-policy.save','dimension-policy.activate',
    'dimension-policy.deactivate','application-group.grant','application-group.revoke','workspace-group.grant',
    'workspace-group.revoke','rule-group.set','rule-group.revoke','group-dimension-access.set',
    'application-authorization.apply','application-authorization.activate']::text[]));
