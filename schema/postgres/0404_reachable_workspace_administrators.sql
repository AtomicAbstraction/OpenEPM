DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=403) THEN
        RAISE EXCEPTION 'MIGRATION_0404_REQUIRES_0403';
    END IF;
END $migration$;

-- One row per current route to a human workspace administrator. Keep this
-- private: callers outside a workspace may only check continuity as a boolean.
CREATE FUNCTION epm.workspace_admin_paths(p_workspace text)
RETURNS TABLE(issuer text,subject_id text,group_id text)
LANGUAGE sql STABLE SET search_path=pg_catalog
AS $body$
    SELECT w.issuer,w.subject_id,NULL::text
    FROM epm.workspace_access_grant w
    JOIN epm.identity_user_directory_state u USING(issuer,subject_id)
    WHERE w.workspace_id=p_workspace AND w.role='Administrator' AND u.status='Active'
    UNION ALL
    SELECT w.issuer,m.subject_id,w.group_id
    FROM epm.workspace_group_access_grant w
    JOIN epm.identity_group_directory_state g USING(issuer,group_id)
    JOIN epm.identity_group_membership_state m USING(issuer,group_id)
    JOIN epm.identity_user_directory_state u USING(issuer,subject_id)
    WHERE w.workspace_id=p_workspace AND w.role='Administrator'
        AND g.status='Active' AND m.active AND u.status='Active'
$body$;
REVOKE ALL ON FUNCTION epm.workspace_admin_paths(text) FROM PUBLIC;

CREATE FUNCTION epm.workspace_has_reachable_admin()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    SELECT EXISTS (SELECT 1 FROM epm.workspace_admin_paths(current_setting('epm.workspace_id',true)))
$body$;
REVOKE ALL ON FUNCTION epm.workspace_has_reachable_admin() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.workspace_has_reachable_admin() TO epm_security;

CREATE FUNCTION epm.directory_removal_preserves_workspace_admins(
    p_issuer text,p_subject text,p_group text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    WITH candidates AS (
        SELECT w.workspace_id FROM epm.workspace_access_grant w
        WHERE p_group IS NULL AND w.issuer=p_issuer AND w.subject_id=p_subject
        UNION
        SELECT g.workspace_id FROM epm.workspace_group_access_grant g
        JOIN epm.identity_group_membership_state m USING (issuer,group_id)
        WHERE g.issuer=p_issuer AND m.active AND (p_group IS NULL OR g.group_id=p_group)
            AND (p_subject IS NULL OR m.subject_id=p_subject)
    )
    SELECT p_issuer IS NOT NULL AND (p_group IS NOT NULL OR p_subject IS NOT NULL)
        AND NOT EXISTS (
            SELECT 1 FROM candidates c JOIN epm.workspace w USING(workspace_id)
            CROSS JOIN LATERAL epm.workspace_admin_paths(c.workspace_id) a
            WHERE w.status<>'Deleting'
            GROUP BY c.workspace_id
            HAVING bool_and(a.issuer=p_issuer AND (p_subject IS NULL OR a.subject_id=p_subject)
                AND (p_group IS NULL OR a.group_id IS NOT DISTINCT FROM p_group))
        )
$body$;
REVOKE ALL ON FUNCTION epm.directory_removal_preserves_workspace_admins(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.directory_removal_preserves_workspace_admins(text,text,text) TO epm_provision;
