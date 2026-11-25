DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=405) THEN
        RAISE EXCEPTION 'MIGRATION_0406_REQUIRES_0405';
    END IF;
END $migration$;

-- Only directly assigned groups in this selected application can contribute
-- to this review. Keep directory storage private to its existing owner.
CREATE FUNCTION epm.resource_review_groups(requested_issuer text)
RETURNS TABLE(group_id text,group_name text,active boolean,has_active_members boolean,directory_gap boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
    WITH assigned AS (
        SELECT DISTINCT a.group_id FROM epm.application_authorization_assignment a
        WHERE a.workspace_id=current_setting('epm.workspace_id',true)
          AND a.application_id=current_setting('epm.application_id',true) AND a.issuer=requested_issuer)
    SELECT a.group_id,coalesce(g.display_name,g.group_name),g.status='Active',
      coalesce(bool_or(m.active AND u.status='Active'),false),
      g.group_id IS NULL OR (g.status='Active' AND (g.group_name IS NULL OR g.principal_digest IS NULL
         OR coalesce(bool_or(m.active AND (u.subject_id IS NULL OR u.status='Active'
            AND (u.principal_digest IS NULL OR u.username IS NULL OR u.display_name IS NULL))),false)))
    FROM assigned a LEFT JOIN epm.identity_group_directory_state g ON g.issuer=requested_issuer AND g.group_id=a.group_id
    LEFT JOIN epm.identity_group_membership_state m ON m.issuer=g.issuer AND m.group_id=g.group_id AND m.active
    LEFT JOIN epm.identity_user_directory_state u ON u.issuer=m.issuer AND u.subject_id=m.subject_id
    GROUP BY a.group_id,g.group_id,g.display_name,g.group_name,g.status,g.principal_digest
    ORDER BY a.group_id COLLATE "C" LIMIT 513
$body$;

CREATE FUNCTION epm.resource_review_people(requested_issuer text,matching_groups text[],after_person text,requested_limit integer)
RETURNS TABLE(subject_id text,username text,display_name text,group_ids text[],entry_ids text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
    WITH assigned AS MATERIALIZED (
        SELECT a.group_id,bool_or(p.action='application.enter' AND p.scope_kind='entire_application') AS admits
        FROM epm.application_authorization_assignment a LEFT JOIN epm.application_authorization_privilege p
        USING(workspace_id,application_id,assignment_id)
        WHERE a.workspace_id=current_setting('epm.workspace_id',true)
          AND a.application_id=current_setting('epm.application_id',true) AND a.issuer=requested_issuer
        GROUP BY a.group_id
    ), matched_people AS (
        SELECT DISTINCT m.subject_id FROM assigned a JOIN epm.identity_group_membership_state m
          ON m.issuer=requested_issuer AND m.group_id=a.group_id AND m.active
        JOIN epm.identity_group_directory_state g ON g.issuer=m.issuer AND g.group_id=m.group_id AND g.status='Active'
        WHERE a.group_id=ANY(matching_groups) AND (after_person IS NULL OR m.subject_id COLLATE "C">after_person)
    )
    SELECT u.subject_id,u.username,u.display_name,array_agg(a.group_id ORDER BY a.group_id COLLATE "C"),
           array_agg(a.group_id ORDER BY a.group_id COLLATE "C") FILTER(WHERE a.admits)
    FROM matched_people mp JOIN epm.identity_user_directory_state u ON u.issuer=requested_issuer AND u.subject_id=mp.subject_id AND u.status='Active'
    JOIN epm.identity_group_membership_state m ON m.issuer=u.issuer AND m.subject_id=u.subject_id
    JOIN assigned a ON a.group_id=m.group_id
    JOIN epm.identity_group_directory_state g ON m.issuer=g.issuer AND m.group_id=g.group_id AND g.status='Active'
    WHERE m.active GROUP BY u.subject_id,u.username,u.display_name HAVING bool_or(a.admits)
    ORDER BY u.subject_id COLLATE "C" LIMIT least(greatest(coalesce(requested_limit,0),0),513)
$body$;
CREATE FUNCTION epm.resource_review_directory_fence() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
    SELECT revision FROM epm.identity_directory_state WHERE singleton
$body$;
REVOKE ALL ON FUNCTION epm.resource_review_groups(text),epm.resource_review_people(text,text[],text,integer),
      epm.resource_review_directory_fence() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.resource_review_groups(text),epm.resource_review_people(text,text[],text,integer),
      epm.resource_review_directory_fence() TO epm_runtime;
