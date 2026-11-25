DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=402) THEN
        RAISE EXCEPTION 'MIGRATION_0403_REQUIRES_0402';
    END IF;
END $migration$;

-- List both models' origins for the selected application, including staged and
-- dormant rows. The migration reader does not acquire a directory-wide roster.
CREATE FUNCTION epm.authorization_migration_origins() RETURNS TABLE(origin jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    WITH current_scope AS (
        SELECT current_setting('epm.workspace_id',true) AS workspace_id,
               current_setting('epm.application_id',true) AS application_id
    ), raw(kind,issuer,person,gid,detail) AS (
        SELECT 'workspace_person',w.issuer,w.subject_id,NULL::text,jsonb_build_object('role',w.role)
        FROM epm.workspace_access_grant w JOIN current_scope USING(workspace_id)
        UNION ALL SELECT 'workspace_group',w.issuer,NULL,w.group_id,jsonb_build_object('role',w.role)
        FROM epm.workspace_group_access_grant w JOIN current_scope USING(workspace_id)
        UNION ALL SELECT 'application_person',a.issuer,a.subject_id,NULL,
            jsonb_build_object('role',a.role,'readTags',a.read_security_tags,'writeTags',a.write_security_tags)
        FROM epm.application_access_grant a JOIN current_scope USING(workspace_id,application_id)
        UNION ALL SELECT 'application_group',a.issuer,NULL,a.group_id,
            jsonb_build_object('role',a.role,'readTags',a.read_security_tags,'writeTags',a.write_security_tags)
        FROM epm.application_group_access_grant a JOIN current_scope USING(workspace_id,application_id)
        UNION ALL SELECT 'rule_person',r.issuer,r.subject_id,NULL,
            jsonb_build_object('can_design',r.can_design,'can_publish',r.can_publish,'can_run',r.can_run)
        FROM epm.rule_access_grant r JOIN current_scope USING(workspace_id,application_id)
        UNION ALL SELECT 'rule_group',r.issuer,NULL,r.group_id,
            jsonb_build_object('can_design',r.can_design,'can_publish',r.can_publish,'can_run',r.can_run)
        FROM epm.rule_group_access_grant r JOIN current_scope USING(workspace_id,application_id)
        UNION ALL SELECT 'assignment',a.issuer,NULL,a.group_id,
            jsonb_build_object('assignmentId',a.assignment_id,'roleId',a.role_id,
                'roleName',r.role_name,'actions',r.actions,'revision',a.revision,
                'privileges',coalesce((SELECT jsonb_agg(jsonb_build_object('action',b.action,'scopeId',s.scope_id,
                        'scopeKind',s.scope_kind,'selector',s.selector,'scopeRevision',s.revision)
                        ORDER BY b.action,s.scope_id)
                    FROM epm.application_authorization_assignment_scope b
                    JOIN epm.application_authorization_scope s USING(workspace_id,application_id,scope_id)
                    WHERE b.workspace_id=a.workspace_id AND b.application_id=a.application_id
                      AND b.assignment_id=a.assignment_id),'[]'::jsonb))
        FROM epm.application_authorization_assignment a JOIN current_scope USING(workspace_id,application_id)
        JOIN epm.application_authorization_role r USING(workspace_id,application_id,role_id)
    )
    SELECT jsonb_build_object('kind',r.kind,'issuer',r.issuer,'subjectId',r.person,'groupId',r.gid,
        'directoryStatus',CASE WHEN r.person IS NULL THEN g.status ELSE u.status END,
        'identityResolved',CASE WHEN r.person IS NULL THEN g.principal_digest IS NOT NULL
            ELSE u.principal_digest IS NOT NULL END,
        'members',CASE WHEN r.gid IS NULL THEN '[]'::jsonb ELSE
            COALESCE((SELECT jsonb_agg(to_jsonb(selected) ORDER BY selected."subjectId") FROM (
                SELECT m.subject_id AS "subjectId",p.status AS status,p.principal_digest IS NOT NULL AS resolved
                FROM epm.identity_group_membership_state m LEFT JOIN epm.identity_user_directory_state p
                USING(issuer,subject_id) WHERE m.issuer=r.issuer AND m.group_id=r.gid AND m.active
                ORDER BY m.subject_id COLLATE "C" LIMIT 101) selected),'[]'::jsonb) END) || r.detail
    FROM raw r LEFT JOIN epm.identity_user_directory_state u ON u.issuer=r.issuer AND u.subject_id=r.person
    LEFT JOIN epm.identity_group_directory_state g ON g.issuer=r.issuer AND g.group_id=r.gid
    ORDER BY r.kind,r.issuer,r.person,r.gid,r.detail->>'assignmentId' LIMIT 201
$body$;

CREATE FUNCTION epm.authorization_migration_dependencies()
RETURNS TABLE(in_flight boolean,live_delegates boolean,active_schedules boolean,unresolved_resource_scope boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
AS $body$
    WITH a AS (SELECT current_setting('epm.workspace_id',true) AS workspace_id,
                      current_setting('epm.application_id',true) AS application_id)
    SELECT EXISTS (SELECT 1 FROM epm.job JOIN a USING(workspace_id,application_id)
                   WHERE status NOT IN ('published','failed','cancelled')),
        EXISTS (SELECT 1 FROM epm.execution_delegation_definition JOIN a USING(workspace_id,application_id)
                WHERE status='Active' AND valid_until>statement_timestamp()),
        EXISTS (SELECT 1 FROM epm.application_schedule_definition JOIN a USING(workspace_id,application_id)
                WHERE status='Active') OR EXISTS (
                SELECT 1 FROM epm.python_program_schedule_definition JOIN a USING(workspace_id,application_id)
                WHERE status='Active'),
        EXISTS (SELECT 1 FROM epm.application_authorization_scope s JOIN a USING(workspace_id,application_id)
            WHERE (s.scope_kind='dimension_tags' AND EXISTS (
                SELECT 1 FROM jsonb_each(s.selector) axis
                CROSS JOIN LATERAL jsonb_array_elements_text(axis.value) selected(tag)
                WHERE NOT EXISTS (SELECT 1 FROM epm.dimension d JOIN epm.security_tag t
                    USING(workspace_id,application_id,dimension_id) WHERE d.workspace_id=s.workspace_id
                    AND d.application_id=s.application_id AND d.dimension_id=axis.key
                    AND d.status='Active' AND t.status='Active' AND t.tag_id=selected.tag)))
              OR (s.scope_kind='exact_object' AND (s.selector->>'objectType'<>'saved_view'
                  OR epm.authorization_saved_view_token(s.selector->>'objectId') IS NULL)))
$body$;

-- Only the fixed migration writer can flip this column. Retain the old
-- facts, grants, audit and receipts. New-app bootstrap remains independent.
CREATE FUNCTION epm.switch_application_authorization_model(p_source text,p_target text,p_created timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $body$
DECLARE w text:=current_setting('epm.workspace_id',true);
        a text:=current_setting('epm.application_id',true);
BEGIN
    IF (p_source,p_target) NOT IN (('legacy','group_assignments'),('group_assignments','legacy'))
       OR (p_target='group_assignments' AND NOT epm.authorization_has_reachable_admin(w,a)) THEN
        RAISE EXCEPTION 'APPLICATION_AUTHORIZATION_MIGRATION_UNAVAILABLE';
    END IF;
    UPDATE epm.application SET authorization_model=p_target WHERE workspace_id=w AND application_id=a
      AND authorization_model=p_source AND created_at=p_created AND status='Active';
    IF NOT FOUND THEN RAISE EXCEPTION 'APPLICATION_AUTHORIZATION_MIGRATION_STALE'; END IF;
    UPDATE epm.application_state SET security_revision=security_revision+1,policy_revision=policy_revision+1
    WHERE workspace_id=w AND application_id=a;
    IF NOT FOUND THEN RAISE EXCEPTION 'APPLICATION_AUTHORIZATION_MIGRATION_STALE'; END IF;
END $body$;
REVOKE ALL ON FUNCTION epm.authorization_migration_origins(),epm.authorization_migration_dependencies(),
    epm.switch_application_authorization_model(text,text,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_migration_origins(),epm.authorization_migration_dependencies(),
    epm.switch_application_authorization_model(text,text,timestamptz) TO epm_security;
