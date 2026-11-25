DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=401) THEN
        RAISE EXCEPTION 'MIGRATION_0402_REQUIRES_0401';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.application_authorization_scope WHERE scope_kind='exact_object') THEN
        RAISE EXCEPTION 'PREEXISTING_EXACT_OBJECT_REFERENCE_REQUIRES_REVIEW';
    END IF;
END $migration$;

-- The security writer can validate an exact ID within its application
-- without permission to read any saved selection, label or cell value.
CREATE FUNCTION epm.authorization_saved_view_token(target_id text)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
    SELECT v.state_token FROM epm.saved_grid_definition v
        WHERE v.workspace_id=current_setting('epm.workspace_id',true)
          AND v.application_id=current_setting('epm.application_id',true)
          AND v.grid_id=target_id
$body$;
REVOKE ALL ON FUNCTION epm.authorization_saved_view_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_saved_view_token(text) TO epm_security;

CREATE FUNCTION epm.authorization_saved_view_choices(p_issuer text,p_subject text,p_signed_groups text[],
    p_after text,p_limit integer)
RETURNS TABLE(object_id text,object_name text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
    WITH actor AS (
        SELECT epm.current_identity_groups(p_issuer,p_subject,p_signed_groups) AS groups
        WHERE epm.identity_subject_active(p_issuer,p_subject)
    ), delegated AS (
        SELECT p.action,p.scope_kind,p.selector FROM epm.application_authorization_privilege p,actor
        WHERE p.workspace_id=current_setting('epm.workspace_id',true) AND p.application_id=current_setting('epm.application_id',true)
          AND p.issuer=p_issuer AND p.group_id=ANY(actor.groups)
    )
    SELECT v.grid_id,v.name FROM epm.saved_grid_definition v JOIN epm.application a USING(workspace_id,application_id)
      CROSS JOIN actor
    WHERE v.workspace_id=current_setting('epm.workspace_id',true) AND v.application_id=current_setting('epm.application_id',true)
      AND p_limit BETWEEN 1 AND 101 AND (p_after IS NULL OR v.grid_id COLLATE "C">p_after)
      AND (CASE a.authorization_model
        WHEN 'legacy' THEN EXISTS(SELECT 1 FROM epm.workspace_access_grant g WHERE g.workspace_id=v.workspace_id
             AND g.issuer=p_issuer AND g.subject_id=p_subject AND g.role='Administrator')
          OR EXISTS(SELECT 1 FROM epm.workspace_group_access_grant g WHERE g.workspace_id=v.workspace_id
             AND g.issuer=p_issuer AND g.group_id=ANY(actor.groups) AND g.role='Administrator')
        WHEN 'group_assignments' THEN EXISTS(SELECT 1 FROM delegated WHERE action='access.manage' AND scope_kind='entire_application')
          AND EXISTS(SELECT 1 FROM delegated WHERE action='application.enter' AND scope_kind='entire_application')
          AND EXISTS(SELECT 1 FROM delegated WHERE action IN ('delegate.views.read','delegate.views.save','delegate.views.run')
              AND (scope_kind='entire_application' OR (scope_kind='exact_object'
                   AND selector=jsonb_build_object('objectType','saved_view','objectId',v.grid_id))))
        ELSE false END)
    ORDER BY v.grid_id COLLATE "C" LIMIT greatest(0,least(p_limit,101))
$body$;
REVOKE ALL ON FUNCTION epm.authorization_saved_view_choices(text,text,text[],text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_saved_view_choices(text,text,text[],text,integer) TO epm_security;

-- Assignment writes hold the exclusive workspace authorization fence; saved
-- view edits hold the shared fence. Referencing a deleted ID cannot carry an
-- old privilege into a subsequently created view of the same name.
CREATE FUNCTION epm.protect_saved_view_authorization_reference()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
BEGIN
    IF EXISTS (SELECT 1 FROM epm.application_authorization_scope s
        WHERE s.workspace_id=OLD.workspace_id AND s.application_id=OLD.application_id
          AND s.scope_kind='exact_object' AND s.selector=jsonb_build_object('objectType','saved_view','objectId',OLD.grid_id)) THEN
        RAISE EXCEPTION 'SAVED_GRID_AUTHORIZATION_SCOPE_IN_USE' USING ERRCODE='23503';
    END IF;
    RETURN OLD;
END $body$;
REVOKE ALL ON FUNCTION epm.protect_saved_view_authorization_reference() FROM PUBLIC;
CREATE TRIGGER saved_grid_authorization_reference_guard BEFORE DELETE ON epm.saved_grid_definition
    FOR EACH ROW EXECUTE FUNCTION epm.protect_saved_view_authorization_reference();

-- Release exact-object references before deleting their referenced views.
-- The application purge already places these four relations first.
DO $reset$ DECLARE
    definition text;
    bindings text := '''application_authorization_assignment_scope'',''application_authorization_assignment'',''application_authorization_scope'',''application_authorization_role'',';
    target text := '''saved_grid_definition'',';
BEGIN
    SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
        INTO definition;
    IF position(bindings || '''application_group_access_grant''' IN definition)=0
       OR position(target IN definition)=0 THEN
        RAISE EXCEPTION 'SAVED_VIEW_RESET_INVENTORY_PREDECESSOR_MISMATCH';
    END IF;
    EXECUTE replace(replace(definition,bindings,''),target,bindings||target);
END $reset$;
