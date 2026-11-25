DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=399) THEN
        RAISE EXCEPTION 'MIGRATION_0400_REQUIRES_0399';
    END IF;
END $migration$;

-- Available only to the lifecycle service inside the transaction that
-- created this application. This cannot convert an existing application.
CREATE FUNCTION epm.initialize_application_group_access(
    p_workspace text,p_application text,p_issuer text,p_group text,p_subject text,p_signed_groups text[],
    p_operation text,p_actor_digest text,p_policy_token text,p_policy_digest text,
    p_actions text[],p_policy jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog
AS $body$
BEGIN
    IF p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
       OR p_application IS DISTINCT FROM current_setting('epm.application_id',true)
       OR NOT EXISTS (SELECT 1 FROM epm.application
           WHERE workspace_id=p_workspace AND application_id=p_application
             AND created_at=transaction_timestamp() AND xmin=pg_current_xact_id()::text::xid
             AND authorization_model='legacy')
       OR EXISTS (SELECT 1 FROM epm.application_access_grant
           WHERE workspace_id=p_workspace AND application_id=p_application)
       OR NOT EXISTS (SELECT 1 FROM epm.workspace_bootstrap_groups(
           p_issuer,p_subject,p_signed_groups) eligible WHERE eligible.group_id=p_group)
    THEN RAISE EXCEPTION 'APPLICATION_GROUP_BOOTSTRAP_UNAVAILABLE'; END IF;
    IF p_actions IS NULL OR NOT p_actions @> ARRAY[
        'application.enter','access.manage','access.review','roles.manage']::text[]
       OR EXISTS (SELECT 1 FROM unnest(p_actions) AS x WHERE x IS NULL OR
           (x NOT IN ('application.enter','access.manage','access.review','roles.manage')
            AND x !~ '^delegate[.][a-z][a-z0-9_.-]*$'))
    THEN RAISE EXCEPTION 'APPLICATION_GROUP_BOOTSTRAP_ACTIONS_INVALID'; END IF;

    INSERT INTO epm.application_authorization_role VALUES
        (p_workspace,p_application,'access-administrator','Application Access Administrator',1,p_actions);
    INSERT INTO epm.application_authorization_scope VALUES
        (p_workspace,p_application,'application','Whole application',1,'entire_application','{}');
    INSERT INTO epm.application_authorization_assignment VALUES
        (p_workspace,p_application,'initial-administrators',p_issuer,p_group,'access-administrator',1);
    INSERT INTO epm.application_authorization_assignment_scope
        SELECT p_workspace,p_application,'initial-administrators',action,'application'
        FROM unnest(p_actions) AS action;
    INSERT INTO epm.dimensional_security_policy_definition
        (workspace_id,application_id,state_token,status,policy_digest,across_dimensions,
         within_dimension,untagged_member,untagged_deny_precedence,member_tag_cardinality,
         hierarchy_tags,write_read_relationship,mixed_selection,administrator_treatment,
         fact_side_authority,updated_operation_id,updated_by_digest)
    VALUES (p_workspace,p_application,p_policy_token,'Active',p_policy_digest,
         p_policy->>'acrossDimensions',p_policy->>'withinDimension',p_policy->>'untaggedMember',
         p_policy->>'untaggedDenyPrecedence',p_policy->>'memberTagCardinality',p_policy->>'hierarchyTags',
         p_policy->>'writeReadRelationship',p_policy->>'mixedSelection',p_policy->>'administratorTreatment',
         p_policy->>'factSideAuthority',p_operation,p_actor_digest);
    UPDATE epm.application SET authorization_model='group_assignments'
        WHERE workspace_id=p_workspace AND application_id=p_application;
    UPDATE epm.application_state SET security_revision=security_revision+1,policy_revision=policy_revision+1
        WHERE workspace_id=p_workspace AND application_id=p_application;
    IF NOT epm.authorization_has_reachable_admin(p_workspace,p_application) THEN
        RAISE EXCEPTION 'LAST_REACHABLE_APPLICATION_ADMINISTRATOR';
    END IF;
END $body$;
REVOKE ALL ON FUNCTION epm.initialize_application_group_access(
    text,text,text,text,text,text[],text,text,text,text,text[],jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.initialize_application_group_access(
    text,text,text,text,text,text[],text,text,text,text,text[],jsonb) TO epm_lifecycle;
