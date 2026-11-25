-- Qualify the four application-owned relations in both protected lifecycle
-- workflows. The privilege relation is a scoped, read-only projection.
DO $migration$ DECLARE
    prior text := '880f4a68a58684ff0da54c1d4c9d2bcd4784ffe1e20adace2e471de00734a532';
    revised text := '01851985aa4a2f60dbfdc32444e0abfc6ce072082203abaa9fd6056fd495b98b';
    definition text;
    relations text[];
    additions text[] := ARRAY['application_authorization_assignment_scope',
        'application_authorization_assignment','application_authorization_scope','application_authorization_role'];
BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=400) THEN
        RAISE EXCEPTION 'MIGRATION_0401_REQUIRES_0400';
    END IF;
    ALTER VIEW epm.application_authorization_privilege SET (security_barrier=true);
    SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
        INTO definition;
    IF position(prior IN definition)=0 OR position('''application_group_access_grant''' IN definition)=0 THEN
        RAISE EXCEPTION 'ASSIGNMENT_WORKSPACE_RESET_PREDECESSOR_MISMATCH';
    END IF;
    definition := replace(definition,'''application_group_access_grant''',
        '''application_authorization_assignment_scope'',''application_authorization_assignment'',''application_authorization_scope'',''application_authorization_role'',''application_group_access_grant''');
    EXECUTE replace(definition,prior,revised);
    relations := epm.application_purge_relations();
    IF relations && additions THEN RAISE EXCEPTION 'ASSIGNMENT_PURGE_INVENTORY_ALREADY_PRESENT'; END IF;
    EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations()
        RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
        'SELECT ' || quote_literal((additions||relations)::text) || '::text[]');
    SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
        INTO definition;
    IF position(prior IN definition)=0 THEN RAISE EXCEPTION 'ASSIGNMENT_PURGE_PREDECESSOR_MISMATCH'; END IF;
    EXECUTE replace(definition,prior,revised);
END $migration$;
