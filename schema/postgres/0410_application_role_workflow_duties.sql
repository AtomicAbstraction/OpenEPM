DO $migration$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=409) THEN
  RAISE EXCEPTION 'MIGRATION_0410_REQUIRES_0409';
 END IF;
END $migration$;

-- Existing roles have no workflow duty until an authorized review links one.
CREATE FUNCTION epm.valid_application_workflow_duties(duties text[])
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $body$
 SELECT cardinality(duties)<=100
   AND (cardinality(duties)=0 OR (array_ndims(duties)=1 AND array_lower(duties,1)=1))
   AND NOT EXISTS (SELECT FROM unnest(duties) AS d
                   WHERE d IS NULL OR d !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$')
   AND cardinality(duties)=(SELECT count(DISTINCT d COLLATE "C") FROM unnest(duties) AS d)
$body$;

ALTER TABLE epm.application_authorization_role
 ADD COLUMN workflow_duties text[] NOT NULL DEFAULT '{}'
 CHECK(epm.valid_application_workflow_duties(workflow_duties)
       AND (cardinality(workflow_duties)=0 OR actions @> ARRAY['facts.read','facts.write']));

CREATE OR REPLACE VIEW epm.application_authorization_privilege WITH (security_invoker=true) AS
SELECT a.workspace_id,a.application_id,a.issuer,a.group_id,a.assignment_id,
       a.revision AS assignment_revision,r.role_id,r.role_name,r.revision AS role_revision,
       b.action,s.scope_id,s.scope_name,s.revision AS scope_revision,s.scope_kind,s.selector,
       r.workflow_duties
FROM epm.application_authorization_assignment a
JOIN epm.application_authorization_role r USING (workspace_id,application_id,role_id)
JOIN epm.application_authorization_assignment_scope b USING (workspace_id,application_id,assignment_id)
JOIN epm.application_authorization_scope s USING (workspace_id,application_id,scope_id)
WHERE b.action=ANY(r.actions);

-- Expose only duty identifiers for the selected application. Security
-- management receives no policy selectors, business members or data.
CREATE FUNCTION epm.authorization_planning_duties(requested text[], row_limit integer)
RETURNS TABLE(duty text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT DISTINCT d.value COLLATE "C"
 FROM epm.cube_write_policy_definition p
 CROSS JOIN LATERAL jsonb_array_elements(p.definition->'rules') r
 CROSS JOIN LATERAL jsonb_array_elements_text(r.value->'workflowRoles') d
 WHERE p.workspace_id=current_setting('epm.workspace_id',true)
   AND p.application_id=current_setting('epm.application_id',true)
   AND p.status='Active' AND (requested IS NULL OR d.value=ANY(requested))
 ORDER BY 1 LIMIT least(101,greatest(0,row_limit))
$body$;
REVOKE ALL ON FUNCTION epm.authorization_planning_duties(text[],integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_planning_duties(text[],integer) TO epm_security;

-- Coarse availability only. Exact coordinates, policy date, rule priority and
-- dimensional selectors are evaluated again at the point of publication.
CREATE FUNCTION epm.planning_duty_candidates(all_assignments boolean, caller_issuer text,
 caller_groups text[], legacy_roles text[])
RETURNS TABLE(active_policy boolean, group_allow_possible boolean, legacy_allow_possible boolean)
LANGUAGE sql STABLE SET search_path=pg_catalog AS $body$
 WITH active AS MATERIALIZED (
   SELECT definition FROM epm.cube_write_policy_definition
   WHERE workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true) AND status='Active'
 ), allows AS MATERIALIZED (
   SELECT DISTINCT duty.value FROM active
   CROSS JOIN LATERAL jsonb_array_elements(active.definition->'rules') rule
   CROSS JOIN LATERAL jsonb_array_elements_text(rule.value->'workflowRoles') duty
   WHERE rule.value->>'effect'='Allow'
 )
 SELECT EXISTS(SELECT FROM active),
        EXISTS(SELECT FROM epm.application_authorization_privilege writer
          WHERE writer.workspace_id=current_setting('epm.workspace_id',true)
            AND writer.application_id=current_setting('epm.application_id',true)
            AND (all_assignments OR (writer.issuer=caller_issuer AND writer.group_id=ANY(caller_groups)))
            AND writer.action='facts.write' AND writer.scope_kind IN ('entire_application','dimension_tags')
            AND EXISTS(SELECT FROM allows WHERE allows.value=ANY(writer.workflow_duties))
            AND EXISTS(SELECT FROM epm.application_authorization_privilege reader
              WHERE (reader.workspace_id,reader.application_id,reader.assignment_id)=
                    (writer.workspace_id,writer.application_id,writer.assignment_id)
                AND reader.action='facts.read' AND reader.scope_kind IN ('entire_application','dimension_tags'))),
        EXISTS(SELECT FROM allows WHERE allows.value=ANY(legacy_roles))
$body$;
REVOKE ALL ON FUNCTION epm.planning_duty_candidates(boolean,text,text[],text[]) FROM PUBLIC;

CREATE FUNCTION epm.caller_planning_duty_unbound(caller_issuer text, caller_groups text[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT active_policy AND NOT group_allow_possible
 FROM epm.planning_duty_candidates(false,caller_issuer,caller_groups,'{}')
$body$;
REVOKE ALL ON FUNCTION epm.caller_planning_duty_unbound(text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.caller_planning_duty_unbound(text,text[]) TO epm_runtime;

CREATE FUNCTION epm.authorization_migration_planning_candidates(legacy_roles text[])
RETURNS TABLE(active_policy boolean, group_allow_possible boolean, legacy_allow_possible boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT * FROM epm.planning_duty_candidates(true,NULL,NULL,legacy_roles)
$body$;
REVOKE ALL ON FUNCTION epm.authorization_migration_planning_candidates(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_migration_planning_candidates(text[]) TO epm_security;
