BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=318) THEN
  RAISE EXCEPTION 'MIGRATION_0319_REQUIRES_0318';
 END IF;
END $migration$;

CREATE FUNCTION epm.current_policy_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_policy_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_policy_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_policy_canonical_json(jsonb) FROM PUBLIC;

CREATE TABLE epm.dimensional_security_policy_definition(
 workspace_id text NOT NULL,application_id text NOT NULL,
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 policy_digest text NOT NULL CHECK(policy_digest~'^[0-9a-f]{64}$'),
 across_dimensions text NOT NULL CHECK(across_dimensions IN('every_protected','any_protected')),
 within_dimension text NOT NULL CHECK(within_dimension IN('any_tag','all_tags')),
 untagged_member text NOT NULL CHECK(untagged_member IN('allow','deny')),
 untagged_deny_precedence text NOT NULL CHECK(untagged_deny_precedence IN('absolute','dimension_result')),
 member_tag_cardinality text NOT NULL CHECK(member_tag_cardinality IN('multiple','exactly_one_when_protected')),
 hierarchy_tags text NOT NULL CHECK(hierarchy_tags IN('selected_member_only','effective_tags_resolved_by_server')),
 write_read_relationship text NOT NULL CHECK(write_read_relationship IN('independent','require_read')),
 mixed_selection text NOT NULL CHECK(mixed_selection IN('filter_reads_reject_writes','filter_reads_and_writes','reject_all')),
 administrator_treatment text NOT NULL CHECK(administrator_treatment IN('require_assignment','bypass')),
 fact_side_authority text NOT NULL CHECK(fact_side_authority='derived_query_aid_only'),
 updated_operation_id text NOT NULL,updated_by_digest text NOT NULL CHECK(updated_by_digest~'^[0-9a-f]{64}$'),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id),
 UNIQUE(workspace_id,application_id,state_token,policy_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT
);

WITH chosen AS(
 SELECT p.*,s.security_revision,s.active_dimensional_security_policy_version,
  row_number() OVER(PARTITION BY p.workspace_id,p.application_id ORDER BY
   (p.policy_version=s.active_dimensional_security_policy_version) DESC,
   p.policy_version DESC) AS choice
 FROM epm.dimensional_security_policy_version p JOIN epm.application_state s
  USING(workspace_id,application_id)
 WHERE s.active_dimensional_security_policy_version IS NOT NULL
    OR p.policy_version=(SELECT max(p2.policy_version)
       FROM epm.dimensional_security_policy_version p2
       WHERE(p2.workspace_id,p2.application_id)=(p.workspace_id,p.application_id))
), normalized AS(
 SELECT *,jsonb_build_object('applicationId',application_id,'policy',
  jsonb_build_object('acrossDimensions',across_dimensions,
   'administratorTreatment',administrator_treatment,
   'factSideAuthority',fact_side_authority,'hierarchyTags',hierarchy_tags,
   'memberTagCardinality',member_tag_cardinality,'mixedSelection',mixed_selection,
   'untaggedDenyPrecedence',untagged_deny_precedence,
   'untaggedMember',untagged_member,'withinDimension',within_dimension,
   'writeReadRelationship',write_read_relationship),'workspaceId',workspace_id) payload
 FROM chosen WHERE choice=1)
INSERT INTO epm.dimensional_security_policy_definition(
 workspace_id,application_id,state_token,status,policy_digest,
 across_dimensions,within_dimension,untagged_member,untagged_deny_precedence,
 member_tag_cardinality,hierarchy_tags,write_read_relationship,mixed_selection,
 administrator_treatment,fact_side_authority,updated_operation_id,
 updated_by_digest,updated_at)
SELECT workspace_id,application_id,encode(sha256(convert_to(workspace_id||E'\n'||
 application_id||E'\n'||policy_version::text||E'\n'||security_revision::text,'UTF8')),'hex'),
 CASE WHEN active_dimensional_security_policy_version=policy_version THEN 'Active' ELSE 'Saved' END,
 encode(sha256(convert_to(epm.current_policy_canonical_json(payload),'UTF8')),'hex'),
 across_dimensions,within_dimension,untagged_member,untagged_deny_precedence,
 member_tag_cardinality,hierarchy_tags,write_read_relationship,mixed_selection,
 administrator_treatment,fact_side_authority,'migration-0319',created_by_digest,created_at
FROM normalized;

ALTER TABLE epm.application_state DROP COLUMN active_dimensional_security_policy_version;
DROP TABLE epm.dimensional_security_policy_version;
DROP FUNCTION epm.current_policy_canonical_json(jsonb);

ALTER TABLE epm.dimensional_security_policy_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY dimensional_security_policy_runtime_scope
 ON epm.dimensional_security_policy_definition TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY dimensional_security_policy_writer_scope
 ON epm.dimensional_security_policy_definition TO epm_security
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY dimensional_security_policy_lifecycle_scope
 ON epm.dimensional_security_policy_definition FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.dimensional_security_policy_definition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT ON epm.dimensional_security_policy_definition TO epm_runtime,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.dimensional_security_policy_definition TO epm_security;

ALTER TABLE epm.security_operation_receipt DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt ADD CONSTRAINT security_operation_receipt_action_check CHECK(action=ANY(
 ARRAY['application.grant','application.revoke','workspace.grant','workspace.revoke',
 'rule.set','rule.revoke','dimension-access.set','dimension-policy.save',
 'dimension-policy.activate','dimension-policy.deactivate','application-group.grant',
 'application-group.revoke','workspace-group.grant','workspace-group.revoke',
 'rule-group.set','rule-group.revoke','group-dimension-access.set']::text[]));

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'''dimensional_security_policy_version''','''dimensional_security_policy_definition''');
 IF position('''dimensional_security_policy_definition''' IN definition)=0 THEN RAISE EXCEPTION 'RESET_0319_TABLE_MISMATCH';END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,'dimensional_security_policy_version','dimensional_security_policy_definition');
 IF position('dimensional_security_policy_definition' IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0319_TABLE_MISMATCH';END IF;
 EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='4eff3423cb81f10bf160bc923f6af8475ed33bcf7cc33d19b384bc4ded08de16';
DECLARE current_graph constant text:='822b552f0da05bdbbd31db4ba651295f868338ca4627b62f50339bd802322145';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0319_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0319_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
