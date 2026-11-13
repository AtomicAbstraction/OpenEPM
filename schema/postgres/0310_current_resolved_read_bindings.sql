BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=309) THEN
    RAISE EXCEPTION 'MIGRATION_0310_REQUIRES_0309';
  END IF;
END $migration$;

CREATE TABLE epm.resolved_read_binding_current(
  workspace_id text NOT NULL, application_id text NOT NULL,
  binding_id text NOT NULL CHECK(binding_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  binding_digest text NOT NULL CHECK(binding_digest~'^[0-9a-f]{64}$'),
  binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'
    AND binding->>'format'='openepm-resolved-read-binding-v1'
    AND NOT binding ? 'version' AND octet_length(binding::text)<=4194304),
  status text NOT NULL CHECK(status IN('Saved','Active','Inactive')),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  policy_revision bigint NOT NULL CHECK(policy_revision>=0),
  activated_revision bigint CHECK(activated_revision>0),
  activation_policy_revision bigint CHECK(activation_policy_revision>0),
  activation_operation_id text,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,binding_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,activation_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  CHECK((status='Active')=(activated_revision IS NOT NULL
    AND activation_policy_revision IS NOT NULL
    AND activation_operation_id IS NOT NULL))
);

-- Preserve the latest editable business binding once, replace calculated-member
-- version locators with the matching current state token, and require explicit
-- reactivation. Old publication pointers are product history and are removed.
INSERT INTO epm.resolved_read_binding_current(workspace_id,application_id,
  binding_id,state_token,binding_digest,binding,status,metadata_revision,
  policy_revision,updated_at)
SELECT latest.workspace_id,latest.application_id,latest.binding_id,
  encode(sha256(convert_to(latest.workspace_id||E'\n'||latest.application_id||
    E'\n'||latest.binding_id||E'\n'||latest.version::text||E'\n'||
    latest.binding_digest,'UTF8')),'hex'),
  encode(sha256(convert_to(transformed.binding::text,'UTF8')),'hex'),
  transformed.binding,'Saved',latest.metadata_revision,latest.policy_revision,
  latest.created_at
FROM epm.resolved_read_binding_version latest
CROSS JOIN LATERAL(
  SELECT (latest.binding-'version') || jsonb_build_object('stages',
    coalesce(jsonb_agg(CASE WHEN stage->>'kind'='calculated_member' THEN
      (stage-'definitionVersion') || jsonb_build_object(
        'definitionStateToken',definition.state_token)
      ELSE stage END ORDER BY ordinal),'[]'::jsonb)) binding
  FROM jsonb_array_elements(latest.binding->'stages')
    WITH ORDINALITY AS item(stage,ordinal)
  LEFT JOIN epm.expression_rule_definition definition
    ON definition.workspace_id=latest.workspace_id
   AND definition.application_id=latest.application_id
   AND definition.rule_id=stage->>'definitionId'
) transformed
WHERE NOT EXISTS(SELECT 1 FROM epm.resolved_read_binding_version newer
  WHERE newer.workspace_id=latest.workspace_id
    AND newer.application_id=latest.application_id
    AND newer.binding_id=latest.binding_id AND newer.version>latest.version);

DROP TABLE epm.resolved_read_binding_publication;
DROP TABLE epm.resolved_read_binding_version;
ALTER TABLE epm.resolved_read_binding_current
  RENAME TO resolved_read_binding_definition;

ALTER TABLE epm.resolved_read_binding_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY resolved_read_binding_definition_runtime_scope
  ON epm.resolved_read_binding_definition TO epm_runtime,epm_worker,epm_analyst
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY resolved_read_binding_definition_lifecycle_scope
  ON epm.resolved_read_binding_definition TO epm_lifecycle
  USING(current_setting('epm.lifecycle_context',true)='workspace_reset');
REVOKE ALL ON epm.resolved_read_binding_definition
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.resolved_read_binding_definition TO epm_runtime;
GRANT SELECT ON epm.resolved_read_binding_definition TO epm_worker,epm_analyst,epm_lifecycle;

DO $migration$
DECLARE definition text;
DECLARE old_tables text :=
  $pattern$'resolved_read_binding_publication','resolved_read_binding_version',$pattern$;
DECLARE new_tables text := $pattern$'resolved_read_binding_definition',$pattern$;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_tables IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0310_TABLES_MISMATCH'; END IF;
  EXECUTE replace(definition,old_tables,new_tables);
  old_tables := 'resolved_read_binding_publication,resolved_read_binding_version';
  new_tables := 'resolved_read_binding_definition';
  SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
    INTO definition;
  IF position(old_tables IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0310_TABLES_MISMATCH'; END IF;
  EXECUTE replace(definition,old_tables,new_tables);
END $migration$;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := 'a3364f3b8d07556e476765f482793dcf0c9f12423f738b42397f44340c98c7f8';
DECLARE current_graph constant text := '7fece1bbacd4a7d108b47b4a1fca88ba066409595e3649713f14083ccde3b090';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0310_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0310_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
