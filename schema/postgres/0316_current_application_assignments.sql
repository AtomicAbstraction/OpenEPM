BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=315) THEN
  RAISE EXCEPTION 'MIGRATION_0316_REQUIRES_0315';
 END IF;
 IF EXISTS(
  SELECT 1 FROM epm.application_workflow_assignment_pin p
  JOIN epm.application_assignment_state s USING(workspace_id,application_id,assignment_set_id)
  WHERE p.assignment_version<>s.latest_version
     OR p.assignment_digest<>(SELECT v.definition_digest
       FROM epm.application_assignment_version v
       WHERE(v.workspace_id,v.application_id,v.assignment_set_id,v.version)=
        (s.workspace_id,s.application_id,s.assignment_set_id,s.latest_version))) THEN
  RAISE EXCEPTION 'MIGRATION_0316_STALE_WORKFLOW_ASSIGNMENT_PIN';
 END IF;
END $migration$;

-- Produce the same sorted, whitespace-free JSON used by the fixed Python
-- canonicalizer. JSON string whitespace remains data and is not altered.
CREATE FUNCTION epm.current_object_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||COALESCE((SELECT string_agg(to_jsonb(key)::text||':'||
    epm.current_object_canonical_json(item),',' ORDER BY key)
    FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||COALESCE((SELECT string_agg(
    epm.current_object_canonical_json(item),',' ORDER BY ordinal)
    FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
REVOKE ALL ON FUNCTION epm.current_object_canonical_json(jsonb)
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;

CREATE TABLE epm.application_assignment_definition(
 workspace_id text NOT NULL,application_id text NOT NULL,
 assignment_set_id text NOT NULL CHECK(length(assignment_set_id) BETWEEN 1 AND 300
  AND assignment_set_id~'^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200 AND name=btrim(name)
  AND name!~'[[:cntrl:]]'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
  AND octet_length(definition::text)<=4194304
  AND definition->>'format'='openepm-application-assignment-set-v1'
  AND definition->>'workspaceId'=workspace_id
  AND definition->>'applicationId'=application_id
  AND definition->>'assignmentSetId'=assignment_set_id
  AND NOT definition?'version'),
 definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
 updated_operation_id text NOT NULL,updated_revision bigint NOT NULL CHECK(updated_revision>0),
 updater_issuer text NOT NULL CHECK(length(updater_issuer) BETWEEN 1 AND 300
  AND updater_issuer!~'[[:cntrl:]]'),
 updater_subject_id text NOT NULL CHECK(length(updater_subject_id) BETWEEN 1 AND 300
  AND updater_subject_id!~'[[:cntrl:]]'),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,assignment_set_id),
 UNIQUE(workspace_id,application_id,assignment_set_id,state_token,definition_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(
  workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,updated_operation_id)
  REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

INSERT INTO epm.application_assignment_definition(
 workspace_id,application_id,assignment_set_id,state_token,status,name,
 definition,definition_digest,updated_operation_id,updated_revision,
 updater_issuer,updater_subject_id,updated_at)
SELECT v.workspace_id,v.application_id,v.assignment_set_id,
 encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
  v.assignment_set_id||E'\n'||v.version::text||E'\n'||s.state_revision::text,'UTF8')),'hex'),
 CASE WHEN s.active_version=v.version THEN 'Active' ELSE 'Saved' END,v.name,
 v.definition-'version',encode(sha256(convert_to(
  epm.current_object_canonical_json(v.definition-'version'),'UTF8')),'hex'),
 s.operation_id,v.created_revision,v.creator_issuer,v.creator_subject_id,s.updated_at
FROM epm.application_assignment_state s JOIN epm.application_assignment_version v
 ON(v.workspace_id,v.application_id,v.assignment_set_id,v.version)=
   (s.workspace_id,s.application_id,s.assignment_set_id,s.latest_version);

ALTER TABLE epm.application_workflow_assignment_pin
 ADD COLUMN assignment_state_token text,
 ADD COLUMN current_assignment_digest text;
UPDATE epm.application_workflow_assignment_pin p SET
 assignment_state_token=d.state_token,current_assignment_digest=d.definition_digest
FROM epm.application_assignment_definition d
WHERE(p.workspace_id,p.application_id,p.assignment_set_id)=
 (d.workspace_id,d.application_id,d.assignment_set_id);
ALTER TABLE epm.application_workflow_assignment_pin
 ALTER COLUMN assignment_state_token SET NOT NULL,
 ALTER COLUMN current_assignment_digest SET NOT NULL,
 ADD CONSTRAINT application_workflow_assignment_pin_state_token_shape
  CHECK(assignment_state_token~'^[0-9a-f]{64}$'),
 ADD CONSTRAINT application_workflow_assignment_pin_current_digest_shape
  CHECK(current_assignment_digest~'^[0-9a-f]{64}$');

ALTER TABLE epm.application_workflow_activity
 DROP CONSTRAINT application_workflow_activit_workspace_id_application_id__fkey1;
ALTER TABLE epm.application_workflow_assignment_pin
 DROP CONSTRAINT application_workflow_assignm_workspace_id_application_id__fkey1;
ALTER TABLE epm.application_workflow_assignment_pin
 DROP COLUMN assignment_version,DROP COLUMN assignment_digest;
ALTER TABLE epm.application_workflow_assignment_pin
 RENAME COLUMN current_assignment_digest TO assignment_digest;
ALTER TABLE epm.application_workflow_assignment_pin
 ADD CONSTRAINT application_workflow_assignment_pin_current_assignment_fkey
 FOREIGN KEY(workspace_id,application_id,assignment_set_id,
  assignment_state_token,assignment_digest)
 REFERENCES epm.application_assignment_definition(workspace_id,application_id,
  assignment_set_id,state_token,definition_digest) ON DELETE RESTRICT;
ALTER TABLE epm.application_workflow_activity
 ADD CONSTRAINT application_workflow_activity_pin_fkey
 FOREIGN KEY(workspace_id,application_id,flow_id,flow_version,activity_id)
 REFERENCES epm.application_workflow_assignment_pin(
  workspace_id,application_id,flow_id,flow_version,activity_id) ON DELETE RESTRICT;

DROP TRIGGER application_assignment_version_immutable ON epm.application_assignment_version;
DROP FUNCTION epm.application_assignment_version_immutable();
DROP TABLE epm.application_assignment_state;
DROP TABLE epm.application_assignment_version;

ALTER TABLE epm.application_assignment_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY application_assignment_definition_runtime_scope
 ON epm.application_assignment_definition TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_assignment_definition_lifecycle_scope
 ON epm.application_assignment_definition FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.application_assignment_definition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.application_assignment_definition TO epm_runtime;
GRANT SELECT(workspace_id,application_id,assignment_set_id,state_token,status)
 ON epm.application_assignment_definition TO epm_lifecycle;

DROP FUNCTION epm.current_object_canonical_json(jsonb);

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'''application_assignment_state'',','');
 definition:=replace(definition,'''application_assignment_version''',
  '''application_assignment_definition''');
 IF position('''application_assignment_definition''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0316_TABLES_MISMATCH';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,'application_assignment_state,','');
 definition:=replace(definition,'application_assignment_version','application_assignment_definition');
 IF position('application_assignment_definition' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0316_TABLES_MISMATCH';END IF;EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='fb7e1dce21dfdf569a0ca137c140137d5309ab51474190a31f8530b67b5afc39';
DECLARE current_graph constant text:='61819e7bb839d55fa6fa8abacb67db6f13687fe365076f42ca4652b48e30e44c';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0316_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0316_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
