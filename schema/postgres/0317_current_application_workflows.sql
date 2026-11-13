BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=316) THEN
  RAISE EXCEPTION 'MIGRATION_0317_REQUIRES_0316';
 END IF;
END $migration$;

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

CREATE TABLE epm.application_workflow_definition(
 workspace_id text NOT NULL,application_id text NOT NULL,
 flow_id text NOT NULL CHECK(length(flow_id) BETWEEN 1 AND 300
  AND flow_id~'^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200 AND name=btrim(name)
  AND name!~'[[:cntrl:]]'),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
  AND octet_length(definition::text)<=4194304
  AND definition->>'format'='openepm-application-task-flow-v2'
  AND definition->>'workspaceId'=workspace_id
  AND definition->>'applicationId'=application_id
  AND definition->>'flowId'=flow_id AND NOT definition?'version'),
 definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
 updated_operation_id text NOT NULL,updated_revision bigint NOT NULL CHECK(updated_revision>0),
 updater_issuer text NOT NULL CHECK(length(updater_issuer) BETWEEN 1 AND 300),
 updater_subject_id text NOT NULL CHECK(length(updater_subject_id) BETWEEN 1 AND 300),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,flow_id),
 UNIQUE(workspace_id,application_id,flow_id,state_token,definition_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(
  workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,updated_operation_id)
  REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

INSERT INTO epm.application_workflow_definition(
 workspace_id,application_id,flow_id,state_token,status,name,definition,
 definition_digest,updated_operation_id,updated_revision,updater_issuer,
 updater_subject_id,updated_at)
SELECT v.workspace_id,v.application_id,v.flow_id,
 encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
  v.flow_id||E'\n'||v.version::text||E'\n'||s.state_revision::text,'UTF8')),'hex'),
 CASE WHEN s.active_version=v.version THEN 'Active' ELSE 'Saved' END,v.name,
 v.definition-'version',encode(sha256(convert_to(
  epm.current_object_canonical_json(v.definition-'version'),'UTF8')),'hex'),
 s.operation_id,v.created_revision,v.creator_issuer,v.creator_subject_id,s.updated_at
FROM epm.application_workflow_state s JOIN epm.application_workflow_version v
 ON(v.workspace_id,v.application_id,v.flow_id,v.version)=
   (s.workspace_id,s.application_id,s.flow_id,s.latest_version);

CREATE TABLE epm.application_workflow_assignment_pin_current(
 workspace_id text NOT NULL,application_id text NOT NULL,flow_id text NOT NULL,
 activity_id text NOT NULL CHECK(length(activity_id) BETWEEN 1 AND 300
  AND activity_id~'^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
 assignment_set_id text NOT NULL,assignment_state_token text NOT NULL
  CHECK(assignment_state_token~'^[0-9a-f]{64}$'),
 assignment_digest text NOT NULL CHECK(assignment_digest~'^[0-9a-f]{64}$'),
 assignment_id text NOT NULL CHECK(length(assignment_id) BETWEEN 1 AND 300
  AND assignment_id~'^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'),
 PRIMARY KEY(workspace_id,application_id,flow_id,activity_id),
 FOREIGN KEY(workspace_id,application_id,flow_id)
  REFERENCES epm.application_workflow_definition(workspace_id,application_id,flow_id)
  ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,assignment_set_id,
  assignment_state_token,assignment_digest)
  REFERENCES epm.application_assignment_definition(workspace_id,application_id,
  assignment_set_id,state_token,definition_digest) ON DELETE RESTRICT
);
INSERT INTO epm.application_workflow_assignment_pin_current
SELECT p.workspace_id,p.application_id,p.flow_id,p.activity_id,p.assignment_set_id,
 p.assignment_state_token,p.assignment_digest,p.assignment_id
FROM epm.application_workflow_assignment_pin p
JOIN epm.application_workflow_state s USING(workspace_id,application_id,flow_id)
WHERE p.flow_version=s.latest_version;

ALTER TABLE epm.application_workflow_occurrence ADD COLUMN flow_state_token text;
UPDATE epm.application_workflow_occurrence o SET flow_state_token=CASE
 WHEN o.flow_version=s.latest_version THEN d.state_token
 ELSE encode(sha256(convert_to(o.workspace_id||E'\n'||o.application_id||E'\n'||
  o.flow_id||E'\nstale-occurrence\n'||o.flow_version::text,'UTF8')),'hex') END
FROM epm.application_workflow_state s
JOIN epm.application_workflow_definition d USING(workspace_id,application_id,flow_id)
WHERE(o.workspace_id,o.application_id,o.flow_id)=
 (s.workspace_id,s.application_id,s.flow_id);
ALTER TABLE epm.application_workflow_occurrence
 ALTER COLUMN flow_state_token SET NOT NULL,
 ADD CONSTRAINT application_workflow_occurrence_state_token_shape
  CHECK(flow_state_token~'^[0-9a-f]{64}$');

-- Active occurrences must already bind the retained current definition.
DO $migration$ BEGIN
 IF EXISTS(SELECT 1 FROM epm.application_workflow_occurrence o
  JOIN epm.application_workflow_state s USING(workspace_id,application_id,flow_id)
  WHERE o.status='Active' AND o.flow_version<>s.latest_version) THEN
  RAISE EXCEPTION 'MIGRATION_0317_STALE_ACTIVE_WORKFLOW_OCCURRENCE';
 END IF;
END $migration$;

ALTER TABLE epm.application_workflow_activity DROP CONSTRAINT application_workflow_activity_occurrence_flow_fkey;
ALTER TABLE epm.application_workflow_activity DROP CONSTRAINT application_workflow_activity_pin_fkey;
ALTER TABLE epm.application_workflow_occurrence DROP CONSTRAINT application_workflow_occurrence_flow_identity;
ALTER TABLE epm.application_workflow_occurrence DROP CONSTRAINT application_workflow_occurren_workspace_id_application_id__fkey;
ALTER TABLE epm.application_workflow_activity DROP COLUMN flow_version;
ALTER TABLE epm.application_workflow_occurrence DROP COLUMN flow_version;

DROP TRIGGER application_workflow_assignment_pin_immutable ON epm.application_workflow_assignment_pin;
DROP TRIGGER application_workflow_version_immutable ON epm.application_workflow_version;
DROP FUNCTION epm.application_workflow_immutable();
DROP TABLE epm.application_workflow_assignment_pin;
DROP TABLE epm.application_workflow_state;
DROP TABLE epm.application_workflow_version;
ALTER TABLE epm.application_workflow_assignment_pin_current
 RENAME TO application_workflow_assignment_pin;

ALTER TABLE epm.application_workflow_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_workflow_assignment_pin ENABLE ROW LEVEL SECURITY;
DO $migration$ DECLARE relation_name text;BEGIN
 FOREACH relation_name IN ARRAY ARRAY['application_workflow_definition',
  'application_workflow_assignment_pin'] LOOP
  EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime USING '
   '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
   'application_id=current_setting(''epm.application_id'',true)) WITH CHECK '
   '(workspace_id=current_setting(''epm.workspace_id'',true) AND '
   'application_id=current_setting(''epm.application_id'',true))',
   relation_name||'_runtime_scope',relation_name);
  EXECUTE format('CREATE POLICY %I ON epm.%I FOR SELECT TO epm_lifecycle '
   'USING(workspace_id=current_setting(''epm.workspace_id'',true))',
   relation_name||'_lifecycle_scope',relation_name);
 END LOOP;
END $migration$;
REVOKE ALL ON epm.application_workflow_definition,
 epm.application_workflow_assignment_pin
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.application_workflow_definition TO epm_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.application_workflow_assignment_pin TO epm_runtime;
GRANT SELECT(workspace_id,application_id,flow_id,state_token,status)
 ON epm.application_workflow_definition TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,flow_id,activity_id,
 assignment_set_id,assignment_state_token,assignment_id)
 ON epm.application_workflow_assignment_pin TO epm_lifecycle;
DROP FUNCTION epm.current_object_canonical_json(jsonb);

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'''application_workflow_state'',','');
 definition:=replace(definition,'''application_workflow_version''',
  '''application_workflow_definition''');
 IF position('''application_workflow_definition''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0317_TABLES_MISMATCH';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,'application_workflow_state,','');
 definition:=replace(definition,'application_workflow_version','application_workflow_definition');
 IF position('application_workflow_definition' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0317_TABLES_MISMATCH';END IF;EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='61819e7bb839d55fa6fa8abacb67db6f13687fe365076f42ca4652b48e30e44c';
DECLARE current_graph constant text:='076f9601bdb2068ad0e6a4a09ca928a10092ace4e34fd4712711b6a44fd66833';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0317_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0317_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
