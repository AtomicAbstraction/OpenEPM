BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=306) THEN
    RAISE EXCEPTION 'MIGRATION_0307_REQUIRES_0306';
  END IF;
END $migration$;

CREATE TABLE epm.member_list_current (
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  list_id text NOT NULL CHECK(list_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  dimension_id text NOT NULL,
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND octet_length(definition::text)<=4194304),
  canonical_digest text NOT NULL CHECK(canonical_digest ~ '^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN ('Saved','Published','Inactive')),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>0),
  creator_issuer text NOT NULL CHECK(length(creator_issuer) BETWEEN 1 AND 300
    AND creator_issuer !~ '[[:cntrl:]]'),
  creator_subject_id text NOT NULL CHECK(length(creator_subject_id) BETWEEN 1 AND 300
    AND creator_subject_id !~ '[[:cntrl:]]'),
  source_build_id text,
  updated_operation_id text,
  updated_revision bigint NOT NULL CHECK(updated_revision>=0),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,list_id),
  FOREIGN KEY(workspace_id,application_id,dimension_id)
    REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,source_build_id)
    REFERENCES epm.python_program_build(workspace_id,application_id,build_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT
);

INSERT INTO epm.member_list_current(workspace_id,application_id,list_id,
  dimension_id,name,definition,canonical_digest,state_token,status,
  metadata_revision,creator_issuer,creator_subject_id,source_build_id,
  updated_operation_id,updated_revision,updated_at)
SELECT v.workspace_id,v.application_id,v.list_id,v.dimension_id,v.name,
  v.definition - 'version',
  encode(sha256(convert_to((v.definition - 'version')::text,'UTF8')),'hex'),
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.list_id||E'\n'||v.version::text||E'\n'||v.canonical_digest||E'\n'||
    coalesce(p.status,'Saved'),'UTF8')),'hex'),
  CASE WHEN p.status='Published' AND p.version=v.version THEN 'Published'
       WHEN p.status='Inactive' THEN 'Inactive' ELSE 'Saved' END,
  v.metadata_revision,v.creator_issuer,v.creator_subject_id,v.source_build_id,
  NULL,0,v.created_at
FROM epm.member_list_version v
LEFT JOIN epm.member_list_publication p USING(workspace_id,application_id,list_id)
WHERE NOT EXISTS(SELECT 1 FROM epm.member_list_version newer
  WHERE newer.workspace_id=v.workspace_id AND newer.application_id=v.application_id
    AND newer.list_id=v.list_id AND newer.version>v.version);

DROP TABLE epm.member_list_publication;
DROP TABLE epm.member_list_version;
ALTER TABLE epm.member_list_current RENAME TO member_list_definition;

ALTER TABLE epm.member_list_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY member_list_definition_runtime_scope
  ON epm.member_list_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY member_list_definition_lifecycle_scope
  ON epm.member_list_definition TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.member_list_definition
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT,DELETE ON epm.member_list_definition TO epm_runtime;
GRANT UPDATE(dimension_id,name,definition,canonical_digest,state_token,status,
  metadata_revision,creator_issuer,creator_subject_id,source_build_id,
  updated_operation_id,updated_revision,updated_at)
  ON epm.member_list_definition TO epm_runtime;
GRANT SELECT ON epm.member_list_definition TO epm_lifecycle;

DO $migration$
DECLARE definition text;
DECLARE old_tables text :=
  $pattern$'member_list_publication','member_list_version',$pattern$;
DECLARE new_tables text := $pattern$'member_list_definition',$pattern$;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_tables IN definition)=0 THEN RAISE EXCEPTION 'RESET_0307_TABLES_MISMATCH'; END IF;
  EXECUTE replace(definition,old_tables,new_tables);
  old_tables := 'member_list_publication,member_list_version';
  new_tables := 'member_list_definition';
  SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
    INTO definition;
  IF position(old_tables IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0307_TABLES_MISMATCH'; END IF;
  EXECUTE replace(definition,old_tables,new_tables);
END $migration$;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := '192a4db51119418273db23abfcd23a453234b54dff4ff9c457b9dc590884cc2c';
DECLARE current_graph constant text := '0dbbec70c6b0dacac73b377a97d29e4077a7e78ea8b30ab18c0b47b703269754';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0307_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0307_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
