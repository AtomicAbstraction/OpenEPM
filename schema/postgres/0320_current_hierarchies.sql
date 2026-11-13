BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=319) THEN
  RAISE EXCEPTION 'MIGRATION_0320_REQUIRES_0319';
 END IF;
END $migration$;

-- A hierarchy build is current derived state, not an authored product version.
-- Preserve only the selected active build for each stable named hierarchy.
CREATE TABLE epm.hierarchy_state(
 workspace_id text NOT NULL,application_id text NOT NULL,
 dimension_id text NOT NULL,hierarchy_id text NOT NULL,
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
 membership_semantics text NOT NULL CHECK(membership_semantics IN
   ('unique_member','placement')),
 operation_id text NOT NULL,built_at timestamptz NOT NULL,
 PRIMARY KEY(workspace_id,application_id,dimension_id,hierarchy_id),
 UNIQUE(workspace_id,application_id,dimension_id,hierarchy_id,state_token),
 FOREIGN KEY(workspace_id,application_id,dimension_id,hierarchy_id)
  REFERENCES epm.hierarchy_definition(workspace_id,application_id,dimension_id,hierarchy_id)
  ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,operation_id)
  REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
  ON DELETE RESTRICT
);
INSERT INTO epm.hierarchy_state(workspace_id,application_id,dimension_id,
 hierarchy_id,state_token,metadata_revision,membership_semantics,operation_id,built_at)
SELECT v.workspace_id,v.application_id,v.dimension_id,v.hierarchy_id,
 encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
   v.dimension_id||E'\n'||v.hierarchy_id||E'\n'||v.version::text||E'\n'||
   v.metadata_revision::text,'UTF8')),'hex'),v.metadata_revision,
 v.membership_semantics,v.operation_id,v.built_at
FROM epm.hierarchy_active a JOIN epm.hierarchy_version v
 USING(workspace_id,application_id,dimension_id,hierarchy_id,version);

ALTER TABLE epm.hierarchy_closure RENAME TO hierarchy_closure_versioned_0320;
ALTER INDEX epm.hierarchy_closure_descendant RENAME TO hierarchy_closure_descendant_versioned_0320;
CREATE TABLE epm.hierarchy_closure(
 workspace_id text NOT NULL,application_id text NOT NULL,
 dimension_id text NOT NULL,hierarchy_id text NOT NULL,
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 ancestor_member_id text NOT NULL,descendant_member_id text NOT NULL,
 min_depth integer NOT NULL CHECK(min_depth>=0),
 path_count bigint NOT NULL CHECK(path_count>0),
 PRIMARY KEY(workspace_id,application_id,dimension_id,hierarchy_id,
   ancestor_member_id,descendant_member_id),
 FOREIGN KEY(workspace_id,application_id,dimension_id,hierarchy_id,state_token)
  REFERENCES epm.hierarchy_state(workspace_id,application_id,dimension_id,hierarchy_id,state_token)
  ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,dimension_id,ancestor_member_id)
  REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id)
  ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,dimension_id,descendant_member_id)
  REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id)
  ON DELETE RESTRICT
);
INSERT INTO epm.hierarchy_closure(workspace_id,application_id,dimension_id,
 hierarchy_id,state_token,ancestor_member_id,descendant_member_id,min_depth,path_count)
SELECT c.workspace_id,c.application_id,c.dimension_id,a.hierarchy_id,s.state_token,
 c.ancestor_member_id,c.descendant_member_id,c.min_depth,c.path_count
FROM epm.hierarchy_closure_versioned_0320 c JOIN epm.hierarchy_active a
 USING(workspace_id,application_id,dimension_id,version)
JOIN epm.hierarchy_state s
 USING(workspace_id,application_id,dimension_id,hierarchy_id);
CREATE INDEX hierarchy_closure_descendant ON epm.hierarchy_closure
 (workspace_id,application_id,dimension_id,hierarchy_id,descendant_member_id,
  ancestor_member_id);

-- Retained calculation lineage receives opaque source-state evidence only.
-- It cannot locate a historical hierarchy because no old closure is retained.
DO $migration$ DECLARE item record;
BEGIN
 FOR item IN SELECT conrelid::regclass AS relation,conname
   FROM pg_constraint WHERE contype='f'
    AND confrelid='epm.hierarchy_version'::regclass
    AND conrelid IN('epm.rollup_source_lineage'::regclass,
                    'epm.rollup_placement_path'::regclass)
 LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',item.relation,item.conname);
 END LOOP;
END $migration$;
ALTER TABLE epm.rollup_source_lineage ADD COLUMN hierarchy_state_token text;
UPDATE epm.rollup_source_lineage l SET hierarchy_state_token=encode(sha256(convert_to(
 v.workspace_id||E'\n'||v.application_id||E'\n'||v.dimension_id||E'\n'||
 v.hierarchy_id||E'\n'||v.version::text||E'\n'||v.metadata_revision::text,'UTF8')),'hex')
FROM epm.hierarchy_version v WHERE (v.workspace_id,v.application_id,v.dimension_id,v.version)=
 (l.workspace_id,l.application_id,l.hierarchy_dimension_id,l.hierarchy_version);
ALTER TABLE epm.rollup_source_lineage DROP COLUMN hierarchy_version;
ALTER TABLE epm.rollup_source_lineage ADD CONSTRAINT rollup_source_hierarchy_token_check
 CHECK(hierarchy_state_token IS NULL OR hierarchy_state_token~'^[0-9a-f]{64}$');

ALTER TABLE epm.rollup_placement_path ADD COLUMN hierarchy_state_token text;
UPDATE epm.rollup_placement_path p SET hierarchy_state_token=encode(sha256(convert_to(
 v.workspace_id||E'\n'||v.application_id||E'\n'||v.dimension_id||E'\n'||
 v.hierarchy_id||E'\n'||v.version::text||E'\n'||v.metadata_revision::text,'UTF8')),'hex')
FROM epm.hierarchy_version v WHERE (v.workspace_id,v.application_id,v.dimension_id,v.version)=
 (p.workspace_id,p.application_id,p.hierarchy_dimension_id,p.hierarchy_version);
ALTER TABLE epm.rollup_placement_path ALTER COLUMN hierarchy_state_token SET NOT NULL;
ALTER TABLE epm.rollup_placement_path ADD CONSTRAINT rollup_path_hierarchy_token_check
 CHECK(hierarchy_state_token~'^[0-9a-f]{64}$');
ALTER TABLE epm.rollup_placement_path DROP COLUMN hierarchy_version;

DROP TRIGGER hierarchy_version_guard ON epm.hierarchy_version;
DROP TRIGGER hierarchy_version_must_seal ON epm.hierarchy_version;
DROP TRIGGER hierarchy_seal_active ON epm.hierarchy_active;
DROP TRIGGER hierarchy_activate_complete ON epm.hierarchy_active;
DROP TRIGGER hierarchy_closure_open ON epm.hierarchy_closure_versioned_0320;
DROP FUNCTION epm.hierarchy_version_guard();
DROP FUNCTION epm.hierarchy_version_must_seal();
DROP FUNCTION epm.hierarchy_seal_active();
DROP FUNCTION epm.hierarchy_activate_complete();
DROP FUNCTION epm.hierarchy_closure_open();
DROP TABLE epm.hierarchy_active;
DROP TABLE epm.hierarchy_closure_versioned_0320;
DROP TABLE epm.hierarchy_version;

ALTER TABLE epm.hierarchy_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.hierarchy_closure ENABLE ROW LEVEL SECURITY;
CREATE POLICY hierarchy_state_scope ON epm.hierarchy_state TO epm_runtime,epm_analyst
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
CREATE POLICY hierarchy_closure_scope ON epm.hierarchy_closure TO epm_runtime,epm_analyst
 USING(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
   AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.hierarchy_state,epm.hierarchy_closure
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.hierarchy_state,epm.hierarchy_closure TO epm_runtime;
GRANT SELECT ON epm.hierarchy_state,epm.hierarchy_closure TO epm_analyst,epm_lifecycle;

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 definition:=replace(definition,'''hierarchy_closure'',''hierarchy_active''',
   '''hierarchy_closure'',''hierarchy_state''');
 definition:=replace(definition,',''hierarchy_version'',',',');
 IF position('''hierarchy_state''' IN definition)=0
    OR position('''hierarchy_active''' IN definition)>0
    OR position('''hierarchy_version''' IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0320_HIERARCHY_INVENTORY_MISMATCH';
 END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,'hierarchy_closure,hierarchy_active',
   'hierarchy_closure,hierarchy_state');
 definition:=replace(definition,',hierarchy_version,',',');
 IF position('hierarchy_state' IN definition)=0
    OR position('hierarchy_active' IN definition)>0
    OR position('hierarchy_version' IN definition)>0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0320_HIERARCHY_INVENTORY_MISMATCH';
 END IF;
 EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='822b552f0da05bdbbd31db4ba651295f868338ca4627b62f50339bd802322145';
DECLARE current_graph constant text:='64d706fe96d5f81f44b517ad285071918457908dd7e7328fd75ef5b5b383e10a';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0320_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0320_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
