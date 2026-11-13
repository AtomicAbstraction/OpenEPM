BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=295) THEN
    RAISE EXCEPTION 'MIGRATION_0296_REQUIRES_0295';
  END IF;
END $migration$;

CREATE TABLE epm.hierarchy_definition (
  workspace_id text NOT NULL, application_id text NOT NULL,
  dimension_id text NOT NULL, hierarchy_id text NOT NULL CHECK(length(hierarchy_id) BETWEEN 1 AND 200),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200),
  status text NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Inactive')),
  membership_mode text NOT NULL CHECK(membership_mode IN ('all_active','explicit')),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,dimension_id,hierarchy_id),
  FOREIGN KEY(workspace_id,application_id,dimension_id)
    REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
  CHECK(NOT is_default OR status='Active')
);
CREATE UNIQUE INDEX hierarchy_default_per_dimension ON epm.hierarchy_definition
  (workspace_id,application_id,dimension_id) WHERE is_default;
CREATE UNIQUE INDEX hierarchy_name_per_dimension ON epm.hierarchy_definition
  (workspace_id,application_id,dimension_id,lower(name));
CREATE TABLE epm.hierarchy_member (
  workspace_id text NOT NULL, application_id text NOT NULL,
  dimension_id text NOT NULL, hierarchy_id text NOT NULL, member_id text NOT NULL,
  status text NOT NULL CHECK(status IN ('Active','Inactive')),
  PRIMARY KEY(workspace_id,application_id,dimension_id,hierarchy_id,member_id),
  FOREIGN KEY(workspace_id,application_id,dimension_id,hierarchy_id)
    REFERENCES epm.hierarchy_definition(workspace_id,application_id,dimension_id,hierarchy_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,dimension_id,member_id)
    REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id) ON DELETE RESTRICT
);
-- Preserve every existing graph/version without introducing an extra tree in
-- dimensions which have never authored a hierarchy.
INSERT INTO epm.hierarchy_definition(workspace_id,application_id,dimension_id,
    hierarchy_id,name,membership_mode,is_default)
  SELECT workspace_id,application_id,dimension_id,'primary','Primary','all_active',true
  FROM (SELECT workspace_id,application_id,dimension_id FROM epm.relationship
        UNION SELECT workspace_id,application_id,dimension_id FROM epm.hierarchy_version) existing;
ALTER TABLE epm.relationship ADD COLUMN hierarchy_id text NOT NULL DEFAULT 'primary';
ALTER TABLE epm.hierarchy_version ADD COLUMN hierarchy_id text NOT NULL DEFAULT 'primary';
ALTER TABLE epm.hierarchy_active ADD COLUMN hierarchy_id text NOT NULL DEFAULT 'primary';
ALTER TABLE epm.relationship ADD CONSTRAINT relationship_hierarchy_fk
 FOREIGN KEY(workspace_id,application_id,dimension_id,hierarchy_id)
 REFERENCES epm.hierarchy_definition(workspace_id,application_id,dimension_id,hierarchy_id) ON DELETE RESTRICT;
ALTER TABLE epm.hierarchy_version ADD CONSTRAINT hierarchy_version_identity_fk
 FOREIGN KEY(workspace_id,application_id,dimension_id,hierarchy_id)
 REFERENCES epm.hierarchy_definition(workspace_id,application_id,dimension_id,hierarchy_id) ON DELETE RESTRICT;
ALTER TABLE epm.hierarchy_version ADD CONSTRAINT hierarchy_version_identity_unique
 UNIQUE(workspace_id,application_id,dimension_id,hierarchy_id,version);
ALTER TABLE epm.hierarchy_active DROP CONSTRAINT hierarchy_active_pkey;
ALTER TABLE epm.hierarchy_active ADD PRIMARY KEY(workspace_id,application_id,dimension_id,hierarchy_id);
ALTER TABLE epm.hierarchy_active ADD CONSTRAINT hierarchy_active_identity_fk
 FOREIGN KEY(workspace_id,application_id,dimension_id,hierarchy_id,version)
 REFERENCES epm.hierarchy_version(workspace_id,application_id,dimension_id,hierarchy_id,version) ON DELETE RESTRICT;
DO $migration$ DECLARE constraint_name text;
BEGIN
 SELECT conname INTO STRICT constraint_name FROM pg_constraint
 WHERE conrelid='epm.relationship'::regclass AND contype='u'
   AND pg_get_constraintdef(oid)='UNIQUE (workspace_id, application_id, dimension_id, parent_member_id, child_member_id)';
 EXECUTE format('ALTER TABLE epm.relationship DROP CONSTRAINT %I',constraint_name);
END $migration$;
ALTER TABLE epm.relationship ADD CONSTRAINT relationship_pair_per_hierarchy
 UNIQUE(workspace_id,application_id,dimension_id,hierarchy_id,parent_member_id,child_member_id);
CREATE INDEX relationship_hierarchy_children ON epm.relationship
 (workspace_id,application_id,dimension_id,hierarchy_id,parent_member_id,status);

CREATE FUNCTION epm.default_hierarchy_id(w text,a text,d text) RETURNS text
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,epm AS $$
 SELECT hierarchy_id FROM epm.hierarchy_definition
 WHERE workspace_id=w AND application_id=a AND dimension_id=d AND is_default AND status='Active'
$$;
REVOKE ALL ON FUNCTION epm.default_hierarchy_id(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.default_hierarchy_id(text,text,text) TO epm_runtime,epm_analyst;

CREATE OR REPLACE FUNCTION epm.reject_relationship_cycle() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE hierarchy epm.hierarchy_definition%ROWTYPE;
BEGIN
 PERFORM 1 FROM epm.application_state WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id FOR UPDATE;
 SELECT * INTO hierarchy FROM epm.hierarchy_definition WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND dimension_id=NEW.dimension_id AND hierarchy_id=NEW.hierarchy_id;
 IF NOT FOUND OR (NEW.status='Active' AND hierarchy.status<>'Active') THEN
   RAISE EXCEPTION 'HIERARCHY_UNAVAILABLE' USING ERRCODE='23514';
 END IF;
 IF NEW.status='Active' AND hierarchy.membership_mode='explicit' AND
    (SELECT count(*) FROM epm.hierarchy_member n JOIN epm.member m
       USING(workspace_id,application_id,dimension_id,member_id)
     WHERE n.workspace_id=NEW.workspace_id AND n.application_id=NEW.application_id
       AND n.dimension_id=NEW.dimension_id AND n.hierarchy_id=NEW.hierarchy_id
       AND n.member_id IN (NEW.parent_member_id,NEW.child_member_id)
       AND n.status='Active' AND m.status='Active')<>2 THEN
   RAISE EXCEPTION 'HIERARCHY_RELATIONSHIP_MEMBER_UNAVAILABLE' USING ERRCODE='23514';
 END IF;
 IF NEW.status='Active' AND EXISTS(
   WITH RECURSIVE reachable(member_id) AS (
     SELECT NEW.child_member_id UNION SELECT r.child_member_id
     FROM epm.relationship r JOIN reachable p ON p.member_id=r.parent_member_id
     WHERE r.workspace_id=NEW.workspace_id AND r.application_id=NEW.application_id
       AND r.dimension_id=NEW.dimension_id AND r.hierarchy_id=NEW.hierarchy_id
       AND r.status='Active' AND r.relationship_id<>NEW.relationship_id)
   SELECT 1 FROM reachable WHERE member_id=NEW.parent_member_id) THEN
   RAISE EXCEPTION 'RELATIONSHIP_CYCLE' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

GRANT SELECT,INSERT,UPDATE ON epm.hierarchy_definition,epm.hierarchy_member TO epm_runtime;
GRANT SELECT ON epm.hierarchy_definition,epm.hierarchy_member TO epm_analyst,epm_lifecycle;
ALTER TABLE epm.hierarchy_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.hierarchy_member ENABLE ROW LEVEL SECURITY;
CREATE POLICY hierarchy_definition_scope ON epm.hierarchy_definition TO epm_runtime,epm_analyst
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY hierarchy_member_scope ON epm.hierarchy_member TO epm_runtime,epm_analyst
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY hierarchy_definition_lifecycle ON epm.hierarchy_definition FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY hierarchy_member_lifecycle ON epm.hierarchy_member FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

-- Extend the existing child-first lifecycle inventories; no new deletion
-- mechanism or scope. Keep the exact qualified predecessor graph check.
DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
   INTO definition;
 IF position('cc795a1184fe76b7b75b9a01a10b0c2b411992da523f9c8cbc1d0d241eabc087' IN definition)=0
    OR position('''numeric_cell_current'',''member''' IN definition)=0
    OR position('''attribute_definition'',''dimension''' IN definition)=0 THEN
   RAISE EXCEPTION 'RESET_0296_PREDECESSOR_MISMATCH';
 END IF;
 revised:=replace(definition,'''numeric_cell_current'',''member'',''manual_journal''',
   '''numeric_cell_current'',''hierarchy_member'',''member'',''manual_journal''');
 revised:=replace(revised,'''attribute_definition'',''dimension''',
   '''attribute_definition'',''hierarchy_definition'',''dimension''');
 EXECUTE replace(revised,'cc795a1184fe76b7b75b9a01a10b0c2b411992da523f9c8cbc1d0d241eabc087','eb1d2ede68050031d9b04d67109cde44e3e4cc92fe980257acc89192bf03b57d');
 inventory:=epm.application_purge_relations();
 idx:=array_position(inventory,'member');
 inventory:=inventory[1:idx-1]||ARRAY['hierarchy_member']||inventory[idx:];
 idx:=array_position(inventory,'dimension');
 inventory:=inventory[1:idx-1]||ARRAY['hierarchy_definition']||inventory[idx:];
 FOR edge IN SELECT child.relname AS child,parent.relname AS parent FROM pg_constraint c
   JOIN pg_class child ON child.oid=c.conrelid JOIN pg_class parent ON parent.oid=c.confrelid
   JOIN pg_namespace cn ON cn.oid=child.relnamespace JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE c.contype='f' AND cn.nspname='epm' AND pn.nspname='epm' AND child.oid<>parent.oid
 LOOP
   IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
      AND array_position(inventory,edge.child)>array_position(inventory,edge.parent) THEN
     RAISE EXCEPTION 'APPLICATION_PURGE_0296_FK_ORDER_INVALID';
   END IF;
 END LOOP;
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
   'SELECT '||quote_literal(inventory::text)||'::text[]');
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
   INTO definition;
 IF position('cc795a1184fe76b7b75b9a01a10b0c2b411992da523f9c8cbc1d0d241eabc087' IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0296_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,'cc795a1184fe76b7b75b9a01a10b0c2b411992da523f9c8cbc1d0d241eabc087','eb1d2ede68050031d9b04d67109cde44e3e4cc92fe980257acc89192bf03b57d');
END $migration$;
COMMIT;
