BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=301) THEN
    RAISE EXCEPTION 'MIGRATION_0302_REQUIRES_0301';
  END IF;
END $migration$;

CREATE TABLE epm.resolved_read_binding_version(
  workspace_id text NOT NULL, application_id text NOT NULL,
  binding_id text NOT NULL CHECK(binding_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  version bigint NOT NULL CHECK(version>0),
  binding_digest text NOT NULL CHECK(binding_digest~'^[0-9a-f]{64}$'),
  binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'
    AND binding->>'format'='openepm-resolved-read-binding-v1'
    AND octet_length(binding::text)<=4194304),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  policy_revision bigint NOT NULL CHECK(policy_revision>=0),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,binding_id,version),
  UNIQUE(workspace_id,application_id,binding_id,version,binding_digest),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT
);

CREATE TABLE epm.resolved_read_binding_publication(
  workspace_id text NOT NULL, application_id text NOT NULL,
  binding_id text NOT NULL,
  version bigint NOT NULL,
  binding_digest text NOT NULL,
  published_revision bigint NOT NULL CHECK(published_revision>0),
  policy_revision bigint NOT NULL CHECK(policy_revision>0),
  operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,binding_id),
  FOREIGN KEY(workspace_id,application_id,binding_id,version,binding_digest)
    REFERENCES epm.resolved_read_binding_version
      (workspace_id,application_id,binding_id,version,binding_digest)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

REVOKE ALL ON epm.resolved_read_binding_version,
  epm.resolved_read_binding_publication
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.resolved_read_binding_version TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.resolved_read_binding_publication TO epm_runtime;
GRANT SELECT ON epm.resolved_read_binding_version,
  epm.resolved_read_binding_publication TO epm_worker,epm_analyst,epm_lifecycle;

DO $migration$ DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['resolved_read_binding_version',
   'resolved_read_binding_publication'] LOOP
  EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
  EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
    'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) '
    'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',relation,relation);
  EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I TO epm_lifecycle '
    'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
 END LOOP;
END $migration$;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
DECLARE previous constant text := 'c48856dfcaea3cb6406941c9804775711a823003a2be80cabcb2762b20ea0953';
DECLARE current_graph constant text := '15bbbfc786a9990e948fc7814a09bf6b176655e7442a4b09bd9411b25c66778c';
DECLARE additions constant text := '''resolved_read_binding_publication'',''resolved_read_binding_version'', ';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 OR position('''calculation_work_task'',''calculation_work_request_key''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0302_PREDECESSOR_MISMATCH'; END IF;
 revised:=replace(definition,
   '''calculation_work_task'',''calculation_work_request_key''',
   additions||'''calculation_work_task'',''calculation_work_request_key''');
 EXECUTE replace(revised,previous,current_graph);

 inventory:=epm.application_purge_relations();
 idx:=array_position(inventory,'calculation_work_task');
 IF idx IS NULL THEN RAISE EXCEPTION 'APPLICATION_PURGE_0302_INVENTORY_MISMATCH'; END IF;
 inventory:=inventory[1:idx-1]||ARRAY[
   'resolved_read_binding_publication','resolved_read_binding_version']||
   inventory[idx:];
 FOR edge IN SELECT child.relname child,parent.relname parent FROM pg_constraint c
   JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace cn ON cn.oid=child.relnamespace
   JOIN pg_class parent ON parent.oid=c.confrelid JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE c.contype='f' AND cn.nspname='epm' AND pn.nspname='epm' AND child.oid<>parent.oid
 LOOP
  IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
     AND array_position(inventory,edge.child)>array_position(inventory,edge.parent) THEN
   RAISE EXCEPTION 'APPLICATION_PURGE_0302_FK_ORDER_INVALID'; END IF;
 END LOOP;
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
   'SELECT '||quote_literal(inventory::text)||'::text[]');
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0302_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
