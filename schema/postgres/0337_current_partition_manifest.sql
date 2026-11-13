BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=336) THEN
    RAISE EXCEPTION 'MIGRATION_0337_REQUIRES_0336';
  END IF;
END $migration$;

CREATE TABLE epm.calculation_partition_manifest_current(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  result_key text NOT NULL CHECK(result_key~'^[A-Za-z0-9._-]{8,128}$'),
  result_state_token text NOT NULL CHECK(result_state_token~'^[0-9a-f]{64}$'),
  binding_digest text NOT NULL,
  execution_manifest_digest text NOT NULL,
  partition_policy_version bigint NOT NULL CHECK(partition_policy_version>0),
  partition_map_digest text NOT NULL CHECK(partition_map_digest~'^[0-9a-f]{64}$'),
  partition_map jsonb NOT NULL CHECK(jsonb_typeof(partition_map)='object'
    AND partition_map->>'format'='openepm-calculation-partition-manifest-v2'
    AND octet_length(partition_map::text)<=8388608),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,result_key),
  UNIQUE(workspace_id,application_id,result_state_token),
  FOREIGN KEY(workspace_id,application_id,result_key,result_state_token)
    REFERENCES epm.calculation_result_state(
      workspace_id,application_id,result_key,state_token) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,application_id,binding_digest)
    REFERENCES epm.calculation_instance_binding(
      workspace_id,application_id,binding_digest) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,execution_manifest_digest)
    REFERENCES epm.calculation_execution_manifest(
      workspace_id,application_id,manifest_digest) ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_partition_current(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  result_key text NOT NULL,
  partition_key text NOT NULL CHECK(length(partition_key) BETWEEN 1 AND 200),
  certificate_digest text NOT NULL CHECK(certificate_digest~'^[0-9a-f]{64}$'),
  presence text NOT NULL CHECK(presence IN('empty','present')),
  row_count bigint NOT NULL CHECK(row_count>=0),
  PRIMARY KEY(workspace_id,application_id,result_key,partition_key),
  FOREIGN KEY(workspace_id,application_id,result_key)
    REFERENCES epm.calculation_partition_manifest_current(
      workspace_id,application_id,result_key) ON DELETE RESTRICT,
  CHECK((presence='empty' AND row_count=0)
     OR (presence='present' AND row_count>0))
);

INSERT INTO epm.calculation_partition_manifest_current(
  workspace_id,application_id,result_key,result_state_token,binding_digest,
  execution_manifest_digest,partition_policy_version,partition_map_digest,
  partition_map,updated_at)
SELECT s.workspace_id,s.application_id,s.result_key,s.state_token,
  m.binding_digest,m.execution_manifest_digest,m.partition_policy_version,
  m.partition_map_digest,m.partition_map,s.updated_at
FROM epm.calculation_result_state s
JOIN epm.calculation_generation_manifest m
  ON m.workspace_id=s.workspace_id AND m.application_id=s.application_id
 AND m.generation_id=s.bridge_generation_id;
INSERT INTO epm.calculation_partition_current(
  workspace_id,application_id,result_key,partition_key,certificate_digest,
  presence,row_count)
SELECT s.workspace_id,s.application_id,s.result_key,p.partition_key,
  p.certificate_digest,p.presence,p.row_count
FROM epm.calculation_result_state s
JOIN epm.calculation_generation_partition p
  ON p.workspace_id=s.workspace_id AND p.application_id=s.application_id
 AND p.generation_id=s.bridge_generation_id;
SET CONSTRAINTS ALL IMMEDIATE;

DO $migration$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['calculation_partition_manifest_current',
    'calculation_partition_current'] LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
    EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',relation,relation);
    EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
    EXECUTE format('REVOKE ALL ON epm.%I FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle',relation);
    EXECUTE format('GRANT SELECT,INSERT,DELETE ON epm.%I TO epm_runtime',relation);
    EXECUTE format('GRANT SELECT ON epm.%I TO epm_worker,epm_analyst,epm_lifecycle',relation);
  END LOOP;
END $migration$;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:='5983c4b06c6d016c8e58b1e078c11a9d011c79e2e37336992e2884c8c794324e';
DECLARE current_graph constant text:='bae3f4f24346b93b423e2fc4e279d43a346832d727e5cdf89ffbd74b7fab7cf9';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 OR
     position('''calculation_result_state''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0337_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,'''calculation_result_state''',
    '''calculation_partition_current'',''calculation_partition_manifest_current'',''calculation_result_state''');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'calculation_result_state');
  IF idx IS NULL THEN RAISE EXCEPTION 'APPLICATION_PURGE_0337_INVENTORY_MISMATCH'; END IF;
  inventory:=inventory[1:idx-1]||ARRAY['calculation_partition_current',
    'calculation_partition_manifest_current']||inventory[idx:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
