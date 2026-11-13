BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=337) THEN
    RAISE EXCEPTION 'MIGRATION_0338_REQUIRES_0337';
  END IF;
  IF EXISTS(
    SELECT 1 FROM epm.calculation_generation generation
    JOIN epm.job job ON job.workspace_id=generation.workspace_id
      AND job.application_id=generation.application_id
      AND job.job_id=generation.job_id
    WHERE generation.generation_kind='partition_manifest'
      AND job.status IN('accepted','ready','running','staged','cancel_requested')
  ) THEN
    RAISE EXCEPTION 'MIGRATION_0338_ACTIVE_PARTITION_WORK';
  END IF;
END $migration$;

-- Worker output is transaction-private staging, not retained application
-- history.  A successful publication copies it into the result-keyed current
-- tables and deletes it before commit.  Failed transactions roll it back.
CREATE TABLE epm.calculation_partition_manifest_staging(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  operation_id text NOT NULL CHECK(operation_id~'^[0-9a-f]{32}$'),
  binding_digest text NOT NULL,
  execution_manifest_digest text NOT NULL,
  partition_policy_version bigint NOT NULL CHECK(partition_policy_version>0),
  partition_map_digest text NOT NULL CHECK(partition_map_digest~'^[0-9a-f]{64}$'),
  partition_map jsonb NOT NULL CHECK(jsonb_typeof(partition_map)='object'
    AND partition_map->>'format'='openepm-calculation-partition-manifest-v2'
    AND octet_length(partition_map::text)<=8388608),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,operation_id),
  FOREIGN KEY(workspace_id,application_id,binding_digest)
    REFERENCES epm.calculation_instance_binding(
      workspace_id,application_id,binding_digest) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,execution_manifest_digest)
    REFERENCES epm.calculation_execution_manifest(
      workspace_id,application_id,manifest_digest) ON DELETE RESTRICT
);
CREATE TABLE epm.calculation_partition_staging(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  operation_id text NOT NULL CHECK(operation_id~'^[0-9a-f]{32}$'),
  partition_key text NOT NULL CHECK(length(partition_key) BETWEEN 1 AND 200),
  certificate_digest text NOT NULL CHECK(certificate_digest~'^[0-9a-f]{64}$'),
  presence text NOT NULL CHECK(presence IN('empty','present')),
  row_count bigint NOT NULL CHECK(row_count>=0),
  PRIMARY KEY(workspace_id,application_id,operation_id,partition_key),
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.calculation_partition_manifest_staging(
      workspace_id,application_id,operation_id) ON DELETE CASCADE,
  CHECK((presence='empty' AND row_count=0)
     OR (presence='present' AND row_count>0))
);

DO $migration$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['calculation_partition_manifest_staging',
    'calculation_partition_staging'] LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
    EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',relation,relation);
    EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
    EXECUTE format('REVOKE ALL ON epm.%I FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle',relation);
    EXECUTE format('GRANT SELECT,INSERT,DELETE ON epm.%I TO epm_runtime,epm_worker',relation);
    EXECUTE format('GRANT SELECT ON epm.%I TO epm_analyst,epm_lifecycle',relation);
  END LOOP;
END $migration$;

DROP TRIGGER calculation_generation_partition_immutable
  ON epm.calculation_generation_partition;
DROP TRIGGER calculation_generation_manifest_immutable
  ON epm.calculation_generation_manifest;
DROP TABLE epm.calculation_generation_partition;
DROP TABLE epm.calculation_generation_manifest;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:='bae3f4f24346b93b423e2fc4e279d43a346832d727e5cdf89ffbd74b7fab7cf9';
DECLARE current_graph constant text:='490f437ceebeacee7874c8e95d8491a50830a4e60b72503138b8d19703f26ae5';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 OR
     position('''calculation_generation_partition'',''calculation_generation_manifest''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0338_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''calculation_generation_partition'',''calculation_generation_manifest''',
    '''calculation_partition_staging'',''calculation_partition_manifest_staging''');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'calculation_generation_partition');
  IF idx IS NULL OR inventory[idx+1]<>'calculation_generation_manifest' THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0338_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['calculation_partition_staging',
    'calculation_partition_manifest_staging']||inventory[idx+2:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
