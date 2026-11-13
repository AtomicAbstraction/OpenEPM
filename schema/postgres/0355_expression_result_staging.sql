BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=354) THEN
    RAISE EXCEPTION 'MIGRATION_0355_REQUIRES_0354';
  END IF;
END $migration$;

-- Request-owned private expression output. This is recoverable worker
-- staging, not an application object, result generation, authored partition
-- or retained history. Successful publication and every terminal failure
-- delete the header and cascade all rows.
CREATE TABLE epm.expression_result_staging(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  operation_id text NOT NULL CHECK(operation_id~'^[0-9a-f]{32}$'),
  program_digest text NOT NULL CHECK(program_digest~'^[0-9a-f]{64}$'),
  expected_metadata_revision bigint NOT NULL CHECK(expected_metadata_revision>=0),
  expected_data_revision bigint NOT NULL CHECK(expected_data_revision>=0),
  expected_policy_revision bigint NOT NULL CHECK(expected_policy_revision>=0),
  expected_target_state_token text
    CHECK(expected_target_state_token IS NULL OR
          expected_target_state_token~'^[0-9a-f]{64}$'),
  relation_id text NOT NULL,
  relation_state_token text NOT NULL CHECK(relation_state_token~'^[0-9a-f]{64}$'),
  relation_digest text NOT NULL CHECK(relation_digest~'^[0-9a-f]{64}$'),
  expected_row_count integer NOT NULL CHECK(expected_row_count BETWEEN 0 AND 100000),
  window_size integer NOT NULL CHECK(window_size BETWEEN 1 AND 500),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,operation_id),
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE CASCADE,
  FOREIGN KEY(workspace_id,application_id,relation_id)
    REFERENCES epm.applicability_relation_definition(
      workspace_id,application_id,relation_id) ON DELETE RESTRICT
);

CREATE TABLE epm.expression_result_staging_row(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  operation_id text NOT NULL,
  relation_row_id text NOT NULL,
  coordinate_id bigint NOT NULL,
  source_amount numeric(28,8) NOT NULL,
  source_change_id text NOT NULL CHECK(length(source_change_id) BETWEEN 1 AND 200),
  amount numeric(28,8) NOT NULL,
  source_lookup_lineage jsonb NOT NULL
    CHECK(jsonb_typeof(source_lookup_lineage)='array'
      AND octet_length(source_lookup_lineage::text)<=16777216),
  PRIMARY KEY(workspace_id,application_id,operation_id,relation_row_id),
  UNIQUE(workspace_id,application_id,operation_id,coordinate_id),
  FOREIGN KEY(workspace_id,application_id,operation_id)
    REFERENCES epm.expression_result_staging(
      workspace_id,application_id,operation_id) ON DELETE CASCADE,
  FOREIGN KEY(workspace_id,application_id,coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT
);

DO $migration$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['expression_result_staging_row',
    'expression_result_staging'] LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
    EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',relation,relation);
    EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
    EXECUTE format('REVOKE ALL ON epm.%I FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle',relation);
    EXECUTE format('GRANT SELECT,INSERT,DELETE ON epm.%I TO epm_runtime,epm_worker',relation);
    EXECUTE format('GRANT SELECT ON epm.%I TO epm_lifecycle',relation);
  END LOOP;
END $migration$;

DO $migration$
DECLARE definition text; inventory text[]; idx integer;
DECLARE previous constant text:=
  '996d631f158526b144e3535e4de638e12c06db0a3765b7ed9026a48cd47e29f4';
DECLARE current_graph constant text:=
  'cde87b63a665e9e1d6f42af4c322521e1fc1ef014fbfd7c4698ef5f6936ddeda';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0355_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'calculation_partition_staging');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0355_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY[
    'expression_result_staging_row','expression_result_staging']||
    inventory[idx:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0355_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
