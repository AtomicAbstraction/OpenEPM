BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=335) THEN
    RAISE EXCEPTION 'MIGRATION_0336_REQUIRES_0335';
  END IF;
END $migration$;

-- Work plans are reconstructible server queue state, not retained product
-- history.  Refuse to discard live work, then remove completed/failed plans
-- whose old generation pins cannot be meaningful under the current contract.
DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.calculation_work_task
      WHERE status IN('pending','queued','running')) THEN
    RAISE EXCEPTION 'MIGRATION_0336_ACTIVE_CALCULATION_WORK';
  END IF;
END $migration$;
DELETE FROM epm.calculation_work_task;
DELETE FROM epm.calculation_work_request_key;
DELETE FROM epm.calculation_work_request;

ALTER TABLE epm.calculation_result_state ADD CONSTRAINT
  calculation_result_state_token_scope_unique
  UNIQUE(workspace_id,application_id,state_token);
ALTER TABLE epm.calculation_scope_state
  ADD COLUMN current_result_state_token text;
UPDATE epm.calculation_scope_state s SET current_result_state_token=r.state_token
FROM epm.calculation_result_state r
WHERE r.workspace_id=s.workspace_id AND r.application_id=s.application_id
  AND r.bridge_generation_id=s.current_generation_id;
ALTER TABLE epm.calculation_scope_state ADD CONSTRAINT
  calculation_scope_current_result_token_check CHECK(
    current_result_state_token IS NULL OR
    current_result_state_token~'^[0-9a-f]{64}$');
ALTER TABLE epm.calculation_scope_state ADD FOREIGN KEY(
  workspace_id,application_id,current_result_state_token)
  REFERENCES epm.calculation_result_state(
    workspace_id,application_id,state_token) ON DELETE RESTRICT
  DEFERRABLE INITIALLY DEFERRED;

DO $migration$ DECLARE item record; BEGIN
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='epm.calculation_work_task'::regclass
      AND pg_get_constraintdef(oid) LIKE '%expected_fragment_generation_id%'
  LOOP EXECUTE format('ALTER TABLE epm.calculation_work_task DROP CONSTRAINT %I',
                      item.conname); END LOOP;
END $migration$;
ALTER TABLE epm.calculation_work_task
  ADD COLUMN expected_result_state_token text CHECK(
    expected_result_state_token IS NULL OR
    expected_result_state_token~'^[0-9a-f]{64}$'),
  ADD COLUMN expected_partition_certificate_digest text CHECK(
    expected_partition_certificate_digest IS NULL OR
    expected_partition_certificate_digest~'^[0-9a-f]{64}$'),
  DROP COLUMN expected_generation_id,
  DROP COLUMN expected_fragment_generation_id,
  ADD CONSTRAINT calculation_work_current_expectation_shape CHECK(
    (expected_manifest_digest IS NULL AND
       expected_partition_certificate_digest IS NULL AND
       expected_result_state_token IS NULL)
    OR (expected_manifest_digest IS NOT NULL AND
       expected_partition_certificate_digest IS NOT NULL AND
       expected_result_state_token IS NOT NULL));

DROP TRIGGER calculation_generation_manifest_immutable
  ON epm.calculation_generation_manifest;
DO $migration$ DECLARE item record; BEGIN
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='epm.calculation_generation_manifest'::regclass
      AND pg_get_constraintdef(oid) LIKE '%openepm-calculation-generation-manifest-v1%'
  LOOP EXECUTE format('ALTER TABLE epm.calculation_generation_manifest DROP CONSTRAINT %I',
                      item.conname); END LOOP;
END $migration$;
WITH converted AS (
  SELECT workspace_id,application_id,generation_id,
    jsonb_set(jsonb_set(partition_map,'{format}',
      to_jsonb('openepm-calculation-partition-manifest-v2'::text)),
      '{partitions}',(SELECT jsonb_agg(value-'fragmentGenerationId'
        ORDER BY value->>'partitionKey')
        FROM jsonb_array_elements(partition_map->'partitions'))) AS value
  FROM epm.calculation_generation_manifest)
UPDATE epm.calculation_generation_manifest target SET
  partition_map=converted.value,
  partition_map_digest=encode(sha256(convert_to(converted.value::text,'UTF8')),'hex')
FROM converted WHERE (target.workspace_id,target.application_id,target.generation_id)=
 (converted.workspace_id,converted.application_id,converted.generation_id);
ALTER TABLE epm.calculation_generation_manifest ADD CONSTRAINT
  calculation_partition_manifest_current_shape CHECK(
    jsonb_typeof(partition_map)='object' AND
    partition_map->>'format'='openepm-calculation-partition-manifest-v2' AND
    octet_length(partition_map::text)<=8388608);
CREATE TRIGGER calculation_generation_manifest_immutable
  BEFORE UPDATE OR DELETE ON epm.calculation_generation_manifest
  FOR EACH ROW EXECUTE FUNCTION epm.calculation_dependency_immutable();

DO $migration$ DECLARE item record; BEGIN
  FOR item IN SELECT conname FROM pg_constraint
    WHERE conrelid='epm.calculation_generation_partition'::regclass
      AND (pg_get_constraintdef(oid) LIKE '%fragment_generation_id%'
        OR pg_get_constraintdef(oid) LIKE '%presence%row_count%')
  LOOP EXECUTE format('ALTER TABLE epm.calculation_generation_partition DROP CONSTRAINT %I',
                      item.conname); END LOOP;
END $migration$;
ALTER TABLE epm.calculation_generation_partition
  DROP COLUMN fragment_generation_id,
  ADD CONSTRAINT calculation_partition_presence_rows CHECK(
    (presence='empty' AND row_count=0)
    OR (presence='present' AND row_count>0));

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='7d480ecdd1f87d9bc2ab9a0b65b8d863216ef9d2401d62d04cfd877398a7902b';
DECLARE current_graph constant text:='5983c4b06c6d016c8e58b1e078c11a9d011c79e2e37336992e2884c8c794324e';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0336_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0336_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
