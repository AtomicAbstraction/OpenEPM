BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=372) THEN
    RAISE EXCEPTION 'MIGRATION_0373_REQUIRES_0372';
  END IF;
END $migration$;

-- Runtime can invoke only this exact retirement after it has inserted and
-- reconciled the typed target in the same transaction. The function owns no
-- transformation logic and grants no general DELETE authority.
CREATE FUNCTION epm.retire_migrated_generic_source_evidence(
  p_workspace_id text,p_application_id text,p_operation_id text,
  p_manifest_digest text)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $function$
DECLARE
  v_active_generation bigint;
  v_source_count bigint;
  v_target_count bigint;
  v_event_count bigint;
  v_projection_count bigint;
  v_table_count bigint;
BEGIN
  IF p_workspace_id IS NULL OR p_workspace_id=''
     OR p_application_id IS NULL OR p_application_id=''
     OR p_workspace_id<>current_setting('epm.workspace_id',true)
     OR p_application_id<>current_setting('epm.application_id',true)
     OR p_operation_id IS NULL OR p_operation_id!~'^oa1_[0-9a-z]{1,13}_[0-9a-f]{32}_[A-Za-z0-9_-]{43}$'
     OR p_manifest_digest IS NULL OR p_manifest_digest!~'^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_ARGUMENT_INVALID';
  END IF;
  IF current_setting('transaction_isolation')<>'read committed' THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_REQUIRES_READ_COMMITTED';
  END IF;

  SELECT active_projection_generation INTO v_active_generation
    FROM epm.application_state
   WHERE workspace_id=p_workspace_id AND application_id=p_application_id
   FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'APPLICATION_UNAVAILABLE'; END IF;
  IF NOT EXISTS(SELECT 1 FROM epm.operation_commit_provenance
      WHERE workspace_id=p_workspace_id AND application_id=p_application_id
        AND operation_id=p_operation_id) THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_PROVENANCE_REQUIRED';
  END IF;

  IF (SELECT count(*) FROM epm.generic_fact_table
       WHERE workspace_id=p_workspace_id AND application_id=p_application_id
         AND status<>'Deleted')<>3
     OR EXISTS(SELECT 1 FROM epm.generic_fact_table
       WHERE workspace_id=p_workspace_id AND application_id=p_application_id
         AND status<>'Deleted' AND name NOT IN
           ('Observation context','Source model','Source records'))
     OR (SELECT count(DISTINCT name) FROM epm.generic_fact_table
       WHERE workspace_id=p_workspace_id AND application_id=p_application_id
         AND status<>'Deleted')<>3 THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_SOURCE_TABLE_SET_INVALID';
  END IF;
  IF EXISTS(SELECT 1 FROM epm.generic_fact_projection
       WHERE workspace_id=p_workspace_id AND application_id=p_application_id
         AND projection_generation<>v_active_generation) THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_STAGED_LEGACY_STATE';
  END IF;

  SELECT count(*) INTO v_source_count
    FROM epm.generic_fact_projection g
    JOIN epm.generic_fact_table t USING(workspace_id,application_id,table_id)
   WHERE g.workspace_id=p_workspace_id AND g.application_id=p_application_id
     AND g.projection_generation=v_active_generation AND t.status<>'Deleted';
  IF v_source_count=0 OR EXISTS(
    SELECT 1 FROM epm.generic_fact_projection g
    JOIN epm.generic_fact_table t USING(workspace_id,application_id,table_id)
    WHERE g.workspace_id=p_workspace_id AND g.application_id=p_application_id
      AND g.projection_generation=v_active_generation AND (
        (t.name='Observation context' AND
          g.value->>'format'<>'openepm-imported-observation-context-v1') OR
        (t.name='Source records' AND
          g.value->>'format'<>'openepm-imported-source-record-v1') OR
        (t.name='Source model' AND
          g.value->>'format'<>'openepm-imported-source-document-v1'))) THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_SOURCE_FORMAT_INVALID';
  END IF;

  SELECT count(*) INTO v_target_count
    FROM epm.generic_fact_projection g
    JOIN epm.generic_fact_table t USING(workspace_id,application_id,table_id)
    JOIN epm.source_evidence_record r
      ON r.workspace_id=g.workspace_id AND r.application_id=g.application_id
     AND r.collection_id=CASE t.name
       WHEN 'Observation context' THEN 'observation-context'
       WHEN 'Source records' THEN 'source-records'
       WHEN 'Source model' THEN 'source-model' END
     AND r.properties->'legacySource'->>'tableId'=g.table_id
     AND r.properties->'legacySource'->>'seriesKey'=g.series_key
     AND r.properties->'legacySource'->>'changeId'=g.change_id
     AND (r.properties->'legacySource'->>'lastRevision')::bigint=g.last_revision
     AND r.properties->'sourceValue'=g.value
     AND r.observation_members=CASE WHEN t.name='Observation context'
       THEN g.value->'members' ELSE '{}'::jsonb END
     AND r.document_id IS NOT DISTINCT FROM CASE WHEN t.name='Source model'
       THEN g.value->>'document' ELSE NULL END
     AND r.source_pointer=CASE WHEN t.name='Source model'
       THEN jsonb_build_object('jsonPointer',g.value->>'pointer')
       ELSE '{}'::jsonb END
   WHERE g.workspace_id=p_workspace_id AND g.application_id=p_application_id
     AND g.projection_generation=v_active_generation;
  IF v_target_count<>v_source_count THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_TARGET_COVERAGE_MISMATCH';
  END IF;
  IF (SELECT count(*) FROM epm.source_evidence_record
       WHERE workspace_id=p_workspace_id AND application_id=p_application_id
         AND collection_id IN
           ('observation-context','source-records','source-model'))<>v_source_count THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_TARGET_EXTRA_RECORD';
  END IF;
  IF (SELECT count(*) FROM epm.source_evidence_collection
       WHERE workspace_id=p_workspace_id AND application_id=p_application_id
         AND collection_id IN
           ('observation-context','source-records','source-model'))<>3 THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_COLLECTION_COVERAGE_MISMATCH';
  END IF;
  IF EXISTS(SELECT 1 FROM epm.source_evidence_document d
       WHERE d.workspace_id=p_workspace_id AND d.application_id=p_application_id
         AND d.collection_id='source-model' AND NOT EXISTS(
           SELECT 1 FROM epm.source_evidence_record r
            WHERE r.workspace_id=d.workspace_id AND r.application_id=d.application_id
              AND r.collection_id=d.collection_id AND r.document_id=d.document_id))
     OR EXISTS(SELECT 1 FROM epm.source_evidence_record r
       WHERE r.workspace_id=p_workspace_id AND r.application_id=p_application_id
         AND r.collection_id='source-model' AND r.document_id IS NULL) THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_DOCUMENT_COVERAGE_MISMATCH';
  END IF;

  DELETE FROM epm.generic_fact_event
   WHERE workspace_id=p_workspace_id AND application_id=p_application_id;
  GET DIAGNOSTICS v_event_count=ROW_COUNT;
  DELETE FROM epm.generic_fact_projection
   WHERE workspace_id=p_workspace_id AND application_id=p_application_id;
  GET DIAGNOSTICS v_projection_count=ROW_COUNT;
  -- The projection-delete integrity trigger is deferred.  Force it to run
  -- while this narrowly scoped SECURITY DEFINER boundary still supplies the
  -- owner authority that permits retirement after immutable event removal.
  -- Otherwise PostgreSQL would run it at outer commit as epm_runtime and
  -- incorrectly require synthetic Delete events for the retired model.
  SET CONSTRAINTS ALL IMMEDIATE;
  DELETE FROM epm.generic_fact_table
   WHERE workspace_id=p_workspace_id AND application_id=p_application_id;
  GET DIAGNOSTICS v_table_count=ROW_COUNT;
  IF v_projection_count<>v_source_count OR v_table_count<>3 THEN
    RAISE EXCEPTION 'SOURCE_EVIDENCE_CUTOVER_RETIREMENT_COUNT_MISMATCH';
  END IF;
  RETURN jsonb_build_object('manifestDigest',p_manifest_digest,
    'sourceRecords',v_source_count,'typedRecords',v_target_count,
    'retiredEvents',v_event_count,'retiredProjections',v_projection_count,
    'retiredTables',v_table_count);
END $function$;

REVOKE ALL ON FUNCTION epm.retire_migrated_generic_source_evidence(
  text,text,text,text) FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,
  epm_security,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.retire_migrated_generic_source_evidence(
  text,text,text,text) TO epm_runtime;

COMMIT;
SELECT '0373 applied' AS migration;
