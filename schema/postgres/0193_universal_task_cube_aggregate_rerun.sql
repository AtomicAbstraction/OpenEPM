-- Version identical aggregate requests into explicit owner rerun attempts.
-- Generation zero preserves the existing ordinary-request uniqueness contract.

DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=192) THEN
  RAISE EXCEPTION 'MIGRATION_0193_PREDECESSOR_0192_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.cube_aggregate_query
 ADD COLUMN rerun_generation integer NOT NULL DEFAULT 0
  CHECK(rerun_generation>=0),
 ADD COLUMN rerun_of_query_id text,
 ADD COLUMN rerun_idempotency_key text,
 ADD CONSTRAINT cube_aggregate_query_rerun_shape CHECK(
  (rerun_generation=0 AND rerun_of_query_id IS NULL
   AND rerun_idempotency_key IS NULL)
  OR (rerun_generation>0 AND rerun_of_query_id IS NOT NULL
   AND rerun_of_query_id<>query_id
   AND rerun_idempotency_key~'^[A-Za-z0-9._-]{8,128}$')),
 ADD CONSTRAINT cube_aggregate_query_rerun_key UNIQUE(
  workspace_id,application_id,issuer,subject_id,rerun_idempotency_key),
 ADD CONSTRAINT cube_aggregate_query_rerun_source_fkey FOREIGN KEY(
  workspace_id,application_id,rerun_of_query_id)
  REFERENCES epm.cube_aggregate_query(workspace_id,application_id,query_id)
  ON DELETE RESTRICT;

CREATE INDEX cube_aggregate_query_rerun_source
 ON epm.cube_aggregate_query(workspace_id,application_id,rerun_of_query_id)
 WHERE rerun_of_query_id IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.project_cube_aggregate_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE projected_task_id text:='c:'||NEW.query_id;DECLARE can_rerun boolean;
BEGIN
 normalized:=epm.normalized_cube_aggregate_task_status(NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_CUBE_AGGREGATE_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 can_rerun:=NEW.status IN('sealed','expired','failed','cancelled');
 IF TG_OP='INSERT' THEN
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,
   task_class,source_family,source_id,issuer,subject_id,function_name,
   resource_class,status,native_status,interruptible,rerun_supported,
   created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'TechnicalExecution','CubeAggregate',NEW.query_id,NEW.issuer,NEW.subject_id,
   'facts.cube.aggregate.request','long',normalized,NEW.status,
   NEW.status IN('accepted','ready','running','computed','cancel_requested'),
   can_rerun,NEW.accepted_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN(
    'accepted','ready','running','computed','cancel_requested'),
   rerun_supported=can_rerun,updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='CubeAggregate' AND source_id=NEW.query_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.project_cube_aggregate_task() FROM PUBLIC;

UPDATE epm.task t SET rerun_supported=q.status IN(
 'sealed','expired','failed','cancelled')
FROM epm.cube_aggregate_query q
WHERE t.workspace_id=q.workspace_id AND t.application_id=q.application_id
 AND t.source_family='CubeAggregate' AND t.source_id=q.query_id;

-- The table inventory is unchanged. The new self-reference is safe because a
-- workspace reset deletes source and rerun query rows in the same statement.
DO $migration$
DECLARE definition text;revised text;
DECLARE old_fingerprint constant text:=
 '85d945348d81f9384de3711063309443de20b599d3a5cca15c0ba59ef1ba7bb9';
DECLARE new_fingerprint constant text:=
 '343305de079073f393f10966dd4781c1e4e8d555e60635042a9c6ee590d1e9e7';
BEGIN
 definition:=pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure);
 IF position(old_fingerprint IN definition)=0
    OR position(new_fingerprint IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0193_FINGERPRINT_DEFINITION_MISMATCH';
 END IF;
 revised:=replace(definition,old_fingerprint,new_fingerprint);
 EXECUTE revised;
END $migration$;
