BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=311) THEN
    RAISE EXCEPTION 'MIGRATION_0312_REQUIRES_0311';
  END IF;
END $migration$;

CREATE TABLE epm.application_schedule_current(
  workspace_id text NOT NULL, application_id text NOT NULL,
  schedule_id text NOT NULL
    CHECK(schedule_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN('Saved','Active')),
  definition jsonb NOT NULL CHECK(jsonb_typeof(definition)='object'
    AND definition->>'format'='openepm-application-schedule-v1'
    AND NOT definition?'version'
    AND octet_length(definition::text)<=1048576),
  definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
  rule_id text NOT NULL,
  rule_state_token text NOT NULL CHECK(rule_state_token~'^[0-9a-f]{64}$'),
  rule_program_digest text NOT NULL CHECK(rule_program_digest~'^[0-9a-f]{64}$'),
  activated_revision bigint NOT NULL CHECK(activated_revision>0),
  execution_issuer text NOT NULL CHECK(length(execution_issuer) BETWEEN 1 AND 300),
  execution_subject text NOT NULL CHECK(length(execution_subject) BETWEEN 1 AND 300),
  delegation_id text NOT NULL,
  delegation_state_token text NOT NULL
    CHECK(delegation_state_token~'^[0-9a-f]{64}$'),
  updated_operation_id text NOT NULL,
  updated_revision bigint NOT NULL CHECK(updated_revision>0),
  execution_groups text[] NOT NULL DEFAULT '{}'::text[]
    CHECK(cardinality(execution_groups)<=100
      AND array_position(execution_groups,NULL) IS NULL),
  authorization_scope_digest text NOT NULL
    CHECK(authorization_scope_digest~'^[0-9a-f]{64}$'),
  execution_token_issued_at bigint,
  execution_authority_kind text NOT NULL,
  last_due_at timestamptz,
  dispatch_generation bigint NOT NULL DEFAULT 0 CHECK(dispatch_generation>=0),
  dispatch_claimant text
    CHECK(dispatch_claimant IS NULL OR length(dispatch_claimant) BETWEEN 1 AND 200),
  dispatch_lease_until timestamptz,
  dispatch_error_code text
    CHECK(dispatch_error_code IS NULL OR length(dispatch_error_code) BETWEEN 1 AND 200),
  dispatch_failure_count integer NOT NULL DEFAULT 0
    CHECK(dispatch_failure_count BETWEEN 0 AND 3),
  dispatch_next_attempt_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,schedule_id),
  FOREIGN KEY(workspace_id,application_id,rule_id)
    REFERENCES epm.expression_rule_definition(workspace_id,application_id,rule_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,delegation_id)
    REFERENCES epm.execution_delegation_definition(
      workspace_id,application_id,delegation_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT,
  CHECK((dispatch_claimant IS NULL)=(dispatch_lease_until IS NULL)),
  CHECK((execution_authority_kind='HumanToken' AND execution_token_issued_at>0)
    OR (execution_authority_kind='Technical'
      AND execution_token_issued_at IS NULL
      AND execution_issuer LIKE 'urn:openepm:%'))
);

INSERT INTO epm.application_schedule_current(
  workspace_id,application_id,schedule_id,state_token,status,definition,
  definition_digest,rule_id,rule_state_token,rule_program_digest,
  activated_revision,execution_issuer,
  execution_subject,delegation_id,delegation_state_token,
  updated_operation_id,updated_revision,execution_groups,
  authorization_scope_digest,execution_token_issued_at,
  execution_authority_kind,last_due_at,dispatch_generation,
  dispatch_claimant,dispatch_lease_until,dispatch_error_code,
  dispatch_failure_count,dispatch_next_attempt_at,updated_at)
SELECT v.workspace_id,v.application_id,v.schedule_id,
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.schedule_id||E'\n'||v.version::text||E'\n'||v.definition_digest||E'\n'||
    s.state_revision::text,'UTF8')),'hex'),
  'Saved',
  jsonb_set((v.definition-'version')#-'{target,version}'
      #-'{target,publicationOperationId}'#-'{target,publishedRevision}',
    '{target}',
    ((v.definition->'target')-'version'-'publicationOperationId'-'publishedRevision')
      ||jsonb_build_object('stateToken',v.rule_state_token,
        'activatedRevision',v.published_revision),true),
  encode(sha256(convert_to((jsonb_set((v.definition-'version')
      #-'{target,version}'#-'{target,publicationOperationId}'
      #-'{target,publishedRevision}','{target}',
      ((v.definition->'target')-'version'-'publicationOperationId'-'publishedRevision')
        ||jsonb_build_object('stateToken',v.rule_state_token,
          'activatedRevision',v.published_revision),true))::text,'UTF8')),'hex'),
  v.rule_id,v.rule_state_token,v.rule_program_digest,
  v.published_revision,v.execution_issuer,
  v.execution_subject,v.delegation_id,v.delegation_state_token,
  v.operation_id,v.created_revision,v.execution_groups,
  v.authorization_scope_digest,v.execution_token_issued_at,
  v.execution_authority_kind,s.last_due_at,s.dispatch_generation,
  s.dispatch_claimant,s.dispatch_lease_until,s.dispatch_error_code,
  s.dispatch_failure_count,s.dispatch_next_attempt_at,s.updated_at
FROM epm.application_schedule_version v
JOIN epm.application_schedule_state s
  ON (s.workspace_id,s.application_id,s.schedule_id,s.latest_version)=
     (v.workspace_id,v.application_id,v.schedule_id,v.version);

ALTER TABLE epm.application_schedule_occurrence
  ADD COLUMN schedule_state_token text;
UPDATE epm.application_schedule_occurrence o SET schedule_state_token=CASE
  WHEN o.schedule_version=s.latest_version THEN current.state_token
  ELSE encode(sha256(convert_to(o.workspace_id||E'\n'||o.application_id||E'\n'||
    o.schedule_id||E'\nstale-occurrence\n'||o.schedule_version::text,'UTF8')),'hex') END
FROM epm.application_schedule_state s
JOIN epm.application_schedule_current current
  USING(workspace_id,application_id,schedule_id)
WHERE (o.workspace_id,o.application_id,o.schedule_id)=
  (s.workspace_id,s.application_id,s.schedule_id);
ALTER TABLE epm.application_schedule_occurrence
  ALTER COLUMN schedule_state_token SET NOT NULL,
  ADD CONSTRAINT application_schedule_occurrence_token_format
    CHECK(schedule_state_token~'^[0-9a-f]{64}$');

-- A transformed schedule must be explicitly re-saved and activated through
-- the current validator.  Retired occurrences cannot execute against a
-- definition whose canonical digest and authority have not been re-admitted.
UPDATE epm.application_schedule_occurrence SET status='cancelled',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  next_attempt_at=NULL,error_code='APPLICATION_SCHEDULE_TARGET_STALE',
  updated_at=transaction_timestamp()
WHERE status IN('ready','running','submitted','cancel_requested');

DO $migration$ DECLARE edge record;
BEGIN
  FOR edge IN SELECT conrelid::regclass relation,conname FROM pg_constraint
    WHERE contype='f' AND confrelid IN(
      'epm.application_schedule_version'::regclass,
      'epm.application_schedule_state'::regclass)
  LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',edge.relation,edge.conname);
  END LOOP;
END $migration$;
DROP INDEX epm.application_schedule_due;
ALTER TABLE epm.application_schedule_occurrence
  DROP CONSTRAINT application_schedule_occurren_workspace_id_application_id_s_key,
  DROP COLUMN schedule_version;
ALTER TABLE epm.application_schedule_occurrence
  ADD CONSTRAINT application_schedule_occurrence_due_unique
    UNIQUE(workspace_id,application_id,schedule_id,schedule_state_token,due_at);
DROP TABLE epm.application_schedule_state;
DROP TABLE epm.application_schedule_version;
ALTER TABLE epm.application_schedule_current
  RENAME TO application_schedule_definition;
CREATE INDEX application_schedule_due ON epm.application_schedule_definition(
  status,dispatch_lease_until,workspace_id,application_id,schedule_id)
  WHERE status='Active';

ALTER TABLE epm.application_schedule_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY application_schedule_definition_runtime_scope
  ON epm.application_schedule_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY application_schedule_definition_lifecycle_scope
  ON epm.application_schedule_definition FOR SELECT TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.application_schedule_definition
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.application_schedule_definition TO epm_runtime;
GRANT SELECT(workspace_id,application_id,schedule_id,state_token,status,
  dispatch_claimant,dispatch_lease_until,execution_issuer,execution_subject,
  execution_token_issued_at,execution_authority_kind)
  ON epm.application_schedule_definition
  TO epm_lifecycle;
GRANT SELECT(schedule_state_token)
  ON epm.application_schedule_occurrence TO epm_lifecycle;

-- Functions that only mutate dispatcher state need no semantic rewrite.
DO $migration$ DECLARE item record;definition text;
BEGIN
  FOR item IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
    WHERE n.nspname='epm' AND p.prokind IN('f','p') AND p.proname IN(
      'application_schedule_dispatch_recover','application_schedule_worker_block',
      'application_schedule_worker_release','application_schedule_worker_renew',
      'application_schedule_worker_settle_unexpected',
      'settle_workspace_reset_application_schedules')
  LOOP
    definition:=pg_get_functiondef(item.oid);
    IF position('epm.application_schedule_state' IN definition)=0 THEN
      RAISE EXCEPTION 'APPLICATION_SCHEDULE_0312_FUNCTION_MISMATCH'; END IF;
    EXECUTE replace(definition,'epm.application_schedule_state',
      'epm.application_schedule_definition');
  END LOOP;
END $migration$;

CREATE OR REPLACE FUNCTION epm.application_schedule_worker_claim(
  p_claimant text,p_lease_seconds integer,p_global_limit integer,
  p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
  dispatch_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 30 AND 300 OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application.schedule.dispatch',0));
 IF (SELECT count(*) FROM epm.application_schedule_definition
  WHERE dispatch_claimant IS NOT NULL AND dispatch_lease_until>clock_timestamp())
  >=p_global_limit THEN RETURN;END IF;
 SELECT s.*,state.schema_epoch INTO candidate
 FROM epm.application_schedule_definition s
 JOIN epm.application a
  ON (a.workspace_id,a.application_id)=(s.workspace_id,s.application_id)
 JOIN epm.application_state state
  ON (state.workspace_id,state.application_id)=(s.workspace_id,s.application_id)
 JOIN epm.workspace ws ON ws.workspace_id=s.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
 WHERE s.status='Active' AND s.dispatch_error_code IS NULL
  AND s.dispatch_claimant IS NULL
  AND (s.dispatch_next_attempt_at IS NULL OR s.dispatch_next_attempt_at<=clock_timestamp())
  AND a.status='Active' AND ws.status='Active' AND state.processing_mode='Active'
  AND (s.definition#>>'{recurrence,firstDueAt}')::timestamptz<=clock_timestamp()
  AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>
    (s.definition#>>'{recurrence,intervalSeconds}')::integer)<=clock_timestamp())
  AND (SELECT count(*) FROM epm.application_schedule_definition active
    WHERE active.workspace_id=s.workspace_id AND active.dispatch_claimant IS NOT NULL
      AND active.dispatch_lease_until>clock_timestamp())<p_workspace_limit
  AND (SELECT count(*) FROM epm.application_schedule_definition active
    WHERE active.workspace_id=s.workspace_id AND active.application_id=s.application_id
      AND active.dispatch_claimant IS NOT NULL
      AND active.dispatch_lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,COALESCE(s.last_due_at,
  (s.definition#>>'{recurrence,firstDueAt}')::timestamptz),s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.application_schedule_definition target SET
  dispatch_generation=target.dispatch_generation+1,dispatch_claimant=p_claimant,
  dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE target.workspace_id=candidate.workspace_id
  AND target.application_id=candidate.application_id
  AND target.schedule_id=candidate.schedule_id;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
  candidate.schedule_id,candidate.dispatch_generation+1,candidate.schema_epoch;
END $$;

CREATE OR REPLACE FUNCTION epm.application_schedule_occurrence_worker_settle_unexpected(
 p_workspace text,p_application text,p_schema_epoch bigint,p_occurrence text,
 p_generation bigint,p_claimant text,p_error text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE outcome text;
BEGIN
 IF p_error NOT IN('APPLICATION_SCHEDULE_WORKER_FAILED',
                   'APPLICATION_SCHEDULE_LEASE_EXPIRED') THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_ERROR_INVALID' USING ERRCODE='22023';
 END IF;
 UPDATE epm.application_schedule_occurrence o SET
  attempt_count=o.attempt_count+1,
  inspection_origin_status=CASE WHEN o.attempt_count+1>=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN o.status ELSE o.inspection_origin_status END,
  status=CASE WHEN o.attempt_count+1>=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer)
   THEN 'needs_inspection' ELSE o.status END,
  next_attempt_at=CASE WHEN o.attempt_count+1>=
   ((v.definition#>>'{retryPolicy,maxAttempts}')::integer) THEN NULL
   ELSE clock_timestamp()+make_interval(secs=>
    ((v.definition#>>'{retryPolicy,backoffSeconds}')::integer)) END,
  claim_generation=o.claim_generation+1,claimant=NULL,lease_until=NULL,
  error_code=p_error,updated_at=transaction_timestamp()
 FROM epm.application_schedule_definition v
 WHERE EXISTS(SELECT 1 FROM epm.application_state incarnation
    WHERE incarnation.workspace_id=p_workspace
      AND incarnation.application_id=p_application
      AND incarnation.schema_epoch=p_schema_epoch
      AND incarnation.processing_mode='Active')
  AND (v.workspace_id,v.application_id,v.schedule_id,v.state_token)=
      (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
  AND o.workspace_id=p_workspace AND o.application_id=p_application
  AND o.occurrence_id=p_occurrence AND o.claim_generation=p_generation
  AND o.claimant=p_claimant
  AND o.status IN('running','submitted','cancel_requested')
 RETURNING CASE WHEN o.status='needs_inspection'
  THEN 'needs_inspection' ELSE 'retry' END INTO outcome;
 RETURN outcome;
END $$;

CREATE OR REPLACE FUNCTION epm.application_schedule_occurrence_worker_claim(
 p_claimant text,p_lease_seconds integer,p_global_limit integer,
 p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,
 status text,claim_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 30 AND 300 OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'APPLICATION_SCHEDULE_OCCURRENCE_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 PERFORM pg_advisory_xact_lock(
  hashtextextended('epm.application.schedule.occurrence.dispatch',0));
 IF (SELECT count(*) FROM epm.application_schedule_occurrence
  WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global_limit
 THEN RETURN;END IF;
 SELECT o.*,state.schema_epoch INTO candidate
 FROM epm.application_schedule_occurrence o
 JOIN epm.application_schedule_definition schedule
  ON (schedule.workspace_id,schedule.application_id,schedule.schedule_id,
      schedule.state_token)=(o.workspace_id,o.application_id,o.schedule_id,
      o.schedule_state_token) AND schedule.status='Active'
 JOIN epm.application a
  ON (a.workspace_id,a.application_id)=(o.workspace_id,o.application_id)
 JOIN epm.application_state state
  ON (state.workspace_id,state.application_id)=(o.workspace_id,o.application_id)
 JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE o.status IN('ready','running','submitted','cancel_requested')
  AND o.claimant IS NULL
  AND (o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
  AND a.status='Active' AND ws.status='Active' AND state.processing_mode='Active'
  AND (SELECT count(*) FROM epm.application_schedule_occurrence active
    WHERE active.workspace_id=o.workspace_id AND active.claimant IS NOT NULL
      AND active.lease_until>clock_timestamp())<p_workspace_limit
  AND (SELECT count(*) FROM epm.application_schedule_occurrence active
    WHERE active.workspace_id=o.workspace_id AND active.application_id=o.application_id
      AND active.claimant IS NOT NULL
      AND active.lease_until>clock_timestamp())<p_application_limit
 ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id
 FOR UPDATE OF o SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.application_schedule_occurrence target SET
  status=CASE WHEN target.status='ready' THEN 'running' ELSE target.status END,
  claim_generation=target.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE target.workspace_id=candidate.workspace_id
  AND target.application_id=candidate.application_id
  AND target.occurrence_id=candidate.occurrence_id;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=EXCLUDED.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
  candidate.occurrence_id,
  CASE WHEN candidate.status='ready' THEN 'running' ELSE candidate.status END,
  candidate.claim_generation+1,candidate.schema_epoch;
END $$;

CREATE OR REPLACE FUNCTION epm.project_application_schedule_occurrence_task()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE authority record;DECLARE projected text:='v:'||NEW.occurrence_id;
BEGIN
 normalized:=epm.normalized_application_schedule_occurrence_task_status(NEW.status);
 IF normalized IS NULL THEN
  RAISE EXCEPTION 'UNKNOWN_APPLICATION_SCHEDULE_OCCURRENCE_TASK_STATUS'; END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status
    AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  SELECT execution_issuer,execution_subject INTO STRICT authority
  FROM epm.application_schedule_definition WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND schedule_id=NEW.schedule_id
   AND state_token=NEW.schedule_state_token;
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
    SET last_sequence=epm.task_cursor.last_sequence+1
   RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected,task_sequence,
   'BusinessExecution','ApplicationScheduleOccurrence',NEW.occurrence_id,
   authority.execution_issuer,authority.execution_subject,
   'schedule.occurrence.run','long',normalized,NEW.status,
   NEW.status IN('ready','running','submitted','cancel_requested'),false,
   NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('ready','running','submitted','cancel_requested'),
   updated_at=NEW.updated_at
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND source_family='ApplicationScheduleOccurrence' AND source_id=NEW.occurrence_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
  WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,
  status,native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());
 RETURN NEW;
END $$;

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 definition:=replace(definition,'epm.application_schedule_state',
  'epm.application_schedule_definition');
 definition:=replace(definition,'''application_schedule_state'',','');
 definition:=replace(definition,'''application_schedule_version''',
  '''application_schedule_definition''');
 IF position('''application_schedule_definition''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0312_TABLES_MISMATCH'; END IF;
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
  INTO definition;
 definition:=replace(definition,'application_schedule_state,','');
 definition:=replace(definition,'application_schedule_version',
  'application_schedule_definition');
 IF position('application_schedule_definition' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0312_TABLES_MISMATCH'; END IF;
 EXECUTE definition;
END $migration$;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := '2ba9942b8ff4f7723f40efeb94aff3a679aaf1054eb6b6693ed217542c184e16';
DECLARE current_graph constant text := '70cadc2257566f60dea6f61549edf04fb761cba56b2c212c674b66f31a08eb77';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0312_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0312_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
