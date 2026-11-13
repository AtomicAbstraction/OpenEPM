BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=314) THEN
  RAISE EXCEPTION 'MIGRATION_0315_REQUIRES_0314';
 END IF;
END $migration$;

CREATE TABLE epm.python_program_schedule_current(
 workspace_id text NOT NULL,application_id text NOT NULL,
 schedule_id text NOT NULL CHECK(schedule_id~'^[A-Za-z0-9._-]{1,200}$'),
 state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
 status text NOT NULL CHECK(status IN('Saved','Active')),
 program_id text NOT NULL,
 program_source_token text NOT NULL CHECK(program_source_token~'^[0-9a-f]{64}$'),
 parameter_values jsonb NOT NULL CHECK(jsonb_typeof(parameter_values)='object'
  AND octet_length(parameter_values::text)<=1048576),
 interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2678400),
 first_due_at timestamptz NOT NULL,
 catch_up_policy text NOT NULL CHECK(catch_up_policy IN('skip','latest','all')),
 max_catch_up integer NOT NULL CHECK(max_catch_up BETWEEN 1 AND 36),
 execution_issuer text NOT NULL CHECK(length(execution_issuer) BETWEEN 1 AND 300),
 execution_subject text NOT NULL CHECK(length(execution_subject) BETWEEN 1 AND 300),
 delegation_id text NOT NULL,
 delegation_state_token text NOT NULL CHECK(delegation_state_token~'^[0-9a-f]{64}$'),
 updated_operation_id text NOT NULL,updated_revision bigint NOT NULL CHECK(updated_revision>0),
 execution_groups text[] NOT NULL DEFAULT '{}'::text[]
  CHECK(cardinality(execution_groups)<=100 AND array_position(execution_groups,NULL) IS NULL),
 authorization_scope_digest text NOT NULL CHECK(authorization_scope_digest~'^[0-9a-f]{64}$'),
 execution_token_issued_at bigint,execution_authority_kind text NOT NULL,
 last_due_at timestamptz,dispatch_generation bigint NOT NULL DEFAULT 0 CHECK(dispatch_generation>=0),
 dispatch_claimant text,dispatch_lease_until timestamptz,dispatch_error_code text,
 dispatch_failure_count integer NOT NULL DEFAULT 0 CHECK(dispatch_failure_count BETWEEN 0 AND 3),
 dispatch_next_attempt_at timestamptz,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,schedule_id),
 FOREIGN KEY(workspace_id,application_id,program_id)
  REFERENCES epm.python_program_definition(workspace_id,application_id,program_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,delegation_id)
  REFERENCES epm.execution_delegation_definition(workspace_id,application_id,delegation_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,updated_operation_id)
  REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT,
 CHECK((dispatch_claimant IS NULL)=(dispatch_lease_until IS NULL)),
 CHECK((execution_authority_kind='HumanToken' AND execution_token_issued_at>0)
  OR(execution_authority_kind='Technical' AND execution_token_issued_at IS NULL
   AND execution_issuer LIKE 'urn:openepm:%'))
);

INSERT INTO epm.python_program_schedule_current(
 workspace_id,application_id,schedule_id,state_token,status,program_id,
 program_source_token,parameter_values,interval_seconds,first_due_at,
 catch_up_policy,max_catch_up,execution_issuer,execution_subject,delegation_id,
 delegation_state_token,updated_operation_id,updated_revision,execution_groups,
 authorization_scope_digest,execution_token_issued_at,execution_authority_kind,
 last_due_at,dispatch_generation,dispatch_claimant,dispatch_lease_until,
 dispatch_error_code,dispatch_failure_count,dispatch_next_attempt_at,updated_at)
SELECT v.workspace_id,v.application_id,v.schedule_id,
 encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
  v.schedule_id||E'\n'||v.version::text||E'\n'||s.state_revision::text,'UTF8')),'hex'),
 'Saved',v.program_id,v.program_source_token,v.parameter_values,v.interval_seconds,
 v.first_due_at,v.catch_up_policy,v.max_catch_up,v.execution_issuer,
 v.execution_subject,v.delegation_id,v.delegation_state_token,v.operation_id,
 v.created_revision,v.execution_groups,v.authorization_scope_digest,
 v.execution_token_issued_at,v.execution_authority_kind,s.last_due_at,
 s.dispatch_generation,s.dispatch_claimant,s.dispatch_lease_until,
 s.dispatch_error_code,s.dispatch_failure_count,s.dispatch_next_attempt_at,s.updated_at
FROM epm.python_program_schedule_version v
JOIN epm.python_program_schedule_state s
 ON(s.workspace_id,s.application_id,s.schedule_id,s.latest_version)=
   (v.workspace_id,v.application_id,v.schedule_id,v.version);

ALTER TABLE epm.python_program_occurrence ADD COLUMN schedule_state_token text;
UPDATE epm.python_program_occurrence o SET schedule_state_token=CASE
 WHEN o.schedule_version=s.latest_version THEN current.state_token
 ELSE encode(sha256(convert_to(o.workspace_id||E'\n'||o.application_id||E'\n'||
  o.schedule_id||E'\nstale-occurrence\n'||o.schedule_version::text,'UTF8')),'hex') END
FROM epm.python_program_schedule_state s
JOIN epm.python_program_schedule_current current USING(workspace_id,application_id,schedule_id)
WHERE(o.workspace_id,o.application_id,o.schedule_id)=
 (s.workspace_id,s.application_id,s.schedule_id);
ALTER TABLE epm.python_program_occurrence ALTER COLUMN schedule_state_token SET NOT NULL,
 ADD CONSTRAINT python_program_occurrence_state_token_shape
 CHECK(schedule_state_token~'^[0-9a-f]{64}$');
UPDATE epm.python_program_occurrence SET status='cancelled',
 claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,next_attempt_at=NULL,
 error_code='PYTHON_SCHEDULE_TARGET_STALE',updated_at=transaction_timestamp()
WHERE status IN('ready','running','building','running_program','cancel_requested');

ALTER TABLE epm.python_program_build ADD COLUMN schedule_state_token text;
UPDATE epm.python_program_build b SET schedule_state_token=CASE
 WHEN b.schedule_version=s.latest_version THEN current.state_token
 ELSE encode(sha256(convert_to(b.workspace_id||E'\n'||b.application_id||E'\n'||
  b.schedule_id||E'\nstale-build\n'||b.schedule_version::text,'UTF8')),'hex') END
FROM epm.python_program_schedule_state s
JOIN epm.python_program_schedule_current current USING(workspace_id,application_id,schedule_id)
WHERE b.schedule_id IS NOT NULL AND
 (b.workspace_id,b.application_id,b.schedule_id)=(s.workspace_id,s.application_id,s.schedule_id);
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_build_schedule_state_token_shape
 CHECK(schedule_state_token IS NULL OR schedule_state_token~'^[0-9a-f]{64}$'),
 ADD CONSTRAINT python_build_schedule_current_pair
 CHECK((schedule_id IS NULL)=(schedule_state_token IS NULL));

DO $migration$ DECLARE edge record;
BEGIN
 FOR edge IN SELECT conrelid::regclass relation,conname FROM pg_constraint
  WHERE contype='f' AND confrelid IN('epm.python_program_schedule_version'::regclass,
   'epm.python_program_schedule_state'::regclass)
 LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',edge.relation,edge.conname);END LOOP;
END $migration$;
ALTER TABLE epm.python_program_occurrence
 DROP CONSTRAINT python_program_occurrence_workspace_id_application_id_sched_key,
 DROP COLUMN schedule_version,
 ADD CONSTRAINT python_program_occurrence_current_due_unique
 UNIQUE(workspace_id,application_id,schedule_id,schedule_state_token,due_at);
ALTER TABLE epm.python_program_build DROP CONSTRAINT python_build_schedule_pair,
 DROP CONSTRAINT python_build_schedule_version_positive,DROP COLUMN schedule_version;
DROP INDEX IF EXISTS epm.python_schedule_due;
DROP TABLE epm.python_program_schedule_state;
DROP TABLE epm.python_program_schedule_version;
ALTER TABLE epm.python_program_schedule_current RENAME TO python_program_schedule_definition;
CREATE INDEX python_schedule_due ON epm.python_program_schedule_definition(
 status,dispatch_lease_until,workspace_id,application_id,schedule_id) WHERE status='Active';

ALTER TABLE epm.python_program_schedule_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY python_program_schedule_definition_runtime_scope
 ON epm.python_program_schedule_definition TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_program_schedule_definition_lifecycle_scope
 ON epm.python_program_schedule_definition FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.python_program_schedule_definition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.python_program_schedule_definition TO epm_runtime;
GRANT SELECT(workspace_id,application_id,schedule_id,state_token,status,
 dispatch_claimant,dispatch_lease_until) ON epm.python_program_schedule_definition TO epm_lifecycle;

-- State-only worker functions can be rewritten without changing their fence semantics.
DO $migration$ DECLARE item record;definition text;
BEGIN
 FOR item IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='epm' AND p.prokind IN('f','p') AND p.proname IN(
   'python_schedule_worker_release','python_schedule_worker_settle_unexpected')
 LOOP
  definition:=pg_get_functiondef(item.oid);
  IF position('epm.python_program_schedule_state' IN definition)=0 THEN
   RAISE EXCEPTION 'PYTHON_SCHEDULE_0315_FUNCTION_MISMATCH';END IF;
  EXECUTE replace(definition,'epm.python_program_schedule_state',
   'epm.python_program_schedule_definition');
 END LOOP;
END $migration$;

CREATE OR REPLACE FUNCTION epm.python_schedule_worker_claim(p_claimant text,p_lease integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,
 dispatch_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease NOT BETWEEN 5 AND 300 THEN RAISE EXCEPTION 'PYTHON_SCHEDULE_CLAIM_INVALID'
  USING ERRCODE='22023';END IF;
 SELECT s.*,state.schema_epoch INTO c FROM epm.python_program_schedule_definition s
 JOIN epm.application_state state USING(workspace_id,application_id)
 JOIN epm.application app USING(workspace_id,application_id)
 JOIN epm.workspace ws USING(workspace_id)
 LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
 WHERE s.status='Active' AND state.processing_mode='Active' AND app.status='Active'
  AND ws.status='Active' AND s.dispatch_error_code IS NULL
  AND(s.dispatch_lease_until IS NULL OR s.dispatch_lease_until<=clock_timestamp())
  AND(s.dispatch_next_attempt_at IS NULL OR s.dispatch_next_attempt_at<=clock_timestamp())
  AND s.first_due_at<=clock_timestamp()
  AND(s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>s.interval_seconds)<=clock_timestamp())
  AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
   s.delegation_id,s.delegation_state_token,s.execution_issuer,s.execution_subject,
   'python.program.build',s.schedule_id)
  AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
   s.delegation_id,s.delegation_state_token,s.execution_issuer,s.execution_subject,
   'python.program.run',s.schedule_id)
 ORDER BY d.last_claim_sequence NULLS FIRST,COALESCE(s.last_due_at,s.first_due_at),s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 IF c.dispatch_claimant IS NOT NULL THEN
  PERFORM epm.python_schedule_worker_settle_unexpected(c.workspace_id,c.application_id,
   c.schema_epoch,c.schedule_id,c.dispatch_generation,c.dispatch_claimant,
   'PYTHON_SCHEDULE_MATERIALIZATION_LEASE_EXPIRED');RETURN;END IF;
 UPDATE epm.python_program_schedule_definition target SET
  dispatch_generation=target.dispatch_generation+1,dispatch_claimant=p_claimant,
  dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease),
  dispatch_next_attempt_at=NULL,updated_at=transaction_timestamp()
 WHERE(target.workspace_id,target.application_id,target.schedule_id)=
  (c.workspace_id,c.application_id,c.schedule_id);
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.schedule_id,
  c.dispatch_generation+1,c.schema_epoch;
END $$;

CREATE OR REPLACE FUNCTION epm.python_occurrence_worker_claim(
 p_claimant text,p_lease integer,p_global integer,p_workspace integer,p_application integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,status text,
 claim_generation bigint,schema_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease NOT BETWEEN 5 AND 300 OR p_application NOT BETWEEN 1 AND p_workspace
  OR p_workspace NOT BETWEEN 1 AND p_global THEN RAISE EXCEPTION 'PYTHON_OCCURRENCE_CLAIM_INVALID'
  USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.occurrence.dispatch',0));
 IF(SELECT count(*) FROM epm.python_program_occurrence WHERE claimant IS NOT NULL
  AND lease_until>clock_timestamp())>=p_global THEN RETURN;END IF;
 SELECT o.*,state.schema_epoch INTO c FROM epm.python_program_occurrence o
 JOIN epm.python_program_schedule_definition schedule
  ON(schedule.workspace_id,schedule.application_id,schedule.schedule_id,schedule.state_token)=
   (o.workspace_id,o.application_id,o.schedule_id,o.schedule_state_token)
  AND schedule.status='Active'
 JOIN epm.application_state state ON(state.workspace_id,state.application_id)=
  (o.workspace_id,o.application_id)
 JOIN epm.application app ON(app.workspace_id,app.application_id)=
  (o.workspace_id,o.application_id)
 JOIN epm.workspace ws ON ws.workspace_id=o.workspace_id
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE state.processing_mode='Active' AND app.status='Active' AND ws.status='Active'
  AND o.status IN('ready','running','building','running_program','cancel_requested')
  AND(o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
  AND(o.next_attempt_at IS NULL OR o.next_attempt_at<=clock_timestamp())
 ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id
 FOR UPDATE OF o SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 IF c.claimant IS NOT NULL THEN
  UPDATE epm.python_program_occurrence target SET
   worker_failures=LEAST(3,target.worker_failures+1),
   status=CASE WHEN target.worker_failures+1>=3 THEN 'needs_inspection' ELSE target.status END,
   error_code=CASE WHEN target.worker_failures+1>=3 THEN 'PYTHON_SCHEDULE_WORKER_RETRY_LIMIT' ELSE target.error_code END,
   next_attempt_at=CASE WHEN target.worker_failures+1>=3 THEN NULL ELSE
    clock_timestamp()+make_interval(secs=>CASE target.worker_failures WHEN 0 THEN 1 ELSE 5 END)END,
   claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
  WHERE(target.workspace_id,target.application_id,target.occurrence_id,target.claim_generation)=
   (c.workspace_id,c.application_id,c.occurrence_id,c.claim_generation)
   AND target.claimant=c.claimant AND target.lease_until<=clock_timestamp();RETURN;END IF;
 UPDATE epm.python_program_occurrence target SET
  status=CASE WHEN target.status='ready' THEN 'running' ELSE target.status END,
  claim_generation=target.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease),next_attempt_at=NULL,
  updated_at=transaction_timestamp()
 WHERE(target.workspace_id,target.application_id,target.occurrence_id)=
  (c.workspace_id,c.application_id,c.occurrence_id);
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.occurrence_id,
  CASE WHEN c.status='ready' THEN 'running' ELSE c.status END,c.claim_generation+1,c.schema_epoch;
END $$;

CREATE OR REPLACE FUNCTION epm.project_python_schedule_occurrence_task() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE task_sequence bigint;DECLARE ordinal bigint;DECLARE normalized text;
DECLARE authority record;DECLARE projected_task_id text:='s:'||NEW.occurrence_id;
BEGIN
 normalized:=epm.normalized_python_schedule_occurrence_task_status(NEW.status);
 IF normalized IS NULL THEN RAISE EXCEPTION 'UNKNOWN_PYTHON_SCHEDULE_OCCURRENCE_TASK_STATUS';END IF;
 IF TG_OP='UPDATE' AND NEW.status=OLD.status AND NEW.claim_generation=OLD.claim_generation THEN RETURN NEW;END IF;
 IF TG_OP='INSERT' THEN
  SELECT execution_issuer,execution_subject INTO STRICT authority
  FROM epm.python_program_schedule_definition WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND schedule_id=NEW.schedule_id
   AND state_token=NEW.schedule_state_token;
  INSERT INTO epm.task_cursor(workspace_id,application_id,last_sequence)
   VALUES(NEW.workspace_id,NEW.application_id,1)
   ON CONFLICT(workspace_id,application_id)DO UPDATE
   SET last_sequence=epm.task_cursor.last_sequence+1 RETURNING last_sequence INTO task_sequence;
  INSERT INTO epm.task(workspace_id,application_id,task_id,sequence,task_class,
   source_family,source_id,issuer,subject_id,function_name,resource_class,status,
   native_status,interruptible,rerun_supported,created_at,updated_at)
  VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,task_sequence,
   'BusinessExecution','PythonScheduleOccurrence',NEW.occurrence_id,
   authority.execution_issuer,authority.execution_subject,'python.schedule.run','long',
   normalized,NEW.status,NEW.status IN('ready','running','building','running_program',
   'cancel_requested'),false,NEW.created_at,NEW.updated_at);ordinal:=1;
 ELSE
  UPDATE epm.task SET status=normalized,native_status=NEW.status,
   interruptible=NEW.status IN('ready','running','building','running_program','cancel_requested'),
   updated_at=NEW.updated_at WHERE workspace_id=NEW.workspace_id
   AND application_id=NEW.application_id AND source_family='PythonScheduleOccurrence'
   AND source_id=NEW.occurrence_id;
  SELECT coalesce(max(event_ordinal),0)+1 INTO ordinal FROM epm.task_event
   WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
   AND task_id=projected_task_id;
 END IF;
 INSERT INTO epm.task_event(workspace_id,application_id,task_id,event_ordinal,status,
  native_status,claim_generation,receipt_revision,error_code,occurred_at)
 VALUES(NEW.workspace_id,NEW.application_id,projected_task_id,ordinal,normalized,
  NEW.status,NEW.claim_generation,NULL,NEW.error_code,transaction_timestamp());RETURN NEW;
END $$;

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 definition:=replace(definition,'epm.python_program_schedule_state',
  'epm.python_program_schedule_definition');
 definition:=replace(definition,'''python_program_schedule_state'',','');
 definition:=replace(definition,'''python_program_schedule_version''',
  '''python_program_schedule_definition''');
 IF position('''python_program_schedule_definition''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0315_TABLES_MISMATCH';END IF;EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 definition:=replace(definition,'python_program_schedule_state,','');
 definition:=replace(definition,'python_program_schedule_version','python_program_schedule_definition');
 IF position('python_program_schedule_definition' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0315_TABLES_MISMATCH';END IF;EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='ab2f48f839645f7f70989a0d4967a92e42d71cdd5762ec660f1e12644231ff0d';
DECLARE current_graph constant text:='fb7e1dce21dfdf569a0ca137c140137d5309ab51474190a31f8530b67b5afc39';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0315_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0315_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
