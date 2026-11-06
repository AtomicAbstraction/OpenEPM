-- Immutable generic Python schedules and durable due occurrences.
DO $$ BEGIN
 IF to_regclass('epm.python_program_schedule_version') IS NOT NULL
 THEN RAISE EXCEPTION 'RESET_0132_DEFINITION_MISMATCH'; END IF;
END $$;

CREATE TABLE epm.python_program_schedule_version(
 workspace_id text NOT NULL, application_id text NOT NULL,
 schedule_id text NOT NULL CHECK(schedule_id ~ '^[A-Za-z0-9._-]{1,200}$'),
 version bigint NOT NULL CHECK(version>0), program_id text NOT NULL,
 program_version integer NOT NULL CHECK(program_version>0),
 parameter_values jsonb NOT NULL CHECK(jsonb_typeof(parameter_values)='object'
   AND octet_length(parameter_values::text)<=1048576),
 interval_seconds integer NOT NULL CHECK(interval_seconds BETWEEN 60 AND 2678400),
 first_due_at timestamptz NOT NULL,
 catch_up_policy text NOT NULL CHECK(catch_up_policy IN ('skip','latest','all')),
 max_catch_up integer NOT NULL CHECK(max_catch_up BETWEEN 1 AND 36),
 execution_issuer text NOT NULL CHECK(length(execution_issuer) BETWEEN 1 AND 300),
 execution_subject text NOT NULL CHECK(length(execution_subject) BETWEEN 1 AND 300),
 delegation_id text NOT NULL CHECK(delegation_id ~ '^[A-Za-z0-9._-]{1,200}$'),
 delegation_version bigint NOT NULL CHECK(delegation_version>0),
 operation_id text NOT NULL,created_revision bigint NOT NULL CHECK(created_revision>0),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,schedule_id,version),
 FOREIGN KEY(workspace_id,application_id,program_id,program_version)
  REFERENCES epm.python_program_version(workspace_id,application_id,program_id,version)
  ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,delegation_id,delegation_version)
  REFERENCES epm.execution_delegation_version(workspace_id,application_id,delegation_id,version)
  ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,operation_id)
  REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT);

CREATE TABLE epm.python_program_schedule_state(
 workspace_id text NOT NULL,application_id text NOT NULL,schedule_id text NOT NULL,
 latest_version bigint NOT NULL CHECK(latest_version>0),active_version bigint,
 state_revision bigint NOT NULL CHECK(state_revision>0),last_due_at timestamptz,
 dispatch_generation bigint NOT NULL DEFAULT 0 CHECK(dispatch_generation>=0),
 dispatch_claimant text,dispatch_lease_until timestamptz,
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,schedule_id),
 FOREIGN KEY(workspace_id,application_id,schedule_id,latest_version)
  REFERENCES epm.python_program_schedule_version(workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,schedule_id,active_version)
  REFERENCES epm.python_program_schedule_version(workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
 CHECK((dispatch_claimant IS NULL)=(dispatch_lease_until IS NULL)));

CREATE TABLE epm.python_program_occurrence(
 workspace_id text NOT NULL,application_id text NOT NULL,occurrence_id text NOT NULL
  CHECK(occurrence_id ~ '^[0-9a-f]{32}$'),schedule_id text NOT NULL,
 schedule_version bigint NOT NULL,due_at timestamptz NOT NULL,
 build_id text CHECK(build_id IS NULL OR build_id ~ '^[0-9a-f]{32}$'),
 workflow_id text CHECK(workflow_id IS NULL OR workflow_id ~ '^[0-9a-f]{32}$'),
 status text NOT NULL CHECK(status IN ('ready','running','building','running_program',
  'published','failed','cancel_requested','cancelled','needs_inspection')),
 claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),claimant text,
 lease_until timestamptz,error_code text,result jsonb,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,occurrence_id),
 UNIQUE(workspace_id,application_id,schedule_id,schedule_version,due_at),
 FOREIGN KEY(workspace_id,application_id,schedule_id,schedule_version)
  REFERENCES epm.python_program_schedule_version(workspace_id,application_id,schedule_id,version) ON DELETE RESTRICT,
 CHECK((claimant IS NULL)=(lease_until IS NULL)));

CREATE INDEX python_schedule_due ON epm.python_program_schedule_state
 (active_version,dispatch_lease_until,workspace_id,application_id,schedule_id)
 WHERE active_version IS NOT NULL;
CREATE INDEX python_occurrence_ready ON epm.python_program_occurrence
 (status,lease_until,due_at,workspace_id,application_id);

GRANT SELECT,INSERT ON epm.python_program_schedule_version,
 epm.python_program_schedule_state,epm.python_program_occurrence TO epm_runtime;
GRANT UPDATE ON epm.python_program_schedule_state,epm.python_program_occurrence TO epm_runtime;
ALTER TABLE epm.python_program_schedule_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_schedule_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.python_program_occurrence ENABLE ROW LEVEL SECURITY;
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['python_program_schedule_version',
 'python_program_schedule_state','python_program_occurrence'] LOOP EXECUTE format(
 'CREATE POLICY %I ON epm.%I TO epm_runtime USING (workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) WITH CHECK (workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',t||'_runtime_scope',t); END LOOP; END $$;

CREATE FUNCTION epm.python_schedule_worker_claim(p_claimant text,p_lease integer)
RETURNS TABLE(workspace_id text,application_id text,schedule_id text,dispatch_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE c record; BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200 OR p_lease NOT BETWEEN 5 AND 300
 THEN RAISE EXCEPTION 'PYTHON_SCHEDULE_CLAIM_INVALID' USING ERRCODE='22023'; END IF;
 SELECT s.* INTO c FROM epm.python_program_schedule_state s
 JOIN epm.python_program_schedule_version v ON (v.workspace_id,v.application_id,v.schedule_id,v.version)=(s.workspace_id,s.application_id,s.schedule_id,s.active_version)
 LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=s.workspace_id
 WHERE s.active_version IS NOT NULL AND (s.dispatch_lease_until IS NULL OR s.dispatch_lease_until<=clock_timestamp())
 AND v.first_due_at<=clock_timestamp() AND (s.last_due_at IS NULL OR s.last_due_at+make_interval(secs=>v.interval_seconds)<=clock_timestamp())
 AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
  v.delegation_id,v.delegation_version,v.execution_issuer,v.execution_subject,
  'python.program.build',s.schedule_id,s.active_version)
 AND epm.execution_delegation_is_current(s.workspace_id,s.application_id,
  v.delegation_id,v.delegation_version,v.execution_issuer,v.execution_subject,
  'python.program.run',s.schedule_id,s.active_version)
 ORDER BY d.last_claim_sequence NULLS FIRST,COALESCE(s.last_due_at,v.first_due_at),s.schedule_id
 FOR UPDATE OF s SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE epm.python_program_schedule_state target SET dispatch_generation=target.dispatch_generation+1,
  dispatch_claimant=p_claimant,dispatch_lease_until=clock_timestamp()+make_interval(secs=>p_lease)
 WHERE target.workspace_id=c.workspace_id AND target.application_id=c.application_id AND target.schedule_id=c.schedule_id;
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.schedule_id,c.dispatch_generation+1;
END $$;
REVOKE ALL ON FUNCTION epm.python_schedule_worker_claim(text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_schedule_worker_claim(text,integer) TO epm_worker;

CREATE FUNCTION epm.python_schedule_worker_release(p_workspace text,p_application text,
 p_schedule text,p_generation bigint,p_claimant text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE n integer; BEGIN
 UPDATE epm.python_program_schedule_state SET dispatch_claimant=NULL,
  dispatch_lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND schedule_id=p_schedule AND dispatch_generation=p_generation
  AND dispatch_claimant=p_claimant;GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;END $$;

CREATE FUNCTION epm.python_occurrence_worker_claim(p_claimant text,p_lease integer,
 p_global integer,p_workspace integer,p_application integer)
RETURNS TABLE(workspace_id text,application_id text,occurrence_id text,status text,
 claim_generation bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200 OR p_lease NOT BETWEEN 5 AND 300
 OR p_application NOT BETWEEN 1 AND p_workspace OR p_workspace NOT BETWEEN 1 AND p_global
 THEN RAISE EXCEPTION 'PYTHON_OCCURRENCE_CLAIM_INVALID' USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.occurrence.dispatch',0));
 IF (SELECT count(*) FROM epm.python_program_occurrence WHERE claimant IS NOT NULL AND lease_until>clock_timestamp())>=p_global THEN RETURN;END IF;
 SELECT o.* INTO c FROM epm.python_program_occurrence o LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=o.workspace_id
 WHERE o.status IN ('ready','running','building','running_program','cancel_requested')
 AND (o.lease_until IS NULL OR o.lease_until<=clock_timestamp())
 AND (SELECT count(*) FROM epm.python_program_occurrence x WHERE x.workspace_id=o.workspace_id AND x.claimant IS NOT NULL AND x.lease_until>clock_timestamp())<p_workspace
 AND (SELECT count(*) FROM epm.python_program_occurrence x WHERE x.workspace_id=o.workspace_id AND x.application_id=o.application_id AND x.claimant IS NOT NULL AND x.lease_until>clock_timestamp())<p_application
 ORDER BY d.last_claim_sequence NULLS FIRST,o.due_at,o.occurrence_id FOR UPDATE OF o SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.python_program_occurrence target SET status=CASE WHEN target.status='ready' THEN 'running' ELSE target.status END,
  claim_generation=target.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease),updated_at=transaction_timestamp()
 WHERE target.workspace_id=c.workspace_id AND target.application_id=c.application_id AND target.occurrence_id=c.occurrence_id;
 RETURN QUERY SELECT c.workspace_id,c.application_id,c.occurrence_id,
  CASE WHEN c.status='ready' THEN 'running' ELSE c.status END,c.claim_generation+1;
END $$;

CREATE FUNCTION epm.python_occurrence_worker_release(p_workspace text,p_application text,
 p_occurrence text,p_generation bigint,p_claimant text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE n integer;BEGIN
 UPDATE epm.python_program_occurrence SET claimant=NULL,lease_until=NULL,
  updated_at=transaction_timestamp() WHERE workspace_id=p_workspace
  AND application_id=p_application AND occurrence_id=p_occurrence
  AND claim_generation=p_generation AND claimant=p_claimant;
 GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;END $$;
REVOKE ALL ON FUNCTION epm.python_schedule_worker_release(text,text,text,bigint,text),
 epm.python_occurrence_worker_claim(text,integer,integer,integer,integer),
 epm.python_occurrence_worker_release(text,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_schedule_worker_release(text,text,text,bigint,text),
 epm.python_occurrence_worker_claim(text,integer,integer,integer,integer),
 epm.python_occurrence_worker_release(text,text,text,bigint,text) TO epm_worker;

GRANT SELECT(workspace_id,application_id,schedule_id,active_version,
 dispatch_claimant,dispatch_lease_until) ON epm.python_program_schedule_state TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,occurrence_id,status,claimant,lease_until)
 ON epm.python_program_occurrence TO epm_lifecycle;
CREATE POLICY python_schedule_state_lifecycle ON epm.python_program_schedule_state
 FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY python_occurrence_lifecycle ON epm.python_program_occurrence
 FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

-- Keep owner reset/delete child-first and reject active schedule work.
DO $$DECLARE d text;r text;marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gate text:='    IF EXISTS (SELECT 1 FROM epm.python_program_occurrence WHERE workspace_id=p_workspace_id AND status IN (''ready'',''running'',''building'',''running_program'',''cancel_requested'',''needs_inspection'')) OR EXISTS (SELECT 1 FROM epm.python_program_schedule_state WHERE workspace_id=p_workspace_id AND dispatch_claimant IS NOT NULL AND dispatch_lease_until>clock_timestamp()) THEN RAISE EXCEPTION ''UNSETTLED_PYTHON_SCHEDULE_WORK''; END IF;'||chr(10)||chr(10);
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(marker in d)=0 OR position('''python_program_workflow_child''' in d)=0
 THEN RAISE EXCEPTION 'RESET_0132_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gate||marker);
 r:=replace(r,'''python_program_workflow_child''','''python_program_occurrence'',''python_program_schedule_state'',''python_program_schedule_version'',''python_program_workflow_child''');
 EXECUTE r;END $$;
