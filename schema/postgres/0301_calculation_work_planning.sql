BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=300) THEN
    RAISE EXCEPTION 'MIGRATION_0301_REQUIRES_0300';
  END IF;
END $migration$;

-- One durable identity covers the bounded affected-work decision.  Individual
-- tasks retain the exact scope epoch, definition and predecessor pins that the
-- worker must recheck before publication.  This is control state, not another
-- business result pointer.
CREATE TABLE epm.calculation_work_request(
  workspace_id text NOT NULL, application_id text NOT NULL,
  request_id text NOT NULL CHECK(request_id~'^[0-9a-f]{32}$'),
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
  subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
  idempotency_key text NOT NULL
    CHECK(idempotency_key~'^[A-Za-z0-9._-]{8,128}$'),
  mode text NOT NULL CHECK(mode IN('affected','force_populated','force_domain')),
  plan_digest text NOT NULL CHECK(plan_digest~'^[0-9a-f]{64}$'),
  plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object'
    AND plan->>'format'='openepm-calculation-work-plan-v1'
    AND octet_length(plan::text)<=8388608),
  status text NOT NULL CHECK(status IN(
    'planned','no_change','running','published','failed','cancelled')),
  error_code text CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,request_id),
  UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT
);
CREATE UNIQUE INDEX calculation_work_compatible_pending
  ON epm.calculation_work_request(workspace_id,application_id,plan_digest)
  WHERE status IN('planned','running');

-- Every caller key remains replayable even when compatible pending work is
-- deduplicated to another request.  The alias is durable control identity;
-- it does not create a second executable request or result pointer.
CREATE TABLE epm.calculation_work_request_key(
  workspace_id text NOT NULL, application_id text NOT NULL,
  issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
  subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
  idempotency_key text NOT NULL
    CHECK(idempotency_key~'^[A-Za-z0-9._-]{8,128}$'),
  request_id text NOT NULL,
  plan_digest text NOT NULL CHECK(plan_digest~'^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,issuer,subject_id,idempotency_key),
  FOREIGN KEY(workspace_id,application_id,request_id)
    REFERENCES epm.calculation_work_request
      (workspace_id,application_id,request_id) ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_work_task(
  workspace_id text NOT NULL, application_id text NOT NULL,
  request_id text NOT NULL, task_ordinal integer NOT NULL
    CHECK(task_ordinal BETWEEN 0 AND 99999),
  binding_digest text NOT NULL CHECK(binding_digest~'^[0-9a-f]{64}$'),
  stage text NOT NULL CHECK(length(stage) BETWEEN 1 AND 200),
  partition_key text NOT NULL CHECK(length(partition_key) BETWEEN 1 AND 200),
  expected_required_epoch bigint NOT NULL CHECK(expected_required_epoch>=0),
  definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
  expected_generation_id text CHECK(expected_generation_id~'^[0-9a-f]{32}$'),
  expected_fragment_generation_id text
    CHECK(expected_fragment_generation_id~'^[0-9a-f]{32}$'),
  expected_manifest_digest text CHECK(expected_manifest_digest~'^[0-9a-f]{64}$'),
  partition_policy_version bigint NOT NULL
    CHECK(partition_policy_version>0),
  reason_codes text[] NOT NULL CHECK(reason_codes<@ARRAY[
    'STALE_DEPENDENCY','CALCULATION_REQUIRED',
    'DEFINITION_REVALIDATION_REQUIRED','FORCE_POPULATED','FORCE_DOMAIN']::text[]),
  predecessor_pins jsonb NOT NULL CHECK(jsonb_typeof(predecessor_pins)='array'
    AND octet_length(predecessor_pins::text)<=2097152),
  job_id text, status text NOT NULL DEFAULT 'pending'
    CHECK(status IN('pending','queued','running','published','failed','cancelled')),
  error_code text CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,request_id,task_ordinal),
  UNIQUE(workspace_id,application_id,request_id,binding_digest,stage,partition_key),
  FOREIGN KEY(workspace_id,application_id,request_id)
    REFERENCES epm.calculation_work_request
      (workspace_id,application_id,request_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,binding_digest,stage,partition_key)
    REFERENCES epm.calculation_scope_state
      (workspace_id,application_id,binding_digest,stage,partition_key)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,job_id)
    REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE RESTRICT,
  CHECK((status='pending' AND job_id IS NULL)
     OR (status<>'pending' AND job_id IS NOT NULL)),
  CHECK((expected_manifest_digest IS NULL
         AND expected_fragment_generation_id IS NULL
        )
     OR (expected_generation_id IS NOT NULL
         AND expected_manifest_digest IS NOT NULL
        ))
);
CREATE INDEX calculation_work_task_job
  ON epm.calculation_work_task(workspace_id,application_id,job_id)
  WHERE job_id IS NOT NULL;
CREATE INDEX calculation_work_task_pending
  ON epm.calculation_work_task(workspace_id,application_id,request_id,task_ordinal)
  WHERE status IN('pending','queued','running');

REVOKE ALL ON epm.calculation_work_request,
  epm.calculation_work_request_key,epm.calculation_work_task
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,UPDATE ON epm.calculation_work_request,
  epm.calculation_work_task TO epm_runtime,epm_worker;
GRANT SELECT,INSERT ON epm.calculation_work_request_key
  TO epm_runtime,epm_worker;
GRANT SELECT ON epm.calculation_work_request,
  epm.calculation_work_request_key,epm.calculation_work_task
  TO epm_analyst,epm_lifecycle;

DO $migration$ DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['calculation_work_request',
   'calculation_work_request_key','calculation_work_task'] LOOP
  EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
  EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
    'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) '
    'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',relation,relation);
  EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I TO epm_lifecycle '
    'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
 END LOOP;
END $migration$;

-- Extend both child-first lifecycle inventories.  Tasks precede requests;
-- both precede their scope-state parents.  The lifecycle login intentionally
-- has no direct DELETE grant: only the existing scoped SECURITY DEFINER purge
-- path may remove them.
DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
DECLARE previous constant text := '5e1a1826f3febb4b5a8e9e9893e3bc2e5040660589e12ec0bb0dbf650065092b';
DECLARE current_graph constant text := 'c48856dfcaea3cb6406941c9804775711a823003a2be80cabcb2762b20ea0953';
DECLARE additions constant text := '''calculation_work_task'',''calculation_work_request_key'',''calculation_work_request'', ';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 OR position('''calculation_impact_fanout'',''calculation_impact_progress''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0301_PREDECESSOR_MISMATCH'; END IF;
 revised:=replace(definition,
   '''calculation_impact_fanout'',''calculation_impact_progress''',
   additions||'''calculation_impact_fanout'',''calculation_impact_progress''');
 EXECUTE replace(revised,previous,current_graph);

 inventory:=epm.application_purge_relations();
 idx:=array_position(inventory,'calculation_impact_fanout');
 IF idx IS NULL THEN RAISE EXCEPTION 'APPLICATION_PURGE_0301_INVENTORY_MISMATCH'; END IF;
 inventory:=inventory[1:idx-1]||ARRAY[
   'calculation_work_task','calculation_work_request_key',
   'calculation_work_request']||inventory[idx:];
 FOR edge IN SELECT child.relname child,parent.relname parent FROM pg_constraint c
   JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace cn ON cn.oid=child.relnamespace
   JOIN pg_class parent ON parent.oid=c.confrelid JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE c.contype='f' AND cn.nspname='epm' AND pn.nspname='epm' AND child.oid<>parent.oid
 LOOP
  IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
     AND array_position(inventory,edge.child)>array_position(inventory,edge.parent) THEN
   RAISE EXCEPTION 'APPLICATION_PURGE_0301_FK_ORDER_INVALID'; END IF;
 END LOOP;
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
   'SELECT '||quote_literal(inventory::text)||'::text[]');
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0301_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
