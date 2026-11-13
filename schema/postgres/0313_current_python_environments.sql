BEGIN;
-- One current deployment-approved Python environment per stable ID. Runtime
-- profile/package/image digests remain reproducibility pins; numbered product
-- environment objects and their retained payload history do not.
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=312) THEN
    RAISE EXCEPTION 'MIGRATION_0313_REQUIRES_0312';
  END IF;
END $migration$;

CREATE TABLE epm.python_environment_definition(
  workspace_id text NOT NULL,application_id text NOT NULL,
  environment_id text NOT NULL
    CHECK(environment_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status='Active'),
  manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'
    AND octet_length(manifest::text)<=1048576),
  manifest_digest text NOT NULL CHECK(manifest_digest~'^[0-9a-f]{64}$'),
  image_digest text NOT NULL CHECK(image_digest~'^sha256:[0-9a-f]{64}$'),
  updated_operation_id text NOT NULL,updated_revision bigint NOT NULL
    CHECK(updated_revision>0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300),
  updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,environment_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT);

INSERT INTO epm.python_environment_definition(workspace_id,application_id,
  environment_id,state_token,status,manifest,manifest_digest,image_digest,
  updated_operation_id,updated_revision,updated_issuer,updated_subject_id,updated_at)
SELECT v.workspace_id,v.application_id,v.environment_id,
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.environment_id||E'\n'||v.manifest_digest||E'\n'||v.image_digest,'UTF8')),'hex'),
  'Active',v.manifest,v.manifest_digest,v.image_digest,c.operation_id,c.revision,
  v.created_issuer,v.created_subject_id,c.updated_at
FROM epm.python_environment_current c
JOIN epm.python_environment_version v
  USING(workspace_id,application_id,environment_id,version)
WHERE c.status='Active';

ALTER TABLE epm.python_program_version ADD COLUMN environment_state_token text;
UPDATE epm.python_program_version p SET environment_state_token=COALESCE(
  (SELECT d.state_token FROM epm.python_environment_definition d
    JOIN epm.python_environment_current c
      USING(workspace_id,application_id,environment_id)
    WHERE d.workspace_id=p.workspace_id AND d.application_id=p.application_id
      AND d.environment_id=p.environment_id AND c.version=p.environment_version),
  encode(sha256(convert_to(p.workspace_id||E'\n'||p.application_id||E'\n'||
    p.environment_id||E'\nretired-environment\n'||p.environment_version::text,'UTF8')),'hex'));
ALTER TABLE epm.python_program_version
  ALTER COLUMN environment_state_token SET NOT NULL,
  ADD CONSTRAINT python_program_environment_token_format
    CHECK(environment_state_token~'^[0-9a-f]{64}$');

DO $migration$ DECLARE edge record;
BEGIN
  FOR edge IN SELECT conrelid::regclass relation,conname FROM pg_constraint
    WHERE contype='f' AND confrelid IN(
      'epm.python_environment_version'::regclass,
      'epm.python_environment_current'::regclass)
  LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',edge.relation,edge.conname);
  END LOOP;
END $migration$;
ALTER TABLE epm.python_program_version DROP COLUMN environment_version;
DROP TABLE epm.python_environment_current;
DROP TABLE epm.python_environment_version;

ALTER TABLE epm.python_environment_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY python_environment_definition_runtime_scope
  ON epm.python_environment_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_environment_definition_coordinator_scope
  ON epm.python_environment_definition FOR SELECT TO epm_python_coordinator
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.python_environment_definition
  FROM PUBLIC,epm_runtime,epm_python_coordinator;
GRANT SELECT,INSERT,UPDATE ON epm.python_environment_definition TO epm_runtime;
GRANT SELECT ON epm.python_environment_definition TO epm_python_coordinator;

-- Worker availability follows the exact current environment token. Retired
-- source/environment pairings remain inspectable technical evidence but are
-- not claimable execution inputs.
CREATE OR REPLACE FUNCTION epm.python_build_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer:=0;step integer:=0;
BEGIN
  UPDATE epm.python_program_build b SET status='failed',
    error_code='PYTHON_BUILD_PROGRAM_UNAVAILABLE',updated_at=transaction_timestamp()
  WHERE b.status IN('accepted','ready') AND NOT EXISTS(
    SELECT 1 FROM epm.python_program_version v
    JOIN epm.python_environment_definition e ON
      (e.workspace_id,e.application_id,e.environment_id,e.state_token)=
      (v.workspace_id,v.application_id,v.environment_id,v.environment_state_token)
      AND e.status='Active'
    JOIN epm.application a ON (a.workspace_id,a.application_id)=
      (b.workspace_id,b.application_id)
    JOIN epm.application_state s ON (s.workspace_id,s.application_id)=
      (b.workspace_id,b.application_id)
    JOIN epm.workspace w ON w.workspace_id=b.workspace_id
    WHERE (v.workspace_id,v.application_id,v.program_id,v.version)=
      (b.workspace_id,b.application_id,b.program_id,b.program_version)
      AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active');
  GET DIAGNOSTICS step=ROW_COUNT;changed:=changed+step;
  UPDATE epm.python_program_build b SET
    status=CASE WHEN b.status='cancel_requested' THEN 'cancelled'
      WHEN b.attempts<3 THEN 'ready' ELSE 'failed' END,
    error_code=CASE WHEN b.status='cancel_requested' THEN NULL
      WHEN b.attempts>=3 THEN 'PYTHON_BUILD_ATTEMPTS_EXHAUSTED' ELSE NULL END,
    claim_generation=b.claim_generation+1,claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE b.status IN('running','cancel_requested')
    AND b.lease_until<=clock_timestamp();
  GET DIAGNOSTICS step=ROW_COUNT;changed:=changed+step;RETURN changed;
END $$;

-- The claim result type is changed deliberately: environmentStateToken
-- replaces the retired product environment version.
DROP FUNCTION epm.python_build_worker_claim(text,integer,integer,integer,integer);
CREATE FUNCTION epm.python_build_worker_claim(p_claimant text,p_lease_seconds integer,
  p_global_limit integer,p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,build_id text,issuer text,
  subject_id text,request_digest text,program_id text,program_version integer,
  parameter_values jsonb,environment_id text,environment_state_token text,
  status text,claim_generation bigint,attempts integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE candidate record;
BEGIN
  IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
    OR p_lease_seconds NOT BETWEEN 65 AND 300
    OR p_global_limit NOT BETWEEN 1 AND 10000
    OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
    OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
    RAISE EXCEPTION 'PYTHON_BUILD_WORKER_CLAIM_INVALID' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.build.dispatch',0));
  IF (SELECT count(*) FROM epm.python_program_build
      WHERE status IN('running','cancel_requested'))>=p_global_limit THEN RETURN;END IF;
  SELECT b.*,v.environment_id,v.environment_state_token INTO candidate
  FROM epm.python_program_build b JOIN epm.python_program_version v ON
    (v.workspace_id,v.application_id,v.program_id,v.version)=
    (b.workspace_id,b.application_id,b.program_id,b.program_version)
  JOIN epm.python_environment_definition e ON
    (e.workspace_id,e.application_id,e.environment_id,e.state_token)=
    (v.workspace_id,v.application_id,v.environment_id,v.environment_state_token)
    AND e.status='Active'
  JOIN epm.application a ON (a.workspace_id,a.application_id)=
    (b.workspace_id,b.application_id)
  JOIN epm.application_state s ON (s.workspace_id,s.application_id)=
    (b.workspace_id,b.application_id)
  JOIN epm.workspace w ON w.workspace_id=b.workspace_id
  LEFT JOIN epm.worker_workspace_dispatch d ON d.workspace_id=b.workspace_id
  WHERE b.status IN('accepted','ready') AND b.attempts<3 AND a.status='Active'
    AND w.status='Active' AND s.processing_mode='Active'
    AND (SELECT count(*) FROM epm.python_program_build active
      WHERE active.workspace_id=b.workspace_id
        AND active.status IN('running','cancel_requested'))<p_workspace_limit
    AND (SELECT count(*) FROM epm.python_program_build active
      WHERE active.workspace_id=b.workspace_id AND active.application_id=b.application_id
        AND active.status IN('running','cancel_requested'))<p_application_limit
  ORDER BY d.last_claim_sequence NULLS FIRST,b.created_at,b.build_id
  FOR UPDATE OF b SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN;END IF;
  UPDATE epm.python_program_build b SET status='running',
    claim_generation=b.claim_generation+1,claimant=p_claimant,
    lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
    attempts=b.attempts+1,updated_at=transaction_timestamp()
  WHERE (b.workspace_id,b.application_id,b.build_id)=
    (candidate.workspace_id,candidate.application_id,candidate.build_id);
  INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
    VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
    ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
      last_claim_sequence=EXCLUDED.last_claim_sequence,
      claim_count=epm.worker_workspace_dispatch.claim_count+1;
  RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,
    candidate.build_id,candidate.issuer,candidate.subject_id,candidate.request_digest,
    candidate.program_id,candidate.program_version,candidate.parameter_values,
    candidate.environment_id,candidate.environment_state_token,'running'::text,
    candidate.claim_generation+1,candidate.attempts+1;
END $$;
REVOKE ALL ON FUNCTION epm.python_build_worker_claim(
  text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_build_worker_claim(
  text,integer,integer,integer,integer) TO epm_worker;

-- Keep the owner-only reset and application purge inventories exact. The
-- current definition replaces both former environment history relations.
DO $migration$ DECLARE definition text;
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position('''python_environment_current'',' IN definition)=0
      OR position('''python_environment_version''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0313_TABLES_MISMATCH'; END IF;
  definition:=replace(definition,'''python_environment_current'',','');
  definition:=replace(definition,'''python_environment_version''',
    '''python_environment_definition''');
  EXECUTE definition;
  SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
    INTO definition;
  IF position('python_environment_current,' IN definition)=0
      OR position('python_environment_version' IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0313_TABLES_MISMATCH'; END IF;
  definition:=replace(definition,'python_environment_current,','');
  definition:=replace(definition,'python_environment_version',
    'python_environment_definition');
  EXECUTE definition;
END $migration$;

DO $migration$
DECLARE definition text;
DECLARE previous constant text := '70cadc2257566f60dea6f61549edf04fb761cba56b2c212c674b66f31a08eb77';
DECLARE current_graph constant text := '80fd5b2340e4e4b273bc54009fa0f41d4c3096a945736444545ed0f7dd757924';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0313_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0313_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
