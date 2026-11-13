BEGIN;
-- One authored Python source per stable program ID. Builds remain technical
-- evidence, but bind an opaque source token and digest rather than a retained
-- numbered product source.
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=313) THEN
    RAISE EXCEPTION 'MIGRATION_0314_REQUIRES_0313';
  END IF;
END $migration$;

CREATE TEMP TABLE current_python_program_token_map ON COMMIT DROP AS
SELECT v.workspace_id,v.application_id,v.program_id,v.version,
  encode(sha256(convert_to(v.workspace_id||E'\n'||v.application_id||E'\n'||
    v.program_id||E'\n'||v.version::text||E'\n'||v.source_digest,'UTF8')),'hex') source_token,
  row_number() OVER(PARTITION BY v.workspace_id,v.application_id,v.program_id
    ORDER BY v.version DESC) source_rank
FROM epm.python_program_version v;
CREATE UNIQUE INDEX current_python_program_token_map_key ON
  current_python_program_token_map(workspace_id,application_id,program_id,version);

CREATE TABLE epm.python_program_definition(
  workspace_id text NOT NULL,application_id text NOT NULL,
  program_id text NOT NULL CHECK(program_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  source_token text NOT NULL CHECK(source_token~'^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN('Inactive','Active')),
  source_text text NOT NULL CHECK(octet_length(source_text) BETWEEN 1 AND 1048576),
  source_digest text NOT NULL CHECK(source_digest~'^[0-9a-f]{64}$'),
  entry_point text NOT NULL CHECK(entry_point~'^[A-Za-z_][A-Za-z0-9_]{0,99}$'),
  parameter_schema jsonb NOT NULL CHECK(jsonb_typeof(parameter_schema)='object'
    AND octet_length(parameter_schema::text)<=262144),
  environment_id text NOT NULL,environment_state_token text NOT NULL
    CHECK(environment_state_token~'^[0-9a-f]{64}$'),
  updated_operation_id text NOT NULL,updated_revision bigint NOT NULL CHECK(updated_revision>0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300),
  updated_subject_id text NOT NULL CHECK(length(updated_subject_id) BETWEEN 1 AND 300),
  activated_revision bigint,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,program_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE RESTRICT);

INSERT INTO epm.python_program_definition(workspace_id,application_id,program_id,
 state_token,source_token,status,source_text,source_digest,entry_point,parameter_schema,
 environment_id,environment_state_token,updated_operation_id,updated_revision,
 updated_issuer,updated_subject_id,activated_revision,updated_at)
SELECT v.workspace_id,v.application_id,v.program_id,
 encode(sha256(convert_to(m.source_token||E'\nstate\n'||
  CASE WHEN p.version=v.version AND p.status='Published' THEN 'Active' ELSE 'Inactive' END,
  'UTF8')),'hex'),m.source_token,
 CASE WHEN p.version=v.version AND p.status='Published' THEN 'Active' ELSE 'Inactive' END,
 v.source_text,v.source_digest,v.entry_point,v.parameter_schema,v.environment_id,
 v.environment_state_token,CASE WHEN p.version=v.version THEN p.operation_id
   ELSE v.created_operation_id END,
 CASE WHEN p.version=v.version THEN p.revision ELSE v.created_revision END,
 v.created_issuer,v.created_subject_id,
 CASE WHEN p.version=v.version AND p.status='Published' THEN p.revision END,
 CASE WHEN p.version=v.version THEN p.updated_at ELSE v.created_at END
FROM current_python_program_token_map m JOIN epm.python_program_version v USING(
 workspace_id,application_id,program_id,version)
LEFT JOIN epm.python_program_publication p USING(workspace_id,application_id,program_id)
WHERE m.source_rank=1;

ALTER TABLE epm.python_program_build ADD COLUMN program_source_token text;
UPDATE epm.python_program_build b SET program_source_token=m.source_token
FROM current_python_program_token_map m WHERE
 (m.workspace_id,m.application_id,m.program_id,m.version)=
 (b.workspace_id,b.application_id,b.program_id,b.program_version);
ALTER TABLE epm.python_program_build ALTER COLUMN program_source_token SET NOT NULL,
 ADD CONSTRAINT python_program_build_source_token_format
 CHECK(program_source_token~'^[0-9a-f]{64}$');

ALTER TABLE epm.python_program_schedule_version ADD COLUMN program_source_token text;
UPDATE epm.python_program_schedule_version s SET program_source_token=m.source_token
FROM current_python_program_token_map m WHERE
 (m.workspace_id,m.application_id,m.program_id,m.version)=
 (s.workspace_id,s.application_id,s.program_id,s.program_version);
ALTER TABLE epm.python_program_schedule_version ALTER COLUMN program_source_token SET NOT NULL,
 ADD CONSTRAINT python_schedule_program_source_token_format
 CHECK(program_source_token~'^[0-9a-f]{64}$');

DO $migration$ DECLARE edge record; BEGIN
 FOR edge IN SELECT conrelid::regclass relation,conname FROM pg_constraint
 WHERE contype='f' AND confrelid IN('epm.python_program_version'::regclass,
   'epm.python_program_publication'::regclass)
 LOOP EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',edge.relation,edge.conname); END LOOP;
END $migration$;
ALTER TABLE epm.python_program_build DROP COLUMN program_version;
ALTER TABLE epm.python_program_schedule_version DROP COLUMN program_version;
GRANT SELECT(program_source_token) ON epm.python_program_build TO epm_lifecycle;
DROP TABLE epm.python_program_publication;
DROP TABLE epm.python_program_version;

ALTER TABLE epm.python_program_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY python_program_definition_runtime_scope ON epm.python_program_definition
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY python_program_definition_coordinator_scope ON epm.python_program_definition
 FOR SELECT TO epm_python_coordinator USING(
  workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.python_program_definition FROM PUBLIC,epm_runtime,epm_python_coordinator;
GRANT SELECT,INSERT,UPDATE,DELETE ON epm.python_program_definition TO epm_runtime;
GRANT SELECT ON epm.python_program_definition TO epm_python_coordinator;

CREATE OR REPLACE FUNCTION epm.python_build_diagnostics_source_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
 IF NEW.diagnostics IS NOT NULL AND NEW.diagnostics->>'sourceDigest' IS DISTINCT FROM
   (SELECT d.source_digest FROM epm.python_program_definition d WHERE
    (d.workspace_id,d.application_id,d.program_id,d.source_token)=
    (NEW.workspace_id,NEW.application_id,NEW.program_id,NEW.program_source_token))
 THEN RAISE EXCEPTION 'PYTHON_BUILD_DIAGNOSTIC_SOURCE_MISMATCH' USING ERRCODE='23514';END IF;
 RETURN NEW;END$$;

CREATE OR REPLACE FUNCTION epm.python_impact_artifact_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE purpose text;source_digest text;BEGIN
 SELECT b.purpose,d.source_digest INTO purpose,source_digest
 FROM epm.python_program_build b JOIN epm.python_program_definition d ON
  (d.workspace_id,d.application_id,d.program_id,d.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 WHERE (b.workspace_id,b.application_id,b.build_id)=
  (NEW.workspace_id,NEW.application_id,NEW.build_id);
 IF purpose IS NULL OR (purpose='ImpactTest') IS DISTINCT FROM(NEW.impact IS NOT NULL)
   OR (NEW.impact IS NOT NULL AND NEW.impact->>'sourceDigest' IS DISTINCT FROM source_digest)
 THEN RAISE EXCEPTION 'PYTHON_IMPACT_ARTIFACT_SOURCE_OR_PURPOSE_MISMATCH' USING ERRCODE='23514';END IF;
 RETURN NEW;END$$;

CREATE OR REPLACE FUNCTION epm.source_bound_definition_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE artifact record;operation jsonb;definition jsonb;function_name text;BEGIN
 IF TG_OP='UPDATE' AND(OLD.source_build_id IS NOT NULL OR NEW.source_build_id IS NOT NULL)
 THEN RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_IMMUTABLE' USING ERRCODE='23514';END IF;
 IF NEW.source_build_id IS NULL THEN RETURN NEW;END IF;
 SELECT b.purpose,b.status,a.canonical_plan,a.source_map,a.impact,a.sealed_at,d.source_digest
 INTO artifact FROM epm.python_program_build b
 JOIN epm.python_plan_artifact a USING(workspace_id,application_id,build_id)
 JOIN epm.python_program_definition d ON
  (d.workspace_id,d.application_id,d.program_id,d.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 WHERE(b.workspace_id,b.application_id,b.build_id)=
  (NEW.workspace_id,NEW.application_id,NEW.source_build_id);
 IF NOT FOUND OR artifact.purpose NOT IN('Validation','ImpactTest') OR artifact.status<>'sealed'
  OR(artifact.purpose='ImpactTest' AND(artifact.impact->>'status' IS DISTINCT FROM 'complete'
   OR artifact.sealed_at<=clock_timestamp()-interval '24 hours'))
  OR artifact.source_map->>'sourceDigest' IS DISTINCT FROM artifact.source_digest
  OR jsonb_array_length(artifact.canonical_plan->'units')<>1
  OR jsonb_array_length(artifact.canonical_plan#>'{units,0,operations}')<>1 THEN
  RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_INVALID' USING ERRCODE='23514';END IF;
 operation:=artifact.canonical_plan#>'{units,0,operations,0}';
 function_name:=operation->>'function';definition:=operation#>'{arguments,definition}';
 IF TG_TABLE_NAME='member_list_definition' THEN
  IF function_name<>'metadata.member_list.save' OR definition IS DISTINCT FROM NEW.definition
   OR definition->>'listId' IS DISTINCT FROM NEW.list_id THEN
   RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_MISMATCH' USING ERRCODE='23514';END IF;
 ELSE
  IF function_name NOT IN('application.rule.save','calculated.member.save')
   OR definition IS DISTINCT FROM NEW.program->'arguments'
   OR COALESCE(operation#>>'{arguments,ruleId}',definition->>'definitionId')
      IS DISTINCT FROM NEW.rule_id
   OR NEW.program->>'function' IS DISTINCT FROM(CASE function_name
      WHEN 'application.rule.save' THEN 'application.rule.plan'
      ELSE 'calculated.member.definition' END) THEN
   RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_MISMATCH' USING ERRCODE='23514';END IF;
 END IF;
 IF(operation#>>'{arguments,expectedMetadataRevision}')::bigint
   IS DISTINCT FROM NEW.metadata_revision THEN
  RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_METADATA_MISMATCH' USING ERRCODE='23514';END IF;
 RETURN NEW;END$$;

CREATE OR REPLACE FUNCTION epm.python_build_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer:=0;step integer:=0;BEGIN
 UPDATE epm.python_program_build b SET status='failed',error_code='PYTHON_BUILD_PROGRAM_UNAVAILABLE',
  updated_at=transaction_timestamp() WHERE b.status IN('accepted','ready') AND NOT EXISTS(
  SELECT 1 FROM epm.python_program_definition d JOIN epm.python_environment_definition e ON
   (e.workspace_id,e.application_id,e.environment_id,e.state_token)=
   (d.workspace_id,d.application_id,d.environment_id,d.environment_state_token)
  JOIN epm.application a USING(workspace_id,application_id)
  JOIN epm.application_state s USING(workspace_id,application_id)
  JOIN epm.workspace w USING(workspace_id)
  WHERE (d.workspace_id,d.application_id,d.program_id,d.state_token)=
   (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
   AND e.status='Active' AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active');
 GET DIAGNOSTICS step=ROW_COUNT;changed:=changed+step;
 UPDATE epm.python_program_build b SET status=CASE WHEN b.status='cancel_requested' THEN 'cancelled'
  WHEN b.attempts<3 THEN 'ready' ELSE 'failed' END,error_code=CASE
  WHEN b.status='cancel_requested' THEN NULL WHEN b.attempts>=3 THEN
  'PYTHON_BUILD_ATTEMPTS_EXHAUSTED' END,claim_generation=b.claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE b.status IN('running','cancel_requested') AND b.lease_until<=clock_timestamp();
 GET DIAGNOSTICS step=ROW_COUNT;RETURN changed+step;END$$;

DROP FUNCTION epm.python_build_worker_claim(text,integer,integer,integer,integer);
CREATE FUNCTION epm.python_build_worker_claim(p_claimant text,p_lease_seconds integer,
 p_global_limit integer,p_workspace_limit integer,p_application_limit integer)
RETURNS TABLE(workspace_id text,application_id text,build_id text,issuer text,
 subject_id text,request_digest text,program_id text,program_source_token text,
 parameter_values jsonb,environment_id text,environment_state_token text,status text,
 claim_generation bigint,attempts integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$DECLARE candidate record;BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
  OR p_lease_seconds NOT BETWEEN 65 AND 300 OR p_global_limit NOT BETWEEN 1 AND 10000
  OR p_workspace_limit NOT BETWEEN 1 AND p_global_limit
  OR p_application_limit NOT BETWEEN 1 AND p_workspace_limit THEN
  RAISE EXCEPTION 'PYTHON_BUILD_WORKER_CLAIM_INVALID' USING ERRCODE='22023';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.python.build.dispatch',0));
 IF(SELECT count(*) FROM epm.python_program_build WHERE status IN('running','cancel_requested'))>=p_global_limit THEN RETURN;END IF;
 SELECT b.*,d.environment_id,d.environment_state_token INTO candidate
 FROM epm.python_program_build b JOIN epm.python_program_definition d ON
  (d.workspace_id,d.application_id,d.program_id,d.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 JOIN epm.python_environment_definition e ON
  (e.workspace_id,e.application_id,e.environment_id,e.state_token)=
  (d.workspace_id,d.application_id,d.environment_id,d.environment_state_token)
 JOIN epm.application a USING(workspace_id,application_id)
 JOIN epm.application_state s USING(workspace_id,application_id)
 JOIN epm.workspace w USING(workspace_id)
 LEFT JOIN epm.worker_workspace_dispatch dispatch ON dispatch.workspace_id=b.workspace_id
 WHERE b.status IN('accepted','ready') AND b.attempts<3 AND e.status='Active'
  AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
  AND(SELECT count(*) FROM epm.python_program_build x WHERE x.workspace_id=b.workspace_id
   AND x.status IN('running','cancel_requested'))<p_workspace_limit
  AND(SELECT count(*) FROM epm.python_program_build x WHERE x.workspace_id=b.workspace_id
   AND x.application_id=b.application_id AND x.status IN('running','cancel_requested'))<p_application_limit
 ORDER BY dispatch.last_claim_sequence NULLS FIRST,b.created_at,b.build_id
 FOR UPDATE OF b SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE epm.python_program_build target SET status='running',claim_generation=target.claim_generation+1,
  claimant=p_claimant,lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  attempts=target.attempts+1,updated_at=transaction_timestamp()
 WHERE(target.workspace_id,target.application_id,target.build_id)=
  (candidate.workspace_id,candidate.application_id,candidate.build_id);
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
  last_claim_sequence=excluded.last_claim_sequence,
  claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN QUERY SELECT candidate.workspace_id,candidate.application_id,candidate.build_id,
  candidate.issuer,candidate.subject_id,candidate.request_digest,candidate.program_id,
  candidate.program_source_token,candidate.parameter_values,candidate.environment_id,
  candidate.environment_state_token,'running'::text,candidate.claim_generation+1,
  candidate.attempts+1;END$$;
REVOKE ALL ON FUNCTION epm.python_build_worker_claim(text,integer,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_build_worker_claim(text,integer,integer,integer,integer) TO epm_worker;

DO $migration$ DECLARE definition text;BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position('''python_program_publication'',' IN definition)=0
  OR position('''python_program_version''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0314_TABLES_MISMATCH';END IF;
 definition:=replace(definition,'''python_program_publication'',','');
 definition:=replace(definition,'''python_program_version''','''python_program_definition''');
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure) INTO definition;
 IF position('python_program_publication,' IN definition)=0
  OR position('python_program_version' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0314_TABLES_MISMATCH';END IF;
 definition:=replace(definition,'python_program_publication,','');
 definition:=replace(definition,'python_program_version','python_program_definition');
 EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='80fd5b2340e4e4b273bc54009fa0f41d4c3096a945736444545ed0f7dd757924';
DECLARE current_graph constant text:='ab2f48f839645f7f70989a0d4967a92e42d71cdd5762ec660f1e12644231ff0d';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0314_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
 INTO definition;IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0314_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
