-- Separately materialized private facts and immutable validation certificates.
-- These relations never participate in active fact views or layout pointers.

ALTER TABLE epm.layout_replacement_request
 DROP CONSTRAINT layout_replacement_request_status_check;
ALTER TABLE epm.layout_replacement_request ADD CONSTRAINT
 layout_replacement_request_status_check CHECK(status IN
 ('Accepted','Staging','Staged','Validated','ValidationFailed','Failed','Cancelled'));

CREATE TABLE epm.layout_replacement_materialization(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL,
 generation_id text NOT NULL,status text NOT NULL DEFAULT 'Ready'
  CHECK(status IN('Ready','Running','Complete','Failed')),
 claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),
 claimant text,lease_until timestamptz,next_chunk integer NOT NULL DEFAULT 0 CHECK(next_chunk>=0),
 target_count integer NOT NULL DEFAULT 0 CHECK(target_count BETWEEN 0 AND 100000),
 content_digest text,error_code text,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,request_id),
 UNIQUE(workspace_id,application_id,generation_id),
 FOREIGN KEY(workspace_id,application_id,request_id)
  REFERENCES epm.layout_replacement_request(workspace_id,application_id,request_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,generation_id)
  REFERENCES epm.layout_replacement_generation(workspace_id,application_id,generation_id) ON DELETE RESTRICT,
 CHECK((status='Running')=(claimant IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(content_digest IS NULL OR content_digest ~ '^[0-9a-f]{64}$'),
 CHECK(error_code IS NULL OR status='Failed')
);

CREATE TABLE epm.layout_replacement_private_coordinate(
 workspace_id text NOT NULL,application_id text NOT NULL,generation_id text NOT NULL,
 target_digest text NOT NULL CHECK(target_digest ~ '^[0-9a-f]{64}$'),
 target_members jsonb NOT NULL CHECK(jsonb_typeof(target_members)='object'),
 target_key text GENERATED ALWAYS AS(target_members::text) STORED,
 source_coordinate_ids bigint[] NOT NULL CHECK(cardinality(source_coordinate_ids)>0),
 PRIMARY KEY(workspace_id,application_id,generation_id,target_digest),
 UNIQUE(workspace_id,application_id,generation_id,target_key),
 FOREIGN KEY(workspace_id,application_id,generation_id)
  REFERENCES epm.layout_replacement_generation(workspace_id,application_id,generation_id) ON DELETE RESTRICT
);
CREATE TABLE epm.layout_replacement_private_numeric(
 workspace_id text NOT NULL,application_id text NOT NULL,generation_id text NOT NULL,
 target_digest text NOT NULL,present boolean NOT NULL,amount numeric(28,8),
 PRIMARY KEY(workspace_id,application_id,generation_id,target_digest),
 FOREIGN KEY(workspace_id,application_id,generation_id,target_digest)
  REFERENCES epm.layout_replacement_private_coordinate
   (workspace_id,application_id,generation_id,target_digest) ON DELETE RESTRICT,
 CHECK(present=(amount IS NOT NULL))
);
CREATE TABLE epm.layout_replacement_private_text(
 workspace_id text NOT NULL,application_id text NOT NULL,generation_id text NOT NULL,
 target_digest text NOT NULL,present boolean NOT NULL,text_value text,
 PRIMARY KEY(workspace_id,application_id,generation_id,target_digest),
 FOREIGN KEY(workspace_id,application_id,generation_id,target_digest)
  REFERENCES epm.layout_replacement_private_coordinate
   (workspace_id,application_id,generation_id,target_digest) ON DELETE RESTRICT,
 CHECK(present=(text_value IS NOT NULL)),CHECK(text_value IS NULL OR length(text_value)<=32768)
);
CREATE TABLE epm.layout_replacement_private_detail(
 workspace_id text NOT NULL,application_id text NOT NULL,generation_id text NOT NULL,
 target_digest text NOT NULL,present boolean NOT NULL,items jsonb,total numeric(28,8),
 PRIMARY KEY(workspace_id,application_id,generation_id,target_digest),
 FOREIGN KEY(workspace_id,application_id,generation_id,target_digest)
  REFERENCES epm.layout_replacement_private_coordinate
   (workspace_id,application_id,generation_id,target_digest) ON DELETE RESTRICT,
 CHECK(present=(items IS NOT NULL) AND present=(total IS NOT NULL)),
 CHECK(items IS NULL OR (jsonb_typeof(items)='array' AND jsonb_array_length(items)<=500))
);
CREATE TABLE epm.layout_replacement_materialization_chunk(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL,
 chunk_index integer NOT NULL CHECK(chunk_index>=0),content_digest text NOT NULL
  CHECK(content_digest ~ '^[0-9a-f]{64}$'),target_count integer NOT NULL CHECK(target_count BETWEEN 1 AND 500),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,request_id,chunk_index),
 FOREIGN KEY(workspace_id,application_id,request_id)
  REFERENCES epm.layout_replacement_materialization(workspace_id,application_id,request_id) ON DELETE RESTRICT
);
CREATE TABLE epm.layout_replacement_validation_certificate(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL,
 generation_id text NOT NULL,plan_digest text NOT NULL CHECK(plan_digest ~ '^[0-9a-f]{64}$'),
 metadata_revision bigint NOT NULL,data_revision bigint NOT NULL,policy_revision bigint NOT NULL,
 schema_epoch bigint NOT NULL,source_commit_revision bigint NOT NULL,
 content_digest text NOT NULL CHECK(content_digest ~ '^[0-9a-f]{64}$'),
 target_count integer NOT NULL CHECK(target_count BETWEEN 0 AND 100000),
 validation_digest text NOT NULL CHECK(validation_digest ~ '^[0-9a-f]{64}$'),
 activation_eligible boolean NOT NULL,certificate jsonb NOT NULL CHECK(jsonb_typeof(certificate)='object'
  AND octet_length(certificate::text)<=1048576),created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,request_id),
 FOREIGN KEY(workspace_id,application_id,request_id)
  REFERENCES epm.layout_replacement_request(workspace_id,application_id,request_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,generation_id)
  REFERENCES epm.layout_replacement_generation(workspace_id,application_id,generation_id) ON DELETE RESTRICT
);

CREATE FUNCTION epm.layout_replacement_certificate_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 RAISE EXCEPTION 'LAYOUT_REPLACEMENT_CERTIFICATE_IMMUTABLE' USING ERRCODE='23514'; END $$;
CREATE TRIGGER layout_replacement_certificate_immutable BEFORE UPDATE ON
 epm.layout_replacement_validation_certificate FOR EACH ROW
 EXECUTE FUNCTION epm.layout_replacement_certificate_immutable();
REVOKE ALL ON FUNCTION epm.layout_replacement_certificate_immutable() FROM PUBLIC,
 epm_runtime,epm_worker,epm_lifecycle;

CREATE FUNCTION epm.layout_replacement_materialization_claim(
 p_workspace text,p_application text,p_request text,p_claimant text,p_seconds integer)
RETURNS TABLE(request_id text,generation_id text,claim_generation bigint,next_chunk integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF length(p_claimant) NOT BETWEEN 1 AND 200 OR p_seconds NOT BETWEEN 30 AND 300 THEN
  RAISE EXCEPTION 'LAYOUT_MATERIALIZATION_CLAIM_INVALID' USING ERRCODE='22023'; END IF;
 INSERT INTO epm.layout_replacement_materialization(workspace_id,application_id,request_id,generation_id)
 SELECT r.workspace_id,r.application_id,r.request_id,r.target_generation_id
 FROM epm.layout_replacement_request r WHERE r.workspace_id=p_workspace
 AND r.application_id=p_application AND r.request_id=p_request AND r.status='Staged'
 ON CONFLICT DO NOTHING;
 RETURN QUERY UPDATE epm.layout_replacement_materialization m SET status='Running',
  claim_generation=m.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_seconds),updated_at=transaction_timestamp()
 FROM epm.layout_replacement_request r WHERE m.workspace_id=p_workspace
  AND m.application_id=p_application AND m.request_id=p_request AND m.status='Ready'
  AND r.workspace_id=m.workspace_id AND r.application_id=m.application_id
  AND r.request_id=m.request_id AND r.status='Staged'
 RETURNING m.request_id,m.generation_id,m.claim_generation,m.next_chunk;
END $$;

CREATE FUNCTION epm.layout_replacement_materialization_chunk(
 p_workspace text,p_application text,p_request text,p_claimant text,p_generation bigint,
 p_chunk integer,p_digest text,p_rows jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior text;row_count integer;g text;
BEGIN
 IF p_chunk<0 OR p_digest !~ '^[0-9a-f]{64}$' OR jsonb_typeof(p_rows)<>'array'
 OR jsonb_array_length(p_rows) NOT BETWEEN 1 AND 500 THEN
  RAISE EXCEPTION 'LAYOUT_MATERIALIZATION_CHUNK_INVALID' USING ERRCODE='22023'; END IF;
 SELECT generation_id INTO g FROM epm.layout_replacement_materialization WHERE
  workspace_id=p_workspace AND application_id=p_application AND request_id=p_request
  AND status='Running' AND claimant=p_claimant AND claim_generation=p_generation
  AND lease_until>clock_timestamp();
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT content_digest INTO prior FROM epm.layout_replacement_materialization_chunk
  WHERE workspace_id=p_workspace AND application_id=p_application
  AND request_id=p_request AND chunk_index=p_chunk;
 IF FOUND THEN
  IF prior<>p_digest THEN RAISE EXCEPTION 'LAYOUT_MATERIALIZATION_CHUNK_CONFLICT'; END IF;
  RETURN true;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM epm.layout_replacement_materialization WHERE
  workspace_id=p_workspace AND application_id=p_application AND request_id=p_request
  AND next_chunk=p_chunk) THEN RETURN false; END IF;
 INSERT INTO epm.layout_replacement_private_coordinate
  (workspace_id,application_id,generation_id,target_digest,target_members,source_coordinate_ids)
 SELECT p_workspace,p_application,g,x->>'targetDigest',x->'targetMembers',
  ARRAY(SELECT jsonb_array_elements_text(x->'sourceCoordinateIds')::bigint ORDER BY 1)
 FROM jsonb_array_elements(p_rows) x;
 INSERT INTO epm.layout_replacement_private_numeric
 SELECT p_workspace,p_application,g,x->>'targetDigest',(x->'numeric'->>'present')::boolean,
  CASE WHEN (x->'numeric'->>'present')::boolean THEN (x->'numeric'->>'amount')::numeric ELSE NULL END
 FROM jsonb_array_elements(p_rows) x;
 INSERT INTO epm.layout_replacement_private_text
 SELECT p_workspace,p_application,g,x->>'targetDigest',(x->'text'->>'present')::boolean,
  CASE WHEN (x->'text'->>'present')::boolean THEN x->'text'->>'value' ELSE NULL END
 FROM jsonb_array_elements(p_rows) x;
 INSERT INTO epm.layout_replacement_private_detail
 SELECT p_workspace,p_application,g,x->>'targetDigest',(x->'detail'->>'present')::boolean,
  CASE WHEN (x->'detail'->>'present')::boolean THEN x->'detail'->'items' ELSE NULL END,
  CASE WHEN (x->'detail'->>'present')::boolean THEN (x->'detail'->>'total')::numeric ELSE NULL END
 FROM jsonb_array_elements(p_rows) x;
 row_count:=jsonb_array_length(p_rows);
 INSERT INTO epm.layout_replacement_materialization_chunk VALUES
  (p_workspace,p_application,p_request,p_chunk,p_digest,row_count,transaction_timestamp());
 UPDATE epm.layout_replacement_materialization SET next_chunk=next_chunk+1,
  target_count=target_count+row_count,lease_until=clock_timestamp()+interval '120 seconds',
  updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application AND request_id=p_request;
 RETURN true;
END $$;

CREATE FUNCTION epm.layout_replacement_materialization_settle(
 p_workspace text,p_application text,p_request text,p_claimant text,p_generation bigint,
 p_digest text,p_expected integer,p_error text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 UPDATE epm.layout_replacement_materialization SET
  status=CASE WHEN p_error IS NULL THEN 'Complete' ELSE 'Failed' END,
  content_digest=CASE WHEN p_error IS NULL THEN p_digest ELSE NULL END,error_code=p_error,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application AND request_id=p_request
  AND status='Running' AND claimant=p_claimant AND claim_generation=p_generation
  AND lease_until>clock_timestamp() AND target_count=p_expected
  AND ((p_error IS NULL AND p_digest ~ '^[0-9a-f]{64}$') OR
       (p_error ~ '^[A-Z0-9_]{1,200}$'));
 GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed=1;
END $$;
CREATE FUNCTION epm.layout_replacement_materialization_recover() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE changed integer;BEGIN
 UPDATE epm.layout_replacement_materialization SET status='Ready',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE status='Running' AND lease_until<=clock_timestamp();
 GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed;END $$;

CREATE FUNCTION epm.layout_replacement_validation_publish(
 p_workspace text,p_application text,p_request text,p_content text,p_count integer,p_certificate jsonb)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.layout_replacement_request%ROWTYPE;m epm.layout_replacement_materialization%ROWTYPE;
 eligible boolean;digest text;target_status text;
BEGIN
 IF p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
 OR p_application IS DISTINCT FROM current_setting('epm.application_id',true)
 OR jsonb_typeof(p_certificate)<>'object' OR octet_length(p_certificate::text)>1048576 THEN
  RAISE EXCEPTION 'LAYOUT_VALIDATION_PUBLISH_INVALID' USING ERRCODE='22023';END IF;
 SELECT * INTO r FROM epm.layout_replacement_request WHERE workspace_id=p_workspace
  AND application_id=p_application AND request_id=p_request FOR UPDATE;
 SELECT * INTO m FROM epm.layout_replacement_materialization WHERE workspace_id=p_workspace
  AND application_id=p_application AND request_id=p_request;
 eligible:=(p_certificate->>'activationEligible')::boolean;
 digest:=p_certificate->>'validationDigest';target_status:=CASE WHEN eligible THEN 'Validated' ELSE 'ValidationFailed' END;
 IF r.status<> 'Staged' OR m.status<>'Complete' OR m.content_digest<>p_content
 OR m.target_count<>p_count OR p_content !~ '^[0-9a-f]{64}$' OR digest !~ '^[0-9a-f]{64}$'
 OR p_certificate->>'requestId'<>p_request OR p_certificate->>'planDigest'<>r.plan_digest
 OR p_certificate->>'privateGenerationId'<>r.target_generation_id
 OR (p_certificate->'pins'->>'metadataRevision')::bigint<>r.metadata_revision
 OR (p_certificate->'pins'->>'dataRevision')::bigint<>r.data_revision
 OR (p_certificate->'pins'->>'policyRevision')::bigint<>r.policy_revision
 OR (p_certificate->'pins'->>'schemaEpoch')::bigint<>r.schema_epoch
 OR (p_certificate->'pins'->>'sourceCommitRevision')::bigint<>r.source_commit_revision
 OR (p_certificate->>'stagedTargetCount')::integer<>p_count
 OR NOT EXISTS (SELECT 1 FROM epm.application_state s WHERE s.workspace_id=p_workspace
   AND s.application_id=p_application AND NOT s.commit_open
   AND s.metadata_revision=r.metadata_revision AND s.data_revision=r.data_revision
   AND s.policy_revision=r.policy_revision AND s.schema_epoch=r.schema_epoch
   AND s.commit_revision=r.source_commit_revision) THEN
  RAISE EXCEPTION 'LAYOUT_VALIDATION_PUBLISH_STALE';END IF;
 INSERT INTO epm.layout_replacement_validation_certificate
  (workspace_id,application_id,request_id,generation_id,plan_digest,
   metadata_revision,data_revision,policy_revision,schema_epoch,source_commit_revision,
   content_digest,target_count,validation_digest,activation_eligible,certificate)
 VALUES(p_workspace,p_application,p_request,r.target_generation_id,r.plan_digest,
   r.metadata_revision,r.data_revision,r.policy_revision,r.schema_epoch,r.source_commit_revision,
   p_content,p_count,digest,eligible,p_certificate);
 UPDATE epm.layout_replacement_request SET status=target_status,updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application AND request_id=p_request;
 RETURN target_status;
END $$;

DO $$ DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY[
 'layout_replacement_materialization','layout_replacement_private_coordinate',
 'layout_replacement_private_numeric','layout_replacement_private_text',
 'layout_replacement_private_detail','layout_replacement_materialization_chunk',
 'layout_replacement_validation_certificate'] LOOP
 EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',t||'_runtime',t);
 END LOOP;END $$;
REVOKE ALL ON epm.layout_replacement_materialization,epm.layout_replacement_private_coordinate,
 epm.layout_replacement_private_numeric,epm.layout_replacement_private_text,
 epm.layout_replacement_private_detail,epm.layout_replacement_materialization_chunk,
 epm.layout_replacement_validation_certificate FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT ON epm.layout_replacement_materialization,epm.layout_replacement_private_coordinate,
 epm.layout_replacement_private_numeric,epm.layout_replacement_private_text,
 epm.layout_replacement_private_detail,epm.layout_replacement_materialization_chunk,
 epm.layout_replacement_validation_certificate TO epm_runtime;
REVOKE ALL ON FUNCTION epm.layout_replacement_materialization_claim(text,text,text,text,integer),
 epm.layout_replacement_materialization_chunk(text,text,text,text,bigint,integer,text,jsonb),
 epm.layout_replacement_materialization_settle(text,text,text,text,bigint,text,integer,text),
 epm.layout_replacement_materialization_recover() FROM PUBLIC,epm_runtime,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_materialization_claim(text,text,text,text,integer),
 epm.layout_replacement_materialization_chunk(text,text,text,text,bigint,integer,text,jsonb),
 epm.layout_replacement_materialization_settle(text,text,text,text,bigint,text,integer,text),
 epm.layout_replacement_materialization_recover() TO epm_worker;
REVOKE ALL ON FUNCTION epm.layout_replacement_validation_publish(text,text,text,text,integer,jsonb)
 FROM PUBLIC,epm_runtime,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_validation_publish(text,text,text,text,integer,jsonb)
 TO epm_runtime;

DO $$ DECLARE v_old text:='4d5241f88afa0ed777a55862d48d831992d2d1d1cb0119d69681e4684e8c080d';
 v_new text:='fddc1a68c34b5af78f8b804b2d4a84555d79e8f20a029aae6fa5a1443009801e';d text;r text;
 b text:='''source_import_diagnostic_artifact'',''fact_export_artifact'',''layout_replacement_staged_coordinate''';
 a text:='''source_import_diagnostic_artifact'',''fact_export_artifact'',''layout_replacement_validation_certificate'',''layout_replacement_materialization_chunk'',''layout_replacement_private_detail'',''layout_replacement_private_text'',''layout_replacement_private_numeric'',''layout_replacement_private_coordinate'',''layout_replacement_materialization'',''layout_replacement_staged_coordinate''';
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(v_old in d)=0 OR position(b in d)=0 THEN RAISE EXCEPTION 'RESET_0109_DEFINITION_MISMATCH';END IF;
 r:=replace(replace(d,v_old,v_new),b,a);EXECUTE r;END $$;
