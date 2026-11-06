-- Durable private staging for populated coordinate-layout replacement.
-- Nothing here changes coordinate_layout or any active projection pointer.

CREATE TABLE epm.layout_replacement_request(
 workspace_id text NOT NULL,application_id text NOT NULL,
 request_id text NOT NULL CHECK(request_id ~ '^[0-9a-f]{32}$'),
 issuer text NOT NULL,subject_id text NOT NULL,
 idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
 preview_digest text NOT NULL CHECK(preview_digest ~ '^[0-9a-f]{64}$'),
 plan_digest text NOT NULL CHECK(plan_digest ~ '^[0-9a-f]{64}$'),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object'
   AND octet_length(plan::text)<=33554432),
 metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
 data_revision bigint NOT NULL CHECK(data_revision>=0),
 policy_revision bigint NOT NULL CHECK(policy_revision>=0),
 schema_epoch bigint NOT NULL CHECK(schema_epoch>=0),
 source_commit_revision bigint NOT NULL CHECK(source_commit_revision>=0),
 target_generation_id text NOT NULL CHECK(target_generation_id ~ '^[0-9a-f]{32}$'),
 expected_coordinate_count integer NOT NULL CHECK(expected_coordinate_count BETWEEN 1 AND 100000),
 status text NOT NULL DEFAULT 'Accepted'
   CHECK(status IN ('Accepted','Staging','Staged','Failed','Cancelled')),
 claim_generation bigint NOT NULL DEFAULT 0 CHECK(claim_generation>=0),
 claimant text,lease_until timestamptz,error_code text,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,request_id),
 UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 UNIQUE(workspace_id,application_id,target_generation_id),
 FOREIGN KEY(workspace_id,application_id)
   REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CHECK((status='Staging')=(claimant IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(error_code IS NULL OR status='Failed')
);

CREATE TABLE epm.layout_replacement_generation(
 workspace_id text NOT NULL,application_id text NOT NULL,
 generation_id text NOT NULL,request_id text NOT NULL,
 state text NOT NULL DEFAULT 'Private' CHECK(state='Private'),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,generation_id),
 UNIQUE(workspace_id,application_id,request_id),
 FOREIGN KEY(workspace_id,application_id,request_id)
   REFERENCES epm.layout_replacement_request(workspace_id,application_id,request_id)
   ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,generation_id)
   REFERENCES epm.layout_replacement_request
     (workspace_id,application_id,target_generation_id) ON DELETE RESTRICT
);

CREATE TABLE epm.layout_replacement_staged_coordinate(
 workspace_id text NOT NULL,application_id text NOT NULL,
 generation_id text NOT NULL,source_coordinate_id bigint NOT NULL,
 target_members jsonb NOT NULL CHECK(jsonb_typeof(target_members)='object'
   AND octet_length(target_members::text)<=1048576),
 target_key text GENERATED ALWAYS AS (target_members::text) STORED,
 target_digest text NOT NULL CHECK(target_digest ~ '^[0-9a-f]{64}$'),
 staged_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,generation_id,source_coordinate_id),
 UNIQUE(workspace_id,application_id,generation_id,target_key),
 FOREIGN KEY(workspace_id,application_id,generation_id)
   REFERENCES epm.layout_replacement_generation
     (workspace_id,application_id,generation_id) ON DELETE RESTRICT
);

CREATE INDEX layout_replacement_dispatch ON epm.layout_replacement_request
 (status,created_at,workspace_id,application_id) WHERE status IN ('Accepted','Staging');

ALTER TABLE epm.layout_replacement_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.layout_replacement_generation ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.layout_replacement_staged_coordinate ENABLE ROW LEVEL SECURITY;
CREATE POLICY layout_replacement_request_runtime ON epm.layout_replacement_request
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true) AND status='Accepted');
CREATE POLICY layout_replacement_generation_runtime ON epm.layout_replacement_generation
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true) AND state='Private');
CREATE POLICY layout_replacement_request_lifecycle ON epm.layout_replacement_request
 TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY layout_replacement_generation_lifecycle ON epm.layout_replacement_generation
 TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY layout_replacement_coordinate_lifecycle ON epm.layout_replacement_staged_coordinate
 TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.layout_replacement_request,epm.layout_replacement_generation,
 epm.layout_replacement_staged_coordinate FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.layout_replacement_request,epm.layout_replacement_generation TO epm_runtime;
GRANT SELECT(workspace_id,application_id,request_id,status)
 ON epm.layout_replacement_request TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,generation_id,request_id)
 ON epm.layout_replacement_generation TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,generation_id,source_coordinate_id)
 ON epm.layout_replacement_staged_coordinate TO epm_lifecycle;

CREATE FUNCTION epm.layout_replacement_worker_claim(
 p_workspace text,p_application text,p_request text,p_claimant text,p_lease_seconds integer)
RETURNS TABLE(request_id text,generation_id text,plan jsonb,claim_generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200
 OR p_lease_seconds NOT BETWEEN 30 AND 300 THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_CLAIM_INVALID' USING ERRCODE='22023';
 END IF;
 RETURN QUERY UPDATE epm.layout_replacement_request r SET status='Staging',
  claim_generation=r.claim_generation+1,claimant=p_claimant,
  lease_until=clock_timestamp()+make_interval(secs=>p_lease_seconds),
  updated_at=transaction_timestamp()
 WHERE r.workspace_id=p_workspace AND r.application_id=p_application
  AND r.request_id=p_request AND r.status='Accepted'
 RETURNING r.request_id,r.target_generation_id,r.plan,r.claim_generation;
END $$;

CREATE FUNCTION epm.layout_replacement_worker_stage(
 p_workspace text,p_application text,p_request text,p_claimant text,
 p_generation bigint,p_source bigint,p_members jsonb,p_digest text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 IF p_source<1 OR p_digest !~ '^[0-9a-f]{64}$' OR jsonb_typeof(p_members)<>'object'
 OR octet_length(p_members::text)>1048576 THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGE_INVALID' USING ERRCODE='22023'; END IF;
 INSERT INTO epm.layout_replacement_staged_coordinate
  (workspace_id,application_id,generation_id,source_coordinate_id,target_members,target_digest)
 SELECT r.workspace_id,r.application_id,r.target_generation_id,p_source,p_members,p_digest
 FROM epm.layout_replacement_request r WHERE r.workspace_id=p_workspace
  AND r.application_id=p_application AND r.request_id=p_request
  AND r.status='Staging' AND r.claimant=p_claimant
  AND r.claim_generation=p_generation AND r.lease_until>clock_timestamp()
  AND EXISTS (SELECT 1 FROM jsonb_array_elements(r.plan->'coordinateMappings') m
    WHERE (m->>'sourceCoordinateId')::bigint=p_source
      AND m->'targetMembers'=p_members)
 ON CONFLICT(workspace_id,application_id,generation_id,source_coordinate_id)
 DO UPDATE SET target_members=EXCLUDED.target_members
 WHERE epm.layout_replacement_staged_coordinate.target_digest=EXCLUDED.target_digest;
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;

CREATE FUNCTION epm.layout_replacement_worker_settle(
 p_workspace text,p_application text,p_request text,p_claimant text,
 p_generation bigint,p_outcome text,p_error text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 IF p_outcome NOT IN ('Staged','Failed') OR (p_outcome='Failed')<>(p_error IS NOT NULL)
 OR (p_error IS NOT NULL AND (length(p_error) NOT BETWEEN 1 AND 200 OR p_error !~ '^[A-Z0-9_]+$')) THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_SETTLEMENT_INVALID' USING ERRCODE='22023'; END IF;
 UPDATE epm.layout_replacement_request r SET status=p_outcome,error_code=p_error,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE r.workspace_id=p_workspace AND r.application_id=p_application
  AND r.request_id=p_request AND r.status='Staging' AND r.claimant=p_claimant
  AND r.claim_generation=p_generation AND r.lease_until>clock_timestamp()
  AND (p_outcome='Failed' OR r.expected_coordinate_count=(SELECT count(*)
    FROM epm.layout_replacement_staged_coordinate c WHERE c.workspace_id=r.workspace_id
    AND c.application_id=r.application_id AND c.generation_id=r.target_generation_id));
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;

CREATE FUNCTION epm.layout_replacement_cancel(
 p_workspace text,p_application text,p_request text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 IF p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
 OR p_application IS DISTINCT FROM current_setting('epm.application_id',true) THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_SCOPE_INVALID' USING ERRCODE='22023'; END IF;
 UPDATE epm.layout_replacement_request SET status='Cancelled',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace AND application_id=p_application
  AND request_id=p_request AND status IN ('Accepted','Staging');
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;

CREATE FUNCTION epm.layout_replacement_worker_recover()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 UPDATE epm.layout_replacement_request SET status='Accepted',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  updated_at=transaction_timestamp()
 WHERE status='Staging' AND lease_until<=clock_timestamp();
 GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed;
END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_worker_claim(text,text,text,text,integer),
 epm.layout_replacement_worker_stage(text,text,text,text,bigint,bigint,jsonb,text),
 epm.layout_replacement_worker_settle(text,text,text,text,bigint,text,text),
 epm.layout_replacement_cancel(text,text,text),
 epm.layout_replacement_worker_recover() FROM PUBLIC,epm_runtime,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_worker_claim(text,text,text,text,integer),
 epm.layout_replacement_worker_stage(text,text,text,text,bigint,bigint,jsonb,text),
 epm.layout_replacement_worker_settle(text,text,text,text,bigint,text,text),
 epm.layout_replacement_worker_recover() TO epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_cancel(text,text,text) TO epm_runtime;

-- Register unsettled work and FK-safe deletion with the exact owner reset.
DO $$
DECLARE v_old text := '6565519d66059bc8041b4704b72f79fe1baf7e8248d987c99d8ebb03f72a82a4';
 v_new text := '36db585a34d01530ca050ce823779befdb8c0fa237d1d1e6aac804f25f1ac45e';v_definition text;v_replaced text;
 v_before text := '''planning_workflow_policy_state'',''planning_workflow_policy_version'',''operation_receipt''';
 v_after text := '''layout_replacement_staged_coordinate'',''layout_replacement_generation'',''layout_replacement_request'',''planning_workflow_policy_state'',''planning_workflow_policy_version'',''operation_receipt''';
 v_gate text := '    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 v_gate_replacement text := '    IF EXISTS (SELECT 1 FROM epm.layout_replacement_request WHERE workspace_id=p_workspace_id AND status IN (''Accepted'',''Staging'',''Staged'')) THEN RAISE EXCEPTION ''UNSETTLED_LAYOUT_REPLACEMENT''; END IF;' || chr(10) || chr(10) || v_gate;
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO v_definition;
 IF position(v_old in v_definition)=0 OR position(v_before in v_definition)=0 OR position(v_gate in v_definition)=0
 THEN RAISE EXCEPTION 'RESET_0107_DEFINITION_MISMATCH'; END IF;
 v_replaced:=replace(replace(replace(v_definition,v_old,v_new),v_before,v_after),v_gate,v_gate_replacement);
 EXECUTE v_replaced;
END $$;
