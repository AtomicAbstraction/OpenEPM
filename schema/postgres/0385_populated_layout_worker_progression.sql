-- Complete the existing private layout lifecycle in the maintained worker.
-- No old row receives invented intent, token time, authority or certificate.
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=384) THEN
  RAISE EXCEPTION 'MIGRATION_0385_PREDECESSOR_0384_REQUIRED';
 END IF;
END $migration$;

ALTER TABLE epm.layout_replacement_request
 ADD COLUMN token_issued_at bigint,
 ADD COLUMN authority_kind text NOT NULL DEFAULT 'LegacyUnverified',
 ADD COLUMN dependency_decisions jsonb,
 ADD COLUMN worker_phase text;
ALTER TABLE epm.layout_replacement_request ADD CONSTRAINT layout_replacement_durable_authority
 CHECK ((authority_kind='LegacyUnverified' AND token_issued_at IS NULL)
 OR (authority_kind='HumanToken' AND token_issued_at IS NOT NULL AND token_issued_at>0)
 OR (authority_kind='Technical' AND token_issued_at IS NULL AND issuer LIKE 'urn:openepm:%')),
 ADD CONSTRAINT layout_replacement_admitted_intent CHECK(dependency_decisions IS NULL OR
 (jsonb_typeof(dependency_decisions)='array' AND jsonb_array_length(dependency_decisions)<=10000
 AND octet_length(dependency_decisions::text)<=1048576)),
 ADD CONSTRAINT layout_replacement_worker_phase CHECK(worker_phase IS NULL OR worker_phase IN('Stage','Validate'));
-- This classifies an already recorded lease; it does not certify its identity.
UPDATE epm.layout_replacement_request SET worker_phase='Stage' WHERE status='Staging';
DO $migration$ DECLARE n text; BEGIN
 SELECT conname INTO STRICT n FROM pg_constraint
 WHERE conrelid='epm.layout_replacement_request'::regclass AND contype='c'
 AND pg_get_constraintdef(oid) LIKE '%Staging%'
 AND pg_get_constraintdef(oid) LIKE '%claimant%'
 AND pg_get_constraintdef(oid) LIKE '%lease_until%';
 EXECUTE format('ALTER TABLE epm.layout_replacement_request DROP CONSTRAINT %I',n);
END $migration$;
ALTER TABLE epm.layout_replacement_request ADD CONSTRAINT layout_replacement_phase_lease CHECK(
 (claimant IS NULL AND lease_until IS NULL AND worker_phase IS NULL AND status<>'Staging')
 OR (claimant IS NOT NULL AND lease_until IS NOT NULL AND
 ((status='Staging' AND worker_phase='Stage') OR (status='Staged' AND worker_phase='Validate'))));
CREATE INDEX layout_replacement_private_work_dispatch ON epm.layout_replacement_request
 (status,updated_at,workspace_id,application_id,request_id)
 WHERE status IN('Accepted','Staged') AND authority_kind<>'LegacyUnverified'
 AND dependency_decisions IS NOT NULL;
CREATE INDEX layout_replacement_phase_expiry ON epm.layout_replacement_request(lease_until)
 WHERE claimant IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.layout_replacement_current_admin(p_workspace text,p_application text,p_request text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE w ALIAS FOR $1; a ALIAS FOR $2; rid ALIAS FOR $3;
 r epm.layout_replacement_request%ROWTYPE; groups_now text[];
BEGIN
 SELECT * INTO r FROM epm.layout_replacement_request
 WHERE workspace_id=w AND application_id=a AND request_id=rid;
 IF NOT FOUND OR r.authorization_scope_digest IS NULL OR r.dependency_decisions IS NULL
 OR r.authority_kind='LegacyUnverified' OR NOT epm.identity_subject_active(r.issuer,r.subject_id)
 OR (r.authority_kind='HumanToken' AND NOT epm.identity_subject_session_valid(r.issuer,r.subject_id,r.token_issued_at))
 OR (r.authority_kind='Technical' AND (r.token_issued_at IS NOT NULL OR r.issuer NOT LIKE 'urn:openepm:%'))
 THEN RETURN false;END IF;
 groups_now:=epm.current_identity_groups(r.issuer,r.subject_id,r.verified_groups);
 RETURN EXISTS(SELECT 1 FROM epm.workspace_access_grant g WHERE g.workspace_id=w
  AND g.issuer=r.issuer AND g.subject_id=r.subject_id AND g.role='Administrator')
 OR EXISTS(SELECT 1 FROM epm.application_access_grant g WHERE g.workspace_id=w AND g.application_id=a
  AND g.issuer=r.issuer AND g.subject_id=r.subject_id AND g.role='Administrator')
 OR EXISTS(SELECT 1 FROM epm.workspace_group_access_grant g WHERE g.workspace_id=w
  AND g.issuer=r.issuer AND g.group_id=ANY(groups_now) AND g.role='Administrator')
 OR EXISTS(SELECT 1 FROM epm.application_group_access_grant g WHERE g.workspace_id=w AND g.application_id=a
  AND g.issuer=r.issuer AND g.group_id=ANY(groups_now) AND g.role='Administrator');
END $$;

-- Preserve the original staging claim/settlement interface and exact fences.
DO $migration$ DECLARE definition text; BEGIN
 SELECT pg_get_functiondef('epm.layout_replacement_authority_claim(text,text,text,text,integer)'::regprocedure) INTO definition;
 IF position('SET status=''Staging'',' IN definition)=0 THEN RAISE EXCEPTION 'LAYOUT_WORKER_CLAIM_SOURCE_MISMATCH';END IF;
 definition:=replace(definition,'SET status=''Staging'',','SET status=''Staging'',worker_phase=''Stage'',');
 EXECUTE definition;
 SELECT pg_get_functiondef('epm.layout_replacement_worker_settle(text,text,text,text,bigint,text,text)'::regprocedure) INTO definition;
 IF position('claimant=NULL,lease_until=NULL' IN definition)=0 THEN RAISE EXCEPTION 'LAYOUT_WORKER_SETTLE_SOURCE_MISMATCH';END IF;
 EXECUTE replace(definition,'claimant=NULL,lease_until=NULL','claimant=NULL,lease_until=NULL,worker_phase=NULL');
 SELECT pg_get_functiondef('epm.layout_replacement_worker_recover()'::regprocedure) INTO definition;
 IF position('claimant=NULL,lease_until=NULL' IN definition)=0 THEN RAISE EXCEPTION 'LAYOUT_WORKER_RECOVER_SOURCE_MISMATCH';END IF;
 EXECUTE replace(definition,'claimant=NULL,lease_until=NULL','claimant=NULL,lease_until=NULL,worker_phase=NULL');
 SELECT pg_get_functiondef('epm.layout_replacement_cancel(text,text,text)'::regprocedure) INTO definition;
 IF position('claimant=NULL,lease_until=NULL' IN definition)=0 THEN RAISE EXCEPTION 'LAYOUT_WORKER_CANCEL_SOURCE_MISMATCH';END IF;
 EXECUTE replace(definition,'claimant=NULL,lease_until=NULL','claimant=NULL,lease_until=NULL,worker_phase=NULL');
END $migration$;

-- A bounded lease census, used while the existing global dispatch gate is held.
-- Materialization and validation count separately only while actually claimed;
-- their prerequisites make overlapping phases for one request impossible.
CREATE FUNCTION epm.layout_worker_capacity(w text,a text,g integer,wl integer,al integer)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT (SELECT count(*) FROM (
  SELECT 1 FROM epm.layout_replacement_request WHERE lease_until>clock_timestamp()
  UNION ALL SELECT 1 FROM epm.layout_replacement_materialization WHERE status='Running' AND lease_until>clock_timestamp()
  UNION ALL SELECT 1 FROM epm.layout_replacement_activation WHERE status='Activating' AND lease_until>clock_timestamp()
  LIMIT g) x)<g
 AND (SELECT count(*) FROM (
  SELECT 1 FROM epm.layout_replacement_request WHERE workspace_id=w AND lease_until>clock_timestamp()
  UNION ALL SELECT 1 FROM epm.layout_replacement_materialization WHERE workspace_id=w AND status='Running' AND lease_until>clock_timestamp()
  UNION ALL SELECT 1 FROM epm.layout_replacement_activation WHERE workspace_id=w AND status='Activating' AND lease_until>clock_timestamp()
  LIMIT wl) x)<wl
 AND (SELECT count(*) FROM (
  SELECT 1 FROM epm.layout_replacement_request WHERE workspace_id=w AND application_id=a AND lease_until>clock_timestamp()
  UNION ALL SELECT 1 FROM epm.layout_replacement_materialization WHERE workspace_id=w AND application_id=a AND status='Running' AND lease_until>clock_timestamp()
  UNION ALL SELECT 1 FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a AND status='Activating' AND lease_until>clock_timestamp()
  LIMIT al) x)<al
$$;

CREATE FUNCTION epm.layout_worker_claim(p_phase text,p_claimant text,p_seconds integer,
 p_global integer,p_workspace integer,p_application integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE candidate record; claimed record; authority record; generation bigint;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR p_phase IS NULL OR p_phase NOT IN('Stage','Materialize','Validate','Activate')
 OR p_claimant IS NULL OR length(p_claimant) NOT BETWEEN 1 AND 200 OR p_seconds IS NULL OR p_seconds NOT BETWEEN 30 AND 300
 OR p_global IS NULL OR p_global NOT BETWEEN 1 AND 10000 OR p_workspace IS NULL OR p_workspace NOT BETWEEN 1 AND p_global
 OR p_application IS NULL OR p_application NOT BETWEEN 1 AND p_workspace THEN RAISE EXCEPTION 'LAYOUT_WORKER_CLAIM_INVALID';END IF;
 SELECT 0 AS next_chunk INTO claimed;
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.layout.worker.dispatch',0));
 IF p_phase='Activate' THEN
  SELECT x.* INTO candidate FROM epm.layout_replacement_activation x
  JOIN epm.application a USING(workspace_id,application_id) JOIN epm.workspace w USING(workspace_id)
  JOIN epm.application_state s USING(workspace_id,application_id)
  LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
  WHERE x.status='Requested' AND x.authority_kind<>'LegacyUnverified'
   AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
   AND epm.layout_replacement_activation_current_admin(x.workspace_id,x.application_id,x.activation_id)
   AND epm.layout_worker_capacity(x.workspace_id,x.application_id,p_global,p_workspace,p_application)
  ORDER BY d.last_claim_sequence NULLS FIRST,x.updated_at,x.workspace_id,x.application_id,x.activation_id
  FOR UPDATE OF x SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN NULL;END IF;
  SELECT * INTO claimed FROM epm.layout_replacement_activation_authority_claim(
   candidate.workspace_id,candidate.application_id,candidate.activation_id,p_claimant,p_seconds);
  IF NOT FOUND THEN RETURN NULL;END IF;
  generation:=claimed.claim_generation;
 ELSE
  SELECT r.* INTO candidate FROM epm.layout_replacement_request r
  JOIN epm.application a USING(workspace_id,application_id) JOIN epm.workspace w USING(workspace_id)
  JOIN epm.application_state s USING(workspace_id,application_id)
  LEFT JOIN epm.layout_replacement_materialization m USING(workspace_id,application_id,request_id)
  LEFT JOIN epm.worker_workspace_dispatch d USING(workspace_id)
  WHERE r.authority_kind<>'LegacyUnverified' AND r.dependency_decisions IS NOT NULL
   AND a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
   AND r.claimant IS NULL
   AND ((p_phase='Stage' AND r.status='Accepted')
    OR (p_phase='Materialize' AND r.status='Staged' AND (m.request_id IS NULL OR m.status='Ready'))
    OR (p_phase='Validate' AND r.status='Staged' AND m.status='Complete'))
   AND epm.layout_replacement_current_admin(r.workspace_id,r.application_id,r.request_id)
   AND epm.layout_worker_capacity(r.workspace_id,r.application_id,p_global,p_workspace,p_application)
  ORDER BY d.last_claim_sequence NULLS FIRST,r.updated_at,r.workspace_id,r.application_id,r.request_id
  FOR UPDATE OF r SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN NULL;END IF;
  IF p_phase='Stage' THEN
   SELECT * INTO claimed FROM epm.layout_replacement_authority_claim(candidate.workspace_id,candidate.application_id,
    candidate.request_id,p_claimant,p_seconds);
   IF NOT FOUND THEN RETURN NULL;END IF;generation:=claimed.claim_generation;
  ELSIF p_phase='Materialize' THEN
   SELECT * INTO claimed FROM epm.layout_replacement_materialization_authority_claim(candidate.workspace_id,candidate.application_id,
    candidate.request_id,p_claimant,p_seconds);
   IF NOT FOUND THEN RETURN NULL;END IF;generation:=claimed.claim_generation;
  ELSE
   UPDATE epm.layout_replacement_request r SET claimant=p_claimant,worker_phase='Validate',
    claim_generation=r.claim_generation+1,lease_until=clock_timestamp()+make_interval(secs=>p_seconds),
    updated_at=transaction_timestamp()
   WHERE r.workspace_id=candidate.workspace_id AND r.application_id=candidate.application_id
    AND r.request_id=candidate.request_id AND r.status='Staged' AND r.claimant IS NULL
   RETURNING r.claim_generation INTO generation;
   IF NOT FOUND THEN RETURN NULL;END IF;
  END IF;
 END IF;
 INSERT INTO epm.worker_workspace_dispatch(workspace_id,last_claim_sequence,claim_count)
 VALUES(candidate.workspace_id,nextval('epm.worker_dispatch_sequence'),1)
 ON CONFLICT ON CONSTRAINT worker_workspace_dispatch_pkey DO UPDATE SET
 last_claim_sequence=EXCLUDED.last_claim_sequence,claim_count=epm.worker_workspace_dispatch.claim_count+1;
 RETURN jsonb_build_object('phase',p_phase,'workspace_id',candidate.workspace_id,'application_id',candidate.application_id,
  'request_id',candidate.request_id,'activation_id',to_jsonb(candidate)->>'activation_id',
  'claimant',p_claimant,'claim_generation',generation,'issuer',candidate.issuer,'subject_id',candidate.subject_id,
  'verified_groups',candidate.verified_groups,'authorization_scope_digest',candidate.authorization_scope_digest,
  'token_issued_at',candidate.token_issued_at,'authority_kind',candidate.authority_kind)
  ||CASE WHEN p_phase='Activate' THEN '{}'::jsonb ELSE jsonb_build_object('plan',to_jsonb(candidate)->'plan',
   'dependency_decisions',candidate.dependency_decisions,'next_chunk',coalesce(to_jsonb(claimed)->'next_chunk','0'::jsonb)) END;
END $$;

CREATE FUNCTION epm.layout_worker_stage_renew(w text,a text,rid text,who text,g bigint,seconds integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR seconds IS NULL OR seconds NOT BETWEEN 30 AND 300 THEN
  RAISE EXCEPTION 'LAYOUT_WORKER_RENEW_INVALID';END IF;
 UPDATE epm.layout_replacement_request SET lease_until=clock_timestamp()+make_interval(secs=>seconds),
  updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND request_id=rid
  AND status='Staging' AND worker_phase='Stage' AND claimant=who AND claim_generation=g
  AND lease_until>clock_timestamp() AND epm.layout_replacement_current_admin(w,a,rid);
 RETURN FOUND;
END $$;

CREATE FUNCTION epm.layout_replacement_validation_publish_claimed(
 w text,a text,rid text,content text,n integer,certificate jsonb,who text,g bigint)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.layout_replacement_request%ROWTYPE;
BEGIN
 IF w IS DISTINCT FROM current_setting('epm.workspace_id',true) OR a IS DISTINCT FROM current_setting('epm.application_id',true)
 THEN RAISE EXCEPTION 'LAYOUT_REPLACEMENT_SCOPE_INVALID';END IF;
 SELECT * INTO r FROM epm.layout_replacement_request WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF NOT FOUND OR r.status<>'Staged' OR r.worker_phase IS DISTINCT FROM 'Validate'
 OR r.claimant IS DISTINCT FROM who OR r.claim_generation<>g OR r.lease_until IS NULL OR r.lease_until<=clock_timestamp()
 OR NOT epm.layout_replacement_current_admin(w,a,rid) THEN RAISE EXCEPTION 'LAYOUT_VALIDATION_STALE_WORKER';END IF;
 IF certificate->'dependencyContext'->'decisions' IS DISTINCT FROM r.dependency_decisions THEN
  RAISE EXCEPTION 'LAYOUT_VALIDATION_INTENT_MISMATCH';END IF;
 -- The row lock spans clearing the lease and immutable certificate publication.
 -- A refusal rolls back both; no other worker can acquire this claim in between.
 UPDATE epm.layout_replacement_request SET claimant=NULL,lease_until=NULL,worker_phase=NULL
 WHERE workspace_id=w AND application_id=a AND request_id=rid;
 RETURN epm.layout_replacement_validation_publish(w,a,rid,content,n,certificate);
END $$;

CREATE FUNCTION epm.layout_worker_settle_failed(p_phase text,w text,a text,id text,who text,g bigint,code text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed boolean; n integer;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR p_phase IS NULL OR p_phase NOT IN('Stage','Materialize','Validate','Activate')
 OR code IS NULL OR code!~'^[A-Z][A-Z0-9_]{2,127}$' THEN RAISE EXCEPTION 'LAYOUT_WORKER_SETTLEMENT_INVALID';END IF;
 IF p_phase='Activate' THEN
  UPDATE epm.layout_replacement_activation SET status='Failed',error_code=code,claimant=NULL,lease_until=NULL,
   updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND activation_id=id
   AND status='Activating' AND claimant=who AND claim_generation=g AND lease_until>clock_timestamp() AND result IS NULL;
  RETURN FOUND;
 ELSIF p_phase='Materialize' THEN
  -- Lock request before its materialization, matching dispatch and private control.
  PERFORM 1 FROM epm.layout_replacement_request WHERE workspace_id=w AND application_id=a
   AND request_id=id AND status='Staged' AND claimant IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN false;END IF;
  SELECT target_count INTO n FROM epm.layout_replacement_materialization WHERE workspace_id=w AND application_id=a
   AND request_id=id AND status='Running' AND claimant=who AND claim_generation=g AND lease_until>clock_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RETURN false;END IF;
  changed:=epm.layout_replacement_materialization_settle(w,a,id,who,g,NULL,n,code);
  IF NOT changed THEN RETURN false;END IF;
  UPDATE epm.layout_replacement_request SET status='Failed',error_code=code,updated_at=transaction_timestamp()
   WHERE workspace_id=w AND application_id=a AND request_id=id;
  RETURN true;
 ELSE
  UPDATE epm.layout_replacement_request SET status='Failed',error_code=code,claimant=NULL,lease_until=NULL,worker_phase=NULL,
   updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND request_id=id
   AND claimant=who AND claim_generation=g AND lease_until>clock_timestamp()
   AND ((p_phase='Stage' AND status='Staging' AND worker_phase='Stage')
     OR (p_phase='Validate' AND status='Staged' AND worker_phase='Validate'));
  RETURN FOUND;
 END IF;
END $$;

CREATE FUNCTION epm.layout_worker_recover(p_limit integer DEFAULT 100)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer; total integer:=0;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
  RAISE EXCEPTION 'LAYOUT_WORKER_RECOVERY_INVALID';END IF;
 WITH expired AS (SELECT workspace_id,application_id,request_id FROM epm.layout_replacement_request
  WHERE claimant IS NOT NULL AND lease_until<=clock_timestamp() ORDER BY lease_until,workspace_id,application_id,request_id
  FOR UPDATE SKIP LOCKED LIMIT p_limit)
 UPDATE epm.layout_replacement_request r SET status=CASE WHEN worker_phase='Stage' THEN 'Accepted' ELSE r.status END,
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,worker_phase=NULL,updated_at=transaction_timestamp()
 FROM expired e WHERE (r.workspace_id,r.application_id,r.request_id)=(e.workspace_id,e.application_id,e.request_id);
 GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 WITH expired AS (SELECT workspace_id,application_id,request_id FROM epm.layout_replacement_materialization
  WHERE status='Running' AND lease_until<=clock_timestamp() ORDER BY lease_until,workspace_id,application_id,request_id
  FOR UPDATE SKIP LOCKED LIMIT p_limit)
 UPDATE epm.layout_replacement_materialization m SET status='Ready',claim_generation=claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 FROM expired e WHERE (m.workspace_id,m.application_id,m.request_id)=(e.workspace_id,e.application_id,e.request_id);
 GET DIAGNOSTICS n=ROW_COUNT;total:=total+n;
 WITH expired AS (SELECT workspace_id,application_id,activation_id FROM epm.layout_replacement_activation
  WHERE status='Activating' AND lease_until<=clock_timestamp() ORDER BY lease_until,workspace_id,application_id,activation_id
  FOR UPDATE SKIP LOCKED LIMIT p_limit)
 UPDATE epm.layout_replacement_activation x SET status='Requested',claim_generation=claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 FROM expired e WHERE (x.workspace_id,x.application_id,x.activation_id)=(e.workspace_id,e.application_id,e.activation_id);
 GET DIAGNOSTICS n=ROW_COUNT;RETURN total+n;
END $$;

CREATE FUNCTION epm.layout_replacement_private_cancel(w text,a text,rid text,expected text,version bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.layout_replacement_request%ROWTYPE; m epm.layout_replacement_materialization%ROWTYPE;
BEGIN
 IF w IS DISTINCT FROM current_setting('epm.workspace_id',true) OR a IS DISTINCT FROM current_setting('epm.application_id',true)
 OR expected IS NULL OR expected NOT IN('Accepted','Staging','Staged','Validated','ValidationFailed','Failed','Cancelled') OR version IS NULL OR version<0 THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_CANCEL_INVALID';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application:'||w||':'||a,0));
 PERFORM 1 FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
 SELECT * INTO r FROM epm.layout_replacement_request WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF NOT FOUND OR r.status<>expected OR r.claim_generation<>version THEN RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STATE_STALE';END IF;
 IF r.status='Cancelled' THEN RETURN r.claim_generation;END IF;
 SELECT * INTO m FROM epm.layout_replacement_materialization
 WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF (r.claimant IS NOT NULL AND r.lease_until>clock_timestamp())
 OR (m.status='Running' AND m.lease_until>clock_timestamp())
 OR EXISTS(SELECT 1 FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a AND request_id=rid
  AND status IN('Requested','Activating','Activated')) THEN RAISE EXCEPTION 'LAYOUT_REPLACEMENT_WORK_IN_PROGRESS';END IF;
 -- Keep all maps, chunks, certificates and receipts. Fence every departed worker.
 UPDATE epm.layout_replacement_materialization SET status='Failed',error_code='LAYOUT_REPLACEMENT_CANCELLED',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid AND status IN('Ready','Running');
 UPDATE epm.layout_replacement_request SET status='Cancelled',claim_generation=claim_generation+1,
  claimant=NULL,lease_until=NULL,worker_phase=NULL,error_code=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid RETURNING claim_generation INTO version;
 RETURN version;
END $$;

REVOKE ALL ON FUNCTION epm.layout_worker_capacity(text,text,integer,integer,integer),
 epm.layout_worker_claim(text,text,integer,integer,integer,integer),
 epm.layout_worker_stage_renew(text,text,text,text,bigint,integer),
 epm.layout_worker_settle_failed(text,text,text,text,text,bigint,text),
 epm.layout_worker_recover(integer),
 epm.layout_replacement_validation_publish_claimed(text,text,text,text,integer,jsonb,text,bigint),
 epm.layout_replacement_private_cancel(text,text,text,text,bigint)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_security,epm_access;
GRANT EXECUTE ON FUNCTION epm.layout_worker_claim(text,text,integer,integer,integer,integer),
 epm.layout_worker_stage_renew(text,text,text,text,bigint,integer),
 epm.layout_worker_settle_failed(text,text,text,text,text,bigint,text),epm.layout_worker_recover(integer) TO epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_validation_publish_claimed(text,text,text,text,integer,jsonb,text,bigint),
 epm.layout_replacement_private_cancel(text,text,text,text,bigint) TO epm_runtime;

CREATE FUNCTION epm.layout_worker_observe(phase text,w text,a text,id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF NOT pg_has_role(session_user,'epm_worker','member') OR phase IS NULL OR phase NOT IN('Stage','Materialize','Validate','Activate')
 THEN RAISE EXCEPTION 'LAYOUT_WORKER_OBSERVATION_INVALID';END IF;
 IF phase='Activate' THEN
  SELECT jsonb_build_object('requestId',request_id,'activationId',activation_id,'status',status,
   'stateVersion',claim_generation,'errorCode',error_code,'receiptPresent',x.result IS NOT NULL) INTO result
  FROM epm.layout_replacement_activation x WHERE workspace_id=w AND application_id=a AND activation_id=id;
 ELSE
  SELECT jsonb_build_object('requestId',r.request_id,'status',r.status,'stateVersion',r.claim_generation,
   'errorCode',r.error_code,'materializationStatus',m.status,'materializationErrorCode',m.error_code,
   'certificatePresent',c.request_id IS NOT NULL) INTO result
  FROM epm.layout_replacement_request r
  LEFT JOIN epm.layout_replacement_materialization m USING(workspace_id,application_id,request_id)
  LEFT JOIN epm.layout_replacement_validation_certificate c USING(workspace_id,application_id,request_id)
  WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=id;
 END IF;
 IF result->>'status'='Activated' AND result->'receiptPresent' IS DISTINCT FROM 'true'::jsonb THEN
  RAISE EXCEPTION 'LAYOUT_WORKER_RECEIPT_MISSING';END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION epm.layout_worker_observe(text,text,text,text)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_security,epm_access;
GRANT EXECUTE ON FUNCTION epm.layout_worker_observe(text,text,text,text) TO epm_worker;

-- All public/task control now routes through the exact state/generation fence.
REVOKE EXECUTE ON FUNCTION epm.layout_replacement_cancel(text,text,text) FROM epm_runtime;

-- Read a lease under the same row lock that protects its private writes.
-- This closes recovery-versus-chunk interleaving without changing conversion.
DO $migration$ DECLARE definition text; old text; replacement text; BEGIN
 SELECT pg_get_functiondef('epm.layout_replacement_materialization_chunk(text,text,text,text,bigint,integer,text,jsonb)'::regprocedure) INTO definition;
 old:='AND lease_until>clock_timestamp();';
 replacement:='AND lease_until>clock_timestamp() FOR UPDATE;';
 IF position(old IN definition)=0 OR position('FOR UPDATE' IN definition)>0 THEN
  RAISE EXCEPTION 'LAYOUT_MATERIALIZATION_CHUNK_LOCK_SOURCE_MISMATCH';END IF;
 EXECUTE replace(definition,old,replacement);
END $migration$;

-- The existing immutable plan and staged-coordinate owner are the progress
-- record. A bounded batch skips only exact already committed mappings; neither
-- a count nor a presumed contiguous prefix can authorize settlement.
CREATE FUNCTION epm.layout_worker_stage_pending(p_workspace text,p_application text,p_request text,
 p_claimant text,p_generation bigint,p_limit integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.layout_replacement_request%ROWTYPE; bad boolean; pending jsonb;
BEGIN
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGE_INVALID' USING ERRCODE='22023';END IF;
 SELECT * INTO r FROM epm.layout_replacement_request
 WHERE workspace_id=p_workspace AND application_id=p_application AND request_id=p_request
 AND status='Staging' AND worker_phase='Stage' AND claimant=p_claimant
 AND claim_generation=p_generation AND lease_until>clock_timestamp() FOR UPDATE;
 IF NOT FOUND OR NOT epm.layout_replacement_current_admin(p_workspace,p_application,p_request) THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STALE_WORKER';END IF;
 WITH mapping AS MATERIALIZED (
  SELECT (m.value->>'sourceCoordinateId')::bigint AS source_id,m.value->'targetMembers' AS members,m.ordinal
  FROM jsonb_array_elements(r.plan->'coordinateMappings') WITH ORDINALITY m(value,ordinal))
 SELECT EXISTS(SELECT 1 FROM epm.layout_replacement_staged_coordinate c LEFT JOIN mapping m
   ON m.source_id=c.source_coordinate_id
   WHERE c.workspace_id=p_workspace AND c.application_id=p_application AND c.generation_id=r.target_generation_id
   AND (m.source_id IS NULL OR c.target_members IS DISTINCT FROM m.members)),
  COALESCE((SELECT jsonb_agg(jsonb_build_object('sourceCoordinateId',q.source_id,'targetMembers',q.members) ORDER BY q.ordinal)
   FROM (SELECT m.* FROM mapping m LEFT JOIN epm.layout_replacement_staged_coordinate c
    ON c.workspace_id=p_workspace AND c.application_id=p_application AND c.generation_id=r.target_generation_id
    AND c.source_coordinate_id=m.source_id
    WHERE c.source_coordinate_id IS NULL ORDER BY m.ordinal LIMIT p_limit) q),'[]'::jsonb)
 INTO bad,pending;
 IF bad THEN RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGED_MAPPING_CONFLICT';END IF;
 RETURN pending;
END $$;

-- One validation/membership scan and set write replaces N full-plan scans.
-- The original single-row entry point below delegates to this same owner.
CREATE FUNCTION epm.layout_replacement_worker_stage_batch(p_workspace text,p_application text,p_request text,
 p_claimant text,p_generation bigint,p_rows jsonb)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.layout_replacement_request%ROWTYPE; item jsonb; n integer; matched integer; changed integer;
BEGIN
 IF jsonb_typeof(p_rows) IS DISTINCT FROM 'array' OR jsonb_array_length(p_rows) NOT BETWEEN 1 AND 500
 OR octet_length(p_rows::text)>33554432 THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGE_INVALID' USING ERRCODE='22023';END IF;
 n:=jsonb_array_length(p_rows);
 FOR item IN SELECT value FROM jsonb_array_elements(p_rows) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGE_INVALID' USING ERRCODE='22023';END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(item))<>3
  OR jsonb_typeof(item->'sourceCoordinateId') IS DISTINCT FROM 'number'
  OR COALESCE(item->>'sourceCoordinateId','') !~ '^[1-9][0-9]{0,18}$'
  OR (item->>'sourceCoordinateId')::numeric>9223372036854775807
  OR jsonb_typeof(item->'targetMembers') IS DISTINCT FROM 'object'
  OR octet_length((item->'targetMembers')::text)>1048576
  OR jsonb_typeof(item->'targetDigest') IS DISTINCT FROM 'string'
  OR COALESCE(item->>'targetDigest','') !~ '^[0-9a-f]{64}$' THEN
   RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGE_INVALID' USING ERRCODE='22023';END IF;
 END LOOP;
 IF (SELECT count(DISTINCT value->>'sourceCoordinateId') FROM jsonb_array_elements(p_rows))<>n THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGE_INVALID' USING ERRCODE='22023';END IF;
 SELECT * INTO r FROM epm.layout_replacement_request
 WHERE workspace_id=p_workspace AND application_id=p_application AND request_id=p_request
 AND status='Staging' AND worker_phase='Stage' AND claimant=p_claimant
 AND claim_generation=p_generation AND lease_until>clock_timestamp() FOR UPDATE;
 IF NOT FOUND OR NOT epm.layout_replacement_current_admin(p_workspace,p_application,p_request) THEN RETURN 0;END IF;
 WITH mapping AS MATERIALIZED (
  SELECT (value->>'sourceCoordinateId')::bigint AS source_id,value->'targetMembers' AS members
  FROM jsonb_array_elements(r.plan->'coordinateMappings'))
 SELECT count(*) INTO matched FROM jsonb_array_elements(p_rows) input
 JOIN mapping m ON m.source_id=(input.value->>'sourceCoordinateId')::bigint
 AND m.members=input.value->'targetMembers';
 IF matched<>n THEN RETURN 0;END IF;
 INSERT INTO epm.layout_replacement_staged_coordinate
 (workspace_id,application_id,generation_id,source_coordinate_id,target_members,target_digest)
 SELECT p_workspace,p_application,r.target_generation_id,(value->>'sourceCoordinateId')::bigint,
  value->'targetMembers',value->>'targetDigest' FROM jsonb_array_elements(p_rows)
 ON CONFLICT(workspace_id,application_id,generation_id,source_coordinate_id)
 DO UPDATE SET target_members=EXCLUDED.target_members
 WHERE epm.layout_replacement_staged_coordinate.target_digest=EXCLUDED.target_digest;
 GET DIAGNOSTICS changed=ROW_COUNT;
 IF changed<>n THEN RAISE EXCEPTION 'LAYOUT_REPLACEMENT_STAGED_MAPPING_CONFLICT';END IF;
 RETURN changed;
END $$;

CREATE OR REPLACE FUNCTION epm.layout_replacement_worker_stage(
 p_workspace text,p_application text,p_request text,p_claimant text,
 p_generation bigint,p_source bigint,p_members jsonb,p_digest text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 RETURN epm.layout_replacement_worker_stage_batch(p_workspace,p_application,p_request,p_claimant,p_generation,
  jsonb_build_array(jsonb_build_object('sourceCoordinateId',p_source,'targetMembers',p_members,'targetDigest',p_digest)))=1;
END $$;
REVOKE ALL ON FUNCTION epm.layout_worker_stage_pending(text,text,text,text,bigint,integer),
 epm.layout_replacement_worker_stage_batch(text,text,text,text,bigint,jsonb)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_security,epm_access;
GRANT EXECUTE ON FUNCTION epm.layout_worker_stage_pending(text,text,text,text,bigint,integer),
 epm.layout_replacement_worker_stage_batch(text,text,text,text,bigint,jsonb) TO epm_worker;
