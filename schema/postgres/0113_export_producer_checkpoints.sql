-- Crash-durable pre-finalization export source checkpoints.
CREATE TABLE epm.fact_export_producer_request(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL CHECK(request_id~'^[0-9a-f]{32}$'),
 issuer text NOT NULL,subject_id text NOT NULL,idempotency_key text NOT NULL CHECK(idempotency_key~'^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),origin text NOT NULL CHECK(length(origin) BETWEEN 1 AND 500),
 snapshot_revision bigint NOT NULL CHECK(snapshot_revision>=0),metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
 expires_at_epoch bigint NOT NULL CHECK(expires_at_epoch>0),schema_identity jsonb NOT NULL,members jsonb NOT NULL,
 status text NOT NULL CHECK(status IN('Accepted','Reading','Prepared','Cancelled','Failed','Completed')),
 claim_generation bigint NOT NULL DEFAULT 0,claimant text,lease_until timestamptz,next_page integer NOT NULL DEFAULT 0,
 expected_cursor text,manifest jsonb,artifact_id text,error_code text,cancel_requested boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,request_id),UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CHECK((status='Reading')=(claimant IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(expected_cursor IS NULL OR length(expected_cursor) BETWEEN 1 AND 16384),
 CHECK(manifest IS NULL OR jsonb_typeof(manifest)='object'));
CREATE TABLE epm.fact_export_producer_page(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL,page_index integer NOT NULL CHECK(page_index>=0),
 request_cursor text,request_cursor_digest text,next_cursor text,next_cursor_digest text,
 content_digest text NOT NULL CHECK(content_digest~'^[0-9a-f]{64}$'),page jsonb NOT NULL CHECK(jsonb_typeof(page)='object' AND octet_length(page::text)<=9437184),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),PRIMARY KEY(workspace_id,application_id,request_id,page_index),
 FOREIGN KEY(workspace_id,application_id,request_id) REFERENCES epm.fact_export_producer_request(workspace_id,application_id,request_id) ON DELETE RESTRICT);
CREATE INDEX fact_export_producer_status ON epm.fact_export_producer_request(status,lease_until,workspace_id,application_id);

CREATE FUNCTION epm.export_producer_page_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
 RAISE EXCEPTION 'EXPORT_PRODUCER_PAGE_IMMUTABLE' USING ERRCODE='23514';END$$;
CREATE TRIGGER export_producer_page_immutable BEFORE UPDATE ON epm.fact_export_producer_page FOR EACH ROW EXECUTE FUNCTION epm.export_producer_page_immutable();
CREATE FUNCTION epm.export_producer_claim(w text,a text,rid text,who text,seconds integer) RETURNS TABLE(claim_generation bigint,next_page integer,expected_cursor text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN
 IF seconds NOT BETWEEN 30 AND 300 OR length(who) NOT BETWEEN 1 AND 200 THEN RAISE EXCEPTION 'EXPORT_PRODUCER_CLAIM_INVALID';END IF;
 RETURN QUERY UPDATE epm.fact_export_producer_request r SET status='Reading',claim_generation=r.claim_generation+1,
 claimant=who,lease_until=clock_timestamp()+make_interval(secs=>seconds),updated_at=transaction_timestamp()
 WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=rid AND NOT r.cancel_requested
 AND (r.status='Accepted' OR (r.status='Reading' AND r.lease_until<=clock_timestamp()))
 RETURNING r.claim_generation,r.next_page,r.expected_cursor;END$$;
CREATE FUNCTION epm.export_producer_append(w text,a text,rid text,who text,generation bigint,idx integer,request_cur text,next_cur text,digest text,p jsonb)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$DECLARE prior epm.fact_export_producer_page%ROWTYPE;r epm.fact_export_producer_request%ROWTYPE;BEGIN
 SELECT * INTO r FROM epm.fact_export_producer_request WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 SELECT * INTO prior FROM epm.fact_export_producer_page WHERE workspace_id=w AND application_id=a AND request_id=rid AND page_index=idx;
 IF FOUND THEN IF prior.content_digest<>digest OR prior.page<>p OR prior.request_cursor IS DISTINCT FROM request_cur OR prior.next_cursor IS DISTINCT FROM next_cur THEN RAISE EXCEPTION 'EXPORT_PRODUCER_PAGE_CONFLICT';END IF;RETURN true;END IF;
 IF r.status<>'Reading' OR r.claimant<>who OR r.claim_generation<>generation OR r.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';END IF;
 IF r.cancel_requested THEN RAISE EXCEPTION 'EXPORT_PRODUCER_CANCELLED';END IF;
 IF idx<>r.next_page OR request_cur IS DISTINCT FROM r.expected_cursor THEN RAISE EXCEPTION 'EXPORT_PRODUCER_PAGE_GAP';END IF;
 INSERT INTO epm.fact_export_producer_page VALUES(w,a,rid,idx,request_cur,CASE WHEN request_cur IS NULL THEN NULL ELSE encode(pg_catalog.sha256(convert_to(request_cur,'UTF8')),'hex') END,next_cur,CASE WHEN next_cur IS NULL THEN NULL ELSE encode(pg_catalog.sha256(convert_to(next_cur,'UTF8')),'hex') END,digest,p,transaction_timestamp());
 UPDATE epm.fact_export_producer_request SET next_page=next_page+1,expected_cursor=next_cur,lease_until=clock_timestamp()+interval '120 seconds',updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND request_id=rid;RETURN true;END$$;
CREATE FUNCTION epm.export_producer_seal(w text,a text,rid text,who text,generation bigint,m jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN
 UPDATE epm.fact_export_producer_request SET status='Prepared',manifest=m,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid AND status='Reading' AND claimant=who AND claim_generation=generation
 AND lease_until>clock_timestamp() AND expected_cursor IS NULL AND NOT cancel_requested;RETURN FOUND;END$$;
CREATE FUNCTION epm.export_producer_cancel(w text,a text,rid text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN
 UPDATE epm.fact_export_producer_request SET cancel_requested=true,status=CASE WHEN status IN('Accepted','Reading') THEN 'Cancelled' ELSE status END,
 claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND request_id=rid AND status IN('Accepted','Reading');RETURN FOUND;END$$;
CREATE FUNCTION epm.export_producer_complete(w text,a text,rid text,artifact text,manifest_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$DECLARE prior epm.fact_export_producer_request%ROWTYPE;BEGIN
 SELECT * INTO prior FROM epm.fact_export_producer_request WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF prior.status='Completed' THEN
  IF prior.artifact_id IS DISTINCT FROM artifact OR prior.manifest->>'manifestDigest' IS DISTINCT FROM manifest_digest THEN
   RAISE EXCEPTION 'EXPORT_PRODUCER_COMPLETE_CONFLICT';END IF;RETURN true;END IF;
 IF prior.status<>'Prepared' OR prior.manifest->>'manifestDigest' IS DISTINCT FROM manifest_digest THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_NOT_PREPARED';END IF;
 UPDATE epm.fact_export_producer_request SET status='Completed',artifact_id=artifact,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid;RETURN true;END$$;
REVOKE ALL ON FUNCTION epm.export_producer_claim(text,text,text,text,integer),epm.export_producer_append(text,text,text,text,bigint,integer,text,text,text,jsonb),epm.export_producer_seal(text,text,text,text,bigint,jsonb),epm.export_producer_cancel(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_claim(text,text,text,text,integer),epm.export_producer_append(text,text,text,text,bigint,integer,text,text,text,jsonb),epm.export_producer_seal(text,text,text,text,bigint,jsonb),epm.export_producer_cancel(text,text,text) TO epm_runtime;
REVOKE ALL ON FUNCTION epm.export_producer_complete(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_complete(text,text,text,text,text) TO epm_runtime;
DO $$DECLARE t text;BEGIN FOREACH t IN ARRAY ARRAY['fact_export_producer_request','fact_export_producer_page'] LOOP EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',t);EXECUTE format('CREATE POLICY %I ON epm.%I TO epm_runtime USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',t||'_runtime',t);END LOOP;END$$;
REVOKE ALL ON epm.fact_export_producer_request,epm.fact_export_producer_page FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.fact_export_producer_request TO epm_runtime;GRANT SELECT ON epm.fact_export_producer_page TO epm_runtime;
DO $$DECLARE old text:='0e91a3cfcdf49a82ff78839ae60febb8f718280a6de921b09f0cf5c620d7f5e5';new text:='28c6c4b5012de669dad732ac09932c5d5f566097e26adaae65a8612f068064d3';d text;r text;b text:='''fact_export_payload_chunk'',''fact_export_payload''';a text:='''fact_export_producer_page'',''fact_export_producer_request'',''fact_export_payload_chunk'',''fact_export_payload''';gate text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';gated text:='    IF EXISTS(SELECT 1 FROM epm.fact_export_producer_request WHERE workspace_id=p_workspace_id AND status IN(''Accepted'',''Reading'',''Prepared'')) THEN RAISE EXCEPTION ''UNSETTLED_EXPORT_PRODUCER'';END IF;'||chr(10)||gate;BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)INTO d;IF position(old in d)=0 OR position(b in d)=0 THEN RAISE EXCEPTION 'RESET_0113_DEFINITION_MISMATCH';END IF;r:=replace(replace(replace(d,old,new),b,a),gate,gated);EXECUTE r;END$$;
