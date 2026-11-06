-- Durable export publication claim and visibility lineage.
DO $$DECLARE c text;BEGIN
 SELECT conname INTO c FROM pg_constraint
 WHERE conrelid='epm.fact_export_producer_request'::regclass
  AND contype='c' AND pg_get_constraintdef(oid) LIKE '%status = ANY%Accepted%Reading%Prepared%';
 IF c IS NULL THEN RAISE EXCEPTION 'EXPORT_PRODUCER_STATUS_CONSTRAINT_NOT_FOUND';END IF;
 EXECUTE format('ALTER TABLE epm.fact_export_producer_request DROP CONSTRAINT %I',c);
 SELECT conname INTO c FROM pg_constraint
 WHERE conrelid='epm.fact_export_producer_request'::regclass AND contype='c'
  AND pg_get_constraintdef(oid) LIKE '%status = ''Reading''%claimant IS NOT NULL%';
 IF c IS NULL THEN RAISE EXCEPTION 'EXPORT_PRODUCER_CLAIM_CONSTRAINT_NOT_FOUND';END IF;
 EXECUTE format('ALTER TABLE epm.fact_export_producer_request DROP CONSTRAINT %I',c);
END$$;
ALTER TABLE epm.fact_export_producer_request
 ADD COLUMN payload_digest text CHECK(payload_digest IS NULL OR payload_digest~'^[0-9a-f]{64}$'),
 ADD COLUMN published_at timestamptz,
 ADD CHECK(status IN('Accepted','Reading','Prepared','Publishing','Cancelled','Failed','Completed')),
 ADD CHECK((status IN('Reading','Publishing'))=(claimant IS NOT NULL AND lease_until IS NOT NULL));

ALTER TABLE epm.fact_export_artifact
 ADD COLUMN producer_request_id text,
 ADD COLUMN producer_claim_generation bigint,
 ADD CHECK((producer_request_id IS NULL)=(producer_claim_generation IS NULL)),
 ADD CHECK(producer_claim_generation IS NULL OR producer_claim_generation>0),
 ADD CONSTRAINT fact_export_artifact_producer_fkey FOREIGN KEY(
  workspace_id,application_id,producer_request_id) REFERENCES
  epm.fact_export_producer_request(workspace_id,application_id,request_id)
  ON DELETE RESTRICT,
 ADD CONSTRAINT fact_export_artifact_producer_unique UNIQUE(
  workspace_id,application_id,producer_request_id);

CREATE FUNCTION epm.export_producer_publish_claim(
 w text,a text,rid text,who text,seconds integer)
RETURNS TABLE(claim_generation bigint,manifest_digest text,status text,
 artifact_id text,payload_digest text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.fact_export_producer_request%ROWTYPE;
BEGIN
 IF seconds NOT BETWEEN 30 AND 300 OR length(who) NOT BETWEEN 1 AND 200 THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_PUBLISH_CLAIM_INVALID';END IF;
 SELECT * INTO r FROM epm.fact_export_producer_request
  WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' THEN
  RETURN QUERY SELECT r.claim_generation,r.manifest->>'manifestDigest',
   r.status,r.artifact_id,r.payload_digest;RETURN;
 END IF;
 IF r.cancel_requested OR r.status='Cancelled' THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_CANCELLED';END IF;
 IF r.status='Publishing' AND r.claimant=who AND r.lease_until>clock_timestamp() THEN
  RETURN QUERY SELECT r.claim_generation,r.manifest->>'manifestDigest',
   r.status,r.artifact_id,r.payload_digest;RETURN;
 END IF;
 IF r.status<>'Prepared' AND NOT(r.status='Publishing' AND r.lease_until<=clock_timestamp()) THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_NOT_PREPARED';END IF;
 UPDATE epm.fact_export_producer_request p SET status='Publishing',
  claim_generation=p.claim_generation+1,claimant=who,
  lease_until=clock_timestamp()+make_interval(secs=>seconds),
  updated_at=transaction_timestamp()
 WHERE p.workspace_id=w AND p.application_id=a AND p.request_id=rid
 RETURNING p.claim_generation,p.manifest->>'manifestDigest',p.status,
  p.artifact_id,p.payload_digest INTO claim_generation,manifest_digest,status,
  artifact_id,payload_digest;
 RETURN NEXT;
END$$;

CREATE FUNCTION epm.export_producer_artifact_adopt(
 w text,a text,rid text,who text,generation bigint,artifact text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.fact_export_producer_request%ROWTYPE;BEGIN
 SELECT * INTO r FROM epm.fact_export_producer_request WHERE workspace_id=w
  AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status<>'Publishing' OR r.claimant<>who
  OR r.claim_generation<>generation OR r.lease_until<=clock_timestamp()
  OR r.cancel_requested THEN RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';END IF;
 UPDATE epm.fact_export_artifact SET producer_claim_generation=generation
  WHERE workspace_id=w AND application_id=a AND artifact_id=artifact
   AND producer_request_id=rid;
 IF NOT FOUND THEN RAISE EXCEPTION 'EXPORT_PRODUCER_ARTIFACT_UNAVAILABLE';END IF;
 RETURN true;
END$$;

CREATE FUNCTION epm.export_producer_assert_claim(
 w text,a text,rid text,who text,generation bigint,artifact text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM 1 FROM epm.fact_export_producer_request r
 JOIN epm.fact_export_artifact x ON x.workspace_id=r.workspace_id
  AND x.application_id=r.application_id AND x.producer_request_id=r.request_id
 WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=rid
  AND x.artifact_id=artifact AND x.producer_claim_generation=generation
  AND r.status='Publishing' AND r.claimant=who
  AND r.claim_generation=generation AND r.lease_until>clock_timestamp()
  AND NOT r.cancel_requested FOR UPDATE OF r,x;
 IF NOT FOUND THEN RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';END IF;
 RETURN true;
END$$;

CREATE OR REPLACE FUNCTION epm.export_producer_cancel(w text,a text,rid text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE epm.fact_export_producer_request SET cancel_requested=true,
  status='Cancelled',claim_generation=claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid
  AND status IN('Accepted','Reading','Prepared','Publishing');
 RETURN FOUND;
END$$;

CREATE FUNCTION epm.export_producer_publish_complete(
 w text,a text,rid text,who text,generation bigint,artifact text,
 manifest_digest text,payload_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.fact_export_producer_request%ROWTYPE;
BEGIN
 SELECT * INTO r FROM epm.fact_export_producer_request
  WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' THEN
  IF r.artifact_id IS DISTINCT FROM artifact
   OR r.manifest->>'manifestDigest' IS DISTINCT FROM manifest_digest
   OR r.payload_digest IS DISTINCT FROM payload_digest THEN
   RAISE EXCEPTION 'EXPORT_PRODUCER_COMPLETE_CONFLICT';END IF;
  RETURN true;
 END IF;
 IF r.status<>'Publishing' OR r.claimant<>who
  OR r.claim_generation<>generation OR r.lease_until<=clock_timestamp()
  OR r.cancel_requested THEN RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';END IF;
 IF r.manifest->>'manifestDigest' IS DISTINCT FROM manifest_digest THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_DURABLE_IDENTITY_DRIFT';END IF;
 IF NOT EXISTS(SELECT 1 FROM epm.fact_export_artifact x
  JOIN epm.fact_export_payload p USING(workspace_id,application_id,artifact_id)
  WHERE x.workspace_id=w AND x.application_id=a AND x.artifact_id=artifact
   AND x.producer_request_id=rid
   AND x.producer_claim_generation=generation
   AND x.manifest_digest=manifest_digest AND p.status='complete'
   AND p.payload_digest=payload_digest) THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_PAYLOAD_INCOMPLETE';END IF;
 UPDATE epm.fact_export_producer_request SET status='Completed',
  artifact_id=artifact,claimant=NULL,lease_until=NULL,
  payload_digest=payload_digest,published_at=clock_timestamp(),
  updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid
  AND status='Publishing' AND claimant=who AND claim_generation=generation
  AND lease_until>clock_timestamp() AND NOT cancel_requested;
 IF NOT FOUND THEN RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';END IF;
 RETURN true;
END$$;

-- Legacy completion is replay-only; all new effects require a publish claim.
CREATE OR REPLACE FUNCTION epm.export_producer_complete(
 w text,a text,rid text,artifact text,manifest_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.fact_export_producer_request%ROWTYPE;BEGIN
 SELECT * INTO r FROM epm.fact_export_producer_request
  WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' AND r.artifact_id=artifact
  AND r.manifest->>'manifestDigest'=manifest_digest THEN RETURN true;END IF;
 RAISE EXCEPTION 'EXPORT_PRODUCER_PUBLISH_CLAIM_REQUIRED';
END$$;

REVOKE ALL ON FUNCTION epm.export_producer_publish_claim(text,text,text,text,integer),
 epm.export_producer_publish_complete(text,text,text,text,bigint,text,text,text),
 epm.export_producer_artifact_adopt(text,text,text,text,bigint,text),
 epm.export_producer_assert_claim(text,text,text,text,bigint,text)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_publish_claim(text,text,text,text,integer),
 epm.export_producer_publish_complete(text,text,text,text,bigint,text,text,text),
 epm.export_producer_artifact_adopt(text,text,text,text,bigint,text),
 epm.export_producer_assert_claim(text,text,text,text,bigint,text)
 TO epm_runtime;

-- Permit only the server-owned adoption function to change claim lineage.
CREATE OR REPLACE FUNCTION epm.transfer_artifact_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN
 IF (to_jsonb(NEW)-ARRAY['retention_status','retention_reason',
      'retention_issuer','retention_subject_id','retention_updated_at',
      'producer_claim_generation']) IS DISTINCT FROM
    (to_jsonb(OLD)-ARRAY['retention_status','retention_reason',
      'retention_issuer','retention_subject_id','retention_updated_at',
      'producer_claim_generation']) THEN
  RAISE EXCEPTION 'TRANSFER_ARTIFACT_IMMUTABLE' USING ERRCODE='23514';END IF;
 RETURN NEW;END$$;

-- Repair cleanup order after adding artifact -> producer-request RESTRICT.
CREATE OR REPLACE FUNCTION epm.transfer_cleanup_execute(
 w text,a text,rid text,who text,generation bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.transfer_cleanup_request%ROWTYPE;dp integer;dd integer;de integer;
 dpl integer;cert jsonb;dig text;
BEGIN
 SELECT * INTO r FROM epm.transfer_cleanup_request WHERE workspace_id=w
  AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' THEN RETURN r.result;END IF;
 IF r.status<>'Running' OR r.claimant<>who OR r.claim_generation<>generation
  OR r.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'TRANSFER_CLEANUP_STALE_WORKER';END IF;
 WITH targets AS(SELECT e.ctid,e.artifact_id,e.producer_request_id
  FROM epm.fact_export_artifact e WHERE e.workspace_id=w AND e.application_id=a
   AND e.retention_status<>'held' AND(e.retention_status='expired'
    OR e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
  ORDER BY e.created_at LIMIT r.batch_limit),
 chunks AS(DELETE FROM epm.fact_export_payload_chunk c USING targets t
  WHERE c.workspace_id=w AND c.application_id=a AND c.artifact_id=t.artifact_id),
 payloads AS(DELETE FROM epm.fact_export_payload p USING targets t
  WHERE p.workspace_id=w AND p.application_id=a AND p.artifact_id=t.artifact_id RETURNING 1),
 exports AS(DELETE FROM epm.fact_export_artifact e USING targets t
  WHERE e.ctid=t.ctid RETURNING e.producer_request_id)
 SELECT (SELECT count(*) FROM payloads),(SELECT count(*) FROM exports) INTO dpl,de;
 WITH targets AS(SELECT p.ctid FROM epm.fact_export_producer_request p
  WHERE p.workspace_id=w AND p.application_id=a
   AND p.status IN('Cancelled','Failed','Completed')
   AND p.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint
   AND NOT EXISTS(SELECT 1 FROM epm.fact_export_artifact e
    WHERE e.workspace_id=p.workspace_id AND e.application_id=p.application_id
     AND e.producer_request_id=p.request_id)
  ORDER BY p.created_at LIMIT r.batch_limit),
 pages AS(DELETE FROM epm.fact_export_producer_page p USING targets t,
  epm.fact_export_producer_request q WHERE q.ctid=t.ctid
   AND p.workspace_id=q.workspace_id AND p.application_id=q.application_id
   AND p.request_id=q.request_id),
 deleted AS(DELETE FROM epm.fact_export_producer_request p USING targets t
  WHERE p.ctid=t.ctid RETURNING 1) SELECT count(*) INTO dp FROM deleted;
 WITH targets AS(SELECT ctid FROM epm.source_import_diagnostic_artifact
  WHERE workspace_id=w AND application_id=a AND retention_status<>'held'
   AND(retention_status='expired' OR expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
  ORDER BY created_at LIMIT r.batch_limit),
 deleted AS(DELETE FROM epm.source_import_diagnostic_artifact d USING targets t
  WHERE d.ctid=t.ctid RETURNING 1) SELECT count(*) INTO dd FROM deleted;
 cert=jsonb_build_object('requestId',rid,'deletedProducerRequests',dp,
  'deletedDiagnostics',dd,'deletedExports',de,'deletedPayloads',dpl,
  'batchLimit',r.batch_limit);
 dig=encode(pg_catalog.sha256(convert_to(cert::text,'UTF8')),'hex');
 UPDATE epm.transfer_cleanup_request SET status='Completed',claimant=NULL,
  lease_until=NULL,result=cert,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid
  AND status='Running' AND claimant=who AND claim_generation=generation
  AND lease_until>clock_timestamp() RETURNING * INTO r;
 IF NOT FOUND THEN RAISE EXCEPTION 'TRANSFER_CLEANUP_STALE_WORKER';END IF;
 INSERT INTO epm.transfer_cleanup_certificate VALUES(
  w,a,rid,dig,dp,dd,de,dpl,cert,transaction_timestamp());RETURN cert;
END$$;

-- Publishing is unsettled lifecycle work just like Prepared.
DO $$DECLARE d text;r text;
 old text:='status IN (''Accepted'',''Reading'',''Prepared'')';
 new text:='status IN (''Accepted'',''Reading'',''Prepared'',''Publishing'')';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(old in d)=0 THEN
  RAISE EXCEPTION 'RESET_0156_DEFINITION_MISMATCH';END IF;
 r=replace(d,old,new);
 IF position('''fact_export_producer_page'',''fact_export_producer_request'',''fact_export_payload_chunk'',''fact_export_payload'',''source_import_diagnostic_artifact'',''fact_export_artifact''' in r)=0 THEN
  RAISE EXCEPTION 'RESET_0156_ORDER_MISMATCH';END IF;
 r=replace(r,
  '''fact_export_producer_page'',''fact_export_producer_request'',''fact_export_payload_chunk'',''fact_export_payload'',''source_import_diagnostic_artifact'',''fact_export_artifact''',
  '''fact_export_producer_page'',''fact_export_payload_chunk'',''fact_export_payload'',''fact_export_artifact'',''fact_export_producer_request'',''source_import_diagnostic_artifact''');
 EXECUTE r;
END$$;
