-- Resume bounded publication, permit exact completed-content reuse, and
-- protect nonterminal producer artifacts from retention cleanup.
DO $$DECLARE c text;BEGIN
 SELECT conname INTO c FROM pg_constraint
 WHERE conrelid='epm.fact_export_artifact'::regclass AND contype='u'
  AND pg_get_constraintdef(oid)='UNIQUE (workspace_id, application_id, manifest_digest)';
 IF c IS NULL THEN RAISE EXCEPTION 'EXPORT_MANIFEST_UNIQUE_CONSTRAINT_NOT_FOUND';END IF;
 EXECUTE format('ALTER TABLE epm.fact_export_artifact DROP CONSTRAINT %I',c);
END$$;
CREATE INDEX fact_export_artifact_manifest_digest ON epm.fact_export_artifact
 (workspace_id,application_id,manifest_digest);

CREATE OR REPLACE FUNCTION epm.export_producer_publish_complete(
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
  LEFT JOIN epm.fact_export_producer_request owner
   ON owner.workspace_id=x.workspace_id AND owner.application_id=x.application_id
   AND owner.request_id=x.producer_request_id
  WHERE x.workspace_id=w AND x.application_id=a AND x.artifact_id=artifact
   AND x.manifest_digest=manifest_digest AND p.status='complete'
   AND p.payload_digest=payload_digest
   AND x.retention_status='retained' AND p.retention_status='retained'
   AND x.expires_at_epoch>extract(epoch from clock_timestamp())::bigint
   AND p.expires_at_epoch>extract(epoch from clock_timestamp())::bigint AND(
    (x.producer_request_id=rid AND x.producer_claim_generation=generation) OR
    x.producer_request_id IS NULL OR
    (owner.status='Completed' AND owner.artifact_id=x.artifact_id
     AND owner.payload_digest=p.payload_digest)) FOR UPDATE OF x,p) THEN
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
   AND(e.producer_request_id IS NULL OR EXISTS(
    SELECT 1 FROM epm.fact_export_producer_request pr
    WHERE pr.workspace_id=e.workspace_id AND pr.application_id=e.application_id
     AND pr.request_id=e.producer_request_id
     AND pr.status IN('Cancelled','Failed','Completed')))
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
