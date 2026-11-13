-- Revalidate cleanup ownership at the last effect boundary.  A long-running
-- delete batch must not certify or publish after its database-clock lease has
-- expired.  Raising here rolls every delete in this transaction back.
CREATE OR REPLACE FUNCTION epm.transfer_cleanup_execute(
 w text,a text,rid text,who text,generation bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.transfer_cleanup_request%ROWTYPE;dp integer;dd integer;de integer;
 dpl integer;cert jsonb;dig text;
BEGIN
 SELECT * INTO r FROM epm.transfer_cleanup_request
  WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' THEN RETURN r.result;END IF;
 IF r.status<>'Running' OR r.claimant<>who OR r.claim_generation<>generation
    OR r.lease_until<=clock_timestamp() THEN
  RAISE EXCEPTION 'TRANSFER_CLEANUP_STALE_WORKER';
 END IF;
 WITH targets AS(
  SELECT p.ctid FROM epm.fact_export_producer_request p
   WHERE p.workspace_id=w AND p.application_id=a
    AND p.status IN('Cancelled','Failed','Completed')
    AND p.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint
   ORDER BY p.created_at LIMIT r.batch_limit),
 delpages AS(DELETE FROM epm.fact_export_producer_page p
  USING targets t,epm.fact_export_producer_request q
  WHERE q.ctid=t.ctid AND p.workspace_id=q.workspace_id
   AND p.application_id=q.application_id AND p.request_id=q.request_id),
 deleted AS(DELETE FROM epm.fact_export_producer_request p USING targets t
  WHERE p.ctid=t.ctid RETURNING 1)
 SELECT count(*) INTO dp FROM deleted;
 WITH targets AS(
  SELECT ctid FROM epm.source_import_diagnostic_artifact
   WHERE workspace_id=w AND application_id=a AND retention_status<>'held'
    AND(retention_status='expired'
     OR expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
   ORDER BY created_at LIMIT r.batch_limit),
 deleted AS(DELETE FROM epm.source_import_diagnostic_artifact d USING targets t
  WHERE d.ctid=t.ctid RETURNING 1)
 SELECT count(*) INTO dd FROM deleted;
 WITH targets AS(
  SELECT e.ctid,e.artifact_id FROM epm.fact_export_artifact e
   WHERE e.workspace_id=w AND e.application_id=a
    AND e.retention_status<>'held'
    AND(e.retention_status='expired'
     OR e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
   ORDER BY e.created_at LIMIT r.batch_limit),
 chunks AS(DELETE FROM epm.fact_export_payload_chunk c USING targets t
  WHERE c.workspace_id=w AND c.application_id=a AND c.artifact_id=t.artifact_id),
 payloads AS(DELETE FROM epm.fact_export_payload p USING targets t
  WHERE p.workspace_id=w AND p.application_id=a AND p.artifact_id=t.artifact_id
  RETURNING 1),
 exports AS(DELETE FROM epm.fact_export_artifact e USING targets t
  WHERE e.ctid=t.ctid RETURNING 1)
 SELECT (SELECT count(*) FROM payloads),(SELECT count(*) FROM exports)
  INTO dpl,de;
 cert=jsonb_build_object('requestId',rid,'deletedProducerRequests',dp,
  'deletedDiagnostics',dd,'deletedExports',de,'deletedPayloads',dpl,
  'batchLimit',r.batch_limit);
 dig=encode(pg_catalog.sha256(convert_to(cert::text,'UTF8')),'hex');

 -- This conditional transition is the final effect fence.  It uses the
 -- database clock and exact claim identity; zero rows raises and rolls back
 -- all preceding artifact deletes.  The certificate insert is in the same
 -- transaction, so neither result can exist without the other.
 UPDATE epm.transfer_cleanup_request SET status='Completed',claimant=NULL,
  lease_until=NULL,result=cert,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND request_id=rid
  AND status='Running' AND claimant=who AND claim_generation=generation
  AND lease_until>clock_timestamp()
 RETURNING * INTO r;
 IF NOT FOUND THEN RAISE EXCEPTION 'TRANSFER_CLEANUP_STALE_WORKER';END IF;
 INSERT INTO epm.transfer_cleanup_certificate VALUES(
  w,a,rid,dig,dp,dd,de,dpl,cert,transaction_timestamp());
 RETURN cert;
END$$;

REVOKE ALL ON FUNCTION epm.transfer_cleanup_execute(
 text,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.transfer_cleanup_execute(
 text,text,text,text,bigint) TO epm_worker;
