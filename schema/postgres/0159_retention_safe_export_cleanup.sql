-- Retention-safe cleanup: artifact and payload are one locked deletion unit.
DO $$BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=158) THEN
  RAISE EXCEPTION 'MIGRATION_0159_PREDECESSOR_0158_REQUIRED';
 END IF;
END$$;

CREATE OR REPLACE FUNCTION epm.transfer_cleanup_execute(
 w text,a text,rid text,who text,generation bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r epm.transfer_cleanup_request%ROWTYPE;dp integer;dd integer;de integer;
 dpl integer;cert jsonb;dig text;paired text[]:=ARRAY[]::text[];
 orphaned text[]:=ARRAY[]::text[];remaining integer;
BEGIN
 SELECT * INTO r FROM epm.transfer_cleanup_request WHERE workspace_id=w
  AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' THEN RETURN r.result;END IF;
 IF r.status<>'Running' OR r.claimant<>who OR r.claim_generation<>generation
  OR r.lease_until<=clock_timestamp() THEN
  RAISE EXCEPTION 'TRANSFER_CLEANUP_STALE_WORKER';END IF;

 -- Both rows are locked before their identities are admitted. SKIP LOCKED is
 -- bounded and deterministic by creation/id; a concurrent retention change
 -- either wins before admission or waits behind these locks.
 SELECT coalesce(array_agg(q.artifact_id ORDER BY q.created_at,q.artifact_id),
                         ARRAY[]::text[]) INTO paired
 FROM(SELECT e.artifact_id,e.created_at FROM epm.fact_export_artifact e
  JOIN epm.fact_export_payload p USING(workspace_id,application_id,artifact_id)
  WHERE e.workspace_id=w AND e.application_id=a
   AND e.retention_status<>'held' AND p.retention_status<>'held'
   AND(e.retention_status='expired'
       OR e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
   AND(p.retention_status='expired'
       OR p.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
   AND(e.producer_request_id IS NULL OR EXISTS(
    SELECT 1 FROM epm.fact_export_producer_request pr
    WHERE pr.workspace_id=e.workspace_id AND pr.application_id=e.application_id
     AND pr.request_id=e.producer_request_id
     AND pr.status IN('Cancelled','Failed','Completed')))
  ORDER BY e.created_at,e.artifact_id LIMIT r.batch_limit
  FOR UPDATE OF e,p SKIP LOCKED)q;

 remaining:=r.batch_limit-cardinality(paired);
 IF remaining>0 THEN
  SELECT coalesce(array_agg(q.artifact_id ORDER BY q.created_at,q.artifact_id),
                           ARRAY[]::text[]) INTO orphaned
  FROM(SELECT e.artifact_id,e.created_at FROM epm.fact_export_artifact e
   WHERE e.workspace_id=w AND e.application_id=a
    AND e.retention_status<>'held'
    AND(e.retention_status='expired'
        OR e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
    AND NOT EXISTS(SELECT 1 FROM epm.fact_export_payload p
     WHERE p.workspace_id=e.workspace_id AND p.application_id=e.application_id
      AND p.artifact_id=e.artifact_id)
    AND(e.producer_request_id IS NULL OR EXISTS(
     SELECT 1 FROM epm.fact_export_producer_request pr
     WHERE pr.workspace_id=e.workspace_id
      AND pr.application_id=e.application_id
      AND pr.request_id=e.producer_request_id
      AND pr.status IN('Cancelled','Failed','Completed')))
   ORDER BY e.created_at,e.artifact_id LIMIT remaining
   FOR UPDATE OF e SKIP LOCKED)q;
 END IF;

 DELETE FROM epm.fact_export_payload_chunk c
  WHERE c.workspace_id=w AND c.application_id=a
   AND c.artifact_id=ANY(paired)
   AND EXISTS(SELECT 1 FROM epm.fact_export_artifact e
    JOIN epm.fact_export_payload p USING(workspace_id,application_id,artifact_id)
    WHERE e.workspace_id=c.workspace_id AND e.application_id=c.application_id
     AND e.artifact_id=c.artifact_id AND e.retention_status<>'held'
     AND p.retention_status<>'held'
     AND(e.retention_status='expired' OR
       e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
     AND(p.retention_status='expired' OR
       p.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint));
 DELETE FROM epm.fact_export_payload p
  WHERE p.workspace_id=w AND p.application_id=a AND p.artifact_id=ANY(paired)
   AND p.retention_status<>'held'
   AND(p.retention_status='expired' OR
       p.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
   AND EXISTS(SELECT 1 FROM epm.fact_export_artifact e
    WHERE e.workspace_id=p.workspace_id AND e.application_id=p.application_id
     AND e.artifact_id=p.artifact_id AND e.retention_status<>'held'
     AND(e.retention_status='expired' OR
       e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint));
 GET DIAGNOSTICS dpl=ROW_COUNT;
 DELETE FROM epm.fact_export_artifact e
  WHERE e.workspace_id=w AND e.application_id=a
   AND e.artifact_id=ANY(paired||orphaned) AND e.retention_status<>'held'
   AND(e.retention_status='expired' OR
       e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
   AND NOT EXISTS(SELECT 1 FROM epm.fact_export_payload p
    WHERE p.workspace_id=e.workspace_id AND p.application_id=e.application_id
     AND p.artifact_id=e.artifact_id);
 GET DIAGNOSTICS de=ROW_COUNT;

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
   AND(retention_status='expired' OR
       expires_at_epoch<=extract(epoch from clock_timestamp())::bigint)
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
