-- PostgreSQL 18 rejects the historical 0158 body because PL/pgSQL parameters
-- named manifest_digest and payload_digest collide with selected table
-- columns.  Keep the public signature and security boundary unchanged while
-- making every parameter reference and potentially ambiguous column explicit.
-- PostgreSQL cannot rename input parameters with CREATE OR REPLACE, so replace
-- the same type signature transactionally and restore the historical ACL.
DROP FUNCTION epm.export_producer_publish_complete(
 text,text,text,text,bigint,text,text,text);
CREATE FUNCTION epm.export_producer_publish_complete(
 p_workspace_id text,p_application_id text,p_request_id text,p_worker_id text,
 p_generation bigint,p_artifact_id text,p_manifest_digest text,
 p_payload_digest text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_request epm.fact_export_producer_request%ROWTYPE;
BEGIN
 SELECT request_row.* INTO v_request
 FROM epm.fact_export_producer_request AS request_row
 WHERE request_row.workspace_id=p_workspace_id
   AND request_row.application_id=p_application_id
   AND request_row.request_id=p_request_id
 FOR UPDATE;
 IF v_request.status='Completed' THEN
  IF v_request.artifact_id IS DISTINCT FROM p_artifact_id
   OR v_request.manifest->>'manifestDigest' IS DISTINCT FROM p_manifest_digest
   OR v_request.payload_digest IS DISTINCT FROM p_payload_digest THEN
   RAISE EXCEPTION 'EXPORT_PRODUCER_COMPLETE_CONFLICT';
  END IF;
  RETURN true;
 END IF;
 IF v_request.status<>'Publishing' OR v_request.claimant<>p_worker_id
  OR v_request.claim_generation<>p_generation
  OR v_request.lease_until<=clock_timestamp()
  OR v_request.cancel_requested THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';
 END IF;
 IF v_request.manifest->>'manifestDigest' IS DISTINCT FROM p_manifest_digest THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_DURABLE_IDENTITY_DRIFT';
 END IF;
 IF NOT EXISTS(
  SELECT 1
  FROM epm.fact_export_artifact AS export_row
  JOIN epm.fact_export_payload AS payload_row
    ON payload_row.workspace_id=export_row.workspace_id
   AND payload_row.application_id=export_row.application_id
   AND payload_row.artifact_id=export_row.artifact_id
  LEFT JOIN epm.fact_export_producer_request AS owner_row
    ON owner_row.workspace_id=export_row.workspace_id
   AND owner_row.application_id=export_row.application_id
   AND owner_row.request_id=export_row.producer_request_id
  WHERE export_row.workspace_id=p_workspace_id
   AND export_row.application_id=p_application_id
   AND export_row.artifact_id=p_artifact_id
   AND export_row.manifest_digest=p_manifest_digest
   AND payload_row.status='complete'
   AND payload_row.payload_digest=p_payload_digest
   AND export_row.retention_status='retained'
   AND payload_row.retention_status='retained'
   AND export_row.expires_at_epoch>
       extract(epoch from clock_timestamp())::bigint
   AND payload_row.expires_at_epoch>
       extract(epoch from clock_timestamp())::bigint
   AND ((export_row.producer_request_id=p_request_id
         AND export_row.producer_claim_generation=p_generation)
        OR export_row.producer_request_id IS NULL
        OR (owner_row.status='Completed'
            AND owner_row.artifact_id=export_row.artifact_id
            AND owner_row.payload_digest=payload_row.payload_digest))
  FOR UPDATE OF export_row,payload_row) THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_PAYLOAD_INCOMPLETE';
 END IF;
 UPDATE epm.fact_export_producer_request AS request_row
 SET status='Completed',artifact_id=p_artifact_id,claimant=NULL,
     lease_until=NULL,payload_digest=p_payload_digest,
     published_at=clock_timestamp(),updated_at=transaction_timestamp()
 WHERE request_row.workspace_id=p_workspace_id
   AND request_row.application_id=p_application_id
   AND request_row.request_id=p_request_id
   AND request_row.status='Publishing'
   AND request_row.claimant=p_worker_id
   AND request_row.claim_generation=p_generation
   AND request_row.lease_until>clock_timestamp()
   AND NOT request_row.cancel_requested;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'EXPORT_PRODUCER_STALE_WORKER';
 END IF;
 RETURN true;
END
$$;
REVOKE ALL ON FUNCTION epm.export_producer_publish_complete(
 text,text,text,text,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.export_producer_publish_complete(
 text,text,text,text,bigint,text,text,text) TO epm_runtime;
