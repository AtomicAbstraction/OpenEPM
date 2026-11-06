-- Lease-fenced, auditable cleanup of expired technical transfer artifacts.
CREATE TABLE epm.transfer_cleanup_request(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL CHECK(request_id~'^[0-9a-f]{32}$'),
 issuer text NOT NULL,subject_id text NOT NULL,idempotency_key text NOT NULL CHECK(idempotency_key~'^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),batch_limit integer NOT NULL CHECK(batch_limit BETWEEN 1 AND 1000),
 status text NOT NULL CHECK(status IN('Accepted','Running','Completed','Cancelled','Failed')),claim_generation bigint NOT NULL DEFAULT 0,
 claimant text,lease_until timestamptz,result jsonb,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,request_id),UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 CHECK((status='Running')=(claimant IS NOT NULL AND lease_until IS NOT NULL)));
CREATE TABLE epm.transfer_cleanup_certificate(
 workspace_id text NOT NULL,application_id text NOT NULL,request_id text NOT NULL,certificate_digest text NOT NULL CHECK(certificate_digest~'^[0-9a-f]{64}$'),
 deleted_producer_requests integer NOT NULL CHECK(deleted_producer_requests>=0),deleted_diagnostics integer NOT NULL CHECK(deleted_diagnostics>=0),
 deleted_exports integer NOT NULL CHECK(deleted_exports>=0),deleted_payloads integer NOT NULL CHECK(deleted_payloads>=0),certificate jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),PRIMARY KEY(workspace_id,application_id,request_id),
 FOREIGN KEY(workspace_id,application_id,request_id) REFERENCES epm.transfer_cleanup_request(workspace_id,application_id,request_id) ON DELETE RESTRICT);
CREATE FUNCTION epm.transfer_cleanup_certificate_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN RAISE EXCEPTION 'TRANSFER_CLEANUP_CERTIFICATE_IMMUTABLE' USING ERRCODE='23514';END$$;
CREATE TRIGGER transfer_cleanup_certificate_immutable BEFORE UPDATE OR DELETE ON epm.transfer_cleanup_certificate FOR EACH ROW EXECUTE FUNCTION epm.transfer_cleanup_certificate_immutable();
CREATE FUNCTION epm.transfer_cleanup_claim(w text,a text,rid text,who text,seconds integer) RETURNS TABLE(claim_generation bigint,batch_limit integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN
 IF length(who) NOT BETWEEN 1 AND 200 OR seconds NOT BETWEEN 30 AND 300 THEN RAISE EXCEPTION 'TRANSFER_CLEANUP_CLAIM_INVALID';END IF;
 RETURN QUERY UPDATE epm.transfer_cleanup_request r SET status='Running',claim_generation=r.claim_generation+1,claimant=who,
 lease_until=clock_timestamp()+make_interval(secs=>seconds),updated_at=transaction_timestamp()
 WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=rid AND (r.status='Accepted' OR(r.status='Running' AND r.lease_until<=clock_timestamp()))
 RETURNING r.claim_generation,r.batch_limit;END$$;
CREATE FUNCTION epm.transfer_cleanup_execute(w text,a text,rid text,who text,generation bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$DECLARE r epm.transfer_cleanup_request%ROWTYPE;dp integer;dd integer;de integer;dpl integer;cert jsonb;dig text;BEGIN
 SELECT * INTO r FROM epm.transfer_cleanup_request WHERE workspace_id=w AND application_id=a AND request_id=rid FOR UPDATE;
 IF r.status='Completed' THEN RETURN r.result;END IF;
 IF r.status<>'Running' OR r.claimant<>who OR r.claim_generation<>generation OR r.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'TRANSFER_CLEANUP_STALE_WORKER';END IF;
 WITH targets AS(SELECT p.ctid FROM epm.fact_export_producer_request p WHERE p.workspace_id=w AND p.application_id=a AND p.status IN('Cancelled','Failed','Completed') AND p.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint ORDER BY p.created_at LIMIT r.batch_limit),delpages AS(DELETE FROM epm.fact_export_producer_page p USING targets t,epm.fact_export_producer_request q WHERE q.ctid=t.ctid AND p.workspace_id=q.workspace_id AND p.application_id=q.application_id AND p.request_id=q.request_id),deleted AS(DELETE FROM epm.fact_export_producer_request p USING targets t WHERE p.ctid=t.ctid RETURNING 1) SELECT count(*) INTO dp FROM deleted;
 WITH targets AS(SELECT ctid FROM epm.source_import_diagnostic_artifact WHERE workspace_id=w AND application_id=a AND retention_status<>'held' AND(retention_status='expired' OR expires_at_epoch<=extract(epoch from clock_timestamp())::bigint) ORDER BY created_at LIMIT r.batch_limit),deleted AS(DELETE FROM epm.source_import_diagnostic_artifact d USING targets t WHERE d.ctid=t.ctid RETURNING 1) SELECT count(*) INTO dd FROM deleted;
 WITH targets AS(SELECT e.ctid,e.artifact_id FROM epm.fact_export_artifact e WHERE e.workspace_id=w AND e.application_id=a AND e.retention_status<>'held' AND(e.retention_status='expired' OR e.expires_at_epoch<=extract(epoch from clock_timestamp())::bigint) ORDER BY e.created_at LIMIT r.batch_limit),chunks AS(DELETE FROM epm.fact_export_payload_chunk c USING targets t WHERE c.workspace_id=w AND c.application_id=a AND c.artifact_id=t.artifact_id),payloads AS(DELETE FROM epm.fact_export_payload p USING targets t WHERE p.workspace_id=w AND p.application_id=a AND p.artifact_id=t.artifact_id RETURNING 1),exports AS(DELETE FROM epm.fact_export_artifact e USING targets t WHERE e.ctid=t.ctid RETURNING 1) SELECT (SELECT count(*) FROM payloads),(SELECT count(*) FROM exports) INTO dpl,de;
 cert=jsonb_build_object('requestId',rid,'deletedProducerRequests',dp,'deletedDiagnostics',dd,'deletedExports',de,'deletedPayloads',dpl,'batchLimit',r.batch_limit);
 dig=encode(pg_catalog.sha256(convert_to(cert::text,'UTF8')),'hex');
 INSERT INTO epm.transfer_cleanup_certificate VALUES(w,a,rid,dig,dp,dd,de,dpl,cert,transaction_timestamp());
 UPDATE epm.transfer_cleanup_request SET status='Completed',claimant=NULL,lease_until=NULL,result=cert,updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND request_id=rid;RETURN cert;END$$;
CREATE FUNCTION epm.transfer_cleanup_cancel(w text,a text,rid text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$BEGIN
 UPDATE epm.transfer_cleanup_request SET status='Cancelled',claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND request_id=rid AND status IN('Accepted','Running');RETURN FOUND;END$$;
REVOKE ALL ON FUNCTION epm.transfer_cleanup_claim(text,text,text,text,integer),epm.transfer_cleanup_execute(text,text,text,text,bigint),epm.transfer_cleanup_cancel(text,text,text),epm.transfer_cleanup_certificate_immutable() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.transfer_cleanup_claim(text,text,text,text,integer),epm.transfer_cleanup_execute(text,text,text,text,bigint) TO epm_worker;
GRANT EXECUTE ON FUNCTION epm.transfer_cleanup_cancel(text,text,text) TO epm_runtime;
ALTER TABLE epm.transfer_cleanup_request ENABLE ROW LEVEL SECURITY;ALTER TABLE epm.transfer_cleanup_certificate ENABLE ROW LEVEL SECURITY;
CREATE POLICY transfer_cleanup_request_runtime ON epm.transfer_cleanup_request TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY transfer_cleanup_certificate_runtime ON epm.transfer_cleanup_certificate TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.transfer_cleanup_request,epm.transfer_cleanup_certificate FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT,INSERT ON epm.transfer_cleanup_request TO epm_runtime;GRANT SELECT ON epm.transfer_cleanup_certificate TO epm_runtime;
DO $$DECLARE old text:='46fa0ba2e425dc471dd571534e04caf892e2b2f3dd3d0f2b32cd857a3a974734';new text:='2e2dd822dd240379fd3ee7068d7f2c91d5a95dcf197490a4a52cc9d562e6c386';d text;r text;b text:='''planning_assignment_state'',''planning_assignment_version''';a text:='''transfer_cleanup_certificate'',''transfer_cleanup_request'',''planning_assignment_state'',''planning_assignment_version''';BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)INTO d;r=replace(replace(d,old,new),b,a);EXECUTE r;END$$;
