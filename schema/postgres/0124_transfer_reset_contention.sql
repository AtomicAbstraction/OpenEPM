-- Transfer producers and cleanup requests are durable technical work. Completed
-- artifacts, holds and immutable cleanup certificates are deletion inventory,
-- not active-work blockers.
GRANT SELECT(workspace_id,application_id,request_id,status,claim_generation,
 claimant,lease_until,cancel_requested,artifact_id)
 ON epm.fact_export_producer_request TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,request_id,status,claim_generation,
 claimant,lease_until) ON epm.transfer_cleanup_request TO epm_lifecycle;
CREATE POLICY fact_export_producer_request_lifecycle_inventory
 ON epm.fact_export_producer_request FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY transfer_cleanup_request_lifecycle_inventory
 ON epm.transfer_cleanup_request FOR SELECT TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));

-- Certificate history is immutable during ordinary operation. The existing
-- owner-reset primitive supplies a transaction/backend-bound capability so its
-- reviewed child-first deletion can remove the certificate before its request.
CREATE OR REPLACE FUNCTION epm.transfer_cleanup_certificate_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' AND current_setting('epm.projection_cleanup_reset_context',true)=
    jsonb_build_array(OLD.workspace_id,pg_current_xact_id()::text,
                      pg_backend_pid())::text THEN
  RETURN OLD;
 END IF;
 RAISE EXCEPTION 'TRANSFER_CLEANUP_CERTIFICATE_IMMUTABLE' USING ERRCODE='23514';
END$$;

DO $$DECLARE
 d text;r text;
 marker text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gate text:='    IF EXISTS (SELECT 1 FROM epm.transfer_cleanup_request WHERE workspace_id=p_workspace_id AND status IN (''Accepted'',''Running'')) THEN RAISE EXCEPTION ''UNSETTLED_TRANSFER_CLEANUP''; END IF;'||chr(10)||chr(10);
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;
 IF position(marker in d)=0 OR position('UNSETTLED_EXPORT_PRODUCER' in d)=0
 OR position('UNSETTLED_PYTHON_WORKFLOWS' in d)=0
 OR position('UNSETTLED_TRANSFER_CLEANUP' in d)>0
 THEN RAISE EXCEPTION 'RESET_0124_DEFINITION_MISMATCH';END IF;
 r:=replace(d,marker,gate||marker);EXECUTE r;
END$$;
