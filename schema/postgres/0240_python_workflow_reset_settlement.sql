-- Safely settle active sealed-plan workflows after an owner-governed reset
-- has quiesced the workspace. The lifecycle role receives only this bounded
-- operation; it cannot update workflows directly.
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=239) THEN
  RAISE EXCEPTION 'MIGRATION_0240_PREDECESSOR_0239_REQUIRED';
 END IF;
END $migration$;

CREATE FUNCTION epm.settle_workspace_reset_python_workflows(
  p_workspace_id text)
RETURNS TABLE(cancelled_workflows bigint,partially_published_workflows bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE workspace_status text; cancelled_count bigint; partial_count bigint;
BEGIN
 IF p_workspace_id IS NULL OR p_workspace_id='' OR
    p_workspace_id<>current_setting('epm.workspace_id',true) THEN
  RAISE EXCEPTION 'RESET_SCOPE_INVALID';
 END IF;
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'RESET_REQUIRES_READ_COMMITTED';
 END IF;
 PERFORM pg_advisory_xact_lock(
  hashtextextended('epm.security.workspace:'||p_workspace_id,0));
 SELECT status INTO workspace_status FROM epm.workspace
  WHERE workspace_id=p_workspace_id;
 IF workspace_status IS DISTINCT FROM 'Maintenance' THEN
  RAISE EXCEPTION 'WORKSPACE_NOT_IN_MAINTENANCE';
 END IF;
 IF (SELECT count(*) FROM epm.python_program_workflow
     WHERE workspace_id=p_workspace_id AND status IN
      ('accepted','running','cancel_requested','needs_inspection'))>1000
 THEN RAISE EXCEPTION 'RESET_ACTIVE_TARGETS_EXCEED_LIMIT'; END IF;

 WITH settled AS (
  UPDATE epm.python_program_workflow SET
   status=CASE WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(
    COALESCE(result->'checkpoints','[]'::jsonb)) checkpoint
    WHERE COALESCE((checkpoint->>'committed')::boolean,false))
    THEN 'partially_published' ELSE 'cancelled' END,
   result=jsonb_set(COALESCE(result,'{}'::jsonb),'{errorCode}',
    to_jsonb('WORKSPACE_RESET_SETTLEMENT'::text)),
   claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
   worker_error_code='WORKSPACE_RESET_SETTLEMENT',
   updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace_id AND status IN
   ('accepted','running','cancel_requested','needs_inspection')
  RETURNING status
 ) SELECT count(*) FILTER(WHERE status='cancelled'),
          count(*) FILTER(WHERE status='partially_published')
   INTO cancelled_count,partial_count FROM settled;
 RETURN QUERY SELECT COALESCE(cancelled_count,0),COALESCE(partial_count,0);
END $function$;

REVOKE ALL ON FUNCTION
 epm.settle_workspace_reset_python_workflows(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 epm.settle_workspace_reset_python_workflows(text) TO epm_lifecycle;
