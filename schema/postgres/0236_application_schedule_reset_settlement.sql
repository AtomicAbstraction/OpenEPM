-- Surface and safely settle generic application-schedule work during an
-- owner-governed workspace reset.  The lifecycle role receives EXECUTE only;
-- it cannot issue arbitrary schedule updates.
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=235) THEN
  RAISE EXCEPTION 'MIGRATION_0236_PREDECESSOR_0235_REQUIRED';
 END IF;
END $migration$;

CREATE FUNCTION epm.settle_workspace_reset_application_schedules(
  p_workspace_id text)
RETURNS TABLE(cancelled_occurrences bigint,cleared_dispatch_claims bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE workspace_status text; occurrence_count bigint; dispatch_count bigint;
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
 IF (SELECT count(*) FROM epm.application_schedule_occurrence
     WHERE workspace_id=p_workspace_id AND status IN
      ('ready','running','submitted','cancel_requested','needs_inspection'))>1000
    OR (SELECT count(*) FROM epm.application_schedule_state
        WHERE workspace_id=p_workspace_id AND dispatch_claimant IS NOT NULL)>1000
 THEN RAISE EXCEPTION 'RESET_ACTIVE_TARGETS_EXCEED_LIMIT'; END IF;

 UPDATE epm.application_schedule_occurrence SET status='cancelled',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  next_attempt_at=NULL,error_code='WORKSPACE_RESET_SETTLEMENT',
  updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace_id AND status IN
  ('ready','running','submitted','cancel_requested','needs_inspection');
 GET DIAGNOSTICS occurrence_count=ROW_COUNT;

 UPDATE epm.application_schedule_state SET
  dispatch_generation=dispatch_generation+1,dispatch_claimant=NULL,
  dispatch_lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=p_workspace_id AND dispatch_claimant IS NOT NULL;
 GET DIAGNOSTICS dispatch_count=ROW_COUNT;
 RETURN QUERY SELECT occurrence_count,dispatch_count;
END $function$;

REVOKE ALL ON FUNCTION
 epm.settle_workspace_reset_application_schedules(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
 epm.settle_workspace_reset_application_schedules(text) TO epm_lifecycle;
