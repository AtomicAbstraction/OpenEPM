BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=388) THEN
    RAISE EXCEPTION 'MIGRATION_0389_REQUIRES_0388';
  END IF;
END $migration$;

CREATE INDEX calculation_impact_dispatch_order
  ON epm.calculation_impact_progress(updated_at,workspace_id,application_id,impact_epoch)
  WHERE status IN ('pending','failed');

-- Select and fence one contiguous head in the worker transaction. Scope
-- details stay inside the worker role. The scoped processor owns all writes.
CREATE FUNCTION epm.calculation_impact_worker_scope(p_workspace text,p_application text)
RETURNS TABLE(workspace_id text,application_id text,impact_epoch bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
BEGIN
  IF NOT pg_has_role(session_user,'epm_worker','member')
      OR (p_workspace IS NULL) <> (p_application IS NULL) THEN
    RAISE EXCEPTION 'CALCULATION_IMPACT_WORKER_SCOPE_INVALID';
  END IF;
  RETURN QUERY
    SELECT s.workspace_id,s.application_id,p.impact_epoch
    FROM epm.calculation_impact_progress p
    JOIN epm.application_state s ON (s.workspace_id,s.application_id)=(p.workspace_id,p.application_id)
    JOIN epm.application a ON (a.workspace_id,a.application_id)=(s.workspace_id,s.application_id)
    JOIN epm.workspace w ON w.workspace_id=s.workspace_id
    WHERE a.status='Active' AND w.status='Active' AND s.processing_mode='Active'
      AND s.processed_impact_epoch<s.impact_epoch AND p.impact_epoch=s.processed_impact_epoch+1
      AND p.status IN ('pending','failed')
      AND (p.status='pending' OR p.updated_at<=statement_timestamp()-interval '30 seconds')
      AND (p_workspace IS NULL OR (s.workspace_id,s.application_id)=(p_workspace,p_application))
    ORDER BY p.updated_at,p.workspace_id,p.application_id,p.impact_epoch
    LIMIT 1
    FOR SHARE OF w,a SKIP LOCKED
    FOR UPDATE OF s SKIP LOCKED;
END $function$;
REVOKE ALL ON FUNCTION epm.calculation_impact_worker_scope(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.calculation_impact_worker_scope(text,text) TO epm_worker;
COMMIT;
