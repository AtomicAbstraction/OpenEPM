-- Settle only fixed forecast failures that are proven to precede publication.
-- Unknown worker exceptions deliberately retain the running lease for durable
-- inspection/takeover instead of manufacturing a rollback result.
CREATE OR REPLACE FUNCTION epm.forecast_occurrence_worker_settle_rejected(
  p_workspace text,p_application text,p_occurrence text,p_generation bigint,
  p_claimant text,p_error_code text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
  IF p_error_code NOT IN (
      'FORECAST_EXECUTION_AUTHORIZATION_REVOKED','PLANNING_SLICE_LOCKED') THEN
    RAISE EXCEPTION 'FORECAST_WORKER_REJECTION_CODE_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.planning_forecast_occurrence SET status='failed',
    error_code=p_error_code,claimant=NULL,lease_until=NULL,
    updated_at=transaction_timestamp()
   WHERE workspace_id=p_workspace AND application_id=p_application
     AND occurrence_id=p_occurrence
     AND (status='running' OR
          (status='cancel_requested' AND
           p_error_code='FORECAST_EXECUTION_AUTHORIZATION_REVOKED'))
     AND claim_generation=p_generation AND claimant=p_claimant
     AND lease_until>=clock_timestamp();
  GET DIAGNOSTICS changed=ROW_COUNT; RETURN changed=1;
END $$;

REVOKE ALL ON FUNCTION
  epm.forecast_occurrence_worker_settle_rejected(text,text,text,bigint,text,text)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  epm.forecast_occurrence_worker_settle_rejected(text,text,text,bigint,text,text)
  TO epm_worker;
