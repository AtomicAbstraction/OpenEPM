BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=291) THEN
    RAISE EXCEPTION 'MIGRATION_0292_REQUIRES_0291';
  END IF;
END $migration$;

ALTER TABLE epm.python_program_build DROP CONSTRAINT python_program_build_status_check;
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_program_build_status_check
  CHECK (status IN ('accepted','ready','running','sealed','failed',
                   'cancel_requested','cancelled','expired'));
ALTER TABLE epm.python_program_build ADD CONSTRAINT python_impact_expired_purpose
  CHECK (status<>'expired' OR purpose='ImpactTest');
CREATE INDEX python_impact_retention_due ON epm.python_plan_artifact(sealed_at)
  WHERE impact IS NOT NULL;

CREATE OR REPLACE FUNCTION epm.normalized_python_build_task_status(native text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
RETURN CASE native
  WHEN 'accepted' THEN 'Accepted'
  WHEN 'ready' THEN 'Waiting'
  WHEN 'running' THEN 'Running'
  WHEN 'cancel_requested' THEN 'InterruptRequested'
  WHEN 'cancelled' THEN 'Interrupted'
  WHEN 'sealed' THEN 'Succeeded'
  WHEN 'expired' THEN 'Succeeded'
  WHEN 'failed' THEN 'Failed'
END;

-- Keep the small task identity for exact retries/status. Remove the entire
-- private result, plan, source map and build output after one day; no archive,
-- snapshot or cleanup-event stream is created. Plan/Validation artifacts are
-- not selected, and live workflows cannot reference ImpactTest artifacts.
CREATE FUNCTION epm.python_impact_expire()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $function$
DECLARE target record; locked boolean; changed integer:=0;
BEGIN
  FOR target IN
    SELECT a.workspace_id,a.application_id,a.build_id FROM epm.python_plan_artifact a
      JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
      WHERE a.impact IS NOT NULL AND a.sealed_at<clock_timestamp()-interval '24 hours'
        AND b.purpose='ImpactTest' AND b.status='sealed'
      ORDER BY a.sealed_at,a.workspace_id,a.application_id,a.build_id LIMIT 10
  LOOP
    SELECT pg_try_advisory_xact_lock_shared(hashtextextended(
      'epm.security.workspace:' || target.workspace_id,0)) INTO locked;
    IF NOT locked THEN CONTINUE; END IF;
    PERFORM 1 FROM epm.python_program_build b
      WHERE b.workspace_id=target.workspace_id AND b.application_id=target.application_id
        AND b.build_id=target.build_id AND b.purpose='ImpactTest' AND b.status='sealed'
      FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN CONTINUE; END IF;
    DELETE FROM epm.python_plan_artifact a
      WHERE a.workspace_id=target.workspace_id AND a.application_id=target.application_id
        AND a.build_id=target.build_id AND a.impact IS NOT NULL
        AND a.sealed_at<clock_timestamp()-interval '24 hours'
        AND NOT EXISTS (SELECT 1 FROM epm.python_program_workflow w
          WHERE w.workspace_id=a.workspace_id AND w.application_id=a.application_id
            AND w.build_id=a.build_id);
    IF FOUND THEN
      UPDATE epm.python_program_build b SET status='expired',updated_at=transaction_timestamp()
        WHERE b.workspace_id=target.workspace_id AND b.application_id=target.application_id
          AND b.build_id=target.build_id AND b.purpose='ImpactTest' AND b.status='sealed';
      changed:=changed+1;
    END IF;
  END LOOP;
  RETURN changed;
END $function$;
REVOKE ALL ON FUNCTION epm.python_impact_expire() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.python_impact_expire() TO epm_worker;
COMMENT ON FUNCTION epm.python_impact_expire() IS
  'Worker maintenance: delete at most ten completed ImpactTest payloads older than24h; retain request identity only; no business revision or audit archive.';
COMMIT;
