BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=290) THEN
    RAISE EXCEPTION 'MIGRATION_0291_REQUIRES_0290';
  END IF;
END $migration$;

-- Preserve the same token-revocation boundary as generic application schedules.
-- Historical human versions provide no verified token epoch and stay unusable.
ALTER TABLE epm.python_program_schedule_version
  ADD COLUMN execution_token_issued_at bigint,
  ADD COLUMN execution_authority_kind text NOT NULL DEFAULT 'LegacyUnverified';
UPDATE epm.python_program_schedule_version SET execution_authority_kind='Technical'
  WHERE execution_issuer LIKE 'urn:openepm:%';
ALTER TABLE epm.python_program_schedule_version
  ADD CONSTRAINT python_schedule_token_authority_valid CHECK ((
    (execution_authority_kind='HumanToken' AND execution_token_issued_at>0)
    OR (execution_authority_kind='Technical' AND execution_token_issued_at IS NULL
      AND execution_issuer LIKE 'urn:openepm:%')
    OR (execution_authority_kind='LegacyUnverified' AND execution_token_issued_at IS NULL)) IS TRUE);

UPDATE epm.python_program_schedule_state s SET active_version=NULL,
  dispatch_generation=dispatch_generation+1,dispatch_claimant=NULL,dispatch_lease_until=NULL,
  dispatch_error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',updated_at=transaction_timestamp()
  WHERE s.active_version IS NOT NULL AND EXISTS (
    SELECT 1 FROM epm.python_program_schedule_version v
    WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
      (s.workspace_id,s.application_id,s.schedule_id,s.active_version)
      AND v.execution_authority_kind='LegacyUnverified');
UPDATE epm.python_program_occurrence o SET status='needs_inspection',
  claim_generation=claim_generation+1,claimant=NULL,lease_until=NULL,
  error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',updated_at=transaction_timestamp()
  WHERE o.status IN ('ready','running','building','running_program','cancel_requested')
    AND EXISTS (SELECT 1 FROM epm.python_program_schedule_version v
      WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
        (o.workspace_id,o.application_id,o.schedule_id,o.schedule_version)
        AND v.execution_authority_kind='LegacyUnverified');

GRANT SELECT(workspace_id,application_id,schedule_id,version,
  execution_issuer,execution_subject,execution_token_issued_at,execution_authority_kind)
  ON epm.python_program_schedule_version TO epm_lifecycle;
COMMENT ON COLUMN epm.python_program_schedule_version.execution_token_issued_at IS
  'Verified execution principal token epoch captured at Save; never inferred for another human.';
COMMIT;
