-- Fence already-issued browser/MCP access tokens after password reset or user
-- disable.  Keycloak still owns authentication; this projection makes its
-- administrator-triggered session boundary enforceable by fixed-core access.
DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=267) THEN
    RAISE EXCEPTION 'MIGRATION_0268_PREDECESSOR_0267_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.identity_user_directory_state
  ADD COLUMN tokens_valid_after bigint NOT NULL DEFAULT 0
  CHECK (tokens_valid_after>=0);

CREATE FUNCTION epm.identity_subject_session_valid(
  requested_issuer text, requested_subject_id text, token_issued_at bigint)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER PARALLEL SAFE
SET search_path=pg_catalog,epm AS $$
  SELECT EXISTS (SELECT 1 FROM epm.identity_user_directory_state u
    WHERE u.issuer=requested_issuer AND u.subject_id=requested_subject_id
      AND u.status='Active' AND token_issued_at>u.tokens_valid_after)
$$;
REVOKE ALL ON FUNCTION epm.identity_subject_session_valid(text,text,bigint)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.identity_subject_session_valid(text,text,bigint)
  TO epm_runtime,epm_access,epm_security,epm_lifecycle,epm_provision;

ALTER TABLE epm.job ADD COLUMN token_issued_at bigint;
ALTER TABLE epm.job ADD COLUMN authority_kind text NOT NULL DEFAULT 'LegacyUnverified';
UPDATE epm.job SET status='needs_inspection',error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE status IN ('accepted','ready','running','staged','cancel_requested');
ALTER TABLE epm.job ADD CONSTRAINT job_token_authority_valid CHECK (
  (authority_kind='HumanToken' AND token_issued_at>0)
  OR (authority_kind='Technical' AND token_issued_at IS NULL
      AND issuer LIKE 'urn:openepm:%')
  OR (authority_kind='LegacyUnverified' AND token_issued_at IS NULL));

-- Sequence coordinators submit child jobs after the originating request has
-- returned, so they must retain the same bounded authority as an ordinary job.
-- Historical unsettled rows cannot prove a token issue time and are terminally
-- quarantined instead of being allowed to mint new child work.
ALTER TABLE epm.expression_rule_sequence ADD COLUMN token_issued_at bigint;
ALTER TABLE epm.expression_rule_sequence ADD COLUMN authority_kind text
  NOT NULL DEFAULT 'LegacyUnverified';
UPDATE epm.expression_rule_sequence
   SET status='failed',error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',
       updated_at=transaction_timestamp()
 WHERE status IN ('accepted','running','cancel_requested');
ALTER TABLE epm.expression_rule_sequence
  ADD CONSTRAINT expression_rule_sequence_token_authority_valid CHECK (
    (authority_kind='HumanToken' AND token_issued_at>0)
    OR (authority_kind='Technical' AND token_issued_at IS NULL
        AND issuer LIKE 'urn:openepm:%')
    OR (authority_kind='LegacyUnverified' AND token_issued_at IS NULL));

ALTER TABLE epm.full_aggregate_sequence ADD COLUMN token_issued_at bigint;
ALTER TABLE epm.full_aggregate_sequence ADD COLUMN authority_kind text
  NOT NULL DEFAULT 'LegacyUnverified';
UPDATE epm.full_aggregate_sequence
   SET status='failed',error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',
       updated_at=transaction_timestamp()
 WHERE status IN ('accepted','running','cancel_requested');
ALTER TABLE epm.full_aggregate_sequence
  ADD CONSTRAINT full_aggregate_sequence_token_authority_valid CHECK (
    (authority_kind='HumanToken' AND token_issued_at>0)
    OR (authority_kind='Technical' AND token_issued_at IS NULL
        AND issuer LIKE 'urn:openepm:%')
    OR (authority_kind='LegacyUnverified' AND token_issued_at IS NULL));

-- Generic schedules are durable execution authority: every materialized
-- occurrence can admit a child job long after the publishing request ends.
ALTER TABLE epm.application_schedule_version
  ADD COLUMN execution_token_issued_at bigint;
ALTER TABLE epm.application_schedule_version
  ADD COLUMN execution_authority_kind text NOT NULL DEFAULT 'LegacyUnverified';
UPDATE epm.application_schedule_version
   SET execution_authority_kind='Technical'
 WHERE execution_issuer LIKE 'urn:openepm:%';
ALTER TABLE epm.application_schedule_version
  ADD CONSTRAINT application_schedule_token_authority_valid CHECK (
    (execution_authority_kind='HumanToken'
      AND execution_token_issued_at>0)
    OR (execution_authority_kind='Technical'
      AND execution_token_issued_at IS NULL
      AND execution_issuer LIKE 'urn:openepm:%')
    OR (execution_authority_kind='LegacyUnverified'
      AND execution_token_issued_at IS NULL));

-- Workspace-reset inventory needs only the immutable authority provenance
-- and join keys.  Keep lifecycle access column-scoped rather than widening it
-- to either schedule table.
GRANT SELECT(workspace_id,application_id,schedule_id,version,
  execution_issuer,execution_subject,execution_token_issued_at,
  execution_authority_kind)
  ON epm.application_schedule_version TO epm_lifecycle;
GRANT SELECT(schedule_id,schedule_version)
  ON epm.application_schedule_occurrence TO epm_lifecycle;

-- No historical version proves a human token epoch.  Stop future
-- materialization and quarantine already-created unsettled occurrences.
UPDATE epm.application_schedule_state
   SET active_version=NULL,dispatch_claimant=NULL,dispatch_lease_until=NULL,
       dispatch_error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',
       updated_at=transaction_timestamp()
 WHERE active_version IS NOT NULL
   AND EXISTS (SELECT 1 FROM epm.application_schedule_version v
     WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
       (application_schedule_state.workspace_id,
        application_schedule_state.application_id,
        application_schedule_state.schedule_id,
        application_schedule_state.active_version)
       AND v.execution_authority_kind='LegacyUnverified');
UPDATE epm.application_schedule_occurrence
   SET status='needs_inspection',claimant=NULL,lease_until=NULL,
       next_attempt_at=NULL,error_code='TOKEN_ISSUE_TIME_UNAVAILABLE',
       inspection_origin_status=CASE WHEN status IN
         ('running','submitted','cancel_requested') THEN status ELSE NULL END,
       updated_at=transaction_timestamp()
 WHERE status IN ('ready','running','submitted','cancel_requested')
   AND EXISTS (SELECT 1 FROM epm.application_schedule_version v
     WHERE (v.workspace_id,v.application_id,v.schedule_id,v.version)=
       (application_schedule_occurrence.workspace_id,
        application_schedule_occurrence.application_id,
        application_schedule_occurrence.schedule_id,
        application_schedule_occurrence.schedule_version)
       AND v.execution_authority_kind='LegacyUnverified');

CREATE OR REPLACE FUNCTION epm.application_schedule_worker_block(
  p_workspace text,p_application text,p_schedule text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_error NOT IN('APPLICATION_SCHEDULE_AUTHORITY_INVALID',
                    'APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED',
                    'APPLICATION_SCHEDULE_DEFINITION_CORRUPT',
                    'TOKEN_ISSUE_TIME_UNAVAILABLE',
                    'TECHNICAL_AUTHORITY_INVALID') THEN
    RAISE EXCEPTION 'APPLICATION_SCHEDULE_WORKER_BLOCK_INVALID'
      USING ERRCODE='22023';
  END IF;
  UPDATE epm.application_schedule_state SET dispatch_error_code=p_error,
    dispatch_claimant=NULL,dispatch_lease_until=NULL,
    updated_at=transaction_timestamp()
  WHERE workspace_id=p_workspace AND application_id=p_application
    AND schedule_id=p_schedule AND dispatch_generation=p_generation
    AND dispatch_claimant=p_claimant
    AND dispatch_lease_until>clock_timestamp();
  RETURN FOUND;
END $$;
