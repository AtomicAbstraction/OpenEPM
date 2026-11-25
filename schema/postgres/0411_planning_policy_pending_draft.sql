DO $migration$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=410) THEN
  RAISE EXCEPTION 'MIGRATION_0411_REQUIRES_0410';
 END IF;
END $migration$;

-- An active definition remains the only input to the fact guard, duty
-- catalogue and approval workflow. An optional same-ID candidate is inert.
ALTER TABLE epm.cube_write_policy_definition
 ADD COLUMN draft_state_token text,
 ADD COLUMN draft_definition jsonb,
 ADD COLUMN draft_canonical_digest text,
 ADD COLUMN draft_updated_operation_id text,
 ADD COLUMN draft_updated_issuer text,
 ADD COLUMN draft_updated_subject_id text,
 ADD COLUMN draft_updated_at timestamptz,
 ADD CONSTRAINT cube_write_policy_pending_draft_shape CHECK (
   num_nonnulls(draft_state_token,draft_definition,draft_canonical_digest,
     draft_updated_operation_id,draft_updated_issuer,draft_updated_subject_id,draft_updated_at)=0
   OR (
     num_nonnulls(draft_state_token,draft_definition,draft_canonical_digest,
       draft_updated_operation_id,draft_updated_issuer,draft_updated_subject_id,draft_updated_at)=7
     AND status='Active' AND draft_state_token~'^[0-9a-f]{64}$' AND draft_state_token<>state_token
     AND draft_canonical_digest~'^[0-9a-f]{64}$'
     AND jsonb_typeof(draft_definition)='object'
     AND octet_length(draft_definition::text)<=4194304
     AND draft_definition @> jsonb_build_object(
       'workspaceId',workspace_id,'applicationId',application_id,'policyId',policy_id)
     AND NOT draft_definition?'version'
     AND length(draft_updated_issuer) BETWEEN 1 AND 300
     AND length(draft_updated_subject_id) BETWEEN 1 AND 300
   )
 );

-- Model review needs only the existence of an unsettled replacement. Policy
-- definitions, authors and state tokens remain inside the planning lifecycle.
CREATE FUNCTION epm.authorization_migration_has_pending_planning_draft()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT EXISTS(SELECT FROM epm.cube_write_policy_definition
   WHERE workspace_id=current_setting('epm.workspace_id',true)
     AND application_id=current_setting('epm.application_id',true)
     AND status='Active' AND draft_state_token IS NOT NULL)
$body$;
REVOKE ALL ON FUNCTION epm.authorization_migration_has_pending_planning_draft() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.authorization_migration_has_pending_planning_draft() TO epm_security;
