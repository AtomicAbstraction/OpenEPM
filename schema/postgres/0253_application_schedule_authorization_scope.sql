-- Seal unattended execution to server-derived Keycloak groups and the exact
-- effective dimensional authorization scope delegated at creation time.
-- Stored groups are an immutable upper bound; every later use intersects them
-- with the current Keycloak-derived directory projection, so revocation is
-- immediate and newly acquired groups never expand an existing delegation.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=252) THEN
        RAISE EXCEPTION 'MIGRATION_0253_PREDECESSOR_0252_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.execution_delegation_version
    ADD COLUMN verified_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.execution_delegation_version
    ADD CONSTRAINT execution_delegation_verified_groups_check CHECK (
        cardinality(verified_groups)<=100
        AND array_position(verified_groups,NULL) IS NULL),
    ADD CONSTRAINT execution_delegation_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

ALTER TABLE epm.application_schedule_version
    ADD COLUMN execution_groups text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN authorization_scope_digest text NULL;

ALTER TABLE epm.application_schedule_version
    ADD CONSTRAINT application_schedule_execution_groups_check CHECK (
        cardinality(execution_groups)<=100
        AND array_position(execution_groups,NULL) IS NULL),
    ADD CONSTRAINT application_schedule_authorization_scope_digest_check CHECK (
        authorization_scope_digest IS NULL
        OR authorization_scope_digest~'^[0-9a-f]{64}$');

-- Only governed fixed-core delegation creation calls this function.  It does
-- not accept caller-authored groups: it discovers current active membership
-- solely from the Keycloak-derived projection.  Unmanaged/federated groups
-- can be captured only from the target user's already verified token claims
-- by the Python boundary when the target is the current actor.
CREATE FUNCTION epm.managed_identity_groups_for_delegation(
    requested_issuer text, requested_subject_id text)
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL SAFE
SET search_path=pg_catalog,epm
AS $$
    SELECT CASE WHEN epm.identity_subject_active(
            requested_issuer,requested_subject_id)
        THEN coalesce(array_agg(m.group_id ORDER BY m.group_id),
                      ARRAY[]::text[])
        ELSE ARRAY[]::text[] END
    FROM epm.identity_group_membership_state m
    JOIN epm.identity_group_directory_state g
      ON g.issuer=m.issuer AND g.group_id=m.group_id
    WHERE m.issuer=requested_issuer
      AND m.subject_id=requested_subject_id
      AND m.active IS TRUE AND g.status='Active'
$$;

REVOKE ALL ON FUNCTION epm.managed_identity_groups_for_delegation(text,text)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    epm.managed_identity_groups_for_delegation(text,text) TO epm_runtime;

-- A schedule can now be blocked specifically when its immutable delegated
-- authorization scope no longer matches current Keycloak/Open EPM policy.
CREATE OR REPLACE FUNCTION epm.application_schedule_worker_block(
  p_workspace text,p_application text,p_schedule text,p_generation bigint,
  p_claimant text,p_error text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  IF p_error NOT IN('APPLICATION_SCHEDULE_AUTHORITY_INVALID',
                    'APPLICATION_SCHEDULE_AUTHORIZATION_SCOPE_CHANGED',
                    'APPLICATION_SCHEDULE_DEFINITION_CORRUPT') THEN
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

COMMENT ON COLUMN epm.execution_delegation_version.verified_groups IS
    'Immutable server-derived Keycloak group upper bound for unattended execution';
COMMENT ON COLUMN epm.application_schedule_version.execution_groups IS
    'Immutable group claims copied from the exact execution delegation';
COMMENT ON FUNCTION epm.managed_identity_groups_for_delegation(text,text) IS
    'Returns current managed Keycloak groups for fixed-core delegation sealing';
