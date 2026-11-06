-- Make the current-directory fence authoritative for the native-only profile.
--
-- Migration 0244 deliberately permitted unknown users and groups so an
-- external identity broker could coexist with governed native identities.
-- Google/social brokering is now retired: every admitted subject and group is
-- administrator-created in Keycloak and projected through the governed Open
-- EPM directory adapter. Unknown or inactive objects therefore fail closed.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=262) THEN
        RAISE EXCEPTION 'MIGRATION_0263_PREDECESSOR_0262_REQUIRED';
    END IF;
END $migration$;

-- Preserve current direct-authority principals during the forward upgrade.
-- A complete governed Keycloak reconciliation remains the authority that can
-- remove a subject absent from the directory. Do not reactivate an explicitly
-- inactive projected subject.
DO $migration$
DECLARE next_revision bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('epm.identity.directory.reconcile',0));
    UPDATE epm.identity_directory_state
       SET revision=revision+1,updated_at=transaction_timestamp()
     WHERE singleton
     RETURNING revision INTO next_revision;
    IF next_revision IS NULL THEN
        RAISE EXCEPTION 'IDENTITY_DIRECTORY_STATE_MISSING';
    END IF;
    INSERT INTO epm.identity_user_directory_state
        (issuer,subject_id,status,directory_revision)
    SELECT DISTINCT principal.issuer,principal.subject_id,'Active',next_revision
    FROM (
        SELECT issuer,subject_id FROM epm.platform_operator_grant
        UNION SELECT issuer,subject_id FROM epm.workspace_access_grant
        UNION SELECT issuer,subject_id FROM epm.application_access_grant
        UNION SELECT issuer,subject_id FROM epm.rule_access_grant
    ) principal
    ON CONFLICT (issuer,subject_id) DO NOTHING;
END $migration$;

CREATE OR REPLACE FUNCTION epm.identity_subject_active(
    requested_issuer text, requested_subject_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL SAFE
SET search_path=pg_catalog,epm
AS $$
    SELECT EXISTS (
        SELECT 1 FROM epm.identity_user_directory_state u
        WHERE u.issuer=requested_issuer
          AND u.subject_id=requested_subject_id
          AND u.status='Active')
$$;

CREATE OR REPLACE FUNCTION epm.current_identity_groups(
    requested_issuer text, requested_subject_id text, token_groups text[])
RETURNS text[]
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL SAFE
SET search_path=pg_catalog,epm
AS $$
    SELECT CASE WHEN epm.identity_subject_active(
            requested_issuer,requested_subject_id)
        THEN coalesce(array_agg(candidate.group_id ORDER BY candidate.group_id),
                      ARRAY[]::text[])
        ELSE ARRAY[]::text[] END
    FROM (
        SELECT DISTINCT supplied.group_id
        FROM unnest(coalesce(token_groups,ARRAY[]::text[]))
            AS supplied(group_id)
        JOIN epm.identity_group_directory_state g
          ON g.issuer=requested_issuer
         AND g.group_id=supplied.group_id
         AND g.status='Active'
        JOIN epm.identity_group_membership_state m
          ON m.issuer=requested_issuer
         AND m.subject_id=requested_subject_id
         AND m.group_id=supplied.group_id
         AND m.active IS TRUE
    ) candidate
$$;

COMMENT ON FUNCTION epm.identity_subject_active(text,text) IS
    'Native-only current-directory fence; unknown and inactive subjects are denied';
COMMENT ON FUNCTION epm.current_identity_groups(text,text,text[]) IS
    'Intersects verified JWT claims with active governed Keycloak groups and memberships';
