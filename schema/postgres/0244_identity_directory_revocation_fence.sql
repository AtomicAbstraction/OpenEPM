-- Current-state authorization fence for Keycloak-managed native identities.
--
-- Keycloak remains the identity and membership authority.  This projection is
-- updated only after a governed Keycloak directory operation succeeds and is
-- committed atomically with that operation's Open EPM receipt.  It lets a
-- business transaction reject an already-issued JWT after user, group, or
-- membership revocation instead of waiting for token expiry.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=243) THEN
        RAISE EXCEPTION 'MIGRATION_0244_PREDECESSOR_0243_REQUIRED';
    END IF;
END $migration$;

-- The provision role owns governed directory writes but previously had no
-- reason to execute the group-ID validator introduced with grant storage.
GRANT EXECUTE ON FUNCTION epm.valid_authorization_group_id(text)
    TO epm_provision;

CREATE TABLE epm.identity_directory_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision>=0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
INSERT INTO epm.identity_directory_state(singleton) VALUES (true);

CREATE TABLE epm.identity_user_directory_state (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300
        AND issuer=btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300
        AND subject_id=btrim(subject_id) AND subject_id !~ '[[:cntrl:]]'),
    status text NOT NULL CHECK (status IN ('Active','Inactive')),
    directory_revision bigint NOT NULL CHECK (directory_revision>0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,subject_id)
);

CREATE TABLE epm.identity_group_directory_state (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300
        AND issuer=btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    group_id text NOT NULL CHECK (epm.valid_authorization_group_id(group_id)),
    status text NOT NULL CHECK (status IN ('Active','Inactive')),
    directory_revision bigint NOT NULL CHECK (directory_revision>0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,group_id)
);

CREATE TABLE epm.identity_group_membership_state (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300
        AND issuer=btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 300
        AND subject_id=btrim(subject_id) AND subject_id !~ '[[:cntrl:]]'),
    group_id text NOT NULL CHECK (epm.valid_authorization_group_id(group_id)),
    active boolean NOT NULL,
    directory_revision bigint NOT NULL CHECK (directory_revision>0),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,subject_id,group_id)
);
CREATE INDEX identity_membership_group_current
    ON epm.identity_group_membership_state(issuer,group_id,active,subject_id);

ALTER TABLE epm.identity_directory_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.identity_user_directory_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.identity_group_directory_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.identity_group_membership_state ENABLE ROW LEVEL SECURITY;

CREATE POLICY identity_directory_state_provision
    ON epm.identity_directory_state TO epm_provision
    USING (true) WITH CHECK (true);
CREATE POLICY identity_user_state_provision
    ON epm.identity_user_directory_state TO epm_provision
    USING (true) WITH CHECK (true);
CREATE POLICY identity_group_state_provision
    ON epm.identity_group_directory_state TO epm_provision
    USING (true) WITH CHECK (true);
CREATE POLICY identity_membership_state_provision
    ON epm.identity_group_membership_state TO epm_provision
    USING (true) WITH CHECK (true);

REVOKE ALL ON epm.identity_directory_state,
    epm.identity_user_directory_state,epm.identity_group_directory_state,
    epm.identity_group_membership_state
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,
         epm_security,epm_lifecycle,epm_provision;
GRANT SELECT,INSERT,UPDATE ON epm.identity_directory_state,
    epm.identity_user_directory_state,epm.identity_group_directory_state,
    epm.identity_group_membership_state TO epm_provision;

CREATE FUNCTION epm.identity_subject_active(
    requested_issuer text, requested_subject_id text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
PARALLEL SAFE
SET search_path=pg_catalog,epm
AS $$
    SELECT NOT EXISTS (
        SELECT 1 FROM epm.identity_user_directory_state u
        WHERE u.issuer=requested_issuer
          AND u.subject_id=requested_subject_id
          AND u.status='Inactive')
$$;

CREATE FUNCTION epm.current_identity_groups(
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
        LEFT JOIN epm.identity_group_directory_state g
          ON g.issuer=requested_issuer AND g.group_id=supplied.group_id
        LEFT JOIN epm.identity_group_membership_state m
          ON m.issuer=requested_issuer
         AND m.subject_id=requested_subject_id
         AND m.group_id=supplied.group_id
        WHERE g.group_id IS NULL OR (g.status='Active' AND m.active IS TRUE)
    ) candidate
$$;

REVOKE ALL ON FUNCTION epm.identity_subject_active(text,text),
    epm.current_identity_groups(text,text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.identity_subject_active(text,text),
    epm.current_identity_groups(text,text,text[])
    TO epm_runtime,epm_worker,epm_access,epm_security,epm_lifecycle,
       epm_provision,epm_analyst;

COMMENT ON TABLE epm.identity_group_membership_state IS
    'Keycloak-derived current-membership revocation projection; not an identity authority';
COMMENT ON FUNCTION epm.current_identity_groups(text,text,text[]) IS
    'Intersects verified JWT claims with current managed Keycloak directory state';
