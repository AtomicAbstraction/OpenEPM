BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=379) THEN
    RAISE EXCEPTION 'MIGRATION_0380_REQUIRES_0379';
  END IF;
END $migration$;

-- Keep current authorization identity and current presentation identity in one
-- governed projection. Existing rows remain valid but unresolved until the
-- next exact Keycloak reconciliation; fixed-core reads never substitute the
-- opaque subject or group identifier for a missing business name.
ALTER TABLE epm.identity_user_directory_state
  ADD COLUMN username text,
  ADD COLUMN display_name text,
  ADD COLUMN principal_digest text,
  ADD CONSTRAINT identity_user_username_valid CHECK(username IS NULL OR
    (length(username) BETWEEN 1 AND 200 AND username=btrim(username)
     AND username !~ '[[:cntrl:]]')),
  ADD CONSTRAINT identity_user_display_name_valid CHECK(display_name IS NULL OR
    (length(display_name) BETWEEN 1 AND 200 AND display_name=btrim(display_name)
     AND display_name !~ '[[:cntrl:]]')),
  ADD CONSTRAINT identity_user_principal_digest_valid CHECK(
    principal_digest IS NULL OR principal_digest ~ '^[0-9a-f]{64}$');

ALTER TABLE epm.identity_group_directory_state
  ADD COLUMN group_name text,
  ADD COLUMN display_name text,
  ADD COLUMN principal_digest text,
  ADD CONSTRAINT identity_group_name_valid CHECK(group_name IS NULL OR
    (length(group_name) BETWEEN 1 AND 200 AND group_name=btrim(group_name)
     AND group_name !~ '[[:cntrl:]]')),
  ADD CONSTRAINT identity_group_display_name_valid CHECK(display_name IS NULL OR
    (length(display_name) BETWEEN 1 AND 200 AND display_name=btrim(display_name)
     AND display_name !~ '[[:cntrl:]]')),
  ADD CONSTRAINT identity_group_principal_digest_valid CHECK(
    principal_digest IS NULL OR principal_digest ~ '^[0-9a-f]{64}$');

CREATE INDEX identity_user_display_current
  ON epm.identity_user_directory_state(issuer,status,lower(display_name),subject_id)
  WHERE display_name IS NOT NULL;
CREATE UNIQUE INDEX identity_user_principal_digest_current
  ON epm.identity_user_directory_state(principal_digest)
  WHERE principal_digest IS NOT NULL;
CREATE UNIQUE INDEX identity_group_principal_digest_current
  ON epm.identity_group_directory_state(principal_digest)
  WHERE principal_digest IS NOT NULL;

CREATE POLICY identity_user_state_security_read
  ON epm.identity_user_directory_state FOR SELECT TO epm_security USING(true);
CREATE POLICY identity_group_state_security_read
  ON epm.identity_group_directory_state FOR SELECT TO epm_security USING(true);
GRANT SELECT ON epm.identity_user_directory_state,
  epm.identity_group_directory_state TO epm_security;

COMMENT ON COLUMN epm.identity_user_directory_state.display_name IS
  'Current Keycloak-governed business display name; never caller-authored by an application administrator';
COMMENT ON COLUMN epm.identity_user_directory_state.principal_digest IS
  'Fixed-core correlation of immutable issuer and subject; not a user-facing identity';
COMMENT ON COLUMN epm.identity_group_directory_state.display_name IS
  'Current Keycloak-governed business display name';

COMMIT;
SELECT '0380 applied' AS migration;
