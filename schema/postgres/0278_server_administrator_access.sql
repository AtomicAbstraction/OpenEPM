BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=277) THEN
    RAISE EXCEPTION 'MIGRATION_0278_REQUIRES_0277';
  END IF;
END $migration$;

-- A current Server Administrator may delegate the same bounded platform
-- authority to an active native-directory subject, or revoke it later.  Keep
-- the table itself non-writable by the provision service: this fixed function
-- owns the global serialization, current-caller recheck, last-administrator
-- guard and immediate bearer-session fence.
CREATE FUNCTION epm.set_server_administrator_access(
  p_actor_issuer text,
  p_actor_subject text,
  p_target_issuer text,
  p_target_subject text,
  p_grant boolean)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  changed boolean := false;
  administrator_count bigint;
  target_active boolean;
BEGIN
  IF NOT pg_has_role(session_user, 'epm_provision', 'member') THEN
    RAISE EXCEPTION 'SERVER_ADMINISTRATOR_SERVICE_REQUIRED'
      USING ERRCODE = '42501';
  END IF;
  IF p_actor_issuer IS NULL OR p_actor_subject IS NULL
      OR p_target_issuer IS NULL OR p_target_subject IS NULL
      OR p_actor_issuer = '' OR p_actor_subject = ''
      OR p_target_issuer = '' OR p_target_subject = ''
      OR p_grant IS NULL THEN
    RAISE EXCEPTION 'SERVER_ADMINISTRATOR_ACCESS_INVALID'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(
    hashtextextended('epm.server-administrator-access', 0));

  IF NOT EXISTS (
      SELECT 1 FROM epm.platform_operator_grant
      WHERE issuer = p_actor_issuer AND subject_id = p_actor_subject) THEN
    RAISE EXCEPTION 'PLATFORM_OPERATOR_REQUIRED'
      USING ERRCODE = '42501';
  END IF;

  SELECT EXISTS (
    SELECT 1 FROM epm.identity_user_directory_state
    WHERE issuer = p_target_issuer AND subject_id = p_target_subject
      AND status = 'Active') INTO target_active;
  IF NOT target_active THEN
    RAISE EXCEPTION 'SERVER_ADMINISTRATOR_TARGET_NOT_ACTIVE'
      USING ERRCODE = '22023';
  END IF;

  IF p_grant THEN
    INSERT INTO epm.platform_operator_grant(issuer, subject_id)
      VALUES (p_target_issuer, p_target_subject)
      ON CONFLICT DO NOTHING;
    changed := FOUND;
  ELSE
    IF (p_actor_issuer, p_actor_subject) =
        (p_target_issuer, p_target_subject) THEN
      RAISE EXCEPTION 'SERVER_ADMINISTRATOR_SELF_REVOKE_FORBIDDEN'
        USING ERRCODE = '22023';
    END IF;
    IF EXISTS (
        SELECT 1 FROM epm.platform_operator_grant
        WHERE issuer = p_target_issuer AND subject_id = p_target_subject) THEN
      SELECT count(*) INTO administrator_count
        FROM epm.platform_operator_grant;
      IF administrator_count <= 1 THEN
        RAISE EXCEPTION 'LAST_SERVER_ADMINISTRATOR_REQUIRED'
          USING ERRCODE = '22023';
      END IF;
      DELETE FROM epm.platform_operator_grant
        WHERE issuer = p_target_issuer AND subject_id = p_target_subject;
      changed := FOUND;
      UPDATE epm.identity_user_directory_state
        SET tokens_valid_after = greatest(tokens_valid_after,
              extract(epoch FROM clock_timestamp())::bigint),
            updated_at = transaction_timestamp()
        WHERE issuer = p_target_issuer AND subject_id = p_target_subject;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'SERVER_ADMINISTRATOR_TARGET_NOT_ACTIVE'
          USING ERRCODE = '22023';
      END IF;
    END IF;
  END IF;

  RETURN jsonb_build_object(
    'issuer', p_target_issuer,
    'subjectId', p_target_subject,
    'access', CASE WHEN p_grant THEN 'Granted' ELSE 'Revoked' END,
    'changed', changed);
END
$function$;

REVOKE ALL ON FUNCTION epm.set_server_administrator_access(
  text, text, text, text, boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.set_server_administrator_access(
  text, text, text, text, boolean) TO epm_provision;

COMMENT ON FUNCTION epm.set_server_administrator_access(
  text, text, text, text, boolean) IS
  'Serialized current-operator delegation/revocation with active-target, self-revocation, last-administrator and bearer-session safeguards';

COMMIT;
