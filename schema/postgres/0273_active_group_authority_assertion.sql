-- Security grant writes must target a group that is currently projected from
-- the same native identity issuer.  Keep directory tables private to the
-- provisioning role and expose only this non-enumerating assertion.
CREATE FUNCTION epm.assert_active_group_authority(
    requested_issuer text, requested_group_id text)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,epm
AS $function$
BEGIN
    IF requested_issuer IS NULL
       OR requested_issuer<>btrim(requested_issuer)
       OR length(requested_issuer) NOT BETWEEN 1 AND 300
       OR requested_issuer ~ '[[:cntrl:]]'
       OR NOT epm.valid_authorization_group_id(requested_group_id)
       OR NOT EXISTS (
          SELECT 1
          FROM epm.identity_group_directory_state AS directory_group
          WHERE directory_group.issuer=requested_issuer
            AND directory_group.group_id=requested_group_id
            AND directory_group.status='Active') THEN
        -- Missing, inactive, and wrong-issuer targets deliberately share one
        -- result so this assertion cannot enumerate the identity directory.
        RAISE EXCEPTION 'GROUP_IDENTITY_UNAVAILABLE'
          USING ERRCODE='P0001';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION epm.assert_active_group_authority(text,text)
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,
       epm_security,epm_lifecycle,epm_provision;
GRANT EXECUTE ON FUNCTION epm.assert_active_group_authority(text,text)
  TO epm_security;
