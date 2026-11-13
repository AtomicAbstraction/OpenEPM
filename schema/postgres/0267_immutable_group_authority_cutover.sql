-- One bounded cutover from mutable Keycloak names to immutable group UUIDs.
DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=266) THEN
        RAISE EXCEPTION 'MIGRATION_0267_PREDECESSOR_0266_REQUIRED';
    END IF;
END $migration$;

CREATE TABLE epm.group_authority_uuid_cutover (
    issuer text PRIMARY KEY,
    mapping_digest text NOT NULL CHECK (mapping_digest ~ '^[0-9a-f]{64}$'),
    migrated_rows bigint NOT NULL CHECK (migrated_rows>=0),
    completed_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
REVOKE ALL ON epm.group_authority_uuid_cutover FROM PUBLIC;

CREATE FUNCTION epm.apply_group_authority_uuid_cutover(
    requested_issuer text, requested_mapping jsonb, requested_digest text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,epm
AS $function$
DECLARE prior record; item record; changed bigint := 0; n bigint;
DECLARE legacy_present boolean;
BEGIN
    IF NOT pg_has_role(session_user,'epm_provision','member') THEN
        RAISE EXCEPTION 'GROUP_AUTHORITY_CUTOVER_CALLER_FORBIDDEN';
    END IF;
    IF requested_issuer IS NULL OR requested_issuer<>btrim(requested_issuer)
       OR length(requested_issuer) NOT BETWEEN 1 AND 300
       OR requested_issuer ~ '[[:cntrl:]]'
       OR jsonb_typeof(requested_mapping)<>'object'
       OR jsonb_typeof(requested_mapping->'mappings')<>'array'
       OR jsonb_typeof(requested_mapping->'immutable_group_ids')<>'array'
       OR requested_digest !~ '^[0-9a-f]{64}$'
       OR requested_digest<>encode(pg_catalog.sha256(
            convert_to(requested_mapping::text,'UTF8')),'hex') THEN
        RAISE EXCEPTION 'GROUP_AUTHORITY_MAPPING_INVALID';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'epm.group-authority:' || requested_issuer,0));
    IF EXISTS (SELECT 1 FROM jsonb_to_recordset(requested_mapping->'mappings')
          AS m(legacy_group_name text,immutable_group_id text)
        WHERE m.legacy_group_name IS NULL OR m.immutable_group_id IS NULL
           OR NOT epm.valid_authorization_group_id(m.legacy_group_name)
           OR NOT epm.valid_authorization_group_id(m.immutable_group_id)
           OR m.legacy_group_name=m.immutable_group_id)
       OR EXISTS (SELECT legacy_group_name FROM jsonb_to_recordset(
             requested_mapping->'mappings') AS m(legacy_group_name text)
           GROUP BY legacy_group_name HAVING count(*)>1)
       OR EXISTS (SELECT immutable_group_id FROM jsonb_to_recordset(
             requested_mapping->'mappings') AS m(immutable_group_id text)
           GROUP BY immutable_group_id HAVING count(*)>1)
       OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
             requested_mapping->'immutable_group_ids') AS i(group_id)
           WHERE NOT epm.valid_authorization_group_id(i.group_id)) THEN
        RAISE EXCEPTION 'GROUP_AUTHORITY_MAPPING_INVALID';
    END IF;
    IF EXISTS (
      SELECT group_id FROM (
        SELECT group_id FROM epm.workspace_group_access_grant WHERE issuer=requested_issuer
        UNION SELECT group_id FROM epm.application_group_access_grant WHERE issuer=requested_issuer
        UNION SELECT group_id FROM epm.rule_group_access_grant WHERE issuer=requested_issuer
      ) observed
      WHERE group_id NOT IN (SELECT jsonb_array_elements_text(requested_mapping->'immutable_group_ids'))
        AND group_id NOT IN (SELECT legacy_group_name FROM jsonb_to_recordset(
          requested_mapping->'mappings') AS m(legacy_group_name text))) THEN
        RAISE EXCEPTION 'GROUP_AUTHORITY_MAPPING_MISSING';
    END IF;
    SELECT EXISTS (
      SELECT 1 FROM (
        SELECT group_id FROM epm.workspace_group_access_grant WHERE issuer=requested_issuer
        UNION SELECT group_id FROM epm.application_group_access_grant WHERE issuer=requested_issuer
        UNION SELECT group_id FROM epm.rule_group_access_grant WHERE issuer=requested_issuer
      ) observed
      WHERE group_id IN (SELECT legacy_group_name FROM jsonb_to_recordset(
        requested_mapping->'mappings') AS m(legacy_group_name text)))
      INTO legacy_present;
    SELECT * INTO prior FROM epm.group_authority_uuid_cutover
      WHERE issuer=requested_issuer;
    IF FOUND THEN
        IF NOT legacy_present THEN RETURN 0; END IF;
        RAISE EXCEPTION 'GROUP_AUTHORITY_CUTOVER_ALREADY_COMPLETED';
    END IF;
    FOR item IN SELECT * FROM jsonb_to_recordset(requested_mapping->'mappings')
      AS m(legacy_group_name text,immutable_group_id text) ORDER BY legacy_group_name LOOP
      IF EXISTS (SELECT 1 FROM epm.workspace_group_access_grant a JOIN epm.workspace_group_access_grant b
          ON b.issuer=a.issuer AND b.workspace_id=a.workspace_id AND b.group_id=item.immutable_group_id
          WHERE a.issuer=requested_issuer AND a.group_id=item.legacy_group_name)
       OR EXISTS (SELECT 1 FROM epm.application_group_access_grant a JOIN epm.application_group_access_grant b
          ON b.issuer=a.issuer AND b.workspace_id=a.workspace_id AND b.application_id=a.application_id
         AND b.group_id=item.immutable_group_id WHERE a.issuer=requested_issuer AND a.group_id=item.legacy_group_name)
       OR EXISTS (SELECT 1 FROM epm.rule_group_access_grant a JOIN epm.rule_group_access_grant b
          ON b.issuer=a.issuer AND b.workspace_id=a.workspace_id AND b.application_id=a.application_id
         AND b.group_id=item.immutable_group_id WHERE a.issuer=requested_issuer AND a.group_id=item.legacy_group_name) THEN
        RAISE EXCEPTION 'GROUP_AUTHORITY_TARGET_COLLISION';
      END IF;
      UPDATE epm.workspace_group_access_grant SET group_id=item.immutable_group_id
        WHERE issuer=requested_issuer AND group_id=item.legacy_group_name;
      GET DIAGNOSTICS n=ROW_COUNT; changed:=changed+n;
      UPDATE epm.application_group_access_grant SET group_id=item.immutable_group_id
        WHERE issuer=requested_issuer AND group_id=item.legacy_group_name;
      GET DIAGNOSTICS n=ROW_COUNT; changed:=changed+n;
      UPDATE epm.rule_group_access_grant SET group_id=item.immutable_group_id
        WHERE issuer=requested_issuer AND group_id=item.legacy_group_name;
      GET DIAGNOSTICS n=ROW_COUNT; changed:=changed+n;
    END LOOP;
    INSERT INTO epm.group_authority_uuid_cutover(issuer,mapping_digest,migrated_rows)
      VALUES(requested_issuer,requested_digest,changed);
    RETURN changed;
END
$function$;
REVOKE ALL ON FUNCTION epm.apply_group_authority_uuid_cutover(text,jsonb,text)
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,epm_security,
       epm_lifecycle,epm_provision;
GRANT EXECUTE ON FUNCTION epm.apply_group_authority_uuid_cutover(text,jsonb,text)
  TO epm_provision;

-- The cutover receipt is global security history, not workspace-owned data.
-- Update the exact reset-schema fingerprint only after reviewing that it has
-- no workspace key or incoming reference and therefore must survive an owner
-- workspace reset.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '1fb2342a6abc2d949593de2b764f018a89cc1134cf0b211482eb9853b3a6fc65';
DECLARE new_fingerprint constant text :=
  'cf777fea26c62979a597561aed109311ecd2bf19b7d694df5db2e70cac6c8ca0';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0267_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0267_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
