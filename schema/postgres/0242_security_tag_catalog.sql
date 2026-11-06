-- First-class application security-tag catalogue. Stable tag IDs remain
-- Open EPM metadata; Keycloak supplies identities/groups but never defines
-- cube-coordinate meaning. Existing typed arrays are backfilled before strict
-- catalogue-reference triggers are enabled.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=241) THEN
        RAISE EXCEPTION 'MIGRATION_0242_PREDECESSOR_0241_REQUIRED';
    END IF;
END $migration$;

CREATE TABLE epm.security_tag (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    dimension_id text NOT NULL,
    tag_id text NOT NULL CHECK (
        epm.valid_dimensional_security_tag_array(ARRAY[tag_id])),
    display_name text NOT NULL CHECK (
        length(display_name) BETWEEN 1 AND 200
        AND display_name=btrim(display_name)
        AND display_name !~ '[[:cntrl:]]'),
    short_description text NOT NULL DEFAULT '' CHECK (
        length(short_description)<=500 AND short_description !~ E'\\x00'),
    semantic_description text NOT NULL DEFAULT '' CHECK (
        length(semantic_description)<=10000
        AND semantic_description !~ E'\\x00'),
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active','Inactive')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,dimension_id,tag_id),
    FOREIGN KEY (workspace_id,application_id,dimension_id)
        REFERENCES epm.dimension(workspace_id,application_id,dimension_id)
        ON DELETE RESTRICT
);
CREATE INDEX security_tag_catalogue_list
    ON epm.security_tag(
        workspace_id,application_id,dimension_id,status,tag_id);

-- Preserve every tag already used by members, direct grants or group grants.
-- The catalogue is descriptive metadata; this backfill changes no assignment
-- and therefore has no authorization effect.
WITH used_tag AS (
    SELECT m.workspace_id,m.application_id,m.dimension_id,
           unnest(m.read_security_tags || m.write_security_tags) tag_id
      FROM epm.member m
    UNION
    SELECT g.workspace_id,g.application_id,a.key dimension_id,
           jsonb_array_elements_text(a.value) tag_id
      FROM epm.application_access_grant g
      CROSS JOIN LATERAL jsonb_each(g.read_security_tags) a
    UNION
    SELECT g.workspace_id,g.application_id,a.key dimension_id,
           jsonb_array_elements_text(a.value) tag_id
      FROM epm.application_access_grant g
      CROSS JOIN LATERAL jsonb_each(g.write_security_tags) a
    UNION
    SELECT g.workspace_id,g.application_id,a.key dimension_id,
           jsonb_array_elements_text(a.value) tag_id
      FROM epm.application_group_access_grant g
      CROSS JOIN LATERAL jsonb_each(g.read_security_tags) a
    UNION
    SELECT g.workspace_id,g.application_id,a.key dimension_id,
           jsonb_array_elements_text(a.value) tag_id
      FROM epm.application_group_access_grant g
      CROSS JOIN LATERAL jsonb_each(g.write_security_tags) a
)
INSERT INTO epm.security_tag(
    workspace_id,application_id,dimension_id,tag_id,display_name)
SELECT DISTINCT workspace_id,application_id,dimension_id,tag_id,tag_id
  FROM used_tag
 WHERE tag_id<>''
ON CONFLICT DO NOTHING;

CREATE FUNCTION epm.enforce_security_tag_catalogue()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
    IF TG_TABLE_NAME='member' THEN
        IF EXISTS (
            SELECT 1 FROM unnest(
                NEW.read_security_tags || NEW.write_security_tags)
                AS requested(tag_id)
            WHERE NOT EXISTS (
                SELECT 1 FROM epm.security_tag c
                 WHERE c.workspace_id=NEW.workspace_id
                   AND c.application_id=NEW.application_id
                   AND c.dimension_id=NEW.dimension_id
                   AND c.tag_id=requested.tag_id
                   AND c.status='Active')) THEN
            RAISE EXCEPTION 'SECURITY_TAG_NOT_CATALOGUED';
        END IF;
    ELSE
        IF EXISTS (
            SELECT 1
              FROM (
                  SELECT key,value FROM jsonb_each(NEW.read_security_tags)
                  UNION ALL
                  SELECT key,value FROM jsonb_each(NEW.write_security_tags)
              ) axis
              CROSS JOIN LATERAL jsonb_array_elements_text(axis.value)
                  AS requested(tag_id)
             WHERE NOT EXISTS (
                SELECT 1 FROM epm.security_tag c
                 WHERE c.workspace_id=NEW.workspace_id
                   AND c.application_id=NEW.application_id
                   AND c.dimension_id=axis.key
                   AND c.tag_id=requested.tag_id
                   AND c.status='Active')) THEN
            RAISE EXCEPTION 'SECURITY_TAG_NOT_CATALOGUED';
        END IF;
    END IF;
    RETURN NEW;
END $function$;

CREATE FUNCTION epm.guard_security_tag_status()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
    IF OLD.status='Active' AND NEW.status='Inactive' AND (
        EXISTS (SELECT 1 FROM epm.member m
            WHERE m.workspace_id=OLD.workspace_id
              AND m.application_id=OLD.application_id
              AND m.dimension_id=OLD.dimension_id
              AND (OLD.tag_id=ANY(m.read_security_tags)
                   OR OLD.tag_id=ANY(m.write_security_tags)))
        OR EXISTS (SELECT 1 FROM epm.application_access_grant g
            WHERE g.workspace_id=OLD.workspace_id
              AND g.application_id=OLD.application_id
              AND ((g.read_security_tags->OLD.dimension_id) ? OLD.tag_id
                   OR (g.write_security_tags->OLD.dimension_id) ? OLD.tag_id))
        OR EXISTS (SELECT 1 FROM epm.application_group_access_grant g
            WHERE g.workspace_id=OLD.workspace_id
              AND g.application_id=OLD.application_id
              AND ((g.read_security_tags->OLD.dimension_id) ? OLD.tag_id
                   OR (g.write_security_tags->OLD.dimension_id) ? OLD.tag_id))
    ) THEN
        RAISE EXCEPTION 'SECURITY_TAG_IN_USE';
    END IF;
    NEW.updated_at=transaction_timestamp();
    RETURN NEW;
END $function$;

CREATE TRIGGER member_security_tag_catalogue_guard
    BEFORE INSERT OR UPDATE OF read_security_tags,write_security_tags
    ON epm.member FOR EACH ROW
    EXECUTE FUNCTION epm.enforce_security_tag_catalogue();
CREATE TRIGGER application_grant_security_tag_catalogue_guard
    BEFORE INSERT OR UPDATE OF read_security_tags,write_security_tags
    ON epm.application_access_grant FOR EACH ROW
    EXECUTE FUNCTION epm.enforce_security_tag_catalogue();
CREATE TRIGGER application_group_grant_security_tag_catalogue_guard
    BEFORE INSERT OR UPDATE OF read_security_tags,write_security_tags
    ON epm.application_group_access_grant FOR EACH ROW
    EXECUTE FUNCTION epm.enforce_security_tag_catalogue();
CREATE TRIGGER security_tag_status_guard
    BEFORE UPDATE OF status ON epm.security_tag FOR EACH ROW
    EXECUTE FUNCTION epm.guard_security_tag_status();

ALTER TABLE epm.security_tag ENABLE ROW LEVEL SECURITY;
CREATE POLICY security_tag_runtime_scope ON epm.security_tag
    TO epm_runtime USING (
        workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (
        workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY security_tag_security_read ON epm.security_tag
    FOR SELECT TO epm_security USING (
        workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY security_tag_lifecycle_read ON epm.security_tag
    FOR SELECT TO epm_lifecycle USING (
        workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.security_tag
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,
         epm_security,epm_lifecycle;
GRANT SELECT,INSERT ON epm.security_tag TO epm_runtime;
GRANT UPDATE(display_name,short_description,semantic_description,status,
             updated_at) ON epm.security_tag TO epm_runtime;
GRANT SELECT ON epm.security_tag TO epm_security,epm_lifecycle;

-- Catalogue rows depend on dimensions and must be removed first.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_order text :=
  $pattern$'full_aggregate_sequence','coordinate','dimension',$pattern$;
DECLARE new_order text :=
  $pattern$'full_aggregate_sequence','coordinate','security_tag','dimension',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_order IN definition)=0
     OR position(new_order IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0242_DEFINITION_MISMATCH';
  END IF;
  revised:=replace(definition,old_order,new_order);
  IF revised=definition OR position(new_order IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0242_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

-- Derived from isolated canonical relation/FK graph inspection after applying
-- this migration to a clean database. The fixed-core verifier pins the same
-- identity; a later structural change must derive and review a new value.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '8e68ae31e4fa93c377f3df269c40f3d57fd0acfd87c957250d78a2d549258336';
DECLARE new_fingerprint constant text :=
  '04ad5cecabe1afc3e4acc76fa61793e6c29c839630c4eb1fca7010450e20ac6c';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0242_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0242_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
