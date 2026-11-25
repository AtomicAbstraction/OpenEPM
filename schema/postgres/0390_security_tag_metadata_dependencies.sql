BEGIN;

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=389) THEN
        RAISE EXCEPTION 'MIGRATION_0390_REQUIRES_0389';
    END IF;
END $migration$;

-- Dimension and relationship Security Strings persist typed tags in the same
-- dimension catalogue. Preserve the existing member and grant checks, and
-- cover both metadata owners in the original status trigger. Existing catalogue
-- rows and assignments are preserved during upgrade.
CREATE OR REPLACE FUNCTION epm.guard_security_tag_status()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
    IF OLD.status='Active' AND NEW.status='Inactive' AND (
        EXISTS (SELECT 1 FROM epm.dimension d
            WHERE (d.workspace_id,d.application_id,d.dimension_id)=
                  (OLD.workspace_id,OLD.application_id,OLD.dimension_id)
              AND (OLD.tag_id=ANY(d.read_security_tags)
                   OR OLD.tag_id=ANY(d.write_security_tags)))
        OR EXISTS (SELECT 1 FROM epm.relationship r
            WHERE (r.workspace_id,r.application_id,r.dimension_id)=
                  (OLD.workspace_id,OLD.application_id,OLD.dimension_id)
              AND (OLD.tag_id=ANY(r.read_security_tags)
                   OR OLD.tag_id=ANY(r.write_security_tags)))
        OR EXISTS (SELECT 1 FROM epm.member m
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

COMMIT;
