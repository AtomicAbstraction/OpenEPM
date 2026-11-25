BEGIN;

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=393) THEN
        RAISE EXCEPTION 'MIGRATION_0394_REQUIRES_0393';
    END IF;
END $migration$;

-- The dimension owns its untouched attribute placeholders. Runtime does not
-- get DELETE on attribute definitions. Edited and additional definitions
-- must survive a refused dimension deletion.
CREATE FUNCTION epm.remove_dimension_seeded_attributes()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    DELETE FROM epm.attribute_definition
    WHERE workspace_id=OLD.workspace_id AND application_id=OLD.application_id
      AND dimension_id=OLD.dimension_id AND scope IN ('Member','Relationship')
      AND attribute_id ~ '^Custom(0[1-9]|1[0-9]|20)$'
      AND default_name=attribute_id AND display_name=attribute_id
      AND short_description='' AND semantic_description=''
      AND value_type='Text' AND validation_constraints='{}'::jsonb
      AND status='Active' AND created_at=updated_at;

    IF EXISTS (SELECT 1 FROM epm.attribute_definition
        WHERE workspace_id=OLD.workspace_id AND application_id=OLD.application_id
          AND dimension_id=OLD.dimension_id AND scope IN ('Member','Relationship')) THEN
        RAISE EXCEPTION 'DIMENSION_HAS_ATTRIBUTE_DEFINITIONS'
            USING ERRCODE='23514', CONSTRAINT='dimension_owned_attribute_definitions';
    END IF;
    RETURN OLD;
END $function$;

REVOKE ALL ON FUNCTION epm.remove_dimension_seeded_attributes() FROM PUBLIC;
CREATE TRIGGER dimension_seeded_attribute_cleanup
    BEFORE DELETE ON epm.dimension FOR EACH ROW
    EXECUTE FUNCTION epm.remove_dimension_seeded_attributes();

COMMIT;
