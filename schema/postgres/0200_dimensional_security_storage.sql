-- Normalized storage foundation for application-scoped dimensional security.
-- This migration deliberately does not choose the unresolved allow/deny,
-- hierarchy, mixed-selection or administrator-bypass semantics.  No reader or
-- writer is authorized by these fields until one fixed policy resolver is
-- integrated across every source and publication boundary.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=199) THEN
        RAISE EXCEPTION 'MIGRATION_0200_PREDECESSOR_0199_REQUIRED';
    END IF;
END $migration$;

CREATE FUNCTION epm.valid_dimensional_security_tag_array(tags text[])
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path=pg_catalog
AS $$
DECLARE tag text;
DECLARE seen text[] := ARRAY[]::text[];
BEGIN
    IF coalesce(array_ndims(tags),1) <> 1 THEN
        RETURN false;
    END IF;
    FOREACH tag IN ARRAY tags LOOP
        IF tag IS NULL OR tag <> btrim(tag)
           OR char_length(tag) NOT BETWEEN 1 AND 20
           OR position(';' IN tag) <> 0 OR tag = ANY(seen) THEN
            RETURN false;
        END IF;
        seen := array_append(seen,tag);
    END LOOP;
    RETURN true;
END
$$;

CREATE FUNCTION epm.valid_dimensional_security_tag_map(tags jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path=pg_catalog
AS $$
DECLARE dimension_id text;
DECLARE values_json jsonb;
DECLARE values_array text[];
BEGIN
    IF jsonb_typeof(tags) <> 'object' THEN
        RETURN false;
    END IF;
    FOR dimension_id,values_json IN SELECT * FROM jsonb_each(tags) LOOP
        IF char_length(dimension_id) NOT BETWEEN 1 AND 200
           OR dimension_id <> btrim(dimension_id)
           OR jsonb_typeof(values_json) <> 'array'
           OR jsonb_array_length(values_json) = 0 THEN
            RETURN false;
        END IF;
        IF EXISTS (
            SELECT 1 FROM jsonb_array_elements(values_json) AS item(value)
            WHERE jsonb_typeof(value) <> 'string'
        ) THEN
            RETURN false;
        END IF;
        BEGIN
            SELECT array_agg(value ORDER BY ordinal)
              INTO values_array
              FROM jsonb_array_elements_text(values_json)
                   WITH ORDINALITY AS item(value,ordinal);
        EXCEPTION WHEN data_exception THEN
            RETURN false;
        END;
        IF values_array IS NULL
           OR NOT epm.valid_dimensional_security_tag_array(values_array) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END
$$;

REVOKE ALL ON FUNCTION epm.valid_dimensional_security_tag_array(text[])
    FROM PUBLIC;
REVOKE ALL ON FUNCTION epm.valid_dimensional_security_tag_map(jsonb)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.valid_dimensional_security_tag_array(text[])
    TO epm_runtime,epm_security,epm_lifecycle;
GRANT EXECUTE ON FUNCTION epm.valid_dimensional_security_tag_map(jsonb)
    TO epm_security,epm_lifecycle;

ALTER TABLE epm.member
    ADD COLUMN read_security_tags text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD COLUMN write_security_tags text[] NOT NULL DEFAULT ARRAY[]::text[],
    ADD CONSTRAINT member_read_security_tags_valid CHECK (
        epm.valid_dimensional_security_tag_array(read_security_tags)),
    ADD CONSTRAINT member_write_security_tags_valid CHECK (
        epm.valid_dimensional_security_tag_array(write_security_tags));

-- Each verified application's access grant stores assignments keyed by the
-- stable dimension ID.  JSON is the normalized server representation; a UI
-- may render a semicolon-delimited list but that string is never authority.
ALTER TABLE epm.application_access_grant
    ADD COLUMN read_security_tags jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN write_security_tags jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT application_grant_read_security_tags_valid CHECK (
        epm.valid_dimensional_security_tag_map(read_security_tags)),
    ADD CONSTRAINT application_grant_write_security_tags_valid CHECK (
        epm.valid_dimensional_security_tag_map(write_security_tags));

-- Input 502 explicitly withdrew access-combination indexing.  These policy
-- inputs therefore add no fact-side or concatenated-tag index.
