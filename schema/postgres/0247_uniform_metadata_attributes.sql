-- Uniform metadata identity and governed, extensible attribute definitions.
-- Existing CustomNN values remain authoritative and are re-identified by the
-- same immutable Attribute ID; no populated value is rewritten or reinterpreted.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=246) THEN
        RAISE EXCEPTION 'MIGRATION_0247_PREDECESSOR_0246_REQUIRED';
    END IF;
END $migration$;

ALTER TABLE epm.dimension
    ADD COLUMN custom_values jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(custom_values)='object'),
    ADD COLUMN read_security_tags text[] NOT NULL DEFAULT ARRAY[]::text[]
        CHECK (epm.valid_dimensional_security_tag_array(read_security_tags)),
    ADD COLUMN write_security_tags text[] NOT NULL DEFAULT ARRAY[]::text[]
        CHECK (epm.valid_dimensional_security_tag_array(write_security_tags)),
    ADD COLUMN semantic_description text
        GENERATED ALWAYS AS (detailed_description) STORED;

ALTER TABLE epm.member
    ADD COLUMN semantic_description text
        GENERATED ALWAYS AS (detailed_description) STORED;

ALTER TABLE epm.relationship
    ADD COLUMN name text,
    ADD COLUMN short_description text NOT NULL DEFAULT '',
    ADD COLUMN read_security_tags text[] NOT NULL DEFAULT ARRAY[]::text[]
        CHECK (epm.valid_dimensional_security_tag_array(read_security_tags)),
    ADD COLUMN write_security_tags text[] NOT NULL DEFAULT ARRAY[]::text[]
        CHECK (epm.valid_dimensional_security_tag_array(write_security_tags)),
    ADD COLUMN semantic_description text
        GENERATED ALWAYS AS (detailed_description) STORED;

UPDATE epm.relationship SET name=relationship_id WHERE name IS NULL;
ALTER TABLE epm.relationship
    ALTER COLUMN name SET NOT NULL,
    ADD CONSTRAINT relationship_name_valid CHECK (
        length(name) BETWEEN 1 AND 200 AND name=btrim(name)
        AND name !~ E'\\x00'),
    ADD CONSTRAINT relationship_short_description_valid CHECK (
        length(short_description)<=500 AND short_description !~ E'\\x00');
CREATE UNIQUE INDEX relationship_name_per_dimension
    ON epm.relationship(
        workspace_id,application_id,dimension_id,lower(name));

CREATE TABLE epm.attribute_definition (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    scope text NOT NULL CHECK (scope IN ('Dimension','Member','Relationship')),
    -- Empty only for application-wide Dimension-row definitions. Member and
    -- Relationship definitions remain dimension-specific, preserving current
    -- semantic-column meaning and allowing different labels per dimension.
    dimension_id text NOT NULL DEFAULT '',
    attribute_id text NOT NULL CHECK (
        length(attribute_id) BETWEEN 1 AND 200
        AND attribute_id=btrim(attribute_id)
        AND attribute_id ~ '^[A-Za-z][A-Za-z0-9._-]*$'),
    default_name text NOT NULL CHECK (
        length(default_name) BETWEEN 1 AND 200
        AND default_name=btrim(default_name)
        AND default_name !~ E'\\x00'),
    display_name text NOT NULL CHECK (
        length(display_name) BETWEEN 1 AND 200
        AND display_name=btrim(display_name)
        AND display_name !~ E'\\x00'),
    short_description text NOT NULL DEFAULT '' CHECK (
        length(short_description)<=500 AND short_description !~ E'\\x00'),
    semantic_description text NOT NULL DEFAULT '' CHECK (
        length(semantic_description)<=10000
        AND semantic_description !~ E'\\x00'),
    value_type text NOT NULL DEFAULT 'Text'
        CHECK (value_type IN ('Text','Decimal','Boolean','MemberReference')),
    validation_constraints jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(validation_constraints)='object'),
    status text NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active','Inactive')),
    definition_version bigint NOT NULL DEFAULT 1
        CHECK (definition_version>=1),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (
        workspace_id,application_id,scope,dimension_id,attribute_id),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application(workspace_id,application_id)
        ON DELETE RESTRICT,
    CHECK ((scope='Dimension' AND dimension_id='') OR
           (scope IN ('Member','Relationship') AND dimension_id<>''))
);
CREATE UNIQUE INDEX attribute_definition_display_name
    ON epm.attribute_definition(
        workspace_id,application_id,scope,dimension_id,lower(display_name));
CREATE INDEX attribute_definition_catalogue
    ON epm.attribute_definition(
        workspace_id,application_id,status,scope,dimension_id,attribute_id);

CREATE FUNCTION epm.attribute_definition_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
    IF TG_OP='UPDATE' THEN
        IF (NEW.workspace_id,NEW.application_id,NEW.scope,NEW.dimension_id,
            NEW.attribute_id,NEW.default_name) IS DISTINCT FROM
           (OLD.workspace_id,OLD.application_id,OLD.scope,OLD.dimension_id,
            OLD.attribute_id,OLD.default_name) THEN
            RAISE EXCEPTION 'ATTRIBUTE_DEFINITION_IDENTITY_IMMUTABLE';
        END IF;
        NEW.definition_version=OLD.definition_version+1;
        NEW.updated_at=transaction_timestamp();
    END IF;
    IF NEW.scope<>'Dimension' AND NOT EXISTS (
        SELECT 1 FROM epm.dimension d
         WHERE d.workspace_id=NEW.workspace_id
           AND d.application_id=NEW.application_id
           AND d.dimension_id=NEW.dimension_id) THEN
        RAISE EXCEPTION 'ATTRIBUTE_DEFINITION_DIMENSION_UNAVAILABLE';
    END IF;
    RETURN NEW;
END $function$;
CREATE TRIGGER attribute_definition_guard
    BEFORE INSERT OR UPDATE ON epm.attribute_definition
    FOR EACH ROW EXECUTE FUNCTION epm.attribute_definition_guard();

-- Preserve every current definition, including Member slots 21-30. CustomNN
-- is already the immutable key in populated sparse JSON and remains so.
INSERT INTO epm.attribute_definition(
    workspace_id,application_id,scope,dimension_id,attribute_id,
    default_name,display_name,semantic_description,value_type,
    validation_constraints)
SELECT workspace_id,application_id,scope,dimension_id,
       'Custom'||lpad(slot::text,2,'0'),
       'Custom'||lpad(slot::text,2,'0'),display_name,semantic_definition,
       COALESCE(properties->>'valueType','Text'),
       jsonb_strip_nulls(jsonb_build_object(
           'allowedValues',properties->'allowedValues',
           'referenceDimensionId',properties->'referenceDimensionId',
           'populationGuidance',population_guidance,
           'restrictions',restrictions))
  FROM epm.semantic_column;

-- Twenty defaults are a starting catalogue, never a maximum. Do not overwrite
-- any migrated Custom01-Custom30 definition or populated CustomNN value.
INSERT INTO epm.attribute_definition(
    workspace_id,application_id,scope,dimension_id,attribute_id,
    default_name,display_name)
SELECT a.workspace_id,a.application_id,'Dimension','',
       'Custom'||lpad(n::text,2,'0'),
       'Custom'||lpad(n::text,2,'0'),'Custom'||lpad(n::text,2,'0')
  FROM epm.application a CROSS JOIN generate_series(1,20) n
ON CONFLICT DO NOTHING;

INSERT INTO epm.attribute_definition(
    workspace_id,application_id,scope,dimension_id,attribute_id,
    default_name,display_name)
SELECT d.workspace_id,d.application_id,s.scope,d.dimension_id,
       'Custom'||lpad(n::text,2,'0'),
       'Custom'||lpad(n::text,2,'0'),'Custom'||lpad(n::text,2,'0')
  FROM epm.dimension d
  CROSS JOIN (VALUES ('Member'),('Relationship')) s(scope)
  CROSS JOIN generate_series(1,20) n
ON CONFLICT DO NOTHING;

CREATE FUNCTION epm.seed_default_attribute_definitions()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
BEGIN
    IF TG_TABLE_NAME='application' THEN
        INSERT INTO epm.attribute_definition(
            workspace_id,application_id,scope,dimension_id,attribute_id,
            default_name,display_name)
        SELECT NEW.workspace_id,NEW.application_id,'Dimension','',
               'Custom'||lpad(n::text,2,'0'),
               'Custom'||lpad(n::text,2,'0'),
               'Custom'||lpad(n::text,2,'0')
          FROM generate_series(1,20) n;
    ELSE
        INSERT INTO epm.attribute_definition(
            workspace_id,application_id,scope,dimension_id,attribute_id,
            default_name,display_name)
        SELECT NEW.workspace_id,NEW.application_id,s.scope,NEW.dimension_id,
               'Custom'||lpad(n::text,2,'0'),
               'Custom'||lpad(n::text,2,'0'),
               'Custom'||lpad(n::text,2,'0')
          FROM (VALUES ('Member'),('Relationship')) s(scope)
          CROSS JOIN generate_series(1,20) n;
    END IF;
    RETURN NEW;
END $function$;
CREATE TRIGGER application_default_attribute_definitions
    AFTER INSERT ON epm.application FOR EACH ROW
    EXECUTE FUNCTION epm.seed_default_attribute_definitions();
CREATE TRIGGER dimension_default_attribute_definitions
    AFTER INSERT ON epm.dimension FOR EACH ROW
    EXECUTE FUNCTION epm.seed_default_attribute_definitions();
REVOKE ALL ON FUNCTION epm.seed_default_attribute_definitions() FROM PUBLIC;

ALTER TABLE epm.attribute_definition ENABLE ROW LEVEL SECURITY;
CREATE POLICY attribute_definition_scope ON epm.attribute_definition
    TO epm_runtime,epm_analyst
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY attribute_definition_lifecycle_read ON epm.attribute_definition
    FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.attribute_definition
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,
         epm_security,epm_lifecycle;
GRANT SELECT ON epm.attribute_definition TO epm_runtime,epm_analyst,epm_lifecycle;
GRANT INSERT ON epm.attribute_definition TO epm_runtime;
GRANT UPDATE(display_name,short_description,semantic_description,value_type,
             validation_constraints,status,definition_version,updated_at)
    ON epm.attribute_definition TO epm_runtime;
GRANT SELECT(custom_values,read_security_tags,write_security_tags,
             semantic_description) ON epm.dimension TO epm_runtime,epm_analyst;
GRANT UPDATE(custom_values,read_security_tags,write_security_tags)
    ON epm.dimension TO epm_runtime;
GRANT SELECT(name,short_description,read_security_tags,write_security_tags,
             semantic_description) ON epm.relationship TO epm_runtime,epm_analyst;
GRANT UPDATE(name,short_description,read_security_tags,write_security_tags)
    ON epm.relationship TO epm_runtime;

-- Attribute definitions depend on applications and, logically, dimensions.
-- Include them in exact workspace reset before dimensions are removed.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_order text :=
  $pattern$'coordinate','security_tag','dimension',$pattern$;
DECLARE new_order text :=
  $pattern$'coordinate','security_tag','attribute_definition','dimension',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_order IN definition)=0
     OR position(new_order IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0247_DEFINITION_MISMATCH';
  END IF;
  revised:=replace(definition,old_order,new_order);
  IF revised=definition OR position(new_order IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0247_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

-- Derived from the clean schema-247 canonical relation/FK graph after the
-- new catalogue and reset order were reviewed together.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  '04ad5cecabe1afc3e4acc76fa61793e6c29c839630c4eb1fca7010450e20ac6c';
DECLARE new_fingerprint constant text :=
  '1fb2342a6abc2d949593de2b764f018a89cc1134cf0b211482eb9853b3a6fc65';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0247_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0247_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;

COMMENT ON TABLE epm.attribute_definition IS
  'Governed extensible attribute catalogue. Attribute IDs and default names are immutable; twenty defaults are provisioned but are not a maximum.';
COMMENT ON COLUMN epm.dimension.semantic_description IS
  'Uniform generated presentation of the single detailed-description authority.';
COMMENT ON COLUMN epm.member.semantic_description IS
  'Uniform generated presentation of the single detailed-description authority.';
COMMENT ON COLUMN epm.relationship.semantic_description IS
  'Uniform generated presentation of the single detailed-description authority.';
