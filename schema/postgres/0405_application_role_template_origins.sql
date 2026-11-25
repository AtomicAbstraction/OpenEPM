DO $migration$ BEGIN
    IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=404) THEN
        RAISE EXCEPTION 'MIGRATION_0405_REQUIRES_0404';
    END IF;
END $migration$;

-- Existing roles remain independent. No definitions, group assignments or
-- action/scope bindings change merely by upgrading the application software.
ALTER TABLE epm.application_authorization_role ADD COLUMN template_origin jsonb
 CHECK (template_origin IS NULL OR (
    jsonb_typeof(template_origin)='object'
    AND template_origin ?& ARRAY['templateId','version','upstreamName','upstreamActions',
                                 'nameOverridden','addedActions','removedActions']
    AND template_origin - ARRAY['templateId','version','upstreamName','upstreamActions',
                                'nameOverridden','addedActions','removedActions']='{}'::jsonb
    AND jsonb_typeof(template_origin->'templateId')='string'
    AND (template_origin->>'templateId') ~ '^[a-z][a-z0-9-]{0,62}$'
    AND jsonb_typeof(template_origin->'version')='number'
    AND (template_origin->>'version') ~ '^[1-9][0-9]{0,8}$'
    AND jsonb_typeof(template_origin->'upstreamName')='string'
    AND jsonb_typeof(template_origin->'upstreamActions')='array'
    AND jsonb_typeof(template_origin->'nameOverridden')='boolean'
    AND jsonb_typeof(template_origin->'addedActions')='array'
    AND jsonb_typeof(template_origin->'removedActions')='array'));
