BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=373) THEN
    RAISE EXCEPTION 'MIGRATION_0374_REQUIRES_0373';
  END IF;
END $migration$;

-- Canonical JSON is used only to reproduce cube_view_digest exactly while
-- transforming populated rows.  It is dropped before the migration commits.
CREATE FUNCTION epm.canonical_json_0374(p_value jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,epm AS $function$
DECLARE result text;
BEGIN
  CASE jsonb_typeof(p_value)
    WHEN 'object' THEN
      SELECT '{'||coalesce(string_agg(to_json(key)::text||':'||
        epm.canonical_json_0374(value),',' ORDER BY key),'')||'}'
        INTO result FROM jsonb_each(p_value);
    WHEN 'array' THEN
      SELECT '['||coalesce(string_agg(epm.canonical_json_0374(value),','
        ORDER BY ordinal),'')||']' INTO result
        FROM jsonb_array_elements(p_value) WITH ORDINALITY AS item(value,ordinal);
    ELSE result:=p_value::text;
  END CASE;
  RETURN result;
END $function$;
REVOKE ALL ON FUNCTION epm.canonical_json_0374(jsonb) FROM PUBLIC;

DO $migration$
DECLARE invalid_count bigint;
BEGIN
  SELECT count(*) INTO invalid_count FROM epm.saved_grid_definition g
  JOIN epm.application_state s USING(workspace_id,application_id)
  WHERE g.definition->>'format' IS DISTINCT FROM 'openepm-cube-view-v1'
    AND (
      g.metadata_revision<>s.metadata_revision
      OR jsonb_typeof(g.definition)<>'object'
      OR NOT g.definition ?& ARRAY[
        'rowDimensions','columnDimensions','pov','dataLayer','pageSize']
      OR EXISTS(SELECT 1 FROM jsonb_object_keys(g.definition) AS field(key)
        WHERE key NOT IN ('rowDimensions','columnDimensions','pov',
          'dataLayer','pageSize','resultKey'))
      OR g.definition->>'dataLayer' NOT IN ('raw','calculated')
      OR (g.definition->>'dataLayer'='raw' AND g.definition ? 'resultKey')
      OR (g.definition->>'dataLayer'='calculated' AND
          coalesce(g.definition->>'resultKey','') !~
            '^[A-Za-z0-9._-]{8,128}$')
      OR jsonb_typeof(g.definition->'rowDimensions')<>'array'
      OR jsonb_typeof(g.definition->'columnDimensions')<>'array'
      OR jsonb_typeof(g.definition->'pov')<>'object'
      OR jsonb_typeof(g.definition->'pageSize')<>'number'
      OR (g.definition->>'pageSize')::numeric<>trunc(
          (g.definition->>'pageSize')::numeric)
      OR (g.definition->>'pageSize')::numeric NOT BETWEEN 1 AND 500
      OR jsonb_array_length(g.definition->'rowDimensions')=0
      OR jsonb_array_length(g.definition->'columnDimensions')=0
      OR (
        WITH placed AS (
          SELECT value#>>'{}' dimension_id
            FROM jsonb_array_elements(g.definition->'rowDimensions') value
          UNION ALL
          SELECT value#>>'{}'
            FROM jsonb_array_elements(g.definition->'columnDimensions') value
          UNION ALL
          SELECT key FROM jsonb_object_keys(g.definition->'pov') AS p(key))
        SELECT count(*)<>(SELECT count(*) FROM epm.dimension d
                 WHERE d.workspace_id=g.workspace_id
                   AND d.application_id=g.application_id AND d.status='Active')
          OR count(*)<>count(DISTINCT dimension_id)
          OR coalesce(bool_or(NOT EXISTS(SELECT 1 FROM epm.dimension d
              WHERE d.workspace_id=g.workspace_id
                AND d.application_id=g.application_id AND d.status='Active'
                AND d.dimension_id=placed.dimension_id)),false)
        FROM placed)
      OR EXISTS(SELECT 1 FROM epm.dimension d
        WHERE d.workspace_id=g.workspace_id AND d.application_id=g.application_id
          AND d.status='Active' AND NOT g.definition->'pov' ? d.dimension_id
          AND (SELECT count(*) FROM epm.member m
            WHERE m.workspace_id=d.workspace_id
              AND m.application_id=d.application_id
              AND m.dimension_id=d.dimension_id AND m.status='Active')
            NOT BETWEEN 1 AND 10000)
      OR EXISTS(SELECT 1 FROM jsonb_each_text(g.definition->'pov') p
        WHERE NOT EXISTS(SELECT 1 FROM epm.member m
          WHERE m.workspace_id=g.workspace_id
            AND m.application_id=g.application_id
            AND m.dimension_id=p.key AND m.member_id=p.value
            AND m.status='Active'))
    );
  IF invalid_count<>0 THEN
    RAISE EXCEPTION 'CANONICAL_SAVED_VIEW_0374_LEGACY_INVALID: %',invalid_count;
  END IF;
END $migration$;

WITH legacy AS (
  SELECT g.* FROM epm.saved_grid_definition g
  WHERE g.definition->>'format' IS DISTINCT FROM 'openepm-cube-view-v1'
), canonical AS (
  SELECT legacy.workspace_id,legacy.application_id,legacy.grid_id,
    jsonb_build_object(
      'format','openepm-cube-view-v1',
      'viewId',legacy.grid_id,
      'name',legacy.name,
      'selection',jsonb_build_object(
        'format','openepm-cube-selection-v1',
        'metadataRevision',legacy.metadata_revision,
        'dimensions',(SELECT jsonb_agg(jsonb_build_object(
          'dimensionId',d.dimension_id,
          'include',CASE WHEN legacy.definition->'pov' ? d.dimension_id
            THEN jsonb_build_object('kind','member','memberId',
              legacy.definition->'pov'->>d.dimension_id)
            ELSE jsonb_build_object('kind','members','memberIds',
              (SELECT jsonb_agg(m.member_id ORDER BY m.member_id)
               FROM epm.member m WHERE m.workspace_id=d.workspace_id
                 AND m.application_id=d.application_id
                 AND m.dimension_id=d.dimension_id AND m.status='Active')) END,
          'exclude','null'::jsonb) ORDER BY d.dimension_id)
          FROM epm.dimension d WHERE d.workspace_id=legacy.workspace_id
            AND d.application_id=legacy.application_id AND d.status='Active')),
      'layout',jsonb_build_object(
        'pages','[]'::jsonb,
        'rows',legacy.definition->'rowDimensions',
        'columns',legacy.definition->'columnDimensions',
        'filters',(SELECT coalesce(jsonb_agg(key ORDER BY key),'[]'::jsonb)
          FROM jsonb_object_keys(legacy.definition->'pov') AS p(key))),
      'dataSource',jsonb_build_object(
        'kind',legacy.definition->>'dataLayer',
        'resultKey',CASE WHEN legacy.definition->>'dataLayer'='raw'
          THEN 'null'::jsonb ELSE to_jsonb(legacy.definition->>'resultKey') END),
      'suppression',jsonb_build_object('missing',false,'zero',false),
      'pageSize',legacy.definition->'pageSize') AS definition
  FROM legacy
)
UPDATE epm.saved_grid_definition g SET
  definition=canonical.definition,
  canonical_digest=encode(sha256(convert_to(
    epm.canonical_json_0374(canonical.definition),'UTF8')),'hex')
FROM canonical WHERE g.workspace_id=canonical.workspace_id
  AND g.application_id=canonical.application_id
  AND g.grid_id=canonical.grid_id;

DO $migration$ BEGIN
  IF EXISTS(SELECT 1 FROM epm.saved_grid_definition
      WHERE definition->>'format'<>'openepm-cube-view-v1'
        OR definition->>'viewId'<>grid_id OR definition->>'name'<>name
        OR (definition->'selection'->>'metadataRevision')::bigint<>
          metadata_revision
        OR canonical_digest<>encode(sha256(convert_to(
          epm.canonical_json_0374(definition),'UTF8')),'hex')) THEN
    RAISE EXCEPTION 'CANONICAL_SAVED_VIEW_0374_RECONCILIATION_FAILED';
  END IF;
END $migration$;

DROP FUNCTION epm.canonical_json_0374(jsonb);

COMMIT;
SELECT '0374 applied' AS migration;
