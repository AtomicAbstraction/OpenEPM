-- One bounded inventory for review, replacement admission and certificate validation.
BEGIN;

DO $migration$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=392) THEN
  RAISE EXCEPTION 'MIGRATION_0393_REQUIRES_0392';
 END IF;
END $migration$;

ALTER TABLE epm.layout_replacement_request
 ADD COLUMN reviewed_dependency_digest text
 CHECK (reviewed_dependency_digest IS NULL OR reviewed_dependency_digest~'^[0-9a-f]{64}$');

CREATE FUNCTION epm.layout_replacement_dependency_inventory(w text,a text)
RETURNS TABLE(dependencies jsonb,dependency_digest text)
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog,epm AS $$
DECLARE inventory jsonb;
BEGIN
 IF w IS NULL OR a IS NULL
    OR w IS DISTINCT FROM current_setting('epm.workspace_id',true)
    OR a IS DISTINCT FROM current_setting('epm.application_id',true) THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_SCOPE_INVALID';
 END IF;
 SELECT coalesce(jsonb_agg(value ORDER BY kind COLLATE "C",id COLLATE "C"),'[]'::jsonb)
 INTO inventory FROM (
  SELECT 'rule'::text kind,r.rule_id id,jsonb_build_object('kind','rule',
   'id',r.rule_id,'stateToken',r.state_token,'contentDigest',r.program_digest) value
  FROM epm.expression_rule_definition r
  WHERE r.workspace_id=w AND r.application_id=a AND r.status='Active'
  UNION ALL
  SELECT 'publication',p.result_key,jsonb_build_object('kind','publication',
   'id',p.result_key,'stateToken',p.state_token,'contentDigest',p.content_digest)
  FROM epm.calculation_result_state p WHERE p.workspace_id=w AND p.application_id=a
  LIMIT 10001
 ) dependencies;
 IF jsonb_array_length(inventory)>10000 THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_LIMIT';
 END IF;
 IF octet_length(inventory::text)>1048576 THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_LIMIT';
 END IF;
 RETURN QUERY SELECT inventory,
    encode(sha256(convert_to(inventory::text,'UTF8')),'hex');
END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_dependency_inventory(text,text)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_access,epm_security;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_dependency_inventory(text,text) TO epm_runtime;

CREATE OR REPLACE FUNCTION epm.layout_replacement_validation_context(
 w text,a text,rid text,decisions jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE plan jsonb; inventory jsonb; actual_sources jsonb; planned_sources jsonb;
 reviewed_digest text; current_digest text;
 canonical_decisions jsonb; identity_layout boolean; context jsonb;
 source_count bigint; source_bytes bigint;
BEGIN
 IF w IS DISTINCT FROM current_setting('epm.workspace_id',true)
    OR a IS DISTINCT FROM current_setting('epm.application_id',true) THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_SCOPE_INVALID';
 END IF;
 SELECT r.plan,r.reviewed_dependency_digest INTO plan,reviewed_digest FROM epm.layout_replacement_request r
 WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=rid;
 IF NOT FOUND OR jsonb_typeof(plan->'coordinateMappings') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'LAYOUT_REPLACEMENT_PLAN_INVALID';
 END IF;
 IF jsonb_typeof(decisions) IS DISTINCT FROM 'array'
    OR jsonb_array_length(decisions)>10000 THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_DECISION_INVALID';
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(decisions) d WHERE
     jsonb_typeof(d) IS DISTINCT FROM 'object'
     OR d-ARRAY['kind','id','decision']<>'{}'::jsonb
     OR jsonb_typeof(d->'kind') IS DISTINCT FROM 'string'
     OR jsonb_typeof(d->'id') IS DISTINCT FROM 'string'
     OR jsonb_typeof(d->'decision') IS DISTINCT FROM 'string'
     OR d->>'kind' NOT IN('rule','publication')
     OR length(d->>'id') NOT BETWEEN 1 AND 256
     OR d->>'decision' NOT IN('Compatible','Invalidate','Rebuild','Incompatible'))
    OR EXISTS(SELECT 1 FROM jsonb_array_elements(decisions)d
       GROUP BY d->>'kind',d->>'id' HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_DECISION_INVALID';
 END IF;
 SELECT d.dependencies,d.dependency_digest INTO inventory,current_digest
 FROM epm.layout_replacement_dependency_inventory(w,a)d;
 IF reviewed_digest IS NOT NULL AND reviewed_digest IS DISTINCT FROM current_digest THEN
  RAISE EXCEPTION 'STALE_LAYOUT_DEPENDENCIES';
 END IF;
 SELECT coalesce(jsonb_agg(d ORDER BY (d->>'kind') COLLATE "C",(d->>'id') COLLATE "C"),'[]'::jsonb)
 INTO canonical_decisions FROM jsonb_array_elements(decisions)d;
 IF (SELECT coalesce(jsonb_agg(d-ARRAY['stateToken','contentDigest']
       ORDER BY (d->>'kind') COLLATE "C",(d->>'id') COLLATE "C"),'[]'::jsonb)
       FROM jsonb_array_elements(inventory)d)
    IS DISTINCT FROM
    (SELECT coalesce(jsonb_agg(d-'decision'
       ORDER BY (d->>'kind') COLLATE "C",(d->>'id') COLLATE "C"),'[]'::jsonb)
       FROM jsonb_array_elements(canonical_decisions)d) THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_INVENTORY_MISMATCH';
 END IF;
 -- Only the active projection identifies logical source coordinates. Old
 -- registry rows remain business provenance and are never a second inventory.
 WITH bounded AS MATERIALIZED (
  SELECT c.coordinate_id,c.members FROM epm.coordinate c
  JOIN epm.coordinate_projection_state p USING(workspace_id,application_id,coordinate_id)
  JOIN epm.application_state s USING(workspace_id,application_id)
  WHERE c.workspace_id=w AND c.application_id=a
   AND p.projection_generation=s.active_projection_generation
   AND p.schema_epoch=s.schema_epoch ORDER BY c.coordinate_id LIMIT 100001
 ), budget AS (
  SELECT count(*) n,coalesce(sum(octet_length(jsonb_build_object(
   'sourceCoordinateId',coordinate_id,'sourceMembers',members)::text)+1),0)+2 bytes
  FROM bounded
 ) SELECT CASE WHEN n<=100000 AND bytes<=33554432 THEN
    (SELECT coalesce(jsonb_agg(jsonb_build_object('sourceCoordinateId',coordinate_id,
       'sourceMembers',members) ORDER BY coordinate_id),'[]'::jsonb) FROM bounded)
   ELSE NULL END,n,bytes INTO actual_sources,source_count,source_bytes FROM budget;
 IF source_count>100000 THEN RAISE EXCEPTION 'POPULATED_LAYOUT_COORDINATE_LIMIT';END IF;
 IF source_bytes>33554432 THEN RAISE EXCEPTION 'POPULATED_LAYOUT_SOURCE_RESPONSE_LIMIT';END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('sourceCoordinateId',m->'sourceCoordinateId',
   'sourceMembers',m->'sourceMembers') ORDER BY (m->>'sourceCoordinateId')::bigint),'[]'::jsonb)
 INTO planned_sources FROM jsonb_array_elements(plan->'coordinateMappings')m;
 IF actual_sources IS DISTINCT FROM planned_sources THEN
  RAISE EXCEPTION 'LAYOUT_SOURCE_INVENTORY_STALE';
 END IF;
 -- Incompatible is retained only for the validator's ineligible diagnostic
 -- certificate. The existing public activation grammar still permits only
 -- Compatible/Invalidate/Rebuild and requires activation_eligible.
 -- Existing generic compatibility proof: unchanged complete grain and exact
 -- coordinate mapping. No arbitrary Python/dependency compatibility inference.
 identity_layout:=(NOT (plan ? 'targetMetadata'))
  AND (SELECT array_agg(x->>'dimensionId' ORDER BY x->>'dimensionId' COLLATE "C")
       FROM jsonb_array_elements(plan->'sourceAxes')x)
      IS NOT DISTINCT FROM
      (SELECT array_agg(x->>'dimensionId' ORDER BY x->>'dimensionId' COLLATE "C")
       FROM jsonb_array_elements(plan->'targetAxes')x)
  AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(plan->'axisMapping')x WHERE x.key<>x.value)
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(plan->'coordinateMappings')m
       WHERE m->'sourceMembers' IS DISTINCT FROM m->'targetMembers');
 IF NOT coalesce(identity_layout,false) AND EXISTS(
   SELECT 1 FROM jsonb_array_elements(canonical_decisions)d WHERE d->>'decision'='Compatible') THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_COMPATIBILITY_UNPROVEN';
 END IF;
 context:=jsonb_build_object('format','openepm-layout-current-dependencies-v1',
  'dependencies',inventory,'decisions',canonical_decisions,
  'sourceInventoryDigest',encode(sha256(convert_to(actual_sources::text,'UTF8')),'hex'),
  'sourceCoordinateCount',jsonb_array_length(actual_sources),
  'identityLayout',coalesce(identity_layout,false));
 IF octet_length(context::text)>1048576 THEN RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_LIMIT';END IF;
 RETURN context;
END $$;

COMMIT;
