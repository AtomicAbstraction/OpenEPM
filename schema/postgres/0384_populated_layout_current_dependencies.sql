-- Current populated-layout activation: retained values and source are not
-- publication pointers. Bind the existing immutable certificate to the current
-- owners and logical coordinate projection; metadata/schema changes invalidate
-- acceptance through the existing definition/current-result readers.
BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=383) THEN
  RAISE EXCEPTION 'MIGRATION_0384_REQUIRES_0383';
 END IF;
END $migration$;

CREATE FUNCTION epm.layout_replacement_validation_context(
 w text,a text,rid text,decisions jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE plan jsonb; inventory jsonb; actual_sources jsonb; planned_sources jsonb;
 canonical_decisions jsonb; identity_layout boolean; context jsonb;
 source_count bigint; source_bytes bigint;
BEGIN
 IF w IS DISTINCT FROM current_setting('epm.workspace_id',true)
    OR a IS DISTINCT FROM current_setting('epm.application_id',true) THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_SCOPE_INVALID';
 END IF;
 SELECT r.plan INTO plan FROM epm.layout_replacement_request r
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
REVOKE ALL ON FUNCTION epm.layout_replacement_validation_context(text,text,text,jsonb)
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle,epm_access,epm_security;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_validation_context(text,text,text,jsonb)
 TO epm_runtime,epm_worker;

-- Preserve every existing materialization/value/pin check and immutable
-- certificate owner. Fail closed for pre384 unbound certificates on new work.
DO $migration$
DECLARE definition text; old text; replacement text;
BEGIN
 SELECT pg_get_functiondef('epm.layout_replacement_validation_publish(text,text,text,text,integer,jsonb)'::regprocedure) INTO definition;
 old:=' INSERT INTO epm.layout_replacement_validation_certificate';
 replacement:=$patch$ IF jsonb_typeof(p_certificate->'dependencyContext') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED';END IF;
 IF p_certificate->'dependencyContext' IS DISTINCT FROM
   epm.layout_replacement_validation_context(p_workspace,p_application,p_request,
     p_certificate->'dependencyContext'->'decisions') THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_STALE';
 END IF;
 INSERT INTO epm.layout_replacement_validation_certificate$patch$;
 IF position(old IN definition)=0 OR position('dependencyContext' IN definition)>0 THEN
  RAISE EXCEPTION 'LAYOUT_VALIDATION_0384_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,old,replacement);
 SELECT pg_get_functiondef('epm.layout_replacement_activation_request(text,text,text,text,text,text,text,text,text,jsonb)'::regprocedure) INTO definition;
 old:=' SELECT greatest(s.active_projection_generation,coalesce(max(target_projection_generation),0))+1 INTO target_gen';
 replacement:=$patch$ IF jsonb_typeof(c.certificate->'dependencyContext') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED';END IF;
 IF c.certificate->'dependencyContext' IS DISTINCT FROM
    epm.layout_replacement_validation_context(w,a,rid,decisions) THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_STALE';
 END IF;
 SELECT greatest(s.active_projection_generation,coalesce(max(target_projection_generation),0))+1 INTO target_gen$patch$;
 IF position(old IN definition)=0 OR position('dependencyContext' IN definition)>0 THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_0384_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,old,replacement);
END $migration$;

CREATE OR REPLACE FUNCTION epm.layout_replacement_activation_publish(w text,a text,aid text,claimant_name text,generation bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE x epm.layout_replacement_activation%ROWTYPE;s epm.application_state%ROWTYPE;cert epm.layout_replacement_validation_certificate%ROWTYPE;
 layout epm.coordinate_layout%ROWTYPE;revision bigint;outcome jsonb;plan jsonb;proposed jsonb;new_axis text;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application:'||w||':'||a,0));
 SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
 SELECT * INTO x FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a AND activation_id=aid FOR UPDATE;
 SELECT * INTO cert FROM epm.layout_replacement_validation_certificate WHERE workspace_id=w AND application_id=a AND request_id=x.request_id;
 SELECT r.plan INTO plan FROM epm.layout_replacement_request r WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=x.request_id;
 IF NOT epm.layout_replacement_activation_current_admin(w,a,aid) THEN
  RAISE EXCEPTION 'LAYOUT_ACTIVATION_STALE';END IF;
 IF x.status='Activated' AND x.claim_generation=generation THEN
  IF NOT EXISTS(SELECT 1 FROM epm.operation_receipt receipt WHERE
    receipt.workspace_id=w AND receipt.application_id=a AND receipt.operation_id=aid
    AND receipt.actor_id=x.subject_id AND receipt.command_digest=x.validation_digest
    AND receipt.result=x.result AND receipt.sealed) THEN
   RAISE EXCEPTION 'LAYOUT_ACTIVATION_RECEIPT_CONFLICT';END IF;
  RETURN x.result;
 END IF;
 IF x.status<>'Activating' OR x.claimant<>claimant_name OR x.claim_generation<>generation OR x.lease_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_STALE_WORKER';END IF;
 IF NOT cert.activation_eligible OR cert.validation_digest<>x.validation_digest OR s.commit_open OR s.processing_mode<>'Active'
  OR ROW(s.metadata_revision,s.data_revision,s.policy_revision,s.schema_epoch,s.commit_revision,s.active_projection_generation)
  IS DISTINCT FROM ROW(x.source_metadata_revision,x.source_data_revision,x.source_policy_revision,x.source_schema_epoch,x.source_commit_revision,x.source_projection_generation)
  OR NOT EXISTS(SELECT 1 FROM epm.workspace WHERE workspace_id=w AND status='Active')
  OR NOT EXISTS(SELECT 1 FROM epm.application WHERE workspace_id=w AND application_id=a AND status='Active')
  OR NOT epm.layout_replacement_activation_current_admin(w,a,aid)
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_STALE';END IF;
 IF jsonb_typeof(cert.certificate->'dependencyContext') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_REQUIRED';END IF;
 IF cert.certificate->'dependencyContext' IS DISTINCT FROM
    epm.layout_replacement_validation_context(w,a,x.request_id,x.dependency_decisions) THEN
  RAISE EXCEPTION 'LAYOUT_DEPENDENCY_CERTIFICATE_STALE';END IF;
 IF EXISTS(SELECT 1 FROM epm.job WHERE workspace_id=w AND application_id=a AND status IN('accepted','ready','running','staged','cancel_requested','needs_inspection'))
  OR EXISTS(SELECT 1 FROM epm.source_batch WHERE workspace_id=w AND application_id=a AND status IN('staging','ready'))
  OR EXISTS(SELECT 1 FROM epm.expression_rule_sequence WHERE workspace_id=w AND application_id=a AND status IN('accepted','running','cancel_requested'))
  OR EXISTS(SELECT 1 FROM epm.full_aggregate_sequence WHERE workspace_id=w AND application_id=a AND status IN('accepted','running','cancel_requested'))
  OR EXISTS(SELECT 1 FROM epm.application_rule_workflow WHERE workspace_id=w AND application_id=a AND status IN('accepted','running','cancel_requested','needs_inspection'))
  OR EXISTS(SELECT 1 FROM epm.python_program_workflow WHERE workspace_id=w AND application_id=a AND status IN('accepted','running','cancel_requested','needs_inspection'))
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_CONFLICTING_WORK';END IF;
 PERFORM set_config('epm.layout_activation_context',jsonb_build_array(w,a,aid,x.target_projection_generation,generation,pg_current_xact_id()::text,pg_backend_pid())::text,true);
 proposed:=plan->'targetMetadata';
 IF proposed IS NOT NULL THEN
  new_axis:=proposed->'dimension'->>'dimensionId';
  IF plan->>'format'<>'openepm-populated-layout-plan-v2' OR new_axis IS NULL
   OR proposed->'dimension'->>'modelRole'<>'Custom'
   OR jsonb_typeof(proposed->'dimension'->'members')<>'array'
   OR jsonb_array_length(proposed->'dimension'->'members') NOT BETWEEN 1 AND 10000
   OR EXISTS(SELECT 1 FROM epm.dimension WHERE workspace_id=w AND application_id=a AND (dimension_id=new_axis OR lower(name)=lower(proposed->'dimension'->>'name')))
   OR EXISTS(SELECT 1 FROM epm.layout_replacement_private_coordinate p WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id AND NOT p.target_members ? new_axis)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(proposed->'dimension'->'members') m WHERE NOT EXISTS(SELECT 1 FROM epm.layout_replacement_private_coordinate p WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id AND p.target_members->>new_axis=m->>'memberId'))
   OR EXISTS(SELECT 1 FROM epm.layout_replacement_private_coordinate p WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(proposed->'dimension'->'members') m WHERE m->>'memberId'=p.target_members->>new_axis))
  THEN RAISE EXCEPTION 'LAYOUT_ADDED_AXIS_METADATA_STALE_OR_INVALID';END IF;
  INSERT INTO epm.dimension(workspace_id,application_id,dimension_id,name,model_role,short_description,detailed_description)
  VALUES(w,a,new_axis,proposed->'dimension'->>'name','Custom',proposed->'dimension'->>'shortDescription',proposed->'dimension'->>'detailedDescription');
  INSERT INTO epm.member(workspace_id,application_id,dimension_id,member_id,name,short_description,detailed_description)
  SELECT w,a,new_axis,m->>'memberId',m->>'name',m->>'shortDescription',m->>'detailedDescription'
  FROM jsonb_array_elements(proposed->'dimension'->'members') m;
 END IF;
 UPDATE epm.dimension SET status=CASE WHEN dimension_id IN(SELECT z->>'dimensionId' FROM jsonb_array_elements(plan->'targetAxes')z) THEN 'Active' ELSE 'Inactive' END
 WHERE workspace_id=w AND application_id=a AND model_role IS DISTINCT FROM 'Currency';
 SELECT x.target_schema_epoch,ARRAY(SELECT z->>'dimensionId' FROM jsonb_array_elements(plan->'targetAxes')z ORDER BY z->>'dimensionId'),
  coalesce(jsonb_object_agg(d.model_role,d.dimension_id)FILTER(WHERE d.model_role IS NOT NULL AND d.model_role<>'Custom'),'{}'),
  coalesce(array_agg(d.dimension_id ORDER BY d.dimension_id)FILTER(WHERE d.model_role IS NULL OR d.model_role='Custom'),'{}')
 INTO layout.schema_epoch,layout.dimensions,layout.role_dimensions,layout.custom_dimensions FROM epm.dimension d
 WHERE d.workspace_id=w AND d.application_id=a AND d.status='Active' AND d.model_role IS DISTINCT FROM 'Currency';
 INSERT INTO epm.coordinate_layout VALUES(w,a,layout.schema_epoch,layout.dimensions,layout.role_dimensions,layout.custom_dimensions);
 INSERT INTO epm.coordinate(workspace_id,application_id,series_key,members)
 SELECT w,a,epm.coordinate_series_key(p.target_members),p.target_members FROM epm.layout_replacement_private_coordinate p
 WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id ON CONFLICT DO NOTHING;
 INSERT INTO epm.layout_replacement_activation_coordinate SELECT w,a,aid,p.target_digest,c.coordinate_id
 FROM epm.layout_replacement_private_coordinate p JOIN epm.coordinate c ON c.workspace_id=p.workspace_id AND c.application_id=p.application_id AND c.series_key=epm.coordinate_series_key(p.target_members)
 WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id;
 INSERT INTO epm.coordinate_member_projection(projection_generation,workspace_id,application_id,coordinate_id,dimension_id,member_id)
 SELECT x.target_projection_generation,w,a,m.coordinate_id,z.key,z.value FROM epm.layout_replacement_activation_coordinate m
 JOIN epm.layout_replacement_private_coordinate p ON p.workspace_id=m.workspace_id AND p.application_id=m.application_id AND p.target_digest=m.target_digest AND p.generation_id=cert.generation_id,LATERAL jsonb_each_text(p.target_members)z
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.coordinate_projection_state(projection_generation,workspace_id,application_id,coordinate_id,schema_epoch,fact_table_id,entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
 SELECT x.target_projection_generation,w,a,m.coordinate_id,x.target_schema_epoch,'cube',p.target_members->>(layout.role_dimensions->>'Entity'),p.target_members->>(layout.role_dimensions->>'Account'),p.target_members->>(layout.role_dimensions->>'Scenario'),p.target_members->>(layout.role_dimensions->>'Year'),p.target_members->>(layout.role_dimensions->>'Period'),p.target_members->>(layout.role_dimensions->>'Value'),p.target_members->>(layout.role_dimensions->>'View'),p.target_members->>(layout.role_dimensions->>'ICP'),p.target_members->>(layout.role_dimensions->>'DataType'),ARRAY(SELECT p.target_members->>d FROM unnest(layout.custom_dimensions)d)
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_coordinate p ON p.workspace_id=m.workspace_id AND p.application_id=m.application_id AND p.target_digest=m.target_digest AND p.generation_id=cert.generation_id
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 revision:=s.commit_revision+1;
 INSERT INTO epm.numeric_cell_projection SELECT w,a,m.coordinate_id,n.present,n.amount,'layout:'||aid,revision,x.target_projection_generation FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_numeric n ON n.workspace_id=m.workspace_id AND n.application_id=m.application_id AND n.target_digest=m.target_digest AND n.generation_id=cert.generation_id WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.text_cell_projection SELECT w,a,m.coordinate_id,t.present,t.text_value,'layout:'||aid,revision,x.target_projection_generation FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_text t ON t.workspace_id=m.workspace_id AND t.application_id=m.application_id AND t.target_digest=m.target_digest AND t.generation_id=cert.generation_id WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.line_detail_projection SELECT w,a,m.coordinate_id,d.items,d.total,'layout:'||aid,revision,x.target_projection_generation FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_detail d ON d.workspace_id=m.workspace_id AND d.application_id=m.application_id AND d.target_digest=m.target_digest AND d.generation_id=cert.generation_id WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid AND d.present;
 INSERT INTO epm.generic_fact_projection SELECT w,a,g.table_id,g.series_key,g.value,g.change_id,g.last_revision,g.updated_at,x.target_projection_generation FROM epm.generic_fact_projection g WHERE g.workspace_id=w AND g.application_id=a AND g.projection_generation=x.source_projection_generation;
 -- Preserve current definitions, values and producing receipts. The existing
 -- metadata/schema currentness fences invalidate old acceptance; no fresh
 -- compilation/publication is performed by Compatible/Invalidate/Rebuild.
 UPDATE epm.application_state SET schema_epoch=x.target_schema_epoch,metadata_revision=metadata_revision+1,data_revision=data_revision+1,active_projection_generation=x.target_projection_generation,commit_revision=revision WHERE workspace_id=w AND application_id=a;
 outcome:=jsonb_build_object('activationId',aid,'requestId',x.request_id,'committedRevision',revision,'schemaEpoch',x.target_schema_epoch,'projectionGeneration',x.target_projection_generation,'historyPreserved',true);
 IF new_axis IS NOT NULL THEN outcome:=outcome||jsonb_build_object('addedDimensionId',new_axis);END IF;
 INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(w,a,aid,x.validation_digest,x.subject_id,revision,outcome);
 UPDATE epm.layout_replacement_activation SET status='Activated',result=outcome,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND activation_id=aid;
 RETURN outcome;END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_activation_publish(text,text,text,text,bigint) FROM PUBLIC,epm_runtime,epm_lifecycle,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_publish(text,text,text,text,bigint) TO epm_worker;

COMMIT;
