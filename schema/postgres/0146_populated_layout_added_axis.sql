-- Plan-v2 activation may introduce exactly one sealed Custom leaf axis.
-- Metadata is inserted only inside the existing atomic activation transaction.
-- Normalize the 0112 event-trigger receipt before its replay guard compares
-- it with the publisher's receipt.  Trigger name ordering (`a_` before `aa_`)
-- guarantees both inserts have one identical result identity; the 0112 replay
-- trigger suppresses the second insert.
CREATE FUNCTION epm.layout_activation_added_axis_receipt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE added_axis text;
BEGIN
 SELECT r.plan->'targetMetadata'->'dimension'->>'dimensionId' INTO added_axis
 FROM epm.layout_replacement_activation x
 JOIN epm.layout_replacement_request r USING(workspace_id,application_id,request_id)
 WHERE x.workspace_id=NEW.workspace_id AND x.application_id=NEW.application_id
 AND x.activation_id=NEW.operation_id AND x.status='Activating'
 AND epm.layout_replacement_activation_allowed(x.workspace_id,x.application_id,
     x.target_projection_generation,'activate');
 IF added_axis IS NOT NULL THEN
  NEW.result:=NEW.result||jsonb_build_object('addedDimensionId',added_axis);
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.layout_activation_added_axis_receipt() FROM PUBLIC,
 epm_runtime,epm_worker,epm_lifecycle;
CREATE TRIGGER a_layout_activation_added_axis_receipt
BEFORE INSERT ON epm.operation_receipt FOR EACH ROW
EXECUTE FUNCTION epm.layout_activation_added_axis_receipt();

CREATE OR REPLACE FUNCTION epm.layout_replacement_activation_publish(w text,a text,aid text,claimant_name text,generation bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE x epm.layout_replacement_activation%ROWTYPE;s epm.application_state%ROWTYPE;cert epm.layout_replacement_validation_certificate%ROWTYPE;
 layout epm.coordinate_layout%ROWTYPE;revision bigint;outcome jsonb;plan jsonb;proposed jsonb;new_axis text;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application:'||w||':'||a,0));
 SELECT * INTO x FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a AND activation_id=aid FOR UPDATE;
 SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
 SELECT * INTO cert FROM epm.layout_replacement_validation_certificate WHERE workspace_id=w AND application_id=a AND request_id=x.request_id;
 SELECT r.plan INTO plan FROM epm.layout_replacement_request r WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=x.request_id;
 IF x.status='Activated' AND x.claim_generation=generation THEN RETURN x.result;END IF;
 IF x.status<>'Activating' OR x.claimant<>claimant_name OR x.claim_generation<>generation OR x.lease_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_STALE_WORKER';END IF;
 IF NOT cert.activation_eligible OR cert.validation_digest<>x.validation_digest OR s.commit_open OR s.processing_mode<>'Active'
  OR ROW(s.metadata_revision,s.data_revision,s.policy_revision,s.schema_epoch,s.commit_revision,s.active_projection_generation)
  IS DISTINCT FROM ROW(x.source_metadata_revision,x.source_data_revision,x.source_policy_revision,x.source_schema_epoch,x.source_commit_revision,x.source_projection_generation)
  OR NOT EXISTS(SELECT 1 FROM epm.workspace WHERE workspace_id=w AND status='Active')
  OR NOT EXISTS(SELECT 1 FROM epm.application WHERE workspace_id=w AND application_id=a AND status='Active')
  OR (NOT EXISTS(SELECT 1 FROM epm.workspace_access_grant WHERE workspace_id=w AND issuer=x.issuer AND subject_id=x.subject_id AND role='Administrator')
      AND NOT EXISTS(SELECT 1 FROM epm.application_access_grant WHERE workspace_id=w AND application_id=a AND issuer=x.issuer AND subject_id=x.subject_id AND role='Administrator'))
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_STALE';END IF;
 IF EXISTS(SELECT 1 FROM epm.job WHERE workspace_id=w AND application_id=a AND status IN('accepted','ready','running','staged','cancel_requested','needs_inspection'))
  OR EXISTS(SELECT 1 FROM epm.source_batch WHERE workspace_id=w AND application_id=a AND status IN('staging','ready'))
  OR EXISTS(SELECT 1 FROM epm.expression_rule_sequence WHERE workspace_id=w AND application_id=a AND status IN('accepted','running','cancel_requested'))
  OR EXISTS(SELECT 1 FROM epm.full_aggregate_sequence WHERE workspace_id=w AND application_id=a AND status IN('accepted','running','cancel_requested'))
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
 JOIN epm.layout_replacement_private_coordinate p USING(workspace_id,application_id,target_digest),LATERAL jsonb_each_text(p.target_members)z
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.coordinate_projection_state(projection_generation,workspace_id,application_id,coordinate_id,schema_epoch,fact_table_id,entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
 SELECT x.target_projection_generation,w,a,m.coordinate_id,x.target_schema_epoch,'cube',p.target_members->>(layout.role_dimensions->>'Entity'),p.target_members->>(layout.role_dimensions->>'Account'),p.target_members->>(layout.role_dimensions->>'Scenario'),p.target_members->>(layout.role_dimensions->>'Year'),p.target_members->>(layout.role_dimensions->>'Period'),p.target_members->>(layout.role_dimensions->>'Value'),p.target_members->>(layout.role_dimensions->>'View'),p.target_members->>(layout.role_dimensions->>'ICP'),p.target_members->>(layout.role_dimensions->>'DataType'),ARRAY(SELECT p.target_members->>d FROM unnest(layout.custom_dimensions)d)
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_coordinate p USING(workspace_id,application_id,target_digest)
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 revision:=s.commit_revision+1;
 INSERT INTO epm.numeric_cell_projection SELECT w,a,m.coordinate_id,n.present,n.amount,'layout:'||aid,revision,x.target_projection_generation FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_numeric n USING(workspace_id,application_id,target_digest) WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.text_cell_projection SELECT w,a,m.coordinate_id,t.present,t.text_value,'layout:'||aid,revision,x.target_projection_generation FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_text t USING(workspace_id,application_id,target_digest) WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.line_detail_projection SELECT w,a,m.coordinate_id,d.items,d.total,'layout:'||aid,revision,x.target_projection_generation FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_detail d USING(workspace_id,application_id,target_digest) WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid AND d.present;
 INSERT INTO epm.generic_fact_projection SELECT w,a,g.table_id,g.series_key,g.value,g.change_id,g.last_revision,g.updated_at,x.target_projection_generation FROM epm.generic_fact_projection g WHERE g.workspace_id=w AND g.application_id=a AND g.projection_generation=x.source_projection_generation;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(x.dependency_decisions)d WHERE d->>'decision' IN('Invalidate','Rebuild') AND ((d->>'kind'='rule' AND NOT EXISTS(SELECT 1 FROM epm.expression_rule_publication p WHERE p.workspace_id=w AND p.application_id=a AND p.rule_id=d->>'id')) OR(d->>'kind'='publication' AND NOT EXISTS(SELECT 1 FROM epm.calculation_publication p WHERE p.workspace_id=w AND p.application_id=a AND p.result_key=d->>'id')))) THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_DEPENDENCY_UNRESOLVED';END IF;
 DELETE FROM epm.expression_rule_publication p USING jsonb_array_elements(x.dependency_decisions)d WHERE p.workspace_id=w AND p.application_id=a AND d->>'kind'='rule' AND d->>'decision' IN('Invalidate','Rebuild') AND p.rule_id=d->>'id';
 DELETE FROM epm.calculation_publication p USING jsonb_array_elements(x.dependency_decisions)d WHERE p.workspace_id=w AND p.application_id=a AND d->>'kind'='publication' AND d->>'decision' IN('Invalidate','Rebuild') AND p.result_key=d->>'id';
 UPDATE epm.application_state SET schema_epoch=x.target_schema_epoch,metadata_revision=metadata_revision+1,data_revision=data_revision+1,active_projection_generation=x.target_projection_generation,commit_revision=revision WHERE workspace_id=w AND application_id=a;
 outcome:=jsonb_build_object('activationId',aid,'requestId',x.request_id,'committedRevision',revision,'schemaEpoch',x.target_schema_epoch,'projectionGeneration',x.target_projection_generation,'historyPreserved',true);
 IF new_axis IS NOT NULL THEN outcome:=outcome||jsonb_build_object('addedDimensionId',new_axis);END IF;
 INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result) VALUES(w,a,aid,x.validation_digest,x.subject_id,revision,outcome);
 UPDATE epm.layout_replacement_activation SET status='Activated',result=outcome,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a AND activation_id=aid;
 RETURN outcome;END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_activation_publish(text,text,text,text,bigint) FROM PUBLIC,epm_runtime,epm_lifecycle,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_publish(text,text,text,text,bigint) TO epm_worker;
