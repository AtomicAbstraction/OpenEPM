-- Atomic activation of one validated private populated-layout generation.
-- Historical coordinates, layouts, projections, events and certificates remain.

CREATE TABLE epm.layout_replacement_activation(
 workspace_id text NOT NULL,application_id text NOT NULL,activation_id text NOT NULL CHECK(activation_id~'^[0-9a-f]{32}$'),
 request_id text NOT NULL,idempotency_key text NOT NULL CHECK(idempotency_key~'^[A-Za-z0-9._-]{8,128}$'),
 request_digest text NOT NULL CHECK(request_digest~'^[0-9a-f]{64}$'),issuer text NOT NULL,subject_id text NOT NULL,
 validation_digest text NOT NULL CHECK(validation_digest~'^[0-9a-f]{64}$'),
 source_schema_epoch bigint NOT NULL,target_schema_epoch bigint NOT NULL,
 source_projection_generation bigint NOT NULL,target_projection_generation bigint NOT NULL,
 source_metadata_revision bigint NOT NULL,source_data_revision bigint NOT NULL,
 source_policy_revision bigint NOT NULL,source_commit_revision bigint NOT NULL,
 dependency_decisions jsonb NOT NULL CHECK(jsonb_typeof(dependency_decisions)='array'),
 status text NOT NULL DEFAULT 'Requested' CHECK(status IN('Requested','Activating','Activated','Failed','Cancelled')),
 claim_generation bigint NOT NULL DEFAULT 0,claimant text,lease_until timestamptz,error_code text,result jsonb,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,activation_id),
 UNIQUE(workspace_id,application_id,issuer,subject_id,idempotency_key),
 UNIQUE(workspace_id,application_id,request_id),
 FOREIGN KEY(workspace_id,application_id,request_id) REFERENCES epm.layout_replacement_validation_certificate
  (workspace_id,application_id,request_id) ON DELETE RESTRICT,
 CHECK((status='Activating')=(claimant IS NOT NULL AND lease_until IS NOT NULL)),
 CHECK(error_code IS NULL OR status='Failed')
);
CREATE UNIQUE INDEX layout_replacement_activation_active ON epm.layout_replacement_activation(workspace_id,application_id)
 WHERE status IN('Requested','Activating');
CREATE TABLE epm.layout_replacement_activation_coordinate(
 workspace_id text NOT NULL,application_id text NOT NULL,activation_id text NOT NULL,target_digest text NOT NULL,
 coordinate_id bigint NOT NULL,PRIMARY KEY(workspace_id,application_id,activation_id,target_digest),
 UNIQUE(workspace_id,application_id,activation_id,coordinate_id),
 FOREIGN KEY(workspace_id,application_id,activation_id) REFERENCES epm.layout_replacement_activation
  (workspace_id,application_id,activation_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,coordinate_id) REFERENCES epm.coordinate
  (workspace_id,application_id,coordinate_id) ON DELETE RESTRICT
);

ALTER TABLE epm.layout_replacement_activation ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.layout_replacement_activation_coordinate ENABLE ROW LEVEL SECURITY;
CREATE POLICY layout_replacement_activation_runtime ON epm.layout_replacement_activation TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY layout_replacement_activation_coordinate_runtime ON epm.layout_replacement_activation_coordinate TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.layout_replacement_activation,epm.layout_replacement_activation_coordinate
 FROM PUBLIC,epm_runtime,epm_worker,epm_lifecycle;
GRANT SELECT ON epm.layout_replacement_activation,epm.layout_replacement_activation_coordinate TO epm_runtime;

CREATE FUNCTION epm.layout_replacement_activation_allowed(w text,a text,target bigint,phase text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$ DECLARE x epm.layout_replacement_activation%ROWTYPE;BEGIN
 IF coalesce(current_setting('epm.layout_activation_context',true),'')='' OR
 NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid='epm.operation_receipt'::regclass),'USAGE') THEN RETURN false;END IF;
 SELECT * INTO x FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a
  AND target_projection_generation=target AND status='Activating' AND claimant IS NOT NULL
  AND lease_until>clock_timestamp() AND current_setting('epm.layout_activation_context',true)=jsonb_build_array(
   w,a,activation_id,target_projection_generation,claim_generation,pg_current_xact_id()::text,pg_backend_pid())::text;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION epm.layout_replacement_activation_allowed(text,text,bigint,text) FROM PUBLIC;

ALTER FUNCTION epm.staged_projection_allowed(text,text,bigint,text) RENAME TO projection_recovery_staged_allowed;
CREATE FUNCTION epm.staged_projection_allowed(w text,a text,target bigint,allowed_phase text DEFAULT NULL)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$ BEGIN
 RETURN epm.layout_replacement_activation_allowed(w,a,target,allowed_phase)
  OR epm.projection_recovery_staged_allowed(w,a,target,allowed_phase);END $$;
REVOKE ALL ON FUNCTION epm.staged_projection_allowed(text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.staged_projection_allowed(text,text,bigint,text) TO epm_runtime,epm_lifecycle;

CREATE OR REPLACE FUNCTION epm.projection_generation_pointer_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$ DECLARE x epm.layout_replacement_activation%ROWTYPE;BEGIN
 IF TG_OP='INSERT' THEN IF NEW.active_projection_generation<>0 THEN RAISE EXCEPTION 'PROJECTION_GENERATION_ACTIVATION_REQUIRED';END IF;
 ELSIF NEW.active_projection_generation IS DISTINCT FROM OLD.active_projection_generation THEN
  IF epm.layout_replacement_activation_allowed(NEW.workspace_id,NEW.application_id,NEW.active_projection_generation,'activate') THEN
   SELECT * INTO x FROM epm.layout_replacement_activation WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
    AND target_projection_generation=NEW.active_projection_generation AND status='Activating';
   IF NEW.schema_epoch<>x.target_schema_epoch OR OLD.schema_epoch<>x.source_schema_epoch
    OR NEW.metadata_revision<>OLD.metadata_revision+1 OR NEW.data_revision<>OLD.data_revision+1
    OR NEW.policy_revision<>OLD.policy_revision OR NEW.commit_revision<>OLD.commit_revision+1
    OR OLD.metadata_revision<>x.source_metadata_revision OR OLD.data_revision<>x.source_data_revision
    OR OLD.policy_revision<>x.source_policy_revision OR OLD.commit_revision<>x.source_commit_revision
    OR OLD.active_projection_generation<>x.source_projection_generation THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_POINTER_INVALID';END IF;
  ELSE
   IF NOT epm.projection_recovery_staged_allowed(NEW.workspace_id,NEW.application_id,NEW.active_projection_generation,'activate')
    OR NOT EXISTS(SELECT 1 FROM epm.projection_recovery_manifest m WHERE m.workspace_id=NEW.workspace_id
     AND m.application_id=NEW.application_id AND m.target_generation=NEW.active_projection_generation
     AND m.original_generation=OLD.active_projection_generation AND m.source_commit_revision=OLD.commit_revision
     AND m.schema_epoch=OLD.schema_epoch AND m.metadata_revision=OLD.metadata_revision
     AND m.data_revision=OLD.data_revision AND m.policy_revision=OLD.policy_revision
     AND m.certificates='{"coordinates":true,"numeric":true,"text":true,"detail":true,"generic":true}'::jsonb
     AND NEW.commit_revision=OLD.commit_revision+1 AND NEW.schema_epoch=OLD.schema_epoch
     AND NEW.metadata_revision=OLD.metadata_revision AND NEW.data_revision=OLD.data_revision
     AND NEW.policy_revision=OLD.policy_revision) THEN RAISE EXCEPTION 'PROJECTION_GENERATION_ACTIVATION_REQUIRED';END IF;
  END IF;
 END IF;RETURN NEW;END $$;

CREATE OR REPLACE FUNCTION epm.coordinate_project_inserted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM coordinate_inserted c JOIN epm.layout_replacement_activation x USING(workspace_id,application_id)
  WHERE x.status='Activating' AND epm.layout_replacement_activation_allowed(c.workspace_id,c.application_id,x.target_projection_generation)) THEN RETURN NULL;END IF;
 PERFORM 1 FROM epm.application_state s JOIN(SELECT DISTINCT workspace_id,application_id FROM coordinate_inserted)c USING(workspace_id,application_id)
  ORDER BY s.workspace_id,s.application_id FOR UPDATE OF s;
 IF EXISTS(SELECT 1 FROM coordinate_inserted c JOIN epm.application_state s USING(workspace_id,application_id)
  JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
  WHERE ARRAY(SELECT key FROM jsonb_object_keys(c.members)keys(key) ORDER BY key COLLATE "C")<>l.dimensions) THEN RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH';END IF;
 INSERT INTO epm.coordinate_projection_state(projection_generation,workspace_id,application_id,coordinate_id,schema_epoch,
  entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
 SELECT s.active_projection_generation,c.workspace_id,c.application_id,c.coordinate_id,l.schema_epoch,
 c.members->>(l.role_dimensions->>'Entity'),c.members->>(l.role_dimensions->>'Account'),c.members->>(l.role_dimensions->>'Scenario'),
 c.members->>(l.role_dimensions->>'Year'),c.members->>(l.role_dimensions->>'Period'),c.members->>(l.role_dimensions->>'Value'),
 c.members->>(l.role_dimensions->>'View'),c.members->>(l.role_dimensions->>'ICP'),c.members->>(l.role_dimensions->>'DataType'),
 ARRAY(SELECT c.members->>axis FROM unnest(l.custom_dimensions) WITH ORDINALITY z(axis,pos) ORDER BY pos)
 FROM coordinate_inserted c JOIN epm.application_state s USING(workspace_id,application_id)
 JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch);RETURN NULL;END $$;

CREATE OR REPLACE FUNCTION epm.coordinate_layout_dimension_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$ DECLARE w text;a text;BEGIN
 w:=CASE WHEN TG_OP='DELETE' THEN OLD.workspace_id ELSE NEW.workspace_id END;
 a:=CASE WHEN TG_OP='DELETE' THEN OLD.application_id ELSE NEW.application_id END;
 IF EXISTS(SELECT 1 FROM epm.layout_replacement_activation x WHERE x.workspace_id=w AND x.application_id=a
  AND x.status='Activating' AND epm.layout_replacement_activation_allowed(w,a,x.target_projection_generation)) THEN RETURN NULL;END IF;
 IF NOT pg_has_role(current_user,(SELECT relowner FROM pg_class WHERE oid='epm.coordinate_layout'::regclass),'USAGE')
  AND (current_setting('epm.workspace_id',true) IS DISTINCT FROM w OR current_setting('epm.application_id',true) IS DISTINCT FROM a)
 THEN RAISE EXCEPTION 'COORDINATE_LAYOUT_SCOPE_INVALID';END IF;
 PERFORM epm.coordinate_layout_refresh(w,a);RETURN NULL;END $$;

CREATE OR REPLACE FUNCTION epm.fact_projection_matches() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM fact_projected c WHERE NOT EXISTS(
  SELECT 1 FROM epm.layout_replacement_activation x WHERE x.workspace_id=c.workspace_id AND x.application_id=c.application_id
   AND x.target_projection_generation=c.projection_generation AND x.status='Activating'
   AND epm.layout_replacement_activation_allowed(c.workspace_id,c.application_id,c.projection_generation))) THEN RETURN NULL;END IF;
 IF TG_TABLE_NAME='numeric_cell_projection' THEN
  IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(SELECT * FROM epm.numeric_fact_event e WHERE e.workspace_id=c.workspace_id
   AND e.application_id=c.application_id AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
   LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
   WHERE e.event_id IS NULL OR(coalesce(r.sealed,true)AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id))
   OR ROW(c.present,c.amount,c.change_id,c.last_revision)IS DISTINCT FROM ROW(e.present,e.resulting_amount,e.change_id,e.committed_revision))
  THEN RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT';END IF;
 ELSIF TG_TABLE_NAME='text_cell_projection' THEN
  IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(SELECT * FROM epm.text_fact_event e WHERE e.workspace_id=c.workspace_id
   AND e.application_id=c.application_id AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC,line_ordinal DESC LIMIT 1)e ON true
   LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
   WHERE e.event_id IS NULL OR(coalesce(r.sealed,true)AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id))
   OR ROW(c.present,c.text_value,c.change_id,c.last_revision)IS DISTINCT FROM ROW(e.present,e.resulting_value,e.change_id,e.committed_revision))
  THEN RAISE EXCEPTION 'FACT_PROJECTION_INCONSISTENT';END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM fact_projected c LEFT JOIN LATERAL(SELECT * FROM epm.line_detail_event e WHERE e.workspace_id=c.workspace_id
   AND e.application_id=c.application_id AND e.coordinate_id=c.coordinate_id ORDER BY committed_revision DESC LIMIT 1)e ON true
   LEFT JOIN epm.operation_receipt r ON r.workspace_id=e.workspace_id AND r.application_id=e.application_id AND r.operation_id=e.operation_id
   WHERE e.event_id IS NULL OR(coalesce(r.sealed,true)AND NOT epm.fact_reconstruction_allowed(c.workspace_id,c.application_id))
   OR NOT e.present OR ROW(c.items,c.total,c.change_id,c.last_revision)IS DISTINCT FROM ROW(e.items,e.total,e.change_id,e.committed_revision))
  THEN RAISE EXCEPTION 'FACT_DETAIL_PROJECTION_INCONSISTENT';END IF;
 END IF;RETURN NULL;END $$;

CREATE FUNCTION epm.layout_replacement_activation_request(
 w text,a text,aid text,rid text,ikey text,rdigest text,issuer_name text,subject_name text,vdigest text,decisions jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE prior epm.layout_replacement_activation%ROWTYPE;s epm.application_state%ROWTYPE;c epm.layout_replacement_validation_certificate%ROWTYPE;
 target_gen bigint;BEGIN
 IF w<>current_setting('epm.workspace_id',true) OR a<>current_setting('epm.application_id',true) THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_SCOPE_INVALID';END IF;
 SELECT * INTO prior FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a
  AND issuer=issuer_name AND subject_id=subject_name AND idempotency_key=ikey;
 IF FOUND THEN IF prior.request_digest<>rdigest THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_IDEMPOTENCY_CONFLICT';END IF;
  RETURN jsonb_build_object('activationId',prior.activation_id,'status',prior.status,'duplicate',true);END IF;
 SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR SHARE;
 SELECT * INTO c FROM epm.layout_replacement_validation_certificate WHERE workspace_id=w AND application_id=a AND request_id=rid;
 IF NOT FOUND OR NOT c.activation_eligible OR c.validation_digest<>vdigest OR s.commit_open
  OR ROW(s.metadata_revision,s.data_revision,s.policy_revision,s.schema_epoch,s.commit_revision)
   IS DISTINCT FROM ROW(c.metadata_revision,c.data_revision,c.policy_revision,c.schema_epoch,c.source_commit_revision)
  OR NOT EXISTS(SELECT 1 FROM epm.layout_replacement_request r WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=rid AND r.status='Validated')
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_VALIDATION_STALE';END IF;
 SELECT greatest(s.active_projection_generation,coalesce(max(target_projection_generation),0))+1 INTO target_gen
  FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a;
 INSERT INTO epm.layout_replacement_activation(workspace_id,application_id,activation_id,request_id,idempotency_key,
  request_digest,issuer,subject_id,validation_digest,source_schema_epoch,target_schema_epoch,source_projection_generation,
  target_projection_generation,source_metadata_revision,source_data_revision,source_policy_revision,source_commit_revision,dependency_decisions)
 VALUES(w,a,aid,rid,ikey,rdigest,issuer_name,subject_name,vdigest,s.schema_epoch,s.schema_epoch+1,
  s.active_projection_generation,target_gen,s.metadata_revision,s.data_revision,s.policy_revision,s.commit_revision,decisions);
 RETURN jsonb_build_object('activationId',aid,'status','Requested','duplicate',false,'targetSchemaEpoch',s.schema_epoch+1,
  'targetProjectionGeneration',target_gen);END $$;

CREATE FUNCTION epm.layout_replacement_activation_claim(w text,a text,aid text,claimant_name text,seconds integer)
RETURNS TABLE(activation_id text,claim_generation bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 RETURN QUERY UPDATE epm.layout_replacement_activation x SET status='Activating',claim_generation=x.claim_generation+1,
  claimant=claimant_name,lease_until=clock_timestamp()+make_interval(secs=>seconds),updated_at=transaction_timestamp()
 WHERE x.workspace_id=w AND x.application_id=a AND x.activation_id=aid AND x.status='Requested' AND seconds BETWEEN 30 AND 300
 RETURNING x.activation_id,x.claim_generation;END $$;
CREATE FUNCTION epm.layout_replacement_activation_cancel(w text,a text,aid text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE n integer;BEGIN
 IF w<>current_setting('epm.workspace_id',true) OR a<>current_setting('epm.application_id',true) THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_SCOPE_INVALID';END IF;
 UPDATE epm.layout_replacement_activation SET status='Cancelled',claim_generation=claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE workspace_id=w AND application_id=a
  AND activation_id=aid AND status='Requested';GET DIAGNOSTICS n=ROW_COUNT;RETURN n=1;END $$;
CREATE FUNCTION epm.layout_replacement_activation_recover() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ DECLARE n integer;BEGIN
 UPDATE epm.layout_replacement_activation SET status='Requested',claim_generation=claim_generation+1,
  claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp() WHERE status='Activating' AND lease_until<=clock_timestamp();
 GET DIAGNOSTICS n=ROW_COUNT;RETURN n;END $$;

CREATE FUNCTION epm.layout_replacement_activation_publish(w text,a text,aid text,claimant_name text,generation bigint)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE x epm.layout_replacement_activation%ROWTYPE;s epm.application_state%ROWTYPE;cert epm.layout_replacement_validation_certificate%ROWTYPE;
 layout epm.coordinate_layout%ROWTYPE;revision bigint;outcome jsonb;BEGIN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||w,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('epm.application:'||w||':'||a,0));
 SELECT * INTO x FROM epm.layout_replacement_activation WHERE workspace_id=w AND application_id=a AND activation_id=aid FOR UPDATE;
 SELECT * INTO s FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
 SELECT * INTO cert FROM epm.layout_replacement_validation_certificate WHERE workspace_id=w AND application_id=a AND request_id=x.request_id;
 IF x.status='Activated' AND x.claim_generation=generation THEN RETURN x.result;END IF;
 IF x.status<>'Activating' OR x.claimant<>claimant_name OR x.claim_generation<>generation OR x.lease_until<=clock_timestamp()
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_STALE_WORKER';END IF;
 IF NOT cert.activation_eligible OR cert.validation_digest<>x.validation_digest OR s.commit_open OR s.processing_mode<>'Active'
  OR ROW(s.metadata_revision,s.data_revision,s.policy_revision,s.schema_epoch,s.commit_revision,s.active_projection_generation)
  IS DISTINCT FROM ROW(x.source_metadata_revision,x.source_data_revision,x.source_policy_revision,x.source_schema_epoch,
   x.source_commit_revision,x.source_projection_generation)
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
 PERFORM set_config('epm.layout_activation_context',jsonb_build_array(w,a,aid,x.target_projection_generation,generation,
  pg_current_xact_id()::text,pg_backend_pid())::text,true);
 UPDATE epm.dimension SET status=CASE WHEN dimension_id IN(SELECT z->>'dimensionId'
  FROM epm.layout_replacement_request r,LATERAL jsonb_array_elements(r.plan->'targetAxes')z
  WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=x.request_id) THEN 'Active' ELSE 'Inactive' END
 WHERE workspace_id=w AND application_id=a AND model_role IS DISTINCT FROM 'Currency';
 SELECT x.target_schema_epoch,ARRAY(SELECT z->>'dimensionId' FROM epm.layout_replacement_request r,
  jsonb_array_elements(r.plan->'targetAxes')z WHERE r.workspace_id=w AND r.application_id=a AND r.request_id=x.request_id ORDER BY z->>'dimensionId'),
  coalesce(jsonb_object_agg(d.model_role,d.dimension_id)FILTER(WHERE d.model_role IS NOT NULL AND d.model_role<>'Custom'),'{}'),
  coalesce(array_agg(d.dimension_id ORDER BY d.dimension_id)FILTER(WHERE d.model_role IS NULL OR d.model_role='Custom'),'{}')
 INTO layout.schema_epoch,layout.dimensions,layout.role_dimensions,layout.custom_dimensions FROM epm.dimension d
 WHERE d.workspace_id=w AND d.application_id=a AND d.status='Active' AND d.model_role IS DISTINCT FROM 'Currency';
 INSERT INTO epm.coordinate_layout VALUES(w,a,layout.schema_epoch,layout.dimensions,layout.role_dimensions,layout.custom_dimensions);
 INSERT INTO epm.coordinate(workspace_id,application_id,series_key,members)
 SELECT w,a,epm.coordinate_series_key(p.target_members),p.target_members FROM epm.layout_replacement_private_coordinate p
  WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id ON CONFLICT DO NOTHING;
 INSERT INTO epm.layout_replacement_activation_coordinate SELECT w,a,aid,p.target_digest,c.coordinate_id
 FROM epm.layout_replacement_private_coordinate p JOIN epm.coordinate c ON c.workspace_id=p.workspace_id
  AND c.application_id=p.application_id AND c.series_key=epm.coordinate_series_key(p.target_members)
 WHERE p.workspace_id=w AND p.application_id=a AND p.generation_id=cert.generation_id;
 INSERT INTO epm.coordinate_member_projection(projection_generation,workspace_id,application_id,coordinate_id,dimension_id,member_id)
 SELECT x.target_projection_generation,w,a,m.coordinate_id,z.key,z.value
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_coordinate p USING(workspace_id,application_id,target_digest),
  LATERAL jsonb_each_text(p.target_members)z WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.coordinate_projection_state(projection_generation,workspace_id,application_id,coordinate_id,schema_epoch,fact_table_id,
  entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
 SELECT x.target_projection_generation,w,a,m.coordinate_id,x.target_schema_epoch,'cube',
  p.target_members->>(layout.role_dimensions->>'Entity'),p.target_members->>(layout.role_dimensions->>'Account'),
  p.target_members->>(layout.role_dimensions->>'Scenario'),p.target_members->>(layout.role_dimensions->>'Year'),
  p.target_members->>(layout.role_dimensions->>'Period'),p.target_members->>(layout.role_dimensions->>'Value'),
  p.target_members->>(layout.role_dimensions->>'View'),p.target_members->>(layout.role_dimensions->>'ICP'),
  p.target_members->>(layout.role_dimensions->>'DataType'),ARRAY(SELECT p.target_members->>d FROM unnest(layout.custom_dimensions)d)
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_coordinate p USING(workspace_id,application_id,target_digest)
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 revision:=s.commit_revision+1;
 INSERT INTO epm.numeric_cell_projection SELECT w,a,m.coordinate_id,n.present,n.amount,'layout:'||aid,revision,x.target_projection_generation
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_numeric n USING(workspace_id,application_id,target_digest)
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.text_cell_projection SELECT w,a,m.coordinate_id,t.present,t.text_value,'layout:'||aid,revision,x.target_projection_generation
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_text t USING(workspace_id,application_id,target_digest)
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid;
 INSERT INTO epm.line_detail_projection SELECT w,a,m.coordinate_id,d.items,d.total,'layout:'||aid,revision,x.target_projection_generation
 FROM epm.layout_replacement_activation_coordinate m JOIN epm.layout_replacement_private_detail d USING(workspace_id,application_id,target_digest)
 WHERE m.workspace_id=w AND m.application_id=a AND m.activation_id=aid AND d.present;
 INSERT INTO epm.generic_fact_projection SELECT w,a,g.table_id,g.series_key,g.value,g.change_id,g.last_revision,g.updated_at,x.target_projection_generation
 FROM epm.generic_fact_projection g WHERE g.workspace_id=w AND g.application_id=a AND g.projection_generation=x.source_projection_generation;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(x.dependency_decisions)d WHERE d->>'decision' IN('Invalidate','Rebuild')
  AND ((d->>'kind'='rule' AND NOT EXISTS(SELECT 1 FROM epm.expression_rule_publication p WHERE p.workspace_id=w AND p.application_id=a AND p.rule_id=d->>'id'))
    OR(d->>'kind'='publication' AND NOT EXISTS(SELECT 1 FROM epm.calculation_publication p WHERE p.workspace_id=w AND p.application_id=a AND p.result_key=d->>'id'))))
 THEN RAISE EXCEPTION 'LAYOUT_ACTIVATION_DEPENDENCY_UNRESOLVED';END IF;
 DELETE FROM epm.expression_rule_publication p USING jsonb_array_elements(x.dependency_decisions)d WHERE p.workspace_id=w AND p.application_id=a
  AND d->>'kind'='rule' AND d->>'decision' IN('Invalidate','Rebuild') AND p.rule_id=d->>'id';
 DELETE FROM epm.calculation_publication p USING jsonb_array_elements(x.dependency_decisions)d WHERE p.workspace_id=w AND p.application_id=a
  AND d->>'kind'='publication' AND d->>'decision' IN('Invalidate','Rebuild') AND p.result_key=d->>'id';
 UPDATE epm.application_state SET schema_epoch=x.target_schema_epoch,metadata_revision=metadata_revision+1,
  data_revision=data_revision+1,active_projection_generation=x.target_projection_generation,commit_revision=revision
 WHERE workspace_id=w AND application_id=a;
 outcome:=jsonb_build_object('activationId',aid,'requestId',x.request_id,'committedRevision',revision,
  'schemaEpoch',x.target_schema_epoch,'projectionGeneration',x.target_projection_generation,'historyPreserved',true);
 INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,command_digest,actor_id,committed_revision,result)
 VALUES(w,a,aid,x.validation_digest,x.subject_id,revision,outcome);
 UPDATE epm.layout_replacement_activation SET status='Activated',result=outcome,claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
 WHERE workspace_id=w AND application_id=a AND activation_id=aid;
 RETURN outcome;END $$;

REVOKE ALL ON FUNCTION epm.layout_replacement_activation_request(text,text,text,text,text,text,text,text,text,jsonb),
 epm.layout_replacement_activation_claim(text,text,text,text,integer),epm.layout_replacement_activation_cancel(text,text,text),
 epm.layout_replacement_activation_publish(text,text,text,text,bigint),epm.layout_replacement_activation_recover() FROM PUBLIC,epm_runtime,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_request(text,text,text,text,text,text,text,text,text,jsonb),
 epm.layout_replacement_activation_cancel(text,text,text) TO epm_runtime;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_claim(text,text,text,text,integer),
 epm.layout_replacement_activation_publish(text,text,text,text,bigint),epm.layout_replacement_activation_recover() TO epm_worker;

DO $$ DECLARE old text:='fddc1a68c34b5af78f8b804b2d4a84555d79e8f20a029aae6fa5a1443009801e';
 new text:='7ffba0dfc873a068e6e2572146420c926f334e77d1bacb6a5d27194de52c423b';d text;r text;
 b text:='''layout_replacement_validation_certificate'',''layout_replacement_materialization_chunk''';
 a text:='''layout_replacement_activation_coordinate'',''layout_replacement_activation'',''layout_replacement_validation_certificate'',''layout_replacement_materialization_chunk''';
 gate text:='    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),';
 gated text:='    IF EXISTS (SELECT 1 FROM epm.layout_replacement_activation WHERE workspace_id=p_workspace_id AND status IN (''Requested'',''Activating'')) THEN RAISE EXCEPTION ''UNSETTLED_LAYOUT_ACTIVATION''; END IF;'||chr(10)||chr(10)||gate;
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)INTO d;
 IF position(old in d)=0 OR position(b in d)=0 OR position(gate in d)=0 THEN RAISE EXCEPTION 'RESET_0110_DEFINITION_MISMATCH';END IF;
 r:=replace(replace(replace(d,old,new),b,a),gate,gated);EXECUTE r;END $$;
