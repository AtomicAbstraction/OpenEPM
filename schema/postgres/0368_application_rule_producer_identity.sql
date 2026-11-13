BEGIN;
DO $preflight$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=367) THEN
  RAISE EXCEPTION 'MIGRATION_0368_REQUIRES_0367';
 END IF;
 IF EXISTS(SELECT 1 FROM epm.application_rule_workflow_child
  GROUP BY workspace_id,application_id,job_id HAVING count(*)<>1) THEN
  RAISE EXCEPTION 'PRODUCER_0368_AMBIGUOUS_CHILD';
 END IF;
 IF EXISTS(SELECT 1 FROM epm.calculation_result_state p LEFT JOIN epm.job j
  ON(j.workspace_id,j.application_id,j.job_id)=(p.workspace_id,p.application_id,p.source_operation_id)
  WHERE j.job_id IS NULL OR j.status<>'published'
   OR (p.source_function,p.source_compiler_version,p.source_program_digest) IS DISTINCT FROM
      (j.function_name,j.compiler_version,j.program_digest)) THEN
  RAISE EXCEPTION 'PRODUCER_0368_CURRENT_HEAD_JOB_UNPROVEN';
 END IF;
 IF EXISTS(SELECT 1 FROM epm.job WHERE status IN
  ('accepted','ready','running','staged','cancel_requested','needs_inspection'))
  OR EXISTS(SELECT 1 FROM epm.application_rule_workflow WHERE status IN
  ('accepted','running','cancel_requested','needs_inspection')) THEN
  RAISE EXCEPTION 'PRODUCER_0368_ACTIVE_LEGACY_WORK';
 END IF;
END $preflight$;

-- Preserve existing records without inferring authority from names or a
-- historical child link. Every new admission must choose its explicit origin.
ALTER TABLE epm.job ADD COLUMN admission_origin_kind text NOT NULL DEFAULT 'unresolved'
 CHECK(admission_origin_kind IN('ordinary','application_rule','unresolved'));
ALTER TABLE epm.job ALTER COLUMN admission_origin_kind DROP DEFAULT;
ALTER TABLE epm.application_rule_workflow ADD COLUMN owner_certificate_digest text
 CHECK(owner_certificate_digest IS NULL OR owner_certificate_digest~'^[0-9a-f]{64}$');
ALTER TABLE epm.application_rule_workflow_child ADD CONSTRAINT application_rule_child_job_unique
 UNIQUE(workspace_id,application_id,job_id);
ALTER TABLE epm.calculation_result_state ADD CONSTRAINT calculation_result_source_job_fk
 FOREIGN KEY(workspace_id,application_id,source_operation_id)
 REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE RESTRICT;
CREATE INDEX calculation_result_source_operation
 ON epm.calculation_result_state(workspace_id,application_id,source_operation_id);

CREATE FUNCTION epm.job_admission_origin_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' AND (NEW.admission_origin_kind IS NULL OR NEW.admission_origin_kind='unresolved') THEN
  RAISE EXCEPTION 'JOB_ADMISSION_ORIGIN_REQUIRED' USING ERRCODE='23514';
 END IF;
 IF NEW.admission_origin_kind='application_rule' AND
  (NEW.python_workflow_id IS NOT NULL OR NEW.execution_delegation_id IS NOT NULL
   OR NEW.execution_delegation_state_token IS NOT NULL OR NEW.execution_schedule_id IS NOT NULL
   OR NEW.execution_schedule_state_token IS NOT NULL) THEN
  RAISE EXCEPTION 'JOB_ADMISSION_ORIGIN_CONFLICT' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND (NEW.workspace_id,NEW.application_id,NEW.job_id,NEW.admission_origin_kind,NEW.issuer,NEW.subject_id,NEW.idempotency_key,NEW.function_name,NEW.normalized_program,NEW.compiler_version,NEW.program_digest,NEW.request_digest,NEW.plan_digest,NEW.expected_metadata_revision,NEW.expected_data_revision,NEW.expected_policy_revision,NEW.resource_class,NEW.verified_groups,NEW.authorization_scope_digest,NEW.python_workflow_id,NEW.execution_delegation_id,NEW.execution_delegation_state_token,NEW.execution_schedule_id,NEW.execution_schedule_state_token,NEW.token_issued_at,NEW.authority_kind)
  IS DISTINCT FROM (OLD.workspace_id,OLD.application_id,OLD.job_id,OLD.admission_origin_kind,OLD.issuer,OLD.subject_id,OLD.idempotency_key,OLD.function_name,OLD.normalized_program,OLD.compiler_version,OLD.program_digest,OLD.request_digest,OLD.plan_digest,OLD.expected_metadata_revision,OLD.expected_data_revision,OLD.expected_policy_revision,OLD.resource_class,OLD.verified_groups,OLD.authorization_scope_digest,OLD.python_workflow_id,OLD.execution_delegation_id,OLD.execution_delegation_state_token,OLD.execution_schedule_id,OLD.execution_schedule_state_token,OLD.token_issued_at,OLD.authority_kind) THEN
  RAISE EXCEPTION 'JOB_ADMISSION_ORIGIN_IMMUTABLE' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER job_admission_origin_guard BEFORE INSERT OR UPDATE OF
 workspace_id,application_id,job_id,admission_origin_kind,issuer,subject_id,idempotency_key,function_name,normalized_program,compiler_version,program_digest,request_digest,plan_digest,expected_metadata_revision,expected_data_revision,expected_policy_revision,resource_class,verified_groups,authorization_scope_digest,python_workflow_id,execution_delegation_id,execution_delegation_state_token,execution_schedule_id,execution_schedule_state_token,token_issued_at,authority_kind ON epm.job
 FOR EACH ROW EXECUTE FUNCTION epm.job_admission_origin_guard();

CREATE FUNCTION epm.application_rule_owner_certificate_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE owner_row epm.expression_rule_definition%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' THEN
  IF (NEW.workspace_id,NEW.application_id,NEW.workflow_id,NEW.rule_id,NEW.rule_state_token,
      NEW.program_digest,NEW.owner_certificate_digest,NEW.sealed_plan,NEW.plan_digest,NEW.compiler_version,
      NEW.expected_metadata_revision,NEW.expected_policy_revision,NEW.expected_schema_epoch,
      NEW.issuer,NEW.subject_id,NEW.verified_groups,NEW.authorization_scope_digest)
   IS DISTINCT FROM
     (OLD.workspace_id,OLD.application_id,OLD.workflow_id,OLD.rule_id,OLD.rule_state_token,
      OLD.program_digest,OLD.owner_certificate_digest,OLD.sealed_plan,OLD.plan_digest,OLD.compiler_version,
      OLD.expected_metadata_revision,OLD.expected_policy_revision,OLD.expected_schema_epoch,
      OLD.issuer,OLD.subject_id,OLD.verified_groups,OLD.authorization_scope_digest) THEN
   RAISE EXCEPTION 'APPLICATION_RULE_OWNER_CERTIFICATE_IMMUTABLE' USING ERRCODE='23514';
  END IF;
 ELSE
  SELECT * INTO owner_row FROM epm.expression_rule_definition
   WHERE(workspace_id,application_id,rule_id)=(NEW.workspace_id,NEW.application_id,NEW.rule_id);
  IF NEW.owner_certificate_digest IS NULL OR owner_row.current_certificate IS NULL
   OR owner_row.definition_kind IS DISTINCT FROM 'ApplicationRule' OR owner_row.status IS DISTINCT FROM 'Active'
   OR (owner_row.state_token,owner_row.program_digest) IS DISTINCT FROM (NEW.rule_state_token,NEW.program_digest)
   OR NEW.owner_certificate_digest IS DISTINCT FROM encode(sha256(convert_to(
        epm.definition_canonical_json(owner_row.current_certificate),'UTF8')),'hex') THEN
   RAISE EXCEPTION 'APPLICATION_RULE_OWNER_CERTIFICATE_REQUIRED' USING ERRCODE='23514';
  END IF;
  IF NEW.sealed_plan->>'format' IS DISTINCT FROM 'openepm-python-plan-v1'
   OR jsonb_typeof(NEW.sealed_plan->'units') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'APPLICATION_RULE_SEALED_PLAN_SHAPE_INVALID' USING ERRCODE='23514';
  END IF;
  IF jsonb_array_length(NEW.sealed_plan->'units') NOT BETWEEN 1 AND 500 THEN
   RAISE EXCEPTION 'APPLICATION_RULE_SEALED_PLAN_SHAPE_INVALID' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER application_rule_owner_certificate_guard BEFORE INSERT OR UPDATE
 ON epm.application_rule_workflow FOR EACH ROW EXECUTE FUNCTION epm.application_rule_owner_certificate_guard();

CREATE FUNCTION epm.application_rule_child_origin_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE child_job epm.job%ROWTYPE; parent epm.application_rule_workflow%ROWTYPE;
BEGIN
 IF TG_OP='UPDATE' THEN
  RAISE EXCEPTION 'APPLICATION_RULE_CHILD_IDENTITY_IMMUTABLE' USING ERRCODE='23514';
 ELSIF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM epm.calculation_result_state WHERE
    (workspace_id,application_id,source_operation_id)=(OLD.workspace_id,OLD.application_id,OLD.job_id)) THEN
   RAISE EXCEPTION 'APPLICATION_RULE_CHILD_CURRENT_RESULT_REQUIRED' USING ERRCODE='23514';
  END IF;
  IF EXISTS(SELECT 1 FROM epm.job WHERE
    (workspace_id,application_id,job_id)=(OLD.workspace_id,OLD.application_id,OLD.job_id)
    AND status IN('accepted','ready','running','staged','cancel_requested','needs_inspection')) THEN
   RAISE EXCEPTION 'APPLICATION_RULE_CHILD_ACTIVE_JOB_REQUIRED' USING ERRCODE='23514';
  END IF;
  RETURN OLD;
 END IF;
 SELECT * INTO child_job FROM epm.job WHERE
  (workspace_id,application_id,job_id)=(NEW.workspace_id,NEW.application_id,NEW.job_id);
 SELECT * INTO parent FROM epm.application_rule_workflow WHERE
  (workspace_id,application_id,workflow_id)=(NEW.workspace_id,NEW.application_id,NEW.workflow_id);
 IF jsonb_typeof(parent.sealed_plan->'units') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'APPLICATION_RULE_CHILD_ORIGIN_MISMATCH' USING ERRCODE='23514';
 END IF;
 IF child_job.admission_origin_kind IS DISTINCT FROM 'application_rule'
  OR parent.owner_certificate_digest IS NULL
  OR parent.status NOT IN('accepted','running')
  OR NEW.unit_ordinal>jsonb_array_length(parent.sealed_plan->'units')
  OR (child_job.issuer,child_job.subject_id,child_job.verified_groups,child_job.authorization_scope_digest)
     IS DISTINCT FROM (parent.issuer,parent.subject_id,parent.verified_groups,parent.authorization_scope_digest) THEN
  RAISE EXCEPTION 'APPLICATION_RULE_CHILD_ORIGIN_MISMATCH' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER application_rule_child_origin_guard BEFORE INSERT OR UPDATE OR DELETE
 ON epm.application_rule_workflow_child FOR EACH ROW EXECUTE FUNCTION epm.application_rule_child_origin_guard();

CREATE FUNCTION epm.application_rule_origin_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE w text; a text; jid text; origin text; links bigint;
BEGIN
 IF TG_OP='DELETE' THEN w:=OLD.workspace_id;a:=OLD.application_id;jid:=OLD.job_id;
 ELSE w:=NEW.workspace_id;a:=NEW.application_id;jid:=NEW.job_id;END IF;
 SELECT admission_origin_kind INTO origin FROM epm.job WHERE
  (workspace_id,application_id,job_id)=(w,a,jid);
 IF NOT FOUND OR origin='unresolved' THEN RETURN NULL;END IF;
 SELECT count(*) INTO links FROM epm.application_rule_workflow_child WHERE
  (workspace_id,application_id,job_id)=(w,a,jid);
 IF (origin='application_rule' AND links<>1) OR (origin='ordinary' AND links<>0) THEN
  RAISE EXCEPTION 'APPLICATION_RULE_JOB_ORIGIN_INCOMPLETE' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER application_rule_job_origin_complete
 AFTER INSERT OR UPDATE OF admission_origin_kind ON epm.job DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.application_rule_origin_complete();
CREATE CONSTRAINT TRIGGER application_rule_child_origin_complete
 AFTER INSERT OR UPDATE OR DELETE ON epm.application_rule_workflow_child DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.application_rule_origin_complete();
REVOKE ALL ON FUNCTION epm.job_admission_origin_guard(),epm.application_rule_owner_certificate_guard(),
 epm.application_rule_child_origin_guard(),epm.application_rule_origin_complete() FROM PUBLIC;

-- Reorder precisely the existing inventories. The additional head-before-child
-- edge represents the deletion guard above; every other edge comes from FKs.
-- The resulting literals remain fixed owner-only deletion inventories.
DO $inventory$
DECLARE signature text; definition text; body text; original text[]; physical text[];
 pending text[]; ordered text[]; name text; chosen text; item text; i integer; mode integer;
BEGIN
 FOR mode IN 1..2 LOOP
  IF mode=1 THEN
   SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
   body:=split_part(split_part(definition,'FOREACH v_table IN ARRAY ARRAY[',2),']',1);
   IF body='' THEN RAISE EXCEPTION 'PRODUCER_0368_RESET_INVENTORY_MISSING';END IF;
   EXECUTE 'SELECT ARRAY['||body||']::text[]' INTO original;
  ELSE original:=epm.application_purge_relations();END IF;
  physical:='{}';
  FOREACH item IN ARRAY original LOOP
   physical:=array_append(physical,CASE item
    WHEN 'numeric_cell_current' THEN 'numeric_cell_projection'
    WHEN 'text_cell_current' THEN 'text_cell_projection'
    WHEN 'line_detail_current' THEN 'line_detail_projection'
    WHEN 'generic_fact_current' THEN 'generic_fact_projection'
    WHEN 'coordinate_member' THEN 'coordinate_member_projection'
    WHEN 'coordinate_projection' THEN 'coordinate_projection_state' ELSE item END);
  END LOOP;
  IF NOT physical @> ARRAY['calculation_result_state','application_rule_workflow_child','application_rule_workflow','job'] THEN
   RAISE EXCEPTION 'PRODUCER_0368_LIFECYCLE_INVENTORY_INVALID' USING DETAIL=format('mode=%s inventory=%s',mode,physical);END IF;
  pending:=physical;ordered:='{}';
  WHILE cardinality(pending)>0 LOOP
   chosen:=NULL;
   FOREACH name IN ARRAY pending LOOP
    IF name='application_rule_workflow_child' AND 'calculation_result_state'=ANY(pending) THEN CONTINUE;END IF;
    IF NOT EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid
      JOIN pg_namespace ns ON ns.oid=child.relnamespace
      WHERE c.contype='f' AND c.confrelid=to_regclass('epm.'||quote_ident(name))
       AND ns.nspname='epm' AND child.relname<>name AND child.relname=ANY(pending)) THEN
     chosen:=name;EXIT;
    END IF;
   END LOOP;
   IF chosen IS NULL THEN RAISE EXCEPTION 'PRODUCER_0368_LIFECYCLE_ORDER_CYCLE';END IF;
   -- Existing reset aliases can address the same physical relation more
   -- than once. Preserve every original entry, grouped at that node's turn.
   FOR i IN 1..cardinality(original) LOOP
    IF physical[i]=chosen THEN ordered:=array_append(ordered,original[i]);END IF;
   END LOOP;
   pending:=array_remove(pending,chosen);
  END LOOP;
  IF mode=1 THEN
   SELECT string_agg(quote_literal(v),',' ORDER BY ordinal) INTO item FROM unnest(ordered) WITH ORDINALITY AS t(v,ordinal);
   EXECUTE replace(definition,'FOREACH v_table IN ARRAY ARRAY['||body||']','FOREACH v_table IN ARRAY ARRAY['||item||']');
  ELSE
   EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(ordered::text)||'::text[]');
  END IF;
 END LOOP;
END $inventory$;

-- Measured on the owned fresh368 schema; no shared application is adopted.
DO $graph$ DECLARE signature text;definition text;
 previous constant text:='b10318fc081736be88091fb3f13bbcf31b7f545d6dda8decce0bffca23080508';
 current_graph constant text:='e2995ccaffc189892c442f38c30cfe576d02aa87473280a5de77e170bca8a0a9';
BEGIN
 FOREACH signature IN ARRAY ARRAY[
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)',
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'] LOOP
  SELECT pg_get_functiondef(signature::regprocedure) INTO definition;
  IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'PRODUCER_0368_LIFECYCLE_GRAPH_PREDECESSOR_MISMATCH';END IF;
  EXECUTE replace(definition,previous,current_graph);
 END LOOP;
END $graph$;
COMMIT;
