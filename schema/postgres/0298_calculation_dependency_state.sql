BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=297) THEN
    RAISE EXCEPTION 'MIGRATION_0298_REQUIRES_0297';
  END IF;
END $migration$;

-- W05 keeps immutable symbolic dependencies separate from the exact tokens
-- resolved for one invocation.  Mutable scope currentness is derived control
-- state; the existing calculation_publication remains the only result head.
ALTER TABLE epm.calculation_generation
  ADD COLUMN generation_kind text NOT NULL DEFAULT 'flat'
  CHECK(generation_kind IN('flat','partition_manifest'));

CREATE TABLE epm.calculation_dependency_template(
  workspace_id text NOT NULL, application_id text NOT NULL,
  template_digest text NOT NULL CHECK(template_digest~'^[0-9a-f]{64}$'),
  definition_id text NOT NULL CHECK(length(definition_id) BETWEEN 1 AND 200),
  definition_version bigint NOT NULL CHECK(definition_version>0),
  definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
  compiler_version text NOT NULL CHECK(length(compiler_version) BETWEEN 1 AND 200),
  schema_epoch bigint NOT NULL CHECK(schema_epoch>=0),
  coverage text NOT NULL CHECK(coverage IN('complete','conservative_superset','unknown')),
  template jsonb NOT NULL CHECK(jsonb_typeof(template)='object'
    AND template->>'format'='openepm-calculation-dependency-template-v1'
    AND octet_length(template::text)<=4194304),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,template_digest),
  UNIQUE(workspace_id,application_id,definition_id,definition_version,
         definition_digest,compiler_version),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_instance_binding(
  workspace_id text NOT NULL, application_id text NOT NULL,
  binding_digest text NOT NULL CHECK(binding_digest~'^[0-9a-f]{64}$'),
  template_digest text NOT NULL,
  definition_id text NOT NULL CHECK(length(definition_id) BETWEEN 1 AND 200),
  definition_version bigint NOT NULL CHECK(definition_version>0),
  stage text NOT NULL CHECK(length(stage) BETWEEN 1 AND 200),
  partition_policy_version bigint NOT NULL CHECK(partition_policy_version>0),
  parameters jsonb NOT NULL CHECK(jsonb_typeof(parameters)='object'
    AND octet_length(parameters::text)<=1048576),
  binding jsonb NOT NULL CHECK(jsonb_typeof(binding)='object'
    AND binding->>'format'='openepm-calculation-instance-binding-v1'
    AND binding->>'bindingDigest'=binding_digest
    AND octet_length(binding::text)<=2097152),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,binding_digest),
  FOREIGN KEY(workspace_id,application_id,template_digest)
    REFERENCES epm.calculation_dependency_template
      (workspace_id,application_id,template_digest) ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_execution_manifest(
  workspace_id text NOT NULL, application_id text NOT NULL,
  manifest_digest text NOT NULL CHECK(manifest_digest~'^[0-9a-f]{64}$'),
  template_digest text NOT NULL, binding_digest text NOT NULL,
  job_id text NOT NULL,
  schema_epoch bigint NOT NULL CHECK(schema_epoch>=0),
  read_commit_revision bigint NOT NULL CHECK(read_commit_revision>=0),
  read_metadata_revision bigint NOT NULL CHECK(read_metadata_revision>=0),
  read_data_revision bigint NOT NULL CHECK(read_data_revision>=0),
  read_policy_revision bigint NOT NULL CHECK(read_policy_revision>=0),
  coverage text NOT NULL CHECK(coverage IN('complete','conservative_superset','unknown')),
  manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'
    AND manifest->>'format'='openepm-calculation-execution-manifest-v1'
    AND octet_length(manifest::text)<=8388608),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,manifest_digest),
  UNIQUE(workspace_id,application_id,job_id),
  FOREIGN KEY(workspace_id,application_id,template_digest)
    REFERENCES epm.calculation_dependency_template
      (workspace_id,application_id,template_digest) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,binding_digest)
    REFERENCES epm.calculation_instance_binding
      (workspace_id,application_id,binding_digest) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,job_id)
    REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_dependency_index(
  workspace_id text NOT NULL, application_id text NOT NULL,
  manifest_digest text NOT NULL,
  dependency_ordinal integer NOT NULL CHECK(dependency_ordinal BETWEEN 0 AND 499),
  dependency_kind text NOT NULL CHECK(dependency_kind IN
    ('raw','absence_range','selector','hierarchy','formula','calendar','unit_policy','upstream')),
  object_type text NOT NULL CHECK(length(object_type) BETWEEN 1 AND 200),
  object_id text NOT NULL CHECK(length(object_id) BETWEEN 1 AND 200),
  token_digest text NOT NULL CHECK(token_digest~'^[0-9a-f]{64}$'),
  scope_matcher jsonb NOT NULL CHECK(jsonb_typeof(scope_matcher)='object'
    AND octet_length(scope_matcher::text)<=2097152),
  output_partition text NOT NULL CHECK(length(output_partition) BETWEEN 1 AND 200),
  PRIMARY KEY(workspace_id,application_id,manifest_digest,
              dependency_ordinal,output_partition),
  FOREIGN KEY(workspace_id,application_id,manifest_digest)
    REFERENCES epm.calculation_execution_manifest
      (workspace_id,application_id,manifest_digest) ON DELETE RESTRICT
);
CREATE INDEX calculation_dependency_reverse_object
  ON epm.calculation_dependency_index
  (workspace_id,application_id,dependency_kind,object_type,object_id);
CREATE INDEX calculation_dependency_reverse_token
  ON epm.calculation_dependency_index
  (workspace_id,application_id,token_digest,output_partition);

CREATE TABLE epm.calculation_scope_state(
  workspace_id text NOT NULL, application_id text NOT NULL,
  binding_digest text NOT NULL,
  stage text NOT NULL CHECK(length(stage) BETWEEN 1 AND 200),
  partition_key text NOT NULL CHECK(length(partition_key) BETWEEN 1 AND 200),
  current_generation_id text CHECK(current_generation_id~'^[0-9a-f]{32}$'),
  required_epoch bigint NOT NULL CHECK(required_epoch>=0),
  published_epoch bigint NOT NULL CHECK(published_epoch>=0 AND published_epoch<=required_epoch),
  dependency_token_digest text CHECK(dependency_token_digest~'^[0-9a-f]{64}$'),
  definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
  coverage text NOT NULL CHECK(coverage IN('complete','conservative_superset','unknown')),
  presence text NOT NULL CHECK(presence IN('unknown','empty','present')),
  reasons text[] NOT NULL DEFAULT '{}' CHECK(reasons<@ARRAY[
    'data_changed','upstream_changed','membership_changed','hierarchy_changed',
    'definition_changed','calendar_changed','unit_policy_changed','coverage_unknown']::text[]),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,binding_digest,stage,partition_key),
  FOREIGN KEY(workspace_id,application_id,binding_digest)
    REFERENCES epm.calculation_instance_binding
      (workspace_id,application_id,binding_digest) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,current_generation_id)
    REFERENCES epm.calculation_generation
      (workspace_id,application_id,generation_id) ON DELETE RESTRICT,
  CHECK((coverage='complete' AND NOT ('coverage_unknown'=ANY(reasons)))
     OR (coverage<>'complete' AND 'coverage_unknown'=ANY(reasons)))
);
CREATE INDEX calculation_scope_state_required
  ON epm.calculation_scope_state
  (workspace_id,application_id,required_epoch,published_epoch,binding_digest);

-- New partitioned profiles attach one immutable map to a normal logical
-- generation.  W07 owns atomic map replacement/publication; these relations
-- cannot become a second mutable result pointer.
CREATE TABLE epm.calculation_generation_manifest(
  workspace_id text NOT NULL, application_id text NOT NULL,
  generation_id text NOT NULL,
  binding_digest text NOT NULL, execution_manifest_digest text NOT NULL,
  partition_policy_version bigint NOT NULL CHECK(partition_policy_version>0),
  partition_map_digest text NOT NULL CHECK(partition_map_digest~'^[0-9a-f]{64}$'),
  partition_map jsonb NOT NULL CHECK(jsonb_typeof(partition_map)='object'
    AND partition_map->>'format'='openepm-calculation-generation-manifest-v1'
    AND octet_length(partition_map::text)<=8388608),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,generation_id),
  FOREIGN KEY(workspace_id,application_id,generation_id)
    REFERENCES epm.calculation_generation
      (workspace_id,application_id,generation_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,binding_digest)
    REFERENCES epm.calculation_instance_binding
      (workspace_id,application_id,binding_digest) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,execution_manifest_digest)
    REFERENCES epm.calculation_execution_manifest
      (workspace_id,application_id,manifest_digest) ON DELETE RESTRICT
);

CREATE TABLE epm.calculation_generation_partition(
  workspace_id text NOT NULL, application_id text NOT NULL,
  generation_id text NOT NULL,
  partition_key text NOT NULL CHECK(length(partition_key) BETWEEN 1 AND 200),
  fragment_generation_id text CHECK(fragment_generation_id~'^[0-9a-f]{32}$'),
  certificate_digest text NOT NULL CHECK(certificate_digest~'^[0-9a-f]{64}$'),
  presence text NOT NULL CHECK(presence IN('empty','present')),
  row_count bigint NOT NULL CHECK(row_count>=0),
  PRIMARY KEY(workspace_id,application_id,generation_id,partition_key),
  FOREIGN KEY(workspace_id,application_id,generation_id)
    REFERENCES epm.calculation_generation_manifest
      (workspace_id,application_id,generation_id) ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,fragment_generation_id)
    REFERENCES epm.calculation_generation
      (workspace_id,application_id,generation_id) ON DELETE RESTRICT,
  CHECK((presence='empty' AND fragment_generation_id IS NULL AND row_count=0)
     OR (presence='present' AND fragment_generation_id IS NOT NULL AND row_count>0))
);

CREATE FUNCTION epm.calculation_dependency_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
BEGIN
  IF TG_OP='DELETE' AND current_setting('epm.lifecycle_context',true)='workspace_reset'
     AND pg_has_role(session_user,'epm_lifecycle','member') THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'CALCULATION_DEPENDENCY_ARTIFACT_IMMUTABLE' USING ERRCODE='23514';
END $function$;
REVOKE ALL ON FUNCTION epm.calculation_dependency_immutable() FROM PUBLIC;
DO $migration$ DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['calculation_dependency_template',
   'calculation_instance_binding','calculation_execution_manifest',
   'calculation_dependency_index','calculation_generation_manifest',
   'calculation_generation_partition'] LOOP
  EXECUTE format('CREATE TRIGGER %I_immutable BEFORE UPDATE OR DELETE ON epm.%I '
    'FOR EACH ROW EXECUTE FUNCTION epm.calculation_dependency_immutable()',relation,relation);
 END LOOP;
END $migration$;

REVOKE ALL ON epm.calculation_dependency_template,
 epm.calculation_instance_binding,epm.calculation_execution_manifest,
 epm.calculation_dependency_index,epm.calculation_scope_state,
 epm.calculation_generation_manifest,epm.calculation_generation_partition
 FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT ON epm.calculation_dependency_template,
 epm.calculation_instance_binding,epm.calculation_execution_manifest,
 epm.calculation_dependency_index,epm.calculation_generation_manifest,
 epm.calculation_generation_partition TO epm_runtime,epm_worker;
GRANT SELECT,INSERT,UPDATE ON epm.calculation_scope_state TO epm_runtime,epm_worker;
GRANT SELECT ON epm.calculation_dependency_template,
 epm.calculation_instance_binding,epm.calculation_execution_manifest,
 epm.calculation_dependency_index,epm.calculation_scope_state,
 epm.calculation_generation_manifest,epm.calculation_generation_partition
 TO epm_analyst,epm_lifecycle;
GRANT DELETE ON epm.calculation_dependency_template,
 epm.calculation_instance_binding,epm.calculation_execution_manifest,
 epm.calculation_dependency_index,epm.calculation_scope_state,
 epm.calculation_generation_manifest,epm.calculation_generation_partition
 TO epm_lifecycle;

DO $migration$ DECLARE relation text;
BEGIN
 FOREACH relation IN ARRAY ARRAY['calculation_dependency_template',
   'calculation_instance_binding','calculation_execution_manifest',
   'calculation_dependency_index','calculation_scope_state',
   'calculation_generation_manifest','calculation_generation_partition'] LOOP
  EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
  EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
    'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true)) '
    'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND application_id=current_setting(''epm.application_id'',true))',relation,relation);
  EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I TO epm_lifecycle '
    'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
 END LOOP;
END $migration$;

-- Extend both qualified child-first lifecycle inventories and advance their
-- common graph pin.  The new relations are all application scoped.
DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
DECLARE previous constant text := 'eb1d2ede68050031d9b04d67109cde44e3e4cc92fe980257acc89192bf03b57d';
DECLARE current_graph constant text := '3f298fc1e53a0ebdb1ae956053ead05d925ab9d763c48bd980b9920e924dd31e';
DECLARE additions constant text := '''calculation_generation_partition'',''calculation_generation_manifest'',''calculation_scope_state'',''calculation_dependency_index'',''calculation_execution_manifest'',''calculation_instance_binding'',''calculation_dependency_template'',';
BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 OR position('''calculation_unit_result'',''calculation_result''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0298_PREDECESSOR_MISMATCH'; END IF;
 revised:=replace(definition,'''calculation_unit_result'',''calculation_result''',
   additions||'''calculation_unit_result'',''calculation_result''');
 EXECUTE replace(revised,previous,current_graph);

 inventory:=epm.application_purge_relations();
 idx:=array_position(inventory,'calculation_unit_result');
 IF idx IS NULL THEN RAISE EXCEPTION 'APPLICATION_PURGE_0298_INVENTORY_MISMATCH'; END IF;
 inventory:=inventory[1:idx-1]||ARRAY[
   'calculation_generation_partition','calculation_generation_manifest',
   'calculation_scope_state','calculation_dependency_index',
   'calculation_execution_manifest','calculation_instance_binding',
   'calculation_dependency_template']||inventory[idx:];
 FOR edge IN SELECT child.relname child,parent.relname parent FROM pg_constraint c
   JOIN pg_class child ON child.oid=c.conrelid JOIN pg_namespace cn ON cn.oid=child.relnamespace
   JOIN pg_class parent ON parent.oid=c.confrelid JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE c.contype='f' AND cn.nspname='epm' AND pn.nspname='epm' AND child.oid<>parent.oid
 LOOP
  IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
     AND array_position(inventory,edge.child)>array_position(inventory,edge.parent) THEN
   RAISE EXCEPTION 'APPLICATION_PURGE_0298_FK_ORDER_INVALID'; END IF;
 END LOOP;
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
   'SELECT '||quote_literal(inventory::text)||'::text[]');
 SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure) INTO definition;
 IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0298_PREDECESSOR_MISMATCH'; END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
