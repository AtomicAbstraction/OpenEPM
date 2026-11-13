BEGIN;
DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=292) THEN
    RAISE EXCEPTION 'MIGRATION_0293_REQUIRES_0292';
  END IF;
END $migration$;

ALTER TABLE epm.expression_rule_version ADD COLUMN source_build_id text;
ALTER TABLE epm.member_list_version ADD COLUMN source_build_id text;
ALTER TABLE epm.expression_rule_version ADD CONSTRAINT expression_rule_source_build_fk
  FOREIGN KEY(workspace_id,application_id,source_build_id)
  REFERENCES epm.python_program_build(workspace_id,application_id,build_id) ON DELETE RESTRICT;
ALTER TABLE epm.member_list_version ADD CONSTRAINT member_list_source_build_fk
  FOREIGN KEY(workspace_id,application_id,source_build_id)
  REFERENCES epm.python_program_build(workspace_id,application_id,build_id) ON DELETE RESTRICT;

CREATE FUNCTION epm.source_bound_definition_guard()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $function$
DECLARE artifact record; operation jsonb; definition jsonb; function_name text;
BEGIN
  IF TG_OP='UPDATE' AND (OLD.source_build_id IS NOT NULL OR NEW.source_build_id IS NOT NULL) THEN
    RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  IF NEW.source_build_id IS NULL THEN RETURN NEW; END IF;
  SELECT b.purpose,b.status,a.canonical_plan,a.source_map,a.impact,a.sealed_at,v.source_digest
    INTO artifact FROM epm.python_program_build b
    JOIN epm.python_plan_artifact a USING(workspace_id,application_id,build_id)
    JOIN epm.python_program_version v ON v.workspace_id=b.workspace_id
      AND v.application_id=b.application_id AND v.program_id=b.program_id AND v.version=b.program_version
    WHERE b.workspace_id=NEW.workspace_id AND b.application_id=NEW.application_id
      AND b.build_id=NEW.source_build_id;
  IF NOT FOUND OR artifact.purpose NOT IN ('Validation','ImpactTest') OR artifact.status<>'sealed'
      OR (artifact.purpose='ImpactTest' AND (artifact.impact->>'status' IS DISTINCT FROM 'complete'
        OR artifact.sealed_at<=clock_timestamp()-interval '24 hours'))
      OR artifact.source_map->>'sourceDigest' IS DISTINCT FROM artifact.source_digest
      OR jsonb_array_length(artifact.canonical_plan->'units')<>1
      OR jsonb_array_length(artifact.canonical_plan#>'{units,0,operations}')<>1 THEN
    RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_INVALID' USING ERRCODE='23514';
  END IF;
  operation:=artifact.canonical_plan#>'{units,0,operations,0}';
  function_name:=operation->>'function'; definition:=operation#>'{arguments,definition}';
  IF TG_TABLE_NAME='member_list_version' THEN
    IF function_name<>'metadata.member_list.version.save'
       OR definition IS DISTINCT FROM NEW.definition
       OR definition->>'listId' IS DISTINCT FROM NEW.list_id
       OR (definition->>'version')::bigint IS DISTINCT FROM NEW.version THEN
      RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_MISMATCH' USING ERRCODE='23514';
    END IF;
  ELSE
    IF function_name NOT IN ('application.rule.version.save','calculated.member.version.save')
       OR definition IS DISTINCT FROM NEW.program->'arguments'
       OR COALESCE(operation#>>'{arguments,ruleId}',definition->>'definitionId') IS DISTINCT FROM NEW.rule_id
       OR COALESCE(operation#>>'{arguments,version}',definition->>'version')::bigint IS DISTINCT FROM NEW.version
       OR NEW.program->>'function' IS DISTINCT FROM (CASE function_name
         WHEN 'application.rule.version.save' THEN 'application.rule.plan'
         ELSE 'calculated.member.definition' END) THEN
      RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_MISMATCH' USING ERRCODE='23514';
    END IF;
  END IF;
  IF (operation#>>'{arguments,expectedMetadataRevision}')::bigint IS DISTINCT FROM NEW.metadata_revision THEN
    RAISE EXCEPTION 'PYTHON_DEFINITION_SOURCE_METADATA_MISMATCH' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $function$;
REVOKE ALL ON FUNCTION epm.source_bound_definition_guard() FROM PUBLIC;
CREATE TRIGGER expression_rule_source_guard BEFORE INSERT OR UPDATE ON epm.expression_rule_version
  FOR EACH ROW EXECUTE FUNCTION epm.source_bound_definition_guard();
CREATE TRIGGER member_list_source_guard BEFORE INSERT OR UPDATE ON epm.member_list_version
  FOR EACH ROW EXECUTE FUNCTION epm.source_bound_definition_guard();

COMMENT ON COLUMN epm.expression_rule_version.source_build_id IS
  'Derived immutable definition; authored source is the referenced Validation build program/version.';
COMMENT ON COLUMN epm.member_list_version.source_build_id IS
  'Derived immutable definition; authored source is the referenced Validation build program/version.';
-- Source definitions already precede builds in both qualified inventories.
-- Verify every retained FK edge under those orders, then pin both lifecycle
-- boundaries to the source-provenance graph. No wider deletion is introduced.
DO $migration$
DECLARE definition text; body text; reset_order text[]; purge_order text[];
DECLARE logical text[]; item text; edge record;
DECLARE previous constant text := '1163589cb3bd257c54c5c988a437cdfdfc00f63afee82189f11675d243460f77';
DECLARE current_graph constant text := 'cc795a1184fe76b7b75b9a01a10b0c2b411992da523f9c8cbc1d0d241eabc087';
BEGIN
  SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'RESET_0293_PREDECESSOR_MISMATCH'; END IF;
  body:=split_part(split_part(definition,'FOREACH v_table IN ARRAY ARRAY[',2),']',1);
  IF body='' THEN RAISE EXCEPTION 'RESET_0293_INVENTORY_MISSING'; END IF;
  EXECUTE 'SELECT ARRAY['||body||']::text[]' INTO logical;
  FOREACH item IN ARRAY logical LOOP
    reset_order:=array_append(reset_order,CASE item
      WHEN 'numeric_cell_current' THEN 'numeric_cell_projection'
      WHEN 'text_cell_current' THEN 'text_cell_projection'
      WHEN 'line_detail_current' THEN 'line_detail_projection'
      WHEN 'generic_fact_current' THEN 'generic_fact_projection'
      WHEN 'coordinate_member' THEN 'coordinate_member_projection'
      WHEN 'coordinate_projection' THEN 'coordinate_projection_state' ELSE item END);
  END LOOP;
  purge_order:=epm.application_purge_relations();
  FOREACH item IN ARRAY ARRAY['expression_rule_version','member_list_version'] LOOP
    IF array_position(reset_order,item) IS NULL OR array_position(purge_order,item) IS NULL
       OR array_position(reset_order,item)>=array_position(reset_order,'python_program_build')
       OR array_position(purge_order,item)>=array_position(purge_order,'python_program_build') THEN
      RAISE EXCEPTION 'RESET_0293_SOURCE_BUILD_ORDER_INVALID';
    END IF;
  END LOOP;
  FOR edge IN SELECT child.relname AS child,parent.relname AS parent
    FROM pg_constraint con JOIN pg_class child ON child.oid=con.conrelid
    JOIN pg_namespace nc ON nc.oid=child.relnamespace
    JOIN pg_class parent ON parent.oid=con.confrelid
    JOIN pg_namespace np ON np.oid=parent.relnamespace
    WHERE con.contype='f' AND nc.nspname='epm' AND np.nspname='epm'
      AND child.oid<>parent.oid
  LOOP
    IF (edge.child=ANY(reset_order) AND edge.parent=ANY(reset_order)
          AND array_position(reset_order,edge.child)>array_position(reset_order,edge.parent))
       OR (edge.child=ANY(purge_order) AND edge.parent=ANY(purge_order)
          AND array_position(purge_order,edge.child)>array_position(purge_order,edge.parent)) THEN
      RAISE EXCEPTION 'RESET_0293_FK_ORDER_INVALID';
    END IF;
  END LOOP;
  EXECUTE replace(definition,previous,current_graph);
  SELECT pg_get_functiondef('epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN RAISE EXCEPTION 'APPLICATION_PURGE_0293_PREDECESSOR_MISMATCH'; END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
