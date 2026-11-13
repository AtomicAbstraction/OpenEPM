BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=334) THEN
    RAISE EXCEPTION 'MIGRATION_0335_REQUIRES_0334';
  END IF;
END $migration$;

-- Rebuildable calculation lineage belongs to the one current logical result,
-- not to a retained generation.  LIKE deliberately excludes foreign keys and
-- indexes; current-key identities and references are declared below.
CREATE TABLE epm.allocation_basis_lineage_current(
  LIKE epm.allocation_basis_lineage INCLUDING DEFAULTS INCLUDING GENERATED
    INCLUDING IDENTITY INCLUDING CONSTRAINTS);
ALTER TABLE epm.allocation_basis_lineage_current
  RENAME COLUMN generation_id TO result_key;
ALTER TABLE epm.allocation_basis_lineage_current
  ADD PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id),
  ADD FOREIGN KEY(workspace_id,application_id,result_key,coordinate_id)
    REFERENCES epm.calculation_result_current(
      workspace_id,application_id,result_key,coordinate_id) ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,basis_coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT;

CREATE TABLE epm.rollup_placement_path_current(
  LIKE epm.rollup_placement_path INCLUDING DEFAULTS INCLUDING GENERATED
    INCLUDING IDENTITY INCLUDING CONSTRAINTS);
ALTER TABLE epm.rollup_placement_path_current
  RENAME COLUMN generation_id TO result_key;
ALTER TABLE epm.rollup_placement_path_current
  ADD PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id,
    placement_path_id),
  ADD UNIQUE(workspace_id,application_id,result_key,coordinate_id,
    placement_path_id,path_ordinal),
  ADD UNIQUE(workspace_id,application_id,result_key,coordinate_id,path_ordinal),
  ADD FOREIGN KEY(workspace_id,application_id,result_key,coordinate_id)
    REFERENCES epm.calculation_result_current(
      workspace_id,application_id,result_key,coordinate_id) ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,hierarchy_dimension_id,
      root_member_id) REFERENCES epm.member(
      workspace_id,application_id,dimension_id,member_id) ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,hierarchy_dimension_id,
      leaf_member_id) REFERENCES epm.member(
      workspace_id,application_id,dimension_id,member_id) ON DELETE RESTRICT;

CREATE TABLE epm.rollup_placement_path_edge_current(
  LIKE epm.rollup_placement_path_edge INCLUDING DEFAULTS INCLUDING GENERATED
    INCLUDING IDENTITY INCLUDING CONSTRAINTS);
ALTER TABLE epm.rollup_placement_path_edge_current
  RENAME COLUMN generation_id TO result_key;
ALTER TABLE epm.rollup_placement_path_edge_current
  ADD PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id,
    placement_path_id,edge_ordinal),
  ADD FOREIGN KEY(workspace_id,application_id,result_key,coordinate_id,
      placement_path_id) REFERENCES epm.rollup_placement_path_current(
      workspace_id,application_id,result_key,coordinate_id,placement_path_id)
      ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,relationship_id,
      hierarchy_dimension_id,parent_member_id,child_member_id)
    REFERENCES epm.relationship(workspace_id,application_id,relationship_id,
      dimension_id,parent_member_id,child_member_id) ON DELETE RESTRICT;

CREATE TABLE epm.rollup_source_lineage_current(
  LIKE epm.rollup_source_lineage INCLUDING DEFAULTS INCLUDING GENERATED
    INCLUDING IDENTITY INCLUDING CONSTRAINTS);
ALTER TABLE epm.rollup_source_lineage_current
  RENAME COLUMN generation_id TO result_key;
ALTER TABLE epm.rollup_source_lineage_current
  ADD PRIMARY KEY(workspace_id,application_id,result_key,coordinate_id,
    lineage_ordinal),
  ADD FOREIGN KEY(workspace_id,application_id,result_key,coordinate_id)
    REFERENCES epm.calculation_result_current(
      workspace_id,application_id,result_key,coordinate_id) ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,source_coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,placement_relationship_id)
    REFERENCES epm.relationship(workspace_id,application_id,relationship_id)
    ON DELETE RESTRICT,
  ADD FOREIGN KEY(workspace_id,application_id,result_key,coordinate_id,
      placement_path_id,placement_path_ordinal)
    REFERENCES epm.rollup_placement_path_current(workspace_id,application_id,
      result_key,coordinate_id,placement_path_id,path_ordinal)
    ON DELETE RESTRICT;
CREATE UNIQUE INDEX rollup_source_current_legacy_unique
  ON epm.rollup_source_lineage_current(workspace_id,application_id,result_key,
    coordinate_id,source_coordinate_id) WHERE placement_path_id IS NULL;
CREATE UNIQUE INDEX rollup_source_current_path_unique
  ON epm.rollup_source_lineage_current(workspace_id,application_id,result_key,
    coordinate_id,placement_path_id,source_coordinate_id)
  WHERE placement_path_id IS NOT NULL;

INSERT INTO epm.allocation_basis_lineage_current
SELECT l.workspace_id,l.application_id,s.result_key,l.coordinate_id,
  l.basis_coordinate_id,l.basis_amount,l.basis_change_id,l.total_basis,
  l.base_units,l.remainder_numerator,l.extra_unit
FROM epm.calculation_result_state s JOIN epm.allocation_basis_lineage l
 ON l.workspace_id=s.workspace_id AND l.application_id=s.application_id
AND l.generation_id=s.bridge_generation_id;
INSERT INTO epm.rollup_placement_path_current
SELECT p.workspace_id,p.application_id,s.result_key,p.coordinate_id,
  p.placement_path_id,p.path_ordinal,p.hierarchy_dimension_id,p.root_member_id,
  p.leaf_member_id,p.relationship_count,p.hierarchy_state_token
FROM epm.calculation_result_state s JOIN epm.rollup_placement_path p
 ON p.workspace_id=s.workspace_id AND p.application_id=s.application_id
AND p.generation_id=s.bridge_generation_id;
INSERT INTO epm.rollup_placement_path_edge_current
SELECT e.workspace_id,e.application_id,s.result_key,e.coordinate_id,
  e.placement_path_id,e.edge_ordinal,e.relationship_id,
  e.hierarchy_dimension_id,e.parent_member_id,e.child_member_id
FROM epm.calculation_result_state s JOIN epm.rollup_placement_path_edge e
 ON e.workspace_id=s.workspace_id AND e.application_id=s.application_id
AND e.generation_id=s.bridge_generation_id;
INSERT INTO epm.rollup_source_lineage_current(
  workspace_id,application_id,result_key,coordinate_id,source_coordinate_id,
  source_amount,source_change_id,hierarchy_dimension_id,source_selection,
  placement_relationship_id,placement_parent_member_id,
  placement_child_member_id,lineage_ordinal,placement_path_id,
  placement_path_ordinal,hierarchy_state_token)
SELECT l.workspace_id,l.application_id,s.result_key,l.coordinate_id,
  l.source_coordinate_id,l.source_amount,l.source_change_id,
  l.hierarchy_dimension_id,l.source_selection,l.placement_relationship_id,
  l.placement_parent_member_id,l.placement_child_member_id,l.lineage_ordinal,
  l.placement_path_id,l.placement_path_ordinal,l.hierarchy_state_token
FROM epm.calculation_result_state s JOIN epm.rollup_source_lineage l
 ON l.workspace_id=s.workspace_id AND l.application_id=s.application_id
AND l.generation_id=s.bridge_generation_id;
SET CONSTRAINTS ALL IMMEDIATE;

DO $migration$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['allocation_basis_lineage_current',
    'rollup_placement_path_current','rollup_placement_path_edge_current',
    'rollup_source_lineage_current'] LOOP
    EXECUTE format('ALTER TABLE epm.%I ENABLE ROW LEVEL SECURITY',relation);
    EXECUTE format('CREATE POLICY %I_scope ON epm.%I TO epm_runtime,epm_worker,epm_analyst '
      'USING(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true)) '
      'WITH CHECK(workspace_id=current_setting(''epm.workspace_id'',true) AND '
      'application_id=current_setting(''epm.application_id'',true))',relation,relation);
    EXECUTE format('CREATE POLICY %I_lifecycle ON epm.%I FOR SELECT TO epm_lifecycle '
      'USING(current_setting(''epm.lifecycle_context'',true)=''workspace_reset'')',relation,relation);
    EXECUTE format('REVOKE ALL ON epm.%I FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle',relation);
    EXECUTE format('GRANT SELECT,INSERT,DELETE ON epm.%I TO epm_runtime',relation);
    EXECUTE format('GRANT SELECT ON epm.%I TO epm_worker,epm_analyst,epm_lifecycle',relation);
  END LOOP;
END $migration$;

DO $migration$
DECLARE definition text; revised text; inventory text[]; item text;
DECLARE previous constant text:='79ba54ed9d83d76880f9b52462bf2e1ce68c745e47b87541bd476d55968a8cb1';
DECLARE current_graph constant text:='7d480ecdd1f87d9bc2ab9a0b65b8d863216ef9d2401d62d04cfd877398a7902b';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  FOREACH item IN ARRAY ARRAY['rollup_source_lineage',
    'rollup_placement_path_edge','rollup_placement_path',
    'allocation_basis_lineage'] LOOP
    IF position(quote_literal(item) IN definition)=0 THEN
      RAISE EXCEPTION 'RESET_0335_PREDECESSOR_MISMATCH:%',item;
    END IF;
    revised:=CASE WHEN revised IS NULL THEN definition ELSE revised END;
    revised:=replace(revised,quote_literal(item),
      quote_literal(item||'_current')||','||quote_literal(item));
  END LOOP;
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  FOREACH item IN ARRAY ARRAY['rollup_source_lineage',
    'rollup_placement_path_edge','rollup_placement_path',
    'allocation_basis_lineage'] LOOP
    revised:=inventory::text;
    revised:=replace(revised,item,item||'_current,'||item);
    inventory:=revised::text[];
  END LOOP;
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
