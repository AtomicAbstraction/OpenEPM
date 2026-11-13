BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=359) THEN
    RAISE EXCEPTION 'MIGRATION_0360_REQUIRES_0359';
  END IF;
END $migration$;

-- Coordinate membership is authoritative in coordinate.members.  Validate a
-- whole insert transition once, before deriving its projections, rather than
-- repeating coordinate/member FK probes for every derived axis row.
CREATE OR REPLACE FUNCTION epm.coordinate_project_inserted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM coordinate_inserted c
    JOIN epm.layout_replacement_activation x USING(workspace_id,application_id)
    WHERE x.status='Activating' AND epm.layout_replacement_activation_allowed(
      c.workspace_id,c.application_id,x.target_projection_generation)) THEN
    RETURN NULL;
  END IF;
  PERFORM 1 FROM epm.application_state s
    JOIN(SELECT DISTINCT workspace_id,application_id FROM coordinate_inserted)c
      USING(workspace_id,application_id)
    ORDER BY s.workspace_id,s.application_id FOR UPDATE OF s;
  IF EXISTS(SELECT 1 FROM coordinate_inserted c
    JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
    WHERE ARRAY(SELECT key FROM jsonb_object_keys(c.members)keys(key)
      ORDER BY key COLLATE "C")<>l.dimensions) THEN
    RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH' USING ERRCODE='23514';
  END IF;
  IF EXISTS(SELECT 1 FROM coordinate_inserted c
    CROSS JOIN LATERAL jsonb_each_text(c.members) item
    LEFT JOIN epm.member m ON m.workspace_id=c.workspace_id
      AND m.application_id=c.application_id
      AND m.dimension_id=item.key AND m.member_id=item.value
    WHERE m.member_id IS NULL) THEN
    RAISE EXCEPTION 'COORDINATE_MEMBER_UNAVAILABLE' USING ERRCODE='23503';
  END IF;
  INSERT INTO epm.coordinate_projection_state(projection_generation,
    workspace_id,application_id,coordinate_id,schema_epoch,entity_member,
    account_member,scenario_member,year_member,period_member,value_member,
    view_member,icp_member,data_type_member,custom_members)
  SELECT s.active_projection_generation,c.workspace_id,c.application_id,
    c.coordinate_id,l.schema_epoch,
    c.members->>(l.role_dimensions->>'Entity'),
    c.members->>(l.role_dimensions->>'Account'),
    c.members->>(l.role_dimensions->>'Scenario'),
    c.members->>(l.role_dimensions->>'Year'),
    c.members->>(l.role_dimensions->>'Period'),
    c.members->>(l.role_dimensions->>'Value'),
    c.members->>(l.role_dimensions->>'View'),
    c.members->>(l.role_dimensions->>'ICP'),
    c.members->>(l.role_dimensions->>'DataType'),
    ARRAY(SELECT c.members->>axis FROM unnest(l.custom_dimensions)
      WITH ORDINALITY z(axis,pos) ORDER BY pos)
  FROM coordinate_inserted c
  JOIN epm.application_state s USING(workspace_id,application_id)
  JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch);
  RETURN NULL;
END $$;

CREATE FUNCTION epm.coordinate_member_projection_coordinate_delete_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM coordinate_deleted d
    JOIN epm.coordinate_member_projection p
      ON p.workspace_id=d.workspace_id
     AND p.application_id=d.application_id
     AND p.coordinate_id=d.coordinate_id) THEN
    RAISE EXCEPTION 'COORDINATE_MEMBER_PROJECTION_REFERENCED'
      USING ERRCODE='23503';
  END IF;
  RETURN NULL;
END $$;

CREATE FUNCTION epm.coordinate_member_projection_member_delete_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
BEGIN
  IF EXISTS(SELECT 1 FROM member_deleted d
    JOIN epm.coordinate_member_projection p
      ON p.workspace_id=d.workspace_id
     AND p.application_id=d.application_id
     AND p.dimension_id=d.dimension_id
     AND p.member_id=d.member_id) THEN
    RAISE EXCEPTION 'COORDINATE_MEMBER_PROJECTION_REFERENCED'
      USING ERRCODE='23503';
  END IF;
  RETURN NULL;
END $$;

CREATE TRIGGER coordinate_member_projection_coordinate_delete_guard
AFTER DELETE ON epm.coordinate
REFERENCING OLD TABLE AS coordinate_deleted FOR EACH STATEMENT
EXECUTE FUNCTION epm.coordinate_member_projection_coordinate_delete_guard();

CREATE TRIGGER coordinate_member_projection_member_delete_guard
AFTER DELETE ON epm.member
REFERENCING OLD TABLE AS member_deleted FOR EACH STATEMENT
EXECUTE FUNCTION epm.coordinate_member_projection_member_delete_guard();

DO $migration$
DECLARE constraint_name text; removed integer:=0;
BEGIN
  FOR constraint_name IN
    SELECT conname FROM pg_constraint
    WHERE conrelid='epm.coordinate_member_projection'::regclass
      AND contype='f'
    ORDER BY conname
  LOOP
    EXECUTE format('ALTER TABLE epm.coordinate_member_projection DROP CONSTRAINT %I',
                   constraint_name);
    removed:=removed+1;
  END LOOP;
  IF removed<>2 THEN
    RAISE EXCEPTION 'MIGRATION_0360_COORDINATE_MEMBER_FK_COUNT: %',removed;
  END IF;
END $migration$;

REVOKE ALL ON FUNCTION
  epm.coordinate_member_projection_coordinate_delete_guard(),
  epm.coordinate_member_projection_member_delete_guard() FROM PUBLIC;

-- The reviewed reset/purge graph fingerprint changes after the two redundant
-- projection FKs are replaced by set-wise boundary guards.
DO $migration$
DECLARE function_id regprocedure; definition text; revised text;
BEGIN
  FOREACH function_id IN ARRAY ARRAY[
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure,
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(function_id) INTO definition;
    revised:=replace(definition,
      '1806a173f9db6dd9a3ceb6cd24bcf772fa6d01f812914706581b5f4da017244e',
      'ec134ab6a03db5d6b8ddc11e0867acc9c1749c8fb339d8677b7ff702647763b0');
    IF revised=definition THEN
      RAISE EXCEPTION 'MIGRATION_0360_FINGERPRINT_PREDECESSOR_MISSING: %',
                      function_id::text;
    END IF;
    EXECUTE revised;
  END LOOP;
END $migration$;

COMMIT;
