BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=352) THEN
    RAISE EXCEPTION 'MIGRATION_0353_REQUIRES_0352';
  END IF;
END $migration$;

-- A sparse applicability relation is one current business mapping.  Rows are
-- semantic tuples consumed set-wise by rules; they are never client-authored
-- batches, partitions, leases or execution work items.
CREATE TABLE epm.applicability_relation_definition(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  relation_id text NOT NULL
    CHECK(relation_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  name text NOT NULL CHECK(length(name) BETWEEN 1 AND 200
    AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
  columns jsonb NOT NULL CHECK(jsonb_typeof(columns)='array'
    AND jsonb_array_length(columns) BETWEEN 1 AND 128
    AND octet_length(columns::text)<=131072),
  definition_digest text NOT NULL CHECK(definition_digest~'^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN ('Saved','Active','Inactive')),
  metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
  updated_issuer text NOT NULL CHECK(length(updated_issuer) BETWEEN 1 AND 300
    AND updated_issuer !~ '[[:cntrl:]]'),
  updated_subject_id text NOT NULL
    CHECK(length(updated_subject_id) BETWEEN 1 AND 300
      AND updated_subject_id !~ '[[:cntrl:]]'),
  updated_operation_id text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,relation_id),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,updated_operation_id)
    REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
    ON DELETE RESTRICT
);

CREATE TABLE epm.applicability_relation_row(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  relation_id text NOT NULL,
  row_id text NOT NULL
    CHECK(row_id~'^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'),
  values jsonb NOT NULL CHECK(jsonb_typeof(values)='object'
    AND octet_length(values::text)<=16777216),
  PRIMARY KEY(workspace_id,application_id,relation_id,row_id),
  FOREIGN KEY(workspace_id,application_id,relation_id)
    REFERENCES epm.applicability_relation_definition(
      workspace_id,application_id,relation_id) ON DELETE RESTRICT
);

ALTER TABLE epm.applicability_relation_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.applicability_relation_row ENABLE ROW LEVEL SECURITY;
CREATE POLICY applicability_relation_definition_runtime_scope
  ON epm.applicability_relation_definition TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY applicability_relation_row_runtime_scope
  ON epm.applicability_relation_row TO epm_runtime
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY applicability_relation_definition_lifecycle_scope
  ON epm.applicability_relation_definition TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY applicability_relation_row_lifecycle_scope
  ON epm.applicability_relation_row TO epm_lifecycle
  USING(workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.applicability_relation_definition,
  epm.applicability_relation_row
  FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_security,epm_lifecycle;
GRANT SELECT,INSERT,DELETE ON epm.applicability_relation_definition,
  epm.applicability_relation_row TO epm_runtime;
GRANT UPDATE(name,columns,definition_digest,state_token,status,
  metadata_revision,updated_issuer,updated_subject_id,updated_operation_id,
  updated_at) ON epm.applicability_relation_definition TO epm_runtime;
GRANT SELECT ON epm.applicability_relation_definition,
  epm.applicability_relation_row TO epm_lifecycle;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer; edge record;
DECLARE child_name text; parent_name text; pass_count integer;
DECLARE previous constant text :=
  'e68626c544dd0a6f53cfa8b97ab9797656a28b50663cebfe40da15843afd6a70';
DECLARE current_graph constant text :=
  '996d631f158526b144e3535e4de638e12c06db0a3765b7ed9026a48cd47e29f4';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 OR
     position('''member_list_definition''' IN definition)=0 THEN
    RAISE EXCEPTION 'RESET_0353_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,'''member_list_definition''',
    '''applicability_relation_row'',''applicability_relation_definition'',''member_list_definition''');
  EXECUTE replace(revised,previous,current_graph);

  -- A former rollup migration left duplicate parent entries and one parent
  -- before its child.  Normalize the complete reviewed inventory, then repair
  -- every non-self FK edge to child-first order before installing the result.
  SELECT array_agg(name ORDER BY first_ordinal) INTO inventory
  FROM (SELECT name,min(ordinality) AS first_ordinal
    FROM unnest(epm.application_purge_relations())
      WITH ORDINALITY AS item(name,ordinality)
    GROUP BY name) distinct_inventory;
  idx:=array_position(inventory,'member_list_definition');
  IF idx IS NULL THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0353_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY[
    'applicability_relation_row','applicability_relation_definition']||
    inventory[idx:];
  FOR pass_count IN 1..cardinality(inventory)*cardinality(inventory) LOOP
    child_name:=NULL; parent_name:=NULL;
    SELECT child.relname,parent.relname INTO child_name,parent_name
    FROM pg_constraint constraint_record
    JOIN pg_class child ON child.oid=constraint_record.conrelid
    JOIN pg_class parent ON parent.oid=constraint_record.confrelid
    JOIN pg_namespace child_namespace ON child_namespace.oid=child.relnamespace
    JOIN pg_namespace parent_namespace ON parent_namespace.oid=parent.relnamespace
    WHERE constraint_record.contype='f'
      AND child_namespace.nspname='epm'
      AND parent_namespace.nspname='epm'
      AND child.oid<>parent.oid
      AND child.relname=ANY(inventory) AND parent.relname=ANY(inventory)
      AND array_position(inventory,child.relname)>
          array_position(inventory,parent.relname)
    ORDER BY array_position(inventory,parent.relname),child.relname
    LIMIT 1;
    EXIT WHEN child_name IS NULL;
    inventory:=array_remove(inventory,child_name);
    idx:=array_position(inventory,parent_name);
    inventory:=inventory[1:idx-1]||ARRAY[child_name]||inventory[idx:];
  END LOOP;
  FOR edge IN SELECT child.relname AS child,parent.relname AS parent
    FROM pg_constraint constraint_record
    JOIN pg_class child ON child.oid=constraint_record.conrelid
    JOIN pg_class parent ON parent.oid=constraint_record.confrelid
    JOIN pg_namespace child_namespace ON child_namespace.oid=child.relnamespace
    JOIN pg_namespace parent_namespace ON parent_namespace.oid=parent.relnamespace
    WHERE constraint_record.contype='f'
      AND child_namespace.nspname='epm'
      AND parent_namespace.nspname='epm'
      AND child.oid<>parent.oid
  LOOP
    IF edge.child=ANY(inventory) AND edge.parent=ANY(inventory)
       AND array_position(inventory,edge.child)>
           array_position(inventory,edge.parent) THEN
      RAISE EXCEPTION 'APPLICATION_PURGE_0353_FK_ORDER_INVALID: % -> %',
        edge.child,edge.parent;
    END IF;
  END LOOP;
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0353_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
