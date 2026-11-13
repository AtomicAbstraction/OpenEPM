BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=368) THEN
    RAISE EXCEPTION 'MIGRATION_0369_REQUIRES_0368';
  END IF;
END $migration$;

-- Business provenance and replay state have different lifetimes.  This table
-- is the additive, minimal provenance side of the split.  Existing receipt
-- references remain unchanged until a later migration proves every reference
-- can be retargeted without weakening integrity or purge semantics.
CREATE TABLE epm.operation_commit_provenance(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  operation_id text NOT NULL CHECK(length(operation_id) BETWEEN 1 AND 200),
  command_digest text NOT NULL CHECK(command_digest~'^[0-9a-f]{64}$'),
  actor_id text NOT NULL CHECK(length(actor_id) BETWEEN 1 AND 200),
  committed_revision bigint NOT NULL CHECK(committed_revision>0),
  committed_at timestamptz NOT NULL,
  PRIMARY KEY(workspace_id,application_id,operation_id),
  UNIQUE(workspace_id,application_id,committed_revision),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE CASCADE
);

INSERT INTO epm.operation_commit_provenance(
  workspace_id,application_id,operation_id,command_digest,actor_id,
  committed_revision,committed_at)
SELECT workspace_id,application_id,operation_id,command_digest,actor_id,
       committed_revision,committed_at
FROM epm.operation_receipt;

CREATE FUNCTION epm.operation_commit_provenance_capture() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  INSERT INTO epm.operation_commit_provenance(
    workspace_id,application_id,operation_id,command_digest,actor_id,
    committed_revision,committed_at)
  VALUES(NEW.workspace_id,NEW.application_id,NEW.operation_id,
    NEW.command_digest,NEW.actor_id,NEW.committed_revision,NEW.committed_at);
  RETURN NULL;
END $$;

CREATE TRIGGER operation_commit_provenance_capture
AFTER INSERT ON epm.operation_receipt FOR EACH ROW
EXECUTE FUNCTION epm.operation_commit_provenance_capture();

REVOKE ALL ON FUNCTION epm.operation_commit_provenance_capture() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.operation_commit_provenance_capture()
  TO epm_runtime;

ALTER TABLE epm.operation_commit_provenance ENABLE ROW LEVEL SECURITY;
CREATE POLICY operation_commit_provenance_scope
ON epm.operation_commit_provenance TO epm_runtime
USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
GRANT SELECT ON epm.operation_commit_provenance TO epm_runtime;

-- Register the new scoped relation in both lifecycle deletion inventories and
-- advance their reviewed graph pin.  The row is a child of application_state;
-- placing it immediately before operation_receipt is child-first and keeps
-- its independently counted deletion visible instead of relying on cascade.
DO $lifecycle$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:=
  'e2995ccaffc189892c442f38c30cfe576d02aa87473280a5de77e170bca8a0a9';
DECLARE current_graph constant text:=
  '3c31399aa62696d9d5de1cd1462bd2bc78e65a2bca1eb7bc122a4d6c1b6dd529';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0
     OR position('''saved_grid_definition'',''operation_receipt'',''generic_fact_table''' IN definition)=0
     OR position('''operation_commit_provenance''' IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0369_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''saved_grid_definition'',''operation_receipt'',''generic_fact_table''',
    '''saved_grid_definition'',''operation_commit_provenance'',''operation_receipt'',''generic_fact_table''');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'operation_receipt');
  IF idx IS NULL OR 'operation_commit_provenance'=ANY(inventory) THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0369_INVENTORY_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY['operation_commit_provenance']||
             inventory[idx:];
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');

  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0369_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $lifecycle$;

COMMIT;
SELECT '0369 applied' AS migration;
