BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=374) THEN
    RAISE EXCEPTION 'MIGRATION_0375_REQUIRES_0374';
  END IF;
END $migration$;

-- Migration 0372 added three typed source-evidence relations and seven exact
-- foreign keys.  Its lifecycle inventories were updated, but the graph value
-- sealed into reset/purge was calculated before the final PostgreSQL graph was
-- observed.  Reconcile only the reviewed identity; no business row changes.
DO $reconcile$
DECLARE reset_definition text;purge_definition text;inventory text[];
DECLARE previous constant text:=
  '6e1f5508abf72f98423b38f06736e3da5ab7982cbbac45dd22c00e1d355c5ff9';
DECLARE current_graph constant text:=
  '090c87c423ce39f0233ea03dc9db290f2305fae43668f413ad657929c4b94fa1';
BEGIN
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='epm' AND c.relkind='r' AND c.relname IN
        ('source_evidence_collection','source_evidence_document',
         'source_evidence_record'))<>3
     OR (SELECT count(*) FROM pg_constraint con
         JOIN pg_class child ON child.oid=con.conrelid
         JOIN pg_namespace n ON n.oid=child.relnamespace
         WHERE con.contype='f' AND n.nspname='epm' AND child.relname IN
           ('source_evidence_collection','source_evidence_document',
            'source_evidence_record'))<>7 THEN
    RAISE EXCEPTION 'RESET_0375_SOURCE_EVIDENCE_GRAPH_DRIFT';
  END IF;

  inventory:=epm.application_purge_relations();
  IF array_position(inventory,'source_evidence_record') IS NULL
     OR array_position(inventory,'source_evidence_document') IS NULL
     OR array_position(inventory,'source_evidence_collection') IS NULL
     OR array_position(inventory,'operation_commit_provenance') IS NULL
     OR NOT (array_position(inventory,'source_evidence_record')<
             array_position(inventory,'source_evidence_document')
       AND array_position(inventory,'source_evidence_document')<
             array_position(inventory,'source_evidence_collection')
       AND array_position(inventory,'source_evidence_collection')<
             array_position(inventory,'operation_commit_provenance')) THEN
    RAISE EXCEPTION 'RESET_0375_SOURCE_EVIDENCE_ORDER_DRIFT';
  END IF;

  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO reset_definition;
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
    INTO purge_definition;
  IF position(previous IN reset_definition)=0
     OR position(previous IN purge_definition)=0
     OR position(current_graph IN reset_definition)>0
     OR position(current_graph IN purge_definition)>0 THEN
    RAISE EXCEPTION 'RESET_0375_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(reset_definition,previous,current_graph);
  EXECUTE replace(purge_definition,previous,current_graph);
END $reconcile$;

COMMIT;
SELECT '0375 applied' AS migration;
