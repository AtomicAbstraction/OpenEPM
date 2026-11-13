BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=317) THEN
  RAISE EXCEPTION 'MIGRATION_0318_REQUIRES_0317';
 END IF;
END $migration$;

-- Development keeps reproducibility in Git and migrations, not copies of
-- retired application payloads in the product database. Remove the archive
-- from both lifecycle inventories before dropping its immutable storage.
DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position('''retired_product_history'',' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0318_RETIRED_HISTORY_MISSING';
 END IF;
 definition:=replace(definition,'''retired_product_history'',','');
 IF position('retired_product_history' IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0318_RETIRED_HISTORY_REMAINS';
 END IF;
 EXECUTE definition;

 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
  INTO definition;
 IF position('retired_product_history' IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0318_RETIRED_HISTORY_MISSING';
 END IF;
 definition:=replace(definition,'retired_product_history,','');
 definition:=replace(definition,',retired_product_history',',');
 IF position('retired_product_history' IN definition)>0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0318_RETIRED_HISTORY_REMAINS';
 END IF;
 EXECUTE definition;
END $migration$;

DROP TRIGGER retired_product_history_immutable ON epm.retired_product_history;
DROP FUNCTION epm.retired_product_history_immutable();
DROP TABLE epm.retired_product_history;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='076f9601bdb2068ad0e6a4a09ca928a10092ace4e34fd4712711b6a44fd66833';
DECLARE current_graph constant text:='4eff3423cb81f10bf160bc923f6af8475ed33bcf7cc33d19b384bc4ded08de16';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0318_PREDECESSOR_MISMATCH';
 END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef(
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0318_PREDECESSOR_MISMATCH';
 END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
