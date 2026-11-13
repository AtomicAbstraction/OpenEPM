BEGIN;
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=323) THEN
  RAISE EXCEPTION 'MIGRATION_0324_REQUIRES_0323';
 END IF;
END $migration$;

-- The planning-assignment product was removed by 0235.  These three tables
-- were its last private compatibility path.  Current application assignments
-- and workflows compose human responsibility around ordinary cube-write
-- scopes; no current product object depends on assignment-bound review rows.
DROP TRIGGER cube_write_scope_assigned_chain_reviewer
 ON epm.cube_write_scope_assigned_reviewer;
DROP TRIGGER cube_write_scope_assigned_chain_submission
 ON epm.cube_write_scope_assigned_submission;
DROP FUNCTION epm.validate_cube_write_scope_assigned_chain();

DROP TABLE epm.cube_write_scope_assigned_review_event;
DROP TABLE epm.cube_write_scope_assigned_reviewer;
DROP TABLE epm.cube_write_scope_assigned_submission;

DO $migration$ DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 definition:=replace(definition,
  '''cube_write_scope_assigned_review_event'',
        ''cube_write_scope_assigned_reviewer'',''cube_write_scope_assigned_submission'',''',
  '''');
 IF position('cube_write_scope_assigned_' IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0324_ASSIGNED_REVIEW_INVENTORY_REMAINS';
 END IF;
 EXECUTE definition;

 SELECT pg_get_functiondef('epm.application_purge_relations()'::regprocedure)
 INTO definition;
 definition:=replace(definition,
  'cube_write_scope_assigned_review_event,cube_write_scope_assigned_reviewer,cube_write_scope_assigned_submission,','');
 IF position('cube_write_scope_assigned_' IN definition)>0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0324_ASSIGNED_REVIEW_INVENTORY_REMAINS';
 END IF;
 EXECUTE definition;
END $migration$;

DO $migration$ DECLARE definition text;
DECLARE previous constant text:='8af52f227ec8277a9a13490ed90df4754018992f70bc51018d709a7c02921a58';
DECLARE current_graph constant text:='85f75c3b7ab2114344d7e3d193562b4d81aad25f3d46ab26c45d7178ce67dd5a';
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0324_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
 SELECT pg_get_functiondef(
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
 INTO definition;
 IF position(previous IN definition)=0 THEN
  RAISE EXCEPTION 'APPLICATION_PURGE_0324_PREDECESSOR_MISMATCH';END IF;
 EXECUTE replace(definition,previous,current_graph);
END $migration$;
COMMIT;
