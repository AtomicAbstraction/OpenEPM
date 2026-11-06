-- Application schedules and their rule workflows reference immutable rule
-- versions. Move the complete child chain ahead of expression_rule_version in
-- the exact owner-reset deletion list.
DO $migration$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=236) THEN
  RAISE EXCEPTION 'MIGRATION_0237_PREDECESSOR_0236_REQUIRED';
 END IF;
END $migration$;

DO $migration$
DECLARE definition text; revised text;
DECLARE old_group text :=
 $pattern$'application_schedule_occurrence','application_schedule_state','application_schedule_version','application_rule_workflow_child','application_rule_workflow','sealed_cube_selection',$pattern$;
DECLARE removed_group text := $pattern$'sealed_cube_selection',$pattern$;
DECLARE old_anchor text :=
 $pattern$'expression_rule_version','raw_operation_membership',$pattern$;
DECLARE new_anchor text :=
 $pattern$'application_schedule_occurrence','application_schedule_state','application_schedule_version','application_rule_workflow_child','application_rule_workflow','expression_rule_version','raw_operation_membership',$pattern$;
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position(old_group IN definition)=0 OR
    position(old_anchor IN definition)=0 OR
    position(new_anchor IN definition)>0 THEN
  RAISE EXCEPTION 'RESET_0237_DEFINITION_MISMATCH';
 END IF;
 revised:=replace(definition,old_group,removed_group);
 revised:=replace(revised,old_anchor,new_anchor);
 IF revised=definition OR position(new_anchor IN revised)=0 OR
    position(old_group IN revised)>0 THEN
  RAISE EXCEPTION 'RESET_0237_UPDATE_FAILED';
 END IF;
 EXECUTE revised;
END $migration$;
