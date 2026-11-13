BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=278) THEN
    RAISE EXCEPTION 'MIGRATION_0279_REQUIRES_0278';
  END IF;
END $migration$;

-- Member-list versions and their publication state retain the operation
-- receipts that created and published them through RESTRICT foreign keys.
-- Delete the publication first, its immutable version second, and only then
-- the receipt.  Keep the constraints restrictive: owner reset must continue
-- to prove a complete, reviewed child-first deletion inventory.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_receipt_anchor text :=
  $pattern$'cube_write_policy_version','operation_receipt','job_event_cursor',$pattern$;
DECLARE new_receipt_anchor text :=
  $pattern$'cube_write_policy_version','member_list_publication','member_list_version','operation_receipt','job_event_cursor',$pattern$;
DECLARE old_member_list_group text :=
  $pattern$'sealed_cube_selection','member_list_publication','member_list_version','saved_grid_definition',$pattern$;
DECLARE new_member_list_group text :=
  $pattern$'sealed_cube_selection','saved_grid_definition',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_receipt_anchor IN definition)=0 OR
     position(old_member_list_group IN definition)=0 OR
     position(new_receipt_anchor IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0279_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_receipt_anchor,new_receipt_anchor);
  revised := replace(revised,old_member_list_group,new_member_list_group);
  IF revised=definition OR
     position(new_receipt_anchor IN revised)=0 OR
     position(old_member_list_group IN revised)>0 THEN
    RAISE EXCEPTION 'RESET_0279_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;

COMMIT;
